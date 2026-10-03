//! ETW collector (administrator): real-time process, network, and DNS events.
//!
//! | Provider | Events used |
//! |---|---|
//! | Microsoft-Windows-Kernel-Process | 1 ProcessStart, 2 ProcessStop |
//! | Microsoft-Windows-Kernel-Network | 12/28 TCP connect (v4/v6), 42/58 UDP send (v4/v6) |
//! | Microsoft-Windows-DNS-Client | 3008 query completed |
//!
//! UDP sends are rate-limited to one `NetConnect` per (pid, destination) per
//! five minutes. Kernel image names are NT device paths and are converted to
//! drive-letter paths.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result, anyhow};
use async_trait::async_trait;
use ferrisetw::EventRecord;
use ferrisetw::parser::Parser;
use ferrisetw::provider::Provider;
use ferrisetw::schema_locator::SchemaLocator;
use ferrisetw::trace::UserTrace;
use tokio::sync::mpsc;
use vigil_core::time::now_ms;
use vigil_core::{Event, EventKind, Proto};
use windows_sys::Win32::Storage::FileSystem::QueryDosDeviceW;

use super::poll::WinSource;
use crate::poll::{Differ, SnapshotSource, is_loopback};

const KERNEL_PROCESS: u128 = 0x22fb2cd6_0e7b_422b_a0c7_2fad1fd0e716;
const KERNEL_NETWORK: u128 = 0x7dd42a49_5329_4832_8dfd_43d979153a88;
const DNS_CLIENT: u128 = 0x1c95126e_7eea_49a9_a3fe_a378b03ddb4d;
const WINEVENT_KEYWORD_PROCESS: u64 = 0x10;
const SESSION_NAME: &str = "Vigil-Collector";
const UDP_REPORT_INTERVAL_MS: i64 = 5 * 60 * 1000;
const UDP_DEDUP_MAX: usize = 50_000;

type Slot = Arc<Mutex<Option<mpsc::Sender<Event>>>>;

/// Maps `\Device\HarddiskVolumeN` prefixes to drive letters.
#[derive(Debug, Default)]
pub struct DevicePaths {
    map: Vec<(String, String)>,
}

impl DevicePaths {
    pub fn load() -> Self {
        let mut map = Vec::new();
        for letter in b'A'..=b'Z' {
            let drive: Vec<u16> = format!("{}:", char::from(letter))
                .encode_utf16()
                .chain([0])
                .collect();
            let mut buf = vec![0u16; 1024];
            // SAFETY: drive is NUL-terminated; buf has the stated capacity.
            let n = unsafe { QueryDosDeviceW(drive.as_ptr(), buf.as_mut_ptr(), buf.len() as u32) };
            if n > 0 {
                let end = buf.iter().position(|&c| c == 0).unwrap_or(n as usize);
                let device = String::from_utf16_lossy(&buf[..end]);
                map.push((device, format!("{}:", char::from(letter))));
            }
        }
        DevicePaths { map }
    }

    /// Converts an NT device path to a drive-letter path when possible.
    pub fn to_dos(&self, nt: &str) -> String {
        for (device, drive) in &self.map {
            if let Some(rest) = nt.strip_prefix(device.as_str())
                && (rest.is_empty() || rest.starts_with('\\'))
            {
                return format!("{drive}{rest}");
            }
        }
        nt.to_string()
    }
}

/// Extracts IP addresses from a DNS-Client `QueryResults` string such as
/// `"type:  5 edge.example.net;::ffff:93.184.216.34;2606:2800::1;"`.
pub fn parse_query_results(s: &str) -> Vec<IpAddr> {
    s.split(';')
        .filter_map(|t| t.trim().parse::<IpAddr>().ok())
        .map(|ip| ip.to_canonical())
        .collect()
}

fn send(slot: &Slot, ev: Event) {
    if let Ok(guard) = slot.lock()
        && let Some(tx) = guard.as_ref()
    {
        // Never block the ETW processing thread; drop on overload.
        if tx.try_send(ev).is_err() {
            tracing::debug!("ETW event dropped (pipeline full)");
        }
    }
}

/// ETW raw timestamps use the session's clock (QPC by default), so events are
/// stamped on receipt; real-time sessions deliver within about a second.
fn event_ts(_record: &EventRecord) -> i64 {
    now_ms()
}

fn process_callback(
    slot: Slot,
    devices: Arc<DevicePaths>,
) -> impl Fn(&EventRecord, &SchemaLocator) + Send + Sync + 'static {
    move |record, locator| {
        let Ok(schema) = locator.event_schema(record) else {
            return;
        };
        let parser = Parser::create(record, &schema);
        let Ok(pid) = parser.try_parse::<u32>("ProcessID") else {
            return;
        };
        let kind = match record.event_id() {
            1 => {
                let ppid = parser.try_parse::<u32>("ParentProcessID").unwrap_or(0);
                let image: String = parser.try_parse("ImageName").unwrap_or_default();
                let exe = devices.to_dos(&image);
                let cmdline = super::poll::cmdline_of(pid);
                EventKind::ProcessStart { ppid, exe, cmdline }
            }
            2 => EventKind::ProcessExit,
            _ => return,
        };
        send(
            &slot,
            Event {
                ts: event_ts(record),
                pid,
                kind,
            },
        );
    }
}

fn network_callback(
    slot: Slot,
    include_loopback: bool,
) -> impl Fn(&EventRecord, &SchemaLocator) + Send + Sync + 'static {
    let recent: Mutex<HashMap<(u32, IpAddr, u16), i64>> = Mutex::new(HashMap::new());
    move |record, locator| {
        let proto = match record.event_id() {
            12 | 28 => Proto::Tcp,
            42 | 58 => Proto::Udp,
            _ => return,
        };
        let Ok(schema) = locator.event_schema(record) else {
            return;
        };
        let parser = Parser::create(record, &schema);
        let (Ok(pid), Ok(daddr), Ok(dport_raw)) = (
            parser.try_parse::<u32>("PID"),
            parser.try_parse::<IpAddr>("daddr"),
            parser.try_parse::<u16>("dport"),
        ) else {
            return;
        };
        let remote_ip = daddr.to_canonical();
        // win:Port fields are in network byte order.
        let remote_port = u16::from_be(dport_raw);
        if pid == 0 || (!include_loopback && is_loopback(remote_ip)) {
            return;
        }
        let ts = event_ts(record);
        if proto == Proto::Udp {
            let Ok(mut map) = recent.lock() else { return };
            let key = (pid, remote_ip, remote_port);
            if map
                .get(&key)
                .is_some_and(|&last| ts - last < UDP_REPORT_INTERVAL_MS)
            {
                return;
            }
            if map.len() >= UDP_DEDUP_MAX {
                map.retain(|_, &mut last| ts - last < UDP_REPORT_INTERVAL_MS);
            }
            map.insert(key, ts);
        }
        send(
            &slot,
            Event {
                ts,
                pid,
                kind: EventKind::NetConnect {
                    remote_ip,
                    remote_port,
                    proto,
                    domain: None,
                    dns_before: false,
                },
            },
        );
    }
}

fn dns_callback(slot: Slot) -> impl Fn(&EventRecord, &SchemaLocator) + Send + Sync + 'static {
    move |record, locator| {
        if record.event_id() != 3008 {
            return;
        }
        let Ok(schema) = locator.event_schema(record) else {
            return;
        };
        let parser = Parser::create(record, &schema);
        if parser.try_parse::<u32>("QueryStatus").unwrap_or(1) != 0 {
            return;
        }
        let (Ok(name), Ok(results)) = (
            parser.try_parse::<String>("QueryName"),
            parser.try_parse::<String>("QueryResults"),
        ) else {
            return;
        };
        let answers = parse_query_results(&results);
        if name.is_empty() || answers.is_empty() {
            return;
        }
        send(
            &slot,
            Event {
                ts: event_ts(record),
                pid: record.process_id(),
                kind: EventKind::DnsQuery { name, answers },
            },
        );
    }
}

pub struct EtwCollector {
    slot: Slot,
    trace: Mutex<Option<UserTrace>>,
    include_loopback: bool,
}

impl std::fmt::Debug for EtwCollector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EtwCollector")
            .field("include_loopback", &self.include_loopback)
            .finish_non_exhaustive()
    }
}

impl EtwCollector {
    /// Starts the ETW session (fails without administrator rights). Events
    /// are delivered once `run` is called.
    pub fn new(include_loopback: bool, dns: bool) -> Result<Self> {
        let slot: Slot = Arc::new(Mutex::new(None));
        let devices = Arc::new(DevicePaths::load());
        let process = Provider::by_guid(KERNEL_PROCESS)
            .any(WINEVENT_KEYWORD_PROCESS)
            .add_callback(process_callback(slot.clone(), devices))
            .build();
        let network = Provider::by_guid(KERNEL_NETWORK)
            .add_callback(network_callback(slot.clone(), include_loopback))
            .build();
        let mut builder = UserTrace::new()
            .named(SESSION_NAME.to_string())
            .enable(process)
            .enable(network);
        if dns {
            builder = builder.enable(
                Provider::by_guid(DNS_CLIENT)
                    .add_callback(dns_callback(slot.clone()))
                    .build(),
            );
        }
        let trace = builder
            .start_and_process()
            .map_err(|e| anyhow!("starting ETW session {SESSION_NAME}: {e:?}"))?;
        Ok(EtwCollector {
            slot,
            trace: Mutex::new(Some(trace)),
            include_loopback,
        })
    }
}

#[async_trait]
impl crate::Collector for EtwCollector {
    fn name(&self) -> &'static str {
        "windows-etw"
    }

    async fn run(&self, tx: mpsc::Sender<Event>) -> Result<()> {
        // Processes already running before the session started.
        let snapshot = tokio::task::spawn_blocking(|| WinSource::new().processes())
            .await
            .context("snapshot task")??;
        for ev in Differ::new(self.include_loopback).diff_processes(&snapshot, now_ms()) {
            tx.send(ev).await?;
        }
        *self.slot.lock().map_err(|_| anyhow!("ETW slot poisoned"))? = Some(tx.clone());
        tx.closed().await;
        *self.slot.lock().map_err(|_| anyhow!("ETW slot poisoned"))? = None;
        if let Some(trace) = self
            .trace
            .lock()
            .map_err(|_| anyhow!("ETW trace lock poisoned"))?
            .take()
        {
            trace
                .stop()
                .map_err(|e| anyhow!("stopping ETW session: {e:?}"))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_results_parsing() {
        let ips = parse_query_results(
            "type:  5 edge.example.net;::ffff:93.184.216.34;2606:2800:220:1::;",
        );
        assert_eq!(
            ips,
            vec![
                "93.184.216.34".parse::<IpAddr>().unwrap(),
                "2606:2800:220:1::".parse().unwrap()
            ]
        );
        assert!(parse_query_results("").is_empty());
        assert!(parse_query_results("type:  5 only.cname;").is_empty());
    }

    #[test]
    fn device_path_conversion() {
        let d = DevicePaths {
            map: vec![(r"\Device\HarddiskVolume3".into(), "C:".into())],
        };
        assert_eq!(
            d.to_dos(r"\Device\HarddiskVolume3\Windows\System32\cmd.exe"),
            r"C:\Windows\System32\cmd.exe"
        );
        assert_eq!(
            d.to_dos(r"\Device\HarddiskVolume30\x.exe"),
            r"\Device\HarddiskVolume30\x.exe"
        );
        assert_eq!(
            d.to_dos(r"\Device\Mup\server\share\a.exe"),
            r"\Device\Mup\server\share\a.exe"
        );
    }

    #[test]
    fn real_device_map_resolves_system_drive() {
        let d = DevicePaths::load();
        let sys = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".into());
        assert!(
            d.map
                .iter()
                .any(|(_, drive)| drive.eq_ignore_ascii_case(&sys))
        );
    }
}
