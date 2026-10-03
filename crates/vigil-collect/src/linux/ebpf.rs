//! eBPF tracepoint collector (feature `ebpf`, root).
//!
//! Processes (exec/exit) and outbound TCP connects arrive in real time with
//! exact PID attribution. A `/proc` snapshot at startup reports processes
//! that were already running. Exec events are enriched from `/proc/<pid>`
//! (ppid, canonical exe path, command line); if the process has already
//! exited, the filename captured in the kernel is used.
#![allow(unsafe_code)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::unix::fs::MetadataExt;
use std::sync::Mutex;

use anyhow::{Context, Result, anyhow};
use async_trait::async_trait;
use aya::maps::RingBuf;
use aya::programs::TracePoint;
use aya::{Ebpf, EbpfLoader};
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc;
use vigil_core::time::now_ms;
use vigil_core::{Event, EventKind, Proto};
use vigil_ebpf_common::{AF_INET, AF_INET6, KIND_CONNECT, KIND_EXEC, KIND_EXIT, RawEvent, layout};

use super::procfs::{self, ProcfsSource};
use crate::Collector;
use crate::poll::{Differ, SnapshotSource, is_loopback};

const PROGRAMS: &[(&str, &str, &str)] = &[
    ("vigil_exec", "sched", "sched_process_exec"),
    ("vigil_exit", "sched", "sched_process_exit"),
    ("vigil_sock", "sock", "inet_sock_set_state"),
];

pub struct EbpfCollector {
    ebpf: Mutex<Option<Ebpf>>,
    include_loopback: bool,
}

impl std::fmt::Debug for EbpfCollector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EbpfCollector")
            .field("include_loopback", &self.include_loopback)
            .finish_non_exhaustive()
    }
}

fn raise_memlock() {
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    // SAFETY: rlim is a valid rlimit; failure only matters on pre-5.11 kernels.
    let rc = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if rc != 0 {
        tracing::debug!("could not raise RLIMIT_MEMLOCK");
    }
}

impl EbpfCollector {
    /// Verifies tracepoint layouts, loads, and attaches the programs.
    pub fn new(include_loopback: bool) -> Result<Self> {
        super::tracefs::verify(layout::CHECKS)
            .map_err(|e| anyhow!("tracepoint layout check failed: {e}"))?;
        raise_memlock();
        // Report PIDs in our own namespace (containers, WSL2).
        let ns = std::fs::metadata("/proc/self/ns/pid").context("stat /proc/self/ns/pid")?;
        let (dev, ino) = (ns.dev(), ns.ino());
        let mut ebpf = EbpfLoader::new()
            .override_global("PIDNS_DEV", &dev, true)
            .override_global("PIDNS_INO", &ino, true)
            .load(aya::include_bytes_aligned!(concat!(
                env!("OUT_DIR"),
                "/vigil-ebpf"
            )))
            .context("loading eBPF object")?;
        for &(prog, category, name) in PROGRAMS {
            let p: &mut TracePoint = ebpf
                .program_mut(prog)
                .ok_or_else(|| anyhow!("program {prog} missing from eBPF object"))?
                .try_into()?;
            p.load().with_context(|| format!("loading {prog}"))?;
            p.attach(category, name)
                .with_context(|| format!("attaching {prog} to {category}/{name}"))?;
        }
        Ok(EbpfCollector {
            ebpf: Mutex::new(Some(ebpf)),
            include_loopback,
        })
    }
}

/// Decodes one ring-buffer record. Returns `None` for unknown kinds or
/// short records.
pub fn decode(bytes: &[u8]) -> Option<RawEvent> {
    if bytes.len() < std::mem::size_of::<RawEvent>() {
        return None;
    }
    // SAFETY: length checked; RawEvent is plain-old-data (repr(C), integers and
    // byte arrays only), so any bit pattern is valid. read_unaligned handles alignment.
    Some(unsafe { std::ptr::read_unaligned(bytes.as_ptr().cast::<RawEvent>()) })
}

fn c_string(buf: &[u8]) -> String {
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..end]).into_owned()
}

/// Turns a raw record into an event (reading `/proc` for exec details).
pub fn to_event(raw: &RawEvent, include_loopback: bool) -> Option<Event> {
    let ts = now_ms();
    let pid = raw.tgid;
    let kind = match raw.kind {
        KIND_EXEC => {
            let dir = format!("/proc/{pid}");
            let ppid = std::fs::read_to_string(format!("{dir}/stat"))
                .ok()
                .and_then(|s| procfs::parse_stat(&s))
                .map_or(0, |s| s.ppid);
            let exe = std::fs::read_link(format!("{dir}/exe"))
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_else(|_| c_string(&raw.filename));
            let cmdline = std::fs::read(format!("{dir}/cmdline"))
                .ok()
                .and_then(|b| procfs::parse_cmdline(&b));
            EventKind::ProcessStart { ppid, exe, cmdline }
        }
        KIND_EXIT => EventKind::ProcessExit,
        KIND_CONNECT => {
            let remote_ip = match raw.family {
                AF_INET => IpAddr::V4(Ipv4Addr::new(
                    raw.daddr[0],
                    raw.daddr[1],
                    raw.daddr[2],
                    raw.daddr[3],
                )),
                AF_INET6 => IpAddr::V6(Ipv6Addr::from(raw.daddr)).to_canonical(),
                _ => return None,
            };
            if !include_loopback && is_loopback(remote_ip) {
                return None;
            }
            EventKind::NetConnect {
                remote_ip,
                remote_port: raw.dport,
                proto: Proto::Tcp,
                domain: None,
                dns_before: false,
            }
        }
        _ => return None,
    };
    Some(Event { ts, pid, kind })
}

#[async_trait]
impl Collector for EbpfCollector {
    fn name(&self) -> &'static str {
        "linux-ebpf"
    }

    async fn run(&self, tx: mpsc::Sender<Event>) -> Result<()> {
        let mut ebpf = self
            .ebpf
            .lock()
            .map_err(|_| anyhow!("eBPF state lock poisoned"))?
            .take()
            .ok_or_else(|| anyhow!("eBPF collector already running"))?;

        // Processes already running before attach.
        let mut source = ProcfsSource::new()?;
        let snapshot = source.processes()?;
        for ev in Differ::new(self.include_loopback).diff_processes(&snapshot, now_ms()) {
            tx.send(ev).await?;
        }

        let map = ebpf
            .take_map("EVENTS")
            .ok_or_else(|| anyhow!("EVENTS map missing"))?;
        let ring = RingBuf::try_from(map)?;
        let mut fd = AsyncFd::new(ring)?;
        loop {
            let mut guard = tokio::select! {
                g = fd.readable_mut() => g?,
                _ = tx.closed() => break,
            };
            let ring = guard.get_inner_mut();
            while let Some(item) = ring.next() {
                if let Some(ev) =
                    decode(&item).and_then(|raw| to_event(&raw, self.include_loopback))
                    && tx.send(ev).await.is_err()
                {
                    return Ok(());
                }
            }
            guard.clear_ready();
        }
        drop(ebpf); // detaches programs
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw(kind: u32) -> RawEvent {
        let mut r = RawEvent::zeroed();
        r.kind = kind;
        r.tgid = 4242;
        r
    }

    fn bytes(r: &RawEvent) -> Vec<u8> {
        // SAFETY: RawEvent is POD; viewing it as bytes is sound.
        unsafe {
            std::slice::from_raw_parts(
                (r as *const RawEvent).cast::<u8>(),
                std::mem::size_of::<RawEvent>(),
            )
        }
        .to_vec()
    }

    #[test]
    fn decodes_connect_v4_and_v6() {
        let mut r = raw(KIND_CONNECT);
        r.family = AF_INET;
        r.dport = 443;
        r.daddr[..4].copy_from_slice(&[93, 184, 216, 34]);
        let ev = to_event(&decode(&bytes(&r)).unwrap(), false).unwrap();
        assert_eq!(ev.pid, 4242);
        match ev.kind {
            EventKind::NetConnect {
                remote_ip,
                remote_port,
                ..
            } => {
                assert_eq!(remote_ip.to_string(), "93.184.216.34");
                assert_eq!(remote_port, 443);
            }
            k => panic!("{k:?}"),
        }
        let mut r6 = raw(KIND_CONNECT);
        r6.family = AF_INET6;
        r6.daddr = "::ffff:10.1.2.3".parse::<Ipv6Addr>().unwrap().octets();
        match to_event(&r6, false).unwrap().kind {
            EventKind::NetConnect { remote_ip, .. } => {
                assert_eq!(remote_ip.to_string(), "10.1.2.3")
            }
            k => panic!("{k:?}"),
        }
    }

    #[test]
    fn loopback_filtered_and_short_records_rejected() {
        let mut r = raw(KIND_CONNECT);
        r.family = AF_INET;
        r.daddr[..4].copy_from_slice(&[127, 0, 0, 1]);
        assert!(to_event(&r, false).is_none());
        assert!(to_event(&r, true).is_some());
        assert!(decode(&[0u8; 8]).is_none());
        assert!(to_event(&raw(99), true).is_none());
    }

    #[test]
    fn exec_falls_back_to_kernel_filename() {
        let mut r = raw(KIND_EXEC);
        r.tgid = u32::MAX; // no such process
        r.filename[..9].copy_from_slice(b"/bin/tool");
        match to_event(&r, false).unwrap().kind {
            EventKind::ProcessStart { exe, ppid, cmdline } => {
                assert_eq!(exe, "/bin/tool");
                assert_eq!(ppid, 0);
                assert!(cmdline.is_none());
            }
            k => panic!("{k:?}"),
        }
    }
}
