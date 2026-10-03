//! `--monitor`: live collection with a per-process connection printer.

use std::io::Write;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use tokio::sync::broadcast;
use vigil_core::{Config, EventBus, EventKind, Observation};

use crate::{logging, service};

/// Formats Unix ms as `HH:MM:SS.mmmZ` (UTC).
pub fn clock(ts_ms: i64) -> String {
    let ms = ts_ms.rem_euclid(86_400_000);
    format!(
        "{:02}:{:02}:{:02}.{:03}Z",
        ms / 3_600_000,
        ms / 60_000 % 60,
        ms / 1000 % 60,
        ms % 1000
    )
}

/// Last path component of a Windows or Unix path.
pub fn basename(path: &str) -> &str {
    path.rsplit(['/', '\\']).next().unwrap_or(path)
}

fn endpoint(ip: IpAddr, port: u16) -> String {
    match ip {
        IpAddr::V4(v4) => format!("{v4}:{port}"),
        IpAddr::V6(v6) => format!("[{v6}]:{port}"),
    }
}

/// Renders connection lines from observations.
#[derive(Debug, Default)]
pub struct Printer;

impl Printer {
    /// Returns a line to print for connections; `None` for other observations.
    pub fn handle(&mut self, obs: &Observation) -> Option<String> {
        let EventKind::NetConnect {
            remote_ip,
            remote_port,
            proto,
            domain,
            dns_before,
        } = &obs.event.kind
        else {
            return None;
        };
        let (name, taint) = match &obs.process {
            Some(p) => (
                basename(&p.exe.path).to_string(),
                match (p.tainted, p.taint_root) {
                    (true, Some(root)) => format!("  TAINTED(root={root})"),
                    (true, None) => "  TAINTED".to_string(),
                    _ => String::new(),
                },
            ),
            None => ("?".to_string(), String::new()),
        };
        Some(format!(
            "{}  pid={:<7} {:<20} -> {:<28} {:<32} dns_before={}{}",
            clock(obs.event.ts),
            obs.event.pid,
            name,
            format!("{}/{}", endpoint(*remote_ip, *remote_port), proto.as_str()),
            domain.as_deref().unwrap_or("-"),
            if *dns_before { "yes" } else { "no" },
            taint,
        ))
    }
}

async fn print_loop(mut rx: broadcast::Receiver<Arc<Observation>>) {
    let mut printer = Printer;
    let stdout = std::io::stdout();
    loop {
        match rx.recv().await {
            Ok(obs) => {
                if let Some(line) = printer.handle(&obs) {
                    let mut out = stdout.lock();
                    let _ = writeln!(out, "{line}");
                    let _ = out.flush();
                }
            }
            Err(broadcast::error::RecvError::Lagged(n)) => {
                tracing::warn!(missed = n, "monitor output lagged");
            }
            Err(broadcast::error::RecvError::Closed) => break,
        }
    }
}

pub fn run(cfg: &Config, duration_secs: Option<u64>, no_store: bool) -> Result<()> {
    let _log = logging::init(&cfg.logging, &cfg.paths.log_dir)?;
    service::block_on(async {
        let bus = EventBus::<Observation>::new(service::BUS_CAPACITY);
        let printer = tokio::spawn(print_loop(bus.subscribe()));
        let opts = service::Options {
            store: !no_store,
            ipc: false,
        };
        let running = service::start(cfg, opts, bus).await?;
        match duration_secs {
            Some(secs) => tokio::time::sleep(Duration::from_secs(secs)).await,
            None => service::shutdown_signal().await,
        }
        running.shutdown().await;
        let _ = printer.await;
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use vigil_core::Proto;

    #[test]
    fn clock_and_basename() {
        assert_eq!(clock(0), "00:00:00.000Z");
        assert_eq!(clock(1_700_000_000_123), "22:13:20.123Z");
        assert_eq!(basename("/usr/bin/curl"), "curl");
        assert_eq!(basename(r"C:\Windows\System32\curl.exe"), "curl.exe");
        assert_eq!(basename("curl"), "curl");
    }

    #[test]
    fn printer_shows_process_and_taint() {
        use vigil_core::{Event, FileInfo, Origin, PathClass, ProcessInfo, SignState};
        let process = Arc::new(ProcessInfo {
            pid: 42,
            ppid: 1,
            start_time: 0,
            exe: FileInfo {
                path: "/home/u/Downloads/curl".into(),
                sha256: [1; 32],
                origin: Origin::Downloaded {
                    url: None,
                    referrer: None,
                },
                sign: SignState::Unsigned,
                yara_hits: vec![],
                first_seen: 0,
            },
            script: None,
            path_class: PathClass::Downloads,
            tainted: true,
            taint_root: Some(42),
            app_id: "sha256:01".into(),
        });
        let conn = Event {
            ts: 1_000,
            pid: 42,
            kind: EventKind::NetConnect {
                remote_ip: "2001:db8::1".parse().unwrap(),
                remote_port: 443,
                proto: Proto::Tcp,
                domain: Some("example.com".into()),
                dns_before: true,
            },
        };
        let mut p = Printer;
        let line = p
            .handle(&Observation {
                event: conn.clone(),
                process: Some(process),
                tags: vec![],
            })
            .unwrap();
        assert!(line.contains("pid=42"), "{line}");
        assert!(line.contains("curl"), "{line}");
        assert!(line.contains("[2001:db8::1]:443/tcp"), "{line}");
        assert!(line.contains("example.com"), "{line}");
        assert!(line.ends_with("dns_before=yes  TAINTED(root=42)"), "{line}");
        let bare = p.handle(&Observation::bare(conn)).unwrap();
        assert!(bare.contains(" ? "), "unknown process shows '?': {bare}");
        assert!(
            p.handle(&Observation::bare(Event {
                ts: 0,
                pid: 1,
                kind: EventKind::ProcessExit
            }))
            .is_none()
        );
    }
}
