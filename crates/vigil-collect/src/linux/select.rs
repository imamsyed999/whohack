//! Linux backend selection.

use std::sync::Arc;
use std::time::Duration;

use vigil_core::config::{CollectBackend, CollectConfig};

use super::dns_sniff::DnsSniffer;
use super::procfs::ProcfsSource;
use crate::poll::{PollCollector, PollScope};
use crate::{Collector, Selection};

pub fn select(cfg: &CollectConfig) -> anyhow::Result<Selection> {
    let root = super::is_root();
    let interval = Duration::from_millis(cfg.poll_interval_ms);
    let mut collectors: Vec<Arc<dyn Collector>> = Vec::new();
    let mut notes = Vec::new();

    let native = match cfg.backend {
        CollectBackend::Poll => None,
        CollectBackend::Auto | CollectBackend::Native => native_collector(cfg, root, &mut notes),
    };
    match native {
        Some(c) => {
            collectors.push(c);
            // eBPF covers processes and TCP; UDP flows still come from /proc.
            collectors.push(Arc::new(PollCollector::new(
                "linux-procfs-udp",
                ProcfsSource::new()?,
                interval,
                cfg.include_loopback,
                PollScope {
                    processes: false,
                    tcp: false,
                    udp: true,
                },
            )));
            notes.push("UDP flows: /proc polling".into());
        }
        None if cfg.backend == CollectBackend::Native => {
            anyhow::bail!(
                "collect.backend = \"native\" but no native Linux backend is available: {}",
                notes.join("; ")
            )
        }
        None => {
            collectors.push(Arc::new(PollCollector::new(
                "linux-procfs",
                ProcfsSource::new()?,
                interval,
                cfg.include_loopback,
                PollScope::ALL,
            )));
            notes.push(if root {
                "processes + network: /proc polling".into()
            } else {
                "processes + network: /proc polling (unprivileged: other users' sockets are not attributed; run as root for full visibility)".into()
            });
        }
    }

    let mut dns_visible = false;
    if cfg.dns {
        match DnsSniffer::probe() {
            Ok(()) => {
                collectors.push(Arc::new(DnsSniffer));
                dns_visible = true;
                notes.push("DNS: AF_PACKET sniffer".into());
            }
            Err(e) => notes.push(format!("DNS: unavailable ({e}); domain attribution off")),
        }
    }
    Ok(Selection {
        collectors,
        dns_visible,
        notes,
    })
}

#[cfg(feature = "ebpf")]
fn native_collector(
    cfg: &CollectConfig,
    root: bool,
    notes: &mut Vec<String>,
) -> Option<Arc<dyn Collector>> {
    if !root {
        notes.push("eBPF: requires root".into());
        return None;
    }
    match super::ebpf::EbpfCollector::new(cfg.include_loopback) {
        Ok(c) => {
            notes.push("processes + TCP: eBPF tracepoints".into());
            Some(Arc::new(c))
        }
        Err(e) => {
            notes.push(format!("eBPF: unavailable ({e:#})"));
            None
        }
    }
}

#[cfg(not(feature = "ebpf"))]
fn native_collector(
    _cfg: &CollectConfig,
    _root: bool,
    notes: &mut Vec<String>,
) -> Option<Arc<dyn Collector>> {
    notes.push("eBPF: not compiled in (build with --features ebpf)".into());
    None
}
