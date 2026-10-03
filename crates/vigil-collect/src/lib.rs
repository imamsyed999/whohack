//! Vigil collectors (SPEC §8): per-OS sources of process, network, and DNS
//! events, plus backend selection.
//!
//! | OS | native (privileged) | fallback |
//! |---|---|---|
//! | Linux | eBPF tracepoints (feature `ebpf`) + AF_PACKET DNS | `/proc` polling |
//! | Windows | ETW (Kernel-Process, Kernel-Network, DNS-Client) | ToolHelp + IP Helper polling |
//! | macOS | Endpoint Security / Network Extension (M9) | libproc polling ("limited mode") |

use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::mpsc;
use vigil_core::Event;

pub mod dns_wire;
pub mod poll;

#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(windows)]
pub mod windows;

pub use poll::{PollCollector, PollScope, ProcSnap, SnapshotSource, SockSnap, SockState};

/// An event source. `run` returns when the receiver is dropped or on a fatal error.
#[async_trait]
pub trait Collector: Send + Sync {
    fn name(&self) -> &'static str;
    async fn run(&self, tx: mpsc::Sender<Event>) -> anyhow::Result<()>;
}

/// The collectors chosen for this machine and configuration.
pub struct Selection {
    pub collectors: Vec<Arc<dyn Collector>>,
    /// True when a DNS source is active (see `vigil_intel::DnsCache::is_visible`).
    pub dns_visible: bool,
    /// Human-readable description of what was chosen and why.
    pub notes: Vec<String>,
}

impl std::fmt::Debug for Selection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Selection")
            .field(
                "collectors",
                &self.collectors.iter().map(|c| c.name()).collect::<Vec<_>>(),
            )
            .field("dns_visible", &self.dns_visible)
            .field("notes", &self.notes)
            .finish()
    }
}

/// Picks collectors for the current OS, privileges, and `cfg`.
pub fn select(cfg: &vigil_core::config::CollectConfig) -> anyhow::Result<Selection> {
    #[cfg(target_os = "linux")]
    return linux::select::select(cfg);
    #[cfg(windows)]
    return windows::select(cfg);
    #[cfg(target_os = "macos")]
    return macos::select(cfg);
    #[cfg(not(any(target_os = "linux", windows, target_os = "macos")))]
    {
        let _ = cfg;
        anyhow::bail!("unsupported operating system")
    }
}
