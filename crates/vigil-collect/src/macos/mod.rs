//! macOS collectors.
//!
//! Full mode (Endpoint Security + Network Extension) needs Apple-granted
//! entitlements (SPEC §8, M9). Until then Vigil runs in **limited mode**:
//! libproc polling for processes and sockets, with no DNS visibility.

pub mod libproc;

use std::sync::Arc;
use std::time::Duration;

use vigil_core::config::{CollectBackend, CollectConfig};

use crate::poll::{PollCollector, PollScope};
use crate::{Collector, Selection};

pub fn select(cfg: &CollectConfig) -> anyhow::Result<Selection> {
    if cfg.backend == CollectBackend::Native {
        anyhow::bail!(
            "collect.backend = \"native\" requires the Endpoint Security / Network Extension build (not yet available); use \"auto\" or \"poll\""
        );
    }
    let collectors: Vec<Arc<dyn Collector>> = vec![Arc::new(PollCollector::new(
        "macos-libproc",
        libproc::MacSource::new(),
        Duration::from_millis(cfg.poll_interval_ms),
        cfg.include_loopback,
        PollScope::ALL,
    ))];
    Ok(Selection {
        collectors,
        dns_visible: false,
        notes: vec![
            "LIMITED MODE: libproc polling (short-lived processes may be missed; no DNS visibility). Full mode needs Endpoint Security entitlements.".into(),
        ],
    })
}
