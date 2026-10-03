use std::sync::Arc;

use super::{CapabilityTag, Event, ProcessInfo};

/// An event after the pipeline's enrichment stages: DNS attribution, the
/// acting process with taint/lineage (M2), and capability tags (M3).
///
/// Internal to the service (not serialized): alerts and IPC messages carry
/// their own types.
#[derive(Debug, Clone, PartialEq)]
pub struct Observation {
    pub event: Event,
    /// The acting process, if known (DNS answers from a sniffer have none).
    pub process: Option<Arc<ProcessInfo>>,
    pub tags: Vec<CapabilityTag>,
}

impl Observation {
    pub fn bare(event: Event) -> Self {
        Observation {
            event,
            process: None,
            tags: Vec::new(),
        }
    }
}
