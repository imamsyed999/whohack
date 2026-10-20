//! Counters are cumulative for this service run. Missing attribution is never
//! filled with a guessed PID. A collector failure makes visibility uncertain.
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

#[derive(Debug, Default)]
pub struct Health {
    pub files: AtomicBool,
    pub registry: AtomicBool,
    pub injection: AtomicBool,
    pub dropped: AtomicU64,
    pub kernel_lost: AtomicU64,
    pub unattributed: AtomicU64,
    pub failures: AtomicU64,
}

impl Health {
    pub fn healthy(&self) -> bool {
        self.failures.load(Ordering::Relaxed) == 0
    }
    pub fn unattributed(&self) {
        self.unattributed.fetch_add(1, Ordering::Relaxed);
    }
}
