//! Bounded aggregation keeps packet volume out of the event/store pipeline.
use std::collections::HashMap;
use whohack_core::{Event, EventKind};
#[derive(Debug, Default)]
pub struct ByteCounters {
    counters: HashMap<u32, (u64, u64, i64)>,
}
impl ByteCounters {
    pub fn record(&mut self, pid: u32, up: u64, down: u64, now: i64) {
        if pid == 0 || (!self.counters.contains_key(&pid) && self.counters.len() >= 16_384) {
            return;
        }
        let c = self.counters.entry(pid).or_insert((0, 0, now));
        c.0 = c.0.saturating_add(up);
        c.1 = c.1.saturating_add(down);
    }
    pub fn forget(&mut self, pid: u32) {
        self.counters.remove(&pid);
    }
    pub fn take(&mut self, pid: u32, now: i64) -> Option<Event> {
        self.counters
            .remove(&pid)
            .map(|(bytes_up, bytes_down, _)| Event {
                ts: now,
                pid,
                kind: EventKind::NetStats {
                    bytes_up,
                    bytes_down,
                },
            })
    }
    pub fn drain_due(&mut self, now: i64) -> Vec<Event> {
        let pids: Vec<_> = self
            .counters
            .iter()
            .filter(|(_, (_, _, first))| now.saturating_sub(*first) >= 1000)
            .map(|(pid, _)| *pid)
            .collect();
        pids.into_iter()
            .filter_map(|pid| self.take(pid, now))
            .collect()
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn byte_deltas_are_aggregated_once_and_pid_reuse_is_cleared() {
        let mut c = ByteCounters::default();
        c.record(7, 100, 0, 1);
        c.record(7, 0, 50, 2);
        assert!(c.drain_due(999).is_empty());
        let e = c.drain_due(1001);
        assert_eq!(
            e[0].kind,
            EventKind::NetStats {
                bytes_up: 100,
                bytes_down: 50
            }
        );
        assert!(c.drain_due(1002).is_empty());
        c.record(7, 1, 2, 1003);
        c.forget(7);
        assert!(c.take(7, 1004).is_none());
    }
}
