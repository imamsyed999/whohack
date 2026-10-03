//! Persists observations to SQLite on a dedicated thread: events (batched
//! per tick), processes with their taint state, and exit times. Old events
//! are pruned hourly.

use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use tokio::sync::broadcast::{self, error::TryRecvError};
use vigil_core::time::{MS_PER_DAY, now_ms};
use vigil_core::{EventKind, Observation, Store};

const MAX_BATCH: usize = 2_000;
const PRUNE_EVERY: Duration = Duration::from_secs(60 * 60);

#[derive(Debug)]
pub struct StoreWriter {
    handle: JoinHandle<u64>,
}

impl StoreWriter {
    /// Starts the writer. It exits (after a final flush) once every bus
    /// sender has been dropped.
    pub fn start(
        store: Store,
        rx: broadcast::Receiver<Arc<Observation>>,
        retention_days: u32,
    ) -> Self {
        let handle = std::thread::Builder::new()
            .name("vigil-store-writer".into())
            .spawn(move || writer_loop(store, rx, retention_days))
            .expect("spawn store writer thread");
        StoreWriter { handle }
    }

    /// Waits for the writer to finish; returns the number of events stored.
    pub fn join(self) -> u64 {
        self.handle.join().unwrap_or(0)
    }
}

fn flush(store: &Store, batch: &mut Vec<Arc<Observation>>) -> u64 {
    if batch.is_empty() {
        return 0;
    }
    // Processes first so events can be joined to them.
    for obs in batch.iter() {
        let Some(p) = &obs.process else { continue };
        let res = match obs.event.kind {
            EventKind::ProcessStart { .. } => store.insert_process(p).map(|_| ()),
            EventKind::ProcessExit => store
                .mark_process_exit(p.pid, p.start_time, obs.event.ts)
                .map(|_| ()),
            _ => Ok(()),
        };
        if let Err(e) = res {
            tracing::error!(error = %e, pid = p.pid, "failed to store process");
        }
    }
    let events: Vec<_> = batch.iter().map(|o| o.event.clone()).collect();
    let stored = match store.insert_events(&events) {
        Ok(n) => n as u64,
        Err(e) => {
            tracing::error!(error = %e, count = events.len(), "failed to store events");
            0
        }
    };
    batch.clear();
    stored
}

fn writer_loop(
    store: Store,
    mut rx: broadcast::Receiver<Arc<Observation>>,
    retention_days: u32,
) -> u64 {
    let retention_ms = i64::from(retention_days) * MS_PER_DAY;
    let mut stored = 0u64;
    let mut last_prune: Option<Instant> = None; // None: prune once at startup
    let mut batch: Vec<Arc<Observation>> = Vec::with_capacity(MAX_BATCH);
    let mut closed = false;
    while !closed {
        // Block for the first observation, then drain whatever else is queued.
        match rx.blocking_recv() {
            Ok(o) => batch.push(o),
            Err(broadcast::error::RecvError::Lagged(n)) => {
                tracing::warn!(missed = n, "store writer lagged; events dropped");
            }
            Err(broadcast::error::RecvError::Closed) => closed = true,
        }
        while batch.len() < MAX_BATCH {
            match rx.try_recv() {
                Ok(o) => batch.push(o),
                Err(TryRecvError::Lagged(n)) => {
                    tracing::warn!(missed = n, "store writer lagged; events dropped");
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Closed) => {
                    closed = true;
                    break;
                }
            }
        }
        stored += flush(&store, &mut batch);
        if last_prune.is_none_or(|t| t.elapsed() >= PRUNE_EVERY) {
            match store.prune_events(now_ms() - retention_ms) {
                Ok(0) => {}
                Ok(n) => tracing::info!(deleted = n, "pruned old events"),
                Err(e) => tracing::error!(error = %e, "event pruning failed"),
            }
            last_prune = Some(Instant::now());
        }
    }
    stored
}

#[cfg(test)]
mod tests {
    use super::*;
    use vigil_core::{Event, EventBus, FileInfo, Origin, PathClass, ProcessInfo, SignState};

    fn proc_info(pid: u32) -> Arc<ProcessInfo> {
        Arc::new(ProcessInfo {
            pid,
            ppid: 1,
            start_time: 1_000,
            exe: FileInfo {
                path: "/home/u/Downloads/tool".into(),
                sha256: [3; 32],
                origin: Origin::Downloaded {
                    url: None,
                    referrer: None,
                },
                sign: SignState::Unsigned,
                yara_hits: vec![],
                first_seen: 1_000,
            },
            script: None,
            path_class: PathClass::Downloads,
            tainted: true,
            taint_root: Some(pid),
            app_id: "sha256:03".into(),
        })
    }

    #[test]
    fn writes_events_and_processes_then_exits_when_bus_closes() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("v.db");
        let bus = EventBus::<Observation>::new(1024);
        let writer = StoreWriter::start(Store::open(&db).unwrap(), bus.subscribe(), 30);
        let p = proc_info(42);
        bus.publish(Observation {
            event: Event {
                ts: 1_000,
                pid: 42,
                kind: EventKind::ProcessStart {
                    ppid: 1,
                    exe: p.exe.path.clone(),
                    cmdline: None,
                },
            },
            process: Some(p.clone()),
            tags: vec![],
        });
        for i in 0..99 {
            bus.publish(Observation::bare(Event {
                ts: now_ms(),
                pid: 1000 + i,
                kind: EventKind::ProcessExit,
            }));
        }
        bus.publish(Observation {
            event: Event {
                ts: 2_000,
                pid: 42,
                kind: EventKind::ProcessExit,
            },
            process: Some(p.clone()),
            tags: vec![],
        });
        drop(bus);
        assert_eq!(writer.join(), 101);
        let s = Store::open(&db).unwrap();
        assert_eq!(s.process(42, 1_000).unwrap().unwrap(), *p);
        assert_eq!(s.process_exit_time(42, 1_000).unwrap(), Some(2_000));
    }

    #[test]
    fn prunes_expired_events_at_startup() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("v.db");
        {
            let s = Store::open(&db).unwrap();
            s.insert_event(&Event {
                ts: now_ms() - 40 * MS_PER_DAY,
                pid: 1,
                kind: EventKind::ProcessExit,
            })
            .unwrap();
        }
        let bus = EventBus::<Observation>::new(16);
        let writer = StoreWriter::start(Store::open(&db).unwrap(), bus.subscribe(), 30);
        bus.publish(Observation::bare(Event {
            ts: now_ms(),
            pid: 2,
            kind: EventKind::ProcessExit,
        }));
        drop(bus);
        writer.join();
        assert_eq!(Store::open(&db).unwrap().row_count("events").unwrap(), 1);
    }
}
