//! Event pipeline (SPEC §5):
//!
//! ```text
//! collectors ─► enricher (DNS attribution, async) ─► analysis thread ─► bus<Observation>
//!                                                    (taint + lineage; tags and
//!                                                     detection join in M3+)
//! ```
//!
//! The analysis stage runs on a dedicated thread because first sight of an
//! executable means file I/O (hashing, signature checks, YARA).

use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use vigil_collect::Collector;
use vigil_core::time::now_ms;
use vigil_core::{Event, EventBus, Observation};
use vigil_intel::enrich::DEFAULT_GRACE_MS;
use vigil_intel::{DnsCache, Enricher};
use vigil_taint::TaintEngine;

/// Capacity of the collectors → enricher channel.
const INGEST_BUFFER: usize = 8192;
/// Capacity of the enricher → analysis channel.
const ANALYSIS_BUFFER: usize = 8192;
/// How often held connections are re-checked for release.
const TICK: Duration = Duration::from_millis(100);
/// Housekeeping interval for the analysis stage.
const ANALYSIS_TICK: Duration = Duration::from_secs(1);

/// A running pipeline.
#[derive(Debug)]
pub struct Pipeline {
    stop: watch::Sender<bool>,
    enrich_task: JoinHandle<()>,
    analysis_task: JoinHandle<u64>,
}

impl Pipeline {
    /// Spawns every collector and both stages. Must be called inside a tokio runtime.
    pub fn start(
        collectors: Vec<Arc<dyn Collector>>,
        dns_visible: bool,
        taint: TaintEngine,
        bus: EventBus<Observation>,
    ) -> Pipeline {
        let (tx, rx) = mpsc::channel::<Event>(INGEST_BUFFER);
        for c in collectors {
            let tx = tx.clone();
            tokio::spawn(async move {
                let name = c.name();
                tracing::info!(collector = name, "collector started");
                match c.run(tx).await {
                    Ok(()) => tracing::info!(collector = name, "collector stopped"),
                    Err(e) => {
                        tracing::error!(collector = name, error = %format!("{e:#}"), "collector failed")
                    }
                }
            });
        }
        drop(tx);
        let (stop, stop_rx) = watch::channel(false);
        let mut enricher = Enricher::new(DnsCache::default(), DEFAULT_GRACE_MS);
        enricher.set_dns_visible(dns_visible);
        let (atx, arx) = mpsc::channel::<Event>(ANALYSIS_BUFFER);
        let enrich_task = tokio::spawn(enrich_stage(rx, stop_rx, enricher, atx));
        let analysis_task = tokio::task::spawn_blocking(move || analysis_stage(arx, taint, bus));
        Pipeline {
            stop,
            enrich_task,
            analysis_task,
        }
    }

    /// Stops collection, flushes held events through every stage, and
    /// returns the number of observations published.
    pub async fn shutdown(self) -> u64 {
        let _ = self.stop.send(true);
        let _ = self.enrich_task.await;
        self.analysis_task.await.unwrap_or(0)
    }
}

async fn enrich_stage(
    mut rx: mpsc::Receiver<Event>,
    mut stop: watch::Receiver<bool>,
    mut enricher: Enricher,
    out: mpsc::Sender<Event>,
) {
    let mut tick = tokio::time::interval(TICK);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        let ready = tokio::select! {
            ev = rx.recv() => match ev {
                Some(ev) => enricher.process(ev, now_ms()),
                None => break, // every collector has stopped
            },
            _ = tick.tick() => enricher.tick(now_ms()),
            _ = stop.changed() => break,
        };
        for ev in ready {
            if out.send(ev).await.is_err() {
                return;
            }
        }
    }
    // Dropping `rx` makes collectors' sends fail, so they exit.
    drop(rx);
    for ev in enricher.drain() {
        if out.send(ev).await.is_err() {
            return;
        }
    }
}

fn analysis_stage(
    mut rx: mpsc::Receiver<Event>,
    mut taint: TaintEngine,
    bus: EventBus<Observation>,
) -> u64 {
    let mut published = 0u64;
    let mut last_tick = Instant::now();
    while let Some(ev) = rx.blocking_recv() {
        let obs = taint.observe(ev, now_ms());
        bus.publish(obs);
        published += 1;
        if last_tick.elapsed() >= ANALYSIS_TICK {
            taint.tick(now_ms());
            last_tick = Instant::now();
        }
    }
    taint.flush();
    published
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use vigil_core::{EventKind, Proto};
    use vigil_taint::{FileAnalyzer, ProcessTracker};

    struct Scripted(Vec<Event>);

    #[async_trait]
    impl Collector for Scripted {
        fn name(&self) -> &'static str {
            "scripted"
        }
        async fn run(&self, tx: mpsc::Sender<Event>) -> anyhow::Result<()> {
            for e in &self.0 {
                tx.send(e.clone()).await?;
            }
            Ok(())
        }
    }

    fn engine() -> TaintEngine {
        TaintEngine::new(FileAnalyzer::new(None), ProcessTracker::default())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn events_flow_through_all_stages_to_bus() {
        let bus = EventBus::<Observation>::new(64);
        let mut rx = bus.subscribe();
        let events = vec![
            Event {
                ts: 1_000,
                pid: 42,
                kind: EventKind::ProcessStart {
                    ppid: 1,
                    exe: "/no/such/curl".into(),
                    cmdline: None,
                },
            },
            Event {
                ts: 1_000,
                pid: 0,
                kind: EventKind::DnsQuery {
                    name: "example.com".into(),
                    answers: vec!["93.184.216.34".parse().unwrap()],
                },
            },
            Event {
                ts: 1_001,
                pid: 42,
                kind: EventKind::NetConnect {
                    remote_ip: "93.184.216.34".parse().unwrap(),
                    remote_port: 443,
                    proto: Proto::Tcp,
                    domain: None,
                    dns_before: false,
                },
            },
        ];
        let p = Pipeline::start(
            vec![Arc::new(Scripted(events))],
            true,
            engine(),
            bus.clone(),
        );
        let start = rx.recv().await.unwrap();
        assert_eq!(start.process.as_ref().unwrap().pid, 42);
        let _dns = rx.recv().await.unwrap();
        let conn = rx.recv().await.unwrap();
        match &conn.event.kind {
            EventKind::NetConnect {
                domain, dns_before, ..
            } => {
                assert_eq!(domain.as_deref(), Some("example.com"));
                assert!(dns_before);
            }
            k => panic!("{k:?}"),
        }
        assert_eq!(
            conn.process.as_ref().unwrap().pid,
            42,
            "connection carries process context"
        );
        assert_eq!(p.shutdown().await, 3);
    }
}
