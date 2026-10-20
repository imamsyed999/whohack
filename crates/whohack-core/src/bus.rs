//! In-process event bus.
//!
//! Collectors send `Event`s on a bounded `mpsc` channel (the shape required by
//! the `Collector` trait, SPEC §8). A single ingest task forwards each event,
//! wrapped in `Arc`, to every subscriber over a `broadcast` channel. A slow
//! subscriber lags (and is told how many events it missed) instead of
//! back-pressuring collectors or other subscribers.

use std::sync::Arc;

use tokio::sync::{broadcast, mpsc};
use tokio::task::JoinHandle;

use crate::types::Event;

/// Broadcast bus. Generic over the message type: raw collectors use
/// `EventBus<Event>`; the service publishes enriched `Observation`s.
#[derive(Debug)]
pub struct EventBus<T = Event> {
    tx: broadcast::Sender<Arc<T>>,
}

impl<T> Clone for EventBus<T> {
    fn clone(&self) -> Self {
        EventBus {
            tx: self.tx.clone(),
        }
    }
}

impl<T: Send + Sync + 'static> EventBus<T> {
    /// `capacity` is the per-subscriber backlog before it starts lagging.
    ///
    /// # Panics
    /// If `capacity` is 0 (a tokio `broadcast` requirement).
    pub fn new(capacity: usize) -> Self {
        let (tx, _) = broadcast::channel(capacity);
        EventBus { tx }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Arc<T>> {
        self.tx.subscribe()
    }

    pub fn subscriber_count(&self) -> usize {
        self.tx.receiver_count()
    }

    /// Broadcasts one message to all current subscribers. With no
    /// subscribers the message is dropped.
    pub fn publish(&self, msg: T) {
        let _ = self.tx.send(Arc::new(msg));
    }

    /// Starts the ingest task. Returns the sender to hand to producers (clone
    /// it per producer) and a handle that resolves to the number of messages
    /// forwarded once every sender has been dropped.
    ///
    /// Must be called within a tokio runtime.
    pub fn spawn_ingest(&self, buffer: usize) -> (mpsc::Sender<T>, JoinHandle<u64>) {
        let (in_tx, mut in_rx) = mpsc::channel::<T>(buffer);
        let out = self.tx.clone();
        let handle = tokio::spawn(async move {
            let mut forwarded = 0u64;
            while let Some(msg) = in_rx.recv().await {
                // An Err only means there are no subscribers right now; the
                // message is intentionally dropped in that case.
                let _ = out.send(Arc::new(msg));
                forwarded += 1;
            }
            tracing::debug!(forwarded, "event bus ingest finished");
            forwarded
        });
        (in_tx, handle)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::EventKind;
    use tokio::sync::broadcast::error::{RecvError, TryRecvError};

    fn ev(i: u32) -> Event {
        Event {
            ts: i64::from(i),
            pid: i,
            kind: EventKind::ProcessExit,
        }
    }

    #[tokio::test]
    async fn every_subscriber_gets_every_event_in_order() {
        let bus = EventBus::<Event>::new(64);
        let mut a = bus.subscribe();
        let mut b = bus.subscribe();
        assert_eq!(bus.subscriber_count(), 2);
        let (tx, ingest) = bus.spawn_ingest(16);
        for i in 0..10 {
            tx.send(ev(i)).await.unwrap();
        }
        drop(tx);
        assert_eq!(ingest.await.unwrap(), 10);
        for rx in [&mut a, &mut b] {
            for i in 0..10 {
                assert_eq!(rx.recv().await.unwrap().pid, i);
            }
            // The bus itself still holds a sender, so the channel is empty, not closed.
            assert!(matches!(rx.try_recv(), Err(TryRecvError::Empty)));
        }
    }

    #[tokio::test]
    async fn publish_reaches_subscribers() {
        let bus = EventBus::<Event>::new(8);
        bus.publish(ev(0)); // no subscribers yet: dropped, no panic
        let mut rx = bus.subscribe();
        bus.publish(ev(7));
        assert_eq!(rx.recv().await.unwrap().pid, 7);
    }

    #[tokio::test]
    async fn ingest_ends_when_all_senders_drop() {
        let bus = EventBus::<Event>::new(4);
        let (tx, ingest) = bus.spawn_ingest(4);
        let tx2 = tx.clone();
        tx.send(ev(1)).await.unwrap();
        tx2.send(ev(2)).await.unwrap();
        drop(tx);
        drop(tx2);
        // No subscribers: events are counted and dropped, not an error.
        assert_eq!(ingest.await.unwrap(), 2);
    }

    #[tokio::test]
    async fn slow_subscriber_lags_without_blocking_others() {
        let bus = EventBus::<Event>::new(4);
        let mut slow = bus.subscribe();
        let mut fast = bus.subscribe();
        let (tx, ingest) = bus.spawn_ingest(64);
        // Reads until it has seen the final event; it may lag if scheduled late,
        // but the last event always stays in the ring buffer.
        let reader = tokio::spawn(async move {
            let mut got = Vec::new();
            loop {
                match fast.recv().await {
                    Ok(e) => {
                        got.push(e.pid);
                        if e.pid == 19 {
                            break;
                        }
                    }
                    Err(RecvError::Lagged(_)) => continue,
                    Err(RecvError::Closed) => break,
                }
            }
            got
        });
        for i in 0..20 {
            tx.send(ev(i)).await.unwrap();
            tokio::task::yield_now().await;
        }
        drop(tx);
        assert_eq!(ingest.await.unwrap(), 20);
        let got = reader.await.unwrap();
        assert_eq!(got.last(), Some(&19));
        // The slow subscriber never read; it must report lag, then the newest events.
        match slow.recv().await {
            Err(RecvError::Lagged(n)) => assert_eq!(n, 16),
            other => panic!("expected Lagged, got {other:?}"),
        }
        assert_eq!(slow.recv().await.unwrap().pid, 16);
    }
}
