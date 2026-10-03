//! Pipeline normalizer stage: maintains the DNS cache from `DnsQuery` events
//! and attributes `NetConnect` events to domains.
//!
//! DNS answers and connections usually come from different collectors, so a
//! connection can reach the enricher a few milliseconds *before* the answer
//! that explains it. While DNS visibility is on, an unresolved connection is
//! held for up to `grace_ms` and released as soon as a matching answer
//! arrives (or when the grace period ends, as a genuine raw-IP connection).

use std::collections::VecDeque;
use std::net::IpAddr;

use vigil_core::{Event, EventKind};

use crate::DnsCache;

/// Default time an unresolved connection waits for a late DNS answer.
pub const DEFAULT_GRACE_MS: i64 = 500;
/// Timestamp skew tolerated between the DNS and connection collectors.
pub const CLOCK_SKEW_MS: i64 = 2_000;
/// Upper bound on held connections; beyond it the oldest is released.
const MAX_PENDING: usize = 10_000;

#[derive(Debug)]
pub struct Enricher {
    cache: DnsCache,
    grace_ms: i64,
    /// (release deadline in local ms, event)
    pending: VecDeque<(i64, Event)>,
}

impl Enricher {
    pub fn new(cache: DnsCache, grace_ms: i64) -> Self {
        Enricher {
            cache,
            grace_ms,
            pending: VecDeque::new(),
        }
    }

    pub fn cache(&self) -> &DnsCache {
        &self.cache
    }

    pub fn set_dns_visible(&mut self, visible: bool) {
        self.cache.set_visible(visible);
    }

    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }

    /// Processes one event at local time `now_ms`; returns the events now
    /// ready to continue down the pipeline, in arrival order.
    pub fn process(&mut self, mut ev: Event, now_ms: i64) -> Vec<Event> {
        let mut out = Vec::new();
        match &ev.kind {
            EventKind::DnsQuery { name, answers } => {
                self.cache.record(name, answers, ev.ts);
                let answers = answers.clone();
                out.push(ev);
                self.release_matching(&answers, &mut out);
            }
            EventKind::NetConnect { .. } => {
                if self.attribute(&mut ev) || !self.cache.is_visible() || self.grace_ms <= 0 {
                    out.push(ev);
                } else {
                    if self.pending.len() >= MAX_PENDING
                        && let Some((_, old)) = self.pending.pop_front()
                    {
                        out.push(old);
                    }
                    self.pending.push_back((now_ms + self.grace_ms, ev));
                }
            }
            _ => out.push(ev),
        }
        out
    }

    /// Releases held connections whose grace period has ended (unresolved,
    /// so `dns_before` stays false).
    pub fn tick(&mut self, now_ms: i64) -> Vec<Event> {
        let mut out = Vec::new();
        while let Some((deadline, _)) = self.pending.front() {
            if *deadline > now_ms {
                break;
            }
            if let Some((_, ev)) = self.pending.pop_front() {
                out.push(ev);
            }
        }
        out
    }

    /// Releases every held event (shutdown).
    pub fn drain(&mut self) -> Vec<Event> {
        self.pending.drain(..).map(|(_, e)| e).collect()
    }

    /// Fills `domain`/`dns_before` from the cache. Returns true if resolved.
    fn attribute(&mut self, ev: &mut Event) -> bool {
        let ts = ev.ts;
        if let EventKind::NetConnect {
            remote_ip,
            domain,
            dns_before,
            ..
        } = &mut ev.kind
            && let Some(d) = self.cache.lookup(*remote_ip, ts, CLOCK_SKEW_MS)
        {
            if domain.is_none() {
                *domain = Some(d.to_string());
            }
            *dns_before = true;
            return true;
        }
        false
    }

    fn release_matching(&mut self, answers: &[IpAddr], out: &mut Vec<Event>) {
        if self.pending.is_empty() || answers.is_empty() {
            return;
        }
        let mut keep = VecDeque::with_capacity(self.pending.len());
        while let Some((deadline, mut ev)) = self.pending.pop_front() {
            let matches = matches!(&ev.kind, EventKind::NetConnect { remote_ip, .. } if answers.contains(remote_ip));
            if matches && self.attribute(&mut ev) {
                out.push(ev);
            } else {
                keep.push_back((deadline, ev));
            }
        }
        self.pending = keep;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vigil_core::Proto;

    fn connect(ts: i64, ip: &str) -> Event {
        Event {
            ts,
            pid: 42,
            kind: EventKind::NetConnect {
                remote_ip: ip.parse().unwrap(),
                remote_port: 443,
                proto: Proto::Tcp,
                domain: None,
                dns_before: false,
            },
        }
    }

    fn dns(ts: i64, name: &str, ip: &str) -> Event {
        Event {
            ts,
            pid: 7,
            kind: EventKind::DnsQuery {
                name: name.into(),
                answers: vec![ip.parse().unwrap()],
            },
        }
    }

    fn net_fields(ev: &Event) -> (Option<String>, bool) {
        match &ev.kind {
            EventKind::NetConnect {
                domain, dns_before, ..
            } => (domain.clone(), *dns_before),
            other => panic!("not a connect: {other:?}"),
        }
    }

    fn enricher() -> Enricher {
        let mut e = Enricher::new(DnsCache::default(), DEFAULT_GRACE_MS);
        e.set_dns_visible(true);
        e
    }

    #[test]
    fn dns_then_connect_is_attributed() {
        let mut e = enricher();
        assert_eq!(
            e.process(dns(1_000, "Example.com", "203.0.113.7"), 0).len(),
            1
        );
        let out = e.process(connect(1_010, "203.0.113.7"), 0);
        assert_eq!(out.len(), 1);
        assert_eq!(net_fields(&out[0]), (Some("example.com".into()), true));
    }

    #[test]
    fn connect_before_late_dns_is_held_then_attributed() {
        let mut e = enricher();
        assert!(e.process(connect(1_000, "203.0.113.7"), 0).is_empty());
        assert_eq!(e.pending_len(), 1);
        let out = e.process(dns(1_002, "example.com", "203.0.113.7"), 10);
        assert_eq!(out.len(), 2, "dns event + released connect");
        assert_eq!(net_fields(&out[1]), (Some("example.com".into()), true));
        assert_eq!(e.pending_len(), 0);
    }

    #[test]
    fn unresolved_connect_released_after_grace_as_raw_ip() {
        let mut e = enricher();
        assert!(e.process(connect(1_000, "198.51.100.9"), 0).is_empty());
        assert!(e.tick(DEFAULT_GRACE_MS - 1).is_empty());
        let out = e.tick(DEFAULT_GRACE_MS);
        assert_eq!(out.len(), 1);
        assert_eq!(net_fields(&out[0]), (None, false));
    }

    #[test]
    fn without_dns_visibility_connects_pass_through_immediately() {
        let mut e = Enricher::new(DnsCache::default(), DEFAULT_GRACE_MS);
        let out = e.process(connect(1_000, "198.51.100.9"), 0);
        assert_eq!(out.len(), 1);
        assert_eq!(net_fields(&out[0]), (None, false));
    }

    #[test]
    fn collector_supplied_domain_is_kept() {
        let mut e = enricher();
        e.process(dns(1_000, "cdn.example", "203.0.113.7"), 0);
        let mut ev = connect(1_001, "203.0.113.7");
        if let EventKind::NetConnect { domain, .. } = &mut ev.kind {
            *domain = Some("app.example".into());
        }
        let out = e.process(ev, 0);
        assert_eq!(net_fields(&out[0]), (Some("app.example".into()), true));
    }

    #[test]
    fn other_events_pass_through_and_drain_releases_all() {
        let mut e = enricher();
        let start = Event {
            ts: 1,
            pid: 1,
            kind: EventKind::ProcessExit,
        };
        assert_eq!(e.process(start.clone(), 0), vec![start]);
        e.process(connect(1_000, "198.51.100.9"), 0);
        e.process(connect(1_001, "198.51.100.10"), 0);
        assert_eq!(e.drain().len(), 2);
        assert_eq!(e.pending_len(), 0);
    }
}
