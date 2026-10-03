//! Bounded IP → domain cache built from observed DNS answers.

use std::net::IpAddr;
use std::num::NonZeroUsize;

use lru::LruCache;

/// How long an answer is trusted for attribution. Applications reuse resolved
/// addresses well past the DNS TTL (connection pools, HTTP keep-alive), so
/// this is deliberately generous.
pub const DEFAULT_TTL_MS: i64 = 6 * 60 * 60 * 1000;

/// Default maximum number of IPs tracked.
pub const DEFAULT_CAPACITY: usize = 65_536;

#[derive(Debug, Clone, PartialEq, Eq)]
struct Entry {
    domain: String,
    seen: i64,
}

#[derive(Debug)]
pub struct DnsCache {
    map: LruCache<IpAddr, Entry>,
    ttl_ms: i64,
    visible: bool,
}

impl Default for DnsCache {
    fn default() -> Self {
        DnsCache::new(DEFAULT_CAPACITY, DEFAULT_TTL_MS)
    }
}

/// Normalizes a DNS name: lowercase, no trailing dot.
pub fn normalize_name(name: &str) -> String {
    name.trim_end_matches('.').to_ascii_lowercase()
}

impl DnsCache {
    /// # Panics
    /// If `capacity` is 0.
    pub fn new(capacity: usize, ttl_ms: i64) -> Self {
        let cap = NonZeroUsize::new(capacity).expect("DnsCache capacity must be > 0");
        DnsCache {
            map: LruCache::new(cap),
            ttl_ms,
            visible: false,
        }
    }

    /// Whether a DNS visibility source is active. When false, a cache miss
    /// means "unknown", not "no DNS lookup happened", and callers must not
    /// treat raw-IP connections as suspicious on that basis.
    pub fn is_visible(&self) -> bool {
        self.visible
    }

    pub fn set_visible(&mut self, visible: bool) {
        self.visible = visible;
    }

    /// Records that `name` resolved to `answers` at `ts` (Unix ms).
    pub fn record(&mut self, name: &str, answers: &[IpAddr], ts: i64) {
        let domain = normalize_name(name);
        if domain.is_empty() {
            return;
        }
        for ip in answers {
            self.map.put(
                *ip,
                Entry {
                    domain: domain.clone(),
                    seen: ts,
                },
            );
        }
    }

    /// The domain most recently resolved to `ip` no later than `at_ms + skew_ms`
    /// and not older than the TTL. `skew_ms` tolerates small timestamp
    /// differences between independent collectors.
    pub fn lookup(&mut self, ip: IpAddr, at_ms: i64, skew_ms: i64) -> Option<&str> {
        let ttl = self.ttl_ms;
        match self.map.get(&ip) {
            Some(e) if e.seen <= at_ms + skew_ms && at_ms - e.seen <= ttl => Some(&e.domain),
            _ => None,
        }
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn record_and_lookup() {
        let mut c = DnsCache::default();
        c.record(
            "Example.COM.",
            &[ip("203.0.113.7"), ip("2001:db8::1")],
            1_000,
        );
        assert_eq!(c.lookup(ip("203.0.113.7"), 2_000, 0), Some("example.com"));
        assert_eq!(c.lookup(ip("2001:db8::1"), 2_000, 0), Some("example.com"));
        assert_eq!(c.lookup(ip("198.51.100.1"), 2_000, 0), None);
        assert_eq!(c.len(), 2);
    }

    #[test]
    fn answer_after_connect_needs_skew() {
        let mut c = DnsCache::default();
        c.record("example.com", &[ip("203.0.113.7")], 1_050);
        assert_eq!(c.lookup(ip("203.0.113.7"), 1_000, 0), None);
        assert_eq!(c.lookup(ip("203.0.113.7"), 1_000, 100), Some("example.com"));
    }

    #[test]
    fn expires_after_ttl() {
        let mut c = DnsCache::new(16, 10_000);
        c.record("example.com", &[ip("203.0.113.7")], 0);
        assert!(c.lookup(ip("203.0.113.7"), 10_000, 0).is_some());
        assert!(c.lookup(ip("203.0.113.7"), 10_001, 0).is_none());
    }

    #[test]
    fn newest_answer_wins() {
        let mut c = DnsCache::default();
        c.record("a.example", &[ip("203.0.113.7")], 0);
        c.record("b.example", &[ip("203.0.113.7")], 5);
        assert_eq!(c.lookup(ip("203.0.113.7"), 10, 0), Some("b.example"));
    }

    #[test]
    fn capacity_is_bounded() {
        let mut c = DnsCache::new(2, DEFAULT_TTL_MS);
        c.record("a", &[ip("10.0.0.1")], 0);
        c.record("b", &[ip("10.0.0.2")], 0);
        c.record("c", &[ip("10.0.0.3")], 0);
        assert_eq!(c.len(), 2);
        assert!(c.lookup(ip("10.0.0.1"), 0, 0).is_none());
    }

    #[test]
    fn ignores_empty_names_and_tracks_visibility() {
        let mut c = DnsCache::default();
        c.record(".", &[ip("10.0.0.1")], 0);
        assert!(c.is_empty());
        assert!(!c.is_visible());
        c.set_visible(true);
        assert!(c.is_visible());
    }
}
