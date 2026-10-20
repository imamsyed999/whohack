//! Bounded recent destination history. Eviction/restart makes a destination first-seen
//! again; this signal alone is never evidence of malicious activity.
use std::collections::VecDeque;
use std::net::IpAddr;
use std::num::NonZeroUsize;

use lru::LruCache;
use whohack_core::{CapabilityTag, EventKind, Observation, Proto};

type Destination = (String, IpAddr, u16, Proto);

#[derive(Debug)]
pub struct NetworkTags {
    dns_visible: bool,
    history: LruCache<Destination, VecDeque<i64>>,
}

impl NetworkTags {
    pub fn new(dns_visible: bool) -> Self {
        Self {
            dns_visible,
            history: LruCache::new(NonZeroUsize::new(16_384).unwrap()),
        }
    }

    pub fn tag(&mut self, obs: &mut Observation) {
        let EventKind::NetConnect {
            remote_ip,
            remote_port,
            proto,
            dns_before,
            ..
        } = obs.event.kind
        else {
            return;
        };
        let Some(p) = &obs.process else { return };
        let key = (p.app_id.clone(), remote_ip, remote_port, proto);
        if !self.history.contains(&key) {
            obs.tags
                .push(CapabilityTag::from_static("network:first_seen_destination"));
            self.history.put(key.clone(), VecDeque::with_capacity(8));
        }
        if !matches!(remote_port, 53 | 80 | 123 | 443 | 853) {
            obs.tags
                .push(CapabilityTag::from_static("network:unusual_port"));
        }
        if self.dns_visible && !dns_before && is_public(remote_ip) {
            obs.tags
                .push(CapabilityTag::from_static("network:raw_ip_no_dns"));
        }
        let times = self
            .history
            .get_mut(&key)
            .expect("just inserted destination");
        if times.back().is_some_and(|last| obs.event.ts <= *last) {
            return; // duplicate or reordered event: never manufacture intervals
        }
        if times
            .back()
            .is_some_and(|last| obs.event.ts.saturating_sub(*last) > 3_600_000)
        {
            times.clear();
        }
        if times.len() == 8 {
            times.pop_front();
        }
        times.push_back(obs.event.ts);
        if regular(times) {
            obs.tags
                .push(CapabilityTag::from_static("network:beaconing"));
        }
    }
}

fn regular(times: &VecDeque<i64>) -> bool {
    if times.len() < 4 {
        return false;
    }
    let intervals: Vec<f64> = times
        .iter()
        .zip(times.iter().skip(1))
        .map(|(a, b)| b.saturating_sub(*a) as f64)
        .collect();
    let mean = intervals.iter().sum::<f64>() / intervals.len() as f64;
    if !(5_000.0..=3_600_000.0).contains(&mean) {
        return false;
    }
    let variance =
        intervals.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / intervals.len() as f64;
    variance.sqrt() / mean <= 0.2
}

/// Conservative public-address test (including IPv4 mapped into IPv6).
pub fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => {
            let [a, b, c, _] = v.octets();
            !(v.is_private()
                || v.is_loopback()
                || v.is_link_local()
                || v.is_broadcast()
                || v.is_documentation()
                || v.is_unspecified()
                || v.is_multicast()
                || a == 0
                || a >= 240
                || (a == 100 && (64..=127).contains(&b))
                || (a == 198 && matches!(b, 18 | 19))
                || (a == 192 && b == 0 && c == 0))
        }
        IpAddr::V6(v) => {
            if let Some(v4) = v.to_ipv4_mapped() {
                return is_public(IpAddr::V4(v4));
            }
            let s = v.segments();
            // Only global-unicast space; exclude documentation and special-use 2001::/23.
            s[0] & 0xe000 == 0x2000
                && !(s[0] == 0x2001 && (s[1] <= 0x01ff || s[1] == 0x0db8))
                && !(s[0] == 0x3fff && s[1] <= 0x0fff)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn interval_thresholds_and_jitter() {
        assert!(regular(&VecDeque::from([0, 60_000, 120_000, 180_000])));
        assert!(!regular(&VecDeque::from([0, 60_000, 120_000])));
        assert!(!regular(&VecDeque::from([0, 60_000, 65_000, 180_000])));
        assert!(!regular(&VecDeque::from([0, 1_000, 2_000, 3_000])));
    }
    #[test]
    fn excludes_local_shared_reserved_and_documentation() {
        for ip in [
            "127.0.0.1",
            "10.1.2.3",
            "100.64.0.1",
            "169.254.1.2",
            "192.0.2.1",
            "198.19.0.1",
            "255.255.255.255",
            "::1",
            "::ffff:192.168.1.1",
            "fe80::1",
            "fc00::1",
            "2001:db8::1",
        ] {
            assert!(!is_public(ip.parse().unwrap()), "{ip}");
        }
        for ip in [
            "8.8.8.8",
            "1.1.1.1",
            "2606:4700:4700::1111",
            "::ffff:8.8.8.8",
        ] {
            assert!(is_public(ip.parse().unwrap()), "{ip}");
        }
    }
}
