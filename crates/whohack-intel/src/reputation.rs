//! Validated, offline snapshots. The service never contacts a feed or uploads
//! samples. A separate opt-in updater publishes a complete snapshot atomically.
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::File;
use std::net::IpAddr;
use std::path::Path;

const MAX_ENTRIES: usize = 250_000;
const MAX_BYTES: u64 = 48 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Indicator {
    pub value: String,
    pub source: String,
    pub expires_at: i64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    pub version: u32,
    pub fetched_at: i64,
    pub indicators: Vec<Indicator>,
}
#[derive(Debug, Clone)]
pub struct Hit {
    pub source: String,
    pub indicator: String,
}

/// Prefix-indexed maps perform at most 33/129 probes, independent of feed size.
/// IPv4-mapped IPv6 addresses share the IPv4 index.
#[derive(Debug, Default)]
pub struct Reputation {
    ipv4: HashMap<(u128, u8), Indicator>,
    ipv6: HashMap<(u128, u8), Indicator>,
    domains: HashMap<String, Indicator>,
    pub fetched_at: i64,
}
fn mask(value: u128, prefix: u8, bits: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        value & (u128::MAX << (bits - prefix))
    }
}
pub fn domain(value: &str) -> Option<String> {
    let value = value.trim_end_matches('.').to_ascii_lowercase();
    if value.len() > 253 || !value.contains('.') || value.parse::<IpAddr>().is_ok() {
        return None;
    }
    if value.split('.').any(|part| {
        part.is_empty()
            || part.len() > 63
            || part.starts_with('-')
            || part.ends_with('-')
            || !part.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
    }) {
        return None;
    }
    Some(value)
}
impl Reputation {
    pub fn load(path: &Path, now: i64) -> Result<Self> {
        let file = File::open(path)?;
        ensure!(
            file.metadata()?.len() <= MAX_BYTES,
            "threat snapshot exceeds 48 MiB"
        );
        Self::from_snapshot(
            serde_json::from_reader(file).context("invalid threat snapshot JSON")?,
            now,
        )
    }
    pub fn from_snapshot(snapshot: Snapshot, now: i64) -> Result<Self> {
        ensure!(snapshot.version == 1, "unsupported threat snapshot version");
        ensure!(
            snapshot.fetched_at > 0 && snapshot.fetched_at <= now.saturating_add(300_000),
            "invalid snapshot timestamp"
        );
        ensure!(
            snapshot.indicators.len() <= MAX_ENTRIES,
            "too many threat indicators"
        );
        let mut index = Self {
            fetched_at: snapshot.fetched_at,
            ..Default::default()
        };
        for mut item in snapshot.indicators {
            ensure!(
                !item.source.is_empty()
                    && item.source.len() <= 80
                    && item
                        .source
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"._ -".contains(&b)),
                "invalid indicator source"
            );
            ensure!(
                item.expires_at > snapshot.fetched_at
                    && item.expires_at <= snapshot.fetched_at.saturating_add(30 * 86_400_000),
                "indicator expiration must be within 30 days"
            );
            ensure!(item.value.len() <= 253, "indicator too long");
            if item.expires_at <= now {
                continue;
            }
            let (address, prefix) = item
                .value
                .split_once('/')
                .map_or((item.value.as_str(), None), |(a, p)| (a, Some(p)));
            if let Ok(ip) = address.parse::<IpAddr>() {
                let (value, bits) = match ip {
                    IpAddr::V4(v) => (u128::from(u32::from(v)), 32),
                    IpAddr::V6(v) => (u128::from(v), 128),
                };
                let prefix: u8 = prefix.map(str::parse).transpose()?.unwrap_or(bits);
                // A feed may not accidentally block the entire internet.
                ensure!(
                    prefix > 0 && prefix <= bits,
                    "invalid or overly broad IP prefix"
                );
                let key = (mask(value, prefix, bits), prefix);
                if bits == 32 {
                    index.ipv4.insert(key, item);
                } else {
                    index.ipv6.insert(key, item);
                }
            } else {
                let host = domain(&item.value).context("invalid threat domain")?;
                item.value.clone_from(&host);
                index.domains.insert(host, item);
            }
        }
        Ok(index)
    }
    pub fn len(&self) -> usize {
        self.ipv4.len() + self.ipv6.len() + self.domains.len()
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    pub fn lookup(&self, ip: IpAddr, host: Option<&str>, now: i64) -> Option<Hit> {
        let ip = match ip {
            IpAddr::V6(v) => v.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
            _ => ip,
        };
        let (value, bits, index) = match ip {
            IpAddr::V4(v) => (u128::from(u32::from(v)), 32, &self.ipv4),
            IpAddr::V6(v) => (u128::from(v), 128, &self.ipv6),
        };
        for prefix in (1..=bits).rev() {
            if let Some(i) = index.get(&(mask(value, prefix, bits), prefix))
                && i.expires_at > now
            {
                return Some(Hit {
                    source: i.source.clone(),
                    indicator: i.value.clone(),
                });
            }
        }
        let mut host = domain(host?)?;
        loop {
            if let Some(i) = self.domains.get(&host)
                && i.expires_at > now
            {
                return Some(Hit {
                    source: i.source.clone(),
                    indicator: i.value.clone(),
                });
            }
            host = host.split_once('.')?.1.to_owned();
            if !host.contains('.') {
                return None;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn snapshot(values: &[&str]) -> Snapshot {
        Snapshot {
            version: 1,
            fetched_at: 1000,
            indicators: values
                .iter()
                .map(|v| Indicator {
                    value: (*v).into(),
                    source: "test".into(),
                    expires_at: 5000,
                })
                .collect(),
        }
    }
    #[test]
    fn prefixes_domains_mapped_addresses_and_expiration() {
        let r = Reputation::from_snapshot(
            snapshot(&["192.0.2.0/24", "2001:db8::/32", "evil.example"]),
            2000,
        )
        .unwrap();
        for ip in ["192.0.2.3", "::ffff:192.0.2.3", "2001:db8::10"] {
            assert!(r.lookup(ip.parse().unwrap(), None, 2000).is_some());
        }
        assert!(
            r.lookup(
                "127.0.0.1".parse().unwrap(),
                Some("child.EVIL.example."),
                2000
            )
            .is_some()
        );
        assert!(
            r.lookup("127.0.0.1".parse().unwrap(), Some("notevil.example"), 2000)
                .is_none()
        );
        assert!(r.lookup("192.0.2.3".parse().unwrap(), None, 5000).is_none());
    }
    #[test]
    fn rejects_poisoned_updates() {
        for bad in [
            "0.0.0.0/0",
            "192.0.2.1/33",
            "https://evil.example/x",
            "bad\n.example",
            "evil..example",
            "*.example",
        ] {
            assert!(
                Reputation::from_snapshot(snapshot(&[bad]), 2000).is_err(),
                "{bad}"
            );
        }
    }
}
