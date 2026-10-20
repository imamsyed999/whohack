//! Explicit allowlist scope; destination trust affects network tags only.
use std::net::IpAddr;
use whohack_core::{AllowEntry, EventKind, Observation};

fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v) => v.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        _ => ip,
    }
}

pub fn destination_matches(value: &str, ip: IpAddr, domain: Option<&str>) -> bool {
    let ip = canonical_ip(ip);
    let value = value.trim();
    if let Ok(expected) = value.parse::<IpAddr>() {
        return canonical_ip(expected) == ip;
    }
    if let Some((net, prefix)) = value.split_once('/') {
        let (Ok(net), Ok(prefix)) = (net.parse::<IpAddr>(), prefix.parse::<u32>()) else {
            return false;
        };
        return match (net, ip) {
            (IpAddr::V4(n), IpAddr::V4(a)) if prefix <= 32 => {
                let mask = u32::MAX.checked_shl(32 - prefix).unwrap_or(0);
                u32::from(n) & mask == u32::from(a) & mask
            }
            (IpAddr::V6(n), IpAddr::V6(a)) if prefix <= 128 => {
                let mask = u128::MAX.checked_shl(128 - prefix).unwrap_or(0);
                u128::from(n) & mask == u128::from(a) & mask
            }
            _ => false,
        };
    }
    let value = value.trim_end_matches('.').to_ascii_lowercase();
    if value.is_empty() {
        return false;
    }
    domain.is_some_and(|d| {
        let d = d.trim_end_matches('.').to_ascii_lowercase();
        d == value
            || d.strip_suffix(&value)
                .is_some_and(|prefix| prefix.ends_with('.'))
    })
}

pub fn filtered(obs: &Observation, entries: &[AllowEntry]) -> Observation {
    let mut result = obs.clone();
    if entries.iter().any(|e| matches!(e, AllowEntry::App { app_id } if obs.process.as_ref().is_some_and(|p| p.app_id == *app_id))) {
        result.tags.clear(); return result;
    }
    result.tags.retain(|tag| {
        !entries.iter().any(|e| match e {
            AllowEntry::Behavior {
                app_id,
                tag: allowed,
            } => {
                obs.process.as_ref().is_some_and(|p| p.app_id == *app_id) && tag.as_str() == allowed
            }
            AllowEntry::Destination { value } if tag.family() == "network" => match &obs.event.kind
            {
                EventKind::NetConnect {
                    remote_ip, domain, ..
                } => destination_matches(value, *remote_ip, domain.as_deref()),
                _ => false,
            },
            _ => false,
        })
    });
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn domain_and_network_boundaries() {
        let ip = "8.8.8.8".parse().unwrap();
        assert!(destination_matches(
            "example.com",
            ip,
            Some("cdn.EXAMPLE.com.")
        ));
        assert!(!destination_matches(
            "example.com",
            ip,
            Some("evilexample.com")
        ));
        assert!(!destination_matches(
            "example.com",
            ip,
            Some("example.com.evil.test")
        ));
        assert!(destination_matches("8.8.8.0/24", ip, None));
        assert!(!destination_matches("8.8.9.0/24", ip, None));
        assert!(!destination_matches("8.8.8.0/33", ip, None));
        assert!(destination_matches(
            "::/0",
            "2606:4700::1".parse().unwrap(),
            None
        ));
    }
}
