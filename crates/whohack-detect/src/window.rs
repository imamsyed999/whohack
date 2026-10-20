//! Versioned, bounded 60-second feature windows. PID reuse and executable
//! changes start a fresh window. Late events cannot resurrect expired evidence.
use lru::LruCache;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::num::NonZeroUsize;
use std::sync::Arc;
use whohack_core::{CapabilityTag, EventKind, Observation, ProcessInfo, SensitiveClass, SignState};
use whohack_tags::{
    Profile,
    taxonomy::{TAGS, lookup},
};

pub const WINDOW_MS: i64 = 60_000;
const MAX_PROCESSES: usize = 1024;
const MAX_SAMPLES: usize = 2048;
const MAX_TOTAL_SAMPLES: usize = 65_536;
pub const FEATURE_NAMES: [&str; 17] = [
    "new_destinations",
    "raw_ip_connections",
    "distinct_ports",
    "child_processes",
    "sensitive_accesses",
    "persistence_writes",
    "bytes_up",
    "bytes_down",
    "upload_download_ratio",
    "interval_cv",
    "unexpected_severity",
    "tainted",
    "unsigned",
    "path_class",
    "signature_class",
    "byte_visibility",
    "window_saturated",
];

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Features {
    #[serde(default)]
    pub tag_counts: Vec<(CapabilityTag, u32)>,
    #[serde(default)]
    pub destinations: u32,
    #[serde(default)]
    pub ports: Vec<u16>,
    #[serde(default)]
    pub mean_interval_s: Option<f32>,
    pub schema_version: u32,
    pub new_destinations: u32,
    pub raw_ip_connections: u32,
    pub distinct_ports: u32,
    pub child_processes: u32,
    pub sensitive_accesses: u32,
    pub persistence_writes: u32,
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub upload_download_ratio: f32,
    pub interval_cv: Option<f32>,
    pub unexpected_severity: u32,
    pub tainted: bool,
    pub unsigned: bool,
    pub path_class: u8,
    pub signature_class: u8,
    pub byte_visibility: bool,
    pub window_saturated: bool,
    pub tags: Vec<CapabilityTag>,
    pub unexpected: Vec<CapabilityTag>,
}
impl Features {
    pub fn vector(&self) -> [f32; 17] {
        [
            self.new_destinations as f32,
            self.raw_ip_connections as f32,
            self.distinct_ports as f32,
            self.child_processes as f32,
            self.sensitive_accesses as f32,
            self.persistence_writes as f32,
            self.bytes_up as f32,
            self.bytes_down as f32,
            self.upload_download_ratio,
            self.interval_cv.unwrap_or(-1.),
            self.unexpected_severity as f32,
            u8::from(self.tainted) as f32,
            u8::from(self.unsigned) as f32,
            self.path_class as f32,
            self.signature_class as f32,
            u8::from(self.byte_visibility) as f32,
            u8::from(self.window_saturated) as f32,
        ]
    }
    pub fn heuristic(&self) -> f32 {
        (self.unexpected_severity as f32 / 6.
            + if self.tainted { 0.2 } else { 0. }
            + if self.unsigned { 0.2 } else { 0. })
        .clamp(0., 1.)
    }
}
#[derive(Debug, Default)]
struct Sample {
    ts: i64,
    tags: u64,
    destination: Option<(IpAddr, u16)>,
    new: bool,
    raw: bool,
    child: Option<(u32, i64)>,
    sensitive: bool,
    persistence: bool,
    bytes: Option<(u64, u64)>,
}
#[derive(Debug)]
struct Window {
    process: Arc<ProcessInfo>,
    latest: i64,
    saturated_until: i64,
    samples: VecDeque<Sample>,
}
#[derive(Debug)]
pub struct Windows {
    windows: LruCache<(u32, i64), Window>,
    pids: HashMap<u32, i64>,
    total: usize,
    pressure_until: i64,
}
impl Default for Windows {
    fn default() -> Self {
        Self {
            windows: LruCache::new(NonZeroUsize::new(MAX_PROCESSES).unwrap()),
            pids: HashMap::new(),
            total: 0,
            pressure_until: 0,
        }
    }
}
impl Windows {
    pub fn observe(&mut self, obs: &Observation, profile: &Profile) -> Features {
        let Some(p) = &obs.process else {
            return Features::default();
        };
        if let EventKind::ProcessStart { ppid, .. } = obs.event.kind
            && let Some(start) = self.pids.get(&ppid).copied()
            && let Some(parent) = self.windows.get_mut(&(ppid, start))
            && start <= p.start_time
        {
            let before = parent.samples.len();
            push(
                parent,
                Sample {
                    ts: obs.event.ts,
                    child: Some((p.pid, p.start_time)),
                    ..Default::default()
                },
            );
            self.total = self.total.saturating_sub(before) + parent.samples.len();
        }
        let key = (p.pid, p.start_time);
        if self.windows.peek(&key).is_some_and(|w| {
            w.process.exe.sha256 != p.exe.sha256
                || w.process.script.as_ref().map(|s| s.sha256)
                    != p.script.as_ref().map(|s| s.sha256)
        }) && let Some(old) = self.windows.pop(&key)
        {
            self.total = self.total.saturating_sub(old.samples.len());
        }
        while self.total >= MAX_TOTAL_SAMPLES
            || (!self.windows.contains(&key) && self.windows.len() >= MAX_PROCESSES)
        {
            if let Some(((pid, start), old)) = self.windows.pop_lru() {
                self.pressure_until = self
                    .pressure_until
                    .max(obs.event.ts.saturating_add(WINDOW_MS));
                self.total = self.total.saturating_sub(old.samples.len());
                if self.pids.get(&pid) == Some(&start) {
                    self.pids.remove(&pid);
                }
            } else {
                break;
            }
        }
        if !self.windows.contains(&key) {
            self.windows.put(
                key,
                Window {
                    process: p.clone(),
                    latest: obs.event.ts,
                    saturated_until: 0,
                    samples: VecDeque::new(),
                },
            );
        }
        self.pids
            .entry(p.pid)
            .and_modify(|start| *start = (*start).max(p.start_time))
            .or_insert(p.start_time);
        let w = self.windows.get_mut(&key).expect("window inserted");
        w.process = p.clone();
        let mut sample = Sample {
            ts: obs.event.ts,
            ..Default::default()
        };
        for t in &obs.tags {
            if let Some(i) = TAGS.iter().position(|d| d.tag == t.as_str()) {
                sample.tags |= 1u64 << i;
            }
        }
        sample.new = obs
            .tags
            .iter()
            .any(|t| t.as_str() == "network:first_seen_destination");
        sample.raw = obs
            .tags
            .iter()
            .any(|t| t.as_str() == "network:raw_ip_no_dns");
        match obs.event.kind {
            EventKind::NetConnect {
                remote_ip,
                remote_port,
                ..
            } => sample.destination = Some((remote_ip, remote_port)),
            EventKind::NetStats {
                bytes_up,
                bytes_down,
                ..
            } => sample.bytes = Some((bytes_up, bytes_down)),
            EventKind::FileAccess { class, .. } => {
                sample.sensitive =
                    !matches!(class, SensitiveClass::Documents | SensitiveClass::Other)
            }
            EventKind::Persistence { .. } => sample.persistence = true,
            _ => {}
        }
        sample.persistence |= obs
            .tags
            .iter()
            .any(|t| t.as_str().starts_with("persistence:"));
        sample.sensitive |= obs
            .tags
            .iter()
            .any(|t| t.as_str().starts_with("credential_access:"));
        let before = w.samples.len();
        push(w, sample);
        self.total = self.total.saturating_sub(before) + w.samples.len();
        let mut features = summarize(w, profile);
        features.window_saturated |= self.pressure_until > 0 && self.pressure_until >= obs.event.ts;
        features
    }
    pub fn process(&self, pid: u32) -> Option<&ProcessInfo> {
        self.pids
            .get(&pid)
            .and_then(|start| self.windows.peek(&(pid, *start)))
            .map(|w| w.process.as_ref())
    }
}
fn push(w: &mut Window, sample: Sample) {
    w.latest = w.latest.max(sample.ts);
    let earliest = w.latest.saturating_sub(WINDOW_MS);
    w.samples.retain(|s| s.ts >= earliest);
    if sample.ts < earliest {
        return;
    }
    if w.samples.len() >= MAX_SAMPLES {
        w.samples.pop_front();
        w.saturated_until = w.latest.saturating_add(WINDOW_MS);
    }
    w.samples.push_back(sample);
}
fn summarize(w: &Window, profile: &Profile) -> Features {
    let file = w.process.script.as_ref().unwrap_or(&w.process.exe);
    let mut f = Features {
        schema_version: 1,
        tainted: w.process.tainted,
        unsigned: matches!(file.sign, SignState::Unsigned),
        path_class: whohack_core::PathClass::ALL
            .iter()
            .position(|c| *c == w.process.path_class)
            .unwrap_or(5) as u8,
        signature_class: match file.sign {
            SignState::ValidTrusted { .. } => 0,
            SignState::ValidUntrusted => 1,
            SignState::Invalid => 2,
            SignState::Unsigned => 3,
        },
        window_saturated: w.saturated_until >= w.latest && w.saturated_until > 0,
        ..Default::default()
    };
    let mut tags = 0u64;
    let mut ports = BTreeSet::new();
    let mut new = HashSet::new();
    let mut destinations = HashSet::new();
    let mut tag_counts = [0u32; TAGS.len()];
    let mut times = Vec::new();
    let mut children = HashSet::new();
    for s in &w.samples {
        tags |= s.tags;
        let mut bits = s.tags;
        while bits != 0 {
            tag_counts[bits.trailing_zeros() as usize] += 1;
            bits &= bits - 1;
        }
        if let Some(d) = s.destination {
            destinations.insert(d);
            ports.insert(d.1);
            if s.new {
                new.insert(d);
            }
            times.push(s.ts);
        }
        f.raw_ip_connections += u32::from(s.raw);
        if let Some(child) = s.child {
            children.insert(child);
        }
        f.sensitive_accesses += u32::from(s.sensitive);
        f.persistence_writes += u32::from(s.persistence);
        if let Some((up, down)) = s.bytes {
            f.byte_visibility = true;
            f.bytes_up = f.bytes_up.saturating_add(up);
            f.bytes_down = f.bytes_down.saturating_add(down);
        }
    }
    f.new_destinations = new.len() as u32;
    f.destinations = destinations.len() as u32;
    f.child_processes = children.len() as u32;
    f.distinct_ports = ports.len() as u32;
    f.ports = ports.into_iter().take(32).collect();
    f.upload_download_ratio =
        (f.bytes_up as f64 / f.bytes_down.max(1) as f64).min(1_000_000.) as f32;
    times.sort_unstable();
    times.dedup();
    if times.len() >= 4 {
        let intervals: Vec<f64> = times
            .windows(2)
            .map(|p| p[1].saturating_sub(p[0]) as f64)
            .collect();
        let mean = intervals.iter().sum::<f64>() / intervals.len() as f64;
        if mean > 0. {
            f.mean_interval_s = Some((mean / 1000.) as f32);
            f.interval_cv = Some(
                (intervals.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / intervals.len() as f64)
                    .sqrt() as f32
                    / mean as f32,
            );
        }
    }
    f.tags = TAGS
        .iter()
        .enumerate()
        .filter(|(i, _)| tags & (1u64 << i) != 0)
        .map(|(_, d)| CapabilityTag::from_static(d.tag))
        .collect();
    f.unexpected = profile.unexpected(&f.tags);
    f.tag_counts = TAGS
        .iter()
        .zip(tag_counts)
        .filter(|(_, count)| *count > 0)
        .map(|(d, count)| (CapabilityTag::from_static(d.tag), count))
        .collect();
    f.unexpected_severity = f
        .unexpected
        .iter()
        .filter_map(|t| lookup(t.as_str()))
        .map(|d| u32::from(d.severity))
        .sum();
    f
}

#[cfg(test)]
mod tests {
    use super::*;
    use whohack_core::{Event, FileInfo, Origin, PathClass, Proto};
    fn obs(ts: i64, start: i64) -> Observation {
        Observation {
            event: Event {
                ts,
                pid: 42,
                kind: EventKind::NetConnect {
                    remote_ip: "192.0.2.1".parse().unwrap(),
                    remote_port: 443,
                    proto: Proto::Tcp,
                    domain: None,
                    dns_before: false,
                },
            },
            process: Some(Arc::new(ProcessInfo {
                downloaded_inputs: Vec::new(),
                pid: 42,
                ppid: 1,
                start_time: start,
                exe: FileInfo {
                    path: "app".into(),
                    sha256: [1; 32],
                    origin: Origin::Unknown,
                    sign: SignState::Unsigned,
                    yara_hits: vec![],
                    first_seen: 0,
                },
                script: None,
                path_class: PathClass::Downloads,
                tainted: true,
                taint_root: None,
                app_id: "app".into(),
            })),
            tags: vec![CapabilityTag::from_static("network:raw_ip_no_dns")],
        }
    }
    fn profile() -> Profile {
        Profile::from_template(
            whohack_tags::CategoryTemplate::builtin("other").unwrap(),
            None,
        )
    }
    #[test]
    fn expiration_reordering_pid_reuse_and_missing_bytes() {
        let mut w = Windows::default();
        let p = profile();
        w.observe(&obs(1, 1), &p);
        let f = w.observe(&obs(10_000, 1), &p);
        assert_eq!(f.raw_ip_connections, 2);
        assert!(!f.byte_visibility);
        let f = w.observe(&obs(70_001, 1), &p);
        assert_eq!(f.raw_ip_connections, 1);
        let f = w.observe(&obs(1, 1), &p);
        assert_eq!(f.raw_ip_connections, 1);
        let f = w.observe(&obs(70_002, 2), &p);
        assert_eq!(f.raw_ip_connections, 1);
        let mut e = obs(70_003, 2);
        e.event.kind = EventKind::NetStats {
            bytes_up: 100,
            bytes_down: 25,
        };
        let f = w.observe(&e, &p);
        assert!(f.byte_visibility);
        assert_eq!(f.upload_download_ratio, 4.);
        assert_eq!(f.vector().len(), FEATURE_NAMES.len());
    }
    #[test]
    fn saturation_is_visible_and_heuristic_bounded() {
        let mut w = Windows::default();
        for ts in 1..=2050 {
            w.observe(&obs(ts, 1), &profile());
        }
        let f = w.observe(&obs(2051, 1), &profile());
        assert!(f.window_saturated);
        assert_eq!(f.raw_ip_connections, MAX_SAMPLES as u32);
        assert!((0.0..=1.0).contains(&f.heuristic()));
    }
}
