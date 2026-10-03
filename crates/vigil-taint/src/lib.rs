//! Vigil taint (SPEC §2, §8): which files came from the internet, and which
//! processes descend from them.
//!
//! [`TaintEngine`] is the pipeline stage: for each event it resolves the
//! acting process, analyzing executables and scripts on first sight
//! ([`FileAnalyzer`]) and tracking lineage ([`ProcessTracker`]).

pub mod analyzer;
pub mod hash;
pub mod lineage;
pub mod origin;
pub mod path_class;
pub mod scan;
pub mod script;
pub mod sign;

use std::path::{Path, PathBuf};
use std::sync::Arc;

pub use analyzer::FileAnalyzer;
pub use lineage::{ProcessTracker, StartInput};
pub use scan::YaraScanner;
use vigil_core::{Event, EventKind, Observation};

/// Reads a live process's working directory (to resolve relative script paths).
fn process_cwd(pid: u32) -> Option<PathBuf> {
    #[cfg(target_os = "linux")]
    {
        std::fs::read_link(format!("/proc/{pid}/cwd")).ok()
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = pid;
        None
    }
}

/// Pipeline stage turning events into observations with process context.
#[derive(Debug)]
pub struct TaintEngine {
    analyzer: FileAnalyzer,
    tracker: ProcessTracker,
}

impl TaintEngine {
    pub fn new(analyzer: FileAnalyzer, tracker: ProcessTracker) -> Self {
        TaintEngine { analyzer, tracker }
    }

    pub fn tracker(&self) -> &ProcessTracker {
        &self.tracker
    }

    /// Resolves the acting process for `event` (blocking: may hash and
    /// verify files on first sight).
    pub fn observe(&mut self, event: Event, now_ms: i64) -> Observation {
        let process = match &event.kind {
            EventKind::ProcessStart { ppid, exe, cmdline } => {
                let exe_info = self.analyzer.analyze(Path::new(exe), now_ms);
                let script = cmdline
                    .as_deref()
                    .and_then(|c| script::script_target(exe, c, process_cwd(event.pid).as_deref()))
                    .map(|p| self.analyzer.analyze(&p, now_ms));
                Some(self.tracker.start(StartInput {
                    pid: event.pid,
                    ppid: *ppid,
                    ts: event.ts,
                    path_class: path_class::classify_here(exe),
                    exe: exe_info,
                    script,
                }))
            }
            EventKind::ProcessExit => self.tracker.exit(event.pid, event.ts),
            _ => self.tracker.get(event.pid),
        };
        Observation {
            event,
            process,
            tags: Vec::new(),
        }
    }

    /// Periodic housekeeping (expires exited processes).
    pub fn tick(&mut self, now_ms: i64) {
        self.tracker.expire(now_ms);
    }

    pub fn process(&self, pid: u32) -> Option<Arc<vigil_core::ProcessInfo>> {
        self.tracker.get(pid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn engine_attaches_process_context() {
        let dir = tempfile::tempdir().unwrap();
        let tool = dir.path().join("tool");
        std::fs::write(&tool, b"#!/bin/sh\n").unwrap();
        let marked = origin::mark_downloaded(&tool, "https://example.com/tool").is_ok()
            && origin::read_marker(&tool).is_some();
        let mut e = TaintEngine::new(FileAnalyzer::new(None), ProcessTracker::default());
        let obs = e.observe(
            Event {
                ts: 10,
                pid: 77,
                kind: EventKind::ProcessStart {
                    ppid: 1,
                    exe: tool.to_string_lossy().into_owned(),
                    cmdline: None,
                },
            },
            10,
        );
        let p = obs.process.unwrap();
        assert_eq!(p.pid, 77);
        assert_eq!(p.tainted, marked);
        let conn = e.observe(
            Event {
                ts: 20,
                pid: 77,
                kind: EventKind::NetConnect {
                    remote_ip: "203.0.113.1".parse().unwrap(),
                    remote_port: 443,
                    proto: vigil_core::Proto::Tcp,
                    domain: None,
                    dns_before: false,
                },
            },
            20,
        );
        assert_eq!(conn.process.unwrap().pid, 77);
        let exit = e.observe(
            Event {
                ts: 30,
                pid: 77,
                kind: EventKind::ProcessExit,
            },
            30,
        );
        assert!(exit.process.is_some());
        let unknown = e.observe(
            Event {
                ts: 40,
                pid: 999,
                kind: EventKind::ProcessExit,
            },
            40,
        );
        assert!(unknown.process.is_none());
    }
}
