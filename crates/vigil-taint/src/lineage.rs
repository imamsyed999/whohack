//! Process lineage and taint propagation.
//!
//! - A process is tainted when its executable, or the script it runs, was
//!   downloaded, or when its parent is tainted. Taint survives `exec`.
//! - `taint_root` is the PID where taint entered the lineage (the oldest
//!   tainted ancestor's root).
//! - Exited processes stay resolvable for a grace period so children that
//!   are reported after their parent exited still inherit taint.

use std::collections::HashMap;
use std::sync::Arc;

use vigil_core::{FileInfo, PathClass, ProcessInfo, SignState};

/// How long exited processes remain resolvable as parents.
pub const DEFAULT_EXIT_GRACE_MS: i64 = 60_000;

/// A process start as seen by the taint stage.
#[derive(Debug, Clone)]
pub struct StartInput {
    pub pid: u32,
    pub ppid: u32,
    pub ts: i64,
    pub exe: FileInfo,
    pub script: Option<FileInfo>,
    pub path_class: PathClass,
}

/// Stable application identity: the script for interpreters, the signer +
/// executable name for trusted-signed binaries, otherwise the file hash.
pub fn app_id(exe: &FileInfo, script: Option<&FileInfo>) -> String {
    if let Some(s) = script {
        return format!("script:{}", vigil_core::hex::encode(&s.sha256));
    }
    match &exe.sign {
        SignState::ValidTrusted { publisher } => {
            let base = exe
                .path
                .rsplit(['/', '\\'])
                .next()
                .unwrap_or(&exe.path)
                .to_ascii_lowercase();
            format!("sig:{publisher}/{base}")
        }
        _ => format!("sha256:{}", vigil_core::hex::encode(&exe.sha256)),
    }
}

#[derive(Debug)]
pub struct ProcessTracker {
    live: HashMap<u32, Arc<ProcessInfo>>,
    exited: HashMap<u32, (i64, Arc<ProcessInfo>)>,
    grace_ms: i64,
}

impl Default for ProcessTracker {
    fn default() -> Self {
        ProcessTracker::new(DEFAULT_EXIT_GRACE_MS)
    }
}

impl ProcessTracker {
    pub fn new(grace_ms: i64) -> Self {
        ProcessTracker {
            live: HashMap::new(),
            exited: HashMap::new(),
            grace_ms,
        }
    }

    pub fn live_count(&self) -> usize {
        self.live.len()
    }

    /// A live process, or one that exited within the grace period.
    pub fn get(&self, pid: u32) -> Option<Arc<ProcessInfo>> {
        self.live
            .get(&pid)
            .cloned()
            .or_else(|| self.exited.get(&pid).map(|(_, p)| p.clone()))
    }

    /// Records a start (or an exec of an already-known PID). Idempotent for
    /// repeated reports of the same image.
    pub fn start(&mut self, s: StartInput) -> Arc<ProcessInfo> {
        let own_taint = s.exe.origin.is_downloaded()
            || s.script.as_ref().is_some_and(|f| f.origin.is_downloaded());
        let script_path = |p: &ProcessInfo| p.script.as_ref().map(|f| f.path.clone());

        let info = if let Some(existing) = self.live.get(&s.pid) {
            if existing.exe.path == s.exe.path
                && script_path(existing) == s.script.as_ref().map(|f| f.path.clone())
            {
                return existing.clone(); // duplicate report
            }
            // exec: same process, new image; lineage and taint carry over.
            let tainted = existing.tainted || own_taint;
            ProcessInfo {
                pid: s.pid,
                ppid: existing.ppid,
                start_time: existing.start_time,
                app_id: app_id(&s.exe, s.script.as_ref()),
                exe: s.exe,
                script: s.script,
                path_class: s.path_class,
                tainted,
                taint_root: existing.taint_root.or(own_taint.then_some(s.pid)),
            }
        } else {
            // A parent must have started no later than the child (guards PID reuse).
            let parent = self
                .get(s.ppid)
                .filter(|p| p.pid != s.pid && p.start_time <= s.ts);
            let inherited = parent.filter(|p| p.tainted);
            ProcessInfo {
                pid: s.pid,
                ppid: s.ppid,
                start_time: s.ts,
                app_id: app_id(&s.exe, s.script.as_ref()),
                exe: s.exe,
                script: s.script,
                path_class: s.path_class,
                tainted: own_taint || inherited.is_some(),
                taint_root: inherited
                    .and_then(|p| p.taint_root)
                    .or(own_taint.then_some(s.pid)),
            }
        };
        let info = Arc::new(info);
        self.exited.remove(&s.pid);
        self.live.insert(s.pid, info.clone());
        info
    }

    /// Records an exit; the process stays resolvable for the grace period.
    pub fn exit(&mut self, pid: u32, ts: i64) -> Option<Arc<ProcessInfo>> {
        let info = self.live.remove(&pid)?;
        self.exited.insert(pid, (ts, info.clone()));
        Some(info)
    }

    /// Forgets processes that exited more than the grace period before `now`.
    pub fn expire(&mut self, now_ms: i64) {
        let grace = self.grace_ms;
        self.exited.retain(|_, (t, _)| now_ms - *t <= grace);
    }

    /// The process and its ancestors, nearest first, up to `max` entries.
    pub fn ancestry(&self, pid: u32, max: usize) -> Vec<Arc<ProcessInfo>> {
        let mut out = Vec::new();
        let mut cur = self.get(pid);
        while let Some(p) = cur {
            if out.len() >= max || out.iter().any(|q: &Arc<ProcessInfo>| q.pid == p.pid) {
                break;
            }
            let next = if p.ppid == p.pid {
                None
            } else {
                self.get(p.ppid)
            };
            out.push(p);
            cur = next;
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vigil_core::Origin;

    fn file(path: &str, downloaded: bool, digest: u8) -> FileInfo {
        FileInfo {
            path: path.into(),
            sha256: [digest; 32],
            origin: if downloaded {
                Origin::Downloaded {
                    url: None,
                    referrer: None,
                }
            } else {
                Origin::System
            },
            sign: SignState::Unsigned,
            yara_hits: vec![],
            first_seen: 0,
        }
    }

    fn start(pid: u32, ppid: u32, ts: i64, exe: FileInfo) -> StartInput {
        StartInput {
            pid,
            ppid,
            ts,
            exe,
            script: None,
            path_class: PathClass::Other,
        }
    }

    #[test]
    fn downloaded_exe_taints_itself_and_descendants() {
        let mut t = ProcessTracker::default();
        t.start(start(1, 0, 0, file("/sbin/init", false, 1)));
        let dl = t.start(start(10, 1, 100, file("/home/u/Downloads/tool", true, 2)));
        assert!(dl.tainted);
        assert_eq!(dl.taint_root, Some(10));
        let child = t.start(start(11, 10, 200, file("/bin/sh", false, 3)));
        let grandchild = t.start(start(12, 11, 300, file("/usr/bin/curl", false, 4)));
        assert!(child.tainted && grandchild.tainted);
        assert_eq!(grandchild.taint_root, Some(10));
        let unrelated = t.start(start(20, 1, 400, file("/usr/bin/vim", false, 5)));
        assert!(!unrelated.tainted);
        assert_eq!(unrelated.taint_root, None);
    }

    #[test]
    fn downloaded_script_taints_interpreter_and_sets_app_id() {
        let mut t = ProcessTracker::default();
        let mut s = start(30, 1, 10, file("/bin/sh", false, 6));
        s.script = Some(file("/home/u/Downloads/run.sh", true, 7));
        let sh = t.start(s);
        assert!(sh.tainted);
        assert_eq!(sh.taint_root, Some(30));
        assert!(sh.app_id.starts_with("script:"));
        let child = t.start(start(31, 30, 20, file("/bin/sleep", false, 8)));
        assert!(child.tainted);
        assert_eq!(child.taint_root, Some(30));
    }

    #[test]
    fn exec_keeps_taint_and_duplicates_are_idempotent() {
        let mut t = ProcessTracker::default();
        let first = t.start(start(40, 1, 10, file("/home/u/Downloads/a", true, 9)));
        let dup = t.start(start(40, 1, 10, file("/home/u/Downloads/a", true, 9)));
        assert!(Arc::ptr_eq(&first, &dup));
        let execd = t.start(start(40, 1, 50, file("/bin/sh", false, 10)));
        assert!(execd.tainted, "taint survives exec");
        assert_eq!(execd.taint_root, Some(40));
        assert_eq!(execd.start_time, 10, "exec keeps the process start time");
        assert_eq!(execd.exe.path, "/bin/sh");
    }

    #[test]
    fn pid_reuse_and_exit_grace() {
        let mut t = ProcessTracker::new(1_000);
        t.start(start(50, 1, 10, file("/home/u/Downloads/a", true, 11)));
        t.exit(50, 100);
        // Child reported after its parent exited, within grace: inherits.
        let late_child = t.start(start(51, 50, 90, file("/bin/sh", false, 12)));
        assert!(late_child.tainted);
        // PID 50 reused by a clean process: not tainted.
        let reused = t.start(start(50, 1, 500, file("/usr/bin/vim", false, 13)));
        assert!(!reused.tainted);
        // A child claiming a parent that started after it is not linked.
        let bogus = t.start(start(52, 50, 400, file("/bin/true", false, 14)));
        assert!(!bogus.tainted);
        t.exit(51, 600);
        t.expire(2_000);
        assert!(t.get(51).is_none(), "expired after grace");
        assert!(t.get(50).is_some(), "live process kept");
    }

    #[test]
    fn ancestry_walks_parents_and_stops_on_cycles() {
        let mut t = ProcessTracker::default();
        t.start(start(1, 1, 0, file("/sbin/init", false, 1)));
        t.start(start(2, 1, 1, file("/bin/sh", false, 2)));
        t.start(start(3, 2, 2, file("/bin/x", false, 3)));
        let chain: Vec<u32> = t.ancestry(3, 10).iter().map(|p| p.pid).collect();
        assert_eq!(chain, vec![3, 2, 1]);
        assert_eq!(t.ancestry(3, 2).len(), 2);
        assert!(t.ancestry(99, 5).is_empty());
    }

    #[test]
    fn app_ids() {
        let mut signed = file(r"C:\Program Files\App\App.exe", false, 1);
        signed.sign = SignState::ValidTrusted {
            publisher: "Contoso".into(),
        };
        assert_eq!(app_id(&signed, None), "sig:Contoso/app.exe");
        assert!(app_id(&file("/x", false, 2), None).starts_with("sha256:0202"));
    }
}
