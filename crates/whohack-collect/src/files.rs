//! Bounded metadata-only file signals shared by native collectors.
use lru::LruCache;
use std::{collections::HashSet, num::NonZeroUsize};
use whohack_core::{Event, EventKind, Os, SensitiveClass, config::SensitiveConfig};
use whohack_tags::sensitive::SensitivePaths;

const WINDOW_MS: i64 = 60_000;
const MAX_PROCESSES: usize = 1024;
const MAX_FILES: usize = 256;

#[derive(Debug)]
struct Burst {
    since: i64,
    reported: Option<i64>,
    modified: HashSet<u64>,
    renamed: HashSet<u64>,
}

#[derive(Debug)]
pub struct FileSignals {
    paths: SensitivePaths,
    // Creation time separates reused process IDs.
    bursts: LruCache<(u32, i64), Burst>,
    recent: LruCache<(u32, i64, String, bool), i64>,
}

impl FileSignals {
    pub fn new(os: Os, cfg: &SensitiveConfig) -> Self {
        Self {
            paths: SensitivePaths::new(os, cfg),
            bursts: LruCache::new(NonZeroUsize::new(MAX_PROCESSES).unwrap()),
            recent: LruCache::new(NonZeroUsize::new(4096).unwrap()),
        }
    }

    /// `id` identifies the file independently of its current path (object / inode).
    /// Successful reads/writes only; callers verify OS identity and completion.
    pub fn access(
        &mut self,
        pid: u32,
        born: i64,
        ts: i64,
        id: u64,
        path: &str,
        change: Change,
    ) -> Vec<Event> {
        if pid == 0 || ts < born || path.is_empty() || path.len() > 4096 {
            return vec![];
        }
        let write = change != Change::Read;
        let mut events = Vec::new();
        let class = self.paths.class(path);
        let normalized = path.replace('\\', "/").to_ascii_lowercase();
        // Native file-read events connect data downloads to already-running
        // players/readers. Polling cannot provide this evidence.
        let download_read = !write && normalized.contains("/downloads/");
        if class != SensitiveClass::Other || download_read {
            let key = (pid, born, path.to_string(), write);
            if !self
                .recent
                .get(&key)
                .is_some_and(|last| ts.saturating_sub(*last) < 1000)
            {
                self.recent.put(key, ts);
                events.push(Event {
                    ts,
                    pid,
                    kind: EventKind::FileAccess {
                        path: path.into(),
                        class,
                        write,
                    },
                });
            }
        }
        // Cache/database/build churn outside user-file locations is not a
        // ransomware signal. Explicit sensitive roots remain configurable.
        let user_files = class != SensitiveClass::Other
            || [
                "/downloads/",
                "/desktop/",
                "/pictures/",
                "/videos/",
                "/music/",
            ]
            .iter()
            .any(|part| normalized.contains(part));
        if write && user_files {
            let b = self.bursts.get_or_insert_mut((pid, born), || Burst {
                since: ts,
                reported: None,
                modified: HashSet::new(),
                renamed: HashSet::new(),
            });
            if ts.saturating_sub(b.since) > WINDOW_MS || ts < b.since {
                *b = Burst {
                    since: ts,
                    reported: None,
                    modified: HashSet::new(),
                    renamed: HashSet::new(),
                };
            }
            let set = if change == Change::Rename {
                &mut b.renamed
            } else {
                &mut b.modified
            };
            if set.len() < MAX_FILES {
                set.insert(id);
            }
            // A write followed by a rename of the same file counts once.
            let modified = b.modified.difference(&b.renamed).count() as u32;
            let renamed = b.renamed.len() as u32;
            if modified + renamed >= 100
                && b.reported
                    .is_none_or(|last| ts.saturating_sub(last) >= 5000)
            {
                b.reported = Some(ts);
                events.push(Event {
                    ts,
                    pid,
                    kind: EventKind::FileBurst {
                        modified,
                        renamed,
                        window_ms: (ts - b.since).clamp(1, WINDOW_MS) as u32,
                    },
                });
            }
        }
        events
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Change {
    Read,
    Write,
    Rename,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn counts_distinct_files_not_repeated_writes_or_renames_and_separates_pids() {
        let mut s = FileSignals::new(Os::Linux, &Default::default());
        for id in 0..99 {
            assert!(
                s.access(10, 100, 200, id, "/home/u/Pictures/a", Change::Write)
                    .is_empty()
            );
            assert!(
                s.access(10, 100, 201, id, "/home/u/Pictures/b", Change::Rename)
                    .is_empty()
            );
        }
        assert!(
            s.access(10, 150, 202, 99, "/home/u/Pictures/a", Change::Write)
                .is_empty()
        );
        assert!(matches!(
            s.access(10, 100, 203, 99, "/home/u/Pictures/a", Change::Write)[0].kind,
            EventKind::FileBurst {
                modified: 1,
                renamed: 99,
                ..
            }
        ));
        assert!(
            s.access(10, 100, 204, 99, "/home/u/Pictures/a", Change::Write)
                .is_empty()
        );
        assert!(
            s.access(10, 100, 61_000, 100, "/home/u/Pictures/a", Change::Write)
                .is_empty()
        );
    }
    #[test]
    fn ordinary_database_and_cache_writes_do_not_emit_file_bursts() {
        let mut s = FileSignals::new(Os::Windows, &Default::default());
        for id in 0..150 {
            assert!(
                s.access(
                    10,
                    1,
                    200,
                    id,
                    r"C:\ProgramData\database\pages",
                    Change::Write
                )
                .is_empty()
            );
        }
    }
    #[test]
    fn sensitive_paths_are_metadata_only_and_rate_limited() {
        let mut s = FileSignals::new(Os::Windows, &Default::default());
        let path = r"C:\Users\someone\.ssh\nonexistent_private_key";
        assert!(matches!(
            s.access(10, 1, 10, 123, path, Change::Read)[0].kind,
            EventKind::FileAccess {
                class: SensitiveClass::SshKeys,
                write: false,
                ..
            }
        ));
        assert!(s.access(10, 1, 11, 123, path, Change::Read).is_empty());
        assert_eq!(s.access(10, 1, 1010, 123, path, Change::Read).len(), 1);
        assert!(s.access(10, 100, 10, 123, path, Change::Read).is_empty());
    }
}
