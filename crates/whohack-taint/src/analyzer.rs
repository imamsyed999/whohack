//! Path → `FileInfo`: origin, SHA-256, signature, and YARA hits, cached per
//! file version (size + mtime).

use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use lru::LruCache;
use whohack_core::{FileInfo, Origin, PathClass, SignState};

use crate::hash::{FileStamp, HashCache, stamp};
use crate::origin::read_marker;
use crate::path_class::classify_here;
use crate::scan::YaraScanner;
use crate::sign::SignChecker;

const CACHE_CAPACITY: usize = 8_192;

#[derive(Debug)]
pub struct FileAnalyzer {
    hashes: HashCache,
    signs: SignChecker,
    yara: Option<Arc<YaraScanner>>,
    cache: LruCache<PathBuf, (FileStamp, FileInfo)>,
}

/// Origin when no download marker is present: package-owned files are
/// installed; otherwise the location decides. Anything run from a
/// Downloads folder is treated as downloaded even without a marker
/// (archive extractors and command-line downloaders often drop it).
pub fn fallback_origin(class: PathClass, package_owned: bool) -> Origin {
    if package_owned {
        return Origin::Installed;
    }
    match class {
        PathClass::Downloads => Origin::Downloaded {
            url: None,
            referrer: None,
        },
        PathClass::System => Origin::System,
        PathClass::ProgramFiles => Origin::Installed,
        _ => Origin::Unknown,
    }
}

impl FileAnalyzer {
    pub fn new(yara: Option<YaraScanner>) -> Self {
        FileAnalyzer {
            hashes: HashCache::new(CACHE_CAPACITY),
            signs: SignChecker::new(),
            yara: yara.map(Arc::new),
            cache: LruCache::new(NonZeroUsize::new(CACHE_CAPACITY).expect("non-zero")),
        }
    }

    /// The digest cache (for persistence across restarts).
    pub fn hashes(&self) -> &HashCache {
        &self.hashes
    }

    pub fn hashes_mut(&mut self) -> &mut HashCache {
        &mut self.hashes
    }

    /// Prepare at most 128 file versions on at most four workers. Results are
    /// cached only; the caller still commits events and lineage in input order.
    pub fn prefetch(
        &mut self,
        paths: impl IntoIterator<Item = PathBuf>,
        now: i64,
        stopping: &std::sync::atomic::AtomicBool,
    ) {
        let paths: std::collections::BTreeSet<_> = paths.into_iter().take(128).collect();
        let mut tasks = Vec::new();
        for path in paths {
            let Ok(st) = stamp(&path) else {
                continue;
            };
            if self.cache.peek(&path).is_some_and(|(seen, _)| *seen == st) {
                continue;
            }
            let cached = self.hashes.cached(&path, st);
            tasks.push((path, st, cached));
        }
        if tasks.is_empty() {
            return;
        }
        let workers = std::thread::available_parallelism()
            .map_or(1, usize::from)
            .min(4);
        let prepared = std::thread::scope(|scope| {
            let mut handles = Vec::new();
            for chunk in tasks.chunks(tasks.len().div_ceil(workers)) {
                let yara = self.yara.clone();
                handles.push(scope.spawn(move || {
                    let mut analyzer = FileAnalyzer::new(None);
                    analyzer.yara = yara;
                    let mut out = Vec::new();
                    for (path, before, cached) in chunk {
                        if stopping.load(std::sync::atomic::Ordering::Relaxed) {
                            break;
                        }
                        if let Some(hash) = cached {
                            analyzer.hashes.remember(path.clone(), *before, *hash);
                        }
                        let info = analyzer.analyze(path, now);
                        if info.sha256 != [0; 32] && stamp(path).ok() == Some(*before) {
                            out.push((path.clone(), *before, info));
                        }
                    }
                    out
                }));
            }
            handles
                .into_iter()
                .flat_map(|handle| match handle.join() {
                    Ok(files) => files,
                    Err(_) => {
                        tracing::error!(
                            "file analysis worker panicked; falling back to ordered analysis"
                        );
                        vec![]
                    }
                })
                .collect::<Vec<_>>()
        });
        for (path, st, mut info) in prepared {
            if let Some((_, previous)) = self.cache.peek(&path) {
                info.first_seen = previous.first_seen;
            }
            self.hashes.remember(path.clone(), st, info.sha256);
            self.cache.put(path, (st, info));
        }
    }

    /// Description of a file that cannot be read (it may have been deleted,
    /// or is inaccessible): zero digest, origin from its location.
    pub fn unreadable(path: &str, now_ms: i64) -> FileInfo {
        FileInfo {
            path: path.to_string(),
            sha256: [0; 32],
            origin: fallback_origin(classify_here(path), false),
            sign: SignState::Unsigned,
            yara_hits: Vec::new(),
            first_seen: now_ms,
        }
    }

    /// Analyzes `path`. First sight costs a hash, signature check, and YARA
    /// scan; later calls for the same unchanged file are cache hits.
    pub fn analyze(&mut self, path: &Path, now_ms: i64) -> FileInfo {
        let display = path.to_string_lossy().into_owned();
        let Ok(st) = stamp(path) else {
            return FileAnalyzer::unreadable(&display, now_ms);
        };
        if let Some((cached, info)) = self.cache.get(path)
            && *cached == st
        {
            return info.clone();
        }
        let Ok(sha256) = self.hashes.sha256(path) else {
            return FileAnalyzer::unreadable(&display, now_ms);
        };
        let verdict = self.signs.check(path);
        let origin = read_marker(path)
            .unwrap_or_else(|| fallback_origin(classify_here(&display), verdict.package_owned));
        let yara_hits = self
            .yara
            .as_ref()
            .map(|y| y.scan_file(path))
            .unwrap_or_default();
        if stamp(path).ok() != Some(st) {
            return FileAnalyzer::unreadable(&display, now_ms);
        }
        let first_seen = self
            .cache
            .get(path)
            .map_or(now_ms, |(_, old)| old.first_seen);
        let info = FileInfo {
            path: display,
            sha256,
            origin,
            sign: verdict.state,
            yara_hits,
            first_seen,
        };
        self.cache.put(path.to_path_buf(), (st, info.clone()));
        info
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fallback_rules() {
        assert_eq!(fallback_origin(PathClass::Other, true), Origin::Installed);
        assert!(fallback_origin(PathClass::Downloads, false).is_downloaded());
        assert_eq!(fallback_origin(PathClass::System, false), Origin::System);
        assert_eq!(
            fallback_origin(PathClass::ProgramFiles, false),
            Origin::Installed
        );
        assert_eq!(fallback_origin(PathClass::Temp, false), Origin::Unknown);
    }

    #[test]
    fn prefetch_keeps_hashes_and_skips_cancelled_work() {
        use std::sync::atomic::AtomicBool;
        let t = tempfile::tempdir().unwrap();
        let paths: Vec<_> = (0..12)
            .map(|i| {
                let p = t.path().join(format!("{i}.txt"));
                std::fs::write(&p, format!("harmless-{i}")).unwrap();
                p
            })
            .collect();
        let mut a = FileAnalyzer::new(None);
        a.prefetch(paths.clone(), 100, &AtomicBool::new(true));
        assert!(a.hashes.is_empty());
        a.prefetch(paths.clone(), 100, &AtomicBool::new(false));
        assert_eq!(a.hashes.len(), 12);
        for path in paths {
            let info = a.analyze(&path, 200);
            assert_eq!(info.first_seen, 100);
            assert_eq!(info.sha256, crate::hash::sha256_file(&path).unwrap());
        }
    }

    #[test]
    fn analyzes_marked_file_and_caches() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("tool.bin");
        std::fs::write(&f, b"hello").unwrap();
        let mut a = FileAnalyzer::new(None);
        let first = a.analyze(&f, 1_000);
        assert_eq!(
            whohack_core::hex::encode(&first.sha256),
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
        assert_eq!(first.sign, SignState::Unsigned);
        if crate::origin::mark_downloaded(&f, "https://example.com/tool.bin").is_ok() {
            // The marker changes the inode's ctime but not size/mtime; write
            // again to invalidate the cache deterministically.
            std::fs::write(&f, b"hello!").unwrap();
            let second = a.analyze(&f, 2_000);
            if crate::origin::read_marker(&f).is_some() {
                assert!(second.origin.is_downloaded());
            }
            assert_eq!(second.first_seen, 1_000, "first sighting is kept");
        }
        let missing = a.analyze(&dir.path().join("gone"), 5);
        assert_eq!(missing.sha256, [0; 32]);
    }
}
