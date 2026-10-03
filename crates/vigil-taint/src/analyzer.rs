//! Path → `FileInfo`: origin, SHA-256, signature, and YARA hits, cached per
//! file version (size + mtime).

use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};

use lru::LruCache;
use vigil_core::{FileInfo, Origin, PathClass, SignState};

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
    yara: Option<YaraScanner>,
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
            yara,
            cache: LruCache::new(NonZeroUsize::new(CACHE_CAPACITY).expect("non-zero")),
        }
    }

    /// Placeholder-free description of a file that cannot be read (it may
    /// have been deleted, or is inaccessible): zero digest, unknown origin.
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
    fn analyzes_marked_file_and_caches() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("tool.bin");
        std::fs::write(&f, b"hello").unwrap();
        let mut a = FileAnalyzer::new(None);
        let first = a.analyze(&f, 1_000);
        assert_eq!(
            vigil_core::hex::encode(&first.sha256),
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
