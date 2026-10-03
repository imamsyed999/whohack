//! Streaming SHA-256 with a cache keyed by (path, size, mtime).

use std::fs::File;
use std::io::{self, Read};
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use lru::LruCache;
use sha2::{Digest, Sha256};

/// SHA-256 of a file's contents.
pub fn sha256_file(path: &Path) -> io::Result<[u8; 32]> {
    let mut f = File::open(path)?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 256 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(h.finalize().into())
}

/// Size and modification time identify a file version for caching.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FileStamp {
    pub size: u64,
    pub mtime_ns: i128,
}

pub fn stamp(path: &Path) -> io::Result<FileStamp> {
    let md = std::fs::metadata(path)?;
    let mtime_ns = md
        .modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map_or(0, |d| d.as_nanos() as i128);
    Ok(FileStamp {
        size: md.len(),
        mtime_ns,
    })
}

/// Bounded cache of file digests; an entry is reused only while the file's
/// size and mtime are unchanged.
#[derive(Debug)]
pub struct HashCache {
    map: LruCache<PathBuf, (FileStamp, [u8; 32])>,
    hits: u64,
    misses: u64,
}

impl HashCache {
    /// # Panics
    /// If `capacity` is 0.
    pub fn new(capacity: usize) -> Self {
        HashCache {
            map: LruCache::new(NonZeroUsize::new(capacity).expect("capacity > 0")),
            hits: 0,
            misses: 0,
        }
    }

    pub fn sha256(&mut self, path: &Path) -> io::Result<[u8; 32]> {
        let st = stamp(path)?;
        if let Some((cached, digest)) = self.map.get(path)
            && *cached == st
        {
            self.hits += 1;
            return Ok(*digest);
        }
        self.misses += 1;
        let digest = sha256_file(path)?;
        self.map.put(path.to_path_buf(), (st, digest));
        Ok(digest)
    }

    pub fn stats(&self) -> (u64, u64) {
        (self.hits, self.misses)
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Persists the cache as tab-separated lines `sha256 size mtime_ns path`
    /// (written atomically). Entries stay valid only while a file's size and
    /// mtime are unchanged, so a stale entry can never be reused.
    pub fn save(&self, file: &Path) -> io::Result<usize> {
        if let Some(dir) = file.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let mut out = String::new();
        let mut n = 0;
        // Least recently used first, so reloading preserves recency order.
        for (path, (st, digest)) in self.map.iter().rev() {
            let Some(p) = path.to_str() else { continue };
            if p.contains(['\n', '\r']) {
                continue;
            }
            out.push_str(&format!(
                "{}\t{}\t{}\t{}\n",
                vigil_core::hex::encode(digest),
                st.size,
                st.mtime_ns,
                p
            ));
            n += 1;
        }
        let tmp = file.with_extension("tmp");
        std::fs::write(&tmp, out)?;
        std::fs::rename(&tmp, file)?;
        Ok(n)
    }

    /// Loads entries saved by [`save`](Self::save); malformed lines are skipped.
    pub fn load(&mut self, file: &Path) -> io::Result<usize> {
        let text = std::fs::read_to_string(file)?;
        let mut n = 0;
        for line in text.lines() {
            let mut f = line.splitn(4, '\t');
            let (Some(h), Some(size), Some(mtime), Some(path)) =
                (f.next(), f.next(), f.next(), f.next())
            else {
                continue;
            };
            let (Ok(digest), Ok(size), Ok(mtime_ns)) = (
                vigil_core::hex::decode32(h),
                size.parse::<u64>(),
                mtime.parse::<i128>(),
            ) else {
                continue;
            };
            self.map
                .put(PathBuf::from(path), (FileStamp { size, mtime_ns }, digest));
            n += 1;
        }
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_digest() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("abc");
        std::fs::write(&f, b"abc").unwrap();
        assert_eq!(
            vigil_core::hex::encode(&sha256_file(&f).unwrap()),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn save_and_load_keep_valid_entries_only() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a");
        let b = dir.path().join("b");
        std::fs::write(&a, b"alpha").unwrap();
        std::fs::write(&b, b"beta").unwrap();
        let mut c = HashCache::new(8);
        let da = c.sha256(&a).unwrap();
        c.sha256(&b).unwrap();
        let store = dir.path().join("cache").join("hashes.tsv");
        assert_eq!(c.save(&store).unwrap(), 2);

        let mut fresh = HashCache::new(8);
        assert_eq!(fresh.load(&store).unwrap(), 2);
        assert_eq!(fresh.sha256(&a).unwrap(), da);
        assert_eq!(
            fresh.stats(),
            (1, 0),
            "unchanged file served from the loaded cache"
        );
        // A file changed after saving is re-hashed, never served stale.
        std::fs::write(&b, b"beta-modified").unwrap();
        fresh.sha256(&b).unwrap();
        assert_eq!(fresh.stats(), (1, 1));

        std::fs::write(&store, "garbage\nzz\t1\t2\t/x\n").unwrap();
        assert_eq!(HashCache::new(4).load(&store).unwrap(), 0);
    }

    #[test]
    fn cache_hits_until_file_changes() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("x");
        std::fs::write(&f, b"one").unwrap();
        let mut c = HashCache::new(8);
        let a = c.sha256(&f).unwrap();
        let b = c.sha256(&f).unwrap();
        assert_eq!(a, b);
        assert_eq!(c.stats(), (1, 1));
        // Different size → miss even if mtime granularity is coarse.
        std::fs::write(&f, b"three").unwrap();
        let d = c.sha256(&f).unwrap();
        assert_ne!(a, d);
        assert_eq!(c.stats(), (1, 2));
        assert!(c.sha256(&dir.path().join("missing")).is_err());
    }
}
