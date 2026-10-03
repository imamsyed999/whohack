//! Linux "signatures": package-manager ownership.
//!
//! A file owned by a dpkg/rpm package is reported as
//! `ValidTrusted { publisher: "dpkg:<package>" }` (or `rpm:`). For dpkg the
//! file's MD5 is also compared with the package's md5sums list, and a
//! mismatch (a modified package binary) is reported as `Invalid`. Files not
//! owned by any package are `Unsigned`.

use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;

use md5::{Digest, Md5};
use vigil_core::SignState;

use super::SignVerdict;

const DPKG_INFO: &str = "/var/lib/dpkg/info";

/// Directories whose package-owned files are indexed (executables live here).
const INDEXED_PREFIXES: &[&str] = &[
    "/usr/bin/",
    "/usr/sbin/",
    "/bin/",
    "/sbin/",
    "/usr/libexec/",
    "/usr/lib/",
    "/lib/",
    "/usr/lib64/",
    "/lib64/",
    "/usr/local/",
    "/opt/",
    "/usr/games/",
];
/// Files with these suffixes are never executables; skipping them keeps the index small.
const SKIPPED_SUFFIXES: &[&str] = &[
    ".py", ".pyc", ".h", ".gz", ".txt", ".json", ".xml", ".mo", ".png", ".svg", ".conf",
    ".typelib", ".a", ".la", ".pc", ".cmake", ".html", ".md", ".rules", ".service",
];

fn indexed(path: &str) -> bool {
    INDEXED_PREFIXES.iter().any(|p| path.starts_with(p))
        && !SKIPPED_SUFFIXES.iter().any(|s| path.ends_with(s))
        && !path.contains(".so")
}

/// Path spellings to try under merged-/usr layouts (`/bin` ↔ `/usr/bin`).
pub fn alternates(path: &str) -> Vec<String> {
    let mut v = vec![path.to_string()];
    for (a, b) in [
        ("/usr/bin/", "/bin/"),
        ("/usr/sbin/", "/sbin/"),
        ("/usr/lib/", "/lib/"),
        ("/usr/lib64/", "/lib64/"),
    ] {
        if let Some(rest) = path.strip_prefix(a) {
            v.push(format!("{b}{rest}"));
        } else if let Some(rest) = path.strip_prefix(b) {
            v.push(format!("{a}{rest}"));
        }
    }
    v
}

/// Parses a dpkg md5sums file (`<md5>  <relative path>` lines) and returns
/// the digest for `path` (absolute), if listed.
pub fn md5_for(md5sums: &str, path: &str) -> Option<String> {
    let rel = path.trim_start_matches('/');
    md5sums.lines().find_map(|l| {
        let (hash, p) = l.split_once("  ")?;
        (p.trim() == rel).then(|| hash.trim().to_ascii_lowercase())
    })
}

fn md5_file(path: &Path) -> Option<String> {
    let mut f = std::fs::File::open(path).ok()?;
    let mut h = Md5::new();
    let mut buf = vec![0u8; 128 * 1024];
    loop {
        let n = f.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Some(vigil_core::hex::encode(&h.finalize()))
}

#[derive(Debug, Default)]
pub struct PackageDb {
    /// path → package name (dpkg); built on first use.
    dpkg: Option<HashMap<Box<str>, Box<str>>>,
    /// rpm results per path (rpm-based systems).
    rpm_cache: HashMap<PathBuf, Option<String>>,
}

impl PackageDb {
    fn dpkg_index(&mut self) -> &HashMap<Box<str>, Box<str>> {
        self.dpkg.get_or_insert_with(|| {
            let mut map = HashMap::new();
            let Ok(rd) = std::fs::read_dir(DPKG_INFO) else {
                return map;
            };
            for e in rd.filter_map(Result::ok) {
                let name = e.file_name();
                let Some(name) = name.to_str() else { continue };
                let Some(pkg) = name.strip_suffix(".list") else {
                    continue;
                };
                let Ok(text) = std::fs::read_to_string(e.path()) else {
                    continue;
                };
                let pkg: Box<str> = pkg.into();
                for line in text.lines().filter(|l| indexed(l)) {
                    map.entry(line.into()).or_insert_with(|| pkg.clone());
                }
            }
            tracing::debug!(entries = map.len(), "dpkg ownership index built");
            map
        })
    }

    fn rpm_owner(&mut self, path: &Path) -> Option<String> {
        if let Some(cached) = self.rpm_cache.get(path) {
            return cached.clone();
        }
        let owner = Command::new("rpm")
            .args(["-qf", "--queryformat", "%{NAME}"])
            .arg(path)
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .filter(|s| !s.is_empty());
        if self.rpm_cache.len() > 10_000 {
            self.rpm_cache.clear();
        }
        self.rpm_cache.insert(path.to_path_buf(), owner.clone());
        owner
    }

    pub fn verdict(&mut self, path: &Path) -> SignVerdict {
        let Some(p) = path.to_str() else {
            return SignVerdict::unsigned();
        };
        if Path::new(DPKG_INFO).is_dir() {
            let index = self.dpkg_index();
            let found = alternates(p)
                .into_iter()
                .find_map(|alt| index.get(alt.as_str()).map(|pkg| (alt, pkg.to_string())));
            let Some((listed, pkg)) = found else {
                return SignVerdict::unsigned();
            };
            let state = match std::fs::read_to_string(format!("{DPKG_INFO}/{pkg}.md5sums"))
                .ok()
                .and_then(|sums| alternates(&listed).iter().find_map(|a| md5_for(&sums, a)))
            {
                Some(expected) if md5_file(path).is_some_and(|got| got != expected) => {
                    SignState::Invalid
                }
                _ => SignState::ValidTrusted {
                    publisher: format!("dpkg:{}", pkg.split(':').next().unwrap_or(&pkg)),
                },
            };
            return SignVerdict {
                state,
                package_owned: true,
            };
        }
        if Path::new("/var/lib/rpm").is_dir()
            && let Some(pkg) = self.rpm_owner(path)
        {
            return SignVerdict {
                state: SignState::ValidTrusted {
                    publisher: format!("rpm:{pkg}"),
                },
                package_owned: true,
            };
        }
        SignVerdict::unsigned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merged_usr_alternates() {
        assert_eq!(
            alternates("/usr/bin/bash"),
            vec!["/usr/bin/bash", "/bin/bash"]
        );
        assert_eq!(
            alternates("/sbin/init"),
            vec!["/sbin/init", "/usr/sbin/init"]
        );
        assert_eq!(alternates("/opt/x"), vec!["/opt/x"]);
    }

    #[test]
    fn md5sums_lookup() {
        let sums = "d41d8cd98f00b204e9800998ecf8427e  usr/bin/true\nABCDEF0123456789ABCDEF0123456789  usr/bin/curl\n";
        assert_eq!(
            md5_for(sums, "/usr/bin/curl").as_deref(),
            Some("abcdef0123456789abcdef0123456789")
        );
        assert_eq!(md5_for(sums, "/usr/bin/wget"), None);
    }

    #[test]
    fn index_filter() {
        assert!(indexed("/usr/bin/curl"));
        assert!(!indexed("/usr/lib/x86_64-linux-gnu/libc.so.6"));
        assert!(!indexed("/usr/share/doc/curl/README"));
        assert!(!indexed("/usr/lib/python3/dist-packages/x.py"));
    }

    #[test]
    fn system_binary_is_package_owned_when_dpkg_present() {
        if !Path::new(DPKG_INFO).is_dir() {
            return; // not a dpkg system
        }
        let sh = std::fs::canonicalize("/bin/sh").unwrap();
        let v = PackageDb::default().verdict(&sh);
        assert!(v.package_owned, "{} should be package-owned", sh.display());
        match v.state {
            SignState::ValidTrusted { publisher } => {
                assert!(publisher.starts_with("dpkg:"), "{publisher}")
            }
            other => panic!("unexpected {other:?}"),
        }
        let dir = tempfile::tempdir().unwrap();
        let mine = dir.path().join("tool");
        std::fs::write(&mine, b"x").unwrap();
        assert_eq!(PackageDb::default().verdict(&mine), SignVerdict::unsigned());
    }
}
