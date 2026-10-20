//! Integrity checking of detection content and configuration (SPEC §14).
//!
//! `MANIFEST.sha256` in the rules directory lists every file under it plus
//! the config file, in `sha256sum` format (`<hex>  <path>`). Paths under the
//! rules directory are relative; the config file is listed by absolute path.
//! `whohack-service --write-manifest` regenerates it after an intentional edit;
//! the service verifies it at startup and periodically, and raises a health
//! alert on any mismatch, missing file, or unlisted file.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use sha2::{Digest, Sha256};

pub const MANIFEST_NAME: &str = "MANIFEST.sha256";

/// Only derive aliases from the caller's configuration path. Resolving names
/// from a manifest could probe arbitrary locations (including network shares).
fn config_names(config: &Path) -> Result<(String, BTreeSet<String>)> {
    let canonical = config.canonicalize()?;
    let absolute = std::path::absolute(config)?;
    let name = canonical
        .to_str()
        .context("config path must be valid UTF-8")?
        .to_owned();
    let mut aliases = BTreeSet::new();
    for path in [config, absolute.as_path(), canonical.as_path()] {
        let alias = path.to_str().context("config path must be valid UTF-8")?;
        ensure!(!alias.chars().any(char::is_control), "invalid config path");
        aliases.insert(alias.to_owned());
    }
    #[cfg(windows)]
    if let Some(std::path::Component::Prefix(prefix)) = canonical.components().next() {
        match prefix.kind() {
            std::path::Prefix::VerbatimDisk(_) => {
                if let Some(plain) = name.strip_prefix(r"\\?\") {
                    aliases.insert(plain.to_owned());
                }
            }
            std::path::Prefix::VerbatimUNC(_, _) => {
                if let Some(plain) = name.strip_prefix(r"\\?\UNC\") {
                    aliases.insert(format!(r"\\{plain}"));
                }
            }
            _ => {}
        }
    }
    Ok((name, aliases))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Problem {
    Missing(String),
    Modified(String),
    Unlisted(String),
    NoManifest,
}

impl fmt::Display for Problem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Problem::Missing(p) => write!(f, "missing: {p}"),
            Problem::Modified(p) => write!(f, "modified: {p}"),
            Problem::Unlisted(p) => write!(f, "unexpected new file: {p}"),
            Problem::NoManifest => write!(
                f,
                "no integrity manifest (run `whohack-service --write-manifest`)"
            ),
        }
    }
}

fn sha256_hex(path: &Path) -> Result<String> {
    let mut f = std::fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
    let before = f.metadata()?;
    ensure!(
        before.is_file() && before.len() <= 8 * 1024 * 1024,
        "integrity input must be a regular file no larger than 8 MiB"
    );
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    let mut size = 0u64;
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        size += n as u64;
        ensure!(size <= 8 * 1024 * 1024, "integrity input grew beyond 8 MiB");
        h.update(&buf[..n]);
    }
    let after = f.metadata()?;
    ensure!(
        size == before.len()
            && before.len() == after.len()
            && before.modified()? == after.modified()?,
        "integrity input changed during verification"
    );
    Ok(whohack_core::hex::encode(&h.finalize()))
}

fn walk(
    dir: &Path,
    base: &Path,
    out: &mut BTreeMap<String, PathBuf>,
    depth: usize,
    count: &mut usize,
) -> Result<()> {
    ensure!(depth <= 16, "rules directory is nested too deeply");
    let mut entries: Vec<_> = std::fs::read_dir(dir)
        .with_context(|| format!("read {}", dir.display()))?
        .collect::<std::io::Result<Vec<_>>>()?;
    entries.sort_by_key(|e| e.file_name());
    for e in entries {
        let p = e.path();
        *count += 1;
        ensure!(*count <= 4096, "too many rule files/directories");
        let kind = e.file_type()?;
        ensure!(
            !kind.is_symlink(),
            "rule symlinks are not supported: {}",
            p.display()
        );
        if kind.is_dir() {
            walk(&p, base, out, depth + 1, count)?;
        } else if p.file_name().and_then(|n| n.to_str()) != Some(MANIFEST_NAME) {
            ensure!(kind.is_file(), "rules must be regular files");
            let rel = p
                .strip_prefix(base)
                .unwrap_or(&p)
                .to_str()
                .context("rule path must be valid UTF-8")?
                .replace('\\', "/");
            ensure!(!rel.chars().any(char::is_control), "invalid rule path");
            out.insert(rel, p);
        }
    }
    Ok(())
}

/// Files covered by the manifest: everything under `rules_dir` (relative
/// names) and the config file (absolute name).
pub fn covered_files(rules_dir: &Path, config: Option<&Path>) -> Result<BTreeMap<String, PathBuf>> {
    let mut files = BTreeMap::new();
    if rules_dir.is_dir() {
        ensure!(
            !std::fs::symlink_metadata(rules_dir)?
                .file_type()
                .is_symlink(),
            "rules root cannot be a symlink"
        );
        walk(rules_dir, rules_dir, &mut files, 0, &mut 0)?;
    }
    if let Some(c) = config {
        let (name, _) = config_names(c)?;
        files.insert(name, c.to_path_buf());
    }
    let mut size = 0u64;
    for path in files.values() {
        size = size
            .checked_add(std::fs::metadata(path)?.len())
            .context("integrity input size overflow")?;
        ensure!(
            size <= 64 * 1024 * 1024,
            "integrity inputs exceed 64 MiB in total"
        );
    }
    Ok(files)
}

pub fn compute(rules_dir: &Path, config: Option<&Path>) -> Result<BTreeMap<String, String>> {
    covered_files(rules_dir, config)?
        .into_iter()
        .map(|(name, path)| Ok((name, sha256_hex(&path)?)))
        .collect()
}

pub fn render(hashes: &BTreeMap<String, String>) -> String {
    hashes
        .iter()
        .map(|(name, h)| format!("{h}  {name}\n"))
        .collect()
}

pub fn parse(text: &str) -> Result<BTreeMap<String, String>> {
    ensure!(
        text.len() <= 1024 * 1024,
        "integrity manifest exceeds 1 MiB"
    );
    let mut out = BTreeMap::new();
    for line in text.lines() {
        let (hash, name) = line
            .split_once("  ")
            .context("malformed integrity manifest line")?;
        whohack_core::hex::decode32(hash).context("invalid integrity digest")?;
        ensure!(
            !name.is_empty() && !name.chars().any(char::is_control),
            "invalid integrity member name"
        );
        ensure!(
            out.insert(name.into(), hash.to_ascii_lowercase()).is_none(),
            "duplicate integrity member"
        );
        ensure!(out.len() <= 4097, "too many integrity members");
    }
    Ok(out)
}

pub fn write_manifest(rules_dir: &Path, config: Option<&Path>) -> Result<PathBuf> {
    std::fs::create_dir_all(rules_dir)?;
    let path = rules_dir.join(MANIFEST_NAME);
    std::fs::write(&path, render(&compute(rules_dir, config)?))?;
    Ok(path)
}

/// Compares the current files with the manifest.
pub fn verify(rules_dir: &Path, config: Option<&Path>) -> Result<Vec<Problem>> {
    let manifest = rules_dir.join(MANIFEST_NAME);
    let mut file = match std::fs::File::open(&manifest) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(vec![Problem::NoManifest]),
        Err(e) => return Err(e.into()),
    };
    let mut text = String::new();
    (&mut file)
        .take(1024 * 1024 + 1)
        .read_to_string(&mut text)?;
    let mut expected = parse(&text)?;
    if let Some(config) = config {
        let (canonical, aliases) = config_names(config)?;
        let entries: Vec<_> = aliases
            .iter()
            .filter_map(|alias| expected.remove(alias))
            .collect();
        ensure!(
            entries.len() <= 1,
            "duplicate configuration integrity member"
        );
        if let Some(hash) = entries.into_iter().next() {
            expected.insert(canonical, hash);
        }
    }
    let files = covered_files(rules_dir, config)?;
    let mut problems = Vec::new();
    for (name, hash) in &expected {
        match files.get(name) {
            None => problems.push(Problem::Missing(name.clone())),
            Some(p) => {
                if sha256_hex(p)? != *hash {
                    problems.push(Problem::Modified(name.clone()));
                }
            }
        }
    }
    for name in files.keys() {
        if !expected.contains_key(name) {
            problems.push(Problem::Unlisted(name.clone()));
        }
    }
    Ok(problems)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_modified_missing_and_unlisted_files() {
        let dir = tempfile::tempdir().unwrap();
        let rules = dir.path().join("rules");
        std::fs::create_dir_all(rules.join("yara")).unwrap();
        std::fs::write(rules.join("yara/a.yar"), "rule a { condition: false }").unwrap();
        std::fs::write(rules.join("b.yaml"), "x: 1").unwrap();
        let cfg = dir.path().join("config.toml");
        std::fs::write(&cfg, "mode = \"prompt\"\n").unwrap();

        assert_eq!(
            verify(&rules, Some(&cfg)).unwrap(),
            vec![Problem::NoManifest]
        );
        write_manifest(&rules, Some(&cfg)).unwrap();
        assert!(verify(&rules, Some(&cfg)).unwrap().is_empty());

        std::fs::write(&cfg, "mode = \"monitor\"\n").unwrap();
        std::fs::remove_file(rules.join("b.yaml")).unwrap();
        std::fs::write(rules.join("yara/new.yar"), "rule n { condition: true }").unwrap();
        let mut problems: Vec<String> = verify(&rules, Some(&cfg))
            .unwrap()
            .iter()
            .map(ToString::to_string)
            .collect();
        problems.sort();
        assert_eq!(problems.len(), 3, "{problems:?}");
        assert!(problems.iter().any(|p| p == "missing: b.yaml"));
        assert!(
            problems
                .iter()
                .any(|p| p.starts_with("modified: ") && p.ends_with("config.toml"))
        );
        assert!(
            problems
                .iter()
                .any(|p| p == "unexpected new file: yara/new.yar")
        );
    }

    #[test]
    fn manifest_format_round_trips() {
        let mut m = BTreeMap::new();
        m.insert("yara/a.yar".to_string(), "ab".repeat(32));
        assert_eq!(parse(&render(&m)).unwrap(), m);
        assert!(parse("broken line\n").is_err());
        assert!(parse(&format!("{}{}", render(&m), render(&m))).is_err());
    }

    #[test]
    fn config_keys_are_stable_and_duplicate_aliases_are_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let rules = dir.path().join("rules");
        std::fs::create_dir_all(dir.path().join("sub")).unwrap();
        let config = dir.path().join("sub/../config.toml");
        std::fs::write(&config, "mode = \"monitor\"\n").unwrap();
        write_manifest(&rules, Some(&config)).unwrap();
        let canonical = config.canonicalize().unwrap();
        assert!(verify(&rules, Some(&canonical)).unwrap().is_empty());
        let mut hashes = compute(&rules, Some(&config)).unwrap();
        hashes.insert(
            config.to_str().unwrap().into(),
            sha256_hex(&config).unwrap(),
        );
        std::fs::write(rules.join(MANIFEST_NAME), render(&hashes)).unwrap();
        assert!(verify(&rules, Some(&config)).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn legacy_windows_manifest_accepts_extended_path_but_still_detects_changes() {
        let dir = tempfile::tempdir().unwrap();
        let rules = dir.path().join("rules");
        std::fs::create_dir_all(&rules).unwrap();
        let config = dir.path().join("config.toml");
        std::fs::write(&config, "mode = \"monitor\"\n").unwrap();
        let canonical = config.canonicalize().unwrap();
        let plain = canonical.to_str().unwrap().strip_prefix(r"\\?\").unwrap();
        let legacy = BTreeMap::from([(plain.to_owned(), sha256_hex(&config).unwrap())]);
        let manifest = render(&legacy);
        std::fs::write(rules.join(MANIFEST_NAME), &manifest).unwrap();
        assert!(verify(&rules, Some(&canonical)).unwrap().is_empty());
        assert_eq!(
            std::fs::read_to_string(rules.join(MANIFEST_NAME)).unwrap(),
            manifest
        );
        std::fs::write(&config, "mode = \"prompt\"\n").unwrap();
        assert!(matches!(
            verify(&rules, Some(&canonical)).unwrap().as_slice(),
            [Problem::Modified(_)]
        ));
    }

    #[cfg(unix)]
    #[test]
    fn symlink_cycles_are_rejected() {
        let t = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(t.path(), t.path().join("cycle")).unwrap();
        assert!(covered_files(t.path(), None).is_err());
    }
}
