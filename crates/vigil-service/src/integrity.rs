//! Integrity checking of detection content and configuration (SPEC §14).
//!
//! `MANIFEST.sha256` in the rules directory lists every file under it plus
//! the config file, in `sha256sum` format (`<hex>  <path>`). Paths under the
//! rules directory are relative; the config file is listed by absolute path.
//! `vigil-service --write-manifest` regenerates it after an intentional edit;
//! the service verifies it at startup and periodically, and raises a health
//! alert on any mismatch, missing file, or unlisted file.

use std::collections::BTreeMap;
use std::fmt;
use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};

pub const MANIFEST_NAME: &str = "MANIFEST.sha256";

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
                "no integrity manifest (run `vigil-service --write-manifest`)"
            ),
        }
    }
}

fn sha256_hex(path: &Path) -> Result<String> {
    let mut f = std::fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(vigil_core::hex::encode(&h.finalize()))
}

fn walk(dir: &Path, base: &Path, out: &mut BTreeMap<String, PathBuf>) -> Result<()> {
    let mut entries: Vec<_> = std::fs::read_dir(dir)
        .with_context(|| format!("read {}", dir.display()))?
        .filter_map(Result::ok)
        .collect();
    entries.sort_by_key(|e| e.file_name());
    for e in entries {
        let p = e.path();
        if p.is_dir() {
            walk(&p, base, out)?;
        } else if p.file_name().and_then(|n| n.to_str()) != Some(MANIFEST_NAME) {
            let rel = p
                .strip_prefix(base)
                .unwrap_or(&p)
                .to_string_lossy()
                .replace('\\', "/");
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
        walk(rules_dir, rules_dir, &mut files)?;
    }
    if let Some(c) = config {
        files.insert(c.to_string_lossy().into_owned(), c.to_path_buf());
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

pub fn parse(text: &str) -> BTreeMap<String, String> {
    text.lines()
        .filter_map(|l| l.split_once("  "))
        .map(|(h, n)| (n.to_string(), h.trim().to_ascii_lowercase()))
        .collect()
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
    let Ok(text) = std::fs::read_to_string(&manifest) else {
        return Ok(vec![Problem::NoManifest]);
    };
    let expected = parse(&text);
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
        assert_eq!(parse(&render(&m)), m);
    }
}
