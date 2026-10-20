//! A package checksum manifest detects damage/changes, not a replacement for a
//! publisher signature. Install-directory ACLs and signing are release gates.
use anyhow::{Context, Result, ensure};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    io::Read,
    path::{Component, Path},
};

pub fn verify(root: &Path) -> Result<()> {
    let manifest = root.join("WHOHACK-PACKAGE.json");
    if !manifest.exists() {
        ensure!(
            !root.join("bin/whohack-service.exe").exists(),
            "portable package is missing WHOHACK-PACKAGE.json"
        );
        return Ok(()); // source checkout: files are checked by the build workflow
    }
    let mut bytes = Vec::new();
    std::fs::File::open(manifest)?
        .take(1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= 1024 * 1024, "package manifest too large");
    let files: BTreeMap<String, String> = serde_json::from_slice(&bytes)?;
    ensure!(
        files.len() <= 4096
            && [
                "whohack.exe",
                "bin/whohack-service.exe",
                "bin/whohack-tray.exe"
            ]
            .iter()
            .all(|n| files.contains_key(*n)),
        "package manifest is incomplete"
    );
    for (name, expected) in &files {
        let path = Path::new(name);
        ensure!(
            !name.contains([':', '\\', '\n', '\r'])
                && !name.is_empty()
                && path.components().all(|c| matches!(c, Component::Normal(_))),
            "invalid package member {name}"
        );
        whohack_core::hex::decode32(expected).context("invalid package digest")?;
        let path = root.join(path);
        let actual = path.canonicalize()?;
        ensure!(
            actual.starts_with(root) && !std::fs::symlink_metadata(&path)?.file_type().is_symlink(),
            "package member escapes root"
        );
        let mut file = std::fs::File::open(&actual)?;
        let metadata = file.metadata()?;
        ensure!(
            metadata.is_file() && metadata.len() <= 1024 * 1024 * 1024,
            "package member too large"
        );
        let mut hash = Sha256::new();
        let mut buffer = [0u8; 256 * 1024];
        let mut size = 0u64;
        loop {
            let n = file.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            size += n as u64;
            ensure!(
                size <= metadata.len(),
                "package member changed during verification"
            );
            hash.update(&buffer[..n]);
        }
        ensure!(
            size == metadata.len(),
            "package member changed during verification"
        );
        ensure!(
            whohack_core::hex::encode(&hash.finalize()) == expected.to_ascii_lowercase(),
            "package integrity check failed: {name}"
        );
    }
    for entry in std::fs::read_dir(root.join("bin"))? {
        let entry = entry?;
        ensure!(
            entry.file_type()?.is_file()
                && files.contains_key(&format!("bin/{}", entry.file_name().to_string_lossy())),
            "unexpected package binary: {}",
            entry.path().display()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn damaged_incomplete_and_escaping_packages_are_rejected() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        std::fs::create_dir(root.join("bin")).unwrap();
        let mut files = BTreeMap::new();
        for name in [
            "whohack.exe",
            "bin/whohack-service.exe",
            "bin/whohack-tray.exe",
        ] {
            std::fs::write(root.join(name), b"safe fixture").unwrap();
            files.insert(
                name,
                whohack_core::hex::encode(&Sha256::digest(b"safe fixture")),
            );
        }
        let write = |files: &BTreeMap<&str, String>| {
            std::fs::write(
                root.join("WHOHACK-PACKAGE.json"),
                serde_json::to_vec(files).unwrap(),
            )
            .unwrap()
        };
        write(&files);
        verify(&root).unwrap();
        std::fs::write(root.join("bin/whohack-service.exe"), b"changed").unwrap();
        assert!(verify(&root).is_err());
        files.insert("../outside", "00".repeat(32));
        write(&files);
        assert!(verify(&root).is_err());
        files.clear();
        write(&files);
        assert!(verify(&root).is_err());
    }
}
