//! Quarantine containers are inert (header plus XOR-encoded bytes), not a
//! malware encryption format. Restores verify the entire digest before making
//! a file visible and never overwrite an existing destination.
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, Write};
use std::path::{Path, PathBuf};
use whohack_core::FileInfo;

// Stable on-disk format: existing quarantined files must survive the rename.
const HEADER: &[u8; 8] = b"VIGILQ01";
const MAX_BYTES: u64 = 512 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Entry {
    pub id: String,
    pub original_path: PathBuf,
    pub sha256: [u8; 32],
    pub size: u64,
    pub modified_ms: Option<u64>,
    pub readonly: bool,
    pub unix_mode: Option<u32>,
    pub quarantined_at: i64,
    pub restored_at: Option<i64>,
    /// Windows Mark-of-the-Web is restored with the file, never silently lost.
    pub zone_identifier: Option<String>,
}

#[derive(Debug)]
pub struct Vault {
    root: PathBuf,
    recovery_errors: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Pending {
    entry: Entry,
    held_path: PathBuf,
}
impl Vault {
    pub fn open(root: PathBuf) -> Result<Self> {
        fs::create_dir_all(&root)?;
        ensure!(
            !fs::symlink_metadata(&root)?.file_type().is_symlink(),
            "vault cannot be a symlink"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
        }
        #[cfg(windows)]
        crate::windows::storage::private_directory(&root)?;
        let mut vault = Self {
            root,
            recovery_errors: vec![],
        };
        // Finish an already authorized claim, retaining every uncertain file.
        vault.recovery_errors = vault.recover_pending()?;
        for error in &vault.recovery_errors {
            tracing::error!(error, "quarantine recovery requires attention");
        }
        Ok(vault)
    }
    pub fn recovery_errors(&self) -> &[String] {
        &self.recovery_errors
    }
    fn entry_dir(&self, id: &str) -> Result<PathBuf> {
        ensure!(
            id.len() == 32 && id.bytes().all(|b| b.is_ascii_hexdigit()),
            "invalid quarantine id"
        );
        let path = self.root.join(id);
        ensure!(
            !fs::symlink_metadata(&path)?.file_type().is_symlink(),
            "quarantine entry cannot be a symlink"
        );
        Ok(path)
    }
    pub fn list(&self) -> Result<Vec<Entry>> {
        let mut entries = Vec::new();
        for item in fs::read_dir(&self.root)?.take(10_001) {
            let item = item?;
            if !item.file_type()?.is_dir() {
                continue;
            }
            if let Some(id) = item.file_name().to_str()
                && let Ok(entry) = self.get(id)
            {
                entries.push(entry);
            }
            ensure!(
                entries.len() <= 10_000,
                "quarantine listing exceeds 10000 entries"
            );
        }
        entries.sort_by_key(|e| std::cmp::Reverse(e.quarantined_at));
        Ok(entries)
    }
    pub fn get(&self, id: &str) -> Result<Entry> {
        let dir = self.entry_dir(id)?;
        let file = File::open(dir.join("metadata.json"))?;
        ensure!(
            file.metadata()?.len() <= 64 * 1024,
            "quarantine metadata too large"
        );
        let e: Entry = serde_json::from_reader(file)?;
        ensure!(
            e.id == id && e.size <= MAX_BYTES && e.original_path.is_absolute(),
            "invalid quarantine metadata"
        );
        Ok(e)
    }

    /// Complete interrupted claims into the inert vault. Never restore a file to
    /// its original name on startup and never remove an unverified held object.
    pub fn recover_pending(&self) -> Result<Vec<String>> {
        let mut errors = Vec::new();
        for item in fs::read_dir(&self.root)?.take(10_001) {
            let item = item?;
            if !item.file_type()?.is_dir() {
                continue;
            }
            let Some(id) = item.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            let path = item.path().join("pending.json");
            if !path.exists() {
                continue;
            }
            if let Err(e) = self.recover_one(&id) {
                errors.push(format!("{id}: {e:#}"));
            }
        }
        Ok(errors)
    }

    fn recover_one(&self, id: &str) -> Result<()> {
        let dir = self.entry_dir(id)?;
        let pending = dir.join("pending.json");
        ensure!(
            !fs::symlink_metadata(&pending)?.file_type().is_symlink(),
            "pending record cannot be a symlink"
        );
        let f = File::open(&pending)?;
        ensure!(f.metadata()?.len() <= 64 * 1024, "pending record too large");
        let p: Pending = serde_json::from_reader(f)?;
        ensure!(
            p.entry.id == id
                && p.entry.original_path.is_absolute()
                && p.entry.size <= MAX_BYTES
                && p.entry.sha256 != [0; 32],
            "invalid pending record"
        );
        let stage = p.held_path.parent().context("missing staging directory")?;
        ensure!(
            p.held_path.file_name().is_some_and(|n| n == "held")
                && stage
                    .file_name()
                    .is_some_and(|n| n.to_string_lossy().starts_with(".vigil-quarantine-")),
            "unexpected held path"
        );
        ensure!(
            stage
                .parent()
                .context("missing staging parent")?
                .canonicalize()?
                == p.entry
                    .original_path
                    .parent()
                    .context("missing original parent")?
                    .canonicalize()?,
            "staging path is outside the original directory"
        );
        if p.held_path.exists() {
            ensure!(
                !fs::symlink_metadata(stage)?.file_type().is_symlink(),
                "staging directory cannot be a symlink"
            );
            self.seal_held(&dir, &p.entry, &p.held_path)?;
            remove_held(&p.held_path)?;
            // Only an empty directory created for this claim is removed.
            let _ = fs::remove_dir(stage);
        } else if dir.join("metadata.json").exists() {
            ensure!(
                self.get(id)? == p.entry,
                "completed metadata differs from pending claim"
            );
            verify_payload(&dir, &p.entry)?;
        } else {
            anyhow::bail!(
                "claimed file is missing; inspect original {} before clearing the journal",
                p.entry.original_path.display()
            );
        }
        fs::remove_file(pending)?;
        Ok(())
    }

    fn seal_held(&self, dir: &Path, entry: &Entry, held: &Path) -> Result<()> {
        let metadata = fs::symlink_metadata(held)?;
        ensure!(
            metadata.is_file()
                && !metadata.file_type().is_symlink()
                && metadata.len() == entry.size,
            "held file changed"
        );
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            options.share_mode(windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ);
        }
        let mut input = options.open(held)?;
        let mut output = tempfile::NamedTempFile::new_in(dir)?;
        output.write_all(HEADER)?;
        let (digest, size) = transcode(&mut input, &mut output, false)?;
        ensure!(
            digest == entry.sha256 && size == entry.size,
            "held file does not match the captured digest; retained untouched"
        );
        output.as_file().sync_all()?;
        if dir.join("metadata.json").exists() {
            ensure!(
                self.get(&entry.id)? == *entry,
                "conflicting completed quarantine metadata"
            );
        }
        output
            .persist(dir.join("contents.vigilq"))
            .map_err(|e| e.error)?;
        write_json(&dir.join("metadata.json"), entry)?;
        Ok(())
    }
    pub fn quarantine(&self, file: &FileInfo) -> Result<Entry> {
        ensure!(
            file.sha256 != [0; 32],
            "cannot quarantine without a known digest"
        );
        let original = Path::new(&file.path);
        ensure!(
            original.is_absolute(),
            "quarantine requires an absolute path"
        );
        let metadata = fs::symlink_metadata(original)?;
        ensure!(
            metadata.is_file() && !metadata.file_type().is_symlink(),
            "quarantine requires a regular file"
        );
        ensure!(
            metadata.len() <= MAX_BYTES,
            "file exceeds the 512 MiB quarantine limit"
        );
        let parent = original.parent().context("file has no parent")?;
        // Claim the directory entry on its own filesystem. Hash the claimed
        // object before deleting anything. This also handles cross-volume vaults.
        let stage = tempfile::Builder::new()
            .prefix(".vigil-quarantine-")
            .tempdir_in(parent)?;
        let held = stage.path().join("held");
        #[cfg(windows)]
        crate::windows::storage::private_directory(stage.path())?;
        let id = format!("{:032x}", rand::random::<u128>());
        let dir = self.root.join(&id);
        fs::create_dir(&dir)?;
        #[cfg(unix)]
        let unix_mode = {
            use std::os::unix::fs::PermissionsExt;
            Some(metadata.permissions().mode() & 0o777)
        };
        #[cfg(not(unix))]
        let unix_mode = None;
        let entry = Entry {
            id,
            original_path: original.to_path_buf(),
            sha256: file.sha256,
            size: metadata.len(),
            modified_ms: metadata
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_millis() as u64),
            readonly: metadata.permissions().readonly(),
            unix_mode,
            quarantined_at: whohack_core::time::now_ms(),
            restored_at: None,
            zone_identifier: zone(original),
        };
        // A recovery record exists before moving the source.
        write_json(
            &dir.join("pending.json"),
            &serde_json::json!({"entry": entry, "held_path": held}),
        )?;
        fs::rename(original, &held).context("claim file for quarantine (stop the process first if Windows reports a sharing violation)")?;
        let result = (|| -> Result<()> {
            self.seal_held(&dir, &entry, &held)?;
            remove_held(&held)?;
            fs::remove_file(dir.join("pending.json"))?;
            Ok(())
        })();
        if let Err(error) = result {
            // hard_link is no-clobber. If an attacker recreated the original
            // name, retain the held file and report its exact recovery location.
            if held.exists() {
                if let Err(restore_error) = fs::hard_link(&held, original) {
                    let kept = stage.keep();
                    return Err(error.context(format!(
                        "rollback failed ({restore_error}); original bytes retained at {}",
                        kept.join("held").display()
                    )));
                }
                fs::remove_file(&held)?;
                if dir.join("metadata.json").exists() {
                    let mut rolled_back = entry.clone();
                    rolled_back.restored_at = Some(whohack_core::time::now_ms());
                    write_json(&dir.join("metadata.json"), &rolled_back)?;
                }
                fs::remove_file(dir.join("pending.json"))?;
            }
            return Err(error);
        }
        Ok(entry)
    }
    pub fn restore(&self, id: &str) -> Result<PathBuf> {
        let mut entry = self.get(id)?;
        ensure!(
            entry.restored_at.is_none(),
            "entry has already been restored"
        );
        let parent = entry
            .original_path
            .parent()
            .context("missing original parent")?;
        ensure!(
            parent.is_dir(),
            "original directory no longer exists; recreate it before restoring"
        );
        let dir = self.entry_dir(id)?;
        let mut input = File::open(dir.join("contents.vigilq"))?;
        ensure!(
            input.metadata()?.len() == entry.size + HEADER.len() as u64,
            "quarantine payload size mismatch"
        );
        let mut header = [0u8; 8];
        input.read_exact(&mut header)?;
        ensure!(&header == HEADER, "unsupported quarantine format");
        let mut restored = tempfile::NamedTempFile::new_in(parent)?;
        let (digest, size) = transcode(&mut input, restored.as_file_mut(), true)?;
        ensure!(
            digest == entry.sha256 && size == entry.size,
            "quarantine payload is corrupt; nothing restored"
        );
        restored.as_file_mut().rewind()?;
        if let Some(ms) = entry.modified_ms {
            restored.as_file().set_times(
                fs::FileTimes::new()
                    .set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_millis(ms)),
            )?;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            restored
                .as_file()
                .set_permissions(fs::Permissions::from_mode(
                    entry.unix_mode.unwrap_or(0o600) & 0o777,
                ))?;
        }
        #[cfg(windows)]
        {
            if let Some(zone) = &entry.zone_identifier {
                fs::write(
                    format!("{}:Zone.Identifier", restored.path().display()),
                    zone,
                )?;
            }
            let mut perms = restored.as_file().metadata()?.permissions();
            perms.set_readonly(entry.readonly);
            restored.as_file().set_permissions(perms)?;
        }
        restored.as_file().sync_all()?;
        restored
            .persist_noclobber(&entry.original_path)
            .map_err(|e| e.error)
            .context("restore refused to overwrite an existing file")?;
        entry.restored_at = Some(whohack_core::time::now_ms());
        write_json(&dir.join("metadata.json"), &entry)?;
        Ok(entry.original_path)
    }
}
fn remove_held(path: &Path) -> Result<()> {
    #[cfg(windows)]
    #[allow(clippy::permissions_set_readonly_false)]
    // Windows file attribute only; never compiled on Unix.
    {
        let mut permissions = fs::metadata(path)?.permissions();
        if permissions.readonly() {
            permissions.set_readonly(false);
            fs::set_permissions(path, permissions)?;
        }
    }
    fs::remove_file(path)?;
    Ok(())
}
fn verify_payload(dir: &Path, entry: &Entry) -> Result<()> {
    let mut input = File::open(dir.join("contents.vigilq"))?;
    ensure!(
        input.metadata()?.len() == entry.size + 8,
        "incomplete quarantine payload"
    );
    let mut header = [0u8; 8];
    input.read_exact(&mut header)?;
    ensure!(&header == HEADER, "invalid quarantine payload header");
    let (hash, size) = transcode(&mut input, &mut std::io::sink(), true)?;
    ensure!(
        hash == entry.sha256 && size == entry.size,
        "quarantine payload failed verification"
    );
    Ok(())
}
fn zone(path: &Path) -> Option<String> {
    #[cfg(windows)]
    {
        let mut f = File::open(format!("{}:Zone.Identifier", path.display()))
            .ok()?
            .take(16 * 1024);
        let mut s = String::new();
        f.read_to_string(&mut s).ok()?;
        Some(s)
    }
    #[cfg(not(windows))]
    {
        let _ = path;
        None
    }
}
fn transcode(
    input: &mut impl Read,
    output: &mut impl Write,
    decode: bool,
) -> Result<([u8; 32], u64)> {
    let mut buf = [0u8; 64 * 1024];
    let mut hash = Sha256::new();
    let mut size = 0;
    loop {
        let n = input.read(&mut buf)?;
        if n == 0 {
            break;
        }
        size += n as u64;
        ensure!(size <= MAX_BYTES, "payload exceeded quarantine size limit");
        if !decode {
            hash.update(&buf[..n]);
        }
        for b in &mut buf[..n] {
            *b ^= 0xa5;
        }
        if decode {
            hash.update(&buf[..n]);
        }
        output.write_all(&buf[..n])?;
    }
    Ok((hash.finalize().into(), size))
}
pub(crate) fn write_json(path: &Path, value: &impl Serialize) -> Result<()> {
    let mut tmp = tempfile::NamedTempFile::new_in(path.parent().context("missing parent")?)?;
    serde_json::to_writer(&mut tmp, value)?;
    tmp.as_file().sync_all()?;
    tmp.persist(path).map_err(|e| e.error)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn file(path: &Path) -> FileInfo {
        FileInfo {
            path: path.to_string_lossy().into(),
            sha256: crate::digest_file(path).unwrap(),
            origin: whohack_core::Origin::Unknown,
            sign: whohack_core::SignState::Unsigned,
            yara_hits: vec![],
            first_seen: 0,
        }
    }
    #[test]
    fn roundtrip_and_no_clobber() {
        let t = tempfile::tempdir().unwrap();
        let path = t.path().join("safe-test.txt");
        fs::write(&path, b"harmless quarantine fixture").unwrap();
        let vault = Vault::open(t.path().join("vault")).unwrap();
        let e = vault.quarantine(&file(&path)).unwrap();
        assert!(!path.exists());
        assert_eq!(vault.list().unwrap(), vec![e.clone()]);
        fs::write(&path, b"new user file").unwrap();
        assert!(vault.restore(&e.id).is_err());
        assert_eq!(fs::read(&path).unwrap(), b"new user file");
        fs::remove_file(&path).unwrap();
        vault.restore(&e.id).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"harmless quarantine fixture");
        assert!(vault.restore(&e.id).is_err());
        assert!(vault.get("../outside").is_err());
    }
    #[test]
    fn stale_hash_rolls_back_and_corrupt_container_never_restores() {
        let t = tempfile::tempdir().unwrap();
        let path = t.path().join("safe.txt");
        fs::write(&path, b"first").unwrap();
        let stale = file(&path);
        fs::write(&path, b"other").unwrap();
        let vault = Vault::open(t.path().join("vault")).unwrap();
        assert!(vault.quarantine(&stale).is_err());
        assert_eq!(fs::read(&path).unwrap(), b"other");
        let e = vault.quarantine(&file(&path)).unwrap();
        fs::write(
            vault.entry_dir(&e.id).unwrap().join("contents.vigilq"),
            b"VIGILQ01wrong",
        )
        .unwrap();
        assert!(vault.restore(&e.id).is_err());
        assert!(!path.exists());
    }

    #[test]
    fn interrupted_claim_finishes_without_overwriting_new_original() {
        let t = tempfile::tempdir().unwrap();
        let original = t.path().join("safe.txt");
        fs::write(&original, b"harmless old bytes").unwrap();
        let vault_path = t.path().join("vault");
        let vault = Vault::open(vault_path.clone()).unwrap();
        let entry = vault.quarantine(&file(&original)).unwrap();
        let dir = vault.entry_dir(&entry.id).unwrap();
        let stage = tempfile::Builder::new()
            .prefix(".vigil-quarantine-")
            .tempdir_in(t.path())
            .unwrap();
        let held = stage.path().join("held");
        fs::write(&held, b"harmless old bytes").unwrap();
        fs::write(&original, b"new user file").unwrap();
        fs::remove_file(dir.join("metadata.json")).unwrap();
        fs::write(dir.join("contents.vigilq"), b"partial interrupted write").unwrap();
        write_json(
            &dir.join("pending.json"),
            &serde_json::json!({"entry": entry, "held_path": held}),
        )
        .unwrap();
        let recovered = Vault::open(vault_path).unwrap();
        assert!(recovered.recovery_errors().is_empty());
        assert!(!held.exists());
        assert!(!dir.join("pending.json").exists());
        assert_eq!(fs::read(&original).unwrap(), b"new user file");
        assert!(recovered.restore(&entry.id).is_err());
        verify_payload(&dir, &entry).unwrap();
    }

    #[test]
    fn recovery_retains_mismatched_held_bytes_and_reports_problem() {
        let t = tempfile::tempdir().unwrap();
        let original = t.path().join("safe.txt");
        fs::write(&original, b"old").unwrap();
        let root = t.path().join("vault");
        let vault = Vault::open(root.clone()).unwrap();
        let entry = vault.quarantine(&file(&original)).unwrap();
        let dir = vault.entry_dir(&entry.id).unwrap();
        let stage = tempfile::Builder::new()
            .prefix(".vigil-quarantine-")
            .tempdir_in(t.path())
            .unwrap();
        let held = stage.path().join("held");
        fs::write(&held, b"new").unwrap();
        write_json(
            &dir.join("pending.json"),
            &serde_json::json!({"entry": entry, "held_path": held}),
        )
        .unwrap();
        let recovered = Vault::open(root).unwrap();
        assert_eq!(recovered.recovery_errors().len(), 1);
        assert_eq!(fs::read(held).unwrap(), b"new");
        verify_payload(&dir, &entry).unwrap();
    }
}
