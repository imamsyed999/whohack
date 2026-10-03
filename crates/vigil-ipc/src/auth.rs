//! Per-session token: 32 random bytes (hex), regenerated at every service
//! start and written to a file only the service and the UI's group can read.
//! The UI presents it in `Hello`; comparison is constant-time.

use std::path::Path;

use rand::RngCore;

pub fn generate_token() -> String {
    let mut b = [0u8; 32];
    rand::rng().fill_bytes(&mut b);
    vigil_core::hex::encode(&b)
}

/// Constant-time equality (no early exit on the first differing byte).
pub fn token_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Writes the token file. On Unix the file is mode 0640 (owner rw, group r),
/// so members of the service's group (the UI users) can read it.
pub fn write_token_file(path: &Path, token: &str) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, token)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o640))?;
    }
    std::fs::rename(&tmp, path)
}

pub fn read_token_file(path: &Path) -> std::io::Result<String> {
    Ok(std::fs::read_to_string(path)?.trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_are_random_hex_and_compare_correctly() {
        let a = generate_token();
        let b = generate_token();
        assert_eq!(a.len(), 64);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a, b);
        assert!(token_eq(&a, &a.clone()));
        assert!(!token_eq(&a, &b));
        assert!(!token_eq(&a, &a[..63]));
    }

    #[test]
    fn token_file_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("sub").join("ipc.token");
        let t = generate_token();
        write_token_file(&f, &t).unwrap();
        assert_eq!(read_token_file(&f).unwrap(), t);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&f).unwrap().permissions().mode() & 0o777,
                0o640
            );
        }
    }
}
