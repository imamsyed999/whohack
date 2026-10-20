//! Opt-in lifetime marker for a launcher-owned local preview.

use std::io::{self, Read};
use std::path::{Path, PathBuf};

/// Removing or replacing the marker asks this particular session to exit.
/// System services do not use this mechanism.
#[derive(Debug, Clone)]
pub struct LocalSession {
    path: PathBuf,
    id: String,
}

fn read_id(path: &Path) -> io::Result<String> {
    let mut text = String::new();
    std::fs::File::open(path)?
        .take(65)
        .read_to_string(&mut text)?;
    if text.len() != 32 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid local session marker",
        ));
    }
    Ok(text)
}

impl LocalSession {
    pub fn open(path: &Path) -> io::Result<Self> {
        Ok(Self {
            path: path.into(),
            id: read_id(path)?,
        })
    }

    pub fn is_active(&self) -> bool {
        read_id(&self.path).is_ok_and(|id| id == self.id)
    }

    pub async fn ended(&self) {
        while self.is_active() {
            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn replacement_and_removal_end_only_the_previous_session() {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("session");
        assert!(LocalSession::open(&marker).is_err());
        std::fs::write(&marker, "a".repeat(32)).unwrap();
        let first = LocalSession::open(&marker).unwrap();
        assert!(first.is_active());
        std::fs::write(&marker, "b".repeat(32)).unwrap();
        let second = LocalSession::open(&marker).unwrap();
        first.ended().await;
        assert!(second.is_active());
        std::fs::remove_file(&marker).unwrap();
        second.ended().await;
        std::fs::write(&marker, "invalid").unwrap();
        assert!(LocalSession::open(&marker).is_err());
    }
}
