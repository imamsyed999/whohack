//! `settings` table: small key/value runtime settings.

use rusqlite::{OptionalExtension, params};

use super::{Store, StoreError};
use crate::time::now_ms;

impl Store {
    pub fn setting(&self, key: &str) -> Result<Option<String>, StoreError> {
        Ok(self
            .conn
            .query_row("SELECT value FROM settings WHERE key = ?1", [key], |r| {
                r.get(0)
            })
            .optional()?)
    }

    pub fn set_setting(&self, key: &str, value: &str) -> Result<(), StoreError> {
        self.conn.execute(
            "INSERT INTO settings (key, value, updated_at) VALUES (?1, ?2, ?3)
             ON CONFLICT (key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
            params![key, value, now_ms()],
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_get_overwrite() {
        let s = Store::open_in_memory().unwrap();
        assert_eq!(s.setting("mode").unwrap(), None);
        s.set_setting("mode", "auto").unwrap();
        s.set_setting("mode", "monitor").unwrap();
        assert_eq!(s.setting("mode").unwrap().as_deref(), Some("monitor"));
    }
}
