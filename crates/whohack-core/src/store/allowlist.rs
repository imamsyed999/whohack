//! `allowlist` table (SPEC §11).

use rusqlite::{OptionalExtension, params};

use super::{Store, StoreError};
use crate::time::now_ms;
use crate::types::AllowEntry;

impl Store {
    /// Adds an entry. Returns false if it was already present.
    pub fn allow(&self, e: &AllowEntry) -> Result<bool, StoreError> {
        let (kind, app_id, value) = e.to_columns();
        let n = self.conn.execute(
            "INSERT INTO allowlist (kind, app_id, value, created_at) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT (kind, app_id, value) DO NOTHING",
            params![kind, app_id, value, now_ms()],
        )?;
        Ok(n > 0)
    }

    /// Removes an entry. Returns false if it was not present.
    pub fn disallow(&self, e: &AllowEntry) -> Result<bool, StoreError> {
        let (kind, app_id, value) = e.to_columns();
        let n = self.conn.execute(
            "DELETE FROM allowlist WHERE kind = ?1 AND app_id = ?2 AND value = ?3",
            params![kind, app_id, value],
        )?;
        Ok(n > 0)
    }

    pub fn is_allowed(&self, e: &AllowEntry) -> Result<bool, StoreError> {
        let (kind, app_id, value) = e.to_columns();
        Ok(self
            .conn
            .query_row(
                "SELECT 1 FROM allowlist WHERE kind = ?1 AND app_id = ?2 AND value = ?3",
                params![kind, app_id, value],
                |_| Ok(()),
            )
            .optional()?
            .is_some())
    }

    /// All entries, oldest first.
    pub fn allowlist(&self) -> Result<Vec<AllowEntry>, StoreError> {
        let mut stmt = self
            .conn
            .prepare("SELECT kind, app_id, value FROM allowlist ORDER BY created_at, id")?;
        let rows = stmt
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        rows.into_iter()
            .map(|(kind, app_id, value)| {
                AllowEntry::from_columns(&kind, app_id, value).ok_or(StoreError::Corrupt {
                    column: "allowlist.kind",
                    value: kind,
                })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_duplicate_check_remove() {
        let s = Store::open_in_memory().unwrap();
        let app = AllowEntry::App {
            app_id: "com.example".into(),
        };
        let dest = AllowEntry::Destination {
            value: "example.com".into(),
        };
        let beh = AllowEntry::Behavior {
            app_id: "com.example".into(),
            tag: "network:unusual_port".into(),
        };
        assert!(s.allow(&app).unwrap());
        assert!(!s.allow(&app).unwrap(), "duplicate must be ignored");
        assert!(s.allow(&dest).unwrap());
        assert!(s.allow(&beh).unwrap());
        assert!(s.is_allowed(&app).unwrap());
        assert!(
            !s.is_allowed(&AllowEntry::App {
                app_id: "other".into()
            })
            .unwrap()
        );
        assert_eq!(
            s.allowlist().unwrap(),
            vec![app.clone(), dest.clone(), beh.clone()]
        );
        assert!(s.disallow(&dest).unwrap());
        assert!(!s.disallow(&dest).unwrap());
        assert!(!s.is_allowed(&dest).unwrap());
        assert_eq!(s.allowlist().unwrap(), vec![app, beh]);
    }

    #[test]
    fn same_value_different_kinds_are_distinct() {
        let s = Store::open_in_memory().unwrap();
        // An app_id and a destination that happen to share a string.
        assert!(s.allow(&AllowEntry::App { app_id: "x".into() }).unwrap());
        assert!(
            s.allow(&AllowEntry::Destination { value: "x".into() })
                .unwrap()
        );
        assert_eq!(s.allowlist().unwrap().len(), 2);
    }
}
