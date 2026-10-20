//! `profiles` table: per-app expected-behavior profiles (SPEC §12.5).

use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};

use super::{Store, StoreError, from_json};
use crate::types::CapabilityTag;

/// Stored form of an app's expected-behavior profile. The profile builder
/// (M3) produces and consumes this.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileRecord {
    pub app_id: String,
    pub category: String,
    pub expected: Vec<CapabilityTag>,
    /// Tag patterns that must never occur, e.g. `"credential_access:*"`.
    pub never: Vec<String>,
    /// End of the learning period (Unix ms); `None` when learning is over.
    pub learning_until: Option<i64>,
    pub updated_at: i64,
}

impl Store {
    pub fn recent_profile_ids(&self, limit: u32) -> Result<Vec<String>, StoreError> {
        let mut stmt = self
            .conn
            .prepare("SELECT app_id FROM profiles ORDER BY updated_at DESC, app_id LIMIT ?1")?;
        Ok(stmt
            .query_map([limit], |r| r.get(0))?
            .collect::<Result<_, _>>()?)
    }

    pub fn app_path(&self, app_id: &str) -> Result<Option<String>, StoreError> {
        Ok(self.conn.query_row("SELECT COALESCE(script_path, exe_path) FROM processes WHERE app_id = ?1 ORDER BY start_time DESC LIMIT 1",
            [app_id], |r| r.get(0)).optional()?)
    }

    /// Observations are proposals only. This never changes the expected tag set.
    pub fn observe_profile_tags(
        &self,
        app_id: &str,
        tags: &[CapabilityTag],
        ts: i64,
    ) -> Result<(), StoreError> {
        let tx = self.conn.unchecked_transaction()?;
        for tag in tags {
            tx.prepare_cached("INSERT INTO profile_observations (app_id, tag, last_seen) VALUES (?1, ?2, ?3)
                ON CONFLICT(app_id, tag) DO UPDATE SET count = count + 1, last_seen = MAX(last_seen, excluded.last_seen)")?
                .execute(params![app_id, tag.as_str(), ts])?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn observed_profile_tags(&self, app_id: &str) -> Result<Vec<CapabilityTag>, StoreError> {
        let mut stmt = self
            .conn
            .prepare("SELECT tag FROM profile_observations WHERE app_id = ?1 ORDER BY tag")?;
        let rows = stmt
            .query_map([app_id], |r| r.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    pub fn upsert_profile(&self, p: &ProfileRecord) -> Result<(), StoreError> {
        self.conn.execute(
            "INSERT INTO profiles (app_id, category, expected, never, learning_until, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT (app_id) DO UPDATE SET
                 category       = excluded.category,
                 expected       = excluded.expected,
                 never          = excluded.never,
                 learning_until = excluded.learning_until,
                 updated_at     = excluded.updated_at",
            params![
                p.app_id,
                p.category,
                serde_json::to_string(&p.expected)?,
                serde_json::to_string(&p.never)?,
                p.learning_until,
                p.updated_at,
            ],
        )?;
        Ok(())
    }

    pub fn profile(&self, app_id: &str) -> Result<Option<ProfileRecord>, StoreError> {
        let row = self
            .conn
            .query_row(
                "SELECT category, expected, never, learning_until, updated_at
                 FROM profiles WHERE app_id = ?1",
                [app_id],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                        r.get::<_, Option<i64>>(3)?,
                        r.get::<_, i64>(4)?,
                    ))
                },
            )
            .optional()?;
        let Some((category, expected, never, learning_until, updated_at)) = row else {
            return Ok(None);
        };
        Ok(Some(ProfileRecord {
            app_id: app_id.to_string(),
            category,
            expected: from_json(&expected)?,
            never: from_json(&never)?,
            learning_until,
            updated_at,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upsert_and_fetch() {
        let s = Store::open_in_memory().unwrap();
        let mut p = ProfileRecord {
            app_id: "com.example.pdf".into(),
            category: "pdf_reader".into(),
            expected: vec![
                CapabilityTag::from_static("file:read_documents"),
                CapabilityTag::from_static("network:vendor_domain"),
            ],
            never: vec!["credential_access:*".into(), "injection:*".into()],
            learning_until: Some(10_000),
            updated_at: 1_000,
        };
        s.upsert_profile(&p).unwrap();
        assert_eq!(s.profile("com.example.pdf").unwrap().unwrap(), p);

        p.learning_until = None;
        p.expected
            .push(CapabilityTag::from_static("network:known_cdn"));
        p.updated_at = 2_000;
        s.upsert_profile(&p).unwrap();
        assert_eq!(s.profile("com.example.pdf").unwrap().unwrap(), p);
        assert_eq!(s.row_count("profiles").unwrap(), 1);
        assert!(s.profile("missing").unwrap().is_none());
    }
}
