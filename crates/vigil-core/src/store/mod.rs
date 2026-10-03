//! SQLite event store (SPEC §15).
//!
//! WAL mode, foreign keys on, schema versioned by `PRAGMA user_version`.
//! The store is synchronous; async callers own it from a dedicated task or
//! `spawn_blocking`. Each table group lives in its own module as an
//! `impl Store` block.

mod alerts;
mod allowlist;
mod events;
mod files;
mod profiles;
mod schema;
mod settings;

use std::path::Path;

use rusqlite::Connection;
use serde::de::DeserializeOwned;

pub use alerts::{AlertRecord, AlertStatus, DecisionRecord, FeedbackRecord};
pub use profiles::ProfileRecord;
pub use schema::SCHEMA_VERSION;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error("cannot create database directory {path}")]
    Io {
        path: std::path::PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("database schema version {found} is newer than this build supports ({supported})")]
    SchemaTooNew { found: u32, supported: u32 },
    #[error("corrupt value in column {column}: {value:?}")]
    Corrupt { column: &'static str, value: String },
}

#[derive(Debug)]
pub struct Store {
    conn: Connection,
}

impl Store {
    /// Opens (creating if needed) the database at `path`, enables WAL, and migrates.
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
            std::fs::create_dir_all(dir).map_err(|source| StoreError::Io {
                path: dir.to_path_buf(),
                source,
            })?;
        }
        Store::init(Connection::open(path)?)
    }

    /// In-memory database for tests. (WAL is not available in memory.)
    pub fn open_in_memory() -> Result<Self, StoreError> {
        Store::init(Connection::open_in_memory()?)
    }

    fn init(conn: Connection) -> Result<Self, StoreError> {
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        // journal_mode returns the resulting mode as a row.
        let _mode: String = conn.query_row("PRAGMA journal_mode = WAL", [], |r| r.get(0))?;
        conn.execute_batch("PRAGMA synchronous = NORMAL; PRAGMA foreign_keys = ON;")?;
        let mut store = Store { conn };
        schema::migrate(&mut store.conn)?;
        Ok(store)
    }

    pub fn schema_version(&self) -> Result<u32, StoreError> {
        Ok(self
            .conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))?)
    }

    pub fn journal_mode(&self) -> Result<String, StoreError> {
        Ok(self
            .conn
            .query_row("PRAGMA journal_mode", [], |r| r.get(0))?)
    }

    /// User tables, sorted by name.
    pub fn table_names(&self) -> Result<Vec<String>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name",
        )?;
        let names = stmt
            .query_map([], |r| r.get(0))?
            .collect::<Result<Vec<String>, _>>()?;
        Ok(names)
    }

    /// Deletes events older than `older_than_ms` (Unix ms). Their derived
    /// `connections` and `dns` rows are removed by `ON DELETE CASCADE`.
    /// Returns the number of events deleted.
    pub fn prune_events(&self, older_than_ms: i64) -> Result<usize, StoreError> {
        Ok(self
            .conn
            .execute("DELETE FROM events WHERE ts < ?1", [older_than_ms])?)
    }

    /// Row count of a table; used by diagnostics and tests.
    pub fn row_count(&self, table: &str) -> Result<i64, StoreError> {
        // Table names cannot be bound as parameters; only allow known tables.
        if !schema::TABLES.contains(&table) {
            return Err(StoreError::Corrupt {
                column: "table",
                value: table.to_string(),
            });
        }
        Ok(self
            .conn
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))?)
    }
}

fn from_json<T: DeserializeOwned>(s: &str) -> Result<T, StoreError> {
    Ok(serde_json::from_str(s)?)
}

fn parse_col<T>(
    column: &'static str,
    value: String,
    parse: impl FnOnce(&str) -> Option<T>,
) -> Result<T, StoreError> {
    parse(&value).ok_or(StoreError::Corrupt { column, value })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_all_tables() {
        let s = Store::open_in_memory().unwrap();
        let mut expected: Vec<String> = schema::TABLES.iter().map(|t| t.to_string()).collect();
        expected.sort();
        assert_eq!(s.table_names().unwrap(), expected);
        assert_eq!(expected.len(), 11);
        assert_eq!(s.schema_version().unwrap(), SCHEMA_VERSION);
    }

    #[test]
    fn file_db_uses_wal_and_reopen_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("vigil.db");
        {
            let s = Store::open(&path).unwrap();
            assert_eq!(s.journal_mode().unwrap(), "wal");
            assert_eq!(s.schema_version().unwrap(), SCHEMA_VERSION);
        }
        let s = Store::open(&path).unwrap();
        assert_eq!(s.schema_version().unwrap(), SCHEMA_VERSION);
        assert_eq!(s.table_names().unwrap().len(), 11);
    }

    #[test]
    fn refuses_newer_schema() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.db");
        {
            let c = Connection::open(&path).unwrap();
            c.execute_batch(&format!("PRAGMA user_version = {}", SCHEMA_VERSION + 1))
                .unwrap();
        }
        match Store::open(&path) {
            Err(StoreError::SchemaTooNew { found, supported }) => {
                assert_eq!(found, SCHEMA_VERSION + 1);
                assert_eq!(supported, SCHEMA_VERSION);
            }
            other => panic!("expected SchemaTooNew, got {other:?}"),
        }
    }

    #[test]
    fn row_count_rejects_unknown_table() {
        let s = Store::open_in_memory().unwrap();
        assert_eq!(s.row_count("events").unwrap(), 0);
        assert!(s.row_count("events; DROP TABLE files").is_err());
    }
}
