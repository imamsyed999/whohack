//! `files` and `processes` tables.

use rusqlite::{Connection, OptionalExtension, params};

use super::{Store, StoreError, from_json, parse_col};
use crate::hex;
use crate::types::{FileInfo, PathClass, ProcessInfo};

/// Raw `files` columns, decoded outside the rusqlite row closure so JSON
/// errors surface as `StoreError::Json`.
struct FileRow {
    path: String,
    sha256: String,
    origin: String,
    sign: String,
    yara_hits: String,
    first_seen: i64,
}

impl FileRow {
    fn decode(self) -> Result<FileInfo, StoreError> {
        let sha256 = hex::decode32(&self.sha256).map_err(|_| StoreError::Corrupt {
            column: "files.sha256",
            value: self.sha256.clone(),
        })?;
        Ok(FileInfo {
            path: self.path,
            sha256,
            origin: from_json(&self.origin)?,
            sign: from_json(&self.sign)?,
            yara_hits: from_json(&self.yara_hits)?,
            first_seen: self.first_seen,
        })
    }
}

fn upsert_file_on(conn: &Connection, f: &FileInfo) -> Result<(), StoreError> {
    conn.execute(
        "INSERT INTO files (sha256, path, origin, sign, yara_hits, first_seen)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)
         ON CONFLICT (sha256, path) DO UPDATE SET
             origin     = excluded.origin,
             sign       = excluded.sign,
             yara_hits  = excluded.yara_hits,
             first_seen = MIN(first_seen, excluded.first_seen)",
        params![
            hex::encode(&f.sha256),
            f.path,
            serde_json::to_string(&f.origin)?,
            serde_json::to_string(&f.sign)?,
            serde_json::to_string(&f.yara_hits)?,
            f.first_seen,
        ],
    )?;
    Ok(())
}

impl Store {
    /// Inserts or refreshes a file. `first_seen` keeps the earliest value.
    pub fn upsert_file(&self, f: &FileInfo) -> Result<(), StoreError> {
        upsert_file_on(&self.conn, f)
    }

    /// The earliest-seen file with this digest, if any.
    pub fn file_by_hash(&self, sha256: &[u8; 32]) -> Result<Option<FileInfo>, StoreError> {
        let row = self
            .conn
            .query_row(
                "SELECT path, sha256, origin, sign, yara_hits, first_seen FROM files
                 WHERE sha256 = ?1 ORDER BY first_seen, id LIMIT 1",
                [hex::encode(sha256)],
                |r| {
                    Ok(FileRow {
                        path: r.get(0)?,
                        sha256: r.get(1)?,
                        origin: r.get(2)?,
                        sign: r.get(3)?,
                        yara_hits: r.get(4)?,
                        first_seen: r.get(5)?,
                    })
                },
            )
            .optional()?;
        row.map(FileRow::decode).transpose()
    }

    /// Records a process and its executable (atomically). Re-inserting the
    /// same `(pid, start_time)` updates the row. Returns the row id.
    pub fn insert_process(&self, p: &ProcessInfo) -> Result<i64, StoreError> {
        let tx = self.conn.unchecked_transaction()?;
        upsert_file_on(&tx, &p.exe)?;
        if let Some(script) = &p.script {
            upsert_file_on(&tx, script)?;
        }
        let id = tx.query_row(
            "INSERT INTO processes
                 (pid, ppid, start_time, exe_sha256, exe_path, path_class, tainted, taint_root, app_id,
                  script_sha256, script_path)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
             ON CONFLICT (pid, start_time) DO UPDATE SET
                 ppid          = excluded.ppid,
                 exe_sha256    = excluded.exe_sha256,
                 exe_path      = excluded.exe_path,
                 path_class    = excluded.path_class,
                 tainted       = excluded.tainted,
                 taint_root    = excluded.taint_root,
                 app_id        = excluded.app_id,
                 script_sha256 = excluded.script_sha256,
                 script_path   = excluded.script_path
             RETURNING id",
            params![
                p.pid,
                p.ppid,
                p.start_time,
                hex::encode(&p.exe.sha256),
                p.exe.path,
                p.path_class.as_str(),
                p.tainted,
                p.taint_root,
                p.app_id,
                p.script.as_ref().map(|f| hex::encode(&f.sha256)),
                p.script.as_ref().map(|f| f.path.as_str()),
            ],
            |r| r.get(0),
        )?;
        tx.commit()?;
        Ok(id)
    }

    /// Sets the exit time. Returns false if the process is unknown.
    pub fn mark_process_exit(
        &self,
        pid: u32,
        start_time: i64,
        exit_ts: i64,
    ) -> Result<bool, StoreError> {
        let n = self.conn.execute(
            "UPDATE processes SET exit_time = ?3 WHERE pid = ?1 AND start_time = ?2",
            params![pid, start_time, exit_ts],
        )?;
        Ok(n > 0)
    }

    /// Exit time of a process, `None` if it is unknown or still running.
    pub fn process_exit_time(&self, pid: u32, start_time: i64) -> Result<Option<i64>, StoreError> {
        let t: Option<Option<i64>> = self
            .conn
            .query_row(
                "SELECT exit_time FROM processes WHERE pid = ?1 AND start_time = ?2",
                params![pid, start_time],
                |r| r.get(0),
            )
            .optional()?;
        Ok(t.flatten())
    }

    pub fn process(&self, pid: u32, start_time: i64) -> Result<Option<ProcessInfo>, StoreError> {
        struct Row {
            ppid: u32,
            path_class: String,
            tainted: bool,
            taint_root: Option<u32>,
            app_id: String,
            file: FileRow,
            script: Option<FileRow>,
        }
        let row = self
            .conn
            .query_row(
                "SELECT p.ppid, p.path_class, p.tainted, p.taint_root, p.app_id,
                        f.path, f.sha256, f.origin, f.sign, f.yara_hits, f.first_seen,
                        s.path, s.sha256, s.origin, s.sign, s.yara_hits, s.first_seen
                 FROM processes p
                 JOIN files f ON f.sha256 = p.exe_sha256 AND f.path = p.exe_path
                 LEFT JOIN files s ON s.sha256 = p.script_sha256 AND s.path = p.script_path
                 WHERE p.pid = ?1 AND p.start_time = ?2",
                params![pid, start_time],
                |r| {
                    let script = match r.get::<_, Option<String>>(11)? {
                        Some(path) => Some(FileRow {
                            path,
                            sha256: r.get(12)?,
                            origin: r.get(13)?,
                            sign: r.get(14)?,
                            yara_hits: r.get(15)?,
                            first_seen: r.get(16)?,
                        }),
                        None => None,
                    };
                    Ok(Row {
                        ppid: r.get(0)?,
                        path_class: r.get(1)?,
                        tainted: r.get(2)?,
                        taint_root: r.get(3)?,
                        app_id: r.get(4)?,
                        file: FileRow {
                            path: r.get(5)?,
                            sha256: r.get(6)?,
                            origin: r.get(7)?,
                            sign: r.get(8)?,
                            yara_hits: r.get(9)?,
                            first_seen: r.get(10)?,
                        },
                        script,
                    })
                },
            )
            .optional()?;
        let Some(row) = row else { return Ok(None) };
        Ok(Some(ProcessInfo {
            pid,
            ppid: row.ppid,
            start_time,
            exe: row.file.decode()?,
            script: row.script.map(FileRow::decode).transpose()?,
            path_class: parse_col("processes.path_class", row.path_class, PathClass::parse)?,
            tainted: row.tainted,
            taint_root: row.taint_root,
            app_id: row.app_id,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Origin, SignState};

    fn file(path: &str, digest: u8, first_seen: i64) -> FileInfo {
        FileInfo {
            path: path.into(),
            sha256: [digest; 32],
            origin: Origin::Downloaded {
                url: Some("https://example.com/x".into()),
                referrer: None,
            },
            sign: SignState::Unsigned,
            yara_hits: vec![],
            first_seen,
        }
    }

    fn proc_(pid: u32, start_time: i64, exe: FileInfo) -> ProcessInfo {
        ProcessInfo {
            pid,
            ppid: 1,
            start_time,
            app_id: hex::encode(&exe.sha256),
            exe,
            script: None,
            path_class: PathClass::Downloads,
            tainted: true,
            taint_root: Some(pid),
        }
    }

    #[test]
    fn file_upsert_keeps_earliest_first_seen_and_updates_fields() {
        let s = Store::open_in_memory().unwrap();
        let f = file("/dl/a", 1, 2_000);
        s.upsert_file(&f).unwrap();
        let mut newer = file("/dl/a", 1, 5_000);
        newer.sign = SignState::Invalid;
        newer.yara_hits = vec!["eicar".into()];
        s.upsert_file(&newer).unwrap();
        let got = s.file_by_hash(&[1; 32]).unwrap().unwrap();
        assert_eq!(got.first_seen, 2_000);
        assert_eq!(got.sign, SignState::Invalid);
        assert_eq!(got.yara_hits, vec!["eicar".to_string()]);
        assert_eq!(s.row_count("files").unwrap(), 1);
        assert!(s.file_by_hash(&[9; 32]).unwrap().is_none());
    }

    #[test]
    fn same_hash_two_paths_returns_earliest() {
        let s = Store::open_in_memory().unwrap();
        s.upsert_file(&file("/b", 2, 300)).unwrap();
        s.upsert_file(&file("/a", 2, 100)).unwrap();
        assert_eq!(s.file_by_hash(&[2; 32]).unwrap().unwrap().path, "/a");
        assert_eq!(s.row_count("files").unwrap(), 2);
    }

    #[test]
    fn process_round_trip_and_exit() {
        let s = Store::open_in_memory().unwrap();
        let p = proc_(100, 1_000, file("/dl/tool", 3, 900));
        s.insert_process(&p).unwrap();
        assert_eq!(s.process(100, 1_000).unwrap().unwrap(), p);
        assert_eq!(s.process_exit_time(100, 1_000).unwrap(), None);
        assert!(s.mark_process_exit(100, 1_000, 2_000).unwrap());
        assert_eq!(s.process_exit_time(100, 1_000).unwrap(), Some(2_000));
        assert!(!s.mark_process_exit(100, 9_999, 2_000).unwrap());
        assert!(s.process(100, 9_999).unwrap().is_none());
    }

    #[test]
    fn process_with_script_round_trips() {
        let s = Store::open_in_memory().unwrap();
        let mut p = proc_(200, 1_000, file("/bin/sh", 6, 900));
        p.script = Some(file("/home/u/Downloads/x.sh", 7, 950));
        s.insert_process(&p).unwrap();
        assert_eq!(s.process(200, 1_000).unwrap().unwrap(), p);
        assert_eq!(s.row_count("files").unwrap(), 2);
    }

    #[test]
    fn reused_pid_is_a_separate_process() {
        let s = Store::open_in_memory().unwrap();
        let a = proc_(7, 1_000, file("/dl/a", 4, 900));
        let mut b = proc_(7, 5_000, file("/usr/bin/b", 5, 4_900));
        b.tainted = false;
        b.taint_root = None;
        b.path_class = PathClass::System;
        let id_a = s.insert_process(&a).unwrap();
        let id_b = s.insert_process(&b).unwrap();
        assert_ne!(id_a, id_b);
        assert_eq!(s.process(7, 1_000).unwrap().unwrap(), a);
        assert_eq!(s.process(7, 5_000).unwrap().unwrap(), b);
        // Re-inserting updates in place.
        let mut a2 = a.clone();
        a2.ppid = 42;
        assert_eq!(s.insert_process(&a2).unwrap(), id_a);
        assert_eq!(s.process(7, 1_000).unwrap().unwrap().ppid, 42);
        assert_eq!(s.row_count("processes").unwrap(), 2);
    }
}
