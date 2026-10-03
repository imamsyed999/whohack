//! Schema migrations, keyed on `PRAGMA user_version`.
//!
//! `MIGRATIONS[i]` upgrades the schema from version `i` to `i + 1`. Never edit
//! a released migration; append a new one.

use rusqlite::Connection;

use super::StoreError;

const MIGRATIONS: &[&str] = &[V1, V2, V3];

pub const SCHEMA_VERSION: u32 = MIGRATIONS.len() as u32;

/// Every user table, for diagnostics and the `row_count` allowlist.
pub(super) const TABLES: &[&str] = &[
    "files",
    "processes",
    "events",
    "connections",
    "dns",
    "profiles",
    "alerts",
    "decisions",
    "feedback",
    "allowlist",
    "settings",
];

const V1: &str = r#"
CREATE TABLE files (
    id          INTEGER PRIMARY KEY,
    sha256      TEXT    NOT NULL,              -- lowercase hex
    path        TEXT    NOT NULL,
    origin      TEXT    NOT NULL,              -- JSON Origin
    sign        TEXT    NOT NULL,              -- JSON SignState
    yara_hits   TEXT    NOT NULL,              -- JSON array of rule names
    first_seen  INTEGER NOT NULL,
    UNIQUE (sha256, path)
);
CREATE INDEX files_sha256 ON files (sha256);

CREATE TABLE processes (
    id          INTEGER PRIMARY KEY,
    pid         INTEGER NOT NULL,
    ppid        INTEGER NOT NULL,
    start_time  INTEGER NOT NULL,
    exit_time   INTEGER,
    exe_sha256  TEXT    NOT NULL,
    exe_path    TEXT    NOT NULL,
    path_class  TEXT    NOT NULL,
    tainted     INTEGER NOT NULL,
    taint_root  INTEGER,
    app_id      TEXT    NOT NULL,
    UNIQUE (pid, start_time)                   -- PIDs are reused
);
CREATE INDEX processes_app_id ON processes (app_id);

CREATE TABLE events (
    id    INTEGER PRIMARY KEY,
    ts    INTEGER NOT NULL,
    pid   INTEGER NOT NULL,
    kind  TEXT    NOT NULL,                    -- EventKind::name()
    data  TEXT    NOT NULL                     -- JSON EventKind
);
CREATE INDEX events_ts      ON events (ts);
CREATE INDEX events_pid_ts  ON events (pid, ts);
CREATE INDEX events_kind_ts ON events (kind, ts);

CREATE TABLE connections (
    id           INTEGER PRIMARY KEY,
    event_id     INTEGER NOT NULL REFERENCES events (id) ON DELETE CASCADE,
    ts           INTEGER NOT NULL,
    pid          INTEGER NOT NULL,
    remote_ip    TEXT    NOT NULL,
    remote_port  INTEGER NOT NULL,
    proto        TEXT    NOT NULL,
    domain       TEXT,
    dns_before   INTEGER NOT NULL
);
CREATE INDEX connections_event   ON connections (event_id);
CREATE INDEX connections_pid_ts  ON connections (pid, ts);
CREATE INDEX connections_remote  ON connections (remote_ip, remote_port);

CREATE TABLE dns (
    id        INTEGER PRIMARY KEY,
    event_id  INTEGER NOT NULL REFERENCES events (id) ON DELETE CASCADE,
    ts        INTEGER NOT NULL,
    pid       INTEGER NOT NULL,
    name      TEXT    NOT NULL,
    answer    TEXT                             -- one row per answer; NULL if none
);
CREATE INDEX dns_event  ON dns (event_id);
CREATE INDEX dns_name   ON dns (name);
CREATE INDEX dns_answer ON dns (answer);

CREATE TABLE profiles (
    app_id          TEXT    PRIMARY KEY,
    category        TEXT    NOT NULL,
    expected        TEXT    NOT NULL,          -- JSON array of tags
    never           TEXT    NOT NULL,          -- JSON array of tag patterns
    learning_until  INTEGER,
    updated_at      INTEGER NOT NULL
);

CREATE TABLE alerts (
    id            INTEGER PRIMARY KEY,
    ts            INTEGER NOT NULL,
    pid           INTEGER NOT NULL,
    app_id        TEXT    NOT NULL,
    label         TEXT    NOT NULL,
    p_benign      REAL    NOT NULL,
    p_suspicious  REAL    NOT NULL,
    p_malicious   REAL    NOT NULL,
    tactic        TEXT    NOT NULL,
    severity      REAL    NOT NULL,
    action        TEXT    NOT NULL,
    tier          INTEGER NOT NULL,
    reasons       TEXT    NOT NULL,            -- JSON array of strings
    status        TEXT    NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'resolved'))
);
CREATE INDEX alerts_status_ts ON alerts (status, ts);

CREATE TABLE decisions (
    id              INTEGER PRIMARY KEY,
    ts              INTEGER NOT NULL,
    alert_id        INTEGER REFERENCES alerts (id) ON DELETE SET NULL,
    app_id          TEXT    NOT NULL,
    state_text      TEXT    NOT NULL,
    answers         TEXT    NOT NULL,          -- JSON
    model_name      TEXT    NOT NULL,
    model_revision  TEXT    NOT NULL,
    tier            INTEGER NOT NULL,
    final_action    TEXT    NOT NULL
);
CREATE INDEX decisions_alert ON decisions (alert_id);

CREATE TABLE feedback (
    id           INTEGER PRIMARY KEY,
    alert_id     INTEGER NOT NULL REFERENCES alerts (id) ON DELETE CASCADE,
    ts           INTEGER NOT NULL,
    user_action  TEXT    NOT NULL,
    note         TEXT
);
CREATE INDEX feedback_alert ON feedback (alert_id);

CREATE TABLE allowlist (
    id          INTEGER PRIMARY KEY,
    kind        TEXT    NOT NULL CHECK (kind IN ('app', 'destination', 'behavior')),
    app_id      TEXT    NOT NULL DEFAULT '',
    value       TEXT    NOT NULL DEFAULT '',
    created_at  INTEGER NOT NULL,
    UNIQUE (kind, app_id, value)
);
"#;

/// v2 (M2): the script an interpreter runs (see `ProcessInfo::script`).
const V2: &str = r#"
ALTER TABLE processes ADD COLUMN script_sha256 TEXT;
ALTER TABLE processes ADD COLUMN script_path   TEXT;
"#;

/// v3 (M7): service settings changed at runtime (e.g. the response mode
/// selected in the UI), overriding the config file.
const V3: &str = r#"
CREATE TABLE settings (
    key         TEXT PRIMARY KEY,
    value       TEXT NOT NULL,
    updated_at  INTEGER NOT NULL
);
"#;

/// Applies every pending migration in one transaction.
pub(super) fn migrate(conn: &mut Connection) -> Result<(), StoreError> {
    let current: u32 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    if current > SCHEMA_VERSION {
        return Err(StoreError::SchemaTooNew {
            found: current,
            supported: SCHEMA_VERSION,
        });
    }
    if current == SCHEMA_VERSION {
        return Ok(());
    }
    let tx = conn.transaction()?;
    for (i, sql) in MIGRATIONS.iter().enumerate().skip(current as usize) {
        tx.execute_batch(sql)?;
        tracing::info!(version = i + 1, "applied store migration");
    }
    // PRAGMA cannot take a bound parameter; the value is a compile-time constant.
    tx.execute_batch(&format!("PRAGMA user_version = {SCHEMA_VERSION}"))?;
    tx.commit()?;
    Ok(())
}
