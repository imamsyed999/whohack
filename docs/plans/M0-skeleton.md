# M0 — Skeleton

> **Status (2026-10-03): implemented.** `fmt`, `clippy -D warnings`, 64 tests, and `cargo deny`
> all pass on Linux (WSL Ubuntu, Rust 1.99). Windows and macOS are verified by CI once the repo is
> pushed. See [Outcome](#outcome) at the end.

Goal: a Cargo workspace with the core types, config, SQLite store, event bus, logging,
and CI on Windows, macOS, and Linux.

Acceptance: `cargo test --workspace` is green on all three OSes in CI, and `cargo fmt --check`
and `cargo clippy -D warnings` are clean.

Toolchain: Rust stable 1.99 (edition 2024), pinned to `stable` in `rust-toolchain.toml`.

## Scope

In scope: `vigil-core` (library) and `vigil-service` (binary). Nothing else.

Out of scope: every other crate in SPEC §6 is created in the milestone that first needs it.
Creating empty crates now would only add placeholder code. Deferred items go in
`docs/backlog.md`.

## Files

```
Cargo.toml                    # workspace: members = ["crates/*"], shared deps, lints
rust-toolchain.toml           # channel = "stable", components rustfmt + clippy
deny.toml                     # cargo-deny: license allowlist + advisories
.gitignore
.github/workflows/ci.yml      # fmt + clippy + test on ubuntu/windows/macos; cargo-deny job
CLAUDE.md                     # points every session at docs/vigil-master-prompt.md + working rules
README.md                     # what Vigil is, status, the honest constraints from SPEC §3
docs/backlog.md
docs/plans/M0-skeleton.md     # this file
config/vigil.example.toml     # documented example config (same output as --print-default-config)

crates/vigil-core/
  Cargo.toml
  src/lib.rs                  # module wiring + re-exports
  src/time.rs                 # now_ms(), the timestamp convention
  src/hex.rs                  # serde helper: [u8; 32] <-> lowercase hex string
  src/types/mod.rs
  src/types/os.rs             # Os, Os::current()
  src/types/file.rs           # Origin, SignState, PathClass, FileInfo
  src/types/process.rs        # ProcessInfo
  src/types/event.rs          # Proto, SensitiveClass, PersistenceKind, EventKind, Event
  src/types/tag.rs            # CapabilityTag
  src/types/verdict.rs        # VerdictLabel, Verdict, Action (ordered), ResponseMode
  src/types/allow.rs          # AllowEntry (app / destination / behavior)
  src/config.rs               # Config + sub-configs, load/validate/defaults, per-OS paths
  src/bus.rs                  # EventBus: mpsc ingest -> broadcast fan-out
  src/store/mod.rs            # Store: open, WAL/pragmas, prune, re-exports
  src/store/schema.rs         # migrations keyed on PRAGMA user_version
  src/store/files.rs          # files + processes tables
  src/store/events.rs         # events (+ derived connections, dns rows)
  src/store/alerts.rs         # alerts, decisions, feedback
  src/store/allowlist.rs      # allowlist
  src/store/profiles.rs       # profiles

crates/vigil-service/
  Cargo.toml
  src/main.rs                 # CLI entry point
  src/cli.rs                  # clap definitions
  src/logging.rs              # tracing-subscriber setup (stderr + optional rolling file)
  tests/cli.rs                # runs the built binary end to end
```

## Core types (SPEC §7)

Implemented as written. Every type derives `Debug, Clone, PartialEq, Serialize, Deserialize`.
Enums use `snake_case` serde names. `EventKind` is internally tagged (`{"type": "net_connect", ...}`).

Additions SPEC §7 references but does not define:

- `Proto { Tcp, Udp }`
- `SensitiveClass { BrowserPasswords, Keychain, SshKeys, CryptoWallet, Lsass, Documents, PersistenceLocation, Other }`
- `PersistenceKind { RunKey, StartupFolder, ScheduledTask, Service, LaunchAgent, LoginItem, Cron, SystemdUnit, ShellRc }`
  (one variant per `persistence:*` tag in §9)
- `ResponseMode { Monitor, Prompt, Auto }` (default `Prompt`), used by config now and by fusion later
- `AllowEntry { App { app_id }, Destination { value }, Behavior { app_id, tag } }` (SPEC §11)

Two deviations from SPEC §7, which I'll also note in the code:

1. `CapabilityTag(pub &'static str)` becomes `CapabilityTag(pub Cow<'static, str>)`.
   serde can't deserialize into `&'static str`, and tags must round-trip through SQLite and IPC.
   A `const fn CapabilityTag::from_static(&'static str)` keeps the taxonomy table zero-allocation.
2. `FileInfo.sha256` stays `[u8; 32]` but serializes as a 64-character hex string, not a
   32-number JSON array.

Other conventions:

- **Timestamps:** every `i64` timestamp (`ts`, `start_time`, `first_seen`) is milliseconds since
  the Unix epoch, UTC.
- **`Action` ordering:** `Action` derives `Ord` in severity order
  `Allow < AskUser < BlockNetwork < SuspendAndAsk < KillAndQuarantine`, so the fusion rule
  "final action = max(rule floor, model action)" (§10.6) is just `max()`.

## Config (`vigil-core::config`)

The config file is TOML. Missing fields fall back to defaults, and unknown fields are rejected so
a typo can't silently do nothing. Relative paths resolve against the config file's directory.

```toml
mode = "prompt"                 # monitor | prompt | auto

[paths]
data_dir = "<per-OS default>"
log_dir  = "<per-OS default>"

[storage]
db_file = "vigil.db"            # relative to data_dir, or absolute
event_retention_days = 30       # 1..=3650

[logging]
level  = "info"                 # tracing EnvFilter directive, e.g. "info,vigil_core=debug"
format = "text"                 # text | json
to_file = true                  # daily-rolling file in log_dir, plus stderr
```

Per-OS defaults:

| | config file | data_dir | log_dir |
|---|---|---|---|
| Windows | `%ProgramData%\Vigil\config.toml` | `%ProgramData%\Vigil\data` | `%ProgramData%\Vigil\logs` |
| Linux | `/etc/vigil/config.toml` | `/var/lib/vigil` | `/var/log/vigil` |
| macOS | `/Library/Application Support/Vigil/config.toml` | `/Library/Application Support/Vigil/data` | `/Library/Logs/Vigil` |

Interface:

```rust
impl Config {
    pub fn default_for_os() -> Self;
    pub fn default_path() -> PathBuf;
    pub fn load(path: &Path) -> Result<Self, ConfigError>;  // parse + resolve + validate
    pub fn from_toml_str(s: &str, base_dir: &Path) -> Result<Self, ConfigError>;
    pub fn validate(&self) -> Result<(), ConfigError>;
    pub fn to_toml_string(&self) -> String;
    pub fn db_path(&self) -> PathBuf;
}
```

Detection thresholds (§10 fusion), feed settings, and similar options are added to `Config`
in the milestones that use them.

## Event bus (`vigil-core::bus`)

```rust
pub struct EventBus { /* broadcast::Sender<Arc<Event>> */ }
impl EventBus {
    pub fn new(capacity: usize) -> Self;
    pub fn subscribe(&self) -> broadcast::Receiver<Arc<Event>>;
    /// Returns the Sender handed to collectors (matches the Collector trait's mpsc::Sender<Event>)
    /// and a task that forwards to all subscribers until every sender is dropped; yields the count forwarded.
    pub fn spawn_ingest(&self, buffer: usize) -> (mpsc::Sender<Event>, JoinHandle<u64>);
}
```

## SQLite store (`vigil-core::store`, SPEC §15)

This uses `rusqlite` with the `bundled` feature, so SQLite builds from source with no system
library needed on any OS.

On open, the store sets `journal_mode=WAL`, `synchronous=NORMAL`, `foreign_keys=ON`, and
`busy_timeout=5000`. Schema migrations are versioned by `PRAGMA user_version` and are idempotent.

| Table | Key columns |
|---|---|
| `files` | `sha256` hex, `path`, `origin` JSON, `sign` JSON, `yara_hits` JSON, `first_seen`; unique (`sha256`, `path`) |
| `processes` | `pid`, `ppid`, `start_time`, `exit_time`, `exe_sha256`, `exe_path`, `path_class`, `tainted`, `taint_root`, `app_id`; unique (`pid`, `start_time`) because PIDs are reused |
| `events` | `ts`, `pid`, `kind` (discriminant, indexed), `data` JSON; indexes on `ts` and (`pid`, `ts`) |
| `connections` | written alongside each `NetConnect` event in the same transaction |
| `dns` | written alongside each `DnsQuery` event in the same transaction |
| `profiles` | `app_id` PK, `category`, `expected` JSON, `never` JSON, `learning_until`, `updated_at` |
| `alerts` | `ts`, `pid`, `app_id`, `label`, `p_benign`, `p_suspicious`, `p_malicious`, `tactic`, `severity`, `action`, `tier`, `reasons` JSON, `status` (open/resolved) |
| `decisions` | `alert_id` FK, `app_id`, `state_text`, `answers` JSON, `model_name`, `model_revision`, `tier`, `final_action` |
| `feedback` | `alert_id` FK, `ts`, `user_action`, `note` |
| `allowlist` | `kind`, `app_id` (`''` when not app-scoped), `value`, `created_at`; unique (`kind`, `app_id`, `value`) |

Interface. The store is synchronous; the service puts it behind a dedicated writer task later.

```rust
impl Store {
    pub fn open(path: &Path) -> Result<Self, StoreError>;
    pub fn open_in_memory() -> Result<Self, StoreError>;          // tests
    pub fn schema_version(&self) -> Result<u32, StoreError>;
    pub fn journal_mode(&self) -> Result<String, StoreError>;
    pub fn table_names(&self) -> Result<Vec<String>, StoreError>;
    pub fn prune_events(&self, older_than_ms: i64) -> Result<usize, StoreError>; // events+connections+dns
    // files / processes
    pub fn upsert_file(&self, f: &FileInfo) -> Result<(), StoreError>;
    pub fn file_by_hash(&self, sha256: &[u8; 32]) -> Result<Option<FileInfo>, StoreError>;
    pub fn insert_process(&self, p: &ProcessInfo) -> Result<i64, StoreError>;
    pub fn mark_process_exit(&self, pid: u32, start_time: i64, exit_ts: i64) -> Result<bool, StoreError>;
    pub fn process(&self, pid: u32, start_time: i64) -> Result<Option<ProcessInfo>, StoreError>;
    // events
    pub fn insert_event(&self, e: &Event) -> Result<i64, StoreError>;
    pub fn events_for_pid(&self, pid: u32, since_ms: i64) -> Result<Vec<Event>, StoreError>;
    // alerts / decisions / feedback
    pub fn insert_alert(&self, ts: i64, pid: u32, app_id: &str, v: &Verdict) -> Result<i64, StoreError>;
    pub fn resolve_alert(&self, alert_id: i64) -> Result<bool, StoreError>;
    pub fn insert_decision(&self, d: &DecisionRecord) -> Result<i64, StoreError>;
    pub fn insert_feedback(&self, alert_id: i64, ts: i64, user_action: Action, note: Option<&str>) -> Result<i64, StoreError>;
    // allowlist
    pub fn allow(&self, e: &AllowEntry) -> Result<bool, StoreError>;   // false if already present
    pub fn disallow(&self, e: &AllowEntry) -> Result<bool, StoreError>;
    pub fn is_allowed(&self, e: &AllowEntry) -> Result<bool, StoreError>;
    pub fn allowlist(&self) -> Result<Vec<AllowEntry>, StoreError>;
    // profiles
    pub fn upsert_profile(&self, p: &ProfileRecord) -> Result<(), StoreError>;
    pub fn profile(&self, app_id: &str) -> Result<Option<ProfileRecord>, StoreError>;
}
```

`DecisionRecord` and `ProfileRecord` are plain storage structs defined in `store/`. The richer
domain types (`Answer`, `Profile`) arrive in M3 and M6 and convert into these records.

## Logging (`vigil-service::logging`)

The service uses `tracing` with `tracing-subscriber` (EnvFilter, text or JSON format) to stderr,
plus an optional `tracing-appender` daily-rolling file in `log_dir`. `RUST_LOG` overrides the
configured level. Library crates use only the `tracing` macros.

## Service CLI (M0 surface)

```
vigil-service [--config PATH] --print-default-config   # emit default TOML for this OS
vigil-service [--config PATH] --check-config           # load + validate (incl. log filter); exit 0/1
vigil-service [--config PATH] --init-db                # create/migrate DB, print version, journal mode, tables
```

`--monitor` arrives in M1. I'm leaving out a long-running "run" mode until there are collectors
to run; an idle loop would be a placeholder.

## Dependencies (all MIT / Apache-2.0; none make network calls)

| Crate | Purpose |
|---|---|
| serde, serde_json, toml | serialization, config |
| thiserror | `ConfigError`, `StoreError` in `vigil-core` |
| anyhow | errors in the binary, and in collector/responder traits later |
| tokio (`sync`, `rt`, `macros`) | event bus |
| tracing, tracing-subscriber (`env-filter`, `json`), tracing-appender | logging |
| rusqlite (`bundled`) | SQLite; the bundled SQLite source is public domain |
| clap (`derive`) | CLI |
| tempfile (dev) | tests |

**License question for you.** The Rust ecosystem's `unicode-ident` crate (pulled in by
serde/clap/tokio derive macros, so effectively unavoidable) is licensed
`(MIT OR Apache-2.0) AND Unicode-3.0`. Unicode-3.0 is a permissive license, but it is not on
your MIT/Apache/BSD list. I plan to allow `Unicode-3.0` in `deny.toml` alongside
MIT/Apache-2.0/BSD-2/BSD-3/ISC/Zlib, with ISC and Zlib also permissive and common in the
dependency tree. Every other license fails CI.

## Tests

`vigil-core`:

- **types:** serde round-trip for every `EventKind` variant, `Origin`, and `SignState`. `sha256`
  serializes as hex and rejects bad hex or the wrong length. `Action` ordering and `max()`.
  `CapabilityTag` round-trips and `from_static` is const. `Os::current()` matches `cfg!`.
- **config:** defaults validate. Partial TOML gets defaults filled in. Unknown keys are rejected.
  Bad mode and `retention = 0` are rejected. Relative paths resolve against the base dir.
  `to_toml_string` → `from_toml_str` round-trips.
- **bus:** two subscribers each receive every event in order. The ingest task ends and reports
  its count when all senders drop. A lagging subscriber reports `Lagged` without blocking the others.
- **store:**
  - Migrations are idempotent when the store is reopened. A file-backed DB reports `wal`. All 10
    tables exist.
  - File upsert and fetch work. Process insert, exit, and fetch work, and the same pid with a
    different `start_time` is stored as a separate process.
  - Event round-trip works for each kind. `NetConnect` writes a `connections` row and `DnsQuery`
    writes `dns` rows. `prune_events` removes old rows from all three tables and keeps new ones.
  - Alert → decision → feedback chains through foreign keys, and feedback on a missing alert
    fails. Allowlist add, duplicate, check, and remove work. Profile upsert and fetch work.

`vigil-service` (`tests/cli.rs`, which runs the real binary):

- `--print-default-config` output parses back as a valid config.
- `--check-config` exits 0 on a good file. It exits non-zero with a readable message on a bad
  file and on a bad log filter.
- `--init-db` against a temp config creates the DB and prints `journal_mode=wal` and all tables.

## CI (`.github/workflows/ci.yml`)

The workflow runs on push and pull request.

- **Matrix** of `ubuntu-latest`, `windows-latest`, and `macos-latest`. Each runs
  `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings`, and
  `cargo test --workspace`, with `Swatinem/rust-cache`.
- **`deny` job** on ubuntu runs `EmbarkStudios/cargo-deny-action` for licenses and advisories.

Windows ARM64 and macOS Intel runners go in the backlog; for now I'm only adding the three
standard runners.

## Demo (proves acceptance locally)

```
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo run -p vigil-service -- --config <tmp>/config.toml --init-db
```

I can only run Windows locally. Green macOS/Linux CI needs the repo pushed to GitHub, and I
won't push without your go-ahead.

## Housekeeping decisions

- **Git:** I'll run `git init` locally with a `.gitignore`. I won't make any commits unless you ask.
- **CLAUDE.md:** it will point to `docs/vigil-master-prompt.md` as the spec rather than duplicate it.

## Outcome

Decisions confirmed by the maintainer:

- **Project license:** `MIT OR Apache-2.0` (open source, "free for everyone"); see `LICENSE-MIT` and `LICENSE-APACHE`.
- **Dependency allowlist (`deny.toml`):** MIT, Apache-2.0, BSD-2/3, ISC, Zlib, Unicode-3.0.
- **Git:** `git init` done locally; nothing is committed or pushed yet.

What changed from the plan:

- **`Cli::action()`:** the selector is named `action()` rather than `command()`, which
  collided with clap's `CommandFactory::command()`.
- **Read-back helpers:** I added `Store::process_exit_time`, `domain_for_ip` (persistent IP→domain
  fallback for DNS attribution), `alert`, `open_alerts`, `decisions_for_alert`,
  `feedback_for_alert`, and `row_count` to make the store round-trip-testable. These are
  needed by M1 and M7 anyway.
- **Error messages:** errors no longer repeat their source error in the message.
  `#[error(transparent)]` or a `#[source]` field is used instead, so `{:#}` chains print once.
- **Example config test:** a test keeps `config/vigil.example.toml` parseable and in sync with
  the defaults.

Environment finding:

- **Smart App Control blocks one build script.** The maintainer's Windows machine has Smart
  App Control enforcing (`VerifiedAndReputablePolicyState=1`). It blocks the compiled
  `libsqlite3-sys` build script (os error 4551). Other build scripts, including a minimal
  `cc` one, run fine.
- **Workaround:** per the working rules, the setting was left alone. Verification ran in WSL
  Ubuntu instead, and Windows coverage comes from CI.

Test counts: `vigil-core` has 52 unit tests, and `vigil-service` has 5 unit tests and 7
end-to-end CLI tests.
