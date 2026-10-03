# M2 — Taint

Goal: know which executables and scripts came from the internet, and propagate that taint to
every process started from them, including their children.

Acceptance: a script marked as downloaded (Linux `user.xdg.origin.url` xattr, the same marker
browsers set) is run by an interpreter that starts child processes. The pipeline reports
`tainted = true` for the interpreter process and for its children, with
`taint_root` = the interpreter's PID.

## Crate `vigil-taint`

| Module | Responsibility |
|---|---|
| `path_class.rs` | Classify a path: Downloads / Temp / ProgramFiles / System / UserApp / Other (per-OS rules, pure functions) |
| `origin.rs` | Download origin. Parsers are pure (testable on every OS). Readers per OS: Windows `Zone.Identifier` ADS, macOS `com.apple.quarantine` xattr, Linux `user.xdg.origin.url` / `user.xdg.referrer.url` xattrs, with a Downloads-folder fallback |
| `hash.rs` | Streaming SHA-256, with a cache keyed by (path, size, mtime) |
| `sign/` | `windows.rs`: WinVerifyTrust (embedded signature, then catalog). `macos.rs`: `codesign` output parsing. `linux.rs`: dpkg/rpm package ownership, plus a dpkg md5sums integrity check |
| `scan.rs` | yara-x scanner over `rules/yara/*.yar` (ships with the EICAR test rule), size-limited |
| `analyzer.rs` | `FileAnalyzer`: path → `FileInfo` (origin, sha256, sign, yara hits), cached |
| `script.rs` | Find the script file an interpreter is running (bash/sh/python/powershell/wscript/cscript/mshta/cmd/node/osascript...) from its command line |
| `lineage.rs` | `ProcessTracker`: pid → `ProcessInfo`. Handles exec (same PID, new image), PID reuse, and a grace period for exited parents. Computes `tainted`, `taint_root`, and `app_id` |

## Taint rules

- A process is tainted if any of these holds:
  - its executable's origin is `Downloaded`;
  - it is an interpreter whose script target's origin is `Downloaded`;
  - its parent is tainted;
  - it was tainted before an exec.
- `taint_root` is the PID where the taint entered: its own PID for the first two cases, the
  parent's `taint_root` otherwise.
- `app_id` is the publisher for a `ValidTrusted` signature (`"sig:<publisher>"`), otherwise
  the sha256 hex.

## Pipeline change

The bus now carries `Observation { event, process: Option<Arc<ProcessInfo>>, tags }`, defined
in `vigil-core`; `tags` is filled in M3. `EventBus` becomes generic over its message type. The
taint stage runs after the enricher. The store writer persists processes (with taint) and
files.

## Tests

- **Path classes:** every class on Windows, macOS, and Linux.
- **Origin parsers:** zone identifier (zones 0–4, missing fields), the quarantine string,
  and the XDG attributes.
- **Hash:** the cache hits on an unchanged file and misses after modification.
- **Script detection:** quoted paths, interpreter switches, and non-interpreters.
- **Lineage:** downloaded exe → tainted, children → tainted, exec keeps taint, PID reuse
  resets it, a child of an exited parent within the grace period inherits, duplicate starts
  are idempotent.
- **Signatures:** Linux dpkg ownership (when dpkg is present) and the `codesign` output
  parser.
- **YARA:** the EICAR test string matches, a benign file does not, and oversized files are
  skipped.
- **Acceptance (Linux live):** procfs collector → enricher → taint stage. A downloaded-marked
  script spawns `sleep` children, and all of them are tainted.

## Outcome (2026-10-03)

Status: **implemented**.

- **Acceptance passes live** (`crates/vigil-service/tests/taint_acceptance.rs`, WSL).
  The interpreter running a download-marked script is tainted, with root = itself, the
  script detected, and `app_id = script:<sha256>`. Both of its child processes are
  tainted with the same root.
- **Unit tests:** 30 in `vigil-taint`. They cover path classes on all three OSes, origin
  parsers, the hash cache, script detection, lineage (exec, PID reuse, exit grace,
  ancestry), the dpkg ownership check (live on Ubuntu), the `codesign` parser, and YARA
  (the EICAR marker is scanned in memory, so no test pattern is ever written to disk).
- **Windows WinVerifyTrust and catalog code:** clippy is clean for `x86_64-pc-windows-msvc`.
  The runtime test (cmd.exe → ValidTrusted "Microsoft…", temp file → Unsigned) runs on
  the CI Windows runner.
- **Core changes:**
  - `ProcessInfo.script` was added (documented in `types/process.rs`), with store
    migration v2.
  - `EventBus` is now generic, and the service bus carries `Observation`s.
  - `paths.rules_dir` was added to the config.
- **yara-x** pulls in wasmtime. `Apache-2.0 WITH LLVM-exception` is allowed (it is
  Apache-2.0 plus a permission). Advisories that don't apply to yara-x's use are ignored
  with reasons in `deny.toml` and tracked in the backlog.
