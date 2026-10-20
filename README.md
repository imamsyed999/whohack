# whohack

whohack is an experimental security layer focused on dangerous behavior from
downloaded programs and apps opening downloaded documents, video and audio. It
tracks their processes and network activity, alerts on suspicious evidence, and
can pause the responsible process and quarantine an identified dangerous input.
Windows is the current primary deliverable; coverage depends on enabled sensors.

It runs entirely on your machine, on ordinary hardware with no GPU, and works alongside
your OS's built-in antivirus (Microsoft Defender, XProtect, ...). It never replaces or
disables that antivirus.

The service does not need Python, training libraries or model downloads to run.
Local model research uses Laya/OpenDecider; no model is enabled by default, and
the development fine-tunes have not passed detection-quality checks. See
[download protection and resource limits](docs/download-protection.md).

The product and source packages are now named **whohack** (version 0.1.1).
Existing `.vigil` data and `vigil.db` remain compatible storage locations, so the
rename preserves configuration, history and quarantine. The
[rename and expanded training record](docs/plans/M14-whohack-and-data.md) records
the new builds and their limits. Unsigned previews may be blocked by Windows
Application Control; they require an approved signing/distribution path.

> **Status: native Windows monitoring preview, in development.** Implemented:
>
> - collect process and network activity on Linux, Windows, and macOS (limited mode);
> - work out which programs came from the internet, and taint everything they start;
> - tag observed capabilities, persist events and per-app behavior profiles;
> - evaluate local YAML rules and category violations, store alerts, and notify the tray;
> - manage app categories and trust decisions from the tray;
> - load expiring threat feeds and pinned local ONNX/typed-decision models;
> - offer optional Windows/Linux response, recovery journals and inert quarantine;
> - replay harmless fixtures without changing the OS.
>
> The Windows preview defaults to **monitor mode with response disabled**. It
> observes Windows processes and TCP connections without administrator rights.
> ETW file/registry sensors, optional existing-Sysmon events and Linux fanotify
> are implemented; ETW/fanotify file acceptance passed, while other privileged
> providers still need live acceptance. Trained-model
> quality gates have **not passed**; no model is enabled by default. This is not
> production protection. See [remaining release gates](docs/backlog.md).

The [2026-10-15 readiness report](docs/readiness-2026-10-15.md) records current
native tests, confirmation-only response, build-specific acceptance limits,
Linux packages and model evaluation. Code is MIT OR Apache-2.0; third-party
dependencies retain their own licenses. Both dependency audits pass with reviewed
exceptions. Production security and signed distribution remain incomplete.

The subsequent [production-use verification](docs/production-verification-2026-10-15.md)
checks the running release, real UI and sensor-to-alert/manual suspend-resume path.
It confirms working integration and records the remaining production blockers.

## Run locally

### Windows

Double-click **`Start whohack.cmd`** in the repository root. It starts the native
Windows service and tray window, monitoring **Windows host processes and TCP**.
WebView2, the Visual C++ x64 runtime and built Windows executables are required.
The native launcher and packaged app need **no Python, Rust or WSL** to run.
From PowerShell:

```powershell
& '.\Start whohack.cmd'          # start the service and open the tray window
& '.\Start whohack.cmd' status   # check native Windows collection
& '.\Start whohack.cmd' stop     # gracefully stop this preview and tray
```

Configuration, rules, logs and data live in `.vigil/windows/`, separate from WSL.
Existing configuration is preserved. This preview needs no administrator rights
and does not install an auto-start system service. Closing the window keeps its
tray icon active; use that icon to reopen it.

To build from source, use `& '.\Start whohack.cmd' build` (Python 3.11+ build helper)
or the native Cargo commands in [building details](docs/building.md#windows).
Windows runtime tests pass here; Application Control can intermittently reject
unsigned build/test executables. The optional build alternative is
`& '.\Start whohack.cmd' build --cross`: WSL compiles a **Windows `.exe`** against the
existing SDK, including the native tray. **Running whohack does not use WSL.**
CI produces an unsigned portable ZIP and per-user MSI with the service, tray and
native launcher. The MSI installs under `%LOCALAPPDATA%\Programs\whohack` and adds
Start-menu launch/stop shortcuts. It does not install a SYSTEM service. Installer
signing and clean-machine install/upgrade/uninstall acceptance remain release gates.

### Linux / WSL

From the repository root:

```sh
# In WSL, keep Rust build output on its native filesystem:
export CARGO_TARGET_DIR="$HOME/whohack-target"
cargo build --workspace --locked
cargo run -p whohack-service -- --init-local
cargo run -p whohack-service -- --config whohack.local.toml --check-config
cargo run -p whohack-service -- --config whohack.local.toml --write-manifest
cargo run -p whohack-service -- --config whohack.local.toml --run
```

`--init-local` creates a private development configuration and refuses to overwrite
it. Reuse it on subsequent launches. No administrator privileges or system-service
installation are required. In another terminal:

```sh
cargo run -p whohack-service -- --config whohack.local.toml --status
WHOHACK_CONFIG="$PWD/whohack.local.toml" cargo run --manifest-path ui/src-tauri/Cargo.toml -- --show
```

To explicitly monitor Linux inside WSL, use the separate Linux launcher:

```powershell
wsl -d Ubuntu -- bash tools/local-launch.sh start
```

Use `status` to check it, `stop` to stop processes launched by this checkout, or
`start-service` for the service alone. **WSL monitors Linux processes inside WSL, not
Windows host processes.** Native Windows protection requires a native Windows build.
See [building details](docs/building.md) for prerequisites and troubleshooting.

Try detection without touching real secrets or changing system settings:

```sh
python3 tools/beacon-sim/beacon_sim.py --fast --output beacon-replay.jsonl
cargo run -p whohack-service -- --replay beacon-replay.jsonl --category pdf_reader
```

This opens four harmless localhost connections and reads/writes dummy files in a
temporary directory. `--fast` uses logical five-second intervals for offline replay.
The output includes tags, unexpected behavior, rule matches, and recommended actions.
Replay never applies those actions or writes fixture alerts into the live database.

## How it works

Downloaded documents, video and audio now have bounded input attribution and an
independent opt-in **automatic danger pause**. Native file monitoring covers
already-running readers; polling only supplies launch-argument association.
See [download protection, setup and tested limits](docs/download-protection.md).

1. **Taint.** whohack knows which files came from the internet and tracks every process
   started from them, and those processes' children.
2. **Behavior.** It watches network connections, sensitive-file access (browser password
   stores, SSH keys, wallets), persistence, and child processes.
3. **Expectation.** Each app gets an expected-behavior profile for its category. A
   mismatch is the core signal of a hidden hack.
4. **Network reputation.** It checks destinations against threat feeds, and flags raw-IP
   connections with no DNS lookup, first-seen destinations, and beaconing.
5. **Decision.** Hard rules, a fast anomaly score, and a small local *typed-decision*
   model classify activity as benign, suspicious, or malicious.
6. **Response.** When explicitly enabled, it can block network access, ask you,
   suspend a process or kill and quarantine it. Blocks and suspensions can be
   released and files restored; killing a process loses its running state.

## Honest constraints

- **No system detects 100% of attacks.** whohack aims for high detection of the behaviors that
  matter most (credential theft, persistence, command-and-control, ransomware, data
  exfiltration) with few false alarms.
- **Malware running with admin/root rights can attack user-mode tools.** whohack adds
  self-protection but is not tamper-proof.
- **When uncertain, whohack prefers safe, reversible actions** (block network + ask you)
  over destructive ones (kill + quarantine).

## Privacy

No user data leaves your machine. The only network traffic is:

- threat-feed downloads;
- an **opt-in** VirusTotal lookup that sends **file hashes only**, using your own API key.

whohack never uploads files.

## Building

You need Rust stable (the version is pinned by `rust-toolchain.toml`) and a C compiler
(for the bundled SQLite).

```sh
cargo test --workspace
cargo run -p whohack-service -- --print-default-config > whohack.toml
cargo run -p whohack-service -- --config whohack.toml --check-config
sudo ./target/debug/whohack-service --config whohack.toml --monitor   # live connections per process
sudo ./target/debug/whohack-service --config whohack.toml --run       # the service (IPC for the tray app)
```

The tray app lives in `ui/`; build it with `cargo build` in `ui/src-tauri`.
`packaging/README.md` covers installing the service on each OS, and `docs/building.md`
covers the eBPF build.

`config/whohack.example.toml` documents every option.

> **Windows with Smart App Control on:** Smart App Control may block one of the
> freshly compiled build scripts with *"An Application Control policy has blocked this
> file"* (os error 4551). The optional cross-build produces native Windows executables;
> CI is another build option. Neither guarantees that policy permits an unsigned
> executable on every PC. Do not weaken OS security settings to build or run whohack.

## Layout

```
crates/                core, collectors, taint, tags, intel, detection, decisions,
                       response, authenticated IPC, service and Windows launcher
ui/                    native Tauri tray application
ml/                    dataset, training, calibration and evaluation tools
tools/                 safe simulator, feed tools, launch/build/package helpers
docs/                  spec, milestone plans, operating guides and release gates
```

The full design is in
[`docs/whohack-master-prompt.md`](docs/whohack-master-prompt.md).

## Roadmap

| Milestone | Scope |
|---|---|
| M0 | ✅ Skeleton: workspace, core types, config, store, logging, CI |
| M1 | ✅ Live process + network monitoring with PID attribution (Linux eBPF/procfs, Windows ETW/polling, macOS limited) |
| M2 | ✅ Taint: download origin, hashing, signatures, YARA, lineage |
| M3 | Tags, 19 templates, profile proposals and replay acceptance implemented; privileged live-sensor acceptance pending |
| M4 | Feeds, durable destination history, Tier 0 rules, Windows/Linux response and quarantine implemented; privileged response/latency acceptance pending |
| M5 | Bounded 60-second features, heuristic, pinned ONNX and training export implemented; scoring microbenchmark meets the 50 µs target here |
| M6 | Sanitized state, typed CPU model adapters, fusion, holds and explanations implemented; representative quality/performance gates not met |
| M7 | Alerts/actions, decision evidence, timeline, trust, categories, responses, recovery and capability-aware settings connected |
| M8 | Dataset, labeling, calibration, training and evaluation tools implemented; [synthetic evaluation is unqualified](ml/reports/eval.md) |
| M9 | ⛔ macOS full mode: needs Apple-granted entitlements |
| M10 | Windows ZIP/MSI and Linux deb/rpm preview packages, watchdog and integrity checks tested locally; signing and clean-machine/real-upgrade acceptance pending |

## Testing safely

whohack is never tested with real malware on a development machine. Detection tests use
the EICAR test file, a harmless beacon simulator (`tools/beacon-sim`), and
Atomic Red Team only inside disposable VMs.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

Unless you explicitly state otherwise, any contribution you intentionally submit for
inclusion in the work, as defined in the Apache-2.0 license, shall be dual licensed as
above, without any additional terms or conditions.
