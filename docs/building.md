# Building whohack

## Keeping development storage small

The Windows app runs from its native release executables; WSL, Rust target trees,
Python environments and model-training checkpoints are development resources.
Do not recreate removed test artifacts just to launch the app. Both Cargo
workspaces now disable debug symbols and incremental compilation for ordinary
development/test profiles. Debugger work can opt in using
`CARGO_PROFILE_DEV_DEBUG=1` or `CARGO_PROFILE_TEST_DEBUG=1`. See Cargo's
[profile settings](https://doc.rust-lang.org/cargo/reference/profiles.html).

Run focused checks for changed components and reuse existing release binaries.
Measure `target/`, `ui/src-tauri/target/`, `.vigil/checks/` and the WSL Cargo target
directories before expensive builds. Keep unique models, datasets, runtime data
and quarantine separate from disposable compiler/test output. Do not install GPU
training packages for a CPU-only runtime or recreate duplicate environments.

Raw history maintenance keeps the newest 100,000 events and 10,000 exited-process
records, with a short interval of possible overflow. Alerts, decisions and
feedback are retained separately. For an existing oversized **stopped** local
database, `python tools/windows/compact_history.py` audits it; `--apply` prunes
only raw history, saves a small protected-record backup, verifies evidence and
compacts free pages. It refuses a running service's data lock. This changes
forensic timeline retention and is not a hard byte limit on all application data.
The [SQLite auto-vacuum documentation](https://www.sqlite.org/pragma.html#pragma_auto_vacuum)
explains why old databases need one offline compaction to reclaim existing space.

## Local preview and validation

Use the `--init-local`, `--check-config`, `--write-manifest`, `--run`, and `--status`
workflow in the root README. The service reports the capabilities of the selected
collector, session status and configured models over authenticated IPC. It does
not expose the authentication token through status. New Windows profiles use
polling, monitor mode, disabled response and no model. This development profile's
explicit manual-only setup is documented in [the readiness report](readiness-2026-10-15.md).
App profiles and observed tags are visible in the tray's **App profiles** tab.
Changing category applies on the next event. Acknowledgement records feedback;
**Always trust this app** suppresses subsequent alerts for that app identity.

`--show` opens the tray window immediately, including on desktops without a system
tray. Set `WHOHACK_CONFIG` to the same absolute file path for both applications.
For WSLg graphics problems, start the tray with process-local settings:

```sh
GDK_BACKEND=x11 LIBGL_ALWAYS_SOFTWARE=1 WHOHACK_CONFIG="$PWD/whohack.local.toml" \
  cargo run --manifest-path ui/src-tauri/Cargo.toml -- --show
```

Local setup places the Unix socket under `~/.local/state/whohack/`: Windows-mounted
WSL drives cannot host Unix sockets. The database and logs live under `.vigil/` in
the config directory. A second service using the same data directory is rejected
before it can replace IPC credentials. Existing configuration is never overwritten.

Validation:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo deny check
cargo deny --manifest-path ui/src-tauri/Cargo.toml check
cargo clippy --manifest-path ui/src-tauri/Cargo.toml --all-targets --locked -- -D warnings
cargo build --manifest-path ui/src-tauri/Cargo.toml --locked
python3 tools/beacon-sim/test_beacon_sim.py
python3 -m unittest discover -s ml -p test_pipeline.py
python3 -m unittest discover -s tools/intel -p 'test_*.py'
```

Rule files in `<rules_dir>/tier0/*.yaml` are validated at startup and reloaded on
activity every ten seconds. Invalid updates keep the previous valid set and emit a
health notification. Bundled rules remain available when the directory is absent.
Rules use all-of tag matching, optional taint/sign/path constraints, severity, and
an action recommendation; monitor mode never executes it. Explicit trust can
suppress matching observations. Probabilities are all zero when no model ran.

After intentional config/rule changes, refresh the integrity manifest using
`--write-manifest`. Templates are embedded into the binary; rebuild after changing
`profiles/*.yaml`. No profiles are inferred from program filenames in live mode.

The development audit uses the existing exceptions in `deny.toml`; a passing check
does not remove the release follow-ups documented in `docs/backlog.md`.

## Everyday build (all OSes)

You need:

- Rust stable (the version is pinned by `rust-toolchain.toml`);
- a C compiler, for the bundled SQLite.

Then:

```sh
cargo build --workspace
cargo test --workspace
```

## Linux eBPF collector (optional, recommended for releases)

The eBPF backend gives real-time, exact PID attribution, including for very short-lived
processes. Without it, Linux uses `/proc` polling. Building it requires:

```sh
rustup toolchain install nightly --component rust-src
# Prebuilt bpf-linker (building it from source needs a matching LLVM):
curl -sSfLO https://github.com/aya-rs/bpf-linker/releases/latest/download/bpf-linker-x86_64-unknown-linux-musl.tar.zst
tar --zstd -xf bpf-linker-x86_64-unknown-linux-musl.tar.zst -C ~/.local/bin
```

Build and run (eBPF needs root):

```sh
cargo build -p whohack-service --features ebpf
sudo ./target/debug/whohack-service --config whohack.toml --monitor
```

Run the live tests as root:

```sh
sudo -E env "PATH=$PATH" cargo test -p whohack-collect --features ebpf -- --include-ignored
```

The eBPF programs live in `ebpf/whohack-ebpf`, which is its own workspace targeting
`bpfel-unknown-none`. `crates/whohack-collect/build.rs` compiles them and embeds the object.
Before loading, the collector checks the tracepoint field offsets against
`/sys/kernel/tracing/events/*/format` and falls back to polling on any mismatch. PIDs are
reported in the collector's own PID namespace, so whohack works inside containers and WSL2.

## Windows

Run the native preview with `Start whohack.cmd` from the repository root. Its native
launcher starts the service without a console window, waits for authenticated
named-pipe status, then opens the Tauri window. WebView2 and
the Microsoft Visual C++ x64 runtime must be installed. No WSL runtime is involved.

```powershell
& '.\Start whohack.cmd' build     # Rust stable MSVC + Visual C++ build tools
& '.\Start whohack.cmd' build --release # optimized service, launcher, helper and UI
& '.\Start whohack.cmd'           # or double-click the file
& '.\Start whohack.cmd' status
& '.\Start whohack.cmd' stop
python tools/windows/smoke_test.py
# Generate attribution first using the commands below.
python tools/windows/package.py # creates .vigil/packages/whohack-Windows-Preview.zip
python tools/windows/test_package.py # isolated extraction, restart and tamper checks
python tools/windows/test_ui.py # real WebView2 UI; test-only Node 22+ dependency
py -3.11 tools/windows/build_msi.py # build-only Python 3.11/3.12 requirement
```

Generate attribution using the locked metadata and `notices.py` commands in
[packaging/README.md](../packaging/README.md#windows) before `package.py`.

Debug executables are `target/debug/whohack-launcher.exe`,
`target/debug/whohack-service.exe` and `ui/src-tauri/target/debug/whohack-tray.exe`.
Release builds use the corresponding `release` directories. `Start whohack.cmd`
prefers release binaries when present; invoke the debug launcher directly to
select a debug build. Use `package.py --profile release` for optimized payloads.
An extracted preview package instead
loads both from `bin/` using `whohack.exe`, without Python, Rust or WSL. The build
helper needs Python 3.11+, but native compilation can also be run directly:

```powershell
cargo build -p whohack-service -p whohack-launcher -p whohack-response-helper --locked
cargo build --manifest-path ui/src-tauri/Cargo.toml --locked
```

The ZIP and per-user MSI are unsigned previews. MSI construction uses Windows
Installer APIs exposed by Python 3.11/3.12 `msilib`; this build-only module was
removed in Python 3.13, so CI pins 3.11 for that step.
`py -3.11 tools/windows/test_msi.py` checks actual per-user install, Start-menu
shortcuts, native startup, a metadata-fixture major upgrade and uninstall while
running, including custom install paths and preserved data. These pass on the
development PC; clean-machine, rollback and real release upgrades remain untested.

The launcher uses `.vigil/windows/config.toml`, with `data/`, `logs/`, and a private
copy of `rules/` beside it. This prevents Linux and Windows from sharing a database
or integrity manifest. Rules are copied on first setup; edit the private copy for
that preview and refresh its manifest after intentional changes. The session
marker is only used by locally launched processes: removing it requests a graceful
flush and exit. Repeated starts do not create a second service or tray. System
services continue to use the Service Control Manager. The native launcher owns a
supervisor with at most three restarts per five-minute failure window. Stop drains
accepted events and waits for the service, supervisor and tray locks. It never
kills an arbitrary PID from a state file. Errors are also written to
`.vigil/windows/launcher-health.json`.

The ETW collector needs an **elevated** (administrator) process. Unelevated, whohack falls
back to ToolHelp and IP Helper polling, which covers processes and TCP but not UDP or DNS.
The local preview explicitly selects polling.

If Windows **Smart App Control** is on, it may block freshly compiled build scripts with
*"An Application Control policy has blocked this file"* (os error 4551). This machine
has intermittently blocked dependency build scripts and individual test executables;
the latest workspace attempt passed 228 tests but one executable was refused.
A checked cross-build path uses LLVM in WSL and the Windows SDK already installed
on the host to produce **native Windows executables**, including the tray:

```powershell
& '.\Start whohack.cmd' stop
& '.\Start whohack.cmd' build --cross
& '.\Start whohack.cmd'
```

For a fresh WSL development environment, unpack LLVM build tools into the user's
directory (no sudo or system package installation required):

```sh
mkdir -p "$HOME/vigil-cross-tools"
cd "$HOME/vigil-cross-tools"
apt-get download clang-18 lld-18 llvm-18 libclang-cpp18 libllvm18 libclang-common-18-dev libclang1-18 libpfm4
for package in ./*.deb; do dpkg-deb -x "$package" "$PWD"; done
rustup target add x86_64-pc-windows-msvc
# Back in the repository:
python3 tools/windows/cross-build.py --stage
python3 tools/windows/cross-build.py --ui --stage
# Add --release for optimized builds; stop that profile before replacing its files.
# Build all Windows test artifacts for native execution:
python3 tools/windows/cross-build.py test-build --workspace
```

Run `python tools/windows/test_native.py` on Windows after the test build. It
reports OS-refused executables as failures rather than omitting them. Explicit
privileged response tests stay separate from the ordinary suite.

`cross-build.py --help` exposes LLVM, MSVC, and SDK paths for other machines. It
uses the existing Visual Studio 2019 MSVC 14.29 and Windows SDK 10.0.19041 by default.
It does not download Microsoft toolchains or change Windows policies. LLVM tools
are build-only; they are not packaged with whohack. Tauri documents the broader
[Windows cross-compilation approach](https://v2.tauri.app/distribute/windows-installer/).
An OS policy can still refuse unsigned executables; CI builds are also unsigned.
Do not weaken OS security settings to build or run whohack.

Validated on this machine: native Windows collection, authenticated IPC, token
rejection, duplicate-service protection, real localhost TCP PID attribution,
graceful event flush, tray rendering, and launcher start/stop/restart.

## macOS

`cargo build --workspace`. This builds **limited mode**: libproc polling with no DNS
visibility.

Full mode (Endpoint Security + Network Extension) needs Apple-granted entitlements; see
milestone M9 in the spec.

## Cross-checking other OSes from Linux

```sh
rustup target add x86_64-pc-windows-msvc aarch64-apple-darwin
cargo clippy -p whohack-collect --target x86_64-pc-windows-msvc --tests -- -D warnings
cargo clippy -p whohack-collect --target aarch64-apple-darwin --tests -- -D warnings
```
