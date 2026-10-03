# Vigil

Vigil is a free, open-source anti-hack layer for personal computers running Windows, macOS, and Linux.
It watches programs you download, compares what they *actually do* with what a program of
that type *should* do, and steps in when they don't match. For example, it can catch a
"PDF reader" that reads your saved browser passwords and phones home every 60 seconds.

It runs entirely on your machine, on ordinary hardware with no GPU, and works alongside
your OS's built-in antivirus (Microsoft Defender, XProtect, ...). It never replaces or
disables that antivirus.

> **Status: early development (milestone M0, the skeleton).** Vigil does not detect anything
> yet. See [the roadmap](#roadmap).

## How it works

1. **Taint.** Vigil knows which files came from the internet and tracks every process
   started from them, and those processes' children.
2. **Behavior.** It watches network connections, sensitive-file access (browser password
   stores, SSH keys, wallets), persistence, and child processes.
3. **Expectation.** Each app gets an expected-behavior profile for its category. A
   mismatch is the core signal of a hidden hack.
4. **Network reputation.** It checks destinations against threat feeds, and flags raw-IP
   connections with no DNS lookup, first-seen destinations, and beaconing.
5. **Decision.** Hard rules, a fast anomaly score, and a small local *typed-decision*
   model classify activity as benign, suspicious, or malicious.
6. **Response.** It blocks the process's network, asks you, or suspends/kills it and
   quarantines the file. Every action is reversible.

## Honest constraints

- **No system detects 100% of attacks.** Vigil aims for high detection of the behaviors that
  matter most (credential theft, persistence, command-and-control, ransomware, data
  exfiltration) with few false alarms.
- **Malware running with admin/root rights can attack user-mode tools.** Vigil adds
  self-protection but is not tamper-proof.
- **When uncertain, Vigil prefers safe, reversible actions** (block network + ask you)
  over destructive ones (kill + quarantine).

## Privacy

No user data leaves your machine. The only network traffic is:

- threat-feed downloads;
- an **opt-in** VirusTotal lookup that sends **file hashes only**, using your own API key.

Vigil never uploads files.

## Building

You need Rust stable (the version is pinned by `rust-toolchain.toml`) and a C compiler
(for the bundled SQLite).

```sh
cargo test --workspace
cargo run -p vigil-service -- --print-default-config > vigil.toml
cargo run -p vigil-service -- --config vigil.toml --check-config
cargo run -p vigil-service -- --config vigil.toml --init-db
```

`config/vigil.example.toml` documents every option.

> **Windows with Smart App Control on:** Smart App Control may block one of the
> freshly compiled build scripts (`libsqlite3-sys`) with *"An Application Control policy
> has blocked this file"* (os error 4551). You can develop in WSL instead, or rely on
> CI for Windows builds. Do not weaken your OS security settings just to build Vigil.

## Layout

```
crates/vigil-core      types, config, event bus, SQLite store
crates/vigil-service   the service binary
docs/                  spec, milestone plans, backlog
```

Further crates (collectors, taint, tags, intel, detection, decision, response, IPC), the
Tauri tray UI, and the ML pipeline are added milestone by milestone. The full design is in
[`docs/vigil-master-prompt.md`](docs/vigil-master-prompt.md).

## Roadmap

| Milestone | Scope |
|---|---|
| **M0** | Skeleton: workspace, core types, config, store, logging, CI |
| M1 | Live process + network monitoring with PID attribution |
| M2 | Taint: download origin, hashing, signatures, YARA, lineage |
| M3 | Capability tags + expected-behavior profiles |
| M4 | Threat intel, Tier 0 rules, per-OS response |
| M5 | Tier 1 anomaly scoring |
| M6 | Tier 2 typed-decision model, fusion policy, explanations |
| M7 | Tray UI |
| M8 | ML pipeline + evaluation report |
| M9 | macOS full mode (Endpoint Security + Network Extension) |
| M10 | Signed installers, watchdog, integrity checks |

## Testing safely

Vigil is never tested with real malware on a development machine. Detection tests use
the EICAR test file, a harmless beacon simulator (`tools/beacon-sim`, coming in M3), and
Atomic Red Team only inside disposable VMs.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

Unless you explicitly state otherwise, any contribution you intentionally submit for
inclusion in the work, as defined in the Apache-2.0 license, shall be dual licensed as
above, without any additional terms or conditions.
