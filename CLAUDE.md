# Vigil — agent instructions

The full specification is **`docs/vigil-master-prompt.md`**. Read it at the start of every
session. Its Section 1 working rules are binding. In short:

1. **One milestone at a time** (spec §18). Before coding a milestone, write
   `docs/plans/M<n>-<name>.md` (files, interfaces, tests) and show it to the maintainer.
2. **Tests alongside code.** Every milestone ends with passing tests and a demo command.
3. **Check current docs** for any external crate, OS API, or model before coding against it.
   If something has changed, say so and propose a replacement.
4. **Stop and ask before** writing a kernel driver, adding a dependency that makes network
   calls, changing OS security settings, or needing paid accounts/entitlements.
5. **Never run real malware.** Use only the safe test methods in spec §16.
6. **Never disable or interfere with built-in antivirus.**
7. **No placeholders** (`todo!()`, `unimplemented!()`, "handle later"). Anything out of scope
   goes in `docs/backlog.md`.
8. **Small, single-responsibility modules.**

## Project facts

- **License:** `MIT OR Apache-2.0`, open source. Dependencies must be permissive. The
  allowlist lives in `deny.toml`; adding any other license needs maintainer approval.
- **Toolchain:** Rust stable (edition 2024).
- **Workspace:** `crates/*`. New crates are created in the milestone that first needs them.
- **Timestamps:** every `i64` timestamp is Unix **milliseconds**, UTC (`vigil_core::time`).
- **`Action` ordering:** `Action` derives `Ord` in severity order, so fusion "max(rule floor,
  model)" is `max()`.
- **Deviations from spec §7** are documented in `crates/vigil-core/src/types/mod.rs`.

## Checks (must pass before a milestone is done)

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

## Dev machine notes

- **Smart App Control:** the maintainer's Windows machine has Smart App Control enabled. It
  blocks the compiled `libsqlite3-sys` build script (os error 4551). Do not change that
  setting. Build and test in WSL Ubuntu with `CARGO_TARGET_DIR=$HOME/vigil-target`, and rely
  on GitHub CI for Windows/macOS.
- **No sudo in WSL:** WSL Ubuntu is available, but sudo needs a password, so you cannot
  install system packages there.
