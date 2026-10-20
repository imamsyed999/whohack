# Contributing

Read [CLAUDE.md](CLAUDE.md), the [specification](docs/whohack-master-prompt.md), and
the [current release gates](docs/backlog.md). Submit focused changes with a
reproduction and relevant validation. Describe unavailable checks honestly.

Use Rust stable and Python 3.11+. Core validation:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo deny check
cargo deny --manifest-path ui/src-tauri/Cargo.toml check
python -m unittest discover -s ml -p test_pipeline.py
python tools/release_audit.py --output .vigil/checks/source-audit.json
```

The tray has a separate Cargo workspace; test its build/lints and dependencies
as well. Its current license-policy failures are recorded in
[the license review](docs/license-review-2026-10-14.md); do not hide them by
broadening the allowlist. See [building.md](docs/building.md) for Windows builds
and the documented cross-build alternative. WSL is a build host, not the Windows
monitoring runtime.

Privileged/ignored tests require explicit operator intent. Run only documented
owned-child tests, with cleanup, in a suitable disposable environment. Do not
disable antivirus, weaken Application Control or test real malware on a host PC.

Never commit `.vigil`, credentials, databases, raw private telemetry, model
weights or virtual environments. Contributions must be yours to license under
MIT OR Apache-2.0; retain upstream notices and identify third-party material.
New license exceptions require maintainer approval. Security issues follow
[SECURITY.md](SECURITY.md).
