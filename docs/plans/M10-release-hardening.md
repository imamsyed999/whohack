# M10 — native Windows delivery and hardening

1. Address the observed Windows cold-start/shutdown delay with bounded parallel
   file analysis, preserving event/lineage order and persistent hash caching.
   Verify real service start, authenticated IPC, event persistence and clean stop.
2. Add a native Windows launcher with a portable layout, local lifecycle marker,
   startup health check, bounded crash restart, integrity verification and clear
   error reporting. Keep source build helpers separate from packaged runtime.
3. Complete interrupted quarantine recovery without overwriting originals, and
   ensure reported response capabilities reflect the current Windows token.
4. Tighten integrity manifest traversal/parsing and expose tampering persistently
   in status. Preserve monitor defaults and existing user configuration.
5. Finish opt-in, hash-only VirusTotal caching/rate-limit tooling; no lookup is
   made without the user's key and explicit opt-in. Use fake transport tests.
6. Refresh CI, packaging manifests, readiness documentation and remaining gates.
   Build an unsigned per-user Windows MSI from the tested archive, with Start-menu
   launch/stop shortcuts and graceful uninstall. Verify its database and extracted
   payload without installing a privileged service or changing Windows security.
   Verify the native Windows archive from an extracted path, plus Rust/Python/UI
   checks. Signing certificates, privileged firewall acceptance, clean-machine
   installers, representative ML evaluation and entitled macOS extensions remain
   external requirements; do not claim those are completed by local compilation.

Primary files: `vigil-taint/{analyzer,hash,scan}.rs`, service pipeline/integrity/
status, a native launcher crate, `vigil-respond/quarantine.rs`, `tools/intel/`,
`tools/windows/package.py`, packaging and user-facing readiness docs.

Local verification (2026-10-13): full Rust tests, formatting and strict Clippy
pass on Windows and Linux. Native tray build/lints and Python/JS checks pass.
The extracted ZIP passes restart, token rotation, tamper, shutdown and integrity
refusal checks without development tools on PATH. The per-user MSI is built and
its decompressed cabinet bytes match the ZIP; installation acceptance is pending.
No privileged firewall/sensor test or system-service installation was performed.
