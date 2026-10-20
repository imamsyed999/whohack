# M4 increment: usable local detection and monitor alerts

The M3 tagging/profile implementation and deterministic replay are in place. This
increment makes their output useful in the service and tray without claiming that
unfinished enforcement, feeds, or live filesystem sensors exist.

- `vigil-detect`: validated YAML hard rules, all six required critical rules,
  automatic profile-never rules, deterministic explanations, and the documented
  untrained score. Reload custom content atomically; keep the last valid rules on
  a bad update. Bundled rules are always available without an installed data folder.
- Service: evaluate tagged observations, persist alerts, publish IPC notifications,
  respect application/destination/behavior trust, and suppress identical repeated
  alerts for five minutes while allowing different reasons to surface.
- Replay: show rule matches and recommended actions alongside tags. Never enforce
  fixture decisions. Keep recommendations separate from actions actually performed.
- UI and IPC: explicitly expose monitor-only capabilities. Reject unsupported
  blocking, killing, and automatic modes; offer acknowledgement and trust.
- Readiness: add local development setup, startup/IPC checks, replay and live smoke
  tests, and document actual collection coverage and remaining release requirements.

Tests: rules and allowlist boundaries, malformed rule reload, trusted benign cases,
replay detections, alert persistence/push/feedback, unsupported actions, shutdown,
and IPC startup failures. Finish with workspace fmt/Clippy/tests and tray build.

No remote feed/model download, firewall change, kernel driver, or paid service is
part of this increment. Full M4 acceptance still requires tested per-OS enforcement.

## Validation (2026-10-13)

- Workspace formatting and Clippy with warnings denied: passed.
- Workspace tests: 195 passed; one privileged AF_PACKET DNS test remains ignored.
- Tray formatting, Clippy, and debug build: passed in WSL Ubuntu.
- New tags/detection plus decision/IPC crates cross-checked with Clippy for Windows
  x64 and macOS ARM64. This does not replace native service/UI runtime testing.
- `cargo deny check`: passed with the repository's existing policy/exceptions.
  YAML uses `serde-saphyr` with only deserialization enabled; no includes,
  environment interpolation, or unmaintained libyaml dependency.
- Simulator tests and seven-record CLI replay: passed; browser-credential and
  tainted-beacon rules fired with recommendations clearly separate from enforcement.
- Live service: authenticated status and profile requests, duplicate-instance
  rejection, wrong-token rejection, visible tray rendering, and local launcher
  start/stop passed. One graceful shutdown saved all 2,588 published observations.
- Windows PowerShell script execution is disabled on this machine. The supported
  launcher invokes a Bash script through WSL and changes no execution policy.
