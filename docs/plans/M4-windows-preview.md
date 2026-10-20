# M4 follow-up: native Windows monitoring preview

The local preview must run as Windows processes and observe the Windows host.
WSL remains an optional development/build environment, not the Windows runtime.

- `tools/windows/` and `Start Vigil.cmd`: build, launch, status, and stop a native
  Windows preview with private configuration, rules, logs, and data under
  `.vigil/windows`. Launch background processes without console windows. Preserve
  existing configuration and do not install a system service or change OS policy.
- `vigil-core::local_session`, service CLI, and tray: opt-in local session marker
  lets the launcher stop its own preview gracefully without terminating arbitrary
  PIDs. Replacing a session marker also ends the old session. Installed service
  behavior stays controlled by the Service Control Manager.
- Service integration tests: exercise authenticated IPC and duplicate-instance
  protection on Windows named pipes as well as Unix sockets. Verify graceful
  session shutdown, persistence, and native TCP process attribution.
- Documentation and CI: make Windows launch instructions prominent, package native
  preview executables, and clearly distinguish monitoring from future enforcement.

Validation: formatting, Clippy, workspace tests, native Windows service and tray
builds, launcher start/status/stop, and visible UI connected to `windows-poll`.
Application Control may block local build scripts or unsigned executables; record
the actual result without weakening that policy. If needed, cross-compile using
the existing Windows SDK and run the resulting executable on Windows.

## Validation (2026-10-13)

- Native service running with `windows-poll`; native WebView2 tray visibly rendered.
  Windows service build scripts hit Application Control error 4551, so the service
  was cross-compiled with local LLVM and the already installed Microsoft SDK.
  The resulting `.exe` ran on Windows under the unchanged policy. Tray builds and
  Clippy passed directly on Windows.
- 88 native Windows collector/core/IPC tests passed, including real child-process
  TCP attribution. Fixed a test's Unix-specific path expectation.
- Full Linux workspace tests passed (196 tests; one privileged DNS test ignored).
  Workspace Clippy passed with warnings denied; Windows target checked separately.
- Native service smoke test passed with an isolated temporary database, real
  localhost traffic, named-pipe authentication, wrong-token rejection, duplicate
  instance/token protection, and all 943 published observations persisted on exit.
- The Windows launcher built both executables with `build --cross`; native start,
  repeated start, status, graceful stop and tray rendering passed. One earlier
  preview shutdown saved all 1,104 accepted observations.
- Added a portable preview ZIP builder and a Windows CI smoke/package artifact
  step. The updated remote workflow has not been run from this local checkout.

Demo from PowerShell: `& '.\Start Vigil.cmd'`, then `& '.\Start Vigil.cmd' status`.
This remains the monitor-only M4 increment; enforcement and the signed installer
remain outstanding.
