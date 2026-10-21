# M16: runtime protection clarity and optional folder checks

The primary workflow remains: keep the native service running, open a downloaded
file normally, associate its reader/process descendants, detect supported
behavior, pause qualified danger, notify, and offer evidence-bound response.
A folder check is optional static inspection, never a substitute for runtime
monitoring and never execution of unknown content.

Implementation:

- Add authenticated start/status/stop requests for one background folder check.
  Use the installed Windows Defender engine and signatures, without downloading
  a model or a second scanner. The bundled whohack YARA rule is only an EICAR test
  rule and must not be advertised as broad malware coverage.
- Default to Defender custom scan with `-DisableRemediation`. Offer a separate,
  confirmed scan with Defender remediation. Defender owns its quarantine and
  restoration; do not present those files as whohack vault entries.
- Only accept absolute local folders, reject device/UNC/stream paths, drive
  roots and link/reparse ancestors. No shell interpolation. One job at a time,
  bounded captured output, a stop request after ten minutes, CPU throttling
  requested, no GPU. Windows controls traversal and cloud settings. Report-only
  checks ignore file exclusions and inspect archives per the documented API.
  Cancellation is best effort; OS waits and output pipe shutdown can take longer.
- A stop ends the owned command client; do not cancel other Defender jobs or
  claim that stopping the client guarantees cancellation inside the AV service.
- Show report text, engine identity, mode, running/finished/error states and
  elapsed time. Exit code 2 is ambiguous (detection OR scan error); never label it
  proof of malware. No percentages or file counts invented from opaque scans.
- Preserve existing runtime alert notifications. Add a separate desktop
  notification when an optional folder check finishes.

Validation: meaningful path/lifecycle/output/exit-status unit checks, native
Windows service IPC + actual Defender check of an owned harmless folder, UI
state and confirmation tests, controlled runtime pause/restore acceptance,
formatting and strict Clippy. Record measurements and policy limitations below.
Do not retry the previously canceled live-profile administrator restart.

Primary API reference:
[Microsoft Defender command-line documentation](https://learn.microsoft.com/en-us/defender-endpoint/command-line-arguments-microsoft-defender-antivirus).

## Integrated implementation and validation

The overlapping drafts were reconciled to one asynchronous Defender start/status/
stop API. The superseded YARA folder-scan request, response and UI were removed.
Existing M15 download activity changes remain. Snapshots of the overlap are
preserved privately under `.vigil/checks/m16-runtime` and
`.vigil/checks/m16/runtime-collision` (the latter is the mixed pre-integration
snapshot; it is not release evidence).

The optional UI defaults to report-only, requires a separate checked remediation
choice and confirmation, displays bounded output as plain text, supports stopping
the exact current job, and disables unsupported/offline controls. It discloses
Defender cloud/sample settings and does not label a successful check a safety
verdict. Remediation is owned by Windows Defender, separate from whohack's vault.
The backend discovers Defender via Windows known-folder APIs rather than mutable
environment paths, revalidates its path, and checks an exact accepted Microsoft
publisher before execution. Path checks are best effort, not a race-proof handle
boundary. No scanner is downloaded and no OS protection settings are changed.

- Native Windows service and tray builds passed. Review artifacts are
  `.vigil/checks/m16-runtime/whohack-service.exe` and `whohack-tray.exe`; prior
  staged executables and the live profile were not replaced.
- Native Windows service unit tests: **27 passed**. Linux service unit tests:
  **27 passed**. These cover the folder job lifecycle, literal command arguments,
  report-only default, path rejection, output limits, ambiguous exit codes,
  optional IPC failure behavior and preserved runtime behavior.
- Linux taint tests: **39 passed**; Linux IPC tests: **8 passed**. Root/UI
  formatting, strict Linux Clippy for affected packages, strict Windows Clippy
  for all root workspace targets and the separate UI workspace all passed.
- After validation, the newly created `/home/esap/whohack-build-cache` was
  resolved and checked for active compilers, then removed (7,271,029,220 bytes).
  Native review executables, the review ZIP and reports were retained.
- Real Chromium tests with a mocked IPC boundary passed, including folder job
  start/stop, report-only default, explicit remediation confirmation, escaped
  output, failed-start feedback, old-service fallback and offline controls.
  Report/screenshots: `.vigil/checks/m15-ui/`. These are not native sensor tests.
- The new native service could not start for isolated end-to-end testing:
  Windows Application Control returned **4551** at `--write-manifest`, before
  starting the isolated service or invoking Defender. No retry or policy bypass
  was attempted. The exact failure and artifact digest are recorded in
  `.vigil/checks/m16-runtime/folder-scan.json`. The reusable harness is
  `tools/windows/test_folder_scan.py`; exact-build Defender integration remains
  unverified behind this OS policy gate.
- Service SHA-256: `ec611c1cc5d55bb51d95b457c7ea99d5c25d44da4ff08ef20e9cb35fa08e4477`.
  Tray SHA-256: `a9fb964775b2bc000de2b876801f36a6fa8f6f0005981184d148efb4a2969131`.

The normal configured service is currently stopped; this source change is not
active protection. Earlier read-only IPC showed service 0.1.0 in Prompt with
native file visibility and download pausing enabled, no model loaded, and
accumulated sensor gaps. Across 60 seconds, queue drops (46,644) and kernel lost
records (876,641) stayed constant; unattributed records grew by 114,552. This
counter combines several attribution failures and does not measure how many
relevant downloaded-file events were missed. No elevation retry or live restart
was attempted. `Update whohack.cmd` remains the user's administrator update path;
Windows Application Control must also permit the selected executable.

## Independent measurements — 2026-10-20

- Installed Defender reports antivirus and real-time protection enabled, engine
  4.18.26090.9, signatures updated at 10:02 local time. A direct report-only scan
  of the harmless packaging README returned 0 and reported no threats. This
  validates the installed command interface, not the newly built integration
  whose executable was blocked by Application Control.
- Existing staged whohack 0.1.1 passed an owned Windows polling fixture for a
  downloaded document: temporary signature -> durable alert -> automatic pause
  in 1,937 ms -> resume -> identified input quarantine -> exact-byte restore.
  The unrelated control process and shared reader executable were preserved.
  Report: `.vigil/checks/m16-poll-document-pause.json`.
- The same staged build passed the independent localhost reputation fixture,
  automatic pause and unaffected-control checks:
  `.vigil/checks/m16-poll-network-pause.json`. These controlled tests establish
  plumbing for the tested signals, not general malware detection accuracy.
- The normal configured service was unreachable. Its own log records a graceful
  stop at 16:37:33 UTC; this session did not stop it. No Vigil/whohack process was
  running at the check. The existing-profile downloaded-WAV test stopped at
  service readiness, before downloading/opening a sample. Failure report:
  `.vigil/checks/m16-live-sample.json`.
- The independent runtime measurement session above made no training/GPU or
  live-profile changes. Subsequent integrated M16 model/data work is recorded
  separately in `M16-download-decisions.md`; it includes three training attempts
  that stopped on the resource guard. The integration checks here created a
  disposable compiler cache and new review artifacts. The previously canceled
  administrator restart was not retried or bypassed.
