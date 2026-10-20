# Downloaded-content protection

whohack can now associate downloaded documents, video and audio with the process
opening them, pause that process on qualified danger signals, and show the file
and reason in an alert. This is a tested detection/response feature in an
experimental preview, not a claim of comprehensive malware detection.

## What happens

- A downloaded executable or script, an absolute local file in launch arguments,
  or a native file-read event supplies download context. Children inherit it.
  Alerts distinguish a launch argument from an observed read.
- An installed YARA signature, a live threat-feed destination match, observed
  remote-thread injection, or qualifying credential-access evidence can cause an
  automatic process pause. Each requires downloaded-process/input context.
- The tray reports the pause. Resume releases it; choosing Allow also updates the
  alert correctly. Monitor mode releases active operations and disables new pauses.
- Stop and quarantine checks the captured process identity and file hash. For a
  shared viewer, exactly one signature-matched input must identify the file to
  remove. Behavior alone cannot select an arbitrary document or the installed
  viewer for deletion. Quarantine removes the original file and retains inert
  bytes for explicit restore; it does not restart the process.

Being unsigned, downloaded, or connected to a new destination is not sufficient
for an automatic pause. System/protection-process exclusions, integrity checks and
the user's trust entries remain effective. No global Wi-Fi shutdown is used.
Mass-write alerts require download context and user-file activity; ordinary
database/cache churn does not by itself justify an alert or a pause. Repeated
window evidence is coalesced instead of generating a popup on each later read.

## Enable on Windows

Stop the owned whohack session before changing its private
`.vigil/windows/config.toml`. Merge these keys into the existing sections:

```toml
mode = "prompt"
[collect]
backend = "native"
dns = true
[response]
enabled = true
automatic = false
pause_downloads = true
```

Regenerate the local manifest with `whohack-service.exe --config <config-path>
--write-manifest` after reviewing the change. Start whohack with Windows
administrator permissions for native file monitoring. Check Status for
`windows-etw`, file visibility, and **Automatic download pause: on**. The ordinary
portable package still defaults to Monitor with response disabled.

For this checkout, right-click `Start whohack.cmd` and choose **Run as administrator**
when starting a stopped instance with the native configuration. WSL is only a
build tool; the service and UI are Windows executables. Polling remains available
without elevation, but cannot observe files opened inside already-running apps.

Threat data is loaded locally from `data/intel.json`. The optional Python updater
refreshes public metadata, never samples or private activity:

```powershell
python tools/intel/update.py --output .vigil/windows/data/intel.json --fetch-public --watch
```

It refreshes at most every six hours while running. Indicators expire after 48
hours without successful refresh. It is not an installed background task.
`intel-sources.json` preserves provider credits, dates and provider notices; caches
created before notice preservation retain their existing dates and source credit.
Public data comes from [Spamhaus DROP](https://www.spamhaus.org/blocklists/do-not-route-or-peer/)
and [Feodo Tracker](https://feodotracker.abuse.ch/blocklist/).

## Evidence and limits

The Windows acceptance harness uses disposable readers and unique harmless
signatures in isolated configurations. The `.mp4`, `.wav` and `.pdf` fixtures are
test data with those extensions, not decoder exploits or a malware corpus. Tests
check automatic suspension, a clean reader continuing, resume, exact-file
quarantine/restore, shared-reader preservation and durable feedback. A separate
test uses a real localhost TCP connection and a temporary threat snapshot; no
malicious server is contacted. The native-read test omits the input from launch
arguments to prove file-event attribution. Reports are private under
`.vigil/checks/downloads/`.

On 2026-10-15, the final focused Windows checks passed with the optimized service
SHA-256 `9aac4da61bb17eb1d10a02be9d68953dbac433513810f63bb6c875370784579c`.
Observed alert/action reporting took about 1.8–2.2 seconds in the five isolated
tests, including process startup and IPC polling. This is not a latency guarantee.
The native-read case also exposed a test-harness issue: verifying restored bytes
while monitoring was still active correctly made the verifier another target of
the temporary signature. Verification now reads restored bytes after sensor
shutdown; the exact two response records are checked.

The native Windows suite passed 234 tests across its full run and the unchanged
four-test retry after Application Control initially blocked one executable. Six
privileged/helper tests remained ignored. The Linux workspace passed 209 tests
with three ignored. Full-suite results do not establish real malware efficacy.

The updated portable ZIP passed real WebView2 testing with the pause option on,
including service identity, tabs, trust add/remove, Monitor/Prompt changes and
disabled general Auto. The local native service and normal-user tray were started
with download pausing enabled, no active responses and no new open alerts after
the rule adjustment. The database passed integrity checks and retained prior
events and feedback. Rollback files are private under `.vigil/backups/`.

A 30-second sample on this 24-logical-processor PC used 2.609 CPU-seconds
(0.362% of total host capacity) and 44.4 MiB service working set. This is a short
local sample, not a gaming or long-duration benchmark. Native collection reported
unattributed records, although its lost-event, queue-drop and failure counters
were zero; complete file coverage is not established. Defender real-time
protection remained enabled. A saved Monitor choice overrides the TOML mode;
choose Prompt in the UI to enable the configured download pause again.

This does not certify that every downloaded file is safe:

- The bundled YARA file is an EICAR test signature, not a maintained malware
  signature collection. Real-use coverage currently depends mainly on the
  implemented behavior rules, configured sensors and current threat data. Keep
  Microsoft Defender enabled. No representative detection-rate study has passed.
- Native input-read reporting currently covers Downloads and configured
  sensitive roots. Moved files, missing origin markers, sandboxed apps,
  memory-mapped reads and other paths can leave attribution incomplete.
- At most eight input files are retained per process. Inputs above 16 MiB retain
  origin context but skip content scanning/hashing. Remote/device paths,
  reparse points, symlink parents and cloud placeholders are skipped.
- Detection follows observed activity. Harm can precede the pause; suspension
  does not undo writes, retract data already sent or stop unrelated processes.
  No zero-latency or universal pre-open blocking guarantee is made.
- Remote-thread evidence needs an existing configured Sysmon channel; whohack does
  not install it. Reserved taxonomy names are not proof of a live sensor.
- No trained decision model is enabled. Fine-tuning requires representative,
  reviewed data; it is not needed to operate this deterministic pause path.

The Windows local-drive classification uses Microsoft's
[GetDriveTypeW API](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getdrivetypew).
See the broader historical readiness reports for release work outside this
download-detection milestone.

## Lightweight operation and model status (2026-10-17)

The intended flow is to observe downloaded content as the user opens, plays or
runs it, attribute dangerous behavior to its process, then pause and notify.
whohack does not automatically execute arbitrary downloads to see whether they
infect the host. It cannot certify that every file or media decoder is safe.

The configured Windows preview uses rules, signatures and threat-feed evidence.
There is no configured AI model and no verified Luna deployment. Research uses
Laya/OpenDecider. The preserved OpenDecider head received one synthetic training
step; in the recorded evaluation, both base and head flagged all seven benign
test examples at the blocking threshold. This is failed qualification, not a
production fine-tune. Next model work needs representative reviewed examples and
false-positive validation before any automatic decisions. The saved weights and
training evidence are preserved; no further model downloads or training were
needed for this storage fix.

Raw event history is now limited to the newest 100,000 rows and 10,000 exited
processes, checked after detection/response every ten seconds during activity and
at shutdown. The configured age limit still applies. All observations continue
through detection; only retained raw history is trimmed. Alerts, decisions,
feedback, trust and response/quarantine records are preserved independently.
Live process rows and durable evidence are outside these limits, so this is not a
hard disk-size ceiling. New databases use incremental page reclamation.

On this PC, offline maintenance reduced the database from 2,146,643,968 to
34,914,304 bytes, keeping all 848 alerts and verifying all protected records and
the response journal unchanged. The previous raw timeline had almost seven
million rows, mainly file access. The [storage milestone](plans/M12-lightweight-storage.md)
records the scoped verification and development-cache cleanup.
