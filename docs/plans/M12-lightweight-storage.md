# M12 — lightweight downloaded-content protection

The maintainer reaffirmed on 2026-10-17 that Vigil should watch downloaded
programs and the apps opening downloaded documents, audio and video, detect
dangerous behavior and promptly contain the responsible process. It must stay
lightweight. Automatically executing untrusted downloads on the user's PC is
outside this workflow.

Audit findings: the checkout contains about 14.3 GiB, WSL build directories about
97 GiB, and the Windows event database about 2 GiB (almost seven million events,
6.6 million file-access records). No Vigil service or model process was running
at inspection. The configured model is absent. Saved OpenDecider training is a
one-step synthetic smoke test, explicitly unqualified; it is not a trained
production malware detector. Preserve its checkpoint and evaluation evidence.

Changes:

- `vigil-core/store/history.rs`: retain a bounded recent raw timeline and exited
  process history without deleting alerts, decisions, feedback or response data.
  New databases support incremental reclamation of freed pages.
- `vigil-service/store_writer.rs`: apply history maintenance every ten seconds,
  after detection/response, including a final maintenance pass on shutdown.
- Existing instructions/build/download docs: record the product priority,
  actual model status and smaller development/build practices.
- Local maintenance: verify alerts and feedback are unchanged before compacting
  the stopped database. Remove only disposable compiler/test artifacts inside
  verified project directories. Preserve executables used to run the app,
  checkpoints, private evidence, quarantine, source and unrelated projects.

Validation: focused history/cascade/evidence-preservation tests, service writer
tests and strict lint checks using existing build caches; build the changed
native Windows service and run a harmless download pause/resume check. No model
downloads, training, malware execution or broad firewall acceptance campaign.

## Verified outcome

- Linux core/service unit tests: 84 passed. Native Windows focused tests: 91
  passed initially; the 11 CLI checks could not launch the debug service because
  Application Control refused it. Those same CLI tests then passed against the
  rebuilt optimized service. OS protection remained enabled.
- Strict Clippy passed on Linux and Windows; formatting, both Cargo workspace
  configurations and `git diff --check` passed. Both development/test profiles
  now omit debug symbols and incremental caches. These profile changes were
  parsed, without generating another full dependency build just to measure size.
- Two small offline-maintenance tests passed, including preserved alert/feedback
  evidence, DNS cascade, live-process preservation and refusal of a busy lock.
  The utility was also refused by the real running native service's lock.
- The local stopped database shrank from 2,146,643,968 to 34,914,304 bytes. It
  retained 100,000 events, 10,000 exited processes plus 2,176 unknown/live rows,
  and all 848 alerts. Protected tables and the response journal were compared
  exactly, with integrity/foreign-key checks and a small private evidence backup.
- The rebuilt release passed harmless MP4-marked input detection, automatic
  pause, unaffected control, resume, exact input quarantine/restore and durable
  feedback. Observed alert latency was 1,375 ms in this fixture, not a guarantee
  of real-malware coverage or a media-decoder exploit test.
- The native Windows service and tray were started. Authenticated status showed
  `windows-etw`, file visibility, independent download pause on, general Auto
  off, no model loaded, no integrity issues and no reported drops/failures.
  Unattributed native events remain a coverage limit. Defender is enabled.
- A 20-second service sample used 51.2 MiB working set and 0.65% total CPU on this
  24-logical-core PC. This excludes tray/WebView memory and is not a sustained
  gaming or minimum-hardware benchmark. Threat data refreshed to 1,783 entries.
- Updated Windows ZIP: 22,507,116 bytes, all 27 manifest entries verified; no
  model weights, private database or IPC token. Service SHA-256:
  `4a69f06011fe84213091025cdd770cca395786e93d7aee6da0c1a95af4d86286`.
  MSI and older source/distribution artifacts were not rebuilt.

Private reports are in `.vigil/checks/storage/`.

## Approved cache cleanup, 2026-10-18

The maintainer explicitly approved these paths. Automatic approval review still
refused raw PowerShell deletion, including a single-file attempt, with "blocked
by policy" and no additional reason. Cargo's supported cleanup succeeded for
the genuine caches after verifying paths and checking for running builds:

- WSL `/home/esap/vigil-target`: 96,753,430,528 allocated bytes removed;
  `/home/esap/vigil-ui-target`: 8,680,722,432 allocated bytes removed. Both paths
  are absent after cleanup: **98.19 GiB** reclaimed inside WSL.
- Windows `ui/src-tauri/target/debug`: 3,842,835,849 logical bytes removed
  (**3.58 GiB**). The release tray is preserved.
- Remaining copied artifacts: `target/debug`, `.vigil/checks/native-tests`,
  `.vigil/checks/downloads/bin`, `.vigil/checks/vigil-service.exe`, totaling
  1,571,252,317 bytes (**1.46 GiB**). Cargo refuses the staged target without a
  cache marker; no marker was fabricated and the policy refusal was not bypassed.

All 28 small native test logs/reports were copied and hash-verified in
`.vigil/checks/storage/native-test-evidence/`; the owned-process fixture is
preserved separately. The reviewed manual fallback is
`tools/windows/cleanup-approved-artifacts.ps1` (inventory by default, deletion only
with `-Apply`). Its syntax was checked, but this PC's script execution policy
refused even its inventory invocation; that policy was left unchanged. With
evidence already preserved, the remaining four paths may also be removed manually
in Explorer. Do not remove the enclosing `target` or `.vigil` folders.

Retain Windows release executables, source, all runtime/quarantine data, saved
model checkpoints, training evidence and the existing rollback backup. Keep one
small owned-process fixture for repeat pause checks without a new full test build.
WSL freed filesystem space is reusable inside WSL; deleting caches alone does
not guarantee the virtual disk immediately shrinks on drive C. No distribution
shutdown or virtual-disk compaction is authorized by this cache-only scope.
