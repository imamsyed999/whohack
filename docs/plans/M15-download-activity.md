# M15: downloaded-file activity and clearer whohack UI

Scope: expose real stored download/process associations in the native Windows
app, simplify everyday controls, and verify a harmless downloaded sample plus
controlled danger detection. Keep the existing data location and quarantine
format compatible. Do not run malware or weaken Windows security policy.

Implementation:

- Add a bounded, read-only download activity query to the store and authenticated
  IPC. Distinguish observed reads, launch arguments, execution and inherited
  context. Bound activity by process birth/exit and PID reuse.
- Show downloaded filenames, opening apps and recent observed behavior on the
  home screen. Explain that a connection or a download alone is not a threat.
- Surface incomplete sensor coverage, offline/stale data and legacy service
  versions. Use plain-language alert and response controls.
- Verify branding in source and in a freshly built native app. Preserve the
  existing running service until replacement is validated.
- Download a small harmless sample over HTTP, open/decode it, and inspect native
  attribution. Separately test pause, clean-control isolation and evidence-bound
  quarantine using local harmless fixtures.

Validation will include PID reuse and attribution regression tests, native
acceptance, UI state/action checks, formatting and strict Clippy. Record measured
results and any OS-policy block below; these tests do not establish detection of
arbitrary malware or production readiness.

## Delivered

The native whohack UI now opens on Download activity, with readable file/app
cards, evidence labels, expandable observed behavior, separate alerts and
response history, and visible sensor/offline limitations. Technical diagnostics,
trust settings and app profiles remain available without dominating the home
screen. No frontend framework, external fonts or runtime dependencies were added.
Service strings remain text-only in the UI; filenames cannot inject HTML.

`list_downloads` is an authenticated, read-only additive IPC request. The service
advertises `download_activity_available`; the UI handles older services without
pretending that an unsupported query is an empty/safe file history. Store queries
return at most 20 processes and 12 recent selected events each, with presentation
strings capped at 256 characters. PID birth/exit/reuse bounds prevent unrelated
process instances' events from being joined. No schema migration is needed.

Two input-tracking bugs are fixed: repeated reads of the same bytes keep the
first association time, and a full inherited eight-file list can no longer
prevent recording a new local open. Replacement prefers the oldest inherited
entry, then the oldest local entry. Parent lists are unchanged. Child launch
arguments cannot inherit a parent's “read confirmed” flag as their own evidence.

Source, native binaries, window, tray, launcher and packages use whohack.
Historical records, the `.vigil` data directory, database/quarantine format,
legacy environment fallbacks and installer upgrade identity intentionally remain
compatible. `Update whohack.cmd` is a concrete local administrator restart entry
point. The launcher explains an older running service instead of silently
reopening its old Vigil tray.

## Measured validation — 2026-10-20

- Downloaded the **6,756-byte WAV** from the
  [CPython v3.14.0 test data](https://github.com/python/cpython/blob/v3.14.0/Lib/test/audiodata/pluck-pcm8.wav).
  SHA-256: `5b7af05fa928568dc9dbf39845da83a48720e019214a0f250aa5e8de0ebec4bb`.
  The test writes Internet Zone.Identifier metadata explicitly, starts a reader
  before the download, decodes 3,307 stereo PCM frames and plays it once through
  the Windows sound API. The existing native ETW service recorded the exact
  file/hash and a real read without a file launch argument. No alert or response
  targeted this benign reader.
- This read-only sample check uses the **existing 0.1.0 service**, not the new
  executable. Observed test-to-query completion was **9.718 seconds**; this is
  not a reaction-time or zero-delay guarantee. That service had cumulative
  sensor loss/drop counters, unchanged during this check.
- Initial sample assertions incorrectly required old ETW timestamps to lie
  inside the current wall-clock spawn interval. The recorded event time differed
  by about 10.5 seconds. The corrected read-only test proves ownership using its
  still-live Popen child, exact parent/image and unique sample path/hash. Earlier
  failed reports remain preserved. This does not correct the long-running
  service's timestamp discrepancy; further native timing work remains.
- New-build **polling collector** acceptance used a current owned Rust helper,
  temporary harmless signatures and local-only reputation fixtures. It passed
  process-to-input attribution, the new activity IPC, automatic pause, unchanged
  clean-control heartbeat, resume, exact-input quarantine and byte-for-byte
  restore. The separate localhost connection test paused its target and refused
  ambiguous removal of a shared viewer. Observed alert/action completion was
  **1.750 seconds** for the signature fixture and **1.859 seconds** for the
  network fixture. Neither is a real-malware efficacy measurement.
- Native focused Rust run: **145 passed, one CLI test blocked by Windows
  Application Control (4551)**. Do not present it as a fully passing suite.
  After the final input/launcher changes, **38 focused native tests passed**,
  including repeated reads, replaced bytes, inherited capacity and parent
  isolation. These overlap the earlier run; counts are not additive.
- Real packaged **WebView2** acceptance passed: authenticated service identity,
  whohack title, download/coverage screen, tabs, trust add/remove, mode changes
  and refusal of unconfigured Auto. The test's own service uses polling, so its
  UI correctly says file tracking is limited.
- Separate Chromium UI checks with **mocked IPC** passed evidence distinctions,
  unsafe-filename rendering, confirmation cancellation, failed-action feedback,
  unavailable-action hiding, sensor gaps, offline controls, legacy service,
  empty history, and light/dark layouts at 1,080 and 720 pixels. These are UI
  checks, not sensor evidence.
- Root/UI formatting and strict Windows Clippy passed. No model was trained,
  downloaded or enabled in this milestone.

Private evidence stays under `.vigil/checks/`: `m15-live-sample-verified.json`,
`m15-poll-pause-current.json`, `m15-poll-network.json`, `m15-native/`,
`m15-regressions/` and `m15-ui/`. An early response test used an obsolete helper
with pre-rename environment variables and failed; the harness now rejects that
helper explicitly. Successful runs used the current whohack helper.

## Remaining local step and limits

Windows administrator elevation for the isolated new-build native-file suite
was canceled. It was not bypassed or retried. The old elevated service and tray
remain running; the new interface/build has been validated separately. To
activate the replacement in this checkout, the owner must run **Update
whohack.cmd as administrator**. It checks configuration, stops this local session
gracefully, starts whohack, and preserves existing settings/data. This activation
script has been reviewed but was not executed against the live session.

The real sample proves native read attribution and benign playback for that
sample. The owned danger tests prove the response path for their controlled
evidence. They do not prove every media player/game/EXE is covered, all unfamiliar
traffic is malicious, every threat is detected before harm, or production-grade
malware detection. New-build native file acceptance after upgrade remains open.
The Laya candidates remain disabled and unqualified. Keep existing OS protection
and the preview's honest coverage indicators.

## Local delivery and storage

Refreshed unsigned Windows ZIP/MSI and a source preview are in `.vigil/packages/`.
MSI database/payload validation passed; no installation of that MSI was performed.
The source audit checked 353 working-tree files and 486 reachable historical
blobs with no supported-pattern findings. This is a bounded hygiene check, not
proof of complete secret, license or release qualification.

Final native executable SHA-256 values:

- Service: `70db3fb62f2aae2f7537ba5c9ba96596556666a6ca3fa6065176b60e8d4b56c4`
- Launcher: `cf461fde98c158a34f2a450fe0e18cfbf4c1d5513f8fc18373d3f5179e3c353c`
- Tray: `9910bbcba0868b1ebabee84694da15168673f5ad5328301d79315f5e9b317bb3`

Removed the verified disposable `/home/esap/whohack-build-cache` via Cargo:
10,077 files / **4.2 GiB**. Native deliverables, small regression evidence and
existing model checkpoints remain. No WSL disk-image compaction was attempted.
