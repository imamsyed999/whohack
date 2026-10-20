# M14 - whohack rename and broader Laya training

The maintainer requested the whole product/project name `whohack` and another
Laya training round with more cases and datasets. Carry forward the 50 GB decimal
VRAM ceiling, 16 GB allocator cap, resource watchdog, single best checkpoint and
no live model enforcement without qualification. A market-leading claim requires
independent comparative evidence; additional training alone does not establish it.

Rename current source crates, executables, UI, packaging, launch entry points and
documentation consistently. Preserve old runtime data, quarantine, evidence,
protocol identities needed for migration, and prior measured artifacts. Existing
`.vigil` local state is a compatibility location, not disposable rename debris.
Add `Start whohack.cmd`; keep the old entry point as a compatibility redirect.
Build and check native Windows binaries with bounded shared compiler storage;
stage only after validating the new build. Preserve the running old protection
until the new service/tray can replace it together.

Inspect permissively licensed public text telemetry, retaining pinned source,
license, digests and acquisition limits. Fetch selected logs, never malware or
multi-gigabyte complete datasets. Map only observed evidence into the native
state contract, and distinguish emulation, observed reports and authored labels.
Do not manufacture sensitive paths, timestamps, human review or threat labels.
Expand uncertainty/benign coverage; keep dataset families/app identities/states
separate across training, checkpoint selection, calibration and a fresh test.
The previously examined test set stays excluded from further fitting.

Run continued full-encoder Laya training using the existing environment. Evaluate
the old and new candidate on the same fresh holdout after checkpoint selection;
report regressions as well as improvements. Keep failed qualification visible.
Record model/resource/storage measurements and tests. Do not run real malware,
upload private telemetry, weaken OS protection, or alter unrelated applications.

## Rename and Windows validation

Renamed all current source crates, Rust imports/workspaces, service/helper/launcher
executables, Tauri product/title/identifier, installer/package identities, Linux
and macOS service files, tooling and current documentation. Version is 0.1.1.
`Start whohack.cmd` is the new entry point. The old command name redirects there.
Historical reports keep their measured old artifact names and digests.

Compatibility is deliberate: `.vigil`, `vigil.db`, the `VIGILQ01` quarantine
header, MSI upgrade identity and `Software\Vigil\Preview` install-location key
remain stable. The tray accepts old configuration/session environment variables,
response self-protection recognizes both binary-name generations, and Linux
response recovery accepts both `vigil_` and `whohack_` table names with exactly
32 hexadecimal suffix characters. Existing system-level service installations
need an explicit migration: do not install a second system service over a live
legacy deployment. Local preview config and IPC endpoint are retained unchanged.

Native Windows release service, launcher, response helper and tray all built.
Root and UI strict Clippy and formatting passed. Of 26 native test executables,
25 ran: 227 tests passed, zero failed and six privileged/helper tests were ignored.
Windows Application Control refused the `whohack_tags` test executable with
error 4551, so the overall native runner correctly reports incomplete acceptance.
The Linux old/new response-table identity regression test passed.

The new Windows service's isolated smoke test passed authenticated IPC,
wrong-token rejection, duplicate-service exclusion, real TCP/PID attribution and
graceful storage flush (664 observed events). Its CLI reports `whohack-service
0.1.1` and validates the existing config and legacy database location.

The whohack ZIP and unsigned per-user MSI were built, with 508 dependency notice
records and no missing notices. MSI database/payload checks passed. The packaged
WebView2 acceptance stopped at launcher creation: Code Integrity events 3033/3077
confirm the executable did not meet this PC's enterprise signing requirements.
No policy was disabled, file relocated to evade the denial, or approval invented.
The UI and MSI install/upgrade checks therefore remain unverified for this build.
The existing Vigil 0.1.0 service (PID 23296) and tray remain running, with downloaded
content pause enabled, general model automation off, and no configured model.
This is a build/source rename, not a successfully activated runtime upgrade on
this policy-controlled PC. A policy-approved signing/distribution path is needed.

The live legacy collector also reports cumulative dropped/lost/unattributed
events; its running status is not proof of complete detection coverage. The
rename and additional training do not resolve that separate sensor limitation.

## Dataset and resource controls

The expanded frozen dataset contains 1,473 cases: 437 previous training cases,
1,026 new authored cases from 54 recipes, and ten provisional public telemetry
cases. Partitions are 827 train, 190 checkpoint-selection, 190 calibration and
266 fresh test cases. All 456 previous validation/test cases stay excluded from
fitting. Public rows are weak-label training only and are never counted as a
trusted detection benchmark. Details, pinning and import limits are in
`docs/training.md`; the public source is
[Splunk attack_data](https://github.com/splunk/attack_data).

Three initial attempts stopped before any completed epoch because NVIDIA
telemetry timed out or became stale. Their small reports were retained, with no
extra checkpoints. The repaired guard uses one persistent NVIDIA query process
and cooperative GPU idle intervals. A 30-second bounded GPU diagnostic passed
before training resumed. It pauses GPU submission when samples age beyond two
seconds, rejects samples stale beyond eight seconds, and retains the original
16 GB allocator, 45 GB device-stop and 50 GB user-ceiling settings. It never
changes global GPU, driver or OS protection settings. The new guard tests cover
stale/invalid/exited telemetry in addition to the existing budget checks.

The resumed run completed epoch one and saved its checkpoint. Another stale GPU
telemetry event stopped epoch two; its partial updates were discarded. Training
took 410.14 seconds including shutdown, and the selected checkpoint came from
epoch one at 180.01 seconds. This is not a completed 16-epoch run. The original
failed training report remains intact. `ml/finalize_laya.py` then calibrated the
selected checkpoint and compared it with the original M13 parent in a separately
guarded process, with zero additional gradient updates and 100 ms idle time
between inference requests. Finalization completed in 222.19 seconds including
shutdown. Later guard changes latch synchronous stale-sample failures and avoid
closing a pipe while its reader still holds its I/O lock; focused tests cover
both cases. GPU telemetry instability remains a limitation on further long runs.

## Recorded results

All numbers below are development measurements, not malware-lab efficacy.
The 266-case fresh test contains 76 benign, 76 suspicious and 114 malicious
authored cases. Both candidates were evaluated with their own separately fitted
calibration, on the exact same test rows after checkpoint selection.

| Question | M13 parent | Expanded candidate |
| --- | ---: | ---: |
| Matches purpose | 100.00% | 100.00% |
| Verdict | 85.71% | 98.87% |
| Tactic | 66.54% | 85.34% |
| Severity | 86.09% | 97.37% |
| Action | 72.18% | 90.23% |

The blocking-policy threshold fired for 114/114 authored malicious cases and
0/76 benign cases for both models; this threshold also counts sufficiently
confident suspicious predictions, so it is not malicious-verdict accuracy.
Calibration was not uniformly better: verdict ECE rose from 0.00456 to 0.01128,
and severity ECE from 0.08415 to 0.08680. Errors remain on combined credential,
persistence and exfiltration/channel scenarios. Seven uncertain LSASS/TLS cases
received overly aggressive action labels; all 19 document-transfer/relay cases
received the wrong action. These examined test families must not be reused for
future fitting or selection.

The bounded native CPU sidecar check covered 16 cases: all top answers matched
GPU inference, maximum probability difference was `3.2486e-6`, and serving left
the checkpoint unchanged. CPU p50 was 2,291.7 ms and p95 2,720.7 ms. Peak RSS of
the complete owned process tree was **2,871.19 MB**, above the 1,200 MB target.
The 16-case latency result does not replace a full representative CPU evaluation.

The actual whohack Windows service also loaded the pinned advisory manifest and
returned all five model answers for a four-event inert replay. It reported
`applied_action: none (offline replay)` and did not change live configuration.
The final verdict was malicious; the tactic favored credential theft over the
authored ransomware label, consistent with the combined-signal errors above.
This verifies native model integration, not universal detection correctness.

Recorded training peaks: total GPU **14.69 GB**, PyTorch allocated **8.36 GB**,
reserved **9.04 GB**, training RSS **3.57 GB**, sampled GPU temperature **44 C**.
The separate finalization peak total GPU was **7.52 GB**. These are observed
samples; independent applications and stalled driver telemetry are outside the
allocator's control. No limit was increased to finish the run.

Candidate weights SHA-256:
`7094f43506967b1c786daeb58293a1c73806c1e7096d6a9584e96b61f5403966`.
Calibration SHA-256:
`83a86960ee454c584bbdefb83e303fdebd8c4e665646064064c04552f0ab1f6d`.
The candidate, advisory-only manifest, original stop report, selected-checkpoint
provenance, comparison and CPU report stay under ignored `.vigil` directories.
No checkpoint is enabled for live decisions or automatic response.

The model remains **unqualified**: representative reviewed data, independent
attack/benign testing, benign-week measurements and the CPU memory target remain
unmet. It cannot be described as production ready or a market leader.

## Remaining artifacts and handoff

Thirty-two ML/data/resource tests, two storage-tool tests and one model-manifest
test passed. JavaScript syntax checks passed. The final source audit scanned 346
selected working-tree files and 190 reachable historical blobs, finding none of
its supported secret patterns. It is not a universal secret audit.

Cargo's own cleanup removed **4.1 GiB** of newly created shared WSL build output;
this returns reusable space inside WSL, not a compacted Windows VHD. Automatic
approval review rejected removal of the 26 hash-verified copied Windows test
executables (297,075,712 bytes) with `blocked by policy`. Those artifacts and the
earlier blocked Windows cleanup remain; no alternative deletion mechanism was
used. Logs, old release binaries, unique checkpoints, configuration, history and
quarantine are preserved. The new public logs total about 111 MiB; model weights
remain about 843 MB, with only one selected expanded checkpoint retained.

The Windows build and source archives are named `whohack-Windows-Preview.zip`,
`whohack-Windows-Preview.msi`, and `whohack-Source-Preview.zip`. They are local
preview artifacts, not published or certified production releases.
