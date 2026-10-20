# Vigil readiness review - 2026-10-15

**Working native Windows preview; production requirements are not all complete.**
This review replaces the current-status claims in the 2026-10-14 report. The
maintainer authorized continuation, reviewed dependency exceptions and replacement
of `CLAUDE.md`. No repository, package or private host telemetry was published.

## Runtime and enforcement

The optimized Windows service/tray are now running as native Windows processes;
the runtime update preserved the configuration byte-for-byte.
WSL builds Windows executables and runs Linux checks; it does not monitor Windows.
This PC's configuration is Prompt, `response.enabled = true`,
`response.automatic = false`, with no model configured. Manual response requires
an explicit choice; network actions also require Windows UAC. Automatic response
is refused by the service. New installations default to monitor-only.

The tests used owned disposable programs, temporary files and private loopback
connections. No ordinary user program was blocked or stopped. Defender, Windows
Application Control and host firewall policy were not weakened. No experiment can
establish that all future enforcement actions have zero effect on a PC: a chosen
block intentionally affects every instance of that executable path.

## Changes completed

- Built optimized Windows x64 service, launcher, response helper and native Tauri
  tray using the installed Windows SDK through WSL. Built the native Linux x64
  service. Source build helpers now support both Windows workspaces and release
  profiles; package selection is explicit.
- Fixed stale launcher health after restart. Explicit command-line launch errors
  return instead of opening a modal dialog that hangs automation.
- Added service-reported automatic-response availability. Window and tray mode
  controls respect the separate automatic flag; rejected mode changes restore
  the service's actual selection.
- Isolated Windows webview data by Vigil profile. The pinned Tauri runtime omits
  `WindowConfig.data_directory` when creating its runtime attributes, so the
  window is built with the explicit data-directory API after the session lock.
  Added a real WebView2/CDP acceptance harness with service-PID verification,
  tab/trust/mode checks and no mocked Tauri API.
- Fixed Linux cleanup when its private nftables table was removed externally;
  cleanup is idempotent and restores the owned process's cgroup. Integrity checks
  inspect the expected chain/rule. Unprivileged Linux no longer advertises a
  usable network-response backend merely because nftables exists.
- Added Debian and RPM packages for a headless, unprivileged Linux preview.
  They install protected payloads, a dedicated account and a hardened systemd
  unit, with no automatic service start or response enablement. Removal preserves
  runtime data. CI now includes these container lifecycle checks and the Windows
  UI harness; the newly edited remote CI workflow has not run in this session.

## Evidence and limits

| Check | Result |
|---|---|
| Linux workspace | 236 passed, zero failed; privileged/helper tests excluded from this count. Formatting and strict Clippy pass. |
| Windows workspace executables | 228 passed, zero assertion failures, six ignored. One executable (`vigil_ebpf_common`) was refused with Application Control error 4551. The suite therefore reports `success: false`, not a full pass. |
| Windows/Windows-tray compilation | Optimized builds completed; strict cross-target Clippy passed. Compilation alone is not runtime acceptance. |
| Normal-user debug UAC helper | Passed IPv4/IPv6 outbound blocking, multiple instances, unaffected control, release and abrupt owner cleanup. Test SHA-256 `3ae80e029d8028f56ecd1ce0de685194fcf23bb3403089526cf97f4b05f1e429`; helper `56efb0a69e152a74b82e7d91b21f36475055b30da4c088453fda9d1fd775ebde`. |
| Optimized UAC helper rerun | Two tests stopped at the 90-second consent timeout. Outbound acceptance is not transferred to this different helper hash. Inbound and existing-flow tests remain unverified. |
| Windows ETW file sensor | Elevated owned-file read and distinct 120-file burst passed. No registry autorun or credential access was used. |
| Linux fanotify file sensor | Owned-file read and 120-file burst passed as root. |
| Linux response recovery | Missing-table cleanup, repeated release/recovery and original cgroup restoration passed inside a private network namespace. |
| Linux network blocking | Environment failure: this WSL kernel has `CONFIG_NFT_SOCKET` disabled. Full block/release acceptance remains required on a supported kernel. |
| Optimized Windows service smoke | Authentication, wrong-token refusal, duplicate protection, actual TCP PID attribution and graceful flush passed (819 events). |
| Windows ZIP/MSI | Fresh optimized ZIP passed startup without development tools, duplicate/config protection, crash restart/token rotation, tamper reporting, damaged-config shutdown and corrupt-package refusal. MSI passed actual per-user install, custom path, shortcuts, runtime, metadata-fixture major upgrade and uninstall while running with data retained. Clean machines and real-payload upgrades remain separate gates. |
| New packaged Windows UI | Passed real WebView2/Tauri/service acceptance after the profile-directory fix: verified service PID, tabs, trust add/remove, mode changes and Auto disabled. Windows first refused the unsigned tray with error 4551; an unchanged-artifact retry succeeded. No security setting changed. |
| Debian/RPM lifecycle | Both passed in isolated Ubuntu 24.04/Fedora 44 containers: install, unprivileged runtime, protected files, no autostart, authenticated status, duplicate guard, flush, configuration-preserving reinstall and data-preserving removal. |
| Linux package compatibility | Current x64 binaries require glibc 2.39. Containers did not boot systemd; unit boot behavior, version-to-version upgrades, rollback and older distribution baselines remain untested. |
| Dependency policy | Both workspaces pass with five approved exact-version MPL exceptions and documented advisory risk exceptions. The Wasmtime feature-surface guard passes. |
| Source/history hygiene | 320 current source files and 190 reachable historical blobs scanned with no common credential/private-key pattern hits or oversized skipped blobs. The exported archive's per-file hashes verify. This is not an exhaustive secret or rights audit. |

The final host status has no model loaded, no open alerts, no collection losses,
no integrity issues and automatic response disabled. Both Windows and Linux UI
workspaces pass strict Clippy. Thirteen Python simulator, training-pipeline,
model-preparation and offline feed tests pass; 40 Python files parse successfully.

Local evidence is under `.vigil/checks/`, including `native-tests/results-2026-10-15.json`,
`linux-tests-2026-10-15.log`, `wfp-broker-user-2026-10-15.json`,
`wfp-broker-release-2026-10-15.json`, `etw-files-2026-10-15.json`,
`fanotify-2026-10-15.log`, `linux-recovery-2026-10-15.log`,
`linux-deb-acceptance-2026-10-15.log` and `linux-rpm-acceptance-2026-10-15.log`.
Archive checksum sidecars and package manifests identify the exact local payloads.

## Jev and model qualification

The official documentation checked today lists Jev 1.14 (`jev-1.14.0`) as the newest
release, available October 14. Its alias table still maps `jev-latest` to 1.13 and
`jev-preview` to 1.14. Pin versions for evaluation. Jev does not support customer
fine-tuning/LoRA; customize state, question instructions and criteria instead.
No Jev API call or private telemetry upload was made.
[TypeSafe model documentation](https://docs.typesafe.ai/models).

Vigil's local adapter uses **OpenDecider**, a separate model. The latest real local
inference run (October 14) completed 15 synthetic held-out cases for both the
pinned base and a one-step head-training checkpoint. Both scored 100% malicious
recall and **100% benign false positives**, with about 2.33 seconds p95 latency and
1,217 MB peak process-tree RSS. This tiny synthetic set does not establish real
detection quality. The trained checkpoint is a save/load smoke test, not an
accuracy improvement. Both remain unqualified and disabled.

Useful next model work requires representative, consented and reviewed data,
application/family-disjoint splits, validation-only calibration and an untouched
test set. Required evidence includes 200+ normal apps, at least 10% human review,
sufficient held-out samples and a measured 168-hour benign replay. Prompt tuning
and deterministic numeric comparisons should precede more training. Test
instruction injection and option-order sensitivity.
[Jev 1.13 documented limitations](https://docs.typesafe.ai/model-jaggedness/jev-1.13).

## Resource sample

A 30-second sample of the optimized service on this 24-logical-processor
development PC measured 41.2 MB working set, 23.0 MB private memory and 2.60% of
one CPU core (about 0.11% of total host CPU). The service, launcher, tray and
WebView2 process tree together used 132.9 MB private memory. Summed working sets
were 415.5 MB and double-count shared pages. This is not the required four-core/
8-GB reference-machine test or a long-duration measurement; no model was loaded.

## Open-source and production decision

The project can be presented as an **experimental open-source preview**, with its
MIT OR Apache-2.0 license, third-party notices and these limitations visible. The
[MPL review](license-review-2026-10-14.md) is approved; the
[advisory review](advisory-review-2026-10-15.md) records accepted dependency risks,
not security fixes. Confirm contributor/asset rights and configure the repository's
private vulnerability reporting before publication. Nothing was pushed or published.

Production still needs signing, clean-machine installation and real upgrade/
rollback tests, protected privileged deployment, a real OS model sandbox,
qualified models, supported-kernel response tests, full native sensor coverage,
fault/power-loss recovery and quarantine metadata fidelity. macOS full mode needs
entitled native helpers and actual hardware testing. ARM64, reference-hardware
resource budgets and the remaining live-evidence work are tracked in the
[backlog](backlog.md). User approval cannot substitute for those implementations
or measured acceptance results.
