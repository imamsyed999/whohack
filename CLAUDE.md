# whohack engineering instructions

The maintainer delegated completion of this project to the coding agent on
2026-10-15 and explicitly authorized replacing this file. Continue implementation,
repair, local builds, scoped acceptance tests and release preparation without
repeating approval requests for work already authorized. Preserve unrelated work.

## Scope and decisions

- The maintainer reaffirmed on 2026-10-17: prioritize lightweight Windows
  protection when downloads are opened, played or run. Observe their readers,
  child processes and network behavior, promptly pause strong danger evidence
  and notify, and use evidence-bound quarantine. Do not automatically execute
  untrusted downloads on this PC. Broad firewall certification is not the current
  task. Keep ordinary media playback and unrelated applications unaffected.
- Storage is a product constraint. Inspect space before expensive builds; reuse
  existing artifacts and run focused checks. Do not download more models, create
  duplicate training environments or run new training without a concrete need.
  Preserve unique checkpoints and reviewed data. Remove disposable test/compiler
  output after validation, with resolved paths confined to this project's caches.
- The current model research is Laya/OpenDecider, not a verified Luna deployment.
  The saved one-step synthetic head is unqualified and no decision model is
  configured for normal use. Do not describe training mechanics as detection
  quality; qualification needs representative reviewed data and false-alarm tests.
- On 2026-10-18 the maintainer clarified that Laya is the intended model and
  explicitly authorized training and the scoped cache cleanup. Keep training
  below 50,000,000,000 bytes of VRAM, with a lower allocator budget and resource
  guard. Use the existing CUDA environment and a small pinned Laya overlay;
  retain bounded checkpoints. No amount of synthetic fine-tuning qualifies the
  model for production. Keep model-driven automatic response behind evaluation.
- The completed M13 Laya candidate is a full-encoder synthetic development
  fine-tune, with five epochs and the best checkpoint from epoch two. Peak total
  GPU usage was 14.78 GB. The 190-case synthetic test and 16-case native CPU
  compatibility check are recorded in `docs/plans/M13-laya-training.md`; CPU
  performance and representative-data gates still fail. Do not enable this
  candidate or describe it as production ready. The valid CPU memory sampler
  includes the real model child behind Windows' venv launcher.
- `docs/whohack-master-prompt.md` defines the target product. Read it for requirements;
  the dated readiness reports and `docs/backlog.md` describe verified status.
  These instructions supersede its obsolete requirement to request routine
  implementation approval. Authorization does not count as a passing test.
- M14 renames the product and source to whohack 0.1.1, preserving legacy state,
  quarantine bytes and installer upgrade identity. Native builds and most tests
  passed; Windows Application Control blocked the new packaged launcher and one
  test binary. Do not bypass that policy. The old native instance remains running.
- M14 expanded Laya to 1,473 development cases, with 266 fresh authored test cases
  and ten weak-label public telemetry training cases. A GPU telemetry stop ended
  the second epoch; the selected first-epoch checkpoint was separately calibrated
  and evaluated. Verdict/action accuracy improved on those fixtures, but the
  model remains unqualified, disabled, and too large for the 1,200 MB CPU target.
  Preserve stopped-run reports and the independent finalization report. Do not
  recycle the now-inspected fresh test families into fitting or repeat test-based
  tuning. See `docs/plans/M14-whohack-and-data.md` for measurements and limits.
- Deliver native Windows executables. WSL may compile them and test Linux, but
  Linux process monitoring is never evidence of Windows host monitoring.
- Implement one reviewable milestone at a time. Record its files, interfaces and
  validation in `docs/plans/`, then proceed. Keep modules focused and avoid stubs.
- The maintainer approved the reviewed exact MPL-2.0 package/version exceptions in
  `docs/license-review-2026-10-14.md`. Keep exceptions narrow, retain attribution
  and source links, and audit both Cargo workspaces.
- Isolated enforcement tests on disposable, owned helper processes are authorized.
  Keep default response confirmation-only. Automatic response requires separate
  configuration and qualified evidence; do not enable an unqualified model merely
  to make a readiness check green.
- The maintainer subsequently prioritized downloaded-content danger detection and
  authorized immediate intervention. M11 permits the separate `pause_downloads`
  opt-in on this PC after owned-process acceptance. Prefer reversible pause and
  evidence-bound quarantine; protect shared viewers. See
  `docs/download-protection.md` for tested scope and remaining detection limits.
- Do not disable Defender, Application Control or other OS protection; run real
  malware; modify unrelated applications; or upload private telemetry. Use normal
  OS elevation when required. Never bypass a denied UAC prompt.
- Build and test local release artifacts. Publishing, spending money, obtaining
  signing identities and changing external accounts require actual credentials
  and applicable authorization; never manufacture these or report them complete.

## Project facts and verification

- M16 reaffirms download-open/run behavior protection as primary and folder checks
  as optional. The new dataset contains 1,067 cases, including 90 weak public
  observations from 138 text logs and 160 new authored states. Prior M13/M14
  holdouts remain excluded. Three new Laya training attempts stopped on stale GPU
  telemetry before completing an epoch; no new checkpoint or accuracy improvement
  exists. Preserve the data and stop reports. The optional NVML monitor retains
  all original limits and now validates source timestamps; never weaken the
  guard to complete training. See `docs/plans/M16-download-decisions.md`.
- Concurrent folder-check changes were reconciled around Microsoft Defender,
  with report-only default and explicit remediation choice. Follow the exact
  build/activation status in `docs/plans/M16-optional-folder-check.md`; source
  implementation is not proof that this PC is running it. The configured legacy
  service stopped during this work, and Windows Application Control blocked the
  new service acceptance launch. Do not bypass OS policy or the earlier canceled
  elevation. No Laya model has been enabled.

- M15 adds the download activity UI/API and fixes bounded-input eviction and
  repeated-read timestamps. Downloaded-file associations are evidence, not safety
  verdicts. Keep the read/argument/inherited distinctions and PID reuse bounds.
  The existing elevated 0.1.0 service remains running because Windows elevation
  for this session was canceled. Do not bypass or repeat that denied elevation.
  `Update whohack.cmd` is the explicit administrator restart entry point.
  See `docs/plans/M15-download-activity.md` for checks and exact-build limits.

- Rust stable, edition 2024; root workspace `crates/*`, separate UI workspace
  `ui/src-tauri`. whohack source is MIT OR Apache-2.0; dependency licenses remain theirs.
- Every `i64` timestamp is Unix milliseconds UTC (`whohack_core::time`). `Action`
  derives `Ord` in severity order. Type deviations are documented in whohack-core.
- Check official current documentation before changing external APIs or models.
- Run `cargo fmt --all --check`, strict Clippy and workspace tests for relevant
  targets, plus meaningful acceptance tests for changed behavior. Report ignored
  privileged tests and external release gates separately from completed checks.
- Keep secrets, tokens, databases, private config, model weights and local test
  evidence out of source archives. Preserve user config and data through upgrades.

## This development machine

- `Start whohack.cmd` launches native Windows service and tray. Local runtime data
  is under `.vigil/windows`; packaged previews use their own private data directory.
- Windows compilation can fail with Application Control error 4551. Keep that
  policy enabled. `tools/windows/cross-build.py` uses the installed Windows SDK
  and local LLVM in WSL; its output executes natively on Windows.
- Shared disposable Cargo artifacts use `/home/esap/whohack-build-cache`; do not overwrite
  active Windows binaries. Stop only the owned whohack instance before staging.
- Windows administrator consent, signing certificates, macOS hardware/entitlements,
  representative reviewed ML data and measured long-duration trials are external
  prerequisites. Complete all independent engineering while documenting evidence
  needed for these gates. Do not promise production readiness without it.
