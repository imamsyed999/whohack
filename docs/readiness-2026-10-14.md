# Vigil readiness review — 2026-10-14

**Verdict: working Windows preview; not a finished production security product.**
The source can be prepared as an experimental open-source project, but the tray
license-policy review and release gates below are unresolved. No repository or
artifact was published by this review. No claim of complete attack coverage or
zero impact on a PC is supported.

## This PC's active configuration

The native Windows launcher, service and tray are running. The service runs as
the ordinary user, not administrator/SYSTEM. WSL was used to compile native
Windows executables because Application Control rejected the native compiler;
it is not the monitoring runtime. Windows security policy and antivirus were
not changed.

`.vigil/windows/config.toml` now uses Prompt with `response.enabled = true` and
`response.automatic = false`. Every response requires a choice in the tray.
Authenticated IPC rejects Auto mode. No model is loaded, no response lease is
active, and no real user application was blocked, suspended or killed by these
tests. The config/rules were checked against their old manifest before the
intentional config edit. A backup is in
`.vigil/windows/backups/manual-response-20261014T181512Z/`.

Network actions request a separate Windows UAC helper. A denied or timed-out
request fails without recording success. The helper's successful end-to-end
path is **not yet accepted**: the normal-user test timed out awaiting consent,
and the subsequent elevated helper test was cancelled at the Windows prompt.
The ordinary preview has confirmation-only controls available, not certified
network protection. Do not enable automatic response based on this report.

At the activation check, integrity issues, collection drops/losses/failures and
open alerts were zero. A 30-second idle sample on this 24-logical-processor PC
measured 59.02 MB working set, 22.43 MB private memory, 2.24% of one CPU core
(0.093% of total host CPU). This is a small development-PC sample, not the
specified four-core/8-GB reference-machine or week-long acceptance test.
An additional instantaneous sample including the tray, WebView2 children and
launcher measured 137.66 MB total private memory. Summed working sets were
456.02 MB and include shared pages counted more than once. The service-only
59 MB figure must not be presented as the complete desktop app's memory use.

## Validation evidence

| Check | Result and limits |
|---|---|
| Linux core workspace | 236 tests passed; two privileged tests ignored. Format and strict Clippy passed. |
| Native Windows changed components | 94 tests passed: core 60, responder 9, service 22, response integration 3. Four helper/privileged tests ignored in the ordinary suite. Cross-compiled binaries ran on Windows. |
| Direct WFP enforcement | Elevated owned-child test passed: new outbound IPv4/IPv6, both instances of one executable, unrelated executable connected, release and abrupt-owner cleanup. Installation asserted below one second. Inbound/existing-flow behavior was not tested. |
| Narrow UAC helper | Build/strict Windows Clippy pass; successful elevation/pipe/WFP acceptance remains unverified after consent timeout/cancellation. |
| Consent responsiveness | Regression test passes: pending response does not lock alert reads/status; concurrent mutations return a busy error. |
| Native runtime smoke | Authentication, wrong-token refusal, duplicate guard, actual localhost TCP PID attribution and graceful flush passed with 859 persisted events. |
| Refreshed portable ZIP | Starts with development tools absent from PATH; preserves config, rejects duplicate launch, restarts an owned crashed service and rotates tokens. Tamper reporting, damaged-config shutdown/flush and corrupt-package refusal passed. |
| Refreshed per-user MSI | Cabinet/database verification, actual install, shortcuts, native startup, metadata-fixture major upgrade and uninstall while running passed on this PC, with data preserved. Clean-machine, rollback and real-payload upgrades remain untested. |
| Host activation | Prompt/manual-only, Auto refused, model unloaded, no active leases, no integrity failures. Native launcher/service/tray observed. |
| Root dependency audit | Passes using the existing documented advisory exceptions; those exceptions do not fix upstream advisories. |
| Tray dependency audit | Fails policy: four unapproved MPL packages and an unmaintained Linux GTK-chain macro dependency. CI now audits this separate workspace. |
| Source/history hygiene | Initial scan: 297 current source files and 190 reachable historical blobs, no common credential/private-key pattern hits or oversized skipped blobs. Re-run on final export. This is not an exhaustive secret/rights audit. |
| Attribution | Windows inventory covers 508 registry dependencies from both locked workspaces, including build dependencies. License/source provenance accompanies generated notices. |
| Local model inference | Fresh base and one-step head checkpoints each produced all 15 synthetic held-out predictions. Both fail qualification. |

Local logs and structured evidence are in `.vigil/checks/`, including
`native-enforcement-tests.json`, `linux-enforcement-tests.log`,
`wfp-acceptance.json`, `wfp-broker-acceptance.log`,
`manual-enforcement-status.json`, `manual-response-resource-sample.json` and
`source-history-audit.json`. The previous 2026-10-13 full native Windows suite
and installer acceptance are historical evidence, not reruns of every platform
test against this revision. ZIP/MSI tests above were rerun for the refreshed
artifacts; this does not replace clean-machine acceptance. The existing tested tray executable was retained;
this milestone changed service/launcher/response code, not its UI source.

## Jev and fine-tuning

If “Jev” means TypeSafe's hosted model, its official documentation currently
lists Jev 1.13 and says customer-specific fine-tuning/LoRA is not supported.
Customization is through state, question instructions and criteria. Numeric
comparisons should remain in deterministic code; model evaluation should include
instruction injection, ambiguous state and option-order variation. See the
[official model documentation](https://docs.typesafe.ai/models) and
[Jev 1.13 limitations](https://docs.typesafe.ai/model-jaggedness/jev-1.13).
No hosted Jev request was made and no host telemetry was uploaded. A cloud
adapter would also change Vigil's local-only privacy design.

Vigil's existing local OpenDecider adapter is a separate model and supports the
implemented CPU head-training workflow. Fresh results on 15 synthetic test cases:

| Checkpoint | Malicious recall | Benign false positives | CPU p95 | Peak process-tree RSS |
|---|---:|---:|---:|---:|
| Pinned base | 100% | 100% | 2328 ms | 1217.51 MB |
| Existing one-step synthetic head | 100% | 100% | 2344 ms | 1217.32 MB |

The one-step checkpoint is a training/save/load smoke test, not evidence of an
accuracy improvement. It was re-pinned to the reviewed current sidecar before
inference; the stale old script pin correctly refused execution. These faster
latencies compared with yesterday are not a fine-tuning gain or controlled
benchmark. Both candidates still fail data, review, sample-size, calibration,
false-positive, benign-week and memory gates. Models remain disabled.

The next useful work needs consented representative data: 200+ normal apps,
family/application-disjoint malicious and benign cases, at least 10% human
review, sufficient held-out samples, validation-only calibration and an untouched
test set. Evaluate instructions/calibration first, then compare a trained head or
encoder using the same held-out protocol. Measure a real 168-hour benign replay
and reference-machine budgets before enabling any model-based response. More
synthetic training cannot establish production safety.

## Release blockers

The [backlog](backlog.md) remains the authoritative detailed list. Major gates:

- Finish UAC-helper acceptance, inbound/existing-flow tests and response
  power-loss/fault recovery. Suspension crash windows and full quarantine
  filesystem-metadata fidelity remain unresolved.
- Validate privileged collectors on real supported OSes. Default Windows
  polling only observes processes/TCP; it does not see DNS, UDP, file reads,
  registry writes or process injection. Full macOS requires entitled helpers and
  actual macOS tests. Linux privileged response/fanotify tests remain outstanding.
- Implement hardened privileged installation with protected paths/ACLs and a
  real OS model sandbox. The current per-user MSI is deliberately unprivileged.
  Finish non-Windows packages, signing, clean-machine/real-payload upgrade and
  rollback tests, ARM64 coverage and reference-hardware budgets.
- Complete or explicitly narrow promised live evidence: AV tamper, log clearing,
  snapshot deletion, remaining eBPF coverage, provenance and model-state limits.
- Qualify models using representative reviewed data, calibration and a benign
  week. Current synthetic model results are unsuitable for automatic protection.
- Resolve [the tray license proposal](license-review-2026-10-14.md), the separate
  tray advisory and existing root advisory exceptions. Confirm contributor and
  asset rights and configure private vulnerability reporting before publishing.

The product is usable for native monitoring and explicit manual experimentation.
It should be labeled an **experimental preview**, with these limits visible,
rather than advertised as complete production endpoint protection.
