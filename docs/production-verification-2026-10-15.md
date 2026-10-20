# Production-use verification - 2026-10-15

**Verdict: working native Windows preview; not ready to rely on for production
protection.** This is a fresh check of the actual release executables and running
configuration, following the earlier [readiness review](readiness-2026-10-15.md).
Passing a harmless fixture establishes working integration, not malware efficacy.

## Fresh results

| Check | Observed result |
|---|---|
| Existing Windows runtime | Service PID 34232 had run for 11,689 seconds and reported 7,953 events in that session. Zero reported collector failures, losses, unattributed records or integrity issues. |
| Actual runtime smoke test | Passed authentication, rejection of a wrong token, duplicate-instance protection, real TCP PID attribution and graceful flush of 838 events. |
| Packaged UI | Passed real WebView2/Tauri/service tests: service identity, tabs, trust add/remove, Monitor/Prompt changes and Auto disabled. The captured Status screen displays the coverage and response limits. |
| Sensor -> alert -> manual response | Passed with the actual optimized service and a harmless temporary rule. Verified the owned child's PID, parent, birth time, path and SHA-256 before suspending it through authenticated IPC. Its heartbeat stopped while a separate control process continued. Resume and repeated release succeeded. |
| Durable response evidence | After graceful shutdown, the alert was resolved, one feedback row existed, the response journal recorded release, all 1,007 events were flushed, and SQLite integrity passed. Observed process-spawn-to-alert polling time was 2,563 ms, a single integration sample, not a performance percentile. |
| Existing live database | Read-only `integrity_check` returned `ok`; no foreign-key violations. Schema version 5; 69,735 events at the snapshot. Its 47.28-hour timestamp span includes previous sessions and is not continuous protection or a qualified benign trial. |
| Release identity | Service, launcher, helper and tray all match the corresponding bytes in the existing Windows ZIP. The launcher is named `Vigil.exe` in the package. |
| Signatures and startup | All four executables are unsigned. No Vigil SCM service, startup command or scheduled task was registered. This is a user-session preview, with no verified protection after reboot. |
| Release firewall outbound/recovery | **Overall failed.** The test reached and passed IPv4/IPv6 blocking, both executable instances, unaffected control and explicit release. It then failed with `WFP owner exited before readiness` during the separate owner-crash phase after 97.74 seconds total. That child discards stderr, so the precise underlying failure was not captured. Do not report crash recovery as passed or assume a specific UAC error from timing alone. |
| Release firewall inbound/existing flows | **Not verified.** The independent test failed before installing its block: `Windows administrator consent did not complete within 90 seconds`. This is a consent timeout, not evidence that inbound filtering passed or failed its traffic assertions. |

The normal profile remains Prompt with manual response enabled, automatic response
disabled and no model loaded. Its response journal was empty. Tests used isolated
profiles, disposable owned executables and loopback connections. They did not
change the normal configuration, stop normal applications or weaken OS security.

## What prevents production use

1. **Insufficient active visibility.** The running polling collector sees processes
   and TCP. DNS, UDP, sensitive-file, registry, injection and network-byte evidence
   are unavailable. Healthy counters describe that limited collector; they do not
   establish complete coverage. Privileged sensors have separate acceptance gaps.
2. **Detection quality is unqualified.** The runtime uses rules and a hand-weighted
   heuristic, with no trained model loaded. The recorded local model evaluation
   produced 100% benign false positives on seven synthetic benign test cases.
   No representative reviewed corpus, sufficient held-out evaluation or measured
   168-hour benign trial has qualified a release. See the [model report](../ml/reports/eval.md).
   It was not rerun here because the model and evaluation inputs were unchanged.
3. **Deployment and trust are incomplete.** Unsigned, user-writable development
   payloads and a session watchdog do not meet the protected service/installer
   requirement. Signing, clean-machine acceptance, real payload upgrades/rollback,
   protected privileged paths and a real OS sandbox for model execution remain.
4. **Response acceptance and recovery are incomplete.** The exact release's full
   firewall suite has not passed. Existing network flows may survive a block.
   Suspension crash/checkpoint gaps and quarantine metadata fidelity remain open;
   ordinary shutdown/resume success does not close those fault scenarios.
5. **The wider release matrix is incomplete.** One native Windows test executable
   remains refused by Application Control in the earlier suite. Linux full network
   response needs a supported kernel; macOS full mode, ARM64, reference hardware,
   long-duration stress and the updated remote CI have outstanding work. Earlier
   passing unit-test counts were not rerun or relabeled as fresh complete suites.

The complete work list remains in [the backlog](backlog.md). This check supports
controlled preview use and an honestly labeled experimental source release. It
does not support a claim that Vigil is a production-ready endpoint protector.

## Reproduction and evidence

The new [acceptance harness](../tools/windows/test_detection.py) uses the real
Windows service and a native `vigil_respond` test executable. It inserts no fake
events, alerts or response records. Its temporary rule recognizes a harmless
fixture, and all actions are restricted to the exact process it created.

```powershell
python tools/windows/smoke_test.py
python tools/windows/test_ui.py --screenshot .vigil/checks/production-recheck/ui.png
python tools/windows/test_detection.py --fixture .vigil/checks/native-tests/vigil_respond-bcf42ebb3f003690.exe --report .vigil/checks/production-recheck/detection.json
```

The fixture filename is specific to this build; a fresh Cargo build produces its
own test executable. The test neither requires nor requests elevation for
suspend/resume. Network acceptance is a separate test that uses normal Windows
administrator consent.

Local, ignored evidence is in `.vigil/checks/production-recheck/`: `runtime.log`,
`ui.log`, `ui.png`, `detection.json`, `host.json`, `deployment.json`,
`enforcement.json`, `enforcement-inbound.json` and the corresponding test
stdout/stderr files. Two initial
harness construction errors (rule directory and hash JSON representation) are
preserved as `detection-harness-*.json`; both were corrected before the successful
run. No runtime Rust code or shipped binary was changed for this verification.

Exact SHA-256 values:

| Artifact | SHA-256 |
|---|---|
| Service | `f541e43c6e8156db5b12f80a38b86cd83c3e2b9549cac9d4243540339027ec50` |
| Launcher | `7e036cff9b852c5f7e81599df15b2e218a395aa43139b4c441380862e4e68dec` |
| Response helper | `bd66aa4c6a994934b8527755949cde125e927e2fa48004e031919aac25ec5586` |
| Tray | `79d2a017fd02b35b4898da2eadd46fc4019ec5a67885ab2fc06219e8549d83cf` |
| Native response test fixture | `9a5c57bcbf9403982160d839e19497a51ffac5e8d4af9e1601eed1dcd05b17f4` |
| Windows preview ZIP | `16dec9719c83139c49e0d77ed02074469704d073e141dd5b618abda371629191` |

The existing source ZIP predates this new harness/report; it was not rebuilt or
published as part of this verification.
