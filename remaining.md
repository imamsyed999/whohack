# whohack readiness

The project now runs natively on Windows. WSL is an optional build/check environment and a separate Linux runtime; it is not required to monitor Windows.

## Use the current preview

- Double-click `Start whohack.cmd` in this checkout.
- For another Windows x64 PC, extract `.vigil/packages/whohack-Windows-Preview.zip` and run `whohack.exe`. The package requires WebView2 and the Visual C++ x64 runtime, with no Python, Rust or WSL.
- An unsigned per-user MSI is also built under `.vigil/packages/`. Payload checks, actual install/uninstall and a metadata-fixture upgrade pass on this PC. Clean-machine and real release upgrade acceptance are still pending.
- Use `Start whohack.cmd status` and `Start whohack.cmd stop` to inspect or stop the launcher-owned session. Local state is under `.vigil/windows/`.

New profiles start in monitor mode with response disabled. On 2026-10-14 this PC's
profile was explicitly switched to Prompt with confirmation-only controls; models
and automatic response remain off. Direct WFP and normal-user debug-helper
acceptance passed. The optimized helper rerun timed out at UAC. Current validation
includes 236 Linux tests, 228 Windows tests (one other executable blocked by OS
policy), real packaged UI acceptance, ETW/fanotify file tests and Debian/RPM
container lifecycle tests. See the dated report for exact-build limits.

## What still prevents a production-protection claim

1. Complete exact-release Windows helper/inbound/existing-flow acceptance, remaining sensor tests and Linux blocking on a kernel with CONFIG_NFT_SOCKET.
2. Representative reviewed training/evaluation data and a measured benign week. The synthetic model evaluation did not pass.
3. macOS full-mode entitlements, native extension work and testing.
4. Signed distribution, protected privileged installation, clean-machine installer tests and the remaining platform coverage/hardening work.
5. Follow up documented upstream advisory exceptions; the exact-version license approvals are complete.

See [the current readiness report](docs/readiness-2026-10-15.md), [the detailed backlog](docs/backlog.md), [Windows build/run instructions](docs/building.md#windows), [response limits](docs/response-and-feeds.md), [sensor coverage](docs/native-sensors.md), and [evaluation results](ml/reports/eval.md).

These are explicit remaining requirements. Building all available code does not establish malware-detection accuracy, privileged-response correctness or production readiness.
