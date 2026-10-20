# Remaining release gates

Updated 2026-10-15. This is the current backlog; it replaces the earlier skeleton-era list. The master specification remains the target, not a claim that every acceptance criterion has passed. See [the dated readiness report](readiness-2026-10-15.md) and [subsequent production-use verification](production-verification-2026-10-15.md) for current evidence.

The subsequent [download-protection milestone](download-protection.md) follows the
maintainer's narrower priority: detect dangerous downloaded-content behavior,
pause the responsible process and notify, with safe source-file quarantine.

The [2026-10-17 storage milestone](plans/M12-lightweight-storage.md) reinforces
that priority, limits raw event/exited-process history, compacts the local event
database with evidence preservation. On 2026-10-18 the approved Cargo cleanup
removed 98.19 GiB inside WSL and 3.58 GiB of Windows UI debug files; 1.46 GiB of
copied test artifacts remains blocked by automatic approval review. The
[Laya training milestone](plans/M13-laya-training.md) uses a pinned, separate
training environment with a 16 GB allocator budget and a 50 GB requested ceiling.
The full Laya development fine-tune completed five epochs and retained epoch two.
Its 190 synthetic test cases gave 90% verdict/action accuracy, but there is no
reviewed real-world dataset. CPU compatibility passed; the 16-case performance
check measured 3.49 s p95 and 2.66 GB peak RAM, exceeding the deployment budgets.
Candidate models remain unqualified and disabled. Normal Windows monitoring does
not require training dependencies or model weights. Existing accumulated ETW
loss and unattributed events also prevent claiming complete live coverage.

## Working and checked locally

- Native Windows service, tray, launcher, authenticated IPC, duplicate protection, process/TCP attribution and graceful event flush.
- Fresh optimized sensor-to-alert/manual suspend-resume acceptance passes with a harmless temporary rule, exact owned-target identity checks, an unaffected control process and durable feedback after shutdown. This proves the integration path, not malware detection quality.
- Capability taxonomy, 19 category templates, taint/lineage, signatures, bounded YARA scanning, rules, alerts, profiles, trust, timelines and stored feedback.
- Durable destination history and expiring threat-feed snapshots. Optional hash-only VirusTotal helper has offline consent/cache/rate-limit tests.
- Bounded 60-second features, local pinned ONNX scoring, five-question CPU decision adapters, fusion, decision evidence, advisory mode and training/evaluation tools.
- Windows/Linux response implementations, response journal, inert quarantine, no-clobber restore and interrupted-quarantine recovery. New profiles keep response disabled. This PC now has native ETW file/network monitoring and the independent automatic download-danger pause enabled. General Auto mode and models remain off; file removal requires an evidence-bound decision.
- Downloaded-input attribution, propagation to children, source-file alerts and shared-viewer quarantine protection. The latest optimized Windows build passes owned-reader MP4/WAV/PDF, native file-read and local threat-destination pause tests. Ordinary content/control processes continue; pause, resume, removal refusal and exact-file restore are checked. These are harmless fixtures, not a malware-efficacy study.
- Native monitoring exposed noisy alerts from ordinary database writes. Mass-write signals now focus on user files, the built-in alert requires download context, and unchanged window evidence is coalesced. The initial 844 insufficient-evidence alerts remain in the local audit history as resolved; no response was applied and no human-feedback labels were fabricated.
- Extracted Windows ZIP test: no development tools on PATH, crash restart, token rotation, duplicate guard, tamper status, disabled response on integrity failure, shutdown and damaged-package refusal.
- Unsigned per-user Windows MSI build, cabinet/database verification, actual install/uninstall with a running service, and a metadata-fixture major upgrade on this development PC. Custom installation paths and existing config/data survive the upgrade; removal preserves runtime data. It adds Start-menu launch/stop shortcuts; it does not install a SYSTEM service.
- Latest root Linux workspace: 209 passed, three privileged tests ignored. Native Windows: 234 passed across the full run and a four-test unchanged-artifact retry, with six privileged/helper tests ignored. Application Control initially blocked that test executable; it remained enabled. Formatting, strict Clippy and optimized Windows builds pass. See the download milestone for the current focused runtime/UI evidence.
- Debian/RPM unprivileged headless packages pass isolated install/runtime/reinstall/remove checks. Current x64 artifacts require glibc 2.39. No systemd boot or real version upgrade was tested in those containers.
- Owned-file ETW and fanotify live tests pass. Linux missing-nftables-table recovery, repeat cleanup and cgroup restoration pass in a private network namespace.
- Five exact-version MPL exceptions are approved; both dependency audits pass with documented advisory exceptions and a Wasmtime feature guard. Exceptions do not fix upstream code.

## External access and remaining acceptance

- **Windows WFP/helper acceptance:** the direct elevated backend and normal-user debug helper passed outbound IPv4/IPv6, executable-wide scope, unaffected control, release and owner cleanup. The latest optimized-helper test passed its initial block/control/release steps, then failed when the separate crash-test owner exited before readiness; that child's stderr was discarded. The independent inbound/existing-flow test timed out waiting for administrator consent. Full release acceptance remains incomplete. Do not transfer an earlier build's result to a new artifact.
- **Privileged collectors:** ETW/fanotify owned-file tests passed. Verify ETW network/DNS/registry events and loss accounting and existing Sysmon events. Run full Linux response acceptance on a kernel with CONFIG_NFT_SOCKET; the installed WSL kernel lacks it. No driver, Sysmon installation, registry autorun entry, injection or antivirus change was performed.
- **macOS full mode (M9):** Endpoint Security/Network Extension entitlements, signed Swift helpers, XPC integration and a physical/virtual macOS test environment. Limited libproc monitoring is implemented; full collection/response is not.
- **Signing and installers:** obtain Windows signing credentials and Apple Developer ID/notarization access. Windows intermittently refuses unsigned artifacts. Repeat MSI install/upgrade/uninstall on clean Windows machines and test rollback plus upgrades between real payloads; complete PKG packaging. Debian/RPM construction and container lifecycle tests are complete; booted-system and real-upgrade tests remain.
- **Representative ML data:** 200+ normal apps, held-out malware/report families, at least 10% human review, calibration and a measured benign week. Synthetic mechanics tests cannot replace these. Current evaluation is unqualified: see [the report](../ml/reports/eval.md).
- **Source/binary release policy:** five exact-version MPL dependencies are approved in the [license review](license-review-2026-10-14.md). Root and tray advisory exceptions are documented; track patched compatible upstream releases. Confirm contributor/asset rights and configure private vulnerability reporting before publication.

## Engineering work before a production release

- Run installed privileged services only from administrator-owned locations with protected config, rules, models and data. The manual SCM registration command does not prepare those ACLs or a safe installer. Enforce a real OS sandbox for privileged model serving; Python offline/audit restrictions and Windows process jobs are not that sandbox.
- Complete native ARM64 Windows and Intel/Apple Silicon macOS CI/runtime coverage. Validate resource budgets on the specified four-core, 8 GB reference PC. The latest local Tier 1 microbenchmark meets 50 microseconds; Tier 2 does not meet the measured memory/latency gates.
- Close response crash/checkpoint gaps with power-loss/fault tests. Quarantine does not preserve all ownership, ACL, xattr and filesystem-time metadata. Linux cgroup migration still uses a numeric PID between checks; missing-table recovery is now tested, but the numeric-PID migration race remains.
- Extend Linux eBPF coverage to fork-only children, unconnected UDP and per-flow bytes. Add download provenance for executables moved out of Downloads without xattrs. Resolve relative script working directories on Windows/macOS and macOS quarantine source URLs.
- Implement or explicitly exclude live AV-tamper, security-log-clear and recovery-snapshot-delete evidence. Reserved taxonomy tags and replay fixtures do not provide live coverage. Sysmon support currently covers remote-thread creation only.
- Complete model-state compaction with exact tokenizer measurements, per-flow/child-name evidence and live profile proposals. Keep raw commands, user paths, contents and untrusted instructions out of model input.
- Replay accepts the configured ONNX/rules and exports the same score in model state. Nested Laya layout, bounded model trees, minimum sample counts, benign-week evidence and exact operating thresholds are checked. Full Laya training now uses an isolated 0.4.11 overlay and a pinned local checkpoint; the existing 0.3.24 serving environment is preserved. Representative reviewed data and measured deployment performance remain release gates.
- Retest cold start under sustained load and crashes during analysis. Pending shutdown observations are persisted without new expensive file analysis; they may lack classification.
- Track upstream YARA-X/Wasmtime advisory fixes and remove the documented exceptions in `deny.toml` when supported patched releases exist. A passing audit with exceptions does not resolve those advisories.

## Current operational limits

Default Windows polling sees processes and TCP only; it cannot detect file reads, DNS, UDP or registry writes. Model loading, response and advanced sensors are opt-in. Automatic response is a separate default-off opt-in and is unavailable to the unprivileged Windows helper route. WFP blocks every instance of one executable path for new connections; Linux blocks new sockets in its cgroup. Neither backend promises to terminate existing flows.

The independent `pause_downloads` flag can suspend a process without firewall
elevation or model-driven Auto. Native file monitoring still needs an administrator
launch. The included YARA signature is only EICAR; threat snapshots expire without
refresh, large inputs skip content scanning, and broad real-malware/false-positive
validation remains open. The current local setup is an experimental extra layer.

Keep built-in antivirus enabled. No real malware has been run on the development host. Local manifests detect changes but are not a signed trust anchor against an administrator-level attacker.
