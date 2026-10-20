# M4: response and threat intelligence

Finish the missing response path before moving to scoring/model milestones.

- Add `vigil-respond`: identity-checked process control, Windows dynamic WFP
  application blocks, Linux cgroup/nftables blocks, portable quarantine containers
  with hash-checked restore, and a durable action journal. Expose truthful backend
  capabilities; reject unsupported operations rather than recording success.
- Integrate the manager with detection, configured response modes, authenticated
  IPC, and the tray. Resolve actions must use the process identity captured with
  the alert, never a recycled PID. UI must show the actual scope of an application
  network block and offer unblock/resume/restore.
- Add bounded, validated offline threat-feed ingestion, persistent IP/CIDR/domain
  reputation, destination history, and service enrichment. Refresh tooling uses
  current feed formats and never downloads malware samples. Credentials stay out
  of stored reports and logs.
- Exercise quarantine with disposable files, process control with owned helpers,
  rule-to-response with a fake backend, malformed feeds, stale process identity,
  failed actions, recovery, and alert/feedback round trips. Compile Windows code
  and run the native preview after validation.

Actual firewall changes and privileged integration tests require a concrete,
reviewable test and approval under CLAUDE.md. Keep the user's normal preview in
monitor mode while building. No driver, antivirus change, paid account, or malware
execution is part of implementation.

External release requirements (not claims of completed validation): Apple ES/NE
entitlements and signing certificates; representative family-labeled telemetry
and human-reviewed labels; privileged OS test environments for each backend.
