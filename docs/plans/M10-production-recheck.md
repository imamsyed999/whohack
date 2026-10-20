# M10: production-use verification (2026-10-15)

Recheck the exact running Windows release and distinguish working preview paths
from unmet production requirements. Preserve the normal configuration and OS
security settings; use only owned disposable processes for response acceptance.

Files and interfaces:

- `tools/windows/test_detection.py`: a real polling sensor -> temporary rule ->
  durable alert -> authenticated IPC -> native suspend/resume acceptance test.
  It verifies the captured PID, birth time, executable path and hash before acting,
  observes an independent control heartbeat, and checks durable feedback/cleanup.
- `docs/production-verification-2026-10-15.md`: fresh results, artifact identity,
  production blockers and the limits of the evidence.
- Local, ignored `.vigil/checks/production-recheck/`: runtime/UI/enforcement logs
  and structured results. Do not export private telemetry or tokens.

Validation: repeat the optimized runtime and packaged WebView2 checks; attempt the
actual release firewall acceptance through normal UAC; run the new bounded
end-to-end test; inspect the live SQLite database read-only, binary signatures,
deployment/startup state and reported sensor coverage. The harmless fixture rule
tests integration, not malware detection efficacy. A missing or failing gate must
remain a failure even when other checks pass.
