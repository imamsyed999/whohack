# M11: downloaded-content detection and immediate pause

The maintainer's 2026-10-15 priority is danger detection when downloaded programs,
documents, video or audio are opened. Stop the responsible process and notify the
user; routine firewall certification is outside this milestone. Removal permission
is granted, but uncertain behavior must not cause deletion of a shared player or
an unrelated document. Use reversible suspension first and evidence-bound quarantine.

Implementation:

- Extend process context with bounded downloaded input files, distinct from scripts
  and executable identity. Discover explicit absolute local command-line inputs and
  observed native file reads; propagate that context to child processes. Persist it
  in process rows and captured alert identities with backward-compatible defaults.
- Scan small inputs with the existing local YARA engine; retain origin-only context
  for large media without blocking the event pipeline on multi-GB hashing. No
  "safe" verdict from an absent signature. Never fetch URLs or inspect device paths.
- Add separately configured automatic suspension for strong downloaded-content
  evidence, independent of firewall elevation and unqualified models. Respect
  Monitor, allowlists, integrity failure and process identity exclusions. Ordinary
  connections and unsigned/downloaded status alone do not trigger a pause.
- Show the source file and actual pause result in alerts/desktop notifications and
  expose the setting and coverage in Status. Quarantine must never select an
  installed shared viewer merely because it opened a download.

Validation: negative ordinary-media/network cases, real file/lineage attribution,
bounded inputs, persistent identity, policy exclusions, and actual native owned
process auto-pause/release with an isolated local signature. Build and run the
updated Windows runtime after those checks, preserving a rollback copy. No malware,
host network shutdown, OS security changes or private telemetry uploads.

Limits to report: command-line association is not proof of a successful open;
already-running players need native file-read events. Existing polling cannot
observe arbitrary file reads. This is observed-activity response, not a universal
pre-execution gate, and no detection rate is established by a harmless fixture.

Implemented and verified on 2026-10-15. The focused optimized Windows tests pass
for signature-triggered MP4/WAV/PDF reader pause, native file-read attribution,
local threat-destination pause, clean controls, resume and source-file quarantine
with byte-identical restore. Live native use revealed and corrected an overbroad
mass-write alert and duplicate window alerts. The local profile uses native ETW
and `pause_downloads = true`; general Auto and models remain disabled. See
`docs/download-protection.md` for reproduction commands and candid limits.
