# M4 follow-up: confirmation-based Windows enforcement

Requested and authorized on 2026-10-14: enable enforcement with minimal impact,
test actual behavior and cleanup, and assess production/open-source readiness.
This supersedes the earlier unanswered request for the owned-child WFP test.

First keep response actions gated on explicit user confirmation. Add
`response.automatic = false` as the default independent of response availability;
automatic rules/models cannot bypass it, even if an old database selects Auto.
Expose that restriction in status and refuse Auto when automatic response is off.
Verify protected OS/antivirus exclusions, stale identities and response cleanup.

Files: core config, response manager, service wiring/IPC, example config, native
response tests and Windows cross-build helper. No real malware or antivirus/
Application Control changes. Windows currently blocks the native Rust compiler;
use the existing documented WSL cross-build tools for Windows executables.

Run the owned-child WFP test elevated through the normal Windows consent flow,
with an isolated copied executable and local listeners. Test IPv4/IPv6, release,
path-wide scope, an unrelated executable and abrupt owner exit. No broad firewall
rule, permanent driver or unprotected privileged boot service is introduced.
If Windows denies elevation or execution, record the exact unavailable checks
and keep unsupported actions unavailable rather than claim success.

Validation: config/default and policy regression tests, workspace format/Clippy/
tests where executable, native owned-child response tests, existing package/IPC
smoke checks, and a before/after record of the host preview configuration. Model
responses remain disabled because no checkpoint has qualified evaluation data.

The elevated direct WFP test passed on 2026-10-14. To enable manual network
response without leaving a privileged service in a user-writable checkout, add
`vigil-response-helper`: one explicitly approved executable block per UAC launch.
It accepts one bounded, immutable target, verifies PID/birth/image/digest and the
parent process, and uses a local pipe with verified peer PIDs and identification
SQOS. It never loads config/models, writes files, starts programs, or accepts a
second target. Closing the pipe or exiting the parent releases dynamic filters.
Automatic response remains unavailable to the unprivileged service. Test this
broker through the same harmless block/release/crash test before activation.

Observed outcome: direct WFP passed; helper acceptance stopped at Windows consent
(timeout/cancellation). The local profile now exposes manual controls with every
action requiring explicit confirmation, automatic response off and models off.
This does not clear the helper release gate or claim its success path passed.
No real user application was targeted. Added a bounded consent wait and a
regression test proving pending consent does not lock alert/status reads.

Readiness audit follows separately: source hygiene and license checks, current
Jev documentation, representative-data requirements and a reproducible test report.
