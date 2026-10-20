whohack for Windows - native monitoring preview

Extract this entire folder to a location you can write to, then double-click
whohack.exe or Start whohack.cmd. Requires Windows 10 22H2+ or Windows 11 x64,
Microsoft Edge WebView2 and the Microsoft Visual C++ x64 runtime.
Python, Rust and WSL are not required to run this package.

The launcher starts native Windows service and tray executables. No administrator
rights are needed. It monitors Windows processes and TCP connections through
ToolHelp/IP Helper. The tray window opens immediately; closing it keeps the tray
running. Use its tray icon or double-click whohack.exe to reopen it. The launcher
retries a crashed service up to three times within five minutes and verifies
package checksums before each launch.

From a terminal in this folder:
  "Start whohack.cmd" status
  "Start whohack.cmd" start-service
  "Start whohack.cmd" stop

Data, logs, copied rules and configuration live in .vigil\windows. Existing
configuration is preserved. Stop requests a graceful shutdown of this preview
session; it does not stop a separately installed whohack system service. Keep the
folder in place while whohack runs. To move an existing installation, stop it first,
update the absolute paths in .vigil\windows\config.toml and regenerate the local
integrity manifest as described in docs\response-and-feeds.md.

This is an unsigned development preview, not a production security release or a
signed installer. Checksums detect damage; they are not a publisher signature.
Application Control may reject unsigned executables. Keep Windows security and
your existing antivirus enabled.
Current whohack 0.1.1 build checks and model limitations are recorded in
docs\plans\M14-whohack-and-data.md. Earlier dated reports describe their own builds.

Default mode is monitor and response is disabled. Events, rule matches and alerts
are recorded without changing processes or network access. Optional response
backends, advanced sensors and local model adapters are implemented, with their
acceptance limits in docs\response-and-feeds.md, docs\native-sensors.md and
docs\decision-runtime.md. Polling cannot see UDP, DNS, file reads or persistence.
No trained model or personal threat-feed credentials are bundled. Privileged
response, representative model evaluation and clean-machine installation still
require validation.

Manual response can be enabled in config with [response] enabled = true and
automatic = false. Actions then require your choice in the tray; Auto is refused.
The separate pause_downloads = true opt-in automatically pauses qualified
download-related danger and alerts you. Native file monitoring requires an
administrator launch; see docs\download-protection.md for setup, source-file
quarantine safeguards and the limits of the included detection rules.
A network block requests Windows consent for a separate, bounded helper. The
direct firewall and debug-helper tests passed. The optimized helper's rerun
timed out at consent; see docs\readiness-2026-10-15.md for exact-build limits.
Existing connections may remain open, and a
block affects all instances of an executable path. See docs\response-and-feeds.md.

Optional tools\intel helpers use Python 3.11+ for feed downloads or explicit
hash-only research. Python is not needed for ordinary monitoring. Model setup and
training use the source checkout and a separately prepared local environment.

If startup fails, inspect .vigil\windows\launcher-health.json, launcher.log and
whohack-service-launch.log. Extract a fresh trusted copy if a package checksum fails;
do not edit WHOHACK-PACKAGE.json to bypass the check.

Source and license information: https://github.com/imamsyed999/whohack
See LICENSE-MIT, LICENSE-APACHE, THIRD-PARTY-NOTICES.txt and docs\licenses.md.
The exact-version tray license exceptions in docs\license-review-2026-10-14.md
were approved on 2026-10-15. Signing, clean-machine acceptance and the documented
security/model gates remain open; this is still an experimental preview.
