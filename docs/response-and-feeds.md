# Response controls and threat feeds

New Windows profiles start in monitor mode. Set `[response] enabled = true`
to make manual actions available. `automatic = false` is the default independent
of response availability: rules and models cannot block, stop or quarantine until
you choose an action. Auto mode is refused while this switch is off. The developer
profile was explicitly changed to Prompt with manual controls on 2026-10-14;
fresh packages retain their conservative defaults. Mode changes and actions
use authenticated IPC. An alert must carry its original process creation time,
executable path and digest; legacy alerts cannot control a process.

Windows uses a dynamic Windows Filtering Platform session with IPv4/IPv6 ALE
connect and receive/accept filters. A block affects **every instance of the same
executable path** and may not close existing flows. The OS removes the filters
when the session closes, including a service crash. WFP requires administrator
rights. An unprivileged preview requests a separate `whohack-response-helper.exe`
through normal Windows UAC for each chosen executable block. That helper accepts
one immutable target, verifies the process identity and local pipe peers, and
releases its dynamic filters if the owner exits or disconnects. The ordinary
service stays unprivileged. Denied/timed-out consent reports failure; it does not
mark the action successful. Consent has a 90-second application timeout. A late
helper cannot attach to a closed owner pipe. The helper has a maximum 24-hour
lease; later integrity checks report its expiry. No automatic UAC requests are
allowed from the unprivileged service. The implementation installs no driver and
does not modify Defender.

The direct elevated WFP test passed on 2026-10-14 for new outbound IPv4/IPv6,
both instances of the test executable, an unaffected control executable, explicit
release and abrupt owner exit. On 2026-10-15 the debug helper also passed the
normal-user UAC/IPC/WFP path, including owner-crash cleanup. A subsequent optimized
helper rerun timed out at Windows consent; that artifact is not accepted by the
earlier result. New inbound/existing-flow tests are implemented but also stopped
at consent. See the exact-build evidence in the [readiness report](readiness-2026-10-15.md).

Linux uses pidfds for process signals and a private cgroup v2/nftables table for
network response. It needs root, writable cgroup v2, nftables and kernel
`CONFIG_NFT_SOCKET` support. Existing sockets
keep their original cgroup; this backend blocks new sockets. macOS remains in
limited collection mode until its entitled helper is installed. Linux recovery
after external deletion of whohack's own table passed in a disposable network
namespace. Full blocking could not run on this WSL kernel, which lacks
`CONFIG_NFT_SOCKET`; nftables being installed alone is insufficient.

Quarantine uses inert `.vigilq` containers, a SHA-256 check, original path, timestamp
and permission metadata, and Windows Mark-of-the-Web preservation. Restore verifies
the entire container and refuses to overwrite a file. It never starts a process.
On Windows the vault and staging directories allow only their owner, SYSTEM and
administrators. On Unix the vault is mode 0700. Setuid/setgid bits are not restored.

The Responses & quarantine tab shows completed, active and failed operations.
Unblock/Resume releases only whohack's operation. Graceful shutdown releases active
leases. After a crash, completed suspension records support an explicit recovery
request using process/thread identities. An interruption before a completion
checkpoint is shown as `recovery_required`, and may require manual inspection.
Do not treat this preview as crash-tested automatic protection yet. A pending
quarantine claim is checked on startup: matching held bytes are sealed into the
inert vault and a newly created file at the old name is left alone. Mismatches
retain the held bytes and report a recovery error. ACLs, ownership, extended
attributes and all filesystem timestamps are not fully restored; Windows MOTW,
last-write time and read-only state are preserved. Killing a process is irreversible.

Active Windows filter IDs are checked every ten seconds. Removal or a query failure
marks the operation degraded and produces a health notification. Its remaining
filters can still be released from the Responses tab or by choosing Allow.

After an intentional configuration/rules change, review it and regenerate the
local integrity manifest (use `bin/whohack-service.exe` in an extracted package):

```powershell
target/debug/whohack-service.exe --config .vigil/windows/config.toml --write-manifest
```

The service checks the manifest at startup and every ten seconds. Missing,
changed, unlisted or unreadable inputs appear persistently in status and disable
response. The unsigned manifest is a change detector, not a tamper-proof trust anchor.

Safe checks:

```powershell
cargo test -p whohack-respond
python -m unittest discover -s tools/intel -p test_*.py
```

The first command creates only harmless test files and its own disposable child
process. The privileged firewall test is deliberately excluded. After approval,
run from an elevated terminal:

```powershell
cargo test -p whohack-respond windows::process::tests::wfp_owned_child_block_unblock -- --exact --ignored --nocapture
```

This test copies its test executable into a temporary directory, checks local TCP
connections, applies temporary filters for that copied executable, verifies blocked
connections, releases the filters, and verifies connections resume. No existing
application is a target.

## Threat metadata

The service loads `<data_dir>/intel.json` offline and reloads it every minute.
Updates are validated in full before replacing the last good index. Entries expire;
stale feeds do not silently remain authoritative. IP prefixes, mapped IPv6 addresses,
and normalized domain boundaries are supported. Destination history survives service
restarts in SQLite, separate from short-lived connection records.

```powershell
python tools/intel/update.py --output .vigil/windows/data/intel.json --fetch-public
# Keep the updater running, refreshing every six hours:
python tools/intel/update.py --output .vigil/windows/data/intel.json --fetch-public --watch
# Import one IP, CIDR or domain per line:
python tools/intel/update.py --output .vigil/windows/data/intel.json --import-indicators local-indicators.txt
```

The updater uses only Python's standard library, TLS verification, bounded reads,
ETag/Last-Modified validation, atomic snapshots, and a six-hour refresh floor. It
downloads metadata only, never payloads or files named in the feeds. No endpoint
telemetry is uploaded. Failed providers retain their unexpired previous records.

Sources checked in October 2026:

- [Spamhaus DROP](https://www.spamhaus.org/blocklists/do-not-route-or-peer/) provides
  current JSON IPv4/IPv6 lists. eDROP was merged into DROP in April 2024.
- [Feodo Tracker](https://feodotracker.abuse.ch/blocklist/) provides the recommended
  IP list. An empty list is valid following takedowns.
- [ThreatFox](https://threatfox.abuse.ch/api/) requires an Auth-Key. `--threatfox`
  reads `WHOHACK_ABUSECH_AUTH_KEY` from the environment. Only high-confidence domain
  indicators are imported; port-specific and URL-path evidence is not broadened.
- [URLhaus](https://urlhaus.abuse.ch/api/) requires an account-specific export URL.
  Import its curated hosts file with `--urlhaus-hosts FILE`, or set
  `WHOHACK_URLHAUS_HOSTS_URL` to the provider's hosts export URL and use `--urlhaus`.
  Keys/secret URLs are never printed or cached. Provider terms apply; the tool does
  not create accounts or subscribe to paid access.

Native elevated WFP validation, Linux privileged validation, crash/power-loss
recovery qualification, and macOS entitlement testing remain release gates.

## Explicit hash-only VirusTotal lookup

`tools/intel/virustotal.py` accepts a SHA-256 digest, explicit `--opt-in` and the
user's `VIRUSTOTAL_API_KEY` environment variable. It never accepts a file path or
uploads file bytes. Example, after setting your own key locally:

```powershell
python tools/intel/virustotal.py <64-hex-character-sha256> --opt-in --cache-dir .vigil/windows/data/virustotal
```

This optional source-checkout helper caches metadata for seven days and limits its
own requests to four per minute and 500 per 24 hours. The key is never cached.
Other clients using the same key share the provider's quota. This is a manual
research lookup; it does not automatically change whohack verdicts or trust rules.
No actual lookup was made during development. See the provider's
[file report API](https://docs.virustotal.com/reference/file-info) and
[public API limits](https://docs.virustotal.com/reference/public-vs-premium-api).
