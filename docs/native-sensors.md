# Native sensor coverage

Windows is a native runtime. With `collect.backend = "auto"`, an elevated service
uses ETW for process, network, DNS, file and registry metadata; an ordinary launch
uses ToolHelp/IP Helper polling. Polling cannot see file reads, registry changes,
UDP destinations or DNS. The tray reports each capability and collection losses.

The file collector resolves bounded, expiring file-object/name associations,
matches I/O to successful OperationEnd events, and verifies the issuing thread's
owner and creation time. It emits sensitive accesses and distinct-file bursts,
never file contents. Unknown names, failed I/O, exited actors and reused IDs are
discarded and counted. Busy systems, missing completions, stale name entries and
short-lived actors can therefore reduce coverage. The elevated owned-file read
and 120-file burst acceptance test passed on Windows on 2026-10-15. Broad event
coverage, loss behavior and sustained-load measurements remain release gates.

Registry collection uses successful Kernel-Registry SetValue records at known
persistence locations, including Run/RunOnce and their 32-bit registry view.
Only key/value **names** are parsed; value data is not inspected. This does not
claim every Windows persistence technique is covered.

`collect.sysmon = true` reads future Event 8 records from an **existing**
Microsoft-Windows-Sysmon/Operational channel. It neither installs Sysmon nor
changes its configuration. Coverage depends on the existing Sysmon filters.
The event's payload UTC time is checked against the source process birth time.
Process-access events alone are not treated as proof of injection.

On Linux, `collect.file_roots` selects explicit directory roots for fanotify.
This requires CAP_SYS_ADMIN and Linux 5.15+ PIDFD support. Notification-class
mount marks observe descendants on the same mount, with userspace filtering
back to the configured roots. It never asks permission to open a file or reads
contents. New mounted filesystems need their own root. Coalesced notifications
can undercount activity; rename-only bursts and download-origin tracking are
not supplied by this collector.

macOS retains explicitly limited libproc mode. Endpoint Security and Network
Extension work needs Apple-approved entitlements and a signed, tested extension.

Harmless live acceptance (requires the privileges above):

```text
cargo test -p whohack-collect --test file_sensors -- --ignored --nocapture
```

It creates 120 tiny dummy files and reads one, all under an owned temporary
directory. It does not read credentials, change a startup entry, inject into a
process, modify a firewall, or install a driver.

Both the Windows ETW and Linux fanotify versions passed locally on 2026-10-15.
This evidence does not validate the separate ETW network/DNS/registry providers
or an existing Sysmon installation.

Provider schemas were inspected from the installed Windows provider manifests
using `Get-WinEvent -ListProvider`. Reference contracts:
[ETW event timestamps](https://learn.microsoft.com/en-us/windows/win32/api/evntcons/ns-evntcons-event_header),
[ETW loss statistics](https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-controltracew),
[Sysmon Event 8](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon),
[fanotify](https://man7.org/linux/man-pages/man7/fanotify.7.html).
