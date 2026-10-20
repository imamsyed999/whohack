# Native sensor completion

- Extend the Windows ETW backend with Kernel-File and Kernel-Registry events,
  using this machine's provider schemas and TDH field names. Track bounded file
  names, classify sensitive reads and persistence writes, and aggregate distinct
  modified/renamed files. Never read credential contents or registry value data.
- Preserve attribution: use the issuing thread's verified owner when needed,
  reject unavailable identities, and expose collection loss/limited visibility.
- Add optional read-only consumption of an existing Sysmon channel for injection
  evidence. Do not install a driver or enable system audit policies.
- Implement Linux fanotify over explicitly configured roots with PID attribution,
  plus safe parsers and tests; privileged live acceptance needs a suitable host.
- Keep macOS limited mode truthful. Endpoint Security / Network Extension signing,
  entitlements and hardware acceptance remain external gates; no fabricated full
  protection mode will be enabled.
- Validate parsers, resource bounds, sensitive path boundaries, Windows compile
  and safe owned-helper tests. Continue to leave automatic response disabled in
  the normal preview and the firewall acceptance test pending approval.
