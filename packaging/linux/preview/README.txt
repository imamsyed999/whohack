whohack Linux headless preview

This package installs the native service, rules and an unprivileged systemd unit.
It does not start monitoring, enable boot startup, download models or change any
firewall policy. The desktop tray is built separately from ui/src-tauri.

Start after reviewing /etc/whohack-preview/config.toml:
  sudo systemctl start whohack-preview
  sudo journalctl -u whohack-preview
  sudo /usr/bin/whohack-service --config /etc/whohack-preview/config.toml --status

Optional boot startup:
  sudo systemctl enable whohack-preview

After intentional changes to configuration or rules:
  sudo /usr/bin/whohack-service --config /etc/whohack-preview/config.toml --write-manifest
  sudo systemctl restart whohack-preview

Configuration files are preserved through upgrades. An altered configuration can
produce an integrity warning after a package upgrade; review the packaged rules
and config before regenerating their manifest. Installation never silently trusts
modified local content by recalculating the manifest. Uninstall stops this unit
and preserves data under /var/lib/whohack-preview and /var/log/whohack-preview.

The service account has no capabilities. Polling observes accessible process and
TCP metadata; private user files may be inaccessible. Response and models are
disabled. Full Linux collection/response requires a separately reviewed privileged
deployment, a suitable kernel and additional acceptance. This is an experimental
preview, not a replacement for built-in operating-system protection.

Only members of whohack-preview (and root) can read its IPC token. Do not add users
to that group unless they should be allowed to control this preview instance.
Build for the oldest supported distribution: the package records the binary's
actual glibc requirement and rejects incompatible installations.
