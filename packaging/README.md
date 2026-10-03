# Installing Vigil

Vigil has two parts:

- **`vigil-service`:** the privileged background service. It runs as root or SYSTEM.
- **`vigil-tray`:** the tray app. It runs as the logged-in user and talks to the service
  over authenticated local IPC.

The service writes a fresh session token to `<data_dir>/ipc.token` at every start. The tray
app's user must be able to read it:

- **Linux and macOS:** the file is mode 0640 and group `vigil`.
- **Windows:** the installer grants interactive users read access to the data directory.

## Linux (systemd)

```sh
sudo groupadd --system vigil
sudo usermod -aG vigil "$USER"            # log out and back in afterwards
sudo install -m 0755 target/release/vigil-service /usr/bin/vigil-service
sudo install -m 0755 ui/src-tauri/target/release/vigil-tray /usr/bin/vigil-tray
sudo install -d -m 0750 -g vigil /etc/vigil /etc/vigil/rules
sudo cp -r rules/* /etc/vigil/rules/
vigil-service --print-default-config | sudo tee /etc/vigil/config.toml >/dev/null
sudo vigil-service --config /etc/vigil/config.toml --write-manifest
sudo install -m 0644 packaging/linux/vigil.service /etc/systemd/system/vigil.service
sudo systemctl daemon-reload
sudo systemctl enable --now vigil
install -D -m 0644 packaging/linux/vigil-tray.desktop ~/.config/autostart/vigil-tray.desktop
```

Build the service with `--features ebpf` for real-time process and connection visibility;
see `docs/building.md`.

## Windows

From an **elevated** prompt:

```powershell
New-Item -ItemType Directory -Force "$env:ProgramData\Vigil\rules" | Out-Null
Copy-Item -Recurse rules\* "$env:ProgramData\Vigil\rules\"
.\vigil-service.exe --print-default-config | Set-Content -Encoding utf8 "$env:ProgramData\Vigil\config.toml"
.\vigil-service.exe --config "$env:ProgramData\Vigil\config.toml" --write-manifest
.\vigil-service.exe --config "$env:ProgramData\Vigil\config.toml" --install-service
```

What the installed service does:

- starts at boot and runs as LocalSystem, so ETW collection is available;
- is restarted by the Service Control Manager if it stops unexpectedly.

To remove it, run `--uninstall-service`.

## macOS (limited mode)

```sh
sudo install -m 0755 target/release/vigil-service /usr/local/bin/vigil-service
sudo mkdir -p "/Library/Application Support/Vigil/rules" /Library/Logs/Vigil
sudo cp -r rules/* "/Library/Application Support/Vigil/rules/"
vigil-service --print-default-config | sudo tee "/Library/Application Support/Vigil/config.toml" >/dev/null
sudo vigil-service --config "/Library/Application Support/Vigil/config.toml" --write-manifest
sudo cp packaging/macos/org.vigil.service.plist /Library/LaunchDaemons/
sudo launchctl bootstrap system /Library/LaunchDaemons/org.vigil.service.plist
```

## After editing rules or config

Regenerate the integrity manifest. Otherwise the service will report the change as tampering:

```sh
sudo vigil-service --config <config> --write-manifest
```

## Signed installers

MSI, notarized PKG, and `.deb`/`.rpm` packages need code-signing certificates (an Apple
Developer ID and a Windows code-signing certificate). They are tracked in `docs/backlog.md`.
