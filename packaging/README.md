# Installing whohack

whohack has two parts:

- **`whohack-service`:** the background collector and analysis service. The preview
  runs as the current user; advanced sensors/response may require root or SYSTEM.
- **`whohack-tray`:** the tray app. It runs as the logged-in user and talks to the service
  over authenticated local IPC.

The service writes a fresh session token to `<data_dir>/ipc.token` at every start. The tray
app's user must be able to read it:

- **Linux and macOS:** the file is mode 0640 and group `whohack`.
- **Windows preview:** service and tray run as the same user. The privileged
  installation's protected configuration and token access policy still need validation.

## Linux unprivileged preview packages

`tools/linux/package.py` builds `.deb` and `.rpm` payloads from a native release
service and target-specific notices. Templates are under `linux/preview/`.
The packages create a dedicated `whohack-preview` account and install a restricted
systemd unit without enabling or starting it. They use polling, disable response
and models, and preserve data/configuration on removal. No tray is bundled.

```sh
cargo build -p whohack-service --release --locked --jobs 2
cargo metadata --format-version 1 --locked --filter-platform x86_64-unknown-linux-gnu > linux-metadata.json
python3 tools/windows/notices.py --target x86_64-unknown-linux-gnu --metadata linux-metadata.json --upstream-cache .vigil/checks/license-cache --output .vigil/packages/linux/THIRD-PARTY-NOTICES.txt
python3 tools/linux/package.py --service target/release/whohack-service --notices .vigil/packages/linux/THIRD-PARTY-NOTICES.txt --output .vigil/packages/linux
```

Build tools are `dpkg-deb`, `rpmbuild`, `readelf` and `strip`; the provided Ubuntu
Dockerfile supplies them in a disposable container. CI demonstrates offline
build mounts and container-only lifecycle checks. Both Ubuntu 24.04 `.deb` and
Fedora 44 `.rpm` acceptance passed locally. Current x64 artifacts require glibc
2.39; do not install them on an older baseline. Container tests do not prove
booted systemd behavior, real version upgrades or rollback. Read the installed
`/usr/share/doc/whohack-preview/README.txt` before starting the optional service.

## Linux privileged source deployment (experimental)

```sh
sudo groupadd --system whohack
sudo usermod -aG whohack "$USER"            # log out and back in afterwards
sudo install -m 0755 target/release/whohack-service /usr/bin/whohack-service
sudo install -m 0755 ui/src-tauri/target/release/whohack-tray /usr/bin/whohack-tray
sudo install -d -m 0750 -g whohack /etc/whohack /etc/whohack/rules
sudo cp -r rules/* /etc/whohack/rules/
whohack-service --print-default-config | sudo tee /etc/whohack/config.toml >/dev/null
sudo whohack-service --config /etc/whohack/config.toml --write-manifest
sudo install -m 0644 packaging/linux/whohack.service /etc/systemd/system/whohack.service
sudo systemctl daemon-reload
sudo systemctl enable --now whohack
install -D -m 0644 packaging/linux/whohack-tray.desktop ~/.config/autostart/whohack-tray.desktop
```

Build the service with `--features ebpf` for real-time process and connection visibility;
see `docs/building.md`.

## Windows

For the unprivileged local monitoring preview, double-click `Start whohack.cmd`.
It runs native Windows executables with data under `.vigil/windows`; see
`packaging/windows/README.txt`. `python tools/windows/package.py` packages built
service, tray, native launcher and manual response-helper executables into an
unsigned preview ZIP. Generate the dependency attribution files first, on the
same build host as Cargo (WSL can run the same commands with shell redirection):

```powershell
New-Item -ItemType Directory -Force .vigil/checks | Out-Null
cargo metadata --format-version 1 --locked --filter-platform x86_64-pc-windows-msvc | Out-File -Encoding utf8 .vigil/checks/core-metadata.json
cargo metadata --manifest-path ui/src-tauri/Cargo.toml --format-version 1 --locked --filter-platform x86_64-pc-windows-msvc | Out-File -Encoding utf8 .vigil/checks/ui-metadata.json
python tools/windows/notices.py --metadata .vigil/checks/core-metadata.json --metadata .vigil/checks/ui-metadata.json --upstream-cache .vigil/checks/license-cache --output .vigil/packages/THIRD-PARTY-NOTICES.txt
```

The optional upstream cache fetches missing license texts from recorded Git
revisions and records their hashes. Packaging refuses an incomplete inventory.
The [tray policy review](../docs/license-review-2026-10-14.md) was approved on
2026-10-15. Generating attribution is not production-release clearance.
`python tools/windows/test_package.py` tests extraction, startup, crash recovery,
tamper reporting and stop with no development tools on PATH. Python, Rust and WSL
are not runtime requirements.

`python tools/windows/package.py --profile release` selects optimized binaries.
`python tools/windows/test_ui.py` additionally exercises the packaged Windows
WebView2 window against a verified, isolated service. Node 22+ is needed only for
that test; its temporary browser-debugging port is not enabled in normal launches.

`py -3.11 tools/windows/build_msi.py` builds an unsigned per-user MSI from that ZIP
and verifies its decompressed cabinet and installer tables. It uses Python
3.11/3.12's Windows Installer module only at build time. Both artifacts and their
SHA-256 sidecars are written under `.vigil/packages/`.

The MSI targets `%LOCALAPPDATA%\Programs\whohack`, adds Start-menu launch/stop
shortcuts and requests graceful shutdown on removal. It preserves the private
`.vigil` data directory. It does not add a boot service, auto-start entry, firewall
policy or model download. `py -3.11 tools/windows/test_msi.py` verifies actual
installation, a metadata-fixture major upgrade and removal while the service is
running. These pass locally, including custom paths and preserved config/data.
Signing, clean-machine tests, rollback and real release upgrades remain outstanding.

`whohack-service --install-service` is a low-level SCM registration command for a
separate LocalSystem deployment. It is not a protected installer: it does not
move binaries into an administrator-owned directory or prepare configuration,
model and token ACLs. Do not register the executable from a user-writable checkout
as SYSTEM. Those installation controls and privileged acceptance remain release
work. `--uninstall-service` removes a separately registered SCM service.

## macOS (limited mode)

```sh
sudo install -m 0755 target/release/whohack-service /usr/local/bin/whohack-service
sudo mkdir -p "/Library/Application Support/whohack/rules" /Library/Logs/whohack
sudo cp -r rules/* "/Library/Application Support/whohack/rules/"
whohack-service --print-default-config | sudo tee "/Library/Application Support/whohack/config.toml" >/dev/null
sudo whohack-service --config "/Library/Application Support/whohack/config.toml" --write-manifest
sudo cp packaging/macos/org.whohack.service.plist /Library/LaunchDaemons/
sudo launchctl bootstrap system /Library/LaunchDaemons/org.whohack.service.plist
```

## After editing rules or config

Regenerate the integrity manifest. Otherwise the service will report the change as tampering:

```sh
sudo whohack-service --config <config> --write-manifest
```

## Signed installers

Windows publisher signing needs a code-signing certificate; macOS notarized PKG
delivery needs Apple credentials and entitlements for full-mode extensions.
Linux `.deb`/`.rpm` construction does not need either certificate. Construction
and isolated lifecycle acceptance now pass; remaining platform gates are tracked
in `docs/backlog.md`.

Installer APIs checked: [Windows installation context](https://learn.microsoft.com/en-us/windows/win32/msi/installation-context),
[upgrade scheduling](https://learn.microsoft.com/en-us/windows/win32/msi/removeexistingproducts-action)
and [Python build API](https://docs.python.org/3.11/library/msilib.html).
