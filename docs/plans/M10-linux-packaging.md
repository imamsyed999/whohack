# Linux preview packages

Build `.deb` and `.rpm` artifacts from an explicitly supplied native service
binary, with complete target-specific Rust notices. Ship a separate, unprivileged
`vigil-preview.service`, protected configuration/rules and a system account. Do
not enable or start monitoring during installation. Preserve configuration and
runtime data on upgrades/removal. Keep advanced root deployment separate.

Files: `tools/linux/package.py`, package templates under `packaging/linux/preview`,
and extracted/container acceptance. Validate ELF architecture and its actual
glibc requirement; never claim compatibility with an older libc without testing.
The package is a headless preview; desktop tray and privileged Linux collection
remain separate build/deployment options.

Tests: inspect package file modes, metadata, conffiles, payload hashes and notices;
exercise the extracted service and disposable-container install/upgrade/removal.
No package installation into the development host is needed.

Execution: x64 `.deb` and `.rpm` built with complete Linux-target notices and
glibc 2.39 minimum. Ubuntu 24.04/Fedora 44 containers passed install, protected
payload, unprivileged runtime, no auto-start, IPC/duplicate/flush checks,
configuration-preserving same-version reinstall and data-preserving removal.
The containers did not boot systemd or prove real version upgrades/rollback.
