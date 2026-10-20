# M10 follow-up — per-user installer acceptance

Exercise the already built Windows MSI in an isolated workspace directory. First
refuse to run if this user's Vigil preview product, registry key or Start-menu
folder already exists. Install with no elevation, reboot or automatic launch,
verify its files/shortcuts and native monitor startup, then remove that exact MSI
product. Confirm graceful service shutdown, removal of packaged files/shortcuts,
and preservation of runtime data. Keep the test log in `.vigil/checks/`.

Files: `tools/windows/test_msi.py`, Windows CI and packaging documentation. This
does not exercise SYSTEM installation, firewall rules or a fresh Windows VM.

Completed locally on 2026-10-13: native install and monitor startup, Start-menu
shortcuts, upgrade with a new product/version and the same verified payload,
preservation of a custom install directory and exact config, then uninstall
while the service is running. Packaged files/shortcuts are removed and runtime
data remains. The test caught and fixed Windows Installer's lost `INSTALLDIR`
on uninstall: a per-user AppSearch now retrieves it, and an embedded native
stop helper also handles missing or damaged config. CI runs the same test.
Clean-machine, rollback and real release payload upgrades remain acceptance gates.
