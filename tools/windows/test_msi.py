"""Install and remove only this per-user preview MSI in an isolated workspace.

Refuses existing products/settings/shortcuts. No elevation, system service or
firewall is requested. Run on Windows with build-only Python 3.11/3.12.
"""
import ctypes
from ctypes import wintypes
from contextlib import contextmanager
import json
import os
from pathlib import Path
import subprocess
import shutil
import sys
import tempfile
import time
import uuid
import winreg

from build_msi import guid, rows

ROOT = Path(__file__).resolve().parents[2]


@contextmanager
def isolated_folder(checks):
    root = Path(tempfile.mkdtemp(prefix='whohack installer test ', dir=checks)).resolve()
    assert root.is_relative_to(ROOT.resolve())
    try:
        yield root
    except BaseException:
        print(f'Preserved failed installer-test files for inspection: {root}', flush=True)
        raise
    else:
        assert root.resolve().is_relative_to(ROOT.resolve())
        shutil.rmtree(root)


def main():
    import msilib as m
    if sys.platform != 'win32': raise SystemExit('Windows is required')
    package = ROOT / '.vigil/packages/whohack-Windows-Preview.msi'
    db = m.OpenDatabase(str(package), m.MSIDBOPEN_READONLY)
    try: props = dict(rows(db, 'Property'))
    finally: db.Close()
    assert props['UpgradeCode'] == guid('windows-user-preview')
    assert props['ProductName'] == 'whohack Preview' and 'ALLUSERS' not in props
    api = ctypes.WinDLL('msi', use_last_error=True)
    api.MsiEnumRelatedProductsW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPWSTR]
    api.MsiEnumRelatedProductsW.restype = wintypes.UINT
    product = ctypes.create_unicode_buffer(39)
    code = api.MsiEnumRelatedProductsW(props['UpgradeCode'], 0, 0, product)
    if code != 259:  # ERROR_NO_MORE_ITEMS
        raise RuntimeError(f'Refusing an existing related preview product or failed product query ({code})')
    menu = Path(os.environ['APPDATA']) / 'Microsoft/Windows/Start Menu/Programs/whohack'
    if menu.exists(): raise RuntimeError('Refusing to modify an existing whohack Start-menu folder')
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r'Software\Vigil\Preview'):
            raise RuntimeError('Refusing to modify existing whohack preview registry settings')
    except FileNotFoundError:
        pass
    checks = ROOT / '.vigil/checks'; checks.mkdir(parents=True, exist_ok=True)
    installer = Path(os.environ['SystemRoot']) / 'System32/msiexec.exe'

    def install_command(*arguments, log, directory=None):
        command = subprocess.list2cmdline([str(installer), *arguments, '/qn', '/norestart', '/l*v', str(log)])
        if directory is not None:
            # MSI parses PROPERTY="value with spaces", not a CRT-quoted whole
            # property argument. This string goes directly to CreateProcess,
            # never through cmd/PowerShell; the property name is fixed.
            assert '"' not in str(directory) and '\x00' not in str(directory)
            command += f' INSTALLDIR="{directory}"'
        result = subprocess.run(command,
                                capture_output=True, text=True, timeout=150, creationflags=subprocess.CREATE_NO_WINDOW)
        if result.returncode != 0:
            raise RuntimeError(f'Windows Installer returned {result.returncode}; inspect {log}')

    with isolated_folder(checks) as directory:
        root = Path(directory).resolve()
        assert root.is_relative_to(ROOT.resolve()), 'cleanup target must remain inside the workspace'
        installed = root / 'app'
        native = installed / 'whohack.exe'
        attempted = False
        uninstalled = False
        owned_products = [props['ProductCode']]
        try:
            attempted = True
            install_command('/i', str(package), directory=installed, log=checks / 'msi-install.log')
            assert native.is_file() and (installed / 'bin/whohack-service.exe').is_file()
            assert (menu / 'whohack.lnk').is_file() and (menu / 'Stop whohack.lnk').is_file()
            env = dict(os.environ, PATH=str(Path(os.environ['SystemRoot']) / 'System32'))
            def run(action):
                return subprocess.run([str(native), action], env=env, capture_output=True, encoding='utf-8',
                                      check=True, timeout=60, creationflags=subprocess.CREATE_NO_WINDOW)
            run('start-service')
            status = json.loads(run('status').stdout)
            assert status['collectors'] == ['windows-poll'] and status['mode'] == 'monitor'
            assert not status['enforcement_available']
            original_config = (installed / '.vigil/windows/config.toml').read_bytes()
            # A local metadata fixture exercises major-upgrade sequencing and
            # stored INSTALLDIR with the same already verified payload.
            upgrade = root / 'upgrade-fixture.msi'
            shutil.copyfile(package, upgrade)
            new_product = '{' + str(uuid.uuid4()).upper() + '}'
            owned_products.insert(0, new_product)
            upgraded = m.OpenDatabase(str(upgrade), m.MSIDBOPEN_TRANSACT)
            try:
                version = '.'.join(props['ProductVersion'].split('.')[:2] + [str(int(props['ProductVersion'].split('.')[2]) + 1)])
                for name, value in [('ProductCode', new_product), ('ProductVersion', version)]:
                    view = upgraded.OpenView(f"UPDATE `Property` SET `Value`='{value}' WHERE `Property`='{name}'")
                    view.Execute(None); view.Close(); del view
                si = upgraded.GetSummaryInformation(1)
                si.SetProperty(m.PID_REVNUMBER, '{' + str(uuid.uuid4()).upper() + '}'); si.Persist(); del si
                upgraded.Commit()
            finally:
                upgraded.Close()
            install_command('/i', str(upgrade), log=checks / 'msi-upgrade.log')
            assert (installed / '.vigil/windows/config.toml').read_bytes() == original_config
            assert not (installed / '.vigil/windows/session').exists()
            run('start-service')
            assert json.loads(run('status').stdout)['mode'] == 'monitor'
            # Leave it running: removal must invoke the exact installed launcher's
            # graceful stop action before deleting its executable files.
            install_command('/x', new_product, log=checks / 'msi-uninstall.log')
            uninstalled = True
            assert not native.exists() and not (installed / 'bin/whohack-service.exe').exists()
            assert not menu.exists()
            assert (installed / '.vigil/windows/config.toml').is_file()
            assert (installed / '.vigil/windows/data/vigil.db').is_file()
            assert not (installed / '.vigil/windows/session').exists()
            try:
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r'Software\Vigil\Preview') as key:
                    assert winreg.QueryInfoKey(key)[:2] == (0, 0), 'preview registry values remain after removal'
            except FileNotFoundError:
                pass
            print('PASS: per-user MSI install, shortcuts, native monitor start, metadata-fixture upgrade and uninstall with a running service; data preserved.', flush=True)
        finally:
            if attempted and not uninstalled:
                # Product code is from this inspected package; never remove an
                # arbitrary installed product or kill processes by name.
                for code in owned_products:
                    result = subprocess.run([str(installer), '/x', code, '/qn', '/norestart', '/l*v', str(checks / 'msi-cleanup.log')],
                                            capture_output=True, timeout=150, creationflags=subprocess.CREATE_NO_WINDOW)
                    if result.returncode not in (0, 1605):
                        raise RuntimeError(f'Installer cleanup needs inspection ({result.returncode}); {root}')
            time.sleep(.5)
            assert root.resolve().is_relative_to(ROOT.resolve())


if __name__ == '__main__':
    main()
