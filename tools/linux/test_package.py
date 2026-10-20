"""Install/upgrade/remove the preview only inside a disposable test container.

Run with --network none and a read-only /artifacts mount. No host privileges or
host system directories are mounted. Runtime data preservation is checked too.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import pwd
import sqlite3
import subprocess
import time
import uuid


def run(*args, **kwargs):
    return subprocess.run(args, check=True, capture_output=True, text=True, timeout=60, **kwargs)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('package', type=Path)
    args = parser.parse_args()
    if os.geteuid() != 0 or not Path('/.dockerenv').is_file() or os.environ.get('WHOHACK_PACKAGE_CONTAINER_TEST') != '1':
        parser.error('This acceptance must run in an explicitly opted-in disposable container')
    package = args.package.resolve(strict=True)
    if not package.is_relative_to(Path('/artifacts')):
        parser.error('Use the read-only /artifacts mount')
    with package.open('rb') as f:
        sha = hashlib.file_digest(f, 'sha256').hexdigest()
    assert sha == package.with_suffix(package.suffix + '.sha256').read_text().split()[0]
    deb = package.suffix == '.deb'
    install = ['dpkg', '--install', str(package)] if deb else ['rpm', '--install', str(package)]
    run(*install)
    user = pwd.getpwnam('whohack-preview')
    assert user.pw_uid != 0 and user.pw_shell.endswith('/nologin')
    assert not Path('/etc/systemd/system/multi-user.target.wants/whohack-preview.service').exists()
    binary = Path('/usr/bin/whohack-service')
    config = Path('/etc/whohack-preview/config.toml')
    for path in [binary, config, *Path('/etc/whohack-preview/rules').rglob('*')]:
        assert not path.is_symlink()
        assert path.stat().st_uid == 0 and path.stat().st_mode & 0o022 == 0
    for name in ('/var/lib/whohack-preview', '/var/log/whohack-preview', '/run/whohack-preview'):
        path = Path(name)
        path.mkdir(exist_ok=True, parents=True)
        path.chmod(0o750)
        os.chown(path, user.pw_uid, user.pw_gid)
    marker = Path('/run/whohack-preview/acceptance-session')
    marker.write_text(uuid.uuid4().hex)
    os.chown(marker, user.pw_uid, user.pw_gid)
    command = ['runuser', '-u', 'whohack-preview', '--', str(binary), '--config', str(config)]
    with Path('/tmp/whohack-package-runtime.log').open('wb') as log:
        process = subprocess.Popen(command + ['--run', '--session-file', str(marker)], stdout=log, stderr=log)
        try:
            deadline = time.monotonic() + 35
            while True:
                result = subprocess.run(command + ['--status'], capture_output=True, text=True, timeout=8)
                if result.returncode == 0:
                    status = json.loads(result.stdout)
                    if status['events_seen'] > 0:
                        break
                assert process.poll() is None, Path('/tmp/whohack-package-runtime.log').read_text()
                assert time.monotonic() < deadline, result.stderr
                time.sleep(.2)
            assert status['mode'] == 'monitor' and not status['enforcement_available']
            assert not status['automatic_response_enabled'] and status['model'] is None
            assert not status['integrity_issues'], status['integrity_issues']
            uid_line = next(l for l in Path(f'/proc/{status["service_pid"]}/status').read_text().splitlines() if l.startswith('Uid:'))
            assert all(int(uid) == user.pw_uid for uid in uid_line.split()[1:])
            duplicate = subprocess.run(command + ['--run'], capture_output=True, text=True, timeout=8)
            assert duplicate.returncode != 0 and 'another instance' in duplicate.stderr
            marker.unlink()
            assert process.wait(timeout=20) == 0
        finally:
            marker.unlink(missing_ok=True)
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=10)
    data = Path('/var/lib/whohack-preview/vigil.db')
    with sqlite3.connect(data) as database:
        assert database.execute('select count(*) from events').fetchone()[0] > 0
    before = config.read_bytes() + b'\n# intentional acceptance configuration\n'
    config.write_bytes(before)
    # Reinstallation exercises package-manager config preservation. A real
    # version-to-version upgrade remains a separate release acceptance.
    run(*(['dpkg', '--force-confold', '--install', str(package)] if deb
          else ['rpm', '--upgrade', '--replacepkgs', str(package)]))
    assert config.read_bytes() == before
    run(*(['dpkg', '--remove', 'whohack-preview'] if deb else ['rpm', '--erase', 'whohack-preview']))
    assert data.exists() and not binary.exists()
    preserved = config if deb else config.with_suffix('.toml.rpmsave')
    assert preserved.read_bytes() == before
    print(json.dumps({'success': True, 'package': package.name, 'sha256': sha,
                      'checks': ['unprivileged runtime', 'protected payload', 'no auto-start', 'authenticated status',
                                 'duplicate guard', 'graceful flush', 'reinstall config preservation', 'removal preserves data']}))


if __name__ == '__main__':
    main()
