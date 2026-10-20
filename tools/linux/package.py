"""Build unprivileged Linux headless preview packages; never install or start them.

Requires dpkg-deb and/or rpmbuild, readelf and strip. Supply a native ELF service
and complete notices generated with --target matching the ELF architecture.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import tomllib

ROOT = Path(__file__).resolve().parents[2]
TEMPLATES = ROOT / 'packaging/linux/preview'
NAME = 'whohack-preview'


def digest(path):
    with path.open('rb') as handle:
        return hashlib.file_digest(handle, 'sha256').hexdigest()


def copy_file(source, root, name, mode=0o644):
    if source.is_symlink() or not source.is_file():
        raise ValueError(f'Only regular package inputs are accepted: {source}')
    target = root / name
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, target)
    target.chmod(mode)
    return target


def write_file(root, name, text, mode=0o644):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding='utf-8', newline='\n')
    path.chmod(mode)


def stage(args, root, version, target):
    binary = copy_file(args.service, root, 'usr/bin/whohack-service', 0o755)
    subprocess.run(['strip', '--strip-unneeded', str(binary)], check=True)
    copy_file(TEMPLATES / 'config.toml', root, 'etc/whohack-preview/config.toml')
    copy_file(TEMPLATES / 'whohack-preview.service', root, 'usr/lib/systemd/system/whohack-preview.service')
    copy_file(TEMPLATES / 'whohack-preview.conf', root, 'usr/lib/sysusers.d/whohack-preview.conf')
    copy_file(TEMPLATES / 'README.txt', root, 'usr/share/doc/whohack-preview/README.txt')
    for source in ('LICENSE-MIT', 'LICENSE-APACHE', 'SECURITY.md'):
        copy_file(ROOT / source, root, 'usr/share/doc/whohack-preview/' + source)
    inventory = json.loads(args.notices.with_suffix('.json').read_text(encoding='utf-8'))
    if inventory.get('target') != target or not inventory.get('packages') or inventory.get('missing_notices'):
        raise ValueError('Complete target-specific dependency notices are required')
    for suffix in ('.txt', '.json'):
        copy_file(args.notices.with_suffix(suffix), root, 'usr/share/doc/whohack-preview/THIRD-PARTY-NOTICES' + suffix)
    for folder in ('tier0', 'yara'):
        for source in sorted((ROOT / 'rules' / folder).rglob('*')):
            if source.is_file() or source.is_symlink():
                copy_file(source, root, 'etc/whohack-preview/' + source.relative_to(ROOT).as_posix())
    rules = root / 'etc/whohack-preview/rules'
    hashes = {p.relative_to(rules).as_posix(): digest(p) for p in rules.rglob('*') if p.is_file()}
    hashes['/etc/whohack-preview/config.toml'] = digest(root / 'etc/whohack-preview/config.toml')
    write_file(root, 'etc/whohack-preview/rules/MANIFEST.sha256',
               ''.join(f'{sha}  {name}\n' for name, sha in sorted(hashes.items())))
    # Directory modes are explicit even under a restrictive build-user umask.
    for directory in root.rglob('*'):
        if directory.is_dir():
            directory.chmod(0o755)
    config_files = sorted('/' + p.relative_to(root).as_posix() for p in (root / 'etc').rglob('*') if p.is_file())
    return config_files


def deb(root, destination, version, arch, glibc, config_files):
    write_file(root, 'DEBIAN/control', f'''Package: {NAME}
Version: {version}-1
Section: admin
Priority: optional
Architecture: {arch}
Maintainer: whohack contributors
Homepage: https://github.com/imamsyed999/whohack
Depends: libc6 (>= {glibc}), libgcc-s1, systemd
Description: Native local monitoring preview (headless)
 Polls accessible processes and TCP metadata. Automatic response and models are
 disabled. Installation does not start or enable monitoring.
''')
    write_file(root, 'DEBIAN/conffiles', '\n'.join(config_files) + '\n')
    write_file(root, 'DEBIAN/postinst', '''#!/bin/sh
set -eu
if [ "$1" = configure ]; then
    systemd-sysusers /usr/lib/sysusers.d/whohack-preview.conf
    if [ -d /run/systemd/system ]; then systemctl daemon-reload; fi
fi
''', 0o755)
    write_file(root, 'DEBIAN/prerm', '''#!/bin/sh
set -eu
case "$1" in
    remove|deconfigure) if [ -d /run/systemd/system ]; then systemctl stop whohack-preview.service; fi ;;
esac
''', 0o755)
    write_file(root, 'DEBIAN/postrm', '''#!/bin/sh
set -eu
if [ -d /run/systemd/system ]; then systemctl daemon-reload; fi
# Runtime data and the service account are deliberately retained.
''', 0o755)
    subprocess.run(['dpkg-deb', '--root-owner-group', '--build', str(root), str(destination)], check=True)


def rpm(root, work, destination, version, arch, glibc, config_files):
    spec = work / 'whohack.spec'
    config_set = set(config_files)
    files = []
    for path in sorted(root.rglob('*')):
        name = '/' + path.relative_to(root).as_posix()
        if path.is_file():
            files.append(('%config(noreplace) ' if name in config_set else '') + name)
        elif name in ('/etc/whohack-preview', '/etc/whohack-preview/rules',
                      '/etc/whohack-preview/rules/tier0', '/etc/whohack-preview/rules/yara',
                      '/usr/share/doc/whohack-preview'):
            files.append('%dir ' + name)
    spec.write_text(f'''Name: {NAME}
Version: {version}
Release: 1
Summary: Native local monitoring preview (headless)
License: MIT OR Apache-2.0
URL: https://github.com/imamsyed999/whohack
BuildArch: {arch}
Requires: systemd
AutoReqProv: yes
%description
Polls accessible processes and TCP metadata. Automatic response and models are
disabled. Installation does not start or enable monitoring.
%post
systemd-sysusers /usr/lib/sysusers.d/whohack-preview.conf || exit $?
if [ -d /run/systemd/system ]; then systemctl daemon-reload; fi
%preun
if [ "$1" -eq 0 ] && [ -d /run/systemd/system ]; then systemctl stop whohack-preview.service; fi
%postun
if [ -d /run/systemd/system ]; then systemctl daemon-reload; fi
%files
%defattr(-,root,root,-)
''' + '\n'.join(files) + '\n', encoding='utf-8')
    subprocess.run(['rpmbuild', '-bb', str(spec), '--buildroot', str(root),
                    '--define', '_topdir ' + str(work), '--define', '_build_id_links none',
                    '--define', '__os_install_post %{nil}', '--define', 'debug_package %{nil}'], check=True)
    candidates = list((work / 'RPMS').rglob('*.rpm'))
    if len(candidates) != 1:
        raise ValueError('Expected exactly one RPM artifact')
    shutil.copyfile(candidates[0], destination)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--service', type=Path, required=True)
    parser.add_argument('--notices', type=Path, required=True)
    parser.add_argument('--format', choices=('deb', 'rpm', 'all'), default='all')
    parser.add_argument('--output', type=Path, default=ROOT / '.vigil/packages/linux')
    args = parser.parse_args()
    if sys.platform != 'linux':
        parser.error('Build native Linux packages on Linux')
    header = args.service.read_bytes()[:20]
    if header[:6] != b'\x7fELF\x02\x01':
        parser.error('Expected a native 64-bit little-endian ELF service')
    machine = struct.unpack_from('<H', header, 18)[0]
    arch, rpm_arch, target = {62: ('amd64', 'x86_64', 'x86_64-unknown-linux-gnu'),
                             183: ('arm64', 'aarch64', 'aarch64-unknown-linux-gnu')}.get(machine, (None, None, None))
    if not arch:
        parser.error('Unsupported ELF architecture')
    versions = subprocess.check_output(['readelf', '--version-info', str(args.service)], text=True)
    requirements = re.findall(r'GLIBC_(\d+(?:\.\d+)+)', versions)
    if not requirements:
        parser.error('Expected a glibc-linked service')
    glibc = max(requirements, key=lambda v: tuple(map(int, v.split('.'))))
    version = tomllib.loads((ROOT / 'Cargo.toml').read_text())['workspace']['package']['version']
    args.output.mkdir(parents=True, exist_ok=True)
    report = {'version': version, 'architecture': arch, 'glibc_minimum': glibc,
              'input_service_sha256': digest(args.service), 'artifacts': []}
    for kind in ('deb', 'rpm') if args.format == 'all' else (args.format,):
        with tempfile.TemporaryDirectory(prefix='whohack-package-') as temp:
            work = Path(temp)
            root = work / 'payload'
            root.mkdir()
            configs = stage(args, root, version, target)
            destination = args.output / (f'{NAME}_{version}-1_{arch}.deb' if kind == 'deb'
                                          else f'{NAME}-{version}-1.{rpm_arch}.rpm')
            if kind == 'deb':
                deb(root, destination, version, arch, glibc, configs)
            else:
                rpm(root, work, destination, version, rpm_arch, glibc, configs)
            sha = digest(destination)
            destination.with_suffix(destination.suffix + '.sha256').write_text(f'{sha}  {destination.name}\n', encoding='ascii')
            report['artifacts'].append({'name': destination.name, 'sha256': sha, 'size': destination.stat().st_size})
    (args.output / 'build.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
