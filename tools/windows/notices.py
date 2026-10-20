"""Collect exact Rust dependency notices from target-filtered Cargo metadata.

Generate metadata for both Cargo workspaces with --locked --filter-platform
x86_64-pc-windows-msvc. Run this on the same host as Cargo so registry source
paths are accessible. This inventory includes build dependencies conservatively.
It records license-policy failures; it does not grant license exceptions.
"""
import argparse
import hashlib
import json
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import urlopen
from urllib.error import HTTPError


def repository_key(package):
    parsed = urlparse(package.get('repository') or '')
    parts = parsed.path.strip('/').removesuffix('.git').split('/')
    if parsed.hostname == 'github.com' and len(parts) >= 2:
        return '/'.join(parts[:2])


def upstream_notices(package, repositories, cache):
    """Fetch only license files at the registry archive's recorded Git commit."""
    vcs_path = Path(package['manifest_path']).parent / '.cargo_vcs_info.json'
    if not vcs_path.is_file():
        return []
    vcs = read_json(vcs_path)
    revision = vcs['git']['sha1']
    if len(revision) != 40 or any(c not in '0123456789abcdef' for c in revision):
        raise ValueError('invalid registry source revision')
    repository = repository_key(package) or repositories.get(revision)
    if not repository:
        return []
    texts = []
    for name in ('LICENSE', 'LICENSE-MIT', 'LICENSE-APACHE', 'LICENSE.md', 'LICENSE.txt', 'NOTICE'):
        url = f'https://raw.githubusercontent.com/{repository}/{revision}/{name}'
        key = hashlib.sha256(url.encode()).hexdigest()
        local = cache / key
        absent = cache / (key + '.missing')
        if absent.exists():
            continue
        if not local.exists():
            try:
                with urlopen(url, timeout=20) as response:
                    raw = response.read(4_000_001)
                if len(raw) > 4_000_000:
                    raise ValueError('oversized upstream license')
                local.write_bytes(raw)
            except HTTPError as error:
                if error.code != 404:
                    raise
                absent.touch()
                continue
        raw = local.read_bytes()
        texts.append((url, raw.decode('utf-8'), hashlib.sha256(raw).hexdigest()))
    return texts


def declared_license_text(package, cache):
    # These archives explicitly declare the indicated license but omit its full
    # text. Preserve the authors as declared, the source link and this provenance;
    # do not invent an upstream copyright notice or silently relicense anything.
    reviewed = {('ascii_tree', '0.1.1'): 'MIT', ('selectors', '0.38.0'): 'MPL-2.0'}
    license_id = reviewed.get((package['name'], package['version']))
    if not license_id or package['license'] != license_id:
        return []
    url = f'https://raw.githubusercontent.com/spdx/license-list-data/v3.27.0/text/{license_id}.txt'
    local = cache / hashlib.sha256(url.encode()).hexdigest()
    if not local.exists():
        with urlopen(url, timeout=20) as response:
            raw = response.read(100_001)
        if len(raw) > 100_000:
            raise ValueError('oversized standard license text')
        local.write_bytes(raw)
    raw = local.read_bytes()
    declaration = ('The registry Cargo.toml declares ' + license_id + '. Authors as declared: '
                   + ', '.join(package.get('authors', [])) + '.\n'
                   'No separate full license text was packaged upstream. The standard SPDX '
                   'license text below is supplied for reference; its template fields are '
                   'not assertions of authorship. Original source notices remain authoritative.\n')
    return [('Registry license declaration', declaration, hashlib.sha256(declaration.encode()).hexdigest()),
            (url, raw.decode('utf-8'), hashlib.sha256(raw).hexdigest())]


def read_json(path):
    data = path.read_bytes()
    return json.loads(data.decode('utf-16' if data.startswith((b'\xff\xfe', b'\xfe\xff')) else 'utf-8-sig'))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--metadata', type=Path, action='append', required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--target', default='x86_64-pc-windows-msvc', help='Target used to filter the supplied Cargo metadata')
    p.add_argument('--upstream-cache', type=Path,
                   help='opt in to fetching missing license texts from pinned upstream Git commits')
    args = p.parse_args()
    packages = {}
    for path in args.metadata:
        data = read_json(path)
        resolved = {n['id'] for n in data['resolve']['nodes']}
        for package in data['packages']:
            if package['id'] in resolved and package.get('source'):
                packages[(package['name'], package['version'])] = package
    records = []
    repositories = {}
    for package in packages.values():
        vcs = Path(package['manifest_path']).parent / '.cargo_vcs_info.json'
        if vcs.is_file() and repository_key(package):
            repositories[read_json(vcs)['git']['sha1']] = repository_key(package)
    if args.upstream_cache:
        args.upstream_cache.mkdir(parents=True, exist_ok=True)
    sections = [
        'whohack preview: third-party Rust dependency notices\n',
        f'Generated from the supplied locked dependency graphs for {args.target}. '
        'Build/procedural-macro dependencies are included conservatively. '
        'Dependencies retain their own licenses. This file does not approve '
        'exceptions to whohack license policy. Model weights, Python packages, '
        'Microsoft WebView2 and operating-system components are not bundled here.\n',
        'Registry source archives can be obtained at the exact-version links below. '
        'The bundled dependency sources are used without local modifications.\n',
    ]
    missing = []
    for (name, version), package in sorted(packages.items()):
        root = Path(package['manifest_path']).resolve().parent
        candidates = [f for f in root.rglob('*') if f.is_file() and not f.is_symlink()
                      and f.name.lower().startswith(('license', 'licence', 'copying', 'notice', 'copyright'))]
        if package.get('license_file'):
            candidates.append(root / package['license_file'])
        texts = []
        for file in sorted(set(candidates)):
            resolved = file.resolve(strict=True)
            if not resolved.is_relative_to(root) or file.stat().st_size > 4_000_000:
                raise ValueError(f'Unsafe/oversize license input for {name} {version}')
            raw = file.read_bytes()
            if b'\0' in raw:
                continue
            text = raw.decode('utf-8', errors='replace')
            texts.append((file.relative_to(root).as_posix(), text, hashlib.sha256(raw).hexdigest()))
        if not texts and args.upstream_cache:
            texts = upstream_notices(package, repositories, args.upstream_cache)
        if not texts and args.upstream_cache:
            texts = declared_license_text(package, args.upstream_cache)
        source = f'https://crates.io/api/v1/crates/{name}/{version}/download'
        record = dict(name=name, version=version, license=package.get('license'), source=source,
                      repository=package.get('repository'),
                      notices=[dict(path=f, sha256=h) for f, _, h in texts])
        records.append(record)
        sections.append(f'\n{"=" * 72}\n{name} {version}\nLicense: {record["license"]}\nSource: {source}\n')
        if texts:
            for filename, text, _ in texts:
                sections.append(f'\n--- {filename} ---\n{text}\n')
        else:
            missing.append(f'{name} {version}')
            sections.append('No license text was included in the registry source archive; review required.\n')
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text('\n'.join(sections), encoding='utf-8')
    args.output.with_suffix('.json').write_text(json.dumps(dict(
        target=args.target, packages=records, missing_notices=missing,
    ), indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(packages=len(records), missing_notices=missing, output=str(args.output))))
    if missing:
        raise SystemExit(2)


if __name__ == '__main__':
    main()
