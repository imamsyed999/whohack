"""Acquire pinned public UTF-8 behavior logs; recorded content is never executed."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import urllib.request

from dataset import sha256

MAX_FILE = 30_000_000
MAX_NEW_TOTAL = 500_000_000
REPOSITORY = 'splunk/attack_data'


def validate_catalog(catalog):
    if (catalog.get('schema_version') != 2 or catalog.get('repository') != REPOSITORY
            or not re.fullmatch(r'[0-9a-f]{40}', catalog.get('revision', ''))
            or catalog.get('license') != 'Apache-2.0'):
        raise ValueError('expected a pinned, licensed Splunk telemetry catalog')
    seen_paths, seen_digests, seen_families = set(), set(), set()
    for entry in catalog['files']:
        path = PurePosixPath(entry['path'])
        if ('..' in path.parts or not re.fullmatch(r'[A-Za-z0-9_./-]+', entry['path'])
                or not entry['path'].startswith(('datasets/malware/', 'datasets/attack_techniques/'))
                or path.suffix != '.log' or 'sysmon' not in path.name.lower()):
            raise ValueError('catalog contains a non-Sysmon telemetry path')
        if type(entry['bytes']) is not int or not 0 < entry['bytes'] <= MAX_FILE:
            raise ValueError('catalog file exceeds the byte budget')
        if not re.fullmatch(r'[0-9a-f]{64}', entry['sha256']):
            raise ValueError('catalog requires pinned SHA-256 digests')
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', entry['family']):
            raise ValueError('invalid source group')
        if (entry['path'].lower() in seen_paths or entry['sha256'] in seen_digests
                or entry['family'].lower() in seen_families):
            raise ValueError('duplicate source path or content')
        seen_paths.add(entry['path'].lower())
        seen_digests.add(entry['sha256'])
        seen_families.add(entry['family'].lower())
    if {n['path'] for n in catalog['notices']} != {'LICENSE', 'README.md'}:
        raise ValueError('pinned upstream notices are required')
    for notice in catalog['notices']:
        if not 0 < notice['bytes'] <= 100_000 or not re.fullmatch(r'[0-9a-f]{64}', notice['sha256']):
            raise ValueError('invalid upstream notice')


def verified_text(path, entry):
    if path.stat().st_size != entry['bytes'] or sha256(path) != entry['sha256']:
        raise ValueError('cached source differs from pinned bytes/digest')
    data = path.read_bytes()
    if b'\x00' in data or data.startswith(b'MZ'):
        raise ValueError('only UTF-8 text is allowed')
    data.decode('utf-8-sig')


def fetch_text(url, path, entry):
    request = urllib.request.Request(url, headers={'User-Agent': 'whohack-public-telemetry'})
    with urllib.request.urlopen(request, timeout=60) as response:
        data = response.read(entry['bytes'] + 1)
    if len(data) != entry['bytes'] or hashlib.sha256(data).hexdigest() != entry['sha256']:
        raise ValueError('download differs from pinned bytes/digest')
    if b'\x00' in data or data.startswith(b'MZ'):
        raise ValueError('only UTF-8 text is allowed')
    data.decode('utf-8-sig')
    path.write_bytes(data)


def acquire(catalog_path, output, reuse=None):
    catalog = json.loads(catalog_path.read_text(encoding='utf-8'))
    validate_catalog(catalog)
    cached = {}
    if reuse:
        previous = json.loads((reuse / 'acquisition.json').read_text(encoding='utf-8'))
        if previous['repository'] != catalog['repository'] or previous['revision'] != catalog['revision']:
            raise ValueError('cache provenance does not match the pinned repository/revision')
        for entry in previous['files']:
            path = (reuse / entry['file']).resolve()
            if not path.is_relative_to(reuse.resolve()):
                raise ValueError('cached file escapes source directory')
            cached[entry['sha256']] = path
    tasks, new_bytes = [], 0
    for entry in catalog['files']:
        path = output / (entry['family'] + '-' + entry['sha256'][:12] + '.log')
        source = path if path.exists() else cached.get(entry['sha256'])
        if source:
            verified_text(source, entry)
        else:
            new_bytes += entry['bytes']
        tasks.append((entry, path, source))
    new_notice_bytes = sum(n['bytes'] for n in catalog['notices'] if not (output / n['path']).exists())
    if new_bytes + new_notice_bytes > MAX_NEW_TOTAL:
        raise ValueError('new downloads exceed the 500 MB total budget; supply a verified reuse cache')
    output.mkdir(parents=True, exist_ok=True)

    def download(task):
        entry, path, source = task
        url = f'https://media.githubusercontent.com/media/{REPOSITORY}/{catalog["revision"]}/{entry["path"]}'
        if source and source.resolve() != path.resolve():
            # Preserve one physical copy of the verified existing logs.
            path.hardlink_to(source)
        elif not source:
            fetch_text(url, path, entry)
        print('Verified telemetry', entry['family'], entry['bytes'], 'reused' if source else 'downloaded', flush=True)
        return dict(file=path.name, source_path=entry['path'], bytes=entry['bytes'],
                    sha256=entry['sha256'], family=entry['family'], url=url,
                    reused=source is not None, technique=entry.get('technique'),
                    source_context=entry['source_context'])

    with ThreadPoolExecutor(max_workers=3) as pool:
        records = list(pool.map(download, tasks))
    notices = []
    for notice in catalog['notices']:
        path = output / notice['path']
        url = f'https://raw.githubusercontent.com/{REPOSITORY}/{catalog["revision"]}/{notice["path"]}'
        if path.exists():
            verified_text(path, notice)
        else:
            fetch_text(url, path, notice)
        notices.append(dict(file=path.name, url=url, bytes=notice['bytes'], sha256=notice['sha256']))
    report = dict(repository=REPOSITORY, revision=catalog['revision'], license=catalog['license'],
                  files=records, notices=notices, catalog_sha256=sha256(catalog_path),
                  total_bytes=sum(r['bytes'] for r in records), newly_downloaded_bytes=new_bytes,
                  newly_downloaded_notice_bytes=new_notice_bytes,
                  reused_files=sum(r['reused'] for r in records), max_new_bytes=MAX_NEW_TOTAL,
                  max_file_bytes=MAX_FILE, samples_downloaded=False,
                  limitation='Lab traces contain mixed process activity; source names are not per-process truth.')
    (output / 'acquisition.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({k: v for k, v in report.items() if k not in ('files', 'notices')}, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--catalog', type=Path, default=Path(__file__).parent / 'fixtures/public-telemetry-v2-catalog.json')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--reuse', type=Path)
    args = parser.parse_args()
    acquire(args.catalog.resolve(strict=True), args.output.resolve(),
            args.reuse.resolve(strict=True) if args.reuse else None)
