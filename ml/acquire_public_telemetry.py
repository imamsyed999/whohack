"""Download only pinned, bounded public text logs; never samples or executables."""
import argparse
import concurrent.futures
import hashlib
import json
from pathlib import Path
import urllib.request

REPOSITORY = 'splunk/attack_data'
REVISION = 'aafa53ea228fbab8d9ac3e33c9275fab2136909d'
MAX_FILE = 20_000_000
MAX_TOTAL = 125_000_000


def fetch(url, path, expected_size=None, expected_sha=None):
    if path.exists():
        data = path.read_bytes()
    else:
        request = urllib.request.Request(url, headers={'User-Agent': 'whohack-telemetry-research'})
        with urllib.request.urlopen(request, timeout=60) as response:
            data = response.read((expected_size or 100_000) + 1)
        if len(data) > (expected_size or 100_000):
            raise ValueError('download exceeds byte budget')
        if expected_size is not None and len(data) != expected_size:
            raise ValueError('download size differs from the pinned LFS pointer')
        if expected_sha and hashlib.sha256(data).hexdigest() != expected_sha:
            raise ValueError('download digest differs from the pinned LFS pointer')
        if b'\x00' in data or data.startswith(b'MZ'):
            raise ValueError('only UTF-8 text logs are allowed')
        data.decode('utf-8')
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    digest = hashlib.sha256(data).hexdigest()
    if expected_size is not None and len(data) != expected_size or expected_sha and digest != expected_sha:
        raise ValueError('cached file differs from the pinned source')
    return dict(url=url, file=path.name, bytes=len(data), sha256=digest)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--catalog', type=Path, default=Path(__file__).parent / 'fixtures/splunk-sysmon-catalog.json')
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    candidates = json.loads(a.catalog.read_text(encoding='utf-8'))
    selected, total = [], 0
    for row in candidates:
        parts = dict(line.split(' ', 1) for line in row['pointer'].splitlines())
        size = int(parts['size'])
        path = row['path']
        if not path.startswith('datasets/malware/') or not path.endswith('.log') or '..' in Path(path).parts:
            raise ValueError('not an allowed public telemetry path')
        if size > MAX_FILE or total + size > MAX_TOTAL:
            continue
        selected.append((path, size, parts['oid'].removeprefix('sha256:')))
        total += size
    a.output.mkdir(parents=True, exist_ok=True)
    def download(record):
        path, size, digest = record
        family = path.split('/')[2]
        url = f'https://media.githubusercontent.com/media/{REPOSITORY}/{REVISION}/{path}'
        result = fetch(url, a.output / (family + '.log'), size, digest)
        result.update(source_path=path, family=family)
        print(f'Verified text telemetry: {family}, {size:,} bytes', flush=True)
        return result
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
        records = list(pool.map(download, selected))
    notices = [fetch(f'https://raw.githubusercontent.com/{REPOSITORY}/{REVISION}/{name}', a.output / name)
               for name in ['LICENSE', 'README.md']]
    report = dict(repository=REPOSITORY, revision=REVISION, license='Apache-2.0', files=records,
                  notices=notices, total_bytes=total, max_total_bytes=MAX_TOTAL,
                  samples_downloaded=False, limitation='Source logs contain mixed process activity; file-level attack labels are not per-event ground truth.')
    (a.output / 'acquisition.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(f'Acquired {len(records)} text datasets, {total:,} bytes; no executables.', flush=True)


if __name__ == '__main__':
    main()
