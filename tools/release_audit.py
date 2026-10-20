"""Audit source/history for common secret patterns and export the working tree.

This is a bounded hygiene check, not proof that all secrets or third-party rights
have been found. It never prints matching credential values. No uploads occur.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import zipfile

ROOT = Path(__file__).resolve().parents[1]
PATTERNS = {
    'private-key': rb'-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----',
    'github-token': rb'\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})\b',
    'aws-access-key': rb'\b(?:AKIA|ASIA)[A-Z0-9]{16}\b',
    'provider-key': rb'\bsk-(?:proj-|ant-)?[A-Za-z0-9_-]{40,}\b',
    'slack-token': rb'\bxox[baprs]-[A-Za-z0-9-]{20,}\b',
}
PRIVATE_PARTS = {'.vigil', '.git', '.venv', 'target', '__pycache__', 'node_modules'}
PRIVATE_SUFFIXES = {'.db', '.log', '.pfx', '.p12', '.safetensors', '.exe', '.dll', '.msi'}


def git(*args):
    return subprocess.check_output(['git', *args], cwd=ROOT)


def matches(data):
    return [name for name, pattern in PATTERNS.items() if re.search(pattern, data)]


def source_files():
    names = git('ls-files', '-z', '--cached', '--others', '--exclude-standard').decode().split('\0')
    files, findings = {}, []
    for name in sorted(set(names) - {''}):
        path = ROOT / name
        if not path.exists():
            continue
        if path.is_symlink() or not path.resolve().is_relative_to(ROOT):
            findings.append(dict(path=name, issue='symlink or outside workspace'))
            continue
        if (PRIVATE_PARTS.intersection(path.relative_to(ROOT).parts)
                or path.suffix.lower() in PRIVATE_SUFFIXES or path.name == '.env'
                or path.name.startswith('.env.') and not path.name.endswith(('.example', '.sample'))):
            findings.append(dict(path=name, issue='private/generated file in source selection'))
            continue
        if path.stat().st_size > 5_000_000:
            findings.append(dict(path=name, issue='file larger than source export limit'))
            continue
        data = path.read_bytes()
        for kind in matches(data):
            findings.append(dict(path=name, issue=kind))
        files[name] = data
    return files, findings


def history():
    entries = git('rev-list', '--objects', '--all').decode().splitlines()
    findings, checked, skipped = [], 0, []
    with subprocess.Popen(['git', 'cat-file', '--batch'], cwd=ROOT,
                          stdin=subprocess.PIPE, stdout=subprocess.PIPE) as process:
        for entry in entries:
            oid, _, name = entry.partition(' ')
            process.stdin.write((oid + '\n').encode()); process.stdin.flush()
            header = process.stdout.readline().decode().split()
            size = int(header[2])
            data = process.stdout.read(size)
            assert process.stdout.read(1) == b'\n'
            if header[1] != 'blob':
                continue
            checked += 1
            if size > 5_000_000:
                skipped.append(dict(object=oid, path=name, bytes=size))
                continue
            for kind in matches(data):
                findings.append(dict(object=oid, path=name, issue=kind))
        process.stdin.close()
        if process.wait(timeout=10):
            raise RuntimeError('Git history reader failed')
    return dict(blobs_checked=checked, findings=findings, oversized_not_scanned=skipped)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--source-zip', type=Path)
    args = p.parse_args()
    files, findings = source_files()
    past = history()
    report = dict(files_checked=len(files), current_findings=findings, history=past,
                  scope='Current Git-selected working tree and reachable Git history; common patterns only. No uploads.')
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(report))
    if findings or past['findings'] or past['oversized_not_scanned']:
        raise SystemExit(2)
    if args.source_zip:
        args.source_zip.parent.mkdir(parents=True, exist_ok=True)
        hashes = {name: hashlib.sha256(data).hexdigest() for name, data in files.items()}
        with zipfile.ZipFile(args.source_zip.with_suffix('.tmp'), 'w', zipfile.ZIP_DEFLATED) as archive:
            for name, data in files.items():
                archive.writestr('whohack-Source-Preview/' + name, data)
            archive.writestr('whohack-Source-Preview/SOURCE-MANIFEST.json', json.dumps(hashes, indent=2) + '\n')
        args.source_zip.with_suffix('.tmp').replace(args.source_zip)
        with zipfile.ZipFile(args.source_zip) as archive:
            assert archive.testzip() is None
            for name, sha in hashes.items():
                assert hashlib.sha256(archive.read('whohack-Source-Preview/' + name)).hexdigest() == sha
        digest = hashlib.sha256(args.source_zip.read_bytes()).hexdigest()
        args.source_zip.with_suffix('.zip.sha256').write_text(f'{digest}  {args.source_zip.name}\n', encoding='ascii')
        print(f'Verified source preview: {args.source_zip} ({len(files)} files)')


if __name__ == '__main__':
    main()
