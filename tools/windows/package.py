"""Package existing native preview binaries; exclude local databases and tokens."""

from pathlib import Path
import argparse
import hashlib
import json
import zipfile

from launch import ROOT


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profile', choices=('debug', 'release'), default='debug')
    args = parser.parse_args()
    target = ROOT / 'target' / args.profile
    ui_target = ROOT / 'ui/src-tauri/target' / args.profile
    files = {
        Path("whohack.exe"): target / "whohack-launcher.exe",
        Path("bin/whohack-service.exe"): target / "whohack-service.exe",
        Path("bin/whohack-tray.exe"): ui_target / "whohack-tray.exe",
        Path("bin/whohack-response-helper.exe"): target / "whohack-response-helper.exe",
    }
    inventory = ROOT / '.vigil/packages/THIRD-PARTY-NOTICES.json'
    notices = json.loads(inventory.read_text(encoding='utf-8'))
    if notices.get('missing_notices') or not notices.get('packages'):
        raise ValueError('Generate and review complete third-party notices before packaging')
    files[Path('THIRD-PARTY-NOTICES.txt')] = inventory.with_suffix('.txt')
    files[Path('THIRD-PARTY-NOTICES.json')] = inventory
    for name in ('docs/readiness-2026-10-15.md', 'docs/advisory-review-2026-10-15.md', 'docs/backlog.md', 'docs/download-protection.md', 'docs/plans/M14-whohack-and-data.md', 'docs/plans/M15-download-activity.md', 'Update whohack.cmd'):
        files[Path(name)] = ROOT / name
    for name in ("Start whohack.cmd", "LICENSE-MIT", "LICENSE-APACHE", "SECURITY.md", "docs/licenses.md", "docs/license-review-2026-10-14.md", "docs/native-sensors.md", "docs/response-and-feeds.md", "docs/decision-runtime.md", "docs/scoring.md", "docs/training.md", "ml/reports/eval.md", "tools/intel/update.py", "tools/intel/virustotal.py"):
        files[Path(name)] = ROOT / name
    files[Path("README.txt")] = ROOT / "packaging/windows/README.txt"
    for folder in ("tier0", "yara"):
        for path in sorted((ROOT / "rules" / folder).rglob("*")):
            if path.is_file() and not path.is_symlink():
                files[path.relative_to(ROOT)] = path
    destination = ROOT / ".vigil/packages/whohack-Windows-Preview.zip"
    destination.parent.mkdir(parents=True, exist_ok=True)
    hashes = {}
    with zipfile.ZipFile(destination.with_suffix(".tmp"), "w", zipfile.ZIP_DEFLATED) as archive:
        for name, path in files.items():
            with path.open("rb") as handle:
                hashes[name.as_posix()] = hashlib.file_digest(handle, "sha256").hexdigest()
            archive.write(path, str(Path("whohack-Windows-Preview") / name))
        archive.writestr("whohack-Windows-Preview/WHOHACK-PACKAGE.json", json.dumps(hashes, indent=2) + "\n")
    destination.with_suffix(".tmp").replace(destination)
    with destination.open("rb") as handle:
        checksum = hashlib.file_digest(handle, "sha256").hexdigest()
    destination.with_suffix(".zip.sha256").write_text(f"{checksum}  {destination.name}\n", encoding="ascii")
    print(destination)


if __name__ == "__main__":
    main()
