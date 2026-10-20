"""Exercise the real packaged WebView2 UI against an isolated native service.

Node 22+ is needed only by this test. The debug port belongs only to the disposable
preview process; no production config or normal WebView2 settings are changed.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--screenshot', type=Path, default=ROOT / '.vigil/checks/windows-ui.png')
    parser.add_argument('--download-pause', action='store_true')
    args = parser.parse_args()
    if sys.platform != 'win32':
        parser.error('Run on Windows with WebView2 installed')
    archive = ROOT / '.vigil/packages/whohack-Windows-Preview.zip'
    with archive.open('rb') as f:
        assert hashlib.file_digest(f, 'sha256').hexdigest() == archive.with_suffix('.zip.sha256').read_text().split()[0]
    with tempfile.TemporaryDirectory(prefix='whohack UI acceptance ') as temporary:
        base = Path(temporary).resolve()
        with zipfile.ZipFile(archive) as zipped:
            assert all((base / n).resolve().is_relative_to(base) for n in zipped.namelist())
            zipped.extractall(base)
        root = base / 'whohack-Windows-Preview'
        launcher = root / 'whohack.exe'
        local = root / '.vigil/windows'
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            port = sock.getsockname()[1]
        env = dict(os.environ, WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS=f'--remote-debugging-port={port}')

        def run(action, check=True):
            def logs():
                return '\n'.join(f'{p.name}:\n{p.read_text(encoding="utf-8", errors="replace")[-6000:]}'
                                 for p in local.glob('*log'))
            try:
                result = subprocess.run([str(launcher), action], cwd=root, env=env, capture_output=True,
                                        text=True, encoding='utf-8', errors='replace', timeout=65,
                                        creationflags=subprocess.CREATE_NO_WINDOW)
            except subprocess.TimeoutExpired as error:
                raise AssertionError(f'{action} timed out: {error.stderr!r}\n{logs()}') from error
            if check and result.returncode:
                raise AssertionError(f'{action} failed: {result.stderr}\n{logs()}')
            return result

        try:
            run('start-service')
            run('stop')
            config = local / 'config.toml'
            body = config.read_text(encoding='utf-8')
            assert '[response]\nenabled = false' in body
            body = body.replace('mode = "monitor"', 'mode = "prompt"', 1)
            body = body.replace('[response]\nenabled = false', '[response]\nenabled = true', 1)
            if args.download_pause:
                assert 'pause_downloads = false' in body
                body = body.replace('pause_downloads = false', 'pause_downloads = true', 1)
            config.write_text(body, encoding='utf-8', newline='\n')
            subprocess.run([str(root / 'bin/whohack-service.exe'), '--config', str(config), '--write-manifest'],
                           check=True, capture_output=True, timeout=15, creationflags=subprocess.CREATE_NO_WINDOW)
            run('start')
            status = json.loads(run('status').stdout)
            assert not status['automatic_response_enabled'] and status['enforcement_available']
            assert status['download_pause_enabled'] == args.download_pause
            args.screenshot.parent.mkdir(parents=True, exist_ok=True)
            subprocess.run(['node', str(ROOT / 'tools/windows/ui_acceptance.mjs'), str(port),
                            str(status['service_pid']), str(args.screenshot.resolve()), str(args.download_pause).lower()],
                           check=True, timeout=100, creationflags=subprocess.CREATE_NO_WINDOW)
        finally:
            run('stop')
    print('PASS: real packaged Windows UI, service identity, tabs, local trust add/remove, mode changes and Auto disabled')


if __name__ == '__main__':
    main()
