"""Exercise the actual Windows service with isolated data and localhost traffic."""

import json
from contextlib import closing
import os
from pathlib import Path
import re
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import uuid

from launch import binary


def main() -> None:
    if sys.platform != "win32":
        raise SystemExit("This smoke test must run on Windows.")
    service = binary("whohack-service")
    with tempfile.TemporaryDirectory(prefix="whohack Windows test ") as directory:
        root = Path(directory)
        config = root / "config.toml"
        marker = root / "session"
        marker.write_text(uuid.uuid4().hex, encoding="ascii")
        config.write_text('\n'.join([
            'mode = "monitor"', '[paths]', 'data_dir = "data"',
            'log_dir = "logs"', 'rules_dir = "rules"', '[collect]',
            'backend = "poll"', 'poll_interval_ms = 100',
            'include_loopback = true', 'dns = false', '[ipc]',
            'endpoint = ' + json.dumps(r"\\.\pipe\whohack-test-" + uuid.uuid4().hex), '',
        ]), encoding="utf-8")

        def run(*args):
            return subprocess.run([str(service), "--config", str(config), *args],
                                  capture_output=True, text=True, encoding="utf-8",
                                  timeout=15, creationflags=subprocess.CREATE_NO_WINDOW)

        assert run("--write-manifest").returncode == 0
        output = root / "service.log"
        with output.open("wb") as log:
            process = subprocess.Popen(
                [str(service), "--config", str(config), "--run", "--session-file", str(marker)],
                stdin=subprocess.DEVNULL, stdout=log, stderr=log,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
            try:
                deadline = time.monotonic() + 30
                while True:
                    result = run("--status")
                    if result.returncode == 0:
                        status = json.loads(result.stdout)
                        break
                    assert process.poll() is None, output.read_text(encoding="utf-8")
                    assert time.monotonic() < deadline, result.stderr
                    time.sleep(0.1)
                assert status["collectors"] == ["windows-poll"], status
                assert status["mode"] == "monitor" and not status["enforcement_available"]
                token_file = root / "data/ipc.token"
                token = token_file.read_bytes()
                duplicate = run("--run")
                assert duplicate.returncode != 0 and "another instance" in duplicate.stderr
                assert token_file.read_bytes() == token
                token_file.write_text("wrong-token", encoding="ascii")
                assert run("--status").returncode != 0, "wrong credentials were accepted"
                token_file.write_bytes(token)
                assert run("--status").returncode == 0

                # Keep a real localhost connection open until it reaches storage.
                with socket.socket() as listener:
                    listener.bind(("127.0.0.1", 0))
                    listener.listen()
                    port = listener.getsockname()[1]
                    with socket.create_connection(("127.0.0.1", port)), listener.accept()[0]:
                        deadline = time.monotonic() + 40
                        while True:
                            with closing(sqlite3.connect(root / "data/vigil.db")) as database:
                                row = database.execute(
                                    "SELECT pid FROM connections WHERE pid=? AND remote_ip=? AND remote_port=?",
                                    (os.getpid(), "127.0.0.1", port),
                                ).fetchone()
                            if row:
                                break
                            assert time.monotonic() < deadline, "Windows TCP event did not reach storage"
                            time.sleep(0.1)
                marker.unlink()
                assert process.wait(timeout=20) == 0
                text = output.read_text(encoding="utf-8")
                counts = re.search(r"whohack service stopped published=(\d+) stored=(\d+)", text)
                assert counts and counts[1] == counts[2] and int(counts[1]) > 0, text
                print(f"PASS: native Windows IPC, wrong-token refusal, duplicate guard, TCP PID attribution, graceful flush ({counts[1]} events).")
            finally:
                marker.unlink(missing_ok=True)
                try:
                    process.wait(timeout=20)
                except subprocess.TimeoutExpired:
                    # Test-only cleanup of the exact child handle we created.
                    process.kill()
                    process.wait()


if __name__ == "__main__":
    main()
