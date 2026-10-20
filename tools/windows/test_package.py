"""Exercise an extracted Windows package without Python, Rust or WSL on PATH.

The restart check terminates only a process whose handle, image and birth time
are verified to belong to this test's isolated package. It never changes system
services, firewall rules, Defender settings or the normal preview configuration.
"""

import ctypes
from ctypes import wintypes
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import time
import zipfile

ROOT = Path(__file__).resolve().parents[2]


def crash_owned_service(pid, expected_image, earliest_start):
    # Microsoft OpenProcess / QueryFullProcessImageNameW / GetProcessTimes APIs.
    k = ctypes.WinDLL("kernel32", use_last_error=True)
    k.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    k.OpenProcess.restype = wintypes.HANDLE
    k.QueryFullProcessImageNameW.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
    k.QueryFullProcessImageNameW.restype = wintypes.BOOL
    k.GetProcessTimes.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 4
    k.GetProcessTimes.restype = wintypes.BOOL
    k.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
    k.TerminateProcess.restype = wintypes.BOOL
    k.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    k.WaitForSingleObject.restype = wintypes.DWORD
    k.CloseHandle.argtypes = [wintypes.HANDLE]
    k.CloseHandle.restype = wintypes.BOOL
    handle = k.OpenProcess(0x1000 | 0x0001 | 0x00100000, False, pid)
    if not handle:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        image = ctypes.create_unicode_buffer(32768)
        size = wintypes.DWORD(len(image))
        if not k.QueryFullProcessImageNameW(handle, 0, image, ctypes.byref(size)):
            raise ctypes.WinError(ctypes.get_last_error())
        assert Path(image.value).resolve() == expected_image.resolve(), "refusing to terminate a different image"
        stamps = [wintypes.FILETIME() for _ in range(4)]
        if not k.GetProcessTimes(handle, *(ctypes.byref(t) for t in stamps)):
            raise ctypes.WinError(ctypes.get_last_error())
        born = ((stamps[0].dwHighDateTime << 32) | stamps[0].dwLowDateTime) / 10_000_000 - 11644473600
        assert born >= earliest_start - 1, "refusing to terminate a process that predates this test"
        if not k.TerminateProcess(handle, 91):
            raise ctypes.WinError(ctypes.get_last_error())
        assert k.WaitForSingleObject(handle, 10_000) == 0
    finally:
        k.CloseHandle(handle)


def main():
    if sys.platform != "win32":
        raise SystemExit("Run this package smoke test on Windows.")
    archive = ROOT / ".vigil/packages/whohack-Windows-Preview.zip"
    with archive.open("rb") as f:
        assert hashlib.file_digest(f, "sha256").hexdigest() == archive.with_suffix(".zip.sha256").read_text().split()[0]
    with tempfile.TemporaryDirectory(prefix="whohack portable test ") as directory:
        with zipfile.ZipFile(archive) as z:
            base = Path(directory).resolve()
            assert all((base / n).resolve().is_relative_to(base) for n in z.namelist())
            z.extractall(base)
        root = base / "whohack-Windows-Preview"
        exe = root / "whohack.exe"
        local = root / ".vigil/windows"
        env = dict(os.environ, PATH=str(Path(os.environ["SystemRoot"]) / "System32"))

        def run(action, check=True):
            result = subprocess.run([str(exe), action], cwd=root, env=env,
                                    capture_output=True, encoding="utf-8", errors="replace",
                                    creationflags=subprocess.CREATE_NO_WINDOW, timeout=65)
            if check and result.returncode:
                logs = "\n".join(p.read_text(encoding="utf-8", errors="replace")[-6000:]
                                 for p in local.glob("*log"))
                raise AssertionError(f"{action}: {result.stderr}\n{logs}")
            return result

        def await_status(predicate, seconds=35):
            deadline = time.monotonic() + seconds
            while time.monotonic() < deadline:
                result = run("status", check=False)
                if result.returncode == 0:
                    status = json.loads(result.stdout)
                    if predicate(status):
                        return status
                time.sleep(.2)
            raise AssertionError("package status did not reach the expected state")

        began = time.time()
        try:
            local.mkdir(parents=True, exist_ok=True)
            health = local / "launcher-health.json"
            health.write_text(json.dumps({"state": "error", "message": "stale test failure"}), encoding="utf-8")
            run("start-service")
            await_status(lambda s: not s["integrity_issues"])
            assert json.loads(health.read_text(encoding="utf-8"))["state"] == "running"
            run("stop")
            assert json.loads(health.read_text(encoding="utf-8"))["state"] == "stopped"
            # Older Python-launched previews recorded ordinary Windows paths;
            # the native launcher uses extended-length paths. Keep the digest.
            manifest_path = local / "rules/MANIFEST.sha256"
            legacy_manifest = manifest_path.read_text(encoding="utf-8").replace('  \\\\?\\', '  ')
            manifest_path.write_text(legacy_manifest, encoding="utf-8")
            run("start-service")
            first = await_status(lambda s: s["events_seen"] > 0 and not s["integrity_issues"])
            assert manifest_path.read_text(encoding="utf-8") == legacy_manifest
            assert first["collectors"] == ["windows-poll"] and first["mode"] == "monitor"
            assert not first["enforcement_available"] and first["service_pid"] > 0
            original_config = (local / "config.toml").read_bytes()
            original_token = (local / "data/ipc.token").read_bytes()
            run("start-service")
            assert json.loads(run("status").stdout)["service_pid"] == first["service_pid"]
            assert (local / "config.toml").read_bytes() == original_config
            crash_owned_service(first["service_pid"], root / "bin/whohack-service.exe", began)
            second = await_status(lambda s: s["service_pid"] != first["service_pid"] and s["events_seen"] > 0)
            assert (local / "data/ipc.token").read_bytes() != original_token
            assert second["mode"] == "monitor"
            assert json.loads(health.read_text(encoding="utf-8"))["state"] == "running"
            print("PASS: native package starts with no development tools on PATH, preserves config, rejects duplicates, restarts a crashed owned service and rotates credentials.", flush=True)

            rule = next((local / "rules/tier0").glob("*.yaml"))
            original_rule = rule.read_bytes()
            rule.write_bytes(original_rule + b"\n# isolated integrity test\n")
            try:
                changed = await_status(lambda s: bool(s["integrity_issues"]))
                assert changed["mode"] == "monitor" and not changed["response_actions"]
            finally:
                rule.write_bytes(original_rule)
            await_status(lambda s: not s["integrity_issues"])
            # The owned marker/supervisor must still stop safely if config is
            # damaged. This is deliberately confined to the extracted test copy.
            (local / "config.toml").write_text('invalid = [', encoding='utf-8')
            try:
                run("stop")
            finally:
                (local / "config.toml").write_bytes(original_config)
            assert run("status", check=False).returncode != 0
            with closing(sqlite3.connect(local / "data/vigil.db")) as db:
                assert db.execute("PRAGMA quick_check").fetchone() == ("ok",)
                assert db.execute("SELECT COUNT(*) FROM events").fetchone()[0] > 0
            run("stop")
            package_rule = next((root / "rules/tier0").glob("*.yaml"))
            package_rule.write_bytes(package_rule.read_bytes() + b"\n# damage\n")
            damaged = run("start-service", check=False)
            assert damaged.returncode != 0 and "integrity check failed" in damaged.stderr
            assert not (local / "session").exists()
            print("PASS: tampering appears in status, response stays disabled, shutdown survives damaged config and flushes SQLite, damaged packages refuse launch.")
        finally:
            # Stop waits for handles/locks, so TemporaryDirectory removes only an
            # isolated, stopped tree. Never enumerate or kill unrelated processes.
            if (local / "session").exists():
                run("stop")
            # Windows releases image mappings just after the supervisor's final
            # lock is dropped; allow that process-exit tail before removing it.
            time.sleep(.5)


if __name__ == "__main__":
    main()
