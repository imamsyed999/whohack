"""Native Windows preview launcher. Python 3.11+, standard library only."""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import tomllib
import uuid


ROOT = Path(__file__).resolve().parents[2]
LOCAL = ROOT / ".vigil" / "windows"
CONFIG = LOCAL / "config.toml"
SESSION = LOCAL / "session"


def binary(name: str) -> Path:
    # A portable package contains bin/. A source checkout uses Cargo output.
    packaged = ROOT / "bin" / f"{name}.exe"
    if packaged.is_file():
        return packaged
    base = ROOT / "ui" / "src-tauri" if name == "whohack-tray" else ROOT
    release = base / "target" / "release" / f"{name}.exe"
    if release.is_file():
        return release
    path = base / "target" / "debug" / f"{name}.exe"
    if not path.is_file():
        raise RuntimeError(f"Missing {path}. Run 'Start whohack.cmd build' first.")
    return path


def command(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(
        [str(binary("whohack-service")), "--config", str(CONFIG), *args],
        cwd=ROOT, capture_output=True, text=True, encoding="utf-8", errors="replace",
        check=check, timeout=15, creationflags=subprocess.CREATE_NO_WINDOW,
    )


def status() -> dict | None:
    if not CONFIG.is_file():
        return None
    result = command("--status", check=False)
    return json.loads(result.stdout) if result.returncode == 0 else None


@contextmanager
def launcher_lock():
    import msvcrt

    LOCAL.mkdir(parents=True, exist_ok=True)
    with (LOCAL / "launcher.lock").open("a+b") as handle:
        handle.seek(0)
        if not handle.read(1):
            handle.write(b"0")
            handle.flush()
        handle.seek(0)
        try:
            msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
        except OSError as error:
            raise RuntimeError("Another whohack launcher command is still running.") from error
        try:
            yield
        finally:
            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)


def prepare() -> None:
    if not CONFIG.exists():
        # Unspecified options take the service's validated defaults.
        # JSON strings are also valid TOML basic strings.
        rules = LOCAL / "rules"
        rules.mkdir(exist_ok=True)
        source = ROOT / "rules"
        if source.is_dir():
            shutil.copytree(source, rules, dirs_exist_ok=True,
                            ignore=shutil.ignore_patterns("MANIFEST.sha256"))
        body = '\n'.join([
            'mode = "monitor"', '[paths]',
            'data_dir = "data"', 'log_dir = "logs"', 'rules_dir = "rules"',
            '[collect]', 'backend = "poll"', 'dns = false',
            '[ipc]', 'endpoint = ' + json.dumps(r"\\.\pipe\whohack-preview-" + uuid.uuid4().hex),
            '',
        ])
        with CONFIG.open("x", encoding="utf-8") as handle:
            handle.write(body)
        command("--write-manifest")
    command("--check-config")


def spawn(name: str, *args: str) -> subprocess.Popen:
    env = dict(os.environ, WHOHACK_CONFIG=str(CONFIG), WHOHACK_SESSION_FILE=str(SESSION))
    with (LOCAL / f"{name}-launch.log").open("ab", buffering=0) as log:
        return subprocess.Popen(
            [str(binary(name)), *args], cwd=ROOT, env=env,
            stdin=subprocess.DEVNULL, stdout=log, stderr=log,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )


def start(with_tray: bool) -> None:
    binary("whohack-service")
    if with_tray:
        binary("whohack-tray")
    prepare()
    current = status()
    if current:
        if not SESSION.is_file():
            raise RuntimeError("This service was started separately; its lifecycle is not owned by this launcher.")
    else:
        # A new identity also tells any stale tray from the old session to quit.
        SESSION.write_text(uuid.uuid4().hex, encoding="ascii")
        process = None
        try:
            process = spawn("whohack-service", "--config", str(CONFIG), "--run",
                            "--session-file", str(SESSION))
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    raise RuntimeError(f"Service exited ({process.returncode}). See {LOCAL / 'whohack-service-launch.log'}")
                current = status()
                if current:
                    break
                time.sleep(0.25)
            else:
                raise RuntimeError(f"Service did not become ready. See logs in {LOCAL}")
        except BaseException:
            SESSION.unlink(missing_ok=True)
            if process is not None:
                process.wait(timeout=15)
            raise
    if "windows-poll" not in current["collectors"] and "windows-etw" not in current["collectors"]:
        raise RuntimeError(f"Unexpected collectors: {current['collectors']}")
    if with_tray:
        process = spawn("whohack-tray", "--show")
        time.sleep(1)
        if process.poll() not in (None, 0):
            raise RuntimeError(f"Tray exited ({process.returncode}). See {LOCAL / 'whohack-tray-launch.log'}")
    print("whohack is monitoring Windows processes and TCP connections.")
    print("Monitor mode: automatic response is off; elevated sensors need the native backend.")
    print(f"Configuration and logs: {LOCAL}")


def stop() -> None:
    if not SESSION.is_file():
        print("No launcher-owned Windows session to stop.")
        return
    SESSION.unlink()
    # The service flushes its event pipeline before releasing the data lock.
    deadline = time.monotonic() + 20
    with CONFIG.open("rb") as handle:
        data_dir = Path(tomllib.load(handle).get("paths", {}).get("data_dir", "data"))
    if not data_dir.is_absolute():
        data_dir = CONFIG.parent / data_dir
    lock_files = [data_dir / "service.lock", SESSION.with_suffix(".tray.lock")]
    import msvcrt
    while time.monotonic() < deadline:
        try:
            for lock_file in lock_files:
                if lock_file.exists():
                    with lock_file.open("r+b") as handle:
                        msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                        msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            break
        except OSError:
            time.sleep(0.25)
    else:
        raise RuntimeError("Shutdown is still in progress. Check the service log; no process was forcibly terminated.")
    print("Stopped this checkout's Windows preview and tray.")


def build(cross: bool, release: bool) -> None:
    if SESSION.is_file():
        raise RuntimeError("Stop whohack before rebuilding: Start whohack.cmd stop")
    env = dict(os.environ, CARGO_TARGET_DIR=str(ROOT / "target"))
    profile = ["--release"] if release else []
    if cross:
        subprocess.run(["wsl", "-d", "Ubuntu", "--", "python3", "tools/windows/cross-build.py", "--stage", *profile],
                       cwd=ROOT, check=True)
        subprocess.run(["wsl", "-d", "Ubuntu", "--", "python3", "tools/windows/cross-build.py", "--ui", "--stage", *profile],
                       cwd=ROOT, check=True)
    else:
        subprocess.run(["cargo", "build", "-p", "whohack-service", "-p", "whohack-launcher", "-p", "whohack-response-helper", "--locked", *profile], cwd=ROOT, env=env, check=True)
        env["CARGO_TARGET_DIR"] = str(ROOT / "ui" / "src-tauri" / "target")
        subprocess.run(["cargo", "build", "--manifest-path", "ui/src-tauri/Cargo.toml", "--locked", *profile],
                       cwd=ROOT, env=env, check=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", nargs="?", default="start",
                        choices=("start", "start-service", "stop", "status", "build"))
    parser.add_argument("--cross", action="store_true", help="With build: compile native Windows service and tray in WSL using the existing SDK")
    parser.add_argument("--release", action="store_true", help="With build: compile optimized executables")
    args = parser.parse_args()
    if sys.platform != "win32":
        parser.error("Run this launcher on Windows, not inside WSL.")
    if args.cross and args.action != "build":
        parser.error("--cross requires build")
    try:
        with launcher_lock():
            if args.action == "build":
                build(args.cross, args.release)
            elif args.action == "stop":
                stop()
            elif args.action == "status":
                current = status()
                if current is None:
                    print("Windows preview is not running.")
                    return 1
                print(json.dumps(current, indent=2))
            else:
                start(with_tray=args.action == "start")
        return 0
    except (OSError, RuntimeError, subprocess.SubprocessError, ValueError) as error:
        print(f"whohack: {error}", file=sys.stderr)
        if isinstance(error, subprocess.CalledProcessError) and error.stderr:
            print(error.stderr, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
