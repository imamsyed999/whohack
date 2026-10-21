"""Download a tiny CPython WAV and prove native read + network attribution.

Run elevated on Windows. Uses an isolated service, a reader started before the
download, and a loopback connection. No malicious payload, remote attack traffic,
global sound settings, existing apps, or production configuration are changed.
The short WAV is played once using Windows' normal sound API.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import tomllib
import urllib.request
import uuid
import wave

from test_detection import require, wait_for

ROOT = Path(__file__).resolve().parents[2]
URL = "https://raw.githubusercontent.com/python/cpython/v3.14.0/Lib/test/audiodata/pluck-pcm8.wav"


def reader():
    import winsound
    root = Path(os.environ["WHOHACK_SAMPLE_ROOT"])
    (root / "reader-ready").write_text(str(os.getpid()), encoding="ascii")
    wait_for(lambda: (root / "download-ready").exists(), "Download did not finish", timeout=60)
    sample = root / "Downloads/sample.wav"
    with wave.open(str(sample), "rb") as audio:
        frames = audio.readframes(audio.getnframes())
        require(len(frames) > 0, "WAV has no audio")
        metadata = {"channels": audio.getnchannels(), "frames": audio.getnframes(),
                    "sample_rate": audio.getframerate(), "decoded_bytes": len(frames)}
    winsound.PlaySound(str(sample), winsound.SND_FILENAME | winsound.SND_NODEFAULT)
    metadata["windows_playback_completed"] = True
    (root / "reader-result.json").write_text(json.dumps(metadata), encoding="utf-8")
    address = ("127.0.0.1", int(os.environ["WHOHACK_SAMPLE_PORT"]))
    while not (root / "reader-stop").exists():
        # Repeat actual reads and loopback connections to exercise the window
        # regression. These are normal benign operations, never a threat label.
        sample.read_bytes()
        with socket.create_connection(address, timeout=2):
            pass
        time.sleep(0.6)


def exercise(service, report, existing_config=None):
    report["sample_source"] = URL
    report["service_sha256"] = hashlib.sha256(service.read_bytes()).hexdigest()
    with tempfile.TemporaryDirectory(prefix="whohack sample acceptance ") as temporary:
        root = Path(temporary)
        (root / "Downloads").mkdir()
        shutil.copytree(ROOT / "rules", root / "rules", ignore=shutil.ignore_patterns("MANIFEST.sha256"))
        config, marker = root / "config.toml", root / "session"
        endpoint = r"\\.\pipe\whohack-sample-" + uuid.uuid4().hex
        marker.write_text(uuid.uuid4().hex, encoding="ascii")
        config.write_text('\n'.join([
            'mode = "prompt"', '[response]', 'enabled = true', 'automatic = false',
            'pause_downloads = true', '[paths]', 'data_dir = "data"',
            'log_dir = "logs"', 'rules_dir = "rules"', '[collect]',
            'backend = "native"', 'include_loopback = true', 'dns = false',
            '[ipc]', 'endpoint = ' + json.dumps(endpoint), '',
        ]), encoding="utf-8")
        data_dir = root / "data"
        if existing_config:
            # Read-only observation of a service already authorized/running.
            # No manifest, settings, mode, session or response changes.
            config = existing_config.resolve()
            existing = tomllib.loads(config.read_text(encoding="utf-8"))
            endpoint = existing["ipc"]["endpoint"]
            data_dir = (config.parent / existing["paths"]["data_dir"]).resolve()
            report["existing_service_observation"] = True
            report["status_client_sha256"] = report.pop("service_sha256")
        else:
            report["existing_service_observation"] = False
        flags = {"creationflags": subprocess.CREATE_NO_WINDOW, "cwd": ROOT}

        def service_command(*args):
            return subprocess.run([str(service), "--config", str(config), *args],
                                  capture_output=True, text=True, timeout=15, **flags)

        def ipc(op, **fields):
            result = subprocess.run([sys.executable, str(ROOT / "tools/windows/test_detection.py"),
                                     "--ipc", endpoint, str(data_dir / "ipc.token"),
                                     json.dumps({"op": op, **fields})],
                                    capture_output=True, text=True, timeout=8, **flags)
            require(result.returncode == 0, "IPC failed: " + result.stderr)
            return json.loads(result.stdout)

        if not existing_config:
            require(service_command("--write-manifest").returncode == 0, "Manifest failed")
        process = child = None
        with socket.socket() as listener, (root / "service.log").open("wb") as log:
            listener.bind(("127.0.0.1", 0))
            listener.listen(128)
            try:
                if not existing_config:
                    process = subprocess.Popen([str(service), "--config", str(config),
                        "--run", "--session-file", str(marker)], stdout=log, stderr=log, **flags)

                def ready():
                    require(process is None or process.poll() is None, "Service exited during startup")
                    result = service_command("--status")
                    return json.loads(result.stdout) if result.returncode == 0 else None

                status = wait_for(ready, "Service unavailable", timeout=40)
                require(process is None or status["service_pid"] == process.pid, "Wrong service")
                report["observed_service_pid"] = status["service_pid"]
                report["observed_service_version"] = status["service_version"]
                require(status["file_visibility"] and "windows-etw" in status["collectors"],
                        "Native file visibility unavailable; run elevated")
                require(existing_config or status["download_activity_available"], "Updated activity API unavailable")
                require(status["download_pause_enabled"], "Download pause is not active")
                report["initial_sensor_health"] = {key: status[key] for key in
                    ("collection_failures", "collection_dropped", "collection_kernel_lost", "file_visibility")}
                env = dict(os.environ, WHOHACK_SAMPLE_ROOT=str(root),
                           WHOHACK_SAMPLE_PORT=str(listener.getsockname()[1]))
                before_birth = int(time.time() * 1000)
                child = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), "--reader"],
                                         env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, **flags)
                after_birth = int(time.time() * 1000)
                report["reader_pid"] = child.pid
                wait_for(lambda: (root / "reader-ready").exists(), "Reader did not start")
                time.sleep(1)
                # Hard size cap; never fetch an executable or follow a local URL.
                with urllib.request.urlopen(URL, timeout=20) as response:
                    require(response.geturl().startswith("https://raw.githubusercontent.com/"), "Unexpected download host")
                    data = response.read(65_537)
                require(44 < len(data) <= 65_536 and data[:4] == b"RIFF" and data[8:12] == b"WAVE",
                        "Unexpected WAV download")
                sample = root / "Downloads/sample.wav"
                sample.write_bytes(data)
                Path(str(sample) + ":Zone.Identifier").write_text(
                    "[ZoneTransfer]\nZoneId=3\nHostUrl=" + URL + "\n", encoding="ascii")
                report["download_bytes"] = len(data)
                report["download_sha256"] = hashlib.sha256(data).hexdigest()
                report["origin_note"] = "HTTPS download; test harness writes the usual Internet Zone.Identifier"
                started = time.monotonic()
                (root / "download-ready").touch()
                wait_for(lambda: (root / "reader-result.json").exists(), "Playback did not complete")
                report["playback"] = json.loads((root / "reader-result.json").read_text())

                def captured():
                    if child.poll() is not None:
                        raise RuntimeError("Reader exited: " + child.stderr.read().decode(errors="replace"))
                    if not status["download_activity_available"]:
                        # The Popen child is still alive, so its PID cannot be
                        # reused. Match parent, image and the unique sample path
                        # + digest below. ETW timestamps on a long-running
                        # service may differ from the current wall clock.
                        # Export no other apps' records.
                        db_file = data_dir / existing["paths"].get("db_file", "vigil.db")
                        with sqlite3.connect(db_file.as_uri() + "?mode=ro", uri=True) as db:
                            found = db.execute(
                                "SELECT start_time, downloaded_inputs, exe_path FROM processes "
                                "WHERE pid=? AND ppid=? AND exit_time IS NULL ORDER BY start_time DESC LIMIT 1",
                                (child.pid, os.getpid())).fetchone()
                        if not found:
                            report["legacy_attribution_diagnostics"] = {"owned_process_recorded": False}
                            return None
                        inputs = json.loads(found[1])
                        require(os.path.normcase(found[2]) == os.path.normcase(sys.executable),
                                "Recorded process image differs from our live child")
                        report["legacy_attribution_diagnostics"] = {
                            "owned_process_recorded": True,
                            "input_slots_used": len(inputs),
                            "inherited_input_count": sum(f["observed_at"] < found[0] for f in inputs),
                            "sensor_start_ms": found[0],
                            "spawn_wall_clock_ms": [before_birth, after_birth],
                        }
                        found_input = next((f for f in inputs if f["file"]["path"].lower() == str(sample).lower()
                            and f["read_observed"]), None)
                        if not found_input:
                            return None
                        require(found_input["file"]["sha256"] == report["download_sha256"], "Wrong observed file bytes")
                        return {"pid": child.pid, "start_time": found[0], "app": found[2],
                                "files": inputs, "events": [],
                                "note": "Read-only legacy store observation; live config excludes loopback; no network assertion"}
                    rows = ipc("list_downloads", limit=20)
                    require(rows["kind"] == "downloads", "Activity request failed")
                    return next((row for row in rows["downloads"] if row["pid"] == child.pid
                        and any(f["path"].lower() == str(sample).lower() and f["evidence"] == "observed_read"
                                for f in row["files"])
                        and any(e["kind"] == "net_connect" and "127.0.0.1:" in e["detail"]
                                for e in row["events"])), None)

                row = wait_for(captured, "Downloaded sample was not associated with its reader"
                               + (" and loopback connection" if status["download_activity_available"] else ""), timeout=25)
                report["observation_latency_ms"] = round((time.monotonic() - started) * 1000, 1)
                report["reader_pid"] = child.pid
                report["activity"] = row
                wait_for(lambda: (root / "reader-result.json").exists(), "Playback did not complete")
                report["playback"] = json.loads((root / "reader-result.json").read_text())
                require(not any(a["pid"] == child.pid for a in ipc("list_alerts", limit=200)["alerts"]),
                        "Benign reader produced an alert")
                require(not any(a["pid"] == child.pid for a in ipc("list_responses")["actions"]),
                        "Benign reader was acted upon")
                report["checks"] = ["HTTPS WAV downloaded", "already-running reader decoded valid PCM",
                    "Windows playback completed", "native file read without a launch argument",
                    "no alert or intervention on benign sample"]
                if status["download_activity_available"]:
                    report["checks"].append("same-process loopback network attribution via new activity API")
                final_status = ipc("status")["status"]
                report["final_sensor_health"] = {key: final_status[key] for key in
                    ("collection_failures", "collection_dropped", "collection_kernel_lost", "collection_unattributed")}
            finally:
                (root / "reader-stop").touch()
                if child:
                    try: child.wait(timeout=5)
                    except subprocess.TimeoutExpired: child.kill(); child.wait(timeout=5)
                    child.stderr.close()
                marker.unlink(missing_ok=True)
                if process:
                    try: process.wait(timeout=20)
                    except subprocess.TimeoutExpired: process.kill(); process.wait(timeout=5)


def main():
    if "--reader" in sys.argv:
        reader()
        return
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--service", type=Path, default=ROOT / "target/release/whohack-service.exe")
    parser.add_argument("--report", type=Path, default=ROOT / ".vigil/checks/m15-download-sample.json")
    parser.add_argument("--existing-config", type=Path, help="Observe an existing service read-only; never restart or reconfigure it")
    args = parser.parse_args()
    report = {"started_utc": datetime.now(timezone.utc).isoformat(), "success": False}
    try:
        exercise(args.service.resolve(), report, args.existing_config)
        report["success"] = True
        print("PASS: downloaded WAV, native read, Windows playback and clean behavior; see report for network scope")
    except Exception as error:
        report["error"] = str(error)
        raise
    finally:
        report["finished_utc"] = datetime.now(timezone.utc).isoformat()
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
