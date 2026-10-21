"""Real Windows sensor/alert/IPC/suspend acceptance using only owned helpers.

The fixture is the whohack_respond Rust test executable, built with cargo test
--no-run. No database rows or service responses are fabricated. A temporary rule
intentionally recognizes a harmless process; this is not a malware efficacy test.
"""

from __future__ import annotations

import argparse
from contextlib import closing
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import socket
import struct
import subprocess
import sys
import tempfile
import time
import uuid

from launch import binary


RULE_DESCRIPTION = "Owned harmless production acceptance fixture"
RULE = f"""- id: owned-acceptance-fixture
  description: {RULE_DESCRIPTION}
  severity: high
  action_floor: block_network
  match:
    tags: ["exec:child_from_downloads_or_temp"]
    path_class: [temp]
"""


def require(condition, message):
    # Keep all ownership checks active even if Python is invoked with -O.
    if not condition:
        raise RuntimeError(message)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def ipc_child(endpoint, token_path, request):
    """One bounded-by-parent client; never put the token on the command line."""
    def read_exact(pipe, length):
        chunks = bytearray()
        while len(chunks) < length:
            chunk = pipe.read(length - len(chunks))
            require(chunk, "IPC closed before the complete frame")
            chunks.extend(chunk)
        return chunks

    def receive(pipe):
        length, = struct.unpack(">I", read_exact(pipe, 4))
        require(length <= 1_048_576, "IPC frame exceeds one MiB")
        return json.loads(read_exact(pipe, length))

    def send(pipe, value):
        body = json.dumps(value).encode("utf-8")
        require(len(body) <= 1_048_576, "IPC request exceeds one MiB")
        data = memoryview(struct.pack(">I", len(body)) + body)
        while data:
            written = pipe.write(data)
            require(written, "IPC closed while writing")
            data = data[written:]

    with open(endpoint, "r+b", buffering=0) as pipe:
        send(pipe, {"type": "hello", "version": 1,
                    "token": Path(token_path).read_text(encoding="ascii").strip()})
        welcome = receive(pipe)
        require(welcome.get("type") == "welcome", "IPC authentication refused")
        require(welcome.get("version") == 1, "Unexpected IPC protocol version")
        send(pipe, {"type": "request", "id": 1, "request": json.loads(request)})
        reply = receive(pipe)
        require(reply.get("type") == "response" and reply.get("id") == 1,
                "Unexpected IPC reply")
        print(json.dumps(reply["response"]))


def wait_for(predicate, message, timeout=20):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(0.1)
    raise RuntimeError(message)


def exercise(service, fixture, report, automatic_download=False, input_extension="mp4", native_reads=False, network_danger=False):
    report.update(service_sha256=digest(service), fixture_sha256=digest(fixture))
    require(b"WHOHACK_TEST_HEARTBEAT" in fixture.read_bytes(),
            "This helper predates the whohack rename. Use a current whohack_respond test executable.")
    with tempfile.TemporaryDirectory(prefix="whohack detection acceptance ") as directory:
        root = Path(directory)
        config, marker = root / "config.toml", root / "session"
        endpoint = r"\\.\pipe\whohack-detection-" + uuid.uuid4().hex
        marker.write_text(uuid.uuid4().hex, encoding="ascii")
        signature = "WHOHACK_HARMLESS_DOWNLOAD_ACCEPTANCE_" + uuid.uuid4().hex
        (root / "rules/tier0").mkdir(parents=True)
        network_listener = None
        if network_danger:
            # An isolated reputation fixture: no external destination is contacted.
            network_listener = socket.socket()
            network_listener.bind(("127.77.83.91", 0))
            network_listener.listen(64)
            (root / "rules/tier0/owned.yaml").write_text('''- id: owned-network-fixture
  description: "Owned harmless threat destination fixture"
  severity: critical
  action_floor: block_network
  match:
    tags: ["network:intel_hit"]
    tainted: true
    path_class: [temp]
''', encoding="utf-8")
            (root / "data").mkdir()
            now = int(time.time() * 1000)
            (root / "data/intel.json").write_text(json.dumps({"version": 1, "fetched_at": now,
                "indicators": [{"value": "127.77.83.91/32", "source": "owned-test", "expires_at": now + 60000}]}), encoding="utf-8")
        elif automatic_download:
            (root / "rules/yara").mkdir()
            (root / "rules/yara/owned.yar").write_text(
                'rule whohack_owned_download_marker { strings: $a = "' + signature + '" condition: $a }', encoding="utf-8")
        else:
            (root / "rules/tier0/owned.yaml").write_text(RULE, encoding="utf-8")
        (root / "Downloads").mkdir()
        target_input = root / "Downloads" / ("downloaded-fixture." + input_extension)
        control_input = root / "Downloads" / ("clean-fixture." + input_extension)
        if automatic_download:
            for path, body in [(target_input, signature.encode("ascii")),
                               (control_input, b"Ordinary harmless downloaded content")]:
                path.write_bytes(body)
                Path(str(path) + ":Zone.Identifier").write_text(
                    "[ZoneTransfer]\nZoneId=3\nHostUrl=https://example.invalid/owned-fixture\n", encoding="ascii")
            report["fixture_content_sha256"] = digest(target_input)
            report["input_extension"] = input_extension
        config.write_text('\n'.join([
            'mode = "prompt"', '[response]', 'enabled = true', 'automatic = false',
            'pause_downloads = ' + str(automatic_download).lower(),
            '[paths]', 'data_dir = "data"', 'log_dir = "logs"', 'rules_dir = "rules"',
            '[collect]', 'backend = ' + ('"native"' if native_reads else '"poll"'), 'poll_interval_ms = 100',
            'include_loopback = true', 'dns = false', '[ipc]',
            'endpoint = ' + json.dumps(endpoint), '',
        ]), encoding="utf-8")
        owned_exe = root / "whohack-owned-response-test.exe"
        shutil.copyfile(fixture, owned_exe)
        expected_hash = digest(owned_exe)
        require(expected_hash == report["fixture_sha256"], "Fixture copy changed")

        def command(*args):
            return subprocess.run(
                [str(service), "--config", str(config), *args],
                capture_output=True, text=True, encoding="utf-8", errors="replace",
                timeout=15, creationflags=subprocess.CREATE_NO_WINDOW)

        def ipc(op, **fields):
            # A separate client makes a stalled named-pipe read safely timeout.
            result = subprocess.run(
                [sys.executable, str(Path(__file__).resolve()), "--ipc", endpoint,
                 str(root / "data/ipc.token"), json.dumps({"op": op, **fields})],
                capture_output=True, text=True, encoding="utf-8", errors="replace",
                timeout=8, creationflags=subprocess.CREATE_NO_WINDOW)
            require(result.returncode == 0, "IPC client failed: " + result.stderr)
            return json.loads(result.stdout)

        def rows(sql, params=()):
            uri = (root / "data/vigil.db").as_uri() + "?mode=ro"
            with closing(sqlite3.connect(uri, uri=True, timeout=3)) as db:
                return db.execute(sql, params).fetchall()

        def spawn_heartbeat(name, input_path=None):
            env = dict(os.environ)
            # Do not inherit the optional network behavior of another test.
            for key in ("WHOHACK_TEST_ADDRESS", "WHOHACK_TEST_LISTENERS", "WHOHACK_TEST_INPUT", "WHOHACK_TEST_PERSISTENT_CONNECTION"):
                env.pop(key, None)
            env["WHOHACK_TEST_HEARTBEAT"] = str(root / name)
            if network_listener and name == "target-heartbeat":
                host, port = network_listener.getsockname()
                env["WHOHACK_TEST_ADDRESS"] = f"{host}:{port}"
                env["WHOHACK_TEST_PERSISTENT_CONNECTION"] = "1"
            args = [str(owned_exe), "--exact", "windows::process::tests::owned_helper",
                    "--ignored", "--nocapture"]
            if input_path:
                env["WHOHACK_TEST_INPUT"] = str(input_path)
                # libtest accepts --skip operands; expose the same local file in
                # the launch command while the owned reader really opens it.
                if not native_reads:
                    args.extend(["--skip", str(input_path)])
            return subprocess.Popen(
                args, env=env, stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                creationflags=subprocess.CREATE_NO_WINDOW)

        checked = command("--check-config")
        require(checked.returncode == 0, "Configuration failed: " + checked.stderr)
        manifest = command("--write-manifest")
        require(manifest.returncode == 0, "Manifest failed: " + manifest.stderr)
        owned_children = []
        service_process = None
        with (root / "service.log").open("wb") as output:
            try:
                service_process = subprocess.Popen(
                    [str(service), "--config", str(config), "--run", "--session-file", str(marker)],
                    stdin=subprocess.DEVNULL, stdout=output, stderr=output,
                    creationflags=subprocess.CREATE_NO_WINDOW)

                def ready():
                    require(service_process.poll() is None, "Owned service exited during startup")
                    result = command("--status")
                    return json.loads(result.stdout) if result.returncode == 0 else None

                status = wait_for(ready, "Owned service did not become ready", timeout=40)
                require(status["service_pid"] == service_process.pid, "Wrong service instance")
                require(status["mode"] == "prompt" and status["enforcement_available"],
                        "Manual response is unavailable")
                require(not status["automatic_response_enabled"], "Automatic response was enabled")
                require(status.get("download_pause_enabled", False) == automatic_download,
                        "Wrong independent download-pause status")
                require(not status["integrity_issues"], "Initial integrity verification failed")
                require(ipc("set_mode", mode="auto")["kind"] == "error", "Auto was not refused")
                require(ipc("status")["status"]["mode"] == "prompt", "Rejected Auto changed mode")
                report["checks"].append("authenticated owned service; automatic response refused")

                before_birth = int(time.time() * 1000)
                started = time.monotonic()
                target = spawn_heartbeat("target-heartbeat", target_input if automatic_download else None)
                owned_children.append(target)
                after_birth = int(time.time() * 1000)
                control = spawn_heartbeat("control-heartbeat", control_input if automatic_download else None)
                owned_children.append(control)
                target_beat, control_beat = root / "target-heartbeat", root / "control-heartbeat"
                wait_for(lambda: control_beat.exists() and (automatic_download or target_beat.exists()), "No helper heartbeats")
                def target_size():
                    return target_beat.stat().st_size if target_beat.exists() else 0

                def matching_alert():
                    require(target.poll() is None, "Owned target exited before detection")
                    reply = ipc("list_alerts", limit=1000)
                    require(reply["kind"] == "alerts", "Could not list real alerts")
                    evidence = ("Owned harmless threat destination fixture" if network_danger else
                                "whohack_owned_download_marker" if automatic_download else RULE_DESCRIPTION)
                    found = min((a for a in reply["alerts"] if a["pid"] == target.pid
                                 and evidence
                                 in a["explanation"] and not a["resolved"]), key=lambda a: a["id"], default=None)
                    # ListAlerts can observe insertion before the native action
                    # completes; wait for its recorded outcome, as the push does.
                    if automatic_download and found and found["action"] != "suspend_and_ask" \
                            and "Response failed:" not in found["explanation"]:
                        return None
                    return found

                alert = wait_for(matching_alert, "Real sensor did not produce the fixture alert", timeout=40)
                report["owned_alert_outcome"] = {"action": alert["action"], "explanation": alert["explanation"]}
                report["observed_alert_latency_ms"] = round((time.monotonic() - started) * 1000, 1)
                captured_rows = rows("SELECT target FROM alerts WHERE id=?", (alert["id"],))
                require(len(captured_rows) == 1, "Alert identity was not persisted")
                captured = json.loads(captured_rows[0][0])
                require(captured["pid"] == target.pid and captured["ppid"] == os.getpid(),
                        "Captured process is not our child")
                require(before_birth <= captured["start_time"] <= after_birth,
                        "Captured process birth time does not match our child")
                require(Path(captured["exe"]["path"]).resolve() == owned_exe.resolve(),
                        "Captured executable is not our fixture")
                require(captured["exe"]["sha256"] == expected_hash,
                        "Captured executable hash mismatch")
                require(captured["script"] is None, "Unexpected interpreter target")
                require(target.poll() is None, "Owned target already exited")
                report["checks"].append("real process sensor -> temporary rule -> durable alert and exact target identity")
                if automatic_download:
                    inputs = captured["downloaded_inputs"]
                    require(len(inputs) == 1 and Path(inputs[0]["file"]["path"]).resolve() == target_input.resolve(),
                            "Wrong downloaded data association")
                    require(inputs[0]["file"]["sha256"] == report["fixture_content_sha256"] and captured["tainted"],
                            "Download hash/origin missing")
                    require(inputs[0]["read_observed"] == native_reads, "Wrong launch/read attribution evidence")
                    if status.get("download_activity_available"):
                        activity = ipc("list_downloads", limit=20)
                        require(activity["kind"] == "downloads", "Download activity API failed")
                        row = next((r for r in activity["downloads"]
                                    if r["pid"] == target.pid and r["start_time"] == captured["start_time"]), None)
                        require(row and any(Path(f["path"]).resolve() == target_input.resolve()
                                            and f["evidence"] == ("observed_read" if native_reads else "launch_argument")
                                            for f in row["files"]), "Activity view lost the exact input association")
                        report["checks"].append("authenticated download activity exposes the owned file and attribution evidence")
                    require(alert["action"] == "suspend_and_ask", "Qualified download evidence did not automatically pause")
                    require(not any(a["pid"] == control.pid for a in ipc("list_alerts", limit=1000)["alerts"]),
                            "Clean downloaded content generated an alert")
                else:
                    require(not ipc("list_responses")["actions"], "An unsolicited response occurred")
                    reply = ipc("resolve", alert_id=alert["id"], action="suspend_and_ask",
                                note="Owned harmless acceptance fixture")
                    require(reply["kind"] == "ok", "Suspend failed: " + json.dumps(reply))
                time.sleep(0.15)
                frozen, control_before = target_size(), control_beat.stat().st_size
                time.sleep(0.6)
                require(target.poll() is None and target_size() == frozen,
                        "Target did not remain suspended")
                require(control.poll() is None and control_beat.stat().st_size > control_before,
                        "Independent control process stopped")
                actions = ipc("list_responses")["actions"]
                require(len(actions) == 1, "Unexpected response count")
                action = actions[0]
                require(action["pid"] == target.pid and action["alert_id"] == alert["id"]
                        and action["action"] == "suspend_and_ask" and action["status"] == "active",
                        "Response journal does not match the owned suspended target")
                report["checks"].append(("automatic download pause" if automatic_download else "manual IPC suspend")
                                        + " stops target heartbeat; clean control continues")
                require(ipc("release_response", id=action["id"])["kind"] == "ok", "Resume failed")
                wait_for(lambda: target_size() > frozen, "Target heartbeat did not resume")
                require(ipc("release_response", id=action["id"])["kind"] == "ok", "Repeat release failed")
                require(ipc("list_responses")["actions"][0]["status"] == "released", "Release not recorded")
                report["checks"].append("native resume and idempotent release")

                final_action = "suspend_and_ask"
                if network_danger:
                    reply = ipc("resolve", alert_id=alert["id"], action="kill_and_quarantine",
                                note="Must refuse to remove an unidentified input or shared viewer")
                    require(reply["kind"] == "error" and target.poll() is None
                            and target_input.exists() and digest(owned_exe) == expected_hash,
                            "Behavior-only evidence removed an unidentified input or shared viewer")
                    require(ipc("resolve", alert_id=alert["id"], action="allow")["kind"] == "ok", "Allow failed")
                    final_action = "allow"
                    report["checks"].append("real localhost TCP -> local threat snapshot -> automatic pause; ambiguous removal refused")
                elif automatic_download:
                    reply = ipc("resolve", alert_id=alert["id"], action="kill_and_quarantine",
                                note="Owned harmless file removal acceptance")
                    require(reply["kind"] == "ok", "Input quarantine failed: " + json.dumps(reply))
                    target.wait(timeout=10)
                    require(not target_input.exists() and digest(owned_exe) == expected_hash,
                            "Wrong file removed or input was not quarantined")
                    require(control.poll() is None, "Shared viewer control was terminated")
                    quarantines = ipc("list_responses")["quarantine"]
                    require(len(quarantines) == 1 and Path(quarantines[0]["original_path"]).resolve() == target_input.resolve(),
                            "Quarantine does not identify the downloaded input")
                    require(ipc("restore_quarantine", id=quarantines[0]["id"])["kind"] == "ok", "Restore failed")
                    require(target_input.exists(), "Restore did not recreate the input")
                    final_action = "kill_and_quarantine"

                marker.unlink()
                require(service_process.wait(timeout=20) == 0, "Graceful service shutdown failed")
                if automatic_download and not network_danger:
                    # Read restored bytes after stopping the isolated sensor:
                    # otherwise our verifier itself opens the matched input and
                    # correctly becomes another pause target in the native test.
                    require(digest(target_input) == report["fixture_content_sha256"], "Restored data changed")
                    report["checks"].append("stop and quarantine only identified input; shared reader/control preserved; exact bytes restored")
                log = (root / "service.log").read_text(encoding="utf-8")
                counts = re.search(r"whohack service stopped published=(\d+) stored=(\d+)", log)
                require(counts and counts[1] == counts[2] and int(counts[1]) > 0, "Event flush incomplete")
                report["events_flushed"] = int(counts[1])
                require(rows("PRAGMA integrity_check") == [("ok",)], "SQLite integrity check failed")
                require(rows("SELECT status, action FROM alerts WHERE id=?", (alert["id"],))
                        == [("resolved", final_action)], "Alert resolution not durable")
                require(rows("SELECT user_action FROM feedback WHERE alert_id=?", (alert["id"],))
                        == [(final_action,)], "Feedback not durably recorded exactly once")
                records = json.loads((root / "data/responses.json").read_text(encoding="utf-8"))
                report["response_outcomes"] = [
                    {"owned_target": r["target"]["pid"] == target.pid,
                     "alert_id": r["alert_id"], "action": r["action"],
                     "status": r["status"], "detail": r["detail"]} for r in records]
                require(len(records) == (2 if automatic_download and not network_danger else 1) and records[0]["status"] == "released",
                        "Response journal not durable")
                if automatic_download and not network_danger:
                    require(records[1]["status"] == "completed", "Quarantine response not durable")
                report["checks"].append("clean shutdown, complete event flush, SQLite integrity and durable feedback/release")
            except Exception:
                # Keep diagnostics limited to the children of this test. Never
                # copy unrelated host events or authentication tokens to reports.
                report["owned_process_diagnostics"] = []
                for child in owned_children:
                    report["owned_process_diagnostics"].append({
                        "pid": child.pid, "exit_code": child.poll(),
                        "identity": rows("SELECT pid, ppid, start_time, path_class, exe_sha256 FROM processes WHERE pid=?", (child.pid,)),
                        "events": rows("SELECT kind, tags FROM events WHERE pid=?", (child.pid,)),
                        "alerts": rows("SELECT id, status, action, reasons FROM alerts WHERE pid=?", (child.pid,)),
                    })
                raise
            finally:
                # Graceful shutdown releases a suspension even after an assertion.
                # Fallback termination uses only exact Popen handles we created.
                marker.unlink(missing_ok=True)
                if service_process is not None:
                    try:
                        service_process.wait(timeout=20)
                    except subprocess.TimeoutExpired:
                        service_process.kill()
                        service_process.wait(timeout=10)
                for child in owned_children:
                    if child.poll() is None:
                        child.kill()
                    child.wait(timeout=10)
                if network_listener:
                    network_listener.close()


def main():
    require(sys.platform == "win32", "This acceptance test must run on Windows")
    if len(sys.argv) > 1 and sys.argv[1] == "--ipc":
        ipc_child(*sys.argv[2:])
        return
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture", type=Path, required=True, help="whohack_respond native Rust test executable")
    parser.add_argument("--service", type=Path, default=binary("whohack-service"))
    parser.add_argument("--report", type=Path)
    parser.add_argument("--automatic-download", action="store_true")
    parser.add_argument("--input-extension", choices=["mp4", "wav", "pdf"], default="mp4")
    parser.add_argument("--native-reads", action="store_true", help="Requires elevation; prove file reads without a command-line input")
    parser.add_argument("--network-danger", action="store_true", help="Harmless loopback TCP destination in an isolated local threat snapshot")
    args = parser.parse_args()
    report = {"started_utc": datetime.now(timezone.utc).isoformat(), "success": False, "checks": []}
    try:
        require(not args.native_reads or args.automatic_download, "--native-reads requires --automatic-download")
        require(not args.network_danger or args.automatic_download, "--network-danger requires --automatic-download")
        exercise(args.service.resolve(), args.fixture.resolve(), report, args.automatic_download, args.input_extension, args.native_reads, args.network_danger)
        report["success"] = True
        print("PASS: real Windows detection, " + ("automatic network-threat pause" if args.network_danger else "automatic download pause and input quarantine/restore" if args.automatic_download else "manual suspend/resume")
              + ", unaffected control and durable feedback.")
    except Exception as error:
        report["error"] = str(error)
        raise
    finally:
        report["finished_utc"] = datetime.now(timezone.utc).isoformat()
        if args.report:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
