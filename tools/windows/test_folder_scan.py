"""Optional Defender job acceptance using an isolated polling service and benign data.

Never changes the live profile, requests elevation, or enables remediation.
Windows Defender retains its own cloud/sample settings.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import uuid

ROOT = Path(__file__).resolve().parents[2]


def exercise(service: Path) -> dict:
    report = {"service_sha256": hashlib.sha256(service.read_bytes()).hexdigest(),
              "boundary": "isolated Windows polling service; actual report-only Defender job",
              "remediation": False}
    with tempfile.TemporaryDirectory(prefix="whohack-folder-test-") as temporary:
        root = Path(temporary)
        inputs = root / "inputs"
        inputs.mkdir()
        sample = inputs / "ordinary.txt"
        original = b"Owned harmless whohack folder-check acceptance fixture.\n"
        sample.write_bytes(original)
        shutil.copytree(ROOT / "rules", root / "rules")
        endpoint = r"\\.\pipe\whohack-folder-" + uuid.uuid4().hex
        config, session = root / "config.toml", root / "session"
        session.write_text("running")
        config.write_text("\n".join([
            'mode = "monitor"', '[response]', 'enabled = false',
            '[collect]', 'backend = "poll"', '[paths]', 'data_dir = "data"',
            'log_dir = "logs"', 'rules_dir = "rules"', '[ipc]',
            'endpoint = ' + json.dumps(endpoint), '',
        ]), encoding="utf-8")
        flags = {"creationflags": subprocess.CREATE_NO_WINDOW, "cwd": ROOT}
        prepare = subprocess.run([str(service), "--config", str(config), "--write-manifest"],
                                 capture_output=True, text=True, timeout=15, **flags)
        if prepare.returncode:
            raise RuntimeError(prepare.stderr)

        def ipc(op, **fields):
            reply = subprocess.run([
                sys.executable, str(ROOT / "tools/windows/test_detection.py"),
                "--ipc", endpoint, str(root / "data/ipc.token"),
                json.dumps({"op": op, **fields}),
            ], capture_output=True, text=True, timeout=8, **flags)
            if reply.returncode:
                raise RuntimeError(reply.stderr)
            return json.loads(reply.stdout)

        with (root / "service.log").open("wb") as log:
            process = subprocess.Popen([
                str(service), "--config", str(config), "--run",
                "--session-file", str(session),
            ], stdout=log, stderr=log, **flags)
            try:
                for _ in range(100):
                    try:
                        status = ipc("status")
                        break
                    except (OSError, RuntimeError):
                        if process.poll() is not None:
                            raise RuntimeError("Owned service exited during startup")
                        time.sleep(0.1)
                else:
                    raise RuntimeError("Owned service did not become ready")
                report["status"] = status["status"]
                if not status["status"].get("folder_scan_available"):
                    raise RuntimeError("Updated service did not discover installed Defender")
                rejected = ipc("start_folder_scan", path="relative", remediate=False)
                if rejected.get("kind") != "error":
                    raise RuntimeError("Relative folder path was accepted")
                started = ipc("start_folder_scan", path=str(inputs), remediate=False)
                if started.get("kind") != "folder_scan":
                    raise RuntimeError(str(started))
                report["started"] = started
                deadline = time.monotonic() + 60
                while time.monotonic() < deadline:
                    # Monitoring/status must remain responsive while scanning.
                    if ipc("status").get("kind") != "status":
                        raise RuntimeError("Status failed during folder scan")
                    result = ipc("folder_scan_status")
                    if result.get("kind") != "folder_scan":
                        raise RuntimeError(str(result))
                    if result["scan"]["state"] != "running":
                        report["result"] = result
                        break
                    time.sleep(0.2)
                else:
                    ipc("stop_folder_scan", id=started["scan"]["id"])
                    raise RuntimeError("Harmless scan exceeded the acceptance deadline")
                if result["scan"]["state"] != "completed":
                    raise RuntimeError("Defender check failed: " + json.dumps(result["scan"]))
                if sample.read_bytes() != original:
                    raise RuntimeError("Report-only check changed the harmless fixture")
                if result["scan"]["remediate"]:
                    raise RuntimeError("Report-only job unexpectedly permitted remediation")
                report["fixture_preserved"] = True
                report["success"] = True
            finally:
                session.write_text("stop")
                try:
                    process.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    process.terminate()  # only this newly launched service
                    process.wait(timeout=10)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--service", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = exercise(args.service.resolve())
    except Exception as error:
        result = {"success": False, "error": str(error),
                  "service_sha256": hashlib.sha256(args.service.read_bytes()).hexdigest(),
                  "boundary": "isolated report-only acceptance; no live profile change"}
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        raise
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print("PASS: isolated IPC and actual report-only Defender folder check")


if __name__ == "__main__":
    main()
