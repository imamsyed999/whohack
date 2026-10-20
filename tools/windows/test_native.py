"""Run all cross-built Rust test executables on Windows, with native fixture paths.

Build first with: wsl -d Ubuntu -- python3 tools/windows/cross-build.py test-build --workspace
Privileged and helper-only tests remain ignored; run those explicitly and separately.
"""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
SUMMARY = re.compile(r"test result: (?:ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored;")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts", type=Path, default=ROOT / ".vigil/checks/native-tests/artifacts.json")
    parser.add_argument("--report", type=Path, default=ROOT / ".vigil/checks/native-tests/results.json")
    args = parser.parse_args()
    if sys.platform != "win32":
        parser.error("Native Windows execution is required")
    artifacts = json.loads(args.artifacts.read_text(encoding="utf-8-sig"))
    if not artifacts:
        parser.error("No test artifacts; build the workspace tests first")
    service = args.artifacts.resolve().parent / "whohack-service.exe"
    if not service.is_file():
        parser.error("The service integration-test executable is missing; rebuild with --workspace")
    env = dict(os.environ, WHOHACK_TEST_ROOT=str(ROOT), WHOHACK_TEST_SERVICE=str(service))
    report = {"tested_utc": datetime.now(timezone.utc).isoformat(), "platform": sys.platform,
              "passed": 0, "failed": 0, "ignored": 0, "executables": []}
    args.report.parent.mkdir(parents=True, exist_ok=True)
    for artifact in artifacts:
        path = (ROOT / artifact["path"]).resolve()
        if not path.is_relative_to(args.artifacts.resolve().parent) or path.suffix != ".exe":
            parser.error(f"Test artifact is outside its staging directory: {path.name}")
        print(f"Running {artifact['name']}", flush=True)
        item = {"name": artifact["name"], "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
        try:
            result = subprocess.run([str(path), "--test-threads=2"], cwd=ROOT, env=env,
                                    capture_output=True, text=True, encoding="utf-8", errors="replace",
                                    creationflags=subprocess.CREATE_NO_WINDOW, timeout=180)
            output = result.stdout + result.stderr
            item["exit_code"] = result.returncode
            matches = list(SUMMARY.finditer(output))
            if not matches:
                item["error"] = "Rust test summary is missing"
            for match in matches:
                for key, value in zip(("passed", "failed", "ignored"), match.groups()):
                    report[key] += int(value)
        except subprocess.TimeoutExpired as error:
            output = (error.stdout or b"") + (error.stderr or b"")
            if isinstance(output, bytes):
                output = output.decode("utf-8", errors="replace")
            item.update(exit_code=None, error="Test executable exceeded 180 seconds")
        except OSError as error:
            output = str(error)
            item.update(exit_code=None, error=str(error))
        log = args.report.parent / f"{path.stem}.log"
        log.write_text(output, encoding="utf-8", newline="\n")
        item["log"] = str(log.relative_to(ROOT)) if log.is_relative_to(ROOT) else str(log)
        report["executables"].append(item)
        if item.get("error") or item["exit_code"] != 0:
            print(output[-6000:], flush=True)
        args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8", newline="\n")
    report["success"] = all(x["exit_code"] == 0 and not x.get("error") for x in report["executables"])
    args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps({key: report[key] for key in ("passed", "failed", "ignored", "success")}))
    raise SystemExit(0 if report["success"] else 1)


if __name__ == "__main__":
    main()
