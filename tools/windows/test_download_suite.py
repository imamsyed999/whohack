"""Run owned native download acceptance sequentially under one Windows elevation."""
import ctypes
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]


def main():
    if sys.platform != "win32" or not ctypes.windll.shell32.IsUserAnAdmin():
        raise SystemExit("This focused native file-sensor suite requires Windows administrator consent.")
    output = ROOT / ".vigil/checks/m15-downloads"
    output.mkdir(parents=True, exist_ok=True)
    fixture = ROOT / ".vigil/checks/fixtures/whohack-owned-process.exe"
    tasks = [
        ("sample", ["test_download_sample.py"]),
        ("native-pause", ["test_detection.py", "--automatic-download", "--native-reads", "--input-extension", "wav"]),
        ("network-pause", ["test_detection.py", "--automatic-download", "--native-reads", "--network-danger"]),
    ]
    results = {"started_utc": datetime.now(timezone.utc).isoformat(), "checks": [], "success": False}
    for name, arguments in tasks:
        command = [sys.executable, str(ROOT / "tools/windows" / arguments[0]), *arguments[1:],
                   "--report", str(output / f"{name}.json")]
        if arguments[0] == "test_detection.py":
            command += ["--fixture", str(fixture)]
        try:
            result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True,
                                    encoding="utf-8", errors="replace", timeout=170,
                                    creationflags=subprocess.CREATE_NO_WINDOW)
            (output / f"{name}.log").write_text(result.stdout + result.stderr, encoding="utf-8")
            results["checks"].append({"name": name, "exit_code": result.returncode})
        except Exception as error:
            results["checks"].append({"name": name, "error": str(error)})
        (output / "suite.json").write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
    results["success"] = all(c.get("exit_code") == 0 for c in results["checks"])
    results["finished_utc"] = datetime.now(timezone.utc).isoformat()
    (output / "suite.json").write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
    raise SystemExit(0 if results["success"] else 1)


if __name__ == "__main__":
    main()
