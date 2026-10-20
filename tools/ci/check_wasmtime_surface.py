"""Fail when feature changes invalidate the reviewed YARA-X advisory exceptions."""

import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]
metadata = json.loads(subprocess.check_output(
    ["cargo", "metadata", "--format-version", "1", "--locked", "--all-features"], cwd=ROOT))
packages = {p["id"]: p for p in metadata["packages"]}
checked = []
for node in metadata["resolve"]["nodes"]:
    package = packages[node["id"]]
    if package["name"] != "wasmtime":
        continue
    features = set(node["features"])
    forbidden = {f for f in features if f in {"async", "component-model", "gc", "gc-drc", "gc-null"}
                 or f.startswith("component-model-")}
    if forbidden:
        raise SystemExit(f"Wasmtime advisory assumptions changed; review enabled features: {sorted(forbidden)}")
    checked.append({"version": package["version"], "features": sorted(features)})
if not checked:
    raise SystemExit("No Wasmtime dependency found; remove or review the obsolete advisory exceptions")
print(json.dumps({"reviewed_surface": "synchronous core WASM; no GC/component model", "wasmtime": checked}, indent=2))
