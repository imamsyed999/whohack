"""Build state/feature rows by invoking the same Rust replay used by the service.

Catalog: JSON array with fixture, source, family, category, labels, synthetic;
optional split, event_indices (default last observation), review.
"""
import argparse
import hashlib
import json
import subprocess
from pathlib import Path
from dataset import CONTRACT, read_jsonl, write_jsonl, validate, split_family, sha256


def build(catalog, service, config=None):
    catalog = Path(catalog).resolve()
    entries = json.loads(catalog.read_text(encoding="utf-8"))
    contract = json.loads(subprocess.check_output([str(service), "--model-contract"], text=True, timeout=30))
    if contract != CONTRACT:
        raise ValueError("unsupported model contract")
    rows = []
    for entry in entries:
        fixture = (catalog.parent / entry["fixture"]).resolve(strict=True)
        raw = read_jsonl(fixture)
        command = [str(service), "--replay", str(fixture), "--category", entry["category"]]
        if config:
            command.extend(["--config", str(config)])
        run = subprocess.run(command,
                             check=True, capture_output=True, text=True, timeout=120)
        replay = [json.loads(line) for line in run.stdout.splitlines()]
        if len(replay) != len(raw):
            raise ValueError("replay count differs from fixture")
        for index in entry.get("event_indices", [len(replay) - 1]):
            result, original = replay[index], raw[index]
            process = original.get("process")
            if not result.get("state") or not process:
                raise ValueError("training case needs classified process identity")
            file = process.get("script") or process["exe"]
            identity = f"{sha256(fixture)}:{index}:{entry['category']}"
            config_sha = sha256(Path(config)) if config else None
            if config_sha:
                identity += ':' + config_sha + ':' + hashlib.sha256(result['state'].encode()).hexdigest()
            rows.append(dict(schema_version=1, id=hashlib.sha256(identity.encode()).hexdigest(),
                             state=result["state"], feature_vector=result["feature_vector"],
                             feature_names=contract["features"], questions=contract["questions"],
                             replay_config_sha256=config_sha, scorer=result["scorer"],
                             labels=entry["labels"], source=entry["source"], family=entry["family"],
                             app_sha256=file["sha256"], fixture_sha256=sha256(fixture),
                             split=entry.get("split") or split_family(entry["family"]),
                             synthetic=entry["synthetic"], review=entry.get("review", {"accepted": False})))
    return validate(rows)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("catalog", type=Path)
    p.add_argument("--service", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--config", type=Path, help="explicit replay rules/sensitive paths and pinned Tier 1 configuration")
    a = p.parse_args()
    rows = build(a.catalog, a.service.resolve(strict=True), a.config.resolve(strict=True) if a.config else None)
    write_jsonl(a.output, rows)
    print(f"Wrote {len(rows)} cases; splits: " + str({s: sum(r['split'] == s for r in rows) for s in ['train', 'val', 'test']}))


if __name__ == "__main__":
    main()
