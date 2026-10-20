"""Shared dataset validation. This module makes no network calls."""
import hashlib
import json
import math
import re
from pathlib import Path

CONTRACT = json.loads((Path(__file__).parent / 'contracts/v1.json').read_text(encoding='utf-8'))
LABELS = {q['id']: q.get('options', ['yes', 'no']) for q in CONTRACT['questions']}


def read_jsonl(path):
    rows = []
    with Path(path).open("rb") as file:
        while line := file.readline(1_048_577):
            if len(line) > 1_048_576:
                raise ValueError("JSONL line exceeds 1 MiB")
            if line.strip():
                rows.append(json.loads(line))
            if len(rows) > 1_000_000:
                raise ValueError("dataset exceeds one million cases")
    return rows


def write_jsonl(path, rows):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as file:
        for row in rows:
            file.write(json.dumps(row, ensure_ascii=False, allow_nan=False) + "\n")


def sha256(path):
    with Path(path).open("rb") as file:
        return hashlib.file_digest(file, "sha256").hexdigest()


def split_family(family):
    bucket = int(hashlib.sha256(("whohack-family-v1:" + family).encode()).hexdigest()[:8], 16) % 100
    return "train" if bucket < 70 else "val" if bucket < 85 else "test"


def validate(rows, require_labels=True):
    ids, partitions, state_splits = set(), {}, {}
    for row in rows:
        if row.get("schema_version") != 1 or not isinstance(row.get("synthetic"), bool):
            raise ValueError("dataset requires version and explicit synthetic provenance")
        if not all(isinstance(row.get(k), str) and row[k].strip() for k in ["id", "state", "source", "family", "app_sha256"]):
            raise ValueError("missing dataset identity, state or provenance")
        if row["id"] in ids:
            raise ValueError("duplicate case id")
        ids.add(row["id"])
        if not re.fullmatch(r'[0-9a-fA-F]{64}', row['app_sha256']):
            raise ValueError('invalid application SHA-256 identity')
        split = row.get("split")
        if split not in {"train", "val", "test"}:
            raise ValueError("invalid split")
        for key in ["family:" + row["family"], "app:" + row["app_sha256"].lower()]:
            if key in partitions and partitions[key] != split:
                raise ValueError("family/app leakage across dataset splits")
            partitions[key] = split
        state_hash = hashlib.sha256(row["state"].encode()).hexdigest()
        if state_hash in state_splits and state_splits[state_hash] != split:
            raise ValueError("duplicate state leakage across dataset splits")
        state_splits[state_hash] = split
        if len(row["state"]) > 16_384 or len(row.get("feature_vector", [])) != 17:
            raise ValueError("invalid state/feature contract")
        if not all(type(x) in (int, float) and math.isfinite(x) for x in row["feature_vector"]):
            raise ValueError("nonfinite feature")
        if row.get('feature_names') != CONTRACT['features']:
            raise ValueError('feature order differs from the serving contract')
        if row.get("questions") != CONTRACT['questions']:
            raise ValueError("questions differ from the serving contract")
        if require_labels:
            labels = row.get("labels", {})
            if set(labels) != set(LABELS) or any(str(labels[q]) not in opts for q, opts in LABELS.items()):
                raise ValueError("missing or invalid gold labels")
        review = row.get("review", {})
        if not isinstance(review, dict) or not isinstance(review.get('accepted', False), bool):
            raise ValueError('review accepted must be a boolean')
        if review.get("accepted") and not (review.get("reviewer") and review.get("reviewed_at")):
            raise ValueError("human review must identify its reviewer and timestamp")
    return rows


def probabilities(prediction):
    result = {}
    for q, labels in LABELS.items():
        values = prediction.get("probabilities", {}).get(q)
        if not isinstance(values, dict) or set(values) != set(labels):
            raise ValueError(f"missing probability distribution: {q}")
        if not all(isinstance(p, (int, float)) and math.isfinite(p) and 0 <= p <= 1 for p in values.values()):
            raise ValueError("invalid probability")
        if abs(sum(values.values()) - 1) > 0.001:
            raise ValueError("probabilities must sum to one")
        result[q] = values
    return result
