"""Evaluate held-out cases and produce an explicit pass/fail release report."""
import argparse
import json
import math
import struct
from pathlib import Path
from dataset import CONTRACT, LABELS, read_jsonl, validate, probabilities, sha256


def percentile(values, fraction):
    if not values:
        return None
    values = sorted(values)
    return values[max(0, math.ceil(len(values) * fraction) - 1)]


def f32(n):
    return struct.unpack('f', struct.pack('f', n))[0]


def top_label(labels, distribution):
    # Rust Iterator::max_by selects the last tied option, after f32 parsing.
    return max(enumerate(labels), key=lambda item: (f32(distribution[item[1]]), item[0]))[1]


def evaluate(rows, predictions, benign_replay=None):
    validate(rows)
    index = {p["id"]: p for p in predictions}
    if len(index) != len(predictions):
        raise ValueError("duplicate predictions")
    test = [r for r in rows if r["split"] == "test"]
    if not test or any(r["id"] not in index for r in test):
        raise ValueError("every test case needs a prediction")
    identities = {tuple(index[r['id']].get(k) for k in ['model', 'revision', 'weights_sha256', 'head_sha256', 'calibration_sha256']) for r in test}
    if len(identities) != 1: raise ValueError('evaluation mixes model revisions or calibration')
    policies = {json.dumps(index[r['id']].get('thresholds', CONTRACT['thresholds']), sort_keys=True) for r in test}
    if len(policies) != 1: raise ValueError('evaluation mixes operating thresholds')
    thresholds = json.loads(next(iter(policies)))
    if set(thresholds) != set(CONTRACT['thresholds']) or not all(type(v) in (int, float) and math.isfinite(v) and 0 <= v <= 1 for v in thresholds.values()) or thresholds['malicious'] < thresholds['block_malicious']:
        raise ValueError('invalid evaluation thresholds')
    per_question = {}
    for q, options in LABELS.items():
        bins = [[] for _ in range(10)]
        correct, brier = 0, 0.
        for row in test:
            dist = probabilities(index[row["id"]])[q]
            top = top_label(options, dist)
            hit = int(top == str(row["labels"][q])); correct += hit
            confidence = dist[top]
            bins[min(9, int(confidence * 10))].append((confidence, hit))
            brier += sum((dist[o] - int(o == str(row["labels"][q]))) ** 2 for o in options)
        ece = sum(abs(sum(p for p, _ in b) - sum(y for _, y in b)) for b in bins) / len(test)
        per_question[q] = dict(accuracy=correct / len(test), brier=brier / len(test), ece=ece, cases=len(test))
    malicious = [r for r in test if r["labels"]["verdict"] == "malicious"]
    benign = [r for r in test if r["labels"]["verdict"] == "benign"]
    def block(row):
        answers = probabilities(index[row["id"]]); p = answers['verdict']
        action = top_label(LABELS['action'], answers['action'])
        # Serving stores probabilities and thresholds as f32. Preserve equality
        # at boundaries such as 0.6 instead of comparing f64 artifacts.
        return f32(p["malicious"]) >= f32(thresholds['block_malicious']) or f32(p["suspicious"]) >= f32(thresholds['block_suspicious']) or action in {'block_network', 'kill_and_quarantine'}
    recall = sum(block(r) for r in malicious) / len(malicious) if malicious else None
    fpr = sum(block(r) for r in benign) / len(benign) if benign else None
    latency = [index[r["id"]].get("latency_ms") for r in test]
    memory = [index[r["id"]].get("rss_mb") for r in test]
    valid_measure = lambda xs: all(isinstance(x, (int, float)) and math.isfinite(x) and x > 0 for x in xs)
    latency_ok, memory_ok = valid_measure(latency), valid_measure(memory)
    replay = benign_replay or {}
    hours = replay.get("duration_hours", 0)
    alerts = replay.get("alerts")
    replay_ok = isinstance(hours, (int, float)) and hours >= 168 and isinstance(alerts, int) and alerts >= 0 and replay.get("apps", 0) >= 200 and replay.get("synthetic") is False and bool(replay.get("source"))
    week = alerts * 168 / hours if replay_ok else None
    reviewed = sum(bool(r.get("review", {}).get("accepted")) for r in rows) / len(rows)
    synthetic = any(r["synthetic"] for r in rows) or any(p.get("synthetic") is not False for p in predictions)
    failures = []
    gates = {
        "pinned model and calibration identity": all(index[test[0]['id']].get(k) for k in ['model', 'revision', 'weights_sha256', 'calibration_sha256']),
        "representative non-synthetic data": not synthetic,
        "at least 10% human review": reviewed >= 0.1,
        "held-out malicious families and benign cases": len(malicious) >= 100 and len(benign) >= 200 and len({r['family'] for r in malicious}) >= 5,
        "malicious recall >= 0.90": recall is not None and recall >= 0.9,
        "benign FPR <= 0.01": fpr is not None and fpr <= 0.01,
        "representative benign week <= 1 alert": week is not None and week <= 1,
        "CPU p95 <= 3000 ms": latency_ok and percentile(latency, .95) <= 3000 and all(index[r['id']].get('device') == 'cpu' for r in test),
        "RSS <= 1200 MB": memory_ok and max(memory) <= 1200,
    }
    failures = [name for name, passed in gates.items() if not passed]
    identity = dict(zip(['model_name', 'model_revision', 'weights_sha256', 'head_sha256', 'calibration_sha256'], next(iter(identities))))
    return dict(**identity, schema_version=1, thresholds=thresholds, passed=not failures, failures=failures, family_disjoint=True,
                synthetic=synthetic, cases=len(test), malicious_cases=len(malicious), benign_cases=len(benign),
                malicious_families=len({r['family'] for r in malicious}),
                device='cpu' if all(index[r['id']].get('device') == 'cpu' for r in test) else 'unverified',
                per_question=per_question, malicious_recall=recall, benign_fpr=fpr,
                human_review_fraction=reviewed, alerts_per_week=week,
                cpu_p50_ms=percentile(latency, .5) if latency_ok else None,
                cpu_p95_ms=percentile(latency, .95) if latency_ok else None,
                rss_mb=max(memory) if memory_ok else None, benign_replay=replay)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("dataset", type=Path); p.add_argument("predictions", type=Path)
    p.add_argument("--benign-replay", type=Path); p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    replay = json.loads(a.benign_replay.read_text()) if a.benign_replay else None
    report = evaluate(read_jsonl(a.dataset), read_jsonl(a.predictions), replay)
    report.update(dataset_sha256=sha256(a.dataset), predictions_sha256=sha256(a.predictions))
    a.output.write_text(json.dumps(report, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    print("PASS" if report["passed"] else "NOT QUALIFIED: " + "; ".join(report["failures"]))
    return 0 if report["passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
