"""Fit per-question temperatures on validation families only."""
import argparse
import json
import math
from pathlib import Path
from dataset import LABELS, read_jsonl, validate, sha256


def softmax(logits, temperature=1.):
    if not math.isfinite(temperature) or temperature <= 0 or not all(math.isfinite(x) for x in logits):
        raise ValueError("invalid logits or temperature")
    z = [x / temperature for x in logits]
    peak = max(z); e = [math.exp(x - peak) for x in z]; total = sum(e)
    return [x / total for x in e]


def fit(rows, predictions):
    validate(rows)
    val = [r for r in rows if r["split"] == "val"]
    if len(val) < 10:
        raise ValueError("at least ten validation cases are needed for calibration")
    by_id = {p["id"]: p for p in predictions}
    if len(by_id) != len(predictions):
        raise ValueError("duplicate prediction id")
    temperatures = {}
    for q, labels in LABELS.items():
        samples = []
        for row in val:
            logits = by_id[row["id"]]["logits"][q]
            if set(logits) != set(labels):
                raise ValueError("calibration logits differ from the label contract")
            samples.append(([logits[l] for l in labels], labels.index(str(row["labels"][q]))))
        def loss(t):
            return sum(-math.log(max(softmax(z, t)[y], 1e-15)) for z, y in samples) / len(samples)
        # Deterministic logarithmic search, no optional optimizer dependency.
        temperatures[q] = min([math.exp(i / 20) for i in range(-60, 61)], key=loss)
    return temperatures


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("dataset", type=Path); p.add_argument("predictions", type=Path)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args(); rows = read_jsonl(a.dataset)
    result = fit(rows, read_jsonl(a.predictions))
    a.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    a.output.with_suffix(".provenance.json").write_text(json.dumps(dict(dataset_sha256=sha256(a.dataset),
        predictions_sha256=sha256(a.predictions), split="val", cases=sum(r['split'] == 'val' for r in rows)), indent=2) + "\n", encoding="utf-8")
    print(f"Wrote validation-only temperatures to {a.output}")


if __name__ == "__main__":
    main()
