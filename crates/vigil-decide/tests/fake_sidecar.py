"""Protocol-v1 compatible fake decision sidecar for Rust integration tests.

Answers every question with a fixed distribution: the first option gets 0.7,
the rest share 0.3. A state containing CRASH makes the process exit, to test
recovery.
"""
import json
import sys

print(json.dumps({"type": "ready", "protocol": 1, "backend": "fake", "model": "fake",
                  "device": "cpu", "threads": 1, "max_len": 2048, "load_ms": 0}), flush=True)

for line in sys.stdin:
    req = json.loads(line)
    op = req.get("op")
    if op == "shutdown":
        print(json.dumps({"id": req.get("id"), "ok": True}), flush=True)
        break
    if op == "ping":
        print(json.dumps({"id": req.get("id"), "ok": True, "pong": True}), flush=True)
        continue
    if "CRASH" in req.get("state", ""):
        sys.exit(3)
    answers = []
    for q in req["questions"]:
        labels = ["yes", "no"] if q["kind"] == "yes_no" else q["options"]
        rest = 0.3 / (len(labels) - 1)
        probs = [0.7] + [rest] * (len(labels) - 1)
        answers.append({"id": q["id"], "labels": labels, "logits": [0.0] * len(labels),
                        "probs": probs, "temperature": 1.0})
    print(json.dumps({"id": req["id"], "ok": True, "answers": answers,
                      "usage": {"state_tokens": 1, "input_tokens": 1, "truncated": False},
                      "latency_ms": 0.1}), flush=True)
