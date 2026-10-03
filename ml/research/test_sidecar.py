"""Drive decision_sidecar.py the way vigil-decide would: spawn it, wait for `ready`, send requests
over stdin, read JSON lines from stdout, check error handling, shut it down.

    python ml/research/test_sidecar.py --backend opendecider --device cpu
    python ml/research/test_sidecar.py --backend laya --device cpu
"""
import argparse
import json
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import vigil_cases as vc  # noqa: E402

ap = argparse.ArgumentParser()
ap.add_argument("--backend", choices=["laya", "opendecider"], required=True)
ap.add_argument("--device", default="cpu")
ap.add_argument("--threads", type=int, default=4)
args = ap.parse_args()

from huggingface_hub import snapshot_download  # noqa: E402  (resolve the local cache path only)
if args.backend == "laya":
    model_dir = os.path.join(snapshot_download(vc.LAYA_REPO, revision=vc.LAYA_REVISION,
                                               allow_patterns=[vc.LAYA_SUBFOLDER + "/*", vc.LAYA_SUBFOLDER + "/*/*"]),
                             vc.LAYA_SUBFOLDER)
else:
    model_dir = snapshot_download(vc.OD_REPO, revision=vc.OD_REVISION)

VIGIL_QUESTIONS = [
    {"id": "matches_purpose", "kind": "yes_no", "text": vc.QUESTIONS["matches_purpose"]["instructions"]},
    {"id": "verdict", "kind": "choice", "text": vc.QUESTIONS["verdict"]["instructions"],
     "options": vc.QUESTIONS["verdict"]["criteria"]},
    {"id": "tactic", "kind": "choice", "text": vc.QUESTIONS["tactic"]["instructions"],
     "options": vc.QUESTIONS["tactic"]["criteria"]},
    {"id": "severity", "kind": "score", "text": vc.QUESTIONS["severity"]["instructions"],
     "options": vc.QUESTIONS["severity"]["criteria"]},
    {"id": "action", "kind": "choice", "text": vc.QUESTIONS["action"]["instructions"],
     "options": vc.QUESTIONS["action"]["criteria"]},
]

t0 = time.perf_counter()
proc = subprocess.Popen([sys.executable, os.path.join(HERE, "decision_sidecar.py"), "--backend", args.backend,
                         "--model-dir", model_dir, "--device", args.device, "--threads", str(args.threads)],
                        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)


def send(obj):
    proc.stdin.write((json.dumps(obj) + "\n").encode("utf-8"))
    proc.stdin.flush()
    return json.loads(proc.stdout.readline())


ready = json.loads(proc.stdout.readline())
print("ready after %.1fs:" % (time.perf_counter() - t0), ready)
for rid, state in (("mal", vc.STATE_MALICIOUS), ("ben", vc.STATE_BENIGN)):
    r = send({"id": rid, "op": "decide", "state": state, "questions": VIGIL_QUESTIONS})
    print(f"\n== {rid}: ok={r['ok']} latency_ms={r.get('latency_ms')} usage={r.get('usage')}")
    for a in r["answers"]:
        print(f"  {a['id']:16s} T={a['temperature']:.3f} " +
              " ".join(f"{lab}={p:.3f}" for lab, p in zip(a["labels"], a["probs"])))
print("\nping:", send({"id": "p", "op": "ping"}))
print("bad request:", send({"id": "x", "op": "decide", "state": "s", "questions": [{"id": "q", "kind": "choice",
                                                                                   "text": "t", "options": ["a"]}]}))
print("bad json:", (proc.stdin.write(b"{not json\n"), proc.stdin.flush(), json.loads(proc.stdout.readline()))[2])
print("shutdown:", send({"id": "s", "op": "shutdown"}), "exit code:", proc.wait(timeout=30))
