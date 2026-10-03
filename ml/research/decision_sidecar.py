"""Prototype of the Vigil Tier-2 decision sidecar: a long-lived process speaking JSON lines.

    python ml/research/decision_sidecar.py --backend opendecider --model-dir <dir> --device cpu --threads 4
    python ml/research/decision_sidecar.py --backend laya --model-dir <dir>/typed-decisions --device cpu --threads 4

Protocol v1 (one JSON object per line, UTF-8, '\n'-terminated; stdout carries ONLY protocol lines,
all logs go to stderr). Full description: docs/research/decision-models.md section 9.

  <- {"type":"ready","protocol":1,"backend":...,"model":...,"device":...,"max_len":...,"load_ms":...}
  -> {"id":"1","op":"decide","state":"APP ...","questions":[
        {"id":"matches_purpose","kind":"yes_no","text":"Is this ...?"},
        {"id":"verdict","kind":"choice","text":"Overall, ...?","options":["benign","suspicious","malicious"]},
        {"id":"severity","kind":"score","text":"How severe ...?","options":["none","low","high","critical"]}]}
  <- {"id":"1","ok":true,"answers":[{"id":"matches_purpose","labels":["yes","no"],"logits":[..],"probs":[..],
        "temperature":1.0}, ...],"usage":{"state_tokens":216,"input_tokens":1264,"truncated":false},"latency_ms":2011.7}
  -> {"id":"2","op":"ping"}      <- {"id":"2","ok":true,"pong":true}
  -> {"id":"3","op":"shutdown"}  <- {"id":"3","ok":true}   (then exit 0; EOF on stdin also exits 0)
  errors: {"id":...,"ok":false,"error":{"code":"bad_request"|"internal","message":"..."}}

This is research code: it relies on private helpers of laya==0.3.24 / opendecider==0.6.0
(the same ones laya.calibrate.records_from_labeled uses) to expose raw logits; pin those versions.
"""
import argparse
import json
import os
import sys
import time

# The sidecar must never touch the network: everything is loaded from --model-dir.
os.environ.setdefault("HF_HUB_OFFLINE", "1")
os.environ.setdefault("TRANSFORMERS_OFFLINE", "1")
os.environ.setdefault("USE_TF", "0")

ap = argparse.ArgumentParser()
ap.add_argument("--backend", choices=["laya", "opendecider"], required=True)
ap.add_argument("--model-dir", required=True, help="local checkpoint directory (no Hub access)")
ap.add_argument("--device", default="cpu")
ap.add_argument("--threads", type=int, default=4)
ap.add_argument("--calibration", default=None,
                help='JSON {"<question id>": temperature}; missing ids use the backend default')
ap.add_argument("--max-line-bytes", type=int, default=1 << 20)
args = ap.parse_args()
if args.device == "cpu":
    os.environ["OMP_NUM_THREADS"] = str(args.threads)
    os.environ["MKL_NUM_THREADS"] = str(args.threads)

import numpy as np  # noqa: E402
import torch  # noqa: E402

LOG = sys.stderr
OUT = sys.stdout


def emit(obj):
    OUT.write(json.dumps(obj, ensure_ascii=False, separators=(",", ":")) + "\n")
    OUT.flush()


def lower_priority():
    try:
        import psutil
        p = psutil.Process()
        p.nice(psutil.BELOW_NORMAL_PRIORITY_CLASS if os.name == "nt" else 10)
    except Exception as e:  # noqa: BLE001
        print(f"[sidecar] could not lower priority: {e}", file=LOG)


def to_library_question(q):
    """Vigil question -> TypeSafe/Jev-style dict understood by both libraries; returns (dict, labels)."""
    kind, text = q.get("kind"), q.get("text")
    if not isinstance(text, str) or not text.strip():
        raise ValueError(f"question {q.get('id')!r}: 'text' must be a non-empty string")
    text = scrub(text)
    if isinstance(q.get("options"), list):
        if any(isinstance(o, str) and scrub(o) != o for o in q["options"]):
            raise ValueError(f"question {q.get('id')!r}: options must not contain tokenizer special tokens")
    if kind == "yes_no":
        return {"type": "noul", "instructions": text}, ["yes", "no"]
    opts = q.get("options")
    if not isinstance(opts, list) or len(opts) < 2 or not all(isinstance(o, str) and o for o in opts):
        raise ValueError(f"question {q.get('id')!r}: 'options' must list >= 2 non-empty strings")
    if len(set(opts)) != len(opts):
        raise ValueError(f"question {q.get('id')!r}: duplicate options")
    if kind == "choice":
        return {"type": "choice", "instructions": text, "criteria": list(opts)}, list(opts)
    if kind == "score":                                  # options = level labels, lowest first
        return {"type": "score", "instructions": text, "criteria": list(opts)}, list(opts)
    raise ValueError(f"question {q.get('id')!r}: unknown kind {kind!r}")


class LayaBackend:
    def __init__(self):
        import laya
        from laya.common import QTYPES, temp_bucket
        self._qtypes, self._bucket = QTYPES, temp_bucket
        self.agent = laya.Agent(args.model_dir, device=args.device)
        self.name = self.agent.cfg.get("model_name", "laya")
        self.max_len = self.agent.cfg.get("max_len")

    def default_temperature(self, lib_q, k):
        qt = self._qtypes[lib_q["type"]]
        a = self.agent
        return a.temperature_by_options.get(self._bucket(qt, k), a.temperature[qt])

    @torch.no_grad()
    def logits(self, state, lib_qs):
        from laya.agent import _option_logits
        from laya.common import collate_items
        a = self.agent
        ids = list(lib_qs)
        for qid in ids:
            a._check_question(qid, lib_qs[qid])
        internal = {qid: a._to_internal(lib_qs[qid]) for qid in ids}
        items = a._encode_state(state, ids, internal)
        b = collate_items([items], a.tok.pad_token_id)
        logits, _ = a._forward(b)
        rows = _option_logits(logits, items, 0)
        st = items[0]["state_stats"]
        usage = {"state_tokens": st["state_tokens"], "input_tokens": int(b["attention_mask"].sum()),
                 "truncated": any(it["state_stats"]["truncated"] for it in items)}
        out = {}
        for qid, row in zip(ids, rows):
            row = [float(x) for x in row]
            if lib_qs[qid]["type"] == "noul":
                row = [row[1], row[0]]                   # laya slot order is [false, true] -> [yes, no]
            out[qid] = row
        return out, usage


class OpenDeciderBackend:
    def __init__(self):
        from opendecider import load
        self.model = load(args.model_dir, device=args.device)
        self.impl = self.model.impl
        self.name = self.model.name
        self.max_len = self.impl.max_len

    def default_temperature(self, lib_q, k):
        return 1.0                                       # opendecider applies no temperature

    @torch.no_grad()
    def logits(self, state, lib_qs):
        from opendecider.questions import as_dict, options
        impl = self.impl
        built, opt_lists = [], []
        for q in lib_qs.values():
            qd = as_dict(dict(q))
            opts = options(qd)                           # noul -> {"yes":..,"no":..}; score -> {"0":..}
            built.append(impl._build(state, qd["instructions"], opts))
            opt_lists.append(list(opts))
        rows = [b for b, _ in built]
        L, pad = max(map(len, rows)), impl.tok.pad_token_id
        x = torch.tensor([r + [pad] * (L - len(r)) for r in rows], device=impl.device)
        att = torch.tensor([[1] * len(r) + [0] * (L - len(r)) for r in rows], device=impl.device)
        h = impl.enc(input_ids=x, attention_mask=att).last_hidden_state
        out = {}
        for i, (qid, r) in enumerate(zip(lib_qs, rows)):
            pos = torch.tensor([j for j, t in enumerate(r) if t == impl.mask_id], device=impl.device)
            out[qid] = impl.head(h[i, pos]).squeeze(-1).float().tolist()
        usage = {"state_tokens": len(impl.tok.encode(state, add_special_tokens=False)),
                 "input_tokens": int(att.sum()), "truncated": any(tr for _, tr in built)}
        return out, usage


def softmax(z, t):
    z = np.asarray(z, dtype=np.float64) / t
    e = np.exp(z - z.max())
    return (e / e.sum()).tolist()


SPECIAL_TOKENS = ("[MASK]", "[CLS]", "[SEP]", "[PAD]", "[UNK]")


def scrub(text):
    """Remove tokenizer special-token strings. opendecider 0.6.0 does NOT do this: a literal "[MASK]"
    in the state becomes an extra option marker and silently corrupts the probabilities (verified:
    a 2-option answer summed to 0.70). laya 0.3.24 only replaces [MASK]."""
    for s in SPECIAL_TOKENS:
        text = text.replace(s, " ")
    return text


def handle_decide(backend, calib, req):
    state = req.get("state")
    if not isinstance(state, str) or not state:
        raise ValueError("'state' must be a non-empty string")
    state = scrub(state)
    qs = req.get("questions")
    if not isinstance(qs, list) or not qs:
        raise ValueError("'questions' must be a non-empty array")
    lib_qs, labels = {}, {}
    for q in qs:
        qid = q.get("id") if isinstance(q, dict) else None
        if not isinstance(qid, str) or not qid or qid in lib_qs:
            raise ValueError(f"bad or duplicate question id {qid!r}")
        lib_qs[qid], labels[qid] = to_library_question(q)
    t0 = time.perf_counter()
    logits, usage = backend.logits(state, lib_qs)
    answers = []
    for qid in lib_qs:
        z = logits[qid]
        t = float(calib.get(qid, backend.default_temperature(lib_qs[qid], len(z))))
        answers.append({"id": qid, "labels": labels[qid], "logits": [round(v, 6) for v in z],
                        "probs": [round(p, 6) for p in softmax(z, t)], "temperature": t})
    return {"answers": answers, "usage": usage, "latency_ms": round((time.perf_counter() - t0) * 1000, 1)}


def main():
    lower_priority()
    if args.device == "cpu":
        torch.set_num_threads(args.threads)
    calib = json.load(open(args.calibration, encoding="utf-8")) if args.calibration else {}
    t0 = time.perf_counter()
    backend = LayaBackend() if args.backend == "laya" else OpenDeciderBackend()
    emit({"type": "ready", "protocol": 1, "backend": args.backend, "model": backend.name,
          "device": args.device, "threads": args.threads if args.device == "cpu" else None,
          "max_len": backend.max_len, "load_ms": round((time.perf_counter() - t0) * 1000)})
    stdin = open(sys.stdin.fileno(), "rb", closefd=False)
    for raw in stdin:
        rid = None
        try:
            if len(raw) > args.max_line_bytes:
                raise ValueError("request line too long")
            req = json.loads(raw.decode("utf-8"))
            if not isinstance(req, dict):
                raise ValueError("request must be a JSON object")
            rid, op = req.get("id"), req.get("op")
            if op == "decide":
                emit({"id": rid, "ok": True, **handle_decide(backend, calib, req)})
            elif op == "ping":
                emit({"id": rid, "ok": True, "pong": True})
            elif op == "shutdown":
                emit({"id": rid, "ok": True})
                return 0
            else:
                raise ValueError(f"unknown op {op!r}")
        except (ValueError, KeyError, TypeError, json.JSONDecodeError, UnicodeDecodeError) as e:
            emit({"id": rid, "ok": False, "error": {"code": "bad_request", "message": str(e)}})
        except Exception as e:  # noqa: BLE001
            print(f"[sidecar] internal error: {e!r}", file=LOG)
            emit({"id": rid, "ok": False, "error": {"code": "internal", "message": str(e)}})
    return 0


if __name__ == "__main__":
    sys.exit(main())
