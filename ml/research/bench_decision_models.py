"""Run and benchmark the two Tier-2 candidate decision models on Vigil's cases.

Usage (from repo root, inside ml/.venv):
    python ml/research/bench_decision_models.py --model laya --device cpu --threads 4
    python ml/research/bench_decision_models.py --model opendecider --device cuda
    python ml/research/bench_decision_models.py --model laya --device cpu --threads 4 --dtype bf16
    python ml/research/bench_decision_models.py --model laya --device cpu --threads 4 --quant int8

Run each configuration in its OWN process: peak RSS is only meaningful for a fresh process.
Prints full typed answers for the malicious and benign states, a normalised "full distribution"
view (a probability for every option, including both sides of yes/no), the raw per-option logits
(what per-question temperature calibration would be fitted on), token counts, load time, peak
RAM and p50/p95 latency of the 5-question call.
"""
import argparse
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)


def parse():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", choices=["laya", "opendecider"], required=True)
    ap.add_argument("--device", choices=["cpu", "cuda"], default="cpu")
    ap.add_argument("--threads", type=int, default=4)
    ap.add_argument("--runs", type=int, default=20)
    ap.add_argument("--warmup", type=int, default=2)
    ap.add_argument("--dtype", choices=["fp32", "bf16"], default="fp32",
                    help="CPU only: bf16 converts the weights (laya) / uses load(dtype=) (opendecider)")
    ap.add_argument("--quant", choices=["none", "int8"], default="none",
                    help="CPU only: torch dynamic int8 quantization of nn.Linear layers (experimental)")
    ap.add_argument("--described", action="store_true", help="use option descriptions variant")
    ap.add_argument("--json-out", default=None)
    ap.add_argument("--quiet", action="store_true")
    return ap.parse_args()


args = parse()
if args.device == "cpu":
    # Must be set before torch is imported to bound OpenMP/MKL pools as well.
    for var in ("OMP_NUM_THREADS", "MKL_NUM_THREADS"):
        os.environ[var] = str(args.threads)

import numpy as np  # noqa: E402
import psutil  # noqa: E402
import torch  # noqa: E402

import vigil_cases as vc  # noqa: E402

PROC = psutil.Process()


def mem_mb():
    mi = PROC.memory_info()
    out = {"rss_mb": round(mi.rss / 2**20, 1)}
    if hasattr(mi, "peak_wset"):          # Windows: peak working set of the process
        out["peak_wset_mb"] = round(mi.peak_wset / 2**20, 1)
    return out


def full_distribution(questions, answers):
    """Normalise both libraries' typed answers to {qid: {option: prob}} with EVERY option present."""
    out = {}
    for qid, q in questions.items():
        a = answers[qid]
        if q["type"] == "noul":
            p_true = float(a["noul"])                       # both libs: noul == P(true)
            out[qid] = {"true": p_true, "false": 1.0 - p_true}
        else:
            out[qid] = {k: float(v) for k, v in a["probabilities"].items()}
    return out


# --------------------------------------------------------------------------- loaders

def load_laya():
    import laya
    agent = laya.load(vc.LAYA_REPO, subfolder=vc.LAYA_SUBFOLDER, revision=vc.LAYA_REVISION,
                      device=args.device)
    if args.device == "cpu" and args.dtype == "bf16":
        agent.model.to(torch.bfloat16)
        # DecisionModel.forward feeds `h[:, 0].float()` + fp32 features to act_head, so that
        # small head must stay fp32 (otherwise: "mat1 and mat2 must have the same dtype").
        agent.model.act_head.float()
    if args.device == "cpu" and args.quant == "int8":
        # encoder only: nn.TransformerEncoderLayer (decision head) breaks when its Linear layers are swapped
        torch.ao.quantization.quantize_dynamic(agent.model.encoder, {torch.nn.Linear}, dtype=torch.qint8, inplace=True)
    return agent


def load_od():
    from opendecider import load
    dtype = "bfloat16" if (args.device == "cpu" and args.dtype == "bf16") else None
    model = load(vc.OD_REPO, revision=vc.OD_REVISION, device=args.device, dtype=dtype)
    if args.device == "cpu" and args.quant == "int8":
        torch.ao.quantization.quantize_dynamic(model.impl.enc, {torch.nn.Linear}, dtype=torch.qint8, inplace=True)
    return model


def predict(model, state, questions):
    if args.model == "laya":
        return model.predict(state, questions)
    return model.system_one(state, questions)


# --------------------------------------------------------------------------- raw logits

@torch.no_grad()
def raw_logits_laya(agent, state, questions):
    """Uncalibrated per-option logits, exactly the rows Agent._decode_answers divides by T.
    Same internal path as laya.calibrate.records_from_labeled (laya 0.3.24)."""
    from laya.common import collate_items
    from laya.agent import _option_logits
    ids = list(questions)
    internal = {qid: agent._to_internal(questions[qid]) for qid in ids}
    items = agent._encode_state(state, ids, internal)
    batch = collate_items([items], agent.tok.pad_token_id)
    logits, _act = agent._forward(batch)
    rows = _option_logits(logits, items, 0)
    res = {}
    for qid, row, q in zip(ids, rows, questions.values()):
        if q["type"] == "noul":
            labels = ["false", "true"]                    # laya noul slot order is [false, true]
        elif q["type"] == "score":
            labels = [str(i) for i in range(len(q["criteria"]))]
        else:
            labels = list(q["criteria"]) if isinstance(q["criteria"], list) else list(q["criteria"].keys())
        res[qid] = dict(zip(labels, [round(float(x), 4) for x in row]))
    return res


@torch.no_grad()
def raw_logits_od(model, state, questions):
    """opendecider-nano has no temperature: probabilities = softmax(head(h[MASK])). Re-run the
    head without the softmax to expose the logits (mirrors NanoModel.decide_many, 0.6.0)."""
    from opendecider.questions import options, as_dict
    impl = model.impl
    res = {}
    for qid, q in questions.items():
        opts = options(as_dict(dict(q)))
        ids, _ = impl._build(state, q["instructions"], opts)
        x = torch.tensor([ids], device=impl.device)
        h = impl.enc(input_ids=x, attention_mask=torch.ones_like(x)).last_hidden_state
        pos = torch.tensor([i for i, t in enumerate(ids) if t == impl.mask_id], device=impl.device)
        z = impl.head(h[0, pos]).squeeze(-1).float().tolist()
        res[qid] = dict(zip(opts.keys(), [round(v, 4) for v in z]))
    return res


def token_counts(model, state, questions):
    if args.model == "laya":
        tok = model.tok
        from laya.common import build_sequence
        state_ids = tok(state, add_special_tokens=False)["input_ids"]
        per_q = {}
        for qid, q in questions.items():
            seq, markers = build_sequence(tok, state, model._to_internal(q),
                                          model.cfg["max_len"], model.cfg["head_max_len"])
            per_q[qid] = len(seq)
        return {"state_tokens": len(state_ids), "sequence_tokens_per_question": per_q,
                "max_len": model.cfg["max_len"], "head_max_len": model.cfg["head_max_len"]}
    impl = model.impl
    from opendecider.questions import options, as_dict
    state_ids = impl.tok.encode(state, add_special_tokens=False)
    per_q = {qid: len(impl._build(state, q["instructions"], options(as_dict(dict(q))))[0])
             for qid, q in questions.items()}
    return {"state_tokens": len(state_ids), "sequence_tokens_per_question": per_q, "max_len": impl.max_len}


def main():
    if args.device == "cpu":
        torch.set_num_threads(args.threads)
    questions = vc.QUESTIONS_DESCRIBED if args.described else vc.QUESTIONS
    report = {"model": args.model, "device": args.device, "threads": args.threads if args.device == "cpu" else None,
              "dtype": args.dtype, "quant": args.quant, "described": args.described,
              "torch": torch.__version__, "mem_before_load": mem_mb()}

    t0 = time.perf_counter()
    model = load_laya() if args.model == "laya" else load_od()
    report["load_s"] = round(time.perf_counter() - t0, 2)
    report["mem_after_load"] = mem_mb()
    if args.model == "laya":
        report["runtime_dtype"] = str(model.dtype_for(5)) if args.dtype == "fp32" else "torch.bfloat16 (weights)"
        report["temperatures_applied"] = {"temperature": model.temperature,
                                          "temperature_by_options": model.temperature_by_options}

    report["tokens_malicious"] = token_counts(model, vc.STATE_MALICIOUS, questions)
    report["tokens_benign"] = token_counts(model, vc.STATE_BENIGN, questions)

    cases = {}
    for name, state in (("malicious", vc.STATE_MALICIOUS), ("benign", vc.STATE_BENIGN)):
        res = predict(model, state, questions)
        cases[name] = {"raw_output": res, "full_distribution": full_distribution(questions, res["answers"]),
                       "raw_logits": (raw_logits_laya if args.model == "laya" else raw_logits_od)(model, state, questions)}
    report["cases"] = cases

    for _ in range(args.warmup):
        predict(model, vc.STATE_MALICIOUS, questions)
    if args.device == "cuda":
        torch.cuda.synchronize()
    lat = []
    for _ in range(args.runs):
        t = time.perf_counter()
        predict(model, vc.STATE_MALICIOUS, questions)
        if args.device == "cuda":
            torch.cuda.synchronize()
        lat.append((time.perf_counter() - t) * 1000)
    report["latency_ms_5q"] = {"runs": args.runs, "p50": round(float(np.percentile(lat, 50)), 1),
                               "p95": round(float(np.percentile(lat, 95)), 1),
                               "mean": round(float(np.mean(lat)), 1), "min": round(min(lat), 1),
                               "max": round(max(lat), 1)}
    report["mem_after_runs"] = mem_mb()
    if args.device == "cuda":
        report["cuda_max_allocated_mb"] = round(torch.cuda.max_memory_allocated() / 2**20, 1)

    if not args.quiet:
        print(json.dumps(report, indent=1, default=str))
    else:
        short = {k: report[k] for k in ("model", "device", "threads", "dtype", "quant", "load_s",
                                         "mem_after_load", "mem_after_runs", "latency_ms_5q")}
        short["full_distribution_malicious"] = {q: {o: round(p, 3) for o, p in d.items()}
                                                for q, d in cases["malicious"]["full_distribution"].items()}
        short["full_distribution_benign"] = {q: {o: round(p, 3) for o, p in d.items()}
                                             for q, d in cases["benign"]["full_distribution"].items()}
        print(json.dumps(short, indent=1, default=str))
    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=1, default=str)


if __name__ == "__main__":
    main()
