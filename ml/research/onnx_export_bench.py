"""Experiment: export both Tier-2 candidates to ONNX and benchmark them with onnxruntime on CPU.

    python ml/research/onnx_export_bench.py export --model laya --out <dir>
    python ml/research/onnx_export_bench.py export --model opendecider --out <dir>
    python ml/research/onnx_export_bench.py bench  --model laya --out <dir> --threads 4
    python ml/research/onnx_export_bench.py bench  --model opendecider --out <dir> --threads 4

laya ships an official exporter (repo scripts/export_onnx.py, not in the wheel) and a runtime
(`laya.onnx_agent.ONNXAgent`, extra `laya[onnx]`); `export` below reproduces that exporter's call.
opendecider 0.6.0 has NO ONNX support (README roadmap: "in progress"); the wrapper below is ours.
Run `bench` in a fresh process (no torch model loaded) so the RAM number is the ONNX runtime's.
"""
import argparse
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import vigil_cases as vc  # noqa: E402

ap = argparse.ArgumentParser()
ap.add_argument("mode", choices=["export", "bench"])
ap.add_argument("--model", choices=["laya", "opendecider"], required=True)
ap.add_argument("--out", required=True)
ap.add_argument("--threads", type=int, default=4)
ap.add_argument("--runs", type=int, default=20)
ap.add_argument("--int8", action="store_true", help="bench the int8 dynamic-quantized graph (written by export)")
args = ap.parse_args()
os.makedirs(args.out, exist_ok=True)


def laya_dir():
    from huggingface_hub import snapshot_download
    root = snapshot_download(vc.LAYA_REPO, revision=vc.LAYA_REVISION,
                             allow_patterns=[vc.LAYA_SUBFOLDER + "/*", vc.LAYA_SUBFOLDER + "/*/*"])
    return os.path.join(root, vc.LAYA_SUBFOLDER)


def od_dir():
    from huggingface_hub import snapshot_download
    return snapshot_download(vc.OD_REPO, revision=vc.OD_REVISION)


def export():
    import torch
    path = os.path.join(args.out, f"{args.model}.onnx")
    if args.model == "laya":
        import laya
        agent = laya.Agent(laya_dir(), device="cpu", compile=False)
        model = agent.model.eval()
        b, s, k = 2, 17, 3              # >1 and pairwise different, as in the official exporter (#695)
        inputs = (torch.randint(0, 100, (b, s)), torch.ones((b, s), dtype=torch.long),
                  torch.tensor([[1, 5, 9]] * b), torch.ones((b, k), dtype=torch.bool), torch.zeros(b, dtype=torch.long))
        names = ["input_ids", "attention_mask", "marker_pos", "marker_mask", "qtype"]
        outs = ["logits", "act_logits"]
        dyn = {"input_ids": {0: "batch_size", 1: "seq_len"}, "attention_mask": {0: "batch_size", 1: "seq_len"},
               "marker_pos": {0: "batch_size", 1: "num_markers"}, "marker_mask": {0: "batch_size", 1: "num_markers"},
               "qtype": {0: "batch_size"}, "logits": {0: "batch_size", 1: "num_markers"}, "act_logits": {0: "batch_size"}}
    else:
        from opendecider import load

        class NanoONNX(torch.nn.Module):
            """input_ids, attention_mask, marker_pos[B,K] -> per-option logits [B,K] (softmax left to caller)."""

            def __init__(self, impl):
                super().__init__()
                self.enc, self.head = impl.enc, impl.head

            def forward(self, input_ids, attention_mask, marker_pos):
                h = self.enc(input_ids=input_ids, attention_mask=attention_mask).last_hidden_state
                idx = marker_pos[:, :, None].expand(-1, -1, h.size(-1))
                return self.head(torch.gather(h, 1, idx)).squeeze(-1)

        m = load(od_dir(), device="cpu")
        model = NanoONNX(m.impl).eval()
        b, s, k = 2, 17, 3
        inputs = (torch.randint(0, 100, (b, s)), torch.ones((b, s), dtype=torch.long), torch.tensor([[1, 5, 9]] * b))
        names, outs = ["input_ids", "attention_mask", "marker_pos"], ["logits"]
        dyn = {"input_ids": {0: "batch_size", 1: "seq_len"}, "attention_mask": {0: "batch_size", 1: "seq_len"},
               "marker_pos": {0: "batch_size", 1: "num_markers"}, "logits": {0: "batch_size", 1: "num_markers"}}
    t = time.perf_counter()
    try:
        torch.onnx.export(model, inputs, path, export_params=True, opset_version=18, do_constant_folding=True,
                          input_names=names, output_names=outs, dynamic_axes=dyn)
        how = "torch.onnx.export (default exporter)"
    except Exception as e:  # noqa: BLE001
        print("default exporter failed:", repr(e)[:400], "-> retrying with dynamo=False")
        torch.onnx.export(model, inputs, path, export_params=True, opset_version=18, do_constant_folding=True,
                          input_names=names, output_names=outs, dynamic_axes=dyn, dynamo=False)
        how = "torch.onnx.export(dynamo=False)"
    print(f"exported {path} via {how} in {time.perf_counter() - t:.1f}s")
    from onnxruntime.quantization import QuantType, quantize_dynamic
    import onnx
    import onnx.external_data_helper  # noqa: F401  (onnx 1.23 + ort 1.30 quantizer needs it imported)
    g = onnx.load(path)
    del g.graph.value_info[:]
    quantize_dynamic(model_input=g, model_output=path.replace(".onnx", ".int8.onnx"),
                     op_types_to_quantize=["MatMul"], weight_type=QuantType.QInt8, per_channel=False)
    print("wrote int8 copy")


def bench():
    import numpy as np
    import onnxruntime as ort
    import psutil
    proc = psutil.Process()
    path = os.path.join(args.out, f"{args.model}{'.int8' if args.int8 else ''}.onnx")
    so = ort.SessionOptions()
    so.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL
    so.intra_op_num_threads = args.threads
    so.inter_op_num_threads = 1
    t0 = time.perf_counter()
    sess = ort.InferenceSession(path, sess_options=so, providers=["CPUExecutionProvider"])
    questions = vc.QUESTIONS
    if args.model == "laya":
        # Use laya's own ONNX runtime (same tokenisation, temperatures and answer shape as Agent)
        # but with our thread-limited session swapped in.
        from laya.onnx_agent import ONNXAgent
        agent = ONNXAgent(laya_dir(), onnx_path=path)
        agent.session = sess
        run = lambda st: agent.predict(st, questions)  # noqa: E731
    else:
        from transformers import AutoTokenizer
        from opendecider.nano import NanoModel
        from opendecider.questions import answer, as_dict, options
        d = od_dir()
        meta = json.load(open(os.path.join(d, "opendecider.json")))

        class Shim:                       # just enough of NanoModel for its _build()
            pass
        shim = Shim()
        shim.tok = AutoTokenizer.from_pretrained(d)
        shim.mask_id, shim.max_len = shim.tok.mask_token_id, meta.get("max_len", 2048)
        qs = {k: as_dict(dict(q)) for k, q in questions.items()}

        def run(st):
            rows = [NanoModel._build(shim, st, q["instructions"], options(q))[0] for q in qs.values()]
            L = max(map(len, rows))
            ids = np.array([r + [shim.tok.pad_token_id] * (L - len(r)) for r in rows], dtype=np.int64)
            att = np.array([[1] * len(r) + [0] * (L - len(r)) for r in rows], dtype=np.int64)
            pos = [[i for i, t in enumerate(r) if t == shim.mask_id] for r in rows]
            K = max(map(len, pos))
            mpos = np.array([p + [0] * (K - len(p)) for p in pos], dtype=np.int64)
            z = sess.run(["logits"], {"input_ids": ids, "attention_mask": att, "marker_pos": mpos})[0]
            out = {}
            for (k, q), p_row, zr in zip(qs.items(), pos, z):
                zr = zr[:len(p_row)].astype(np.float64)
                p = np.exp(zr - zr.max()); p /= p.sum()
                out[k] = answer(q, dict(zip(options(q).keys(), p.tolist())))
            return {"answers": out}
    load_s = time.perf_counter() - t0
    mem_load = proc.memory_info()
    res = {}
    for name, st in (("malicious", vc.STATE_MALICIOUS), ("benign", vc.STATE_BENIGN)):
        a = run(st)["answers"]
        res[name] = {qid: ({"true": a[qid]["noul"], "false": 1 - a[qid]["noul"]} if q["type"] == "noul"
                           else a[qid]["probabilities"]) for qid, q in questions.items()}
    for _ in range(2):
        run(vc.STATE_MALICIOUS)
    lat = []
    for _ in range(args.runs):
        t = time.perf_counter()
        run(vc.STATE_MALICIOUS)
        lat.append((time.perf_counter() - t) * 1000)
    mi = proc.memory_info()
    rep = {"model": args.model, "graph": os.path.basename(path), "file_mb": round(os.path.getsize(path) / 2**20, 1),
           "threads": args.threads, "load_s": round(load_s, 2),
           "rss_after_load_mb": round(mem_load.rss / 2**20, 1), "rss_after_runs_mb": round(mi.rss / 2**20, 1),
           "peak_wset_mb": round(getattr(mi, "peak_wset", 0) / 2**20, 1),
           "latency_ms_5q": {"p50": round(float(np.percentile(lat, 50)), 1), "p95": round(float(np.percentile(lat, 95)), 1)},
           "full_distribution": {c: {q: {o: round(float(p), 4) for o, p in d.items()} for q, d in v.items()}
                                 for c, v in res.items()}}
    print(json.dumps(rep, indent=1))
    with open(os.path.join(HERE, "results", f"onnx_{args.model}{'_int8' if args.int8 else ''}_cpu{args.threads}.json"), "w") as f:
        json.dump(rep, f, indent=1)


if __name__ == "__main__":
    export() if args.mode == "export" else bench()
