# Tier-2 decision models: research and verification

Status: research only (no Vigil Rust code). Date: 2026-10-03. Spec context: `docs/vigil-master-prompt.md`
sections 4 (budget), 10 (pipeline), 12 (decision model integration) and 17 (ML pipeline).

Every statement below comes from one of four sources, and the source is named where it matters:
**[src]** the installed library source code (site-packages); **[ran]** a run on the dev machine, with
results saved under `ml/research/results/`; **[card]** a model card, README or notebook; **[unverified]**
an inference that was not tested.

Rerunnable scripts are in `ml/research/`:

| Script | Purpose |
|---|---|
| `vigil_cases.py` | Pinned repos/revisions, the malicious and benign test states, Vigil's 5 questions (plain and "described" variants) |
| `bench_decision_models.py` | Runs a model on GPU or CPU: full outputs, full per-option distributions, raw logits, token counts, load time, RAM, p50/p95 latency |
| `onnx_export_bench.py` | Exports to ONNX (official laya exporter call; our own wrapper for opendecider), int8 quantization, onnxruntime CPU benchmark |
| `decision_sidecar.py` | **Working prototype** of the recommended JSON-lines sidecar (protocol v1, section 9) for both backends |
| `test_sidecar.py` | Drives the sidecar the way `vigil-decide` would (spawn, ready, decide, ping, error cases, shutdown) |
| `list_licenses.py` | Lists the license of every installed distribution |
| `requirements-research.txt` | `pip freeze` of `ml/.venv` |

---

## 0. Summary and recommendation

* **Both libraries work on this machine** (RTX PRO 6000 Blackwell, torch `2.11.0+cu128`; Core Ultra 9 285K CPU)
  and accept the same Jev-style question schema. Both return a probability for **every** option of a choice or
  score question. For yes/no, laya returns only `noul = P(true)`, so `P(false) = 1 - noul`. Both
  probability sets can be rebuilt from raw per-option logits (section 3.4 / 4.4).
* **Zero-shot quality on Vigil's questions:** `opendecider-nano` gives sensible, decisive answers on both test
  states. `laya` typed-decisions gives near-uniform distributions; it leans the right way on `verdict` but
  `matches_purpose` is wrong on the benign case. This matches laya's own documentation: base checkpoints are
  "near chance zero-shot" on new workflows, and fine-tuning is where its value is. Neither model answers
  `matches_purpose` correctly on the benign Chrome state.
* **CPU budget (spec: < 1.2 GB RAM, p95 < 3 s on a 4-core PC):**
  * The only configuration that met the RAM budget was **opendecider-nano in bf16 on the CPU-only torch wheel**:
    peak working set 1,163 MB and p95 2.06 s at 4 threads. Its outputs matched fp32 to about 0.003.
  * laya measured 1.9–2.3 GB RSS (2.7–3.0 GB peak) in every PyTorch configuration, at about 2.3 s.
  * Latency was measured with 4 threads on a fast desktop CPU. **A real 4-core budget PC will be slower, so the
    3 s p95 target is at risk [unverified].**
* **GGUF / ggmlc (`mys/laya-typed-decisions-GGUF`) is not viable as the default runtime today:**
  * The published Windows binary **crashes with STATUS_ILLEGAL_INSTRUCTION on `--device cpu`** on this
    Core Ultra 9 285K, with both F16 and Q8_0.
  * There are no CPU-only Windows builds. The prebuilt CUDA builds are sm86/sm89 only.
  * Upstream's own CPU measurement is 28.3 s for 7 questions.
  * The repo claims MIT but has no LICENSE file.
  * On the Vulkan backend it worked and matched Python (13.5 ms p50). Its stdin/stdout `daemon` JSON contract is
    documented in section 8.3.
* **Fine-tuning:**
  * laya has an **official, public recipe**: a Kaggle 2xT4 notebook, a single-device script, and docs. It covers
    data format, RLCD loss, hyperparameters, checkpoint layout and temperature calibration (section 7.1).
  * **opendecider has no official fine-tuning recipe** (README roadmap: "Next: Fine-tune nano on your own labels").
    Section 7.2 gives a recipe derived from the source code, marked unofficial.
* **Recommendation:**
  * Make **`manjunathshiva/opendecider-nano` the Tier-2 default**, run in bf16 on CPU-only PyTorch, in a
    **long-lived Python sidecar speaking JSON lines over stdin/stdout** (protocol in section 9; a working
    prototype is in `ml/research/decision_sidecar.py`).
  * Keep **laya typed-decisions as the fine-tuning challenger**: it has the official recipe the spec asks for.
    Pick the winner with `evaluate.py` on Vigil's own family-split eval set, as spec 12.1 requires.
  * Spec 12.2's `LayaSidecar` over the ggmlc binary should be replaced by the generic sidecar.
  * The sidecar must apply **per-question temperatures itself**, from returned raw logits. Neither library
    supports per-question temperatures (laya's are per question type and option count; opendecider has none).

---

## 1. Environment and installed versions

| Item | Value |
|---|---|
| venv | `ml/.venv` (Python 3.11.9), gitignored |
| PyTorch | `torch==2.11.0+cu128` from `https://download.pytorch.org/whl/cu128`; `torch.cuda.get_arch_list()` includes `sm_120`; Blackwell works [ran] |
| laya | `laya==0.3.24` (PyPI name is just `laya`), Apache-2.0, home `https://github.com/NandhaKishorM/laya` (GitHub license: Apache-2.0) |
| opendecider | `opendecider==0.6.0`, Apache-2.0 (PyPI metadata, LICENSE and NOTICE files are Apache-2.0; the GitHub API reports "Other" only because NOTICE sits next to it), `https://github.com/manjunathshiva/opendecider` |
| transformers / tokenizers | 5.18.0 / 0.23.2 (Apache-2.0) |
| huggingface_hub / safetensors | 1.33.0 / 0.8.0 (Apache-2.0) |
| ONNX (experiment only) | onnx 1.23.1 (Apache-2.0), onnxruntime 1.30.0 (MIT), onnxscript 0.7.2 (MIT) |
| psutil | 7.2.2 (BSD-3) |
| Second venv (CPU torch) | `ml/.venv/cpu-venv` with `torch==2.11.0+cpu`, same laya/opendecider/transformers versions |

### 1.1 Licenses (full list: `ml/research/results/licenses.txt`)

Everything installed is MIT, BSD, Apache-2.0, PSF or ISC, with these exceptions:

* `certifi` is **MPL-2.0**, and `tqdm` is **MPL-2.0 AND MIT**. Both are transitive dependencies of
  `huggingface_hub`/`transformers`. MPL-2.0 is file-level weak copyleft. It needs maintainer approval under
  `deny.toml` if it ships inside the sidecar bundle. `certifi` is only needed for HTTPS downloads, which the
  sidecar never does.
* `regex` is `Apache-2.0 AND CNRI-Python`. CNRI-Python is a permissive, Python-style license.
* **The `+cu128` torch wheel bundles NVIDIA CUDA runtime DLLs** (cuBLAS, cuDNN, cuFFT, NVRTC, ...) under NVIDIA's
  EULA. **Ship the CPU-only wheel**, which bundles only torch DLLs and Intel OpenMP `libiomp5md.dll`
  (Intel-signed). The Intel OpenMP redistribution license still needs review [unverified].
* **Model weights:**
  * laya typed-decisions: Apache-2.0. Base `answerdotai/ModernBERT-large`, Apache-2.0 [card].
  * opendecider-nano: Apache-2.0. Base `jhu-clsp/ettin-encoder-400m`, MIT.
  * opendecider's NOTICE lists training sets under CC BY / CC BY-SA (SQuAD 2.0, DBpedia-14, FEVER NLI, HotpotQA,
    Natural Questions) and says no dataset text is redistributed. This is common practice, but **flag it for
    legal review**.
  * Fine-tuning data `LocalLLaMA/typed-decisions`: Apache-2.0.
* **ggmlc** (GGUF runtime): `pyproject.toml` and README say MIT, but **there is no LICENSE file at the repo
  root** (only `third_party/ggml/LICENSE`) [checked via the GitHub tree API]. Treat it as unlicensed until fixed
  upstream.

---

## 2. Model artifacts (pin these)

| | laya typed-decisions | opendecider-nano | laya typed-decisions GGUF |
|---|---|---|---|
| Repo | `convaiinnovations/laya`, subfolder `typed-decisions` (also standalone `convaiinnovations/laya-typed-decisions`) | `manjunathshiva/opendecider-nano` | `mys/laya-typed-decisions-GGUF` |
| Revision used | `55cf4c4ebb4ebe31b2550e8bdf3bd21b99753851` (bundle). This is also laya's own reviewed pin `PINNED_REVISIONS["convaiinnovations/laya"]`; the standalone repo's pin is `1a793eb568e6718f15941d08f85432581df534e3` | `beeeb640f3333aec4ef78ed3b7bd0605f973a590` | `1e9e8ba1f5271316601e0fefd940786660bd6964` |
| Weights sha256 | `typed-decisions/model.safetensors` `4fa56de72383a9d3efa9cfa78955733c81b9fc8067a587ca4beb82c78107a24e` (842.6 MB, fp16; identical in the standalone repo) | `model.safetensors` `da243ae586e17ee87b5aa68e1bd06112c1c4cf756ea651d335ae7a2d6097cb38` (789.6 MB, bf16); `head.safetensors` `b57ad139c1ca8984a5205dc57aebeb921c9c59eaa536880d6b5e81d7734eee56` | f16 `71bf4421…0147ee2c` (850 MB); q8_0 `6eb6ef58…1f18` (455 MB); ud_q4_k_m `42919cae…010c` (424 MB) |
| Other files | `rl_agent_config.json`, `encoder/config.json`, `tokenizer/tokenizer.json`, `tokenizer/tokenizer_config.json` | `config.json`, `opendecider.json`, `tokenizer.json`, `tokenizer_config.json`, `LICENSE` | README |
| Architecture | ModernBERT-large encoder + 2-layer transformer decision head (`nn.TransformerEncoder`) + type embedding + scorer MLP + "act" head (~421M) | Ettin-encoder-400m (ModernBERT architecture) + MLP head Linear-GELU-LayerNorm-Linear (~400M) | Same as laya, compiled by ggmlc |
| Context | `max_len` 1024, `head_max_len` 256 | `max_len` 2048 | `max_len` 1024 |
| Tokenizer | ModernBERT BPE, vocab 50,368, `[CLS]=50281 [SEP]=50282 [PAD]=50283 [MASK]=50284` | **The same vocabulary** (checked: `get_vocab()` identical) | Same |

* Loader integrity: `laya.load(..., revision=..., expected_sha256={"model.safetensors": "<hex>", ...})` verifies
  the files before parsing. `LAYA_REVISION=reviewed` uses laya's pinned SHAs [src `laya/revisions.py`].
* `opendecider.load(..., revision=...)` pins the revision but has no digest check [src]. The sidecar should check
  digests itself before loading. Spec 14 already requires this.
* The weights were uploaded 2026-09-18. Later laya commits are README-only. The GGUF (2026-09-20) was compiled
  from those weights, and its output matched Python to about 0.002 [ran].

---

## 3. laya 0.3.24 API (from source)

### 3.1 Loading

```python
import laya
agent = laya.load("convaiinnovations/laya", subfolder="typed-decisions",
                  revision="55cf4c4e...", device="cpu",          # "cuda" | "mps" | "xpu" | None (auto)
                  expected_sha256=None, calibration=None,         # calibration: path to a JSON written by save_calibration
                  fast=False, compile=False)                      # fast = TileLang CUDA path (laya[fast]); compile = torch.compile
# or laya.Agent(local_dir, device="cpu") for a local checkpoint directory (rl_agent_config.json + model.safetensors
# + tokenizer/ + encoder/); laya.load("typed-decisions") also resolves the alias.
```

* `snapshot_download` fetches only `rl_agent_config.json`, `model.safetensors`, `tokenizer/*` and `encoder/*`
  [src `agent.py` L550-562].
* The weights are fp16 on disk and are loaded into an **fp32** model on CPU.
* On CUDA (capability ≥ 8) inference runs under **bf16 autocast** (`amp_dtype: "bf16"` in the config; override
  with `LAYA_CUDA_AMP=fp16|bf16`).
* On CPU, bf16 autocast is opt-in via `LAYA_CPU_AMP=bf16`. There is no `dtype=` argument.

### 3.2 `predict` / `system_one`

`Agent.predict` is an alias of `system_one` [src L1820]:

```python
system_one(state: str | dict | list, questions: dict[str, dict], lang=None, hooks=None,
           on_predict_start=None, on_predict_end=None, hooks_raise=None, hooks_timeout=None,
           max_len=None, head_max_len=None, min_confidence=None) -> dict
```

* **state:** a `str` is used verbatim. A `dict` is `json.dumps(..., ensure_ascii=False)`. A `list` (a
  conversation) is JSON too, and is **left-truncated** so the newest turns survive. Every occurrence of the
  `[MASK]` string in the state is replaced by a space [src `_encode_state`]. Other special-token strings are not.
* **questions:** `{qid: qdef}`, validated by `_check_question` (good error messages):
  * `choice`: `{"type":"choice","instructions":str,"criteria": {label: description|None} | [label,...]}`. Labels
    must be unique scalars.
  * `score`: `{"type":"score","instructions":str,"criteria":[level0, level1, ...]}`. Lowest level first, no nulls.
  * `noul`: `{"type":"noul","instructions":str,"criteria":{"true":str,"false":str} (optional),"labels":{"false":..,"true":..} (optional)}`.
  * Optional `"option_order": [permutation]` reorders the options in the input; results are un-permuted.
  * `instructions` may be a dict or list; it is JSON-encoded.
* **Return** (real output, malicious state, CPU fp32; abbreviated to two questions):

```json
{"model": "laya-rl-agent",
 "answers": {
  "matches_purpose": {"type": "noul", "noul": 0.4564, "confidence": 0.5436, "answer_confidence": 0.5436,
                      "action": {"act_probability": 1.0}},
  "verdict": {"type": "choice", "choice": "malicious",
              "probabilities": {"benign": 0.2375, "suspicious": 0.3191, "malicious": 0.4434},
              "confidence": 0.0292, "answer_confidence": 0.4434, "action": {"act_probability": 1.0}},
  "severity": {"type": "score", "score": 1.5906, "legend": {"0": "none", "1": "low", "2": "high", "3": "critical"},
               "probabilities": {"0": 0.2351, "1": 0.2024, "2": 0.2995, "3": 0.2631},
               "confidence": 0.0074, "answer_confidence": 0.2995, "action": {"act_probability": 1.0}}},
 "usage": {"input_tokens": 1274, "output_tokens": 0, "state_tokens": 216, "state_tokens_dropped": 0,
           "truncated": false, "truncated_questions": []}}
```

The full output for all 5 questions and both states is in `ml/research/results/laya_cpu4_fp32.json`. Field
meanings [src `_decode_answers`]:

| Field | Meaning |
|---|---|
| `choice` | argmax label |
| `probabilities` | **all options**, rounded to 4 decimals. Score keys are `"0".."k-1"` |
| `score` | for score questions: the **expected value** Σ i·p_i (a float, not the argmax) |
| `noul` | P(true). No `probabilities` dict for noul |
| `confidence` | for noul: max(p). For choice/score: `1 - H(p)/log k`, documented as *not* calibrated |
| `answer_confidence` | max(p). This is the quantity temperature scaling fits |
| `action.act_probability` | softmax of a 2-way "act vs escalate" head (`act_costs: {"escalate": 0.5}`). It was 1.0 in every run; not useful to Vigil |

### 3.3 Input construction, lengths, truncation [src `common.build_head` / `build_sequence`]

One sequence is built **per question**:

```
[CLS] "{type} question: {instructions}" [SEP] [MASK] " opt0" [MASK] " opt1" ... [SEP] {state} [SEP]
```

* `type` is the literal `choice` / `score` / `noul`.
* How each option is rendered:
  * choice: the label, or `"label: description"`.
  * score: `"level {i}: {text}"`.
  * noul: always two options in the order **[false, true]**, rendered `"false: no, the statement does not hold"`
    and `"true: yes, the statement holds"` (or the given criteria).
* Each option is truncated to **48 tokens**.
* If the options exceed `head_max_len` (256) - 16 tokens, each option is cut to
  `max(4, (head_max_len-16)//n_opts)` tokens. Identical spans are reported in `usage.options`.
* The instruction is truncated to `max(8, remaining head budget)`.
* State room = `max_len - len(head) - 1`. Strings and dicts keep the **start** (right-truncation); lists keep the
  end. Dropped tokens are reported in `usage.state_tokens_dropped` / `truncated` / `truncated_questions`.
* With Vigil's questions the head costs 25–50 tokens, so the room is about 975 state tokens. The "~768" in spec
  12.1 is the worst case, when the head uses its full 256 tokens.
* All question rows of one state run in **one padded forward pass** (batch = number of questions; padded to the
  longest row).
* The decision head adds a per-type embedding (`type_emb[qtype]`) to every hidden state. It then runs 2
  transformer layers, gathers the hidden state at each `[MASK]`, and applies the scorer, which gives one logit per
  option. Padding markers are filled with -1e4.

### 3.4 Probabilities, temperatures, calibration [src `_decode_answers`, `calibrate.py`]

* `p = softmax(logits / T)`. `T` comes from `temperature_by_options[temp_bucket(qtype, k)]` if that bucket exists,
  else from `temperature[qtype]` (the order is choice, score, noul).
* Buckets: `"{type}:{2 | 3-5 | 6-10 | 11+}"`. Every T is clamped to **[0.5, 5.0]**.
* The shipped typed-decisions temperatures:
  * `temperature = [1.0148, 1.0374, 1.0575]`.
  * `temperature_by_options`: `choice:2` 1.906, `choice:3-5` 1.760, `choice:6-10` 1.000, `choice:11+`
    0.1006→**clamped to 0.5**, `score:3-5` 1.251, `noul:2` 1.983.
  * For Vigil's questions that gives: matches_purpose T=1.983, verdict 1.760, tactic 1.000, severity 1.251,
    action 1.760.
* The model card itself says these are **not trustworthy**: the bucket map was inherited from the base model, and
  the per-type values were fitted on training data. "Treat its confidence as uncalibrated."
* Built-in calibration tools:
  * `laya.calibrate.records_from_labeled(agent, [(state, questions, targets)])` returns
    `(qtype, logits, target, k)` records.
  * `agent.fit_temperatures(records)` uses LBFGS on log T with NLL. It fits per-type scalars (at least 10
    records each) and per-bucket temperatures (at least **2,000** records per bucket).
  * `agent.save_calibration(path)` / `laya.load(..., calibration=path)` read and write
    `{"version":2,"temperature":[3],"temperature_by_options":{...},"model_id_or_path",...}`.
  * Also available: `fit_abstention_thresholds`, `fit_binning_map`, per-language temperatures and a
    `min_confidence` gate.
* **None of this is per question id.** Vigil's per-question T (spec 12.2) must be applied outside the library.
* **Full per-option distribution:** choice and score already list every option. For noul use
  `{"true": noul, "false": 1 - noul}`.
* **Raw logits** (needed for Vigil's own per-question calibration). This uses the same private path as
  `records_from_labeled`:

```python
from laya.common import collate_items
from laya.agent import _option_logits
ids = list(questions); internal = {q: agent._to_internal(questions[q]) for q in ids}
items = agent._encode_state(state, ids, internal)
logits, _ = agent._forward(collate_items([items], agent.tok.pad_token_id))
rows = _option_logits(logits, items, 0)      # rows[j] = logits of question ids[j]; noul rows are [false, true]
```

### 3.5 Batching and other runtime features

* `predict_batch(states, questions, batch_size=None, sort_by_length=False, ...)` packs many states into shared
  forward passes and returns results in input order.
* `predict_long(state, questions, window, stride, aggregate)` scans documents longer than the context.
* `Agent` is thread-safe for inference (read/write gate). A GPU OOM triggers a scoped CPU fallback.
* Also present: hooks (`on_predict_start/end`), `decide()` for JSON-schema/pydantic output, a Router for
  language routing, an HTTP server (`laya[serve]`), MCP, and integrations.
* `laya` CLI: one-shot or `--batch FILE|-` (reads all of stdin, then exits). It is **not** a persistent stdio
  server.

---

## 4. opendecider 0.6.0 API (from source)

### 4.1 Loading

```python
from opendecider import load, Choice, Score, Noul
model = load("manjunathshiva/opendecider-nano", device="cpu", revision="beeeb640...", dtype=None)
# dtype: None/"float32" (default, "as evaluated") | "bfloat16". device: "cuda"|"mps"|"cpu"|None (auto).
# A local folder containing opendecider.json loads offline: load("./nano").
```

* `opendecider.json` has `"kind": "nano"` and `max_len` 2048.
* `NanoModel` loads `AutoModel` (the Ettin encoder) plus `head.safetensors` into
  `nn.Sequential(Linear(d,d), GELU, LayerNorm(d), Linear(d,1))` [src `nano.py`].
* The weights are bf16 on disk and run in fp32 by default.

### 4.2 `system_one`

```python
system_one(state, questions: dict) -> dict          # state: str, or anything JSON-serialisable
system_one_batch(states: list, questions: dict) -> list[dict]
```

* **state:** a `str` is used verbatim. Anything else goes through `json.dumps(state, ensure_ascii=False)`.
  **There is no special-token scrubbing** (section 4.5).
* **questions:** a `{qid: dict | Choice | Score | Noul}` mapping. It is the same dict schema as laya: choice
  criteria is a dict or list; score criteria is a list, lowest first; noul criteria is an optional
  `{"true","false"}`. The helper classes `Choice(instr, criteria)`, `Score(instr, levels)` and
  `Noul(instr, criteria={})` produce the same dicts.
* **Return** (real output, malicious state, CPU fp32; floats shortened):

```json
{"model": "opendecider-nano",
 "answers": {
  "matches_purpose": {"type": "noul", "noul": 0.1516, "probabilities": {"true": 0.1516, "false": 0.8484}, "confidence": 0.8484},
  "verdict": {"type": "choice", "choice": "suspicious",
              "probabilities": {"benign": 0.0468, "suspicious": 0.5363, "malicious": 0.4169}, "confidence": 0.5363},
  "tactic": {"type": "choice", "choice": "persistence", "probabilities": {"none": 0.0396, "credential_theft": 0.1878,
             "persistence": 0.4495, "command_and_control": 0.1265, "ransomware": 0.0496, "data_exfiltration": 0.0775,
             "reconnaissance": 0.0694}, "confidence": 0.4495},
  "severity": {"type": "score", "score": 3, "expected": 2.4589, "legend": {"0": "none", "1": "low", "2": "high", "3": "critical"},
               "probabilities": {"0": 0.0412, "1": 0.0473, "2": 0.3228, "3": 0.5887}, "confidence": 0.5887},
  "action": {"type": "choice", "choice": "kill_and_quarantine", "probabilities": {"allow": 0.0477, "ask_user": 0.1935,
             "block_network": 0.2904, "kill_and_quarantine": 0.4685}, "confidence": 0.4685}},
 "usage": {"input_tokens": 1264, "output_tokens": 0},
 "latency_ms": 2030.0}
```

* Here `score` is the **argmax** level and `expected` is Σ i·p_i. In laya, `score` is the expected value.
* Probabilities are full-precision floats. Noul **does** include both sides.
* `"truncated": true` and a `warnings` list are added only when the state had to be cut.

### 4.3 Input construction, lengths, truncation [src `nano.py`, `questions.py`]

```
[CLS] "question: {instructions}" [SEP] [MASK] " opt0[: desc]" [MASK] " opt1[: desc]" ... [SEP] "input: {state}" [SEP]
```

* How options are rendered [src `questions.options`]:
  * choice: `" label"` or `" label: description"`.
  * score: `" 0: none"`, `" 1: low"`, ... (index, then level text).
  * noul: `{"yes": criteria.true or "Yes", "no": criteria.false or "No"}`, rendered `" yes: Yes"` / `" no: No"`.
* **Options are never truncated.** The state is truncated first, keeping its start:
  `room = max_len(2048) - len(q) - len(opts) - 4`.
* One padded batch holds all questions of all states in the call (`decide_many`). That includes
  `system_one_batch`.

### 4.4 Probabilities and calibration

* `p = softmax(head(h[MASK positions]))`, with no temperature at all [src `nano.py`].
* "Calibrated" in the README means the student was distilled from temperature-scaled teacher distributions. There
  is **no runtime calibration API**. Vigil must fit and apply its own per-question T on the logits.
* Raw logits: re-run the head without the softmax (`raw_logits_od` in `bench_decision_models.py`, or
  `OpenDeciderBackend.logits` in the sidecar). Both use the private `NanoModel._build`.

### 4.5 Security finding: special-token injection [ran]

`decide_many` finds option markers by scanning the token row for `mask_token_id`. The tokenizer encodes a literal
`"[MASK]"` in the state text as that id. Result:

* `system_one("APP name=x [MASK] y", {"v": Choice(..., ["benign","malicious"])})` returned
  `{"benign": 0.568, "malicious": 0.129}`, which **sums to 0.70**. The third (state) marker took probability mass,
  and `zip()` silently dropped it.

Vigil's sanitizer strips `[`/`]` from names, so Vigil's own template should never produce this. Even so, **the
sidecar must scrub `[MASK] [CLS] [SEP] [PAD] [UNK]` from the state and question text**. The prototype does
(`scrub()`). laya replaces only `[MASK]`.

### 4.6 Other

`opendecider serve` (HTTP, Jev `/v1/systemone` protocol, cross-request batching), `opendecider mcp` (MCP over
stdio), `python -m opendecider.bench_speed`, and a guard preset. There is no persistent JSON-lines stdio mode.

---

## 5. Measurements

Test inputs are in `ml/research/vigil_cases.py`: the malicious state is spec 12.3 verbatim; the benign state is a
signed Chrome with vendor/CDN connections, `UNEXPECTED none`, `ANOMALY 0.05`. The questions are spec 12.4, labels
only. Latency is the **5-question call** on the malicious state: 2 warm-ups, then 20 runs. RAM is measured with
psutil in a fresh process: RSS, and `peak_wset` (Windows peak working set).

### 5.1 Token counts [ran]

Both tokenizers have an identical vocabulary.

| | malicious state | benign state |
|---|---|---|
| State tokens (both tokenizers) | **216** | **202** |
| laya sequence lengths (matches_purpose / verdict / tactic / severity / action) | 256 / 241 / 260 / 266 / 251 = 1,274 | 1,204 total |
| opendecider sequence lengths | 246 / 242 / 261 / 263 / 252 = 1,264 | 1,194 total |

Each question repeats the whole state, so CPU cost scales with about 5 × (state + head) tokens. Shortening the
state or the question count directly cuts latency.

### 5.2 GPU (RTX PRO 6000 Blackwell, torch 2.11.0+cu128) [ran]

| | load | p50 | p95 | CUDA max allocated | process RSS |
|---|---|---|---|---|---|
| laya (bf16 autocast) | 3.2 s | **21.5 ms** | 28.0 ms | 2,345 MB | 2.0 GB |
| opendecider (fp32) | 2.5 s | **28.2 ms** | 33.7 ms | 1,600 MB | 2.3 GB |
| laya GGUF f16 via `laya.exe bench --device vulkan` | – | **13.5 ms** | (best 12.8) | – | – |

The first opendecider call took 199 ms (cold kernels). The first Vulkan `daemon` call took 2.0 s (shader warm-up),
and the next took 47 ms.

### 5.3 CPU, 4 threads (`torch.set_num_threads(4)`, `OMP_NUM_THREADS=4`), Intel Core Ultra 9 285K [ran]

| Configuration | load | RSS after load | RSS after runs | peak WS | p50 | p95 | Output vs fp32 |
|---|---|---|---|---|---|---|---|
| laya fp32, cu128 wheel | 1.9 s | 2,209 MB | 2,323 MB | 3,013 MB | 2,274 ms | 2,288 ms | reference |
| laya fp32, **CPU wheel** | 2.0 s | 1,924 MB | 2,013 MB | 2,727 MB | 2,272 ms | 2,298 ms | identical |
| laya weights→bf16, CPU wheel | 2.0 s | 1,922 MB | 1,920 MB | 2,727 MB | 2,283 ms | 2,295 ms | ≤0.005 |
| laya torch dynamic int8 (encoder) | 3.2 s | 2,872 MB | 2,899 MB | 3,009 MB | 955 ms | 966 ms | **broken** (benign verdict→malicious) |
| laya ONNX fp32 (onnxruntime) | 8.0 s | 2,250 MB | 2,479 MB | 4,071 MB | 2,290 ms | 2,329 ms | ≈1e-4 |
| laya ONNX int8 (`MatMul` dynamic) | 5.4 s | 1,212 MB | 1,487 MB | 2,005 MB | 1,079 ms | 1,099 ms | **broken** (benign verdict→malicious) |
| opendecider fp32, cu128 wheel | 2.2 s | 2,118 MB | 2,238 MB | 2,260 MB | 2,012 ms | 2,040 ms | reference |
| opendecider fp32, **CPU wheel** | 2.4 s | 1,832 MB | 1,951 MB | 1,979 MB | 1,988 ms | 2,010 ms | identical |
| opendecider bf16, cu128 wheel | 2.2 s | 1,359 MB | 1,462 MB | 1,474 MB | 2,020 ms | 2,068 ms | ≤0.004 |
| **opendecider bf16, CPU wheel** | 2.2 s | **1,076 MB** | **1,151 MB** | **1,163 MB** | 2,020 ms | **2,063 ms** | ≤0.004 |
| opendecider torch dynamic int8 | 3.4 s | 2,861 MB | 3,021 MB | 3,036 MB | 749 ms | 902 ms | drift (malicious tactic→C2; benign action→block_network) |
| opendecider ONNX fp32 | 3.9 s | 1,953 MB | 2,464 MB | 2,464 MB | 2,161 ms | 2,804 ms | identical argmax |
| opendecider ONNX int8 | 3.6 s | 1,166 MB | 1,427 MB | 1,427 MB | 988 ms | 1,026 ms | drift (malicious action→block_network; probabilities move 0.05–0.27) |
| laya GGUF via `laya.exe --device cpu --threads 4` | – | – | – | – | **crash** | – | exit 0xC000001D (illegal instruction), F16 and Q8_0 |

Notes:

* **Importing torch costs 481 MB RSS with the cu128 wheel, and 192 MB with the CPU-only wheel** [ran]. Use the
  CPU wheel for the shipped sidecar.
* bf16 gave no speed-up on this CPU (no AMX/AVX-512-BF16). opendecider's README says bf16 is faster on CPUs with
  bf16 units.
* laya has no way to *load* in bf16. It builds fp32 and then copies (peak about 2.7 GB), so its RAM stays far over
  budget. Fixing that would need a custom loader [unverified].
* Torch dynamic int8 RSS is *higher*, because quantization workspace is kept. int8 also changes answers;
  upstream laya documents the same ("do not use it where the calibrated probability matters"). Not recommended
  without a full eval.
* The ONNX opendecider benchmark process also imports torch and transformers (for the tokenizer shim). A
  Rust `ort` + `tokenizers` runtime would use less memory [unverified].
* **The latency figures come from a modern 24-core desktop CPU restricted to 4 threads.** The spec's reference
  4-core / 8 GB laptop is likely slower per core, so measure on target hardware before claiming the < 3 s p95
  [unverified].

### 5.4 Spec budget check (< 1.2 GB RAM loaded, p95 < 3 s, CPU)

| Option | RAM | p95 (this CPU, 4 thr) | Verdict |
|---|---|---|---|
| opendecider-nano bf16, CPU-only torch | 1.08–1.16 GB | 2.06 s | **Meets both (thin margins)** |
| opendecider-nano fp32 | 1.8–2.0 GB | 2.0 s | RAM fails |
| laya typed-decisions (any PyTorch config) | 1.9–2.3 GB (2.7–3.0 GB peak) | 2.3 s | RAM fails |
| ONNX int8 (either) | 1.2–1.5 GB | ~1.0 s | fast, but answers drift; would need re-eval and recalibration after fine-tuning |
| ggmlc laya.exe CPU | – | – | crashes on this CPU; upstream reports 28.3 s / 7 questions on CPU |

---

## 6. Zero-shot quality (no fine-tuning) [ran]

Top answer and probability. Full distributions are in the result JSON files.

| Question | laya, malicious | laya, benign | opendecider, malicious | opendecider, benign |
|---|---|---|---|---|
| matches_purpose (yes/no) | no 0.54 | **no 0.72** ✗ | no 0.85 ✓ | **no 0.56** ✗ (weak) |
| verdict | malicious 0.44 (b .24 / s .32) | benign 0.42 (s .26 / m .32) | suspicious 0.54 / malicious 0.42 / benign 0.05 | **benign 0.84** ✓ |
| tactic | ransomware 0.27 ✗ | persistence 0.20 ✗ | persistence 0.45 (cred_theft .19, C2 .13) | **none 0.64** ✓ |
| severity (0–3) | 2: 0.30 (near-uniform) | 0: 0.53 | 3: 0.59, 2: 0.32 ✓ | 0: 0.49, 1: 0.38 ✓ |
| action | block_network 0.29 (near-uniform) | allow 0.39 | kill_and_quarantine 0.47, block 0.29 ✓ | **allow 0.66** ✓ |

Observations:

* **laya typed-decisions is near-uniform zero-shot.** Its maximum probability is about 0.3–0.5 and it gets the
  tactic wrong. That fits its card: "fine-tuned on four specific synthetic workflows. Expect it to behave like
  the base laya checkpoint, or worse, on anything else". The docs report the base checkpoints at 0.36 on
  typed-decisions zero-shot, against 0.318 for random guessing.
* **opendecider-nano is sensible zero-shot**, and clearly separates the two states on verdict, tactic, severity
  and action. Under Vigil's fusion policy (spec 10):
  * Malicious state: p_malicious 0.42 with Tier-0 rule `T0-001` fired. Rule 2 does not apply (it needs ≥ 0.85).
    Rule 3 (`p_malicious ≥ 0.50 OR p_suspicious ≥ 0.60`) also misses (0.42 / 0.54). That leads to `AskUser` with
    network hold. Any Tier-0 rule floor still applies on top.
  * Benign state: p_benign 0.84 and no rule. Rule 4 gives `Allow`.
  * So zero-shot it is a reasonable conservative default, but not decisive enough. **Fine-tuning plus per-question
    calibration is required** to reach spec 17's targets.
* **Both models fail `matches_purpose` on the benign Chrome state.** The yes/no "consistent with category"
  phrasing is the weakest question for both. The typed-decisions training data phrases noul questions as
  declarative statements with explicit true/false criteria (for example
  `"This alert reflects genuinely malicious or unauthorised activity."` with
  `criteria: {true: "...", false: "..."}`). Vigil should try that style; the fix to rely on is fine-tuning.
* **Sensitivity to option wording** (`--described` variant, one-line descriptions per option):
  * opendecider benign matches_purpose flipped to yes 0.53.
  * opendecider malicious tactic switched to credential_theft 0.37.
  * opendecider malicious action kill_and_quarantine rose from 0.47 to 0.56.
  * laya stayed near-uniform.
  * Conclusion: freeze the exact question text and options before fine-tuning, and reuse them byte-for-byte at
    runtime.
* For reference, on the public typed-decisions test split (2,000 decisions) the reported accuracies are
  laya-typed-decisions 0.766 and opendecider-nano 0.796. Both were fine-tuned on its train split [card], so these
  numbers do not transfer to Vigil's task.

---

## 7. Fine-tuning

### 7.1 laya: official recipe

Sources:

* `notebooks/laya_finetune_typed_decisions_2xT4_kaggle.ipynb` (downloaded and read in full).
* `research/scripts/finetune_single_device.py` (single GPU or CPU, the one to adapt).
* `docs/finetune.md`.
* All in `NandhaKishorM/laya` @ main, Apache-2.0.

**Data format** (one JSON object per line, `finetune_single_device.py --data dataset.jsonl`):

```json
{"state": "<string or JSON object>",
 "questions": {"verdict": {"type": "choice", "instructions": "...", "criteria": {"benign": null, "suspicious": null, "malicious": null}},
               "matches_purpose": {"type": "noul", "instructions": "...", "criteria": {"true": "...", "false": "..."}},
               "severity": {"type": "score", "instructions": "...", "criteria": ["none", "low", "high", "critical"]}},
 "gold": {"verdict": {"label": "malicious", "probabilities": {"benign": 0.02, "suspicious": 0.18, "malicious": 0.80}},
          "matches_purpose": {"label": "false", "probabilities": {"false": 0.9, "true": 0.1}},
          "severity": {"label": "3", "probabilities": {"0": 0.0, "1": 0.05, "2": 0.25, "3": 0.70}}}}
```

* This mirrors the `LocalLLaMA/typed-decisions` rows (`id, workflow, split, state, questions, gold, ...`). In that
  dataset `state`, `questions` and `gold` are JSON strings; the script expects parsed objects.
* `gold[qid].probabilities` is the **soft target**. Its keys are the choice labels; `"0".."k-1"` for score;
  `"false"`/`"true"` for noul (missing noul keys default to 0.5; missing other keys to 0.0). The target is
  renormalized.
* `label` is not used by training; the evaluation cell uses it.
* **Choice `criteria` must be a dict here.** The preprocessor reads `crit.keys()`, so list criteria would break
  `build_training_item`. Use `{label: null}`.
* **Mapping from spec 17's row** `{state, questions, labels:{qid: label}, ...}`:
  * Convert each question to the dict above.
  * Set `gold[qid] = {"label": l, "probabilities": <teacher distribution, or label-smoothed one-hot>}`.
  * Spec 17 has `teacher_label.py` produce teacher answers. Store the teacher's **probabilities**, not just the
    argmax, because RLCD trains on distributions.

**Preprocessing:**

* For every (case, question), `build_sequence(tok, state, {"t","ins","crit"}, max_len=1024, head_max_len=256)`
  produces `{"ids", "markers", "qtype", "target", "label"}`.
* Items whose marker count ≠ option count are dropped.

**Model:**

* `cfg = rl_agent_config.json` from the checkpoint, with `max_len=1024`, `head_max_len=256` and
  `max_tokens_per_batch=4096`.
* `model = build_model(cfg, encoder_dir=<ckpt>/encoder)`, then
  `model.load_state_dict(load_file(<ckpt>/model.safetensors), strict=True)`.
* On GPU: encoder `gradient_checkpointing_enable(use_reentrant=False)` and `model.head_checkpointing=True`.

**Calibration hold-out:** before training, a seeded shuffle withholds `min(400, len(items)//10)` items. They never
enter training.

**Loss (RLCD) per micro-batch:**

```python
logits, act = model(input_ids, attention_mask, marker_pos, marker_mask, qtype)   # fp16 autocast on CUDA
eps = randn((G,) + logits.shape) * sigma * mask; eps = (eps - eps.sum(-1, keepdim=True) / k) * mask   # zero-mean noise, G=4
z = logits.detach().unsqueeze(0) + eps
q = softmax(z.masked_fill(~mask, -1e4), -1)
r = proper_reward(q, target.unsqueeze(0), qtype, mask, w_sph=0.75, w_rps=1.0)    # log score + 0.75 spherical - 1.0 RPS (score qs)
adv = (r - r.mean(0)) / (std + 1e-6)
logp = -(((z - logits.unsqueeze(0)) ** 2) * mask).sum(-1) / (2 * sigma**2)
loss = -(adv * logp).mean() + 1.0 * soft_cross_entropy(logits, target) + 0.0 * act.sum()
```

**Hyperparameters:**

| Setting | Value |
|---|---|
| Epochs | 4 |
| Micro-batch | 8 sequences |
| Gradient accumulation | 4 in the notebook (effective 64 on 2 GPUs) |
| Optimizer | AdamW, weight decay 0.01, LR encoder 2.5e-5, LR head (all non-encoder params) 1e-4 |
| Schedule | CosineAnnealingLR to 1e-6 |
| Exploration σ | 0.4 → 0.1, linear over epochs |
| Gradient clipping | 1.0 |
| Precision | GradScaler, fp16 autocast |
| Runtime | about 4–6 min for 6k decisions on 2×T4; about 4–5 h for ~30k questions [card] |

**Temperature fit:**

* After training, compute fp16 logits on the hold-out set.
* Per question type, `fit_one_temp`: LBFGS (lr 0.1, 100 iterations) on log T, minimizing
  `-(T * log_softmax(Z/T)).sum(-1).mean()`.
* Clamp to [TEMP_MIN, TEMP_MAX] = [0.5, 5.0]. Fall back to 1.0 with fewer than 10 items, or 1.2 if the fit raises.
* Write the values to `cfg["temperature"]` and **delete `temperature_by_options`**. Otherwise the inherited
  bucket values override the new fit.

**Saved checkpoint** (loadable with `laya.Agent(output_dir)` / `laya.load(output_dir)`; there is no special
fine-tune API):

```
output_dir/model.safetensors        # state_dict, fp16
output_dir/encoder/config.json      # model.encoder.config.save_pretrained
output_dir/tokenizer/...            # tok.save_pretrained
output_dir/rl_agent_config.json     # cfg + fine_tuned, model_name, temperature
```

A rolling `checkpoint_latest/` is written after every epoch.

**Starting point:** fine-tune from `typed-decisions` (it already saw security-incident workflows) or from the base
English root checkpoint. Base it on an A/B test on Vigil's validation split [unverified which is better]. On this
machine's 96 GB GPU, a single-device run of the script needs no DDP [unverified runtime].

### 7.2 opendecider-nano: no official recipe

* README roadmap, "Next": "**Fine-tune nano on your own labels:** a script and a guide for adapting
  opendecider-nano to your decisions." The package contains no training code. The repo contains only
  benchmarks and the inference package. The Colab notebook is inference and serving only.
* Model provenance [card/NOTICE]: distilled from temperature-scaled Qwen3-235B and DeepSeek V4.1 Flash
  distributions, then "a short fine-tune on the typed-decisions train split". Hyperparameters are not published.
* **Unofficial recipe derived from the source** (consistent with how `NanoModel` scores; untested):
  1. Build each row with `NanoModel._build(state, instructions, options(qdict))`, which gives the token ids.
     Markers are the positions of `mask_token_id`. Note: noul options are `{"yes","no"}`; score options are
     `{"0": level0, ...}`.
  2. Logits = `head(enc(ids, mask).last_hidden_state[markers])`. Loss = soft cross-entropy against the target
     distribution, which is the same objective as laya's CE term. laya's RLCD term can be added unchanged:
     `laya.common.proper_reward` only needs logits, target, qtype and mask.
  3. Hyperparameters: start from laya's (AdamW, encoder 2.5e-5 / head 1e-4, cosine, clip 1.0, 4 epochs, bf16
     autocast).
  4. Save:
     * `enc.save_pretrained(dir)` → `config.json` + `model.safetensors`.
     * `safetensors.torch.save_file(head.state_dict(), dir/"head.safetensors")`.
     * `tok.save_pretrained(dir)`.
     * Copy `opendecider.json`, keeping `"kind": "nano"` and `"max_len": 2048`.
     * `opendecider.load(dir)` then loads it unchanged, because `NanoModel` reads exactly these files.
  5. Calibration: none at runtime. Fit Vigil's per-question T on the held-out logits (section 7.3) and apply it in
     the sidecar.
* Spec 17.5 says "using each project's official fine-tuning recipe". For opendecider this is impossible today.
  Record this as a deviation in `docs/backlog.md` / the M-plan when `ml/finetune.py` is written.

### 7.3 Per-question calibration for Vigil (`calibrate.py`)

1. Run the fine-tuned model on the **val** split (family-disjoint) and collect raw logits per question id. The
   sidecar returns them (`answers[i].logits`), as does `bench_decision_models.py`.
2. For each question id, fit a scalar T by NLL with LBFGS on log T. Reuse `laya.calibrate.fit_one_temperature`
   with `min_n` set to your sample size. It is library-agnostic: it takes `(logits, target)` pairs. Clamp T to
   [0.5, 5].
3. Store `{question_id: T}` in Vigil config. The sidecar (or Rust) computes `softmax(logits / T)`. Report ECE and
   Brier before and after, on the **test** split.

---

## 8. Runtime and packaging options

### 8.1 Python sidecar (recommended)

* Works for both models with identical outputs to the libraries [ran: `test_sidecar.py`].
* About 2.2–3.3 s cold start on this machine. The process can be unloaded after 10 min idle (spec 12.2) by simply
  terminating it.
* Ship a pinned, self-contained environment: an embeddable CPython plus a wheelhouse with the **CPU-only torch
  wheel**, `transformers`, `tokenizers`, `safetensors`, `numpy`, and `opendecider` (or `laya`). The models go in a
  local directory, and the sidecar runs with `HF_HUB_OFFLINE=1`.
* **Smart App Control risk [ran]:**
  * `torch 2.14.1+cpu` was **blocked** (`OSError: [WinError 4551] An Application Control policy has blocked this
    file ... torch\lib\shm.dll`), both in the scratchpad and inside the project directory.
  * `torch 2.11.0+cpu` and `2.11.0+cu128` loaded fine.
  * The DLLs are unsigned. SAC appears to judge by reputation, so newly released builds can be blocked on end-user
    PCs. Pin wheels that already have reputation, test the bundle on a SAC-enabled machine before each release, and
    surface a clear error when the sidecar fails to start (`os error 4551`).

### 8.2 ONNX

* **laya:** official exporter `scripts/export_onnx.py` (repo only, not in the wheel). It calls `torch.onnx.export`
  on `agent.model` (opset 18) with:
  * inputs `input_ids, attention_mask (int64 [B,S]), marker_pos (int64 [B,K]), marker_mask (bool [B,K]), qtype (int64 [B])`;
  * outputs `logits [B,K], act_logits [B,2]`;
  * dynamic B, S and K;
  * optional `--quantize` (int8 `MatMul` dynamic, `per_channel=False`).
* Runtime: `laya.onnx_agent.ONNXAgent(checkpoint_dir, onnx_path=...)` (extra `laya[onnx]`) reuses the same
  tokenization, temperatures and answer shape.
* There is also a TypeScript port, `laya-ts` (ONNX).
* The export of typed-decisions **worked with torch 2.11** (1.6 GB fp32 graph). Its outputs matched PyTorch to
  about 1e-4, but it was neither faster nor smaller on CPU (section 5.3).
* Community ONNX exports exist only for the English and multilingual laya checkpoints (for example
  `onnx-community/laya-multilingual-ONNX`), not for typed-decisions.
* **opendecider:** no ONNX support in 0.6.0 (README roadmap: "In progress"). Our wrapper exports
  `(input_ids, attention_mask, marker_pos) → logits` (`onnx_export_bench.py`). It matched PyTorch.
* ONNX would allow a pure Rust runtime (`ort` crate + `tokenizers` crate) instead of Python. But:
  * fp32 graphs are about 1.6 GB, so they miss the RAM budget;
  * int8 graphs fit RAM and are 2× faster, but change answers;
  * the token-sequence construction (sections 3.3 / 4.3) would have to be re-implemented in Rust exactly.
  * That makes ONNX a later optimization, not the first integration [recommendation].

### 8.3 GGUF / ggmlc (`mys/laya-typed-decisions-GGUF`)

* These are not llama.cpp files. They are compiled by **ggmlc** (`https://github.com/monatis/ggmlc`, example
  `examples/laya`, C++). The latest release is **v0.9.7** (2026-10-01).
* Assets: `laya-windows-x86_64-{cuda-sm86, cuda-sm89, vulkan}.zip`, `laya-linux-x86_64-{cuda-sm80/86/89, vulkan}`,
  `laya-macos-arm64-metal`. There is **no CPU-only Windows build and no sm120 (Blackwell) CUDA build**.
* License: MIT is claimed in `pyproject.toml` and the README, but **there is no LICENSE file** (section 1.1).
* The GGUFs predate the `ggmlc.decision` metadata key. The binary falls back to a built-in Laya preprocessor
  (`recipe=laya-compat`, template `[CLS] {qtype} question: {instructions} [SEP] ([MASK] {option})* [SEP] {state} [SEP]`,
  `max_opts=16`, `max_batch=8`, temperatures read from the GGUF) [ran `laya.exe info`].
* The C++ engine **does not clamp** temperatures (Python clamps `choice:11+` 0.1 → 0.5) [src `engine.cpp`]. This
  only matters for 11+ options.
* CLI [src `main.cpp`, ran]:
  * `laya.exe help | list-presets | info <gguf> | detect-lang`
  * `laya.exe decide <gguf> [--state <JSON|TEXT> | --state-file <PATH>] [--questions <JSON> | --questions-file <PATH>] [--preset NAME] [--text STR] [--family auto|english|multilingual|typed-decisions] [--models-dir DIR] [--json] [--device auto|cpu|cuda|cuda:0|metal|vulkan|vulkan:0] [--threads N (default 4)] [--cuda-graph] [--max-batch N]`
  * `laya.exe bench <gguf> ... [--warmup N] [--runs N]`
  * `laya.exe serve <gguf> [--port P] ...`: TypeSafe-compatible `POST /v1/systemone`, `/v1/decide`,
    `/v1/decide/batch`, Decision Studio at `/`. `LAYA_API_KEY` enables bearer auth.
  * `laya.exe daemon <gguf> [--device ..] [--threads N]`: newline JSON-RPC on stdin/stdout.
* **Daemon contract** [ran, Vulkan, Q8_0]:
  * On start the daemon prints `{"status":"ready","model":"laya"}`.
  * Request: `{"id":"mal","state":"APP name=...","questions":{"verdict":{"type":"choice","instructions":"...","criteria":[...]}, ...}}`.
    `preset` and `text` are optional.
  * Response:
    `{"model":"laya-typed-decisions","family":"typed-decisions","route":"forced typed-decisions","answers":{...same shape as Python laya, plus "probabilities" for choice/score; noul has only "noul"...},"usage":{"input_tokens":1274,"output_tokens":0,"latency_ms":2007.29},"id":"mal"}`.
  * Errors: `{"error":"..."}` for unparseable JSON; `{"id":...,"error":"missing questions"}`.
  * A JSON string state is passed through raw, the same as Python.
* **Results [ran]:**
  * Vulkan F16: 13.5 ms p50 for the 5 questions. Q8_0 Vulkan matched Python within about 0.02 (tactic 0.259 vs
    0.275).
  * **`--device cpu` crashed** with exit code `0xC000001D` (STATUS_ILLEGAL_INSTRUCTION) for both F16 and Q8_0 on
    the Core Ultra 9 285K (no AVX-512). The prebuilt CPU backend appears to be compiled for an ISA this consumer
    CPU lacks [inferred from the exit code].
  * Upstream's own README table: "`laya.exe` CPU 4 threads … 28.3 s (1 forward)" for the 7-question email preset,
    against 2.26 s for Python CPU.
  * The unsigned `laya.exe` was **not** blocked by SAC when launched from PowerShell. Launching it from Git Bash
    gave "Permission denied", probably a tool-sandbox artifact, not SAC [unverified].
* Conclusion: there is no GGUF build of opendecider-nano. The opendecider GGUFs are for the 4B Qwen models via
  llama.cpp, LM Studio or Ollama.

---

## 9. Recommended integration: Python sidecar, protocol v1

A working prototype is in `ml/research/decision_sidecar.py`, with a test driver in `ml/research/test_sidecar.py`.
Both backends were verified end to end on CPU and GPU [ran].

### 9.1 Process model (maps to spec 12.2)

* Rust's `DecisionSidecar` implements `DecisionModel`. On first use it spawns:
  `<bundle>/python.exe decision_sidecar.py --backend opendecider --model-dir <models>/opendecider-nano --device cpu --threads <n> [--calibration <cfg.json>]`.
* Before spawning, Rust verifies the sha256 of every model file and of the sidecar script.
* The sidecar sets `HF_HUB_OFFLINE=1` and `TRANSFORMERS_OFFLINE=1` and loads only from `--model-dir`. It lowers
  its own priority to BELOW_NORMAL (nice 10 on Unix). Rust should *also* create it at low priority and block its
  network access (spec 12.2 sandboxing).
* stdout carries only protocol lines; stderr carries logs, which Rust forwards to tracing. Both are UTF-8,
  one compact JSON object per line.
* One request is in flight at a time; Rust serializes on a dedicated thread (spec 12.2). The `id` field allows
  pipelining later.
* Timeouts: wait for the `ready` line for up to 60 s. Each `decide` gets 10 s, matching spec 10's network-hold
  window. On a timeout or a broken pipe, kill the process, fall back to `AskUser`, and respawn lazily.
* Idle unload: after 10 min with no requests, send `{"op":"shutdown"}`, wait 2 s, then kill. EOF on stdin also
  makes the sidecar exit 0.

### 9.2 Messages

**Ready line** (sidecar → Rust, once):

```json
{"type":"ready","protocol":1,"backend":"opendecider","model":"opendecider-nano","device":"cpu","threads":4,"max_len":2048,"load_ms":2279}
```

**Decide request** (Rust → sidecar). The questions are an **ordered array** that mirrors
`Question { id, kind: QKind, text }`:

```json
{"id":"7f3c","op":"decide","state":"APP name=PDFViewerPro.exe category=pdf_reader ...\nANOMALY 0.93",
 "questions":[
  {"id":"matches_purpose","kind":"yes_no","text":"Is this behavior consistent with what an application of this category normally does?"},
  {"id":"verdict","kind":"choice","text":"Overall, is this activity benign, suspicious, or malicious?","options":["benign","suspicious","malicious"]},
  {"id":"tactic","kind":"choice","text":"Which attacker goal does this activity most resemble?","options":["none","credential_theft","persistence","command_and_control","ransomware","data_exfiltration","reconnaissance"]},
  {"id":"severity","kind":"score","text":"How severe would the impact be if this is malicious? 0 none, 1 low, 2 high, 3 critical.","options":["none","low","high","critical"]},
  {"id":"action","kind":"choice","text":"What should a careful security analyst do right now?","options":["allow","ask_user","block_network","kill_and_quarantine"]}]}
```

Field rules:

* `kind` is `yes_no`, `choice` or `score`.
* For `score`, `options` lists the level labels from `min` to `max`. Rust's `QKind::Score{min,max}` maps to
  `max-min+1` labels, and option i means level `min+i`.
* `yes_no` takes no `options`; its labels are always `["yes","no"]`.
* Validation, each failure returning `bad_request`: non-empty state; unique, non-empty question ids; at least 2
  unique options; no tokenizer special tokens in options.
* The sidecar removes `[MASK] [CLS] [SEP] [PAD] [UNK]` from `state` and `text` (section 4.5).

**Decide response** (real output, opendecider, CPU; trimmed to two answers):

```json
{"id":"7f3c","ok":true,
 "answers":[
  {"id":"matches_purpose","labels":["yes","no"],"logits":[-1.5754,0.1463],"probs":[0.151650,0.848350],"temperature":1.0},
  {"id":"verdict","labels":["benign","suspicious","malicious"],"logits":[-2.0628,0.376,0.1242],"probs":[0.046799,0.536299,0.416902],"temperature":1.0}],
 "usage":{"state_tokens":216,"input_tokens":1264,"truncated":false},
 "latency_ms":2020.7}
```

* `answers` keeps the request's order, and `labels`, `logits` and `probs` are aligned. That maps directly to
  `Answer { id, probs: Vec<(String, f32)> }` via `labels.zip(probs)`.
* `probs = softmax(logits / temperature)`. `temperature` is the per-question value from `--calibration`
  (`{"verdict": 1.4, ...}`). If a question has none: 1.0 for opendecider; laya's built-in bucket/type temperature
  for laya.
* `logits` are always the raw, uncalibrated values. `calibrate.py` fits on them, and Rust may recompute the
  probabilities if it stores T itself.
* `usage.truncated == true` means the state did not fit. Rust should log it, and the state builder should have
  trimmed lower-severity lines first (spec 12.3).

**Other ops:**

```json
{"id":"p1","op":"ping"}        ->  {"id":"p1","ok":true,"pong":true}
{"id":"s1","op":"shutdown"}    ->  {"id":"s1","ok":true}              (process then exits 0)
```

**Errors** (the process stays alive):

```json
{"id":"x","ok":false,"error":{"code":"bad_request","message":"question 'q': 'options' must list >= 2 non-empty strings"}}
{"id":null,"ok":false,"error":{"code":"bad_request","message":"Expecting property name enclosed in double quotes: line 1 column 2 (char 1)"}}
{"id":"y","ok":false,"error":{"code":"internal","message":"..."}}
```

Planned extension (not in the prototype): `{"op":"decide_batch","states":[...],"questions":[...]}` returning
`results:[...]`, built on `system_one_batch` / `predict_batch`. It is useful for the install-time profile
(spec 12.5) and for `evaluate.py`.

### 9.3 `max_state_tokens()` for the Rust trait

* opendecider: `2048 - max over questions of (len(question tokens) + len(option tokens) + 4)`. That is about 2,000
  for Vigil's questions.
* laya: `1024 - len(head) - 1`, where the head is at most 256 + 3 tokens. That is about 975 for Vigil's questions,
  and 765 in the worst case.
* Unit-test the Rust state builder against the HF tokenizer. The `tokenizers` Rust crate can load the
  `tokenizer.json` shipped with each model; both models share the same vocabulary. The test should check that the
  state never truncates (`usage.truncated == false`).

---

## 10. Open items and caveats

1. **Measure CPU latency on real 4-core / 8 GB target hardware.** All CPU numbers here come from a Core Ultra 9
   285K limited to 4 threads.
2. **opendecider fine-tuning is unofficial.** Section 7.2 is derived from source and untested. Spec 17.5's
   "official recipe" requirement cannot be met for opendecider until upstream ships one.
3. **Zero-shot results come from two hand-written states.** They show direction, not accuracy. Decide only on
   Vigil's family-split eval (spec 17.6).
4. **The opendecider bf16 RAM fit is thin** (1.16 GB peak against a 1.2 GB limit). It depends on the CPU-only torch
   wheel and on the transformers version. Add a RAM regression test to the perf suite.
5. **Licenses to review before shipping:**
   * certifi and tqdm (MPL-2.0);
   * Intel OpenMP DLL in the torch CPU wheel [unverified terms];
   * CC BY-SA-derived training data behind opendecider-nano;
   * ggmlc's missing LICENSE file.
6. **Smart App Control:** a newly released unsigned torch build (2.14.1+cpu) was blocked. Pin and test wheels on a
   SAC-enabled Windows machine before each release.
7. **Both libraries are young and move fast** (laya 0.3.x and opendecider 0.6.x released within weeks). The
   sidecar uses private helpers (`Agent._encode_state`, `_forward`, `agent._option_logits`, `NanoModel._build`).
   Pin exact versions, and keep a parity test comparing sidecar probabilities with `predict()` / `system_one()`.
