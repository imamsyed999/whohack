# Local decisions

whohack's service runs natively on Windows. The optional Python model is also a
native Windows CPU process; WSL is only an optional build host.

`tools/ml/prepare_model.py` pins an existing local installation, its script,
tokenizer, configuration and safetensors weights. Set `[decision] manifest` in the
service config to its JSON output. No model or package is downloaded by the
service. A changed file fails verification before startup. Python's offline flags
and audit hook reject Python network operations; these are **not an OS sandbox**.
An OS-enforced serving sandbox remains a release gate for privileged deployment.
Windows jobs bound the child tree and terminate it on service exit. The model tree
is rechecked before every child start, including after idle unloading. Symlinks,
pickle/code files, unexpected files and oversized trees are refused.

Laya uses `rl_agent_config.json`, `encoder/` and `tokenizer/`; OpenDecider uses
root-level config/tokenizer files and separate model/head safetensors. Laya serving
requires float32. Older tokenizer metadata must be migrated before pinning with
`prepare_model.py --backend laya --normalize-laya-tokenizer ...`; the sidecar
refuses metadata that its library would rewrite during startup.

Five typed questions, their label order and the Tier 1 feature order can be
exported with `whohack-service --model-contract`. Replay uses the same Rust state
builder and 60-second windows as live alerts:

```powershell
python tools/beacon-sim/beacon_sim.py --fast --output .vigil/beacon.jsonl
target/debug/whohack-service.exe --replay .vigil/beacon.jsonl --category pdf_reader
target/debug/whohack-service.exe --replay .vigil/beacon.jsonl --category pdf_reader --model-manifest .vigil/models/opendecider-manifest.json
# Include the deployment's Tier 1 model and rule configuration:
target/debug/whohack-service.exe --replay .vigil/beacon.jsonl --category pdf_reader --config .vigil/windows/config.toml
```

Replay never applies a response. States exclude command lines, raw domains, URLs,
file contents and user directories. Network evidence is aggregated into classified
counts and ports; child evidence currently includes parent/current basenames and
the child count. Missing byte telemetry remains explicit. Exact tokenizer checks
reject oversized state rather than silently discard evidence. Automatic compaction
and a complete child-name/flow state require further measured tokenizer work.

The worker has a 32-case queue, expires queued cases after 10 seconds, validates
all five complete probability distributions, and unloads an idle model after 10
minutes. Serving includes pin verification and startup in the ten-second request
deadline. Slow cold loads produce a review alert while the loading process remains
available for the next case, for up to 60 seconds; they do not restart endlessly.
Windows child processes run
hidden and below normal priority. Rules are evaluated immediately; model inference
does not run on the collection or store-writer thread.

Unqualified checkpoints are advisory. A manifest may reference a pinned evaluation
report and per-question temperature calibration only after held-out family tests,
human review, false-positive, latency and memory gates pass. Qualified model
reports must include at least 100 malicious cases from five families, 200 benign
cases, the benign-week evidence and the exact operating thresholds. A report's
`passed` field alone cannot qualify a model. Qualified model
fusion preserves every rule floor. Prompt mode automatically applies at most a
network block; stronger recommendations require the user's choice. Temporary holds
are retained on uncertainty and visible in Responses. Monitor mode applies no
response. User resolution/trust changes take precedence over late model results.

`decisions` stores sanitized input, primary and optional secondary answers, fused
answers, model/revision, failures, recommendation and actual action. The alert's
Decision evidence panel exposes this record. No model answer automatically adds a
trust rule or behavior permission.

The optional `[decision] tier3_manifest` uses the same pinned typed-protocol adapter,
checks physical RAM of at least 16 GiB in the child, and blends ambiguous results
with weights 0.4/0.6. A larger GGUF decision model still needs a separately verified
adapter; the Python adapter only supports the documented Laya/OpenDecider contracts.

Validation on this development PC (2026-10-13): workspace tests and Windows/Linux
Clippy passed; native Windows CPU OpenDecider with bf16 loaded in about 10.7 seconds
on its first standalone invocation. One-question inference took 294 ms. These are
runtime smoke results, not the required five-question p95 or detection-quality
acceptance. The base model was uncertain on a synthetic credential-access fixture.
Its weights match revision `beeeb640f3333aec4ef78ed3b7bd0605f973a590` and the hashes in
the research report. No calibrated protection claim is made.
The full five-question synthetic test failed qualification; see
[the current evaluation](../ml/reports/eval.md). A later seven-event native replay
using the trained ONNX score and pinned OpenDecider produced six complete answers
and one cold-load review case. Replay applied no OS response.

Upstream contracts checked: [OpenDecider Python API](https://manjunathshiva.github.io/opendecider/reference/python-api/)
and the installed pinned `opendecider==0.6.0` source. Existing research documents
explain why the Windows GGUF candidate was not selected.
