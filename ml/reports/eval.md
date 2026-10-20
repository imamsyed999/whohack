# Local evaluation — not qualified

The newer **2026-10-18 Laya candidate** completed a full-encoder fine-tune using
893 synthetic cases, with separate training, checkpoint-selection, calibration
and test families. The 190-case test gave 90% verdict/action accuracy and 70%
tactic accuracy. It remains unqualified: there is no reviewed real-world data,
and the native CPU check measured 3.49 s p95 / 2.66 GB peak process-tree RAM,
exceeding the existing budgets. See the [complete run record](../../docs/plans/M13-laya-training.md).
The older OpenDecider measurements below are historical; these different datasets
and models do not establish a controlled comparative improvement.

Fresh verification on 2026-10-14 ran all 15 synthetic test cases through both
the pinned base checkpoint and the existing one-step head. Both still have
benign FPR 1.00 and fail qualification. Base p95 was 2328 ms with 1217.51 MB RSS;
head p95 was 2344 ms with 1217.32 MB RSS. These are development-machine samples,
not proof of an accuracy improvement or a controlled hardware benchmark. See
[the current readiness assessment](../../docs/readiness-2026-10-14.md).

Recorded 2026-10-13 on the development Windows x64 PC. These results exercise implementation mechanics with synthetic cases, not real-world detection accuracy. The runtime model is disabled in the normal preview.

## Dataset and model

80 synthetic cases passed the Rust state builder: 50 training, 15 validation and 15 test, with distinct family/application/state identities across splits. The test set contains eight malicious-label and seven benign-label cases. Human-reviewed fraction: 0%. No measured benign week or representative 200-app corpus is available.

CPU OpenDecider, four threads, bf16, revision `beeeb640f3333aec4ef78ed3b7bd0605f973a590`. The following base-checkpoint evaluation is not the one-step fine-tuned smoke checkpoint:

- Weights SHA-256: `da243ae586e17ee87b5aa68e1bd06112c1c4cf756ea651d335ae7a2d6097cb38`
- Head SHA-256: `b57ad139c1ca8984a5205dc57aebeb921c9c59eaa536880d6b5e81d7734eee56`
- Dataset SHA-256: `ab6b3647765af0b42fa97e36be21aa1e8811e315ec1c250c1af5901f2a883f78`
- Predictions SHA-256: `9d600a55e8483978c7442fc9a86a1920face7036895fbb8e155b08a77c91f6db`

The evaluation predictions did not use a pinned calibration file. A validation-only calibration artifact was generated separately and has not qualified a release model.

## Measurements

| Question | Accuracy | Brier score | ECE |
|---|---:|---:|---:|
| Matches purpose | 0.5333 | 0.6149 | 0.4581 |
| Verdict | 0.0000 | 0.6994 | 0.5074 |
| Tactic | 0.4667 | 0.5903 | 0.4731 |
| Severity | 1.0000 | 0.5007 | 0.6048 |
| Action | 0.0000 | 0.7435 | 0.3276 |

At the evaluator's blocking threshold, malicious recall was 1.00 and benign false-positive rate was also **1.00**. Blocking everything passes recall alone; it is unusable protection.

Five-question CPU p50 was 3453 ms, p95 was 4297 ms, and peak measured process-tree RSS was 1217.08 MB. Measurements include the actual Windows child behind the virtual-environment redirector. Earlier measurements of the redirector alone are invalid. Concurrent compilation was active, so this is not a controlled hardware-budget benchmark.

Alerts per benign week: unavailable. The gate requires at most one alert over a measured 168-hour, 200-app replay. Current result: **NOT QUALIFIED**. It fails representative-data, human-review, sample-size, calibrated-identity, false-positive, benign-week, CPU latency and memory gates. No automatic protection was enabled on this evidence.

## Training and export mechanics

LightGBM 4.7.0 plus 16 benign isolation trees produced a 14,728-byte ONNX artifact with 64 supervised trees, 17 inputs and one score. Maximum validation difference from the Python reference was `2.6406547615209774e-8`. Rust loaded the pinned model successfully. Artifact SHA-256: `b9ca85860013647d645a66382c144b60f8ac0792d86df893586ccb0fae870e53`. It is synthetic and unqualified.

A one-step CPU OpenDecider head update saved a safetensors checkpoint that reloaded and produced typed predictions. This checks the training/save/load path; no accuracy improvement is claimed. The installed Laya 0.3.24 package lacks the published training module, so its export adapter reports that limitation.

The current Tier 1 release microbenchmark (WSL, one thread, 3,000 timed samples after warm-up, saturated 2,048-event window) measured p50 25.938 µs and p95 33.591 µs against the 50 µs target. It includes window aggregation and heuristic scoring, not model inference or end-to-end service latency.

## Reproduction

Local generated evidence is under `.vigil/checks/training/`: `dataset.jsonl`, `base-predictions.jsonl`, `evaluation.json`, `tier1.json`, `tier1.onnx` and the isolated head checkpoint. These generated artifacts and large weights are not committed or included in the Windows package.

Run the commands in [training.md](../../docs/training.md), then:

```powershell
python ml/evaluate.py .vigil/checks/training/dataset.jsonl .vigil/checks/training/base-predictions.jsonl --output .vigil/checks/training/evaluation.json
```

Exit status 2 is expected for this unqualified result. Qualification needs representative, consented telemetry/reports, resolved human review, validation-only calibration, untouched family-held-out tests and independent benign-week/performance measurements.
