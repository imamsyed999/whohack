# M13 — bounded Laya training and approved cache cleanup

On 2026-10-18 the maintainer explicitly approved removal of the previously
identified build/test caches and requested substantial Laya fine-tuning with
VRAM below 50 GB. Laya is the intended model name, not Luna. Preserve the native
Windows app, model checkpoints, evidence, quarantine and unrelated work.

Machine: RTX PRO 6000 Blackwell, 102,641,500,160 CUDA-visible bytes, about 128 GiB
system RAM. Use a much smaller training allocator budget, small micro-batches,
gradient checkpointing, memory/temperature monitoring and bounded runtime/output.
The 50 GB ceiling means 50,000,000,000 bytes, not 50 GiB. Other applications can
allocate VRAM independently; this job can stop itself, not control those apps.

Current evidence: 80 synthetic cases, no reviewed cases and no production ML
decisions/feedback. The saved OpenDecider one-step smoke checkpoint is not a Laya
security fine-tune. Training cannot establish protection against every unknown
attack or file type. Keep candidate weights unqualified and automatic model-driven
response disabled unless representative evaluation passes the existing gates.

Implementation:

- Use existing CUDA/Python dependencies. Install only the verified small Laya
  0.4.11 wheel into an isolated overlay; preserve the pinned serving environments.
- Acquire only the five required typed-decisions files at Hugging Face revision
  `7b928d828b7b0e022f929d9bd2e44165aa270148`, checking the published weight hash.
- Create clearly synthetic, balanced security scenarios via native Rust replay,
  including benign downloads and ambiguous activity; keep scenario/app/state
  identities separate across train, validation and test. Do not fabricate human
  review or present simulated events as observed attacks.
- Train the complete Laya encoder and decision head using its pinned official
  training API. Validate after each epoch, retain one best checkpoint, stop on
  deterioration and calibrate separately. Evaluate the untouched test partition
  only after selecting the checkpoint. Save provenance and resource measurements.
- Preserve failed qualification as a failed result. No model is enabled in Vigil
  automatically. No raw telemetry or user files are uploaded; no malware runs.

Validate dataset leakage and label coverage, resource-limit decisions, bounded
checkpoint retention and evaluation honesty. Reuse native binaries; do not
recreate the deleted Rust caches for this Python/model-only change.

Primary references checked:
[official Laya training](https://github.com/NandhaKishorM/laya/blob/main/docs/finetune.md),
[model repository](https://huggingface.co/convaiinnovations/laya),
[PyTorch allocator limit](https://docs.pytorch.org/docs/main/generated/torch.cuda.memory.set_per_process_memory_fraction.html).

Cleanup: raw PowerShell deletion was refused by automatic approval review, even
after explicit approval and a single-file attempt ("blocked by policy"). Cargo's
own verified-cache cleanup succeeded for both WSL target directories and the
native UI debug directory. Cargo refused the staged native target directory
because it has no cache marker; do not fabricate one or bypass that guard.
The remaining copied test artifacts need a user-run cleanup if tool policy
continues to deny it. WSL filesystem space is reusable after cache removal;
physical VHD compaction has not been performed.

## Completed local run, 2026-10-18

The full Laya encoder and head trained successfully: **421,293,827 trainable
parameters**, five epochs, 345 optimizer updates, 328.44 seconds. Checkpoint
selection retained epoch two (138 updates); three later epochs failed to improve
selection loss, so early stopping prevented needless additional training. The
checkpoint's weights differ from the base. No model was enabled in the live app.

Dataset: 893 authored synthetic cases, 47 recipe families, 19 categories. Splits
are 437 training, 133 selection, 133 calibration and 190 test cases. Training
includes every contract label. Application hashes, recipes and exact states stay
separate across all four roles; shared behavior primitives remain a limitation.
Zero cases have accepted human review. Downloaded-input extensions in the inert
metadata do not exercise real media parsers or prove file-format coverage.

Resource measurements:

| Measurement | Observed | Guard |
| --- | ---: | ---: |
| Total GPU memory, including other apps | 14.78 GB peak | Stop at 45 GB; requested ceiling 50 GB |
| PyTorch allocated / reserved | 8.35 / 9.11 GB peak | 16 GB allocator cap |
| Training process RAM | 3.89 GB peak | 24 GB ceiling |
| GPU temperature | 71 C peak | Stop at 82 C |
| Available host RAM | 90.30 GB minimum | Stop below 16 GB |
| New retained training files | 1.70 GB total | One base plus one candidate, small tools/data |

Checkpoint saving briefly used 1.69 GB inside the run directory while replacing
the previous best file; final run directory is about 847 MB. No series of epoch
checkpoints, duplicate large dependency environment or new Rust caches was created.
The GPU guard never tripped. These observations do not guarantee crash immunity.

Untouched synthetic test results after separate calibration:

| Question | Accuracy |
| --- | ---: |
| Matches application purpose | 100% |
| Benign / suspicious / malicious | 90% |
| Attacker tactic | 70% |
| Severity | 91.58% |
| Recommended action | 90% |

The report's blocking-policy recall was 94/95 malicious cases (98.95%) and its
benign false-positive count was 0/57. These small generated counts are not real
malware efficacy estimates. The model classified all 19 held-out hidden document
exfiltration scenarios as suspicious and recommended asking instead of the
authored network-block label. Tactic confusion also affected combined credential,
persistence and mass-write scenarios. Test results were inspected for the report
only; they were not recycled into training or used to change thresholds.

CPU compatibility passed through the unchanged Laya 0.3.24 serving environment:
16 cases, all top answers match GPU, maximum probability difference `2.75e-6`,
no truncation, and all checkpoint files unchanged. With four CPU threads, p50 was
2,942.4 ms and p95 was **3,492.8 ms**. Peak RAM across the Windows venv launcher
and actual model process was **2,657.30 MB**. Both exceed the existing 3,000 ms /
1,200 MB deployment gates. The initial sampler counted only the tiny venv launcher;
that measurement was rejected, the sampler fixed, and the check repeated.

Qualification remains **failed**: synthetic-only data, no human review,
insufficient independent test counts, no representative benign week, and failed
CPU memory/latency targets. More repetitions of these generated recipes cannot
resolve those gaps. Next work needs reviewed real behavior with uncertain cases,
fresh held-out families, and a separately evaluated smaller/optimized inference
representation of Laya. Keep calibrated candidate responses advisory until those
requirements pass. Training adds no missing native sensors.

The running Windows service remained PID 23296, with ETW file/network/registry
monitoring, download pause enabled, no loaded model and no integrity failures.
Its status had an accumulated kernel-loss metric of 334,255; it did not increase
during a 20-second spot check. Unattributed events increased by 10,858, so complete
attribution and gap-free collection cannot be claimed. No sensor rebuild or
service restart was performed for this Python/model-only task.

Validation: 14 new budget/partition/label/CPU-memory tests, five existing ML
pipeline tests and the tokenizer-preparation test passed. Native replay generated
every state/feature row using the existing release binary. `git diff --check`
passed. Model files remain under ignored `.vigil/`, outside the Windows package.

Private evidence:

- `.vigil/models/laya-security-development/training-report.json`,
  `resources.json`, `evaluation.json`, `test-predictions.jsonl`,
  `error-analysis.json`, and the single `checkpoint/`.
- `.vigil/checks/laya-cpu-verified/report.json` is the valid CPU measurement;
  `.vigil/checks/laya-cpu-compatibility/report.json` is superseded for memory.
- `.vigil/checks/storage/cleanup-2026-10-18.json` and
  `monitor-during-training.json` record cleanup and live service observations.

Pinned candidate weights:
`1a6d9023f5f2f17fdfbac99eac1b6884ba24acf86f0a0b5f68710927e36d17f0`.
Per-question calibration:
`e258e70d513830277723137f2cde26ece57ce0bec9ffa5632370dc11f5b2d29c`.
