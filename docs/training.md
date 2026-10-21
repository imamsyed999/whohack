# Training, calibration and release evidence

All dataset, serving, training and feedback commands operate on local files. They
do not upload telemetry, samples or labels. Model acquisition is a separate
explicit operation. Use `ml/.venv/Scripts/python.exe` for training and the CPU
environment for serving measurements.

1. Create a catalog for `ml/build_dataset.py`: a JSON array with each fixture's
   relative path, category, source, family, all five labels and `synthetic` boolean.
   `event_indices` selects labeled observations; the default selects the last one.
   A review entry must record `accepted`, `reviewer`, and `reviewed_at`.
2. Build with `python ml/build_dataset.py catalog.json --service path/to/whohack-service.exe
   --output dataset.jsonl`. This invokes Rust replay and `--model-contract`, so the
   state text, question order and feature vector match the service. Splits are
   deterministic by family unless explicitly assigned. Reusing a family, app hash
   or identical state across splits is rejected.
   Use `--config scorer.toml` to include the deployment's pinned Tier 1 model,
   custom rules and sensitive-path configuration. With no explicit config, replay
   uses the bootstrap heuristic and built-in rules. Dataset rows retain the scorer
   and config digest. The versioned question text, option order and feature order
   must match `ml/contracts/v1.json`, which Rust tests check against serving.
3. `python ml/teacher_label.py dataset.jsonl --manifest model-manifest.json --output
   predictions.jsonl` runs a pinned local checkpoint. Predictions propose labels
   separately; gold labels and human-review status are never overwritten. Review
   at least 10% of the real dataset and resolve disagreements before qualification.
4. `python ml/train_tier1.py dataset.jsonl --output tier1.onnx` fits LightGBM on
   training families, selects the number of trees on validation families, and fits
   an isolation forest on benign training cases. Export uses ordinary ONNX
   arithmetic/selection operators supported by Rust tract, with numeric parity
   checks against the original model. The output is a ranking score, not a
   calibrated probability. Install local training math dependencies from
   `ml/requirements-training.txt`; no new network client is needed.
5. `python ml/finetune.py dataset.jsonl --base LOCAL_MODEL_DIRECTORY --output
   NEW_CHECKPOINT` trains the OpenDecider head on CPU by default. `--full-encoder`
   trains the encoder too. Test and validation families are excluded from gradient
   updates. Synthetic smoke runs require `--allow-synthetic`; they never qualify a
   checkpoint. The OpenDecider loop implements supervised cross entropy on the
   published nano mask-head architecture; it does not claim an unpublished upstream
   fine-tuning recipe.
6. For Laya, use `ml/train_laya.py` with the separately installed, verified
   `laya==0.4.11` overlay and local checkpoint. The older
   `ml/finetune.py --backend laya --export-only` remains a data export adapter;
   the serving environment still pins `laya==0.3.24`. Do not change that environment
   to obtain training APIs. The bounded full-encoder trainer applies a 16 GB
   PyTorch allocator cap before moving weights to CUDA, monitors total-device
   usage, host RAM, temperature, disk/output growth and runtime, and stops the
   owned process on a limit. The requested ceiling is 50,000,000,000 bytes;
   total-device monitoring stops at 45 GB. These controls cannot reserve VRAM
   against other applications or guarantee against all OS/driver failures.
   Checkpoint selection and calibration use separate validation families; test
   cases are evaluated only after selecting the checkpoint. Only one best
   checkpoint is retained, and failed qualification never enables enforcement.
7. Predict validation families, then `python ml/calibrate.py dataset.jsonl
   predictions.jsonl --output calibration.json`. Only validation logits/labels
   influence temperatures. Pin this file, make new predictions with calibration,
   and evaluate test families once for release.
8. `python ml/evaluate.py dataset.jsonl predictions.jsonl --benign-replay week.json
   --output evaluation.json` reports per-question accuracy, Brier score, ECE,
   malicious recall, benign false-positive rate, latency and RSS. Missing
   measurements fail the gate. The benign report requires at least 168 hours,
   200 apps, alert count, source and `synthetic: false`. Its duration must be
   measured; it cannot be inferred from the number of fixture rows.

Qualification additionally requires at least 100 malicious test cases from five
families and 200 benign cases, >=90% malicious recall, <=1% benign false positives,
<=1 alert/week, <=3000 ms CPU p95 and <=1200 MB RSS. Predictions must agree on
checkpoint and calibration hashes. The manifest verifies the report belongs to
the exact pinned weights/revision/calibration before model-driven response is
available. These extra sample-count checks prevent tiny perfect fixtures from
being treated as acceptance evidence; they are not a substitute for representative
sampling or confidence intervals.

`python ml/export_feedback.py --database PATH --output review.jsonl` opens SQLite
read-only and exports sanitized model states, file hashes and user actions. Raw
paths and free-text feedback notes are excluded. Allow/block feedback is not a
ground-truth malware label; exported rows require human classification and a
family assignment before training.

Validation on 2026-10-13: an 80-case synthetic mechanics dataset exercised the real
Rust state builder (50 train / 15 validation / 15 test). LightGBM + isolation ONNX
export matched the Python reference within `2.65e-8`. A one-step native Windows CPU
head update saved a loadable OpenDecider checkpoint. Leakage, invalid probabilities,
validation-only calibration and privacy filtering tests pass. These are tooling
checks. A representative detection-quality result and benign-week acceptance remain
unavailable until real reviewed evaluation data are supplied.

Primary contracts checked before implementation:
[LightGBM](https://lightgbm.readthedocs.io/en/stable/Python-API.html),
[OpenDecider](https://github.com/manjunathshiva/opendecider), and
[Laya fine-tuning](https://github.com/NandhaKishorM/laya/blob/main/docs/finetune.md).

The 2026-10-18 local Laya development run is reproducible with:

```powershell
ml/.venv/Scripts/python.exe ml/security_scenarios.py --service target/release/whohack-service.exe --output .vigil/training/laya-security-v2
ml/.venv/Scripts/python.exe ml/train_laya.py .vigil/training/laya-security-v2/dataset.jsonl --base .vigil/models/laya-typed-base --laya-overlay .vigil/training-tools/laya-0.4.11 --output .vigil/models/laya-security-development --epochs 16 --patience 3 --allocator-gb 16 --allow-synthetic
```

Use a new output directory when rerunning. The generator creates 893 inert cases
from 47 authored recipe families across 19 app categories. Families, application
identities and exact states are separate across train/selection/calibration/test;
behavior primitives still overlap. There are no real samples or accepted human
reviews. Input extensions are metadata: these fixtures do not exercise a real
media decoder or prove coverage of exploits. All five question label sets are
present in training, including uncertain cases that should ask the user.

The full typed-decisions model has about 421 million parameters and an 843 MB
weight file. Training memory and native service memory are separate measurements.
Measure CPU inference before describing this optional model as lightweight.
`ml/check_laya_sidecar.py` performs a bounded CPU compatibility/latency/RSS check
against GPU predictions using the unchanged serving environment, verifies that
serving leaves the checkpoint untouched, and never enables the candidate.

## Expanded whohack development data

The follow-up M14 round continues from the M13 checkpoint. It adds 54 authored
recipe families (1,026 states across 19 app categories), retains only the 437
previous training rows, and excludes all 456 previous validation/test rows from
fitting. The fresh test has 266 cases. These recipes share behavior primitives;
the split is not an independent malware-lab benchmark.

`ml/acquire_public_telemetry.py` fetches selected UTF-8 Sysmon logs from
[Splunk attack_data](https://github.com/splunk/attack_data), pinned at
`aafa53ea228fbab8d9ac3e33c9275fab2136909d`. The checked-in catalog contains Git LFS
sizes and SHA-256 pointers under the upstream Apache-2.0 license. Acquisition
allows at most 20 MB per log and 125 MB total, verifies bytes/digests, preserves
LICENSE/README, and never downloads or executes malware binaries. Sixteen logs
total 116,068,752 bytes; they include attack-range activity and ordinary processes.

`ml/import_sysmon.py` verifies those digests and renders observed events through
the native replay contract. Only 10 windows from six source groups have signals
suitable for the conservative provisional labels used here. All ten are training
only, marked weak-label and unreviewed. The other 2,885 observed windows are not
called benign merely because they lack mapped evidence. A malware folder name
does not label every process in that file as malicious.

The importer distinguishes query-only LSASS handles from handles granting memory
read permission; even read permission does not prove that memory was read. It
does not convert file deletions into writes, invent network byte counts, or treat
a destination hostname as proof of an observed earlier DNS answer. Source paths
are anonymized, app category/path class are normalized to `other`, and missing
signature information uses the existing schema's `unsigned` placeholder. Those
normalizations and differences between Sysmon and live ETW are material limits.
These rows require review and richer metadata before production qualification.

```powershell
ml/.venv/Scripts/python.exe ml/acquire_public_telemetry.py --output .vigil/training/public-splunk
ml/.venv/Scripts/python.exe ml/import_sysmon.py --source .vigil/training/public-splunk --service target/release/whohack-service.exe --output .vigil/training/public-sysmon-v1
ml/.venv/Scripts/python.exe ml/expanded_scenarios.py --service target/release/whohack-service.exe --previous .vigil/training/laya-security-v2/dataset.jsonl --public .vigil/training/public-sysmon-v1/dataset.jsonl --output .vigil/training/whohack-expanded-v1
ml/.venv/Scripts/python.exe ml/train_laya.py .vigil/training/whohack-expanded-v1/dataset.jsonl --base .vigil/models/laya-security-development/checkpoint --laya-overlay .vigil/training-tools/laya-0.4.11 --output .vigil/models/whohack-laya-expanded --epochs 16 --patience 3 --allocator-gb 16 --allow-synthetic
```

Use fresh output directories. Continued training verifies the parent's weights,
calibration and completed training report. The same fresh test evaluates both
parent and candidate after selection, with a comparison report that includes
regressions. Weak public labels do not become evaluation ground truth. No result
from this workflow establishes market leadership or coverage of every file type.

The GPU guard uses NVIDIA's documented continuous query mode, checks for stale
samples after eight seconds, and leaves short idle periods for driver telemetry
and the desktop. If telemetry starts aging, GPU work pauses until a fresh sample
arrives or the guard stops the run. The 16 GB allocator and 45 GB device stop
thresholds remain unchanged. See the [NVIDIA query documentation](https://docs.nvidia.com/deploy/nvidia-smi/index.html).

The recorded M14 run stopped on stale GPU telemetry during epoch two. Its saved
first-epoch checkpoint was finalized separately, without further training:

```powershell
ml/.venv/Scripts/python.exe ml/finalize_laya.py --run .vigil/models/whohack-laya-expanded --dataset .vigil/training/whohack-expanded-v1/dataset.jsonl --parent .vigil/models/laya-security-development/checkpoint --laya-overlay .vigil/training-tools/laya-0.4.11 --output .vigil/models/whohack-laya-expanded/evaluation-finalized
```

The finalizer requires the original data and parent digests, preserves the stop
report, and performs only calibration and inference. Later continuation verifies
the finalization report is tied to the stopped run and exact saved weights. This
does not resume optimizer state or imply the interrupted epochs completed.
Measured comparisons and remaining false actions are in the
[M14 record](plans/M14-whohack-and-data.md). The model remains disabled.

## Download behavior continuation (M16)

The next corpus adds 122 pinned Sysmon text logs from the same Apache-2.0
[Splunk source](https://github.com/splunk/attack_data), spanning 46 source
technique identifiers. New logs use 437,643,567 bytes; 16 existing logs are reused
through hardlinks. The acquisition cap is 500 MB of new data, 30 MB per log.
Byte counts, hashes, source revision and upstream notices are checked before
import. A technique name describes source context, not a per-process label.

The 138-log import produces 90 distinct provisional training cases from 32 source
groups: 43 credential-access concerns, 31 persistence concerns and 16 injection
concerns. All are `suspicious` / `ask_user`, unreviewed and training-only.
Of 20,396 candidate windows, 20,180 lack suitable mapped evidence and 126 duplicate
another state. They are not relabeled benign. Only 31 selected application
identities have recorded image hashes; 59 explicitly use path-derived identities.
LSASS memory-read permission is not proof that memory was actually read.
Process-local ordering is preserved, but shared-image network history across
processes is not a fully chronological replay.

The purpose-specific generator adds 66 authored recipes and 160 states, covering
ordinary media playback, games, updates and documents; uncertain behavior; and
corroborated credential theft, exfiltration, injection, persistence and impact.
It selects relevant application categories rather than repeating every recipe
across all categories. Extensions and input association are saved as metadata;
the existing model state does not expose them. These are not decoder exploit
tests or measurements of live sensor-to-response latency.

The frozen combined corpus has 1,067 cases: 977 training, 28 selection,
26 calibration and 36 test. It retains 827 old training cases, incorporates all
90 public cases, and discards ten duplicate inputs. All 1,102 previous M13/M14
evaluation rows remain excluded by identity, family, application hash and state.
The small authored holdout and shared behavior primitives do not establish
real-world detection accuracy.

```powershell
ml/.venv/Scripts/python.exe ml/acquire_behavior_telemetry.py --output .vigil/training/public-splunk-v2 --reuse .vigil/training/public-splunk
ml/.venv/Scripts/python.exe ml/import_sysmon.py --source .vigil/training/public-splunk-v2 --service target/release/whohack-service.exe --output NEW_PUBLIC_OUTPUT
ml/.venv/Scripts/python.exe ml/download_scenarios.py --service target/release/whohack-service.exe --previous .vigil/training/whohack-expanded-v1/dataset.jsonl --public NEW_PUBLIC_OUTPUT/dataset.jsonl --exclude-evaluation .vigil/training/laya-security-v2/dataset.jsonl --output NEW_DATASET_OUTPUT
```

Use new directories for generation and training. `ml/audit_download_decisions.py`
adds post-selection error analysis by application category and family, including
restrictive recommendations for uncertain activity, unnecessary quarantine and
missed malicious actions. It compares parent/candidate predictions on the same
frozen test with identical operating thresholds, and never tunes or qualifies
the model. See the [M16 record](plans/M16-download-decisions.md) for actual
training, resource and compatibility results.
