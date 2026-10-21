# M16 - download behavior decisions and optional folder scanning

The maintainer reaffirmed on 2026-10-20 that the primary workflow is to watch
downloaded content when the user opens, plays or executes it, detect unexpected
behavior from the responsible application and descendants, intervene on strong
evidence, and notify. File extensions alone are not threat evidence. Networked
games, media streaming, updates and ordinary document activity need benign
coverage alongside uncertain and dangerous behavior. Folder scanning is optional.

This milestone extends the existing runtime, rather than automatically executing
downloads. Immediate response uses the existing deterministic evidence path.
Suspension and evidence-bound quarantine preserve recovery; an unqualified
decision model cannot authorize destructive actions.

Data work adds bounded, pinned public text telemetry and purpose-specific authored
scenarios. Public weak labels remain training-only. Prior validation and test
rows are excluded from further fitting. Fresh checkpoint-selection, calibration
and test families are separate, with exact-state and application identity checks.
Authored cases exercise the native replay contract, not real exploits or decoders.

Continue full-encoder Laya fine-tuning from the verified M14 checkpoint using
the existing local environment. Preserve the 16 GB allocator limit, 45 GB device
stop threshold, 50 GB requested ceiling, resource watchdog and one selected
checkpoint. Compare parent and candidate only after checkpoint selection. Report
regressions and failed qualification without enabling the candidate.

## Frozen data and validation

The new acquisition pins the existing Splunk revision
`aafa53ea228fbab8d9ac3e33c9275fab2136909d`, all content hashes, byte counts and
Apache-2.0 notices. It downloads 122 additional Sysmon text logs spanning 46
source technique IDs: 437,643,567 log bytes plus 17,843 notice bytes. Sixteen prior
logs are reused through hardlinks. The source-level technique count does not
mean the model detects those techniques.

Importing all 138 logs yields 90 unique, unreviewed training cases from 32 source
groups. Labels are provisional `suspicious` / `ask_user`: 43 credential concerns,
31 persistence concerns and 16 injection concerns. Of 20,396 candidate windows,
20,180 lack usable mapped evidence and 126 duplicate states. No absence-of-signal
benign labels, malware downloads or execution are used. Thirty-one application
identities use recorded hashes; 59 are explicit path-derived fallbacks.
The native replay preserves within-process order, but shared-image network
history across processes is not a fully chronological replay.

Sixty-six new authored recipes produce 160 purpose-specific states, with relevant
category pairs and signed/unsigned variants. Metadata preserves input extension,
association and execution phase; the serving state does not expose these fields.
Actual media decoders and live exploits are not exercised.

The merged frozen dataset contains 1,067 cases: 977 train, 28 selection,
26 calibration and 36 test. It retains 827 prior training cases, includes all
90 public cases and discards ten repeated inputs. All 1,102 M13/M14 evaluation
rows remain excluded by ID, family, application identity and exact state.
No human review is claimed. Replaying the hardened public importer reproduces
the exact same dataset bytes. The small authored holdout is not a representative
malware benchmark.

Artifacts:

- `.vigil/training/public-splunk-v2/acquisition.json` and pinned text logs.
- `.vigil/training/public-telemetry-v2/dataset.jsonl`, SHA-256
  `6011550438f6e6b424b03b30609028f0b88658e46a3bada3c2cdde2896c5c8a1`.
- `.vigil/training/download-behavior-v3-complete/dataset.jsonl`, SHA-256
  `fe5ee841c3af6e2f9dfc1947e98a531dffc7f2e7dc4d2d7c6cae16fcdae638d7`.

The earlier incomplete merge directory is retained as evidence; it is not the
training input. Public records with matching source observation, model input,
labels and application identity can deduplicate harmless provenance enrichment;
conflicting labels, inputs or partitions fail closed.

## Training attempts: no new checkpoint

Three full-encoder attempts used the verified M14 parent, the frozen data,
12-epoch maximum, three-epoch patience, micro-batch four and a 45-minute bound.
All stopped on stale GPU telemetry before completing an epoch:

| Run directory under `.vigil/models/` | Telemetry | Completed epochs |
| --- | --- | ---: |
| `whohack-laya-download-v3` | persistent NVIDIA query stream | 0 |
| `whohack-laya-download-v3-throttled` | query stream, 100 ms idle per forward | 0 |
| `whohack-laya-download-v3-nvml` | isolated direct NVML, 100 ms idle per forward | 0 |

The first attempt reached baseline selection evaluation before stopping;
the next two stopped during baseline evaluation. Selection results are not
test-set performance. No new candidate weights, calibration or test evaluation
exist. The previous checkpoints remain preserved and disabled. Do not describe
this milestone as a completed fine-tune or improved detection accuracy.

The direct NVML attempt recorded a peak of 9.13 GB total device memory including
reservations, 2.49 GB training-process RAM and 32 C GPU temperature. Its report
ended after 28.42 seconds. These are samples before monitoring failed, not proof
of uninterrupted visibility. Both 25-second bounded CUDA preflights passed;
they did not predict reliability under the actual model workload. Sustained
driver telemetry remains an external blocker. No memory, temperature or
freshness limit was increased.

The optional NVML worker loads the OS System32 library in an isolated standard
Python interpreter. It only initializes, queries and shuts down NVML; it never
changes device settings. Memory accounting includes reservations conservatively.
Following review, it includes a source monotonic timestamp taken before both
queries. The parent rejects stale, future and nonadvancing timestamps instead
of treating delayed pipe data as fresh. This timestamp improvement was made
after the stopped attempt; it has unit and idle integration validation but no
successful training validation.

The resource watchdog now preserves its emergency exit even if report writing
or telemetry-process cleanup throws. The 16 GB allocator, 45 GB device stop,
50 GB ceiling, eight-second stale limit and 15-second emergency grace remain.
Sixty-five ML/data/resource tests pass, including provenance isolation, uncertain
action auditing, NVML ABI/units, stale-source rejection and cleanup failure.
An isolated timestamped-worker integration returned three valid samples and
terminated its owned process. No further model attempt was made.

Once reliable workload telemetry is available, use a **new** output directory:

```powershell
ml/.venv/Scripts/python.exe ml/train_laya.py .vigil/training/download-behavior-v3-complete/dataset.jsonl --base .vigil/models/whohack-laya-expanded/checkpoint --laya-overlay .vigil/training-tools/laya-0.4.11 --output NEW_RUN_DIRECTORY --epochs 12 --patience 3 --micro-batch 4 --allocator-gb 16 --max-minutes 45 --gpu-telemetry nvml --allow-synthetic
```

Do not disable the telemetry guard to finish a run. After successful selection,
`ml/audit_download_decisions.py` can compare parent/candidate test predictions
and expose uncertain-case overreaction, excessive quarantine and missed malicious
actions by family and application category. It does not select new thresholds
or authorize enforcement.

## Runtime status and separate folder work

The main runtime already has deterministic download attribution, evidence-bound
pause and notifications. A read-only check initially found the legacy 0.1.0
service in Prompt mode with download pause enabled and no loaded model. Its
accumulated dropped/lost counters did not increase during the measured minute,
but unattributed records increased by 114,552. These counters include records
outside relevant download activity; complete sensor attribution is not proven.

Another active editing session added a Defender-based optional folder check while
this session initially implemented a bounded YARA scan. The overlap was detected,
snapshotted and reconciled around the existing Defender implementation. The
[folder-check record](M16-optional-folder-check.md) owns its exact build/test and
policy status; the abandoned YARA interface is not an additional product mode.

The configured service subsequently stopped. This training work did not restart,
elevate or reconfigure it. A newly built service was denied by Windows Application
Control before its integration harness could start; no bypass was attempted.
Therefore neither new folder scanning nor Laya has been activated in the live
application by this milestone.

Primary references: [Splunk attack_data](https://github.com/splunk/attack_data),
[Laya training](https://github.com/NandhaKishorM/laya/blob/main/docs/finetune.md),
[NVML queries](https://docs.nvidia.com/deploy/nvml-api/latest/api/group__nvmlDeviceQueries.html),
and [NVML memory accounting](https://docs.nvidia.com/deploy/nvml-api/latest/api/structnvmlMemory__v2__t.html).
