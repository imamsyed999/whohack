# License policy

Vigil is licensed under **MIT OR Apache-2.0**; see `LICENSE-MIT` and `LICENSE-APACHE`.

## Rust dependencies

These are enforced in CI by `cargo deny`, configured in `deny.toml`. Allowed licenses:

- MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause, ISC, Zlib, Unicode-3.0;
- Apache-2.0 WITH LLVM-exception (wasmtime/cranelift via yara-x). This is Apache-2.0 plus an
  extra permission.

Any other license needs maintainer approval and an entry here.

## Python decision-model sidecar

The sidecar runs the typed-decision model (see `docs/research/decision-models.md`). It ships as
a separate process with its own Python environment. Approved exceptions:

| Package | License | Why it is present | Approved |
|---|---|---|---|
| `certifi` | MPL-2.0 | CA bundle pulled in by `requests` / Hugging Face libraries | 2026-10-03 (maintainer) |
| `tqdm` | MPL-2.0 AND MIT | progress bars used by Hugging Face libraries | 2026-10-03 (maintainer) |

MPL-2.0 is file-level copyleft. Vigil uses these packages unmodified and does not include
their source in its own files, so Vigil's own license is unaffected.

Packaging notes:

- **Use the CPU-only PyTorch wheel.** CUDA wheels bundle NVIDIA's redistributable libraries,
  which come under NVIDIA's own license terms.
- **Model weights are Apache-2.0.** This covers `manjunathshiva/opendecider-nano` and
  `convaiinnovations/laya`.
- **Training data provenance:** part of the opendecider-nano training data is CC BY-SA.
  This does not affect use of the weights.
