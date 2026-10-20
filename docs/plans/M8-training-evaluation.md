# M8: reproducible dataset and quality gates

- Add dataset construction that calls the real Rust replay/state builder and
  model-contract command, validates provenance and labels, and partitions by
  family/source identity to prevent train/test leakage.
- Add local teacher prediction/import and a human review ledger. Do not send any
  cases to a remote model; do not claim synthetic labels are human-reviewed.
- Implement evaluation (accuracy, Brier/ECE, operating-point recall/FPR, weekly
  alerts, CPU latency/RSS), temperature calibration on validation data only, and a
  pinned machine-readable release gate that fails without representative evidence.
- Add reproducible Tier 1 training/export using supported ONNX arithmetic operators
  and documented typed-model fine-tuning entry points with official recipe pins.
- Export opt-in local feedback for review, excluding raw paths, command lines and
  free-text notes. Add fixtures that prove leakage and missing evidence are rejected.
- Run the complete tooling with synthetic fixtures to verify mechanics; retain
  human-reviewed benign-week and malicious-family quality tests as external gates.
