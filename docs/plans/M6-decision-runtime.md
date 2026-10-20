# M6: typed decisions, fusion and explanations

- Build the exact bounded APP/EXPECTED/UNEXPECTED/TREE/NET/FILES/PERSIST/RULES/ANOMALY
  state from the same Rust window features used by replay. Exclude raw command lines,
  user paths, URLs and file contents. Define the five ordered typed questions.
- Implement fusion as a pure, configurable function with a non-overridable rule
  floor, conservative timeout handling, prompt/monitor/automatic behavior and
  optional uncertainty escalation to a second pinned model.
- Integrate a bounded decision worker outside collection/store threads. Persist
  state, full answers, model revision, actual applied action and deterministic
  explanations; publish updated alerts and release temporary holds appropriately.
- Configure local sidecars with mandatory pins, CPU thread limits, offline loading,
  exact tokenizer budget checks, startup/inference deadlines and idle unloading.
  Existing base checkpoints may validate the runtime but must remain explicitly
  uncalibrated until M8's representative-data quality gate passes.
- Test thresholds, floor dominance, hostile strings, missing/invalid answers,
  timeout/failure paths, queue pressure and full replay-to-decision-to-IPC behavior.

M4's privileged WFP test is awaiting explicit approval. No firewall test or
automatic response is enabled in the user's normal Windows preview by this plan.
