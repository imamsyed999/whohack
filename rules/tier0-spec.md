## 10. Detection pipeline (whohack-detect, whohack-decide)

### Tier 0 — hard rules (every event, deterministic)
- Sigma-style YAML in `rules/`. Each rule: `id`, `description`, `match` (tags, taint, path_class, sign state), `severity` (`low|medium|high|critical`), `action_floor`.
- Ship at least these critical rules: tainted+unsigned process reads browser password stores; shadow-copy deletion; `impact:mass_file_modification`; `network:intel_hit`; `credential_access:lsass` from non-system process; `injection:remote_thread` from tainted process.
- Rules are hot-reloadable and have unit tests with fixture events.

### Tier 1 — anomaly scoring (every event window, microseconds)
- Per-app feature vector over a 60 s sliding window: count of new destinations, raw-IP connects, distinct ports, child processes, sensitive file accesses, persistence writes, bytes up/down ratio, connect-interval regularity (coefficient of variation), sum of unexpected-tag severities (vs profile), taint flag, sign state, path class.
- Model: gradient-boosted trees (LightGBM) for the supervised score + isolation forest trained on the user's own benign history, both trained in `ml/`, exported to ONNX, run in Rust with `tract-onnx` (pure Rust, no native deps).
- Before any model is trained, use a hand-weighted score: `s1 = clamp(Σ unexpected_tag_severity / 6 + 0.2·tainted + 0.2·unsigned, 0, 1)`.

### Escalation to Tier 2 when ANY of:
- `s1 ≥ 0.6`
- any unexpected tag with severity ≥ 2
- first network connection of a tainted process
- a Tier 0 rule of severity `medium` or `high` (critical rules act immediately AND escalate, for the explanation)

While a tainted process is escalated and awaiting a verdict, apply **network hold**: block its new outbound flows. If no verdict in 10 s, show the user an alert with action `AskUser`.

### Tier 2 — typed-decision model (escalated cases only)
See Section 12 for model, input format, and questions.

### Tier 3 — optional deep check
Only if enabled and the machine has ≥ 16 GB RAM: when Tier 2's top verdict probability is between 0.40 and 0.70, run the larger model (Section 12) and average the probabilities (weight 0.4 Tier 2, 0.6 Tier 3).

### Fusion policy (implement exactly; make thresholds configurable)
1. Tier 0 `critical` → action floor `BlockNetwork` (prompt mode) or `KillAndQuarantine` (auto mode). Models can never lower this.
2. `p_malicious ≥ 0.85` AND (`s1 ≥ 0.8` OR a Tier 0 rule fired) → `SuspendAndAsk` (prompt mode) / `KillAndQuarantine` (auto mode).
3. `p_malicious ≥ 0.50` OR `p_suspicious ≥ 0.60` → `BlockNetwork` + alert asking the user.
4. `p_benign ≥ 0.80` and no Tier 0 rule → `Allow`, log only. Do NOT add the behavior to the profile automatically.
5. Otherwise → `AskUser` with network hold kept.
6. The final action is the maximum of the rule floor and the model-suggested action. Models may raise severity, never lower it below a rule floor.

---

