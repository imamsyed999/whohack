# MASTER BUILD PROMPT — "Vigil" Cross-Platform Anti-Hack Detection System

> How to use: paste this whole file into an AI coding agent (Claude Code or similar) at the root of an empty repository, or save it as `SPEC.md` / `CLAUDE.md` so the agent reads it on every session. "Vigil" is a working name; rename freely.

---

## 1. Your role and working rules

You are the lead engineer building Vigil, a personal-PC security tool for Windows, macOS, and Linux. Follow these rules for the whole project:

1. Work one milestone at a time (Section 17). At the start of each milestone, write a short plan to `docs/plans/M<n>-<name>.md` listing files, interfaces, and tests, then implement it.
2. Write tests alongside code. Every milestone ends with passing tests and a demo command that proves the acceptance criteria.
3. The decision models, crates, and OS APIs named here change often. Before coding against any external API or model, read its current documentation or model card and adapt. If something named here no longer exists or behaves differently, say so and propose the closest replacement.
4. Stop and ask me before you: write a kernel driver, add any dependency that makes network calls, change OS security settings, or need paid accounts or entitlements (Apple, Microsoft).
5. Never run real malware on the development machine. Use only the safe test methods in Section 16.
6. Never disable, weaken, or interfere with the OS's built-in antivirus (Microsoft Defender, XProtect, etc.). Vigil is an extra layer.
7. No placeholders in delivered code: no `todo!()`, no "handle errors later". If something is out of scope for the current milestone, it goes in `docs/backlog.md`.
8. Keep each file focused on one responsibility. Prefer small modules with clear interfaces.

---

## 2. Mission

Detect and stop malicious behavior from programs the user downloads and runs. Specifically:

- Know which files came from the internet, and track every process started from them (and their children). This is called **taint**.
- Watch what those processes actually do: network connections, sensitive file access, persistence, child processes.
- Compare actual behavior against what the program is **expected** to do for its type. A mismatch is the core signal of a hidden hack.
- Detect unknown or malicious network destinations (threat feeds, raw-IP connections without DNS, first-seen destinations, beaconing).
- Decide intelligently, using a lightweight local typed-decision model, whether activity is benign, suspicious, or malicious.
- Respond: block the process's network, ask the user, or suspend/kill and quarantine.
- Run on ordinary PCs with no GPU.

## 3. Honest constraints (put these in the README too)

- No system detects 100% of attacks. Vigil aims for high detection of the behaviors that matter most (credential theft, persistence, command-and-control, ransomware, data exfiltration) with few false alarms.
- Malware running with admin/root rights can attack user-mode tools. Vigil adds self-protection (Section 14) but is not tamper-proof.
- When uncertain, Vigil prefers safe, reversible actions (block network + ask the user) over destructive ones (kill + quarantine).

---

## 4. Global constraints

- Core language: Rust (stable, latest). macOS system extensions in Swift. ML training scripts in Python 3.11+.
- Platforms: Windows 10 22H2+ and 11 (x64, ARM64); macOS 13+ (Apple Silicon and Intel); Linux kernel 5.15+ with cgroup v2 (Ubuntu 22.04+, Debian 12+, Fedora 39+).
- Privilege separation: the core service runs as SYSTEM/root; the UI runs as the normal user; they talk over authenticated local IPC only.
- Privacy: no user data leaves the machine. Only exceptions: threat-feed downloads and an opt-in VirusTotal **hash-only** lookup using the user's own API key. Never upload files.
- Resource budget on a 4-core, 8 GB RAM, no-GPU PC:
  - Core service idle: < 1% average CPU, < 150 MB RAM (excluding the decision model).
  - Tier 2 decision model: < 1.2 GB RAM when loaded, unloaded after 10 minutes idle, p95 latency < 3 s per case on CPU.
  - Tier 1 scoring: < 50 µs per event.
- Default response mode: `prompt` (Section 11). Auto-block is opt-in.
- Licenses: only permissive (MIT, Apache-2.0, BSD) dependencies unless I approve otherwise.

---

## 5. Architecture

```
            ┌──────────────── Core service (Rust, SYSTEM/root) ────────────────┐
 OS hooks → │ Collectors → Normalizer → Taint+Lineage → Tagger → Detection → Response │
            │      │                                         │ Tier0 rules            │
            │      └──────────── SQLite event store ←────────┤ Tier1 anomaly (ONNX)   │
            │                                                │ Tier2 typed-decision   │
            │  Threat-intel cache   Profiles store           │ Tier3 optional deep    │
            └───────────────────────────── IPC ──────────────────────────────────┘
                                             │
                                  Tray UI (Tauri, user)
```

Data flow: raw OS events → normalized `Event` → taint/lineage attached → mapped to `CapabilityTag`s → scored by tiers → `Verdict` → `Action` → alert to UI → user feedback stored as labeled data.

## 6. Repository layout

```
vigil/
  crates/
    vigil-core/        # types, config, event bus, SQLite store
    vigil-collect/     # collector trait + per-OS modules (windows/, linux/, macos/)
    vigil-taint/       # download origin, hashing, signatures, lineage
    vigil-tags/        # capability taxonomy + event→tag mapping
    vigil-intel/       # threat feeds, DNS cache, destination reputation
    vigil-detect/      # tier0 rules, tier1 anomaly, fusion policy
    vigil-decide/      # DecisionModel trait, state builder, model adapters
    vigil-respond/     # firewall/process/quarantine backends per OS
    vigil-ipc/         # authenticated IPC protocol
    vigil-service/     # binary: wires everything, service install
  macos/VigilExtensions/  # Swift: Endpoint Security + Network Extension, XPC bridge
  ui/                  # Tauri tray app
  rules/               # Tier0 YAML rules
  profiles/            # category templates YAML
  ml/                  # Python: dataset builder, labeling, fine-tuning, evaluation, export
  tools/beacon-sim/    # harmless beacon simulator for testing
  docs/plans/  docs/backlog.md
```

---

## 7. Core data model (vigil-core)

Implement these types (serde-serializable). Extend only if needed, and document changes.

```rust
pub enum Os { Windows, MacOs, Linux }

pub enum Origin { Downloaded { url: Option<String>, referrer: Option<String> }, Installed, System, Unknown }

pub enum SignState { ValidTrusted { publisher: String }, ValidUntrusted, Invalid, Unsigned }

pub enum PathClass { Downloads, Temp, ProgramFiles, System, UserApp, Other }

pub struct FileInfo { pub path: String, pub sha256: [u8; 32], pub origin: Origin,
                      pub sign: SignState, pub yara_hits: Vec<String>, pub first_seen: i64 }

pub struct ProcessInfo { pub pid: u32, pub ppid: u32, pub start_time: i64, pub exe: FileInfo,
                         pub path_class: PathClass, pub tainted: bool, pub taint_root: Option<u32>,
                         pub app_id: String /* stable id: sha256 or signing id */ }

pub enum EventKind {
    ProcessStart, ProcessExit,
    NetConnect { remote_ip: IpAddr, remote_port: u16, proto: Proto, domain: Option<String>, dns_before: bool },
    DnsQuery { name: String, answers: Vec<IpAddr> },
    FileAccess { path: String, class: SensitiveClass, write: bool },
    Persistence { location: PersistenceKind, target: String },
    Injection { target_pid: u32 },
    FileBurst { modified: u32, renamed: u32, window_ms: u32 }, // ransomware signal
}

pub struct Event { pub ts: i64, pub pid: u32, pub kind: EventKind }

pub struct CapabilityTag(pub &'static str); // e.g. "credential_access:browser_passwords"

pub enum VerdictLabel { Benign, Suspicious, Malicious }

pub struct Verdict { pub label: VerdictLabel, pub p: [f32; 3], pub tactic: String,
                     pub severity: f32, pub action: Action, pub tier: u8, pub reasons: Vec<String> }

pub enum Action { Allow, AskUser, BlockNetwork, SuspendAndAsk, KillAndQuarantine }
```

---

## 8. Per-OS backends

| Function | Windows | macOS | Linux |
|---|---|---|---|
| Download origin | `Zone.Identifier` alternate data stream (Mark-of-the-Web: ZoneId, HostUrl, ReferrerUrl) | `com.apple.quarantine` xattr (+ LaunchServices quarantine DB for URL) | `user.xdg.origin.url` / `user.xdg.referrer.url` xattrs when present; otherwise fanotify watch on Downloads/temp dirs marks new executables as `Downloaded{url:None}` |
| Signatures | WinVerifyTrust (Authenticode) | Security framework `SecStaticCode` / codesign | Package-manager ownership (dpkg/rpm) as "Installed"; else Unsigned |
| Process events | ETW Microsoft-Windows-Kernel-Process (crate: `ferrisetw`) | Endpoint Security (`ES_EVENT_TYPE_NOTIFY_EXEC`, `FORK`, `EXIT`) in Swift, bridged via XPC | eBPF (`aya`): `sched_process_exec`, `sched_process_fork`, `sched_process_exit` |
| Network → PID | ETW Microsoft-Windows-Kernel-Network + IP Helper `GetExtendedTcpTable` fallback | Network Extension `NEFilterDataProvider` (flow has source app audit token) | eBPF kprobes on `tcp_connect`/`udp_sendmsg` + `/proc/net` fallback |
| DNS | ETW Microsoft-Windows-DNS-Client | NE flows on port 53 / DNS proxy provider | eBPF on UDP/53 or resolver logs |
| Sensitive file access | ETW File provider filtered to sensitive paths | ES `ES_EVENT_TYPE_NOTIFY_OPEN` filtered | fanotify on sensitive paths |
| Block network per process | WFP user-mode filter with `FWPM_CONDITION_ALE_APP_ID` (no driver needed) | NE filter verdict `drop` for flows from that signing ID / audit token | Move PID into cgroup `vigil-quarantine`; nftables rule `socket cgroupv2 level 1 "vigil-quarantine" drop` |
| Suspend / kill | `NtSuspendProcess` / `TerminateProcess` | `SIGSTOP` / `SIGKILL` | `SIGSTOP` / `SIGKILL` |

macOS notes: Endpoint Security needs the `com.apple.developer.endpoint-security.client` entitlement and Network Extension needs content-filter entitlements; both require an Apple Developer account and approval. Until approved, build a degraded macOS mode (polling `proc_pidinfo` + `lsof`-style socket listing, `pf` anchor for blocking) and clearly label it "limited mode".

Every collector implements:

```rust
#[async_trait]
pub trait Collector: Send + Sync {
    fn name(&self) -> &'static str;
    async fn run(&self, tx: tokio::sync::mpsc::Sender<Event>) -> anyhow::Result<()>;
}
```

Every response backend implements:

```rust
pub trait Responder: Send + Sync {
    fn block_network(&self, p: &ProcessInfo) -> anyhow::Result<BlockHandle>;
    fn unblock(&self, h: BlockHandle) -> anyhow::Result<()>;
    fn suspend(&self, pid: u32) -> anyhow::Result<()>;
    fn resume(&self, pid: u32) -> anyhow::Result<()>;
    fn kill(&self, pid: u32) -> anyhow::Result<()>;
    fn quarantine(&self, f: &FileInfo) -> anyhow::Result<QuarantineId>; // move + strip exec bit/ACL, keep restorable
}
```

---

## 9. Capability tag taxonomy (vigil-tags)

Map every event to zero or more tags. Each tag has a base severity 0–3 and an ATT&CK technique ID where one applies. Store the table in `crates/vigil-tags/src/taxonomy.rs` with unit tests.

- `network:vendor_domain` (0), `network:known_cdn` (0), `network:first_seen_destination` (1), `network:raw_ip_no_dns` (2), `network:unusual_port` (1), `network:intel_hit` (3), `network:beaconing` (3, T1071), `network:large_upload` (2, T1041)
- `exec:script_interpreter` (2, T1059) — powershell, cmd, wscript, cscript, mshta, bash, sh, python, osascript
- `exec:lolbin` (2, T1218) — rundll32, regsvr32, certutil, bitsadmin, curl/wget spawned by a non-shell app
- `exec:hidden_window` (2)
- `exec:child_from_downloads_or_temp` (2)
- `credential_access:browser_passwords` (3, T1555.003), `credential_access:keychain` (3, T1555.001), `credential_access:ssh_keys` (3, T1552.004), `credential_access:crypto_wallets` (3), `credential_access:lsass` (3, T1003.001)
- `persistence:run_key` / `persistence:startup_folder` / `persistence:scheduled_task` / `persistence:service` (Windows), `persistence:launch_agent` / `persistence:login_item` (macOS), `persistence:cron` / `persistence:systemd_unit` / `persistence:shell_rc` (Linux) — all severity 2, T1547/T1053/T1543
- `defense_evasion:av_tamper` (3, T1562), `defense_evasion:log_clear` (3, T1070), `defense_evasion:shadow_copy_delete` (3, T1490)
- `discovery:process_enum` (1, T1057), `discovery:system_info` (1, T1082)
- `collection:screen_capture` (2, T1113), `collection:clipboard` (1, T1115), `collection:keylogging` (3, T1056)
- `impact:mass_file_modification` (3, T1486)
- `injection:remote_thread` (3, T1055)
- `file:read_documents` (0), `file:write_own_dir` (0)

Sensitive path classes (per OS, in config): browser profile credential DBs (Chrome/Edge/Brave `Login Data`, Firefox `logins.json`/`key4.db`), `~/.ssh`, macOS Keychain DBs, common crypto wallet dirs, persistence locations.

---

## 10. Detection pipeline (vigil-detect, vigil-decide)

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

## 11. Response modes
- `monitor`: log and notify only.
- `prompt` (default): block network on suspicion, ask user for anything stronger.
- `auto`: apply the fusion policy's strongest action automatically, notify after.
- All blocks are reversible from the UI. Quarantine keeps the file restorable with its original path and metadata.
- Allowlist: user can trust an app (by signing ID or sha256), a destination, or a specific behavior for an app.

---

## 12. Decision model integration (vigil-decide)

### 12.1 Model choice
These are "typed decision" models: input = a text **state** + a list of **typed questions** (yes/no, choice, score); output = a probability for every option in one forward pass, no generated text. Candidates (verify current versions on Hugging Face and pin exact revisions + file hashes):

| Tier | Model | Notes |
|---|---|---|
| 2 (default) | `convaiinnovations/laya`, subfolder `typed-decisions` (ModernBERT-large encoder, ~421M params, Apache-2.0). GGUF build: `mys/laya-typed-decisions-GGUF`, runnable via the `ggmlc` `laya` CLI binary | Trained on workflows incl. security incidents. Context 1,024 tokens (~768 for state). |
| 2 (alternative) | `manjunathshiva/opendecider-nano` (~400M, Apache-2.0) | Benchmark both on OUR eval set; keep the winner. |
| 3 (optional) | `evalengine/decision-4b-gguf` Q4_K_M (~2.7 GB) via llama.cpp; or `flymy-ai/decision-4b-v1.2` (Qwen3.5-4B + LoRA) on GPU machines | Heavier; only for uncertain cases on strong PCs. |

### 12.2 Adapter design
```rust
pub struct Question { pub id: &'static str, pub kind: QKind, pub text: String }
pub enum QKind { YesNo, Choice(Vec<&'static str>), Score { min: u8, max: u8 } }
pub struct Answer { pub id: String, pub probs: Vec<(String, f32)> }

pub trait DecisionModel: Send + Sync {
    fn name(&self) -> &str;
    fn max_state_tokens(&self) -> usize;
    fn decide(&self, state: &str, qs: &[Question]) -> anyhow::Result<Vec<Answer>>;
}
```
- Implement `LayaSidecar`: runs the pinned `laya` GGUF binary as a sandboxed child process (low priority, no network), exchanging JSON over stdin/stdout. Read the binary's current CLI/JSON contract and map it to `Question`/`Answer`.
- Implement `MockDecisionModel` for tests (deterministic answers from fixtures).
- Load lazily; unload after 10 min idle; run inference on a dedicated low-priority thread.
- Apply per-question temperature calibration (fit in `ml/`, stored in config).

### 12.3 State format (the exact template; must fit the model's state budget)
Build the state ONLY from Vigil's own classified fields — never paste raw strings from the program.

```
APP name={sanitized_basename} category={category} signed={valid_trusted|valid_untrusted|invalid|unsigned} publisher={sanitized_publisher|none} origin={downloaded|installed|system|unknown} age_h={hours} path={downloads|temp|program_files|system|user_app|other}
EXPECTED {tag1}, {tag2}, ...
UNEXPECTED {tag}(x{count}), ...
TREE {parent_basename} > {basename} > {child_basename}[hidden] ...
NET {n_dest} destinations: {ip_or_domain_class}:{port} dns_before={yes|no} intel={hit|none} first_seen={yes|no} interval_s={n|none}; ...
FILES sensitive={class1, class2|none}
PERSIST {persistence tags|none}
RULES {rule_ids|none}
ANOMALY {s1 to 2 decimals}
```

Sanitization (prompt-injection defense): basenames and publisher names are truncated to 40 chars and stripped to `[A-Za-z0-9._ -]`; command lines, window titles, URLs, and file contents are NEVER included; domains are reduced to registrable domain + a class (`vendor|cdn|unknown|intel_hit`). Truncate lower-severity lines first if over budget. Unit-test the token count against the model's tokenizer.

### 12.4 Runtime questions (always these five, in this order)
1. `matches_purpose` — YesNo — "Is this behavior consistent with what an application of this category normally does?"
2. `verdict` — Choice [`benign`, `suspicious`, `malicious`] — "Overall, is this activity benign, suspicious, or malicious?"
3. `tactic` — Choice [`none`, `credential_theft`, `persistence`, `command_and_control`, `ransomware`, `data_exfiltration`, `reconnaissance`] — "Which attacker goal does this activity most resemble?"
4. `severity` — Score 0–3 — "How severe would the impact be if this is malicious? 0 none, 1 low, 2 high, 3 critical."
5. `action` — Choice [`allow`, `ask_user`, `block_network`, `kill_and_quarantine`] — "What should a careful security analyst do right now?"

### 12.5 Install-time expected-behavior profile
When a new app is first seen:
1. Ask Choice question `category` with options: `browser, office_document, pdf_reader, media_player, game, game_launcher, chat_messaging, developer_tool, ide, terminal, system_utility, driver_or_hardware_tool, vpn_or_network_tool, security_tool, installer_updater, archive_tool, password_manager, crypto_wallet, other`. State = sanitized name, publisher, file description, install path class, sign state.
2. Load `profiles/{category}.yaml` as the base expected tag set.
3. For each tag NOT in the base set that has severity ≥ 1, ask YesNo: "Would a typical {category} application legitimately need to: {tag plain-language description}?" Batch as many questions per pass as the model supports.
4. Learning period: 72 h of use for trusted-signed apps, 0 h for tainted unsigned apps. Observed tags are proposed to the user, never auto-accepted for severity ≥ 2.

Example `profiles/pdf_reader.yaml`:
```yaml
category: pdf_reader
expected: [file:read_documents, file:write_own_dir, network:vendor_domain, network:known_cdn]
never: [credential_access:*, injection:*, persistence:run_key, exec:script_interpreter, impact:*]
```
Create templates for every category above; `never` tags are an automatic Tier 0 `high` rule for that app.

### 12.6 Explanations
The decision model emits no text, so generate the user-facing explanation deterministically from tags + verdict, e.g. "PDFViewerPro (unsigned, downloaded 2 hours ago) launched hidden PowerShell, read your browser's saved passwords, and is contacting an unknown server every 60 seconds. This does not match a PDF reader. Network blocked." Templates live in `crates/vigil-decide/src/explain.rs` with tests.

---

## 13. Threat intelligence (vigil-intel)
- Feeds (verify current URLs/terms; respect rate limits): abuse.ch URLhaus, ThreatFox, Feodo Tracker IP blocklist; Spamhaus DROP/EDROP.
- Refresh every 6 h with ETag/If-Modified-Since; store in an in-memory radix tree (IPs/CIDRs) + hash set (domains); persist to disk.
- Maintain a local DNS cache (domain ↔ IPs, from DNS events) so `dns_before` and domain attribution work.
- Optional VirusTotal: hash-only lookup, opt-in, user-supplied key, cached 7 days, respect the free-tier rate limit.

## 14. IPC and self-protection
- IPC: Windows named pipe with a DACL limited to SYSTEM + the interactive user; Unix domain socket mode 0660, group `vigil`; macOS XPC between the Swift extensions and the Rust core. Messages are length-prefixed JSON with a per-session token.
- Self-protection: watchdog that restarts the service; config and rule files integrity-checked (SHA-256 manifest); UI alerts loudly if the service stops or blocks are removed externally; the service binary and model files are verified against pinned hashes at startup.

## 15. Storage (SQLite, WAL mode)
Tables: `files`, `processes`, `events` (rolling 30 days), `connections`, `dns`, `profiles`, `alerts`, `decisions` (state text, question answers, model name+revision, tier, final action), `feedback` (user's allow/block on an alert → becomes a labeled training example), `allowlist`.

## 16. Testing and safety
- Unit tests for every crate; integration tests with recorded event fixtures replayed through the full pipeline.
- Safe detection tests ONLY:
  - EICAR test file for the file-scanning path.
  - `tools/beacon-sim`: a harmless program you write that, when run from Downloads, reads a dummy file named like a browser password DB in a temp test directory, writes a dummy autorun entry under a test key, and connects every 60 s to a local test server on 127.0.0.1 or a VM. Must clean up after itself.
  - Atomic Red Team tests ONLY inside a disposable VM snapshot.
- Benign replay test: record 1 week of normal-use events on the developer VM; the pipeline must produce ≤ 1 user-facing alert per week of replay in `prompt` mode.
- Performance tests enforcing the Section 4 budgets.

## 17. ML pipeline (`ml/`, Python)
1. `build_dataset.py`: converts recorded/sandbox cases into JSONL rows: `{ "state": str, "questions": [...], "labels": {"verdict": "malicious", ...}, "source": str, "family": str, "split": "train|val|test" }`.
2. Sources: benign — 200+ common apps recorded in VMs through install and normal use; malicious — public sandbox reports (e.g., CAPE outputs), OTRF Security-Datasets, Atomic Red Team telemetry from VMs. All converted through the SAME state builder logic (port it or call the Rust builder via CLI so formats match exactly).
3. Split by **program/malware family**, never by row, to avoid leakage.
4. `teacher_label.py`: a large model answers the five questions per case; a human reviews ≥ 10% of rows; disagreements resolved by hand.
5. `finetune.py`: fine-tune the Tier 2 candidates (Laya typed-decisions, OpenDecider-nano) using each project's official fine-tuning recipe; keep the better one.
6. `evaluate.py`: per-question accuracy, Brier score, ECE, malicious recall at the operating threshold, benign false-positive rate per case, alerts/week on benign replay, p50/p95 CPU latency. Targets: malicious recall ≥ 0.90 on the held-out family split, benign FPR ≤ 1% per escalated case. Report honestly if targets are not met.
7. `train_tier1.py`: LightGBM + isolation forest on feature vectors; export ONNX; verify identical scores in Rust.
8. `calibrate.py`: per-question temperature scaling; write to config.
9. Feedback loop: `export_feedback.py` turns `feedback` rows into new labeled examples for the next training round.

---

## 18. Milestones and acceptance criteria

- **M0 Skeleton**: workspace, core types, config, SQLite store, logging, CI on all three OSes. ✅ `cargo test` green on Windows, macOS, Linux CI.
- **M1 Monitor (Linux first, then Windows, then macOS limited mode)**: process + network collectors, PID attribution, DNS cache, CLI `vigil-service --monitor` printing live connections per process. ✅ Correctly attributes `curl` connections to the right PID on each OS.
- **M2 Taint**: download origin, hashing, signatures, YARA (`yara-x`), lineage propagation to children. ✅ A script downloaded via browser and its child processes all show `tainted=true`.
- **M3 Tags + profiles**: taxonomy, event→tag mapping, category templates, install-time profile flow using `MockDecisionModel`. ✅ beacon-sim produces the expected unexpected-tag set.
- **M4 Intel + Tier 0 + response**: feeds, rules engine, per-OS network block/suspend/kill/quarantine, response modes. ✅ beacon-sim's network is blocked within 1 s of a critical rule firing; unblock restores it.
- **M5 Tier 1**: hand-weighted score, feature extraction, ONNX runtime path with a toy model. ✅ Budget tests pass.
- **M6 Tier 2**: `LayaSidecar` adapter, state builder with token test, five questions, fusion policy, network hold, explanations. ✅ beacon-sim → malicious verdict + correct explanation; benign replay ≤ 1 alert/week.
- **M7 UI**: Tauri tray app: live alerts with Allow / Block / Kill buttons, timeline, allowlist, mode switch, model status. ✅ Full alert round-trip from detection to user decision to stored feedback.
- **M8 ML pipeline**: dataset builder, teacher labeling, fine-tune, evaluation report, Tier 1 training. ✅ `ml/reports/eval.md` with all metrics from Section 17.
- **M9 macOS full mode** (after Apple entitlements are approved): ES + NE extensions via XPC. ✅ Same M6 acceptance on macOS.
- **M10 Packaging + self-protection**: signed installers (MSI, notarized PKG, .deb/.rpm), watchdog, integrity checks. ✅ Clean install/uninstall on all three OSes; tamper alert works.

Start now with M0. Write `docs/plans/M0-skeleton.md` first, show it to me, then implement.
