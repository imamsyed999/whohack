# M3 — Capability tags and expected-behavior profiles

Goal: every observation is mapped to capability tags (SPEC §9). Each app has an
expected-behavior profile for its category (SPEC §12.5). Tags outside the profile are
"unexpected", which is the core signal of a hidden hack.

Acceptance: `tools/beacon-sim`, run as a tainted process categorized as `pdf_reader`, yields
the expected **unexpected-tag set**:

- `credential_access:browser_passwords` — it reads a dummy file classified as a browser
  password store;
- a `persistence:*` tag — it writes a dummy autorun entry into a location configured as a
  persistence location;
- `network:beaconing` — it connects to a local test server at a regular interval;
- `network:first_seen_destination` and `network:unusual_port`.

## New crates

**`vigil-tags`**

| File | Contents |
|---|---|
| `taxonomy.rs` | Static table: tag, severity 0–3, ATT&CK id, plain-language description. Every SPEC §9 tag, plus `persistence:autostart` (Linux XDG autostart, severity 2). |
| `sensitive.rs` | Classifies a path into `SensitiveClass` / `PersistenceKind` using a per-OS default table plus config extras. Rules are prefixes or name globs, with `~` = any user's home. |
| `net.rs` | Destination state per app: first-seen destinations, unusual ports, raw-IP-without-DNS (public addresses only, and only when DNS visibility is on), and beaconing. Beaconing means at least 4 connects to one destination whose intervals have a coefficient of variation ≤ 0.2 and a mean between 5 s and 1 h. |
| `exec.rs` | Process-start tags: `exec:script_interpreter`, `exec:lolbin` (the binary-name list from SPEC §9), `exec:child_from_downloads_or_temp`. |
| `tagger.rs` | `Tagger::tag(&mut Observation)` fills `obs.tags`. |
| `profile.rs` | `CategoryTemplate` (YAML), `Profile`, wildcard matching (`credential_access:*`), `unexpected(tags)`, and `violates_never(tags)`. |

**`vigil-decide`** (the M3 part)

| File | Contents |
|---|---|
| `model.rs` | `Question`, `QKind`, `Answer`, and the `DecisionModel` trait, exactly as in SPEC §12.2. |
| `mock.rs` | `MockDecisionModel`: deterministic answers from fixtures (JSON), with a uniform fallback. |
| `profile_flow.rs` | The install-time flow from SPEC §12.5: ask for the category, load its template, then ask yes/no for each extra tag with severity ≥ 1. Accept "yes" only for severity ≤ 1; severity ≥ 2 answers become proposals. Learning period is 72 h for trusted-signed apps, 0 for tainted or unsigned ones. |
| `state.rs` | Sanitization helpers shared with M6 (basename and publisher are reduced to `[A-Za-z0-9._ -]`, at most 40 characters). |

## Other files

- **`profiles/*.yaml`:** templates for all 19 categories.
- **Collectors for file access and persistence on Linux:** fanotify marks on the configured
  sensitive and persistence directories, which needs root. Events are `FileAccess` and
  `Persistence`. The Windows equivalent (ETW File and Registry providers) and macOS full
  mode are in the backlog. macOS limited mode has no file visibility, and this is
  documented.
- **Config `[sensitive]`:** `extra_paths` (class → paths) and `extra_persistence`
  (kind → paths). This lets tests and beacon-sim register their temp directories.
- **`tools/beacon-sim`:** a harmless simulator (SPEC §16). It reads a dummy
  `Login Data` file in its own temp directory, writes a dummy autorun file in its own temp
  directory, and connects to a local listener every N seconds (default 60). It cleans up
  after itself.

## Pipeline

The analysis stage becomes taint → tagger → profiles:

1. A new `app_id` triggers the install-time profile flow. In M3 this uses
   `MockDecisionModel`; the real model arrives in M6.
2. Each observation gets `tags`.
3. The profile store records observed tags during learning.

Profiles persist through the existing `profiles` table.

## Tests

- **Taxonomy:** unique tags, severities in 0–3, every SPEC §9 tag present, and every
  template's tags exist in the taxonomy.
- **Sensitive classifier:** browser stores, `.ssh`, wallets, and persistence dirs on each
  OS; config extras.
- **Net:** first-seen per app; unusual port; raw IP rules (private and loopback excluded,
  visibility required); beaconing with regular vs. jittered intervals.
- **Profiles:** wildcard matching, unexpected set, never-violations, YAML load of every
  template.
- **Profile flow with the mock model:** category picked; severity ≥ 2 answers proposed,
  not accepted; learning period by sign/taint.
- **Acceptance (Linux, root):** beacon-sim runs under the full pipeline (eBPF or procfs
  collectors plus fanotify) and produces the expected unexpected-tag set.
