# Tray dependency license review — approved 2026-10-15

The separate Tauri Cargo workspace was omitted from the previous root audit.
The 2026-10-14 full-workspace `cargo deny` check finds these existing transitive
dependencies outside the permissive-license allowlist:

| Package | Version | License | Dependency path |
|---|---|---|---|
| cssparser | 0.37.0 | MPL-2.0 | dom_query → tauri-utils |
| cssparser-macros | 0.7.1 | MPL-2.0 | cssparser → dom_query → tauri-utils |
| dtoa-short | 0.3.5 | MPL-2.0 | cssparser → dom_query → tauri-utils |
| selectors | 0.38.0 | MPL-2.0 | dom_query → tauri-utils |
| option-ext | 0.2.0 | MPL-2.0 | dirs-sys → dirs → Tauri (non-Windows targets) |

The maintainer approved the pending dependency decisions on 2026-10-15 in
the instruction to approve the remaining decisions and complete the build.
`deny.toml` now contains exact-version MPL-2.0 exceptions. Retain their notices and
identify exact source archives to recipients. Other MPL dependencies and future
versions remain subject to review; the global permissive allowlist is unchanged.
The repeat audit also identified `cssparser` 0.37.0, omitted from the initial
four-package list. It belongs to the same Tauri chain and uses the same license;
it was reviewed and added as a fifth exact-version exception under that delegation.

MPL is an open-source, file-level copyleft license. It permits combination with
separately licensed files and requires source-availability information for its
covered code in distributed binaries. See the [Mozilla FAQ, questions 8 and
11](https://www.mozilla.org/en-US/MPL/2.0/FAQ/) and the
[license text](https://www.mozilla.org/en-US/MPL/2.0/). This proposal preserves
Vigil's MIT OR Apache-2.0 license and does not claim ownership of dependencies.

`tools/windows/notices.py` generates a target-filtered inventory and attribution
file from **both** locked workspaces. The local preview inventory covers 508
registry packages, conservatively including build dependencies. Missing registry
license files are retrieved from recorded upstream Git revisions. Two archives
(ascii_tree 0.1.1 and selectors 0.38.0) omit full license text; their declared
authors/license and standard SPDX text are identified explicitly, without
inventing an upstream copyright notice. Binary review should retain this detail.

The full tray audit also flags [RUSTSEC-2024-0370](https://rustsec.org/advisories/RUSTSEC-2024-0370.html).
Reviewed 2026-10-15: `proc-macro-error` 1.0.4 is an unmaintained build-time dependency
of `glib-macros` 0.18.5 and `gtk3-macros` 0.18.2 in Tauri's Linux GTK chain. RustSec
lists no patched version and reports maintenance status, not a runtime exploit.
The locked Windows target does not include this chain. A targeted advisory
exception is accepted under the maintainer's delegation, with upstream migration
tracked in the backlog. This is risk acceptance, not a security patch. Do not
globally suppress unmaintained-package advisories or silently replace a transitive
macro implementation. Dependency checks passing with exceptions do not certify
cross-platform production readiness.

Before public release, confirm the rights to contributed source/assets, configure
private vulnerability reporting, and retain dependency/source notices. Common
secret-pattern scanning is evidence of hygiene, not a guarantee that every
credential or rights issue has been found.
