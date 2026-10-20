# M10 follow-up: existing Windows configuration paths

The native launcher canonicalizes its root. On Windows this changes a normal
`C:\...` configuration path to `\\?\C:\...`, while older local manifests retain
the normal spelling. Preserve the recorded digest and recognize only aliases of
the supplied configuration path; do not refresh the manifest automatically.

Files: `crates/vigil-service/src/integrity.rs` and the extracted-package check.
Use a canonical key for newly written config entries, accept the known original,
absolute and Windows display spellings on verification, and reject duplicate
aliases. Never resolve paths supplied by an untrusted manifest.

Tests: old manifest with the canonical launcher path, changed config still
detected, duplicate config entries refused, workspace format/Clippy/tests on
Windows and Linux, and extracted ZIP plus live native status. Demo:
`Start Vigil.cmd status` must report an empty `integrity_issues` list without
rewriting the existing manifest or configuration.

Reference: Rust's [canonicalize documentation](https://doc.rust-lang.org/std/fs/fn.canonicalize.html)
describes Windows extended-length paths.

Verified on 2026-10-13: Windows and Linux workspace tests and strict Clippy pass.
The extracted ZIP accepts an older ordinary-path manifest without rewriting it,
still reports tampered rules and refuses a damaged package. The rebuilt MSI
passes install, metadata-fixture upgrade and uninstall acceptance. The normal
native service/tray is running with an empty integrity status, unchanged config
and unchanged manifest. The archive and MSI contain the rebuilt service.
