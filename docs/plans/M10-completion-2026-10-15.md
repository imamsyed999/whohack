# M10 continuation: approved release preparation

The maintainer authorized the remaining work and dependency decisions on
2026-10-15. Complete concrete engineering and acceptance work; report unavailable
hardware, credentials and model qualification data as external release gates.

1. Update `CLAUDE.md`, scoped dependency policy and license review. Audit both
   locked Cargo workspaces and record the GTK procedural-macro advisory review.
2. Complete the native Windows response-helper acceptance using only owned
   disposable executables. Fix failures and preserve prompt-only host operation.
3. Make cross-built native tests portable, run the entire Windows workspace and
   repair launcher health reporting. Verify normal startup clears stale failure.
4. Build native Windows binaries and refresh ZIP/MSI/source artifacts with notices;
   test installation, runtime, failure recovery and source archive hygiene.
5. Address additional release engineering supported by this environment, including
   Linux packaging and response recovery. Give each independently scoped change
   its own test evidence. Keep the remaining-platform requirements explicit.

Validation: formatting, strict Clippy, both workspace dependency audits, native
Windows and Linux tests, bounded owned-process response acceptance, packaging
acceptance, checksums and a dated machine-readable/readable readiness report.

Execution: policy/instructions updated; both audits pass with documented
exceptions. Native release builds, ZIP/MSI lifecycle checks, real Windows UI,
Linux deb/rpm container acceptance and source hygiene checks completed. The native
host was updated with its manual-only config unchanged. Ordinary tests: Linux
236 passed; Windows 228 passed and one OS-blocked executable. Debug-helper UAC
acceptance passed; optimized-helper consent timed out. Those external/remaining
gates are retained in the 2026-10-15 readiness report, not marked complete.
