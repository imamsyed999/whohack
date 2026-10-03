# Backlog

Work that is known but out of scope for the current milestone. Each item names the
milestone expected to pick it up.

## From M0

- **Remaining crates (M1+):** create `vigil-collect`, `vigil-taint`, `vigil-tags`,
  `vigil-intel`, `vigil-detect`, `vigil-decide`, `vigil-respond`, and `vigil-ipc` in the
  milestone that first needs each.
- **First-seen destinations (M4):** the `connections` table is pruned with events, so
  long-term "first seen" state belongs in `vigil-intel` (persisted separately), not in
  `connections`.
- **Detection config (M4–M6):** add the fusion thresholds (§10), the Tier 3 toggle, feed
  settings, and the per-OS sensitive path table (§9) to `Config` as each feature lands.
- **CI coverage (M10, or earlier if runners are cheap):** add Windows ARM64
  (`windows-11-arm`) and macOS Intel (`macos-13`/`macos-15-intel`) runners. The spec
  targets both; CI currently covers x64 Windows, Apple Silicon macOS, and x64 Linux.
- **Typed domain records (M3, M6):** `DecisionRecord.answers` is stored as raw JSON. When
  `vigil-decide::Answer` exists, add typed conversion helpers. `ProfileRecord` gets the
  same treatment for M3's `Profile`.
- **Config file permissions (M10):** the installer should make the system config file
  writable only by SYSTEM/root (it controls the response mode).

## From M1

- **Exec image changes (M2):** a `ProcessStart` can repeat for the same PID. eBPF reports
  every `execve`, and the startup snapshot can overlap live events. Lineage must treat it as
  an exec (new image, same lineage) and stay idempotent.
- **eBPF fork tracking (M2/M5):** forks without exec are not reported. Child lineage relies
  on `ppid` read from `/proc` at exec time. A `sched_process_fork` program would close the
  gap for fork-only workers.
- **UDP attribution on Linux (M5):** UDP comes only from `/proc` polling of connected
  sockets, so `sendto()` on unconnected sockets is invisible. A `udp_sendmsg` kprobe with
  CO-RE would fix this.
- **Byte counters (M5):** Tier 1 needs bytes up/down per flow (`network:large_upload`, the
  up/down ratio). Add a `NetStats` event kind fed by eBPF `tcp_sendmsg`/`tcp_cleanup_rbuf`
  and ETW send/recv sizes.
- **Windows ETW validation (CI or maintainer):** run `vigil-service --monitor` elevated
  once, and confirm the Kernel-Network port byte order and DNS-Client `QueryResults`
  parsing against live data.
- **Windows UDP without ETW:** IP Helper exposes no UDP remote endpoints, so UDP and DNS
  need the elevated ETW backend.

## From M2

- **Security advisories (track):** bump yara-x as soon as it moves to a patched wasmtime
  (>= 49.0.2 covers RUSTSEC-2026-0222/-0269/-0316/-0327). Then remove those ignores from
  `deny.toml`, and re-check the bincode and rsa notices.
- **Persistent hash cache (M5, idle budget):** file digests are cached in memory only, so
  a restart rehashes every running executable once. Persist (path, size, mtime, sha256) in
  the store.
- **macOS quarantine URL (M9):** read the source URL from the per-user LaunchServices
  QuarantineEventsV2 database, keyed by the quarantine UUID.
- **Linux download watcher (M5):** files dropped into Downloads/temp by tools that set no
  xattr (curl, wget, unzip) get origin `Unknown` once moved out of Downloads. Use a
  fanotify/inotify watcher that marks new executables there as `Downloaded { url: None }`.
- **Script working directory on Windows/macOS:** relative script paths are only resolved
  on Linux (`/proc/<pid>/cwd`). Elsewhere a script started by relative path is not detected.
- **Startup analysis latency (M5, performance budget):** on a busy machine the startup
  snapshot makes the analysis stage hash and signature-check hundreds of executables one
  after another (CI showed delays of more than 10 s). Fix with a worker pool for first-sight
  file analysis that preserves per-PID event order, plus the persistent hash cache above.
