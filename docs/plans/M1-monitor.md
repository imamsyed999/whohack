# M1 — Monitor

Goal: live process and network collection on Linux, Windows, and macOS (limited mode), with
PID attribution, a DNS cache, and `vigil-service --monitor` printing live connections per
process.

Acceptance: a test spawns a child process that opens a TCP connection, and the collector
reports a `NetConnect` event carrying **that child's PID**. The spec says `curl`; the test
uses our own child process so it is deterministic and needs no internet.

| Path | Where it runs |
|---|---|
| Linux procfs | WSL, unprivileged |
| Linux eBPF | WSL as root |
| Windows polling | locally, unelevated |
| Windows ETW | needs an elevated run, by the maintainer or CI |
| macOS limited mode | compile-checked for `aarch64-apple-darwin`; executed in CI |

## Design

```
            ┌ Linux:   EbpfCollector (feature "ebpf", root)      ─┐
collectors ─┤          PollCollector<ProcfsSource>  (fallback)   ├─ mpsc<Event> ─► Pipeline ─► EventBus ─► monitor printer
            │          DnsSniffer (AF_PACKET, root)              │                (Enricher:            └► store writer
            ├ Windows: EtwCollector (admin)                      │                 DNS cache)
            │          PollCollector<WinSource> (fallback)       │
            └ macOS:   PollCollector<MacSource>  ("limited mode")┘
```

- **Shared poller.** `PollCollector<S: SnapshotSource>` holds all the diffing logic and is
  unit-tested with a fake source. Each OS implements only
  `SnapshotSource::{processes(), sockets()}`.
- **Startup snapshot.** Every backend first emits a `ProcessStart` for each running process,
  stamped with its real start time, so the process table is complete from the start.
- **Backend choice.** `backend = "auto"` picks native (eBPF/ETW) when privileged and
  available, otherwise polling. On Linux, polling still covers UDP flows even when eBPF is
  active, because eBPF only covers TCP.
- **Loopback** traffic is dropped unless `collect.include_loopback = true`, which the tests
  set.

### Linux eBPF (feature `ebpf`)

- **Code layout.** The eBPF programs live in `ebpf/vigil-ebpf` (`no_std`, its own workspace,
  built by `aya-build` with nightly and `bpf-linker`). Shared `#[repr(C)]` records live in
  `crates/vigil-ebpf-common`.
- **Tracepoints.**
  - `sched/sched_process_exec` reads the pid and the filename via `__data_loc`.
  - `sched/sched_process_exit` filters to thread-group leaders using `tid == tgid`.
  - `sock/inet_sock_set_state` fires on `newstate == TCP_SYN_SENT`, which happens in the
    connecting task's context, so `bpf_get_current_pid_tgid` is the connecting process.
- **Delivery.** One `RingBuf` carries events to userspace, read through tokio `AsyncFd`.
- **Offset check.** Before loading, userspace parses each tracepoint's `format` file and
  checks that the field offsets match the compiled-in ones. On a mismatch it logs a warning
  and falls back to polling.
- **What userspace adds.** It enriches exec events with `/proc/<pid>/{exe,cmdline,stat}`
  (ppid and start time). If the process has already exited, it falls back to the filename
  from the event.

### DNS

- **Linux:** `DnsSniffer` captures UDP source-port-53 responses on all interfaces through an
  `AF_PACKET` socket (root), and parses A/AAAA answers with a small, bounds-checked parser.
- **Windows:** ETW `Microsoft-Windows-DNS-Client` (event 3008, QueryName + QueryResults)
  when elevated.
- **macOS limited mode:** no DNS visibility.
- **Unknown visibility.** `DnsCache` tracks whether any DNS source is live. Later
  milestones must not tag `network:raw_ip_no_dns` when visibility is off.

## Core type change (documented in `vigil-core::types`)

`EventKind::ProcessStart` gains fields. Collectors are the only place this data exists, and
taint/lineage (M2) and tagging (M3) need it:

```rust
ProcessStart { ppid: u32, exe: String, cmdline: Option<String> }
```

`cmdline` is used **only** by Tier 0 rules and the tagger, for example
`vssadmin delete shadows` → `defense_evasion:shadow_copy_delete`. It is never placed in the
decision-model state (SPEC §12.3).

`vigil-core` also gets a default-on `store` feature that gates rusqlite, so crates that don't
need the database don't pull it in. This lets OS-specific crates compile for macOS from Linux,
and on the Windows host despite the Smart App Control block on `libsqlite3-sys`.

## Crates and files

```
crates/vigil-core/          + feature "store"; ProcessStart fields; EventBus::publish
crates/vigil-ebpf-common/   #[repr(C)] ExecEvent / ExitEvent / ConnectEvent shared with eBPF
ebpf/vigil-ebpf/            no_std tracepoint programs (separate workspace)
crates/vigil-collect/
  src/lib.rs                Collector trait (SPEC §8), CollectConfig, select_collectors()
  src/poll.rs               PollCollector<S> + SnapshotSource trait + diff logic (OS-independent)
  src/proc_table.rs         pid → ProcEntry, keyed by (pid, start_time)
  src/linux/procfs.rs       ProcfsSource: /proc/<pid>/stat|exe|cmdline, /proc/net/{tcp,tcp6,udp,udp6}, fd inode map
  src/linux/ebpf.rs         EbpfCollector (cfg feature "ebpf")
  src/linux/dns_sniff.rs    DnsSniffer (AF_PACKET)
  src/dns_wire.rs           DNS response parser (OS-independent, fuzz-style tests)
  src/windows/poll.rs       WinSource: ToolHelp32 + QueryFullProcessImageNameW + GetExtendedTcp/UdpTable
  src/windows/etw.rs        EtwCollector (ferrisetw): Kernel-Process, Kernel-Network, DNS-Client
  src/macos/libproc.rs      MacSource: proc_listallpids, proc_pidinfo, proc_pidfdinfo (libc)
crates/vigil-intel/
  src/dns_cache.rs          DnsCache: ip → (domain, expiry), bounded, visibility flag
  src/enrich.rs             Enricher: DnsQuery → cache; NetConnect → domain + dns_before
crates/vigil-service/
  src/pipeline.rs           collectors → Enricher → EventBus
  src/monitor.rs            --monitor: live per-process connection printer
  src/store_writer.rs       subscribes to the bus and persists events (batched per tick)
```

## Config (`[collect]`)

```toml
[collect]
backend = "auto"          # auto | poll | native
poll_interval_ms = 1000   # 100..=60000
include_loopback = false
dns = true                # enable DNS visibility source when available
```

## Tests

- **`poll` diff logic** (fake source):
  - New pid → `ProcessStart`; a vanished pid → `ProcessExit`.
  - A reused pid with a new start time gives exit then start.
  - A new socket tuple gives one `NetConnect`; it is not re-emitted while the socket persists.
  - Loopback is filtered.
  - A socket whose inode has no owning pid is dropped.
- **procfs parsing:** fixtures for `/proc/net/tcp` and `tcp6` (byte-order traps), `stat`
  with spaces or parentheses in `comm`, and cmdline NUL splitting.
- **`dns_wire`:** A/AAAA/CNAME answers, compression pointers, truncated and garbage input
  (must never panic), and pointer loops.
- **`DnsCache` / `Enricher`:** lookup, expiry, capacity bound, `dns_before` true/false, and
  visibility.
- **PID attribution, live on each OS:** a test listener on 127.0.0.1 and a spawned child
  that connects. The test asserts that the collector emits `NetConnect` with
  `pid == child.id()`. Linux polling runs unprivileged. Linux eBPF and Windows ETW are
  `#[ignore]` unless privileged, and run via `--ignored` as root or admin.
- **macOS:** `cargo check --target aarch64-apple-darwin -p vigil-collect` on Linux.
- **Service:** `--monitor --duration-secs N` runs headless and prints connection lines,
  covered by an end-to-end test using loopback mode.

## Demo

```
vigil-service --config cfg.toml --monitor
  12:00:01.204  pid=4242 curl           -> 93.184.216.34:443/tcp  example.com  dns_before=yes
```

## Outcome (2026-10-03)

Status: **implemented**.

| Path | Status |
|---|---|
| Linux procfs polling | **Passes live** (unprivileged, WSL): a child's TCP connection is attributed to the child's PID. |
| Linux eBPF | **Passes live as root:** a 300 ms child gets its exec, connect, and exit, all attributed. |
| Linux DNS sniffer | **Passes live as root**, hermetic loopback test. The in-kernel cBPF filter is also verified by an interpreter unit test. |
| `vigil-service --monitor` | End-to-end test passes: the test process's own connection appears in the output, and events are persisted. |
| Windows (polling + ETW) | Compiles; clippy clean for `x86_64-pc-windows-msvc`. Can't run locally: Smart App Control blocks build scripts (`libsqlite3-sys`, `num-traits`). The runtime tests, including attribution, run on the CI Windows runner. |
| macOS limited mode | Compiles; clippy clean for `aarch64-apple-darwin`. Struct layouts were hand-checked against xnu headers, with size tests. The runtime tests run on the CI macOS runner. |

Deviations and findings:

- **eBPF build script.** `aya-build` assumes the eBPF crate is a member of the host
  workspace, which breaks `cargo test --workspace`. `crates/vigil-collect/build.rs`
  reproduces its nightly invocation from the eBPF crate's own directory.
- **PID namespaces.** WSL2 (like containers) runs in a separate PID namespace, so
  `bpf_get_current_pid_tgid` reported the wrong PIDs. The programs now use
  `bpf_get_ns_current_pid_tgid` with the collector's namespace, which is passed in as
  load-time globals.
- **ETW timestamps.** These depend on the session clock (QPC by default), so ETW events
  are stamped when they are received.
- **bpf-linker install.** `cargo install bpf-linker` needs a system LLVM, so the prebuilt
  release binary is used instead (WSL and CI).
