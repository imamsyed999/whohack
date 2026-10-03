# Building Vigil

## Everyday build (all OSes)

You need:

- Rust stable (the version is pinned by `rust-toolchain.toml`);
- a C compiler, for the bundled SQLite.

Then:

```sh
cargo build --workspace
cargo test --workspace
```

## Linux eBPF collector (optional, recommended for releases)

The eBPF backend gives real-time, exact PID attribution, including for very short-lived
processes. Without it, Linux uses `/proc` polling. Building it requires:

```sh
rustup toolchain install nightly --component rust-src
# Prebuilt bpf-linker (building it from source needs a matching LLVM):
curl -sSfLO https://github.com/aya-rs/bpf-linker/releases/latest/download/bpf-linker-x86_64-unknown-linux-musl.tar.zst
tar --zstd -xf bpf-linker-x86_64-unknown-linux-musl.tar.zst -C ~/.local/bin
```

Build and run (eBPF needs root):

```sh
cargo build -p vigil-service --features ebpf
sudo ./target/debug/vigil-service --config vigil.toml --monitor
```

Run the live tests as root:

```sh
sudo -E env "PATH=$PATH" cargo test -p vigil-collect --features ebpf -- --include-ignored
```

The eBPF programs live in `ebpf/vigil-ebpf`, which is its own workspace targeting
`bpfel-unknown-none`. `crates/vigil-collect/build.rs` compiles them and embeds the object.
Before loading, the collector checks the tracepoint field offsets against
`/sys/kernel/tracing/events/*/format` and falls back to polling on any mismatch. PIDs are
reported in the collector's own PID namespace, so Vigil works inside containers and WSL2.

## Windows

`cargo build --workspace` with the MSVC toolchain.

The ETW collector needs an **elevated** (administrator) process. Unelevated, Vigil falls
back to ToolHelp and IP Helper polling, which covers processes and TCP but not UDP or DNS.

If Windows **Smart App Control** is on, it may block freshly compiled build scripts with
*"An Application Control policy has blocked this file"* (os error 4551). Build in WSL or CI
instead. Do not weaken OS security settings to build Vigil.

## macOS

`cargo build --workspace`. This builds **limited mode**: libproc polling with no DNS
visibility.

Full mode (Endpoint Security + Network Extension) needs Apple-granted entitlements; see
milestone M9 in the spec.

## Cross-checking other OSes from Linux

```sh
rustup target add x86_64-pc-windows-msvc aarch64-apple-darwin
cargo clippy -p vigil-collect --target x86_64-pc-windows-msvc --tests -- -D warnings
cargo clippy -p vigil-collect --target aarch64-apple-darwin --tests -- -D warnings
```
