//! With feature `ebpf` on a Linux target, compiles `ebpf/vigil-ebpf` for
//! `bpfel-unknown-none` into `OUT_DIR/vigil-ebpf`.
//!
//! Requires `rustup` with a nightly toolchain that has `rust-src`, and
//! `bpf-linker` on PATH. The eBPF crate is its own workspace, so cargo is run
//! from its directory (`aya-build` assumes a shared workspace, which would
//! break host-side `cargo test --workspace`). Flags mirror aya-build's.

fn main() -> Result<(), String> {
    println!("cargo:rerun-if-changed=build.rs");
    if std::env::var_os("CARGO_FEATURE_EBPF").is_some()
        && std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("linux")
    {
        build_ebpf()?;
    }
    Ok(())
}

fn build_ebpf() -> Result<(), String> {
    use std::path::{Path, PathBuf};
    use std::process::Command;

    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../ebpf/vigil-ebpf")
        .canonicalize()
        .map_err(|e| format!("eBPF crate not found: {e}"))?;
    println!("cargo:rerun-if-changed={}", root.join("src").display());
    println!(
        "cargo:rerun-if-changed={}",
        root.join("Cargo.toml").display()
    );
    let common = root.join("../../crates/vigil-ebpf-common/src");
    println!("cargo:rerun-if-changed={}", common.display());

    let out_dir = PathBuf::from(std::env::var("OUT_DIR").map_err(|e| e.to_string())?);
    let target_dir = out_dir.join("ebpf-target");
    let arch = std::env::var("CARGO_CFG_TARGET_ARCH").map_err(|e| e.to_string())?;
    let rustflags = [
        format!("--cfg=bpf_target_arch=\"{arch}\""),
        "-Cdebuginfo=2".into(),
        "-Clink-arg=--btf".into(),
    ]
    .join("\u{1f}");

    let status = Command::new("rustup")
        .args(["run", "nightly", "cargo", "build", "--package", "vigil-ebpf", "--bins", "--release"])
        .args(["--target", "bpfel-unknown-none", "-Z", "build-std=core", "--target-dir"])
        .arg(&target_dir)
        .current_dir(&root)
        .env_remove("RUSTC")
        .env_remove("RUSTC_WORKSPACE_WRAPPER")
        .env_remove("RUSTFLAGS")
        .env_remove("CARGO_TARGET_DIR")
        .env_remove("CARGO_BUILD_TARGET")
        .env("CARGO_ENCODED_RUSTFLAGS", rustflags)
        .status()
        .map_err(|e| format!("running `rustup run nightly cargo` failed: {e} (install rustup + nightly with rust-src, and bpf-linker)"))?;
    if !status.success() {
        return Err(format!("building eBPF programs failed ({status})"));
    }
    let obj = target_dir.join("bpfel-unknown-none/release/vigil-ebpf");
    std::fs::copy(&obj, out_dir.join("vigil-ebpf"))
        .map_err(|e| format!("copying {}: {e}", obj.display()))?;
    Ok(())
}
