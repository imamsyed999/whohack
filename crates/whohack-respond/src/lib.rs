//! Response is explicitly enabled by the operator. Every operation revalidates
//! the alert's captured identity; PID-only actions are deliberately absent.
#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
mod linux;
pub mod manager;
pub mod quarantine;
#[cfg(windows)]
#[allow(unsafe_code)]
mod windows;

use anyhow::{Result, bail, ensure};
use serde::{Deserialize, Serialize};
use whohack_core::{PathClass, ProcessInfo};

pub use manager::{ActionRecord, ActionStatus, Manager};

#[cfg(windows)]
pub fn run_windows_network_helper(request: &str) -> anyhow::Result<()> {
    windows::broker::run(request)
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Capabilities {
    pub network: bool,
    pub suspend: bool,
    pub terminate: bool,
    pub quarantine: bool,
    pub network_scope: String,
    pub limitation: String,
}

/// An owned, reversible OS operation. Implementations release on drop as well.
pub trait Lease: std::fmt::Debug + Send {
    fn release(&mut self) -> Result<()>;
    /// Read-only verification where the OS exposes an owned operation's state.
    fn intact(&self) -> Result<bool> {
        Ok(true)
    }
    fn recovery_data(&self) -> serde_json::Value {
        serde_json::Value::Null
    }
}

pub trait Backend: std::fmt::Debug + Send {
    fn capabilities(&self) -> Capabilities;
    fn automatic_available(&self) -> bool {
        true
    }
    fn block(&mut self, target: &ProcessInfo) -> Result<Box<dyn Lease>>;
    fn suspend(&mut self, target: &ProcessInfo) -> Result<Box<dyn Lease>>;
    fn terminate(&mut self, target: &ProcessInfo) -> Result<()>;
    fn recover_release(
        &mut self,
        _target: &ProcessInfo,
        _action: whohack_core::Action,
        _data: &serde_json::Value,
    ) -> Result<()> {
        bail!(
            "this operation has no safe automatic recovery; inspect its target before manual recovery"
        )
    }
}

pub fn native_backend() -> Box<dyn Backend> {
    #[cfg(windows)]
    {
        Box::new(windows::WindowsBackend)
    }
    #[cfg(target_os = "linux")]
    {
        Box::new(linux::LinuxBackend)
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        Box::new(Unavailable)
    }
}

#[cfg(not(any(windows, target_os = "linux")))]
#[derive(Debug)]
struct Unavailable;
#[cfg(not(any(windows, target_os = "linux")))]
impl Backend for Unavailable {
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            limitation: "Process enforcement requires the entitled macOS helper".into(),
            ..Default::default()
        }
    }
    fn block(&mut self, _: &ProcessInfo) -> Result<Box<dyn Lease>> {
        bail!("network response unavailable on this platform")
    }
    fn suspend(&mut self, _: &ProcessInfo) -> Result<Box<dyn Lease>> {
        bail!("suspension unavailable on this platform")
    }
    fn terminate(&mut self, _: &ProcessInfo) -> Result<()> {
        bail!("termination unavailable on this platform")
    }
}

/// Conservative exclusions remain in force even in automatic mode. In
/// particular, never interfere with the operating system or built-in antivirus.
pub(crate) fn guard(target: &ProcessInfo) -> Result<()> {
    ensure!(
        target.pid > 4 && target.pid != std::process::id(),
        "protected process"
    );
    ensure!(
        target.start_time > 0,
        "process has no verified creation time"
    );
    ensure!(
        target.path_class != PathClass::System,
        "system processes are protected"
    );
    ensure!(
        target.exe.sha256 != [0; 32],
        "process has no verified image digest"
    );
    let path = target.exe.path.replace('\\', "/").to_ascii_lowercase();
    let name = path.rsplit('/').next().unwrap_or("");
    if path.contains("/windows/")
        || path.contains("/windows defender/")
        || path.contains("/microsoft defender/")
        || path.contains("/microsoft/windows defender/")
        || matches!(
            name,
            "msmpeng.exe"
                | "mssense.exe"
                | "nissrv.exe"
                | "securityhealthservice.exe"
                | "whohack-service.exe"
                | "whohack-service"
                | "whohack-response-helper.exe"
                | "whohack-launcher.exe"
                | "whohack-tray.exe"
                | "whohack.exe"
                | "vigil-service.exe"
                | "vigil-service"
                | "vigil-response-helper.exe"
                | "vigil-launcher.exe"
                | "vigil-tray.exe"
                | "vigil.exe"
                | "launchd"
                | "systemd"
                | "init"
        )
    {
        bail!("operating system and protection services are protected");
    }
    Ok(())
}

pub(crate) fn digest_file(path: &std::path::Path) -> Result<[u8; 32]> {
    use sha2::{Digest, Sha256};
    use std::io::Read;
    let mut input = std::fs::File::open(path)?;
    let mut hash = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = input.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hash.update(&buf[..n]);
    }
    Ok(hash.finalize().into())
}
