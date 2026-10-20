//! Documented user-mode Windows APIs; no driver or antivirus policy changes.
pub(crate) mod broker;
mod process;
pub(crate) mod storage;
mod wfp;
use crate::{Backend, Capabilities, Lease};
use anyhow::Result;
use whohack_core::ProcessInfo;

#[derive(Debug)]
pub struct WindowsBackend;
impl Backend for WindowsBackend {
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            network: elevated() || broker::available(), suspend: true, terminate: true, quarantine: true,
            network_scope: "New inbound/outbound connections for every instance of this executable".into(),
            limitation: "Manual network blocks request Windows administrator consent for a separate helper. Existing flows may remain open. Suspension resumes when whohack shuts down normally; a service crash requires manual recovery.".into(),
        }
    }
    fn automatic_available(&self) -> bool {
        elevated()
    }
    fn block(&mut self, target: &ProcessInfo) -> Result<Box<dyn Lease>> {
        let _identity = process::open(target, 0)?;
        if !elevated() {
            return Ok(Box::new(broker::Block::new(target)?));
        }
        Ok(Box::new(wfp::Block::new(&target.exe.path)?))
    }
    fn suspend(&mut self, target: &ProcessInfo) -> Result<Box<dyn Lease>> {
        Ok(Box::new(process::Suspension::new(target)?))
    }
    fn terminate(&mut self, target: &ProcessInfo) -> Result<()> {
        process::terminate(target)
    }
    fn recover_release(
        &mut self,
        target: &ProcessInfo,
        action: whohack_core::Action,
        data: &serde_json::Value,
    ) -> Result<()> {
        anyhow::ensure!(
            action == whohack_core::Action::SuspendAndAsk,
            "only suspensions require Windows recovery"
        );
        process::recover(target, data)
    }
}

fn elevated() -> bool {
    use windows_sys::Win32::{
        Foundation::CloseHandle,
        Security::{GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation},
        System::Threading::{GetCurrentProcess, OpenProcessToken},
    };
    // SAFETY: query-only token handle and correctly sized output buffer.
    unsafe {
        let mut token = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return false;
        }
        let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut used = 0;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            (&raw mut elevation).cast(),
            std::mem::size_of_val(&elevation) as u32,
            &mut used,
        );
        CloseHandle(token);
        ok != 0 && elevation.TokenIsElevated != 0
    }
}
