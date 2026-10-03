//! Windows collectors: ETW when elevated, ToolHelp + IP Helper polling otherwise.
#![allow(unsafe_code)]

pub mod etw;
pub mod poll;

use std::sync::Arc;
use std::time::Duration;

use vigil_core::config::{CollectBackend, CollectConfig};
use windows_sys::Win32::Foundation::{CloseHandle, FILETIME, HANDLE};
use windows_sys::Win32::Security::{
    GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

use crate::poll::{PollCollector, PollScope};
use crate::{Collector, Selection};

/// 100 ns intervals between 1601-01-01 and 1970-01-01.
const FILETIME_UNIX_EPOCH: u64 = 116_444_736_000_000_000;

/// Converts a FILETIME value (100 ns since 1601) to Unix ms.
pub fn filetime_to_unix_ms(ft: u64) -> i64 {
    i64::try_from(ft.saturating_sub(FILETIME_UNIX_EPOCH) / 10_000).unwrap_or(i64::MAX)
}

pub fn filetime_u64(ft: &FILETIME) -> u64 {
    (u64::from(ft.dwHighDateTime) << 32) | u64::from(ft.dwLowDateTime)
}

/// Owned Win32 handle, closed on drop.
pub(crate) struct OwnedHandle(pub HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: we own the handle and close it exactly once.
            unsafe { CloseHandle(self.0) };
        }
    }
}

/// True when the current process token is elevated (admin).
pub fn is_elevated() -> bool {
    let mut token: HANDLE = std::ptr::null_mut();
    // SAFETY: GetCurrentProcess returns a pseudo-handle; token is a valid out-pointer.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return false;
    }
    let token = OwnedHandle(token);
    let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
    let mut len = 0u32;
    // SAFETY: elevation is a correctly sized out-buffer for TokenElevation.
    let ok = unsafe {
        GetTokenInformation(
            token.0,
            TokenElevation,
            (&raw mut elevation).cast(),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut len,
        )
    };
    ok != 0 && elevation.TokenIsElevated != 0
}

pub fn select(cfg: &CollectConfig) -> anyhow::Result<Selection> {
    let elevated = is_elevated();
    let interval = Duration::from_millis(cfg.poll_interval_ms);
    let mut notes = Vec::new();
    let want_native = cfg.backend != CollectBackend::Poll;
    if want_native && elevated {
        match etw::EtwCollector::new(cfg.include_loopback, cfg.dns) {
            Ok(c) => {
                notes.push(format!(
                    "processes + network{}: ETW (Kernel-Process, Kernel-Network{})",
                    if cfg.dns { " + DNS" } else { "" },
                    if cfg.dns { ", DNS-Client" } else { "" }
                ));
                return Ok(Selection {
                    collectors: vec![Arc::new(c) as Arc<dyn Collector>],
                    dns_visible: cfg.dns,
                    notes,
                });
            }
            Err(e) => notes.push(format!("ETW: unavailable ({e:#})")),
        }
    } else if want_native {
        notes.push("ETW: requires an elevated (administrator) process".into());
    }
    if cfg.backend == CollectBackend::Native {
        anyhow::bail!(
            "collect.backend = \"native\" but ETW is unavailable: {}",
            notes.join("; ")
        );
    }
    notes.push(
        "processes + TCP: ToolHelp/IP Helper polling (UDP and DNS need ETW; run elevated for full visibility)"
            .into(),
    );
    Ok(Selection {
        collectors: vec![Arc::new(PollCollector::new(
            "windows-poll",
            poll::WinSource::new(),
            interval,
            cfg.include_loopback,
            PollScope::ALL,
        ))],
        dns_visible: false,
        notes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filetime_conversion() {
        assert_eq!(filetime_to_unix_ms(FILETIME_UNIX_EPOCH), 0);
        assert_eq!(filetime_to_unix_ms(FILETIME_UNIX_EPOCH + 10_000), 1);
        assert_eq!(filetime_to_unix_ms(0), 0, "pre-1970 clamps to 0");
        let ft = FILETIME {
            dwLowDateTime: 0x0000_0001,
            dwHighDateTime: 0x0000_0002,
        };
        assert_eq!(filetime_u64(&ft), 0x2_0000_0001);
    }

    #[test]
    fn elevation_check_does_not_fail() {
        let _ = is_elevated();
    }
}
