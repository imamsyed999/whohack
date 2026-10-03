//! Code-signature state (SPEC §8 "Signatures").
//!
//! | OS | Method |
//! |---|---|
//! | Windows | WinVerifyTrust: embedded Authenticode, then the system catalog |
//! | macOS | `codesign --verify` + `codesign -dv` |
//! | Linux | Package ownership (dpkg / rpm); dpkg md5sums detect modified package files |

#[cfg(target_os = "linux")]
pub mod linux;
pub mod macos;
#[cfg(windows)]
pub mod windows;

use std::path::Path;

use vigil_core::SignState;

/// Result of a signature check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignVerdict {
    pub state: SignState,
    /// Installed by the OS package manager (Linux).
    pub package_owned: bool,
}

impl SignVerdict {
    pub fn unsigned() -> Self {
        SignVerdict {
            state: SignState::Unsigned,
            package_owned: false,
        }
    }
}

/// Per-OS signature checker. Keeps lazily built indexes (Linux package DB).
#[derive(Debug, Default)]
pub struct SignChecker {
    #[cfg(target_os = "linux")]
    packages: linux::PackageDb,
}

impl SignChecker {
    pub fn new() -> Self {
        SignChecker::default()
    }

    pub fn check(&mut self, path: &Path) -> SignVerdict {
        #[cfg(target_os = "linux")]
        {
            self.packages.verdict(path)
        }
        #[cfg(target_os = "macos")]
        {
            macos::check(path)
        }
        #[cfg(windows)]
        {
            windows::check(path)
        }
        #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
        {
            let _ = path;
            SignVerdict::unsigned()
        }
    }
}
