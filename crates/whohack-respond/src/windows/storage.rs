use anyhow::{Result, ensure};
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{
    DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, SetFileSecurityW,
};

/// Protect only whohack's own vault/staging directories. Owner, SYSTEM, and local
/// administrators have access; no host-wide policy is modified.
pub(crate) fn private_directory(path: &Path) -> Result<()> {
    let sddl: Vec<u16> = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;OW)"
        .encode_utf16()
        .chain(Some(0))
        .collect();
    let path: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let mut sd = std::ptr::null_mut();
    // SAFETY: null-terminated UTF-16 strings and a valid out-pointer.
    ensure!(
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut sd,
                std::ptr::null_mut(),
            )
        } != 0,
        "create private vault descriptor: {}",
        std::io::Error::last_os_error()
    );
    let ok = unsafe {
        SetFileSecurityW(
            path.as_ptr(),
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            sd,
        )
    };
    let error = std::io::Error::last_os_error();
    unsafe {
        LocalFree(sd);
    }
    ensure!(ok != 0, "protect vault directory: {error}");
    Ok(())
}
