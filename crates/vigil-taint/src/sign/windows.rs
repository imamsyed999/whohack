//! Windows Authenticode verification with WinVerifyTrust.
//!
//! Embedded signatures are checked first; most OS binaries are instead
//! signed through a system catalog, which is checked when no embedded
//! signature exists. Revocation is not checked online (no network calls).
#![allow(unsafe_code)]

use std::os::windows::ffi::OsStrExt;
use std::path::Path;

use vigil_core::SignState;
use windows_sys::Win32::Foundation::{CloseHandle, GENERIC_READ, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Security::Cryptography::Catalog::{
    CATALOG_INFO, CryptCATAdminAcquireContext2, CryptCATAdminCalcHashFromFileHandle2,
    CryptCATAdminEnumCatalogFromHash, CryptCATAdminReleaseCatalogContext,
    CryptCATAdminReleaseContext, CryptCATCatalogInfoFromContext,
};
use windows_sys::Win32::Security::Cryptography::{
    CERT_NAME_SIMPLE_DISPLAY_TYPE, CertGetNameStringW,
};
use windows_sys::Win32::Security::WinTrust::{
    WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_CATALOG_INFO, WINTRUST_DATA, WINTRUST_DATA_0,
    WINTRUST_FILE_INFO, WTD_CACHE_ONLY_URL_RETRIEVAL, WTD_CHOICE_CATALOG, WTD_CHOICE_FILE,
    WTD_REVOKE_NONE, WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY, WTD_UI_NONE,
    WTHelperGetProvSignerFromChain, WTHelperProvDataFromStateData, WinVerifyTrust,
};
use windows_sys::Win32::Storage::FileSystem::{CreateFileW, FILE_SHARE_READ, OPEN_EXISTING};
use windows_sys::core::GUID;

use super::SignVerdict;

const TRUST_E_NOSIGNATURE: i32 = 0x800B0100_u32 as i32;
const TRUST_E_SUBJECT_FORM_UNKNOWN: i32 = 0x800B0003_u32 as i32;
const TRUST_E_PROVIDER_UNKNOWN: i32 = 0x800B0001_u32 as i32;
const TRUST_E_BAD_DIGEST: i32 = 0x80096010_u32 as i32;
const TRUST_E_EXPLICIT_DISTRUST: i32 = 0x800B0111_u32 as i32;
const TRUST_E_CERT_SIGNATURE: i32 = 0x80096004_u32 as i32;
const CERT_E_REVOKED: i32 = 0x800B010C_u32 as i32;

/// DRIVER_ACTION_VERIFY {F750E6C3-38EE-11D1-85E5-00C04FC295EE}.
const DRIVER_ACTION_VERIFY: GUID = GUID {
    data1: 0xF750_E6C3,
    data2: 0x38EE,
    data3: 0x11D1,
    data4: [0x85, 0xE5, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE],
};

fn wide(s: &std::ffi::OsStr) -> Vec<u16> {
    s.encode_wide().chain([0]).collect()
}

/// Maps a WinVerifyTrust result to a signature state.
pub fn classify(status: i32) -> Option<SignState> {
    match status {
        0 => None, // trusted: caller fills in the publisher
        TRUST_E_NOSIGNATURE | TRUST_E_SUBJECT_FORM_UNKNOWN | TRUST_E_PROVIDER_UNKNOWN => {
            Some(SignState::Unsigned)
        }
        TRUST_E_BAD_DIGEST
        | TRUST_E_EXPLICIT_DISTRUST
        | TRUST_E_CERT_SIGNATURE
        | CERT_E_REVOKED => Some(SignState::Invalid),
        _ => Some(SignState::ValidUntrusted),
    }
}

/// Runs WinVerifyTrust on prepared data; returns (status, signer display name).
///
/// # Safety
/// `data` must be fully initialized with valid pointers for its union choice.
unsafe fn verify(data: &mut WINTRUST_DATA) -> (i32, Option<String>) {
    let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    data.dwStateAction = WTD_STATEACTION_VERIFY;
    // SAFETY: guaranteed by the caller.
    let status = unsafe {
        WinVerifyTrust(
            std::ptr::null_mut(),
            &mut action,
            (data as *mut WINTRUST_DATA).cast(),
        )
    };
    let mut signer = None;
    if status == 0 {
        // SAFETY: after a successful VERIFY the state handle refers to valid provider data.
        unsafe {
            let prov = WTHelperProvDataFromStateData(data.hWVTStateData);
            if !prov.is_null() {
                let sgnr = WTHelperGetProvSignerFromChain(prov, 0, 0, 0);
                if !sgnr.is_null() && (*sgnr).csCertChain > 0 && !(*sgnr).pasCertChain.is_null() {
                    let cert = (*(*sgnr).pasCertChain).pCert;
                    if !cert.is_null() {
                        let mut buf = vec![0u16; 512];
                        let n = CertGetNameStringW(
                            cert,
                            CERT_NAME_SIMPLE_DISPLAY_TYPE,
                            0,
                            std::ptr::null(),
                            buf.as_mut_ptr(),
                            buf.len() as u32,
                        );
                        if n > 1 {
                            signer = Some(String::from_utf16_lossy(&buf[..n as usize - 1]));
                        }
                    }
                }
            }
        }
    }
    data.dwStateAction = WTD_STATEACTION_CLOSE;
    // SAFETY: closing the state opened above.
    unsafe {
        WinVerifyTrust(
            std::ptr::null_mut(),
            &mut action,
            (data as *mut WINTRUST_DATA).cast(),
        )
    };
    (status, signer)
}

fn base_data(choice: u32, union: WINTRUST_DATA_0) -> WINTRUST_DATA {
    // SAFETY: WINTRUST_DATA is a plain C struct; all-zero is a valid start.
    let mut d: WINTRUST_DATA = unsafe { std::mem::zeroed() };
    d.cbStruct = std::mem::size_of::<WINTRUST_DATA>() as u32;
    d.dwUIChoice = WTD_UI_NONE;
    d.fdwRevocationChecks = WTD_REVOKE_NONE;
    d.dwUnionChoice = choice;
    d.Anonymous = union;
    d.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;
    d
}

fn verify_embedded(path: &[u16]) -> (i32, Option<String>) {
    let mut file = WINTRUST_FILE_INFO {
        cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: path.as_ptr(),
        hFile: std::ptr::null_mut(),
        pgKnownSubject: std::ptr::null_mut(),
    };
    let mut data = base_data(WTD_CHOICE_FILE, WINTRUST_DATA_0 { pFile: &mut file });
    // SAFETY: `file` and `path` outlive the call.
    unsafe { verify(&mut data) }
}

struct Handle(HANDLE);
impl Drop for Handle {
    fn drop(&mut self) {
        if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
            // SAFETY: we own the handle.
            unsafe { CloseHandle(self.0) };
        }
    }
}

fn verify_catalog(path: &[u16]) -> Option<(i32, Option<String>)> {
    // SAFETY: each call below receives valid, live buffers; handles are released on all paths.
    unsafe {
        let file = Handle(CreateFileW(
            path.as_ptr(),
            GENERIC_READ,
            FILE_SHARE_READ,
            std::ptr::null(),
            OPEN_EXISTING,
            0,
            std::ptr::null_mut(),
        ));
        if file.0 == INVALID_HANDLE_VALUE {
            return None;
        }
        let mut admin: isize = 0;
        let sha256: Vec<u16> = "SHA256".encode_utf16().chain([0]).collect();
        if CryptCATAdminAcquireContext2(
            &mut admin,
            &DRIVER_ACTION_VERIFY,
            sha256.as_ptr(),
            std::ptr::null(),
            0,
        ) == 0
        {
            return None;
        }
        let mut hash = vec![0u8; 64];
        let mut hash_len = hash.len() as u32;
        let result = (|| {
            if CryptCATAdminCalcHashFromFileHandle2(
                admin,
                file.0,
                &mut hash_len,
                hash.as_mut_ptr(),
                0,
            ) == 0
            {
                return None;
            }
            let cat = CryptCATAdminEnumCatalogFromHash(
                admin,
                hash.as_mut_ptr(),
                hash_len,
                0,
                std::ptr::null_mut(),
            );
            if cat == 0 {
                return None;
            }
            let mut info: CATALOG_INFO = std::mem::zeroed();
            info.cbStruct = std::mem::size_of::<CATALOG_INFO>() as u32;
            let got_info = CryptCATCatalogInfoFromContext(cat, &mut info, 0) != 0;
            let out = if got_info {
                let tag: Vec<u16> = vigil_core::hex::encode(&hash[..hash_len as usize])
                    .to_ascii_uppercase()
                    .encode_utf16()
                    .chain([0])
                    .collect();
                let mut ci = WINTRUST_CATALOG_INFO {
                    cbStruct: std::mem::size_of::<WINTRUST_CATALOG_INFO>() as u32,
                    dwCatalogVersion: 0,
                    pcwszCatalogFilePath: info.wszCatalogFile.as_ptr(),
                    pcwszMemberTag: tag.as_ptr(),
                    pcwszMemberFilePath: path.as_ptr(),
                    hMemberFile: file.0,
                    pbCalculatedFileHash: hash.as_mut_ptr(),
                    cbCalculatedFileHash: hash_len,
                    pcCatalogContext: std::ptr::null_mut(),
                    hCatAdmin: admin,
                };
                let mut data = base_data(WTD_CHOICE_CATALOG, WINTRUST_DATA_0 { pCatalog: &mut ci });
                Some(verify(&mut data))
            } else {
                None
            };
            CryptCATAdminReleaseCatalogContext(admin, cat, 0);
            out
        })();
        CryptCATAdminReleaseContext(admin, 0);
        result
    }
}

pub fn check(path: &Path) -> SignVerdict {
    let w = wide(path.as_os_str());
    let (status, signer) = verify_embedded(&w);
    let (status, signer) = if classify(status) == Some(SignState::Unsigned) {
        verify_catalog(&w).unwrap_or((status, signer))
    } else {
        (status, signer)
    };
    let state = classify(status).unwrap_or_else(|| SignState::ValidTrusted {
        publisher: signer.unwrap_or_else(|| "unknown".into()),
    });
    SignVerdict {
        state,
        package_owned: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_mapping() {
        assert_eq!(classify(0), None);
        assert_eq!(classify(TRUST_E_NOSIGNATURE), Some(SignState::Unsigned));
        assert_eq!(classify(TRUST_E_BAD_DIGEST), Some(SignState::Invalid));
        assert_eq!(
            classify(0x800B0109_u32 as i32),
            Some(SignState::ValidUntrusted),
            "untrusted root"
        );
    }

    #[test]
    fn system_binary_is_trusted_microsoft() {
        let windir = std::env::var("WINDIR").unwrap_or_else(|_| r"C:\Windows".into());
        let cmd = Path::new(&windir).join("System32").join("cmd.exe");
        match check(&cmd).state {
            SignState::ValidTrusted { publisher } => {
                assert!(publisher.contains("Microsoft"), "{publisher}")
            }
            other => panic!("cmd.exe: {other:?}"),
        }
    }

    #[test]
    fn plain_file_is_unsigned() {
        let dir = std::env::temp_dir().join(format!("vigil-sign-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("plain.exe");
        std::fs::write(&f, b"MZ not really").unwrap();
        assert_eq!(check(&f).state, SignState::Unsigned);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
