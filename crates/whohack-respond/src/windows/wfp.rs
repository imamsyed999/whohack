use crate::Lease;
use anyhow::{Result, ensure};
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::*;
use windows_sys::Win32::System::Rpc::RPC_C_AUTHN_WINNT;

#[derive(Debug)]
pub(super) struct Block {
    engine: HANDLE,
    filters: Vec<u64>,
}
// SAFETY: the engine is owned and used only under the manager lock.
unsafe impl Send for Block {}
fn check(rc: u32) -> Result<()> {
    ensure!(rc == 0, "Windows Filtering Platform error 0x{rc:08x}");
    Ok(())
}
impl Block {
    pub fn new(path: &str) -> Result<Self> {
        let mut engine = std::ptr::null_mut();
        let session = FWPM_SESSION0 {
            flags: FWPM_SESSION_FLAG_DYNAMIC,
            txnWaitTimeoutInMSec: 2000,
            ..Default::default()
        };
        // SAFETY: valid inputs and out pointer. Dynamic session automatically
        // removes all four filters when this handle closes, even after a crash.
        check(unsafe {
            FwpmEngineOpen0(
                std::ptr::null(),
                RPC_C_AUTHN_WINNT,
                std::ptr::null(),
                &session,
                &mut engine,
            )
        })?;
        let mut block = Self {
            engine,
            filters: Vec::new(),
        };
        let wide: Vec<u16> = path.encode_utf16().chain(Some(0)).collect();
        let mut blob = std::ptr::null_mut();
        check(unsafe { FwpmGetAppIdFromFileName0(wide.as_ptr(), &mut blob) })?;
        let result = block.add_filters(blob);
        unsafe {
            FwpmFreeMemory0((&mut blob as *mut *mut FWP_BYTE_BLOB).cast());
        }
        result?;
        Ok(block)
    }
    fn add_filters(&mut self, blob: *mut FWP_BYTE_BLOB) -> Result<()> {
        check(unsafe { FwpmTransactionBegin0(self.engine, 0) })?;
        let result = (|| {
            let mut condition = FWPM_FILTER_CONDITION0 {
                fieldKey: FWPM_CONDITION_ALE_APP_ID,
                matchType: FWP_MATCH_EQUAL,
                conditionValue: FWP_CONDITION_VALUE0 {
                    r#type: FWP_BYTE_BLOB_TYPE,
                    Anonymous: FWP_CONDITION_VALUE0_0 { byteBlob: blob },
                },
            };
            let mut name: Vec<u16> = "whohack temporary application block"
                .encode_utf16()
                .chain(Some(0))
                .collect();
            for layer in [
                FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                FWPM_LAYER_ALE_AUTH_CONNECT_V6,
                FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
                FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
            ] {
                let filter = FWPM_FILTER0 {
                    displayData: FWPM_DISPLAY_DATA0 {
                        name: name.as_mut_ptr(),
                        description: std::ptr::null_mut(),
                    },
                    layerKey: layer,
                    subLayerKey: FWPM_SUBLAYER_UNIVERSAL,
                    numFilterConditions: 1,
                    filterCondition: &mut condition,
                    action: FWPM_ACTION0 {
                        r#type: FWP_ACTION_BLOCK,
                        ..Default::default()
                    },
                    ..Default::default()
                };
                let mut id = 0;
                check(unsafe {
                    FwpmFilterAdd0(self.engine, &filter, std::ptr::null_mut(), &mut id)
                })?;
                self.filters.push(id);
            }
            check(unsafe { FwpmTransactionCommit0(self.engine) })
        })();
        if result.is_err() {
            unsafe {
                FwpmTransactionAbort0(self.engine);
            }
        }
        result
    }
}
impl Lease for Block {
    fn intact(&self) -> Result<bool> {
        if self.engine.is_null() || self.filters.len() != 4 {
            return Ok(false);
        }
        for id in &self.filters {
            let mut filter: *mut FWPM_FILTER0 = std::ptr::null_mut();
            let code = unsafe { FwpmFilterGetById0(self.engine, *id, &mut filter) };
            if code == 0x80320003 {
                return Ok(false);
            } // FWP_E_FILTER_NOT_FOUND
            check(code)?;
            let matches =
                !filter.is_null() && unsafe { (*filter).action.r#type == FWP_ACTION_BLOCK };
            if !filter.is_null() {
                unsafe {
                    FwpmFreeMemory0((&mut filter as *mut *mut FWPM_FILTER0).cast());
                }
            }
            if !matches {
                return Ok(false);
            }
        }
        Ok(true)
    }
    fn release(&mut self) -> Result<()> {
        if !self.engine.is_null() {
            check(unsafe { FwpmEngineClose0(self.engine) })?;
            self.engine = std::ptr::null_mut();
        }
        Ok(())
    }
}
impl Drop for Block {
    fn drop(&mut self) {
        let _ = self.release();
    }
}
