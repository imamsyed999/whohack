//! A single manually approved WFP lease. No privileged config, model loading,
//! filesystem writes or process-control commands cross this boundary.
use super::{process::Handle, wfp};
use crate::Lease;
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use std::{
    os::windows::ffi::OsStrExt,
    path::PathBuf,
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::{
        FILETIME, GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE, LocalFree,
        WAIT_OBJECT_0,
    },
    Security::{
        Authorization::{ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1},
        SECURITY_ATTRIBUTES,
    },
    Storage::FileSystem::{
        CreateFileW, FILE_FLAG_FIRST_PIPE_INSTANCE, OPEN_EXISTING, PIPE_ACCESS_DUPLEX, ReadFile,
        SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT, WriteFile,
    },
    System::{
        Com::{COINIT_APARTMENTTHREADED, COINIT_DISABLE_OLE1DDE, CoInitializeEx, CoUninitialize},
        Pipes::{
            CreateNamedPipeW, GetNamedPipeClientProcessId, GetNamedPipeServerProcessId,
            PIPE_NOWAIT, PIPE_REJECT_REMOTE_CLIENTS, PeekNamedPipe, SetNamedPipeHandleState,
        },
        Threading::{
            GetCurrentProcess, GetProcessId, GetProcessTimes, OpenProcess,
            PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE, WaitForSingleObject,
        },
    },
    UI::{
        Shell::{
            SEE_MASK_FLAG_NO_UI, SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW,
            ShellExecuteExW,
        },
        WindowsAndMessaging::SW_HIDE,
    },
};

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    target: whohack_core::ProcessInfo,
    parent_pid: u32,
    parent_birth: u64,
    nonce: String,
}

fn helper() -> Result<PathBuf> {
    Ok(std::env::current_exe()?.with_file_name("whohack-response-helper.exe"))
}
pub(super) fn available() -> bool {
    helper().is_ok_and(|path| path.is_file())
}
fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(Some(0)).collect()
}
fn check(ok: i32) -> Result<()> {
    ensure!(
        ok != 0,
        "Windows response helper: {}",
        std::io::Error::last_os_error()
    );
    Ok(())
}
fn birth(handle: HANDLE) -> Result<u64> {
    let mut times = [FILETIME::default(); 4];
    let [a, b, c, d] = &mut times;
    check(unsafe { GetProcessTimes(handle, a, b, c, d) })?;
    Ok((u64::from(times[0].dwHighDateTime) << 32) | u64::from(times[0].dwLowDateTime))
}
fn pipe_name(nonce: &str) -> Result<Vec<u16>> {
    ensure!(
        nonce.len() == 32 && nonce.bytes().all(|b| b.is_ascii_hexdigit()),
        "invalid helper nonce"
    );
    Ok(wide(&format!(r"\\.\pipe\whohack-response-{nonce}")))
}
fn server(name: &[u16]) -> Result<Handle> {
    let sddl = wide("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;OW)");
    let mut sd = std::ptr::null_mut();
    check(unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut sd,
            std::ptr::null_mut(),
        )
    })?;
    let security = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd,
        bInheritHandle: 0,
    };
    let raw = unsafe {
        CreateNamedPipeW(
            name.as_ptr(),
            PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
            PIPE_NOWAIT | PIPE_REJECT_REMOTE_CLIENTS,
            1,
            1024,
            1024,
            0,
            &security,
        )
    };
    let error = std::io::Error::last_os_error();
    unsafe {
        LocalFree(sd);
    }
    ensure!(raw != INVALID_HANDLE_VALUE, "create response pipe: {error}");
    Ok(Handle(raw))
}
fn send(pipe: HANDLE, value: u8) -> Result<()> {
    let mut written = 0;
    check(unsafe {
        WriteFile(
            pipe,
            (&raw const value).cast(),
            1,
            &mut written,
            std::ptr::null_mut(),
        )
    })?;
    ensure!(written == 1, "response helper pipe is full");
    Ok(())
}
fn receive(pipe: HANDLE) -> Result<Option<u8>> {
    let mut available = 0;
    check(unsafe {
        PeekNamedPipe(
            pipe,
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            &mut available,
            std::ptr::null_mut(),
        )
    })?;
    if available == 0 {
        return Ok(None);
    }
    ensure!(
        available <= 1024,
        "response helper protocol exceeded bounds"
    );
    let mut byte = 0u8;
    let mut read = 0;
    check(unsafe {
        ReadFile(
            pipe,
            (&raw mut byte).cast(),
            1,
            &mut read,
            std::ptr::null_mut(),
        )
    })?;
    ensure!(read == 1, "response helper closed its pipe");
    Ok(Some(byte))
}

fn elevate(path: PathBuf, argument: String) -> Result<Handle> {
    // ShellExecute's COM requirements are isolated from the service's Tokio threads.
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let result = (|| {
            let initialized = unsafe {
                CoInitializeEx(
                    std::ptr::null(),
                    (COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE) as u32,
                )
            };
            ensure!(
                initialized >= 0,
                "initialize Windows consent thread: {initialized:#x}"
            );
            let verb = wide("runas");
            let file: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
            let args = wide(&argument); // Hex only: no shell or command-string interpolation.
            let mut info = SHELLEXECUTEINFOW {
                cbSize: std::mem::size_of::<SHELLEXECUTEINFOW>() as u32,
                // Return errors rather than leaving an invisible shell error dialog
                // open. Windows still displays and enforces its UAC consent prompt.
                fMask: SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC | SEE_MASK_FLAG_NO_UI,
                lpVerb: verb.as_ptr(),
                lpFile: file.as_ptr(),
                lpParameters: args.as_ptr(),
                nShow: SW_HIDE,
                ..Default::default()
            };
            let result = check(unsafe { ShellExecuteExW(&mut info) });
            unsafe {
                CoUninitialize();
            }
            result.context(
                "Administrator consent was cancelled or the response helper could not start",
            )?;
            ensure!(
                !info.hProcess.is_null(),
                "response helper returned no process handle"
            );
            Ok(Handle(info.hProcess))
        })();
        let _ = sender.send(result);
    });
    // If consent arrives after the timeout, the owner pipe has been dropped and
    // the helper cannot create a lease. Never hold the response manager forever.
    receiver
        .recv_timeout(Duration::from_secs(90))
        .context("Windows administrator consent did not complete within 90 seconds")?
}

#[derive(Debug)]
pub(super) struct Block {
    process: Handle,
    pipe: Option<Handle>,
}
impl Block {
    pub fn new(target: &whohack_core::ProcessInfo) -> Result<Self> {
        let request = Request {
            target: target.clone(),
            parent_pid: std::process::id(),
            parent_birth: birth(unsafe { GetCurrentProcess() })?,
            nonce: format!("{:032x}", rand::random::<u128>()),
        };
        let encoded = serde_json::to_vec(&request)?;
        ensure!(
            encoded.len() <= 12_000,
            "response target metadata is too large"
        );
        let pipe = server(&pipe_name(&request.nonce)?)?;
        let process = elevate(helper()?, whohack_core::hex::encode(&encoded))?;
        let block = Self {
            process,
            pipe: Some(pipe),
        };
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            ensure!(
                unsafe { WaitForSingleObject(block.process.0, 0) } != WAIT_OBJECT_0,
                "response helper exited before confirming the block"
            );
            ensure!(
                Instant::now() < deadline,
                "response helper did not confirm the block"
            );
            let pipe = block.pipe.as_ref().unwrap().0;
            let mut peer = 0;
            if unsafe { GetNamedPipeClientProcessId(pipe, &mut peer) } != 0 {
                ensure!(
                    peer == unsafe { GetProcessId(block.process.0) },
                    "unexpected response helper peer"
                );
                if let Some(status) = receive(pipe)? {
                    ensure!(
                        status == b'R',
                        "response helper could not install the block"
                    );
                    return Ok(block);
                }
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}
impl Lease for Block {
    fn intact(&self) -> Result<bool> {
        let Some(pipe) = &self.pipe else {
            return Ok(false);
        };
        if unsafe { WaitForSingleObject(self.process.0, 0) } == WAIT_OBJECT_0 {
            return Ok(false);
        }
        send(pipe.0, b'I')?;
        let deadline = Instant::now() + Duration::from_secs(1);
        while Instant::now() < deadline {
            if let Some(status) = receive(pipe.0)? {
                return Ok(status == b'R');
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        bail!("response helper integrity check timed out")
    }
    fn release(&mut self) -> Result<()> {
        if let Some(pipe) = self.pipe.take() {
            let _ = send(pipe.0, b'S');
            drop(pipe);
        }
        ensure!(
            unsafe { WaitForSingleObject(self.process.0, 5000) } == WAIT_OBJECT_0,
            "response helper is still releasing its block"
        );
        Ok(())
    }
}
impl Drop for Block {
    fn drop(&mut self) {
        let _ = self.release();
    }
}

/// Entry point of the narrow elevated executable. The target is fixed at launch;
/// the only subsequent operations are integrity inspection and releasing it.
pub(crate) fn run(encoded: &str) -> Result<()> {
    ensure!(
        super::elevated(),
        "Windows administrator consent is required"
    );
    ensure!(
        !encoded.is_empty()
            && encoded.len() <= 24_000
            && encoded.len().is_multiple_of(2)
            && encoded.bytes().all(|b| b.is_ascii_hexdigit()),
        "invalid helper request"
    );
    let bytes: Vec<u8> = encoded
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            ((pair[0] as char).to_digit(16).unwrap() * 16 + (pair[1] as char).to_digit(16).unwrap())
                as u8
        })
        .collect();
    let request: Request = serde_json::from_slice(&bytes)?;
    let name = pipe_name(&request.nonce)?;
    ensure!(
        request.parent_pid > 4 && request.parent_pid != std::process::id(),
        "invalid parent"
    );
    let parent = unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
            0,
            request.parent_pid,
        )
    };
    ensure!(!parent.is_null(), "parent is unavailable");
    let parent = Handle(parent);
    ensure!(
        birth(parent.0)? == request.parent_birth,
        "parent process identity changed"
    );
    // Identification SQOS prevents the unprivileged pipe server from impersonating
    // this elevated client. Remote pipe paths cannot be supplied by the caller.
    let raw = unsafe {
        CreateFileW(
            name.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            0,
            std::ptr::null(),
            OPEN_EXISTING,
            SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
            std::ptr::null_mut(),
        )
    };
    ensure!(
        raw != INVALID_HANDLE_VALUE,
        "connect to response owner: {}",
        std::io::Error::last_os_error()
    );
    let pipe = Handle(raw);
    let mut peer = 0;
    check(unsafe { GetNamedPipeServerProcessId(pipe.0, &mut peer) })?;
    ensure!(peer == request.parent_pid, "unexpected response owner");
    let mode = PIPE_NOWAIT;
    check(unsafe { SetNamedPipeHandleState(pipe.0, &mode, std::ptr::null(), std::ptr::null()) })?;
    let _identity = super::process::open(&request.target, 0)?;
    let lease = wfp::Block::new(&request.target.exe.path)?;
    send(pipe.0, b'R')?;
    let deadline = Instant::now() + Duration::from_secs(24 * 60 * 60);
    while Instant::now() < deadline && unsafe { WaitForSingleObject(parent.0, 0) } != WAIT_OBJECT_0
    {
        match receive(pipe.0) {
            Ok(Some(b'I')) => send(pipe.0, if lease.intact()? { b'R' } else { b'D' })?,
            Ok(None) => {}
            _ => break,
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    drop(lease); // Also runs on errors; WFP closes dynamic filters on crashes.
    Ok(())
}
