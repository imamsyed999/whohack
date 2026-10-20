//! Own the complete Python process tree, including Windows venv redirectors.
#![allow(unsafe_code)]
use anyhow::{Result, ensure};
use std::{os::windows::io::AsRawHandle, process::Child};
use windows_sys::Win32::{
    Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE, WAIT_OBJECT_0},
    System::{Diagnostics::ToolHelp::*, JobObjects::*, Threading::*},
};

#[derive(Debug)]
struct Handle(HANDLE);
// SAFETY: exclusive ownership; kernel handles may be moved between threads.
unsafe impl Send for Handle {}
impl Drop for Handle {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}

#[derive(Debug)]
pub(crate) struct Job {
    _handle: Handle,
}
impl Job {
    /// The caller created this owned child with CREATE_SUSPENDED. Attach before
    /// resuming so the venv launcher cannot create an uncontained interpreter.
    pub fn attach_and_resume(child: &mut Child) -> Result<Self> {
        // SAFETY: no pointers retained; all structures/buffers have Win32 sizes.
        unsafe {
            let raw = CreateJobObjectW(std::ptr::null(), std::ptr::null());
            ensure!(
                !raw.is_null(),
                "create model job: {}",
                std::io::Error::last_os_error()
            );
            let handle = Handle(raw);
            let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
            limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
                | JOB_OBJECT_LIMIT_ACTIVE_PROCESS
                | JOB_OBJECT_LIMIT_PRIORITY_CLASS;
            limits.BasicLimitInformation.ActiveProcessLimit = 4;
            limits.BasicLimitInformation.PriorityClass = BELOW_NORMAL_PRIORITY_CLASS;
            ensure!(
                SetInformationJobObject(
                    raw,
                    JobObjectExtendedLimitInformation,
                    (&raw const limits).cast(),
                    std::mem::size_of_val(&limits) as u32
                ) != 0,
                "set model job limits: {}",
                std::io::Error::last_os_error()
            );
            ensure!(
                AssignProcessToJobObject(raw, child.as_raw_handle().cast()) != 0,
                "assign model job: {}",
                std::io::Error::last_os_error()
            );
            let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
            ensure!(
                snapshot != INVALID_HANDLE_VALUE,
                "snapshot model thread: {}",
                std::io::Error::last_os_error()
            );
            let snapshot = Handle(snapshot);
            let mut entry = THREADENTRY32 {
                dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
                ..Default::default()
            };
            let mut ok = Thread32First(snapshot.0, &mut entry);
            let mut resumed = false;
            while ok != 0 {
                if entry.th32OwnerProcessID == child.id() {
                    let thread = OpenThread(
                        THREAD_SUSPEND_RESUME | THREAD_QUERY_LIMITED_INFORMATION,
                        0,
                        entry.th32ThreadID,
                    );
                    ensure!(
                        !thread.is_null(),
                        "open model main thread: {}",
                        std::io::Error::last_os_error()
                    );
                    let thread = Handle(thread);
                    ensure!(
                        GetProcessIdOfThread(thread.0) == child.id()
                            && WaitForSingleObject(child.as_raw_handle().cast(), 0)
                                != WAIT_OBJECT_0,
                        "model exited during launch"
                    );
                    ensure!(
                        ResumeThread(thread.0) != u32::MAX,
                        "resume model: {}",
                        std::io::Error::last_os_error()
                    );
                    resumed = true;
                }
                ok = Thread32Next(snapshot.0, &mut entry);
            }
            ensure!(resumed, "no model main thread found");
            Ok(Self { _handle: handle })
        }
    }
}
