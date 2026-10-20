//! Reject late ETW/event-log records whose PID or TID has already been reused.
use super::{OwnedHandle, filetime_to_unix_ms, filetime_u64};
use windows_sys::Win32::{Foundation::FILETIME, System::Threading::*};

pub fn process_birth(pid: u32, event_filetime: u64) -> Option<i64> {
    if pid <= 4 {
        return None;
    }
    // SAFETY: query-only access; all handles and output buffers are owned here.
    unsafe {
        let h = OwnedHandle(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid));
        if h.0.is_null() {
            return None;
        }
        let mut created: FILETIME = std::mem::zeroed();
        let mut exited = created;
        let mut kernel = created;
        let mut user = created;
        if GetProcessTimes(h.0, &mut created, &mut exited, &mut kernel, &mut user) == 0 {
            return None;
        }
        let birth = filetime_u64(&created);
        if birth == 0 || birth > event_filetime {
            return None;
        }
        Some(filetime_to_unix_ms(birth))
    }
}

pub fn thread_owner(tid: u32, event_filetime: u64) -> Option<(u32, i64)> {
    if tid == 0 {
        return None;
    }
    // SAFETY: query-only handle, checked creation time, valid output pointers.
    unsafe {
        let h = OwnedHandle(OpenThread(THREAD_QUERY_LIMITED_INFORMATION, 0, tid));
        if h.0.is_null() {
            return None;
        }
        let mut created: FILETIME = std::mem::zeroed();
        let mut exited = created;
        let mut kernel = created;
        let mut user = created;
        if GetThreadTimes(h.0, &mut created, &mut exited, &mut kernel, &mut user) == 0 {
            return None;
        }
        let thread_birth = filetime_u64(&created);
        if thread_birth == 0 || thread_birth > event_filetime {
            return None;
        }
        let pid = GetProcessIdOfThread(h.0);
        // A process reusing the owner's PID cannot predate the held thread.
        process_birth(pid, thread_birth).map(|born| (pid, born))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn identifies_own_thread_and_rejects_events_before_birth() {
        let tid = unsafe { GetCurrentThreadId() };
        assert_eq!(thread_owner(tid, u64::MAX).unwrap().0, std::process::id());
        assert!(thread_owner(tid, 1).is_none());
        assert!(process_birth(std::process::id(), 1).is_none());
    }
}
