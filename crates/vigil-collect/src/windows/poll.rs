//! Unprivileged Windows snapshot source: ToolHelp32 for processes and
//! `GetExtendedTcpTable` for TCP connections with owning PIDs.
//!
//! UDP sockets expose no remote address through IP Helper, and DNS is not
//! observable without ETW; both require the elevated ETW backend.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use vigil_core::Proto;
use vigil_core::time::now_ms;
use windows_sys::Wdk::System::Threading::{NtQueryInformationProcess, PROCESSINFOCLASS};
use windows_sys::Win32::Foundation::{
    ERROR_INSUFFICIENT_BUFFER, FILETIME, INVALID_HANDLE_VALUE, NO_ERROR, UNICODE_STRING,
};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCPROW_OWNER_PID, TCP_TABLE_OWNER_PID_ALL,
};
use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::Threading::{
    GetProcessTimes, OpenProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
    QueryFullProcessImageNameW,
};

use super::{OwnedHandle, filetime_to_unix_ms, filetime_u64};
use crate::poll::{ProcSnap, SnapshotSource, SockSnap, SockState};

/// `ProcessCommandLineInformation` (Windows 8.1+); works with
/// `PROCESS_QUERY_LIMITED_INFORMATION`.
const PROCESS_COMMAND_LINE_INFORMATION: PROCESSINFOCLASS = 60;

const MIB_TCP_STATE_LISTEN: u32 = 2;
const MIB_TCP_STATE_SYN_SENT: u32 = 3;
const MIB_TCP_STATE_ESTAB: u32 = 5;

fn wide_to_string(w: &[u16]) -> String {
    let end = w.iter().position(|&c| c == 0).unwrap_or(w.len());
    String::from_utf16_lossy(&w[..end])
}

/// Details readable by opening the process (fails for protected processes).
struct ProcDetails {
    path: Option<String>,
    start_ms: Option<i64>,
    cmdline: Option<String>,
}

fn query_process(pid: u32) -> ProcDetails {
    let mut d = ProcDetails {
        path: None,
        start_ms: None,
        cmdline: None,
    };
    // SAFETY: plain call; a null return means failure.
    let h = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if h.is_null() {
        return d;
    }
    let h = OwnedHandle(h);

    let mut buf = vec![0u16; 1024];
    let mut len = buf.len() as u32;
    // SAFETY: buf has `len` u16 slots; len is updated to the written length.
    if unsafe { QueryFullProcessImageNameW(h.0, PROCESS_NAME_WIN32, buf.as_mut_ptr(), &mut len) }
        != 0
    {
        d.path = Some(String::from_utf16_lossy(&buf[..len as usize]));
    }

    let zero = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    let (mut created, mut exited, mut kernel, mut user) = (zero, zero, zero, zero);
    // SAFETY: all four out-pointers are valid FILETIMEs.
    if unsafe { GetProcessTimes(h.0, &mut created, &mut exited, &mut kernel, &mut user) } != 0 {
        d.start_ms = Some(filetime_to_unix_ms(filetime_u64(&created)));
    }

    d.cmdline = query_cmdline(&h);
    d
}

/// Command line of a running process, if it can be opened.
pub fn cmdline_of(pid: u32) -> Option<String> {
    // SAFETY: plain call; a null return means failure.
    let h = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if h.is_null() {
        return None;
    }
    query_cmdline(&OwnedHandle(h))
}

fn query_cmdline(h: &OwnedHandle) -> Option<String> {
    let mut needed = 0u32;
    // SAFETY: a zero-length query only reports the required size.
    unsafe {
        NtQueryInformationProcess(
            h.0,
            PROCESS_COMMAND_LINE_INFORMATION,
            std::ptr::null_mut(),
            0,
            &mut needed,
        )
    };
    if needed < std::mem::size_of::<UNICODE_STRING>() as u32 || needed > 1 << 20 {
        return None;
    }
    // u64 elements keep the buffer aligned for UNICODE_STRING.
    let mut buf = vec![0u64; (needed as usize).div_ceil(8)];
    // SAFETY: buf is at least `needed` bytes and suitably aligned.
    let status = unsafe {
        NtQueryInformationProcess(
            h.0,
            PROCESS_COMMAND_LINE_INFORMATION,
            buf.as_mut_ptr().cast(),
            (buf.len() * 8) as u32,
            &mut needed,
        )
    };
    if status < 0 {
        return None;
    }
    // SAFETY: on success the buffer starts with a UNICODE_STRING whose Buffer
    // points inside `buf` and spans `Length` bytes.
    unsafe {
        let us = &*(buf.as_ptr().cast::<UNICODE_STRING>());
        if us.Buffer.is_null() || us.Length == 0 {
            return None;
        }
        let chars = std::slice::from_raw_parts(us.Buffer, usize::from(us.Length) / 2);
        Some(String::from_utf16_lossy(chars))
    }
}

#[derive(Debug, Default)]
pub struct WinSource {
    /// Fallback start times for processes whose times cannot be queried,
    /// kept stable across snapshots.
    first_seen: HashMap<u32, i64>,
}

impl WinSource {
    pub fn new() -> Self {
        WinSource::default()
    }
}

/// Reads a whole `GetExtendedTcpTable` result for one address family.
fn tcp_table(family: u16) -> io::Result<Vec<u64>> {
    let mut size = 0u32;
    for _ in 0..4 {
        let mut buf = vec![0u64; (size as usize).div_ceil(8).max(1)];
        let mut len = (buf.len() * 8) as u32;
        // SAFETY: buf is `len` bytes, 8-byte aligned.
        let rc = unsafe {
            GetExtendedTcpTable(
                buf.as_mut_ptr().cast(),
                &mut len,
                0,
                u32::from(family),
                TCP_TABLE_OWNER_PID_ALL,
                0,
            )
        };
        match rc {
            NO_ERROR => return Ok(buf),
            ERROR_INSUFFICIENT_BUFFER => size = len + 4096,
            e => return Err(io::Error::from_raw_os_error(e as i32)),
        }
    }
    Err(io::Error::other("TCP table kept growing"))
}

fn state(s: u32) -> SockState {
    match s {
        MIB_TCP_STATE_LISTEN => SockState::Listen,
        MIB_TCP_STATE_SYN_SENT => SockState::SynSent,
        MIB_TCP_STATE_ESTAB => SockState::Established,
        _ => SockState::Other,
    }
}

/// Ports are stored in network byte order in the low 16 bits.
fn port(dw: u32) -> u16 {
    u16::from_be((dw & 0xffff) as u16)
}

impl SnapshotSource for WinSource {
    fn processes(&mut self) -> io::Result<Vec<ProcSnap>> {
        // SAFETY: plain call; INVALID_HANDLE_VALUE signals failure.
        let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
        if snap == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        let snap = OwnedHandle(snap);
        // SAFETY: zeroed PROCESSENTRY32W is valid once dwSize is set.
        let mut entry: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        let now = now_ms();
        let mut out = Vec::new();
        let mut live = Vec::new();
        // SAFETY: entry is a valid, sized PROCESSENTRY32W.
        let mut ok = unsafe { Process32FirstW(snap.0, &mut entry) } != 0;
        while ok {
            let pid = entry.th32ProcessID;
            if pid != 0 {
                live.push(pid);
                let name = wide_to_string(&entry.szExeFile);
                let d = query_process(pid);
                let start_time = d
                    .start_ms
                    .unwrap_or_else(|| *self.first_seen.entry(pid).or_insert(now));
                out.push(ProcSnap {
                    pid,
                    ppid: entry.th32ParentProcessID,
                    start_time,
                    exe: d.path.unwrap_or(name),
                    cmdline: d.cmdline,
                });
            }
            // SAFETY: as above.
            ok = unsafe { Process32NextW(snap.0, &mut entry) } != 0;
        }
        self.first_seen.retain(|pid, _| live.contains(pid));
        Ok(out)
    }

    fn sockets(&mut self) -> io::Result<Vec<SockSnap>> {
        let mut out = Vec::new();
        let v4 = tcp_table(AF_INET)?;
        // SAFETY: the buffer holds a MIB_TCPTABLE_OWNER_PID: a u32 count followed
        // by `count` rows; we bound-check against the buffer length.
        unsafe {
            let base = v4.as_ptr().cast::<u8>();
            let count = *(base.cast::<u32>()) as usize;
            let rows = base
                .add(std::mem::size_of::<u32>())
                .cast::<MIB_TCPROW_OWNER_PID>();
            let max = (v4.len() * 8 - 4) / std::mem::size_of::<MIB_TCPROW_OWNER_PID>();
            for i in 0..count.min(max) {
                let r = &*rows.add(i);
                out.push(SockSnap {
                    pid: r.dwOwningPid,
                    proto: Proto::Tcp,
                    local: SocketAddr::new(
                        IpAddr::V4(Ipv4Addr::from(r.dwLocalAddr.to_ne_bytes())),
                        port(r.dwLocalPort),
                    ),
                    remote: SocketAddr::new(
                        IpAddr::V4(Ipv4Addr::from(r.dwRemoteAddr.to_ne_bytes())),
                        port(r.dwRemotePort),
                    ),
                    state: state(r.dwState),
                });
            }
        }
        if let Ok(v6) = tcp_table(AF_INET6) {
            // SAFETY: as above for MIB_TCP6TABLE_OWNER_PID.
            unsafe {
                let base = v6.as_ptr().cast::<u8>();
                let count = *(base.cast::<u32>()) as usize;
                let rows = base
                    .add(std::mem::size_of::<u32>())
                    .cast::<MIB_TCP6ROW_OWNER_PID>();
                let max = (v6.len() * 8 - 4) / std::mem::size_of::<MIB_TCP6ROW_OWNER_PID>();
                for i in 0..count.min(max) {
                    let r = &*rows.add(i);
                    out.push(SockSnap {
                        pid: r.dwOwningPid,
                        proto: Proto::Tcp,
                        local: SocketAddr::new(
                            IpAddr::V6(Ipv6Addr::from(r.ucLocalAddr)),
                            port(r.dwLocalPort),
                        ),
                        remote: SocketAddr::new(
                            IpAddr::V6(Ipv6Addr::from(r.ucRemoteAddr)),
                            port(r.dwRemotePort),
                        ),
                        state: state(r.dwState),
                    });
                }
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn port_byte_order() {
        // 443 in network order stored in the low 16 bits.
        assert_eq!(port(u32::from(443u16.to_be())), 443);
    }

    #[test]
    fn snapshot_contains_this_process_with_path() {
        let mut s = WinSource::new();
        let procs = s.processes().unwrap();
        let me = procs
            .iter()
            .find(|p| p.pid == std::process::id())
            .expect("own process listed");
        assert!(me.exe.to_ascii_lowercase().ends_with(".exe"), "{}", me.exe);
        assert!(me.exe.contains('\\'), "full path expected: {}", me.exe);
        assert!(me.start_time > 1_600_000_000_000);
        assert!(me.cmdline.is_some());
        // Stable across snapshots.
        let again = s.processes().unwrap();
        let me2 = again.iter().find(|p| p.pid == std::process::id()).unwrap();
        assert_eq!(me.start_time, me2.start_time);
    }

    #[test]
    fn socket_table_reports_own_listener() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let p = l.local_addr().unwrap().port();
        let socks = WinSource::new().sockets().unwrap();
        assert!(socks.iter().any(|s| s.state == SockState::Listen
            && s.local.port() == p
            && s.pid == std::process::id()));
    }
}
