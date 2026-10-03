//! libproc snapshot source for macOS limited mode.
#![allow(unsafe_code)]

use std::collections::HashMap;
use std::ffi::c_void;
use std::io;
use std::mem::{MaybeUninit, size_of};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use vigil_core::Proto;
use vigil_core::time::now_ms;

use crate::poll::{ProcSnap, SnapshotSource, SockSnap, SockState};

// <sys/proc_info.h> constants not all exported by libc.
const PROC_PIDTBSDINFO: i32 = 3;
const PROC_PIDLISTFDS: i32 = 1;
const PROC_PIDFDSOCKETINFO: i32 = 3;
const PROX_FDTYPE_SOCKET: u32 = 2;
const PROC_PIDPATHINFO_MAXSIZE: usize = 4096;
const SOCKINFO_IN: i32 = 1;
const SOCKINFO_TCP: i32 = 2;
const INI_IPV4: u8 = 0x1;
const INI_IPV6: u8 = 0x2;
const TSI_S_LISTEN: i32 = 1;
const TSI_S_SYN_SENT: i32 = 2;
const TSI_S_ESTABLISHED: i32 = 4;
const AF_INET: i32 = 2;
const AF_INET6: i32 = 30;
const IPPROTO_TCP: i32 = 6;
const IPPROTO_UDP: i32 = 17;

/// `struct proc_bsdinfo` (xnu bsd/sys/proc_info.h).
#[repr(C)]
#[derive(Clone, Copy)]
struct ProcBsdInfo {
    pbi_flags: u32,
    pbi_status: u32,
    pbi_xstatus: u32,
    pbi_pid: u32,
    pbi_ppid: u32,
    pbi_uid: u32,
    pbi_gid: u32,
    pbi_ruid: u32,
    pbi_rgid: u32,
    pbi_svuid: u32,
    pbi_svgid: u32,
    rfu_1: u32,
    pbi_comm: [u8; 16],
    pbi_name: [u8; 32],
    pbi_nfiles: u32,
    pbi_pgid: u32,
    pbi_pjobc: u32,
    e_tdev: u32,
    e_tpgid: u32,
    pbi_nice: i32,
    pbi_start_tvsec: u64,
    pbi_start_tvusec: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct ProcFdInfo {
    proc_fd: i32,
    proc_fdtype: u32,
}

/// `struct in_sockinfo`.
#[repr(C)]
#[derive(Clone, Copy)]
struct InSockInfo {
    insi_fport: i32,
    insi_lport: i32,
    insi_gencnt: u64,
    insi_flags: u32,
    insi_flow: u32,
    insi_vflag: u8,
    insi_ip_ttl: u8,
    rfu_1: u32,
    /// union { struct in4in6_addr; struct in6_addr } — 16 bytes either way.
    insi_faddr: [u8; 16],
    insi_laddr: [u8; 16],
    insi_v4: u8,
    insi_v6: [u8; 9],
}

/// `struct tcp_sockinfo`.
#[repr(C)]
#[derive(Clone, Copy)]
struct TcpSockInfo {
    tcpsi_ini: InSockInfo,
    tcpsi_state: i32,
    tcpsi_timer: [i32; 4],
    tcpsi_mss: i32,
    tcpsi_flags: u32,
    rfu_1: u32,
    tcpsi_tp: u64,
}

/// Leading part of `struct socket_fdinfo`: `proc_fileinfo` then
/// `socket_info`, whose protocol union we read through `soi_proto`.
#[repr(C)]
#[derive(Clone, Copy)]
struct ProcFileInfo {
    fi_openflags: u32,
    fi_status: u32,
    fi_offset: i64,
    fi_type: i32,
    fi_guardflags: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct VinfoStat {
    _raw: [u8; 136],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct SockbufInfo {
    _raw: [u8; 24],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct SocketInfo {
    soi_stat: VinfoStat,
    soi_so: u64,
    soi_pcb: u64,
    soi_type: i32,
    soi_protocol: i32,
    soi_family: i32,
    soi_options: i16,
    soi_linger: i16,
    soi_state: i16,
    soi_qlen: i16,
    soi_incqlen: i16,
    soi_qlimit: i16,
    soi_timeo: i16,
    soi_error: u16,
    soi_oobmark: u32,
    soi_rcv: SockbufInfo,
    soi_snd: SockbufInfo,
    soi_kind: i32,
    rfu_1: u32,
    /// Union; `tcp_sockinfo` is the member we need and the largest we read.
    soi_proto: [u8; 524],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct SocketFdInfo {
    pfi: ProcFileInfo,
    psi: SocketInfo,
}

unsafe extern "C" {
    fn proc_listallpids(buffer: *mut c_void, buffersize: i32) -> i32;
    fn proc_pidinfo(pid: i32, flavor: i32, arg: u64, buffer: *mut c_void, buffersize: i32) -> i32;
    fn proc_pidfdinfo(pid: i32, fd: i32, flavor: i32, buffer: *mut c_void, buffersize: i32) -> i32;
    fn proc_pidpath(pid: i32, buffer: *mut c_void, buffersize: u32) -> i32;
}

/// Parses a `KERN_PROCARGS2` buffer: `argc` (i32), the exec path, NUL
/// padding, then `argc` NUL-terminated arguments.
pub fn parse_procargs2(buf: &[u8]) -> Option<String> {
    let argc = i32::from_ne_bytes(buf.get(..4)?.try_into().ok()?);
    let mut rest = &buf[4..];
    let path_end = rest.iter().position(|&b| b == 0)?;
    rest = &rest[path_end..];
    let start = rest.iter().position(|&b| b != 0)?;
    rest = &rest[start..];
    let args: Vec<String> = rest
        .split(|&b| b == 0)
        .take(usize::try_from(argc).ok()?)
        .map(|a| {
            let s = String::from_utf8_lossy(a);
            if s.chars().any(char::is_whitespace) {
                format!("\"{}\"", s.replace('"', "\\\""))
            } else {
                s.into_owned()
            }
        })
        .collect();
    (!args.is_empty()).then(|| args.join(" "))
}

fn cmdline(pid: i32) -> Option<String> {
    let mut mib = [libc::CTL_KERN, libc::KERN_PROCARGS2, pid];
    let mut size: libc::size_t = 0;
    // SAFETY: a null buffer queries the size.
    let rc = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            3,
            std::ptr::null_mut(),
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    if rc != 0 || size == 0 || size > 1 << 20 {
        return None;
    }
    let mut buf = vec![0u8; size];
    // SAFETY: buf has `size` bytes.
    let rc = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            3,
            buf.as_mut_ptr().cast(),
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    if rc != 0 {
        return None;
    }
    buf.truncate(size);
    parse_procargs2(&buf)
}

fn pids() -> io::Result<Vec<i32>> {
    // SAFETY: a null buffer returns the number of pids.
    let n = unsafe { proc_listallpids(std::ptr::null_mut(), 0) };
    if n <= 0 {
        return Err(io::Error::last_os_error());
    }
    let mut buf = vec![0i32; n as usize + 64];
    // SAFETY: buf holds the stated number of bytes.
    let n = unsafe {
        proc_listallpids(
            buf.as_mut_ptr().cast(),
            (buf.len() * size_of::<i32>()) as i32,
        )
    };
    if n <= 0 {
        return Err(io::Error::last_os_error());
    }
    buf.truncate(n as usize);
    Ok(buf.into_iter().filter(|&p| p > 0).collect())
}

fn bsdinfo(pid: i32) -> Option<ProcBsdInfo> {
    let mut info = MaybeUninit::<ProcBsdInfo>::zeroed();
    let size = size_of::<ProcBsdInfo>() as i32;
    // SAFETY: info is a correctly sized out-buffer.
    let n = unsafe { proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, info.as_mut_ptr().cast(), size) };
    // SAFETY: fully written when n == size.
    (n == size).then(|| unsafe { info.assume_init() })
}

fn exe_path(pid: i32) -> Option<String> {
    let mut buf = vec![0u8; PROC_PIDPATHINFO_MAXSIZE];
    // SAFETY: buf has the stated capacity.
    let n = unsafe { proc_pidpath(pid, buf.as_mut_ptr().cast(), buf.len() as u32) };
    (n > 0).then(|| String::from_utf8_lossy(&buf[..n as usize]).into_owned())
}

fn c_str(b: &[u8]) -> String {
    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    String::from_utf8_lossy(&b[..end]).into_owned()
}

fn addr(raw: &[u8; 16], vflag: u8) -> Option<IpAddr> {
    if vflag & INI_IPV4 != 0 {
        // in4in6_addr: 12 bytes of padding, then the IPv4 address.
        Some(IpAddr::V4(Ipv4Addr::new(
            raw[12], raw[13], raw[14], raw[15],
        )))
    } else if vflag & INI_IPV6 != 0 {
        Some(IpAddr::V6(Ipv6Addr::from(*raw)).to_canonical())
    } else {
        None
    }
}

fn port(p: i32) -> u16 {
    u16::from_be(p as u16)
}

fn sockets_of(pid: i32, out: &mut Vec<SockSnap>) {
    let mut fds = vec![
        ProcFdInfo {
            proc_fd: 0,
            proc_fdtype: 0
        };
        1024
    ];
    let bytes = (fds.len() * size_of::<ProcFdInfo>()) as i32;
    // SAFETY: fds is a correctly sized out-buffer.
    let n = unsafe { proc_pidinfo(pid, PROC_PIDLISTFDS, 0, fds.as_mut_ptr().cast(), bytes) };
    if n <= 0 {
        return;
    }
    let count = n as usize / size_of::<ProcFdInfo>();
    for fd in fds
        .iter()
        .take(count)
        .filter(|f| f.proc_fdtype == PROX_FDTYPE_SOCKET)
    {
        let mut si = MaybeUninit::<SocketFdInfo>::zeroed();
        let size = size_of::<SocketFdInfo>() as i32;
        // SAFETY: si is a correctly sized out-buffer.
        let got = unsafe {
            proc_pidfdinfo(
                pid,
                fd.proc_fd,
                PROC_PIDFDSOCKETINFO,
                si.as_mut_ptr().cast(),
                size,
            )
        };
        if got < size {
            continue;
        }
        // SAFETY: fully written (got == size).
        let si = unsafe { si.assume_init() }.psi;
        if si.soi_family != AF_INET && si.soi_family != AF_INET6 {
            continue;
        }
        let (proto, ini, state) = match (si.soi_kind, si.soi_protocol) {
            (SOCKINFO_TCP, IPPROTO_TCP) => {
                // SAFETY: soi_kind says the union holds a tcp_sockinfo.
                let tcp: TcpSockInfo =
                    unsafe { std::ptr::read_unaligned(si.soi_proto.as_ptr().cast()) };
                let st = match tcp.tcpsi_state {
                    TSI_S_LISTEN => SockState::Listen,
                    TSI_S_SYN_SENT => SockState::SynSent,
                    TSI_S_ESTABLISHED => SockState::Established,
                    _ => SockState::Other,
                };
                (Proto::Tcp, tcp.tcpsi_ini, st)
            }
            (SOCKINFO_IN, IPPROTO_UDP) => {
                // SAFETY: soi_kind says the union holds an in_sockinfo.
                let ini: InSockInfo =
                    unsafe { std::ptr::read_unaligned(si.soi_proto.as_ptr().cast()) };
                let st = if ini.insi_fport != 0 {
                    SockState::UdpConnected
                } else {
                    SockState::Listen
                };
                (Proto::Udp, ini, st)
            }
            _ => continue,
        };
        let (Some(l), Some(r)) = (
            addr(&ini.insi_laddr, ini.insi_vflag),
            addr(&ini.insi_faddr, ini.insi_vflag),
        ) else {
            continue;
        };
        out.push(SockSnap {
            pid: pid as u32,
            proto,
            local: SocketAddr::new(l, port(ini.insi_lport)),
            remote: SocketAddr::new(r, port(ini.insi_fport)),
            state,
        });
    }
}

#[derive(Debug, Default)]
pub struct MacSource {
    first_seen: HashMap<u32, i64>,
}

impl MacSource {
    pub fn new() -> Self {
        MacSource::default()
    }
}

impl SnapshotSource for MacSource {
    fn processes(&mut self) -> io::Result<Vec<ProcSnap>> {
        let now = now_ms();
        let mut out = Vec::new();
        for pid in pids()? {
            let Some(info) = bsdinfo(pid) else { continue };
            let start = i64::try_from(info.pbi_start_tvsec).unwrap_or(0) * 1000
                + i64::try_from(info.pbi_start_tvusec / 1000).unwrap_or(0);
            let start_time = if start > 0 {
                start
            } else {
                *self.first_seen.entry(pid as u32).or_insert(now)
            };
            let exe = exe_path(pid).unwrap_or_else(|| c_str(&info.pbi_comm));
            out.push(ProcSnap {
                pid: pid as u32,
                ppid: info.pbi_ppid,
                start_time,
                exe,
                cmdline: cmdline(pid),
            });
        }
        let live: std::collections::HashSet<u32> = out.iter().map(|p| p.pid).collect();
        self.first_seen.retain(|p, _| live.contains(p));
        Ok(out)
    }

    fn sockets(&mut self) -> io::Result<Vec<SockSnap>> {
        let mut out = Vec::new();
        for pid in pids()? {
            sockets_of(pid, &mut out);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn struct_sizes_match_xnu() {
        assert_eq!(size_of::<ProcBsdInfo>(), 136);
        assert_eq!(size_of::<ProcFdInfo>(), 8);
        assert_eq!(size_of::<InSockInfo>(), 80);
        assert_eq!(size_of::<ProcFileInfo>(), 24);
    }

    #[test]
    fn procargs2() {
        let mut b = 3i32.to_ne_bytes().to_vec();
        b.extend_from_slice(b"/usr/bin/curl\0\0\0\0curl\0-s\0http://x/a b\0PATH=/bin\0");
        assert_eq!(
            parse_procargs2(&b).as_deref(),
            Some("curl -s \"http://x/a b\"")
        );
        assert_eq!(parse_procargs2(&[1, 0]), None);
    }

    #[test]
    fn snapshot_contains_this_process() {
        let mut s = MacSource::new();
        let procs = s.processes().unwrap();
        let me = procs
            .iter()
            .find(|p| p.pid == std::process::id())
            .expect("own process listed");
        assert!(me.exe.starts_with('/'), "{}", me.exe);
        assert!(me.start_time > 1_600_000_000_000);
    }
}
