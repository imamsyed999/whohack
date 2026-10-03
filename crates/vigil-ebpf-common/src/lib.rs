//! Records and tracepoint layout shared by `ebpf/vigil-ebpf` (kernel side)
//! and `vigil-collect::linux::ebpf` (userspace). `no_std` so the eBPF crate
//! can use it.
#![no_std]

/// `RawEvent::kind` values.
pub const KIND_EXEC: u32 = 1;
pub const KIND_EXIT: u32 = 2;
pub const KIND_CONNECT: u32 = 3;

pub const AF_INET: u16 = 2;
pub const AF_INET6: u16 = 10;
pub const IPPROTO_TCP: u16 = 6;
pub const TCP_SYN_SENT: i32 = 2;

pub const FILENAME_LEN: usize = 256;

/// One ring-buffer record. A single fixed layout for all kinds keeps the
/// userspace reader trivial; unused fields are zero.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct RawEvent {
    pub kind: u32,
    /// Thread-group id (the process id seen by userspace).
    pub tgid: u32,
    /// `KIND_CONNECT`: address family (`AF_INET` / `AF_INET6`).
    pub family: u16,
    /// `KIND_CONNECT`: destination port, host byte order.
    pub dport: u16,
    pub _pad: u32,
    /// `KIND_CONNECT`: destination address; IPv4 uses the first 4 bytes.
    pub daddr: [u8; 16],
    /// `KIND_EXEC`: path passed to execve (NUL-terminated, may be relative).
    pub filename: [u8; FILENAME_LEN],
}

impl RawEvent {
    pub const fn zeroed() -> Self {
        RawEvent {
            kind: 0,
            tgid: 0,
            family: 0,
            dport: 0,
            _pad: 0,
            daddr: [0; 16],
            filename: [0; FILENAME_LEN],
        }
    }
}

/// Field offsets read by the eBPF programs, as `(tracepoint, field, offset)`.
/// Userspace verifies each against `/sys/kernel/tracing/events/<tp>/format`
/// before loading and falls back to polling on any mismatch.
pub mod layout {
    pub const EXEC_FILENAME_LOC: usize = 8;
    pub const EXEC_PID: usize = 12;
    pub const SOCK_NEWSTATE: usize = 20;
    pub const SOCK_DPORT: usize = 26;
    pub const SOCK_FAMILY: usize = 28;
    pub const SOCK_PROTOCOL: usize = 30;
    pub const SOCK_DADDR: usize = 36;
    pub const SOCK_DADDR_V6: usize = 56;

    pub const CHECKS: &[(&str, &str, usize)] = &[
        ("sched/sched_process_exec", "filename", EXEC_FILENAME_LOC),
        ("sched/sched_process_exec", "pid", EXEC_PID),
        ("sock/inet_sock_set_state", "newstate", SOCK_NEWSTATE),
        ("sock/inet_sock_set_state", "dport", SOCK_DPORT),
        ("sock/inet_sock_set_state", "family", SOCK_FAMILY),
        ("sock/inet_sock_set_state", "protocol", SOCK_PROTOCOL),
        ("sock/inet_sock_set_state", "daddr", SOCK_DADDR),
        ("sock/inet_sock_set_state", "daddr_v6", SOCK_DADDR_V6),
    ];
}
