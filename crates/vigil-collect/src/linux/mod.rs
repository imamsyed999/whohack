//! Linux collectors.

pub mod dns_sniff;
#[cfg(feature = "ebpf")]
pub mod ebpf;
pub mod procfs;
pub mod select;
pub mod tracefs;

/// `sysconf(_SC_CLK_TCK)`, the unit of `/proc/<pid>/stat` start times.
pub fn clock_ticks_per_sec() -> i64 {
    // SAFETY: sysconf has no preconditions and only reads a constant.
    #[allow(unsafe_code)]
    let v = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    if v > 0 { v } else { 100 }
}

/// True when running with effective UID 0.
pub fn is_root() -> bool {
    // SAFETY: geteuid has no preconditions and cannot fail.
    #[allow(unsafe_code)]
    unsafe {
        libc::geteuid() == 0
    }
}
