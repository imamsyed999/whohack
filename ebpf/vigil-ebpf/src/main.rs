//! Vigil kernel-side programs. Three tracepoints feed one ring buffer:
//!
//! - `sched/sched_process_exec`: a process image was executed.
//! - `sched/sched_process_exit`: a thread-group leader exited.
//! - `sock/inet_sock_set_state` → `TCP_SYN_SENT`: an outbound TCP connect.
//!   This transition runs in the connecting task's context, so the current
//!   tgid is the connecting process.
//!
//! Field offsets come from `vigil_ebpf_common::layout` and are verified
//! against the running kernel by userspace before these programs load.
//!
//! PIDs are reported in the *collector's* PID namespace (set by userspace in
//! `PIDNS_DEV`/`PIDNS_INO`), so attribution is correct inside containers and
//! WSL2, where userspace PIDs differ from the kernel's root-namespace PIDs.
//! Tasks outside that namespace are skipped.
#![no_std]
#![no_main]

use aya_ebpf::EbpfContext;
use aya_ebpf::bindings::bpf_pidns_info;
use aya_ebpf::helpers::{
    bpf_get_current_pid_tgid, bpf_get_ns_current_pid_tgid, bpf_probe_read_kernel_str_bytes,
};
use aya_ebpf::macros::{map, tracepoint};
use aya_ebpf::maps::RingBuf;
use aya_ebpf::programs::TracePointContext;
use vigil_ebpf_common::layout::*;
use vigil_ebpf_common::{
    AF_INET, AF_INET6, IPPROTO_TCP, KIND_CONNECT, KIND_EXEC, KIND_EXIT, RawEvent, TCP_SYN_SENT,
};

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(512 * 1024, 0);

/// Device and inode of the collector's PID namespace; set at load time.
/// Both zero means "use root-namespace PIDs".
#[unsafe(no_mangle)]
static PIDNS_DEV: u64 = 0;
#[unsafe(no_mangle)]
static PIDNS_INO: u64 = 0;

/// `(tgid, tid)` of the current task in the collector's PID namespace.
#[inline(always)]
fn current_tgid() -> Option<(u32, u32)> {
    // SAFETY: plain reads of load-time constants; volatile stops const-folding.
    let (dev, ino) = unsafe {
        (
            core::ptr::read_volatile(&PIDNS_DEV),
            core::ptr::read_volatile(&PIDNS_INO),
        )
    };
    if dev == 0 && ino == 0 {
        let id = bpf_get_current_pid_tgid();
        return Some(((id >> 32) as u32, id as u32));
    }
    let mut info = bpf_pidns_info { pid: 0, tgid: 0 };
    // SAFETY: `info` is a valid, correctly sized out-parameter.
    let rc = unsafe {
        bpf_get_ns_current_pid_tgid(
            dev,
            ino,
            &mut info,
            core::mem::size_of::<bpf_pidns_info>() as u32,
        )
    };
    if rc != 0 { None } else { Some((info.tgid, info.pid)) }
}

#[tracepoint]
pub fn vigil_exec(ctx: TracePointContext) -> u32 {
    let _ = try_exec(&ctx);
    0
}

fn try_exec(ctx: &TracePointContext) -> Result<(), i64> {
    let Some((tgid, _)) = current_tgid() else {
        return Ok(());
    };
    // SAFETY: offsets are verified against the kernel's tracepoint format.
    let loc: u32 = unsafe { ctx.read_at(EXEC_FILENAME_LOC)? };
    let Some(mut entry) = EVENTS.reserve::<RawEvent>(0) else {
        return Ok(());
    };
    let ev = entry.as_mut_ptr();
    // SAFETY: `ev` points to reserved ring-buffer memory sized for RawEvent;
    // every field read by userspace for KIND_EXEC is written here.
    unsafe {
        (*ev).kind = KIND_EXEC;
        (*ev).tgid = tgid;
        (*ev).family = 0;
        (*ev).dport = 0;
        (*ev)._pad = 0;
        (*ev).daddr = [0; 16];
        (*ev).filename[0] = 0;
        let off = (loc & 0xffff) as usize;
        let src = (ctx.as_ptr() as *const u8).add(off);
        if bpf_probe_read_kernel_str_bytes(src, &mut (*ev).filename).is_err() {
            (*ev).filename[0] = 0;
        }
    }
    entry.submit(0);
    Ok(())
}

#[tracepoint]
pub fn vigil_exit(_ctx: TracePointContext) -> u32 {
    let Some((tgid, tid)) = current_tgid() else {
        return 0;
    };
    if tgid != tid {
        return 0; // a thread, not the process
    }
    if let Some(mut entry) = EVENTS.reserve::<RawEvent>(0) {
        let ev = entry.as_mut_ptr();
        // SAFETY: reserved memory sized for RawEvent; header fields written.
        unsafe {
            (*ev).kind = KIND_EXIT;
            (*ev).tgid = tgid;
            (*ev).family = 0;
            (*ev).dport = 0;
            (*ev)._pad = 0;
        }
        entry.submit(0);
    }
    0
}

#[tracepoint]
pub fn vigil_sock(ctx: TracePointContext) -> u32 {
    let _ = try_sock(&ctx);
    0
}

fn try_sock(ctx: &TracePointContext) -> Result<(), i64> {
    // SAFETY: offsets are verified against the kernel's tracepoint format.
    let (newstate, protocol, family, dport) = unsafe {
        (
            ctx.read_at::<i32>(SOCK_NEWSTATE)?,
            ctx.read_at::<u16>(SOCK_PROTOCOL)?,
            ctx.read_at::<u16>(SOCK_FAMILY)?,
            ctx.read_at::<u16>(SOCK_DPORT)?,
        )
    };
    if newstate != TCP_SYN_SENT || protocol != IPPROTO_TCP {
        return Ok(());
    }
    let mut daddr = [0u8; 16];
    match family {
        // SAFETY: as above.
        AF_INET => unsafe {
            let a: [u8; 4] = ctx.read_at(SOCK_DADDR)?;
            daddr[0] = a[0];
            daddr[1] = a[1];
            daddr[2] = a[2];
            daddr[3] = a[3];
        },
        // SAFETY: as above.
        AF_INET6 => daddr = unsafe { ctx.read_at(SOCK_DADDR_V6)? },
        _ => return Ok(()),
    }
    let Some((tgid, _)) = current_tgid() else {
        return Ok(());
    };
    if let Some(mut entry) = EVENTS.reserve::<RawEvent>(0) {
        let ev = entry.as_mut_ptr();
        // SAFETY: reserved memory sized for RawEvent; all KIND_CONNECT fields written.
        unsafe {
            (*ev).kind = KIND_CONNECT;
            (*ev).tgid = tgid;
            (*ev).family = family;
            (*ev).dport = dport;
            (*ev)._pad = 0;
            (*ev).daddr = daddr;
        }
        entry.submit(0);
    }
    Ok(())
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
