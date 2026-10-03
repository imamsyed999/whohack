//! DNS visibility via an `AF_PACKET` socket (root / CAP_NET_RAW).
//!
//! A classic-BPF filter attached in the kernel passes only UDP packets with
//! source port 53, so the collector wakes only for DNS responses. Outgoing
//! copies (seen on loopback) are skipped to avoid duplicates.
#![allow(unsafe_code)]

use std::io;
use std::net::IpAddr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use async_trait::async_trait;
use tokio::sync::mpsc;
use vigil_core::time::now_ms;
use vigil_core::{Event, EventKind};

use crate::Collector;
use crate::dns_wire::parse_response;

const ETH_P_ALL: u16 = 0x0003;
const ETH_P_IP: u32 = 0x0800;
const ETH_P_IPV6: u32 = 0x86DD;

// Classic BPF opcodes (linux/filter.h).
const BPF_LD: u16 = 0x00;
const BPF_LDX: u16 = 0x01;
const BPF_JMP: u16 = 0x05;
const BPF_RET: u16 = 0x06;
const BPF_H: u16 = 0x08;
const BPF_B: u16 = 0x10;
const BPF_ABS: u16 = 0x20;
const BPF_IND: u16 = 0x40;
const BPF_MSH: u16 = 0xa0;
const BPF_JEQ: u16 = 0x10;
const BPF_JSET: u16 = 0x40;
const BPF_K: u16 = 0x00;
const SKF_AD_OFF: u32 = 0xFFFF_F000; // -0x1000
const SKF_AD_PROTOCOL: u32 = 0;

const fn ins(code: u16, jt: u8, jf: u8, k: u32) -> libc::sock_filter {
    libc::sock_filter { code, jt, jf, k }
}

/// Accept UDP/IPv4 (unfragmented) or UDP/IPv6 (no extension headers) with
/// source port 53. Offsets are relative to the L3 header (SOCK_DGRAM).
fn dns_filter() -> [libc::sock_filter; 14] {
    [
        /* 0 */ ins(BPF_LD | BPF_H | BPF_ABS, 0, 0, SKF_AD_OFF + SKF_AD_PROTOCOL),
        /* 1 */ ins(BPF_JMP | BPF_JEQ | BPF_K, 0, 7, ETH_P_IP),
        /* 2 */ ins(BPF_LD | BPF_B | BPF_ABS, 0, 0, 9), // IPv4 protocol
        /* 3 */ ins(BPF_JMP | BPF_JEQ | BPF_K, 0, 11, 17),
        /* 4 */ ins(BPF_LD | BPF_H | BPF_ABS, 0, 0, 6), // flags + fragment offset
        /* 5 */ ins(BPF_JMP | BPF_JSET | BPF_K, 9, 0, 0x1fff),
        /* 6 */ ins(BPF_LDX | BPF_B | BPF_MSH, 0, 0, 0), // X = IHL * 4
        /* 7 */ ins(BPF_LD | BPF_H | BPF_IND, 0, 0, 0), // UDP source port
        /* 8 */ ins(BPF_JMP | BPF_JEQ | BPF_K, 5, 6, 53),
        /* 9 */ ins(BPF_JMP | BPF_JEQ | BPF_K, 0, 5, ETH_P_IPV6),
        /* 10 */ ins(BPF_LD | BPF_B | BPF_ABS, 0, 0, 6), // IPv6 next header
        /* 11 */ ins(BPF_JMP | BPF_JEQ | BPF_K, 0, 3, 17),
        /* 12 */ ins(BPF_LD | BPF_H | BPF_ABS, 0, 0, 40), // UDP source port
        /* 13 */
        ins(BPF_JMP | BPF_JEQ | BPF_K, 0, 1, 53),
        // Targets: 14 = accept, 15 = drop (appended by `filter_program`).
    ]
}

fn filter_program() -> Vec<libc::sock_filter> {
    let mut p = dns_filter().to_vec();
    p.push(ins(BPF_RET | BPF_K, 0, 0, 0xFFFF)); // 14: accept
    p.push(ins(BPF_RET | BPF_K, 0, 0, 0)); // 15: drop
    p
}

/// Extracts the UDP payload from an L3 packet (IPv4 or IPv6 without
/// extension headers) if it is UDP from port 53.
pub fn udp53_payload(pkt: &[u8]) -> Option<&[u8]> {
    let version = pkt.first()? >> 4;
    let (l4, proto) = match version {
        4 => {
            let ihl = usize::from(pkt[0] & 0x0f) * 4;
            if ihl < 20 {
                return None;
            }
            (ihl, *pkt.get(9)?)
        }
        6 => (40, *pkt.get(6)?),
        _ => return None,
    };
    if proto != 17 {
        return None;
    }
    let udp = pkt.get(l4..l4 + 8)?;
    let sport = u16::from_be_bytes([udp[0], udp[1]]);
    let len = usize::from(u16::from_be_bytes([udp[4], udp[5]]));
    if sport != 53 || len < 8 {
        return None;
    }
    pkt.get(l4 + 8..(l4 + len).min(pkt.len()))
}

fn open_socket() -> io::Result<OwnedFd> {
    // SAFETY: plain syscall; the returned fd is checked and immediately owned.
    let fd = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
            i32::from(ETH_P_ALL.to_be()),
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fd is a valid, newly created descriptor we exclusively own.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let prog = filter_program();
    let fprog = libc::sock_fprog {
        len: prog.len() as u16,
        filter: prog.as_ptr().cast_mut(),
    };
    // SAFETY: fprog points to `prog`, which outlives the call; the kernel copies it.
    let rc = unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_ATTACH_FILTER,
            (&raw const fprog).cast(),
            std::mem::size_of::<libc::sock_fprog>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    // Wake up periodically so shutdown is noticed on an idle network.
    let tv = libc::timeval {
        tv_sec: 1,
        tv_usec: 0,
    };
    // SAFETY: tv is a valid timeval for the duration of the call.
    let rc = unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            (&raw const tv).cast(),
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(fd)
}

fn sniff_loop(fd: OwnedFd, tx: mpsc::Sender<Event>) -> io::Result<()> {
    let mut buf = vec![0u8; 65_536];
    loop {
        if tx.is_closed() {
            return Ok(());
        }
        // SAFETY: zeroed sockaddr_ll is a valid initial value.
        let mut from: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        let mut from_len = std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t;
        // SAFETY: buf and from are valid writable buffers of the stated sizes.
        let n = unsafe {
            libc::recvfrom(
                fd.as_raw_fd(),
                buf.as_mut_ptr().cast(),
                buf.len(),
                0,
                (&raw mut from).cast(),
                &mut from_len,
            )
        };
        if n < 0 {
            let e = io::Error::last_os_error();
            match e.kind() {
                io::ErrorKind::WouldBlock
                | io::ErrorKind::TimedOut
                | io::ErrorKind::Interrupted => continue,
                _ => return Err(e),
            }
        }
        if from.sll_pkttype == libc::PACKET_OUTGOING {
            continue;
        }
        let pkt = &buf[..n as usize];
        let Some(answer) = udp53_payload(pkt).and_then(parse_response) else {
            continue;
        };
        if answer.addrs.is_empty() {
            continue;
        }
        let ev = Event {
            ts: now_ms(),
            pid: 0, // the resolver, not the requesting app; attribution comes from the cache
            kind: EventKind::DnsQuery {
                name: answer.name,
                answers: answer.addrs.iter().map(IpAddr::to_canonical).collect(),
            },
        };
        if tx.blocking_send(ev).is_err() {
            return Ok(());
        }
    }
}

/// DNS response sniffer.
#[derive(Debug, Default)]
pub struct DnsSniffer;

impl DnsSniffer {
    /// Checks that a capture socket can be opened (requires root/CAP_NET_RAW).
    pub fn probe() -> io::Result<()> {
        open_socket().map(drop)
    }
}

#[async_trait]
impl Collector for DnsSniffer {
    fn name(&self) -> &'static str {
        "linux-dns-sniffer"
    }

    async fn run(&self, tx: mpsc::Sender<Event>) -> anyhow::Result<()> {
        let fd = open_socket()?;
        tokio::task::spawn_blocking(move || sniff_loop(fd, tx)).await??;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns_wire::tests::build_response;

    fn ipv4_udp(sport: u16, payload: &[u8]) -> Vec<u8> {
        let mut p = vec![
            0x45, 0, 0, 0, 0, 0, 0x40, 0, 64, 17, 0, 0, 8, 8, 8, 8, 10, 0, 0, 2,
        ];
        let len = (8 + payload.len()) as u16;
        p.extend_from_slice(&sport.to_be_bytes());
        p.extend_from_slice(&40000u16.to_be_bytes());
        p.extend_from_slice(&len.to_be_bytes());
        p.extend_from_slice(&[0, 0]);
        p.extend_from_slice(payload);
        p
    }

    #[test]
    fn extracts_dns_payload_from_ipv4() {
        let dns = build_response("example.com", None, &["93.184.216.34".parse().unwrap()]);
        let pkt = ipv4_udp(53, &dns);
        let payload = udp53_payload(&pkt).unwrap();
        assert_eq!(parse_response(payload).unwrap().name, "example.com");
        assert!(udp53_payload(&ipv4_udp(5353, &dns)).is_none());
    }

    #[test]
    fn extracts_dns_payload_from_ipv6() {
        let dns = build_response("example.com", None, &["2001:db8::1".parse().unwrap()]);
        let mut p = vec![0x60, 0, 0, 0, 0, 0, 17, 64];
        p.extend_from_slice(&[0u8; 32]);
        p.extend_from_slice(&53u16.to_be_bytes());
        p.extend_from_slice(&40000u16.to_be_bytes());
        p.extend_from_slice(&((8 + dns.len()) as u16).to_be_bytes());
        p.extend_from_slice(&[0, 0]);
        p.extend_from_slice(&dns);
        assert_eq!(
            parse_response(udp53_payload(&p).unwrap())
                .unwrap()
                .addrs
                .len(),
            1
        );
    }

    #[test]
    fn rejects_non_udp_and_garbage() {
        let mut tcp = ipv4_udp(53, b"x");
        tcp[9] = 6;
        assert!(udp53_payload(&tcp).is_none());
        assert!(udp53_payload(&[]).is_none());
        assert!(udp53_payload(&[0x45, 0, 0]).is_none());
        assert!(udp53_payload(&[0x41; 30]).is_none(), "IHL < 5");
    }

    /// Minimal classic-BPF interpreter covering the opcodes `filter_program` uses.
    fn run_cbpf(prog: &[libc::sock_filter], pkt: &[u8], ethertype: u32) -> u32 {
        let (mut a, mut x, mut pc) = (0u32, 0u32, 0usize);
        let load = |off: usize, size: usize| -> Option<u32> {
            let b = pkt.get(off..off + size)?;
            Some(b.iter().fold(0u32, |acc, &v| (acc << 8) | u32::from(v)))
        };
        loop {
            let i = prog[pc];
            pc += 1;
            match i.code {
                c if c == BPF_LD | BPF_H | BPF_ABS && i.k == SKF_AD_OFF + SKF_AD_PROTOCOL => {
                    a = ethertype
                }
                c if c == BPF_LD | BPF_H | BPF_ABS => match load(i.k as usize, 2) {
                    Some(v) => a = v,
                    None => return 0,
                },
                c if c == BPF_LD | BPF_B | BPF_ABS => match load(i.k as usize, 1) {
                    Some(v) => a = v,
                    None => return 0,
                },
                c if c == BPF_LD | BPF_H | BPF_IND => match load(x as usize + i.k as usize, 2) {
                    Some(v) => a = v,
                    None => return 0,
                },
                c if c == BPF_LDX | BPF_B | BPF_MSH => match load(i.k as usize, 1) {
                    Some(v) => x = (v & 0xf) * 4,
                    None => return 0,
                },
                c if c == BPF_JMP | BPF_JEQ | BPF_K => {
                    pc += usize::from(if a == i.k { i.jt } else { i.jf })
                }
                c if c == BPF_JMP | BPF_JSET | BPF_K => {
                    pc += usize::from(if a & i.k != 0 { i.jt } else { i.jf })
                }
                c if c == BPF_RET | BPF_K => return i.k,
                c => panic!("unsupported opcode {c:#x}"),
            }
        }
    }

    #[test]
    fn filter_accepts_only_udp_from_port_53() {
        let prog = filter_program();
        let dns = build_response("example.com", None, &["93.184.216.34".parse().unwrap()]);
        assert_ne!(run_cbpf(&prog, &ipv4_udp(53, &dns), ETH_P_IP), 0);
        assert_eq!(run_cbpf(&prog, &ipv4_udp(5353, &dns), ETH_P_IP), 0);
        let mut tcp = ipv4_udp(53, &dns);
        tcp[9] = 6;
        assert_eq!(run_cbpf(&prog, &tcp, ETH_P_IP), 0);
        let mut frag = ipv4_udp(53, &dns);
        frag[6] = 0x20;
        frag[7] = 0x10; // non-zero fragment offset
        assert_eq!(run_cbpf(&prog, &frag, ETH_P_IP), 0);
        let mut v6 = vec![0x60, 0, 0, 0, 0, 0, 17, 64];
        v6.extend_from_slice(&[0u8; 32]);
        v6.extend_from_slice(&53u16.to_be_bytes());
        v6.extend_from_slice(&[0u8; 6]);
        assert_ne!(run_cbpf(&prog, &v6, ETH_P_IPV6), 0);
        v6[40] = 0x14; // source port 5173
        assert_eq!(run_cbpf(&prog, &v6, ETH_P_IPV6), 0);
        assert_eq!(run_cbpf(&prog, &[0u8; 64], 0x0806), 0, "ARP dropped");
    }

    #[test]
    fn filter_jump_targets_are_in_range() {
        let p = filter_program();
        for (i, insn) in p.iter().enumerate() {
            if insn.code & 0x07 == BPF_JMP {
                assert!(
                    i + 1 + usize::from(insn.jt) < p.len(),
                    "jt out of range at {i}"
                );
                assert!(
                    i + 1 + usize::from(insn.jf) < p.len(),
                    "jf out of range at {i}"
                );
            }
        }
        // Every IPv4/IPv6 "no" path ends at the drop instruction (index 15).
        assert_eq!(p[15].code, BPF_RET | BPF_K);
        assert_eq!(p[15].k, 0);
    }
}
