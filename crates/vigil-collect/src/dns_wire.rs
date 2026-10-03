//! Minimal DNS response parser (RFC 1035) for the DNS visibility collectors.
//!
//! Input is untrusted network data: every read is bounds-checked, name
//! compression pointers are loop-protected, and malformed input yields
//! `None` rather than a panic.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const TYPE_A: u16 = 1;
const TYPE_AAAA: u16 = 28;
const CLASS_IN: u16 = 1;
const MAX_NAME_LEN: usize = 255;
const MAX_POINTER_JUMPS: usize = 32;

/// The queried name and the A/AAAA addresses in a DNS response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsAnswer {
    pub name: String,
    pub addrs: Vec<IpAddr>,
}

struct Reader<'a> {
    buf: &'a [u8],
}

impl<'a> Reader<'a> {
    fn u8(&self, at: usize) -> Option<u8> {
        self.buf.get(at).copied()
    }

    fn u16(&self, at: usize) -> Option<u16> {
        let b = self.buf.get(at..at + 2)?;
        Some(u16::from_be_bytes([b[0], b[1]]))
    }

    fn slice(&self, at: usize, len: usize) -> Option<&'a [u8]> {
        self.buf.get(at..at.checked_add(len)?)
    }

    /// Reads a (possibly compressed) name at `at`. Returns the name and the
    /// offset just past it in the original (non-jumped) position.
    fn name(&self, mut at: usize) -> Option<(String, usize)> {
        let mut name = String::new();
        let mut end = None;
        let mut jumps = 0;
        loop {
            let len = self.u8(at)?;
            match len & 0xC0 {
                0x00 => {
                    if len == 0 {
                        let next = at + 1;
                        return Some((name, end.unwrap_or(next)));
                    }
                    let label = self.slice(at + 1, usize::from(len))?;
                    if !name.is_empty() {
                        name.push('.');
                    }
                    for &c in label {
                        // Keep printable ASCII only; anything else is replaced so a
                        // hostile name can never smuggle control characters downstream.
                        name.push(if c.is_ascii_graphic() {
                            char::from(c)
                        } else {
                            '?'
                        });
                    }
                    if name.len() > MAX_NAME_LEN {
                        return None;
                    }
                    at += 1 + usize::from(len);
                }
                0xC0 => {
                    let lo = self.u8(at + 1)?;
                    if end.is_none() {
                        end = Some(at + 2);
                    }
                    jumps += 1;
                    if jumps > MAX_POINTER_JUMPS {
                        return None;
                    }
                    at = (usize::from(len & 0x3F) << 8) | usize::from(lo);
                }
                _ => return None, // reserved label types
            }
        }
    }
}

/// Parses a DNS message. Returns `None` unless it is a successful response
/// (QR=1, RCODE=0) with exactly one question.
pub fn parse_response(msg: &[u8]) -> Option<DnsAnswer> {
    let r = Reader { buf: msg };
    let flags = r.u16(2)?;
    let is_response = flags & 0x8000 != 0;
    let rcode = flags & 0x000F;
    if !is_response || rcode != 0 {
        return None;
    }
    let qdcount = r.u16(4)?;
    let ancount = r.u16(6)?;
    if qdcount != 1 {
        return None;
    }
    let (qname, mut at) = r.name(12)?;
    at += 4; // QTYPE + QCLASS
    r.slice(at - 4, 4)?;
    let mut addrs = Vec::new();
    for _ in 0..ancount {
        let (_owner, next) = r.name(at)?;
        let rtype = r.u16(next)?;
        let class = r.u16(next + 2)?;
        let rdlen = usize::from(r.u16(next + 8)?);
        let rdata = r.slice(next + 10, rdlen)?;
        if class == CLASS_IN {
            match (rtype, rdlen) {
                (TYPE_A, 4) => addrs.push(IpAddr::V4(Ipv4Addr::new(
                    rdata[0], rdata[1], rdata[2], rdata[3],
                ))),
                (TYPE_AAAA, 16) => {
                    let mut o = [0u8; 16];
                    o.copy_from_slice(rdata);
                    addrs.push(IpAddr::V6(Ipv6Addr::from(o)));
                }
                _ => {}
            }
        }
        at = next + 10 + rdlen;
    }
    if qname.is_empty() {
        return None;
    }
    Some(DnsAnswer { name: qname, addrs })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    fn push_name(out: &mut Vec<u8>, name: &str) {
        for label in name.split('.') {
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
        out.push(0);
    }

    /// Builds a response for `qname` with a CNAME (compressed) then the given records.
    pub(crate) fn build_response(qname: &str, cname: Option<&str>, addrs: &[IpAddr]) -> Vec<u8> {
        let mut m = vec![0x12, 0x34, 0x81, 0x80, 0, 1];
        let ancount = addrs.len() + usize::from(cname.is_some());
        m.extend_from_slice(&(ancount as u16).to_be_bytes());
        m.extend_from_slice(&[0, 0, 0, 0]);
        push_name(&mut m, qname);
        m.extend_from_slice(&[0, 1, 0, 1]);
        if let Some(c) = cname {
            m.extend_from_slice(&[0xC0, 12, 0, 5, 0, 1, 0, 0, 0, 60]);
            let mut rd = Vec::new();
            push_name(&mut rd, c);
            m.extend_from_slice(&(rd.len() as u16).to_be_bytes());
            m.extend_from_slice(&rd);
        }
        for a in addrs {
            m.extend_from_slice(&[0xC0, 12]);
            match a {
                IpAddr::V4(v4) => {
                    m.extend_from_slice(&[0, 1, 0, 1, 0, 0, 0, 60, 0, 4]);
                    m.extend_from_slice(&v4.octets());
                }
                IpAddr::V6(v6) => {
                    m.extend_from_slice(&[0, 28, 0, 1, 0, 0, 0, 60, 0, 16]);
                    m.extend_from_slice(&v6.octets());
                }
            }
        }
        m
    }

    #[test]
    fn parses_a_aaaa_with_cname_and_compression() {
        let addrs: Vec<IpAddr> = vec![
            "93.184.216.34".parse().unwrap(),
            "2606:2800:220:1::".parse().unwrap(),
        ];
        let msg = build_response("www.example.com", Some("edge.example.net"), &addrs);
        let a = parse_response(&msg).unwrap();
        assert_eq!(a.name, "www.example.com");
        assert_eq!(a.addrs, addrs);
    }

    #[test]
    fn rejects_queries_errors_and_garbage() {
        let mut q = build_response("example.com", None, &[]);
        q[2] = 0x01; // QR = 0: a query
        assert!(parse_response(&q).is_none());
        let mut nx = build_response("example.com", None, &[]);
        nx[3] = 0x83; // NXDOMAIN
        assert!(parse_response(&nx).is_none());
        assert!(parse_response(&[]).is_none());
        assert!(parse_response(&[0xff; 11]).is_none());
    }

    #[test]
    fn truncated_messages_never_panic() {
        let msg = build_response(
            "a.example.com",
            Some("b.example.net"),
            &["10.0.0.1".parse().unwrap()],
        );
        for cut in 0..msg.len() {
            let _ = parse_response(&msg[..cut]);
        }
        // Every single-byte corruption must also be handled.
        for i in 0..msg.len() {
            for v in [0x00, 0x3f, 0xc0, 0xff] {
                let mut m = msg.clone();
                m[i] = v;
                let _ = parse_response(&m);
            }
        }
    }

    #[test]
    fn pointer_loop_is_rejected() {
        let mut m = vec![0x12, 0x34, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0];
        m.extend_from_slice(&[0xC0, 12]); // name points to itself
        m.extend_from_slice(&[0, 1, 0, 1]);
        assert!(parse_response(&m).is_none());
    }

    #[test]
    fn control_characters_are_neutralized() {
        let mut m = vec![0x12, 0x34, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0];
        m.extend_from_slice(&[3, b'a', b'\n', b'b', 3, b'c', b'o', b'm', 0, 0, 1, 0, 1]);
        assert_eq!(parse_response(&m).unwrap().name, "a?b.com");
    }
}
