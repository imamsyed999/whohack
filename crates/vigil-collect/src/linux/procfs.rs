//! `/proc`-based snapshot source (unprivileged fallback; also used for the
//! startup snapshot and UDP flows when eBPF is active).
//!
//! Unprivileged, only the caller's own processes expose `exe` and `fd`, so
//! other users' processes are reported by name and their sockets are not
//! attributed. Run as root for full visibility.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};

use vigil_core::Proto;

use crate::poll::{ProcSnap, SnapshotSource, SockSnap, SockState};

/// Fields parsed from `/proc/<pid>/stat`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stat {
    pub comm: String,
    pub ppid: u32,
    /// Clock ticks since boot (field 22).
    pub start_ticks: u64,
}

/// Parses `/proc/<pid>/stat`. `comm` may itself contain spaces and `)`, so it
/// is delimited by the first `(` and the *last* `)`.
pub fn parse_stat(s: &str) -> Option<Stat> {
    let open = s.find('(')?;
    let close = s.rfind(')')?;
    let comm = s.get(open + 1..close)?.to_string();
    let rest: Vec<&str> = s.get(close + 1..)?.split_whitespace().collect();
    // rest[0] = state (field 3), rest[1] = ppid (field 4), rest[19] = starttime (field 22)
    Some(Stat {
        comm,
        ppid: rest.get(1)?.parse().ok()?,
        start_ticks: rest.get(19)?.parse().ok()?,
    })
}

/// Joins a NUL-separated `/proc/<pid>/cmdline`, quoting arguments that
/// contain whitespace. Returns `None` for an empty command line (kernel threads).
pub fn parse_cmdline(raw: &[u8]) -> Option<String> {
    let args: Vec<String> = raw
        .split(|&b| b == 0)
        .filter(|a| !a.is_empty())
        .map(|a| {
            let s = String::from_utf8_lossy(a);
            if s.chars().any(char::is_whitespace) {
                format!("\"{}\"", s.replace('"', "\\\""))
            } else {
                s.into_owned()
            }
        })
        .collect();
    if args.is_empty() {
        None
    } else {
        Some(args.join(" "))
    }
}

/// Boot time in Unix ms from `/proc/stat` (`btime`).
pub fn parse_btime_ms(proc_stat: &str) -> Option<i64> {
    proc_stat
        .lines()
        .find_map(|l| l.strip_prefix("btime "))
        .and_then(|v| v.trim().parse::<i64>().ok())
        .map(|s| s * 1000)
}

/// Parses an address from `/proc/net/{tcp,udp}{,6}`: hex words in host byte
/// order for the IP, then a big-endian hex port.
pub fn parse_net_addr(s: &str) -> Option<SocketAddr> {
    let (ip_hex, port_hex) = s.split_once(':')?;
    let port = u16::from_str_radix(port_hex, 16).ok()?;
    let ip = match ip_hex.len() {
        8 => {
            let w = u32::from_str_radix(ip_hex, 16).ok()?;
            IpAddr::V4(Ipv4Addr::from(w.to_ne_bytes()))
        }
        32 => {
            let mut o = [0u8; 16];
            for i in 0..4 {
                let w = u32::from_str_radix(ip_hex.get(i * 8..i * 8 + 8)?, 16).ok()?;
                o[i * 4..i * 4 + 4].copy_from_slice(&w.to_ne_bytes());
            }
            IpAddr::V6(Ipv6Addr::from(o))
        }
        _ => return None,
    };
    Some(SocketAddr::new(ip, port))
}

/// One row of a `/proc/net` socket table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetRow {
    pub local: SocketAddr,
    pub remote: SocketAddr,
    pub state: SockState,
    pub inode: u64,
}

/// Parses a `/proc/net/{tcp,tcp6,udp,udp6}` table.
pub fn parse_net_table(text: &str, proto: Proto) -> Vec<NetRow> {
    text.lines()
        .skip(1)
        .filter_map(|line| {
            let f: Vec<&str> = line.split_whitespace().collect();
            let local = parse_net_addr(f.get(1)?)?;
            let remote = parse_net_addr(f.get(2)?)?;
            let st = u8::from_str_radix(f.get(3)?, 16).ok()?;
            let inode: u64 = f.get(9)?.parse().ok()?;
            let state = match (proto, st) {
                (Proto::Tcp, 0x01) => SockState::Established,
                (Proto::Tcp, 0x02) => SockState::SynSent,
                (Proto::Tcp, 0x0A) => SockState::Listen,
                (Proto::Udp, 0x01) => SockState::UdpConnected,
                // An unconnected UDP socket bound to a port is a server socket.
                (Proto::Udp, 0x07) if remote.port() == 0 => SockState::Listen,
                _ => SockState::Other,
            };
            Some(NetRow {
                local,
                remote,
                state,
                inode,
            })
        })
        .collect()
}

/// Extracts the inode from a `socket:[12345]` fd link target.
pub fn socket_inode(link: &Path) -> Option<u64> {
    link.to_str()?
        .strip_prefix("socket:[")?
        .strip_suffix(']')?
        .parse()
        .ok()
}

#[derive(Debug)]
pub struct ProcfsSource {
    root: PathBuf,
    clk_tck: i64,
    btime_ms: i64,
    inode_pid: HashMap<u64, u32>,
}

impl ProcfsSource {
    pub fn new() -> io::Result<Self> {
        ProcfsSource::with_root(Path::new("/proc"))
    }

    /// Uses an alternate procfs root (tests).
    pub fn with_root(root: &Path) -> io::Result<Self> {
        let stat = fs::read_to_string(root.join("stat"))?;
        let btime_ms = parse_btime_ms(&stat)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "no btime in /proc/stat"))?;
        Ok(ProcfsSource {
            root: root.to_path_buf(),
            clk_tck: super::clock_ticks_per_sec(),
            btime_ms,
            inode_pid: HashMap::new(),
        })
    }

    fn pids(&self) -> io::Result<Vec<u32>> {
        Ok(fs::read_dir(&self.root)?
            .filter_map(Result::ok)
            .filter_map(|e| e.file_name().to_str()?.parse().ok())
            .collect())
    }

    fn read_proc(&self, pid: u32) -> Option<ProcSnap> {
        let dir = self.root.join(pid.to_string());
        let stat = parse_stat(&fs::read_to_string(dir.join("stat")).ok()?)?;
        // Kernel threads (kthreadd = 2 and its children) have no executable.
        if pid == 2 || stat.ppid == 2 {
            return None;
        }
        let cmdline = fs::read(dir.join("cmdline"))
            .ok()
            .and_then(|b| parse_cmdline(&b));
        let exe = fs::read_link(dir.join("exe"))
            .ok()
            .map(|p| {
                p.to_string_lossy()
                    .trim_end_matches(" (deleted)")
                    .to_string()
            })
            .or_else(|| {
                cmdline
                    .as_deref()
                    .and_then(|c| c.split_whitespace().next())
                    .map(|s| s.trim_matches('"').to_string())
            })
            .unwrap_or_else(|| stat.comm.clone());
        let start_ms = self.btime_ms
            + i64::try_from(stat.start_ticks).unwrap_or(0) * 1000 / self.clk_tck.max(1);
        Some(ProcSnap {
            pid,
            ppid: stat.ppid,
            start_time: start_ms,
            exe,
            cmdline,
        })
    }

    /// Rebuilds the inode → pid map by scanning `/proc/<pid>/fd`.
    fn refresh_inode_map(&mut self) {
        let mut map = HashMap::new();
        if let Ok(pids) = self.pids() {
            for pid in pids {
                let fd_dir = self.root.join(pid.to_string()).join("fd");
                let Ok(rd) = fs::read_dir(&fd_dir) else {
                    continue;
                };
                for e in rd.filter_map(Result::ok) {
                    if let Some(ino) = fs::read_link(e.path())
                        .ok()
                        .as_deref()
                        .and_then(socket_inode)
                    {
                        map.entry(ino).or_insert(pid);
                    }
                }
            }
        }
        self.inode_pid = map;
    }
}

impl SnapshotSource for ProcfsSource {
    fn processes(&mut self) -> io::Result<Vec<ProcSnap>> {
        Ok(self
            .pids()?
            .into_iter()
            .filter_map(|p| self.read_proc(p))
            .collect())
    }

    fn sockets(&mut self) -> io::Result<Vec<SockSnap>> {
        let mut rows = Vec::new();
        for (file, proto) in [
            ("tcp", Proto::Tcp),
            ("tcp6", Proto::Tcp),
            ("udp", Proto::Udp),
            ("udp6", Proto::Udp),
        ] {
            // A missing table (IPv6 disabled) is not an error.
            if let Ok(text) = fs::read_to_string(self.root.join("net").join(file)) {
                rows.extend(
                    parse_net_table(&text, proto)
                        .into_iter()
                        .map(|r| (proto, r)),
                );
            }
        }
        // Only rescan fds when an interesting socket has an unknown owner.
        let unknown = rows.iter().any(|(_, r)| {
            r.inode != 0 && r.state != SockState::Other && !self.inode_pid.contains_key(&r.inode)
        });
        if unknown {
            self.refresh_inode_map();
        }
        let live: HashSet<u64> = rows.iter().map(|(_, r)| r.inode).collect();
        self.inode_pid.retain(|ino, _| live.contains(ino));
        Ok(rows
            .into_iter()
            .map(|(proto, r)| SockSnap {
                pid: self.inode_pid.get(&r.inode).copied().unwrap_or(0),
                proto,
                local: r.local,
                remote: r.remote,
                state: r.state,
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stat_with_hostile_comm() {
        let s = "1234 (evil) (x) S 99 1234 1234 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 98765 1000 200 18446744073709551615";
        let st = parse_stat(s).unwrap();
        assert_eq!(st.comm, "evil) (x");
        assert_eq!(st.ppid, 99);
        assert_eq!(st.start_ticks, 98765);
        assert!(parse_stat("garbage").is_none());
        assert!(parse_stat("1 (a) S").is_none());
    }

    #[test]
    fn cmdline_joins_and_quotes() {
        assert_eq!(
            parse_cmdline(b"/usr/bin/curl\0-s\0http://x/a b\0").as_deref(),
            Some("/usr/bin/curl -s \"http://x/a b\"")
        );
        assert_eq!(parse_cmdline(b""), None);
        assert_eq!(parse_cmdline(b"\0\0"), None);
    }

    #[test]
    fn btime() {
        assert_eq!(
            parse_btime_ms("cpu 1 2\nbtime 1700000000\nprocesses 5\n"),
            Some(1_700_000_000_000)
        );
        assert_eq!(parse_btime_ms("cpu 1"), None);
    }

    #[test]
    fn net_addr_byte_order() {
        // 127.0.0.1:8080 on a little-endian host
        if cfg!(target_endian = "little") {
            assert_eq!(
                parse_net_addr("0100007F:1F90").unwrap(),
                "127.0.0.1:8080".parse().unwrap()
            );
            assert_eq!(
                parse_net_addr("00000000000000000000000001000000:0050").unwrap(),
                "[::1]:80".parse().unwrap()
            );
            // ::ffff:93.184.216.34
            assert_eq!(
                parse_net_addr("0000000000000000FFFF000022D8B85D:01BB").unwrap(),
                "[::ffff:93.184.216.34]:443".parse().unwrap()
            );
        }
        assert!(parse_net_addr("zz:1").is_none());
        assert!(parse_net_addr("0100007F").is_none());
    }

    #[test]
    fn net_table_states() {
        let tcp = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 11111 1 0000000000000000 100 0 0 10 0\n\
   1: 0201000A:C350 22D8B85D:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 22222 1 0000000000000000 20 4 30 10 -1\n\
   2: 0201000A:C351 22D8B85D:01BB 02 00000000:00000000 00:00000000 00000000  1000        0 33333 1\n\
   3: 0201000A:C352 22D8B85D:01BB 06 00000000:00000000 00:00000000 00000000  1000        0 0 1\n";
        let rows = parse_net_table(tcp, Proto::Tcp);
        let states: Vec<SockState> = rows.iter().map(|r| r.state).collect();
        assert_eq!(
            states,
            vec![
                SockState::Listen,
                SockState::Established,
                SockState::SynSent,
                SockState::Other
            ]
        );
        assert_eq!(rows[1].inode, 22222);
        if cfg!(target_endian = "little") {
            assert_eq!(rows[1].remote, "93.184.216.34:443".parse().unwrap());
            assert_eq!(rows[1].local, "10.0.1.2:50000".parse().unwrap());
        }
        let udp = "header\n   5: 00000000:14E9 00000000:0000 07 00000000:00000000 00:00000000 00000000   0 0 444 2\n";
        assert_eq!(parse_net_table(udp, Proto::Udp)[0].state, SockState::Listen);
    }

    #[test]
    fn socket_link() {
        assert_eq!(socket_inode(Path::new("socket:[12345]")), Some(12345));
        assert_eq!(socket_inode(Path::new("pipe:[1]")), None);
        assert_eq!(socket_inode(Path::new("/dev/null")), None);
    }

    #[test]
    fn fake_procfs_tree() {
        let dir = std::env::temp_dir().join(format!("vigil-procfs-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("100")).unwrap();
        fs::create_dir_all(dir.join("3")).unwrap();
        fs::create_dir_all(dir.join("net")).unwrap();
        fs::write(dir.join("stat"), "cpu 0\nbtime 1700000000\n").unwrap();
        fs::write(
            dir.join("100/stat"),
            "100 (tool) S 1 100 100 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 500 0 0",
        )
        .unwrap();
        fs::write(dir.join("100/cmdline"), b"/opt/tool\0--x\0").unwrap();
        // pid 3 is a kernel thread (ppid 2)
        fs::write(
            dir.join("3/stat"),
            "3 (kworker/0:0) I 2 0 0 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 5 0 0",
        )
        .unwrap();
        let mut src = ProcfsSource::with_root(&dir).unwrap();
        let procs = src.processes().unwrap();
        assert_eq!(procs.len(), 1);
        let p = &procs[0];
        assert_eq!((p.pid, p.ppid), (100, 1));
        assert_eq!(
            p.exe, "/opt/tool",
            "falls back to argv0 when exe is unreadable"
        );
        assert_eq!(p.cmdline.as_deref(), Some("/opt/tool --x"));
        assert_eq!(p.start_time, 1_700_000_000_000 + 500 * 1000 / src.clk_tck);
        assert!(src.sockets().unwrap().is_empty());
        let _ = fs::remove_dir_all(&dir);
    }
}
