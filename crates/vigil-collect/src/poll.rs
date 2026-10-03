//! OS-independent polling collector.
//!
//! Each OS implements [`SnapshotSource`] (a list of processes and a list of
//! sockets at one instant); [`Differ`] turns consecutive snapshots into
//! events, and [`PollCollector`] runs the loop on a blocking thread.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use async_trait::async_trait;
use tokio::sync::mpsc;
use vigil_core::time::now_ms;
use vigil_core::{Event, EventKind, Proto};

use crate::Collector;

/// One process at snapshot time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcSnap {
    pub pid: u32,
    pub ppid: u32,
    /// Unix ms. Must be stable across snapshots for the same process.
    pub start_time: i64,
    pub exe: String,
    pub cmdline: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SockState {
    Listen,
    SynSent,
    Established,
    /// UDP socket with a connected peer.
    UdpConnected,
    Other,
}

/// One socket at snapshot time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SockSnap {
    /// Owning process; 0 if unknown.
    pub pid: u32,
    pub proto: Proto,
    pub local: SocketAddr,
    pub remote: SocketAddr,
    pub state: SockState,
}

/// A platform's point-in-time view of processes and sockets.
pub trait SnapshotSource: Send + 'static {
    fn processes(&mut self) -> std::io::Result<Vec<ProcSnap>>;
    fn sockets(&mut self) -> std::io::Result<Vec<SockSnap>>;
}

/// What a [`PollCollector`] reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PollScope {
    pub processes: bool,
    pub tcp: bool,
    pub udp: bool,
}

impl PollScope {
    pub const ALL: PollScope = PollScope {
        processes: true,
        tcp: true,
        udp: true,
    };
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct SockKey {
    pid: u32,
    proto: Proto,
    local_port: u16,
    remote: SocketAddr,
}

/// Turns consecutive snapshots into events.
#[derive(Debug)]
pub struct Differ {
    procs: HashMap<u32, i64>,
    socks: HashSet<SockKey>,
    include_loopback: bool,
}

pub fn is_loopback(ip: IpAddr) -> bool {
    ip.to_canonical().is_loopback()
}

impl Differ {
    pub fn new(include_loopback: bool) -> Self {
        Differ {
            procs: HashMap::new(),
            socks: HashSet::new(),
            include_loopback,
        }
    }

    /// `ProcessStart` for new processes (stamped with their real start time,
    /// parents before children), `ProcessExit` for vanished ones, and
    /// exit-then-start when a PID was reused.
    pub fn diff_processes(&mut self, snaps: &[ProcSnap], now: i64) -> Vec<Event> {
        let mut exits = Vec::new();
        let mut starts: Vec<&ProcSnap> = Vec::new();
        let mut seen = HashSet::with_capacity(snaps.len());
        for s in snaps {
            seen.insert(s.pid);
            match self.procs.get(&s.pid) {
                Some(&t) if t == s.start_time => {}
                Some(_) => {
                    exits.push(Event {
                        ts: now,
                        pid: s.pid,
                        kind: EventKind::ProcessExit,
                    });
                    starts.push(s);
                }
                None => starts.push(s),
            }
        }
        let gone: Vec<u32> = self
            .procs
            .keys()
            .filter(|p| !seen.contains(p))
            .copied()
            .collect();
        for pid in gone {
            self.procs.remove(&pid);
            exits.push(Event {
                ts: now,
                pid,
                kind: EventKind::ProcessExit,
            });
        }
        // Parents normally start before children; ordering by start time keeps
        // lineage reconstruction simple. PID breaks ties deterministically.
        starts.sort_by_key(|s| (s.start_time, s.pid));
        let mut out = exits;
        for s in starts {
            self.procs.insert(s.pid, s.start_time);
            out.push(Event {
                ts: s.start_time,
                pid: s.pid,
                kind: EventKind::ProcessStart {
                    ppid: s.ppid,
                    exe: s.exe.clone(),
                    cmdline: s.cmdline.clone(),
                },
            });
        }
        out
    }

    /// One `NetConnect` per new outbound flow. Inbound flows (local port is
    /// a listening port), unowned sockets, and (by default) loopback are
    /// skipped. A flow is reported once for as long as it persists.
    pub fn diff_sockets(&mut self, snaps: &[SockSnap], scope: PollScope, now: i64) -> Vec<Event> {
        let listening: HashSet<(Proto, u16)> = snaps
            .iter()
            .filter(|s| s.state == SockState::Listen)
            .map(|s| (s.proto, s.local.port()))
            .collect();
        let mut current = HashSet::with_capacity(snaps.len());
        let mut out = Vec::new();
        for s in snaps {
            let wanted_proto = match s.proto {
                Proto::Tcp => scope.tcp,
                Proto::Udp => scope.udp,
            };
            let outbound_state = matches!(
                s.state,
                SockState::SynSent | SockState::Established | SockState::UdpConnected
            );
            let remote_ip = s.remote.ip().to_canonical();
            if !wanted_proto
                || !outbound_state
                || s.pid == 0
                || s.remote.port() == 0
                || remote_ip.is_unspecified()
                || listening.contains(&(s.proto, s.local.port()))
                || (!self.include_loopback && is_loopback(remote_ip))
            {
                continue;
            }
            let key = SockKey {
                pid: s.pid,
                proto: s.proto,
                local_port: s.local.port(),
                remote: SocketAddr::new(remote_ip, s.remote.port()),
            };
            if !self.socks.contains(&key) {
                out.push(Event {
                    ts: now,
                    pid: s.pid,
                    kind: EventKind::NetConnect {
                        remote_ip,
                        remote_port: s.remote.port(),
                        proto: s.proto,
                        domain: None,
                        dns_before: false,
                    },
                });
            }
            current.insert(key);
        }
        self.socks = current;
        out
    }
}

/// Polling collector over any [`SnapshotSource`].
#[derive(Debug)]
pub struct PollCollector<S> {
    name: &'static str,
    source: std::sync::Mutex<Option<S>>,
    interval: Duration,
    include_loopback: bool,
    scope: PollScope,
}

impl<S: SnapshotSource> PollCollector<S> {
    pub fn new(
        name: &'static str,
        source: S,
        interval: Duration,
        include_loopback: bool,
        scope: PollScope,
    ) -> Self {
        PollCollector {
            name,
            source: std::sync::Mutex::new(Some(source)),
            interval,
            include_loopback,
            scope,
        }
    }
}

/// Runs the polling loop until the receiver is dropped.
fn poll_loop<S: SnapshotSource>(
    name: &'static str,
    mut source: S,
    interval: Duration,
    include_loopback: bool,
    scope: PollScope,
    tx: mpsc::Sender<Event>,
) {
    let mut differ = Differ::new(include_loopback);
    let mut warned_procs = false;
    let mut warned_socks = false;
    loop {
        let now = now_ms();
        let mut events = Vec::new();
        if scope.processes {
            match source.processes() {
                Ok(p) => events.extend(differ.diff_processes(&p, now)),
                Err(e) if !warned_procs => {
                    tracing::warn!(collector = name, error = %e, "process snapshot failed");
                    warned_procs = true;
                }
                Err(_) => {}
            }
        }
        if scope.tcp || scope.udp {
            match source.sockets() {
                Ok(s) => events.extend(differ.diff_sockets(&s, scope, now)),
                Err(e) if !warned_socks => {
                    tracing::warn!(collector = name, error = %e, "socket snapshot failed");
                    warned_socks = true;
                }
                Err(_) => {}
            }
        }
        for ev in events {
            if tx.blocking_send(ev).is_err() {
                return;
            }
        }
        if tx.is_closed() {
            return;
        }
        std::thread::sleep(interval);
    }
}

#[async_trait]
impl<S: SnapshotSource> Collector for PollCollector<S> {
    fn name(&self) -> &'static str {
        self.name
    }

    async fn run(&self, tx: mpsc::Sender<Event>) -> anyhow::Result<()> {
        let source = self
            .source
            .lock()
            .map_err(|_| anyhow::anyhow!("{} source lock poisoned", self.name))?
            .take()
            .ok_or_else(|| anyhow::anyhow!("{} collector already running", self.name))?;
        let (name, interval, lb, scope) =
            (self.name, self.interval, self.include_loopback, self.scope);
        tokio::task::spawn_blocking(move || poll_loop(name, source, interval, lb, scope, tx))
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(pid: u32, ppid: u32, start: i64, exe: &str) -> ProcSnap {
        ProcSnap {
            pid,
            ppid,
            start_time: start,
            exe: exe.into(),
            cmdline: None,
        }
    }

    fn s(pid: u32, proto: Proto, local: &str, remote: &str, state: SockState) -> SockSnap {
        SockSnap {
            pid,
            proto,
            local: local.parse().unwrap(),
            remote: remote.parse().unwrap(),
            state,
        }
    }

    fn kinds(evs: &[Event]) -> Vec<(u32, &'static str)> {
        evs.iter().map(|e| (e.pid, e.kind.name())).collect()
    }

    #[test]
    fn first_snapshot_starts_everything_parents_first() {
        let mut d = Differ::new(false);
        let evs = d.diff_processes(
            &[
                p(30, 20, 300, "child"),
                p(1, 0, 10, "init"),
                p(20, 1, 200, "parent"),
            ],
            1_000,
        );
        assert_eq!(
            kinds(&evs),
            vec![
                (1, "process_start"),
                (20, "process_start"),
                (30, "process_start")
            ]
        );
        assert_eq!(evs[2].ts, 300, "start events carry the real start time");
        assert!(
            d.diff_processes(
                &[
                    p(1, 0, 10, "init"),
                    p(20, 1, 200, "parent"),
                    p(30, 20, 300, "child")
                ],
                2_000
            )
            .is_empty()
        );
    }

    #[test]
    fn exits_and_pid_reuse() {
        let mut d = Differ::new(false);
        d.diff_processes(&[p(1, 0, 10, "init"), p(5, 1, 50, "old")], 100);
        let evs = d.diff_processes(&[p(1, 0, 10, "init"), p(5, 1, 900, "new")], 1_000);
        assert_eq!(kinds(&evs), vec![(5, "process_exit"), (5, "process_start")]);
        let evs = d.diff_processes(&[p(1, 0, 10, "init")], 2_000);
        assert_eq!(kinds(&evs), vec![(5, "process_exit")]);
        assert_eq!(evs[0].ts, 2_000);
    }

    #[test]
    fn new_flow_reported_once_while_it_persists() {
        let mut d = Differ::new(false);
        let snap = [s(
            7,
            Proto::Tcp,
            "10.0.0.2:50000",
            "93.184.216.34:443",
            SockState::Established,
        )];
        let evs = d.diff_sockets(&snap, PollScope::ALL, 1);
        assert_eq!(evs.len(), 1);
        match &evs[0].kind {
            EventKind::NetConnect {
                remote_ip,
                remote_port,
                proto,
                ..
            } => {
                assert_eq!(remote_ip.to_string(), "93.184.216.34");
                assert_eq!((*remote_port, *proto), (443, Proto::Tcp));
            }
            k => panic!("{k:?}"),
        }
        assert!(d.diff_sockets(&snap, PollScope::ALL, 2).is_empty());
        // Gone, then a new connection on a new local port is reported again.
        assert!(d.diff_sockets(&[], PollScope::ALL, 3).is_empty());
        let snap2 = [s(
            7,
            Proto::Tcp,
            "10.0.0.2:50001",
            "93.184.216.34:443",
            SockState::SynSent,
        )];
        assert_eq!(d.diff_sockets(&snap2, PollScope::ALL, 4).len(), 1);
    }

    #[test]
    fn filters_inbound_listen_unowned_unspecified_and_loopback() {
        let mut d = Differ::new(false);
        let snap = [
            s(1, Proto::Tcp, "0.0.0.0:22", "0.0.0.0:0", SockState::Listen),
            // inbound: local port 22 is listening
            s(
                1,
                Proto::Tcp,
                "10.0.0.2:22",
                "198.51.100.5:61000",
                SockState::Established,
            ),
            s(
                0,
                Proto::Tcp,
                "10.0.0.2:50000",
                "198.51.100.5:443",
                SockState::Established,
            ),
            s(
                2,
                Proto::Tcp,
                "127.0.0.1:50001",
                "127.0.0.1:8080",
                SockState::Established,
            ),
            s(
                2,
                Proto::Tcp,
                "[::1]:50002",
                "[::1]:8080",
                SockState::Established,
            ),
            s(3, Proto::Udp, "0.0.0.0:5353", "0.0.0.0:0", SockState::Other),
            s(
                4,
                Proto::Tcp,
                "10.0.0.2:50003",
                "198.51.100.6:443",
                SockState::Other,
            ),
        ];
        assert!(d.diff_sockets(&snap, PollScope::ALL, 1).is_empty());

        let mut d = Differ::new(true);
        let evs = d.diff_sockets(&snap, PollScope::ALL, 1);
        assert_eq!(
            evs.len(),
            2,
            "loopback flows included when enabled: {evs:?}"
        );
    }

    #[test]
    fn v4_mapped_v6_is_canonicalized_and_scope_filters_protocols() {
        let mut d = Differ::new(false);
        let snap = [
            s(
                9,
                Proto::Tcp,
                "[::ffff:10.0.0.2]:50000",
                "[::ffff:93.184.216.34]:443",
                SockState::Established,
            ),
            s(
                9,
                Proto::Udp,
                "10.0.0.2:50001",
                "8.8.8.8:443",
                SockState::UdpConnected,
            ),
        ];
        let udp_only = PollScope {
            processes: false,
            tcp: false,
            udp: true,
        };
        let evs = d.diff_sockets(&snap, udp_only, 1);
        assert_eq!(evs.len(), 1);
        assert!(matches!(
            evs[0].kind,
            EventKind::NetConnect {
                proto: Proto::Udp,
                ..
            }
        ));
        let evs = Differ::new(false).diff_sockets(&snap, PollScope::ALL, 1);
        match &evs[0].kind {
            EventKind::NetConnect { remote_ip, .. } => assert!(remote_ip.is_ipv4()),
            k => panic!("{k:?}"),
        }
    }

    struct FakeSource {
        polls: u32,
    }

    impl SnapshotSource for FakeSource {
        fn processes(&mut self) -> std::io::Result<Vec<ProcSnap>> {
            self.polls += 1;
            Ok(vec![p(1, 0, 10, "init")])
        }
        fn sockets(&mut self) -> std::io::Result<Vec<SockSnap>> {
            Ok(vec![s(
                1,
                Proto::Tcp,
                "10.0.0.2:50000",
                "198.51.100.1:443",
                SockState::Established,
            )])
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn collector_emits_then_stops_when_receiver_drops() {
        let c = std::sync::Arc::new(PollCollector::new(
            "fake",
            FakeSource { polls: 0 },
            Duration::from_millis(10),
            false,
            PollScope::ALL,
        ));
        let (tx, mut rx) = mpsc::channel(16);
        let runner = {
            let c = c.clone();
            tokio::spawn(async move { c.run(tx).await })
        };
        let first = rx.recv().await.unwrap();
        assert!(matches!(first.kind, EventKind::ProcessStart { .. }));
        let second = rx.recv().await.unwrap();
        assert!(matches!(second.kind, EventKind::NetConnect { .. }));
        drop(rx);
        runner.await.unwrap().unwrap();
        // A collector runs once.
        let (tx, _rx) = mpsc::channel(1);
        assert!(c.run(tx).await.is_err());
    }
}
