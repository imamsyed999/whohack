//! M1 acceptance: a child process's TCP connection is attributed to the
//! child's PID by the platform polling collector (unprivileged).
//!
//! The child is this test binary re-executed with `VIGIL_CONNECT_TO` set, so
//! the test needs no external tools and works on every OS.

use std::io::Read;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::mpsc;
use vigil_collect::{Collector, PollCollector, PollScope};
use vigil_core::EventKind;

const CHILD_ENV: &str = "VIGIL_CONNECT_TO";

/// Child mode: connect, hold the connection open, then exit.
#[test]
fn child_helper() {
    if let Ok(addr) = std::env::var(CHILD_ENV) {
        let addr: SocketAddr = addr.parse().unwrap();
        let _s = TcpStream::connect(addr).unwrap();
        std::thread::sleep(Duration::from_secs(4));
    }
}

#[cfg(target_os = "linux")]
fn source() -> vigil_collect::linux::procfs::ProcfsSource {
    vigil_collect::linux::procfs::ProcfsSource::new().unwrap()
}

#[cfg(windows)]
fn source() -> vigil_collect::windows::poll::WinSource {
    vigil_collect::windows::poll::WinSource::new()
}

#[cfg(target_os = "macos")]
fn source() -> vigil_collect::macos::libproc::MacSource {
    vigil_collect::macos::libproc::MacSource::new()
}

#[tokio::test(flavor = "multi_thread")]
async fn child_connection_is_attributed_to_child_pid() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    // Accept and drain so the child's connect completes.
    std::thread::spawn(move || {
        if let Ok((mut s, _)) = listener.accept() {
            let mut buf = [0u8; 16];
            let _ = s.read(&mut buf);
        }
    });

    let collector = Arc::new(PollCollector::new(
        "test-poll",
        source(),
        Duration::from_millis(100),
        true, // loopback included for the test
        PollScope::ALL,
    ));
    let (tx, mut rx) = mpsc::channel(4096);
    let runner = {
        let c = collector.clone();
        tokio::spawn(async move { c.run(tx).await })
    };

    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "child_helper", "--nocapture", "--test-threads=1"])
        .env(CHILD_ENV, addr.to_string())
        .spawn()
        .unwrap();
    let child_pid = child.id();

    let deadline = Instant::now() + Duration::from_secs(10);
    let mut saw_start = false;
    let mut connect_pid = None;
    while Instant::now() < deadline && (connect_pid.is_none() || !saw_start) {
        let Ok(Some(ev)) = tokio::time::timeout(Duration::from_millis(500), rx.recv()).await else {
            continue;
        };
        match &ev.kind {
            EventKind::ProcessStart { .. } if ev.pid == child_pid => saw_start = true,
            EventKind::NetConnect {
                remote_ip,
                remote_port,
                ..
            } if *remote_port == addr.port() && remote_ip.is_loopback() => {
                connect_pid = Some(ev.pid)
            }
            _ => {}
        }
    }
    let _ = child.kill();
    let _ = child.wait();
    drop(rx);
    let _ = runner.await;

    assert!(saw_start, "no ProcessStart for child pid {child_pid}");
    assert_eq!(
        connect_pid,
        Some(child_pid),
        "connection to {addr} must be attributed to the child"
    );
}
