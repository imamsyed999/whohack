//! Live eBPF test (Linux, feature `ebpf`, root). Run with:
//! `sudo -E cargo test -p vigil-collect --features ebpf --test ebpf_attribution -- --ignored`
#![cfg(all(target_os = "linux", feature = "ebpf"))]

use std::io::Read;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::mpsc;
use vigil_collect::Collector;
use vigil_collect::linux::ebpf::EbpfCollector;
use vigil_core::EventKind;

const CHILD_ENV: &str = "VIGIL_EBPF_CONNECT_TO";

#[test]
fn child_helper() {
    if let Ok(addr) = std::env::var(CHILD_ENV) {
        let addr: SocketAddr = addr.parse().unwrap();
        let _s = TcpStream::connect(addr).unwrap();
        std::thread::sleep(Duration::from_millis(300));
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires root and the ebpf feature"]
async fn ebpf_attributes_short_lived_child_connection() {
    let collector = Arc::new(EbpfCollector::new(true).expect("load eBPF (are you root?)"));
    let (tx, mut rx) = mpsc::channel(65_536);
    let runner = {
        let c = collector.clone();
        tokio::spawn(async move { c.run(tx).await })
    };
    // Let the startup snapshot drain.
    tokio::time::sleep(Duration::from_millis(300)).await;

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        if let Ok((mut s, _)) = listener.accept() {
            let mut b = [0u8; 8];
            let _ = s.read(&mut b);
        }
    });
    // A short-lived child: polling could miss it, eBPF must not.
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "child_helper", "--nocapture", "--test-threads=1"])
        .env(CHILD_ENV, addr.to_string())
        .spawn()
        .unwrap();
    let child_pid = child.id();
    child.wait().unwrap();

    let deadline = Instant::now() + Duration::from_secs(10);
    let (mut saw_exec, mut saw_exit, mut connect_pid) = (false, false, None);
    let mut counts = std::collections::BTreeMap::<&'static str, usize>::new();
    let mut child_events = Vec::new();
    while Instant::now() < deadline && !(saw_exec && saw_exit && connect_pid.is_some()) {
        let Ok(Some(ev)) = tokio::time::timeout(Duration::from_millis(500), rx.recv()).await else {
            continue;
        };
        *counts.entry(ev.kind.name()).or_default() += 1;
        if ev.pid == child_pid {
            child_events.push(format!("{:?}", ev.kind));
        }
        match &ev.kind {
            EventKind::ProcessStart { .. } if ev.pid == child_pid => saw_exec = true,
            EventKind::ProcessExit if ev.pid == child_pid => saw_exit = true,
            EventKind::NetConnect { remote_port, .. } if *remote_port == addr.port() => {
                connect_pid = Some(ev.pid)
            }
            _ => {}
        }
    }
    drop(rx);
    let _ = runner.await;
    eprintln!(
        "event counts: {counts:?}
child events: {child_events:#?}"
    );
    assert!(saw_exec, "exec of child {child_pid} not seen");
    assert!(saw_exit, "exit of child {child_pid} not seen");
    assert_eq!(connect_pid, Some(child_pid));
}
