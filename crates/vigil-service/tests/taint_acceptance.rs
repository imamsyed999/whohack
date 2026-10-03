//! M2 acceptance (Linux, live): a script marked as downloaded (the
//! `user.xdg.origin.url` xattr browsers set) is run by `/bin/sh` and starts
//! child processes. The interpreter and its children must all be tainted,
//! rooted at the interpreter.
#![cfg(target_os = "linux")]

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use vigil_collect::linux::procfs::ProcfsSource;
use vigil_collect::{Collector, PollCollector, PollScope};
use vigil_core::{EventBus, EventKind, Observation, ProcessInfo};
use vigil_service::pipeline::Pipeline;
use vigil_taint::{FileAnalyzer, ProcessTracker, TaintEngine, origin};

#[tokio::test(flavor = "multi_thread")]
async fn downloaded_script_and_children_are_tainted() {
    let dir = tempfile::tempdir().unwrap();
    let script = dir.path().join("installer.sh");
    std::fs::write(&script, "#!/bin/sh\nsleep 3 &\nsleep 3\nwait\n").unwrap();
    if origin::mark_downloaded(&script, "https://downloads.example.com/installer.sh").is_err()
        || origin::read_marker(&script).is_none()
    {
        eprintln!("skipping: filesystem does not support user xattrs");
        return;
    }

    let bus = EventBus::<Observation>::new(65_536);
    let mut rx = bus.subscribe();
    let collector: Arc<dyn Collector> = Arc::new(PollCollector::new(
        "procfs",
        ProcfsSource::new().unwrap(),
        Duration::from_millis(100),
        false,
        PollScope::ALL,
    ));
    let taint = TaintEngine::new(FileAnalyzer::new(None), ProcessTracker::default());
    let pipeline = Pipeline::start(vec![collector], false, taint, bus.clone());
    // Let the startup snapshot drain: on a busy machine the analysis stage
    // hashes and signature-checks every running executable once.
    let drain_deadline = Instant::now() + Duration::from_secs(180);
    while Instant::now() < drain_deadline {
        match tokio::time::timeout(Duration::from_secs(2), rx.recv()).await {
            Err(_) => break, // quiet for 2 s: backlog processed
            Ok(Err(tokio::sync::broadcast::error::RecvError::Closed)) => break,
            Ok(_) => {}
        }
    }

    let mut child = std::process::Command::new("/bin/sh")
        .arg(&script)
        .spawn()
        .unwrap();
    let sh_pid = child.id();

    let mut seen: HashMap<u32, Arc<ProcessInfo>> = HashMap::new();
    let deadline = Instant::now() + Duration::from_secs(60);
    let done = |seen: &HashMap<u32, Arc<ProcessInfo>>| {
        seen.contains_key(&sh_pid) && seen.values().filter(|p| p.ppid == sh_pid).count() >= 2
    };
    while Instant::now() < deadline && !done(&seen) {
        let Ok(Ok(obs)) = tokio::time::timeout(Duration::from_millis(300), rx.recv()).await else {
            continue;
        };
        if let (EventKind::ProcessStart { .. }, Some(p)) = (&obs.event.kind, &obs.process) {
            seen.insert(p.pid, p.clone());
        }
    }
    let _ = child.kill();
    let _ = child.wait();
    pipeline.shutdown().await;

    let sh = seen.get(&sh_pid).expect("interpreter process observed");
    assert!(
        sh.tainted,
        "interpreter running a downloaded script must be tainted: {sh:?}"
    );
    assert_eq!(sh.taint_root, Some(sh_pid));
    let script_info = sh.script.as_ref().expect("script detected");
    assert!(script_info.origin.is_downloaded());
    assert!(sh.app_id.starts_with("script:"));

    let children: Vec<_> = seen.values().filter(|p| p.ppid == sh_pid).collect();
    assert!(
        children.len() >= 2,
        "expected the two sleep children, saw {}",
        children.len()
    );
    for c in children {
        assert!(
            c.tainted,
            "child {} ({}) must be tainted",
            c.pid, c.exe.path
        );
        assert_eq!(c.taint_root, Some(sh_pid));
    }
    // An unrelated process (this test binary) is not tainted.
    if let Some(me) = seen.get(&std::process::id()) {
        assert!(!me.tainted);
    }
}
