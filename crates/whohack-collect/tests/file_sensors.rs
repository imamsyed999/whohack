//! Owned-child file acceptance. No credentials, startup entries or injection.
#![cfg(any(windows, target_os = "linux"))]
use std::{
    process::{Child, Command, Stdio},
    sync::Arc,
    time::{Duration, Instant},
};
use whohack_collect::Collector;
use whohack_core::{EventKind, SensitiveClass, config::SensitiveConfig};

#[test]
fn file_helper() {
    let Some(root) = std::env::var_os("WHOHACK_TEST_FILE_ROOT") else {
        return;
    };
    let root = std::path::PathBuf::from(root);
    assert!(
        root.file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("whohack-sensor-test-")
    );
    for n in 0..120 {
        std::fs::write(
            root.join(format!("dummy-{n}.txt")),
            b"harmless metadata sensor test\n",
        )
        .unwrap();
    }
    let _ = std::fs::read(root.join("dummy-0.txt")).unwrap();
    // Keep the actor alive through ETW flush / fanotify delivery.
    std::thread::sleep(Duration::from_secs(6));
}

struct Guard(Child);
impl Drop for Guard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

async fn acceptance() {
    let root = tempfile::Builder::new()
        .prefix("whohack-sensor-test-")
        .tempdir()
        .unwrap();
    let mut sensitive = SensitiveConfig::default();
    sensitive
        .extra_paths
        .insert("documents".into(), vec![root.path().to_path_buf()]);
    let health = Arc::new(whohack_collect::health::Health::default());
    #[cfg(windows)]
    let collector = whohack_collect::windows::etw::EtwCollector::with_sensitive(
        false,
        false,
        &sensitive,
        health.clone(),
    )
    .unwrap();
    #[cfg(target_os = "linux")]
    let collector = whohack_collect::linux::fanotify::Fanotify::new(
        &[root.path().to_path_buf()],
        &sensitive,
        health.clone(),
    )
    .unwrap();
    let (tx, mut rx) = tokio::sync::mpsc::channel(8192);
    let runner = tokio::spawn(async move { collector.run(tx).await });
    tokio::time::sleep(Duration::from_secs(1)).await;
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", "file_helper", "--nocapture"])
        .env("WHOHACK_TEST_FILE_ROOT", root.path())
        .stdout(Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000);
    }
    let child = Guard(command.spawn().unwrap());
    let pid = child.0.id();
    let mut read = false;
    let mut burst = false;
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline && !(read && burst) {
        if let Ok(Some(event)) = tokio::time::timeout(Duration::from_millis(250), rx.recv()).await {
            if event.pid != pid {
                continue;
            }
            match event.kind {
                EventKind::FileAccess {
                    write: false,
                    class: SensitiveClass::Documents,
                    ..
                } => read = true,
                EventKind::FileBurst { modified, .. } if modified >= 100 => burst = true,
                _ => {}
            }
        }
    }
    drop(child);
    drop(rx);
    tokio::time::timeout(Duration::from_secs(5), runner)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(
        read,
        "no sensitive read attributed to owned child; {health:?}"
    );
    assert!(
        burst,
        "no distinct-file burst attributed to owned child; {health:?}"
    );
}

#[cfg(windows)]
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires administrator ETW access; only touches owned temporary files"]
async fn etw_owned_file_access_and_burst() {
    acceptance().await;
}

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires CAP_SYS_ADMIN and fanotify PIDFD support; only touches owned temporary files"]
async fn fanotify_owned_file_access_and_burst() {
    acceptance().await;
}
