//! End-to-end tests of the built `whohack-service` binary.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use whohack_core::Config;

fn bin() -> Command {
    let executable = std::env::var_os("WHOHACK_TEST_SERVICE")
        .unwrap_or_else(|| env!("CARGO_BIN_EXE_whohack-service").into());
    let mut c = Command::new(executable);
    c.env_remove("RUST_LOG");
    c
}

fn run(args: &[&str]) -> Output {
    bin()
        .args(args)
        .output()
        .expect("failed to spawn whohack-service")
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

/// Writes a config whose data/log/rules dirs live inside `dir`. `extra` goes
/// first so top-level keys are not swallowed by the `[paths]` table.
fn write_config(dir: &Path, extra: &str) -> PathBuf {
    let path = dir.join("config.toml");
    let body = format!(
        "{extra}\n[paths]\ndata_dir = \"data\"\nlog_dir = \"logs\"\nrules_dir = \"rules\"\n"
    );
    std::fs::write(&path, body).unwrap();
    path
}

#[test]
fn print_default_config_parses_back() {
    let o = run(&["--print-default-config"]);
    assert!(o.status.success(), "{}", stderr(&o));
    let cfg = Config::from_toml_str(&stdout(&o), Path::new(".")).unwrap();
    assert_eq!(cfg, Config::default_for_os());
}

#[test]
fn check_config_accepts_valid_file() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = write_config(dir.path(), "mode = \"monitor\"\n");
    let o = run(&["--config", cfg.to_str().unwrap(), "--check-config"]);
    assert!(o.status.success(), "{}", stderr(&o));
    let out = stdout(&o);
    assert!(out.contains("config ok"), "{out}");
    assert!(out.contains("mode=monitor"), "{out}");
}

#[test]
fn check_config_rejects_bad_syntax_and_unknown_keys() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = write_config(dir.path(), "mode = \n");
    let o = run(&["--config", cfg.to_str().unwrap(), "--check-config"]);
    assert!(!o.status.success());
    assert!(stderr(&o).contains("error:"), "{}", stderr(&o));

    let cfg = write_config(dir.path(), "[storage]\nretention = 3\n");
    let o = run(&["--config", cfg.to_str().unwrap(), "--check-config"]);
    assert!(!o.status.success());
    assert!(stderr(&o).contains("retention"), "{}", stderr(&o));
}

#[test]
fn check_config_rejects_bad_log_filter() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = write_config(
        dir.path(),
        "[logging]\nlevel = \"info,whohack_core=loud\"\n",
    );
    let o = run(&["--config", cfg.to_str().unwrap(), "--check-config"]);
    assert!(!o.status.success());
    assert!(stderr(&o).contains("logging.level"), "{}", stderr(&o));
}

#[test]
fn check_config_reports_missing_file() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("nope.toml");
    let o = run(&["--config", missing.to_str().unwrap(), "--check-config"]);
    assert!(!o.status.success());
    assert!(stderr(&o).contains("nope.toml"), "{}", stderr(&o));
}

#[test]
fn init_db_creates_wal_database_with_all_tables_and_log_file() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = write_config(dir.path(), "");
    let o = run(&["--config", cfg.to_str().unwrap(), "--init-db"]);
    assert!(o.status.success(), "{}", stderr(&o));
    let out = stdout(&o);
    assert!(out.contains("journal_mode=wal"), "{out}");
    assert!(
        out.contains(&format!(
            "schema_version={}",
            whohack_core::store::SCHEMA_VERSION
        )),
        "{out}"
    );
    for t in [
        "alerts",
        "allowlist",
        "connections",
        "decisions",
        "dns",
        "events",
        "feedback",
        "files",
        "processes",
        "profiles",
    ] {
        assert!(out.contains(t), "missing table {t}: {out}");
    }
    assert!(dir.path().join("data").join("vigil.db").exists());

    let logs: Vec<_> = std::fs::read_dir(dir.path().join("logs"))
        .unwrap()
        .filter_map(Result::ok)
        .collect();
    assert_eq!(logs.len(), 1, "expected one rolling log file");
    let text = std::fs::read_to_string(logs[0].path()).unwrap();
    assert!(text.contains("database ready"), "{text}");

    // Running again is idempotent.
    let o = run(&["--config", cfg.to_str().unwrap(), "--init-db"]);
    assert!(o.status.success(), "{}", stderr(&o));
}

#[test]
fn requires_an_action() {
    let o = run(&[]);
    assert!(!o.status.success());
}

#[test]
fn monitor_prints_this_process_connection() {
    use std::io::Read as _;
    let dir = tempfile::tempdir().unwrap();
    let cfg = write_config(
        dir.path(),
        "[collect]\nbackend = \"poll\"\npoll_interval_ms = 100\ninclude_loopback = true\ndns = false\n",
    );
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        if let Ok((mut s, _)) = listener.accept() {
            let mut b = [0u8; 8];
            let _ = s.read(&mut b);
        }
    });
    let child = bin()
        .args([
            "--config",
            cfg.to_str().unwrap(),
            "--monitor",
            "--duration-secs",
            "3",
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    // Connect from this test process while the monitor runs.
    std::thread::sleep(std::time::Duration::from_millis(700));
    let _conn = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
    let o = child.wait_with_output().unwrap();
    assert!(o.status.success(), "{}", stderr(&o));
    let out = stdout(&o);
    let me = format!("pid={}", std::process::id());
    let target = format!("127.0.0.1:{port}/tcp");
    assert!(
        out.lines().any(|l| l.contains(&me) && l.contains(&target)),
        "expected a line with {me} and {target}:\n{out}\nstderr:\n{}",
        stderr(&o)
    );
    assert!(
        dir.path().join("data").join("vigil.db").exists(),
        "events persisted"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn run_mode_serves_authenticated_ipc() {
    use whohack_ipc::{Client, Request, Response};
    let dir = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    let endpoint = dir
        .path()
        .join("whohack.sock")
        .to_string_lossy()
        .into_owned();
    #[cfg(windows)]
    let endpoint = format!(
        r"\\.\pipe\whohack-test-{}-{}",
        std::process::id(),
        dir.path().file_name().unwrap().to_string_lossy()
    );
    let cfg = write_config(
        dir.path(),
        "[collect]\nbackend = \"poll\"\ndns = false\npoll_interval_ms = 100\n",
    );
    let mut config = Config::load(&cfg).unwrap();
    config.ipc.endpoint.clone_from(&endpoint);
    std::fs::write(&cfg, config.to_toml_string().unwrap()).unwrap();
    let marker = dir.path().join("session");
    std::fs::write(&marker, "a".repeat(32)).unwrap();
    // Keep failure paths from leaving a test service running.
    struct ChildGuard(std::process::Child);
    impl Drop for ChildGuard {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let mut child = ChildGuard(
        bin()
            .args([
                "--config",
                cfg.to_str().unwrap(),
                "--run",
                "--session-file",
                marker.to_str().unwrap(),
            ])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap(),
    );
    let token_file = dir.path().join("data").join("ipc.token");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let stream = loop {
        if token_file.exists()
            && let Ok(s) = whohack_ipc::transport::connect(&endpoint).await
        {
            break s;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "service did not start"
        );
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    };
    let token = whohack_ipc::auth::read_token_file(&token_file).unwrap();
    let mut c = Client::connect(stream, &token).await.unwrap();
    match c.request(Request::Status).await.unwrap() {
        Response::Status { status } => {
            assert_eq!(status.mode, whohack_core::ResponseMode::Monitor);
            assert!(!status.enforcement_available);
            assert!(!status.file_visibility);
            assert!(!status.collectors.is_empty());
            #[cfg(windows)]
            assert_eq!(status.collectors, ["windows-poll"]);
        }
        r => panic!("{r:?}"),
    }
    assert_eq!(
        c.request(Request::SetMode {
            mode: whohack_core::ResponseMode::Monitor
        })
        .await
        .unwrap(),
        Response::Ok
    );
    let duplicate = bin()
        .args(["--config", cfg.to_str().unwrap(), "--run"])
        .output()
        .unwrap();
    assert!(!duplicate.status.success());
    assert!(stderr(&duplicate).contains("another instance may be running"));
    assert_eq!(
        whohack_ipc::auth::read_token_file(&token_file).unwrap(),
        token
    );
    assert!(matches!(
        c.request(Request::Status).await.unwrap(),
        Response::Status { .. }
    ));
    assert!(matches!(
        c.request(Request::SetMode {
            mode: whohack_core::ResponseMode::Auto
        })
        .await
        .unwrap(),
        Response::Error { .. }
    ));
    assert!(
        matches!(c.request(Request::ListProfiles { limit: 10 }).await.unwrap(), Response::Profiles { categories, .. } if categories.len() == 19)
    );
    // A wrong token is refused.
    let s2 = whohack_ipc::transport::connect(&endpoint).await.unwrap();
    assert!(Client::connect(s2, "wrong").await.is_err());
    // The launcher-owned session ends gracefully and saves accepted events.
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    std::fs::remove_file(marker).unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            assert!(
                status.success(),
                "service failed to stop gracefully: {status}"
            );
            break;
        }
        assert!(std::time::Instant::now() < deadline, "shutdown timed out");
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    let store = whohack_core::Store::open(&config.db_path()).unwrap();
    assert!(!store.recent_events(10).unwrap().is_empty());
}

#[test]
fn local_setup_and_invalid_replay_fail_with_useful_errors() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("local.toml");
    let output = bin()
        .args(["--config", config.to_str().unwrap(), "--init-local"])
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", stderr(&output));
    let cfg = Config::load(&config).unwrap();
    assert_eq!(cfg.mode, whohack_core::ResponseMode::Monitor);
    #[cfg(unix)]
    assert!(cfg.ipc.endpoint.contains("/.local/state/whohack/"));
    let original = std::fs::read(&config).unwrap();
    assert!(
        !run(&["--config", config.to_str().unwrap(), "--init-local"])
            .status
            .success()
    );
    assert_eq!(std::fs::read(&config).unwrap(), original);
    let bad = dir.path().join("bad.jsonl");
    std::fs::write(&bad, "this is not a fixture").unwrap();
    let output = run(&["--replay", bad.to_str().unwrap()]);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("replay line 1"));
}

#[test]
fn write_manifest_covers_rules_and_config() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = write_config(dir.path(), "");
    let rules = dir.path().join("rules").join("yara");
    std::fs::create_dir_all(&rules).unwrap();
    std::fs::write(rules.join("t.yar"), "rule t { condition: false }").unwrap();
    let o = run(&["--config", cfg.to_str().unwrap(), "--write-manifest"]);
    assert!(o.status.success(), "{}", stderr(&o));
    assert!(stdout(&o).contains("manifest written"));
    let manifest =
        std::fs::read_to_string(dir.path().join("rules").join("MANIFEST.sha256")).unwrap();
    assert!(manifest.contains("yara/t.yar"), "{manifest}");
    assert!(manifest.contains("config.toml"), "{manifest}");
}
