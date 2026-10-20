//! Process-level tests of `DecisionSidecar` against a fake protocol-v1
//! sidecar (needs a `python3`/`python` interpreter; skipped otherwise).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use whohack_decide::{DecisionModel, DecisionSidecar, QKind, Question, SidecarConfig};

fn python() -> Option<PathBuf> {
    ["python3", "python"]
        .into_iter()
        .map(PathBuf::from)
        .find(|p| {
            std::process::Command::new(p)
                .arg("--version")
                .output()
                .is_ok_and(|o| o.status.success())
        })
}

fn config(py: PathBuf, idle: Duration) -> SidecarConfig {
    let root = std::env::var_os("WHOHACK_TEST_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")).join("../.."));
    SidecarConfig {
        model_dir: None,
        python: py,
        script: root.join("crates/whohack-decide/tests/fake_sidecar.py"),
        args: vec![],
        model_name: "fake".into(),
        max_state_tokens: 2000,
        pinned: BTreeMap::new(),
        idle_unload: idle,
    }
}

fn questions() -> Vec<Question> {
    vec![
        Question {
            id: "verdict",
            kind: QKind::Choice(vec!["benign", "suspicious", "malicious"]),
            text: "v".into(),
        },
        Question {
            id: "matches_purpose",
            kind: QKind::YesNo,
            text: "m".into(),
        },
    ]
}

#[test]
fn decides_recovers_from_crash_and_unloads_when_idle() {
    let Some(py) = python() else {
        eprintln!("skipping: no python interpreter");
        return;
    };
    let s = DecisionSidecar::new(config(py.clone(), Duration::from_secs(600)));
    assert!(!s.is_loaded(), "lazy start");
    let a = s.decide("APP name=x", &questions()).unwrap();
    assert!(s.is_loaded());
    assert_eq!(a[0].top(), Some(("benign", 0.7)));
    assert_eq!(a[1].prob("yes"), 0.7);

    // The sidecar dies mid-request: an error, then a fresh process next time.
    assert!(s.decide("CRASH", &questions()).is_err());
    assert!(!s.is_loaded());
    assert!(s.decide("APP name=y", &questions()).is_ok());

    // Idle unload.
    let idle = DecisionSidecar::new(config(py, Duration::from_millis(0)));
    idle.decide("APP", &questions()).unwrap();
    idle.reap_idle();
    assert!(!idle.is_loaded());
}

#[test]
fn refuses_to_start_when_pinned_file_mismatches() {
    let Some(py) = python() else {
        return;
    };
    let mut cfg = config(py, Duration::from_secs(600));
    cfg.pinned.insert(cfg.script.clone(), "0".repeat(64));
    let s = DecisionSidecar::new(cfg);
    let err = s.decide("APP", &questions()).unwrap_err();
    assert!(err.to_string().contains("sha256"), "{err}");
    assert!(!s.is_loaded());
}

#[test]
fn cold_load_may_finish_after_case_deadline_without_restart_loop() {
    let Some(py) = python() else {
        return;
    };
    let mut cfg = config(py, Duration::from_secs(600));
    cfg.args.push("--slow-start".into());
    let sidecar = DecisionSidecar::new(cfg);
    let started = std::time::Instant::now();
    assert!(
        sidecar
            .decide("APP", &questions())
            .unwrap_err()
            .to_string()
            .contains("still loading")
    );
    assert!(started.elapsed() < Duration::from_secs(12));
    assert!(sidecar.decide("APP", &questions()).is_ok());
    assert!(sidecar.is_loaded());
}
