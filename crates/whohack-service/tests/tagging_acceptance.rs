//! M3 deterministic acceptance. All paths and process records are inert fixtures.
use std::collections::BTreeSet;

use whohack_core::{
    Event, EventKind, FileInfo, Origin, Os, PathClass, PersistenceKind, ProcessInfo, Proto,
    SensitiveClass, SignState,
};
use whohack_service::replay::{ReplayRecord, analyze};
use whohack_tags::{CategoryTemplate, Profile, Tagger};

fn process(app: &str) -> ProcessInfo {
    ProcessInfo {
        downloaded_inputs: Vec::new(),
        pid: 42,
        ppid: 1,
        start_time: 0,
        exe: FileInfo {
            path: "/home/u/Downloads/demo-reader".into(),
            sha256: [1; 32],
            origin: Origin::Downloaded {
                url: None,
                referrer: None,
            },
            sign: SignState::Unsigned,
            yara_hits: vec![],
            first_seen: 0,
        },
        script: None,
        path_class: PathClass::Downloads,
        tainted: true,
        taint_root: Some(42),
        app_id: app.into(),
    }
}

fn connect(ts: i64, app: &str, ip: &str) -> ReplayRecord {
    ReplayRecord {
        event: Event {
            ts,
            pid: 42,
            kind: EventKind::NetConnect {
                remote_ip: ip.parse().unwrap(),
                remote_port: 45678,
                proto: Proto::Tcp,
                domain: None,
                dns_before: false,
            },
        },
        process: Some(process(app)),
    }
}

#[test]
fn configured_replay_uses_the_same_pinned_onnx_score_in_detection_and_model_state() {
    use sha2::{Digest, Sha256};
    let root = std::env::var_os("WHOHACK_TEST_ROOT")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../.."));
    let model = root.join("ml/fixtures/toy-tier1.onnx");
    let sha = whohack_core::hex::encode(&Sha256::digest(std::fs::read(&model).unwrap()));
    let scorer = whohack_detect::onnx::OnnxScorer::load(&model, &sha).unwrap();
    let profile = Profile::from_template(CategoryTemplate::builtin("pdf_reader").unwrap(), None);
    let mut tagger = Tagger::new(true, Os::Linux, &Default::default());
    let mut windows = whohack_detect::window::Windows::default();
    let result = whohack_service::replay::analyze_configured(
        connect(100, "demo", "192.0.2.1"),
        &mut tagger,
        &profile,
        &mut windows,
        &whohack_detect::rules::RuleSet::builtin(),
        Some(&scorer),
    )
    .unwrap();
    assert_eq!(result.scorer, "onnx");
    assert_eq!(result.score, scorer.score(&result.features).unwrap());
    assert!(
        result
            .state
            .unwrap()
            .contains(&format!("ANOMALY {:.2}", result.score))
    );
    if let Some(d) = result.detection {
        assert_eq!(d.score, result.score);
    }
    assert!((result.score - result.features.heuristic()).abs() > 0.001);
}

#[test]
fn beacon_replay_has_expected_unexpected_tags_without_raw_ip_on_loopback() {
    let mut t = Tagger::new(true, Os::Linux, &Default::default());
    let p = Profile::from_template(CategoryTemplate::builtin("pdf_reader").unwrap(), None);
    let mut observed = BTreeSet::new();
    for kind in [
        EventKind::FileAccess {
            path: "/fixture/Login Data".into(),
            class: SensitiveClass::BrowserPasswords,
            write: false,
        },
        EventKind::Persistence {
            location: PersistenceKind::Autostart,
            target: "/fixture/startup".into(),
        },
    ] {
        let r = analyze(
            ReplayRecord {
                event: Event {
                    ts: 0,
                    pid: 42,
                    kind,
                },
                process: Some(process("demo")),
            },
            &mut t,
            &p,
        )
        .unwrap();
        observed.extend(r.unexpected.into_iter().map(|t| t.to_string()));
    }
    for ts in [0, 60_000, 120_000, 180_000] {
        let r = analyze(connect(ts, "demo", "127.0.0.1"), &mut t, &p).unwrap();
        observed.extend(r.unexpected.into_iter().map(|t| t.to_string()));
    }
    let expected: BTreeSet<_> = [
        "credential_access:browser_passwords",
        "persistence:autostart",
        "network:beaconing",
        "network:first_seen_destination",
        "network:unusual_port",
    ]
    .into_iter()
    .map(str::to_string)
    .collect();
    assert_eq!(observed, expected);
}

#[test]
fn network_history_is_per_app_duplicates_do_not_beacon_and_dns_visibility_is_required() {
    let p = Profile::from_template(CategoryTemplate::builtin("other").unwrap(), None);
    let mut t = Tagger::new(false, Os::Linux, &Default::default());
    let first = |r: &whohack_service::replay::ReplayResult| {
        r.tags
            .iter()
            .any(|t| t.as_str() == "network:first_seen_destination")
    };
    assert!(first(
        &analyze(connect(0, "one", "8.8.8.8"), &mut t, &p).unwrap()
    ));
    assert!(first(
        &analyze(connect(0, "two", "8.8.8.8"), &mut t, &p).unwrap()
    ));
    for _ in 0..5 {
        let r = analyze(connect(0, "one", "8.8.8.8"), &mut t, &p).unwrap();
        assert!(!first(&r));
        assert!(
            !r.tags
                .iter()
                .any(|t| matches!(t.as_str(), "network:beaconing" | "network:raw_ip_no_dns"))
        );
    }
    let mut t = Tagger::new(true, Os::Linux, &Default::default());
    let r = analyze(connect(0, "one", "8.8.8.8"), &mut t, &p).unwrap();
    assert!(r.tags.iter().any(|t| t.as_str() == "network:raw_ip_no_dns"));
}

#[test]
fn tags_and_learning_evidence_survive_database_reopen_without_granting_behavior() {
    use whohack_core::{Observation, Store, store::ProfileRecord};
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("events.db");
    let s = Store::open(&db).unwrap();
    let t = CategoryTemplate::builtin("pdf_reader").unwrap();
    let record = ProfileRecord {
        app_id: "demo".into(),
        category: t.category,
        expected: t.expected.into_iter().map(Into::into).collect(),
        never: t.never,
        learning_until: Some(5000),
        updated_at: 0,
    };
    s.upsert_profile(&record).unwrap();
    let tags = vec![whohack_core::CapabilityTag::from_static(
        "credential_access:browser_passwords",
    )];
    s.observe_profile_tags("demo", &tags, 1).unwrap();
    let obs = Observation {
        event: Event {
            ts: 1,
            pid: 42,
            kind: EventKind::ProcessExit,
        },
        process: None,
        tags: tags.clone(),
    };
    s.insert_observations([&obs]).unwrap();
    drop(s);
    let s = Store::open(&db).unwrap();
    assert_eq!(
        s.recent_tagged_events(1).unwrap(),
        vec![(obs.event, tags.clone())]
    );
    assert_eq!(s.observed_profile_tags("demo").unwrap(), tags);
    assert_eq!(s.profile("demo").unwrap(), Some(record));
}
