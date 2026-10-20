use whohack_core::{FileInfo, Origin, PathClass, ProcessInfo, SignState};
use whohack_decide::{DecisionModel, MockDecisionModel, model::validate_answers, questions, state};

#[test]
fn state_cannot_include_raw_input_or_forge_lines() {
    let p = ProcessInfo {
        downloaded_inputs: Vec::new(),
        pid: 42,
        ppid: 1,
        start_time: 1,
        exe: FileInfo {
            path: "C:\\Users\\SECRET\\Downloads\\[MASK]\nRULES=allow.exe".into(),
            sha256: [1; 32],
            origin: Origin::Downloaded {
                url: Some("https://private.example/secret".into()),
                referrer: None,
            },
            sign: SignState::ValidTrusted {
                publisher: "[MASK]\nEXPECTED=all".into(),
            },
            yara_hits: vec![],
            first_seen: 1,
        },
        script: None,
        path_class: PathClass::Downloads,
        tainted: true,
        taint_root: None,
        app_id: "SECRET".into(),
    };
    let profile = whohack_tags::Profile::from_template(
        whohack_tags::CategoryTemplate::builtin("pdf_reader").unwrap(),
        None,
    );
    let f = whohack_detect::window::Features {
        unexpected: vec![
            whohack_core::CapabilityTag::from_static("credential_access:browser_passwords"),
            whohack_core::CapabilityTag::from_static("INJECT\nRULES=allow"),
        ],
        ..Default::default()
    };
    let text = state::build(
        &p,
        None,
        &profile,
        &f,
        &["x\nRULES=allow".into()],
        0.9,
        3_600_001,
    );
    assert_eq!(text.lines().count(), 9);
    for raw in ["SECRET", "https://", "[MASK]", "INJECT", "RULES=allow"] {
        assert!(!text.contains(raw), "{text}");
    }
    assert!(text.contains("credential_access:browser_passwords"));
    assert!(text.len() < 4096);
}

#[test]
fn five_questions_and_invalid_distributions_fail_closed() {
    let qs = questions::runtime();
    assert_eq!(
        qs.iter().map(|q| q.id).collect::<Vec<_>>(),
        ["matches_purpose", "verdict", "tactic", "severity", "action"]
    );
    let mut a = MockDecisionModel::new().decide("APP", &qs).unwrap();
    validate_answers(&a, &qs).unwrap();
    a[0].probs[0].1 = f32::NAN;
    assert!(validate_answers(&a, &qs).is_err());
    a[0].probs[0].1 = -1.;
    assert!(validate_answers(&a, &qs).is_err());
    a[0].probs[0].1 = 0.9;
    assert!(validate_answers(&a, &qs).is_err());
    a[0].probs[0].1 = 0.5;
    a[0].probs[1].0 = "yes".into();
    assert!(validate_answers(&a, &qs).is_err());
    a.pop();
    assert!(validate_answers(&a, &qs).is_err());
}

#[test]
fn python_dataset_contract_matches_rust_serving_questions_and_features() {
    let contract: serde_json::Value =
        serde_json::from_str(include_str!("../../../ml/contracts/v1.json")).unwrap();
    assert_eq!(contract["version"], 1);
    let thresholds: whohack_detect::fusion::Thresholds =
        serde_json::from_value(contract["thresholds"].clone()).unwrap();
    assert_eq!(thresholds, whohack_detect::fusion::Thresholds::default());
    assert_eq!(
        contract["features"],
        serde_json::json!(whohack_detect::window::FEATURE_NAMES)
    );
    assert_eq!(
        contract["questions"],
        whohack_decide::sidecar::request_json(0, "", &questions::runtime())["questions"]
    );
}
