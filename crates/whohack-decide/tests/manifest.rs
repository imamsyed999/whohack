//! Qualification tests use fake bytes, never a downloaded or executing model.
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, path::Path};
use whohack_decide::manifest::Manifest;

fn pin(m: &mut Manifest, name: &str, bytes: &[u8]) {
    let path = m.model_dir.join(name);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, bytes).unwrap();
    m.files.insert(
        name.into(),
        whohack_core::hex::encode(&Sha256::digest(bytes)),
    );
}
fn fixture(root: &Path) -> Manifest {
    let root = root.canonicalize().unwrap();
    let script = root.join("sidecar.py");
    std::fs::write(&script, b"# fake, not executed").unwrap();
    let model_dir = root.join("model");
    std::fs::create_dir(&model_dir).unwrap();
    let mut m = Manifest {
        version: 1,
        model_name: "opendecider".into(),
        revision: "test-revision".into(),
        backend: "opendecider".into(),
        python: std::env::current_exe().unwrap(),
        script,
        script_sha256: whohack_core::hex::encode(&Sha256::digest(b"# fake, not executed")),
        model_dir,
        files: BTreeMap::new(),
        dtype: "bfloat16".into(),
        threads: 1,
        max_state_tokens: 768,
        evaluation: None,
        calibration: Some("calibration.json".into()),
        thresholds: Default::default(),
    };
    for name in [
        "config.json",
        "tokenizer.json",
        "model.safetensors",
        "head.safetensors",
        "calibration.json",
    ] {
        pin(&mut m, name, b"{}");
    }
    m
}
fn report(m: &Manifest) -> serde_json::Value {
    serde_json::json!({"schema_version":1,"model_name":m.model_name,"model_revision":m.revision,
        "thresholds":m.thresholds,
        "weights_sha256":m.files["model.safetensors"],"head_sha256":m.files["head.safetensors"],"calibration_sha256":m.files["calibration.json"],
        "family_disjoint":true,"synthetic":false,"device":"cpu","passed":true,"malicious_cases":100,"benign_cases":200,"malicious_families":5,
        "malicious_recall":0.95,"human_review_fraction":0.1,"benign_fpr":0.005,"alerts_per_week":1.0,"cpu_p95_ms":1000.,"rss_mb":700.,
        "benign_replay":{"synthetic":false,"duration_hours":168,"alerts":1,"apps":200,"source":"fake unit test only"}})
}
fn set_report(m: &mut Manifest, v: &serde_json::Value) {
    pin(m, "evaluation.json", &serde_json::to_vec(v).unwrap());
    m.evaluation = Some("evaluation.json".into());
}

#[test]
fn report_claims_do_not_bypass_identity_sample_size_and_measurement_gates() {
    let t = tempfile::tempdir().unwrap();
    let mut m = fixture(t.path());
    m.verify().unwrap();
    assert!(!m.qualified().unwrap());
    let good = report(&m);
    set_report(&mut m, &good);
    assert!(m.qualified().unwrap());
    for (key, bad) in [
        ("malicious_cases", serde_json::json!(99)),
        ("benign_cases", serde_json::json!(199)),
        ("malicious_families", serde_json::json!(4)),
        ("synthetic", serde_json::json!(true)),
        ("device", serde_json::json!("gpu")),
        ("cpu_p95_ms", serde_json::json!(0)),
        ("rss_mb", serde_json::json!(1201)),
        ("model_revision", serde_json::json!("wrong")),
        ("weights_sha256", serde_json::json!("00".repeat(32))),
    ] {
        let mut bad_report = good.clone();
        bad_report[key] = bad;
        set_report(&mut m, &bad_report);
        assert!(m.qualified().is_err(), "accepted invalid {key}");
    }
    let mut mismatch = good.clone();
    mismatch["benign_replay"]["alerts"] = 2.into();
    set_report(&mut m, &mismatch);
    assert!(m.qualified().is_err());
    let mut missing = good.clone();
    missing
        .as_object_mut()
        .unwrap()
        .remove("malicious_families");
    set_report(&mut m, &missing);
    assert!(m.qualified().is_err());
    set_report(&mut m, &good);
    m.thresholds.block_malicious = 0.4;
    assert!(m.qualified().is_err());
    m.thresholds = Default::default();
    std::fs::write(m.model_dir.join("evaluation.json"), b"{}").unwrap();
    assert!(m.qualified().is_err());
}

#[test]
fn layouts_require_local_model_inputs_and_reject_unpinned_or_executable_files() {
    let t = tempfile::tempdir().unwrap();
    let mut m = fixture(t.path());
    m.verify().unwrap();
    std::fs::write(m.model_dir.join("injected.config"), b"{}").unwrap();
    assert!(m.verify().is_err());
    std::fs::remove_file(m.model_dir.join("injected.config")).unwrap();
    m.backend = "laya".into();
    m.dtype = "float32".into();
    assert!(m.verify().is_err());
    for name in [
        "rl_agent_config.json",
        "encoder/config.json",
        "tokenizer/tokenizer.json",
        "tokenizer/tokenizer_config.json",
    ] {
        pin(&mut m, name, b"{}");
    }
    m.verify().unwrap();
    m.dtype = "bfloat16".into();
    assert!(m.verify().is_err());
    m.dtype = "float32".into();
    pin(&mut m, "payload.PY", b"# inert");
    assert!(m.verify().is_err());
}
