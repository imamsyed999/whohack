use std::sync::Arc;
use whohack_core::{
    Action, AllowEntry, CapabilityTag, Event, EventKind, FileInfo, Observation, Origin, PathClass,
    ProcessInfo, SignState,
};
use whohack_detect::{evaluate, rules::RuleSet, score};
use whohack_tags::{CategoryTemplate, Profile};

fn obs(tags: &[&str]) -> Observation {
    Observation {
        event: Event {
            ts: 0,
            pid: 42,
            kind: EventKind::Injection { target_pid: 43 },
        },
        process: Some(Arc::new(ProcessInfo {
            downloaded_inputs: Vec::new(),
            pid: 42,
            ppid: 1,
            start_time: 0,
            exe: FileInfo {
                path: "/Downloads/app".into(),
                sha256: [1; 32],
                origin: Origin::Unknown,
                sign: SignState::Unsigned,
                yara_hits: vec![],
                first_seen: 0,
            },
            script: None,
            path_class: PathClass::Downloads,
            tainted: true,
            taint_root: Some(42),
            app_id: "demo".into(),
        })),
        tags: tags
            .iter()
            .map(|s| CapabilityTag::from((*s).to_string()))
            .collect(),
    }
}
fn profile(category: &str) -> Profile {
    Profile::from_template(CategoryTemplate::builtin(category).unwrap(), None)
}

#[test]
fn downloaded_media_is_not_danger_by_itself_and_content_matches_preserve_viewer_identity() {
    use whohack_core::DownloadedInput;
    let mut o = obs(&[]);
    o.event.kind = EventKind::ProcessStart {
        ppid: 1,
        exe: "player".into(),
        cmdline: None,
    };
    let p = Arc::make_mut(o.process.as_mut().unwrap());
    p.exe.origin = Origin::Installed;
    p.exe.sign = SignState::ValidTrusted {
        publisher: "Player vendor".into(),
    };
    p.downloaded_inputs.push(DownloadedInput {
        file: FileInfo {
            path: "C:/Users/test/Downloads/movie.mp4".into(),
            sha256: [9; 32],
            origin: Origin::Downloaded {
                url: None,
                referrer: None,
            },
            sign: SignState::Unsigned,
            yara_hits: vec![],
            first_seen: 1,
        },
        observed_at: 1,
        read_observed: false,
    });
    let rules = RuleSet::builtin();
    assert!(evaluate(&o, &profile("other"), &rules, &[]).is_none());
    Arc::make_mut(o.process.as_mut().unwrap()).downloaded_inputs[0]
        .file
        .yara_hits
        .push("owned_signature".into());
    let d = evaluate(&o, &profile("other"), &rules, &[]).unwrap();
    assert!(d.verdict.reasons.iter().any(|r| r.contains("movie.mp4")));
    assert!(whohack_detect::download_protection::should_pause(&o, &d));
    assert!(
        evaluate(
            &o,
            &profile("other"),
            &rules,
            &[AllowEntry::App {
                app_id: "demo".into()
            }]
        )
        .is_none()
    );
    // Ordinary outbound traffic is not promoted to automatic danger.
    o.event.kind = EventKind::NetConnect {
        remote_ip: "93.184.216.34".parse().unwrap(),
        remote_port: 443,
        proto: whohack_core::Proto::Tcp,
        domain: Some("example.com".into()),
        dns_before: true,
    };
    assert!(evaluate(&o, &profile("other"), &rules, &[]).is_none());
    o.tags.push(CapabilityTag::from_static("network:intel_hit"));
    let d = evaluate(&o, &profile("other"), &rules, &[]).unwrap();
    assert!(whohack_detect::download_protection::should_pause(&o, &d));
    Arc::make_mut(o.process.as_mut().unwrap()).tainted = false;
    assert!(!whohack_detect::download_protection::should_pause(&o, &d));
}

#[test]
fn all_required_critical_rules_fire_and_report_recommendations_without_claiming_enforcement() {
    let r = RuleSet::builtin();
    for tag in [
        "credential_access:browser_passwords",
        "defense_evasion:shadow_copy_delete",
        "impact:mass_file_modification",
        "network:intel_hit",
        "credential_access:lsass",
        "injection:remote_thread",
    ] {
        let d = evaluate(&obs(&[tag]), &profile("other"), &r, &[]).unwrap();
        assert!(d.recommended_action >= Action::BlockNetwork, "{tag}");
        assert_eq!(d.verdict.action, Action::AskUser);
        assert_eq!(d.verdict.p, [0.0; 3]);
        assert_eq!(d.verdict.severity, 3.0);
    }
}

#[test]
fn rule_conditions_and_profile_never_are_not_blanket_rules() {
    let r = RuleSet::builtin();
    let mut churn = obs(&["impact:mass_file_modification"]);
    Arc::make_mut(churn.process.as_mut().unwrap()).tainted = false;
    assert!(evaluate(&churn, &profile("other"), &r, &[]).is_none());
    let mut o = obs(&["credential_access:browser_passwords"]);
    let p = Arc::make_mut(o.process.as_mut().unwrap());
    p.tainted = false;
    p.exe.sign = SignState::ValidTrusted {
        publisher: "Vendor".into(),
    };
    assert!(evaluate(&o, &profile("browser"), &r, &[]).is_none());
    let d = evaluate(&o, &profile("pdf_reader"), &r, &[]).unwrap();
    assert_eq!(d.rule_ids, ["profile-never"]);
    let mut o = obs(&["credential_access:lsass"]);
    Arc::make_mut(o.process.as_mut().unwrap()).path_class = PathClass::System;
    assert!(evaluate(&o, &profile("other"), &r, &[]).is_none());
    let mut o = obs(&["injection:remote_thread"]);
    o.process = None;
    assert!(evaluate(&o, &profile("other"), &r, &[]).is_none());
}

#[test]
fn explicit_trust_is_scoped_and_untrained_score_is_not_an_alert_alone() {
    let r = RuleSet::builtin();
    let o = obs(&["injection:remote_thread"]);
    assert!(
        evaluate(
            &o,
            &profile("other"),
            &r,
            &[AllowEntry::App {
                app_id: "demo".into()
            }]
        )
        .is_none()
    );
    assert!(
        evaluate(
            &o,
            &profile("other"),
            &r,
            &[AllowEntry::Behavior {
                app_id: "demo".into(),
                tag: "injection:remote_thread".into()
            }]
        )
        .is_none()
    );
    assert!(
        evaluate(
            &o,
            &profile("other"),
            &r,
            &[AllowEntry::Destination {
                value: "0.0.0.0/0".into()
            }]
        )
        .is_some()
    );
    let o = obs(&["exec:script_interpreter", "network:unusual_port"]);
    assert!(score(&o, &profile("other")) >= 0.8);
    assert!(evaluate(&o, &profile("other"), &r, &[]).is_none());
}

#[test]
fn yara_matches_without_capability_tags_and_app_trust_applies() {
    let mut o = obs(&[]);
    o.event.kind = EventKind::ProcessStart {
        ppid: 1,
        exe: "demo".into(),
        cmdline: None,
    };
    Arc::make_mut(o.process.as_mut().unwrap())
        .exe
        .yara_hits
        .push("eicar".into());
    assert_eq!(
        evaluate(&o, &profile("other"), &RuleSet::builtin(), &[])
            .unwrap()
            .rule_ids,
        ["yara-match"]
    );
    assert!(
        evaluate(
            &o,
            &profile("other"),
            &RuleSet::builtin(),
            &[AllowEntry::App {
                app_id: "demo".into()
            }]
        )
        .is_none()
    );
}

#[test]
fn malformed_unknown_and_weak_critical_rules_are_rejected() {
    for yaml in [
        "[{}]",
        "- id: a\n  description: test\n  severity: critical\n  action_floor: allow\n  match:\n    tags: ['injection:*']",
        "- id: a\n  description: test\n  severity: high\n  action_floor: block_network\n  match:\n    tags: ['unknown:*']",
    ] {
        assert!(RuleSet::from_yaml(yaml).is_err());
    }
    let dir = tempfile::tempdir().unwrap();
    assert_eq!(RuleSet::load(dir.path()).unwrap().rules.len(), 7);
    std::fs::write(dir.path().join("bad.yaml"), "- id: bad").unwrap();
    assert!(RuleSet::load(dir.path()).is_err());
}
