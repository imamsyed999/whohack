//! Deterministic monitor detections. Recommended actions are not enforcement.
pub mod download_protection;
pub mod fusion;
pub mod onnx;
pub mod rules;
pub mod trust;
pub mod window;

use rules::{RuleSet, Severity};
use serde::Serialize;
use whohack_core::{Action, AllowEntry, Observation, Verdict, VerdictLabel};
use whohack_tags::{Profile, taxonomy::lookup};

#[derive(Debug, Clone, Serialize)]
pub struct Detection {
    pub rule_ids: Vec<String>,
    pub score: f32,
    pub recommended_action: Action,
    pub verdict: Verdict,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub features: Option<window::Features>,
}

/// Untrained score from SPEC section 10. This is a heuristic, not a probability.
pub fn score(obs: &Observation, profile: &Profile) -> f32 {
    let mut tags = profile.unexpected(&obs.tags);
    tags.sort();
    tags.dedup();
    let severity: u32 = tags
        .iter()
        .filter_map(|t| lookup(t.as_str()))
        .map(|d| u32::from(d.severity))
        .sum();
    let Some(p) = &obs.process else {
        return (severity as f32 / 6.0).min(1.0);
    };
    let file = p.script.as_ref().unwrap_or(&p.exe);
    (severity as f32 / 6.0
        + if p.tainted { 0.2 } else { 0.0 }
        + if matches!(file.sign, whohack_core::SignState::Unsigned) {
            0.2
        } else {
            0.0
        })
    .clamp(0.0, 1.0)
}

pub fn evaluate(
    obs: &Observation,
    profile: &Profile,
    rules: &RuleSet,
    allowlist: &[AllowEntry],
) -> Option<Detection> {
    if allowlist.iter().any(|e| matches!(e, AllowEntry::App { app_id } if obs.process.as_ref().is_some_and(|p| p.app_id == *app_id))) {
        return None;
    }
    let obs = trust::filtered(obs, allowlist);
    let matched: Vec<_> = rules.rules.iter().filter(|r| r.matches(&obs)).collect();
    let mut yara = if matches!(obs.event.kind, whohack_core::EventKind::ProcessStart { .. }) {
        obs.process
            .as_ref()
            .map(|p| p.script.as_ref().unwrap_or(&p.exe).yara_hits.clone())
            .unwrap_or_default()
    } else {
        vec![]
    };
    if let Some(p) = &obs.process {
        for input in &p.downloaded_inputs {
            let relevant = match &obs.event.kind {
                whohack_core::EventKind::ProcessStart { .. } => true,
                whohack_core::EventKind::FileAccess {
                    path, write: false, ..
                } => path == &input.file.path,
                _ => false,
            };
            if relevant {
                yara.extend(input.file.yara_hits.clone());
            }
        }
    }
    yara.sort();
    yara.dedup();
    let never = profile.violates_never(&obs.tags);
    // The untrained heuristic is reported but does not alone generate noisy alerts.
    if matched.is_empty() && never.is_empty() && yara.is_empty() {
        return None;
    }
    let mut ids: Vec<_> = matched.iter().map(|r| r.id.clone()).collect();
    let mut reasons: Vec<_> = matched.iter().map(|r| r.description.clone()).collect();
    let mut action = matched
        .iter()
        .map(|r| r.action_floor)
        .max()
        .unwrap_or(Action::AskUser);
    if !yara.is_empty() {
        ids.push("yara-match".into());
        reasons.push(format!(
            "File scanning matched YARA rules: {}.",
            yara.iter()
                .take(10)
                .map(|s| s
                    .chars()
                    .filter(|c| !c.is_control())
                    .take(80)
                    .collect::<String>())
                .collect::<Vec<_>>()
                .join(", ")
        ));
        action = action.max(Action::BlockNetwork);
    }
    if !never.is_empty() {
        ids.push("profile-never".into());
        reasons.push(format!(
            "Behavior forbidden for category {}: {}.",
            profile.category,
            never
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        ));
        action = action.max(Action::BlockNetwork);
    }
    let critical = matched.iter().any(|r| r.severity == Severity::Critical);
    let name = obs
        .process
        .as_ref()
        .map(|p| {
            p.script
                .as_ref()
                .unwrap_or(&p.exe)
                .path
                .rsplit(['/', '\\'])
                .next()
                .unwrap_or("unknown")
        })
        .unwrap_or("unknown")
        .chars()
        .filter(|c| !c.is_control())
        .take(80)
        .collect::<String>();
    reasons.insert(0, format!("{name} (PID {}):", obs.event.pid));
    if let Some(p) = &obs.process {
        for input in p.downloaded_inputs.iter().take(8) {
            let name: String = input
                .file
                .path
                .rsplit(['/', '\\'])
                .next()
                .unwrap_or("downloaded file")
                .chars()
                .filter(|c| !c.is_control())
                .take(120)
                .collect();
            reasons.push(format!(
                "Downloaded input: {name} ({}).",
                if input.read_observed {
                    "file read observed"
                } else {
                    "listed in launch arguments"
                }
            ));
        }
    }
    reasons.push(format!(
        "Recommended action: {}. Monitor only: no process or network action was taken.",
        action.as_str()
    ));
    Some(Detection {
        features: None,
        rule_ids: ids,
        score: score(&obs, profile),
        recommended_action: action,
        verdict: Verdict {
            label: VerdictLabel::Suspicious,
            p: [0.0; 3],
            tactic: "none".into(),
            severity: if critical { 3.0 } else { 2.0 },
            action: Action::AskUser,
            tier: 0,
            reasons,
        },
    })
}
