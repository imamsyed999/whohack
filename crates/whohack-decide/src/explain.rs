//! Deterministic statements about recorded evidence and actual actions.
use whohack_core::{Action, ProcessInfo};
use whohack_detect::window::Features;

pub fn evidence(p: &ProcessInfo, f: &Features, category: &str) -> String {
    let file = p.script.as_ref().unwrap_or(&p.exe);
    let descriptions: Vec<_> = f
        .unexpected
        .iter()
        .filter_map(|t| whohack_tags::taxonomy::lookup(t.as_str()))
        .map(|d| d.description)
        .collect();
    format!(
        "{} ({}, {}) showed behavior outside the {} profile: {}.",
        crate::state::basename(&file.path),
        file.sign.as_str(),
        file.origin.as_str(),
        crate::state::sanitize(category),
        if descriptions.is_empty() {
            "an unusual combination of recent events".into()
        } else {
            descriptions.join(", ")
        }
    )
}

pub fn action(action: Action) -> &'static str {
    match action {
        Action::Allow => "The temporary response was released; no trust rule was added.",
        Action::AskUser => {
            "Review is required. Any existing response remains visible in Responses."
        }
        Action::BlockNetwork => "A network block is active; review or release it in Responses.",
        Action::SuspendAndAsk => "The process is suspended pending your review.",
        Action::KillAndQuarantine => "The process was terminated and its file quarantined.",
    }
}
