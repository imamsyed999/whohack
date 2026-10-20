//! Install-time profile proposals. Model suggestions never grant high-risk behavior
//! and never override a category's forbidden behavior.
use anyhow::{Result, ensure};
use whohack_core::{CapabilityTag, ProcessInfo, SignState};
use whohack_tags::profile::{CATEGORIES, CategoryTemplate, Profile, matches};
use whohack_tags::taxonomy::TAGS;

use crate::model::{DecisionModel, QKind, Question, answer};
use crate::state::{basename, sanitize};

#[derive(Debug)]
pub struct ProfileProposal {
    pub profile: Profile,
    pub proposed: Vec<CapabilityTag>,
}

pub fn build(
    model: &dyn DecisionModel,
    process: &ProcessInfo,
    now: i64,
) -> Result<ProfileProposal> {
    let file = process.script.as_ref().unwrap_or(&process.exe);
    let publisher = match &file.sign {
        SignState::ValidTrusted { publisher } => sanitize(publisher),
        _ => "none".into(),
    };
    let state = format!(
        "APP name={} signed={} publisher={} origin={} path={}",
        basename(&file.path),
        file.sign.as_str(),
        publisher,
        file.origin.as_str(),
        process.path_class.as_str()
    );
    // ASCII bytes are a conservative upper bound on tokens for supported tokenizers.
    ensure!(
        state.len() <= model.max_state_tokens(),
        "model budget too small for profile state"
    );
    let answers = model.decide(
        &state,
        &[Question {
            id: "category",
            kind: QKind::Choice(CATEGORIES.to_vec()),
            text: "Which application category best matches this app?".into(),
        }],
    )?;
    let category = answer(&answers, "category")
        .and_then(|a| a.top())
        .filter(|(c, p)| CATEGORIES.contains(c) && p.is_finite() && (0.5..=1.0).contains(p))
        .map_or("other", |(c, _)| c);
    let learning_until = if !process.tainted && matches!(file.sign, SignState::ValidTrusted { .. })
    {
        Some(now.saturating_add(72 * 60 * 60 * 1000))
    } else {
        None
    };
    let mut profile = Profile::from_template(CategoryTemplate::builtin(category)?, learning_until);
    let questions: Vec<_> = TAGS
        .iter()
        .filter(|d| d.severity >= 1 && !profile.expected.iter().any(|p| matches(p.as_str(), d.tag)))
        .map(|d| Question {
            id: d.tag,
            kind: QKind::YesNo,
            text: format!(
                "Would a typical {category} application legitimately need to: {}?",
                d.description
            ),
        })
        .collect();
    let mut proposed = Vec::new();
    for batch in questions.chunks(8) {
        let answers = model.decide(&state, batch)?;
        for q in batch {
            let yes = answer(&answers, q.id).map_or(0.0, |a| a.prob("yes"));
            if !yes.is_finite() || !(0.8..=1.0).contains(&yes) {
                continue;
            }
            let def = whohack_tags::taxonomy::lookup(q.id).expect("questions use taxonomy");
            let tag = CapabilityTag::from_static(q.id);
            if def.severity <= 1 && !profile.never.iter().any(|p| matches(p, q.id)) {
                profile.expected.push(tag);
            } else {
                proposed.push(tag);
            }
        }
    }
    Ok(ProfileProposal { profile, proposed })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock::MockDecisionModel;
    use whohack_core::{FileInfo, Origin, PathClass};
    #[test]
    fn category_learning_and_high_severity_proposals() {
        let mut p = ProcessInfo {
            downloaded_inputs: Vec::new(),
            pid: 42,
            ppid: 1,
            start_time: 0,
            exe: FileInfo {
                path: "/Downloads/reader.exe".into(),
                sha256: [1; 32],
                origin: Origin::Unknown,
                sign: SignState::ValidTrusted {
                    publisher: "Vendor".into(),
                },
                yara_hits: vec![],
                first_seen: 0,
            },
            script: None,
            path_class: PathClass::UserApp,
            tainted: false,
            taint_root: None,
            app_id: "test".into(),
        };
        let m = MockDecisionModel::new()
            .answer("category", &[("pdf_reader", 1.0)])
            .answer("network:first_seen_destination", &[("yes", 1.0)])
            .answer("credential_access:browser_passwords", &[("yes", 1.0)]);
        let result = build(&m, &p, 100).unwrap();
        assert_eq!(result.profile.category, "pdf_reader");
        assert_eq!(
            result.profile.learning_until,
            Some(100 + 72 * 60 * 60 * 1000)
        );
        let bad = CapabilityTag::from_static("credential_access:browser_passwords");
        assert_eq!(result.proposed, vec![bad.clone()]);
        assert!(!result.profile.expected.contains(&bad));
        p.tainted = true;
        assert_eq!(build(&m, &p, 100).unwrap().profile.learning_until, None);
        p.tainted = false;
        p.exe.sign = SignState::Unsigned;
        assert_eq!(build(&m, &p, 100).unwrap().profile.learning_until, None);
        assert_eq!(
            build(&MockDecisionModel::new(), &p, 100)
                .unwrap()
                .profile
                .category,
            "other"
        );
    }
}
