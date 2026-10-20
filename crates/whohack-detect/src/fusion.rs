//! Pure fusion policy; OS effects and user consent belong to the response layer.
use serde::{Deserialize, Serialize};
use whohack_core::{Action, ResponseMode};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Thresholds {
    pub malicious: f32,
    pub corroborating_score: f32,
    pub block_malicious: f32,
    pub block_suspicious: f32,
    pub allow_benign: f32,
    pub escalation: f32,
}
impl Default for Thresholds {
    fn default() -> Self {
        Self {
            malicious: 0.85,
            corroborating_score: 0.8,
            block_malicious: 0.5,
            block_suspicious: 0.6,
            allow_benign: 0.8,
            escalation: 0.6,
        }
    }
}
impl Thresholds {
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            [
                self.malicious,
                self.corroborating_score,
                self.block_malicious,
                self.block_suspicious,
                self.allow_benign,
                self.escalation
            ]
            .iter()
            .all(|x| x.is_finite() && (0.0..=1.0).contains(x)),
            "fusion thresholds must be finite probabilities"
        );
        anyhow::ensure!(
            self.malicious >= self.block_malicious,
            "malicious threshold must be >= block threshold"
        );
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Input {
    pub probabilities: Option<[f32; 3]>,
    pub score: f32,
    pub rule_floor: Action,
    pub rule_fired: bool,
    pub critical: bool,
    pub model_action: Action,
    pub mode: ResponseMode,
}

pub fn fuse(i: Input, t: &Thresholds) -> Action {
    let critical = if i.critical {
        if i.mode == ResponseMode::Auto {
            Action::KillAndQuarantine
        } else {
            Action::BlockNetwork
        }
    } else {
        Action::Allow
    };
    let action = match i.probabilities {
        Some([_, _, m])
            if m >= t.malicious && (i.score >= t.corroborating_score || i.rule_fired) =>
        {
            if i.mode == ResponseMode::Auto {
                Action::KillAndQuarantine
            } else {
                Action::SuspendAndAsk
            }
        }
        Some([_, s, m]) if m >= t.block_malicious || s >= t.block_suspicious => {
            Action::BlockNetwork
        }
        Some([b, _, _]) if b >= t.allow_benign && !i.rule_fired => Action::Allow,
        _ => Action::AskUser,
    };
    let recommended = critical.max(i.rule_floor).max(action).max(i.model_action);
    // Monitor records the recommendation separately and performs no effects.
    if i.mode == ResponseMode::Monitor {
        Action::AskUser
    } else {
        recommended
    }
}

pub fn escalates(
    f: &super::window::Features,
    score: f32,
    rule_fired: bool,
    t: &Thresholds,
) -> bool {
    rule_fired
        || score >= t.escalation
        || (f.tainted && f.new_destinations > 0)
        || f.unexpected
            .iter()
            .filter_map(|t| whohack_tags::taxonomy::lookup(t.as_str()))
            .any(|d| d.severity >= 2)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn input() -> Input {
        Input {
            probabilities: Some([0.9, 0.05, 0.05]),
            score: 0.9,
            rule_floor: Action::Allow,
            rule_fired: false,
            critical: false,
            model_action: Action::Allow,
            mode: ResponseMode::Prompt,
        }
    }
    #[test]
    fn thresholds_and_floors() {
        let t = Thresholds::default();
        let mut i = input();
        assert_eq!(fuse(i, &t), Action::Allow);
        i.probabilities = Some([0.05, 0.1, 0.85]);
        assert_eq!(fuse(i, &t), Action::SuspendAndAsk);
        i.mode = ResponseMode::Auto;
        assert_eq!(fuse(i, &t), Action::KillAndQuarantine);
        i = input();
        i.critical = true;
        assert_eq!(fuse(i, &t), Action::BlockNetwork);
        i.mode = ResponseMode::Auto;
        assert_eq!(fuse(i, &t), Action::KillAndQuarantine);
        i.mode = ResponseMode::Monitor;
        assert_eq!(fuse(i, &t), Action::AskUser);
        for floor in Action::ALL {
            let mut i = input();
            i.rule_floor = floor;
            assert!(fuse(i, &t) >= floor);
        }
    }
    #[test]
    fn uncertainty_and_corroborration() {
        let t = Thresholds::default();
        let mut i = input();
        i.probabilities = None;
        assert_eq!(fuse(i, &t), Action::AskUser);
        i.probabilities = Some([0.1, 0.05, 0.85]);
        i.score = 0.79;
        assert_eq!(fuse(i, &t), Action::BlockNetwork);
        i.rule_fired = true;
        assert_eq!(fuse(i, &t), Action::SuspendAndAsk);
        i = input();
        i.model_action = Action::KillAndQuarantine;
        assert_eq!(fuse(i, &t), Action::KillAndQuarantine);
    }
}
