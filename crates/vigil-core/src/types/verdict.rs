use serde::{Deserialize, Serialize};

/// Overall classification of an escalated case.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerdictLabel {
    Benign,
    Suspicious,
    Malicious,
}

impl VerdictLabel {
    pub const ALL: [VerdictLabel; 3] = [
        VerdictLabel::Benign,
        VerdictLabel::Suspicious,
        VerdictLabel::Malicious,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            VerdictLabel::Benign => "benign",
            VerdictLabel::Suspicious => "suspicious",
            VerdictLabel::Malicious => "malicious",
        }
    }

    pub fn parse(s: &str) -> Option<VerdictLabel> {
        VerdictLabel::ALL.into_iter().find(|v| v.as_str() == s)
    }
}

/// Response action. Variants are declared in increasing severity, so the
/// derived `Ord` implements the fusion rule "final action = max(rule floor,
/// model action)" (SPEC §10) as plain `max()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Allow,
    AskUser,
    BlockNetwork,
    SuspendAndAsk,
    KillAndQuarantine,
}

impl Action {
    pub const ALL: [Action; 5] = [
        Action::Allow,
        Action::AskUser,
        Action::BlockNetwork,
        Action::SuspendAndAsk,
        Action::KillAndQuarantine,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Action::Allow => "allow",
            Action::AskUser => "ask_user",
            Action::BlockNetwork => "block_network",
            Action::SuspendAndAsk => "suspend_and_ask",
            Action::KillAndQuarantine => "kill_and_quarantine",
        }
    }

    pub fn parse(s: &str) -> Option<Action> {
        Action::ALL.into_iter().find(|a| a.as_str() == s)
    }
}

/// Result of the detection pipeline for one case.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Verdict {
    pub label: VerdictLabel,
    /// Probabilities in `VerdictLabel::ALL` order: `[benign, suspicious, malicious]`.
    pub p: [f32; 3],
    pub tactic: String,
    pub severity: f32,
    pub action: Action,
    /// Highest tier that contributed (0 = rules, 1 = anomaly, 2/3 = decision models).
    pub tier: u8,
    pub reasons: Vec<String>,
}

impl Verdict {
    pub fn p_benign(&self) -> f32 {
        self.p[0]
    }
    pub fn p_suspicious(&self) -> f32 {
        self.p[1]
    }
    pub fn p_malicious(&self) -> f32 {
        self.p[2]
    }
}

/// How aggressively Vigil responds (SPEC §11).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponseMode {
    /// Log and notify only.
    Monitor,
    /// Block network on suspicion; ask the user for anything stronger.
    #[default]
    Prompt,
    /// Apply the strongest fusion-policy action automatically, notify after.
    Auto,
}

impl ResponseMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            ResponseMode::Monitor => "monitor",
            ResponseMode::Prompt => "prompt",
            ResponseMode::Auto => "auto",
        }
    }

    pub fn parse(s: &str) -> Option<ResponseMode> {
        [
            ResponseMode::Monitor,
            ResponseMode::Prompt,
            ResponseMode::Auto,
        ]
        .into_iter()
        .find(|m| m.as_str() == s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn action_order_is_severity_order() {
        let mut sorted = Action::ALL;
        sorted.reverse();
        sorted.sort();
        assert_eq!(sorted, Action::ALL);
        assert_eq!(
            Action::BlockNetwork.max(Action::AskUser),
            Action::BlockNetwork
        );
        assert_eq!(
            Action::KillAndQuarantine.max(Action::Allow),
            Action::KillAndQuarantine
        );
    }

    #[test]
    fn string_forms_match_serde() {
        for a in Action::ALL {
            assert_eq!(
                serde_json::to_string(&a).unwrap(),
                format!("\"{}\"", a.as_str())
            );
            assert_eq!(Action::parse(a.as_str()), Some(a));
        }
        for l in VerdictLabel::ALL {
            assert_eq!(
                serde_json::to_string(&l).unwrap(),
                format!("\"{}\"", l.as_str())
            );
            assert_eq!(VerdictLabel::parse(l.as_str()), Some(l));
        }
        assert_eq!(Action::parse("explode"), None);
    }

    #[test]
    fn default_mode_is_prompt() {
        assert_eq!(ResponseMode::default(), ResponseMode::Prompt);
        for m in [
            ResponseMode::Monitor,
            ResponseMode::Prompt,
            ResponseMode::Auto,
        ] {
            assert_eq!(
                serde_json::to_string(&m).unwrap(),
                format!("\"{}\"", m.as_str())
            );
        }
    }

    #[test]
    fn verdict_round_trip() {
        let v = Verdict {
            label: VerdictLabel::Malicious,
            p: [0.05, 0.1, 0.85],
            tactic: "credential_theft".into(),
            severity: 3.0,
            action: Action::SuspendAndAsk,
            tier: 2,
            reasons: vec!["read browser passwords".into()],
        };
        let s = serde_json::to_string(&v).unwrap();
        let back: Verdict = serde_json::from_str(&s).unwrap();
        assert_eq!(back, v);
        assert_eq!(back.p_malicious(), 0.85);
        assert_eq!(back.p_benign(), 0.05);
        assert_eq!(back.p_suspicious(), 0.1);
    }
}
