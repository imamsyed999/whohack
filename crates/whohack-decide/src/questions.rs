//! The ordered, versioned runtime contract shared by serving and dataset export.
use crate::{QKind, Question};

pub fn runtime() -> Vec<Question> {
    vec![
        Question { id: "matches_purpose", kind: QKind::YesNo, text: "Is this behavior consistent with what an application of this category normally does?".into() },
        Question { id: "verdict", kind: QKind::Choice(vec!["benign", "suspicious", "malicious"]), text: "Overall, is this activity benign, suspicious, or malicious?".into() },
        Question { id: "tactic", kind: QKind::Choice(vec!["none", "credential_theft", "persistence", "command_and_control", "ransomware", "data_exfiltration", "reconnaissance"]), text: "Which attacker goal does this activity most resemble?".into() },
        Question { id: "severity", kind: QKind::Score { min: 0, max: 3 }, text: "How severe would the impact be if this is malicious? 0 none, 1 low, 2 high, 3 critical.".into() },
        Question { id: "action", kind: QKind::Choice(vec!["allow", "ask_user", "block_network", "kill_and_quarantine"]), text: "What should a careful security analyst do right now?".into() },
    ]
}
