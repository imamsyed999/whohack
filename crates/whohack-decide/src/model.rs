//! The typed-decision interface (SPEC §12.2).

/// A typed question asked about a state.
#[derive(Debug, Clone, PartialEq)]
pub struct Question {
    pub id: &'static str,
    pub kind: QKind,
    pub text: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum QKind {
    YesNo,
    Choice(Vec<&'static str>),
    Score { min: u8, max: u8 },
}

impl QKind {
    /// Option labels in model order. Yes/no is `["yes", "no"]`; a score
    /// question is its levels `min..=max` as decimal strings.
    pub fn labels(&self) -> Vec<String> {
        match self {
            QKind::YesNo => vec!["yes".into(), "no".into()],
            QKind::Choice(opts) => opts.iter().map(|s| (*s).to_string()).collect(),
            QKind::Score { min, max } => (*min..=*max).map(|l| l.to_string()).collect(),
        }
    }
}

/// One answer: a probability for every option of the question.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Answer {
    pub id: String,
    pub probs: Vec<(String, f32)>,
}

impl Answer {
    pub fn prob(&self, label: &str) -> f32 {
        self.probs
            .iter()
            .find(|(l, _)| l == label)
            .map_or(0.0, |(_, p)| *p)
    }

    /// The most likely option.
    pub fn top(&self) -> Option<(&str, f32)> {
        self.probs
            .iter()
            .max_by(|a, b| a.1.total_cmp(&b.1))
            .map(|(l, p)| (l.as_str(), *p))
    }

    /// Expected value for a score question (labels are numeric levels).
    pub fn expected_score(&self) -> f32 {
        self.probs
            .iter()
            .filter_map(|(l, p)| l.parse::<f32>().ok().map(|v| v * p))
            .sum()
    }
}

/// A model that answers typed questions about a text state in one pass.
pub trait DecisionModel: Send + Sync {
    fn name(&self) -> &str;
    fn max_state_tokens(&self) -> usize;
    fn decide(&self, state: &str, qs: &[Question]) -> anyhow::Result<Vec<Answer>>;
    fn reap_idle(&self) {}
    fn is_loaded(&self) -> bool {
        false
    }
}

/// Validate at the trust boundary, including fixtures and alternate adapters.
pub fn validate_answers(answers: &[Answer], questions: &[Question]) -> anyhow::Result<()> {
    anyhow::ensure!(answers.len() == questions.len(), "wrong number of answers");
    for q in questions {
        let matching: Vec<_> = answers.iter().filter(|a| a.id == q.id).collect();
        anyhow::ensure!(matching.len() == 1, "missing or duplicate answer {}", q.id);
        let a = matching[0];
        let labels = q.kind.labels();
        anyhow::ensure!(a.probs.len() == labels.len(), "wrong labels for {}", q.id);
        for label in &labels {
            let values: Vec<_> = a.probs.iter().filter(|(l, _)| l == label).collect();
            anyhow::ensure!(
                values.len() == 1 && values[0].1.is_finite() && (0.0..=1.0).contains(&values[0].1),
                "invalid probability for {}:{label}",
                q.id
            );
        }
        anyhow::ensure!(
            (a.probs.iter().map(|(_, p)| p).sum::<f32>() - 1.).abs() <= 0.001,
            "probabilities do not sum to one for {}",
            q.id
        );
    }
    Ok(())
}

/// Finds an answer by question id.
pub fn answer<'a>(answers: &'a [Answer], id: &str) -> Option<&'a Answer> {
    answers.iter().find(|a| a.id == id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_per_kind() {
        assert_eq!(QKind::YesNo.labels(), vec!["yes", "no"]);
        assert_eq!(QKind::Choice(vec!["a", "b"]).labels(), vec!["a", "b"]);
        assert_eq!(
            QKind::Score { min: 0, max: 3 }.labels(),
            vec!["0", "1", "2", "3"]
        );
    }

    #[test]
    fn answer_helpers() {
        let a = Answer {
            id: "severity".into(),
            probs: vec![
                ("0".into(), 0.1),
                ("1".into(), 0.2),
                ("2".into(), 0.3),
                ("3".into(), 0.4),
            ],
        };
        assert_eq!(a.top(), Some(("3", 0.4)));
        assert!((a.expected_score() - 2.0).abs() < 1e-6);
        assert_eq!(a.prob("2"), 0.3);
        assert_eq!(a.prob("9"), 0.0);
        assert!(answer(std::slice::from_ref(&a), "severity").is_some());
    }
}
