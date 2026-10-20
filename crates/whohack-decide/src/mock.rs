//! Deterministic model for tests (SPEC §12.2 `MockDecisionModel`).
//!
//! Answers come from fixtures: a default distribution per question id, plus
//! optional overrides that apply when the state contains a given substring.
//! Questions without a fixture get a uniform distribution.

use std::collections::HashMap;
use std::sync::Mutex;

use crate::model::{Answer, DecisionModel, Question};

#[derive(Debug, Clone)]
struct Override {
    when_state_contains: String,
    question: String,
    probs: Vec<(String, f32)>,
}

#[derive(Debug, Default)]
pub struct MockDecisionModel {
    defaults: HashMap<String, Vec<(String, f32)>>,
    overrides: Vec<Override>,
    calls: Mutex<Vec<(String, Vec<String>)>>,
}

impl MockDecisionModel {
    pub fn new() -> Self {
        MockDecisionModel::default()
    }

    /// Default answer for question `id`: `(label, probability)` pairs.
    pub fn answer(mut self, id: &str, probs: &[(&str, f32)]) -> Self {
        self.defaults.insert(
            id.into(),
            probs.iter().map(|(l, p)| ((*l).into(), *p)).collect(),
        );
        self
    }

    /// Answer for question `id` when the state contains `needle`.
    pub fn answer_when(mut self, needle: &str, id: &str, probs: &[(&str, f32)]) -> Self {
        self.overrides.push(Override {
            when_state_contains: needle.into(),
            question: id.into(),
            probs: probs.iter().map(|(l, p)| ((*l).into(), *p)).collect(),
        });
        self
    }

    /// `(state, question ids)` for every call, for assertions.
    pub fn calls(&self) -> Vec<(String, Vec<String>)> {
        self.calls.lock().map(|c| c.clone()).unwrap_or_default()
    }
}

impl DecisionModel for MockDecisionModel {
    fn name(&self) -> &str {
        "mock"
    }

    fn max_state_tokens(&self) -> usize {
        2_000
    }

    fn decide(&self, state: &str, qs: &[Question]) -> anyhow::Result<Vec<Answer>> {
        if let Ok(mut calls) = self.calls.lock() {
            calls.push((
                state.to_string(),
                qs.iter().map(|q| q.id.to_string()).collect(),
            ));
        }
        Ok(qs
            .iter()
            .map(|q| {
                let labels = q.kind.labels();
                let fixture = self
                    .overrides
                    .iter()
                    .find(|o| o.question == q.id && state.contains(&o.when_state_contains))
                    .map(|o| &o.probs)
                    .or_else(|| self.defaults.get(q.id));
                let probs = match fixture {
                    Some(f) => labels
                        .iter()
                        .map(|l| {
                            (
                                l.clone(),
                                f.iter().find(|(fl, _)| fl == l).map_or(0.0, |(_, p)| *p),
                            )
                        })
                        .collect(),
                    None => {
                        let p = 1.0 / labels.len().max(1) as f32;
                        labels.iter().map(|l| (l.clone(), p)).collect()
                    }
                };
                Answer {
                    id: q.id.to_string(),
                    probs,
                }
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::QKind;

    fn q(id: &'static str, kind: QKind) -> Question {
        Question {
            id,
            kind,
            text: String::new(),
        }
    }

    #[test]
    fn fixtures_overrides_and_uniform_fallback() {
        let m = MockDecisionModel::new()
            .answer("category", &[("pdf_reader", 0.9), ("other", 0.1)])
            .answer_when("name=Chrome", "category", &[("browser", 1.0)]);
        let qs = [
            q(
                "category",
                QKind::Choice(vec!["browser", "pdf_reader", "other"]),
            ),
            q("x", QKind::YesNo),
        ];
        let a = m.decide("APP name=Viewer", &qs).unwrap();
        assert_eq!(a[0].top(), Some(("pdf_reader", 0.9)));
        assert_eq!(a[1].probs, vec![("yes".into(), 0.5), ("no".into(), 0.5)]);
        let b = m.decide("APP name=Chrome", &qs).unwrap();
        assert_eq!(b[0].top(), Some(("browser", 1.0)));
        assert_eq!(m.calls().len(), 2);
    }
}
