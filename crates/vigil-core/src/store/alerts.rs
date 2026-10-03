//! `alerts`, `decisions`, and `feedback` tables.
//!
//! A feedback row (the user's allow/block on an alert) joined with its alert
//! and decision rows is one labeled training example (SPEC §17, step 9).

use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};

use super::{Store, StoreError, from_json, parse_col};
use crate::types::{Action, Verdict, VerdictLabel};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertStatus {
    Open,
    Resolved,
}

impl AlertStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            AlertStatus::Open => "open",
            AlertStatus::Resolved => "resolved",
        }
    }

    pub fn parse(s: &str) -> Option<AlertStatus> {
        match s {
            "open" => Some(AlertStatus::Open),
            "resolved" => Some(AlertStatus::Resolved),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AlertRecord {
    pub id: i64,
    pub ts: i64,
    pub pid: u32,
    pub app_id: String,
    pub verdict: Verdict,
    pub status: AlertStatus,
}

/// One decision-model run (SPEC §15 `decisions`). `answers` holds the
/// model's per-question probabilities as JSON; the typed `Answer` struct
/// lives in `vigil-decide` and serializes into this field.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DecisionRecord {
    pub ts: i64,
    pub alert_id: Option<i64>,
    pub app_id: String,
    pub state_text: String,
    pub answers: serde_json::Value,
    pub model_name: String,
    pub model_revision: String,
    pub tier: u8,
    pub final_action: Action,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeedbackRecord {
    pub id: i64,
    pub alert_id: i64,
    pub ts: i64,
    pub user_action: Action,
    pub note: Option<String>,
}

const ALERT_COLUMNS: &str = "id, ts, pid, app_id, label, p_benign, p_suspicious, p_malicious,
                             tactic, severity, action, tier, reasons, status";

struct AlertRow {
    id: i64,
    ts: i64,
    pid: u32,
    app_id: String,
    label: String,
    p: [f64; 3],
    tactic: String,
    severity: f64,
    action: String,
    tier: u8,
    reasons: String,
    status: String,
}

impl AlertRow {
    fn read(r: &rusqlite::Row<'_>) -> rusqlite::Result<AlertRow> {
        Ok(AlertRow {
            id: r.get(0)?,
            ts: r.get(1)?,
            pid: r.get(2)?,
            app_id: r.get(3)?,
            label: r.get(4)?,
            p: [r.get(5)?, r.get(6)?, r.get(7)?],
            tactic: r.get(8)?,
            severity: r.get(9)?,
            action: r.get(10)?,
            tier: r.get(11)?,
            reasons: r.get(12)?,
            status: r.get(13)?,
        })
    }

    fn decode(self) -> Result<AlertRecord, StoreError> {
        Ok(AlertRecord {
            id: self.id,
            ts: self.ts,
            pid: self.pid,
            app_id: self.app_id,
            verdict: Verdict {
                label: parse_col("alerts.label", self.label, VerdictLabel::parse)?,
                p: self.p.map(|x| x as f32),
                tactic: self.tactic,
                severity: self.severity as f32,
                action: parse_col("alerts.action", self.action, Action::parse)?,
                tier: self.tier,
                reasons: from_json(&self.reasons)?,
            },
            status: parse_col("alerts.status", self.status, AlertStatus::parse)?,
        })
    }
}

impl Store {
    pub fn insert_alert(
        &self,
        ts: i64,
        pid: u32,
        app_id: &str,
        v: &Verdict,
    ) -> Result<i64, StoreError> {
        self.conn.execute(
            "INSERT INTO alerts (ts, pid, app_id, label, p_benign, p_suspicious, p_malicious,
                                 tactic, severity, action, tier, reasons)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                ts,
                pid,
                app_id,
                v.label.as_str(),
                f64::from(v.p[0]),
                f64::from(v.p[1]),
                f64::from(v.p[2]),
                v.tactic,
                f64::from(v.severity),
                v.action.as_str(),
                v.tier,
                serde_json::to_string(&v.reasons)?,
            ],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    pub fn alert(&self, id: i64) -> Result<Option<AlertRecord>, StoreError> {
        let row = self
            .conn
            .query_row(
                &format!("SELECT {ALERT_COLUMNS} FROM alerts WHERE id = ?1"),
                [id],
                AlertRow::read,
            )
            .optional()?;
        row.map(AlertRow::decode).transpose()
    }

    /// Open alerts, newest first.
    pub fn open_alerts(&self) -> Result<Vec<AlertRecord>, StoreError> {
        let mut stmt = self.conn.prepare(&format!(
            "SELECT {ALERT_COLUMNS} FROM alerts WHERE status = 'open' ORDER BY ts DESC, id DESC"
        ))?;
        let rows = stmt
            .query_map([], AlertRow::read)?
            .collect::<Result<Vec<_>, _>>()?;
        rows.into_iter().map(AlertRow::decode).collect()
    }

    /// Most recent alerts (open and resolved), newest first.
    pub fn recent_alerts(&self, limit: u32) -> Result<Vec<AlertRecord>, StoreError> {
        let mut stmt = self.conn.prepare(&format!(
            "SELECT {ALERT_COLUMNS} FROM alerts ORDER BY ts DESC, id DESC LIMIT ?1"
        ))?;
        let rows = stmt
            .query_map([limit], AlertRow::read)?
            .collect::<Result<Vec<_>, _>>()?;
        rows.into_iter().map(AlertRow::decode).collect()
    }

    /// Marks an alert resolved. Returns false if it does not exist.
    pub fn resolve_alert(&self, alert_id: i64) -> Result<bool, StoreError> {
        let n = self.conn.execute(
            "UPDATE alerts SET status = 'resolved' WHERE id = ?1",
            [alert_id],
        )?;
        Ok(n > 0)
    }

    pub fn insert_decision(&self, d: &DecisionRecord) -> Result<i64, StoreError> {
        self.conn.execute(
            "INSERT INTO decisions (ts, alert_id, app_id, state_text, answers, model_name,
                                    model_revision, tier, final_action)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                d.ts,
                d.alert_id,
                d.app_id,
                d.state_text,
                serde_json::to_string(&d.answers)?,
                d.model_name,
                d.model_revision,
                d.tier,
                d.final_action.as_str(),
            ],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    pub fn decisions_for_alert(&self, alert_id: i64) -> Result<Vec<DecisionRecord>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT ts, alert_id, app_id, state_text, answers, model_name, model_revision,
                    tier, final_action
             FROM decisions WHERE alert_id = ?1 ORDER BY ts, id",
        )?;
        type Raw = (
            i64,
            Option<i64>,
            String,
            String,
            String,
            String,
            String,
            u8,
            String,
        );
        let rows = stmt
            .query_map([alert_id], |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                    r.get(6)?,
                    r.get(7)?,
                    r.get(8)?,
                ))
            })?
            .collect::<Result<Vec<Raw>, _>>()?;
        rows.into_iter()
            .map(
                |(
                    ts,
                    alert_id,
                    app_id,
                    state_text,
                    answers,
                    model_name,
                    model_revision,
                    tier,
                    act,
                )| {
                    Ok(DecisionRecord {
                        ts,
                        alert_id,
                        app_id,
                        state_text,
                        answers: from_json(&answers)?,
                        model_name,
                        model_revision,
                        tier,
                        final_action: parse_col("decisions.final_action", act, Action::parse)?,
                    })
                },
            )
            .collect()
    }

    /// Records the user's decision on an alert. Fails if the alert does not exist.
    pub fn insert_feedback(
        &self,
        alert_id: i64,
        ts: i64,
        user_action: Action,
        note: Option<&str>,
    ) -> Result<i64, StoreError> {
        self.conn.execute(
            "INSERT INTO feedback (alert_id, ts, user_action, note) VALUES (?1, ?2, ?3, ?4)",
            params![alert_id, ts, user_action.as_str(), note],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    pub fn feedback_for_alert(&self, alert_id: i64) -> Result<Vec<FeedbackRecord>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, ts, user_action, note FROM feedback WHERE alert_id = ?1 ORDER BY ts, id",
        )?;
        let rows = stmt
            .query_map([alert_id], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, i64>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, Option<String>>(3)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        rows.into_iter()
            .map(|(id, ts, act, note)| {
                Ok(FeedbackRecord {
                    id,
                    alert_id,
                    ts,
                    user_action: parse_col("feedback.user_action", act, Action::parse)?,
                    note,
                })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn verdict() -> Verdict {
        Verdict {
            label: VerdictLabel::Malicious,
            p: [0.05, 0.10, 0.85],
            tactic: "credential_theft".into(),
            severity: 3.0,
            action: Action::BlockNetwork,
            tier: 2,
            reasons: vec!["reads browser passwords".into(), "beaconing".into()],
        }
    }

    #[test]
    fn alert_round_trip_and_resolve() {
        let s = Store::open_in_memory().unwrap();
        let id = s.insert_alert(1_000, 42, "app", &verdict()).unwrap();
        let a = s.alert(id).unwrap().unwrap();
        assert_eq!(a.verdict, verdict());
        assert_eq!(a.status, AlertStatus::Open);
        assert_eq!((a.ts, a.pid, a.app_id.as_str()), (1_000, 42, "app"));
        assert_eq!(s.open_alerts().unwrap().len(), 1);
        assert!(s.resolve_alert(id).unwrap());
        assert_eq!(s.alert(id).unwrap().unwrap().status, AlertStatus::Resolved);
        assert!(s.open_alerts().unwrap().is_empty());
        assert!(!s.resolve_alert(id + 100).unwrap());
        assert!(s.alert(id + 100).unwrap().is_none());
    }

    #[test]
    fn open_alerts_newest_first() {
        let s = Store::open_in_memory().unwrap();
        let old = s.insert_alert(1, 1, "a", &verdict()).unwrap();
        let new = s.insert_alert(2, 1, "a", &verdict()).unwrap();
        let ids: Vec<i64> = s.open_alerts().unwrap().iter().map(|a| a.id).collect();
        assert_eq!(ids, vec![new, old]);
        s.resolve_alert(old).unwrap();
        let recent: Vec<i64> = s.recent_alerts(10).unwrap().iter().map(|a| a.id).collect();
        assert_eq!(recent, vec![new, old]);
        assert_eq!(s.recent_alerts(1).unwrap().len(), 1);
    }

    #[test]
    fn alert_decision_feedback_chain() {
        let s = Store::open_in_memory().unwrap();
        let alert_id = s.insert_alert(1_000, 42, "app", &verdict()).unwrap();
        let d = DecisionRecord {
            ts: 1_001,
            alert_id: Some(alert_id),
            app_id: "app".into(),
            state_text: "APP name=x category=pdf_reader".into(),
            answers: serde_json::json!({"verdict": {"benign": 0.05, "suspicious": 0.1, "malicious": 0.85}}),
            model_name: "mock".into(),
            model_revision: "0".into(),
            tier: 2,
            final_action: Action::BlockNetwork,
        };
        s.insert_decision(&d).unwrap();
        assert_eq!(s.decisions_for_alert(alert_id).unwrap(), vec![d]);

        let fid = s
            .insert_feedback(alert_id, 2_000, Action::KillAndQuarantine, Some("not mine"))
            .unwrap();
        let fb = s.feedback_for_alert(alert_id).unwrap();
        assert_eq!(
            fb,
            vec![FeedbackRecord {
                id: fid,
                alert_id,
                ts: 2_000,
                user_action: Action::KillAndQuarantine,
                note: Some("not mine".into()),
            }]
        );
    }

    #[test]
    fn feedback_requires_existing_alert() {
        let s = Store::open_in_memory().unwrap();
        let err = s.insert_feedback(999, 1, Action::Allow, None).unwrap_err();
        assert!(matches!(err, StoreError::Sqlite(_)), "{err}");
    }
}
