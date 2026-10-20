//! Bounded, serial inference outside the collector and database-writer threads.
use crate::ipc_handler::{ServiceState, summarize};
use anyhow::{Result, anyhow};
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, RecvTimeoutError, SyncSender},
    },
    thread::JoinHandle,
    time::{Duration, Instant},
};
use tokio::sync::broadcast;
use whohack_core::{
    Action, ProcessInfo, ResponseMode, Store, VerdictLabel,
    store::{AlertStatus, DecisionRecord},
    time::now_ms,
};
use whohack_decide::{Answer, DecisionModel, answer};
use whohack_detect::fusion::{self, Input, Thresholds};
use whohack_ipc::PushEvent;

#[derive(Debug)]
pub struct Case {
    pub alert_id: i64,
    pub process: Arc<ProcessInfo>,
    pub state_text: String,
    pub score: f32,
    pub rule_floor: Action,
    pub rule_fired: bool,
    pub critical: bool,
    pub queued: Instant,
}
#[derive(Debug, Clone)]
pub struct Queue {
    tx: SyncSender<Case>,
}
impl Queue {
    pub fn submit(&self, case: Case) -> Result<()> {
        self.tx
            .try_send(case)
            .map_err(|_| anyhow!("decision queue is full or stopped; review required"))
    }
}
pub struct Models {
    pub primary: Box<dyn DecisionModel>,
    pub secondary: Option<Box<dyn DecisionModel>>,
    pub revision: String,
    pub qualified: bool,
    pub thresholds: Thresholds,
}
impl std::fmt::Debug for Models {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Models")
            .field("primary", &self.primary.name())
            .field("qualified", &self.qualified)
            .finish_non_exhaustive()
    }
}
#[derive(Debug)]
pub struct Worker {
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}
impl Worker {
    pub fn start(
        store: Store,
        state: Arc<ServiceState>,
        pushes: broadcast::Sender<PushEvent>,
        models: Models,
    ) -> Result<(Self, Queue)> {
        let (tx, rx) = mpsc::sync_channel::<Case>(32);
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = stop.clone();
        let handle = std::thread::Builder::new()
            .name("whohack-decisions".into())
            .spawn(move || {
                loop {
                    match rx.recv_timeout(Duration::from_secs(1)) {
                        Ok(case) => {
                            let stale = case.queued.elapsed() > Duration::from_secs(10)
                                || stopped.load(Ordering::Relaxed);
                            if let Err(e) =
                                process_case(&store, &state, &pushes, &models, case, stale)
                            {
                                tracing::error!(error=%e, "decision failed");
                                let _ = pushes.send(PushEvent::Health {
                                    ok: false,
                                    message: format!("Decision failed: {e:#}"),
                                });
                            }
                        }
                        Err(RecvTimeoutError::Disconnected) => break,
                        Err(RecvTimeoutError::Timeout) => {
                            if stopped.load(Ordering::Relaxed) {
                                break;
                            }
                            models.primary.reap_idle();
                            if let Some(second) = &models.secondary {
                                second.reap_idle();
                            }
                            state
                                .model_loaded
                                .store(models.primary.is_loaded(), Ordering::Relaxed);
                        }
                    }
                }
                state.model_loaded.store(false, Ordering::Relaxed);
            })?;
        Ok((
            Self {
                stop,
                handle: Some(handle),
            },
            Queue { tx },
        ))
    }
    pub fn shutdown(mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}
impl Drop for Worker {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

fn open_case(store: &Store, case: &Case) -> Result<bool> {
    Ok(store.alert(case.alert_id)?.is_some_and(|a| a.status == AlertStatus::Open)
        && !store.allowlist()?.iter().any(|a| matches!(a, whohack_core::AllowEntry::App { app_id } if *app_id == case.process.app_id)))
}

fn process_case(
    store: &Store,
    state: &ServiceState,
    pushes: &broadcast::Sender<PushEvent>,
    models: &Models,
    case: Case,
    stale: bool,
) -> Result<()> {
    let qs = whohack_decide::questions::runtime();
    let mut hold_error = None;
    {
        let _gate = state
            .decision_gate
            .lock()
            .map_err(|_| anyhow!("decision lock poisoned"))?;
        if !open_case(store, &case)? {
            return Ok(());
        }
        if !stale
            && models.qualified
            && case.process.tainted
            && state.mode() != ResponseMode::Monitor
        {
            hold_error = state
                .with_responder(|m| {
                    m.automatic(
                        case.alert_id,
                        &case.process,
                        Action::BlockNetwork,
                        state.mode(),
                    )
                })
                .err();
        }
    }
    let mut tier = 2;
    let mut secondary_answers = None;
    let mut secondary_error = None;
    let result = if stale {
        Err(anyhow!("decision expired in queue or service is stopping"))
    } else {
        models.primary.decide(&case.state_text, &qs).and_then(|a| {
            whohack_decide::model::validate_answers(&a, &qs)?;
            Ok(a)
        })
    };
    state
        .model_loaded
        .store(models.primary.is_loaded(), Ordering::Relaxed);
    let mut answers = match result {
        Ok(a) => Some(a),
        Err(e) => {
            secondary_error = Some(e.to_string());
            None
        }
    };
    let primary_answers = answers.clone();
    if let Some(a) = &mut answers
        && let Some(top) = answer(a, "verdict").and_then(Answer::top).map(|(_, p)| p)
        && (0.4..=0.7).contains(&top)
        && let Some(second) = &models.secondary
    {
        // The primary deadline already produced a result. Tell the user that the
        // existing hold is retained while the optional second check runs.
        let _ = pushes.send(PushEvent::Health {
            ok: true,
            message: format!(
                "Alert {}: uncertain decision; running optional local deep check.",
                case.alert_id
            ),
        });
        match second.decide(&case.state_text, &qs).and_then(|b| {
            whohack_decide::model::validate_answers(&b, &qs)?;
            Ok(b)
        }) {
            Ok(b) => {
                for x in a.iter_mut() {
                    if let Some(y) = answer(&b, &x.id) {
                        for (label, p) in &mut x.probs {
                            *p = 0.4 * *p + 0.6 * y.prob(label);
                        }
                    }
                }
                secondary_answers = Some(serde_json::json!({"model": second.name(), "answers": b}));
                tier = 3;
            }
            Err(e) => secondary_error = Some(format!("Optional deep check failed: {e}")),
        }
    }
    // No automatic effect may race a user's Allow, Resolve, mode or trust change.
    let _gate = state
        .decision_gate
        .lock()
        .map_err(|_| anyhow!("decision lock poisoned"))?;
    let mut alert = store
        .alert(case.alert_id)?
        .ok_or_else(|| anyhow!("alert disappeared"))?;
    let mut v = alert.verdict.clone();
    let active = open_case(store, &case)?;
    let p = answers
        .as_ref()
        .and_then(|a| answer(a, "verdict"))
        .map(|a| [a.prob("benign"), a.prob("suspicious"), a.prob("malicious")]);
    let model_action = answers
        .as_ref()
        .and_then(|a| answer(a, "action"))
        .and_then(Answer::top)
        .and_then(|(l, _)| Action::parse(l))
        .unwrap_or(Action::AskUser);
    let input = Input {
        probabilities: if models.qualified { p } else { None },
        score: case.score,
        rule_floor: case.rule_floor,
        rule_fired: case.rule_fired,
        critical: case.critical,
        model_action: if models.qualified {
            model_action
        } else {
            Action::AskUser
        },
        mode: state.mode(),
    };
    let recommendation = fusion::fuse(input, &models.thresholds);
    let mut response_error = None;
    if active {
        v.tier = tier;
        if models.qualified
            && let Some(p) = p
        {
            v.p = p;
            v.label = VerdictLabel::ALL[p
                .iter()
                .enumerate()
                .max_by(|(_, a), (_, b)| a.total_cmp(b))
                .map_or(1, |(i, _)| i)];
        }
        if let Some(a) = &answers {
            if let Some(t) = answer(a, "tactic").and_then(Answer::top) {
                v.tactic = t.0.into();
            }
            if let Some(s) = answer(a, "severity") {
                v.severity = v.severity.max(s.expected_score());
            }
            v.reasons.push(format!(
                "Local model {}{}.",
                models.primary.name(),
                if models.qualified {
                    ""
                } else {
                    " is advisory: representative-data validation has not passed"
                }
            ));
        }
        if let Some(e) = &secondary_error {
            v.reasons.push(format!("Model review required: {e}."));
        }
        if let Some(e) = hold_error {
            v.reasons
                .push(format!("Temporary network hold failed: {e}."));
        }
        if models.qualified
            && state.mode() != ResponseMode::Monitor
            && state.automatic_response_enabled()
        {
            if recommendation == Action::Allow && !case.rule_fired {
                match state.with_responder(|m| m.release_alert(case.alert_id)) {
                    Ok(()) => {
                        v.action = Action::Allow;
                        store.resolve_alert(case.alert_id)?;
                    }
                    Err(e) => response_error = Some(e),
                }
            } else if recommendation >= Action::BlockNetwork {
                match state.with_responder(|m| {
                    m.automatic(case.alert_id, &case.process, recommendation, state.mode())
                }) {
                    Ok(Some(r)) => v.action = r.action,
                    Ok(None) => {}
                    Err(e) => response_error = Some(e),
                }
            }
        }
        // A successful temporary hold is an actual action too, including timeout.
        if state.response.is_some() {
            let held = state
                .with_responder(|m| {
                    Ok(m.records()
                        .iter()
                        .filter(|r| {
                            r.alert_id == case.alert_id
                                && r.status == whohack_respond::ActionStatus::Active
                        })
                        .map(|r| r.action)
                        .max())
                })
                .ok()
                .flatten();
            if let Some(a) = held {
                v.action = v.action.max(a);
            }
        }
        if let Some(e) = &response_error {
            v.reasons.push(format!("Response failed: {e}."));
        }
        v.reasons.push(format!(
            "Decision recommendation: {}. {}",
            recommendation.as_str(),
            whohack_decide::explain::action(v.action)
        ));
        store.update_alert_verdict(case.alert_id, &v)?;
    }
    store.insert_decision(&DecisionRecord {
        ts: now_ms(), alert_id: Some(case.alert_id), app_id: case.process.app_id.clone(), state_text: case.state_text,
        answers: serde_json::json!({"answers": answers, "primary": primary_answers, "secondary": secondary_answers, "error": secondary_error, "response_error": response_error, "advisory": !models.qualified, "superseded_by_user": !active, "recommended_action": recommendation}),
        model_name: models.primary.name().into(), model_revision: models.revision.clone(), tier, final_action: v.action,
    })?;
    if active {
        alert = store
            .alert(case.alert_id)?
            .ok_or_else(|| anyhow!("alert disappeared"))?;
        let _ = pushes.send(PushEvent::Alert {
            alert: summarize(&alert),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use whohack_core::{FileInfo, Origin, PathClass, SignState, Verdict};
    use whohack_decide::{MockDecisionModel, Question};

    fn fixture(store: &Store) -> Case {
        let p = Arc::new(ProcessInfo {
            downloaded_inputs: Vec::new(),
            pid: 4242,
            ppid: 1,
            start_time: 10,
            exe: FileInfo {
                path: "safe-test.exe".into(),
                sha256: [1; 32],
                origin: Origin::Unknown,
                sign: SignState::Unsigned,
                yara_hits: vec![],
                first_seen: 10,
            },
            script: None,
            path_class: PathClass::Other,
            tainted: true,
            taint_root: Some(4242),
            app_id: "test".into(),
        });
        let id = store
            .insert_alert(
                10,
                p.pid,
                &p.app_id,
                &Verdict {
                    label: VerdictLabel::Suspicious,
                    p: [0.; 3],
                    tactic: "none".into(),
                    severity: 1.,
                    action: Action::AskUser,
                    tier: 1,
                    reasons: vec!["Test evidence".into()],
                },
            )
            .unwrap();
        store.set_alert_target(id, &p).unwrap();
        Case {
            alert_id: id,
            process: p,
            state_text: "APP name=safe-test.exe\nANOMALY 0.90".into(),
            score: 0.9,
            rule_floor: Action::Allow,
            rule_fired: false,
            critical: false,
            queued: Instant::now(),
        }
    }
    fn models(qualified: bool) -> Models {
        Models {
            primary: Box::new(
                MockDecisionModel::new()
                    .answer(
                        "verdict",
                        &[("benign", 0.02), ("suspicious", 0.03), ("malicious", 0.95)],
                    )
                    .answer("action", &[("kill_and_quarantine", 1.)]),
            ),
            secondary: None,
            revision: "fixture".into(),
            qualified,
            thresholds: Thresholds::default(),
        }
    }
    #[test]
    fn worker_persists_full_decision_and_monitor_has_no_response() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.db");
        let store = Store::open(&path).unwrap();
        let case = fixture(&store);
        let id = case.alert_id;
        let state = Arc::new(ServiceState::new(ResponseMode::Monitor, vec![], false));
        let (pushes, mut rx) = broadcast::channel(8);
        let (worker, queue) =
            Worker::start(Store::open(&path).unwrap(), state, pushes, models(true)).unwrap();
        queue.submit(case).unwrap();
        drop(queue);
        worker.shutdown();
        // shutdown may cancel queued work; exercise the live path separately below.
        assert_eq!(store.decisions_for_alert(id).unwrap().len(), 1);
        let case = fixture(&store);
        let id = case.alert_id;
        let state = ServiceState::new(ResponseMode::Monitor, vec![], false);
        let (pushes, _) = broadcast::channel(8);
        process_case(&store, &state, &pushes, &models(true), case, false).unwrap();
        let a = store.alert(id).unwrap().unwrap();
        assert_eq!(a.verdict.label, VerdictLabel::Malicious);
        assert_eq!(a.verdict.action, Action::AskUser);
        let d = store.decisions_for_alert(id).unwrap();
        assert_eq!(d[0].model_revision, "fixture");
        assert_eq!(d[0].answers["answers"].as_array().unwrap().len(), 5);
        assert!(rx.try_recv().is_ok());
    }
    #[test]
    fn unqualified_and_expired_models_cannot_drive_response() {
        let store = Store::open_in_memory().unwrap();
        let (pushes, _) = broadcast::channel(8);
        let state = ServiceState::new(ResponseMode::Auto, vec![], false);
        let case = fixture(&store);
        let id = case.alert_id;
        process_case(&store, &state, &pushes, &models(false), case, false).unwrap();
        let a = store.alert(id).unwrap().unwrap();
        assert_eq!(a.verdict.action, Action::AskUser);
        assert_eq!(a.verdict.p, [0.; 3]);
        let case = fixture(&store);
        let id = case.alert_id;
        process_case(&store, &state, &pushes, &models(true), case, true).unwrap();
        let d = store.decisions_for_alert(id).unwrap();
        assert!(d[0].answers["error"].as_str().unwrap().contains("expired"));
        assert_eq!(d[0].final_action, Action::AskUser);
        let (tx, _rx) = mpsc::sync_channel(1);
        let q = Queue { tx };
        q.submit(fixture(&store)).unwrap();
        assert!(q.submit(fixture(&store)).is_err());
    }
    struct UserResolves {
        path: std::path::PathBuf,
        id: i64,
    }
    impl DecisionModel for UserResolves {
        fn name(&self) -> &str {
            "user-race-test"
        }
        fn max_state_tokens(&self) -> usize {
            768
        }
        fn decide(&self, s: &str, q: &[Question]) -> Result<Vec<Answer>> {
            let store = Store::open(&self.path)?;
            store.resolve_alert(self.id)?;
            models(true).primary.decide(s, q)
        }
    }
    #[test]
    fn late_result_never_overrides_user_resolution() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.db");
        let store = Store::open(&path).unwrap();
        let case = fixture(&store);
        let id = case.alert_id;
        let mut model = models(true);
        model.primary = Box::new(UserResolves { path, id });
        let state = ServiceState::new(ResponseMode::Auto, vec![], false);
        let (pushes, _) = broadcast::channel(8);
        process_case(&store, &state, &pushes, &model, case, false).unwrap();
        let a = store.alert(id).unwrap().unwrap();
        assert_eq!(a.status, AlertStatus::Resolved);
        assert_eq!(a.verdict.tier, 1);
        assert_eq!(
            store.decisions_for_alert(id).unwrap()[0].answers["superseded_by_user"],
            true
        );
    }
}
