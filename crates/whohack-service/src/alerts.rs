//! Persist and publish detections on the store-writer thread, after process/profile
//! records have been written. Repeated evidence is coalesced for five minutes.
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::Result;
use lru::LruCache;
use tokio::sync::broadcast;
use whohack_core::{Observation, Store};
use whohack_detect::{evaluate, rules::RuleSet};
use whohack_ipc::PushEvent;
use whohack_tags::{CategoryTemplate, Profile};

#[derive(Debug)]
pub struct AlertEngine {
    rules: RuleSet,
    rules_dir: PathBuf,
    last_reload: Instant,
    seen: LruCache<(String, u32, i64, String), i64>,
    pushes: broadcast::Sender<PushEvent>,
    state: Option<std::sync::Arc<crate::ipc_handler::ServiceState>>,
    intel: whohack_intel::reputation::Reputation,
    intel_path: Option<PathBuf>,
    intel_reload: Instant,
    windows: whohack_detect::window::Windows,
    scorer: Option<whohack_detect::onnx::OnnxScorer>,
    decisions: Option<crate::decisions::Queue>,
    thresholds: whohack_detect::fusion::Thresholds,
}

impl AlertEngine {
    pub fn new(rules_dir: PathBuf, pushes: broadcast::Sender<PushEvent>) -> Result<Self> {
        Ok(Self {
            rules: RuleSet::load(&rules_dir)?,
            rules_dir,
            last_reload: Instant::now(),
            seen: LruCache::new(NonZeroUsize::new(4096).unwrap()),
            pushes,
            state: None,
            intel: whohack_intel::reputation::Reputation::default(),
            intel_path: None,
            intel_reload: Instant::now(),
            windows: whohack_detect::window::Windows::default(),
            scorer: None,
            decisions: None,
            thresholds: Default::default(),
        })
    }

    pub fn with_state(mut self, state: std::sync::Arc<crate::ipc_handler::ServiceState>) -> Self {
        self.state = Some(state);
        self
    }

    pub fn with_decisions(
        mut self,
        queue: Option<crate::decisions::Queue>,
        thresholds: whohack_detect::fusion::Thresholds,
    ) -> Self {
        self.decisions = queue;
        self.thresholds = thresholds;
        self
    }

    pub fn with_intelligence(mut self, path: PathBuf) -> Result<Self> {
        if path.exists() {
            self.intel =
                whohack_intel::reputation::Reputation::load(&path, whohack_core::time::now_ms())?;
        }
        self.intel_path = Some(path);
        Ok(self)
    }

    pub fn with_scorer(mut self, cfg: &whohack_core::config::Tier1Config) -> Result<Self> {
        if let (Some(path), Some(sha)) = (&cfg.model, &cfg.sha256) {
            self.scorer = Some(whohack_detect::onnx::OnnxScorer::load(path, sha)?);
        }
        Ok(self)
    }

    /// Runs before observations are persisted so evidence in the timeline and
    /// detection agree. Failed updates retain the last valid index.
    pub fn enrich(&mut self, store: &Store, obs: &mut Observation) -> Result<()> {
        if self.intel_reload.elapsed() >= Duration::from_secs(60) {
            self.intel_reload = Instant::now();
            if let Some(path) = &self.intel_path
                && path.exists()
            {
                match whohack_intel::reputation::Reputation::load(
                    path,
                    whohack_core::time::now_ms(),
                ) {
                    Ok(index) => self.intel = index,
                    Err(e) => {
                        let _ = self.pushes.send(PushEvent::Health {
                            ok: false,
                            message: format!(
                                "Threat feed rejected; previous valid data retained: {e}"
                            ),
                        });
                    }
                }
            }
        }
        if let whohack_core::EventKind::NetConnect {
            remote_ip,
            remote_port,
            proto,
            domain,
            ..
        } = &obs.event.kind
        {
            if let Some(p) = &obs.process {
                let destination = format!("{remote_ip}:{remote_port}/{}", proto.as_str());
                if !store.observe_destination(&p.app_id, &destination, obs.event.ts)? {
                    obs.tags
                        .retain(|t| t.as_str() != "network:first_seen_destination");
                } else if !obs
                    .tags
                    .iter()
                    .any(|t| t.as_str() == "network:first_seen_destination")
                {
                    obs.tags.push(whohack_core::CapabilityTag::from_static(
                        "network:first_seen_destination",
                    ));
                }
            }
            if self
                .intel
                .lookup(*remote_ip, domain.as_deref(), whohack_core::time::now_ms())
                .is_some()
            {
                obs.tags.push(whohack_core::CapabilityTag::from_static(
                    "network:intel_hit",
                ));
            }
        }
        obs.tags.sort();
        obs.tags.dedup();
        Ok(())
    }

    pub fn process(&mut self, store: &Store, obs: &Observation, now: i64) -> Result<Option<i64>> {
        if self.last_reload.elapsed() >= Duration::from_secs(10) {
            self.last_reload = Instant::now();
            match RuleSet::load(&self.rules_dir) {
                Ok(rules) => self.rules = rules,
                Err(e) => {
                    tracing::error!(error = %e, "rule reload rejected; keeping last valid rules");
                    let _ = self.pushes.send(PushEvent::Health {
                        ok: false,
                        message: format!("Rule update rejected; previous rules remain active: {e}"),
                    });
                }
            }
        }
        let Some(p) = &obs.process else {
            return Ok(None);
        };
        let profile = match store.profile(&p.app_id)? {
            Some(r) => Profile {
                category: r.category,
                expected: r.expected,
                never: r.never,
                learning_until: r.learning_until,
            },
            None => Profile::from_template(CategoryTemplate::builtin("other")?, None),
        };
        let allowlist = store.allowlist()?;
        if allowlist
            .iter()
            .any(|a| matches!(a, whohack_core::AllowEntry::App { app_id } if *app_id == p.app_id))
        {
            return Ok(None);
        }
        let filtered = whohack_detect::trust::filtered(obs, &allowlist);
        let features = self.windows.observe(&filtered, &profile);
        let mut context = filtered.clone();
        context.tags = features.tags.clone();
        let mut scorer_failed = false;
        let score = match self.scorer.as_ref().map(|m| m.score(&features)).transpose() {
            Ok(score) => score.unwrap_or_else(|| features.heuristic()),
            Err(e) => {
                scorer_failed = true;
                let _ = self.pushes.send(PushEvent::Health {
                    ok: false,
                    message: format!("Local ONNX failed; using heuristic: {e}"),
                });
                features.heuristic()
            }
        };
        let rule_detection = evaluate(&context, &profile, &self.rules, &allowlist);
        let rule_fired = rule_detection.is_some();
        let escalate =
            whohack_detect::fusion::escalates(&features, score, rule_fired, &self.thresholds);
        let mut detection = match rule_detection {
            Some(d) => d,
            None if escalate && (self.decisions.is_some() || self.scorer.is_some()) => {
                whohack_detect::Detection {
                    rule_ids: vec![],
                    score,
                    recommended_action: whohack_core::Action::AskUser,
                    features: None,
                    verdict: whohack_core::Verdict {
                        label: whohack_core::VerdictLabel::Suspicious,
                        p: [0.; 3],
                        tactic: "none".into(),
                        severity: 1.,
                        action: whohack_core::Action::AskUser,
                        tier: 1,
                        reasons: vec![whohack_decide::explain::evidence(
                            p,
                            &features,
                            &profile.category,
                        )],
                    },
                }
            }
            _ => return Ok(None),
        };
        detection.score = score;
        detection.verdict.reasons.push(format!(
            "60-second behavior score: {:.3} ({}).{}",
            detection.score,
            if self.scorer.is_some() && !scorer_failed {
                "local ONNX"
            } else {
                "hand-weighted heuristic"
            },
            if features.window_saturated {
                " Window reached a resource limit; evidence is incomplete."
            } else {
                ""
            }
        ));
        let state_text = whohack_decide::state::build(
            p,
            self.windows
                .process(p.ppid)
                .filter(|parent| parent.start_time <= p.start_time),
            &profile,
            &features,
            &detection.rule_ids,
            score,
            obs.event.ts,
        );
        detection.features = Some(features);
        let evidence = format!(
            "{}:{}:{}",
            detection.rule_ids.join(","),
            profile
                .violates_never(&context.tags)
                .iter()
                .map(|t| t.as_str())
                .collect::<Vec<_>>()
                .join(","),
            p.downloaded_inputs
                .iter()
                .map(|i| whohack_core::hex::encode(&i.file.sha256))
                .collect::<Vec<_>>()
                .join(",")
        );
        let key = (p.app_id.clone(), p.pid, p.start_time, evidence);
        if self
            .seen
            .get(&key)
            .is_some_and(|last| now >= *last && now.saturating_sub(*last) < 300_000)
        {
            return Ok(None);
        }
        let id = store.insert_alert(obs.event.ts, p.pid, &p.app_id, &detection.verdict)?;
        store.set_alert_target(id, p)?;
        let critical = rule_fired && detection.verdict.severity >= 3.;
        let floor = if rule_fired {
            detection.recommended_action
        } else {
            whohack_core::Action::Allow
        };
        if let Some(state) = &self.state {
            let _gate = state
                .decision_gate
                .lock()
                .map_err(|_| anyhow::anyhow!("response coordination unavailable"))?;
            let recommendation = whohack_detect::fusion::fuse(
                whohack_detect::fusion::Input {
                    probabilities: None,
                    score,
                    rule_floor: floor,
                    rule_fired,
                    critical,
                    model_action: whohack_core::Action::Allow,
                    mode: state.mode(),
                },
                &self.thresholds,
            );
            if state.mode() != whohack_core::ResponseMode::Monitor {
                detection
                    .verdict
                    .reasons
                    .retain(|r| !r.contains("Monitor only:"));
                let pause =
                    whohack_detect::download_protection::should_pause(&filtered, &detection);
                match state.with_responder(|m| {
                    if let Some(record) = m.pause_download(id, p, pause, state.mode())? {
                        return Ok(Some(record));
                    }
                    m.automatic(id, p, recommendation, state.mode())
                }) {
                    Ok(Some(record)) => {
                        detection.verdict.action = record.action;
                        detection.verdict.reasons.push(record.detail);
                    }
                    Ok(None) => detection
                        .verdict
                        .reasons
                        .push("No automatic response was requested.".into()),
                    Err(error) => {
                        detection
                            .verdict
                            .reasons
                            .push(format!("Response failed: {error}"));
                        let _ = self.pushes.send(PushEvent::Health {
                            ok: false,
                            message: format!("Alert {id}: response failed: {error}"),
                        });
                    }
                }
                store.update_alert_verdict(id, &detection.verdict)?;
            }
        }
        if escalate
            && let Some(queue) = &self.decisions
            && let Err(e) = queue.submit(crate::decisions::Case {
                alert_id: id,
                process: p.clone(),
                state_text,
                score,
                rule_floor: floor,
                rule_fired,
                critical,
                queued: Instant::now(),
            })
        {
            detection.verdict.reasons.push(e.to_string());
            store.update_alert_verdict(id, &detection.verdict)?;
            let _ = self.pushes.send(PushEvent::Health {
                ok: false,
                message: e.to_string(),
            });
        }
        self.seen.put(key, now);
        let record = store.alert(id)?.expect("just inserted alert");
        let summary = crate::ipc_handler::summarize(&record);
        tracing::warn!(
            alert_id = id,
            pid = p.pid,
            app_id = p.app_id,
            score = detection.score,
            "{}",
            summary.explanation
        );
        let _ = self.pushes.send(PushEvent::Alert { alert: summary });
        Ok(Some(id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use whohack_core::{
        Action, Event, EventKind, FileInfo, Origin, PathClass, ProcessInfo, ResponseMode, SignState,
    };
    use whohack_ipc::{Handler, Request, Response};

    #[test]
    fn alert_push_cooldown_reload_trust_and_feedback() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("v.db");
        let store = Store::open(&db).unwrap();
        let (tx, mut rx) = broadcast::channel(16);
        let mut engine = AlertEngine::new(dir.path().join("rules"), tx.clone()).unwrap();
        let obs = Observation {
            event: Event {
                ts: 1,
                pid: 42,
                kind: EventKind::Injection { target_pid: 43 },
            },
            process: Some(Arc::new(ProcessInfo {
                downloaded_inputs: Vec::new(),
                pid: 42,
                ppid: 1,
                start_time: 0,
                exe: FileInfo {
                    path: "test-app".into(),
                    sha256: [1; 32],
                    origin: Origin::Unknown,
                    sign: SignState::Unsigned,
                    yara_hits: vec![],
                    first_seen: 0,
                },
                script: None,
                path_class: PathClass::Other,
                tainted: true,
                taint_root: Some(42),
                app_id: "test".into(),
            })),
            tags: vec![whohack_core::CapabilityTag::from_static(
                "injection:remote_thread",
            )],
        };
        let id = engine.process(&store, &obs, 1).unwrap().unwrap();
        assert!(matches!(rx.try_recv().unwrap(), PushEvent::Alert { alert } if alert.id == id));
        assert_eq!(engine.process(&store, &obs, 2).unwrap(), None);
        // A retained window rule must not produce another popup on an unrelated
        // read just because the raw observation has different tags.
        let mut next = obs.clone();
        next.event.ts = 2;
        next.event.kind = EventKind::FileAccess {
            path: "/tmp/document".into(),
            class: whohack_core::SensitiveClass::Documents,
            write: false,
        };
        next.tags = vec![whohack_core::CapabilityTag::from_static(
            "file:read_documents",
        )];
        assert_eq!(engine.process(&store, &next, 3).unwrap(), None);
        // Bad hot reload retains the prior working rules.
        std::fs::create_dir_all(&engine.rules_dir).unwrap();
        std::fs::write(engine.rules_dir.join("bad.yaml"), "bad rules").unwrap();
        engine.last_reload = Instant::now() - Duration::from_secs(11);
        assert!(engine.process(&store, &obs, 300_002).unwrap().is_some());
        assert!(matches!(
            rx.try_recv().unwrap(),
            PushEvent::Health { ok: false, .. }
        ));
        let handler = crate::ipc_handler::ServiceHandler::new(
            Store::open(&db).unwrap(),
            Arc::new(crate::ipc_handler::ServiceState::new(
                ResponseMode::Monitor,
                vec![],
                false,
            )),
            tx,
        );
        assert!(matches!(
            handler.handle(Request::Resolve {
                alert_id: id,
                action: Action::BlockNetwork,
                note: None
            }),
            Response::Error { .. }
        ));
        assert_eq!(store.feedback_for_alert(id).unwrap().len(), 0);
        assert_eq!(
            handler.handle(Request::Resolve {
                alert_id: id,
                action: Action::AskUser,
                note: None
            }),
            Response::Ok
        );
        assert_eq!(store.feedback_for_alert(id).unwrap().len(), 1);
        assert!(matches!(
            handler.handle(Request::SetMode {
                mode: ResponseMode::Auto
            }),
            Response::Error { .. }
        ));
        store
            .allow(&whohack_core::AllowEntry::App {
                app_id: "test".into(),
            })
            .unwrap();
        assert_eq!(engine.process(&store, &obs, 900_000).unwrap(), None);
    }
}
