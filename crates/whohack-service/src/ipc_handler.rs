//! Serves tray-UI requests (SPEC §14) from the service's state and store.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Instant;

use tokio::sync::broadcast;
use whohack_core::store::AlertRecord;
use whohack_core::time::now_ms;
use whohack_core::{Event, EventKind, ResponseMode, Store};
use whohack_ipc::{AlertSummary, EventSummary, Handler, PushEvent, Request, Response, StatusInfo};

/// Store setting key for the runtime response-mode override.
pub const MODE_SETTING: &str = "mode";

/// Live service state shared with the IPC handler.
#[derive(Debug)]
pub struct ServiceState {
    pub mode: RwLock<ResponseMode>,
    pub collectors: Vec<String>,
    pub dns_visible: bool,
    pub collection: Arc<whohack_collect::health::Health>,
    pub collection_notes: Vec<String>,
    pub integrity_issues: RwLock<Vec<String>>,
    pub model: Option<String>,
    pub started: Instant,
    pub events_seen: AtomicU64,
    pub response: Option<Mutex<whohack_respond::Manager>>,
    pub tier1_onnx: bool,
    pub model_loaded: AtomicBool,
    /// Serialize response changes with user resolution and trust changes. Never
    /// hold this across model inference.
    pub decision_gate: Mutex<()>,
}

impl ServiceState {
    pub fn new(mode: ResponseMode, collectors: Vec<String>, dns_visible: bool) -> Self {
        ServiceState {
            mode: RwLock::new(mode),
            collectors,
            dns_visible,
            collection: Arc::default(),
            collection_notes: vec![],
            integrity_issues: RwLock::new(vec![]),
            model: None,
            started: Instant::now(),
            events_seen: AtomicU64::new(0),
            response: None,
            tier1_onnx: false,
            model_loaded: AtomicBool::new(false),
            decision_gate: Mutex::new(()),
        }
    }

    pub fn mode(&self) -> ResponseMode {
        if self
            .integrity_issues
            .read()
            .map_or(true, |issues| !issues.is_empty())
        {
            return ResponseMode::Monitor;
        }
        self.mode
            .read()
            .map(|m| *m)
            .unwrap_or(ResponseMode::Monitor)
    }

    pub fn with_response(mut self, response: Option<whohack_respond::Manager>) -> Self {
        self.response = response.map(Mutex::new);
        self
    }
    pub fn automatic_response_enabled(&self) -> bool {
        self.with_responder(|m| Ok(m.automatic_enabled()))
            .unwrap_or(false)
    }
    pub fn response_capabilities(&self) -> whohack_respond::Capabilities {
        if self
            .integrity_issues
            .read()
            .map_or(true, |issues| !issues.is_empty())
        {
            return whohack_respond::Capabilities { limitation: "Integrity verification failed; inspect the reported changes before enabling response".into(), ..Default::default() };
        }
        self.response
            .as_ref()
            .and_then(|m| m.try_lock().ok())
            .map(|m| m.capabilities())
            .unwrap_or_else(|| whohack_respond::Capabilities {
                limitation: "Response is unavailable or another response is awaiting completion."
                    .into(),
                ..Default::default()
            })
    }
    pub fn with_responder<T>(
        &self,
        f: impl FnOnce(&mut whohack_respond::Manager) -> anyhow::Result<T>,
    ) -> Result<T, String> {
        let mut m = self
            .response
            .as_ref()
            .ok_or("response manager is unavailable")?
            .try_lock()
            .map_err(
                |_| "response unavailable or awaiting completion; try again when it finishes",
            )?;
        f(&mut m).map_err(|e| format!("{e:#}"))
    }
}

/// The effective mode at startup: a mode chosen in the UI (stored) wins
/// over the config file.
pub fn effective_mode(store: &Store, configured: ResponseMode, enabled: bool) -> ResponseMode {
    let requested = store
        .setting(MODE_SETTING)
        .ok()
        .flatten()
        .and_then(|s| ResponseMode::parse(&s))
        .unwrap_or(configured);
    if enabled {
        return requested;
    }
    if requested != ResponseMode::Monitor {
        tracing::warn!(
            requested = requested.as_str(),
            "enforcement is unavailable; using monitor mode"
        );
    }
    ResponseMode::Monitor
}

pub fn summarize(a: &AlertRecord) -> AlertSummary {
    let app_name = a
        .app_id
        .rsplit(['/', '\\', ':'])
        .next()
        .unwrap_or(&a.app_id)
        .to_string();
    AlertSummary {
        id: a.id,
        ts: a.ts,
        pid: a.pid,
        app_id: a.app_id.clone(),
        app_name,
        label: a.verdict.label,
        p: a.verdict.p,
        severity: a.verdict.severity,
        action: a.verdict.action,
        explanation: a.verdict.reasons.join(" "),
        resolved: a.status == whohack_core::store::AlertStatus::Resolved,
    }
}

/// Timeline row for an event.
pub fn summarize_event(e: &Event) -> EventSummary {
    let detail = match &e.kind {
        EventKind::ProcessStart { exe, ppid, .. } => format!("{exe} (parent {ppid})"),
        EventKind::ProcessExit => String::new(),
        EventKind::NetConnect {
            remote_ip,
            remote_port,
            proto,
            domain,
            ..
        } => format!(
            "{remote_ip}:{remote_port}/{} {}",
            proto.as_str(),
            domain.as_deref().unwrap_or("")
        )
        .trim_end()
        .to_string(),
        EventKind::DnsQuery { name, answers } => format!("{name} -> {} address(es)", answers.len()),
        EventKind::NetStats {
            bytes_up,
            bytes_down,
        } => format!("{bytes_up} bytes sent, {bytes_down} bytes received"),
        EventKind::FileAccess { path, class, write } => {
            format!(
                "{} {path} ({})",
                if *write { "write" } else { "read" },
                class.as_str()
            )
        }
        EventKind::Persistence { location, target } => format!("{} {target}", location.as_str()),
        EventKind::Injection { target_pid } => format!("target pid {target_pid}"),
        EventKind::FileBurst {
            modified,
            renamed,
            window_ms,
        } => {
            format!("{modified} modified, {renamed} renamed in {window_ms} ms")
        }
    };
    EventSummary {
        ts: e.ts,
        pid: e.pid,
        kind: e.kind.name().to_string(),
        detail,
    }
}

#[derive(Debug)]
pub struct ServiceHandler {
    store: Mutex<Store>,
    state: std::sync::Arc<ServiceState>,
    pushes: broadcast::Sender<PushEvent>,
}

impl ServiceHandler {
    pub fn new(
        store: Store,
        state: std::sync::Arc<ServiceState>,
        pushes: broadcast::Sender<PushEvent>,
    ) -> Self {
        ServiceHandler {
            store: Mutex::new(store),
            state,
            pushes,
        }
    }

    fn with_store<T>(
        &self,
        f: impl FnOnce(&Store) -> Result<T, whohack_core::StoreError>,
    ) -> Result<T, String> {
        let store = self
            .store
            .lock()
            .map_err(|_| "store lock poisoned".to_string())?;
        f(&store).map_err(|e| e.to_string())
    }
}

fn reply(r: Result<Response, String>) -> Response {
    r.unwrap_or_else(|message| Response::Error { message })
}

impl Handler for ServiceHandler {
    fn handle(&self, request: Request) -> Response {
        // Read-only history/status must remain responsive while Windows asks for
        // consent. Serialize mutations with model decisions, but do not queue
        // more mutations behind a pending user-controlled response.
        let _gate = if matches!(
            request,
            Request::Resolve { .. }
                | Request::SetMode { .. }
                | Request::ReleaseResponse { .. }
                | Request::RestoreQuarantine { .. }
                | Request::SetCategory { .. }
                | Request::Allow { .. }
                | Request::Disallow { .. }
        ) {
            match self.state.decision_gate.try_lock() {
                Ok(gate) => Some(gate),
                Err(_) => return Response::Error {
                    message:
                        "Another response or decision is in progress; try again when it finishes."
                            .into(),
                },
            }
        } else {
            None
        };
        match request {
            Request::DecisionDetails { alert_id } => reply(self.with_store(|s| {
                s.decisions_for_alert(alert_id)?.into_iter().take(20).map(|d| serde_json::to_value(d).map_err(Into::into)).collect::<Result<Vec<_>, whohack_core::StoreError>>()
            }).map(|records| Response::Decisions { records })),
            Request::Status => {
                let capabilities = self.state.response_capabilities();
                reply(
                    self.with_store(|s| s.open_alerts())
                        .map(|open| Response::Status {
                            status: Box::new(StatusInfo {
                                service_version: env!("CARGO_PKG_VERSION").into(),
                                service_pid: std::process::id(),
                                mode: self.state.mode(),
                                collectors: self.state.collectors.clone(),
                                dns_visible: self.state.dns_visible && self.state.collection.healthy(),
                                enforcement_available: capabilities.network,
                                automatic_response_enabled: self.state.automatic_response_enabled(),
                                download_pause_enabled: capabilities.suspend && self.state.mode() != ResponseMode::Monitor
                                    && self.state.with_responder(|m| Ok(m.download_pause_enabled())).unwrap_or(false),
                                response_actions: {
                                    let c = &capabilities;
                                    let mut a = vec![];
                                    if c.network { a.push(whohack_core::Action::BlockNetwork); }
                                    if c.suspend { a.push(whohack_core::Action::SuspendAndAsk); }
                                    if c.terminate && c.quarantine { a.push(whohack_core::Action::KillAndQuarantine); }
                                    a
                                },
                                network_scope: capabilities.network_scope,
                                response_limitation: capabilities.limitation,
                                file_visibility: self.state.collection.files.load(Ordering::Relaxed) && self.state.collection.healthy(),
                                registry_visibility: self.state.collection.registry.load(Ordering::Relaxed) && self.state.collection.healthy(),
                                injection_visibility: self.state.collection.injection.load(Ordering::Relaxed) && self.state.collection.healthy(),
                                collection_dropped: self.state.collection.dropped.load(Ordering::Relaxed),
                                collection_kernel_lost: self.state.collection.kernel_lost.load(Ordering::Relaxed),
                                collection_unattributed: self.state.collection.unattributed.load(Ordering::Relaxed),
                                collection_failures: self.state.collection.failures.load(Ordering::Relaxed),
                                collection_notes: self.state.collection_notes.clone(),
                                integrity_issues: self.state.integrity_issues.read().map(|v| v.clone()).unwrap_or_else(|_| vec!["integrity state unavailable".into()]),
                                byte_visibility: self.state.collection.healthy() && self.state.collectors.iter().any(|c| c == "windows-etw"),
                                scorer: if self.state.tier1_onnx { "pinned local ONNX" } else { "hand-weighted 60-second heuristic" }.into(),
                                model: self.state.model.clone(),
                                model_loaded: self.state.model_loaded.load(Ordering::Relaxed),
                                uptime_s: self.state.started.elapsed().as_secs(),
                                events_seen: self.state.events_seen.load(Ordering::Relaxed),
                                open_alerts: open.len() as u32,
                            }),
                        }),
                )
            }
            Request::ListAlerts { limit } => reply(
                self.with_store(|s| s.recent_alerts(limit.min(1000)))
                    .map(|alerts| Response::Alerts {
                        alerts: alerts.iter().map(summarize).collect(),
                    }),
            ),
            Request::Resolve {
                alert_id,
                action,
                note,
            } => reply((|| {
                let (alert, target) = self.with_store(|s| Ok((s.alert(alert_id)?, s.alert_target(alert_id)?)))?;
                let Some(alert) = alert else {
                    return Ok(Response::Error {
                        message: format!("no alert {alert_id}"),
                    });
                };
                if alert.status == whohack_core::store::AlertStatus::Resolved { return Ok(Response::Ok); }
                if action >= whohack_core::Action::BlockNetwork {
                    if self.state.integrity_issues.read().map_or(true, |v| !v.is_empty()) {
                        return Ok(Response::Error { message: "Integrity verification failed; response is disabled until the reported changes are reviewed.".into() });
                    }
                    let Some(target) = target else {
                        return Ok(Response::Error { message: "This alert has no captured process identity; it cannot safely control a process.".into() });
                    };
                    match self.state.with_responder(|m| m.apply(alert_id, &target, action)) {
                        Ok(record) => {
                            self.with_store(|s| {
                                if let Some(mut current) = s.alert(alert_id)? {
                                    current.verdict.action = record.action;
                                    current.verdict.reasons.push(record.detail);
                                    s.update_alert_verdict(alert_id, &current.verdict)?;
                                }
                                Ok(())
                            })?;
                        },
                        Err(message) => return Ok(Response::Error { message }),
                    }
                } else if action == whohack_core::Action::Allow && self.state.response.is_some()
                    && let Err(message) = self.state.with_responder(|m| {
                        m.release_alert(alert_id)?;
                        if let Some(target) = &target { m.release_process_pause(target)?; }
                        Ok(())
                    }) {
                        return Ok(Response::Error { message });
                }
                self.with_store(|s| {
                    if action == whohack_core::Action::Allow
                        && let Some(mut current) = s.alert(alert_id)? {
                        current.verdict.action = action;
                        current.verdict.reasons.push("Allowed by the user; whohack released its matching process suspension.".into());
                        s.update_alert_verdict(alert_id, &current.verdict)?;
                    }
                    s.insert_feedback(alert_id, now_ms(), action, note.as_deref())?;
                    s.resolve_alert(alert_id)
                })?;
                Ok(Response::Ok)
            })()),
            Request::SetMode { mode: ResponseMode::Auto } if !self.state.automatic_response_enabled() => Response::Error {
                message: "Automatic responses are disabled in the service configuration. Responses require your confirmation.".into()
            },
            Request::SetMode { mode } if mode != ResponseMode::Monitor && !self.state.response_capabilities().network && !self.state.response_capabilities().suspend => Response::Error {
                message: "Enable a supported response backend in the service configuration before choosing this mode.".into()
            },
            Request::ListResponses => reply(self.state.with_responder(|m| {
                Ok(Response::Responses {
                    actions: m.records().iter().rev().take(1000).map(|r| whohack_ipc::ResponseSummary {
                        id: r.id.clone(), alert_id: r.alert_id, ts: r.ts, app: r.target.exe.path.clone(), pid: r.target.pid, action: r.action,
                        status: serde_json::to_value(r.status).ok().and_then(|v| v.as_str().map(str::to_owned)).unwrap_or_default(), detail: r.detail.clone(), quarantine_id: r.quarantine_id.clone(),
                    }).collect(),
                    quarantine: m.quarantine_entries()?.into_iter().take(1000).map(|q| whohack_ipc::QuarantineSummary { id: q.id, original_path: q.original_path.to_string_lossy().into(), sha256: whohack_core::hex::encode(&q.sha256), size: q.size, quarantined_at: q.quarantined_at, restored_at: q.restored_at }).collect(),
                })
            })),
            Request::ReleaseResponse { id } => reply(self.state.with_responder(|m| m.release(&id).map(|()| Response::Ok))),
            Request::RestoreQuarantine { id } => reply(self.state.with_responder(|m| m.restore(&id).map(|_| Response::Ok))),
            Request::SetMode { mode } => reply(
                self.with_store(|s| s.set_setting(MODE_SETTING, mode.as_str()))
                    .map(|()| {
                        if let Ok(mut m) = self.state.mode.write() {
                            *m = mode;
                        }
                        if mode == ResponseMode::Monitor && self.state.response.is_some()
                            && let Err(message) = self.state.with_responder(|m| m.shutdown()) {
                                let _ = self.pushes.send(PushEvent::Health { ok: false, message: format!("Monitor mode selected, but a response could not be released: {message}") });
                                return Response::Error { message };
                            }
                        tracing::info!(mode = mode.as_str(), "response mode changed from the UI");
                        let _ = self.pushes.send(PushEvent::ModeChanged { mode });
                        Response::Ok
                    }),
            ),
            Request::ListAllowlist => reply(
                self.with_store(|s| s.allowlist())
                    .map(|entries| Response::Allowlist { entries }),
            ),
            Request::ListProfiles { limit } => reply(self.with_store(|s| {
                let mut profiles = Vec::new();
                for id in s.recent_profile_ids(limit.min(1000))? {
                    if let Some(p) = s.profile(&id)? {
                        profiles.push(whohack_ipc::ProfileSummary { path: s.app_path(&id)?.unwrap_or_default(),
                            category: p.category, observed: s.observed_profile_tags(&id)?.iter().map(ToString::to_string).collect(), app_id: id });
                    }
                }
                Ok(Response::Profiles { profiles, categories: whohack_tags::profile::CATEGORIES.iter().map(|s| (*s).to_string()).collect() })
            })),
            Request::SetCategory { app_id, category } => {
                match whohack_tags::CategoryTemplate::builtin(&category) {
                    Err(e) => Response::Error { message: e.to_string() },
                    Ok(t) => reply(self.with_store(|s| {
                        if s.profile(&app_id)?.is_none() { return Ok(Response::Error { message: "unknown app".into() }); }
                        s.upsert_profile(&whohack_core::store::ProfileRecord { app_id, category: t.category,
                            expected: t.expected.into_iter().map(Into::into).collect(), never: t.never,
                            learning_until: None, updated_at: now_ms() })?;
                        Ok(Response::Ok)
                    })),
                }
            },
            Request::RecentEvents { limit } => reply(
                self.with_store(|s| s.recent_tagged_events(limit.min(5_000)))
                    .map(|events| Response::Events {
                        events: events
                            .iter()
                            .map(|(e, tags)| {
                                let mut row = summarize_event(e);
                                if !tags.is_empty() {
                                    row.detail.push_str(&format!(
                                        " [{}]",
                                        tags.iter()
                                            .map(|t| t.as_str())
                                            .collect::<Vec<_>>()
                                            .join(", ")
                                    ));
                                }
                                row
                            })
                            .collect(),
                    }),
            ),
            Request::Allow { entry } => {
                reply(self.with_store(|s| s.allow(&entry)).map(|_| Response::Ok))
            }
            Request::Disallow { entry } => reply(
                self.with_store(|s| s.disallow(&entry))
                    .map(|_| Response::Ok),
            ),
            // Handled by the connection loop; reaching here is harmless.
            Request::Subscribe => Response::Ok,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use whohack_core::{Action, AllowEntry, Verdict, VerdictLabel};

    fn handler() -> (
        ServiceHandler,
        Arc<ServiceState>,
        broadcast::Receiver<PushEvent>,
    ) {
        let state = Arc::new(ServiceState::new(
            ResponseMode::Prompt,
            vec!["test".into()],
            true,
        ));
        let (tx, rx) = broadcast::channel(8);
        (
            ServiceHandler::new(Store::open_in_memory().unwrap(), state.clone(), tx),
            state,
            rx,
        )
    }

    #[test]
    fn status_mode_and_allowlist() {
        let (h, state, mut rx) = handler();
        match h.handle(Request::Status) {
            Response::Status { status } => {
                assert_eq!(status.mode, ResponseMode::Prompt);
                assert_eq!(status.collectors, vec!["test".to_string()]);
                assert_eq!(status.open_alerts, 0);
            }
            r => panic!("{r:?}"),
        }
        assert_eq!(
            h.handle(Request::SetMode {
                mode: ResponseMode::Monitor
            }),
            Response::Ok
        );
        assert_eq!(state.mode(), ResponseMode::Monitor);
        assert_eq!(
            rx.try_recv().unwrap(),
            PushEvent::ModeChanged {
                mode: ResponseMode::Monitor
            }
        );
        assert_eq!(
            effective_mode(&h.store.lock().unwrap(), ResponseMode::Prompt, false),
            ResponseMode::Monitor
        );

        let e = AllowEntry::App {
            app_id: "sig:Contoso/app.exe".into(),
        };
        assert_eq!(h.handle(Request::Allow { entry: e.clone() }), Response::Ok);
        assert_eq!(
            h.handle(Request::ListAllowlist),
            Response::Allowlist {
                entries: vec![e.clone()]
            }
        );
        assert_eq!(h.handle(Request::Disallow { entry: e }), Response::Ok);
    }

    #[test]
    fn timeline_rows() {
        let (h, _, _) = handler();
        h.store
            .lock()
            .unwrap()
            .insert_event(&Event {
                ts: 5,
                pid: 9,
                kind: EventKind::NetConnect {
                    remote_ip: "203.0.113.5".parse().unwrap(),
                    remote_port: 443,
                    proto: whohack_core::Proto::Tcp,
                    domain: Some("example.com".into()),
                    dns_before: true,
                },
            })
            .unwrap();
        match h.handle(Request::RecentEvents { limit: 10 }) {
            Response::Events { events } => {
                assert_eq!(events.len(), 1);
                assert_eq!(events[0].kind, "net_connect");
                assert_eq!(events[0].detail, "203.0.113.5:443/tcp example.com");
            }
            r => panic!("{r:?}"),
        }
    }

    #[test]
    fn alert_round_trip_to_feedback() {
        let (h, _, _) = handler();
        let id = {
            let s = h.store.lock().unwrap();
            s.insert_alert(
                1_000,
                42,
                "sha256:abcd",
                &Verdict {
                    label: VerdictLabel::Suspicious,
                    p: [0.2, 0.6, 0.2],
                    tactic: "none".into(),
                    severity: 1.0,
                    action: Action::AskUser,
                    tier: 1,
                    reasons: vec!["Example reason.".into()],
                },
            )
            .unwrap()
        };
        match h.handle(Request::ListAlerts { limit: 10 }) {
            Response::Alerts { alerts } => {
                assert_eq!(alerts.len(), 1);
                assert_eq!(alerts[0].app_name, "abcd");
                assert_eq!(alerts[0].explanation, "Example reason.");
                assert!(!alerts[0].resolved);
            }
            r => panic!("{r:?}"),
        }
        assert_eq!(
            h.handle(Request::Resolve {
                alert_id: id,
                action: Action::Allow,
                note: Some("mine".into())
            }),
            Response::Ok
        );
        let s = h.store.lock().unwrap();
        assert_eq!(s.alert(id).unwrap().unwrap().verdict.action, Action::Allow);
        assert_eq!(
            s.feedback_for_alert(id).unwrap()[0].user_action,
            Action::Allow
        );
        drop(s);
        assert!(matches!(
            h.handle(Request::Resolve {
                alert_id: 999,
                action: Action::Allow,
                note: None
            }),
            Response::Error { .. }
        ));
    }
}
