//! Serves tray-UI requests (SPEC §14) from the service's state and store.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, RwLock};
use std::time::Instant;

use tokio::sync::broadcast;
use vigil_core::store::AlertRecord;
use vigil_core::time::now_ms;
use vigil_core::{ResponseMode, Store};
use vigil_ipc::{AlertSummary, Handler, PushEvent, Request, Response, StatusInfo};

/// Store setting key for the runtime response-mode override.
pub const MODE_SETTING: &str = "mode";

/// Live service state shared with the IPC handler.
#[derive(Debug)]
pub struct ServiceState {
    pub mode: RwLock<ResponseMode>,
    pub collectors: Vec<String>,
    pub dns_visible: bool,
    pub model: Option<String>,
    pub started: Instant,
    pub events_seen: AtomicU64,
}

impl ServiceState {
    pub fn new(mode: ResponseMode, collectors: Vec<String>, dns_visible: bool) -> Self {
        ServiceState {
            mode: RwLock::new(mode),
            collectors,
            dns_visible,
            model: None,
            started: Instant::now(),
            events_seen: AtomicU64::new(0),
        }
    }

    pub fn mode(&self) -> ResponseMode {
        self.mode.read().map(|m| *m).unwrap_or_default()
    }
}

/// The effective mode at startup: a mode chosen in the UI (stored) wins
/// over the config file.
pub fn effective_mode(store: &Store, configured: ResponseMode) -> ResponseMode {
    store
        .setting(MODE_SETTING)
        .ok()
        .flatten()
        .and_then(|s| ResponseMode::parse(&s))
        .unwrap_or(configured)
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
        resolved: a.status == vigil_core::store::AlertStatus::Resolved,
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
        f: impl FnOnce(&Store) -> Result<T, vigil_core::StoreError>,
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
        match request {
            Request::Status => {
                reply(
                    self.with_store(|s| s.open_alerts())
                        .map(|open| Response::Status {
                            status: StatusInfo {
                                service_version: env!("CARGO_PKG_VERSION").into(),
                                mode: self.state.mode(),
                                collectors: self.state.collectors.clone(),
                                dns_visible: self.state.dns_visible,
                                model: self.state.model.clone(),
                                model_loaded: false,
                                uptime_s: self.state.started.elapsed().as_secs(),
                                events_seen: self.state.events_seen.load(Ordering::Relaxed),
                                open_alerts: open.len() as u32,
                            },
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
            } => reply(self.with_store(|s| {
                if s.alert(alert_id)?.is_none() {
                    return Ok(Response::Error {
                        message: format!("no alert {alert_id}"),
                    });
                }
                s.insert_feedback(alert_id, now_ms(), action, note.as_deref())?;
                s.resolve_alert(alert_id)?;
                Ok(Response::Ok)
            })),
            Request::SetMode { mode } => reply(
                self.with_store(|s| s.set_setting(MODE_SETTING, mode.as_str()))
                    .map(|()| {
                        if let Ok(mut m) = self.state.mode.write() {
                            *m = mode;
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
    use vigil_core::{Action, AllowEntry, Verdict, VerdictLabel};

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
            effective_mode(&h.store.lock().unwrap(), ResponseMode::Prompt),
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
