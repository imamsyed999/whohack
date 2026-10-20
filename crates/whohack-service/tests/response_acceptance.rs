//! Authenticated-handler contract with an inert responder. OS behavior is
//! separately exercised by whohack-respond's owned-child tests.
use anyhow::Result;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use whohack_core::{
    Action, FileInfo, Origin, PathClass, ProcessInfo, ResponseMode, SignState, Store, Verdict,
    VerdictLabel,
};
use whohack_ipc::{Handler, Request, Response};
use whohack_respond::{Backend, Capabilities, Lease, Manager};
use whohack_service::ipc_handler::{ServiceHandler, ServiceState};

#[derive(Debug)]
struct Fake(Arc<AtomicUsize>);
#[derive(Debug)]
struct Hold(Arc<AtomicUsize>);
impl Lease for Hold {
    fn release(&mut self) -> Result<()> {
        self.0.fetch_sub(1, Ordering::SeqCst);
        Ok(())
    }
}
impl Backend for Fake {
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            network: true,
            suspend: true,
            network_scope: "test executable scope".into(),
            ..Default::default()
        }
    }
    fn block(&mut self, p: &ProcessInfo) -> Result<Box<dyn Lease>> {
        anyhow::ensure!(p.start_time == 1234, "wrong captured identity");
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(Box::new(Hold(self.0.clone())))
    }
    fn suspend(&mut self, _: &ProcessInfo) -> Result<Box<dyn Lease>> {
        anyhow::bail!("simulated access denied")
    }
    fn terminate(&mut self, _: &ProcessInfo) -> Result<()> {
        anyhow::bail!("not used")
    }
}
fn target() -> ProcessInfo {
    ProcessInfo {
        downloaded_inputs: Vec::new(),
        pid: 12345,
        ppid: 1,
        start_time: 1234,
        exe: FileInfo {
            path: "C:/test/app.exe".into(),
            sha256: [1; 32],
            origin: Origin::Unknown,
            sign: SignState::Unsigned,
            yara_hits: vec![],
            first_seen: 1,
        },
        script: None,
        path_class: PathClass::Other,
        tainted: true,
        taint_root: None,
        app_id: "app".into(),
    }
}
fn verdict() -> Verdict {
    Verdict {
        label: VerdictLabel::Suspicious,
        p: [0.; 3],
        tactic: "none".into(),
        severity: 2.,
        action: Action::AskUser,
        tier: 0,
        reasons: vec!["test evidence".into()],
    }
}

#[test]
fn captured_identity_actions_feedback_and_release_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("test.db");
    let store = Store::open(&db).unwrap();
    let id = store.insert_alert(1, 12345, "app", &verdict()).unwrap();
    let n = Arc::new(AtomicUsize::new(0));
    let manager = Manager::open(dir.path().into(), true, Box::new(Fake(n.clone()))).unwrap();
    let state = Arc::new(
        ServiceState::new(ResponseMode::Monitor, vec![], false).with_response(Some(manager)),
    );
    let (tx, _) = tokio::sync::broadcast::channel(16);
    let handler = ServiceHandler::new(Store::open(&db).unwrap(), state, tx);
    let Response::Status { status } = handler.handle(Request::Status) else {
        panic!("status missing")
    };
    assert!(status.enforcement_available);
    assert!(!status.automatic_response_enabled);
    assert!(
        matches!(handler.handle(Request::SetMode { mode: ResponseMode::Auto }), Response::Error { message } if message.contains("confirmation"))
    );
    // Old alerts without a captured identity cannot control a recycled PID.
    assert!(matches!(
        handler.handle(Request::Resolve {
            alert_id: id,
            action: Action::BlockNetwork,
            note: None
        }),
        Response::Error { .. }
    ));
    assert_eq!(n.load(Ordering::SeqCst), 0);
    store.set_alert_target(id, &target()).unwrap();
    let mut replacement = target();
    replacement.start_time = 9999;
    store.set_alert_target(id, &replacement).unwrap();
    assert_eq!(store.alert_target(id).unwrap().unwrap().start_time, 1234);
    assert_eq!(
        handler.handle(Request::Resolve {
            alert_id: id,
            action: Action::BlockNetwork,
            note: None
        }),
        Response::Ok
    );
    assert_eq!(n.load(Ordering::SeqCst), 1);
    assert_eq!(store.feedback_for_alert(id).unwrap().len(), 1);
    assert_eq!(
        store.alert(id).unwrap().unwrap().verdict.action,
        Action::BlockNetwork
    );
    let Response::Responses { actions, .. } = handler.handle(Request::ListResponses) else {
        panic!("missing response history")
    };
    assert_eq!(actions.len(), 1);
    assert_eq!(actions[0].status, "active");
    assert_eq!(
        handler.handle(Request::ReleaseResponse {
            id: actions[0].id.clone()
        }),
        Response::Ok
    );
    assert_eq!(n.load(Ordering::SeqCst), 0);
    // A failed action remains open and is not mislabeled as successful feedback.
    let id = store.insert_alert(2, 12345, "app", &verdict()).unwrap();
    store.set_alert_target(id, &target()).unwrap();
    assert!(
        matches!(handler.handle(Request::Resolve {alert_id:id,action:Action::SuspendAndAsk,note:None}),Response::Error{message} if message.contains("access denied"))
    );
    assert!(store.feedback_for_alert(id).unwrap().is_empty());
    assert_eq!(
        store.alert(id).unwrap().unwrap().status,
        whohack_core::store::AlertStatus::Open
    );
}

#[test]
fn destination_history_survives_restart() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("history.db");
    let store = Store::open(&db).unwrap();
    assert!(
        store
            .observe_destination("app", "192.0.2.1:443/tcp", 1)
            .unwrap()
    );
    drop(store);
    let store = Store::open(&db).unwrap();
    assert!(
        !store
            .observe_destination("app", "192.0.2.1:443/tcp", 2)
            .unwrap()
    );
    assert!(
        store
            .observe_destination("another-app", "192.0.2.1:443/tcp", 2)
            .unwrap()
    );
}

#[test]
fn waiting_for_response_consent_does_not_lock_alert_reads() {
    use std::{sync::mpsc, time::Duration};
    #[derive(Debug)]
    struct Consent {
        entered: mpsc::Sender<()>,
        finish: mpsc::Receiver<()>,
    }
    impl Backend for Consent {
        fn capabilities(&self) -> Capabilities {
            Capabilities {
                network: true,
                ..Default::default()
            }
        }
        fn block(&mut self, _: &ProcessInfo) -> Result<Box<dyn Lease>> {
            self.entered.send(())?;
            self.finish.recv_timeout(Duration::from_secs(5))?;
            anyhow::bail!("consent cancelled")
        }
        fn suspend(&mut self, _: &ProcessInfo) -> Result<Box<dyn Lease>> {
            anyhow::bail!("unused")
        }
        fn terminate(&mut self, _: &ProcessInfo) -> Result<()> {
            anyhow::bail!("unused")
        }
    }
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("alerts.db")).unwrap();
    let id = store.insert_alert(1, 12345, "app", &verdict()).unwrap();
    store.set_alert_target(id, &target()).unwrap();
    let (entered, waiting) = mpsc::channel();
    let (finish, consent) = mpsc::channel();
    let manager = Manager::open(
        dir.path().into(),
        true,
        Box::new(Consent {
            entered,
            finish: consent,
        }),
    )
    .unwrap();
    let state = Arc::new(
        ServiceState::new(ResponseMode::Prompt, vec![], false).with_response(Some(manager)),
    );
    let (pushes, _) = tokio::sync::broadcast::channel(16);
    let handler = Arc::new(ServiceHandler::new(store, state, pushes));
    let resolving = handler.clone();
    let request = std::thread::spawn(move || {
        resolving.handle(Request::Resolve {
            alert_id: id,
            action: Action::BlockNetwork,
            note: None,
        })
    });
    waiting.recv_timeout(Duration::from_secs(3)).unwrap();
    let (send, receive) = mpsc::channel();
    let reading = std::thread::spawn(move || {
        let status = handler.handle(Request::Status);
        let mutation = handler.handle(Request::SetMode {
            mode: ResponseMode::Monitor,
        });
        let alerts = handler.handle(Request::ListAlerts { limit: 10 });
        send.send((status, mutation, alerts)).unwrap()
    });
    let result = receive.recv_timeout(Duration::from_secs(1));
    finish.send(()).unwrap();
    assert!(
        matches!(request.join().unwrap(), Response::Error { message } if message.contains("cancelled"))
    );
    reading.join().unwrap();
    assert!(
        matches!(result, Ok((Response::Status { .. }, Response::Error { .. }, Response::Alerts { alerts })) if alerts.len() == 1)
    );
}
