//! The service runtime shared by `--run` and `--monitor`: collectors →
//! pipeline → bus, plus the store writer and (for `--run`) the IPC server.

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::sync::broadcast;
use tokio::task::JoinHandle;
use whohack_core::{Config, EventBus, Observation, Store};
use whohack_ipc::PushEvent;

use crate::ipc_handler::{ServiceHandler, ServiceState, effective_mode};
use crate::pipeline::Pipeline;
use crate::stages;
use crate::store_writer::StoreWriter;

pub const BUS_CAPACITY: usize = 16_384;
const PUSH_CAPACITY: usize = 256;

#[derive(Debug, Clone, Copy)]
pub struct Options {
    pub store: bool,
    pub ipc: bool,
}

/// Runs `fut` on a multi-threaded runtime and shuts it down with a bounded wait.
pub fn block_on<F: std::future::Future<Output = Result<()>>>(fut: F) -> Result<()> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("whohack-worker")
        .build()
        .context("tokio runtime")?;
    let result = rt.block_on(fut);
    rt.shutdown_timeout(Duration::from_secs(3));
    result
}

/// Resolves on Ctrl-C, or SIGTERM on Unix (service managers stop with it).
pub async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        match signal(SignalKind::terminate()) {
            Ok(mut term) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = term.recv() => {}
                }
            }
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

#[derive(Debug)]
pub struct Running {
    _instance_lock: Option<std::fs::File>,
    pipeline: Pipeline,
    bus: EventBus<Observation>,
    writer: Option<StoreWriter>,
    ipc: Option<JoinHandle<()>>,
    counter: JoinHandle<()>,
    decisions: Option<crate::decisions::Worker>,
    pub state: Arc<ServiceState>,
    pub pushes: broadcast::Sender<PushEvent>,
}

/// Starts collection on `bus` (subscribe consumers before calling).
pub async fn start(cfg: &Config, opts: Options, bus: EventBus<Observation>) -> Result<Running> {
    let instance_lock = if opts.store || opts.ipc {
        std::fs::create_dir_all(&cfg.paths.data_dir)?;
        let lock = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(cfg.paths.data_dir.join("service.lock"))?;
        lock.try_lock().map_err(|e| {
            anyhow::anyhow!(
                "cannot lock service data directory (another instance may be running): {e}"
            )
        })?;
        Some(lock)
    } else {
        None
    };
    let selection = whohack_collect::select_with_sensitive(&cfg.collect, &cfg.sensitive)?;
    for note in &selection.notes {
        tracing::info!("{note}");
        eprintln!("whohack: {note}");
    }
    let collectors: Vec<String> = selection
        .collectors
        .iter()
        .map(|c| c.name().to_string())
        .collect();

    let db = cfg.db_path();
    let open_store = || Store::open(&db).with_context(|| format!("database {}", db.display()));
    let response = if opts.store {
        Some(
            whohack_respond::Manager::open(
                cfg.paths.data_dir.clone(),
                cfg.response.enabled,
                whohack_respond::native_backend(),
            )?
            .with_automatic(cfg.response.automatic)
            .with_download_pause(cfg.response.pause_downloads),
        )
    } else {
        None
    };
    let mode = if opts.store || opts.ipc {
        effective_mode(
            &open_store()?,
            cfg.mode,
            response
                .as_ref()
                .is_some_and(|r| r.capabilities().network || r.capabilities().suspend),
        )
    } else {
        whohack_core::ResponseMode::Monitor
    };
    let mode = if mode == whohack_core::ResponseMode::Auto
        && !response.as_ref().is_some_and(|r| r.automatic_enabled())
    {
        whohack_core::ResponseMode::Prompt
    } else {
        mode
    };
    let mut state =
        ServiceState::new(mode, collectors, selection.dns_visible).with_response(response);
    state.tier1_onnx = cfg.tier1.model.is_some();
    state.collection = selection.health.clone();
    state.collection_notes = selection.notes.clone();
    if opts.ipc {
        *state.integrity_issues.get_mut().unwrap() =
            vec!["Integrity verification has not completed".into()];
    }
    let manifest = cfg
        .decision
        .manifest
        .as_deref()
        .map(whohack_decide::manifest::Manifest::load)
        .transpose()?;
    let secondary = cfg
        .decision
        .tier3_manifest
        .as_deref()
        .map(whohack_decide::manifest::Manifest::load)
        .transpose()?;
    let thresholds = manifest
        .as_ref()
        .map(|m| m.thresholds.clone())
        .unwrap_or_default();
    if let Some(m) = &manifest {
        state.model = Some(format!(
            "{}@{} ({})",
            m.model_name,
            m.revision,
            if m.qualified()? {
                "validated"
            } else {
                "advisory"
            }
        ));
    }
    let state = Arc::new(state);
    let (pushes, _) = broadcast::channel(PUSH_CAPACITY);

    let (decisions, decision_queue) = if opts.store
        && let Some(m) = &manifest
    {
        let qualified = m.qualified()?
            && secondary
                .as_ref()
                .map(|s| s.qualified())
                .transpose()?
                .unwrap_or(true);
        let models = crate::decisions::Models {
            primary: Box::new(m.sidecar(false)?),
            secondary: secondary
                .as_ref()
                .map(|s| {
                    s.sidecar(true)
                        .map(|m| Box::new(m) as Box<dyn whohack_decide::DecisionModel>)
                })
                .transpose()?,
            revision: m.revision.clone(),
            qualified,
            thresholds: thresholds.clone(),
        };
        let (worker, queue) =
            crate::decisions::Worker::start(open_store()?, state.clone(), pushes.clone(), models)?;
        (Some(worker), Some(queue))
    } else {
        (None, None)
    };

    let listener = if opts.ipc {
        Some(
            whohack_ipc::transport::BoundServer::bind(&cfg.ipc.endpoint)
                .await
                .with_context(|| format!("binding IPC {}", cfg.ipc.endpoint))?,
        )
    } else {
        None
    };
    let alerts = if opts.store {
        Some(
            crate::alerts::AlertEngine::new(cfg.paths.rules_dir.join("tier0"), pushes.clone())?
                .with_state(state.clone())
                .with_decisions(decision_queue, thresholds)
                .with_intelligence(cfg.paths.data_dir.join("intel.json"))?
                .with_scorer(&cfg.tier1)?,
        )
    } else {
        None
    };
    let taint = stages::taint_engine(cfg);

    let writer_store = if opts.store {
        Some(open_store()?)
    } else {
        None
    };

    let ipc = if let Some(listener) = listener {
        let token = whohack_ipc::auth::generate_token();
        let token_file = cfg.paths.data_dir.join("ipc.token");
        whohack_ipc::auth::write_token_file(&token_file, &token)
            .with_context(|| format!("writing {}", token_file.display()))?;
        let handler = Arc::new(ServiceHandler::new(
            open_store()?,
            state.clone(),
            pushes.clone(),
        ));
        let endpoint = cfg.ipc.endpoint.clone();
        let p = pushes.clone();
        Some(tokio::spawn(async move {
            if let Err(e) = listener.run(Arc::from(token.as_str()), handler, p).await {
                tracing::error!(error = %e, endpoint, "IPC server stopped");
            }
        }))
    } else {
        None
    };

    let writer = writer_store.map(|store| {
        StoreWriter::start_with_alerts(
            store,
            bus.subscribe(),
            cfg.storage.event_retention_days,
            alerts,
        )
    });

    let counter = {
        let mut rx = bus.subscribe();
        let st = state.clone();
        tokio::spawn(async move {
            loop {
                match rx.recv().await {
                    Ok(_) => {
                        st.events_seen.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        st.events_seen.fetch_add(n, Ordering::Relaxed);
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        })
    };

    let pipeline = Pipeline::start_with_health(
        selection.collectors,
        selection.dns_visible,
        taint,
        stages::tagger(cfg, selection.dns_visible),
        bus.clone(),
        selection.health,
    );
    tracing::info!(mode = state.mode().as_str(), "whohack service started");
    Ok(Running {
        _instance_lock: instance_lock,
        pipeline,
        bus,
        writer,
        ipc,
        counter,
        decisions,
        state,
        pushes,
    })
}

impl Running {
    /// Stops collection, flushes every stage, and waits for the store writer.
    pub async fn shutdown(self) {
        // Draining already accepted observations must not initiate new response.
        if let Ok(_gate) = self.state.decision_gate.lock()
            && let Ok(mut mode) = self.state.mode.write()
        {
            *mode = whohack_core::ResponseMode::Monitor;
        }
        if let Some(ipc) = self.ipc {
            ipc.abort();
        }
        let published = self.pipeline.shutdown().await;
        drop(self.bus);
        let _ = self.counter.await;
        let stored = match self.writer {
            Some(w) => tokio::task::spawn_blocking(move || w.join())
                .await
                .unwrap_or(0),
            None => 0,
        };
        if let Some(worker) = self.decisions {
            let _ = tokio::task::spawn_blocking(move || worker.shutdown()).await;
        }
        if self.state.response.is_some()
            && let Err(e) = self.state.with_responder(|m| m.shutdown())
        {
            tracing::error!(error=%e, "response cleanup failed during shutdown");
        }
        tracing::info!(published, stored, "whohack service stopped");
    }
}

/// How often detection content and config are re-verified.
const INTEGRITY_INTERVAL: Duration = Duration::from_secs(10);

/// Verifies the integrity manifest; logs and pushes a health alert on problems.
fn check_integrity(
    cfg: &Config,
    config_path: &std::path::Path,
    pushes: &broadcast::Sender<PushEvent>,
    state: &ServiceState,
) {
    let issues = match crate::integrity::verify(&cfg.paths.rules_dir, Some(config_path)) {
        Ok(problems) => problems.iter().map(ToString::to_string).collect::<Vec<_>>(),
        Err(e) => vec![format!("Integrity check could not complete: {e:#}")],
    };
    if let Ok(_gate) = state.decision_gate.lock()
        && let Ok(mut current) = state.integrity_issues.write()
    {
        *current = issues.clone();
    }
    if !issues.is_empty() {
        let message = format!(
            "Integrity verification failed; response disabled: {}",
            issues.join("; ")
        );
        tracing::error!("{message}");
        let _ = pushes.send(PushEvent::Health { ok: false, message });
    }
    if state.response.is_some() {
        match state.with_responder(|m| m.verify_active()) {
            Ok(problems) => {
                for message in problems {
                    tracing::error!("{message}");
                    let _ = pushes.send(PushEvent::Health { ok: false, message });
                }
            }
            Err(message) => {
                tracing::error!("{message}");
                let _ = pushes.send(PushEvent::Health { ok: false, message });
            }
        }
    }
}

/// `--run`: the long-running service (collection, storage, IPC, integrity),
/// until Ctrl-C or SIGTERM.
pub fn run(cfg: &Config, config_path: &std::path::Path) -> Result<()> {
    run_until(cfg, config_path, shutdown_signal())
}

/// Runs the service until `stop` resolves (a signal, or a service-manager stop).
pub fn run_until<F: std::future::Future<Output = ()>>(
    cfg: &Config,
    config_path: &std::path::Path,
    stop: F,
) -> Result<()> {
    let _log = crate::logging::init(&cfg.logging, &cfg.paths.log_dir)?;
    block_on(async {
        let bus = EventBus::<Observation>::new(BUS_CAPACITY);
        let opts = Options {
            store: true,
            ipc: true,
        };
        let running = start(cfg, opts, bus).await?;
        check_integrity(cfg, config_path, &running.pushes, &running.state);
        let mut ticker = tokio::time::interval(INTEGRITY_INTERVAL);
        ticker.tick().await; // the first tick is immediate
        let signal = stop;
        tokio::pin!(signal);
        loop {
            tokio::select! {
                _ = &mut signal => break,
                _ = ticker.tick() => check_integrity(cfg, config_path, &running.pushes, &running.state),
            }
        }
        running.shutdown().await;
        Ok(())
    })
}
