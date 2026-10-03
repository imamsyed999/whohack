//! The service runtime shared by `--run` and `--monitor`: collectors →
//! pipeline → bus, plus the store writer and (for `--run`) the IPC server.

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::sync::broadcast;
use tokio::task::JoinHandle;
use vigil_core::{Config, EventBus, Observation, Store};
use vigil_ipc::PushEvent;

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
        .thread_name("vigil-worker")
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
    pipeline: Pipeline,
    bus: EventBus<Observation>,
    writer: Option<StoreWriter>,
    ipc: Option<JoinHandle<()>>,
    counter: JoinHandle<()>,
    pub state: Arc<ServiceState>,
    pub pushes: broadcast::Sender<PushEvent>,
}

/// Starts collection on `bus` (subscribe consumers before calling).
pub async fn start(cfg: &Config, opts: Options, bus: EventBus<Observation>) -> Result<Running> {
    let selection = vigil_collect::select(&cfg.collect)?;
    for note in &selection.notes {
        tracing::info!("{note}");
        eprintln!("vigil: {note}");
    }
    let collectors: Vec<String> = selection
        .collectors
        .iter()
        .map(|c| c.name().to_string())
        .collect();

    let db = cfg.db_path();
    let open_store = || Store::open(&db).with_context(|| format!("database {}", db.display()));
    let mode = if opts.store || opts.ipc {
        effective_mode(&open_store()?, cfg.mode)
    } else {
        cfg.mode
    };
    let state = Arc::new(ServiceState::new(mode, collectors, selection.dns_visible));
    let (pushes, _) = broadcast::channel(PUSH_CAPACITY);

    let writer = if opts.store {
        Some(StoreWriter::start(
            open_store()?,
            bus.subscribe(),
            cfg.storage.event_retention_days,
        ))
    } else {
        None
    };

    let ipc = if opts.ipc {
        let token = vigil_ipc::auth::generate_token();
        let token_file = cfg.paths.data_dir.join("ipc.token");
        vigil_ipc::auth::write_token_file(&token_file, &token)
            .with_context(|| format!("writing {}", token_file.display()))?;
        let handler = Arc::new(ServiceHandler::new(
            open_store()?,
            state.clone(),
            pushes.clone(),
        ));
        let endpoint = cfg.ipc.endpoint.clone();
        let p = pushes.clone();
        Some(tokio::spawn(async move {
            if let Err(e) =
                vigil_ipc::transport::run_server(&endpoint, Arc::from(token.as_str()), handler, p)
                    .await
            {
                tracing::error!(error = %e, endpoint, "IPC server stopped");
            }
        }))
    } else {
        None
    };

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

    let taint = stages::taint_engine(cfg);
    let pipeline = Pipeline::start(
        selection.collectors,
        selection.dns_visible,
        taint,
        bus.clone(),
    );
    tracing::info!(mode = state.mode().as_str(), "Vigil service started");
    Ok(Running {
        pipeline,
        bus,
        writer,
        ipc,
        counter,
        state,
        pushes,
    })
}

impl Running {
    /// Stops collection, flushes every stage, and waits for the store writer.
    pub async fn shutdown(self) {
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
        tracing::info!(published, stored, "Vigil service stopped");
    }
}

/// `--run`: the long-running service (collection, storage, IPC).
pub fn run(cfg: &Config) -> Result<()> {
    let _log = crate::logging::init(&cfg.logging, &cfg.paths.log_dir)?;
    block_on(async {
        let bus = EventBus::<Observation>::new(BUS_CAPACITY);
        let running = start(
            cfg,
            Options {
                store: true,
                ipc: true,
            },
            bus,
        )
        .await?;
        shutdown_signal().await;
        running.shutdown().await;
        Ok(())
    })
}
