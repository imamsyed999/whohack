//! Connection to the Vigil service over authenticated local IPC.
//!
//! The endpoint and token location come from the service's config file
//! (`VIGIL_CONFIG` or the per-OS default); the token is re-read on every
//! connect because the service generates a new one each time it starts.

use std::path::PathBuf;

use tokio::sync::Mutex;
use vigil_core::Config;
use vigil_ipc::transport::{IpcStream, connect};
use vigil_ipc::{Client, Request, Response};

pub type IpcClient = Client<Box<dyn IpcStream>>;

#[derive(Debug, Clone)]
pub struct Settings {
    pub endpoint: String,
    pub token_file: PathBuf,
}

impl Settings {
    pub fn load() -> Self {
        let path = std::env::var_os("VIGIL_CONFIG")
            .map(PathBuf::from)
            .unwrap_or_else(Config::default_path);
        let cfg = Config::load(&path).unwrap_or_else(|_| Config::default_for_os());
        Settings {
            endpoint: cfg.ipc.endpoint.clone(),
            token_file: cfg.paths.data_dir.join("ipc.token"),
        }
    }

    pub async fn open(&self) -> Result<IpcClient, String> {
        let token = vigil_ipc::auth::read_token_file(&self.token_file).map_err(|e| {
            format!(
                "cannot read {}: {e} (is the Vigil service running?)",
                self.token_file.display()
            )
        })?;
        let stream = connect(&self.endpoint).await.map_err(|e| {
            format!(
                "cannot connect to {}: {e} (is the Vigil service running?)",
                self.endpoint
            )
        })?;
        Client::connect(stream, &token)
            .await
            .map_err(|e| e.to_string())
    }
}

/// Request connection, opened lazily and reopened after any failure.
pub struct Conn {
    pub settings: Settings,
    client: Mutex<Option<IpcClient>>,
}

impl Conn {
    pub fn new(settings: Settings) -> Self {
        Conn {
            settings,
            client: Mutex::new(None),
        }
    }

    pub async fn call(&self, request: Request) -> Result<Response, String> {
        let mut guard = self.client.lock().await;
        if guard.is_none() {
            *guard = Some(self.settings.open().await?);
        }
        let Some(client) = guard.as_mut() else {
            return Err("not connected".into());
        };
        match client.request(request).await {
            Ok(Response::Error { message }) => Err(message),
            Ok(r) => Ok(r),
            Err(e) => {
                *guard = None;
                Err(e.to_string())
            }
        }
    }
}
