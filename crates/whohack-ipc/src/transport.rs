//! OS transports (SPEC §14).
//!
//! - Unix: a domain socket, mode 0660, so the service's group (the UI users)
//!   can connect; the token still gates every session.
//! - Windows: a named pipe whose DACL grants SYSTEM and Administrators full
//!   access and interactive users read/write; network logons are excluded.

use std::sync::Arc;

use tokio::sync::broadcast;

use crate::protocol::PushEvent;
use crate::server::{Handler, serve_connection};

/// Default endpoint for this OS.
pub fn default_endpoint() -> String {
    #[cfg(target_os = "linux")]
    {
        "/run/whohack/whohack.sock".into()
    }
    #[cfg(target_os = "macos")]
    {
        "/var/run/whohack/whohack.sock".into()
    }
    #[cfg(windows)]
    {
        r"\\.\pipe\whohack".into()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        "whohack.sock".into()
    }
}

#[cfg(unix)]
pub mod unix {
    use std::path::Path;

    use tokio::net::{UnixListener, UnixStream};

    pub async fn bind(path: &Path) -> std::io::Result<UnixListener> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        // Never replace a regular file, symlink, or a live service's socket.
        if let Ok(meta) = std::fs::symlink_metadata(path) {
            use std::os::unix::fs::FileTypeExt;
            if !meta.file_type().is_socket() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    "IPC endpoint is not a socket",
                ));
            }
            match tokio::time::timeout(
                std::time::Duration::from_millis(500),
                UnixStream::connect(path),
            )
            .await
            {
                Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
                    std::fs::remove_file(path)?
                }
                Ok(Err(e)) if e.kind() == std::io::ErrorKind::NotFound => {}
                _ => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::AddrInUse,
                        "IPC endpoint is already in use",
                    ));
                }
            }
        }
        let l = UnixListener::bind(path)?;
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))?;
        Ok(l)
    }

    pub async fn connect(path: &Path) -> std::io::Result<UnixStream> {
        UnixStream::connect(path).await
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        #[tokio::test]
        async fn preserves_files_and_live_sockets_but_recovers_stale_sockets() {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("v.sock");
            std::fs::write(&path, "keep me").unwrap();
            assert!(bind(&path).await.is_err());
            assert_eq!(std::fs::read_to_string(&path).unwrap(), "keep me");
            std::fs::remove_file(&path).unwrap();
            let first = bind(&path).await.unwrap();
            assert!(bind(&path).await.is_err());
            assert!(connect(&path).await.is_ok());
            drop(first);
            let _second = bind(&path).await.unwrap();
        }
    }
}

#[cfg(windows)]
pub mod windows {
    #![allow(unsafe_code)]

    use tokio::net::windows::named_pipe::{
        ClientOptions, NamedPipeClient, NamedPipeServer, ServerOptions,
    };
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};

    /// SYSTEM and Administrators: full; interactive users: read/write.
    const SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)";

    /// Owns a security descriptor allocated by the SDDL converter.
    struct Sd(PSECURITY_DESCRIPTOR);
    impl Drop for Sd {
        fn drop(&mut self) {
            // SAFETY: allocated with LocalAlloc by the converter; freed once.
            unsafe { LocalFree(self.0) };
        }
    }

    fn security_descriptor() -> std::io::Result<Sd> {
        let w: Vec<u16> = SDDL.encode_utf16().chain([0]).collect();
        let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        // SAFETY: w is NUL-terminated; sd receives a LocalAlloc'd descriptor.
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                w.as_ptr(),
                SDDL_REVISION_1,
                &mut sd,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(Sd(sd))
    }

    /// Creates one pipe instance with the restricted DACL.
    pub fn create(name: &str, first: bool) -> std::io::Result<NamedPipeServer> {
        let sd = security_descriptor()?;
        let mut sa = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: sd.0,
            bInheritHandle: 0,
        };
        // SAFETY: sa and the descriptor it points to are valid for this call.
        unsafe {
            ServerOptions::new()
                .first_pipe_instance(first)
                .reject_remote_clients(true)
                .create_with_security_attributes_raw(name, (&raw mut sa).cast())
        }
    }

    pub fn connect(name: &str) -> std::io::Result<NamedPipeClient> {
        ClientOptions::new().open(name)
    }
}

/// Any bidirectional IPC stream (Unix socket or named pipe).
pub trait IpcStream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> IpcStream for T {}

/// Connects to the service endpoint on this OS.
pub async fn connect(endpoint: &str) -> std::io::Result<Box<dyn IpcStream>> {
    #[cfg(unix)]
    {
        Ok(Box::new(
            unix::connect(std::path::Path::new(endpoint)).await?,
        ))
    }
    #[cfg(windows)]
    {
        Ok(Box::new(windows::connect(endpoint)?))
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = endpoint;
        Err(std::io::Error::other("unsupported OS"))
    }
}

/// Accepts connections on `endpoint` forever, serving each on its own task.
pub async fn run_server(
    endpoint: &str,
    token: Arc<str>,
    handler: Arc<dyn Handler>,
    pushes: broadcast::Sender<PushEvent>,
) -> std::io::Result<()> {
    BoundServer::bind(endpoint)
        .await?
        .run(token, handler, pushes)
        .await
}

/// Bind before announcing startup or replacing authentication credentials.
#[derive(Debug)]
pub struct BoundServer {
    endpoint: String,
    #[cfg(unix)]
    listener: tokio::net::UnixListener,
    #[cfg(windows)]
    listener: tokio::net::windows::named_pipe::NamedPipeServer,
}

impl BoundServer {
    pub async fn bind(endpoint: &str) -> std::io::Result<Self> {
        #[cfg(unix)]
        let listener = unix::bind(std::path::Path::new(endpoint)).await?;
        #[cfg(windows)]
        let listener = windows::create(endpoint, true)?;
        Ok(Self {
            endpoint: endpoint.into(),
            listener,
        })
    }

    pub async fn run(
        self,
        token: Arc<str>,
        handler: Arc<dyn Handler>,
        pushes: broadcast::Sender<PushEvent>,
    ) -> std::io::Result<()> {
        let endpoint = &self.endpoint;
        #[cfg(unix)]
        {
            let listener = self.listener;
            tracing::info!(endpoint, "IPC listening");
            loop {
                let (stream, _) = listener.accept().await?;
                let (t, h, p) = (token.clone(), handler.clone(), pushes.clone());
                tokio::spawn(async move {
                    if let Err(e) = serve_connection(stream, t, h, p).await {
                        tracing::debug!(error = %e, "IPC connection ended");
                    }
                });
            }
        }
        #[cfg(windows)]
        {
            let mut server = self.listener;
            tracing::info!(endpoint, "IPC listening");
            loop {
                server.connect().await?;
                let connected = server;
                server = windows::create(endpoint, false)?;
                let (t, h, p) = (token.clone(), handler.clone(), pushes.clone());
                tokio::spawn(async move {
                    if let Err(e) = serve_connection(connected, t, h, p).await {
                        tracing::debug!(error = %e, "IPC connection ended");
                    }
                });
            }
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = (endpoint, token, handler, pushes);
            Err(std::io::Error::other("unsupported OS"))
        }
    }
}
