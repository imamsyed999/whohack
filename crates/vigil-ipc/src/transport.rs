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
        "/run/vigil/vigil.sock".into()
    }
    #[cfg(target_os = "macos")]
    {
        "/var/run/vigil/vigil.sock".into()
    }
    #[cfg(windows)]
    {
        r"\\.\pipe\vigil".into()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        "vigil.sock".into()
    }
}

#[cfg(unix)]
pub mod unix {
    use std::path::Path;

    use tokio::net::{UnixListener, UnixStream};

    pub fn bind(path: &Path) -> std::io::Result<UnixListener> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        // A stale socket from a previous run blocks bind.
        if path.exists() {
            std::fs::remove_file(path)?;
        }
        let l = UnixListener::bind(path)?;
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))?;
        Ok(l)
    }

    pub async fn connect(path: &Path) -> std::io::Result<UnixStream> {
        UnixStream::connect(path).await
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
    #[cfg(unix)]
    {
        let listener = unix::bind(std::path::Path::new(endpoint))?;
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
        let mut server = windows::create(endpoint, true)?;
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
