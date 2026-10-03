//! Vigil local IPC (SPEC §14): authenticated, length-prefixed JSON between
//! the privileged service and the unprivileged tray UI.

pub mod auth;
pub mod client;
pub mod frame;
pub mod protocol;
pub mod server;
pub mod transport;

pub use client::{Client, ClientError};
pub use protocol::*;
pub use server::{Handler, serve_connection};

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use tokio::sync::broadcast;
    use vigil_core::ResponseMode;

    use super::*;

    struct Echo;
    impl Handler for Echo {
        fn handle(&self, request: Request) -> Response {
            match request {
                Request::SetMode { .. } => Response::Ok,
                Request::ListAllowlist => Response::Allowlist { entries: vec![] },
                _ => Response::Error {
                    message: "unsupported".into(),
                },
            }
        }
    }

    #[tokio::test]
    async fn authenticated_session_requests_and_pushes() {
        let (client_end, server_end) = tokio::io::duplex(64 * 1024);
        let (push_tx, _) = broadcast::channel(16);
        let token: Arc<str> = Arc::from("secret");
        let server = tokio::spawn(serve_connection(
            server_end,
            token,
            Arc::new(Echo),
            push_tx.clone(),
        ));

        let mut c = Client::connect(client_end, "secret").await.unwrap();
        assert!(!c.service_version.is_empty());
        assert_eq!(
            c.request(Request::SetMode {
                mode: ResponseMode::Monitor
            })
            .await
            .unwrap(),
            Response::Ok
        );
        assert_eq!(c.request(Request::Subscribe).await.unwrap(), Response::Ok);
        push_tx
            .send(PushEvent::ModeChanged {
                mode: ResponseMode::Monitor,
            })
            .unwrap();
        assert_eq!(
            c.next_push().await.unwrap(),
            PushEvent::ModeChanged {
                mode: ResponseMode::Monitor
            }
        );
        assert!(matches!(
            c.request(Request::ListAllowlist).await.unwrap(),
            Response::Allowlist { .. }
        ));
        drop(c);
        server.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn wrong_token_is_refused() {
        let (client_end, server_end) = tokio::io::duplex(4096);
        let (push_tx, _) = broadcast::channel(4);
        let server = tokio::spawn(serve_connection(
            server_end,
            Arc::from("secret"),
            Arc::new(Echo),
            push_tx,
        ));
        match Client::connect(client_end, "guess").await {
            Err(ClientError::Refused(m)) => assert!(m.contains("authentication")),
            other => panic!("expected refusal, got {other:?}"),
        }
        server.await.unwrap().unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn unix_socket_end_to_end() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vigil.sock");
        let (push_tx, _) = broadcast::channel(4);
        let ep = path.to_string_lossy().into_owned();
        let srv = tokio::spawn(async move {
            transport::run_server(&ep, Arc::from("tok"), Arc::new(Echo), push_tx).await
        });
        let mut tries = 0;
        let stream = loop {
            match transport::unix::connect(&path).await {
                Ok(s) => break s,
                Err(_) if tries < 50 => {
                    tries += 1;
                    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                }
                Err(e) => panic!("connect: {e}"),
            }
        };
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o660
        );
        let mut c = Client::connect(stream, "tok").await.unwrap();
        assert_eq!(
            c.request(Request::SetMode {
                mode: ResponseMode::Prompt
            })
            .await
            .unwrap(),
            Response::Ok
        );
        srv.abort();
    }
}
