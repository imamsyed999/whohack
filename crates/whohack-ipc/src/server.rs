//! Per-connection server logic, independent of the transport.

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{broadcast, mpsc};

use crate::auth::token_eq;
use crate::frame::{FrameError, read_frame, write_frame};
use crate::protocol::{ClientMsg, PROTOCOL_VERSION, PushEvent, Request, Response, ServerMsg};

/// How long a client has to authenticate.
pub const HELLO_TIMEOUT: Duration = Duration::from_secs(5);

/// Service-side request handling. Called on a blocking thread, so it may
/// use the (synchronous) store.
pub trait Handler: Send + Sync + 'static {
    fn handle(&self, request: Request) -> Response;
}

/// Serves one connection: authenticate, then answer requests and (after
/// `Subscribe`) forward push events until either side closes.
pub async fn serve_connection<S>(
    stream: S,
    token: Arc<str>,
    handler: Arc<dyn Handler>,
    pushes: broadcast::Sender<PushEvent>,
) -> Result<(), FrameError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut r, mut w) = tokio::io::split(stream);
    let hello = tokio::time::timeout(HELLO_TIMEOUT, read_frame::<_, ClientMsg>(&mut r)).await;
    match hello {
        Ok(Ok(ClientMsg::Hello { token: t, version }))
            if token_eq(&t, &token) && version == PROTOCOL_VERSION => {}
        Ok(Ok(ClientMsg::Hello { version, .. })) if version != PROTOCOL_VERSION => {
            let message = format!(
                "protocol version {version} not supported (service speaks {PROTOCOL_VERSION})"
            );
            let _ = write_frame(&mut w, &ServerMsg::Error { message }).await;
            return Ok(());
        }
        _ => {
            tracing::warn!("IPC client failed authentication");
            let _ = write_frame(
                &mut w,
                &ServerMsg::Error {
                    message: "authentication failed".into(),
                },
            )
            .await;
            return Ok(());
        }
    }
    write_frame(
        &mut w,
        &ServerMsg::Welcome {
            version: PROTOCOL_VERSION,
            service_version: env!("CARGO_PKG_VERSION").into(),
        },
    )
    .await?;

    // A dedicated reader keeps frame reads cancel-safe.
    let (req_tx, mut req_rx) = mpsc::channel::<(u64, Request)>(32);
    let reader = tokio::spawn(async move {
        loop {
            match read_frame::<_, ClientMsg>(&mut r).await {
                Ok(ClientMsg::Request { id, request }) => {
                    if req_tx.send((id, request)).await.is_err() {
                        break;
                    }
                }
                Ok(ClientMsg::Hello { .. }) => {} // ignore repeated hello
                Err(_) => break,
            }
        }
    });

    let mut push_rx: Option<broadcast::Receiver<PushEvent>> = None;
    let result = loop {
        let next_push = async {
            match push_rx.as_mut() {
                Some(rx) => rx.recv().await,
                None => std::future::pending().await,
            }
        };
        tokio::select! {
            req = req_rx.recv() => {
                let Some((id, request)) = req else { break Ok(()) };
                if matches!(request, Request::Subscribe) {
                    push_rx = Some(pushes.subscribe());
                    if let Err(e) = write_frame(&mut w, &ServerMsg::Response { id, response: Response::Ok }).await {
                        break Err(e);
                    }
                    continue;
                }
                let h = handler.clone();
                let response = tokio::task::spawn_blocking(move || h.handle(request))
                    .await
                    .unwrap_or_else(|e| Response::Error { message: format!("handler failed: {e}") });
                if let Err(e) = write_frame(&mut w, &ServerMsg::Response { id, response }).await {
                    break Err(e);
                }
            }
            ev = next_push => match ev {
                Ok(event) => {
                    if let Err(e) = write_frame(&mut w, &ServerMsg::Push { event }).await {
                        break Err(e);
                    }
                }
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    tracing::warn!(missed = n, "IPC subscriber lagged");
                }
                Err(broadcast::error::RecvError::Closed) => push_rx = None,
            },
        }
    };
    reader.abort();
    result
}
