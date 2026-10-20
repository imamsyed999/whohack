//! Client side (used by the tray UI and tests).

use std::collections::VecDeque;

use tokio::io::{AsyncRead, AsyncWrite, ReadHalf, WriteHalf};

use crate::frame::{FrameError, read_frame, write_frame};
use crate::protocol::{ClientMsg, PROTOCOL_VERSION, PushEvent, Request, Response, ServerMsg};

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error(transparent)]
    Frame(#[from] FrameError),
    #[error("service refused the connection: {0}")]
    Refused(String),
    #[error("unexpected message from service")]
    Protocol,
}

#[derive(Debug)]
pub struct Client<S> {
    r: ReadHalf<S>,
    w: WriteHalf<S>,
    next_id: u64,
    pushes: VecDeque<PushEvent>,
    pub service_version: String,
}

impl<S: AsyncRead + AsyncWrite + Unpin> Client<S> {
    /// Authenticates with `token` and waits for the service's welcome.
    pub async fn connect(stream: S, token: &str) -> Result<Self, ClientError> {
        let (mut r, mut w) = tokio::io::split(stream);
        write_frame(
            &mut w,
            &ClientMsg::Hello {
                token: token.into(),
                version: PROTOCOL_VERSION,
            },
        )
        .await?;
        match read_frame::<_, ServerMsg>(&mut r).await? {
            ServerMsg::Welcome {
                service_version, ..
            } => Ok(Client {
                r,
                w,
                next_id: 1,
                pushes: VecDeque::new(),
                service_version,
            }),
            ServerMsg::Error { message } => Err(ClientError::Refused(message)),
            _ => Err(ClientError::Protocol),
        }
    }

    /// Sends a request and waits for its response; pushes received meanwhile
    /// are queued for [`next_push`](Self::next_push).
    pub async fn request(&mut self, request: Request) -> Result<Response, ClientError> {
        let id = self.next_id;
        self.next_id += 1;
        write_frame(&mut self.w, &ClientMsg::Request { id, request }).await?;
        loop {
            match read_frame::<_, ServerMsg>(&mut self.r).await? {
                ServerMsg::Response { id: rid, response } if rid == id => return Ok(response),
                ServerMsg::Response { .. } => return Err(ClientError::Protocol),
                ServerMsg::Push { event } => self.pushes.push_back(event),
                ServerMsg::Error { message } => return Err(ClientError::Refused(message)),
                ServerMsg::Welcome { .. } => return Err(ClientError::Protocol),
            }
        }
    }

    /// Next push event (after `Request::Subscribe`).
    pub async fn next_push(&mut self) -> Result<PushEvent, ClientError> {
        if let Some(e) = self.pushes.pop_front() {
            return Ok(e);
        }
        match read_frame::<_, ServerMsg>(&mut self.r).await? {
            ServerMsg::Push { event } => Ok(event),
            ServerMsg::Error { message } => Err(ClientError::Refused(message)),
            _ => Err(ClientError::Protocol),
        }
    }
}
