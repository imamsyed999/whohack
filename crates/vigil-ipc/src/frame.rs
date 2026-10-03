//! Length-prefixed JSON framing: a big-endian `u32` byte length, then that
//! many bytes of UTF-8 JSON. Frames above [`MAX_FRAME`] are rejected before
//! any allocation, so a misbehaving peer cannot exhaust memory.

use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const MAX_FRAME: usize = 1 << 20;

#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("frame of {0} bytes exceeds the {MAX_FRAME}-byte limit")]
    TooLarge(usize),
    #[error("invalid message: {0}")]
    Json(#[from] serde_json::Error),
    #[error("connection closed")]
    Closed,
}

pub async fn write_frame<W, T>(w: &mut W, msg: &T) -> Result<(), FrameError>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    let body = serde_json::to_vec(msg)?;
    if body.len() > MAX_FRAME {
        return Err(FrameError::TooLarge(body.len()));
    }
    w.write_all(&(body.len() as u32).to_be_bytes()).await?;
    w.write_all(&body).await?;
    w.flush().await?;
    Ok(())
}

pub async fn read_frame<R, T>(r: &mut R) -> Result<T, FrameError>
where
    R: AsyncRead + Unpin,
    T: DeserializeOwned,
{
    let mut len = [0u8; 4];
    match r.read_exact(&mut len).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Err(FrameError::Closed),
        Err(e) => return Err(e.into()),
    }
    let len = u32::from_be_bytes(len) as usize;
    if len > MAX_FRAME {
        return Err(FrameError::TooLarge(len));
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body).await?;
    Ok(serde_json::from_slice(&body)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{ClientMsg, Request};

    #[tokio::test]
    async fn round_trip_and_limits() {
        let (mut a, mut b) = tokio::io::duplex(4096);
        let msg = ClientMsg::Request {
            id: 5,
            request: Request::Status,
        };
        write_frame(&mut a, &msg).await.unwrap();
        let got: ClientMsg = read_frame(&mut b).await.unwrap();
        assert_eq!(got, msg);

        // Oversized length prefix is rejected without reading the body.
        a.write_all(&((MAX_FRAME as u32) + 1).to_be_bytes())
            .await
            .unwrap();
        assert!(matches!(
            read_frame::<_, ClientMsg>(&mut b).await,
            Err(FrameError::TooLarge(_))
        ));

        // Garbage JSON.
        a.write_all(&3u32.to_be_bytes()).await.unwrap();
        a.write_all(b"{x}").await.unwrap();
        assert!(matches!(
            read_frame::<_, ClientMsg>(&mut b).await,
            Err(FrameError::Json(_))
        ));

        drop(a);
        assert!(matches!(
            read_frame::<_, ClientMsg>(&mut b).await,
            Err(FrameError::Closed)
        ));
    }
}
