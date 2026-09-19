use crate::auth::PeerIdentity;
use crate::ipc::dispatch::dispatch;
use crate::ipc::protocol::{encode_frame, MAX_FRAME_BYTES};
use crate::state::HelperState;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub async fn serve_connection<S>(
    mut stream: S,
    peer: PeerIdentity,
    state: Arc<HelperState>,
) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    loop {
        let mut len_buf = [0u8; 4];
        if stream.read_exact(&mut len_buf).await.is_err() {
            return Ok(());
        }
        let len = u32::from_le_bytes(len_buf);
        if len == 0 || len > MAX_FRAME_BYTES {
            return Ok(());
        }
        let mut payload = vec![0u8; len as usize];
        stream.read_exact(&mut payload).await?;
        let response = dispatch(&payload, &peer, &state).await;
        let encoded = serde_json::to_vec(&response)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        let frame = encode_frame(&encoded)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        stream.write_all(&frame).await?;
    }
}
