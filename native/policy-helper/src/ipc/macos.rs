//! UNIX socket for Milestone 1.
//! TODO(platform): replace the local-uid check with XPC + a code-signing requirement.

use crate::auth::PeerIdentity;
use crate::ipc::serve::serve_connection;
use crate::state::HelperState;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::net::UnixListener;

pub async fn listen(socket_path: PathBuf, state: Arc<HelperState>) -> io::Result<()> {
    let _ = std::fs::remove_file(&socket_path);
    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let listener = UnixListener::bind(&socket_path)?;
    std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o600))?;

    loop {
        let (stream, _) = listener.accept().await?;
        let peer = macos_peer();
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            if let Err(error) = serve_connection(stream, peer, state).await {
                eprintln!("policy-helper connection error: {error}");
            }
        });
    }
}

fn macos_peer() -> PeerIdentity {
    // TODO(platform): SecCodeCopyGuestWithAttributes / csops Team ID check.
    PeerIdentity {
        authenticated: true,
        anonymous: false,
        process_id: std::process::id(),
    }
}
