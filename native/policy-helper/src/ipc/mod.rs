use crate::ipc::protocol::PIPE_SDDL;
use crate::state::HelperState;
use std::io;
use std::sync::Arc;

pub mod dispatch;
pub mod protocol;
mod serve;

#[cfg(windows)]
mod windows;
#[cfg(target_os = "macos")]
mod macos;

#[cfg(windows)]
pub async fn listen(pipe_name: String, state: Arc<HelperState>) -> io::Result<()> {
    windows::listen(pipe_name, state).await
}

#[cfg(target_os = "macos")]
pub async fn listen(_pipe_name: String, state: Arc<HelperState>) -> io::Result<()> {
    let socket = state.store.dir().join("helper.sock");
    macos::listen(socket, state).await
}

#[cfg(not(any(windows, target_os = "macos")))]
pub async fn listen(_pipe_name: String, _state: Arc<HelperState>) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "vmg-sentinel-helper supports Windows and macOS only",
    ))
}

pub fn pipe_sddl() -> &'static str {
    PIPE_SDDL
}
