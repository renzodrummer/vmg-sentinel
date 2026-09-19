#![deny(clippy::all)]

use napi::bindgen_prelude::*;
use napi_derive::napi;

#[cfg(windows)]
mod windows;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(not(any(windows, target_os = "macos")))]
mod linux;

#[napi(object)]
#[derive(Clone)]
pub struct CaptureSession {
    #[napi(js_name = "pid")]
    pub pid: u32,
    #[napi(js_name = "process_name")]
    pub process_name: String,
    #[napi(js_name = "is_capture_active")]
    pub is_capture_active: bool,
}

#[napi(object)]
#[derive(Clone)]
pub struct WindowContext {
    #[napi(js_name = "pid")]
    pub pid: u32,
    #[napi(js_name = "title")]
    pub title: String,
    #[napi(js_name = "is_focused")]
    pub is_focused: bool,
}

#[napi(object)]
#[derive(Clone)]
pub struct HardwareSnapshot {
    #[napi(js_name = "is_available")]
    pub is_available: bool,
    #[napi(js_name = "unavailable_reason")]
    pub unavailable_reason: Option<String>,
    #[napi(js_name = "sessions")]
    pub sessions: Vec<CaptureSession>,
    #[napi(js_name = "windows")]
    pub windows: Vec<WindowContext>,
    #[napi(js_name = "device_running_somewhere")]
    pub device_running_somewhere: bool,
    #[napi(js_name = "captured_at")]
    pub captured_at: String,
}

pub(crate) fn now_iso() -> String {
    format!(
        "{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0)
    )
}

fn poll_impl() -> HardwareSnapshot {
    #[cfg(windows)]
    {
        return windows::poll();
    }
    #[cfg(target_os = "macos")]
    {
        return macos::poll();
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        return linux::poll();
    }
}

#[napi]
pub async fn poll_capture_sessions() -> Result<HardwareSnapshot> {
    napi::tokio::task::spawn_blocking(poll_impl)
        .await
        .map_err(|e| Error::from_reason(e.to_string()))
}

pub(crate) fn empty_unavailable(reason: &str) -> HardwareSnapshot {
    HardwareSnapshot {
        is_available: false,
        unavailable_reason: Some(reason.to_string()),
        sessions: vec![],
        windows: vec![],
        device_running_somewhere: false,
        captured_at: now_iso(),
    }
}

pub(crate) fn snapshot(
    sessions: Vec<CaptureSession>,
    windows: Vec<WindowContext>,
    device_running_somewhere: bool,
) -> HardwareSnapshot {
    HardwareSnapshot {
        is_available: true,
        unavailable_reason: None,
        sessions,
        windows,
        device_running_somewhere,
        captured_at: now_iso(),
    }
}