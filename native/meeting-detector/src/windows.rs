use crate::{CaptureSession, HardwareSnapshot, WindowContext};
use std::path::Path;
use windows::{
    core::{Interface, PWSTR},
    Win32::Foundation::{CloseHandle, BOOL, HWND, LPARAM, MAX_PATH},
    Win32::Media::Audio::{
        eCapture, AudioSessionStateActive, IAudioSessionControl, IAudioSessionControl2,
        IAudioSessionManager2, IMMDeviceEnumerator, MMDeviceEnumerator, DEVICE_STATE_ACTIVE,
    },
    Win32::System::Com::{CoCreateInstance, CoInitializeEx, CLSCTX_ALL, COINIT_MULTITHREADED},
    Win32::System::Threading::{
        OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
    },
    Win32::UI::WindowsAndMessaging::{
        EnumWindows, GetForegroundWindow, GetWindowTextW, GetWindowThreadProcessId, IsWindowVisible,
    },
};

pub fn poll() -> HardwareSnapshot {
    unsafe { poll_wasapi() }.unwrap_or_else(|reason| crate::empty_unavailable(&reason))
}

unsafe fn poll_wasapi() -> Result<HardwareSnapshot, String> {
    let _ = CoInitializeEx(None, COINIT_MULTITHREADED);

    let enumerator: IMMDeviceEnumerator =
        CoCreateInstance(&MMDeviceEnumerator, None, CLSCTX_ALL)
            .map_err(|e| format!("wasapi_failed: enumerator {e}"))?;

    let collection = enumerator
        .EnumAudioEndpoints(eCapture, DEVICE_STATE_ACTIVE)
        .map_err(|e| format!("wasapi_failed: endpoints {e}"))?;
    let count = collection
        .GetCount()
        .map_err(|e| format!("wasapi_failed: count {e}"))?;

    let mut sessions = Vec::new();
    for i in 0..count {
        let device = match collection.Item(i) {
            Ok(d) => d,
            Err(_) => continue,
        };
        let manager = match device.Activate::<IAudioSessionManager2>(CLSCTX_ALL, None) {
            Ok(m) => m,
            Err(_) => continue,
        };
        let _ = collect_sessions(&manager, &mut sessions);
    }

    Ok(crate::snapshot(dedupe(sessions), collect_windows(), false))
}

unsafe fn collect_sessions(
    manager: &IAudioSessionManager2,
    out: &mut Vec<CaptureSession>,
) -> Result<(), String> {
    let enumerator = manager
        .GetSessionEnumerator()
        .map_err(|e| format!("wasapi_failed: sessions {e}"))?;
    let count = enumerator
        .GetCount()
        .map_err(|e| format!("wasapi_failed: session_count {e}"))?;

    for i in 0..count {
        let control: IAudioSessionControl = match enumerator.GetSession(i) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let state = match control.GetState() {
            Ok(s) => s,
            Err(_) => continue,
        };
        if state != AudioSessionStateActive {
            continue;
        }
        let control2: IAudioSessionControl2 = match control.cast() {
            Ok(s) => s,
            Err(_) => continue,
        };
        let pid = match control2.GetProcessId() {
            Ok(pid) => pid,
            Err(_) => continue,
        };
        out.push(CaptureSession {
            pid,
            process_name: process_name(pid),
            is_capture_active: true,
        });
    }
    Ok(())
}

unsafe fn process_name(pid: u32) -> String {
    let Ok(handle) = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) else {
        return format!("pid_{pid}");
    };
    let mut buf = [0u16; MAX_PATH as usize];
    let mut size = buf.len() as u32;
    let name = if QueryFullProcessImageNameW(
        handle,
        PROCESS_NAME_WIN32,
        PWSTR(buf.as_mut_ptr()),
        &mut size,
    )
    .is_ok()
    {
        let path = String::from_utf16_lossy(&buf[..size as usize]);
        Path::new(&path)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or(&path)
            .to_string()
    } else {
        format!("pid_{pid}")
    };
    let _ = CloseHandle(handle);
    name
}

struct EnumState {
    foreground: HWND,
    windows: Vec<WindowContext>,
}

unsafe fn collect_windows() -> Vec<WindowContext> {
    let mut state = EnumState {
        foreground: GetForegroundWindow(),
        windows: Vec::new(),
    };
    let _ = EnumWindows(Some(enum_proc), LPARAM(&mut state as *mut _ as isize));
    state.windows
}

unsafe extern "system" fn enum_proc(hwnd: HWND, lparam: LPARAM) -> BOOL {
    let state = &mut *(lparam.0 as *mut EnumState);
    if !IsWindowVisible(hwnd).as_bool() {
        return BOOL(1);
    }
    let mut pid = 0u32;
    GetWindowThreadProcessId(hwnd, Some(&mut pid));
    let mut buf = [0u16; 512];
    let len = GetWindowTextW(hwnd, &mut buf);
    if len > 0 {
        state.windows.push(WindowContext {
            pid,
            title: String::from_utf16_lossy(&buf[..len as usize]),
            is_focused: hwnd == state.foreground,
        });
    }
    BOOL(1)
}

fn dedupe(mut sessions: Vec<CaptureSession>) -> Vec<CaptureSession> {
    sessions.sort_by_key(|s| s.pid);
    sessions.dedup_by_key(|s| s.pid);
    sessions
}