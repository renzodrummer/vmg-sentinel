use crate::{CaptureSession, HardwareSnapshot};
use coreaudio_sys::*;
use std::mem;
use std::ptr;

const PID_SEL: AudioObjectPropertySelector = u32::from_be_bytes(*b"pid ");
const RUN_INPUT_SEL: AudioObjectPropertySelector = u32::from_be_bytes(*b"runi");
const PROC_LIST_SEL: AudioObjectPropertySelector = u32::from_be_bytes(*b"plst");

pub fn poll() -> HardwareSnapshot {
    let device_running = device_is_running_somewhere();
    match process_sessions() {
        Ok(sessions) => crate::snapshot(sessions, Vec::new(), device_running),
        Err(reason) => {
            let mut snap = crate::empty_unavailable(&reason);
            snap.device_running_somewhere = device_running;
            snap
        }
    }
}

fn property_address(selector: AudioObjectPropertySelector) -> AudioObjectPropertyAddress {
    AudioObjectPropertyAddress {
        mSelector: selector,
        mScope: kAudioObjectPropertyScopeGlobal,
        mElement: kAudioObjectPropertyElementMain,
    }
}

fn process_sessions() -> Result<Vec<CaptureSession>, String> {
    let addr = property_address(PROC_LIST_SEL);
    let mut data_size: u32 = 0;
    let status = unsafe {
        AudioObjectGetPropertyDataSize(kAudioObjectSystemObject, &addr, 0, ptr::null(), &mut data_size)
    };
    if status != 0 {
        return Err(format!("coreaudio_failed: process_list {status}"));
    }

    let count = data_size as usize / mem::size_of::<AudioObjectID>();
    let mut ids = vec![0 as AudioObjectID; count];
    let status = unsafe {
        AudioObjectGetPropertyData(
            kAudioObjectSystemObject,
            &addr,
            0,
            ptr::null(),
            &mut data_size,
            ids.as_mut_ptr() as *mut _,
        )
    };
    if status != 0 {
        return Err(format!("coreaudio_failed: process_list_data {status}"));
    }

    let mut sessions = Vec::new();
    for id in ids {
        if !is_running_input(id) {
            continue;
        }
        let pid = process_pid(id).unwrap_or(0);
        sessions.push(CaptureSession {
            pid,
            process_name: process_name(pid),
            is_capture_active: true,
        });
    }
    Ok(sessions)
}

fn is_running_input(id: AudioObjectID) -> bool {
    let addr = property_address(RUN_INPUT_SEL);
    let mut running: u32 = 0;
    let mut size = mem::size_of::<u32>() as u32;
    let status = unsafe {
        AudioObjectGetPropertyData(id, &addr, 0, ptr::null(), &mut size, &mut running as *mut _ as *mut _)
    };
    status == 0 && running != 0
}

fn process_pid(id: AudioObjectID) -> Option<u32> {
    let addr = property_address(PID_SEL);
    let mut pid: i32 = 0;
    let mut size = mem::size_of::<i32>() as u32;
    let status = unsafe {
        AudioObjectGetPropertyData(id, &addr, 0, ptr::null(), &mut size, &mut pid as *mut _ as *mut _)
    };
    if status == 0 {
        Some(pid as u32)
    } else {
        None
    }
}

fn process_name(pid: u32) -> String {
    let mut buf = [0i8; 1024];
    let n = unsafe { libc::proc_pidpath(pid as i32, buf.as_mut_ptr() as *mut _, buf.len() as u32) };
    if n > 0 {
        let raw = unsafe { std::ffi::CStr::from_ptr(buf.as_ptr()) };
        let path = raw.to_string_lossy();
        return path.rsplit('/').next().unwrap_or(&path).to_string();
    }
    format!("pid_{pid}")
}

fn device_is_running_somewhere() -> bool {
    let default_addr = property_address(kAudioHardwarePropertyDefaultInputDevice);
    let mut device: AudioObjectID = 0;
    let mut size = mem::size_of::<AudioObjectID>() as u32;
    let status = unsafe {
        AudioObjectGetPropertyData(
            kAudioObjectSystemObject,
            &default_addr,
            0,
            ptr::null(),
            &mut size,
            &mut device as *mut _ as *mut _,
        )
    };
    if status != 0 {
        return false;
    }
    let run_addr = property_address(kAudioDevicePropertyDeviceIsRunningSomewhere);
    let mut running: u32 = 0;
    let mut run_size = mem::size_of::<u32>() as u32;
    let status = unsafe {
        AudioObjectGetPropertyData(
            device,
            &run_addr,
            0,
            ptr::null(),
            &mut run_size,
            &mut running as *mut _ as *mut _,
        )
    };
    status == 0 && running != 0
}