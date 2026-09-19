//! Windows enforcement: session-scoped WFP. Filters are dynamic (gone if the
//! helper exits). Sites use resolved IPs. Apps use application-id network
//! block. TerminateProcess is opt-in only.

use crate::enforce::plan::{resolve_deny_hosts, EnforcePlan};
use crate::enforce::safety::{AppEngine, SiteEngine};
use crate::enforce::{rule_matches_process, EnforceReport};
use sha2::{Digest, Sha256};
use std::ffi::OsStr;
use std::net::IpAddr;
use std::os::windows::ffi::OsStrExt;
use std::sync::Mutex;
use windows::core::{GUID, PCWSTR, PWSTR};
use windows::Win32::Foundation::{CloseHandle, HANDLE, MAX_PATH};
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FwpmEngineClose0, FwpmEngineOpen0, FwpmFilterAdd0, FwpmFilterDeleteById0, FwpmFreeMemory0,
    FwpmGetAppIdFromFileName0, FwpmSubLayerAdd0, FWP_ACTION_BLOCK, FWP_BYTE_BLOB_TYPE,
    FWP_CONDITION_VALUE0, FWP_MATCH_EQUAL, FWP_UINT32, FWP_V4_ADDR_AND_MASK, FWP_V4_ADDR_MASK,
    FWP_V6_ADDR_AND_MASK, FWP_V6_ADDR_MASK, FWPM_ACTION0, FWPM_CONDITION_ALE_APP_ID,
    FWPM_CONDITION_IP_REMOTE_ADDRESS, FWPM_DISPLAY_DATA0, FWPM_FILTER0, FWPM_FILTER_CONDITION0,
    FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_CONNECT_V6,
    FWPM_LAYER_OUTBOUND_TRANSPORT_V4, FWPM_LAYER_OUTBOUND_TRANSPORT_V6, FWPM_SESSION0,
    FWPM_SESSION_FLAG_DYNAMIC, FWPM_SUBLAYER0,
};
use windows::Win32::Security::PSECURITY_DESCRIPTOR;
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, TerminateProcess, PROCESS_NAME_WIN32,
    PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_TERMINATE,
};
use windows::Win32::UI::Shell::IsUserAnAdmin;

#[allow(dead_code)]
const RPC_C_AUTHN_WINNT: u32 = 10;
#[allow(dead_code)]
const SUBLAYER_KEY: GUID = GUID::from_u128(0x6b2e1c90_5d4a_4f11_9c8e_00a1b2c3d4e5);

struct Engine {
    handle: HANDLE,
    filter_ids: Vec<u64>,
    killed_for: Option<u64>,
}

unsafe impl Send for Engine {}
unsafe impl Sync for Engine {}

static ENGINE: Mutex<Option<Engine>> = Mutex::new(None);

pub fn apply(
    plan: &EnforcePlan,
    site_engine: SiteEngine,
    app_engine: AppEngine,
) -> Result<EnforceReport, String> {
    let add_ip = site_engine == SiteEngine::IpFallback;
    let add_apps = app_engine == AppEngine::NetworkFilter || app_engine == AppEngine::TerminateOptIn;
    let terminate = app_engine == AppEngine::TerminateOptIn;
    let mut report = EnforceReport {
        needs_admin: !unsafe { IsUserAnAdmin().as_bool() },
        ..EnforceReport::default()
    };

    if !add_ip && !add_apps {
        let _ = crate::enforce::firewall::clear();
        let _ = clear_filters();
        return Ok(report);
    }

    if add_ip || add_apps {
        let _ = crate::enforce::firewall::clear();
    }

    if add_ip {
        let resolved = resolve_deny_hosts(&plan.sites_deny);
        match crate::enforce::firewall::apply_sites(&resolved) {
            Ok(count) => report.filters_added += count,
            Err(error) => report.last_error = Some(error),
        }
    }
    if add_apps {
        let paths: Vec<String> = running_processes()
            .into_iter()
            .filter_map(|(_, path)| {
                let hash = sha256_file(&path);
                plan.apps_deny
                    .iter()
                    .any(|rule| rule_matches_process(rule, &path, hash.as_deref(), None))
                    .then_some(path)
            })
            .collect();
        match crate::enforce::firewall::apply_apps(&paths) {
            Ok(count) => {
                report.filters_added += count;
                report.apps_reconciled += count;
            }
            Err(error) => report.last_error = Some(error),
        }
    }

    if terminate {
        report.apps_reconciled += reconcile_apps(plan, &mut report);
    }
    Ok(report)
}

pub fn clear() -> Result<(), String> {
    let firewall_error = crate::enforce::firewall::clear().err();
    let wfp_error = clear_filters().err();
    match (firewall_error, wfp_error) {
        (None, None) => Ok(()),
        (Some(error), _) | (_, Some(error)) => Err(error),
    }
}

#[allow(dead_code)]
fn open_engine() -> Result<(), String> {
    let mut guard = ENGINE.lock().map_err(|_| "engine lock")?;
    if guard.is_some() {
        return Ok(());
    }

    let mut session = FWPM_SESSION0::default();
    session.flags = FWPM_SESSION_FLAG_DYNAMIC;
    let mut name: Vec<u16> = wide("VMG Sentinel helper");
    session.displayData = FWPM_DISPLAY_DATA0 {
        name: PWSTR(name.as_mut_ptr()),
        description: PWSTR::null(),
    };

    let mut handle = HANDLE::default();
    let status = unsafe {
        FwpmEngineOpen0(
            PCWSTR::null(),
            RPC_C_AUTHN_WINNT,
            None,
            Some(&session),
            &mut handle,
        )
    };
    if status != 0 {
        return Err(format!("FwpmEngineOpen0 failed: 0x{status:08x}"));
    }

    let mut sublayer = FWPM_SUBLAYER0::default();
    sublayer.subLayerKey = SUBLAYER_KEY;
    let mut sub_name: Vec<u16> = wide("VMG Sentinel sublayer");
    sublayer.displayData = FWPM_DISPLAY_DATA0 {
        name: PWSTR(sub_name.as_mut_ptr()),
        description: PWSTR::null(),
    };
    sublayer.weight = 0xFFFF;
    let _ = unsafe { FwpmSubLayerAdd0(handle, &sublayer, PSECURITY_DESCRIPTOR::default()) };

    *guard = Some(Engine {
        handle,
        filter_ids: Vec::new(),
        killed_for: None,
    });
    Ok(())
}

fn clear_filters() -> Result<(), String> {
    let mut guard = ENGINE.lock().map_err(|_| "engine lock")?;
    let Some(engine) = guard.as_mut() else {
        return Ok(());
    };
    for id in engine.filter_ids.drain(..) {
        unsafe {
            let _ = FwpmFilterDeleteById0(engine.handle, id);
        }
    }
    engine.killed_for = None;
    Ok(())
}

#[allow(dead_code)]
fn add_ip_filter(engine: HANDLE, ip: IpAddr, hostname: &str) -> Result<Vec<u64>, String> {
    let mut ids = Vec::new();
    match ip {
        IpAddr::V4(v4) => {
            // FWP_V4_ADDR_AND_MASK.addr is network byte order (same as inet_addr).
            let mut mask = FWP_V4_ADDR_AND_MASK {
                addr: u32::from_ne_bytes(v4.octets()),
                mask: u32::MAX,
            };
            eprintln!("policy-helper: WFP v4 block {hostname} {v4}");
            for layer in [FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_OUTBOUND_TRANSPORT_V4] {
                let mut cond = FWPM_FILTER_CONDITION0::default();
                cond.fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
                cond.matchType = FWP_MATCH_EQUAL;
                cond.conditionValue = FWP_CONDITION_VALUE0::default();
                cond.conditionValue.r#type = FWP_V4_ADDR_MASK;
                cond.conditionValue.Anonymous.v4AddrMask = &mut mask;
                ids.push(add_filter(
                    engine,
                    layer,
                    &mut cond,
                    &format!("Sentinel site {hostname}"),
                )?);

                let mut cond32 = FWPM_FILTER_CONDITION0::default();
                cond32.fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
                cond32.matchType = FWP_MATCH_EQUAL;
                cond32.conditionValue = FWP_CONDITION_VALUE0::default();
                cond32.conditionValue.r#type = FWP_UINT32;
                cond32.conditionValue.Anonymous.uint32 = u32::from_be_bytes(v4.octets());
                ids.push(add_filter(
                    engine,
                    layer,
                    &mut cond32,
                    &format!("Sentinel site {hostname} u32"),
                )?);
            }
        }
        IpAddr::V6(v6) => {
            let mut mask = FWP_V6_ADDR_AND_MASK {
                addr: v6.octets(),
                prefixLength: 128,
            };
            eprintln!("policy-helper: WFP v6 block {hostname} {v6}");
            for layer in [FWPM_LAYER_ALE_AUTH_CONNECT_V6, FWPM_LAYER_OUTBOUND_TRANSPORT_V6] {
                let mut cond = FWPM_FILTER_CONDITION0::default();
                cond.fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
                cond.matchType = FWP_MATCH_EQUAL;
                cond.conditionValue = FWP_CONDITION_VALUE0::default();
                cond.conditionValue.r#type = FWP_V6_ADDR_MASK;
                cond.conditionValue.Anonymous.v6AddrMask = &mut mask;
                ids.push(add_filter(
                    engine,
                    layer,
                    &mut cond,
                    &format!("Sentinel site {hostname}"),
                )?);
            }
        }
    }
    Ok(ids)
}

#[allow(dead_code)]
fn add_app_filter(engine: HANDLE, path: &str) -> Result<Vec<u64>, String> {
    let mut app_id = std::ptr::null_mut();
    let wide_path = wide(path);
    let status = unsafe { FwpmGetAppIdFromFileName0(PCWSTR(wide_path.as_ptr()), &mut app_id) };
    if status != 0 || app_id.is_null() {
        return Err(format!("FwpmGetAppIdFromFileName0 failed: 0x{status:08x}"));
    }
    let mut cond = FWPM_FILTER_CONDITION0::default();
    cond.fieldKey = FWPM_CONDITION_ALE_APP_ID;
    cond.matchType = FWP_MATCH_EQUAL;
    cond.conditionValue = FWP_CONDITION_VALUE0::default();
    cond.conditionValue.r#type = FWP_BYTE_BLOB_TYPE;
    cond.conditionValue.Anonymous.byteBlob = app_id;
    let result = add_filter(
        engine,
        FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        &mut cond,
        &format!("Sentinel app {path}"),
    );
    let mut mem = app_id as *mut core::ffi::c_void;
    unsafe {
        FwpmFreeMemory0(&mut mem);
    }
    Ok(vec![result?])
}

#[allow(dead_code)]
fn add_filter(
    engine: HANDLE,
    layer: GUID,
    condition: &mut FWPM_FILTER_CONDITION0,
    name: &str,
) -> Result<u64, String> {
    let mut name_w = wide(name);
    let mut filter = FWPM_FILTER0::default();
    filter.displayData = FWPM_DISPLAY_DATA0 {
        name: PWSTR(name_w.as_mut_ptr()),
        description: PWSTR::null(),
    };
    filter.layerKey = layer;
    filter.subLayerKey = SUBLAYER_KEY;
    filter.numFilterConditions = 1;
    filter.filterCondition = condition;
    filter.action = FWPM_ACTION0 {
        r#type: FWP_ACTION_BLOCK,
        Anonymous: Default::default(),
    };
    let mut id = 0u64;
    let status = unsafe {
        FwpmFilterAdd0(
            engine,
            &filter,
            PSECURITY_DESCRIPTOR::default(),
            Some(&mut id),
        )
    };
    if status != 0 {
        return Err(format!("FwpmFilterAdd0 failed: 0x{status:08x}"));
    }
    Ok(id)
}

fn reconcile_apps(plan: &EnforcePlan, report: &mut EnforceReport) -> u32 {
    let mut engine = match ENGINE.lock() {
        Ok(guard) => guard,
        Err(_) => return 0,
    };
    if let Some(existing) = engine.as_ref() {
        if existing.killed_for == Some(plan.policy_version) {
            return 0;
        }
    }

    let mut killed = 0u32;
    for (pid, path) in running_processes() {
        let hash = sha256_file(&path);
        let publisher = None;
        let matched = plan.apps_deny.iter().any(|rule| {
            rule_matches_process(rule, &path, hash.as_deref(), publisher)
        });
        if !matched {
            continue;
        }
        report.events.push(crate::enforce::plan::AuditEvent {
            policy_version: plan.policy_version,
            rule_id: format!("app:{path}"),
            actor: "helper".into(),
            process_path: path.clone(),
            hostname: String::new(),
            action: "block".into(),
        });
        if terminate_pid(pid) {
            killed += 1;
        }
    }

    if let Some(engine) = engine.as_mut() {
        engine.killed_for = Some(plan.policy_version);
    }
    killed
}

fn running_processes() -> Vec<(u32, String)> {
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    let Ok(snapshot) = snapshot else {
        return vec![];
    };
    let mut entry = PROCESSENTRY32W {
        dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };
    let mut out = Vec::new();
    unsafe {
        if Process32FirstW(snapshot, &mut entry).is_ok() {
            loop {
                let pid = entry.th32ProcessID;
                if let Some(path) = process_path(pid) {
                    out.push((pid, path));
                }
                if Process32NextW(snapshot, &mut entry).is_err() {
                    break;
                }
            }
        }
        let _ = CloseHandle(snapshot);
    }
    out
}

fn process_path(pid: u32) -> Option<String> {
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }.ok()?;
    let mut buf = [0u16; MAX_PATH as usize];
    let mut size = buf.len() as u32;
    let ok = unsafe {
        QueryFullProcessImageNameW(handle, PROCESS_NAME_WIN32, PWSTR(buf.as_mut_ptr()), &mut size)
            .is_ok()
    };
    unsafe {
        let _ = CloseHandle(handle);
    }
    if !ok {
        return None;
    }
    Some(String::from_utf16_lossy(&buf[..size as usize]))
}

fn terminate_pid(pid: u32) -> bool {
    let Ok(handle) = (unsafe { OpenProcess(PROCESS_TERMINATE, false, pid) }) else {
        return false;
    };
    let ok = unsafe { TerminateProcess(handle, 1) }.is_ok();
    unsafe {
        let _ = CloseHandle(handle);
    }
    ok
}

fn sha256_file(path: &str) -> Option<String> {
    let bytes = std::fs::read(path).ok()?;
    let digest = Sha256::digest(bytes);
    Some(hex::encode(digest))
}

#[allow(dead_code)]
fn wide(value: &str) -> Vec<u16> {
    OsStr::new(value)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

impl Drop for Engine {
    fn drop(&mut self) {
        for id in self.filter_ids.drain(..) {
            unsafe {
                let _ = FwpmFilterDeleteById0(self.handle, id);
            }
        }
        unsafe {
            let _ = FwpmEngineClose0(self.handle);
        }
    }
}
