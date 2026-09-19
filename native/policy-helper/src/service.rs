//! LocalSystem Windows service. Electron never elevates; it attaches to this pipe.

#![cfg(windows)]

use crate::runtime::{default_service_store, parse_args, run_helper};
use std::ffi::OsString;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::Duration;
use windows_service::service::{
    ServiceAccess, ServiceControl, ServiceControlAccept, ServiceErrorControl, ServiceExitCode,
    ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_dispatcher;
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

pub const SERVICE_NAME: &str = "VMGSentinelHelper";
const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;

static STOP: AtomicBool = AtomicBool::new(false);
static STATUS: Mutex<Option<service_control_handler::ServiceStatusHandle>> = Mutex::new(None);

windows_service::define_windows_service!(ffi_service_main, service_main);

pub fn dispatch() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)?;
    Ok(())
}

fn service_main(_args: Vec<OsString>) {
    if let Err(error) = run_service() {
        eprintln!("policy-helper service failed: {error}");
    }
}

fn run_service() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    STOP.store(false, Ordering::SeqCst);
    let event_handler = move |control| match control {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            STOP.store(true, Ordering::SeqCst);
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    };
    let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)?;
    {
        let mut guard = STATUS.lock().map_err(|_| "status lock")?;
        *guard = Some(status_handle);
    }
    set_state(ServiceState::Running)?;

    let args = parse_args(true);
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let result = rt.block_on(run_helper(args, wait_stop()));
    set_state(ServiceState::Stopped)?;
    result
}

async fn wait_stop() {
    loop {
        if STOP.load(Ordering::SeqCst) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

fn set_state(state: ServiceState) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let guard = STATUS.lock().map_err(|_| "status lock")?;
    let Some(handle) = guard.as_ref() else {
        return Ok(());
    };
    handle.set_service_status(ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state: state,
        controls_accepted: if state == ServiceState::Running {
            ServiceControlAccept::STOP
        } else {
            ServiceControlAccept::empty()
        },
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;
    Ok(())
}

fn service_info(exe: std::path::PathBuf, store: std::path::PathBuf) -> ServiceInfo {
    ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from("VMG Sentinel Policy Helper"),
        service_type: SERVICE_TYPE,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: exe,
        launch_arguments: vec![
            OsString::from("--service"),
            OsString::from("--store-dir"),
            store.into_os_string(),
            OsString::from("--pipe-name"),
            OsString::from("vmg-sentinel-helper"),
        ],
        dependencies: vec![],
        account_name: None,
        account_password: None,
    }
}

fn wait_until_stopped(service: &windows_service::service::Service) {
    for _ in 0..50 {
        if let Ok(status) = service.query_status() {
            if status.current_state == ServiceState::Stopped {
                return;
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

pub fn install() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )?;
    let exe = std::env::current_exe()?;
    let store = default_service_store();
    std::fs::create_dir_all(&store)?;
    let info = service_info(exe, store);
    let existing_access = ServiceAccess::START
        | ServiceAccess::STOP
        | ServiceAccess::QUERY_STATUS
        | ServiceAccess::CHANGE_CONFIG;
    if let Ok(service) = manager.open_service(SERVICE_NAME, existing_access) {
        let _ = service.stop();
        wait_until_stopped(&service);
        service.change_config(&info)?;
        service.start::<OsString>(&[])?;
        eprintln!("updated and started {SERVICE_NAME} as LocalSystem");
        return Ok(());
    }
    let service = manager.create_service(&info, ServiceAccess::START)?;
    service.start::<OsString>(&[])?;
    eprintln!("installed and started {SERVICE_NAME} as LocalSystem");
    Ok(())
}

pub fn uninstall() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    match manager.open_service(SERVICE_NAME, ServiceAccess::STOP | ServiceAccess::DELETE) {
        Ok(service) => {
            let _ = service.stop();
            service.delete()?;
            eprintln!("deleted {SERVICE_NAME}");
            Ok(())
        }
        Err(_) => {
            eprintln!("{SERVICE_NAME} was not installed");
            Ok(())
        }
    }
}
