//! Running under the Service Control Manager, and installing there (spec section 3: `LocalSystem`, auto-start,
//! restart on failure). Installing needs an administrator: on the owner's PC that waits for their go-ahead, so
//! development runs in console mode and the service is installed on a VM.

use crate::log;
use crate::runner::Runner;
use std::ffi::OsString;
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use windows_service::service::{
    ServiceAccess, ServiceAction, ServiceActionType, ServiceControl, ServiceControlAccept, ServiceErrorControl, ServiceExitCode,
    ServiceFailureActions, ServiceFailureResetPeriod, ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_service::{define_windows_service, service_dispatcher};

pub const SERVICE_NAME: &str = "eGuard";
const DISPLAY_NAME: &str = "eGuard";
const DESCRIPTION: &str = "Keeps the family's eGuard rules on this computer and reports to the parent's dashboard.";

define_windows_service!(ffi_service_main, service_main);

/// Hands the process to the SCM. Fails at once when not started by it (someone ran the exe by hand).
pub fn dispatch() -> windows_service::Result<()> {
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
}

fn service_main(_args: Vec<OsString>) {
    if let Err(e) = run() {
        log::error(&format!("the service failed: {e}"));
    }
}

/// The service's own exit code when setting up failed (the data folder, `WinHTTP`, the server URL), so the SCM's
/// event says "service-specific error 1" instead of a start that timed out (1053).
const EXIT_SETUP_FAILED: u32 = 1;
/// The service's own exit code when the runner stopped with an error.
const EXIT_RUN_FAILED: u32 = 2;

fn status(state: ServiceState, accept: ServiceControlAccept, exit: ServiceExitCode) -> ServiceStatus {
    ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: accept,
        exit_code: exit,
        checkpoint: 0,
        wait_hint: Duration::from_secs(30),
        process_id: None,
    }
}

fn run() -> Result<(), String> {
    // The control handler first: the SCM hears about everything after it, a setup failure included
    let runner: Arc<OnceLock<Arc<Runner>>> = Arc::default();
    let r = Arc::clone(&runner);
    let handler = move |event| match event {
        // Stopping is allowed until removal protection locks the service (Phase 6). Not accepted while starting,
        // so the runner is there by the time a stop can arrive
        ServiceControl::Stop | ServiceControl::Shutdown => {
            if let Some(r) = r.get() {
                r.request_stop();
            }
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    };
    let handle = service_control_handler::register(SERVICE_NAME, handler).map_err(|e| e.to_string())?;
    let _ = handle.set_service_status(status(ServiceState::StartPending, ServiceControlAccept::empty(), ServiceExitCode::Win32(0)));
    let started = match crate::service_runner() {
        Ok(started) => started,
        Err(e) => {
            // A non-zero exit code makes the SCM's recovery actions try again (failure actions on non-crash failures)
            let _ = handle.set_service_status(status(
                ServiceState::Stopped,
                ServiceControlAccept::empty(),
                ServiceExitCode::ServiceSpecific(EXIT_SETUP_FAILED),
            ));
            return Err(format!("setting up failed: {e}"));
        }
    };
    let _ = runner.set(Arc::clone(&started));
    let accept = ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN;
    handle.set_service_status(status(ServiceState::Running, accept, ServiceExitCode::Win32(0))).map_err(|e| e.to_string())?;
    let result = Runner::run(&started);
    let code = if result.is_err() { ServiceExitCode::ServiceSpecific(EXIT_RUN_FAILED) } else { ServiceExitCode::Win32(0) };
    let _ = handle.set_service_status(status(ServiceState::Stopped, ServiceControlAccept::empty(), code));
    result
}

/// Registers the service: `LocalSystem`, automatic start, restarted after 5 s, 5 s, then every minute, the count
/// reset daily. Also on a non-crash failure (the service stopping with an error code).
pub fn install() -> Result<(), String> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE)
        .map_err(|e| format!("couldn't open the service manager ({e}); run this as an administrator"))?;
    let info = ServiceInfo {
        name: SERVICE_NAME.into(),
        display_name: DISPLAY_NAME.into(),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: std::env::current_exe().map_err(|e| e.to_string())?,
        launch_arguments: vec![],
        dependencies: vec![],
        // None: LocalSystem
        account_name: None,
        account_password: None,
    };
    let service = manager
        .create_service(&info, ServiceAccess::CHANGE_CONFIG | ServiceAccess::START)
        .map_err(|e| format!("couldn't create the service: {e}"))?;
    service.set_description(DESCRIPTION).map_err(|e| e.to_string())?;
    let restart = |secs| ServiceAction { action_type: ServiceActionType::Restart, delay: Duration::from_secs(secs) };
    service
        .update_failure_actions(ServiceFailureActions {
            reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(24 * 60 * 60)),
            reboot_msg: None,
            command: None,
            actions: Some(vec![restart(5), restart(5), restart(60)]),
        })
        .map_err(|e| e.to_string())?;
    service.set_failure_actions_on_non_crash_failures(true).map_err(|e| e.to_string())?;
    service.start::<&str>(&[]).map_err(|e| format!("installed, but it didn't start: {e}"))?;
    Ok(())
}

/// Stops and deletes the service. For a VM between test runs; the real removal flow is Phase 6.
pub fn uninstall() -> Result<(), String> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(|e| format!("couldn't open the service manager ({e}); run this as an administrator"))?;
    let service = manager
        .open_service(SERVICE_NAME, ServiceAccess::STOP | ServiceAccess::DELETE | ServiceAccess::QUERY_STATUS)
        .map_err(|e| format!("couldn't open the service: {e}"))?;
    if service.query_status().is_ok_and(|s| s.current_state != ServiceState::Stopped) {
        let _ = service.stop();
    }
    service.delete().map_err(|e| e.to_string())
}

/// eGuard is removing itself (spec section 10): the service is marked for deletion, which Windows carries out once it
/// has stopped. Called from inside the running service, as `LocalSystem`.
pub fn delete_self() -> Result<(), String> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT).map_err(|e| e.to_string())?;
    let service = manager.open_service(SERVICE_NAME, ServiceAccess::DELETE).map_err(|e| e.to_string())?;
    service.delete().map_err(|e| e.to_string())
}
