//! `eguard-guard`: the guard (spec section 3, section 10). A SYSTEM scheduled task at boot (`\eGuard\Guard`, set up
//! by `eguard-service install`) that runs until eGuard is removed:
//!
//! - every `ROUND`, each program file in `C:\Program Files\eGuard` is compared with the guard's copy in
//!   `C:\ProgramData\eGuard\cache` (which only SYSTEM writes). One that's missing or different is put back, the
//!   changed one kept aside, and the parent hears (`FILES_CHANGED`, through the service);
//! - then the service is started again if it has stopped;
//! - the program files are held open while they match, so nobody can delete, replace or rename them.
//!
//! The service starts this task again when no guard is running. When the service is gone (eGuard was removed) the
//! guard ends too: an authorized removal deletes the task and ends the guard first.

use eguard_core::ipc::{self, Request};
use eguard_core::logging;
use eguard_core::wire::TamperKind;
use eguard_win::files;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;
use windows_service::service::{ServiceAccess, ServiceState};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

const ROUND: Duration = Duration::from_secs(10);
const SERVICE_NAME: &str = "eGuard";
const PROGRAMS: [&str; 3] = ["eguard-service.exe", "eguard-agent.exe", "eguard-guard.exe"];

fn install_dir() -> PathBuf {
    let base = std::env::var_os("ProgramFiles").map_or_else(|| PathBuf::from(r"C:\Program Files"), PathBuf::from);
    base.join("eGuard")
}

/// What a program file is, against the guard's copy.
#[derive(Debug, PartialEq, Eq)]
enum Check {
    Same,
    /// Missing or different: put back.
    Changed,
    /// The guard has no copy of it: nothing to put back.
    NoCopy,
}

fn check(installed: &Path, copy: &Path) -> Check {
    let Ok(Some(want)) = files::read_optional(copy) else { return Check::NoCopy };
    match std::fs::read(installed) {
        Ok(have) if have == want => Check::Same,
        _ => Check::Changed,
    }
}

/// Puts the guard's copy back at `installed`. A changed file is first moved aside (renaming works on a file Windows
/// is running, deleting doesn't) and deleted when it can be; one that can't be is left beside it, named for when.
fn restore(installed: &Path, copy: &Path) -> std::io::Result<()> {
    if installed.exists() {
        let secs = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs());
        let aside = installed.with_extension(format!("changed-{secs}"));
        std::fs::rename(installed, &aside)?;
        let _ = std::fs::remove_file(&aside);
    }
    std::fs::copy(copy, installed).map(|_| ())
}

/// The service's state; `None` when it isn't there (eGuard was removed) or can't be asked.
fn service_state() -> Option<ServiceState> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT).ok()?;
    let service = manager.open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS).ok()?;
    service.query_status().ok().map(|s| s.current_state)
}

fn start_service() -> Result<(), String> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT).map_err(|e| e.to_string())?;
    let service = manager.open_service(SERVICE_NAME, ServiceAccess::START).map_err(|e| e.to_string())?;
    service.start::<&str>(&[]).map_err(|e| e.to_string())
}

/// Tells the service, for the parent. False when it couldn't be reached (tried again next round).
fn tell(kind: TamperKind) -> bool {
    let Ok(mut pipe) = std::fs::OpenOptions::new().read(true).write(true).open(ipc::PIPE_NAME) else { return false };
    pipe.write_all(&ipc::encode(&Request::Tamper { kind })).is_ok() && ipc::read_line(&mut pipe).is_ok_and(|l| l.is_some())
}

fn main() {
    eguard_win::crash::install();
    logging::init("guard", Some(&files::program_data_dir().join("logs").join("guard.log")), false);
    let dir = install_dir();
    let cache = files::program_data_dir().join("cache");
    logging::info(&format!("eguard-guard {} watching {}", env!("CARGO_PKG_VERSION"), dir.display()));
    let mut held: Vec<Option<std::fs::File>> = PROGRAMS.iter().map(|_| None).collect();
    let mut untold = false;
    loop {
        let Some(state) = service_state() else {
            logging::info("eGuard's service isn't there any more; the guard ends");
            return;
        };
        for (i, p) in PROGRAMS.iter().enumerate() {
            // A file held since it last matched can't have changed
            if held[i].is_some() {
                continue;
            }
            let (installed, copy) = (dir.join(p), cache.join(p));
            match check(&installed, &copy) {
                Check::Same => {}
                Check::NoCopy => {
                    logging::error(&format!("the guard has no copy of {p}"));
                    continue;
                }
                Check::Changed => {
                    untold = true;
                    match restore(&installed, &copy) {
                        Ok(()) => logging::warn(&format!("{p} was missing or changed; put back")),
                        Err(e) => {
                            logging::error(&format!("{p} was missing or changed and couldn't be put back: {e}"));
                            continue;
                        }
                    }
                }
            }
            held[i] = files::hold(&installed).ok();
        }
        if untold && tell(TamperKind::FilesChanged) {
            untold = false;
        }
        if state == ServiceState::Stopped {
            match start_service() {
                Ok(()) => logging::warn("eGuard's service had stopped; started it again"),
                Err(e) => logging::error(&format!("eGuard's service has stopped and couldn't be started: {e}")),
            }
        }
        std::thread::sleep(ROUND);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_changed_or_missing_file_is_put_back_from_the_copy() {
        let dir = std::env::temp_dir().join(format!("eguard-guard-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let (installed, copy) = (dir.join("eguard-agent.exe"), dir.join("copy.exe"));
        assert_eq!(check(&installed, &copy), Check::NoCopy);
        std::fs::write(&copy, b"MZ eguard").unwrap();
        assert_eq!(check(&installed, &copy), Check::Changed);
        restore(&installed, &copy).unwrap();
        assert_eq!(check(&installed, &copy), Check::Same);
        std::fs::write(&installed, b"MZ something else").unwrap();
        assert_eq!(check(&installed, &copy), Check::Changed);
        restore(&installed, &copy).unwrap();
        assert_eq!(std::fs::read(&installed).unwrap(), b"MZ eguard");
        // The changed file was deleted after it was moved aside
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 2);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
