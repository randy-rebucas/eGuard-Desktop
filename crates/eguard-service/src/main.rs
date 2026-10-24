//! `eguard-service`: holds the device token, pairs, syncs and reports (spec section 3).
//!
//! ```text
//! eguard-service                      started by Windows as the eGuard service
//! eguard-service run [--server URL] [--data-dir DIR] [--sandbox DIR]
//!                                     the same work in this console (development; Ctrl+C stops it). Programs are
//!                                     ended only inside --sandbox; without it, what would be ended is logged
//! eguard-service install | uninstall  register / remove the Windows service (administrator; use a VM)
//! ```
//!
//! Console mode keeps its data in `%LOCALAPPDATA%\eGuard\dev`, not `%ProgramData%\eGuard`: a folder made there by
//! an ordinary user would belong to that user, and a later real install must not inherit it.

#![windows_subsystem = "console"]

mod lockdown;
mod log;
mod monitor;
mod runner;
mod scan;
mod sessions;
mod store;
mod svc;
mod update;
mod web;

use eguard_core::api::ServerUrl;
use eguard_core::keys;
use runner::{Mode, Options, Runner};
use std::path::PathBuf;
use std::sync::Arc;
use store::Store;

/// The server this build talks to: `EGUARD_SERVER_URL` at compile time, or the local dev server in a dev build.
const DEFAULT_SERVER: Option<&str> = match option_env!("EGUARD_SERVER_URL") {
    Some(url) => Some(url),
    None if keys::is_dev_build() => Some("http://localhost:3000"),
    None => None,
};

fn server_url(arg: Option<&str>) -> Result<ServerUrl, String> {
    // Only a development build may be pointed elsewhere at run time
    if arg.is_some() && !keys::is_dev_build() {
        return Err("--server is only for development builds".into());
    }
    let url = arg.or(DEFAULT_SERVER).ok_or("this build has no server URL (set EGUARD_SERVER_URL when building)")?;
    ServerUrl::parse(url, keys::is_dev_build()).map_err(|e| e.to_string())
}

/// The runner as the Windows service: `%ProgramData%\eGuard`, locked down, pipe for SYSTEM and administrators. The
/// log starts as soon as the folder is locked down, so whatever fails after it (`WinHTTP`, the server URL) is logged.
pub(crate) fn service_runner() -> Result<Arc<Runner>, String> {
    let dir = eguard_win::files::program_data_dir();
    let logs = dir.join("logs");
    let store = match Store::open(&dir, Some(eguard_win::security::DATA_DIR_SDDL)) {
        Ok(s) => s,
        Err(e) => {
            // The log is still wanted for this one line, if the folder can be written at all (the caller logs it)
            log::init(Some(&logs), false);
            return Err(format!("{}: {e}", dir.display()));
        }
    };
    log::init(Some(&logs), false);
    Runner::new(Options { store, server: server_url(None)?, pipe_sddl: eguard_win::pipe::SERVICE_PIPE_SDDL.into(), mode: Mode::Service })
}

fn console(args: &[String]) -> Result<(), String> {
    let mut server = None;
    let mut data_dir = None;
    let mut sandbox = None;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--server" => server = Some(it.next().ok_or("--server needs a URL")?.clone()),
            "--data-dir" => data_dir = Some(PathBuf::from(it.next().ok_or("--data-dir needs a folder")?)),
            "--sandbox" => sandbox = Some(PathBuf::from(it.next().ok_or("--sandbox needs a folder")?)),
            other => return Err(format!("unknown option {other}")),
        }
    }
    let dir = data_dir.unwrap_or_else(|| {
        let base = std::env::var_os("LOCALAPPDATA").map_or_else(std::env::temp_dir, PathBuf::from);
        base.join("eGuard").join("dev")
    });
    let store = Store::open(&dir, None).map_err(|e| format!("{}: {e}", dir.display()))?;
    log::init(Some(&dir.join("logs")), true);
    let sid = eguard_win::security::current_user_sid().map_err(|e| e.to_string())?;
    let runner = Runner::new(Options {
        store,
        server: server_url(server.as_deref())?,
        pipe_sddl: eguard_win::pipe::console_pipe_sddl(&sid),
        mode: Mode::Console { sandbox },
    })?;
    runner.run()
}

fn usage() -> String {
    "usage: eguard-service run [--server URL] [--data-dir DIR] [--sandbox DIR] | scan | web | install | msi-check | purge [--force]".into()
}

/// The log for the installer's steps (`msi-check`, `purge`, `install`): eGuard's own log folder when it can be
/// written (SYSTEM), so the steps are there to read after the program files have gone.
fn installer_log() {
    log::init(Some(&eguard_win::files::program_data_dir().join("logs")), false);
}

/// The installer's uninstall check (spec section 10: `msiexec /x` is refused unless eGuard may be removed). Exit 0
/// lets the uninstall go on; anything else makes the installer roll it back. A refused one goes to the parent as
/// `UNINSTALL_BLOCKED`, through the running service.
fn msi_check() -> Result<(), String> {
    installer_log();
    if lockdown::may_be_removed() {
        log::info("uninstall check: eGuard may be removed");
        return Ok(());
    }
    let told = ask_service(&eguard_core::ipc::Request::Tamper { kind: eguard_core::wire::TamperKind::UninstallBlocked }).is_ok();
    Err(format!("eGuard can only be removed by a parent, from the eGuard dashboard{}.", if told { "; the parent was told" } else { "" }))
}

/// `purge`: takes out everything eGuard put on this computer but the program files (`lockdown::purge`), as SYSTEM,
/// when eGuard may be removed. `--force`, development builds only: whatever the state says (a VM between test runs).
fn purge(args: &[String]) -> Result<(), String> {
    installer_log();
    let force = args.iter().any(|a| a == "--force");
    if force && !keys::is_dev_build() {
        return Err("--force is only for development builds".into());
    }
    if !force && !lockdown::may_be_removed() {
        return Err("eGuard can only be removed by a parent, from the eGuard dashboard.".into());
    }
    let left = lockdown::purge(true);
    if left.is_empty() { Ok(()) } else { Err(format!("eGuard was removed except: {}", left.join("; "))) }
}

/// One request on the admin pipe.
fn ask_service(request: &eguard_core::ipc::Request) -> Result<eguard_core::ipc::Response, String> {
    use std::io::Write;
    let mut pipe = std::fs::OpenOptions::new().read(true).write(true).open(eguard_core::ipc::PIPE_NAME).map_err(|e| e.to_string())?;
    pipe.write_all(&eguard_core::ipc::encode(request)).map_err(|e| e.to_string())?;
    let line = eguard_core::ipc::read_line(&mut pipe).map_err(|e| e.to_string())?.ok_or("the service closed the connection")?;
    eguard_core::ipc::decode(&line).map_err(|e| e.to_string())
}

fn main() {
    eguard_win::crash::install();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("run") => console(&args[1..]),
        Some("scan") => scan::run(&args[1..]),
        Some("install") => {
            installer_log();
            lockdown::install().map(|()| println!("eGuard installed, locked and started"))
        }
        Some("msi-check") => msi_check(),
        Some("purge") => purge(&args[1..]),
        Some("web") => {
            web::show();
            Ok(())
        }
        Some(_) => Err(usage()),
        // No arguments: Windows started us. If not, the dispatcher fails at once and we say how to run it
        None => svc::dispatch().map_err(|_| usage()),
    };
    if let Err(e) = result {
        log::error(&e);
        eprintln!("{e}");
        std::process::exit(1);
    }
}
