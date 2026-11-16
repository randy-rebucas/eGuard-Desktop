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

/// The server this build talks to: `EGUARD_SERVER_URL` at compile time, else production for a build that trusts
/// production's key and the local dev server for one that trusts the dev key (each can only check its own server's
/// signatures).
const DEFAULT_SERVER: &str = match option_env!("EGUARD_SERVER_URL") {
    Some(url) => url,
    None if keys::is_dev_build() => "http://localhost:3000",
    None => "https://www.eguard.family",
};

/// Whether `url` starts with `https://`, at compile time.
const fn is_https(url: &str) -> bool {
    let (u, want) = (url.as_bytes(), b"https://");
    if u.len() < want.len() {
        return false;
    }
    let mut i = 0;
    while i < want.len() {
        if u[i] != want[i] {
            return false;
        }
        i += 1;
    }
    true
}

// A build with the production key and an `http://` server would compile, then fail at every start and protect
// nothing: refused here instead (`release.ps1` checks it too)
const _: () = assert!(keys::is_dev_build() || is_https(DEFAULT_SERVER), "EGUARD_SERVER_URL must be https:// for a release");

fn server_url(arg: Option<&str>) -> Result<ServerUrl, String> {
    // Only a development build may be pointed elsewhere at run time
    if arg.is_some() && !keys::is_dev_build() {
        return Err("--server is only for development builds".into());
    }
    let url = arg.unwrap_or(DEFAULT_SERVER);
    ServerUrl::parse(url, keys::is_dev_build()).map_err(|e| e.to_string())
}

/// The runner as the Windows service: `%ProgramData%\eGuard`, locked down, pipe for SYSTEM and administrators. The
/// log starts as soon as the folder is locked down, so whatever fails after it (`WinHTTP`, the server URL) is logged.
pub(crate) fn service_runner() -> Result<Arc<Runner>, String> {
    let dir = eguard_win::files::program_data_dir();
    let store = match Store::open(&dir, Some(eguard_win::security::DATA_DIR_SDDL)) {
        Ok(s) => s,
        Err(e) => {
            // The folder isn't eGuard's (someone else made it, or a link to elsewhere): SYSTEM writes nothing in it,
            // a log included. The service manager keeps the error
            log::init(None, false);
            return Err(format!("{}: {e}", dir.display()));
        }
    };
    log::init(locked_logs(&dir).as_deref(), false);
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
/// written (SYSTEM), so the steps are there to read after the program files have gone. Made and checked like the
/// data folder first: these steps run as SYSTEM, perhaps before `install` has locked anything down.
fn installer_log() {
    let dir = eguard_win::files::program_data_dir();
    let logs = eguard_win::files::ensure_dir(&dir, Some(eguard_win::security::DATA_DIR_SDDL)).ok().and_then(|()| locked_logs(&dir));
    log::init(logs.as_deref(), false);
}

/// `logs` in the data folder `dir`, made or checked as eGuard's own (`ensure_dir`: never a folder or link someone
/// else put there, which would have SYSTEM create, rename and delete files where they chose). `None` when it can't
/// be: nothing is logged to a file then.
fn locked_logs(dir: &std::path::Path) -> Option<PathBuf> {
    let logs = dir.join("logs");
    eguard_win::files::ensure_dir(&logs, Some(eguard_win::security::DATA_DIR_SDDL)).ok().map(|()| logs)
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
