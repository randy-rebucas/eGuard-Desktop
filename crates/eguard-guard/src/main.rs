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
//!
//! An update (spec section 10; `eguard_core::update`) is the one time the program files change on purpose. The service
//! puts the new version in the cache, keeps the old one in `cache\previous`, writes `update.json` and stops. The guard
//! then puts the cache's files in place (no `FILES_CHANGED`: it's eGuard's own change), starts the new version and
//! waits for it to say it works. If it doesn't within 10 minutes, the guard puts the previous version back.

use eguard_core::ipc::{self, Request};
use eguard_core::logging;
use eguard_core::update::{self, GuardAction, Handoff, Health, Outcome, Step};
use eguard_core::wire::TamperKind;
use eguard_win::{files, process};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use windows_service::service::{ServiceAccess, ServiceState};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

const ROUND: Duration = Duration::from_secs(10);
/// While an update's files are swapped: the computer has no service between the old version's stop and the new one's
/// start.
const UPDATE_ROUND: Duration = Duration::from_secs(1);
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
/// is running, deleting doesn't) and deleted when it can be; one that can't be is left beside it, named for why
/// (`tag`) and when, and deleted by a later guard (`sweep`).
fn restore(installed: &Path, copy: &Path, tag: &str) -> std::io::Result<()> {
    if installed.exists() {
        let secs = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs());
        let aside = installed.with_extension(format!("{tag}-{secs}"));
        std::fs::rename(installed, &aside)?;
        let _ = std::fs::remove_file(&aside);
    }
    std::fs::copy(copy, installed).map(|_| ())
}

/// Deletes the files set aside in `dir` (`restore`) that nothing runs any more.
fn sweep(dir: &Path) {
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for e in entries.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        let aside = name.split_once('.').is_some_and(|(_, ext)| ext.starts_with("old-") || ext.starts_with("changed-"));
        if aside && std::fs::remove_file(e.path()).is_ok() {
            logging::info(&format!("deleted {name}, set aside earlier"));
        }
    }
}

/// Puts every program file that differs from the cache's in place. An update's: the old one is set aside as `old`.
fn put_in_place(dir: &Path, cache: &Path) -> Result<(), String> {
    for p in update::PROGRAMS {
        let (installed, copy) = (dir.join(p), cache.join(p));
        match check(&installed, &copy) {
            Check::Same => {}
            Check::NoCopy => return Err(format!("the cache has no {p}")),
            Check::Changed => restore(&installed, &copy, "old").map_err(|e| format!("{p}: {e}"))?,
        }
    }
    Ok(())
}

/// The previous version back in the cache, from `cache\previous`.
fn previous_to_cache(cache: &Path) -> Result<(), String> {
    let previous = cache.join(update::PREVIOUS_DIR);
    for p in update::PROGRAMS {
        let bytes = std::fs::read(previous.join(p)).map_err(|e| format!("the previous {p}: {e}"))?;
        files::write_atomic(&cache.join(p), &bytes).map_err(|e| format!("{p}: {e}"))?;
    }
    Ok(())
}

/// Takes out the update's own files: the hand-off, the health and the previous version.
fn finish(cache: &Path) {
    let _ = std::fs::remove_file(cache.join(update::HANDOFF_FILE));
    let _ = std::fs::remove_file(cache.join(update::HEALTH_FILE));
    let _ = std::fs::remove_dir_all(cache.join(update::PREVIOUS_DIR));
}

fn read<T: serde::de::DeserializeOwned>(path: &Path) -> Option<T> {
    files::read_optional(path).ok().flatten().and_then(|b| serde_json::from_slice(&b).ok())
}

/// Ends the service (it didn't stop by itself, or the new version is being rolled back) and puts the cache's files
/// in place. The service manager restarts an ended service within seconds, so this tries again for a while: once
/// it has started from the old files they're held again.
fn end_service_and_put_in_place(dir: &Path, cache: &Path) -> Result<(), String> {
    let mut last = String::new();
    for _ in 0..40 {
        for pid in process::end_program(&dir.join("eguard-service.exe")) {
            logging::warn(&format!("ended eGuard's service ({pid}) for the update"));
        }
        // Ended on purpose: its next start isn't a restart to tell the parent about (`SERVICE_RESTARTED`)
        let _ = std::fs::remove_file(files::program_data_dir().join("running"));
        match put_in_place(dir, cache) {
            Ok(()) => return Ok(()),
            Err(e) => last = e,
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    Err(last)
}

/// Carries an update on (`update::guard_action`). Returns true when this guard should end: the new version works,
/// and the service starts the new guard.
fn update_step(dir: &Path, cache: &Path, h: &Handoff, action: GuardAction) -> bool {
    let write_handoff = |h: &Handoff| files::write_atomic(&cache.join(update::HANDOFF_FILE), &serde_json::to_vec(h).unwrap_or_default());
    match action {
        GuardAction::Wait => {}
        GuardAction::Swap { end_service } => {
            let placed = if end_service { end_service_and_put_in_place(dir, cache) } else { put_in_place(dir, cache) };
            match placed {
                Ok(()) => {
                    match write_handoff(&Handoff { step: Step::Running, ..h.clone() }) {
                        Ok(()) => logging::info(&format!("eGuard {} is in place of {}; starting it", h.to, h.from)),
                        Err(e) => logging::error(&format!("eGuard {} is in place, but the hand-off couldn't be updated: {e}", h.to)),
                    }
                    if let Err(e) = start_service() {
                        logging::error(&format!("eGuard {} couldn't be started: {e}", h.to));
                    }
                }
                Err(e) => logging::warn(&format!("eGuard {} couldn't be put in place yet: {e}", h.to)),
            }
        }
        GuardAction::Commit => {
            finish(cache);
            sweep(dir);
            logging::info(&format!("eGuard {} works; the previous version {} is gone. This guard ends for the new one", h.to, h.from));
            return true;
        }
        GuardAction::RollBack => {
            let why = match h.step {
                Step::Swap => "it couldn't be put in place within 10 minutes",
                Step::Running => "it didn't sync and save its state within 10 minutes",
            };
            logging::error(&format!("eGuard {}: {why}; putting {} back", h.to, h.from));
            if let Err(e) = previous_to_cache(cache) {
                // Without the previous version there's nothing to go back to: the new one stays, and the guard
                // goes on keeping it
                logging::error(&format!("the previous version can't be put back ({e}); {} stays", h.to));
                finish(cache);
                return false;
            }
            if let Err(e) = end_service_and_put_in_place(dir, cache) {
                logging::error(&format!("{} couldn't be put back yet: {e}; trying again", h.from));
                return false;
            }
            let outcome = Outcome { version: h.to.clone(), why: why.into() };
            let _ = files::write_atomic(&cache.join(update::OUTCOME_FILE), &serde_json::to_vec(&outcome).unwrap_or_default());
            finish(cache);
            match start_service() {
                Ok(()) => logging::warn(&format!("eGuard {} is back in place and started", h.from)),
                Err(e) => logging::error(&format!("eGuard {} is back in place but couldn't be started: {e}", h.from)),
            }
        }
    }
    false
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
    logging::info(&format!("eguard-guard {} watching {}", update::VERSION, dir.display()));
    let mut held: Vec<Option<std::fs::File>> = PROGRAMS.iter().map(|_| None).collect();
    let mut untold = false;
    // The update step last seen, and since when by this guard's own clock
    let mut seen: Option<(Step, Instant)> = None;
    sweep(&dir);
    loop {
        let Some(state) = service_state() else {
            logging::info("eGuard's service isn't there any more; the guard ends");
            return;
        };
        let handoff = read::<Handoff>(&cache.join(update::HANDOFF_FILE));
        if let Some(h) = &handoff {
            let since = match seen {
                Some((step, at)) if step == h.step => at,
                _ => seen.insert((h.step, Instant::now())).1,
            };
            let healthy = read::<Health>(&cache.join(update::HEALTH_FILE)).map(|x| x.version);
            let waited = u64::try_from(since.elapsed().as_millis()).unwrap_or(u64::MAX);
            let action = update::guard_action(h, state == ServiceState::Stopped, waited, healthy.as_deref());
            // The files may change now: nothing of them is held
            if matches!(action, GuardAction::Swap { .. } | GuardAction::RollBack) {
                held.fill_with(|| None);
            }
            if update_step(&dir, &cache, h, action) {
                return;
            }
            // Between two versions the program files aren't compared with the cache (they differ on purpose), and after
            // a swap or a rollback the next round starts from what's there now
            if h.step == Step::Swap || action != GuardAction::Wait {
                std::thread::sleep(UPDATE_ROUND);
                continue;
            }
        } else {
            seen = None;
        }
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
                    match restore(&installed, &copy, "changed") {
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
        restore(&installed, &copy, "changed").unwrap();
        assert_eq!(check(&installed, &copy), Check::Same);
        std::fs::write(&installed, b"MZ something else").unwrap();
        assert_eq!(check(&installed, &copy), Check::Changed);
        restore(&installed, &copy, "changed").unwrap();
        assert_eq!(std::fs::read(&installed).unwrap(), b"MZ eguard");
        // The changed file was deleted after it was moved aside
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 2);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A program folder with version `v` of the three programs, and a cache with `cache` in it and `previous` kept.
    fn folders(name: &str, v: &str, cache_v: &str) -> (PathBuf, PathBuf, PathBuf) {
        let root = std::env::temp_dir().join(format!("eguard-guard-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let (dir, cache) = (root.join("program"), root.join("cache"));
        std::fs::create_dir_all(cache.join(update::PREVIOUS_DIR)).unwrap();
        std::fs::create_dir_all(&dir).unwrap();
        for p in update::PROGRAMS {
            std::fs::write(dir.join(p), format!("MZ {p} {v}")).unwrap();
            std::fs::write(cache.join(p), format!("MZ {p} {cache_v}")).unwrap();
            std::fs::write(cache.join(update::PREVIOUS_DIR).join(p), format!("MZ {p} {v}")).unwrap();
        }
        (root, dir, cache)
    }

    fn version_of(dir: &Path) -> Vec<String> {
        update::PROGRAMS.iter().map(|p| std::fs::read_to_string(dir.join(p)).unwrap().rsplit(' ').next().unwrap().to_owned()).collect()
    }

    #[test]
    fn an_update_is_put_in_place_and_the_old_files_swept_once_nothing_runs_them() {
        let (root, dir, cache) = folders("swap", "0.1.0", "0.2.0");
        put_in_place(&dir, &cache).unwrap();
        assert_eq!(version_of(&dir), ["0.2.0"; 3]);
        // Nothing ran them here, so the old files were deleted at once; one left over (a running one) is swept later
        std::fs::write(dir.join("eguard-guard.old-1"), b"MZ").unwrap();
        std::fs::write(dir.join("notes.txt"), b"kept").unwrap();
        sweep(&dir);
        let mut left: Vec<String> =
            std::fs::read_dir(&dir).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
        left.sort();
        assert_eq!(left, ["eguard-agent.exe", "eguard-guard.exe", "eguard-service.exe", "notes.txt"]);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn a_rollback_puts_the_previous_version_in_the_cache_and_the_update_files_go() {
        let (root, dir, cache) = folders("rollback", "0.1.0", "0.2.0");
        put_in_place(&dir, &cache).unwrap();
        std::fs::write(cache.join(update::HANDOFF_FILE), br#"{"from":"0.1.0","to":"0.2.0","step":"running"}"#).unwrap();
        std::fs::write(cache.join(update::HEALTH_FILE), br#"{"version":"0.1.0"}"#).unwrap();
        previous_to_cache(&cache).unwrap();
        put_in_place(&dir, &cache).unwrap();
        assert_eq!(version_of(&dir), ["0.1.0"; 3]);
        assert_eq!(version_of(&cache), ["0.1.0"; 3]);
        finish(&cache);
        let left: Vec<String> = std::fs::read_dir(&cache).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
        assert_eq!(left.len(), 3, "{left:?}");
        // Without a previous version there's nothing to go back to
        assert!(previous_to_cache(&cache).is_err());
        std::fs::remove_dir_all(&root).unwrap();
    }
}
