//! Removal protection (spec section 10): what locks eGuard in place, and taking all of it out again.
//!
//! `install` (`eguard-service install`, run as SYSTEM by the installer, or by an administrator on a VM) puts in place:
//!
//! | What | Where |
//! |---|---|
//! | The service: `LocalSystem`, automatic start, restarted on failure | the service manager, `eGuard` |
//! | Who may do what to it (`SERVICE_SDDL`) | the service's security descriptor |
//! | Started in Safe Mode too | `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\Minimal\eGuard`, `…\Network\eGuard` |
//! | The program folder: SYSTEM writes, everyone else reads and runs | `C:\Program Files\eGuard` (`INSTALL_DIR_SDDL`) |
//! | The data folder: SYSTEM writes, administrators read | `C:\ProgramData\eGuard` |
//! | The guard's copy of the program files | `C:\ProgramData\eGuard\cache` |
//! | The guard: a SYSTEM task at boot, restarted when it fails | Task Scheduler, `\eGuard\Guard` |
//!
//! The installer adds the program files and the Settings entry (`installer/eguard.wxs`). `purge` takes out every row
//! above, the browser policies and the data folder (all but `logs`), and ends eGuard's processes; the installer then
//! removes its own files and entry. Nothing is taken out unless eGuard may be removed (`may_be_removed`).

use crate::log;
use crate::store::Store;
use eguard_core::removal;
use eguard_win::registry::{Key, Root, View};
use eguard_win::{files, process, security, services};
use std::path::{Path, PathBuf};
use std::process::Command;

/// The service's permissions. SYSTEM: everything. Administrators: query, start, stop (the stop request reaches the
/// service, which refuses it outside an authorized removal and tells the parent: owner's decision, 2026-10-24),
/// interrogate, read the permissions; not change its configuration, delete it or change its permissions or owner.
/// Signed-in and service users: query only. No deny entries: SYSTEM's token holds the administrators group too, so a
/// deny for administrators would lock SYSTEM out as well.
pub const SERVICE_SDDL: &str =
    "D:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCLCSWRPWPDTLOCRRC;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)";

/// The program folder's permissions: SYSTEM writes; administrators and users read and run. Owned by SYSTEM.
pub const INSTALL_DIR_SDDL: &str = "O:SYD:P(A;OICI;FA;;;SY)(A;OICI;FRFX;;;BA)(A;OICI;FRFX;;;BU)";

/// The guard's task.
pub const GUARD_TASK: &str = r"\eGuard\Guard";

/// The three programs, in the program folder and in the guard's cache.
pub const PROGRAMS: [&str; 3] = ["eguard-service.exe", "eguard-agent.exe", "eguard-guard.exe"];

const SAFE_BOOT: [&str; 2] =
    [r"SYSTEM\CurrentControlSet\Control\SafeBoot\Minimal\eGuard", r"SYSTEM\CurrentControlSet\Control\SafeBoot\Network\eGuard"];

/// `C:\Program Files\eGuard`, where a real install's programs are.
pub fn install_dir() -> PathBuf {
    let base = std::env::var_os("ProgramFiles").map_or_else(|| PathBuf::from(r"C:\Program Files"), PathBuf::from);
    base.join("eGuard")
}

/// The guard's copy of the programs.
pub fn cache_dir() -> PathBuf {
    files::program_data_dir().join("cache")
}

/// This exe's folder, when it's the real install's: nothing is locked anywhere else (a developer's build folder).
fn installed_here() -> Result<PathBuf, String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let dir = exe.parent().ok_or("this program has no folder")?.to_owned();
    if !same_dir(&dir, &install_dir()) {
        return Err(format!("eGuard installs only from {} (this is {})", install_dir().display(), dir.display()));
    }
    Ok(dir)
}

fn same_dir(a: &Path, b: &Path) -> bool {
    a.to_string_lossy().trim_end_matches('\\').eq_ignore_ascii_case(b.to_string_lossy().trim_end_matches('\\'))
}

/// Whether eGuard may be removed now, from what's on disk (the installer's check and `purge` run without the
/// service): not paired, or a removal authorized and acknowledged. Fails closed: a state that can't be read but
/// secrets that exist mean paired and not removing.
pub fn may_be_removed() -> bool {
    let store = Store::at(&files::program_data_dir());
    let (state, secrets) = store.load();
    removal::may_be_removed(secrets.is_some() || state.agent.is_some() || store.has_secrets(), state.removing.as_ref())
}

/// Puts everything in the table above in place, and starts the service and the guard. Run again, it repairs what's
/// missing or changed.
pub fn install() -> Result<(), String> {
    let dir = installed_here()?;
    let data = files::program_data_dir();
    files::ensure_dir(&data, Some(security::DATA_DIR_SDDL)).map_err(|e| format!("{}: {e}", data.display()))?;
    std::fs::create_dir_all(cache_dir()).map_err(|e| format!("{}: {e}", cache_dir().display()))?;
    for p in PROGRAMS {
        std::fs::copy(dir.join(p), cache_dir().join(p)).map_err(|e| format!("copying {p} to the guard's cache: {e}"))?;
    }
    security::set_dir_security(&dir, INSTALL_DIR_SDDL).map_err(|e| format!("locking {}: {e}", dir.display()))?;
    crate::svc::register(&dir.join("eguard-service.exe"))?;
    services::set_security(crate::svc::SERVICE_NAME, SERVICE_SDDL).map_err(|e| format!("locking the service: {e}"))?;
    for k in SAFE_BOOT {
        let key = Key::create(Root::LocalMachine, k, View::Native).map_err(|e| format!("{k}: {e}"))?;
        key.set_string("", "Service").map_err(|e| format!("{k}: {e}"))?;
    }
    register_guard(&dir.join("eguard-guard.exe"))?;
    crate::svc::start()?;
    schtasks(&["/Run", "/TN", GUARD_TASK])?;
    Ok(())
}

/// What's in place, for `/report` (`UNINSTALL_PROTECTION`) and the log: `Ok` when every row of the table holds.
pub fn status() -> Result<(), String> {
    let off = |what: &str| {
        Err(format!("eGuard's removal protection isn't fully set up on this computer ({what}). Install eGuard again to repair it."))
    };
    match services::security(crate::svc::SERVICE_NAME) {
        Ok(sddl) if !admins_may_change(&sddl) => {}
        Ok(_) => return off("administrators can change the service"),
        Err(_) => return off("the service's permissions can't be read"),
    }
    if SAFE_BOOT.iter().any(|k| Key::open(Root::LocalMachine, k, View::Native).is_none()) {
        return off("Safe Mode");
    }
    if !task_exists() {
        return off("the guard");
    }
    if PROGRAMS.iter().any(|p| !cache_dir().join(p).is_file()) {
        return off("the guard's copy of the programs");
    }
    Ok(())
}

/// Whether an SDDL DACL gives administrators (`BA`) a right that changes or deletes the service.
fn admins_may_change(sddl: &str) -> bool {
    sddl.split('(').filter(|ace| ace.starts_with("A;") && ace.trim_end_matches(')').ends_with(";BA")).any(|ace| {
        let rights = ace.split(';').nth(2).unwrap_or("");
        ["DC", "SD", "WD", "WO", "GA", "GW"].iter().any(|r| rights.as_bytes().chunks(2).any(|c| c == r.as_bytes()))
    })
}

/// Takes out everything `install` put in place, the browser policies and the data folder (all but `logs`), and ends
/// eGuard's processes, the service's included (`me_too`: false when the service itself calls this and stops after).
/// Runs as SYSTEM. Carries on past what fails and returns it, in words; each step is logged.
pub fn purge(me_too: bool) -> Vec<String> {
    let mut left = Vec::new();
    let mut step = |what: &str, result: Result<(), String>| match result {
        Ok(()) => log::info(&format!("removed: {what}")),
        Err(e) => {
            log::error(&format!("couldn't remove {what}: {e}"));
            left.push(format!("{what}: {e}"));
        }
    };
    // The guard first: it would start the service again
    let _ = schtasks(&["/End", "/TN", GUARD_TASK]);
    step("the guard's task", if task_exists() { schtasks(&["/Delete", "/TN", GUARD_TASK, "/F"]) } else { Ok(()) });
    end_all("eguard-guard.exe");
    step("the service", crate::svc::delete_if_there());
    for k in SAFE_BOOT {
        // `SafeBoot\Minimal` and `\Network` are Windows' own and always there
        let parent = k.rsplit_once('\\').map_or("", |(p, _)| p);
        let result = Key::create(Root::LocalMachine, parent, View::Native).and_then(|key| key.delete_tree("eGuard"));
        step(k, result.map_err(|e| e.to_string()));
    }
    step("the browser policies", crate::web::remove_machine());
    end_all("eguard-agent.exe");
    if me_too {
        end_all("eguard-service.exe");
    }
    let data = files::program_data_dir();
    let leftovers = if data.exists() { Store::at(&data).remove_all() } else { Vec::new() };
    step("the data folder (but logs)", if leftovers.is_empty() { Ok(()) } else { Err(leftovers.join("; ")) });
    left
}

/// Ends every running copy of eGuard's `exe` (from the program folder) but this process.
pub fn end_all(exe: &str) {
    for pid in process::end_program(&install_dir().join(exe)) {
        log::info(&format!("ended {exe} ({pid})"));
    }
}

/// Whether the guard is running (from the program folder).
pub fn guard_running() -> bool {
    !process::running_program(&install_dir().join("eguard-guard.exe")).is_empty()
}

fn task_exists() -> bool {
    Command::new("schtasks.exe").args(["/Query", "/TN", GUARD_TASK]).output().is_ok_and(|o| o.status.success())
}

fn schtasks(args: &[&str]) -> Result<(), String> {
    let out = Command::new("schtasks.exe").args(args).output().map_err(|e| format!("schtasks: {e}"))?;
    if out.status.success() { Ok(()) } else { Err(format!("schtasks {}: {}", args[0], String::from_utf8_lossy(&out.stderr).trim())) }
}

/// The guard's task: SYSTEM, at boot, never stopped for running long, restarted every minute when it fails. Its own
/// permissions let administrators read and run it, not change or delete it.
fn register_guard(exe: &Path) -> Result<(), String> {
    let xml = guard_task_xml(exe);
    let path = files::program_data_dir().join("guard-task.xml");
    // Task Scheduler reads the file as UTF-16, as its own exports are
    let mut bytes = vec![0xFF, 0xFE];
    bytes.extend(xml.encode_utf16().flat_map(u16::to_le_bytes));
    std::fs::write(&path, bytes).map_err(|e| format!("{}: {e}", path.display()))?;
    let result = schtasks(&["/Create", "/TN", GUARD_TASK, "/XML", &path.to_string_lossy(), "/F"]);
    let _ = std::fs::remove_file(&path);
    result
}

fn guard_task_xml(exe: &Path) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>eGuard's guard: starts eGuard's service again if it stops and puts back its files if they change.</Description>
    <SecurityDescriptor>D:P(A;;FA;;;SY)(A;;FRFX;;;BA)</SecurityDescriptor>
  </RegistrationInfo>
  <Triggers>
    <BootTrigger><Enabled>true</Enabled></BootTrigger>
  </Triggers>
  <Principals>
    <Principal id="System"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <RestartOnFailure><Interval>PT1M</Interval><Count>999</Count></RestartOnFailure>
    <IdleSettings><StopOnIdleEnd>false</StopOnIdleEnd><RestartOnIdle>false</RestartOnIdle></IdleSettings>
  </Settings>
  <Actions Context="System">
    <Exec><Command>"{}"</Command></Exec>
  </Actions>
</Task>
"#,
        exe.display()
    )
}

/// Starts the guard's task when no guard is running (it was ended, or its task failed for good). The service calls
/// this about once a minute; the guard does the same for the service.
pub fn keep_guard_running() {
    if !guard_running() {
        match schtasks(&["/Run", "/TN", GUARD_TASK]) {
            Ok(()) => log::warn("eGuard's guard wasn't running; started it again"),
            Err(e) => log::error(&format!("eGuard's guard isn't running and couldn't be started: {e}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn administrators_may_not_change_the_locked_service() {
        assert!(!admins_may_change(SERVICE_SDDL));
        // Windows' default for a new service: administrators may do anything
        assert!(admins_may_change("D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)"));
        assert!(admins_may_change("D:(A;;GA;;;BA)"));
        // Two-letter rights are read in pairs: "LCSW" holds no "CS"-style false match of "SD"
        assert!(!admins_may_change("D:(A;;LCSWLO;;;BA)"));
        assert!(eguard_win::security::SecurityDescriptor::from_sddl(SERVICE_SDDL).is_ok());
        assert!(eguard_win::security::SecurityDescriptor::from_sddl(INSTALL_DIR_SDDL).is_ok());
    }

    #[test]
    fn the_guards_task_names_its_program() {
        let xml = guard_task_xml(Path::new(r"C:\Program Files\eGuard\eguard-guard.exe"));
        assert!(xml.contains(r#"<Command>"C:\Program Files\eGuard\eguard-guard.exe"</Command>"#));
        assert!(xml.contains("<UserId>S-1-5-18</UserId>"));
    }

    #[test]
    fn nothing_installs_from_a_build_folder() {
        assert!(installed_here().unwrap_err().contains("installs only from"));
    }
}
