//! Running processes, seen from outside (spec principle: nothing touches a game's process from the inside). eGuard
//! lists them, reads where each one's executable is, and ends a blocked one with `TerminateProcess`. It never reads
//! or writes another process's memory, injects anything or attaches a debugger.
#![allow(unsafe_code)]

use crate::wide::from_wide;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_INSUFFICIENT_BUFFER, ERROR_SHARING_VIOLATION, FILETIME, GetLastError, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::RemoteDesktop::ProcessIdToSessionId;
use windows_sys::Win32::System::Threading::{
    GetCurrentProcessId, GetExitCodeProcess, GetProcessTimes, OpenProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
    PROCESS_TERMINATE, QueryFullProcessImageNameW, TerminateProcess,
};

/// The exit code eGuard ends a process with ("eGua" in ASCII), so it can be told apart in a crash report.
const ENDED_BY_EGUARD: u32 = 0x6547_7561;

/// One entry of the process list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessEntry {
    pub pid: u32,
    pub parent: u32,
    /// The executable's file name (no folder).
    pub exe: String,
}

/// A process handle, closed on drop.
struct Handle(HANDLE);

// A kernel handle: usable from any thread
unsafe impl Send for Handle {}

impl Handle {
    fn open(pid: u32, access: u32) -> Option<Self> {
        // SAFETY: plain call; a null result means no access or no such process.
        let h = unsafe { OpenProcess(access, 0, pid) };
        (!h.is_null()).then_some(Self(h))
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        // SAFETY: a handle we opened, closed once.
        unsafe { CloseHandle(self.0) };
    }
}

/// A process eGuard started, with its handle kept so how it ended can be read (a killed agent is a tamper event).
#[derive(Debug)]
pub struct Child {
    pub pid: u32,
    handle: Handle,
}

impl std::fmt::Debug for Handle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Handle")
    }
}

/// `GetExitCodeProcess`'s answer for a process still running.
const STILL_ACTIVE: u32 = 259;

impl Child {
    /// Takes the handle `CreateProcess*` returned.
    pub(crate) fn from_handle(pid: u32, handle: HANDLE) -> Self {
        Self { pid, handle: Handle(handle) }
    }

    /// Takes over a child started with `std::process::Command`.
    pub fn from_std(child: std::process::Child) -> Self {
        use std::os::windows::io::IntoRawHandle;
        let pid = child.id();
        Self { pid, handle: Handle(child.into_raw_handle() as HANDLE) }
    }

    /// `None` while it runs; its exit code once it has ended.
    pub fn exit_code(&self) -> Option<u32> {
        let mut code = 0u32;
        // SAFETY: our own process handle; `code` is a live out-parameter.
        let ok = unsafe { GetExitCodeProcess(self.handle.0, &raw mut code) } != 0;
        (ok && code != STILL_ACTIVE).then_some(code)
    }
}

/// Every process now. Empty if the snapshot fails (rare: out of memory).
pub fn list() -> Vec<ProcessEntry> {
    // SAFETY: plain call; the handle is closed below.
    let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snap == INVALID_HANDLE_VALUE {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut e = PROCESSENTRY32W { dwSize: size_of::<PROCESSENTRY32W>() as u32, ..Default::default() };
    // SAFETY: `e` is a live entry with its size set, as the walk requires.
    let mut more = unsafe { Process32FirstW(snap, &raw mut e) } != 0;
    while more {
        out.push(ProcessEntry { pid: e.th32ProcessID, parent: e.th32ParentProcessID, exe: from_wide(&e.szExeFile) });
        // SAFETY: as above.
        more = unsafe { Process32NextW(snap, &raw mut e) } != 0;
    }
    // SAFETY: opened above, closed once.
    unsafe { CloseHandle(snap) };
    out
}

/// The full path of `pid`'s executable. Works for any process the caller can query, which as SYSTEM is all but the
/// protected ones (and those are Windows' own).
pub fn image_path(pid: u32) -> Option<PathBuf> {
    image_path_of(&Handle::open(pid, PROCESS_QUERY_LIMITED_INFORMATION)?)
}

/// The executable's path of an open process. A path longer than the first buffer (deep folders) is
/// read again with room for the longest path Windows allows, so it isn't mistaken for "can't be read".
fn image_path_of(h: &Handle) -> Option<PathBuf> {
    for size in [1024usize, 32_768] {
        let mut buf = vec![0u16; size];
        let mut len = buf.len() as u32;
        // SAFETY: `buf` holds `len` u16s; on success `len` is the length written.
        if unsafe { QueryFullProcessImageNameW(h.0, PROCESS_NAME_WIN32, buf.as_mut_ptr(), &raw mut len) } != 0 {
            return Some(PathBuf::from(from_wide(&buf[..(len as usize).min(buf.len())])));
        }
        // SAFETY: plain call, right after the failing one.
        if unsafe { GetLastError() } != ERROR_INSUFFICIENT_BUFFER {
            return None;
        }
    }
    None
}

/// When `pid` started (FILETIME ticks), to tell a process from a later one that reused its id.
pub fn start_time(pid: u32) -> Option<u64> {
    created(&Handle::open(pid, PROCESS_QUERY_LIMITED_INFORMATION)?)
}

/// Whether the file at `path` is still the one a process that started at `started` (FILETIME ticks) runs.
///
/// A running program's file can be renamed and another file put at its path, which would then be judged instead
/// (a game swapped for a trusted publisher's exe right after it started). Two things only the running file has:
/// - Windows refuses to open it for writing while it runs (a sharing violation; nobody can choose that answer,
///   unlike "access denied", which a file's owner can arrange). It's only opened, never written.
/// - It wasn't created, written or changed (renamed or moved into place) after the process started.
///
/// `false` when either fails: the program is then judged as an unknown one, the stricter reading.
pub fn still_its_file(path: &Path, started: u64) -> bool {
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_BASIC_INFO, FILE_READ_ATTRIBUTES, FILE_WRITE_DATA, FileBasicInfo, GetFileInformationByHandleEx,
    };
    let refused = std::fs::OpenOptions::new().access_mode(FILE_WRITE_DATA).open(path).err();
    if refused.and_then(|e| e.raw_os_error()) != Some(ERROR_SHARING_VIOLATION as i32) {
        return false;
    }
    let Ok(f) = std::fs::OpenOptions::new().access_mode(FILE_READ_ATTRIBUTES).open(path) else { return false };
    let mut info = FILE_BASIC_INFO::default();
    // SAFETY: `f` is an open file; `info` is a live FILE_BASIC_INFO and its size is passed.
    let ok = unsafe {
        GetFileInformationByHandleEx(
            f.as_raw_handle() as HANDLE,
            FileBasicInfo,
            (&raw mut info).cast(),
            size_of::<FILE_BASIC_INFO>() as u32,
        )
    } != 0;
    let started = i64::try_from(started).unwrap_or(i64::MAX);
    ok && [info.CreationTime, info.LastWriteTime, info.ChangeTime].iter().all(|&t| t <= started)
}

/// When the process behind `h` started (FILETIME ticks). Read on the handle that will be used, so the answer is
/// about that very process and not a later one with the same id.
fn created(h: &Handle) -> Option<u64> {
    let (mut created, mut exited, mut kernel, mut user) =
        (FILETIME::default(), FILETIME::default(), FILETIME::default(), FILETIME::default());
    // SAFETY: four live FILETIMEs for the four out-parameters.
    let ok = unsafe { GetProcessTimes(h.0, &raw mut created, &raw mut exited, &raw mut kernel, &raw mut user) } != 0;
    ok.then(|| (u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime))
}

/// The session `pid` runs in.
pub fn session_of(pid: u32) -> Option<u32> {
    let mut session = 0u32;
    // SAFETY: `session` is a live out-parameter.
    (unsafe { ProcessIdToSessionId(pid, &raw mut session) } != 0).then_some(session)
}

/// This process's id.
pub fn current_pid() -> u32 {
    // SAFETY: no arguments.
    unsafe { GetCurrentProcessId() }
}

/// `pid` (which started at `start`) and everything it started (and they started), from `procs`, each with when
/// it started. A child must have started after its parent, so a process that only inherited a dead parent's reused
/// id isn't taken along; a process whose start can't be read is left out, and so are its children (nothing tells
/// whether they are really its own).
pub fn tree(pid: u32, start: u64, procs: &[ProcessEntry]) -> Vec<(u32, u64)> {
    let mut children: HashMap<u32, Vec<u32>> = HashMap::new();
    for p in procs {
        if p.pid != p.parent {
            children.entry(p.parent).or_default().push(p.pid);
        }
    }
    let mut out = vec![(pid, start)];
    let mut seen: HashSet<u32> = HashSet::from([pid]);
    let mut i = 0;
    while i < out.len() {
        let (parent, parent_start) = out[i];
        for &c in children.get(&parent).map_or(&[][..], Vec::as_slice) {
            if let Some(child_start) = start_time(c).filter(|&s| s >= parent_start)
                && seen.insert(c)
            {
                out.push((c, child_start));
            }
        }
        i += 1;
    }
    out
}

/// Ends `pid` and its tree, children first, when `pid` is still the process that started at `start`; otherwise
/// (gone, or its id reused) ends nothing. Each process is checked again on the very handle that ends it, so one
/// that took over a dead process's id between the listing and the end is left alone. `keep(pid)` decides for each
/// one whether it may be ended (console mode's sandbox); it's asked while that process's handle is held open, so
/// the id can't change hands meanwhile. Returns how many were ended. eGuard's own process is never touched.
pub fn end_tree(pid: u32, start: u64, keep: impl Fn(u32) -> bool) -> usize {
    let me = current_pid();
    if pid == me || pid == 0 || pid == 4 {
        return 0;
    }
    let Some(root) = Handle::open(pid, PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION) else { return 0 };
    if created(&root) != Some(start) {
        return 0;
    }
    let mut ended = 0;
    // Children first, deepest last-found first; the root (first in the tree) last, on the handle checked above
    for (p, s) in tree(pid, start, &list()).into_iter().skip(1).rev() {
        if p != me && p != 0 && p != 4 && end(p, s, &keep) {
            ended += 1;
        }
    }
    if keep(pid) && terminate(&root) {
        ended += 1;
    }
    ended
}

/// Ends `pid` alone (not its children), when it's still the process that started at `start`. For eGuard's own
/// processes during removal: the service's children include the uninstaller, which must carry on.
pub fn end_one(pid: u32, start: u64) -> bool {
    pid != current_pid() && pid != 0 && pid != 4 && end(pid, start, &|_| true)
}

/// Ends one process, when `pid` is still the one that started at `start` and `keep` lets it.
fn end(pid: u32, start: u64, keep: &impl Fn(u32) -> bool) -> bool {
    let Some(h) = Handle::open(pid, PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION) else { return false };
    created(&h) == Some(start) && keep(pid) && terminate(&h)
}

fn terminate(h: &Handle) -> bool {
    // SAFETY: a handle with terminate rights; the process ends with eGuard's exit code.
    unsafe { TerminateProcess(h.0, ENDED_BY_EGUARD) != 0 }
}

/// Whether `pid` is still running (and is the same process that started at `started`).
pub fn alive(pid: u32, started: u64) -> bool {
    start_time(pid) == Some(started) && image_path(pid).is_some()
}

/// The processes running the program at `path` (the whole path, in any case), with when each started.
pub fn running_program(path: &Path) -> Vec<(u32, u64)> {
    let Some(name) = path.file_name().map(|n| n.to_string_lossy().into_owned()) else { return Vec::new() };
    let want = path.to_string_lossy();
    list()
        .into_iter()
        .filter(|p| p.exe.eq_ignore_ascii_case(&name))
        .filter(|p| image_path(p.pid).is_some_and(|i| i.to_string_lossy().eq_ignore_ascii_case(&want)))
        .filter_map(|p| start_time(p.pid).map(|t| (p.pid, t)))
        .collect()
}

/// Ends every process running the program at `path` but this one, each alone (`end_one`). Returns their ids.
pub fn end_program(path: &Path) -> Vec<u32> {
    running_program(path).into_iter().filter(|&(pid, start)| end_one(pid, start)).map(|(pid, _)| pid).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_running_programs_file_is_its_own_and_a_copy_is_not() {
        let me = current_pid();
        let exe = image_path(me).unwrap();
        let started = start_time(me).unwrap();
        assert!(still_its_file(&exe, started));
        // The same bytes at another path, put there after this process started: not what it runs
        let copy = std::env::temp_dir().join(format!("eguard-image-{me}.exe"));
        std::fs::copy(&exe, &copy).unwrap();
        assert!(!still_its_file(&copy, started));
        std::fs::remove_file(&copy).unwrap();
        assert!(!still_its_file(&copy, started));
    }

    #[test]
    fn this_process_is_listed_with_its_path_and_session() {
        let me = current_pid();
        let all = list();
        assert!(all.iter().any(|p| p.pid == me));
        let path = image_path(me).unwrap();
        assert!(path.is_file());
        assert!(start_time(me).is_some());
        assert!(session_of(me).is_some());
    }

    #[test]
    fn a_tree_is_ended_children_first_and_only_the_tree() {
        // cmd starts ping, which waits: ending cmd's tree ends both
        let cmd = std::process::Command::new("cmd.exe").args(["/c", "ping -n 30 127.0.0.1 >nul"]).spawn().unwrap();
        let pid = cmd.id();
        let ping = (0..100)
            .find_map(|_| {
                std::thread::sleep(std::time::Duration::from_millis(50));
                list().into_iter().find(|p| p.parent == pid && p.exe.eq_ignore_ascii_case("ping.exe"))
            })
            .expect("ping started");
        let cmd_start = start_time(pid).unwrap();
        let started = start_time(ping.pid).unwrap();
        assert_eq!(tree(pid, cmd_start, &list()), vec![(pid, cmd_start), (ping.pid, started)]);
        // A start that isn't this cmd's (its id reused): nothing is ended
        assert_eq!(end_tree(pid, cmd_start + 1, |_| true), 0);
        // The filter is asked for each one, and what it refuses stays
        assert_eq!(end_tree(pid, cmd_start, |p| p != ping.pid && p != pid), 0);
        assert!(alive(ping.pid, started) && alive(pid, cmd_start));
        assert_eq!(end_tree(pid, cmd_start, |_| true), 2);
        let cmd = Child::from_std(cmd);
        std::thread::sleep(std::time::Duration::from_millis(200));
        assert_eq!(cmd.exit_code(), Some(ENDED_BY_EGUARD));
        std::thread::sleep(std::time::Duration::from_millis(200));
        assert!(!alive(ping.pid, started));
        // Never this process
        let me = current_pid();
        assert_eq!(end_tree(me, start_time(me).unwrap(), |_| true), 0);
    }

    #[test]
    fn a_program_is_found_by_its_whole_path_and_this_process_never_ended() {
        let me = current_pid();
        let exe = image_path(me).unwrap();
        assert!(running_program(&exe).iter().any(|&(pid, _)| pid == me));
        assert_eq!(running_program(&exe.with_file_name("not-this.exe")), Vec::new());
        assert_eq!(end_program(&exe), Vec::<u32>::new());
    }
}
