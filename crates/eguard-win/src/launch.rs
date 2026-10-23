//! The overlay's app buttons (spec section 8): bringing an always-allowed app's window to the front, or starting it.
//!
//! The agent runs as the child in their own session, so whatever it starts runs as the child, never elevated
//! (`CreateProcessW`, not `ShellExecuteW`, which could ask for an administrator). It acts only on a program path the
//! service named in its view, and only on one that looks like a program on a local disk: no share, no device path,
//! no relative path, no arguments. What it starts is checked by the service like any other program, so a button
//! can't open anything the child's rules don't allow.
#![allow(unsafe_code)]

use crate::wide::wide;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::ptr::null;
use windows_sys::Win32::Foundation::{CloseHandle, HWND, LPARAM};
use windows_sys::Win32::System::Threading::{CreateProcessW, PROCESS_INFORMATION, STARTUPINFOW};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    AllowSetForegroundWindow, BringWindowToTop, EnumWindows, GW_OWNER, GWL_EXSTYLE, GetWindow, GetWindowLongW, GetWindowThreadProcessId,
    IsIconic, IsWindowVisible, SW_RESTORE, SetForegroundWindow, ShowWindow, WS_EX_TOOLWINDOW,
};

/// `path` if it names a program on a local disk in the plain form Windows reports running programs in
/// (`C:\folder\app.exe`). Anything else is refused: a share (`\\server\…`), a device path (`\\?\…`), a relative path,
/// `.` or `..` in it, quotes (it goes on a command line), or a file that isn't an `.exe`.
pub fn well_formed(path: &str) -> Option<PathBuf> {
    let b = path.as_bytes();
    if !(b.len() > 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && b[2] == b'\\') {
        return None;
    }
    // The first three bytes are ASCII, so slicing after them is on a character boundary
    let rest = &path[3..];
    // A second ':' would be a stream name
    let clean = !rest.contains(['/', '"', '\0', '*', '?', '<', '>', '|', ':']);
    let parts = rest.split('\\').all(|p| !p.is_empty() && p != "." && p != "..");
    let exe = Path::new(path).extension().is_some_and(|e| e.eq_ignore_ascii_case("exe"));
    (clean && parts && exe).then(|| PathBuf::from(path))
}

/// `well_formed`, and the file is there: what a button may start.
pub fn startable(path: &str) -> Option<PathBuf> {
    well_formed(path).filter(|p| std::fs::metadata(p).is_ok_and(|m| m.is_file()))
}

struct Search {
    target: String,
    /// Each process's program, looked up once per search.
    paths: HashMap<u32, Option<String>>,
    found: Option<(HWND, u32)>,
}

/// A visible top-level window of a process running `exe` in this session, and its process: the window the child
/// would pick with Alt+Tab (no owned dialogs, no tool windows).
fn window_of(exe: &Path) -> Option<(HWND, u32)> {
    unsafe extern "system" fn each(hwnd: HWND, lparam: LPARAM) -> i32 {
        // SAFETY: `lparam` is the `Search` that `window_of` passes and keeps alive until `EnumWindows` returns.
        let search = unsafe { &mut *(lparam as *mut Search) };
        // SAFETY: plain reads on a window handle Windows just gave us; a window that has gone answers zero.
        let (visible, owned, tool) = unsafe {
            (
                IsWindowVisible(hwnd) != 0,
                !GetWindow(hwnd, GW_OWNER).is_null(),
                GetWindowLongW(hwnd, GWL_EXSTYLE) as u32 & WS_EX_TOOLWINDOW != 0,
            )
        };
        if !visible || owned || tool {
            return 1;
        }
        let mut pid = 0u32;
        // SAFETY: as above; `pid` is a live out-parameter.
        unsafe { GetWindowThreadProcessId(hwnd, &raw mut pid) };
        let path = search.paths.entry(pid).or_insert_with(|| crate::process::image_path(pid).map(|p| p.to_string_lossy().to_lowercase()));
        if path.as_deref() == Some(search.target.as_str()) {
            search.found = Some((hwnd, pid));
            return 0;
        }
        1
    }
    let mut search = Search { target: exe.to_string_lossy().to_lowercase(), paths: HashMap::new(), found: None };
    // SAFETY: the callback only reads windows and writes `search`, which outlives the call. Only this desktop's
    // windows are listed, so only this session's.
    unsafe { EnumWindows(Some(each), (&raw mut search) as LPARAM) };
    search.found
}

/// Whether `exe` has a window the child could be switched to.
pub fn running(exe: &str) -> bool {
    well_formed(exe).is_some_and(|p| window_of(&p).is_some())
}

/// Starts `exe` as whoever runs this (the child), in its own folder, with no arguments. Returns its process id.
fn start(exe: &Path) -> std::io::Result<u32> {
    let app = wide(&exe.to_string_lossy());
    let mut cmd = wide(&format!("\"{}\"", exe.display()));
    let dir = exe.parent().map(|d| wide(&d.to_string_lossy()));
    let si = STARTUPINFOW { cb: size_of::<STARTUPINFOW>() as u32, ..Default::default() };
    let mut pi = PROCESS_INFORMATION::default();
    // SAFETY: every pointer is to a live local (`cmd` is writable, as CreateProcess requires); no handles are
    // inherited. The handles it returns are closed below.
    let ok = unsafe {
        CreateProcessW(
            app.as_ptr(),
            cmd.as_mut_ptr(),
            null(),
            null(),
            0,
            0,
            null(),
            dir.as_ref().map_or(null(), Vec::as_ptr),
            &raw const si,
            &raw mut pi,
        )
    } != 0;
    if !ok {
        return Err(crate::last_error());
    }
    // SAFETY: both handles are ours, closed once.
    unsafe {
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }
    Ok(pi.dwProcessId)
}

/// What pressing an app's button did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Opened {
    /// Its window is in front now.
    Switched,
    /// It wasn't running and was started; its window comes when it has loaded.
    Started,
    /// Neither: no window, and it may not or could not be started.
    Nothing,
}

/// Brings `exe`'s window to the front, or starts it when it has none and `may_start`. Call it while one of this
/// process's windows has the focus: Windows lets only the program in front hand the focus on.
pub fn open(exe: &str, may_start: bool) -> Opened {
    let Some(path) = well_formed(exe) else { return Opened::Nothing };
    if let Some((hwnd, pid)) = window_of(&path) {
        // SAFETY: plain calls on a window of the child's session; a window that has gone just fails.
        unsafe {
            if IsIconic(hwnd) != 0 {
                ShowWindow(hwnd, SW_RESTORE);
            }
            // So the app can also bring up its own windows once it's in front
            AllowSetForegroundWindow(pid);
            BringWindowToTop(hwnd);
            SetForegroundWindow(hwnd);
        }
        return Opened::Switched;
    }
    if !may_start {
        return Opened::Nothing;
    }
    match startable(exe).map(|p| start(&p)) {
        Some(Ok(pid)) => {
            // A program started by the one in front may take the focus anyway; this makes it certain
            // SAFETY: plain call.
            unsafe { AllowSetForegroundWindow(pid) };
            Opened::Started
        }
        _ => Opened::Nothing,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_plain_local_program_path_is_used() {
        assert!(well_formed(r"C:\Program Files\Khan\khan.exe").is_some());
        assert!(well_formed(r"d:\Games\App.EXE").is_some());
        for bad in [
            r"\\server\share\app.exe",
            r"\\?\C:\app.exe",
            r"\\.\C:\app.exe",
            r"app.exe",
            r"C:app.exe",
            r"C:\Games\..\Windows\app.exe",
            r"C:\Games\.\app.exe",
            r"C:\Games\\app.exe",
            r"C:/Games/app.exe",
            r#"C:\Games\app.exe" --evil"#,
            r"C:\Games\app.exe:stream",
            r"C:\Games\notes.txt",
            r"C:\Games\app.exe.lnk",
            r"C:\Games\app",
            "",
        ] {
            assert!(well_formed(bad).is_none(), "{bad}");
        }
        // Startable: the file is there
        let me = std::env::current_exe().unwrap();
        let me = me.to_string_lossy();
        if well_formed(&me).is_some() {
            assert!(startable(&me).is_some());
        }
        assert!(startable(r"C:\eguard-no-such-folder\app.exe").is_none());
        assert!(!running(r"C:\eguard-no-such-folder\app.exe"));
    }
}
