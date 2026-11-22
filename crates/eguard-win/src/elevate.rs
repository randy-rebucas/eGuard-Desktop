//! Asking Windows for an administrator (UAC), and the small things a window-only command needs: no console window
//! left behind it, and a message box for what it has to say.
//!
//! Used by "Pair eGuard", which the installer opens when it finishes: the installer's own UI runs without an
//! administrator's rights, and only an administrator may talk to eGuard's service (its main pipe), so the window asks
//! for them itself. A standard user's UAC prompt asks for an administrator's password: nobody is ever paired without
//! one.
#![allow(unsafe_code)]

use crate::wide::wide;
use std::ptr::null_mut;
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
use windows_sys::Win32::Security::{GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation};
use windows_sys::Win32::System::Console::{FreeConsole, GetConsoleProcessList};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows_sys::Win32::UI::Shell::{SEE_MASK_NOASYNC, SHELLEXECUTEINFOW, ShellExecuteExW};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    MB_ICONINFORMATION, MB_ICONWARNING, MB_OK, MB_SETFOREGROUND, MB_TOPMOST, MessageBoxW, SW_SHOWNORMAL,
};

/// `ERROR_CANCELLED`: the UAC prompt was answered No (or closed).
pub const ERROR_CANCELLED: i32 = 1223;

/// Whether this process runs with an administrator's full rights (elevated). False when it can't be told.
pub fn is_elevated() -> bool {
    let mut token: HANDLE = null_mut();
    // SAFETY: the current process's pseudo handle; `token` is written on success and closed below.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut token) } == 0 {
        return false;
    }
    let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
    let mut len = 0u32;
    // SAFETY: `elevation` is writable for the size passed; `len` receives the size used.
    let ok = unsafe {
        GetTokenInformation(token, TokenElevation, (&raw mut elevation).cast(), size_of::<TOKEN_ELEVATION>() as u32, &raw mut len)
    };
    // SAFETY: the token opened above.
    unsafe { CloseHandle(token) };
    ok != 0 && elevation.TokenIsElevated != 0
}

/// Starts this exe again with `args`, as an administrator: Windows shows its UAC prompt. Returns once it has started
/// (or the prompt was refused: an error with `ERROR_CANCELLED`).
pub fn run_self_elevated(args: &str) -> std::io::Result<()> {
    let exe = std::env::current_exe()?;
    let file = wide(&exe.to_string_lossy());
    let params = wide(args);
    let verb = wide("runas");
    let mut info = SHELLEXECUTEINFOW {
        cbSize: size_of::<SHELLEXECUTEINFOW>() as u32,
        // Return only once the new process exists, not on a shell thread that ends with this process
        fMask: SEE_MASK_NOASYNC,
        lpVerb: verb.as_ptr(),
        lpFile: file.as_ptr(),
        lpParameters: params.as_ptr(),
        nShow: SW_SHOWNORMAL,
        ..Default::default()
    };
    // SAFETY: every string is zero-terminated and outlives the call; `info` is initialised with its size.
    if unsafe { ShellExecuteExW(&raw mut info) } == 0 {
        return Err(crate::last_error());
    }
    Ok(())
}

/// Leaves the console this process was given, when it's the only one on it: the console window then closes, and a
/// command that shows only windows doesn't leave an empty black one behind (msiexec and Settings start the agent
/// directly). A console someone typed the command into is shared with their shell, and stays.
pub fn leave_own_console() {
    let mut pids = [0u32; 2];
    // SAFETY: `pids` is writable for its length.
    let attached = unsafe { GetConsoleProcessList(pids.as_mut_ptr(), pids.len() as u32) };
    if attached == 1 {
        // SAFETY: plain call; nothing else in this process uses the console afterwards (stdout goes nowhere).
        unsafe { FreeConsole() };
    }
}

/// Shows `text` in a message box titled `title` and waits for OK. `warning`: the warning icon, else information.
pub fn message(title: &str, text: &str, warning: bool) {
    let (title, text) = (wide(title), wide(text));
    let icon = if warning { MB_ICONWARNING } else { MB_ICONINFORMATION };
    // SAFETY: zero-terminated strings; no owner window.
    unsafe { MessageBoxW(null_mut(), text.as_ptr(), title.as_ptr(), MB_OK | icon | MB_SETFOREGROUND | MB_TOPMOST) };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn elevation_can_be_asked() {
        // Either answer is right; asking must not fail or hang (a test run may or may not be elevated)
        let _ = is_elevated();
    }
}
