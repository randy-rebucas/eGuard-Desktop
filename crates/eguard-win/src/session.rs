//! Signed-in sessions (spec section 3): which are in use, starting the agent in each as its user, the logon SID its
//! pipe admits, and disconnecting one as the backstop when its overlay keeps disappearing (spec section 8).
//!
//! Starting a process in another session (`WTSQueryUserToken`) needs the service's rights as SYSTEM; console mode
//! starts the agent in its own session instead.
#![allow(unsafe_code)]

use crate::wide::{from_wide, wide};
use std::path::Path;
use std::ptr::{null, null_mut};
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
use windows_sys::Win32::Security::{DuplicateTokenEx, SecurityImpersonation, TOKEN_ALL_ACCESS, TokenLogonSid, TokenPrimary};
use windows_sys::Win32::System::Environment::{CreateEnvironmentBlock, DestroyEnvironmentBlock};
use windows_sys::Win32::System::RemoteDesktop::{
    WTS_CURRENT_SERVER_HANDLE, WTS_SESSION_INFOW, WTS_SESSIONSTATE_LOCK, WTSActive, WTSDisconnectSession, WTSEnumerateSessionsW,
    WTSFreeMemory, WTSINFOEXW, WTSQuerySessionInformationW, WTSQueryUserToken, WTSSessionInfoEx,
};
use windows_sys::Win32::System::Threading::{
    CREATE_NO_WINDOW, CREATE_UNICODE_ENVIRONMENT, CreateProcessAsUserW, PROCESS_INFORMATION, STARTUPINFOW,
};

/// A session someone is signed in to and using (not disconnected).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    pub id: u32,
    pub user: String,
    /// The signed-in account's SID (`None` if it couldn't be looked up).
    pub sid: Option<String>,
    /// The lock screen is up: nobody is using it now.
    pub locked: bool,
}

/// Sessions in use: signed in and connected (at the console or over Remote Desktop). Session 0 (services) never.
pub fn active() -> Vec<Session> {
    let mut list: *mut WTS_SESSION_INFOW = null_mut();
    let mut count = 0u32;
    // SAFETY: out-parameters are live; the list is freed below with WTSFreeMemory.
    if unsafe { WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &raw mut list, &raw mut count) } == 0 {
        return Vec::new();
    }
    // SAFETY: on success `list` holds `count` entries.
    let ids: Vec<u32> = unsafe { std::slice::from_raw_parts(list, count as usize) }
        .iter()
        .filter(|s| s.State == WTSActive && s.SessionId != 0)
        .map(|s| s.SessionId)
        .collect();
    // SAFETY: allocated by WTSEnumerateSessionsW, freed once.
    unsafe { WTSFreeMemory(list.cast()) };
    ids.into_iter().filter_map(info).filter(|s| !s.user.is_empty()).collect()
}

fn info(id: u32) -> Option<Session> {
    let mut buf = null_mut();
    let mut len = 0u32;
    // SAFETY: out-parameters are live; the buffer is freed below.
    if unsafe { WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, id, WTSSessionInfoEx, &raw mut buf, &raw mut len) } == 0 {
        return None;
    }
    let s = (len as usize >= size_of::<WTSINFOEXW>()).then(|| {
        // SAFETY: the buffer holds a WTSINFOEXW (checked by size), read without assuming its alignment; level 1 is
        // the only level.
        let level1 = unsafe { buf.cast::<WTSINFOEXW>().read_unaligned().Data.WTSInfoExLevel1 };
        let (user, domain) = (from_wide(&level1.UserName), from_wide(&level1.DomainName));
        let sid = if user.is_empty() { None } else { crate::accounts::sid_of(&format!("{domain}\\{user}")) };
        Session {
            id,
            user,
            sid,
            // Windows 7 had these two the other way round; Windows 10 and 11 report them as documented
            locked: level1.SessionFlags as u32 == WTS_SESSIONSTATE_LOCK,
        }
    });
    // SAFETY: allocated by WTSQuerySessionInformationW, freed once.
    unsafe { WTSFreeMemory(buf.cast()) };
    s
}

/// A token handle, closed on drop.
struct Token(HANDLE);

impl Drop for Token {
    fn drop(&mut self) {
        // SAFETY: a handle we own, closed once.
        unsafe { CloseHandle(self.0) };
    }
}

/// The signed-in user's token for `session`, as a primary token. Needs SYSTEM.
fn user_token(session: u32) -> std::io::Result<Token> {
    let mut t: HANDLE = null_mut();
    // SAFETY: `t` is a live out-parameter.
    if unsafe { WTSQueryUserToken(session, &raw mut t) } == 0 {
        return Err(crate::last_error());
    }
    let impersonation = Token(t);
    let mut primary: HANDLE = null_mut();
    // SAFETY: `impersonation` is a valid token; `primary` is a live out-parameter.
    if unsafe { DuplicateTokenEx(impersonation.0, TOKEN_ALL_ACCESS, null(), SecurityImpersonation, TokenPrimary, &raw mut primary) } == 0 {
        return Err(crate::last_error());
    }
    Ok(Token(primary))
}

/// The logon SID of whoever is signed in to `session`, for its pipe's DACL. Needs SYSTEM.
pub fn logon_sid(session: u32) -> std::io::Result<String> {
    let t = user_token(session)?;
    crate::security::token_sid(t.0, TokenLogonSid)
}

/// Starts `exe args` in `session` as its signed-in user, on the interactive desktop, without a console window.
/// Needs SYSTEM.
pub fn launch(session: u32, exe: &Path, args: &str) -> std::io::Result<crate::process::Child> {
    let token = user_token(session)?;
    let mut env = null_mut();
    // SAFETY: `token` is a valid primary token; `env` is freed below.
    if unsafe { CreateEnvironmentBlock(&raw mut env, token.0, 0) } == 0 {
        return Err(crate::last_error());
    }
    let app = wide(&exe.to_string_lossy());
    let mut cmd = wide(&format!("\"{}\" {args}", exe.display()));
    let mut desktop = wide(r"winsta0\default");
    let si = STARTUPINFOW { cb: size_of::<STARTUPINFOW>() as u32, lpDesktop: desktop.as_mut_ptr(), ..Default::default() };
    let mut pi = PROCESS_INFORMATION::default();
    // SAFETY: every pointer is to a live local (`cmd` is writable, as CreateProcess requires); `env` is the block
    // made above. The process and thread handles it returns are closed below.
    let ok = unsafe {
        CreateProcessAsUserW(
            token.0,
            app.as_ptr(),
            cmd.as_mut_ptr(),
            null(),
            null(),
            0,
            CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW,
            env,
            null(),
            &raw const si,
            &raw mut pi,
        )
    } != 0;
    let err = (!ok).then(crate::last_error);
    // SAFETY: freed once; the thread handle is ours when the call succeeded (the process handle goes to `Child`).
    unsafe {
        DestroyEnvironmentBlock(env);
        if ok {
            CloseHandle(pi.hThread);
        }
    }
    match err {
        Some(e) => Err(e),
        None => Ok(crate::process::Child::from_handle(pi.dwProcessId, pi.hProcess)),
    }
}

/// Disconnects `session`: its screen goes to the lock screen and its programs keep running. The backstop for an
/// overlay that keeps being closed (spec section 8, where `LockWorkStation` is the agent's own).
pub fn disconnect(session: u32) -> std::io::Result<()> {
    // SAFETY: plain call on the local server.
    if unsafe { WTSDisconnectSession(WTS_CURRENT_SERVER_HANDLE, session, 0) } == 0 {
        return Err(crate::last_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn this_session_is_active_and_signed_in() {
        let me = crate::process::session_of(crate::process::current_pid()).unwrap();
        // Tests run in a signed-in session (or in session 0 on a build machine, which has none to show)
        if me != 0 {
            let s = active().into_iter().find(|s| s.id == me).expect("this session is listed");
            assert_ne!(s.user, "");
            assert_eq!(s.sid, Some(crate::security::current_user_sid().unwrap()));
        }
        // Without SYSTEM's rights, another session's token isn't ours to have
        assert!(launch(me, Path::new(r"C:\Windows\System32\cmd.exe"), "/c exit").is_err());
    }
}
