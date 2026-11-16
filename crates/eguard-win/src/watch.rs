//! Incremental scans (spec section 5): something was installed or removed when an Uninstall key changes
//! (`RegNotifyChangeKeyValue`) or a launcher's manifest folder does (`FindFirstChangeNotificationW`).
//!
//! One thread waits on all of them. After a change it waits a little more (an installer writes many keys), says so
//! once, and starts watching again. Every 30 minutes it rebuilds its watches anyway, to pick up a user who signed in
//! (their hive) and launcher folders found since.
//!
//! A change only in a user's own Uninstall key (which that user, the child included, can write in a loop) asks for a
//! scan at most once every `USER_ONLY_EVERY` (one held back is asked for when that ends); a change anywhere else
//! always does.
#![allow(unsafe_code)]

use crate::registry::{Key, Root, View};
use crate::wide::wide;
use std::path::PathBuf;
use std::ptr::null;
use std::time::Duration;
use windows_sys::Win32::Foundation::{CloseHandle, ERROR_SUCCESS, HANDLE, INVALID_HANDLE_VALUE, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_NOTIFY_CHANGE_DIR_NAME, FILE_NOTIFY_CHANGE_FILE_NAME, FILE_NOTIFY_CHANGE_LAST_WRITE, FindCloseChangeNotification,
    FindFirstChangeNotificationW,
};
use windows_sys::Win32::System::Registry::{REG_NOTIFY_CHANGE_LAST_SET, REG_NOTIFY_CHANGE_NAME, RegNotifyChangeKeyValue};
use windows_sys::Win32::System::Threading::{CreateEventW, WaitForMultipleObjects, WaitForSingleObject};

const UNINSTALL: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
/// `WaitForMultipleObjects` takes at most 64 handles.
const MAX_WATCHES: usize = 64;
const REBUILD_EVERY: Duration = Duration::from_secs(30 * 60);
/// After a change, quiet for this long before saying so.
const SETTLE: Duration = Duration::from_secs(20);
/// Changes seen only in users' own Uninstall keys ask for a scan at most this often.
const USER_ONLY_EVERY: Duration = Duration::from_secs(10 * 60);

enum Watch {
    /// The event the key signals. The key stays open while watched: closing it cancels the notification.
    Registry {
        _open: Key,
        event: HANDLE,
    },
    Folder(HANDLE),
}

impl Watch {
    fn handle(&self) -> HANDLE {
        match self {
            Watch::Registry { event: h, .. } | Watch::Folder(h) => *h,
        }
    }
}

impl Drop for Watch {
    fn drop(&mut self) {
        // SAFETY: handles we created, closed once (the key closes itself).
        unsafe {
            match self {
                Watch::Registry { event, .. } => CloseHandle(*event),
                Watch::Folder(h) => FindCloseChangeNotification(*h),
            };
        }
    }
}

fn watch_key(root: Root, path: &str, view: View) -> Option<Watch> {
    let key = Key::open(root, path, view)?;
    // SAFETY: an auto-reset event with default security and no name; closed by `Watch`'s drop.
    let event = unsafe { CreateEventW(null(), 0, 0, null()) };
    if event.is_null() {
        return None;
    }
    // SAFETY: a key we hold open and an event we own; asynchronous, so it returns at once and signals later.
    let rc = unsafe { RegNotifyChangeKeyValue(key.raw(), 1, REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET, event, 1) };
    let w = Watch::Registry { _open: key, event };
    (rc == ERROR_SUCCESS).then_some(w)
}

fn watch_folder(dir: &std::path::Path) -> Option<Watch> {
    let p = wide(&dir.to_string_lossy());
    // SAFETY: `p` is zero-terminated; the handle is closed by `Watch`'s drop.
    let h = unsafe {
        FindFirstChangeNotificationW(
            p.as_ptr(),
            0,
            FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME | FILE_NOTIFY_CHANGE_LAST_WRITE,
        )
    };
    (h != INVALID_HANDLE_VALUE && !h.is_null()).then_some(Watch::Folder(h))
}

/// The watches, and which of them are users' own Uninstall keys (`users`, a range of indexes).
fn build(folders: &[PathBuf]) -> (Vec<Watch>, std::ops::Range<usize>) {
    let mut w: Vec<Watch> = [View::Native, View::Wow32].into_iter().filter_map(|v| watch_key(Root::LocalMachine, UNINSTALL, v)).collect();
    let first_user = w.len();
    for u in crate::apps::users() {
        w.extend(watch_key(Root::Users, &format!(r"{}\{UNINSTALL}", u.sid), View::Native));
    }
    let users = first_user..w.len();
    w.extend(folders.iter().filter_map(|f| watch_folder(f)));
    w.truncate(MAX_WATCHES);
    let users = users.start.min(w.len())..users.end.min(w.len());
    (w, users)
}

/// Whether a settled change asks for a scan: always, unless it was seen only in users' own keys and one such did
/// within `USER_ONLY_EVERY`.
fn wanted(user_only: bool, last_user_only: &mut Option<std::time::Instant>, now: std::time::Instant) -> bool {
    if !user_only {
        return true;
    }
    if last_user_only.is_some_and(|at| now.duration_since(at) < USER_ONLY_EVERY) {
        return false;
    }
    *last_user_only = Some(now);
    true
}

/// Watches until the process ends, calling `on_change` after each settled change. `folders` gives the launcher
/// folders to watch (the last scan's `watch_dirs`), asked again at each rebuild.
pub fn spawn(folders: impl Fn() -> Vec<PathBuf> + Send + 'static, on_change: impl Fn() + Send + 'static) -> std::io::Result<()> {
    std::thread::Builder::new().name("watch".into()).spawn(move || {
        let mut last_user_only = None;
        // A change held back by `USER_ONLY_EVERY`, and when it's due: held back, never dropped (a game installed
        // for one user right after the child changed their own keys would otherwise wait for the 6-hourly scan)
        let mut pending: Option<std::time::Instant> = None;
        loop {
            let (watches, users) = build(&folders());
            let handles: Vec<HANDLE> = watches.iter().map(Watch::handle).collect();
            if handles.is_empty() {
                std::thread::sleep(REBUILD_EVERY);
                continue;
            }
            let wait = pending.map_or(REBUILD_EVERY, |at| at.saturating_duration_since(std::time::Instant::now()).min(REBUILD_EVERY));
            // SAFETY: `handles` are live handles owned by `watches`, which outlives the wait.
            let rc = unsafe { WaitForMultipleObjects(handles.len() as u32, handles.as_ptr(), 0, wait.as_millis() as u32) };
            match rc {
                WAIT_TIMEOUT => {}
                // A handle went bad: don't spin, rebuild after a pause
                WAIT_FAILED => std::thread::sleep(Duration::from_secs(60)),
                _ => {
                    std::thread::sleep(SETTLE);
                    // The one that woke the wait, and any other signalled meanwhile (the watches are still open)
                    let first = (rc as usize).checked_sub(WAIT_OBJECT_0 as usize).filter(|i| *i < handles.len());
                    let others = handles.iter().enumerate().filter(|&(i, h)| {
                        // SAFETY: a live handle owned by `watches`; a zero timeout only polls it.
                        Some(i) != first && unsafe { WaitForSingleObject(*h, 0) } == WAIT_OBJECT_0
                    });
                    let user_only = first.is_some_and(|i| users.contains(&i)) && others.map(|(i, _)| i).all(|i| users.contains(&i));
                    if wanted(user_only, &mut last_user_only, std::time::Instant::now()) {
                        on_change();
                        pending = None;
                    } else {
                        pending = pending.or(last_user_only.map(|at| at + USER_ONLY_EVERY));
                    }
                }
            }
            if pending.is_some_and(|at| std::time::Instant::now() >= at) {
                pending = None;
                last_user_only = Some(std::time::Instant::now());
                on_change();
            }
            drop(watches);
        }
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_folder_change_is_seen() {
        let dir = std::env::temp_dir().join(format!("eguard-watch-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let w = watch_folder(&dir).unwrap();
        std::fs::write(dir.join("appmanifest_1.acf"), b"x").unwrap();
        let h = w.handle();
        // SAFETY: one live handle owned by `w`.
        let rc = unsafe { WaitForMultipleObjects(1, &raw const h, 0, 5_000) };
        assert_eq!(rc, 0, "the change should signal");
        drop(w);
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(!build(&[]).0.is_empty(), "the Uninstall keys are always watchable");
    }

    #[test]
    fn changes_only_in_users_keys_ask_for_a_scan_at_most_every_ten_minutes() {
        let t0 = std::time::Instant::now();
        let mut last = None;
        assert!(wanted(true, &mut last, t0));
        assert!(!wanted(true, &mut last, t0 + Duration::from_secs(30)));
        // A change elsewhere always does
        assert!(wanted(false, &mut last, t0 + Duration::from_secs(40)));
        assert!(!wanted(true, &mut last, t0 + Duration::from_secs(9 * 60)));
        assert!(wanted(true, &mut last, t0 + USER_ONLY_EVERY));
    }
}
