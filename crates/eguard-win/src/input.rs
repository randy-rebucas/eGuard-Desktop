//! What the person at this session is doing, read by the agent in that session (spec section 8): the program whose
//! window has the focus, and how long since the last input. Only window ownership and input times are read; no
//! window's contents, no keystrokes.
#![allow(unsafe_code)]

use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::{HWND, LPARAM};
use windows_sys::Win32::System::SystemInformation::GetTickCount;
use windows_sys::Win32::UI::Input::KeyboardAndMouse::{GetLastInputInfo, LASTINPUTINFO};
use windows_sys::Win32::UI::Input::XboxController::{XINPUT_STATE, XInputGetState};
use windows_sys::Win32::UI::WindowsAndMessaging::{EnumChildWindows, GetClassNameW, GetForegroundWindow, GetWindowThreadProcessId};

/// `XInput`'s four controller slots.
const PADS: u32 = 4;
/// A slot that wasn't connected is looked at again only this often (asking an empty slot is slow).
const EMPTY_PAD_RECHECK: Duration = Duration::from_secs(5);

/// The process that owns the window with the focus, if any.
pub fn foreground_pid() -> Option<u32> {
    // SAFETY: no arguments; may return null.
    let hwnd = unsafe { GetForegroundWindow() };
    if hwnd.is_null() {
        return None;
    }
    let pid = window_pid(hwnd)?;
    // A Store app's window is a frame owned by ApplicationFrameHost (part of Windows, never counted); the app itself
    // runs in its own process, whose window sits inside the frame
    if class_of(hwnd).as_deref() == Some("ApplicationFrameWindow") {
        return Some(hosted_pid(hwnd, pid).unwrap_or(pid));
    }
    Some(pid)
}

fn window_pid(hwnd: HWND) -> Option<u32> {
    let mut pid = 0u32;
    // SAFETY: `hwnd` came from Windows just now (a window that closed since only yields 0); `pid` is live.
    unsafe { GetWindowThreadProcessId(hwnd, &raw mut pid) };
    (pid != 0).then_some(pid)
}

fn class_of(hwnd: HWND) -> Option<String> {
    // Class names are at most 256 characters
    let mut buf = [0u16; 257];
    // SAFETY: `buf` is writable for its length, which is passed.
    let n = unsafe { GetClassNameW(hwnd, buf.as_mut_ptr(), buf.len() as i32) };
    (n > 0).then(|| crate::wide::from_wide(&buf[..n as usize]))
}

/// The process of the window a Store app's frame (`frame`, owned by `frame_pid`) hosts: the first child window
/// owned by another process.
fn hosted_pid(frame: HWND, frame_pid: u32) -> Option<u32> {
    unsafe extern "system" fn each(child: HWND, lparam: LPARAM) -> windows_sys::core::BOOL {
        // SAFETY: `lparam` is the `(u32, Option<u32>)` below, alive and not otherwise used during the enumeration.
        let found = unsafe { &mut *(lparam as *mut (u32, Option<u32>)) };
        match window_pid(child) {
            Some(pid) if pid != found.0 => {
                found.1 = Some(pid);
                0
            }
            _ => 1,
        }
    }
    let mut found: (u32, Option<u32>) = (frame_pid, None);
    // SAFETY: `each` matches WNDENUMPROC and only runs during the call; `found` outlives it.
    unsafe { EnumChildWindows(frame, Some(each), (&raw mut found) as LPARAM) };
    found.1
}

/// Milliseconds since the last keyboard or mouse input in this session.
fn keyboard_mouse_idle_ms() -> u64 {
    let mut info = LASTINPUTINFO { cbSize: size_of::<LASTINPUTINFO>() as u32, dwTime: 0 };
    // SAFETY: `info` is live with its size set.
    if unsafe { GetLastInputInfo(&raw mut info) } == 0 {
        return 0;
    }
    // SAFETY: no arguments. Both counters wrap every 49 days; the difference doesn't care.
    u64::from(unsafe { GetTickCount() }.wrapping_sub(info.dwTime))
}

/// Tracks input, including game controllers, which Windows doesn't count as input: a child playing with a pad
/// would otherwise look idle after two minutes and the game's time would stop counting.
#[derive(Debug)]
pub struct InputWatch {
    pads: [Option<u32>; PADS as usize],
    pad_checked: [Option<Instant>; PADS as usize],
    last_pad_input: Option<Instant>,
}

impl Default for InputWatch {
    fn default() -> Self {
        Self::new()
    }
}

impl InputWatch {
    pub fn new() -> Self {
        Self { pads: [None; PADS as usize], pad_checked: [None; PADS as usize], last_pad_input: None }
    }

    /// Milliseconds since the last input of any kind. Call it about once a second.
    pub fn idle_ms(&mut self) -> u64 {
        let now = Instant::now();
        for slot in 0..PADS {
            let i = slot as usize;
            if self.pads[i].is_none() && self.pad_checked[i].is_some_and(|t| now - t < EMPTY_PAD_RECHECK) {
                continue;
            }
            self.pad_checked[i] = Some(now);
            let mut state = XINPUT_STATE::default();
            // SAFETY: `state` is a live out-parameter; a slot without a controller returns an error code.
            let connected = unsafe { XInputGetState(slot, &raw mut state) } == 0;
            let packet = connected.then_some(state.dwPacketNumber);
            // The packet number changes whenever the controller's state does
            if let (Some(before), Some(after)) = (self.pads[i], packet)
                && before != after
            {
                self.last_pad_input = Some(now);
            }
            self.pads[i] = packet;
        }
        let pad_idle = self.last_pad_input.map_or(u64::MAX, |t| (now - t).as_millis() as u64);
        keyboard_mouse_idle_ms().min(pad_idle)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn idle_time_is_read() {
        let mut w = InputWatch::new();
        // Whatever it is, it's a number of milliseconds since boot at most
        assert!(w.idle_ms() <= crate::clock::mono_ms());
        let _ = foreground_pid();
    }

    /// Opens Calculator (a Store app) on this desktop: run by hand with `--ignored`.
    #[test]
    #[ignore = "opens Calculator on the desktop"]
    fn a_store_apps_frame_resolves_to_the_app() {
        use windows_sys::Win32::UI::WindowsAndMessaging::{FindWindowW, PostMessageW, WM_CLOSE};
        // calc.exe hands over to the Store app and ends at once
        std::process::Command::new("calc.exe").spawn().unwrap().wait().unwrap();
        let class = crate::wide::wide("ApplicationFrameWindow");
        let title = crate::wide::wide("Calculator");
        let mut frame = std::ptr::null_mut();
        for _ in 0..50 {
            std::thread::sleep(Duration::from_millis(200));
            // SAFETY: both strings are zero-terminated and live for the call.
            frame = unsafe { FindWindowW(class.as_ptr(), title.as_ptr()) };
            if !frame.is_null() && hosted_pid(frame, window_pid(frame).unwrap()).is_some() {
                break;
            }
        }
        assert!(!frame.is_null(), "Calculator's frame");
        let host = window_pid(frame).unwrap();
        let app = hosted_pid(frame, host).expect("the app's own process");
        assert_ne!(app, host);
        let name = crate::process::image_path(app).unwrap();
        assert!(name.to_string_lossy().to_lowercase().ends_with("calculatorapp.exe"), "{}", name.display());
        // SAFETY: a window handle from FindWindowW; posting to a closed window just fails.
        unsafe { PostMessageW(frame, WM_CLOSE, 0, 0) };
    }
}
