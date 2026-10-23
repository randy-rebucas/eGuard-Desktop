//! What the person at this session is doing, read by the agent in that session (spec section 8): the program whose
//! window has the focus, and how long since the last input. Only window ownership and input times are read; no
//! window's contents, no keystrokes.
#![allow(unsafe_code)]

use std::time::{Duration, Instant};
use windows_sys::Win32::System::SystemInformation::GetTickCount;
use windows_sys::Win32::UI::Input::KeyboardAndMouse::{GetLastInputInfo, LASTINPUTINFO};
use windows_sys::Win32::UI::Input::XboxController::{XINPUT_STATE, XInputGetState};
use windows_sys::Win32::UI::WindowsAndMessaging::{GetForegroundWindow, GetWindowThreadProcessId};

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
    let mut pid = 0u32;
    // SAFETY: `hwnd` came from Windows just now (a window that closed since only yields 0); `pid` is live.
    unsafe { GetWindowThreadProcessId(hwnd, &raw mut pid) };
    (pid != 0).then_some(pid)
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
}
