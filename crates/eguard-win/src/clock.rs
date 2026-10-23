//! Clock samples for `eguard_core::clock` (spec section 8).
#![allow(unsafe_code)]

use eguard_core::clock::ClockSample;
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};
use windows_sys::Win32::System::SystemInformation::GetTickCount64;

/// Windows counts boots here; it changes on every start (not on resume from sleep).
const BOOT_ID_KEY: &str = r"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters";

/// The boot counter, read once: it can't change while this process runs.
pub fn boot_id() -> u64 {
    static ID: OnceLock<u64> = OnceLock::new();
    *ID.get_or_init(|| crate::registry::hklm_dword(BOOT_ID_KEY, "BootId").map_or(0, u64::from))
}

/// Milliseconds since boot, sleep and hibernation included (so a sleeping PC's time still counts).
pub fn mono_ms() -> u64 {
    // SAFETY: no arguments, no state; always succeeds.
    unsafe { GetTickCount64() }
}

/// The three clocks, read together.
pub fn sample() -> ClockSample {
    let wall_ms = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_millis() as i64);
    ClockSample { mono_ms: mono_ms(), boot_id: boot_id(), wall_ms }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn this_boot_has_an_id_and_time_moves_on() {
        assert_ne!(boot_id(), 0);
        let (a, b) = (sample(), sample());
        assert!(b.mono_ms >= a.mono_ms && a.boot_id == b.boot_id);
    }
}
