//! Reading `HKEY_LOCAL_MACHINE` values (`RegGetValueW`).
#![allow(unsafe_code)]

use crate::wide::{from_wide, wide};
use std::ptr::null_mut;
use windows_sys::Win32::Foundation::{ERROR_MORE_DATA, ERROR_SUCCESS};
use windows_sys::Win32::System::Registry::{HKEY_LOCAL_MACHINE, RRF_RT_REG_DWORD, RRF_RT_REG_SZ, RegGetValueW};

/// A `REG_SZ` under HKLM. `None` when missing or not a string.
pub fn hklm_string(subkey: &str, value: &str) -> Option<String> {
    let (k, v) = (wide(subkey), wide(value));
    let mut buf: Vec<u16> = vec![0; 128];
    loop {
        let mut bytes = (buf.len() * 2) as u32;
        // SAFETY: `k` and `v` are zero-terminated and outlive the call; `buf` is writable for `bytes` bytes, and
        // RegGetValueW writes at most that many, updating `bytes` to what it needs when the buffer is too small.
        let rc = unsafe {
            RegGetValueW(HKEY_LOCAL_MACHINE, k.as_ptr(), v.as_ptr(), RRF_RT_REG_SZ, null_mut(), buf.as_mut_ptr().cast(), &raw mut bytes)
        };
        match rc {
            ERROR_SUCCESS => return Some(from_wide(&buf[..(bytes as usize / 2).min(buf.len())])),
            ERROR_MORE_DATA if buf.len() < 32 * 1024 => buf.resize((bytes as usize).div_ceil(2) + 1, 0),
            _ => return None,
        }
    }
}

/// A `REG_DWORD` under HKLM.
pub fn hklm_dword(subkey: &str, value: &str) -> Option<u32> {
    let (k, v) = (wide(subkey), wide(value));
    let mut data: u32 = 0;
    let mut bytes = 4u32;
    // SAFETY: as above; `data` is 4 writable bytes and RRF_RT_REG_DWORD only accepts a 4-byte value.
    let rc = unsafe {
        RegGetValueW(HKEY_LOCAL_MACHINE, k.as_ptr(), v.as_ptr(), RRF_RT_REG_DWORD, null_mut(), (&raw mut data).cast(), &raw mut bytes)
    };
    (rc == ERROR_SUCCESS).then_some(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_values_every_windows_has() {
        let v = hklm_string(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "CurrentBuildNumber").unwrap();
        assert!(v.parse::<u32>().unwrap() > 10_000);
        assert!(hklm_string(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "NoSuchValue").is_none());
        assert!(hklm_dword(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "CurrentMajorVersionNumber").is_some());
    }
}
