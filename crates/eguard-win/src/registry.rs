//! Reading the registry: values under HKLM, and walking keys (Uninstall entries, each user's hive).
#![allow(unsafe_code)]

use crate::wide::{from_wide, wide};
use std::ptr::{null, null_mut};
use windows_sys::Win32::Foundation::{ERROR_MORE_DATA, ERROR_SUCCESS};
use windows_sys::Win32::System::Registry::{
    HKEY, HKEY_LOCAL_MACHINE, HKEY_USERS, KEY_READ, KEY_WOW64_32KEY, KEY_WOW64_64KEY, RRF_RT_REG_DWORD, RRF_RT_REG_SZ, RegCloseKey,
    RegEnumKeyExW, RegGetValueW, RegOpenKeyExW,
};

/// Which half of the registry on 64-bit Windows: 32-bit programs' entries live under `WOW6432Node`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum View {
    Native,
    Wow32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Root {
    LocalMachine,
    Users,
}

/// An open key, closed on drop.
#[derive(Debug)]
pub struct Key(HKEY);

// A registry handle may be used from any thread
unsafe impl Send for Key {}

impl Drop for Key {
    fn drop(&mut self) {
        // SAFETY: a key we opened, closed once.
        unsafe { RegCloseKey(self.0) };
    }
}

impl Key {
    /// Opens `path` under `root` for reading. `None` when it doesn't exist or isn't readable.
    pub fn open(root: Root, path: &str, view: View) -> Option<Self> {
        let root = match root {
            Root::LocalMachine => HKEY_LOCAL_MACHINE,
            Root::Users => HKEY_USERS,
        };
        Self::open_under(root, path, view)
    }

    fn open_under(parent: HKEY, path: &str, view: View) -> Option<Self> {
        let p = wide(path);
        let sam = KEY_READ | if view == View::Wow32 { KEY_WOW64_32KEY } else { KEY_WOW64_64KEY };
        let mut out: HKEY = null_mut();
        // SAFETY: `p` is zero-terminated; `out` receives a key we close on drop.
        let rc = unsafe { RegOpenKeyExW(parent, p.as_ptr(), 0, sam, &raw mut out) };
        (rc == ERROR_SUCCESS).then_some(Self(out))
    }

    /// The raw handle, for calls this module doesn't wrap (change notifications). Valid while `self` lives.
    pub(crate) fn raw(&self) -> HKEY {
        self.0
    }

    /// A subkey of this key.
    pub fn sub(&self, path: &str, view: View) -> Option<Self> {
        Self::open_under(self.0, path, view)
    }

    /// The names of the subkeys (at most 10 000: no real key has more).
    pub fn subkeys(&self) -> Vec<String> {
        let mut out = Vec::new();
        let mut buf = [0u16; 512];
        for i in 0..10_000 {
            let mut len = buf.len() as u32;
            // SAFETY: `buf` is writable for `len` characters; class and time out-pointers are null (not wanted).
            let rc = unsafe { RegEnumKeyExW(self.0, i, buf.as_mut_ptr(), &raw mut len, null(), null_mut(), null_mut(), null_mut()) };
            match rc {
                ERROR_SUCCESS => out.push(from_wide(&buf[..len as usize])),
                // A name longer than 511 characters: skip it
                ERROR_MORE_DATA => {}
                // ERROR_NO_MORE_ITEMS, or the key went away while being read
                _ => break,
            }
        }
        out
    }

    /// A string value (`REG_SZ`, or `REG_EXPAND_SZ` with its variables expanded). `None` when missing or empty.
    pub fn string(&self, value: &str) -> Option<String> {
        get_string(self.0, value).map(|s| s.trim().to_owned()).filter(|s| !s.is_empty())
    }

    pub fn dword(&self, value: &str) -> Option<u32> {
        get_dword(self.0, value)
    }
}

fn get_string(key: HKEY, value: &str) -> Option<String> {
    let v = wide(value);
    let mut buf: Vec<u16> = vec![0; 128];
    loop {
        let mut bytes = (buf.len() * 2) as u32;
        // SAFETY: `v` is zero-terminated and outlives the call; `buf` is writable for `bytes` bytes, and
        // RegGetValueW writes at most that many, updating `bytes` to what it needs when the buffer is too small.
        let rc = unsafe { RegGetValueW(key, null(), v.as_ptr(), RRF_RT_REG_SZ, null_mut(), buf.as_mut_ptr().cast(), &raw mut bytes) };
        match rc {
            ERROR_SUCCESS => return Some(from_wide(&buf[..(bytes as usize / 2).min(buf.len())])),
            ERROR_MORE_DATA if buf.len() < 32 * 1024 => buf.resize((bytes as usize).div_ceil(2) + 1, 0),
            _ => return None,
        }
    }
}

fn get_dword(key: HKEY, value: &str) -> Option<u32> {
    let v = wide(value);
    let mut data: u32 = 0;
    let mut bytes = 4u32;
    // SAFETY: as above; `data` is 4 writable bytes and RRF_RT_REG_DWORD only accepts a 4-byte value.
    let rc = unsafe { RegGetValueW(key, null(), v.as_ptr(), RRF_RT_REG_DWORD, null_mut(), (&raw mut data).cast(), &raw mut bytes) };
    (rc == ERROR_SUCCESS).then_some(data)
}

/// A `REG_SZ` under HKLM. `None` when missing or not a string.
pub fn hklm_string(subkey: &str, value: &str) -> Option<String> {
    Key::open(Root::LocalMachine, subkey, View::Native)?.string(value)
}

/// A `REG_DWORD` under HKLM.
pub fn hklm_dword(subkey: &str, value: &str) -> Option<u32> {
    Key::open(Root::LocalMachine, subkey, View::Native)?.dword(value)
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

    #[test]
    fn walks_keys_in_both_views() {
        let path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
        let native = Key::open(Root::LocalMachine, path, View::Native).unwrap().subkeys();
        let wow = Key::open(Root::LocalMachine, path, View::Wow32).unwrap().subkeys();
        assert!(!native.is_empty() && !wow.is_empty() && native != wow);
        assert_ne!(Key::open(Root::Users, "", View::Native).unwrap().subkeys(), Vec::<String>::new());
    }
}
