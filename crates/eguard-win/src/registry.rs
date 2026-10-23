//! The registry: values under HKLM, walking keys (Uninstall entries, each user's hive), and writing the browser
//! policies (`browsers`).
#![allow(unsafe_code)]

use crate::wide::{from_wide, wide};
use std::collections::BTreeMap;
use std::io;
use std::ptr::{null, null_mut};
use windows_sys::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_MORE_DATA, ERROR_NO_MORE_ITEMS, ERROR_SUCCESS, WIN32_ERROR};
use windows_sys::Win32::System::Registry::{
    HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, HKEY_USERS, KEY_READ, KEY_WOW64_32KEY, KEY_WOW64_64KEY, KEY_WRITE, REG_DWORD,
    REG_OPTION_NON_VOLATILE, REG_SZ, RRF_RT_REG_DWORD, RRF_RT_REG_SZ, RegCloseKey, RegCreateKeyExW, RegDeleteTreeW, RegDeleteValueW,
    RegEnumKeyExW, RegEnumValueW, RegGetValueW, RegOpenKeyExW, RegSetValueExW,
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
    /// The account running this program's own hive.
    CurrentUser,
}

fn root_key(root: Root) -> HKEY {
    match root {
        Root::LocalMachine => HKEY_LOCAL_MACHINE,
        Root::Users => HKEY_USERS,
        Root::CurrentUser => HKEY_CURRENT_USER,
    }
}

fn view_flag(view: View) -> u32 {
    if view == View::Wow32 { KEY_WOW64_32KEY } else { KEY_WOW64_64KEY }
}

fn check(rc: WIN32_ERROR) -> io::Result<()> {
    if rc == ERROR_SUCCESS { Ok(()) } else { Err(io::Error::from_raw_os_error(rc as i32)) }
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
        Self::open_under(root_key(root), path, view)
    }

    /// Opens `path` under `root` for reading and writing, creating it (and the keys above it) when missing.
    pub fn create(root: Root, path: &str, view: View) -> io::Result<Self> {
        let p = wide(path);
        let mut out: HKEY = null_mut();
        // SAFETY: `p` is zero-terminated; no class, default security (inherited from the parent key); `out`
        // receives a key we close on drop; the disposition isn't wanted.
        let rc = unsafe {
            RegCreateKeyExW(
                root_key(root),
                p.as_ptr(),
                0,
                null(),
                REG_OPTION_NON_VOLATILE,
                KEY_READ | KEY_WRITE | view_flag(view),
                null(),
                &raw mut out,
                null_mut(),
            )
        };
        check(rc).map(|()| Self(out))
    }

    fn open_under(parent: HKEY, path: &str, view: View) -> Option<Self> {
        let p = wide(path);
        let sam = KEY_READ | view_flag(view);
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

    /// The `REG_SZ` values, by name (at most 10 000; values of other types are left out).
    pub fn strings(&self) -> BTreeMap<String, String> {
        let mut out = BTreeMap::new();
        let mut name = [0u16; 512];
        for i in 0..10_000 {
            let mut len = name.len() as u32;
            let mut kind = 0u32;
            // SAFETY: `name` is writable for `len` characters; only the name and type are asked for (data pointers
            // null), so nothing else is written.
            let rc = unsafe { RegEnumValueW(self.0, i, name.as_mut_ptr(), &raw mut len, null(), &raw mut kind, null_mut(), null_mut()) };
            match rc {
                ERROR_SUCCESS if kind == REG_SZ => {
                    let n = from_wide(&name[..len as usize]);
                    if let Some(v) = get_string(self.0, &n) {
                        out.insert(n, v);
                    }
                }
                ERROR_SUCCESS | ERROR_MORE_DATA => {}
                _ => break,
            }
        }
        out
    }

    /// Writes a `REG_SZ`.
    pub fn set_string(&self, value: &str, data: &str) -> io::Result<()> {
        let v = wide(value);
        let d = wide(data);
        let bytes = u32::try_from(d.len() * 2).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        // SAFETY: `v` and `d` are zero-terminated and outlive the call; `bytes` is `d`'s size, terminator included.
        check(unsafe { RegSetValueExW(self.0, v.as_ptr(), 0, REG_SZ, d.as_ptr().cast(), bytes) })
    }

    /// Writes a `REG_DWORD`.
    pub fn set_dword(&self, value: &str, data: u32) -> io::Result<()> {
        let v = wide(value);
        // SAFETY: `v` is zero-terminated; the data is 4 bytes, as REG_DWORD needs.
        check(unsafe { RegSetValueExW(self.0, v.as_ptr(), 0, REG_DWORD, (&raw const data).cast(), 4) })
    }

    /// Deletes a value. One that isn't there is fine.
    pub fn delete_value(&self, value: &str) -> io::Result<()> {
        let v = wide(value);
        // SAFETY: `v` is zero-terminated.
        match unsafe { RegDeleteValueW(self.0, v.as_ptr()) } {
            ERROR_FILE_NOT_FOUND => Ok(()),
            rc => check(rc),
        }
    }

    /// Deletes the subkey `path` and everything under it. One that isn't there is fine.
    pub fn delete_tree(&self, path: &str) -> io::Result<()> {
        let p = wide(path);
        // SAFETY: `p` is zero-terminated; this key was opened with write access (`create`), which the call needs.
        match unsafe { RegDeleteTreeW(self.0, p.as_ptr()) } {
            ERROR_FILE_NOT_FOUND => Ok(()),
            rc => check(rc),
        }
    }

    /// True when the key has no values and no subkeys.
    pub fn is_empty(&self) -> bool {
        let mut name = [0u16; 2];
        let mut len = name.len() as u32;
        // SAFETY: as in `strings`; an empty key answers ERROR_NO_MORE_ITEMS at once, any value or a long name doesn't.
        let rc = unsafe { RegEnumValueW(self.0, 0, name.as_mut_ptr(), &raw mut len, null(), null_mut(), null_mut(), null_mut()) };
        rc == ERROR_NO_MORE_ITEMS && self.subkeys().is_empty()
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
