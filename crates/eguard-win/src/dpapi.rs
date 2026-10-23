//! DPAPI, machine scope (spec principle 5): the device token and removal secret are encrypted for this computer.
//!
//! Machine scope means any process on this computer could decrypt the blob, so what keeps it secret is the folder:
//! only SYSTEM (and administrators) can read `%ProgramData%\eGuard` (`files::ensure_dir`). What DPAPI adds is that a
//! copy of the file is useless on another computer, and that it never sits on disk in the clear.
#![allow(unsafe_code)]

use std::ptr::{null, null_mut};
use windows_sys::Win32::Foundation::{HLOCAL, LocalFree};
use windows_sys::Win32::Security::Cryptography::{
    CRYPT_INTEGER_BLOB, CRYPTPROTECT_LOCAL_MACHINE, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData, CryptUnprotectData,
};

/// Ties blobs to eGuard: another program's DPAPI blob won't decrypt as ours, and ours won't decrypt without it.
const ENTROPY: &[u8] = b"eGuard device secrets v1";

fn blob(data: &[u8]) -> CRYPT_INTEGER_BLOB {
    CRYPT_INTEGER_BLOB { cbData: data.len() as u32, pbData: data.as_ptr().cast_mut() }
}

/// Copies DPAPI's output and frees it.
fn take(out: CRYPT_INTEGER_BLOB) -> Vec<u8> {
    // SAFETY: DPAPI returned `cbData` bytes at `pbData`, allocated with LocalAlloc; we copy them, then free once.
    unsafe {
        let v = std::slice::from_raw_parts(out.pbData, out.cbData as usize).to_vec();
        LocalFree(out.pbData as HLOCAL);
        v
    }
}

pub fn protect(plain: &[u8]) -> std::io::Result<Vec<u8>> {
    let (input, entropy) = (blob(plain), blob(ENTROPY));
    let mut out = CRYPT_INTEGER_BLOB { cbData: 0, pbData: null_mut() };
    // SAFETY: the input blobs point at live slices for the call; DPAPI only reads them. `out` receives a buffer
    // we free in `take`. No prompt (UI_FORBIDDEN): services have no desktop.
    let ok = unsafe {
        CryptProtectData(
            &raw const input,
            null(),
            &raw const entropy,
            null(),
            null(),
            CRYPTPROTECT_LOCAL_MACHINE | CRYPTPROTECT_UI_FORBIDDEN,
            &raw mut out,
        )
    };
    if ok == 0 {
        return Err(crate::last_error());
    }
    Ok(take(out))
}

pub fn unprotect(sealed: &[u8]) -> std::io::Result<Vec<u8>> {
    let (input, entropy) = (blob(sealed), blob(ENTROPY));
    let mut out = CRYPT_INTEGER_BLOB { cbData: 0, pbData: null_mut() };
    // SAFETY: as in `protect`; the description out-pointer is null (not wanted).
    let ok = unsafe {
        CryptUnprotectData(&raw const input, null_mut(), &raw const entropy, null(), null(), CRYPTPROTECT_UI_FORBIDDEN, &raw mut out)
    };
    if ok == 0 {
        return Err(crate::last_error());
    }
    Ok(take(out))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_and_rejects_tampering() {
        let sealed = protect(b"device token").unwrap();
        assert!(!sealed.windows(12).any(|w| w == b"device token"));
        assert_eq!(unprotect(&sealed).unwrap(), b"device token");
        let mut bad = sealed.clone();
        let last = bad.len() - 1;
        bad[last] ^= 0xff;
        assert!(unprotect(&bad).is_err());
    }
}
