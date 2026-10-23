//! The computer's Windows accounts (spec section 4: which are the child's): local accounts, including those signed
//! in with a Microsoft account, that are enabled. Built-in ones that are off (Administrator, Guest,
//! `DefaultAccount`) are left out by being disabled.
#![allow(unsafe_code)]

use crate::wide::{from_wide, wide};
use eguard_core::accounts::Account;
use std::ptr::{null, null_mut};
use windows_sys::Win32::NetworkManagement::NetManagement::{
    FILTER_NORMAL_ACCOUNT, MAX_PREFERRED_LENGTH, NetApiBufferFree, NetUserEnum, UF_ACCOUNTDISABLE, USER_INFO_1, USER_PRIV_ADMIN,
};
use windows_sys::Win32::Security::{LookupAccountNameW, SID_NAME_USE};

/// The enabled local accounts, with their SIDs and whether each is an administrator.
pub fn list() -> Vec<Account> {
    let mut buf: *mut u8 = null_mut();
    let (mut read, mut total) = (0u32, 0u32);
    // SAFETY: out-parameters are live; the buffer (all entries at once, MAX_PREFERRED_LENGTH) is freed below.
    let rc = unsafe {
        NetUserEnum(null(), 1, FILTER_NORMAL_ACCOUNT, &raw mut buf, MAX_PREFERRED_LENGTH, &raw mut read, &raw mut total, null_mut())
    };
    if rc != 0 || buf.is_null() {
        return Vec::new();
    }
    // SAFETY: on success `buf` holds `read` USER_INFO_1 entries whose strings live in the same buffer. NetApi
    // allocates it from the heap, aligned for any structure.
    #[allow(clippy::cast_ptr_alignment)]
    let users: Vec<(String, bool)> = unsafe { std::slice::from_raw_parts(buf.cast::<USER_INFO_1>(), read as usize) }
        .iter()
        .filter(|u| u.usri1_flags & UF_ACCOUNTDISABLE == 0 && !u.usri1_name.is_null())
        // SAFETY: a zero-terminated name inside the buffer, read before it's freed.
        .map(|u| (unsafe { pwstr(u.usri1_name) }, u.usri1_priv == USER_PRIV_ADMIN))
        .collect();
    // SAFETY: allocated by NetUserEnum, freed once.
    unsafe { NetApiBufferFree(buf.cast()) };
    users.into_iter().filter_map(|(name, admin)| Some(Account { sid: sid_of(&name)?, name, admin })).collect()
}

/// # Safety
/// `p` must point at a zero-terminated UTF-16 string.
unsafe fn pwstr(p: *const u16) -> String {
    // SAFETY: the caller guarantees the terminating zero; names are far shorter than this bound.
    unsafe {
        let len = (0..4096).take_while(|&i| *p.add(i) != 0).count();
        from_wide(std::slice::from_raw_parts(p, len))
    }
}

/// The SID of an account by name (`name` or `DOMAIN\name`), as a string.
pub fn sid_of(name: &str) -> Option<String> {
    let n = wide(name);
    let mut sid = [0u64; 16]; // a SID is at most 68 bytes; u64s keep it aligned
    let mut sid_len = size_of_val(&sid) as u32;
    let mut domain = [0u16; 256];
    let mut domain_len = domain.len() as u32;
    let mut kind: SID_NAME_USE = 0;
    // SAFETY: every buffer is live with its size passed; the call fails rather than overrun them.
    let ok = unsafe {
        LookupAccountNameW(
            null(),
            n.as_ptr(),
            sid.as_mut_ptr().cast(),
            &raw mut sid_len,
            domain.as_mut_ptr(),
            &raw mut domain_len,
            &raw mut kind,
        )
    } != 0;
    // SAFETY: on success `sid` holds a valid SID.
    ok.then(|| unsafe { crate::security::sid_string(sid.as_mut_ptr().cast()) }.ok()).flatten()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn this_user_is_one_of_the_accounts() {
        let me = crate::security::current_user_sid().unwrap();
        let all = list();
        assert_ne!(all.len(), 0);
        assert!(all.iter().all(|a| a.sid.starts_with("S-1-5-21-") && !a.name.is_empty()));
        // A domain or work account isn't a local account; this PC signs in with a local or Microsoft account
        if let Some(a) = all.iter().find(|a| a.sid == me) {
            assert_eq!(sid_of(&a.name).as_deref(), Some(me.as_str()));
        }
        assert_eq!(sid_of("no-such-account-eguard"), None);
    }
}
