//! Security descriptors from SDDL, the current user's SID, and locking down eGuard's folder.
#![allow(unsafe_code)]

use crate::wide::{from_wide, wide};
use std::ptr::{null, null_mut};
use windows_sys::Win32::Foundation::{CloseHandle, ERROR_SUCCESS, HANDLE, HLOCAL, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, GetNamedSecurityInfoW, GetSecurityInfo, SDDL_REVISION_1,
    SE_FILE_OBJECT, SetNamedSecurityInfoW,
};
use windows_sys::Win32::Security::{
    ACL, DACL_SECURITY_INFORMATION, GetSecurityDescriptorDacl, GetSecurityDescriptorOwner, GetTokenInformation, OWNER_SECURITY_INFORMATION,
    PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES, TOKEN_GROUPS, TOKEN_INFORMATION_CLASS,
    TOKEN_QUERY, TOKEN_USER, TokenLogonSid, TokenUser,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

/// eGuard's data folder in a real install (spec section 3): owned by SYSTEM, which alone writes it; administrators
/// may read it. Nothing is inherited from `ProgramData` (where every user can create files). Files inside inherit it.
pub const DATA_DIR_SDDL: &str = "O:SYD:P(A;OICI;FA;;;SY)(A;OICI;FRFX;;;BA)";

/// Owners a real install's data folder may already have: SYSTEM, or administrators (the default owner of objects
/// SYSTEM creates). Anyone else made the folder first.
const TRUSTED_OWNERS: [&str; 2] = ["S-1-5-18", "S-1-5-32-544"];

/// A self-relative security descriptor made from SDDL, freed on drop.
#[derive(Debug)]
pub struct SecurityDescriptor(PSECURITY_DESCRIPTOR);

// The descriptor is an immutable block of memory owned by this value
unsafe impl Send for SecurityDescriptor {}
unsafe impl Sync for SecurityDescriptor {}

impl SecurityDescriptor {
    pub fn from_sddl(sddl: &str) -> std::io::Result<Self> {
        let s = wide(sddl);
        let mut sd: PSECURITY_DESCRIPTOR = null_mut();
        // SAFETY: `s` is zero-terminated; on success `sd` receives a LocalAlloc'd descriptor that `Drop` frees.
        let ok = unsafe { ConvertStringSecurityDescriptorToSecurityDescriptorW(s.as_ptr(), SDDL_REVISION_1, &raw mut sd, null_mut()) };
        if ok == 0 {
            return Err(crate::last_error());
        }
        Ok(Self(sd))
    }

    /// For `CreateNamedPipeW` / `CreateDirectoryW`. Valid while `self` lives.
    pub fn attributes(&self) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES { nLength: size_of::<SECURITY_ATTRIBUTES>() as u32, lpSecurityDescriptor: self.0, bInheritHandle: 0 }
    }

    /// The descriptor itself, for calls that take one. Valid while `self` lives.
    pub(crate) fn raw(&self) -> PSECURITY_DESCRIPTOR {
        self.0
    }

    fn owner(&self) -> std::io::Result<PSID> {
        let (mut owner, mut defaulted) = (null_mut(), 0);
        // SAFETY: `self.0` is a valid descriptor; the out-pointers are live locals. The SID points into it.
        let ok = unsafe { GetSecurityDescriptorOwner(self.0, &raw mut owner, &raw mut defaulted) };
        if ok == 0 || owner.is_null() {
            return Err(std::io::Error::other("the descriptor has no owner"));
        }
        Ok(owner)
    }

    fn dacl(&self) -> std::io::Result<*mut ACL> {
        let (mut present, mut defaulted, mut dacl) = (0, 0, null_mut());
        // SAFETY: `self.0` is a valid descriptor; the out-pointers are live locals. The DACL points into it.
        let ok = unsafe { GetSecurityDescriptorDacl(self.0, &raw mut present, &raw mut dacl, &raw mut defaulted) };
        if ok == 0 || present == 0 {
            return Err(std::io::Error::other("the descriptor has no DACL"));
        }
        Ok(dacl)
    }
}

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        // SAFETY: allocated by ConvertStringSecurityDescriptorToSecurityDescriptorW, freed once here.
        unsafe { LocalFree(self.0 as HLOCAL) };
    }
}

/// Replaces a folder's owner (when `sddl` names one) and DACL with those in `sddl`, the DACL protected from
/// inheritance. Files and folders inside inherit it. Needs the right to change the folder's owner and permissions
/// (the service has it as SYSTEM).
pub fn set_dir_security(path: &std::path::Path, sddl: &str) -> std::io::Result<()> {
    let sd = SecurityDescriptor::from_sddl(sddl)?;
    let dacl = sd.dacl()?;
    let owner = sd.owner().ok();
    let mut what = DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION;
    if owner.is_some() {
        what |= OWNER_SECURITY_INFORMATION;
    }
    let p = wide(&path.to_string_lossy());
    // SAFETY: `p` is zero-terminated; `owner` and `dacl` point into `sd`, alive for the call. Group and SACL
    // untouched.
    let rc = unsafe { SetNamedSecurityInfoW(p.as_ptr(), SE_FILE_OBJECT, what, owner.unwrap_or(null_mut()), null_mut(), dacl, null()) };
    if rc != ERROR_SUCCESS {
        return Err(std::io::Error::from_raw_os_error(rc as i32));
    }
    Ok(())
}

/// The SID of a file's or folder's owner, as a string.
pub fn owner_of(path: &std::path::Path) -> std::io::Result<String> {
    let p = wide(&path.to_string_lossy());
    let (mut owner, mut sd): (PSID, PSECURITY_DESCRIPTOR) = (null_mut(), null_mut());
    // SAFETY: `p` is zero-terminated; on success `sd` is a LocalAlloc'd descriptor (freed below) that `owner`
    // points into.
    let rc = unsafe {
        GetNamedSecurityInfoW(
            p.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &raw mut owner,
            null_mut(),
            null_mut(),
            null_mut(),
            &raw mut sd,
        )
    };
    if rc != ERROR_SUCCESS {
        return Err(std::io::Error::from_raw_os_error(rc as i32));
    }
    // SAFETY: `owner` points into `sd`, which is freed once below, after the SID is read.
    let out = unsafe { sid_string(owner) };
    // SAFETY: allocated by GetNamedSecurityInfoW, freed once.
    unsafe { LocalFree(sd as HLOCAL) };
    out
}

/// Whether `sid` may own a real install's data folder (`DATA_DIR_SDDL`): SYSTEM or administrators.
pub fn is_trusted_owner(sid: &str) -> bool {
    TRUSTED_OWNERS.contains(&sid)
}

/// The SID of the user this process runs as, as a string (`S-1-5-21-…`), for SDDL.
pub fn current_user_sid() -> std::io::Result<String> {
    with_own_token(|t| token_sid(t, TokenUser))
}

/// This process's logon SID (`S-1-5-5-…`): the one sign-in it belongs to, for a session pipe's DACL.
pub fn current_logon_sid() -> std::io::Result<String> {
    with_own_token(|t| token_sid(t, TokenLogonSid))
}

fn with_own_token<T>(f: impl FnOnce(HANDLE) -> std::io::Result<T>) -> std::io::Result<T> {
    let mut token: HANDLE = null_mut();
    // SAFETY: the pseudo-handle from GetCurrentProcess needs no closing; `token` is closed below.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut token) } == 0 {
        return Err(crate::last_error());
    }
    let result = f(token);
    // SAFETY: opened above, closed once.
    unsafe { CloseHandle(token) };
    result
}

/// A SID from `token` as a string: its user (`TokenUser`) or its logon SID (`TokenLogonSid`). Both answers start
/// with a SID pointer (a `TOKEN_USER`, or a `TOKEN_GROUPS` whose first group is the logon SID).
pub(crate) fn token_sid(token: HANDLE, class: TOKEN_INFORMATION_CLASS) -> std::io::Result<String> {
    // TOKEN_USER or TOKEN_GROUPS plus a SID: 256 bytes is ample (a SID is at most 68 bytes). u64s keep it aligned.
    let mut buf = [0u64; 32];
    let mut len = 0u32;
    // SAFETY: `buf` is writable for its size in bytes; GetTokenInformation fails rather than overrun it.
    if unsafe { GetTokenInformation(token, class, buf.as_mut_ptr().cast(), size_of_val(&buf) as u32, &raw mut len) } == 0 {
        return Err(crate::last_error());
    }
    // SAFETY: on success the buffer holds the answer for `class`, whose SIDs point inside the buffer.
    let sid = unsafe {
        if class == TokenLogonSid {
            let groups = &*buf.as_ptr().cast::<TOKEN_GROUPS>();
            if groups.GroupCount == 0 {
                return Err(std::io::Error::other("the token has no logon SID"));
            }
            groups.Groups[0].Sid
        } else {
            (*buf.as_ptr().cast::<TOKEN_USER>()).User.Sid
        }
    };
    // SAFETY: `sid` points into `buf`, alive for the call.
    unsafe { sid_string(sid) }
}

/// Who may own or change a file without it being in a standard account's reach: SYSTEM, administrators, Local and
/// Network Service, and service SIDs (`S-1-5-80-…`, `TrustedInstaller` among them).
fn trusted_writer(sid: &str) -> bool {
    matches!(sid, "S-1-5-18" | "S-1-5-19" | "S-1-5-20" | "S-1-5-32-544") || sid.starts_with("S-1-5-80-")
}

/// Rights that let someone change what a file or folder holds: write or add to it, delete it or what's in it,
/// change its permissions or owner (and the generic rights that include them).
const CHANGE_RIGHTS: u32 = 0x2 // FILE_WRITE_DATA / FILE_ADD_FILE
    | 0x4 // FILE_APPEND_DATA / FILE_ADD_SUBDIRECTORY
    | 0x40 // FILE_DELETE_CHILD
    | 0x1_0000 // DELETE
    | 0x4_0000 // WRITE_DAC
    | 0x8_0000 // WRITE_OWNER
    | 0x1000_0000 // GENERIC_ALL
    | 0x4000_0000; // GENERIC_WRITE

/// Whether only SYSTEM, administrators and services can change the file or folder at `path`: its owner is one of
/// them (an owner can always change the permissions), and its permissions let no one else write to it, add to it,
/// delete from it or change who may. Anything that can't be read counts as within reach.
///
/// This, not the path, is what says a program is out of the child's reach: a folder under Program Files can be
/// writable by every user (Steam's is), and a path can spell the same folder several ways.
pub fn out_of_users_reach(path: &std::path::Path) -> bool {
    let p = wide(&path.to_string_lossy());
    let (mut owner, mut dacl, mut sd): (PSID, *mut ACL, PSECURITY_DESCRIPTOR) = (null_mut(), null_mut(), null_mut());
    // SAFETY: `p` is zero-terminated; on success `sd` is a LocalAlloc'd descriptor (freed in `judge_reach`) that
    // `owner` and `dacl` point into.
    let rc = unsafe {
        GetNamedSecurityInfoW(
            p.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &raw mut owner,
            null_mut(),
            &raw mut dacl,
            null_mut(),
            &raw mut sd,
        )
    };
    // SAFETY: as above
    rc == ERROR_SUCCESS && unsafe { judge_reach(owner, dacl, sd) }
}

/// `out_of_users_reach` for an open file (opened with read access, which includes the right to read its
/// permissions), so the answer is about that file and no other put at its path.
pub fn file_out_of_users_reach(file: &std::fs::File) -> bool {
    use std::os::windows::io::AsRawHandle;
    let (mut owner, mut dacl, mut sd): (PSID, *mut ACL, PSECURITY_DESCRIPTOR) = (null_mut(), null_mut(), null_mut());
    // SAFETY: the handle is open for the call; on success `sd` is a LocalAlloc'd descriptor (freed in
    // `judge_reach`) that `owner` and `dacl` point into.
    let rc = unsafe {
        GetSecurityInfo(
            file.as_raw_handle() as HANDLE,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &raw mut owner,
            null_mut(),
            &raw mut dacl,
            null_mut(),
            &raw mut sd,
        )
    };
    // SAFETY: as above
    rc == ERROR_SUCCESS && unsafe { judge_reach(owner, dacl, sd) }
}

/// # Safety
/// `owner` and `dacl` point into `sd`, a descriptor from `Get*SecurityInfo` that this frees.
unsafe fn judge_reach(owner: PSID, dacl: *mut ACL, sd: PSECURITY_DESCRIPTOR) -> bool {
    // SAFETY: the caller guarantees the pointers
    let out = unsafe { !owner.is_null() && sid_string(owner).is_ok_and(|s| trusted_writer(&s)) && !dacl_lets_others_change(dacl) };
    // SAFETY: allocated by Get*SecurityInfo, freed once.
    unsafe { LocalFree(sd as HLOCAL) };
    out
}

/// Whether an allow entry in `dacl` gives `CHANGE_RIGHTS` to anyone not a `trusted_writer`. No DACL at all lets
/// everyone do anything. Deny entries aren't weighed: they could only make the answer less strict.
///
/// # Safety
/// `dacl` is null or points at a valid ACL.
unsafe fn dacl_lets_others_change(dacl: *mut ACL) -> bool {
    use windows_sys::Win32::Security::{ACCESS_ALLOWED_ACE, ACE_HEADER, GetAce};
    const ACCESS_ALLOWED: u8 = 0;
    const ACCESS_ALLOWED_CALLBACK: u8 = 9;
    const INHERIT_ONLY: u8 = 0x08;
    if dacl.is_null() {
        return true;
    }
    // SAFETY: the caller guarantees `dacl`
    let count = unsafe { (*dacl).AceCount };
    for i in 0..u32::from(count) {
        let mut ace = null_mut();
        // SAFETY: `i` is below the ACL's count; `ace` receives a pointer into the ACL.
        if unsafe { GetAce(dacl, i, &raw mut ace) } == 0 {
            return true;
        }
        // SAFETY: every ACE starts with an ACE_HEADER
        let header = unsafe { &*ace.cast::<ACE_HEADER>() };
        if header.AceFlags & INHERIT_ONLY != 0 || !matches!(header.AceType, ACCESS_ALLOWED | ACCESS_ALLOWED_CALLBACK) {
            continue;
        }
        // SAFETY: both allow types are laid out as ACCESS_ALLOWED_ACE (header, mask, then the SID)
        let allowed = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
        if allowed.Mask & CHANGE_RIGHTS == 0 {
            continue;
        }
        // SAFETY: the SID starts at `SidStart` and lies inside the ACE
        let sid = unsafe { sid_string((&raw const allowed.SidStart).cast_mut().cast()) };
        if !sid.is_ok_and(|s| trusted_writer(&s)) {
            return true;
        }
    }
    false
}

/// A SID as a string (`S-1-5-21-…`).
///
/// # Safety
/// `sid` must point at a valid SID for the duration of the call.
pub(crate) unsafe fn sid_string(sid: windows_sys::Win32::Security::PSID) -> std::io::Result<String> {
    let mut s = null_mut();
    // SAFETY: the caller guarantees `sid`; `s` receives a LocalAlloc'd string freed below.
    if unsafe { ConvertSidToStringSidW(sid, &raw mut s) } == 0 {
        return Err(crate::last_error());
    }
    // SAFETY: `s` is a zero-terminated UTF-16 string from Windows; read up to the zero, then freed once.
    let out = unsafe {
        // A SID string is at most 184 characters
        let len = (0..256).take_while(|&i| *s.add(i) != 0).count();
        let v = from_wide(std::slice::from_raw_parts(s, len));
        LocalFree(s as HLOCAL);
        v
    };
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sddl_parses_and_the_user_has_a_sid() {
        assert!(SecurityDescriptor::from_sddl(DATA_DIR_SDDL).is_ok());
        assert!(SecurityDescriptor::from_sddl("not sddl").is_err());
        let sid = current_user_sid().unwrap();
        assert!(sid.starts_with("S-1-5-"), "{sid}");
        assert!(SecurityDescriptor::from_sddl(&format!("D:P(A;;GA;;;SY)(A;;GA;;;{sid})")).is_ok());
        assert!(SecurityDescriptor::from_sddl(DATA_DIR_SDDL).unwrap().owner().is_ok());
        let owner = owner_of(&std::env::temp_dir()).unwrap();
        assert!(owner.starts_with("S-1-5-"), "{owner}");
        assert!(is_trusted_owner("S-1-5-18") && is_trusted_owner("S-1-5-32-544") && !is_trusted_owner(&sid));
        let logon = current_logon_sid().unwrap();
        assert!(logon.starts_with("S-1-5-5-"), "{logon}");
    }

    #[test]
    fn program_files_is_out_of_reach_and_a_users_own_folder_is_not() {
        let system_root = std::env::var_os("SystemRoot").unwrap();
        let system32 = std::path::Path::new(&system_root).join("System32");
        assert!(out_of_users_reach(&system32));
        let program_files = std::path::PathBuf::from(std::env::var_os("ProgramFiles").unwrap());
        assert!(out_of_users_reach(&program_files) && out_of_users_reach(&program_files.join("Common Files")));
        let notepad = std::fs::File::open(system32.join("notepad.exe")).unwrap();
        assert!(file_out_of_users_reach(&notepad));
        // Made by this (non-SYSTEM) user, who owns it
        let dir = std::env::temp_dir().join(format!("eguard-reach-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("game.exe"), b"MZ").unwrap();
        let mine = std::fs::File::open(dir.join("game.exe")).unwrap();
        let (folder, file) = (out_of_users_reach(&dir), file_out_of_users_reach(&mine));
        drop(mine);
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(!folder && !file);
        assert!(!out_of_users_reach(&dir), "a folder that isn't there");
        assert!(trusted_writer("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"));
        assert!(!trusted_writer("S-1-5-32-545") && !trusted_writer("S-1-5-11") && !trusted_writer("S-1-1-0"));
    }
}
