//! Security descriptors from SDDL, the current user's SID, and locking down eGuard's folder.
#![allow(unsafe_code)]

use crate::wide::{from_wide, wide};
use std::ptr::{null, null_mut};
use windows_sys::Win32::Foundation::{CloseHandle, ERROR_SUCCESS, HANDLE, HLOCAL, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1, SE_FILE_OBJECT, SetNamedSecurityInfoW,
};
use windows_sys::Win32::Security::{
    ACL, DACL_SECURITY_INFORMATION, GetSecurityDescriptorDacl, GetTokenInformation, PROTECTED_DACL_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER, TokenUser,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

/// eGuard's data folder in a real install: SYSTEM and administrators only, nothing inherited from `ProgramData`
/// (where every user can create files). Files inside inherit it.
pub const DATA_DIR_SDDL: &str = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";

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

/// Replaces a folder's DACL with the one in `sddl`, protected from inheritance. Files and folders inside inherit it.
/// Needs the right to change the folder's permissions (the service has it as SYSTEM).
pub fn set_dir_dacl(path: &std::path::Path, sddl: &str) -> std::io::Result<()> {
    let sd = SecurityDescriptor::from_sddl(sddl)?;
    let dacl = sd.dacl()?;
    let p = wide(&path.to_string_lossy());
    // SAFETY: `p` is zero-terminated; `dacl` points into `sd`, alive for the call. Owner, group and SACL untouched.
    let rc = unsafe {
        SetNamedSecurityInfoW(
            p.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            dacl,
            null(),
        )
    };
    if rc != ERROR_SUCCESS {
        return Err(std::io::Error::from_raw_os_error(rc as i32));
    }
    Ok(())
}

/// The SID of the user this process runs as, as a string (`S-1-5-21-…`), for SDDL.
pub fn current_user_sid() -> std::io::Result<String> {
    let mut token: HANDLE = null_mut();
    // SAFETY: the pseudo-handle from GetCurrentProcess needs no closing; `token` is closed below.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut token) } == 0 {
        return Err(crate::last_error());
    }
    let result = (|| {
        // TOKEN_USER plus its SID: 256 bytes is ample (a SID is at most 68 bytes). u64s keep it aligned.
        let mut buf = [0u64; 32];
        let mut len = 0u32;
        // SAFETY: `buf` is writable for its size in bytes; GetTokenInformation fails rather than overrun it.
        if unsafe { GetTokenInformation(token, TokenUser, buf.as_mut_ptr().cast(), size_of_val(&buf) as u32, &raw mut len) } == 0 {
            return Err(crate::last_error());
        }
        // SAFETY: on success the buffer starts with a TOKEN_USER whose SID points inside the buffer.
        let sid = unsafe { (*buf.as_ptr().cast::<TOKEN_USER>()).User.Sid };
        let mut s = null_mut();
        // SAFETY: `sid` is valid while `buf` lives; `s` receives a LocalAlloc'd string freed below.
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
    })();
    // SAFETY: opened above, closed once.
    unsafe { CloseHandle(token) };
    result
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
    }
}
