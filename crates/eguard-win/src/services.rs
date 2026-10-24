//! Who may do what to eGuard's service (spec section 10). The service manager keeps a security descriptor per
//! service; the `windows-service` crate doesn't reach it, so it's set here.
#![allow(unsafe_code)]

use crate::security::SecurityDescriptor;
use crate::wide::{from_wide, wide};
use std::ptr::null;
use windows_sys::Win32::Foundation::{HLOCAL, LocalFree};
use windows_sys::Win32::Security::Authorization::{ConvertSecurityDescriptorToStringSecurityDescriptorW, SDDL_REVISION_1};
use windows_sys::Win32::Security::DACL_SECURITY_INFORMATION;
use windows_sys::Win32::System::Services::{
    CloseServiceHandle, OpenSCManagerW, OpenServiceW, QueryServiceObjectSecurity, SC_HANDLE, SC_MANAGER_CONNECT, SetServiceObjectSecurity,
};

/// `READ_CONTROL` and `WRITE_DAC`, the standard rights to read and replace an object's permissions.
const READ_CONTROL: u32 = 0x0002_0000;
const WRITE_DAC: u32 = 0x0004_0000;

/// A service manager or service handle, closed on drop.
struct ScHandle(SC_HANDLE);

impl Drop for ScHandle {
    fn drop(&mut self) {
        // SAFETY: a handle from OpenSCManagerW/OpenServiceW, closed once here.
        unsafe { CloseServiceHandle(self.0) };
    }
}

fn open(name: &str, access: u32) -> std::io::Result<ScHandle> {
    // SAFETY: no strings (this computer, the active database); the handle is closed on drop.
    let manager = unsafe { OpenSCManagerW(null(), null(), SC_MANAGER_CONNECT) };
    if manager.is_null() {
        return Err(crate::last_error());
    }
    let manager = ScHandle(manager);
    let n = wide(name);
    // SAFETY: a live manager handle and a zero-terminated name; the handle is closed on drop.
    let service = unsafe { OpenServiceW(manager.0, n.as_ptr(), access) };
    if service.is_null() {
        return Err(crate::last_error());
    }
    Ok(ScHandle(service))
}

/// Replaces the service's DACL with the one in `sddl`. Needs `WRITE_DAC` on it (SYSTEM, or whoever created it, before
/// it's locked).
pub fn set_security(name: &str, sddl: &str) -> std::io::Result<()> {
    let sd = SecurityDescriptor::from_sddl(sddl)?;
    let service = open(name, WRITE_DAC)?;
    // SAFETY: a service handle with WRITE_DAC and a valid descriptor, alive for the call.
    if unsafe { SetServiceObjectSecurity(service.0, DACL_SECURITY_INFORMATION, sd.raw()) } == 0 {
        return Err(crate::last_error());
    }
    Ok(())
}

/// The service's DACL as SDDL (`D:…`), as Windows writes it back.
pub fn security(name: &str) -> std::io::Result<String> {
    let service = open(name, READ_CONTROL)?;
    let mut buf = vec![0u8; 1024];
    let mut needed = 0u32;
    for _ in 0..2 {
        // SAFETY: `buf` is writable for its length, passed as that length; `needed` is a live out-parameter.
        let ok = unsafe {
            QueryServiceObjectSecurity(service.0, DACL_SECURITY_INFORMATION, buf.as_mut_ptr().cast(), buf.len() as u32, &raw mut needed)
        };
        if ok != 0 {
            let mut s = std::ptr::null_mut();
            // SAFETY: `buf` now holds a self-relative descriptor; `s` receives a LocalAlloc'd string freed below.
            let ok = unsafe {
                ConvertSecurityDescriptorToStringSecurityDescriptorW(
                    buf.as_mut_ptr().cast(),
                    SDDL_REVISION_1,
                    DACL_SECURITY_INFORMATION,
                    &raw mut s,
                    std::ptr::null_mut(),
                )
            };
            if ok == 0 {
                return Err(crate::last_error());
            }
            // SAFETY: a zero-terminated string from the call above (a DACL in SDDL, far under 4096 characters); its
            // length is found before reading it.
            let text = unsafe {
                let len = (0..4096).take_while(|&i| *s.add(i) != 0).count();
                from_wide(std::slice::from_raw_parts(s, len))
            };
            // SAFETY: allocated by the conversion, freed once.
            unsafe { LocalFree(s as HLOCAL) };
            return Ok(text);
        }
        buf.resize(needed as usize, 0);
    }
    Err(crate::last_error())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_services_permissions_read_back() {
        // Any user may read the Windows Event Log service's permissions
        let sddl = security("EventLog").unwrap();
        assert!(sddl.starts_with("D:") && sddl.contains(";;;SY)"), "{sddl}");
        assert!(security("eGuard-no-such-service").is_err());
    }
}
