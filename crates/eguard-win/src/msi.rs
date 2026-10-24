//! eGuard's Windows Installer package: finding the installed product, so an authorized removal can take out what the
//! installer put in place (the program files, the Settings entry).
#![allow(unsafe_code)]

use crate::wide::{from_wide, wide};
use windows_sys::Win32::Foundation::ERROR_SUCCESS;
use windows_sys::Win32::System::ApplicationInstallationAndServicing::MsiEnumRelatedProductsW;

/// eGuard's upgrade code: the same in every version of the package (`installer/eguard.wxs`).
pub const UPGRADE_CODE: &str = "{6F1B7C2A-3E4D-4B8A-9C51-2D7E8F0A9B63}";

/// The product code of the installed eGuard package, `{…}`; `None` when it wasn't installed with one (a VM's
/// `eguard-service install`, console mode).
pub fn installed_product() -> Option<String> {
    let code = wide(UPGRADE_CODE);
    // A product code is a GUID in braces: 38 characters and the terminating zero
    let mut buf = [0u16; 39];
    // SAFETY: `code` is zero-terminated; `buf` holds the 39 characters the call writes.
    let rc = unsafe { MsiEnumRelatedProductsW(code.as_ptr(), 0, 0, buf.as_mut_ptr()) };
    (rc == ERROR_SUCCESS).then(|| from_wide(&buf))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn not_installed_here() {
        // eGuard's package is only ever installed on a VM
        assert_eq!(installed_product(), None);
    }
}
