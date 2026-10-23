//! Who signed a file, when the signature is valid (`WinVerifyTrust`, spec section 5 rule 3 and section 7).
//!
//! Checked offline: no revocation lookups and no downloads, so a scan never waits on the network and never tells
//! anyone what's installed. `signer_names` reads embedded signatures (what apps carry); `catalog_signer` reads
//! Windows' catalogs (how Windows signs most of its own files), for telling Windows' programs apart at enforcement.
#![allow(unsafe_code)]

use crate::wide::{from_wide, wide};
use std::fmt::Write;
use std::ptr::{null, null_mut};
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::Security::Cryptography::Catalog::{
    CATALOG_INFO, CryptCATAdminAcquireContext2, CryptCATAdminCalcHashFromFileHandle2, CryptCATAdminEnumCatalogFromHash,
    CryptCATAdminReleaseCatalogContext, CryptCATAdminReleaseContext, CryptCATCatalogInfoFromContext,
};
use windows_sys::Win32::Security::Cryptography::{
    BCRYPT_SHA256_ALGORITHM, CERT_NAME_ATTR_TYPE, CERT_NAME_SIMPLE_DISPLAY_TYPE, CertGetNameStringW, szOID_ORGANIZATION_NAME,
};
use windows_sys::Win32::Security::WinTrust::{
    DRIVER_ACTION_VERIFY, WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_CATALOG_INFO, WINTRUST_DATA, WINTRUST_DATA_0, WINTRUST_FILE_INFO,
    WTD_CACHE_ONLY_URL_RETRIEVAL, WTD_CHOICE_CATALOG, WTD_CHOICE_FILE, WTD_DISABLE_MD2_MD4, WTD_REVOCATION_CHECK_NONE, WTD_REVOKE_NONE,
    WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY, WTD_UI_NONE, WTHelperGetProvSignerFromChain, WTHelperProvDataFromStateData,
    WinVerifyTrust,
};

/// Who signed a file: the certificate's organisation (O), which names the company the way the catalog does, and
/// its common name (CN) when that's different (Microsoft signs .NET as CN ".NET", O "Microsoft Corporation").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signer {
    pub organization: Option<String>,
    pub common_name: Option<String>,
}

impl Signer {
    /// The organisation, else the common name. Lower case.
    pub fn name(&self) -> Option<&str> {
        self.organization.as_deref().or(self.common_name.as_deref())
    }

    /// The common name when it isn't the organisation.
    pub fn alternative(&self) -> Option<&str> {
        self.common_name.as_deref().filter(|cn| self.organization.as_deref().is_some_and(|o| o != *cn))
    }
}

/// The signer's names (lower case) when `path` carries a valid signature.
pub fn signer(path: &std::path::Path) -> Option<String> {
    signer_names(path).and_then(|s| s.name().map(str::to_owned))
}

/// Both names, when `path` carries a valid embedded signature.
pub fn signer_names(path: &std::path::Path) -> Option<Signer> {
    let p = wide(&path.to_string_lossy());
    let mut file = WINTRUST_FILE_INFO { cbStruct: size_of::<WINTRUST_FILE_INFO>() as u32, pcwszFilePath: p.as_ptr(), ..Default::default() };
    let mut data = trust_data(WTD_CHOICE_FILE, WINTRUST_DATA_0 { pFile: &raw mut file });
    // SAFETY: `data` points at `file`, which points at `p`; all three outlive the call.
    unsafe { verify(&mut data) }
}

/// Who signed `path` through one of Windows' catalogs (how Windows signs most of its own files, and how a driver
/// package's files are signed), when that signature is valid. Offline, like `signer_names`.
pub fn catalog_signer(path: &std::path::Path) -> Option<Signer> {
    use std::os::windows::io::AsRawHandle;
    let f = std::fs::File::open(path).ok()?;
    let handle = f.as_raw_handle() as HANDLE;
    // Windows 11's catalogs are SHA-256; older ones (and some drivers') SHA-1, which a null algorithm asks for
    [BCRYPT_SHA256_ALGORITHM, null()].into_iter().find_map(|alg| {
        let mut admin: isize = 0;
        // SAFETY: `admin` is a live out-parameter; released below.
        if unsafe { CryptCATAdminAcquireContext2(&raw mut admin, &DRIVER_ACTION_VERIFY, alg, null(), 0) } == 0 {
            return None;
        }
        let signer = catalog_member(admin, handle, path);
        // SAFETY: acquired above, released once.
        unsafe { CryptCATAdminReleaseContext(admin, 0) };
        signer
    })
}

/// Finds the catalog that lists the open file `handle` and verifies the file against it.
fn catalog_member(admin: isize, handle: HANDLE, path: &std::path::Path) -> Option<Signer> {
    let mut len = 0u32;
    // SAFETY: a null buffer asks for the hash's size.
    unsafe { CryptCATAdminCalcHashFromFileHandle2(admin, handle, &raw mut len, null_mut(), 0) };
    if len == 0 || len > 64 {
        return None;
    }
    let mut hash = vec![0u8; len as usize];
    // SAFETY: `hash` holds `len` bytes; `handle` is the open file.
    if unsafe { CryptCATAdminCalcHashFromFileHandle2(admin, handle, &raw mut len, hash.as_mut_ptr(), 0) } == 0 {
        return None;
    }
    // SAFETY: `hash` is `len` bytes; no previous context.
    let cat = unsafe { CryptCATAdminEnumCatalogFromHash(admin, hash.as_ptr(), len, 0, null_mut()) };
    if cat == 0 {
        return None;
    }
    let mut info = CATALOG_INFO { cbStruct: size_of::<CATALOG_INFO>() as u32, ..Default::default() };
    // SAFETY: `cat` is the context just returned; `info` is a live struct with its size set.
    let found = unsafe { CryptCATCatalogInfoFromContext(cat, &raw mut info, 0) } != 0;
    let result = if found {
        let tag = wide(&hash.iter().fold(String::new(), |mut s, b| {
            let _ = write!(s, "{b:02X}");
            s
        }));
        let member = wide(&path.to_string_lossy());
        let mut c = WINTRUST_CATALOG_INFO {
            cbStruct: size_of::<WINTRUST_CATALOG_INFO>() as u32,
            pcwszCatalogFilePath: info.wszCatalogFile.as_ptr(),
            pcwszMemberTag: tag.as_ptr(),
            pcwszMemberFilePath: member.as_ptr(),
            hMemberFile: handle,
            pbCalculatedFileHash: hash.as_mut_ptr(),
            cbCalculatedFileHash: len,
            hCatAdmin: admin,
            ..Default::default()
        };
        let mut data = trust_data(WTD_CHOICE_CATALOG, WINTRUST_DATA_0 { pCatalog: &raw mut c });
        // SAFETY: `data` points at `c`, whose pointers (catalog path, tag, member path, hash) are live locals here;
        // the file handle is open.
        unsafe { verify(&mut data) }
    } else {
        None
    };
    // SAFETY: the context from the enumeration above, released once.
    unsafe { CryptCATAdminReleaseCatalogContext(admin, cat, 0) };
    result
}

/// Microsoft's name on a signature (O "Microsoft Corporation", CN "Microsoft Windows" or a hardware-publisher CN).
pub fn is_microsoft(s: &Signer) -> bool {
    [s.organization.as_deref(), s.common_name.as_deref()].into_iter().flatten().any(|n| n.starts_with("microsoft "))
}

/// Signed by Microsoft, embedded or through a catalog (spec section 7: never block Windows' own programs).
pub fn microsoft_signed(path: &std::path::Path) -> bool {
    signer_names(path).as_ref().is_some_and(is_microsoft) || catalog_signer(path).as_ref().is_some_and(is_microsoft)
}

fn trust_data(choice: u32, what: WINTRUST_DATA_0) -> WINTRUST_DATA {
    WINTRUST_DATA {
        cbStruct: size_of::<WINTRUST_DATA>() as u32,
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_NONE,
        dwUnionChoice: choice,
        Anonymous: what,
        dwStateAction: WTD_STATEACTION_VERIFY,
        dwProvFlags: WTD_REVOCATION_CHECK_NONE | WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_DISABLE_MD2_MD4,
        ..Default::default()
    }
}

/// Verifies, reads the leaf certificate's names, and releases the state.
///
/// # Safety
/// `data`'s union member must point at a live, filled-in file or catalog struct for the duration of the call.
unsafe fn verify(data: &mut WINTRUST_DATA) -> Option<Signer> {
    let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    // SAFETY: the caller guarantees `data` is complete. No window: UI is off.
    let status = unsafe { WinVerifyTrust(null_mut(), &raw mut action, (&raw mut *data).cast()) };
    let name = if status == 0 {
        // SAFETY: after a successful verify, the state data holds the provider data until the close below. Its
        // first signer's chain starts with the leaf certificate. Each pointer is checked before use.
        unsafe {
            let prov = WTHelperProvDataFromStateData(data.hWVTStateData);
            let sgnr = if prov.is_null() { null_mut() } else { WTHelperGetProvSignerFromChain(prov, 0, 0, 0) };
            if sgnr.is_null() || (*sgnr).csCertChain == 0 || (*sgnr).pasCertChain.is_null() {
                None
            } else {
                let cert = (*(*sgnr).pasCertChain).pCert;
                let get = |kind: u32, para: *const std::ffi::c_void| {
                    let mut buf = [0u16; 256];
                    let n = CertGetNameStringW(cert, kind, 0, para, buf.as_mut_ptr(), buf.len() as u32);
                    Some(from_wide(&buf[..n as usize]).trim().to_lowercase()).filter(|s| n > 1 && !s.is_empty())
                };
                Some(Signer {
                    organization: get(CERT_NAME_ATTR_TYPE, szOID_ORGANIZATION_NAME.cast()),
                    common_name: get(CERT_NAME_SIMPLE_DISPLAY_TYPE, null()),
                })
            }
        }
    } else {
        None
    };
    data.dwStateAction = WTD_STATEACTION_CLOSE;
    // SAFETY: releases the state the verify call allocated (harmless when it allocated none).
    unsafe { WinVerifyTrust(null_mut(), &raw mut action, (&raw mut *data).cast()) };
    name.filter(|s| s.name().is_some())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn microsoft_signs_its_tools_and_a_plain_file_is_unsigned() {
        // Edge's setup ships with an embedded Microsoft signature on every Windows 11
        let edge = std::path::Path::new(r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe");
        if edge.exists() {
            assert_eq!(signer(edge).as_deref(), Some("microsoft corporation"));
        }
        let plain = std::env::temp_dir().join(format!("eguard-unsigned-{}.exe", std::process::id()));
        std::fs::write(&plain, b"MZ not really").unwrap();
        assert_eq!(signer(&plain), None);
        assert!(!microsoft_signed(&plain));
        std::fs::remove_file(&plain).unwrap();
        assert!(!microsoft_signed(std::path::Path::new(r"C:\no\such\file.exe")));
    }

    #[test]
    fn windows_own_programs_are_catalog_signed_by_microsoft() {
        let system = std::path::PathBuf::from(std::env::var("SystemRoot").unwrap()).join("System32");
        for exe in ["notepad.exe", "cmd.exe", "taskmgr.exe"] {
            let p = system.join(exe);
            assert!(microsoft_signed(&p), "{exe}: embedded {:?}, catalog {:?}", signer_names(&p), catalog_signer(&p));
        }
    }
}
