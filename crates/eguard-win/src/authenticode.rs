//! Who signed a file, when the signature is valid (`WinVerifyTrust`, spec section 5 rule 3).
//!
//! Embedded signatures only, checked offline: no revocation lookups and no downloads, so a scan never waits on the
//! network and never tells anyone what's installed. A file Windows signs through a catalog instead (its own system
//! files) reads as unsigned here; those live under the Windows folder, which the scan leaves out anyway.
#![allow(unsafe_code)]

use crate::wide::{from_wide, wide};
use std::ptr::{null, null_mut};
use windows_sys::Win32::Security::Cryptography::{
    CERT_NAME_ATTR_TYPE, CERT_NAME_SIMPLE_DISPLAY_TYPE, CertGetNameStringW, szOID_ORGANIZATION_NAME,
};
use windows_sys::Win32::Security::WinTrust::{
    WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_DATA_0, WINTRUST_FILE_INFO, WTD_CACHE_ONLY_URL_RETRIEVAL, WTD_CHOICE_FILE,
    WTD_DISABLE_MD2_MD4, WTD_REVOCATION_CHECK_NONE, WTD_REVOKE_NONE, WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY, WTD_UI_NONE,
    WTHelperGetProvSignerFromChain, WTHelperProvDataFromStateData, WinVerifyTrust,
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

/// Both names, when `path` carries a valid signature.
pub fn signer_names(path: &std::path::Path) -> Option<Signer> {
    let p = wide(&path.to_string_lossy());
    let mut file = WINTRUST_FILE_INFO { cbStruct: size_of::<WINTRUST_FILE_INFO>() as u32, pcwszFilePath: p.as_ptr(), ..Default::default() };
    let mut data = WINTRUST_DATA {
        cbStruct: size_of::<WINTRUST_DATA>() as u32,
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_NONE,
        dwUnionChoice: WTD_CHOICE_FILE,
        Anonymous: WINTRUST_DATA_0 { pFile: &raw mut file },
        dwStateAction: WTD_STATEACTION_VERIFY,
        dwProvFlags: WTD_REVOCATION_CHECK_NONE | WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_DISABLE_MD2_MD4,
        ..Default::default()
    };
    let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    // SAFETY: `data` and `file` point at live locals (`p` outlives both). No window: UI is off.
    let status = unsafe { WinVerifyTrust(null_mut(), &raw mut action, (&raw mut data).cast()) };
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
    unsafe { WinVerifyTrust(null_mut(), &raw mut action, (&raw mut data).cast()) };
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
        std::fs::remove_file(&plain).unwrap();
    }
}
