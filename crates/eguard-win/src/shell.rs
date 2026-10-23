//! Store apps name themselves with resource references (`@{Package?ms-resource://…}`); the shell resolves them.
#![allow(unsafe_code)]

use crate::wide::{from_wide, wide};
use std::ptr::null;
use windows_sys::Win32::UI::Shell::SHLoadIndirectString;

/// The text behind an `@…` reference, or the string itself when it isn't one. `None` when it can't be resolved.
pub fn indirect_string(s: &str) -> Option<String> {
    if !s.starts_with('@') {
        return Some(s.to_owned());
    }
    let src = wide(s);
    let mut buf = [0u16; 512];
    // SAFETY: `src` is zero-terminated; `buf` is writable for its length in characters.
    let hr = unsafe { SHLoadIndirectString(src.as_ptr(), buf.as_mut_ptr(), buf.len() as u32, null()) };
    let out = from_wide(&buf);
    (hr >= 0 && !out.trim().is_empty()).then(|| out.trim().to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_strings_pass_and_bad_references_dont() {
        assert_eq!(indirect_string("WhatsApp").as_deref(), Some("WhatsApp"));
        assert_eq!(indirect_string("@{No.Such.Package_1.0.0.0_x64__abc?ms-resource://x/y}"), None);
    }
}
