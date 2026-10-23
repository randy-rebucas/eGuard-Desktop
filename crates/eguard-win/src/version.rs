//! An executable's product name, from its version resource (part of the `EXE` id, spec section 6).
#![allow(unsafe_code)]

use crate::wide::{from_wide, wide};
use std::ffi::c_void;
use std::ptr::null_mut;
use windows_sys::Win32::Storage::FileSystem::{GetFileVersionInfoSizeW, GetFileVersionInfoW, VerQueryValueW};

/// The resource's `ProductName`, in its first language (or US English). `None` when there is none.
pub fn product_name(path: &std::path::Path) -> Option<String> {
    let p = wide(&path.to_string_lossy());
    let mut handle = 0u32;
    // SAFETY: `p` is zero-terminated.
    let size = unsafe { GetFileVersionInfoSizeW(p.as_ptr(), &raw mut handle) };
    if size == 0 || size > 1024 * 1024 {
        return None;
    }
    let mut block = vec![0u8; size as usize];
    // SAFETY: `block` is writable for `size` bytes.
    if unsafe { GetFileVersionInfoW(p.as_ptr(), 0, size, block.as_mut_ptr().cast()) } == 0 {
        return None;
    }
    let query = |sub: &str| -> Option<(*mut c_void, u32)> {
        let s = wide(sub);
        let (mut ptr, mut len) = (null_mut(), 0u32);
        // SAFETY: `block` holds the version info read above; the returned pointer points inside it.
        let ok = unsafe { VerQueryValueW(block.as_ptr().cast(), s.as_ptr(), &raw mut ptr, &raw mut len) } != 0;
        (ok && !ptr.is_null() && len > 0).then_some((ptr, len))
    };
    let mut langs = Vec::new();
    if let Some((ptr, len)) = query(r"\VarFileInfo\Translation") {
        // SAFETY: Translation is an array of (language, code page) u16 pairs, `len` bytes long, inside `block`.
        let pairs = unsafe { std::slice::from_raw_parts(ptr.cast::<u16>(), (len / 2) as usize) };
        langs.extend(pairs.as_chunks::<2>().0.iter().take(8).map(|[lang, page]| format!("{lang:04x}{page:04x}")));
    }
    langs.extend(["040904b0".to_owned(), "040904e4".to_owned(), "000004b0".to_owned()]);
    langs.iter().find_map(|l| {
        let (ptr, len) = query(&format!(r"\StringFileInfo\{l}\ProductName"))?;
        // SAFETY: a string value: `len` UTF-16 units, inside `block`.
        let s = from_wide(unsafe { std::slice::from_raw_parts(ptr.cast::<u16>(), len as usize) });
        let s = s.trim();
        (!s.is_empty()).then(|| s.to_owned())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notepad_has_a_product_name() {
        let p = product_name(std::path::Path::new(r"C:\Windows\System32\notepad.exe"));
        assert!(p.is_some_and(|p| p.contains("Windows")));
        assert_eq!(product_name(std::path::Path::new(r"C:\no\such\file.exe")), None);
    }
}
