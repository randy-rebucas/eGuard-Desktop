// A stand-in "game" for eGuard's enforcement checks: an unsigned program with one window (a message box) that
// stays open until closed or ended.
#![windows_subsystem = "windows"]

#[link(name = "user32")]
unsafe extern "system" {
    fn MessageBoxW(hwnd: *mut u8, text: *const u16, caption: *const u16, flags: u32) -> i32;
}

fn main() {
    let name = std::env::current_exe().ok().and_then(|p| p.file_stem().map(|s| s.to_string_lossy().into_owned())).unwrap_or_default();
    let text: Vec<u16> = format!("Stand-in game for eGuard's tests ({name})").encode_utf16().chain([0]).collect();
    let caption: Vec<u16> = name.encode_utf16().chain([0]).collect();
    // SAFETY: both strings are zero-terminated and outlive the call.
    unsafe { MessageBoxW(std::ptr::null_mut(), text.as_ptr(), caption.as_ptr(), 0) };
}
