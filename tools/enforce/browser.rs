// A stand-in browser for eGuard's web checks: an unsigned program that imports a browser engine the way Chromium's
// do (a `*_elf.dll`, here `pixel_elf.dll`, built from browser_elf.rs), so eGuard takes it for a browser its extension
// can't run in. It shows one message box and stays open until closed or ended.
#![windows_subsystem = "windows"]

// raw-dylib: no import library needed, the import is written straight into the exe
#[link(name = "pixel_elf", kind = "raw-dylib")]
unsafe extern "C" {
    fn pixel_engine() -> u32;
}

#[link(name = "user32")]
unsafe extern "system" {
    fn MessageBoxW(hwnd: *mut u8, text: *const u16, caption: *const u16, flags: u32) -> i32;
}

fn main() {
    // SAFETY: a function of pixel_elf.dll that takes nothing and returns a number.
    let engine = unsafe { pixel_engine() };
    let text: Vec<u16> = format!("Stand-in browser for eGuard's tests (engine {engine})").encode_utf16().chain([0]).collect();
    let caption: Vec<u16> = "Pixel Browser".encode_utf16().chain([0]).collect();
    // SAFETY: both strings are zero-terminated and outlive the call.
    unsafe { MessageBoxW(std::ptr::null_mut(), text.as_ptr(), caption.as_ptr(), 0) };
}
