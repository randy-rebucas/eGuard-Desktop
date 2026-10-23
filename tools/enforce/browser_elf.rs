// The stand-in browser's "engine" (browser.rs): a DLL named like Chromium's early-start DLL.

/// Called by the stand-in browser at start.
#[unsafe(no_mangle)]
pub extern "C" fn pixel_engine() -> u32 {
    1
}
