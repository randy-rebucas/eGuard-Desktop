//! The crash handler (Phase 7): a panic or a fault (an access violation in a Win32 call, a stack overflow) writes one
//! last line to the log (`eguard_core::logging::last_words`), then the process ends at once with a failure code.
//!
//! - Ended, not left half running: in a build that unwinds, a panic would end only its thread, and a dead monitor
//!   thread is a service that looks fine but ends nothing. The SCM restarts a service that fails (`svc`), and the
//!   service starts a new agent; both come back with the last saved state.
//! - No crash dump and no "has stopped working" box: a dump of the service holds the device token and the removal
//!   secret (prompt: they never appear in crash dumps), and a box would wait for a click no one makes. The process is
//!   ended with `TerminateProcess`, so Windows Error Reporting never sees it.
#![allow(unsafe_code)]

use eguard_core::logging;
use std::backtrace::Backtrace;
use windows_sys::Win32::Foundation::HMODULE;
use windows_sys::Win32::System::Diagnostics::Debug::{
    EXCEPTION_POINTERS, SEM_FAILCRITICALERRORS, SEM_NOGPFAULTERRORBOX, SetErrorMode, SetUnhandledExceptionFilter,
};
use windows_sys::Win32::System::LibraryLoader::{
    GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, GetModuleFileNameW, GetModuleHandleExW,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, TerminateProcess};

/// The exit code after a panic (Rust's own for a panic, so it reads the same in the SCM's log).
pub const PANIC_EXIT_CODE: u32 = 101;

/// Installs the handler for this process. Call first in `main`; the log can be set up later (until then the last
/// line goes to stderr only).
pub fn install() {
    // SAFETY: sets this process's error mode; no pointers.
    unsafe { SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX) };
    std::panic::set_hook(Box::new(|info| {
        logging::last_words(&logging::panic_report(info, &Backtrace::force_capture()));
        end(PANIC_EXIT_CODE);
    }));
    // SAFETY: `on_fault` is a function with the signature Windows expects, alive as long as the process.
    unsafe { SetUnhandledExceptionFilter(Some(on_fault)) };
}

/// Called by Windows for a fault no one handled, on the thread that faulted.
unsafe extern "system" fn on_fault(info: *const EXCEPTION_POINTERS) -> i32 {
    // SAFETY: Windows passes a valid `EXCEPTION_POINTERS` whose record lives through this call; null is checked.
    let record = unsafe { info.as_ref().and_then(|p| p.ExceptionRecord.as_ref()) };
    let (code, address) = record.map_or((0, 0), |r| (r.ExceptionCode as u32, r.ExceptionAddress as usize));
    logging::last_words(&format!("crashed: exception 0x{code:08X} at {}", where_in(address)));
    end(code)
}

/// `module.exe+0x1a2b`: an address means nothing on its own, since every start loads the module somewhere else.
fn where_in(address: usize) -> String {
    let mut module: HMODULE = std::ptr::null_mut();
    // SAFETY: with FROM_ADDRESS the second argument is an address, not a string; `module` is a valid out pointer.
    // UNCHANGED_REFCOUNT: nothing to release after.
    let found = unsafe {
        GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            address as *const u16,
            &raw mut module,
        )
    } != 0;
    if !found {
        return format!("0x{address:X}");
    }
    let mut buf = [0u16; 260];
    // SAFETY: `buf` is writable for its length; the length passed is that length.
    let n = unsafe { GetModuleFileNameW(module, buf.as_mut_ptr(), buf.len() as u32) } as usize;
    let path = String::from_utf16_lossy(&buf[..n.min(buf.len())]);
    let name = path.rsplit('\\').next().unwrap_or(&path);
    format!("{name}+0x{:X}", address - module as usize)
}

/// Ends this process now with `code`.
fn end(code: u32) -> ! {
    // SAFETY: `GetCurrentProcess` is a pseudo-handle that needs no closing; ending ourselves doesn't return.
    unsafe { TerminateProcess(GetCurrentProcess(), code) };
    std::process::abort()
}

/// Faults on purpose (an access violation), for checking the handler by hand (`eguard-agent crash fault`, dev
/// builds only).
pub fn fault_for_testing() {
    let p = std::hint::black_box(std::ptr::null_mut::<u32>());
    // SAFETY: not safe, on purpose: writing through null raises the access violation the handler is checked with.
    unsafe { p.write_volatile(1) };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_address_is_named_by_its_module() {
        let here = where_in(where_in as *const () as usize);
        assert!(here.starts_with("eguard_win-") && here.contains(".exe+0x"), "{here}");
        assert_eq!(where_in(0x10), "0x10");
    }
}
