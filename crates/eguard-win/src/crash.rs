//! The crash handler (Phase 7): a panic or a fault (an access violation in a Win32 call, a stack overflow) writes one
//! last line to the log, then the process ends at once with a failure code.
//!
//! - Ended, not left half running: in a build that unwinds, a panic would end only its thread, and a dead monitor
//!   thread is a service that looks fine but ends nothing. The SCM restarts a service that fails (`svc`), and the
//!   service starts a new agent; both come back with the last saved state.
//! - No crash dump and no "has stopped working" box: a dump of the service holds the device token and the removal
//!   secret (prompt: they never appear in crash dumps), and a box would wait for a click no one makes. The process is
//!   ended with `TerminateProcess`, so Windows Error Reporting never sees it; and the exe is excluded from it too
//!   (`WerAddExcludedApplication`), in case the handler itself faults.
//! - A fault's line is written without allocating or taking a lock (the heap or a lock may be what broke, and a stack
//!   overflow leaves little room): fixed static buffers, `WriteFile` to a log handle opened beforehand
//!   (`log_faults_to`) and to stderr. A panic's report (with its stack) still goes through `logging::last_words`.
#![allow(unsafe_code)]

use eguard_core::logging;
use std::backtrace::Backtrace;
use std::cell::UnsafeCell;
use std::sync::atomic::{AtomicBool, AtomicPtr, Ordering};
use windows_sys::Win32::Foundation::{HANDLE, HMODULE, INVALID_HANDLE_VALUE, SYSTEMTIME};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_APPEND_DATA, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_ALWAYS, WriteFile,
};
use windows_sys::Win32::System::Console::{GetStdHandle, STD_ERROR_HANDLE};
use windows_sys::Win32::System::Diagnostics::Debug::{
    EXCEPTION_POINTERS, SEM_FAILCRITICALERRORS, SEM_NOGPFAULTERRORBOX, SetErrorMode, SetUnhandledExceptionFilter,
};
use windows_sys::Win32::System::ErrorReporting::WerAddExcludedApplication;
use windows_sys::Win32::System::LibraryLoader::{
    GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, GetModuleFileNameW, GetModuleHandleExW,
};
use windows_sys::Win32::System::SystemInformation::GetSystemTime;
use windows_sys::Win32::System::Threading::{GetCurrentProcess, TerminateProcess};

/// The exit code after a panic (Rust's own for a panic, so it reads the same in the SCM's log).
pub const PANIC_EXIT_CODE: u32 = 101;

/// Installs the handler for this process. Call first in `main`; `log_faults_to` once the log is set up (until then a
/// fault's line goes to stderr only).
pub fn install() {
    // SAFETY: sets this process's error mode; no pointers.
    unsafe { SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX) };
    std::panic::set_hook(Box::new(|info| {
        logging::last_words(&logging::panic_report(info, &Backtrace::force_capture()));
        end(PANIC_EXIT_CODE);
    }));
    // SAFETY: `on_fault` is a function with the signature Windows expects, alive as long as the process.
    unsafe { SetUnhandledExceptionFilter(Some(on_fault)) };
    // Never a report or a dump of this exe (this user's setting; the service's is SYSTEM's)
    // It takes the exe's name (`eguard-service.exe`), as Windows Error Reporting keeps its list; a full path never
    // matches
    if let Some(name) = std::env::current_exe().ok().and_then(|p| p.file_name().map(|f| f.to_string_lossy().into_owned())) {
        let w = crate::wide::wide(&name);
        // SAFETY: `w` is zero-terminated and lives for the call.
        unsafe { WerAddExcludedApplication(w.as_ptr(), 0) };
    }
}

/// Where a fault's line goes: `path` (the component's log, opened now for appending and kept open), as `component`.
/// Call after `logging::init`. Opened again each time the log is cut (`logging::on_rotate`), so the line goes to the
/// current file, never one renamed and later deleted.
pub fn log_faults_to(component: &'static &'static str, path: &std::path::Path) {
    let _ = FAULT_LOG_PATH.set((component, path.to_owned()));
    logging::on_rotate(reopen_fault_log);
    open_fault_log(component, path);
}

/// The log, as `log_faults_to` was given it.
static FAULT_LOG_PATH: std::sync::OnceLock<(&'static &'static str, std::path::PathBuf)> = std::sync::OnceLock::new();

fn reopen_fault_log() {
    if let Some((component, path)) = FAULT_LOG_PATH.get() {
        open_fault_log(component, path);
    }
}

fn open_fault_log(component: &'static &'static str, path: &std::path::Path) {
    let w = crate::wide::wide(&path.to_string_lossy());
    // SAFETY: `w` is zero-terminated; the handle is kept for the life of the process (or until replaced).
    let h = unsafe {
        CreateFileW(
            w.as_ptr(),
            FILE_APPEND_DATA,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null(),
            OPEN_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            std::ptr::null_mut(),
        )
    };
    if h != INVALID_HANDLE_VALUE && !h.is_null() {
        COMPONENT.store(std::ptr::from_ref(component).cast_mut().cast(), Ordering::Release);
        // The handle it replaces is left open: a thread faulting right now may have read it already, and a closed
        // handle's number can be reused by anything (a log rotates a few times a day; the cost is one handle each)
        FAULT_LOG.swap(h, Ordering::AcqRel);
    }
}

/// The handle `log_faults_to` opened.
static FAULT_LOG: AtomicPtr<core::ffi::c_void> = AtomicPtr::new(std::ptr::null_mut());
/// The component's name: a `&'static &'static str`, as a pointer.
static COMPONENT: AtomicPtr<()> = AtomicPtr::new(std::ptr::null_mut());
/// Only the first faulting thread writes; another that faults meanwhile just ends the process.
static FAULTING: AtomicBool = AtomicBool::new(false);

/// A fixed buffer a line is written into without allocating.
struct Line {
    buf: [u8; 512],
    len: usize,
}

impl Line {
    fn raw(&mut self, bytes: &[u8]) {
        for &b in bytes {
            if self.len < self.buf.len() {
                self.buf[self.len] = b;
                self.len += 1;
            }
        }
    }

    /// Text from outside (a module's name): JSON-safe, so no quotes, backslashes, control or non-ASCII characters.
    fn text(&mut self, bytes: impl Iterator<Item = u32>) {
        for c in bytes {
            let b = u8::try_from(c).ok().filter(|b| (0x20..0x7F).contains(b) && *b != b'"' && *b != b'\\');
            self.raw(&[b.unwrap_or(b'_')]);
        }
    }

    fn number(&mut self, mut n: u64, radix: u64, width: usize) {
        let mut digits = [b'0'; 20];
        let mut i = digits.len();
        while n > 0 || digits.len() - i < width.max(1) {
            i -= 1;
            digits[i] = b"0123456789ABCDEF"[(n % radix) as usize];
            n /= radix;
        }
        self.raw(&digits[i..]);
    }
}

/// The fault handler's buffers: static, so a thread out of stack still has room.
struct Scratch {
    line: UnsafeCell<Line>,
    module: UnsafeCell<[u16; 260]>,
}

// SAFETY: used only by the one thread that won `FAULTING`.
unsafe impl Sync for Scratch {}

static SCRATCH: Scratch = Scratch { line: UnsafeCell::new(Line { buf: [0; 512], len: 0 }), module: UnsafeCell::new([0; 260]) };

/// Called by Windows for a fault no one handled, on the thread that faulted.
unsafe extern "system" fn on_fault(info: *const EXCEPTION_POINTERS) -> i32 {
    // SAFETY: Windows passes a valid `EXCEPTION_POINTERS` whose record lives through this call; null is checked.
    let record = unsafe { info.as_ref().and_then(|p| p.ExceptionRecord.as_ref()) };
    let (code, address) = record.map_or((0, 0), |r| (r.ExceptionCode as u32, r.ExceptionAddress as usize));
    if !FAULTING.swap(true, Ordering::AcqRel) {
        // SAFETY: only the thread that set `FAULTING` gets here, once: nothing else touches the buffers.
        let (line, module) = unsafe { (&mut *SCRATCH.line.get(), &mut *SCRATCH.module.get()) };
        fault_line(line, module, code, address);
        write_all(FAULT_LOG.load(Ordering::Acquire), &line.buf[..line.len]);
        // SAFETY: plain call; the handle may be null or invalid (no console), which `write_all` tolerates.
        let err = unsafe { GetStdHandle(STD_ERROR_HANDLE) };
        write_all(err, &line.buf[..line.len]);
    }
    end(code)
}

/// The fault's JSON line, as `logging` writes them, into `line`. No allocation, no lock.
fn fault_line(line: &mut Line, module_buf: &mut [u16; 260], code: u32, address: usize) {
    let mut t = SYSTEMTIME::default();
    // SAFETY: `t` is a live out-parameter.
    unsafe { GetSystemTime(&raw mut t) };
    line.len = 0;
    line.raw(b"{\"ts\":\"");
    for (n, width, after) in
        [(t.wYear, 4, b"-"), (t.wMonth, 2, b"-"), (t.wDay, 2, b"T"), (t.wHour, 2, b":"), (t.wMinute, 2, b":"), (t.wSecond, 2, b"Z")]
    {
        line.number(u64::from(n), 10, width);
        line.raw(after);
    }
    line.raw(b"\",\"level\":\"error\",\"component\":\"");
    let component = COMPONENT.load(Ordering::Acquire).cast::<&'static str>();
    // SAFETY: set only by `log_faults_to`, from a `&'static &'static str`.
    let component: &str = if component.is_null() { "eguard" } else { unsafe { *component } };
    line.text(component.bytes().map(u32::from));
    line.raw(b"\",\"pid\":");
    line.number(u64::from(crate::process::current_pid()), 10, 1);
    line.raw(b",\"msg\":\"crashed: exception 0x");
    line.number(u64::from(code), 16, 8);
    line.raw(b" at ");
    if let Some((name, base)) = module_of(address, module_buf) {
        line.text(name.iter().map(|&u| u32::from(u)));
        line.raw(b"+0x");
        line.number((address - base) as u64, 16, 1);
    } else {
        line.raw(b"0x");
        line.number(address as u64, 16, 1);
    }
    line.raw(b"\"}\n");
}

fn write_all(h: HANDLE, bytes: &[u8]) {
    if h.is_null() || h == INVALID_HANDLE_VALUE {
        return;
    }
    let mut written = 0u32;
    // SAFETY: `bytes` is readable for its length; `written` is a live out-parameter; no overlapped I/O.
    unsafe { WriteFile(h, bytes.as_ptr(), bytes.len() as u32, &raw mut written, std::ptr::null_mut()) };
}

/// The module holding `address`: its file name (in `buf`) and base address.
fn module_of(address: usize, buf: &mut [u16; 260]) -> Option<(&[u16], usize)> {
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
        return None;
    }
    // SAFETY: `buf` is writable for its length; the length passed is that length.
    let n = unsafe { GetModuleFileNameW(module, buf.as_mut_ptr(), buf.len() as u32) } as usize;
    let path = &buf[..n.min(buf.len())];
    let name = path.iter().rposition(|&c| c == u16::from(b'\\')).map_or(path, |i| &path[i + 1..]);
    Some((name, module as usize))
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

    fn line_for(address: usize) -> serde_json::Value {
        let mut line = Line { buf: [0; 512], len: 0 };
        let mut module = [0u16; 260];
        fault_line(&mut line, &mut module, 0xC000_0005, address);
        let text = std::str::from_utf8(&line.buf[..line.len]).unwrap();
        assert!(text.ends_with('\n'));
        serde_json::from_str(text.trim_end()).unwrap()
    }

    #[test]
    fn a_faults_line_is_one_json_object_naming_the_module() {
        let v = line_for(line_for as *const () as usize);
        assert_eq!(v["level"], "error");
        assert_eq!(v["ts"].as_str().unwrap().len(), 20);
        let msg = v["msg"].as_str().unwrap();
        assert!(msg.starts_with("crashed: exception 0xC0000005 at eguard_win-") && msg.contains(".exe+0x"), "{msg}");
        assert_eq!(line_for(0x10)["msg"], "crashed: exception 0xC0000005 at 0x10");
    }
}
