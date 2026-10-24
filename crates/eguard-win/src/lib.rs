//! The Windows side of eGuard: everything `eguard-core` needs from the platform (spec section 3).
//!
//! `unsafe` is allowed only in the modules that call Win32, each call wrapped in a small safe function with a
//! `SAFETY` comment. Everything above them is safe Rust.

pub mod accounts;
pub mod apps;
pub mod authenticode;
pub mod browsers;
pub mod clock;
pub mod codebox;
pub mod crash;
pub mod dpapi;
pub mod etw;
pub mod files;
pub mod http;
pub mod input;
pub mod launch;
pub mod pipe;
pub mod process;
pub mod registry;
pub mod security;
pub mod session;
pub mod shell;
pub mod sysinfo;
pub mod ui;
pub mod version;
pub mod watch;
mod wide;

/// The last Win32 error as an `io::Error` (it carries the code and the system's message).
pub(crate) fn last_error() -> std::io::Error {
    std::io::Error::last_os_error()
}
