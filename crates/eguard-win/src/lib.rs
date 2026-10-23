//! The Windows side of eGuard: everything `eguard-core` needs from the platform (spec section 3).
//!
//! `unsafe` is allowed only in the modules that call Win32, each call wrapped in a small safe function with a
//! `SAFETY` comment. Everything above them is safe Rust.

pub mod clock;
pub mod dpapi;
pub mod files;
pub mod http;
pub mod pipe;
pub mod registry;
pub mod security;
pub mod sysinfo;
mod wide;

/// The last Win32 error as an `io::Error` (it carries the code and the system's message).
pub(crate) fn last_error() -> std::io::Error {
    std::io::Error::last_os_error()
}
