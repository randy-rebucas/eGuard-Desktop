//! The service's named pipe (spec section 3). Its DACL decides who may talk to the service; the service still
//! treats every message as untrusted (`eguard_core::ipc`).
//!
//! - Only local clients (`PIPE_REJECT_REMOTE_CLIENTS`).
//! - The first instance is created with `FILE_FLAG_FIRST_PIPE_INSTANCE`: if another process already owns the name,
//!   the service fails loudly instead of sharing it.
#![allow(unsafe_code)]

use crate::security::SecurityDescriptor;
use crate::wide::wide;
use std::fs::File;
use std::os::windows::io::{FromRawHandle, RawHandle};
use std::ptr::null_mut;
use windows_sys::Win32::Foundation::{CloseHandle, ERROR_PIPE_CONNECTED, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Storage::FileSystem::{FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_ACCESS_DUPLEX};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, GetNamedPipeClientProcessId, GetNamedPipeServerProcessId, PIPE_READMODE_BYTE,
    PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_WAIT,
};

/// Instances at once: one per signed-in session is plenty.
const MAX_INSTANCES: u32 = 8;
const BUFFER_BYTES: u32 = 16 * 1024;

/// A real install: SYSTEM, and administrators (pairing happens from the elevated installer).
pub const SERVICE_PIPE_SDDL: &str = "D:P(A;;GA;;;SY)(A;;GRGW;;;BA)";

/// Console mode on a developer's PC: SYSTEM and the user running it.
pub fn console_pipe_sddl(user_sid: &str) -> String {
    format!("D:P(A;;GA;;;SY)(A;;GA;;;{user_sid})")
}

#[derive(Debug)]
pub struct PipeServer {
    name: Vec<u16>,
    security: SecurityDescriptor,
    first: bool,
}

impl PipeServer {
    pub fn new(name: &str, sddl: &str) -> std::io::Result<Self> {
        Ok(Self { name: wide(name), security: SecurityDescriptor::from_sddl(sddl)?, first: true })
    }

    /// Who may connect to instances created from now on (a session's sign-in changed).
    pub fn set_sddl(&mut self, sddl: &str) -> std::io::Result<()> {
        self.security = SecurityDescriptor::from_sddl(sddl)?;
        Ok(())
    }

    /// Waits for the next client and returns the connection. Reading and writing it is plain `Read`/`Write`.
    pub fn accept(&mut self) -> std::io::Result<File> {
        self.create()?.connect()
    }

    /// Creates the next instance without waiting for a client. The first call claims the name, or fails if
    /// another process holds it.
    pub fn create(&mut self) -> std::io::Result<Pending> {
        let sa = self.security.attributes();
        let open_mode = PIPE_ACCESS_DUPLEX | if self.first { FILE_FLAG_FIRST_PIPE_INSTANCE } else { 0 };
        // SAFETY: `name` is zero-terminated; `sa` points at `self.security`, alive for the call.
        let h = unsafe {
            CreateNamedPipeW(
                self.name.as_ptr(),
                open_mode,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                MAX_INSTANCES,
                BUFFER_BYTES,
                BUFFER_BYTES,
                0,
                &raw const sa,
            )
        };
        if h == INVALID_HANDLE_VALUE {
            return Err(crate::last_error());
        }
        self.first = false;
        Ok(Pending(h))
    }
}

/// A pipe instance waiting for its client. Closed on drop unless connected.
#[derive(Debug)]
pub struct Pending(HANDLE);

// A kernel handle, used by one thread at a time
unsafe impl Send for Pending {}

impl Pending {
    /// Waits for a client and returns the connection.
    pub fn connect(self) -> std::io::Result<File> {
        let h = std::mem::ManuallyDrop::new(self).0;
        // SAFETY: a pipe handle we own; synchronous, so null OVERLAPPED. A client that connected between creating
        // and this call is reported as ERROR_PIPE_CONNECTED, which is a success.
        let connected = unsafe { ConnectNamedPipe(h, null_mut()) } != 0;
        if !connected {
            let e = crate::last_error();
            if e.raw_os_error() != Some(ERROR_PIPE_CONNECTED as i32) {
                // SAFETY: owned here (not dropped: ManuallyDrop), closed once.
                unsafe { CloseHandle(h) };
                return Err(e);
            }
        }
        // SAFETY: `h` is a valid handle we own; the File takes ownership and closes it on drop.
        Ok(unsafe { File::from_raw_handle(h as RawHandle) })
    }
}

impl Drop for Pending {
    fn drop(&mut self) {
        // SAFETY: a handle we own that was never handed to a File; closed once.
        unsafe { CloseHandle(self.0) };
    }
}

/// Connects to the service's pipe as a client.
pub fn connect(name: &str) -> std::io::Result<File> {
    std::fs::OpenOptions::new().read(true).write(true).open(name)
}

/// A session's pipe: SYSTEM, and the logon SID of the one sign-in it serves (spec section 3).
pub fn session_pipe_sddl(logon_sid: &str) -> String {
    format!("D:P(A;;GA;;;SY)(A;;GRGW;;;{logon_sid})")
}

/// The process at the other end of a connection the server accepted.
pub fn client_pid(conn: &File) -> Option<u32> {
    use std::os::windows::io::AsRawHandle;
    let mut pid = 0u32;
    // SAFETY: `conn` is an open pipe handle; `pid` is a live out-parameter.
    (unsafe { GetNamedPipeClientProcessId(conn.as_raw_handle() as HANDLE, &raw mut pid) } != 0).then_some(pid)
}

/// The process serving a pipe the client connected to (so an agent can check it's talking to eGuard's service).
pub fn server_pid(conn: &File) -> Option<u32> {
    use std::os::windows::io::AsRawHandle;
    let mut pid = 0u32;
    // SAFETY: `conn` is an open pipe handle; `pid` is a live out-parameter.
    (unsafe { GetNamedPipeServerProcessId(conn.as_raw_handle() as HANDLE, &raw mut pid) } != 0).then_some(pid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    #[test]
    fn a_client_talks_to_the_server_and_a_second_server_is_refused() {
        let name = format!(r"\\.\pipe\eguard-test-{}", std::process::id());
        let sddl = console_pipe_sddl(&crate::security::current_user_sid().unwrap());
        let mut server = PipeServer::new(&name, &sddl).unwrap();
        let n = name.clone();
        let client = std::thread::spawn(move || {
            let mut c = loop {
                if let Ok(c) = connect(&n) {
                    break c;
                }
                std::thread::sleep(std::time::Duration::from_millis(20));
            };
            assert_eq!(server_pid(&c), Some(crate::process::current_pid()));
            c.write_all(b"ping\n").unwrap();
            let mut s = String::new();
            c.read_to_string(&mut s).unwrap();
            s
        });
        let mut conn = server.accept().unwrap();
        assert_eq!(client_pid(&conn), Some(crate::process::current_pid()));
        let mut buf = [0u8; 5];
        conn.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"ping\n");
        conn.write_all(b"pong").unwrap();
        conn.sync_all().unwrap();
        drop(conn);
        assert_eq!(client.join().unwrap(), "pong");

        // Someone else trying to create the same pipe name first-instance fails while ours exists
        let mut squatter = PipeServer::new(&name, &sddl).unwrap();
        let _ours = std::thread::spawn(move || server.accept());
        std::thread::sleep(std::time::Duration::from_millis(100));
        assert!(squatter.accept().is_err());
    }
}
