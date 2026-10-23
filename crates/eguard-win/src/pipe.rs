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
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::{FromRawHandle, RawHandle};
use std::ptr::null_mut;
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::{CloseHandle, ERROR_PIPE_CONNECTED, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Storage::FileSystem::{FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_ACCESS_DUPLEX, SECURITY_ANONYMOUS};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, GetNamedPipeClientProcessId, GetNamedPipeServerProcessId, PIPE_READMODE_BYTE,
    PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_UNLIMITED_INSTANCES, PIPE_WAIT, PeekNamedPipe,
};

/// Instances at once. Idle connections are dropped after `READ_TIMEOUT`, so a client can't hold them all; the limit
/// is the most Windows allows, so filling them takes more than a handful of connections.
const MAX_INSTANCES: u32 = PIPE_UNLIMITED_INSTANCES;

/// What a client is granted: read and write (`FILE_GENERIC_READ | FILE_GENERIC_WRITE`) without
/// `FILE_CREATE_PIPE_INSTANCE` (the same bit as `FILE_APPEND_DATA`, part of `GW`), so it can't serve instances of
/// eGuard's pipe itself.
const CLIENT_RIGHTS: &str = "0x12019b";

/// How long a client has to send its whole request line after connecting.
pub const READ_TIMEOUT: Duration = Duration::from_secs(5);
const BUFFER_BYTES: u32 = 16 * 1024;

/// A real install: SYSTEM, and administrators (pairing happens from the elevated installer).
pub const SERVICE_PIPE_SDDL: &str = "D:P(A;;GA;;;SY)(A;;0x12019b;;;BA)";

/// Console mode on a developer's PC: SYSTEM and the user running it (who is also the server, so needs to create
/// instances).
pub fn console_pipe_sddl(user_sid: &str) -> String {
    format!("D:P(A;;GA;;;SY)(A;;GA;;;{user_sid})")
}

#[derive(Debug)]
pub struct PipeServer {
    name: Vec<u16>,
    security: SecurityDescriptor,
    first: bool,
    /// An instance already listening, so there is never a moment with none: in such a moment anyone allowed to
    /// create pipes could take the name.
    spare: Option<Pending>,
}

impl PipeServer {
    pub fn new(name: &str, sddl: &str) -> std::io::Result<Self> {
        Ok(Self { name: wide(name), security: SecurityDescriptor::from_sddl(sddl)?, first: true, spare: None })
    }

    /// Who may connect to instances created from now on (a session's sign-in changed).
    pub fn set_sddl(&mut self, sddl: &str) -> std::io::Result<()> {
        self.security = SecurityDescriptor::from_sddl(sddl)?;
        Ok(())
    }

    /// Waits for the next client and returns the connection. Reading and writing it is plain `Read`/`Write`.
    ///
    /// Another instance is created before this one is waited on, so one is always listening, also while a client
    /// is being served and after an error.
    pub fn accept(&mut self) -> std::io::Result<File> {
        let this = match self.spare.take() {
            Some(p) => p,
            None => self.create()?,
        };
        // Without a spare the next call makes one; the name stays ours while `this` exists
        self.spare = self.create().ok();
        this.connect()
    }

    /// Serves `first` (made with `create`) as the next instance `accept` waits on.
    pub fn keep(&mut self, first: Pending) {
        self.spare = Some(first);
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

/// Connects to the service's pipe as a client. Anonymous: whoever serves the pipe can't act as this client.
pub fn connect(name: &str) -> std::io::Result<File> {
    std::fs::OpenOptions::new().read(true).write(true).security_qos_flags(SECURITY_ANONYMOUS).open(name)
}

/// Waits until a whole line (up to `\n`) is waiting on `conn`, for at most `timeout`. `false`: the client sent
/// nothing whole in time (or went away), and the connection should be dropped rather than read, which would wait
/// for it forever. Lines are at most `ipc`'s 8 KB; a longer one is reported as ready, for the reader to refuse.
pub fn wait_for_line(conn: &File, timeout: Duration) -> bool {
    use std::os::windows::io::AsRawHandle;
    let deadline = Instant::now() + timeout;
    let mut buf = vec![0u8; BUFFER_BYTES as usize];
    loop {
        let mut read = 0u32;
        // SAFETY: `conn` is an open pipe handle; `buf` is writable for its length; the other out-parameters are
        // optional. Peeking leaves the data in the pipe.
        let ok = unsafe {
            PeekNamedPipe(conn.as_raw_handle() as HANDLE, buf.as_mut_ptr().cast(), buf.len() as u32, &raw mut read, null_mut(), null_mut())
        } != 0;
        if !ok {
            return false;
        }
        if buf[..read as usize].contains(&b'\n') || read == BUFFER_BYTES {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// A session's pipe: SYSTEM, and the logon SID of the one sign-in it serves (spec section 3).
pub fn session_pipe_sddl(logon_sid: &str) -> String {
    format!("D:P(A;;GA;;;SY)(A;;{CLIENT_RIGHTS};;;{logon_sid})")
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
        assert!(wait_for_line(&conn, Duration::from_secs(5)));
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

    #[test]
    fn a_client_that_sends_no_whole_line_is_given_up_on() {
        let name = format!(r"\\.\pipe\eguard-test-idle-{}", std::process::id());
        let sddl = console_pipe_sddl(&crate::security::current_user_sid().unwrap());
        let mut server = PipeServer::new(&name, &sddl).unwrap();
        let pending = server.create().unwrap();
        let n = name.clone();
        let client = std::thread::spawn(move || {
            let mut c = connect(&n).unwrap();
            c.write_all(b"half a line").unwrap();
            std::thread::sleep(Duration::from_millis(800));
            drop(c);
        });
        let conn = pending.connect().unwrap();
        let t = Instant::now();
        assert!(!wait_for_line(&conn, Duration::from_millis(300)));
        assert!(t.elapsed() >= Duration::from_millis(300));
        client.join().unwrap();
    }
}
