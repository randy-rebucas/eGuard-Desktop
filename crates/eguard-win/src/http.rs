//! `eguard_core::api::Transport` over `WinHTTP`: the system's TLS and certificate store, and the system proxy.
//!
//! Chosen over rustls because rustls needs `ring` or `aws-lc-rs`, which compile C at build time (docs/STATUS.md).
//! Redirects are never followed: the device token must only ever go to the server it was meant for. `download` (an
//! update's files, which carry no token) follows them, but never from https to http.
#![allow(unsafe_code)]

use crate::wide::{from_wide, wide};
use eguard_core::api::{HttpRequest, HttpResponse, MAX_RESPONSE_BYTES, Method, Transport, TransportError, parse_retry_after};
use std::ffi::c_void;
use std::io::Write as _;
use std::path::Path;
use std::ptr::{null, null_mut};
use std::time::Duration;
use windows_sys::Win32::Networking::WinHttp::{
    URL_COMPONENTS, WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, WINHTTP_FLAG_SECURE, WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2,
    WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3, WINHTTP_INTERNET_SCHEME_HTTPS, WINHTTP_OPTION_REDIRECT_POLICY,
    WINHTTP_OPTION_REDIRECT_POLICY_DISALLOW_HTTPS_TO_HTTP, WINHTTP_OPTION_REDIRECT_POLICY_NEVER, WINHTTP_OPTION_SECURE_PROTOCOLS,
    WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_QUERY_RETRY_AFTER, WINHTTP_QUERY_STATUS_CODE, WinHttpCloseHandle, WinHttpConnect, WinHttpCrackUrl,
    WinHttpOpen, WinHttpOpenRequest, WinHttpQueryHeaders, WinHttpReadData, WinHttpReceiveResponse, WinHttpSendRequest, WinHttpSetOption,
    WinHttpSetTimeouts,
};

/// A `WinHTTP` handle, closed on drop.
struct Handle(*mut c_void);

impl Handle {
    fn new(h: *mut c_void) -> Result<Self, TransportError> {
        if h.is_null() { Err(error("opening")) } else { Ok(Self(h)) }
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        // SAFETY: a handle WinHTTP gave us, closed once.
        unsafe { WinHttpCloseHandle(self.0) };
    }
}

/// `WinHTTP`'s error codes, in words for the log.
fn error(step: &str) -> TransportError {
    let code = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
    let what = match code {
        12002 => "timed out",
        12007 => "the server's name couldn't be found",
        12029 => "couldn't connect",
        12030 => "the connection was dropped",
        12175 | 12045 | 12038 | 12037 => "the server's certificate isn't trusted",
        _ => "failed",
    };
    TransportError(format!("{step} {what} (WinHTTP {code})"))
}

fn set_u32(h: &Handle, option: u32, value: u32) -> bool {
    // SAFETY: `value` is 4 readable bytes for the call; WinHTTP copies it.
    unsafe { WinHttpSetOption(h.0, option, (&raw const value).cast(), 4) != 0 }
}

/// One `WinHTTP` session for the service's lifetime.
pub struct WinHttp {
    session: Handle,
}

impl std::fmt::Debug for WinHttp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("WinHttp")
    }
}

// WinHTTP session handles may be used from any thread
unsafe impl Send for WinHttp {}
unsafe impl Sync for WinHttp {}

impl WinHttp {
    pub fn new(user_agent: &str) -> Result<Self, TransportError> {
        let ua = wide(user_agent);
        // SAFETY: `ua` is zero-terminated; null proxy name and bypass mean "the system's". Synchronous mode (no flags).
        let session = Handle::new(unsafe { WinHttpOpen(ua.as_ptr(), WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, null(), null(), 0) })?;
        // TLS 1.2 or later only. TLS 1.3 isn't on every Windows 10; then 1.2 alone
        if !set_u32(&session, WINHTTP_OPTION_SECURE_PROTOCOLS, WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2 | WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3)
            && !set_u32(&session, WINHTTP_OPTION_SECURE_PROTOCOLS, WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2)
        {
            return Err(error("setting TLS versions"));
        }
        Ok(Self { session })
    }
}

/// Host, port, path (with query) and whether it's https, from `WinHTTP`'s own URL parser.
fn crack(url: &[u16]) -> Result<(Vec<u16>, u16, Vec<u16>, bool), TransportError> {
    let mut c = URL_COMPONENTS {
        dwStructSize: size_of::<URL_COMPONENTS>() as u32,
        // Lengths of u32::MAX ask for pointers into `url` rather than copies
        dwHostNameLength: u32::MAX,
        dwUrlPathLength: u32::MAX,
        dwExtraInfoLength: u32::MAX,
        ..URL_COMPONENTS::default()
    };
    // SAFETY: `url` is zero-terminated (length 0 means "up to the zero"); the returned pointers point into it.
    if unsafe { WinHttpCrackUrl(url.as_ptr(), 0, 0, &raw mut c) } == 0 {
        return Err(error("reading the URL"));
    }
    // SAFETY: each pointer/length pair is a slice of `url`, which outlives this function's use of it.
    let part = |p: *mut u16, n: u32| if p.is_null() { Vec::new() } else { unsafe { std::slice::from_raw_parts(p, n as usize) }.to_vec() };
    let mut host = part(c.lpszHostName, c.dwHostNameLength);
    host.push(0);
    let mut path = part(c.lpszUrlPath, c.dwUrlPathLength);
    path.extend(part(c.lpszExtraInfo, c.dwExtraInfoLength));
    path.push(0);
    Ok((host, c.nPort, path, c.nScheme == WINHTTP_INTERNET_SCHEME_HTTPS))
}

/// An open request. The request handle is closed before its connection's (fields drop in order).
struct Open {
    request: Handle,
    _connect: Handle,
}

impl WinHttp {
    /// Opens a request to `url`. `redirects`: which `WinHTTP` follows (`WINHTTP_OPTION_REDIRECT_POLICY_*`).
    fn open(&self, verb: &str, url: &str, timeout: Duration, redirects: u32) -> Result<Open, TransportError> {
        let (host, port, path, https) = crack(&wide(url))?;
        // SAFETY: `host` is zero-terminated; the connection handle is closed on drop, before the session's.
        let connect = Handle::new(unsafe { WinHttpConnect(self.session.0, host.as_ptr(), port, 0) })?;
        let verb = wide(verb);
        let flags = if https { WINHTTP_FLAG_SECURE } else { 0 };
        // SAFETY: `verb` and `path` are zero-terminated; null version, referrer and accept types are the defaults.
        let request = Handle::new(unsafe { WinHttpOpenRequest(connect.0, verb.as_ptr(), path.as_ptr(), null(), null(), null(), flags) })?;
        let ms = i32::try_from(timeout.as_millis()).unwrap_or(i32::MAX);
        // SAFETY: a live request handle; plain integers.
        if unsafe { WinHttpSetTimeouts(request.0, ms, ms, ms, ms) } == 0 {
            return Err(error("setting timeouts"));
        }
        if !set_u32(&request, WINHTTP_OPTION_REDIRECT_POLICY, redirects) {
            return Err(error("setting the redirect policy"));
        }
        Ok(Open { request, _connect: connect })
    }

    /// Downloads `url` into a new file at `dest`, sending no token, and stops past `max` bytes. Redirects are
    /// followed (a download site may hand over to its storage), but never from https to http: the file still has to
    /// match the signed manifest, and a plain-text hop would only tell everyone on the way what's being fetched.
    /// Returns the bytes written; a partial file is deleted.
    pub fn download(&self, url: &str, dest: &Path, max: u64, timeout: Duration) -> Result<u64, TransportError> {
        let open = self.open("GET", url, timeout, WINHTTP_OPTION_REDIRECT_POLICY_DISALLOW_HTTPS_TO_HTTP)?;
        let headers = wide("Accept: application/octet-stream\r\n");
        // SAFETY: `headers` is zero-terminated (its length without the zero is passed); no body.
        if unsafe { WinHttpSendRequest(open.request.0, headers.as_ptr(), (headers.len() - 1) as u32, null(), 0, 0, 0) } == 0 {
            return Err(error("sending"));
        }
        // SAFETY: a live request handle that was sent; the reserved argument must be null.
        if unsafe { WinHttpReceiveResponse(open.request.0, null_mut()) } == 0 {
            return Err(error("waiting for the answer"));
        }
        let status = status_of(&open.request)?;
        if status != 200 {
            return Err(TransportError(format!("the download answered {status}")));
        }
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(dest)
            .map_err(|e| TransportError(format!("creating {}: {e}", dest.display())))?;
        let written = read_all(&open.request, max, |chunk| file.write_all(chunk).map_err(|e| TransportError(format!("writing: {e}"))))
            .and_then(|n| file.sync_all().map(|()| n).map_err(|e| TransportError(format!("writing: {e}"))));
        drop(file);
        if written.is_err() {
            let _ = std::fs::remove_file(dest);
        }
        written
    }
}

/// The answer's status code.
fn status_of(request: &Handle) -> Result<u32, TransportError> {
    let mut status = 0u32;
    let mut len = 4u32;
    // SAFETY: `status` is 4 writable bytes, and FLAG_NUMBER asks for exactly a u32.
    let ok = unsafe {
        WinHttpQueryHeaders(
            request.0,
            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            null(),
            (&raw mut status).cast(),
            &raw mut len,
            null_mut(),
        )
    };
    if ok == 0 { Err(error("reading the status")) } else { Ok(status) }
}

/// Reads the answer's body in chunks into `sink`, failing past `max` bytes. Returns how many bytes there were.
fn read_all(request: &Handle, max: u64, mut sink: impl FnMut(&[u8]) -> Result<(), TransportError>) -> Result<u64, TransportError> {
    let mut total = 0u64;
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let mut n = 0u32;
        // SAFETY: `buf` is writable for its length; WinHTTP writes at most that and reports how much in `n`.
        if unsafe { WinHttpReadData(request.0, buf.as_mut_ptr().cast(), buf.len() as u32, &raw mut n) } == 0 {
            return Err(error("reading the answer"));
        }
        if n == 0 {
            return Ok(total);
        }
        total += u64::from(n);
        if total > max {
            return Err(TransportError("the answer was too large".into()));
        }
        sink(&buf[..n as usize])?;
    }
}

impl Transport for WinHttp {
    fn send(&self, req: HttpRequest) -> Result<HttpResponse, TransportError> {
        let verb = match req.method {
            Method::Get => "GET",
            Method::Post => "POST",
        };
        let open = self.open(verb, &req.url, req.timeout, WINHTTP_OPTION_REDIRECT_POLICY_NEVER)?;
        let request = &open.request;

        let mut headers = String::from("Accept: application/json\r\n");
        if req.body.is_some() {
            headers.push_str("Content-Type: application/json\r\n");
        }
        if let Some(token) = &req.bearer {
            headers.push_str("Authorization: Bearer ");
            headers.push_str(token);
            headers.push_str("\r\n");
        }
        let headers = wide(&headers);
        let body = req.body.as_deref().unwrap_or(&[]);
        let body_len = u32::try_from(body.len()).map_err(|_| TransportError("body too large".into()))?;
        // SAFETY: `headers` is zero-terminated (its length without the zero is passed); `body` is readable for
        // `body_len` bytes and stays alive until the call returns (synchronous mode sends it all before returning).
        let sent = unsafe {
            WinHttpSendRequest(request.0, headers.as_ptr(), (headers.len() - 1) as u32, body.as_ptr().cast(), body_len, body_len, 0)
        };
        if sent == 0 {
            return Err(error("sending"));
        }
        // SAFETY: a live request handle that was sent; the reserved argument must be null.
        if unsafe { WinHttpReceiveResponse(request.0, null_mut()) } == 0 {
            return Err(error("waiting for the answer"));
        }

        let status = status_of(request)?;

        let mut retry = [0u16; 64];
        let mut len = size_of_val(&retry) as u32;
        // SAFETY: `retry` is writable for `len` bytes; WinHTTP fails rather than overrun it (and when it's absent).
        let has_retry = unsafe {
            WinHttpQueryHeaders(request.0, WINHTTP_QUERY_RETRY_AFTER, null(), retry.as_mut_ptr().cast(), &raw mut len, null_mut())
        } != 0;
        let retry_after_secs = if has_retry { parse_retry_after(&from_wide(&retry)) } else { None };

        let mut out = Vec::new();
        read_all(request, MAX_RESPONSE_BYTES as u64, |chunk| {
            out.extend_from_slice(chunk);
            Ok(())
        })?;
        Ok(HttpResponse { status: status as u16, body: out, retry_after_secs })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls_split_into_host_port_and_path() {
        let (host, port, path, https) = crack(&wide("https://eguard.app/api/device/v1/catalog?since=3")).unwrap();
        assert_eq!(
            (from_wide(&host), port, from_wide(&path), https),
            ("eguard.app".into(), 443, "/api/device/v1/catalog?since=3".into(), true)
        );
        let (host, port, _, https) = crack(&wide("http://localhost:3000/api/device/v1/sync")).unwrap();
        assert_eq!((from_wide(&host), port, https), ("localhost".into(), 3000, false));
    }

    #[test]
    fn an_unreachable_server_is_a_transport_error() {
        let t = WinHttp::new("eGuard-test").unwrap();
        let r = t.send(HttpRequest {
            method: Method::Post,
            // Port 9 (discard) on loopback: nothing listens, the connection is refused at once
            url: "http://127.0.0.1:9/api/device/v1/sync".into(),
            bearer: Some("t".into()),
            body: Some(b"{}".to_vec()),
            timeout: std::time::Duration::from_secs(5),
        });
        assert!(r.is_err());
    }

    #[test]
    fn a_failed_download_leaves_no_file() {
        let t = WinHttp::new("eGuard-test").unwrap();
        let dest = std::env::temp_dir().join(format!("eguard-download-{}.exe", std::process::id()));
        let _ = std::fs::remove_file(&dest);
        assert!(t.download("http://127.0.0.1:9/eguard-agent.exe", &dest, 10, Duration::from_secs(5)).is_err());
        assert!(!dest.exists());
    }
}
