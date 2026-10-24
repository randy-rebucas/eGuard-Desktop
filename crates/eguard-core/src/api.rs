//! The device API client (mobile-api Part C), over whatever HTTP the platform has (`Transport`).
//!
//! The client builds requests and reads answers; it never decides what an error means for protection. That is
//! `state` and `queue`, which always fail closed. Bodies and answers are the types in `wire`.

use crate::queue::{Outbound, SendOutcome};
use crate::wire::{ErrorBody, PairRequest, PairResponse, SyncRequest};
use serde::Serialize;
use serde_json::Value;
use std::time::Duration;

/// The longest answer read. `/sync` with a few hundred apps is well under 1 MB.
pub const MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
/// Per request, end to end. A slow server mustn't hold up the queue for long.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Get,
    Post,
}

/// One request, ready to send. `bearer` is the device token: transports must never log it.
#[derive(Clone)]
pub struct HttpRequest {
    pub method: Method,
    pub url: String,
    pub bearer: Option<String>,
    /// JSON, sent with `content-type: application/json`.
    pub body: Option<Vec<u8>>,
    pub timeout: Duration,
}

impl std::fmt::Debug for HttpRequest {
    // The token never reaches logs
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpRequest")
            .field("method", &self.method)
            .field("url", &self.url)
            .field("bearer", &self.bearer.as_ref().map(|_| "<redacted>"))
            .field("body_len", &self.body.as_ref().map(Vec::len))
            .finish_non_exhaustive()
    }
}

/// An answer with any status. Transports return non-2xx statuses as answers, not errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    pub status: u16,
    pub body: Vec<u8>,
    /// `Retry-After` in seconds, when the server sent one.
    pub retry_after_secs: Option<u32>,
}

/// The request never got an answer: no network, DNS, TLS, a timeout, an answer over `MAX_RESPONSE_BYTES`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct TransportError(pub String);

/// HTTP as the platform does it (`WinHTTP` on Windows). Blocking; called from the service's own thread.
pub trait Transport: Send + Sync {
    fn send(&self, request: HttpRequest) -> Result<HttpResponse, TransportError>;
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ApiError {
    #[error("couldn't reach eGuard: {0}")]
    Unreachable(#[from] TransportError),
    /// A non-2xx answer. `message` is the server's `{ error }`, written for people, when it sent one.
    #[error("eGuard answered {status}{}", message.as_deref().map(|m| format!(": {m}")).unwrap_or_default())]
    Status { status: u16, message: Option<String>, retry_after_secs: Option<u32> },
    #[error("eGuard's answer didn't parse: {0}")]
    Malformed(String),
}

impl ApiError {
    pub fn status(&self) -> Option<u16> {
        match self {
            Self::Status { status, .. } => Some(*status),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BadServerUrl {
    #[error("the server URL must start with https:// (http:// only for localhost in a development build)")]
    NotHttps,
    #[error("the server URL has no host")]
    NoHost,
    #[error("the server URL's host or port isn't valid")]
    BadHost,
}

/// The host of `authority` (`host[:port]`, an IPv6 host in brackets), checked. A user name or password is refused:
/// `http://localhost@example.com` goes to example.com.
fn host_of(authority: &str) -> Result<&str, BadServerUrl> {
    if authority.contains('@') {
        return Err(BadServerUrl::BadHost);
    }
    let (host, port) = if authority.starts_with('[') {
        let end = authority.find(']').ok_or(BadServerUrl::BadHost)?;
        (&authority[..=end], &authority[end + 1..])
    } else {
        match authority.find(':') {
            Some(i) => (&authority[..i], &authority[i..]),
            None => (authority, ""),
        }
    };
    if !port.is_empty() {
        let digits = port.strip_prefix(':').ok_or(BadServerUrl::BadHost)?;
        if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) || digits.parse::<u16>().is_err() {
            return Err(BadServerUrl::BadHost);
        }
    }
    if host.is_empty() {
        return Err(BadServerUrl::NoHost);
    }
    Ok(host)
}

/// The eGuard server, checked: `https://` always, except `http://localhost` in a development build (the dev server).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerUrl(String);

impl ServerUrl {
    pub fn parse(url: &str, dev_build: bool) -> Result<Self, BadServerUrl> {
        let url = url.trim();
        let (https, rest) = match (url.strip_prefix("https://"), url.strip_prefix("http://")) {
            (Some(rest), _) => (true, rest),
            (None, Some(rest)) => (false, rest),
            (None, None) => return Err(BadServerUrl::NotHttps),
        };
        let host = host_of(rest.split(['/', '?', '#']).next().unwrap_or(""))?;
        let local = ["localhost", "127.0.0.1", "[::1]"].iter().any(|h| host.eq_ignore_ascii_case(h));
        // Plain http only for the dev server on this machine, in a dev build
        if !(https || dev_build && local) {
            return Err(BadServerUrl::NotHttps);
        }
        Ok(Self(url.trim_end_matches('/').to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn device(&self, path: &str) -> String {
        format!("{}/api/device/v1{path}", self.0)
    }
}

/// The device API on one server.
pub struct Api {
    server: ServerUrl,
    transport: Box<dyn Transport>,
}

impl std::fmt::Debug for Api {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Api").field("server", &self.server).finish_non_exhaustive()
    }
}

impl Api {
    pub fn new(server: ServerUrl, transport: Box<dyn Transport>) -> Self {
        Self { server, transport }
    }

    pub fn server(&self) -> &ServerUrl {
        &self.server
    }

    fn post(&self, path: &str, token: Option<&str>, body: &impl Serialize) -> Result<HttpResponse, TransportError> {
        let body = serde_json::to_vec(body).map_err(|e| TransportError(e.to_string()))?;
        self.transport.send(HttpRequest {
            method: Method::Post,
            url: self.server.device(path),
            bearer: token.map(str::to_owned),
            body: Some(body),
            timeout: REQUEST_TIMEOUT,
        })
    }

    /// `POST /pair` (no token). `201` gives the token and removal secret, once.
    pub fn pair(&self, request: &PairRequest) -> Result<PairResponse, ApiError> {
        let res = self.post("/pair", None, request)?;
        let res = ok_or_status(res)?;
        serde_json::from_slice(&res.body).map_err(|e| ApiError::Malformed(e.to_string()))
    }

    /// `POST /sync`. The answer comes back as raw JSON: `state::AgentState::apply_sync` parses it and checks the
    /// uninstall signature on exactly what was received.
    pub fn sync(&self, token: &str, request: &SyncRequest) -> Result<Value, ApiError> {
        let res = self.post("/sync", Some(token), request)?;
        let res = ok_or_status(res)?;
        serde_json::from_slice(&res.body).map_err(|e| ApiError::Malformed(e.to_string()))
    }

    /// `GET /catalog?since=<version>`. Raw JSON: `signature::verify_catalog` checks it as received.
    pub fn catalog(&self, token: &str, since: Option<&str>) -> Result<Value, ApiError> {
        // A version is a hash or a number; anything else (a kept copy someone edited) just fetches the whole catalog
        let query = since
            .filter(|v| !v.is_empty() && v.bytes().all(|b| b.is_ascii_alphanumeric()))
            .map(|v| format!("?since={v}"))
            .unwrap_or_default();
        let res = self.transport.send(HttpRequest {
            method: Method::Get,
            url: self.server.device(&format!("/catalog{query}")),
            bearer: Some(token.to_owned()),
            body: None,
            timeout: REQUEST_TIMEOUT,
        })?;
        let res = ok_or_status(res)?;
        serde_json::from_slice(&res.body).map_err(|e| ApiError::Malformed(e.to_string()))
    }

    /// `GET /update`: the version eGuard offers this computer. Raw JSON: `update::verify_manifest` checks it as
    /// received.
    pub fn update(&self, token: &str) -> Result<Value, ApiError> {
        let res = self.transport.send(HttpRequest {
            method: Method::Get,
            url: self.server.device("/update"),
            bearer: Some(token.to_owned()),
            body: None,
            timeout: REQUEST_TIMEOUT,
        })?;
        let res = ok_or_status(res)?;
        serde_json::from_slice(&res.body).map_err(|e| ApiError::Malformed(e.to_string()))
    }

    /// Sends one queued item and says how it went, for `OutboundQueue::settle`.
    pub fn send(&self, token: &str, item: &Outbound) -> SendOutcome {
        let res = match item {
            Outbound::Usage(b) => self.post(item.path(), Some(token), b),
            Outbound::Report(b) => self.post(item.path(), Some(token), b),
            Outbound::Event(b) => self.post(item.path(), Some(token), b),
        };
        match res {
            Ok(r) => match SendOutcome::from_status(r.status) {
                SendOutcome::RateLimited { .. } => SendOutcome::RateLimited { retry_after_secs: r.retry_after_secs },
                o => o,
            },
            Err(_) => SendOutcome::Unreachable,
        }
    }
}

fn ok_or_status(res: HttpResponse) -> Result<HttpResponse, ApiError> {
    if (200..300).contains(&res.status) {
        return Ok(res);
    }
    let message = serde_json::from_slice::<ErrorBody>(&res.body).ok().map(|b| b.error.chars().take(300).collect());
    Err(ApiError::Status { status: res.status, message, retry_after_secs: res.retry_after_secs })
}

/// `Retry-After` as seconds. The HTTP-date form isn't used by eGuard and is ignored.
pub fn parse_retry_after(value: &str) -> Option<u32> {
    value.trim().parse().ok()
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Answers requests from a script, and remembers what was asked.
    pub(crate) struct Scripted {
        pub answers: Mutex<Vec<Result<HttpResponse, TransportError>>>,
        /// What `GET /catalog` answers, every time (no network when unset). Kept apart from `answers` so tests of
        /// sync and the queue don't have to script the catalog in between.
        pub catalog: Mutex<Option<Value>>,
        /// What `GET /update` answers, every time (no network when unset), kept apart for the same reason.
        pub update: Mutex<Option<Value>>,
        pub seen: Mutex<Vec<HttpRequest>>,
    }

    impl Scripted {
        pub fn new(answers: Vec<Result<HttpResponse, TransportError>>) -> std::sync::Arc<Self> {
            std::sync::Arc::new(Self {
                answers: Mutex::new(answers),
                catalog: Mutex::new(None),
                update: Mutex::new(None),
                seen: Mutex::new(Vec::new()),
            })
        }
    }

    impl Transport for std::sync::Arc<Scripted> {
        fn send(&self, request: HttpRequest) -> Result<HttpResponse, TransportError> {
            let (catalog, update) = (request.url.contains("/catalog"), request.url.ends_with("/update"));
            self.seen.lock().unwrap().push(request);
            let fixed = if catalog {
                Some(&self.catalog)
            } else if update {
                Some(&self.update)
            } else {
                None
            };
            if let Some(fixed) = fixed {
                return fixed.lock().unwrap().as_ref().map_or_else(|| Err(TransportError("no network".into())), |v| json(200, v));
            }
            let mut a = self.answers.lock().unwrap();
            if a.is_empty() { Err(TransportError("no network".into())) } else { a.remove(0) }
        }
    }

    #[allow(clippy::unnecessary_wraps)] // Shaped like a transport answer, to go straight into a script
    pub(crate) fn json(status: u16, body: &Value) -> Result<HttpResponse, TransportError> {
        Ok(HttpResponse { status, body: serde_json::to_vec(body).unwrap(), retry_after_secs: None })
    }

    #[test]
    fn server_url_is_https_except_a_dev_localhost() {
        assert!(ServerUrl::parse("https://eguard.app/", false).is_ok());
        assert_eq!(ServerUrl::parse("https://eguard.app/", false).unwrap().as_str(), "https://eguard.app");
        assert_eq!(ServerUrl::parse("http://eguard.app", true), Err(BadServerUrl::NotHttps));
        assert_eq!(ServerUrl::parse("http://localhost:3000", false), Err(BadServerUrl::NotHttps));
        assert!(ServerUrl::parse("http://localhost:3000", true).is_ok());
        // A host that merely starts with "localhost" is someone else's
        assert_eq!(ServerUrl::parse("http://localhost.evil.example", true), Err(BadServerUrl::NotHttps));
        assert_eq!(ServerUrl::parse("https://", false), Err(BadServerUrl::NoHost));
        assert_eq!(ServerUrl::parse("ftp://x", true), Err(BadServerUrl::NotHttps));
    }

    #[test]
    fn ipv6_hosts_are_read_whole_and_userinfo_is_refused() {
        assert!(ServerUrl::parse("http://[::1]:3000", true).is_ok());
        assert!(ServerUrl::parse("http://[::1]/", true).is_ok());
        assert_eq!(ServerUrl::parse("http://[::1]:3000", false), Err(BadServerUrl::NotHttps));
        assert!(ServerUrl::parse("https://[2001:db8::1]:8443", false).is_ok());
        assert_eq!(ServerUrl::parse("http://[::2]:3000", true), Err(BadServerUrl::NotHttps));
        assert_eq!(ServerUrl::parse("http://[::1", true), Err(BadServerUrl::BadHost));
        assert_eq!(ServerUrl::parse("http://[::1]x", true), Err(BadServerUrl::BadHost));
        assert_eq!(ServerUrl::parse("http://localhost:99999", true), Err(BadServerUrl::BadHost));
        // "localhost" before an @ is a user name: the host is someone else's
        assert_eq!(ServerUrl::parse("http://localhost@evil.example", true), Err(BadServerUrl::BadHost));
        assert_eq!(ServerUrl::parse("https://:443", false), Err(BadServerUrl::NoHost));
        assert!(ServerUrl::parse("http://LOCALHOST:3000", true).is_ok());
    }

    #[test]
    fn errors_carry_the_servers_words_and_the_token_stays_out_of_debug() {
        let t = Scripted::new(vec![json(400, &serde_json::json!({ "error": "Pairing code is invalid or expired" }))]);
        let api = Api::new(ServerUrl::parse("http://localhost:3000", true).unwrap(), Box::new(t.clone()));
        let req = PairRequest {
            code: "ABCD2345".into(),
            platform: crate::wire::Platform::Windows,
            name: "PC".into(),
            model: "M".into(),
            kind: None,
            os_version: "Windows 11".into(),
            app_version: None,
        };
        let e = api.pair(&req).unwrap_err();
        assert_eq!(e.to_string(), "eGuard answered 400: Pairing code is invalid or expired");
        let seen = t.seen.lock().unwrap();
        assert_eq!(seen[0].url, "http://localhost:3000/api/device/v1/pair");
        assert!(seen[0].bearer.is_none());

        let r = HttpRequest {
            method: Method::Post,
            url: "u".into(),
            bearer: Some("secret-token".into()),
            body: None,
            timeout: REQUEST_TIMEOUT,
        };
        assert!(!format!("{r:?}").contains("secret-token"));
    }

    #[test]
    fn a_429_keeps_its_retry_after() {
        let t = Scripted::new(vec![Ok(HttpResponse { status: 429, body: vec![], retry_after_secs: Some(600) })]);
        let api = Api::new(ServerUrl::parse("https://eguard.app", false).unwrap(), Box::new(t));
        let item = Outbound::Event(crate::wire::EventEnvelope::new(crate::wire::DeviceEvent::Tamper {
            kind: crate::wire::TamperKind::ClockChanged,
        }));
        assert_eq!(api.send("t", &item), SendOutcome::RateLimited { retry_after_secs: Some(600) });
        assert_eq!(parse_retry_after(" 120 "), Some(120));
        assert_eq!(parse_retry_after("Wed, 21 Oct 2026 07:28:00 GMT"), None);
    }
}
