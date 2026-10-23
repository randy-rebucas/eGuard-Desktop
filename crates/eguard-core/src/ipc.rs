//! Messages between the service and `eguard-agent` over the named pipe (spec section 3).
//!
//! One JSON object per line, each with the protocol version `v`. The service treats everything the agent sends as
//! untrusted: a line longer than `MAX_MESSAGE_BYTES`, a version it doesn't speak or a message that doesn't parse is
//! answered with an error and the connection closed. Nothing on the pipe ever carries a secret.

use serde::{Deserialize, Serialize};

/// The service's pipe.
pub const PIPE_NAME: &str = r"\\.\pipe\eguard";
pub const PROTOCOL_VERSION: u32 = 1;
/// The longest line either side reads.
pub const MAX_MESSAGE_BYTES: usize = 8 * 1024;

/// From the agent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum Request {
    /// Pair with a code from the parent's dashboard. Refused once paired.
    Pair {
        code: String,
        /// The computer's name on the dashboard; the Windows name when left out.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        name: Option<String>,
    },
    Status,
}

/// What the agent may know about the service. No token, no removal secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StatusInfo {
    pub paired: bool,
    pub device_id: Option<String>,
    pub child_name: Option<String>,
    pub server: String,
    /// eGuard's time of the last good `/sync`, ISO 8601.
    pub last_sync_at: Option<String>,
    /// False while the server refuses the token (protection carries on).
    pub authorized: bool,
    /// Items waiting to be sent.
    pub queued: usize,
}

/// From the service.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum Response {
    #[serde(rename_all = "camelCase")]
    Paired {
        child_name: String,
    },
    Status(StatusInfo),
    /// In words for the person at the computer.
    Error {
        message: String,
    },
}

#[derive(Serialize, Deserialize)]
struct Envelope<T> {
    v: u32,
    #[serde(flatten)]
    body: T,
}

/// One line to write: the message as JSON, then `\n`.
pub fn encode<T: Serialize>(message: &T) -> Vec<u8> {
    let mut line = serde_json::to_vec(&Envelope { v: PROTOCOL_VERSION, body: message }).unwrap_or_default();
    line.push(b'\n');
    line
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DecodeError {
    #[error("message too long")]
    TooLong,
    #[error("protocol version {0} isn't supported (this eGuard speaks {PROTOCOL_VERSION})")]
    Version(u32),
    #[error("message didn't parse: {0}")]
    Malformed(String),
}

/// Reads one line (`line` without its `\n`).
pub fn decode<T: for<'de> Deserialize<'de>>(line: &[u8]) -> Result<T, DecodeError> {
    #[derive(Deserialize)]
    struct Version {
        v: u32,
    }
    if line.len() > MAX_MESSAGE_BYTES {
        return Err(DecodeError::TooLong);
    }
    let v: Version = serde_json::from_slice(line).map_err(|e| DecodeError::Malformed(e.to_string()))?;
    if v.v != PROTOCOL_VERSION {
        return Err(DecodeError::Version(v.v));
    }
    let e: Envelope<T> = serde_json::from_slice(line).map_err(|e| DecodeError::Malformed(e.to_string()))?;
    Ok(e.body)
}

/// Reads up to `\n` from `r`, at most `MAX_MESSAGE_BYTES`. `Ok(None)` when the other side closed first.
pub fn read_line(r: &mut impl std::io::Read) -> std::io::Result<Option<Vec<u8>>> {
    let mut line = Vec::new();
    let mut buf = [0u8; 512];
    loop {
        let n = r.read(&mut buf)?;
        if n == 0 {
            return Ok(if line.is_empty() { None } else { Some(line) });
        }
        if let Some(i) = buf[..n].iter().position(|&b| b == b'\n') {
            line.extend_from_slice(&buf[..i]);
            return Ok(Some(line));
        }
        line.extend_from_slice(&buf[..n]);
        if line.len() > MAX_MESSAGE_BYTES {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "message too long"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn messages_are_versioned_lines() {
        let line = encode(&Request::Pair { code: "ABCD-2345".into(), name: None });
        assert_eq!(line, b"{\"v\":1,\"type\":\"pair\",\"code\":\"ABCD-2345\"}\n");
        let back: Request = decode(&line[..line.len() - 1]).unwrap();
        assert_eq!(back, Request::Pair { code: "ABCD-2345".into(), name: None });
        let status = encode(&Response::Paired { child_name: "Mia".into() });
        assert_eq!(status, b"{\"v\":1,\"type\":\"paired\",\"childName\":\"Mia\"}\n");
    }

    #[test]
    fn untrusted_lines_are_refused() {
        assert_eq!(decode::<Request>(br#"{"v":2,"type":"status"}"#), Err(DecodeError::Version(2)));
        assert!(matches!(decode::<Request>(br#"{"v":1,"type":"uninstall"}"#), Err(DecodeError::Malformed(_))));
        assert!(matches!(decode::<Request>(b"not json"), Err(DecodeError::Malformed(_))));
        assert_eq!(decode::<Request>(&vec![b' '; MAX_MESSAGE_BYTES + 1]), Err(DecodeError::TooLong));
        let mut endless = std::io::repeat(b'x');
        assert!(read_line(&mut endless).is_err());
        let mut two = &b"{\"v\":1,\"type\":\"status\"}\nrest"[..];
        assert_eq!(read_line(&mut two).unwrap().unwrap(), b"{\"v\":1,\"type\":\"status\"}");
    }
}
