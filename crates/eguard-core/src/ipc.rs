//! Messages between the service and `eguard-agent` over the named pipes (spec section 3).
//!
//! - `\\.\pipe\eguard`: pairing, status and scans, for SYSTEM and administrators (the installer).
//! - `\\.\pipe\eguard-session-<id>`: one per signed-in session, for SYSTEM and that session's logon. The agent
//!   there sends heartbeats and the child's "Ask" buttons; the service knows the session from the pipe, never from
//!   what the agent says.
//!
//! One JSON object per line, each with the protocol version `v`. The service treats everything the agent sends as
//! untrusted: a line longer than `MAX_MESSAGE_BYTES`, a version it doesn't speak or a message that doesn't parse is
//! answered with an error and the connection closed. Nothing on the pipe ever carries a secret.
//!
//! The version changes only when a message's meaning does. A field added later is optional on both sides, so an
//! older agent skips it (the overlay's app buttons: it shows the overlay without them) and a newer agent reading an
//! older service gets the field's empty default. Either way nothing the screens enforce goes missing.

use serde::{Deserialize, Serialize};

/// The service's pipe.
pub const PIPE_NAME: &str = r"\\.\pipe\eguard";

/// The pipe for one session's agent.
pub fn session_pipe_name(session: u32) -> String {
    format!(r"{PIPE_NAME}-session-{session}")
}

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
        /// The Windows accounts that are the child's, by name; every standard account when left out.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        accounts: Option<Vec<String>>,
    },
    /// The computer's Windows accounts and which are the child's; with `set`, make those the child's first.
    Accounts {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        set: Option<Vec<String>>,
    },
    Status,
    /// Scan for apps now rather than at the next 6-hourly scan.
    Scan,
    /// From a session's agent, about once a second: what has the focus, and how long since the last input.
    #[serde(rename_all = "camelCase")]
    Heartbeat {
        /// The process owning the focused window; `None` when nothing has the focus.
        foreground_pid: Option<u32>,
        idle_ms: u64,
    },
    /// The child pressed "Ask parent" on a block screen.
    AskParent {
        notice: u64,
    },
    /// The child pressed "Ask for more time" on a block screen (`notice`) or the overlay (`None`).
    AskTime {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        notice: Option<u64>,
    },
}

/// One of the agent's screens, in words for the child. The service writes the words; the agent only shows them.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Screen {
    /// Names this screen in `AskParent` / `AskTime` (0 for the overlay).
    pub id: u64,
    pub title: String,
    pub body: String,
    pub ask_parent: bool,
    pub ask_time: bool,
    /// The answer to the child's last ask, shown instead of the buttons.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asked: Option<String>,
    /// The overlay only: the always-allowed apps still usable now, one button each. The taskbar is under the
    /// overlay, so these (and Alt+Tab) are how the child gets to them.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub apps: Vec<AppButton>,
}

/// An always-allowed app on the overlay. Pressing it brings the app's window to the front, or starts it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppButton {
    /// The name on the button.
    pub name: String,
    /// The program the service saw this app run as in front of the child, full path. The agent starts or looks for
    /// this path only, never one from anywhere else. `None` until the app has been used on this computer: the button
    /// can't do anything then.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exe: Option<String>,
    /// The agent may start `exe` when it isn't running. False for a Store app, which Windows starts only through the
    /// app's own activation: its button only brings it to the front.
    #[serde(default)]
    pub start: bool,
}

/// A short notice ("5 minutes of gaming time left today"). Shown once: each has a new id.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Warning {
    pub id: u64,
    pub text: String,
}

/// What a session's screen shows now.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionView {
    /// Full screen, over everything: bedtime, or the day's screen time used up.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overlay: Option<Screen>,
    /// The newest program eGuard ended in this session, and why.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub block: Option<Screen>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub warning: Option<Warning>,
}

/// What the agent may know about the service. No token, no removal secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StatusInfo {
    /// Paired, so the rules apply. Also true when the secrets were lost (then `authorized` is false).
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
    /// Apps the last scan reported; `None` before the first scan.
    #[serde(default)]
    pub apps_reported: Option<usize>,
    /// eGuard's time of the last scan, ISO 8601.
    #[serde(default)]
    pub last_scan_at: Option<String>,
}

/// One Windows account, for choosing the child's.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountInfo {
    pub name: String,
    pub admin: bool,
    /// The child's rules apply in it.
    pub enforced: bool,
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
    /// The answer to a heartbeat.
    Session(SessionView),
    /// The computer's Windows accounts.
    Accounts {
        accounts: Vec<AccountInfo>,
    },
    /// The answer to an ask, in words for the child.
    Asked {
        message: String,
    },
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
        let line = encode(&Request::Pair { code: "ABCD-2345".into(), name: None, accounts: None });
        assert_eq!(line, b"{\"v\":1,\"type\":\"pair\",\"code\":\"ABCD-2345\"}\n");
        let back: Request = decode(&line[..line.len() - 1]).unwrap();
        assert_eq!(back, Request::Pair { code: "ABCD-2345".into(), name: None, accounts: None });
        let status = encode(&Response::Paired { child_name: "Mia".into() });
        assert_eq!(status, b"{\"v\":1,\"type\":\"paired\",\"childName\":\"Mia\"}\n");
        let hb = encode(&Request::Heartbeat { foreground_pid: Some(42), idle_ms: 1500 });
        assert_eq!(hb, b"{\"v\":1,\"type\":\"heartbeat\",\"foregroundPid\":42,\"idleMs\":1500}\n");
        let view = SessionView { warning: Some(Warning { id: 3, text: "1 minute left".into() }), ..SessionView::default() };
        let line = encode(&Response::Session(view.clone()));
        assert_eq!(decode::<Response>(&line[..line.len() - 1]).unwrap(), Response::Session(view));
        assert_eq!(session_pipe_name(2), r"\\.\pipe\eguard-session-2");
    }

    #[test]
    fn app_buttons_are_optional_both_ways() {
        // From an older service (no buttons): the overlay still reads, with none
        let old = br#"{"v":1,"type":"session","overlay":{"id":0,"title":"T","body":"B","askParent":false,"askTime":true}}"#;
        let Response::Session(view) = decode::<Response>(old).unwrap() else { panic!() };
        assert_eq!(view.overlay.unwrap().apps, Vec::<AppButton>::new());
        // To an older agent: a field it doesn't know, which serde skips
        let screen = Screen {
            apps: vec![AppButton { name: "Khan Academy".into(), exe: Some(r"C:\Khan\khan.exe".into()), start: true }],
            ..Screen::default()
        };
        let line = encode(&Response::Session(SessionView { overlay: Some(screen.clone()), ..SessionView::default() }));
        let text = String::from_utf8(line.clone()).unwrap();
        assert!(text.contains(r#""apps":[{"name":"Khan Academy","exe":"C:\\Khan\\khan.exe","start":true}]"#), "{text}");
        let Response::Session(back) = decode::<Response>(&line[..line.len() - 1]).unwrap() else { panic!() };
        assert_eq!(back.overlay, Some(screen));
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
