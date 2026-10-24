//! eGuard's local logs (Phase 7): one JSON object per line, so a support script can read them, rotated by size, and
//! scrubbed of anything that looks like a secret before it's written.
//!
//! - `service.log` (the service, in the data folder) and `agent.log` (each session's agent, in that user's local
//!   app data). Each is cut at `MAX_BYTES` and the last `KEEP` cut files are kept (`service.log.1` newest).
//! - A line: `{"ts":"…","level":"WARN","component":"service","pid":1234,"thread":"monitor","msg":"…"}`. The console
//!   (console mode) gets the same as plain text.
//! - Secrets: the types that hold them redact themselves in `Debug` and no message formats a token. `scrub` is the
//!   second line: a run of 32 or more token characters (base64url, hex) is replaced before anything is written. The
//!   device token and the removal secret are such runs; nothing eGuard logs on purpose is (device ids are 25, catalog
//!   versions 16, Windows SIDs are kept as they are).
//!
//! The platform adds the crash handler (`eguard-win::crash`), which writes its last line through `last_words`;
//! `panic_report` is what it says for a panic.

use serde::Serialize;
use std::borrow::Cow;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock, PoisonError};

/// A log file is cut when it passes this size.
pub const MAX_BYTES: u64 = 1024 * 1024;
/// Cut files kept beside the current one.
pub const KEEP: usize = 5;
/// Runs of token characters at least this long are taken for secrets.
pub const SECRET_RUN: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Level {
    Info,
    Warn,
    Error,
}

impl Level {
    fn name(self) -> &'static str {
        match self {
            Self::Info => "INFO",
            Self::Warn => "WARN",
            Self::Error => "ERROR",
        }
    }
}

/// `msg` with every run of `SECRET_RUN` or more token characters (letters, digits, `-`, `_`) replaced by
/// `[redacted]`. Left alone: a Windows SID (`S-1-5-…`), which names an account, and a GUID (`8-4-4-4-12` hex), which
/// Windows puts in folder names. Neither unlocks anything.
pub fn scrub(msg: &str) -> Cow<'_, str> {
    let token = |c: char| c.is_ascii_alphanumeric() || c == '-' || c == '_';
    let mut out = String::new();
    let mut last = 0;
    let mut i = 0;
    let bytes = msg.as_bytes();
    while i < bytes.len() {
        if !token(bytes[i] as char) {
            i += 1;
            continue;
        }
        let start = i;
        while i < bytes.len() && token(bytes[i] as char) {
            i += 1;
        }
        let run = &msg[start..i];
        if run.len() >= SECRET_RUN && !run.starts_with("S-1-") && !is_guid(run) {
            out.push_str(&msg[last..start]);
            out.push_str("[redacted]");
            last = i;
        }
    }
    if last == 0 {
        Cow::Borrowed(msg)
    } else {
        out.push_str(&msg[last..]);
        Cow::Owned(out)
    }
}

/// `8-4-4-4-12` hex digits, as Windows and UUIDs write them.
fn is_guid(run: &str) -> bool {
    let parts: Vec<&str> = run.split('-').collect();
    parts.len() == 5 && parts.iter().zip([8, 4, 4, 4, 12]).all(|(p, n)| p.len() == n && p.chars().all(|c| c.is_ascii_hexdigit()))
}

#[derive(Serialize)]
struct Line<'a> {
    ts: String,
    level: Level,
    component: &'a str,
    pid: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    thread: Option<&'a str>,
    msg: &'a str,
}

/// One log line as written to the file, with its `\n`. `msg` is scrubbed first.
pub fn json_line(ts: jiff::Timestamp, level: Level, component: &str, pid: u32, thread: Option<&str>, msg: &str) -> String {
    let msg = scrub(msg);
    let line = Line { ts: ts.round(jiff::Unit::Millisecond).unwrap_or(ts).to_string(), level, component, pid, thread, msg: &msg };
    let mut s = serde_json::to_string(&line).unwrap_or_default();
    s.push('\n');
    s
}

/// The file a log writes to, cut by size.
#[derive(Debug)]
pub struct RotatingFile {
    path: PathBuf,
    file: Option<File>,
    size: u64,
    max: u64,
    keep: usize,
}

impl RotatingFile {
    /// Opens (or creates) `path` for appending; its folder is created.
    pub fn open(path: &Path, max: u64, keep: usize) -> std::io::Result<Self> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        let size = file.metadata()?.len();
        Ok(Self { path: path.to_owned(), file: Some(file), size, max, keep })
    }

    fn cut_name(&self, n: usize) -> PathBuf {
        let mut name = self.path.clone().into_os_string();
        name.push(format!(".{n}"));
        PathBuf::from(name)
    }

    /// Moves `log` to `log.1`, `log.1` to `log.2` …, dropping the oldest, and starts a new file.
    fn rotate(&mut self) {
        // Closed first: Windows doesn't rename a file this process holds open for writing
        self.file = None;
        let _ = std::fs::remove_file(self.cut_name(self.keep));
        for n in (1..self.keep).rev() {
            let _ = std::fs::rename(self.cut_name(n), self.cut_name(n + 1));
        }
        let _ = std::fs::rename(&self.path, self.cut_name(1));
        self.file = OpenOptions::new().create(true).append(true).open(&self.path).ok();
        self.size = 0;
    }

    /// Appends one line, cutting the file first when it would pass the limit. Errors are dropped: a log that can't
    /// be written mustn't stop protection.
    pub fn write_line(&mut self, line: &str) {
        if self.size > 0 && self.size + line.len() as u64 > self.max {
            self.rotate();
        }
        if self.file.is_none() {
            self.file = OpenOptions::new().create(true).append(true).open(&self.path).ok();
        }
        if let Some(f) = self.file.as_mut()
            && f.write_all(line.as_bytes()).is_ok()
        {
            self.size += line.len() as u64;
        }
    }
}

struct Logger {
    component: &'static str,
    console: bool,
    file: Option<Mutex<RotatingFile>>,
}

static LOGGER: OnceLock<Logger> = OnceLock::new();
/// The log file's path, readable without the lock (`last_words`).
static PATH: OnceLock<PathBuf> = OnceLock::new();

/// Call once at start. `file`: the log file (`None`: none); `console`: also print each line as text.
pub fn init(component: &'static str, file: Option<&Path>, console: bool) {
    if let Some(p) = file {
        let _ = PATH.set(p.to_owned());
    }
    let file = file.and_then(|p| RotatingFile::open(p, MAX_BYTES, KEEP).ok()).map(Mutex::new);
    let _ = LOGGER.set(Logger { component, console, file });
}

/// Writes one line (scrubbed) to the console and the file, as `init` set up.
pub fn write(level: Level, msg: &str) {
    let Some(log) = LOGGER.get() else { return };
    let now = jiff::Timestamp::now();
    let current = std::thread::current();
    let line = json_line(now, level, log.component, std::process::id(), current.name(), msg);
    if log.console {
        eprintln!("{} {} {}", now.round(jiff::Unit::Second).unwrap_or(now), level.name(), scrub(msg));
    }
    if let Some(file) = &log.file {
        file.lock().unwrap_or_else(PoisonError::into_inner).write_line(&line);
    }
}

/// The last line before the process ends (the crash handler). Never waits: if another thread holds the file (it may
/// be the one that crashed), the line goes straight to the file through a handle of its own, uncut. Also printed to
/// stderr as text, so a command run by hand (`eguard-agent pair`, before any log) still says why it ended.
pub fn last_words(msg: &str) {
    let now = jiff::Timestamp::now();
    eprintln!("{} {} {}", now.round(jiff::Unit::Second).unwrap_or(now), Level::Error.name(), scrub(msg));
    let Some(log) = LOGGER.get() else { return };
    let current = std::thread::current();
    let line = json_line(now, Level::Error, log.component, std::process::id(), current.name(), msg);
    let Some(file) = &log.file else { return };
    match file.try_lock() {
        Ok(mut f) => f.write_line(&line),
        Err(std::sync::TryLockError::Poisoned(p)) => p.into_inner().write_line(&line),
        Err(std::sync::TryLockError::WouldBlock) => {
            if let Some(path) = PATH.get()
                && let Ok(mut f) = OpenOptions::new().append(true).open(path)
            {
                let _ = f.write_all(line.as_bytes());
            }
        }
    }
}

/// What a panic says, as `panic!` was given it (a `&str` or a `String`; anything else has no words).
pub fn panic_payload(payload: &(dyn std::any::Any + Send)) -> &str {
    payload.downcast_ref::<&str>().copied().or_else(|| payload.downcast_ref::<String>().map(String::as_str)).unwrap_or("(no message)")
}

/// The crash handler's line for a panic: what it said, where, and the stack (scrubbed like any line when written).
pub fn panic_report(info: &std::panic::PanicHookInfo<'_>, backtrace: &std::backtrace::Backtrace) -> String {
    let at = info.location().map_or_else(String::new, |l| format!(" at {}:{}:{}", l.file(), l.line(), l.column()));
    crash_report(panic_payload(info.payload()), &at, &backtrace.to_string())
}

fn crash_report(what: &str, at: &str, backtrace: &str) -> String {
    let backtrace = backtrace.trim_end();
    if backtrace.is_empty() { format!("crashed: panic{at}: {what}") } else { format!("crashed: panic{at}: {what}\n{backtrace}") }
}

pub fn info(msg: &str) {
    write(Level::Info, msg);
}

pub fn warn(msg: &str) {
    write(Level::Warn, msg);
}

pub fn error(msg: &str) {
    write(Level::Error, msg);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secrets_are_scrubbed_and_ordinary_words_kept() {
        let token = "eyJhbGciOiJFUzI1NiJ9_k3Hq9vX0aZb7cD1eF2gH3iJ4kL5mN6oP";
        assert_eq!(scrub(&format!("sent with Bearer {token}.")), "sent with Bearer [redacted].");
        let secret = "dSE3AFEcf91DR9Oa3e7GLyG80ZG3RUpB14Tj9ZJl0ac";
        assert_eq!(scrub(&format!("{secret},{secret}")), "[redacted],[redacted]");
        // Device ids, catalog versions, paths, SIDs, sentences: untouched (and not copied)
        for kept in [
            "paired as cmvl46frt00f9ncv4lgdzx7w4 for Mia",
            "catalog version 9f2c4e1a7b3d5f60 (412 entries)",
            r"C:\Program Files (x86)\Steam\steamapps\common\Counter-Strike Global Offensive\game\bin\win64\cs2.exe",
            "session 2: S-1-5-21-3623811015-3361044348-30300820-1013 signed in",
            r"data in C:\Users\corew\AppData\Local\Temp\63a3f36e-d86b-4dad-99af-792d1036e113\data",
            "",
        ] {
            assert!(matches!(scrub(kept), Cow::Borrowed(_)), "{kept}");
        }
        // Exactly at the limit counts; one short doesn't
        assert_eq!(scrub(&"a".repeat(SECRET_RUN)), "[redacted]");
        assert_eq!(scrub(&"a".repeat(SECRET_RUN - 1)), "a".repeat(SECRET_RUN - 1));
        assert_eq!(scrub("é ünïcode stays"), "é ünïcode stays");
        // Shaped like a GUID but not hex, or one part too long: a secret as far as the log knows
        assert_eq!(scrub("63a3f36e-d86b-4dad-99af-792d1036e11z"), "[redacted]");
        assert_eq!(scrub("63a3f36e-d86b-4dad-99af-792d1036e1133"), "[redacted]");
    }

    #[test]
    fn a_panic_says_what_and_where() {
        let s: Box<dyn std::any::Any + Send> = Box::new("index out of range");
        assert_eq!(panic_payload(s.as_ref()), "index out of range");
        let s: Box<dyn std::any::Any + Send> = Box::new(String::from("bad state: 3"));
        assert_eq!(panic_payload(s.as_ref()), "bad state: 3");
        let s: Box<dyn std::any::Any + Send> = Box::new(42_u8);
        assert_eq!(panic_payload(s.as_ref()), "(no message)");
        assert_eq!(crash_report("boom", " at src/x.rs:1:2", ""), "crashed: panic at src/x.rs:1:2: boom");
        assert_eq!(crash_report("boom", "", "   0: main\n"), "crashed: panic: boom\n   0: main");
    }

    #[test]
    fn a_line_is_one_json_object() {
        let ts: jiff::Timestamp = "2026-10-24T01:02:03.456789Z".parse().unwrap();
        let line = json_line(ts, Level::Warn, "service", 42, Some("monitor"), "said \"hi\"\nthen left");
        assert!(line.ends_with('\n') && line.matches('\n').count() == 1);
        let v: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(
            v,
            serde_json::json!({ "ts": "2026-10-24T01:02:03.457Z", "level": "WARN", "component": "service", "pid": 42, "thread": "monitor", "msg": "said \"hi\"\nthen left" })
        );
        let v: serde_json::Value = serde_json::from_str(&json_line(ts, Level::Info, "agent", 1, None, &"x".repeat(40))).unwrap();
        assert_eq!(v["msg"], "[redacted]");
        assert!(v.get("thread").is_none());
    }

    #[test]
    fn files_are_cut_by_size_and_only_the_newest_kept() {
        let dir = std::env::temp_dir().join(format!("eguard-logging-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("logs").join("service.log");
        let mut f = RotatingFile::open(&path, 100, 2).unwrap();
        for i in 0..10 {
            f.write_line(&format!("{i:0>39}\n"));
        }
        // 40 bytes a line, 100 a file: two lines each. Ten lines: the current file and two cut ones, the oldest gone
        let read = |p: PathBuf| std::fs::read_to_string(p).unwrap();
        assert_eq!(read(path.clone()), format!("{:0>39}\n{:0>39}\n", 8, 9));
        assert_eq!(read(dir.join("logs").join("service.log.1")), format!("{:0>39}\n{:0>39}\n", 6, 7));
        assert_eq!(read(dir.join("logs").join("service.log.2")), format!("{:0>39}\n{:0>39}\n", 4, 5));
        assert!(!dir.join("logs").join("service.log.3").exists());
        // Opened again, it carries on from its size
        drop(f);
        let mut f = RotatingFile::open(&path, 100, 2).unwrap();
        f.write_line(&format!("{:0>39}\n", 10));
        assert_eq!(read(path), format!("{:0>39}\n", 10));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
