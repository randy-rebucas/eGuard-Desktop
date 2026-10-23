//! A small log: one line per event, to the console and to `logs\service.log` in the data folder, kept under 1 MB
//! (one older file is kept beside it). Structured, rotated logs come in Phase 7. Nothing logged carries a secret:
//! the types that hold them redact themselves in `Debug`, and no message formats a token.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

const MAX_BYTES: u64 = 1024 * 1024;

struct Log {
    file: Option<PathBuf>,
    console: bool,
    lock: Mutex<()>,
}

static LOG: OnceLock<Log> = OnceLock::new();

/// Call once at start. `dir` is where `service.log` goes; `console` also prints each line.
pub fn init(dir: Option<&Path>, console: bool) {
    let file = dir.and_then(|d| std::fs::create_dir_all(d).ok().map(|()| d.join("service.log")));
    let _ = LOG.set(Log { file, console, lock: Mutex::new(()) });
}

fn write(level: &str, msg: &str) {
    let Some(log) = LOG.get() else { return };
    let line = format!("{} {level} {msg}\n", jiff::Timestamp::now().round(jiff::Unit::Second).unwrap_or_else(|_| jiff::Timestamp::now()));
    let _guard = log.lock.lock();
    if log.console {
        eprint!("{line}");
    }
    if let Some(path) = &log.file {
        if std::fs::metadata(path).is_ok_and(|m| m.len() > MAX_BYTES) {
            let _ = std::fs::rename(path, path.with_extension("log.1"));
        }
        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
            let _ = f.write_all(line.as_bytes());
        }
    }
}

pub fn info(msg: &str) {
    write("INFO", msg);
}

pub fn warn(msg: &str) {
    write("WARN", msg);
}

pub fn error(msg: &str) {
    write("ERROR", msg);
}
