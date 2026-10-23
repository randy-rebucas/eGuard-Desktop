//! Watching processes and ending blocked ones (spec section 7).
//!
//! New processes come from ETW as they start (when the service may open a kernel session: as SYSTEM) and from a
//! sweep of the process list every second, which also catches anything ETW missed. Every program eGuard tracks is
//! checked again on each sweep: a limit can run out while a game is open. A program to end is ended with its tree
//! (`TerminateProcess`, from outside), and its session shows the block screen.
//!
//! Console mode on a developer's PC never ends the developer's own programs: it ends only what runs from the
//! `--sandbox` folder, and without one it only logs what it would have ended.

use crate::log;
use crate::sessions::SessionSids;
use eguard_core::enforce::{Decision, Enforcer, Program};
use eguard_win::{apps, authenticode, process};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

/// How often the process list is swept without ETW: a blocked program is gone within about this long.
pub const SWEEP_EVERY: Duration = Duration::from_secs(1);
/// With ETW reporting starts as they happen, the sweep only re-checks running programs (limits running out).
pub const SWEEP_EVERY_WITH_ETW: Duration = Duration::from_secs(2);

/// What ending a program means here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EndMode {
    /// The service: end what the rules say.
    Real,
    /// Console mode with `--sandbox DIR`: end only what runs from inside DIR (lower case).
    Sandbox(String),
    /// Console mode: log what would be ended, end nothing.
    DryRun,
}

/// A checked program, with the size and modification time of the file it was checked as.
type Checked = (u64, i64, Arc<Program>);

/// What eGuard knows about each executable, cached by path, size and modification time (checking a signature
/// takes milliseconds; the sweep runs every second).
#[derive(Debug)]
pub struct Facts {
    cache: Mutex<HashMap<String, Checked>>,
    system_root: String,
    program_files: Vec<String>,
    /// eGuard's own folder (where this service's exe is).
    own_dir: String,
}

fn lower(p: &Path) -> String {
    p.to_string_lossy().trim_end_matches('\\').to_lowercase()
}

fn under(path: &str, dir: &str) -> bool {
    !dir.is_empty() && path.starts_with(dir) && path[dir.len()..].starts_with('\\')
}

impl Default for Facts {
    fn default() -> Self {
        Self::new()
    }
}

impl Facts {
    pub fn new() -> Self {
        let env = |k: &str| std::env::var_os(k).map(|v| lower(Path::new(&v)));
        let own_dir = std::env::current_exe().ok().and_then(|p| p.parent().map(lower)).unwrap_or_default();
        Self {
            cache: Mutex::new(HashMap::new()),
            system_root: env("SystemRoot").unwrap_or_else(|| r"c:\windows".into()),
            program_files: ["ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"].iter().filter_map(|k| env(k)).collect(),
            own_dir,
        }
    }

    /// The program at `path`, checked once per version of the file.
    pub fn program(&self, path: &Path) -> Option<Arc<Program>> {
        let meta = std::fs::metadata(path).ok()?;
        let modified = meta.modified().ok().and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()).map_or(0, |d| d.as_millis() as i64);
        let key = lower(path);
        if let Some((size, m, p)) = self.cache.lock().unwrap_or_else(PoisonError::into_inner).get(&key)
            && *size == meta.len()
            && *m == modified
        {
            return Some(Arc::clone(p));
        }
        let windows = under(&key, &self.system_root) && authenticode::microsoft_signed(path);
        let file_name = path.file_name().map(|f| f.to_string_lossy().to_lowercase()).unwrap_or_default();
        let ours = path.parent().map(lower).as_deref() == Some(self.own_dir.as_str()) && file_name.starts_with("eguard-");
        // Windows' own programs need nothing more: they're never ended
        let exe = if windows || ours { eguard_core::scan::ExeFacts { file_name, ..Default::default() } } else { apps::exe_facts(path) };
        let program = Arc::new(Program {
            path: path.to_string_lossy().into_owned(),
            exe,
            windows,
            ours,
            program_files: self.program_files.iter().any(|d| under(&key, d)),
        });
        let mut cache = self.cache.lock().unwrap_or_else(PoisonError::into_inner);
        // Programs come and go; a cache this big is someone running thousands of different files
        if cache.len() > 5_000 {
            cache.clear();
        }
        cache.insert(key, (meta.len(), modified, Arc::clone(&program)));
        Some(program)
    }
}

#[derive(Debug)]
struct Tracked {
    program: Option<Arc<Program>>,
    session: u32,
    /// Its parent and exe name in the process list. Different in a later sweep: the pid was reused by another
    /// process between two sweeps, which is looked at afresh. `None` until a sweep has seen it (found by ETW).
    seen_as: Option<(u32, String)>,
    /// Already tried to end it (or logged that it would have been): don't again for this process.
    handled: bool,
}

/// The monitor's state; runs on its own thread (`run`).
#[derive(Debug)]
pub struct Monitor {
    facts: Arc<Facts>,
    enforcer: Arc<Mutex<Enforcer>>,
    mode: EndMode,
    tracked: HashMap<(u32, u64), Tracked>,
    /// ETW reports starts: sweep less often.
    etw: bool,
    /// Each signed-in session's account, so programs in a parent's own session are left alone.
    session_sids: SessionSids,
}

impl Monitor {
    pub fn new(facts: Arc<Facts>, enforcer: Arc<Mutex<Enforcer>>, mode: EndMode, etw: bool, session_sids: SessionSids) -> Self {
        Self { facts, enforcer, mode, tracked: HashMap::new(), etw, session_sids }
    }

    /// Sweeps every `SWEEP_EVERY` (`SWEEP_EVERY_WITH_ETW` with ETW), and handles each pid from `started` (ETW) as it
    /// arrives.
    pub fn run(mut self, started: &Receiver<u32>) {
        let every = if self.etw { SWEEP_EVERY_WITH_ETW } else { SWEEP_EVERY };
        let mut next_sweep = std::time::Instant::now();
        loop {
            match started.recv_timeout(next_sweep.saturating_duration_since(std::time::Instant::now())) {
                Ok(pid) => {
                    if let Some(start) = process::start_time(pid) {
                        self.track(pid, start, None);
                        self.enforce(&[(pid, start)]);
                    }
                }
                Err(RecvTimeoutError::Timeout) => {
                    self.sweep();
                    next_sweep = std::time::Instant::now() + every;
                }
                // No ETW: sweeping alone
                Err(RecvTimeoutError::Disconnected) => {
                    std::thread::sleep(every);
                    self.sweep();
                }
            }
        }
    }

    fn track(&mut self, pid: u32, start: u64, seen_as: Option<(u32, String)>) {
        if self.tracked.contains_key(&(pid, start)) {
            return;
        }
        let program = process::image_path(pid).and_then(|p| self.facts.program(&p));
        let session = process::session_of(pid).unwrap_or(0);
        self.tracked.insert((pid, start), Tracked { program, session, seen_as, handled: false });
    }

    fn sweep(&mut self) {
        let me = process::current_pid();
        let list = process::list();
        let running: HashMap<u32, (u32, String)> = list.iter().map(|p| (p.pid, (p.parent, p.exe.to_lowercase()))).collect();
        self.tracked.retain(|(pid, _), t| match (running.get(pid), &t.seen_as) {
            (None, _) => false,
            (Some(now), Some(before)) => now == before,
            (Some(now), None) => {
                t.seen_as = Some(now.clone());
                true
            }
        });
        let known: HashSet<u32> = self.tracked.keys().map(|(pid, _)| *pid).collect();
        let mut new: Vec<(u32, u64, (u32, String))> = list
            .iter()
            .filter(|p| p.pid > 4 && p.pid != me && !known.contains(&p.pid))
            .filter_map(|p| process::start_time(p.pid).map(|start| (p.pid, start, (p.parent, p.exe.to_lowercase()))))
            .collect();
        // Newest first, each checked as soon as it's known: after the service starts, hundreds of programs are new
        // and checking their signatures takes seconds, while the one the child just opened is the newest. What isn't
        // done within the budget waits for the next sweep, which looks at a fresh list again.
        new.sort_by_key(|n| std::cmp::Reverse(n.1));
        let budget = std::time::Instant::now() + SWEEP_EVERY;
        for (pid, start, seen_as) in new {
            if std::time::Instant::now() > budget {
                break;
            }
            self.track(pid, start, Some(seen_as));
            self.enforce(&[(pid, start)]);
        }
        let all: Vec<(u32, u64)> = self.tracked.keys().copied().collect();
        self.enforce(&all);
    }

    /// Checks `which` against the rules and ends what they say to end.
    fn enforce(&mut self, which: &[(u32, u64)]) {
        let sample = eguard_win::clock::sample();
        let mut to_end = Vec::new();
        let sids = self.session_sids.lock().unwrap_or_else(PoisonError::into_inner).clone();
        {
            let mut e = self.enforcer.lock().unwrap_or_else(PoisonError::into_inner);
            for key in which {
                let Some(t) = self.tracked.get(key) else { continue };
                let Some(program) = &t.program else { continue };
                // Programs in a session that isn't the child's are left alone. A session not (yet) known by its
                // account (the services' session 0, or one just signed in) is checked: the stricter choice
                if !e.applies_to(sids.get(&t.session).cloned().flatten().as_deref()) {
                    continue;
                }
                if let Decision::End { app, block } = e.check(program, sample) {
                    to_end.push((*key, app, block));
                }
            }
        }
        for ((pid, start), app, block) in to_end {
            let Some(t) = self.tracked.get_mut(&(pid, start)) else { continue };
            let path = t.program.as_ref().map(|p| p.path.clone()).unwrap_or_default();
            let file = Path::new(&path).file_name().map(|f| f.to_string_lossy().into_owned()).unwrap_or_default();
            let allowed = match &self.mode {
                EndMode::Real => true,
                EndMode::Sandbox(dir) => under(&path.to_lowercase(), dir),
                EndMode::DryRun => false,
            };
            if !allowed {
                if !t.handled {
                    log::info(&format!("would end {app} ({file}, pid {pid}): {block:?} (development: not in --sandbox)"));
                    t.handled = true;
                }
                continue;
            }
            let ended = process::end_tree(pid);
            if ended > 0 {
                log::info(&format!("ended {app} ({file}, pid {pid}, {ended} process(es)): {block:?}"));
                let session = t.session;
                self.tracked.remove(&(pid, start));
                self.enforcer.lock().unwrap_or_else(PoisonError::into_inner).ended(session, &app, block, eguard_win::clock::sample());
            } else if !t.handled {
                // Protected, or gone already. Logged once; the next sweep tries again
                log::warn(&format!("couldn't end {app} ({file}, pid {pid})"));
                t.handled = true;
            }
        }
    }
}

/// The folder `--sandbox` names, as the monitor compares paths.
pub fn sandbox_dir(dir: &Path) -> std::io::Result<String> {
    let full: PathBuf = std::fs::canonicalize(dir)?;
    // canonicalize gives `\\?\C:\...`; processes report plain paths
    let s = full.to_string_lossy();
    Ok(s.strip_prefix(r"\\?\").unwrap_or(&s).trim_end_matches('\\').to_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn programs_are_read_once_and_windows_own_are_recognized() {
        let facts = Facts::new();
        let notepad = PathBuf::from(std::env::var("SystemRoot").unwrap()).join(r"System32\notepad.exe");
        let p = facts.program(&notepad).unwrap();
        assert!(p.windows && !p.ours);
        assert!(Arc::ptr_eq(&p, &facts.program(&notepad).unwrap()));
        let me = std::env::current_exe().unwrap();
        let mine = facts.program(&me).unwrap();
        // The test binary isn't named eguard-*: not one of eGuard's programs
        assert!(!mine.ours && !mine.windows);
        assert!(under(r"c:\program files\x\y.exe", r"c:\program files"));
        assert!(!under(r"c:\program files2\y.exe", r"c:\program files"));
    }
}
