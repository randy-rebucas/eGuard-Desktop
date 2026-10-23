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
use eguard_win::apps::FileIdentity;
use eguard_win::{apps, authenticode, process};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

/// How often the process list is swept without ETW: a blocked program is gone within about this long.
pub const SWEEP_EVERY: Duration = Duration::from_secs(1);
/// With ETW reporting starts as they happen, the sweep only re-checks running programs (limits running out).
pub const SWEEP_EVERY_WITH_ETW: Duration = Duration::from_secs(2);
/// Most ETW starts handled between two looks at the clock: a burst of starts mustn't hold the sweep off.
const STARTS_AT_ONCE: usize = 64;
/// How long a process's program may stay unreadable before it's checked as an unknown program instead.
const UNREADABLE_FOR: Duration = Duration::from_secs(5);

/// Folders under `%SystemRoot%` a standard account can write to (or could on some Windows versions), relative to
/// it. A Microsoft-signed program copied into one of them isn't "Windows' own": anyone could have put it there.
const WRITABLE_UNDER_WINDOWS: &[&str] = &[
    "temp",
    "tasks",
    "tracing",
    "debug",
    r"registration\crmlog",
    r"pla\reports",
    r"pla\rules",
    r"pla\templates",
    r"system32\tasks",
    r"system32\tasks_migrated",
    r"system32\com\dmp",
    r"system32\fxstmp",
    r"system32\spool\drivers\color",
    r"system32\spool\printers",
    r"system32\spool\servers",
    r"system32\microsoft\crypto\rsa\machinekeys",
    r"syswow64\tasks",
    r"syswow64\com\dmp",
    r"syswow64\fxstmp",
    r"syswow64\microsoft\crypto\rsa\machinekeys",
];

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

/// A checked program, with the identity of the file it was checked as.
type Checked = (FileIdentity, Arc<Program>);

/// What eGuard knows about each executable, cached by path and the file's identity (volume, file id, size and
/// modification time: checking a signature takes milliseconds; the sweep runs every second).
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

/// Whether `path` (lower case) is where Windows' own programs live: under `system_root` and not in one of its
/// folders a standard account can write to. A path that could spell a folder some other way (a short `~` name, a
/// stream, `..`) doesn't count.
fn windows_place(path: &str, system_root: &str) -> bool {
    if !under(path, system_root) {
        return false;
    }
    let rel = &path[system_root.len() + 1..];
    if rel.contains('~') || rel.contains(':') {
        return false;
    }
    // Windows ignores trailing dots and spaces in a folder's name
    let parts: Vec<&str> = rel.split('\\').map(|c| c.trim_end_matches(['.', ' '])).collect();
    if parts.iter().any(|c| c.is_empty() || *c == "." || *c == "..") {
        return false;
    }
    !WRITABLE_UNDER_WINDOWS.iter().any(|w| {
        let w: Vec<&str> = w.split('\\').collect();
        parts.len() > w.len() && parts[..w.len()] == w[..]
    })
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

    /// The program at `path`, checked once per file and version of it. Another file put at the same path (even
    /// with the same size and time) is checked afresh.
    pub fn program(&self, path: &Path) -> Option<Arc<Program>> {
        let id = apps::file_identity(path)?;
        let key = lower(path);
        if let Some((was, p)) = self.cache.lock().unwrap_or_else(PoisonError::into_inner).get(&key)
            && *was == id
        {
            return Some(Arc::clone(p));
        }
        let windows = windows_place(&key, &self.system_root) && authenticode::microsoft_signed(path);
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
        // Kept only when the file is still the one identified before it was read (not swapped meanwhile)
        if apps::file_identity(path) == Some(id) {
            let mut cache = self.cache.lock().unwrap_or_else(PoisonError::into_inner);
            // Programs come and go; a cache this big is someone running thousands of different files
            if cache.len() > 5_000 {
                cache.clear();
            }
            cache.insert(key, (id, Arc::clone(&program)));
        }
        Some(program)
    }
}

#[derive(Debug)]
struct Tracked {
    /// What it runs. `None` while its path or file can't be read, which is tried again on each check.
    program: Option<Arc<Program>>,
    /// `program` is the stand-in for one that couldn't be read (`unreadable`), and reading it is still tried.
    stand_in: bool,
    /// When eGuard first saw it, for giving up on reading its program.
    since: Instant,
    /// Its session; `None` until it could be read (tried again on each check).
    session: Option<u32>,
    /// Its parent and exe name in the process list. Different in a later sweep: the pid was reused by another
    /// process between two sweeps, which is looked at afresh. `None` until a sweep has seen it (found by ETW).
    seen_as: Option<(u32, String)>,
    /// Already tried to end it (or logged that it would have been): don't again for this process.
    handled: bool,
}

/// What a process whose program can't be read is checked as: an unknown, unsigned program outside Program Files,
/// the strictest reading (App Approval applies to it). Reading it from outside fails for very few processes, and
/// a program that hides its path mustn't be let through for that.
fn unreadable(path: Option<&Path>, exe: Option<&str>) -> Program {
    let file_name = path
        .and_then(Path::file_name)
        .map(|f| f.to_string_lossy().to_lowercase())
        .or_else(|| exe.map(str::to_lowercase))
        .filter(|f| !f.is_empty())
        .unwrap_or_else(|| "unknown.exe".into());
    Program {
        path: path.map_or_else(|| file_name.clone(), |p| p.to_string_lossy().into_owned()),
        exe: eguard_core::scan::ExeFacts { file_name, ..Default::default() },
        windows: false,
        ours: false,
        program_files: false,
    }
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
    /// arrives. The sweep runs on time however many starts arrive: they're taken a bounded number at a time.
    pub fn run(mut self, started: &Receiver<u32>) {
        let every = if self.etw { SWEEP_EVERY_WITH_ETW } else { SWEEP_EVERY };
        let mut next_sweep = Instant::now();
        loop {
            if Instant::now() >= next_sweep {
                self.sweep();
                next_sweep = Instant::now() + every;
            }
            match started.recv_timeout(next_sweep.saturating_duration_since(Instant::now())) {
                Ok(pid) => {
                    self.started(pid);
                    for pid in started.try_iter().take(STARTS_AT_ONCE - 1) {
                        self.started(pid);
                    }
                }
                Err(RecvTimeoutError::Timeout) => {}
                // No ETW: sweeping alone
                Err(RecvTimeoutError::Disconnected) => std::thread::sleep(next_sweep.saturating_duration_since(Instant::now())),
            }
        }
    }

    /// A start ETW reported.
    fn started(&mut self, pid: u32) {
        if let Some(start) = process::start_time(pid) {
            self.track(pid, start, None);
            self.enforce(&[(pid, start)]);
        }
    }

    fn track(&mut self, pid: u32, start: u64, seen_as: Option<(u32, String)>) {
        self.tracked.entry((pid, start)).or_insert_with(|| Tracked {
            program: None,
            stand_in: false,
            since: Instant::now(),
            session: None,
            seen_as,
            handled: false,
        });
    }

    /// Reads what `key` runs and its session, where that hasn't worked yet. After `UNREADABLE_FOR` of failing, its
    /// program is checked as an unknown one (`unreadable`) until it can be read.
    fn refresh(&mut self, key: (u32, u64)) {
        let Some(t) = self.tracked.get_mut(&key) else { return };
        let (pid, start) = key;
        if t.session.is_none() {
            t.session = process::session_of(pid);
        }
        if t.program.is_some() && !t.stand_in {
            return;
        }
        let path = process::image_path(pid);
        // Read by pid: believed only while the pid is still this process (the next sweep drops a reused one)
        if path.is_some() && process::start_time(pid) != Some(start) {
            return;
        }
        match path.as_deref().and_then(|p| self.facts.program(p)) {
            Some(p) => {
                t.program = Some(p);
                t.stand_in = false;
            }
            None if t.program.is_none() && t.since.elapsed() >= UNREADABLE_FOR => {
                let exe = t.seen_as.as_ref().map(|(_, exe)| exe.as_str());
                let p = unreadable(path.as_deref(), exe);
                log::warn(&format!("couldn't read pid {pid}'s program ({}); checking it as an unknown program", p.path));
                t.program = Some(Arc::new(p));
                t.stand_in = true;
            }
            None => {}
        }
    }

    /// Forgets processes that are gone, or whose pid now belongs to another process. `running` is the process
    /// list: pid → (parent, exe name in lower case).
    fn forget_gone(&mut self, running: &HashMap<u32, (u32, String)>) {
        self.tracked.retain(|&(pid, start), t| match (running.get(&pid), &t.seen_as) {
            (None, _) => false,
            (Some(now), Some(before)) => now == before,
            // Found by ETW: it's the same process only if it started when ETW's did
            (Some(now), None) => {
                let same = process::start_time(pid) == Some(start);
                if same {
                    t.seen_as = Some(now.clone());
                }
                same
            }
        });
    }

    fn sweep(&mut self) {
        let me = process::current_pid();
        let list = process::list();
        let running: HashMap<u32, (u32, String)> = list.iter().map(|p| (p.pid, (p.parent, p.exe.to_lowercase()))).collect();
        self.forget_gone(&running);
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
        let budget = Instant::now() + SWEEP_EVERY;
        for (pid, start, seen_as) in new {
            if Instant::now() > budget {
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
        for key in which {
            self.refresh(*key);
        }
        let sample = eguard_win::clock::sample();
        let mut to_end = Vec::new();
        let sids = self.session_sids.lock().unwrap_or_else(PoisonError::into_inner).clone();
        {
            let mut e = self.enforcer.lock().unwrap_or_else(PoisonError::into_inner);
            for key in which {
                let Some(t) = self.tracked.get(key) else { continue };
                let Some(program) = &t.program else { continue };
                // Session 0 is the services' (no one signs in there): never the child's, and ending a parent's
                // service or driver tool there would be eGuard breaking the computer
                if t.session == Some(0) {
                    continue;
                }
                // Programs in a session that isn't the child's are left alone. A session not (yet) known by its
                // account (one just signed in, or a process whose session couldn't be read) is checked: the
                // stricter choice
                let sid = t.session.and_then(|s| sids.get(&s).cloned().flatten());
                if !e.applies_to(sid.as_deref()) {
                    continue;
                }
                if let Decision::End { app, block } = e.check(program, sample) {
                    to_end.push((*key, app, block));
                }
            }
        }
        let mode = &self.mode;
        // Console mode's sandbox, asked for every process of a tree: one outside it is never ended
        let keep = |p: u32| match mode {
            EndMode::Real => true,
            EndMode::Sandbox(dir) => process::image_path(p).is_some_and(|path| under(&lower(&path), dir)),
            EndMode::DryRun => false,
        };
        for ((pid, start), app, block) in to_end {
            let Some(t) = self.tracked.get_mut(&(pid, start)) else { continue };
            let path = t.program.as_ref().map(|p| p.path.clone()).unwrap_or_default();
            let file = Path::new(&path).file_name().map(|f| f.to_string_lossy().into_owned()).unwrap_or_default();
            let allowed = match mode {
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
            let ended = process::end_tree(pid, start, keep);
            if ended > 0 {
                log::info(&format!("ended {app} ({file}, pid {pid}, {ended} process(es)): {block:?}"));
                let session = t.session;
                self.tracked.remove(&(pid, start));
                if let Some(session) = session {
                    self.enforcer.lock().unwrap_or_else(PoisonError::into_inner).ended(session, &app, block, eguard_win::clock::sample());
                }
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

    fn monitor() -> Monitor {
        Monitor::new(Arc::new(Facts::new()), Arc::new(Mutex::new(Enforcer::default())), EndMode::DryRun, false, SessionSids::default())
    }

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

    #[test]
    fn folders_anyone_can_write_under_windows_are_not_windows_own() {
        let root = r"c:\windows";
        for yes in [r"c:\windows\notepad.exe", r"c:\windows\system32\notepad.exe", r"c:\windows\system32\spool\spoolsv.exe"] {
            assert!(windows_place(yes, root), "{yes}");
        }
        for no in [
            r"c:\windows\temp\notepad.exe",
            r"c:\windows\tasks\x\notepad.exe",
            r"c:\windows\tracing\a.exe",
            r"c:\windows\debug\a.exe",
            r"c:\windows\registration\crmlog\a.exe",
            r"c:\windows\system32\tasks\a.exe",
            r"c:\windows\syswow64\tasks\a.exe",
            r"c:\windows\system32\spool\drivers\color\a.exe",
            r"c:\windows\system32\microsoft\crypto\rsa\machinekeys\a.exe",
            r"c:\windows\syswow64\microsoft\crypto\rsa\machinekeys\a.exe",
            r"c:\windows\temp.\a.exe",
            r"c:\windows\regist~1\crmlog\a.exe",
            r"c:\windows\tasks:a.exe",
            r"c:\windows\system32\..\temp\a.exe",
            r"c:\windows2\notepad.exe",
            r"c:\users\x\notepad.exe",
        ] {
            assert!(!windows_place(no, root), "{no}");
        }
        // The whole path through Facts, which lower-cases it first
        let facts = Facts::new();
        let temp = PathBuf::from(std::env::var("SystemRoot").unwrap()).join(r"TEMP\Notepad.exe");
        assert!(!windows_place(&lower(&temp), &facts.system_root));
    }

    #[test]
    fn a_reused_pid_is_not_adopted_and_an_unreadable_program_is_checked_after_a_while() {
        let mut m = monitor();
        let me = process::current_pid();
        let start = process::start_time(me).unwrap();
        m.track(me, start, None);
        // Another process's start (its pid since reused by this one): forgotten at the next sweep
        m.track(me, start - 1, None);
        let running = HashMap::from([(me, (0, "me.exe".to_owned()))]);
        m.forget_gone(&running);
        assert_eq!(m.tracked.keys().copied().collect::<Vec<_>>(), vec![(me, start)]);
        assert_eq!(m.tracked[&(me, start)].seen_as, Some((0, "me.exe".to_owned())));

        // A process whose program can't be read: nothing yet, then an unknown program
        let ghost = (0xFFFF_FFF0, 1);
        m.track(ghost.0, ghost.1, Some((0, "Hidden.exe".into())));
        m.refresh(ghost);
        assert!(m.tracked[&ghost].program.is_none());
        m.tracked.get_mut(&ghost).unwrap().since -= UNREADABLE_FOR;
        m.refresh(ghost);
        let t = &m.tracked[&ghost];
        let p = t.program.as_ref().unwrap();
        assert!(t.stand_in && !p.windows && !p.ours && !p.program_files && p.exe.signer.is_none());
        assert_eq!((p.exe.file_name.as_str(), p.path.as_str()), ("hidden.exe", "hidden.exe"));
        // Its session couldn't be read either: checked (not taken for session 0)
        assert_eq!(t.session, None);
    }
}
