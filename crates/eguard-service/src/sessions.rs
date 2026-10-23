//! The agent in each signed-in session (spec sections 3 and 8).
//!
//! - One `eguard-agent session` per session, started by the service as the session's user (console mode: in its
//!   own session, as itself). One that ends while its session goes on was killed or crashed: it's started again and
//!   the parent hears `TAMPER` `AGENT_RESTARTED`, at most once per session every 10 minutes. The only exit that
//!   isn't news is the one the agent makes when Windows ends its session (`AGENT_EXIT_SESSION_ENDING`).
//! - A disconnected session (fast user switching) is still signed in: its account stays known and its agent and
//!   record stay, but nothing is counted or shown there until it's connected again.
//! - One pipe per session, `\\.\pipe\eguard-session-<id>`, open to SYSTEM and that session's logon SID. Requests are
//!   taken only from eGuard's agent executable running in that session; the session is the pipe's, never the
//!   message's.
//! - A session in use with no agent reporting (killed, hung) counts as in use: fail closed.
//! - Only the child's Windows accounts (chosen at pairing) get an agent, have their time counted and their programs
//!   ended; each session's account is published in `session_sids` for the monitor.
//! - The backstop for an overlay that keeps disappearing (spec section 8): while the screen is paused, an agent
//!   restarted three times in a minute, or silent for 20 seconds, gets its session disconnected (the lock screen).
//!   Not in console mode.

use crate::log;
use crate::monitor::Facts;
use eguard_core::enforce::{Ask, Enforcer, Seen};
use eguard_core::ipc::{self, Request, Response, SessionView};
use eguard_core::wire::{DeviceEvent, TamperKind};
use eguard_win::pipe::{self, PipeServer};
use eguard_win::process::{self, Child};
use eguard_win::{clock, security, session};
use std::collections::{HashMap, HashSet, VecDeque};
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

const CHECK_EVERY: Duration = Duration::from_secs(2);
/// An agent this quiet isn't reporting; its session's time counts as in use.
const SILENT_AFTER: Duration = Duration::from_secs(10);
/// While paused: this many agent starts within `RESTARTS_WINDOW`, or silence this long, disconnects the session.
const RESTARTS_TO_DISCONNECT: usize = 3;
const RESTARTS_WINDOW: Duration = Duration::from_secs(60);
const SILENT_TO_DISCONNECT: Duration = Duration::from_secs(20);
/// At most one `AGENT_RESTARTED` per session this often: an agent that fails at every start would otherwise send
/// one every few seconds. The rest are logged.
const ALERT_EVERY: Duration = Duration::from_secs(10 * 60);
/// After an agent exits because its session is ending, it isn't started again this long: a new one would only be
/// ended by the sign-out too, and that would read as tamper. If the session is still there after, it's started.
const SIGNOUT_GRACE: Duration = Duration::from_secs(20);

/// What the supervisor and the session pipes share.
pub struct Shared {
    pub enforcer: Arc<Mutex<Enforcer>>,
    pub facts: Arc<Facts>,
    /// `eguard-agent.exe` next to this service's exe.
    pub agent_exe: PathBuf,
    /// Console mode: agents start in this session as this user, with the development build's overlay.
    pub console: bool,
    /// When each session's agent last reported. Cleared when the session goes (its id comes back with another
    /// sign-in).
    heartbeats: Mutex<HashMap<u32, Instant>>,
    /// Signed-in sessions nobody is connected to (fast user switching): their agents get no screens and their time
    /// isn't counted.
    disconnected: Mutex<HashSet<u32>>,
    /// Each signed-in session's account SID (`None`: couldn't be read), for deciding whose rules apply.
    pub session_sids: SessionSids,
    /// Called after the child asks for something, so the sync loop sends it now.
    wake: Box<dyn Fn() + Send + Sync>,
}

impl std::fmt::Debug for Shared {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Shared").field("agent_exe", &self.agent_exe).field("console", &self.console).finish_non_exhaustive()
    }
}

impl Shared {
    pub fn new(
        enforcer: Arc<Mutex<Enforcer>>,
        facts: Arc<Facts>,
        session_sids: SessionSids,
        console: bool,
        wake: Box<dyn Fn() + Send + Sync>,
    ) -> Self {
        let agent_exe = std::env::current_exe().ok().and_then(|p| p.parent().map(|d| d.join("eguard-agent.exe"))).unwrap_or_default();
        Self {
            enforcer,
            facts,
            agent_exe,
            console,
            heartbeats: Mutex::new(HashMap::new()),
            disconnected: Mutex::new(HashSet::new()),
            session_sids,
            wake,
        }
    }

    fn is_disconnected(&self, id: u32) -> bool {
        self.disconnected.lock().unwrap_or_else(PoisonError::into_inner).contains(&id)
    }

    /// Whether the child's rules apply in session `id` (its account is one of the child's).
    fn applies(&self, id: u32) -> bool {
        let sid = self.session_sids.lock().unwrap_or_else(PoisonError::into_inner).get(&id).cloned().flatten();
        self.enforcer().applies_to(sid.as_deref())
    }

    fn enforcer(&self) -> std::sync::MutexGuard<'_, Enforcer> {
        self.enforcer.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Each signed-in session's account SID, shared with the monitor.
pub type SessionSids = Arc<Mutex<HashMap<u32, Option<String>>>>;

/// What the supervisor keeps per signed-in session, until it's signed out (not while it's only disconnected, so
/// its agent isn't started a second time when it comes back).
#[derive(Debug)]
struct Tracked {
    /// The logon SID its pipe admits.
    sid: String,
    agent: Option<Child>,
    starts: VecDeque<Instant>,
    /// When the session was first seen, and when its agent was last started: silence is measured from the latest
    /// of these and its last heartbeat, so an agent that never reports still trips the backstop.
    seen_at: Instant,
    started_at: Option<Instant>,
    /// The last `AGENT_RESTARTED` sent for this session.
    alerted_at: Option<Instant>,
    /// The agent exited because Windows was ending the session.
    ending_since: Option<Instant>,
}

impl Tracked {
    fn new(now: Instant) -> Self {
        Self {
            sid: String::new(),
            agent: None,
            starts: VecDeque::new(),
            seen_at: now,
            started_at: None,
            alerted_at: None,
            ending_since: None,
        }
    }
}

/// Runs forever on its own thread.
pub fn supervise(shared: &Arc<Shared>) {
    let mine = process::session_of(process::current_pid()).unwrap_or(0);
    let mut tracked: HashMap<u32, Tracked> = HashMap::new();
    // Pipes stay up once made: a session id comes back with the next sign-in
    let mut pipes: HashMap<u32, Arc<Mutex<Option<String>>>> = HashMap::new();
    loop {
        let sessions: Vec<session::Session> = if shared.console {
            let s = session::active().into_iter().find(|s| s.id == mine);
            vec![s.unwrap_or(session::Session {
                id: mine,
                user: String::new(),
                sid: security::current_user_sid().ok(),
                locked: false,
                connected: true,
            })]
        } else {
            session::signed_in()
        };
        let now = Instant::now();
        let sample = clock::sample();
        for s in &sessions {
            // Whose session it is, connected or not: a parent's session switched away from stays the parent's, so
            // the monitor keeps leaving its programs alone
            shared.session_sids.lock().unwrap_or_else(PoisonError::into_inner).insert(s.id, s.sid.clone());
            {
                let mut d = shared.disconnected.lock().unwrap_or_else(PoisonError::into_inner);
                if s.connected {
                    d.remove(&s.id)
                } else {
                    d.insert(s.id)
                };
            }
            let t = tracked.entry(s.id).or_insert_with(|| Tracked::new(now));
            // Nobody can be using a disconnected session: no agent checks, no time counted. Its record (and agent)
            // stay for when it comes back
            if !s.connected {
                continue;
            }
            let logon = if shared.console { security::current_logon_sid() } else { session::logon_sid(s.id) };
            match logon {
                Ok(sid) if t.sid != sid => {
                    let slot = pipes.entry(s.id).or_insert_with(|| {
                        let slot = Arc::new(Mutex::new(None));
                        let (sh, sl, id) = (Arc::clone(shared), Arc::clone(&slot), s.id);
                        let _ = std::thread::Builder::new().name(format!("session-{id}")).spawn(move || serve(&sh, id, &sl));
                        slot
                    });
                    *slot.lock().unwrap_or_else(PoisonError::into_inner) = Some(pipe::session_pipe_sddl(&sid));
                    t.sid = sid;
                    // A new sign-in in this session: it gets its agent now
                    t.ending_since = None;
                    // Wakes the pipe's waiting instance (made for the last sign-in) so the next one admits this one
                    let _ = pipe::connect(&ipc::session_pipe_name(s.id));
                }
                Ok(_) => {}
                // Without its logon there's no pipe for its agent; the agent is still started and the session's
                // time counted (silent agent), which is the stricter way to be wrong
                Err(e) => log::warn(&format!("session {}: couldn't read its logon ({e})", s.id)),
            }
            // Not one of the child's accounts (a parent's own on a family PC): no agent, nothing counted or ended
            if !shared.applies(s.id) {
                continue;
            }

            keep_agent(shared, s.id, t, now);

            // Nobody reporting from a session in use: its time counts
            let last = shared.heartbeats.lock().unwrap_or_else(PoisonError::into_inner).get(&s.id).copied();
            let silent = last.is_none_or(|at| now - at > SILENT_AFTER);
            if silent && !s.locked {
                let _ = shared.enforcer().heartbeat(s.id, Seen::Unknown, 0, sample);
            }

            // The backstop. Silence counts from the latest of the session's first sight, its agent's start and its
            // last heartbeat: an agent that never reports at all is as quiet as one that stopped
            let quiet_since = [Some(t.seen_at), t.started_at, last].into_iter().flatten().max().unwrap_or(now);
            let too_quiet = now - quiet_since > SILENT_TO_DISCONNECT;
            if !shared.console && !s.locked && (t.starts.len() >= RESTARTS_TO_DISCONNECT || too_quiet) {
                let paused = shared.enforcer().screen_paused(sample);
                if let Some(why) = paused {
                    log::warn(&format!("session {}: the screen is paused ({why:?}) but its overlay keeps going away; disconnecting", s.id));
                    if let Err(e) = session::disconnect(s.id) {
                        log::warn(&format!("couldn't disconnect session {}: {e}", s.id));
                    }
                    t.starts.clear();
                }
            }
        }
        // Signed out: everything about the session goes (its id comes back with a later sign-in)
        let live: Vec<u32> = sessions.iter().map(|s| s.id).collect();
        shared.session_sids.lock().unwrap_or_else(PoisonError::into_inner).retain(|id, _| live.contains(id));
        shared.heartbeats.lock().unwrap_or_else(PoisonError::into_inner).retain(|id, _| live.contains(id));
        shared.disconnected.lock().unwrap_or_else(PoisonError::into_inner).retain(|id| live.contains(id));
        tracked.retain(|id, _| {
            let keep = live.contains(id);
            if !keep {
                shared.enforcer().session_gone(*id);
            }
            keep
        });
        std::thread::sleep(CHECK_EVERY);
    }
}

/// Notices the session's agent ended and starts it again. Any end while the session goes on is the agent having
/// been ended (0 included: a child can end it with any code), except the code it exits with when Windows ends the
/// session; at most one alert per `ALERT_EVERY`.
fn keep_agent(shared: &Shared, id: u32, t: &mut Tracked, now: Instant) {
    if let Some(code) = t.agent.as_ref().and_then(Child::exit_code) {
        t.agent = None;
        if code == session::AGENT_EXIT_SESSION_ENDING {
            log::info(&format!("session {id}: the agent exited because the session is ending"));
            t.ending_since = Some(now);
        } else if t.alerted_at.is_none_or(|at| now - at >= ALERT_EVERY) {
            log::warn(&format!("session {id}: the agent was ended (exit code {code:#x}); starting it again"));
            t.alerted_at = Some(now);
            shared.enforcer().report(DeviceEvent::Tamper { kind: TamperKind::AgentRestarted });
            (shared.wake)();
        } else {
            log::warn(&format!(
                "session {id}: the agent was ended again (exit code {code:#x}); starting it again, the parent was told already"
            ));
        }
    }
    let waiting_for_signout = t.ending_since.is_some_and(|at| now - at < SIGNOUT_GRACE);
    if t.agent.is_none() && !waiting_for_signout {
        t.ending_since = None;
        match start_agent(shared, id) {
            Ok(child) => {
                log::info(&format!("session {id}: agent started (pid {})", child.pid));
                t.agent = Some(child);
                t.starts.push_back(now);
                t.started_at = Some(now);
            }
            Err(e) => log::warn(&format!("session {id}: couldn't start the agent ({e})")),
        }
    }
    t.starts.retain(|at| now - *at < RESTARTS_WINDOW);
}

fn start_agent(shared: &Shared, session_id: u32) -> std::io::Result<Child> {
    if shared.console {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        let child = std::process::Command::new(&shared.agent_exe).args(["session", "--dev"]).creation_flags(CREATE_NO_WINDOW).spawn()?;
        Ok(Child::from_std(child))
    } else {
        session::launch(session_id, &shared.agent_exe, "session")
    }
}

/// Serves one session's pipe. Waits for its first sign-in's SDDL; each new instance uses the newest.
fn serve(shared: &Arc<Shared>, id: u32, sddl: &Mutex<Option<String>>) {
    let name = ipc::session_pipe_name(id);
    let current = || sddl.lock().unwrap_or_else(PoisonError::into_inner).clone();
    let first = loop {
        if let Some(s) = current() {
            break s;
        }
        std::thread::sleep(Duration::from_millis(200));
    };
    let mut server = match PipeServer::new(&name, &first) {
        Ok(s) => s,
        Err(e) => {
            log::error(&format!("{name}: {e}"));
            return;
        }
    };
    let mut in_use = first;
    loop {
        if let Some(s) = current().filter(|s| *s != in_use) {
            if let Err(e) = server.set_sddl(&s) {
                log::warn(&format!("{name}: {e}"));
            }
            in_use = s;
        }
        let conn = match server.accept() {
            Ok(c) => c,
            Err(e) => {
                // The name taken by someone else first is worth knowing about; retry slowly
                log::warn(&format!("{name}: {e}"));
                std::thread::sleep(Duration::from_secs(5));
                continue;
            }
        };
        let sh = Arc::clone(shared);
        let _ = std::thread::Builder::new().name("session-client".into()).spawn(move || client(&sh, id, conn));
    }
}

fn client(shared: &Shared, id: u32, mut conn: std::fs::File) {
    let response = match ipc::read_line(&mut conn) {
        Ok(Some(line)) => match ipc::decode::<Request>(&line) {
            Ok(req) => handle(shared, id, &conn, &req),
            Err(e) => Response::Error { message: e.to_string() },
        },
        // The supervisor waking the pipe, or an agent that went away
        Ok(None) => return,
        Err(e) => Response::Error { message: e.to_string() },
    };
    let _ = conn.write_all(&ipc::encode(&response));
    let _ = conn.sync_all();
}

fn same_file(a: &std::path::Path, b: &std::path::Path) -> bool {
    a.to_string_lossy().eq_ignore_ascii_case(&b.to_string_lossy())
}

fn handle(shared: &Shared, id: u32, conn: &std::fs::File, req: &Request) -> Response {
    // Only eGuard's agent, in this session
    let client = pipe::client_pid(conn);
    let genuine = client.is_some_and(|pid| {
        process::session_of(pid) == Some(id) && process::image_path(pid).is_some_and(|p| same_file(&p, &shared.agent_exe))
    });
    let Some(client) = client.filter(|_| genuine) else {
        return Response::Error { message: "Only eGuard's own app can use this.".into() };
    };
    let sample = clock::sample();
    match req {
        &Request::Heartbeat { .. } if !shared.applies(id) => Response::Session(SessionView::default()),
        // Switched away from: the agent is alive (so it isn't silent), but nobody is there to see a screen or use time
        &Request::Heartbeat { .. } if shared.is_disconnected(id) => {
            shared.heartbeats.lock().unwrap_or_else(PoisonError::into_inner).insert(id, Instant::now());
            Response::Session(SessionView::default())
        }
        &Request::Heartbeat { foreground_pid, idle_ms } => {
            let program = foreground_pid
                .filter(|pid| *pid != client && process::session_of(*pid) == Some(id))
                .and_then(process::image_path)
                .and_then(|p| shared.facts.program(&p));
            let seen = match (foreground_pid, &program) {
                (Some(pid), _) if pid == client => Seen::Ours,
                (_, Some(p)) => Seen::Program(p),
                _ => Seen::Nothing,
            };
            shared.heartbeats.lock().unwrap_or_else(PoisonError::into_inner).insert(id, Instant::now());
            Response::Session(shared.enforcer().heartbeat(id, seen, idle_ms, sample))
        }
        // The enforcer's lock is let go before waking the loop (lock order: engine, then enforcer)
        &Request::AskParent { notice } => {
            let result = shared.enforcer().ask(id, Ask::Parent { notice }, sample);
            asked(shared, result)
        }
        &Request::AskTime { notice } => {
            let result = shared.enforcer().ask(id, Ask::Time { notice }, sample);
            asked(shared, result)
        }
        Request::Pair { .. } | Request::Status | Request::Scan | Request::Accounts { .. } => {
            Response::Error { message: "That isn't asked on this pipe.".into() }
        }
    }
}

fn asked(shared: &Shared, result: Result<String, String>) -> Response {
    match result {
        Ok(message) => {
            (shared.wake)();
            Response::Asked { message }
        }
        Err(message) => Response::Error { message },
    }
}
