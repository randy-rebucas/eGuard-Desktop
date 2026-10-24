//! The service's work, the same in console mode and as a Windows service:
//!
//! - the sync loop (this thread): `/sync`, the catalog, sending the queue;
//! - the pipe (`\\.\pipe\eguard`): pairing, status, scans;
//! - scans, on a thread of their own when due;
//! - the process monitor (`monitor`): ending what the rules say to end;
//! - the session supervisor (`sessions`): an agent and a pipe per signed-in session;
//! - the browsers' policies (`web`), after every tick;
//! - eGuard's own removal (spec section 10), once eGuard's signed command or a right code authorized it;
//! - eGuard's own update (spec section 10, `update`), on a thread of its own when eGuard offers a newer version.
//!
//! The engine (sync state) and the enforcer (rules in force, usage) each sit behind their own lock, so ending a
//! program never waits for a network call. After each tick the loop hands the enforcer the newest rules, and takes
//! its events and usage into the queue. Lock order, where both are held: engine, then enforcer.

use crate::log;
use crate::monitor::{self, EndMode, Facts, Monitor};
use crate::sessions::{self, Shared};
use crate::store::Store;
use crate::web::Browsers;
use eguard_core::accounts::AccountChoice;
use eguard_core::api::{Api, ServerUrl};
use eguard_core::enforce::{Enforcer, Memo};
use eguard_core::engine::{DeviceInfo, Engine, Note, Removal};
use eguard_core::ipc::{self, AccountInfo, Request, Response};
use eguard_core::report::{AVAILABLE, Capabilities};
use eguard_core::scan::{self, Classifier, ExeCache};
use eguard_core::signature::TrustedKeys;
use eguard_core::update::Manifest;
use eguard_core::usage::UsageLedger;
use eguard_core::wire::TamperKind;
use eguard_win::apps;
use eguard_win::{clock, http::WinHttp, pipe::PipeServer, sysinfo};
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock, PoisonError};
use std::time::{Duration, Instant};

/// This build's version (`update::VERSION`).
pub const APP_VERSION: &str = eguard_core::update::VERSION;

/// How the service runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mode {
    /// The Windows service, as SYSTEM: agents in every session, programs ended for real.
    Service,
    /// A console on a developer's PC: an agent in this session only; programs ended only inside `sandbox`, and with
    /// none, only logged.
    Console { sandbox: Option<PathBuf> },
}

/// What this build can do (spec section 11). The AVAILABLE protections are reported applied only by the service,
/// which ends programs anywhere. Console mode ends them only inside `--sandbox` (or not at all), so it reports them
/// as not applied, which is the truth: the parent mustn't be told a developer's PC is protected. Removal protection
/// is what `lockdown::status` found at start (the engine also turns it off while a child's account is an
/// administrator). Web filtering starts off and is decided after the browsers are set up (`apply_web`), before the
/// first sync.
fn capabilities(enforcing: bool, locked: Result<(), String>) -> Capabilities {
    Capabilities {
        enforced: if enforcing { AVAILABLE.into_iter().collect() } else { std::collections::BTreeSet::new() },
        uninstall_protection: locked,
        web: Err("eGuard hasn't set up its browser extension on this computer yet.".into()),
    }
}

/// How often the service tries again for the admin pipe's name while something else holds it.
const PIPE_RETRY: Duration = Duration::from_secs(5);

/// What went wrong creating the admin pipe, in words. `FILE_FLAG_FIRST_PIPE_INSTANCE` answers "access denied" when
/// another process already holds the name; any other error is something else and says so.
fn pipe_error(e: &std::io::Error) -> String {
    if e.kind() == std::io::ErrorKind::PermissionDenied {
        format!("couldn't create {} ({e}); is another eGuard running?", ipc::PIPE_NAME)
    } else {
        format!("couldn't create {} ({e})", ipc::PIPE_NAME)
    }
}

/// Creates the admin pipe's first instance, trying every `PIPE_RETRY` until the name is free. Only the admin tools
/// wait meanwhile: enforcement is already running.
fn claim_pipe(server: &mut PipeServer) -> eguard_win::pipe::Pending {
    let mut said = false;
    loop {
        match server.create() {
            Ok(p) => {
                if said {
                    log::info(&format!("{} is eGuard's now", ipc::PIPE_NAME));
                }
                return p;
            }
            Err(e) => {
                // Loud once, then quiet: a program squatting on the name would otherwise fill the log
                if !said {
                    log::error(&format!("{}; pairing and status wait until it's free, protection carries on", pipe_error(&e)));
                    said = true;
                }
                std::thread::sleep(PIPE_RETRY);
            }
        }
    }
}

#[derive(Debug)]
pub struct Options {
    pub store: Store,
    pub server: ServerUrl,
    /// SDDL for the pipe: who may connect.
    pub pipe_sddl: String,
    pub mode: Mode,
}

#[derive(Debug)]
struct Inner {
    engine: Engine,
    /// Set by the pipe after pairing, so the loop syncs at once instead of sleeping out its timeout.
    woken: bool,
}

#[derive(Debug)]
pub struct Runner {
    inner: Mutex<Inner>,
    wake: Condvar,
    stop: AtomicBool,
    store: Store,
    info: DeviceInfo,
    pipe_sddl: String,
    mode: Mode,
    enforcer: Arc<Mutex<Enforcer>>,
    facts: Arc<Facts>,
    /// Something to send now (the child asked for something): set without the engine's lock, which a sync may hold.
    poked: AtomicBool,
    /// A scan is running; the loop doesn't start another.
    scanning: AtomicBool,
    /// An update is being downloaded or installed.
    updating: AtomicBool,
    /// This version's health went to the guard (or no update waits for it).
    health_noted: AtomicBool,
    /// Launcher folders the last scan found, for the watcher.
    watch_dirs: Arc<Mutex<Vec<PathBuf>>>,
    browsers: Browsers,
    /// What the session pipes share, once enforcement has started (removal tells the agents through it).
    shared: OnceLock<Arc<Shared>>,
    /// eGuard has removed itself: nothing is saved again.
    removed: AtomicBool,
    /// `Engine::may_be_removed` as of the loop's last look, for the service's stop control.
    may_stop: AtomicBool,
    /// A stop request was refused since the loop last looked.
    stop_denied: AtomicBool,
    /// Removal protection was in place at start (`lockdown::status`): the guard is kept running.
    locked: bool,
    /// The program files, held open so they can't be deleted, replaced or renamed while the service runs.
    _held: Vec<std::fs::File>,
}

fn log_notes(engine: &mut Engine) {
    for n in engine.take_notes() {
        match n {
            Note::Info(m) => log::info(&m),
            Note::Warn(m) => log::warn(&m),
        }
    }
}

impl Runner {
    pub fn new(opts: Options) -> Result<Arc<Self>, String> {
        let keys = TrustedKeys::builtin().map_err(|e| format!("the built-in signing key is broken: {e}"))?;
        let transport = WinHttp::new(&format!("eGuard-Windows/{APP_VERSION}")).map_err(|e| e.to_string())?;
        let api = Api::new(opts.server, Box::new(transport));
        let (state, secrets) = opts.store.load();
        let enforcing = opts.mode == Mode::Service;
        let browsers =
            Browsers::new(if enforcing { eguard_win::browsers::Place::machine() } else { eguard_win::browsers::Place::development() });
        let locked = match opts.mode {
            Mode::Service => crate::lockdown::status(),
            Mode::Console { .. } => Err("eGuard runs in development mode on this computer, which installs no removal protection.".into()),
        };
        if let (Mode::Service, Err(e)) = (&opts.mode, &locked) {
            log::warn(e);
        }
        let held = if locked.is_ok() {
            crate::lockdown::PROGRAMS.iter().filter_map(|p| eguard_win::files::hold(&crate::lockdown::install_dir().join(p)).ok()).collect()
        } else {
            Vec::new()
        };
        let mut engine = Engine::new(state, secrets, api, keys, capabilities(enforcing, locked.clone()));
        let may_stop = engine.may_be_removed();
        log_notes(&mut engine);
        // Usage and what enforcement remembers move to the enforcer; they're copied back at every save
        let mut enforcer = Enforcer::new(std::mem::take(&mut engine.data.usage), std::mem::take(&mut engine.data.enforce));
        enforcer.update(engine.enforce_inputs());
        let info = DeviceInfo::new(
            &sysinfo::computer_name().unwrap_or_default(),
            &sysinfo::model(),
            &sysinfo::os_version(),
            APP_VERSION,
            sysinfo::battery(),
        );
        Ok(Arc::new(Self {
            inner: Mutex::new(Inner { engine, woken: false }),
            wake: Condvar::new(),
            stop: AtomicBool::new(false),
            store: opts.store,
            info,
            pipe_sddl: opts.pipe_sddl,
            mode: opts.mode,
            enforcer: Arc::new(Mutex::new(enforcer)),
            facts: Arc::new(Facts::new()),
            poked: AtomicBool::new(false),
            scanning: AtomicBool::new(false),
            updating: AtomicBool::new(false),
            health_noted: AtomicBool::new(false),
            watch_dirs: Arc::new(Mutex::new(Vec::new())),
            browsers,
            shared: OnceLock::new(),
            removed: AtomicBool::new(false),
            may_stop: AtomicBool::new(may_stop),
            stop_denied: AtomicBool::new(false),
            locked: locked.is_ok(),
            _held: held,
        }))
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        // A panic elsewhere mustn't stop protection: the engine's state is still the last consistent one
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn enforcer(&self) -> std::sync::MutexGuard<'_, Enforcer> {
        self.enforcer.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub fn request_stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
        self.wake.notify_all();
    }

    /// Wakes the loop now, without waiting for the engine's lock.
    fn poke(&self) {
        self.poked.store(true, Ordering::SeqCst);
        self.wake.notify_all();
    }

    fn save(&self, inner: &mut Inner) {
        // Removed: a state written now would be a paired computer's again
        if self.removed.load(Ordering::SeqCst) {
            return;
        }
        {
            let e = self.enforcer();
            inner.engine.data.usage = e.ledger().clone();
            inner.engine.data.enforce = e.memo().clone();
        }
        if let Err(e) = self.store.save_state(&inner.engine.data) {
            log::error(&format!("saving state.json failed: {e}"));
        }
    }

    /// Moves enforcement's events and usage into the queue. True when there was something.
    fn collect_enforcement(&self, inner: &mut Inner) -> bool {
        let sample = clock::sample();
        let (events, usage) = {
            let mut e = self.enforcer();
            (e.take_events(), e.usage_due(sample))
        };
        if events.is_empty() && usage.is_empty() {
            return false;
        }
        let now = inner.engine.now_ms(sample);
        inner.engine.queue_enforcement(events, usage, now);
        true
    }

    /// Runs until `request_stop`.
    pub fn run(self: &Arc<Self>) -> Result<(), String> {
        // Enforcement first: nothing that goes wrong with the admin pipe may leave the child's rules unenforced
        self.start_enforcement()?;
        self.start_watcher();
        self.start_pipe()?;

        {
            let mut inner = self.lock();
            log::info(&format!(
                "eGuard {APP_VERSION} for {} ({}), server {}, data in {}",
                self.info.name,
                self.info.os_version,
                inner.engine.server(),
                self.store.dir().display()
            ));
            if !inner.engine.is_paired() {
                log::info("not paired yet: run `eguard-agent pair` and type the code from the parent dashboard");
            }
            if inner.engine.on_start(clock::sample()) {
                self.save(&mut inner);
            }
            // Ended without being asked to in this same boot (killed, or crashed): the parent hears (spec section 10)
            if self.mode == Mode::Service && self.store.mark_running(clock::boot_id()) == Some(clock::boot_id()) {
                log::warn("eGuard's service ended without being asked to and was started again");
                let now = inner.engine.now_ms(clock::sample());
                if inner.engine.tamper(TamperKind::ServiceRestarted, now) {
                    self.save(&mut inner);
                }
            }
            // The guard put this version back after an update that didn't work: that version isn't tried again
            if self.installs_updates() {
                crate::update::show_version(APP_VERSION);
                if let Some(o) = crate::update::take_outcome() {
                    inner.engine.update_rolled_back(&o);
                    self.save(&mut inner);
                }
            }
            // Safe Mode is a way around eGuard (spec section 10); the parent hears of it when the computer is back
            // online
            if eguard_win::sysinfo::safe_mode() {
                log::warn("Windows was started in Safe Mode");
                let now = inner.engine.now_ms(clock::sample());
                if inner.engine.tamper(TamperKind::SafeMode, now) {
                    self.save(&mut inner);
                }
            }
            log_notes(&mut inner.engine);
            // Before the first sync, so its report already says whether web filtering holds
            self.apply_web(&mut inner);
        }

        let mut next_tick = Instant::now();
        while !self.stop.load(Ordering::SeqCst) {
            let poked = self.poked.swap(false, Ordering::SeqCst);
            let mut inner = self.lock();
            // Enforcement's events and usage are looked at every 10 s; a tick (sync, send, save) runs when it's due,
            // when woken, or when there's something to send
            let queued = self.collect_enforcement(&mut inner);
            if self.stop_denied.swap(false, Ordering::SeqCst) {
                log::warn("a stop request was refused: eGuard is protecting this computer");
                let now = inner.engine.now_ms(clock::sample());
                inner.engine.tamper(TamperKind::ServiceStopDenied, now);
                inner.woken = true;
            }
            self.may_stop.store(inner.engine.may_be_removed(), Ordering::SeqCst);
            if queued || poked || inner.woken || Instant::now() >= next_tick {
                let info = DeviceInfo { battery: sysinfo::battery(), ..self.info.clone() };
                let tick = inner.engine.tick(clock::sample(), &info);
                // The Windows accounts: a new one is news, and the list goes to /report when it changed
                let now = inner.engine.now_ms(clock::sample());
                inner.engine.observe_accounts(&eguard_win::accounts::list(), &info, now);
                log_notes(&mut inner.engine);
                if self.removal(&mut inner) {
                    break;
                }
                if self.locked {
                    crate::lockdown::keep_guard_running();
                }
                self.enforcer().update(inner.engine.enforce_inputs());
                let web_changed = self.apply_web(&mut inner);
                if tick.changed || web_changed {
                    self.save(&mut inner);
                    // Synced and saved: a new version is healthy, and the guard keeps it
                    if self.installs_updates() && inner.engine.has_synced() && !self.health_noted.load(Ordering::SeqCst) {
                        self.health_noted.store(crate::update::note_health(APP_VERSION), Ordering::SeqCst);
                    }
                }
                self.start_scan_if_due(&mut inner);
                self.start_update_if_offered(&mut inner);
                next_tick = Instant::now() + Duration::from_millis(tick.sleep_ms);
            }
            inner.woken = false;
            let sleep = next_tick.saturating_duration_since(Instant::now()).min(Duration::from_secs(10));
            let (_inner, _) = self
                .wake
                .wait_timeout_while(inner, sleep, |i| !i.woken && !self.poked.load(Ordering::SeqCst) && !self.stop.load(Ordering::SeqCst))
                .unwrap_or_else(PoisonError::into_inner);
        }
        let mut inner = self.lock();
        self.save(&mut inner);
        self.store.clear_running();
        log::info("stopped");
        Ok(())
    }

    /// Acts on an authorized removal: the server is told first (`Engine::removal`), then eGuard removes itself. True
    /// when it did, and the loop ends.
    fn removal(&self, inner: &mut Inner) -> bool {
        let now = inner.engine.now_ms(clock::sample());
        let step = inner.engine.removal(now);
        log_notes(&mut inner.engine);
        match step {
            Removal::Remove => {
                self.remove_self(inner);
                true
            }
            Removal::Kept => {
                self.save(inner);
                false
            }
            Removal::Wait | Removal::None => false,
        }
    }

    /// Removes eGuard from the computer: the agents' screens, the browser policies, and in service mode everything
    /// removal protection put in place and the data folder (secrets, state; the log stays while it's being written),
    /// then has the installer remove the program files. Console mode installed no service, so it removes its own
    /// development data and its copy of the browser policies only.
    fn remove_self(&self, inner: &mut Inner) {
        log::warn("eGuard is removing itself from this computer");
        // Saved first: if anything below stops the process, the next start carries on removing
        self.save(inner);
        if let Some(shared) = self.shared.get() {
            shared.close_agents();
            // Each agent hears it at its next heartbeat (every second) and closes its screens
            std::thread::sleep(Duration::from_secs(3));
        }
        match self.browsers.remove() {
            Ok(()) => log::info("eGuard's browser policies removed"),
            Err(e) => log::error(&format!("removing the browser policies: {e}")),
        }
        self.may_stop.store(true, Ordering::SeqCst);
        match self.mode {
            Mode::Service => {
                // Everything removal protection put in place, the data folder included (`lockdown::purge`); then the
                // installer takes out the program files and the Settings entry. Its uninstall check passes: nothing
                // is paired any more
                self.removed.store(true, Ordering::SeqCst);
                let left = crate::lockdown::purge(false);
                if !left.is_empty() {
                    log::warn(&format!("removal left {} thing(s) behind (above)", left.len()));
                }
                match eguard_win::msi::installed_product() {
                    Some(product) => match std::process::Command::new("msiexec.exe").args(["/x", &product, "/qn", "/norestart"]).spawn() {
                        Ok(_) => log::info(&format!("the installer is removing eGuard's program files ({product})")),
                        Err(e) => log::error(&format!("couldn't start the installer to remove the program files: {e}")),
                    },
                    None => log::info("eGuard wasn't installed with its installer; its program files stay"),
                }
            }
            Mode::Console { .. } => {
                log::info("development: console mode installed no service, so there's none to remove");
                self.removed.store(true, Ordering::SeqCst);
                for left in self.store.remove_all() {
                    log::warn(&format!("couldn't remove {left}"));
                }
            }
        }
        log::info(&format!("eGuard's data removed from {}; stopping", self.store.dir().display()));
        self.request_stop();
    }

    /// Something another part of eGuard saw, for the parent (one alert per kind per hour, `Engine::tamper`).
    fn tamper(&self, kind: TamperKind) -> Response {
        log::warn(&format!("tamper: {kind:?}"));
        let mut inner = self.lock();
        let now = inner.engine.now_ms(clock::sample());
        if inner.engine.tamper(kind, now) {
            self.save(&mut inner);
            inner.woken = true;
            self.wake.notify_all();
        }
        Response::Status(inner.engine.status())
    }

    /// Whether a stop request may stop the service now (`Engine::may_be_removed`, as of the last look). Read by the
    /// service's control handler, which mustn't wait for the engine's lock (a sync may hold it).
    pub fn may_stop(&self) -> bool {
        self.may_stop.load(Ordering::SeqCst)
    }

    /// A stop request was refused: the loop tells the parent (`SERVICE_STOP_DENIED`).
    pub fn stop_denied(&self) {
        self.stop_denied.store(true, Ordering::SeqCst);
        self.poke();
    }

    /// "Remove with a code", from either pipe: the engine checks it, and a right code wakes the loop to remove.
    fn remove_with_code(&self, code: &str) -> Response {
        let mut inner = self.lock();
        let now = inner.engine.now_ms(clock::sample());
        let result = inner.engine.remove_with_code(code, now);
        log_notes(&mut inner.engine);
        self.save(&mut inner);
        match result {
            Ok(message) => {
                inner.woken = true;
                self.wake.notify_all();
                Response::Removing { message }
            }
            Err(message) => {
                // Wrong codes and lockouts go to the parent: sent now, not at the next tick
                inner.woken = true;
                self.wake.notify_all();
                Response::Error { message }
            }
        }
    }

    /// Forces eGuard's extension in each browser, with the link from the last sync, and tells the engine whether web
    /// filtering holds (what `/report` says). Nothing before pairing. True when that changed (a report is queued, and
    /// sent at the next tick).
    fn apply_web(&self, inner: &mut Inner) -> bool {
        if !inner.engine.enforces() {
            return false;
        }
        let now = inner.engine.now_ms(clock::sample());
        let setup = self.browsers.apply(inner.engine.browser_link(), now);
        let held = eguard_core::web::capability(self.mode == Mode::Service, &setup);
        let info = DeviceInfo { battery: sysinfo::battery(), ..self.info.clone() };
        inner.engine.set_web(held, &info, now)
    }

    fn start_watcher(self: &Arc<Self>) {
        let me = Arc::clone(self);
        let dirs = Arc::clone(&self.watch_dirs);
        let watching = eguard_win::watch::spawn(
            move || dirs.lock().map(|d| d.clone()).unwrap_or_default(),
            move || {
                let mut inner = me.lock();
                inner.engine.request_scan();
                inner.woken = true;
                me.wake.notify_all();
            },
        );
        if let Err(e) = watching {
            log::warn(&format!("couldn't watch for installs ({e}); scans run every 6 hours only"));
        }
    }

    /// The process monitor and the session supervisor.
    fn start_enforcement(self: &Arc<Self>) -> Result<(), String> {
        let mode = match &self.mode {
            Mode::Service => EndMode::Real,
            Mode::Console { sandbox: Some(dir) } => {
                let dir = monitor::sandbox_dir(dir).map_err(|e| format!("--sandbox {}: {e}", dir.display()))?;
                log::info(&format!("development: programs are ended only inside {dir}"));
                EndMode::Sandbox(dir)
            }
            Mode::Console { sandbox: None } => {
                log::info("development: no --sandbox, so nothing is ended; what would be is logged");
                EndMode::DryRun
            }
        };
        let (tx, rx) = std::sync::mpsc::channel();
        let tx = Mutex::new(tx);
        let etw = match eguard_win::etw::spawn(move |pid| {
            let _ = tx.lock().map(|t| t.send(pid));
        }) {
            Ok(()) => {
                log::info("watching process starts (ETW)");
                true
            }
            Err(e) => {
                log::info(&format!("no ETW process events ({e}); sweeping the process list every second"));
                false
            }
        };
        let session_sids: sessions::SessionSids = Arc::default();
        let monitor = Monitor::new(Arc::clone(&self.facts), Arc::clone(&self.enforcer), mode, etw, Arc::clone(&session_sids));
        std::thread::Builder::new().name("monitor".into()).spawn(move || monitor.run(&rx)).map_err(|e| e.to_string())?;

        let me = Arc::clone(self);
        let remover = Arc::clone(self);
        let shared = Arc::new(Shared::new(
            Arc::clone(&self.enforcer),
            Arc::clone(&self.facts),
            session_sids,
            matches!(self.mode, Mode::Console { .. }),
            Box::new(move || me.poke()),
            Box::new(move |req| match req {
                Request::RemoveWithCode { code } => remover.remove_with_code(code),
                Request::Tamper { kind } => remover.tamper(*kind),
                _ => Response::Error { message: "That isn't asked on this pipe.".into() },
            }),
        ));
        let _ = self.shared.set(Arc::clone(&shared));
        std::thread::Builder::new().name("sessions".into()).spawn(move || sessions::supervise(&shared)).map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Whether this service puts updates in place: only the Windows service with removal protection, whose guard
    /// swaps the program files. Console mode (and a service without the guard) downloads and checks them only.
    fn installs_updates(&self) -> bool {
        self.mode == Mode::Service && self.locked
    }

    fn start_update_if_offered(self: &Arc<Self>, inner: &mut Inner) {
        if self.updating.load(Ordering::SeqCst) {
            return;
        }
        let Some(m) = inner.engine.take_update() else { return };
        self.updating.store(true, Ordering::SeqCst);
        let me = Arc::clone(self);
        let (version, started) = (m.version.clone(), std::thread::Builder::new().name("update".into()).spawn(move || me.update(&m)));
        if let Err(e) = started {
            self.updating.store(false, Ordering::SeqCst);
            inner.engine.update_done(Err(format!("couldn't start updating to {version}: {e}")), clock::sample());
        }
    }

    /// Downloads and checks eGuard `m.version`, without the lock (it takes a while). The service then puts it in the
    /// guard's cache and stops, and the guard swaps the program files and starts the new version (`update`).
    fn update(&self, m: &Manifest) {
        log::info(&format!("downloading eGuard {}", m.version));
        let staged = self.store.dir().join("update");
        let result = crate::update::stage(m, &staged).and_then(|()| {
            if !self.installs_updates() {
                let _ = std::fs::remove_dir_all(&staged);
                log::info(&format!(
                    "eGuard {} downloaded and checked; {} installs nothing",
                    m.version,
                    if self.mode == Mode::Service {
                        "without removal protection there's no guard to swap the files, so this"
                    } else {
                        "development mode"
                    }
                ));
                return Ok(false);
            }
            // The guard puts the new version in place once this service has stopped: without one, nothing would
            if !crate::lockdown::guard_running() {
                return Err("the guard isn't running, so nothing would put the new version in place".into());
            }
            crate::update::install(m, &staged).map(|()| true)
        });
        match result {
            Ok(true) => {
                log::warn(&format!("eGuard {} is in the guard's cache; stopping so the guard can put it in place", m.version));
                if let Some(shared) = self.shared.get() {
                    shared.close_agents();
                    // Each agent hears it at its next heartbeat (every second) and closes its screens
                    std::thread::sleep(Duration::from_secs(3));
                }
                self.request_stop();
            }
            other => {
                let mut inner = self.lock();
                inner.engine.update_done(other.map(|_| ()), clock::sample());
                log_notes(&mut inner.engine);
                self.updating.store(false, Ordering::SeqCst);
            }
        }
    }

    fn start_scan_if_due(self: &Arc<Self>, inner: &mut Inner) {
        if self.scanning.load(Ordering::SeqCst) {
            return;
        }
        let now = inner.engine.now_ms(clock::sample());
        let Some((classifier, cache)) = inner.engine.scan_due(now) else { return };
        self.scanning.store(true, Ordering::SeqCst);
        let me = Arc::clone(self);
        let started = std::thread::Builder::new().name("scan".into()).spawn(move || me.scan(&classifier, cache));
        if let Err(e) = started {
            self.scanning.store(false, Ordering::SeqCst);
            log::warn(&format!("couldn't start a scan: {e}"));
        }
    }

    /// One full scan, without the lock (it reads the disk and checks signatures for a while), then its results.
    fn scan(&self, classifier: &Classifier, mut cache: ExeCache) {
        let started = Instant::now();
        let collected = apps::collect(&mut cache);
        if let Ok(mut d) = self.watch_dirs.lock() {
            d.clone_from(&collected.watch_dirs);
        }
        let candidates = scan::merge_with(collected.candidates, crate::monitor::admin_only());
        let result = scan::classify_all(classifier, &candidates);
        log::info(&format!(
            "scanned {} candidates in {:.1} s ({} files checked, {} from the cache)",
            candidates.len(),
            started.elapsed().as_secs_f64(),
            collected.exes_checked,
            collected.cache_hits
        ));
        let mut inner = self.lock();
        let now = inner.engine.now_ms(clock::sample());
        inner.engine.apply_scan(&result, cache, now);
        log_notes(&mut inner.engine);
        self.enforcer().update(inner.engine.enforce_inputs());
        self.save(&mut inner);
        self.scanning.store(false, Ordering::SeqCst);
        // Send what the scan found now, not at the next tick
        inner.woken = true;
        self.wake.notify_all();
    }

    /// The admin pipe (`\\.\pipe\eguard`: pairing, status, scans). If another program holds its name, the service
    /// keeps enforcing and keeps trying for the name on the pipe's thread; console mode stops with a clear error,
    /// which is what a developer who left another eGuard running needs to see.
    fn start_pipe(self: &Arc<Self>) -> Result<(), String> {
        let mut server =
            PipeServer::new(ipc::PIPE_NAME, &self.pipe_sddl).map_err(|e| format!("the pipe's permissions didn't parse: {e}"))?;
        let first = match self.mode {
            Mode::Service => None,
            Mode::Console { .. } => Some(server.create().map_err(|e| pipe_error(&e))?),
        };
        let me = Arc::clone(self);
        std::thread::Builder::new()
            .name("pipe".into())
            .spawn(move || {
                let first = first.unwrap_or_else(|| claim_pipe(&mut server));
                me.serve_pipe(server, first);
            })
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    fn serve_pipe(self: Arc<Self>, mut server: PipeServer, first: eguard_win::pipe::Pending) {
        server.keep(first);
        loop {
            let conn = match server.accept() {
                Ok(c) => c,
                Err(e) => {
                    log::warn(&format!("pipe: {e}"));
                    std::thread::sleep(Duration::from_secs(1));
                    continue;
                }
            };
            let me = Arc::clone(&self);
            // One thread per client, so a client that never writes can't hold up the next one
            let _ = std::thread::Builder::new().name("pipe-client".into()).spawn(move || me.serve_client(conn));
        }
    }

    fn serve_client(&self, mut conn: std::fs::File) {
        // A client that connects and never sends a whole request is let go, not waited on forever
        if !eguard_win::pipe::wait_for_line(&conn, eguard_win::pipe::READ_TIMEOUT) {
            return;
        }
        let response = match ipc::read_line(&mut conn) {
            Ok(Some(line)) => match ipc::decode::<Request>(&line) {
                Ok(req) => self.handle(req),
                Err(e) => Response::Error { message: e.to_string() },
            },
            Ok(None) => return,
            Err(e) => Response::Error { message: e.to_string() },
        };
        let _ = conn.write_all(&ipc::encode(&response));
        // Waits until the client has read it all, so closing doesn't cut the answer off
        let _ = conn.sync_all();
    }

    fn handle(&self, req: Request) -> Response {
        match req {
            Request::Status => Response::Status(self.lock().engine.status()),
            Request::Scan => {
                let mut inner = self.lock();
                inner.engine.request_scan();
                inner.woken = true;
                self.wake.notify_all();
                Response::Status(inner.engine.status())
            }
            Request::Pair { code, name, accounts } => self.pair(&code, name, accounts.as_deref()),
            Request::Accounts { set } => self.accounts(set),
            Request::RemoveWithCode { code } => self.remove_with_code(&code),
            // From the installer's uninstall check and the guard (both SYSTEM), or an administrator's "Remove eGuard"
            // window: only these kinds, which an administrator could at worst send for nothing
            Request::Tamper { kind: kind @ (TamperKind::UninstallBlocked | TamperKind::FilesChanged) } => self.tamper(kind),
            Request::Tamper { .. } => Response::Error { message: "eGuard doesn't take that from here.".into() },
            // A session's agent talks on its own session's pipe
            Request::Heartbeat { .. } | Request::AskParent { .. } | Request::AskTime { .. } => {
                Response::Error { message: "That is asked on the session's own pipe.".into() }
            }
        }
    }

    /// The Windows accounts and which are the child's; `set` names the child's first (an administrator at the
    /// computer: the main pipe admits only administrators in a real install).
    fn accounts(&self, set: Option<Vec<String>>) -> Response {
        let list = eguard_win::accounts::list();
        let mut inner = self.lock();
        if let Some(names) = set {
            if !inner.engine.enforces() {
                return Response::Error { message: "This computer isn't paired yet.".into() };
            }
            if names.iter().all(|n| n.trim().is_empty()) {
                return Response::Error { message: "Name at least one account: eGuard would apply no rules at all.".into() };
            }
            if let Err(e) = inner.engine.set_accounts(&list, &names) {
                return Response::Error { message: e.to_string() };
            }
            let now = inner.engine.now_ms(clock::sample());
            let info = DeviceInfo { battery: sysinfo::battery(), ..self.info.clone() };
            inner.engine.observe_accounts(&list, &info, now);
            log_notes(&mut inner.engine);
            self.enforcer().update(inner.engine.enforce_inputs());
            self.save(&mut inner);
            inner.woken = true;
            self.wake.notify_all();
        }
        // Unpaired, no rules apply anywhere yet (a computer that lost its secrets still enforces)
        let paired = inner.engine.enforces();
        let accounts = list
            .iter()
            .map(|a| AccountInfo { name: a.name.clone(), admin: a.admin, enforced: paired && inner.engine.account_applies(&a.sid) })
            .collect();
        Response::Accounts { accounts }
    }

    fn pair(&self, code: &str, name: Option<String>, accounts: Option<&[String]>) -> Response {
        // The child's accounts are settled before the code is used: a code works once
        let list = eguard_win::accounts::list();
        let choice = match accounts {
            Some(names) => match AccountChoice::named(&list, names) {
                Ok(c) => c,
                Err(e) => return Response::Error { message: e.to_string() },
            },
            None => AccountChoice::standard(&list),
        };
        if choice.enforced.is_empty() {
            return Response::Error {
                message:
                    "Every account on this computer is an administrator. Name your child's account: eguard-agent pair CODE --accounts NAME"
                        .into(),
            };
        }
        let mut inner = self.lock();
        let mut info = DeviceInfo { battery: sysinfo::battery(), ..self.info.clone() };
        if let Some(name) = name.filter(|n| !n.trim().is_empty()) {
            info = DeviceInfo::new(&name, &info.model, &info.os_version, &info.app_version, info.battery);
        }
        let paired = match inner.engine.pair(code, &info) {
            Ok(p) => p,
            Err(e) => {
                log::warn(&format!("pairing refused: {e}"));
                return Response::Error { message: e.to_string() };
            }
        };
        // The server sends the secrets once: they're on disk before anything else happens
        if let Err(e) = self.store.save_secrets(&paired.secrets) {
            log::error(&format!("pairing succeeded but saving the secrets failed: {e}"));
            return Response::Error {
                message: "eGuard paired, but this computer couldn't save its key. Remove it from the dashboard and pair again.".into(),
            };
        }
        let child_name = paired.child_name.clone();
        inner.engine.adopt(paired, Some(choice));
        let now = inner.engine.now_ms(clock::sample());
        inner.engine.observe_accounts(&list, &info, now);
        log_notes(&mut inner.engine);
        // A new pairing starts its usage afresh, like the rest of the state
        {
            let mut e = self.enforcer();
            *e = Enforcer::new(UsageLedger::default(), Memo::default());
            e.update(inner.engine.enforce_inputs());
        }
        self.browsers.forget_link();
        self.apply_web(&mut inner);
        self.save(&mut inner);
        inner.woken = true;
        self.wake.notify_all();
        Response::Paired { child_name }
    }
}
