//! The service's work, the same in console mode and as a Windows service: the sync loop on one thread, the pipe on
//! another, scans on a third (so syncing never waits for one), all sharing the engine behind a lock.

use crate::log;
use crate::store::Store;
use eguard_core::api::{Api, ServerUrl};
use eguard_core::engine::{DeviceInfo, Engine, Note};
use eguard_core::ipc::{self, Request, Response};
use eguard_core::report::Capabilities;
use eguard_core::scan::{self, Classifier, ExeCache};
use eguard_core::signature::TrustedKeys;
use eguard_win::apps;
use eguard_win::{clock, http::WinHttp, pipe::PipeServer, sysinfo};
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

pub const APP_VERSION: &str = env!("CARGO_PKG_VERSION");

/// What this build can do (spec section 11). Phase 2 enforces nothing yet, so the AVAILABLE protections are left
/// out of `/report` and the server shows them as not applied; the guided ones are reported off, with why.
fn capabilities() -> Capabilities {
    Capabilities {
        enforced: std::collections::BTreeSet::new(),
        uninstall_protection: Err("Removal protection isn't in this version of eGuard for Windows yet.".into()),
        web: Err("This version of eGuard for Windows doesn't set up the browser extension yet.".into()),
    }
}

#[derive(Debug)]
pub struct Options {
    pub store: Store,
    pub server: ServerUrl,
    /// SDDL for the pipe: who may connect.
    pub pipe_sddl: String,
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
    /// A scan is running; the loop doesn't start another.
    scanning: AtomicBool,
    /// Launcher folders the last scan found, for the watcher.
    watch_dirs: Arc<Mutex<Vec<PathBuf>>>,
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
        let mut engine = Engine::new(state, secrets, api, keys, capabilities());
        log_notes(&mut engine);
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
            scanning: AtomicBool::new(false),
            watch_dirs: Arc::new(Mutex::new(Vec::new())),
        }))
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        // A panic elsewhere mustn't stop protection: the engine's state is still the last consistent one
        self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub fn request_stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
        self.wake.notify_all();
    }

    fn save(&self, inner: &Inner) {
        if let Err(e) = self.store.save_state(&inner.engine.data) {
            log::error(&format!("saving state.json failed: {e}"));
        }
    }

    /// Runs until `request_stop`.
    pub fn run(self: &Arc<Self>) -> Result<(), String> {
        let mut server =
            PipeServer::new(ipc::PIPE_NAME, &self.pipe_sddl).map_err(|e| format!("the pipe's permissions didn't parse: {e}"))?;
        // Created here, not on the thread: if another program already owns the pipe's name, fail now and loudly
        let first = server.create().map_err(|e| format!("couldn't create {} ({e}); is another eGuard running?", ipc::PIPE_NAME))?;
        let me = Arc::clone(self);
        std::thread::Builder::new().name("pipe".into()).spawn(move || me.serve_pipe(server, first)).map_err(|e| e.to_string())?;
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
                self.save(&inner);
            }
            log_notes(&mut inner.engine);
        }

        while !self.stop.load(Ordering::SeqCst) {
            let mut inner = self.lock();
            let info = DeviceInfo { battery: sysinfo::battery(), ..self.info.clone() };
            let tick = inner.engine.tick(clock::sample(), &info);
            log_notes(&mut inner.engine);
            if tick.changed {
                self.save(&inner);
            }
            self.start_scan_if_due(&mut inner);
            inner.woken = false;
            let (_inner, _) = self
                .wake
                .wait_timeout_while(inner, Duration::from_millis(tick.sleep_ms), |i| !i.woken && !self.stop.load(Ordering::SeqCst))
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
        let inner = self.lock();
        self.save(&inner);
        log::info("stopped");
        Ok(())
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
        let candidates = scan::merge(collected.candidates);
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
        self.save(&inner);
        self.scanning.store(false, Ordering::SeqCst);
        // Send what the scan found now, not at the next tick
        inner.woken = true;
        self.wake.notify_all();
    }

    fn serve_pipe(self: Arc<Self>, mut server: PipeServer, first: eguard_win::pipe::Pending) {
        let mut pending = Some(first);
        loop {
            let conn = match pending.take().map_or_else(|| server.accept(), eguard_win::pipe::Pending::connect) {
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
            Request::Pair { code, name } => {
                let mut inner = self.lock();
                let mut info = DeviceInfo { battery: sysinfo::battery(), ..self.info.clone() };
                if let Some(name) = name.filter(|n| !n.trim().is_empty()) {
                    info = DeviceInfo::new(&name, &info.model, &info.os_version, &info.app_version, info.battery);
                }
                let paired = match inner.engine.pair(&code, &info) {
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
                        message: "eGuard paired, but this computer couldn't save its key. Remove it from the dashboard and pair again."
                            .into(),
                    };
                }
                let child_name = paired.child_name.clone();
                inner.engine.adopt(paired);
                log_notes(&mut inner.engine);
                self.save(&inner);
                inner.woken = true;
                self.wake.notify_all();
                Response::Paired { child_name }
            }
        }
    }
}
