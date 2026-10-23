//! The service's work, the same in console mode and as a Windows service: the sync loop on one thread, the pipe on
//! another, sharing the engine behind a lock.

use crate::log;
use crate::store::Store;
use eguard_core::api::{Api, ServerUrl};
use eguard_core::engine::{DeviceInfo, Engine, Note};
use eguard_core::ipc::{self, Request, Response};
use eguard_core::report::Capabilities;
use eguard_core::signature::TrustedKeys;
use eguard_win::{clock, http::WinHttp, pipe::PipeServer, sysinfo};
use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

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
