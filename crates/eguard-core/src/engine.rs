//! The service's work between pairing and removal, without the platform: pairing, the `/sync` loop, `/report`, the
//! catalog, when to scan and what a scan sends, and the offline queue. The platform gives it a `Transport`, clock
//! samples and the computer's details, runs the scans it asks for, and saves `Persisted` (and, at pairing, the
//! secrets) when told something changed.
//!
//! Fail closed throughout: a failed, refused or unreadable `/sync` changes nothing but when the next one is tried.

use crate::accounts::{self, Account, AccountChoice, UnknownAccount};
use crate::api::{Api, ApiError};
use crate::clock::{ClockChange, ClockSample};
use crate::enforce::{Inputs, Inventory};
use crate::queue::{self, Settled};
use crate::removal::{AttemptResult, RemovalSecret};
use crate::report::{self, Capabilities};
use crate::scan::{self, Classifier, ExeCache, ScanResult};
use crate::signature::{CatalogUpdate, TrustedKeys, verify_catalog};
use crate::state::{AgentState, AuthState, UNAUTHORIZED_SYNC_SECS};
use crate::store::{DeviceSecrets, Persisted};
use crate::wire::{Catalog, DeviceEvent, EventEnvelope, PairRequest, Platform, ReportRequest, SyncRequest, TamperKind, UsageReport};

/// The longest the service sleeps: the wall clock is checked for changes about this often.
pub const MAX_SLEEP_MS: u64 = 60_000;
/// Rounds of sending per tick: each round sends the oldest due item of every lane.
const SEND_ROUNDS: usize = 20;
/// A full scan this often (spec section 5), and the catalog checked for changes as often.
pub const SCAN_EVERY_MS: i64 = 6 * 60 * 60_000;
const CATALOG_EVERY_MS: u64 = 6 * 60 * 60_000;
/// Scans asked for by a change (an install writes many keys) wait at least this long after the last.
pub const SCAN_MIN_GAP_MS: i64 = 2 * 60_000;

/// The computer as `/pair`, `/sync` and `/report` describe it. Cut to the server's limits by `DeviceInfo::new`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceInfo {
    pub name: String,
    pub model: String,
    pub os_version: String,
    pub app_version: String,
    pub battery: Option<u8>,
}

fn cut(s: &str, max: usize, fallback: &str) -> String {
    let s: String = s.trim().chars().take(max).collect();
    let s = s.trim_end();
    if s.is_empty() { fallback.to_owned() } else { s.to_owned() }
}

impl DeviceInfo {
    /// Limits from `pair/route.ts`: name and model 1–60, osVersion 1–40, appVersion ≤ 20.
    pub fn new(name: &str, model: &str, os_version: &str, app_version: &str, battery: Option<u8>) -> Self {
        Self {
            name: cut(name, 60, "Windows PC"),
            model: cut(model, 60, "PC"),
            os_version: cut(os_version, 40, "Windows"),
            app_version: cut(app_version, 20, "0"),
            battery: battery.filter(|b| *b <= 100),
        }
    }
}

/// Something worth a line in the log. Never carries a secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Note {
    Info(String),
    Warn(String),
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PairError {
    #[error("This computer is already paired. To pair it again, remove it from the parent dashboard first.")]
    AlreadyPaired,
    #[error("That doesn't look like a pairing code. It's the 8 letters and numbers shown on the dashboard.")]
    BadCode,
    /// The server said no; its words are written for people.
    #[error("{0}")]
    Refused(String),
    #[error("eGuard couldn't be reached. Check the internet connection and try again.")]
    Unreachable,
    #[error("eGuard's answer didn't make sense. Try again in a minute.")]
    Malformed,
}

/// A pairing the server accepted. Save `secrets` first, then hand it to `Engine::adopt`.
#[derive(Debug)]
pub struct Paired {
    pub secrets: DeviceSecrets,
    pub child_name: String,
}

/// What a tick did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tick {
    /// Sleep at most this long before the next tick (or until woken).
    pub sleep_ms: u64,
    /// `Persisted` changed: save it.
    pub changed: bool,
}

/// Strips spaces and dashes and checks the code's shape, as the server does (6–12 letters and numbers).
pub fn normalize_code(code: &str) -> Option<String> {
    let c: String = code.chars().filter(|c| !c.is_whitespace() && *c != '-').collect::<String>().to_uppercase();
    ((6..=12).contains(&c.len()) && c.chars().all(|c| c.is_ascii_alphanumeric())).then_some(c)
}

/// A random number in `[0, 1)`, for backoff jitter.
fn random_unit() -> f64 {
    (uuid::Uuid::new_v4().as_u128() as u64 >> 11) as f64 / (1u64 << 53) as f64
}

pub struct Engine {
    pub data: Persisted,
    secrets: Option<DeviceSecrets>,
    api: Api,
    keys: TrustedKeys,
    caps: Capabilities,
    /// The monotonic time of the next `/sync`.
    next_sync_mono_ms: u64,
    sync_failures: u32,
    /// The catalog in force: the last good copy, verified.
    catalog: Option<Catalog>,
    next_catalog_mono_ms: u64,
    catalog_failures: u32,
    /// Something changed (an Uninstall key, a launcher's folder): scan again soon.
    scan_requested: bool,
    notes: Vec<Note>,
    jitter: fn() -> f64,
}

impl std::fmt::Debug for Engine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Engine").field("paired", &self.is_paired()).field("api", &self.api).finish_non_exhaustive()
    }
}

impl Engine {
    /// `secrets` as loaded (when paired). A `data` that doesn't belong to them is replaced by `Persisted::recover`.
    pub fn new(data: Persisted, secrets: Option<DeviceSecrets>, api: Api, keys: TrustedKeys, caps: Capabilities) -> Self {
        let mut notes = Vec::new();
        let data = match &secrets {
            Some(s) if !data.matches(s) => {
                notes.push(Note::Warn("the state file doesn't match this computer's secrets; starting from the secrets".into()));
                Persisted::recover(s)
            }
            None if data.agent.is_some() => {
                notes.push(Note::Warn(
                    "this computer was paired but its secrets are missing or unreadable: it keeps enforcing the last rules it had, \
                     and can't reach eGuard until it's removed from the dashboard and paired again"
                        .into(),
                ));
                data
            }
            _ => data,
        };
        let mut data = data;
        // The kept copy is checked again: a catalog decides what's never reported, so only eGuard's signed one counts
        let catalog = match data.catalog.as_ref().map(|raw| verify_catalog(&keys, raw, None)) {
            Some(Ok(CatalogUpdate::Changed(c))) => Some(c),
            Some(_) => {
                notes.push(Note::Warn("the kept catalog didn't verify; fetching it again".into()));
                data.catalog = None;
                None
            }
            None => None,
        };
        Self {
            data,
            secrets,
            api,
            keys,
            caps,
            next_sync_mono_ms: 0,
            sync_failures: 0,
            catalog,
            next_catalog_mono_ms: 0,
            catalog_failures: 0,
            scan_requested: false,
            notes,
            jitter: random_unit,
        }
    }

    /// This computer has its secrets and can talk to eGuard (sync, send, pair refused). For enforcement use `enforces`.
    pub fn is_paired(&self) -> bool {
        self.secrets.is_some()
    }

    /// This computer was paired, so the child's rules apply: the secrets are there, or the state says it was paired
    /// and the secrets were lost or don't decrypt. A deleted token never switches protection off (spec principle
    /// 5): without it the computer can't sync, but it keeps enforcing the last good policy, counting time and
    /// scanning, and what it queues waits for the secrets to come back.
    pub fn enforces(&self) -> bool {
        self.secrets.is_some() || self.data.agent.is_some()
    }

    pub fn server(&self) -> &str {
        self.api.server().as_str()
    }

    /// Log lines since the last call.
    pub fn take_notes(&mut self) -> Vec<Note> {
        std::mem::take(&mut self.notes)
    }

    /// Exchanges a pairing code for the device's secrets. Nothing is kept until `adopt`.
    pub fn pair(&self, code: &str, info: &DeviceInfo) -> Result<Paired, PairError> {
        // A state without secrets is a computer that was paired and lost its secrets: it stays as it is, so losing a
        // file can't move the computer to another family's rules (or none)
        if self.enforces() {
            return Err(PairError::AlreadyPaired);
        }
        let code = normalize_code(code).ok_or(PairError::BadCode)?;
        let request = PairRequest {
            code,
            platform: Platform::Windows,
            name: info.name.clone(),
            model: info.model.clone(),
            kind: None,
            os_version: info.os_version.clone(),
            app_version: Some(info.app_version.clone()),
        };
        let res = self.api.pair(&request).map_err(|e| match e {
            ApiError::Unreachable(_) => PairError::Unreachable,
            ApiError::Malformed(_) => PairError::Malformed,
            ApiError::Status { status, message, .. } => {
                PairError::Refused(message.unwrap_or_else(|| format!("eGuard refused the pairing ({status}).")))
            }
        })?;
        if res.device_id.is_empty() || res.token.is_empty() {
            return Err(PairError::Malformed);
        }
        Ok(Paired {
            secrets: DeviceSecrets { device_id: res.device_id, token: res.token, removal_secret: res.removal_secret },
            child_name: res.child_name,
        })
    }

    /// Takes a pairing whose secrets are saved, and the parent's choice of the child's Windows accounts (`None`:
    /// every account). Save `data` next; the first `/sync` is due right away.
    pub fn adopt(&mut self, paired: Paired, accounts: Option<AccountChoice>) {
        match paired.secrets.removal_secret.as_deref().map(RemovalSecret::from_base64url) {
            Some(Ok(_)) => {}
            Some(Err(_)) => self.notes.push(Note::Warn("the removal secret from eGuard isn't 32 bytes; removal codes won't work".into())),
            None => self.notes.push(Note::Warn("eGuard sent no removal secret; removal codes won't work".into())),
        }
        // The catalog is eGuard's, not the device's: it stays. Everything else starts over (the first scan after
        // pairing reports everything)
        let catalog = self.data.catalog.take();
        self.data = Persisted {
            agent: Some(AgentState::paired(&paired.secrets.device_id, &paired.child_name)),
            catalog,
            accounts,
            ..Persisted::default()
        };
        self.notes.push(Note::Info(format!("paired as {} for {}", paired.secrets.device_id, paired.child_name)));
        self.secrets = Some(paired.secrets);
        self.next_sync_mono_ms = 0;
    }

    /// Sync as soon as possible (pairing, network back).
    pub fn sync_soon(&mut self) {
        self.next_sync_mono_ms = 0;
    }

    /// Once at service start, before the first tick.
    pub fn on_start(&mut self, s: ClockSample) -> bool {
        let Some(agent) = &self.data.agent else { return false };
        match agent.clock.wall_set_back_since_last_run(s) {
            Some(c) => {
                self.clock_changed(c, s.wall_ms);
                true
            }
            None => false,
        }
    }

    fn clock_changed(&mut self, c: ClockChange, now_ms: i64) {
        self.notes.push(Note::Warn(format!("the computer's clock was changed by {} s", c.delta_ms / 1000)));
        self.data.queue.push_event(EventEnvelope::new(DeviceEvent::Tamper { kind: TamperKind::ClockChanged }), now_ms);
    }

    /// One round of work: sync if due, then send what's due.
    pub fn tick(&mut self, s: ClockSample, info: &DeviceInfo) -> Tick {
        let (Some(agent), Some(token)) = (self.data.agent.as_mut(), self.secrets.as_ref().map(|x| x.token.clone())) else {
            return Tick { sleep_ms: MAX_SLEEP_MS, changed: false };
        };
        let wall_change = agent.clock.check_wall(s);
        let mut now_ms = agent.clock.now(s).map_or(s.wall_ms, |n| n.ms);
        if let Some(c) = wall_change {
            self.clock_changed(c, now_ms);
        }
        // The clock is saved every tick: its high-water mark moved
        let changed = true;

        if s.mono_ms >= self.next_sync_mono_ms {
            self.sync(&token, s, info, now_ms);
            now_ms = self.data.agent.as_mut().and_then(|a| a.clock.now(s)).map_or(now_ms, |n| n.ms);
        }
        if s.mono_ms >= self.next_catalog_mono_ms {
            self.refresh_catalog(&token, s);
        }
        self.send_due(&token, now_ms);

        let until_sync = self.next_sync_mono_ms.min(self.next_catalog_mono_ms).saturating_sub(s.mono_ms);
        let until_send = self.data.queue.next_due_ms().map_or(u64::MAX, |t| t.saturating_sub(now_ms).max(0) as u64);
        Tick { sleep_ms: until_sync.min(until_send).clamp(1_000, MAX_SLEEP_MS), changed }
    }

    fn sync(&mut self, token: &str, s: ClockSample, info: &DeviceInfo, now_ms: i64) {
        let request =
            SyncRequest { battery: info.battery, os_version: Some(info.os_version.clone()), app_version: Some(info.app_version.clone()) };
        let wait_ms = match self.api.sync(token, &request) {
            Ok(raw) => self.apply_sync(&raw, s, info),
            Err(ApiError::Status { status: 401, .. }) => {
                let agent = self.data.agent.as_mut().expect("paired");
                if agent.auth == AuthState::Ok {
                    self.notes.push(Note::Warn("eGuard refused this computer's token; protection carries on as it was".into()));
                }
                agent.on_unauthorized(now_ms);
                u64::from(UNAUTHORIZED_SYNC_SECS) * 1000
            }
            Err(ApiError::Status { status: 429, retry_after_secs, .. }) => {
                self.notes.push(Note::Warn("eGuard asked this computer to slow down".into()));
                (queue::RATE_LIMITED_MIN_MS as u64).max(u64::from(retry_after_secs.unwrap_or(0)) * 1000)
            }
            Err(e) => {
                self.sync_failures += 1;
                self.notes.push(Note::Warn(format!("sync failed: {e}")));
                queue::backoff_ms(self.sync_failures, (self.jitter)()) as u64
            }
        };
        self.next_sync_mono_ms = s.mono_ms + wait_ms;
    }

    /// A `/sync` answer arrived: apply it and queue what it asks for. Returns ms until the next sync.
    fn apply_sync(&mut self, raw: &serde_json::Value, s: ClockSample, info: &DeviceInfo) -> u64 {
        let agent = self.data.agent.as_mut().expect("paired");
        let outcome = match agent.apply_sync(raw, &self.keys, s, &info.app_version) {
            Ok(o) => o,
            Err(e) => {
                self.sync_failures += 1;
                self.notes.push(Note::Warn(format!("{e}; the last good policy stays in force")));
                return queue::backoff_ms(self.sync_failures, (self.jitter)()) as u64;
            }
        };
        self.sync_failures = 0;
        for n in &outcome.notes {
            self.notes.push(Note::Warn(n.clone()));
        }
        let now_ms = agent.clock.now(s).map_or(s.wall_ms, |n| n.ms);
        let update_required = agent.update_required;
        let sync = agent.last_sync.as_ref().expect("just applied");
        let protections = report::protections(sync, &self.caps);
        if let Some(c) = outcome.clock_change {
            self.clock_changed(c, now_ms);
        }
        if let Some(cmd) = &outcome.uninstall {
            // Acting on it comes with removal (spec section 10); until then the computer keeps enforcing
            self.notes.push(Note::Warn(format!(
                "eGuard asked to remove this computer (verified, requested {}); this version can't remove itself yet",
                cmd.requested_at
            )));
        }
        if let Some(e) = &outcome.uninstall_rejected {
            self.notes.push(Note::Warn(format!("an uninstall command failed verification and was ignored: {e}")));
        }
        if update_required {
            self.notes.push(Note::Warn("eGuard needs a newer version of this app; enforcement carries on".into()));
        }
        let unchanged = self.data.last_reported.as_ref() == Some(&protections);
        if outcome.full_report_requested || !outcome.requests.is_empty() || !unchanged {
            let mut body = report::full_report(protections.clone(), &info.os_version, &info.app_version, info.battery);
            body.accounts.clone_from(&self.data.accounts_reported);
            self.data.queue.push_report(body, now_ms);
            self.data.last_reported = Some(protections);
        }
        u64::from(outcome.next_sync_secs) * 1000
    }

    /// `GET /catalog?since=` the kept version. A catalog that doesn't verify is ignored and the kept one stays.
    fn refresh_catalog(&mut self, token: &str, s: ClockSample) {
        let kept = self.catalog.as_ref().map(|c| c.version.clone());
        let wait_ms = match self.api.catalog(token, kept.as_deref()) {
            Ok(raw) => match verify_catalog(&self.keys, &raw, kept.as_deref()) {
                Ok(CatalogUpdate::Changed(c)) => {
                    self.notes.push(Note::Info(format!("catalog version {} ({} entries)", c.version, c.entries.len())));
                    // Another catalog may change what's reported: the next scan uses it
                    self.scan_requested = self.catalog.is_some();
                    self.catalog = Some(c);
                    self.data.catalog = Some(raw);
                    self.catalog_failures = 0;
                    CATALOG_EVERY_MS
                }
                Ok(CatalogUpdate::Unchanged { .. }) => {
                    self.catalog_failures = 0;
                    CATALOG_EVERY_MS
                }
                Err(e) => {
                    self.catalog_failures += 1;
                    self.notes.push(Note::Warn(format!("the catalog from eGuard was refused: {e}; the kept one stays")));
                    queue::backoff_ms(self.catalog_failures, (self.jitter)()) as u64
                }
            },
            // Its limit is 30 an hour: wait out the hour
            Err(ApiError::Status { status: 429, .. }) => 60 * 60_000,
            Err(e) => {
                self.catalog_failures += 1;
                if self.catalog.is_none() {
                    self.notes.push(Note::Warn(format!("couldn't fetch the catalog ({e}); scanning waits for it")));
                }
                queue::backoff_ms(self.catalog_failures, (self.jitter)()) as u64
            }
        };
        self.next_catalog_mono_ms = s.mono_ms + wait_ms;
    }

    /// eGuard's time now (the wall clock before the first sync ever).
    pub fn now_ms(&mut self, s: ClockSample) -> i64 {
        self.data.agent.as_mut().and_then(|a| a.clock.now(s)).map_or(s.wall_ms, |n| n.ms)
    }

    /// Something changed that may mean new apps: scan again soon (not before `SCAN_MIN_GAP_MS` after the last).
    pub fn request_scan(&mut self) {
        self.scan_requested = true;
    }

    /// When a scan is due, what it needs: the catalog's rules and the cache of checked files. A scan waits for a
    /// verified catalog: without one, every trusted publisher's app would be reported.
    pub fn scan_due(&self, now_ms: i64) -> Option<(Classifier, ExeCache)> {
        let catalog = self.catalog.as_ref().filter(|_| self.enforces())?;
        let since = self.data.last_scan_ms.map(|t| now_ms - t);
        let due = match since {
            None => true,
            Some(gap) => !(0..SCAN_EVERY_MS).contains(&gap) || (self.scan_requested && gap >= SCAN_MIN_GAP_MS),
        };
        due.then(|| (Classifier::new(catalog), self.data.exe_cache.clone()))
    }

    /// A scan finished: queue what's new (the first scan: everything, as `APPS_FOUND`), and keep the cache.
    pub fn apply_scan(&mut self, result: &ScanResult, cache: ExeCache, now_ms: i64) {
        let events = scan::events(self.data.apps_reported.as_ref(), &result.found);
        let first = self.data.apps_reported.is_none();
        for e in &events {
            self.data.queue.push_event(EventEnvelope::new(e.clone()), now_ms);
        }
        self.notes.push(Note::Info(format!(
            "scan: {} apps to report, {} left out as trusted; {} {}",
            result.found.len(),
            result.skipped.len(),
            events.len(),
            if first { "APPS_FOUND events (first scan)" } else { "events for new apps" }
        )));
        self.data.apps_reported = Some(result.found.iter().map(|a| (a.app.clone(), a.clone())).collect());
        self.data.places.clone_from(&result.places);
        self.data.exe_cache = cache;
        self.data.last_scan_ms = Some(now_ms);
        self.scan_requested = false;
    }

    /// What enforcement works from now: the rules in force, the family's zone, eGuard's clock, the catalog's
    /// trusted publishers and games, and what the last scan found.
    pub fn enforce_inputs(&self) -> Inputs {
        let agent = self.data.agent.as_ref();
        Inputs {
            paired: self.enforces(),
            rules: agent.map(AgentState::rules).unwrap_or_default(),
            zone: agent.map_or_else(crate::localtime::FamilyZone::utc, AgentState::zone),
            clock: agent.map(|a| a.clock.clone()).unwrap_or_default(),
            classifier: self.catalog.as_ref().map(Classifier::new),
            inventory: Inventory::new(&self.data.places, self.data.apps_reported.as_ref()),
            accounts: self.data.accounts.as_ref().map(|c| c.enforced.clone()),
        }
    }

    /// The computer's Windows accounts, looked at again (at start and every few minutes). An account not seen
    /// before is news once (`TAMPER` `NEW_ACCOUNT`) and isn't enforced; the list goes to `/report` when it changed.
    /// Returns true when `data` changed.
    pub fn observe_accounts(&mut self, list: &[Account], now_ms: i64) -> bool {
        if !self.enforces() || list.is_empty() {
            return false;
        }
        let mut changed = false;
        if let Some(choice) = self.data.accounts.as_mut() {
            let new: Vec<String> = choice.take_new(list).into_iter().map(|a| a.name.clone()).collect();
            if !new.is_empty() {
                self.notes
                    .push(Note::Warn(format!("new Windows account(s) {}: not enforced until an administrator adds them", new.join(", "))));
                self.data.queue.push_event(EventEnvelope::new(DeviceEvent::Tamper { kind: TamperKind::NewAccount }), now_ms);
                changed = true;
            }
        }
        let reported = accounts::report(self.data.accounts.as_ref(), list);
        if self.data.accounts_reported.as_ref() != Some(&reported) {
            let body = ReportRequest { accounts: Some(reported.clone()), ..ReportRequest::default() };
            self.data.queue.push_report(body, now_ms);
            self.data.accounts_reported = Some(reported);
            changed = true;
        }
        changed
    }

    /// Whether the child's rules apply in the account `sid`.
    pub fn account_applies(&self, sid: &str) -> bool {
        accounts::applies(self.data.accounts.as_ref(), sid)
    }

    /// The parent (an administrator at the computer) names the child's accounts. Reported at the next look.
    pub fn set_accounts(&mut self, list: &[Account], names: &[String]) -> Result<(), UnknownAccount> {
        let choice = AccountChoice::named(list, names)?;
        self.notes.push(Note::Info(format!("the child's accounts are now: {}", names.join(", "))));
        self.data.accounts = Some(choice);
        self.data.accounts_reported = None;
        Ok(())
    }

    /// A code typed into "Remove with a code" (spec section 10). Wrong ones count toward a lockout, and each new
    /// lockout tells the parent (`TAMPER` `REMOVAL_CODE_GUESSED`). `None` when this computer has no removal secret.
    pub fn try_removal_code(&mut self, input: &str, now_ms: i64) -> Option<AttemptResult> {
        let secrets = self.secrets.as_ref()?;
        let secret = RemovalSecret::from_base64url(secrets.removal_secret.as_deref()?).ok()?;
        let result = self.data.code_attempts.attempt(&secret, &secrets.device_id, input, now_ms);
        if let AttemptResult::LockedOut { newly: true, .. } = result {
            self.notes.push(Note::Warn("wrong removal codes: \"Remove with a code\" is locked for a while".into()));
            self.data.queue.push_event(EventEnvelope::new(DeviceEvent::Tamper { kind: TamperKind::RemovalCodeGuessed }), now_ms);
        }
        Some(result)
    }

    /// Queues what enforcement has to tell the server.
    pub fn queue_enforcement(&mut self, events: Vec<DeviceEvent>, usage: Vec<UsageReport>, now_ms: i64) {
        if !self.enforces() {
            return;
        }
        for e in events {
            self.data.queue.push_event(EventEnvelope::new(e), now_ms);
        }
        for u in usage {
            self.data.queue.push_usage(u, now_ms);
        }
    }

    fn send_due(&mut self, token: &str, now_ms: i64) {
        for _ in 0..SEND_ROUNDS {
            let due: Vec<_> = self.data.queue.due(now_ms).into_iter().map(|q| (q.seq, q.item.clone())).collect();
            if due.is_empty() {
                return;
            }
            let mut delivered = false;
            for (seq, item) in due {
                let outcome = self.api.send(token, &item);
                match self.data.queue.settle(seq, outcome, now_ms, (self.jitter)()) {
                    Some(Settled::Done) => delivered = true,
                    Some(Settled::Dropped(item)) => {
                        self.notes.push(Note::Warn(format!("eGuard refused a {} message ({outcome:?}); dropped", item.lane())));
                    }
                    Some(Settled::GaveUp(item)) => {
                        self.notes.push(Note::Warn(format!(
                            "eGuard kept failing on a {} message ({outcome:?}); given up so the ones after it can go",
                            item.lane()
                        )));
                    }
                    _ => {}
                }
            }
            if !delivered {
                return;
            }
        }
    }

    /// For `eguard-agent`'s status screen.
    pub fn status(&self) -> crate::ipc::StatusInfo {
        let agent = self.data.agent.as_ref();
        crate::ipc::StatusInfo {
            paired: self.enforces(),
            device_id: agent.map(|a| a.device_id.clone()),
            child_name: agent.map(|a| a.child_name.clone()).filter(|n| !n.is_empty()),
            server: self.server().to_owned(),
            last_sync_at: agent
                .and_then(|a| a.last_sync_ms)
                .and_then(|ms| jiff::Timestamp::from_millisecond(ms).ok())
                .map(|t| t.to_string()),
            // Without its secrets a paired computer can't reach eGuard: shown as not authorized, protection on
            authorized: (self.is_paired() || agent.is_none()) && agent.is_none_or(|a| a.auth == AuthState::Ok),
            queued: self.data.queue.len(),
            apps_reported: self.data.apps_reported.as_ref().map(std::collections::BTreeMap::len),
            last_scan_at: self.data.last_scan_ms.and_then(|ms| jiff::Timestamp::from_millisecond(ms).ok()).map(|t| t.to_string()),
        }
    }

    #[cfg(test)]
    fn fixed_jitter(mut self) -> Self {
        self.jitter = || 0.5;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::ServerUrl;
    use crate::api::tests::{Scripted, json};
    use crate::queue::Outbound;
    use crate::wire::ProtectionKey;
    use serde_json::{Value, json as j};
    use std::collections::BTreeSet;
    use std::sync::Arc;

    fn fixture(name: &str) -> Value {
        let path = format!("{}/../../fixtures/server/{name}", env!("CARGO_MANIFEST_DIR"));
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
    }

    fn caps() -> Capabilities {
        Capabilities {
            enforced: BTreeSet::new(),
            uninstall_protection: Err("Removal protection isn't on yet.".into()),
            web: Err("No extension yet.".into()),
        }
    }

    fn info() -> DeviceInfo {
        DeviceInfo::new("MIA-PC", "Custom build", "Windows 11 25H2", "0.1.0", None)
    }

    fn engine(t: &Arc<Scripted>) -> Engine {
        let api = Api::new(ServerUrl::parse("http://localhost:3000", true).unwrap(), Box::new(t.clone()));
        Engine::new(Persisted::default(), None, api, TrustedKeys::builtin().unwrap(), caps()).fixed_jitter()
    }

    fn at(mono_ms: u64, iso: &str) -> ClockSample {
        ClockSample { mono_ms, boot_id: 7, wall_ms: crate::clock::parse_iso_ms(iso).unwrap() }
    }

    /// Pairs with the captured `/pair` answer. Returns the sync fixture's `serverTime` for clock samples.
    fn paired(t: &Arc<Scripted>) -> (Engine, String) {
        t.answers.lock().unwrap().push(json(201, &fixture("pair-response.json")));
        let mut e = engine(t);
        let p = e.pair("7jx8-7r2f", &info()).unwrap();
        e.adopt(p, None);
        let server_time = fixture("sync-first.json")["serverTime"].as_str().unwrap().to_owned();
        (e, server_time)
    }

    #[test]
    fn codes_are_normalized_like_the_server() {
        assert_eq!(normalize_code(" abcd-2345 ").as_deref(), Some("ABCD2345"));
        assert_eq!(normalize_code("ab 12"), None);
        assert_eq!(normalize_code("ABCD2345;DROP"), None);
    }

    #[test]
    fn pairing_sends_what_the_server_accepted_and_refuses_a_second_time() {
        let t = Scripted::new(vec![]);
        let (mut e, _) = paired(&t);
        let body: Value = serde_json::from_slice(t.seen.lock().unwrap()[0].body.as_ref().unwrap()).unwrap();
        assert_eq!(
            body,
            j!({ "code": "7JX87R2F", "platform": "WINDOWS", "name": "MIA-PC", "model": "Custom build", "osVersion": "Windows 11 25H2", "appVersion": "0.1.0" })
        );
        assert!(e.is_paired());
        assert_eq!(e.pair("ABCD2345", &info()).unwrap_err(), PairError::AlreadyPaired);
        assert!(e.take_notes().iter().any(|n| matches!(n, Note::Info(m) if m.starts_with("paired as"))));
    }

    #[test]
    fn a_refused_code_shows_the_servers_words() {
        let t = Scripted::new(vec![json(400, &j!({ "error": "Pairing code is invalid or expired" }))]);
        let e = engine(&t);
        assert_eq!(e.pair("ABCD2345", &info()).unwrap_err(), PairError::Refused("Pairing code is invalid or expired".into()));
        let t = Scripted::new(vec![]);
        assert_eq!(engine(&t).pair("ABCD2345", &info()).unwrap_err(), PairError::Unreachable);
    }

    #[test]
    fn first_sync_queues_a_full_report_and_sends_it() {
        let t = Scripted::new(vec![]);
        let (mut e, now) = paired(&t);
        let mut first = fixture("sync-first.json");
        first["deviceId"] = j!(e.secrets.as_ref().unwrap().device_id);
        t.answers.lock().unwrap().extend([json(200, &first), json(200, &j!({ "ok": true }))]);
        *t.catalog.lock().unwrap() = Some(fixture("catalog.json"));

        let tick = e.tick(at(1_000, &now), &info());
        assert!(tick.changed);
        let seen = t.seen.lock().unwrap();
        let urls: Vec<_> = seen.iter().map(|r| r.url.rsplit('/').next().unwrap().to_owned()).collect();
        assert_eq!(urls, ["pair", "sync", "catalog", "report"]);
        assert!(seen[1].bearer.is_some());
        let report: Value = serde_json::from_slice(seen[3].body.as_ref().unwrap()).unwrap();
        assert_eq!(report["full"], true);
        let keys: Vec<_> = report["protections"].as_array().unwrap().iter().map(|p| p["key"].as_str().unwrap()).collect();
        // Nothing enforced yet: only the guided ones, as off, with why
        assert_eq!(keys, ["UNINSTALL_PROTECTION", "WEB"]);
        assert!(e.data.queue.is_empty());
        assert!(e.status().last_sync_at.is_some());
        drop(seen);
        // Next sync in nextSyncSeconds (300), not before
        assert_eq!(tick.sleep_ms, MAX_SLEEP_MS);
    }

    #[test]
    fn failures_and_401_keep_the_policy_and_back_off() {
        let t = Scripted::new(vec![]);
        let (mut e, now) = paired(&t);
        let mut first = fixture("sync-first.json");
        first["deviceId"] = j!(e.secrets.as_ref().unwrap().device_id);
        t.answers.lock().unwrap().extend([json(200, &first), json(200, &j!({ "ok": true }))]);
        e.tick(at(1_000, &now), &info());
        let policy = e.data.agent.as_ref().unwrap().last_sync.clone();

        // No network: retried after the backoff, policy untouched
        e.sync_soon();
        e.tick(at(2_000, &now), &info());
        assert_eq!(e.data.agent.as_ref().unwrap().last_sync, policy);
        assert_eq!(e.next_sync_mono_ms, 2_000 + queue::backoff_ms(1, 0.5) as u64);

        // 401: nothing switched off, tried again in 15 minutes
        t.answers.lock().unwrap().push(json(401, &fixture("sync-401.json")));
        e.sync_soon();
        e.tick(at(3_000, &now), &info());
        assert_eq!(e.data.agent.as_ref().unwrap().last_sync, policy);
        assert!(!e.status().authorized);
        assert_eq!(e.next_sync_mono_ms, 3_000 + u64::from(UNAUTHORIZED_SYNC_SECS) * 1000);

        // Someone else's answer changes nothing
        let mut other = fixture("sync-first.json");
        other["deviceId"] = j!("dev_someone_else");
        t.answers.lock().unwrap().push(json(200, &other));
        e.sync_soon();
        e.tick(at(4_000, &now), &info());
        assert_eq!(e.data.agent.as_ref().unwrap().last_sync, policy);
    }

    #[test]
    fn an_unchanged_report_isnt_sent_again_unless_asked() {
        let t = Scripted::new(vec![]);
        let (mut e, now) = paired(&t);
        let mut first = fixture("sync-first.json");
        first["deviceId"] = j!(e.secrets.as_ref().unwrap().device_id);
        let mut quiet = first.clone();
        quiet["fullReportRequested"] = j!(false);
        quiet["requests"] = j!([]);
        t.answers.lock().unwrap().extend([json(200, &first), json(200, &j!({ "ok": true })), json(200, &quiet)]);
        e.tick(at(1_000, &now), &info());
        e.sync_soon();
        e.tick(at(2_000, &now), &info());
        let reports = t.seen.lock().unwrap().iter().filter(|r| r.url.ends_with("/report")).count();
        assert_eq!(reports, 1);
    }

    #[test]
    fn a_report_that_fails_stays_queued() {
        let t = Scripted::new(vec![]);
        let (mut e, now) = paired(&t);
        let mut first = fixture("sync-first.json");
        first["deviceId"] = j!(e.secrets.as_ref().unwrap().device_id);
        t.answers.lock().unwrap().extend([json(200, &first), json(500, &j!({ "error": "boom" }))]);
        let tick = e.tick(at(1_000, &now), &info());
        assert_eq!(e.data.queue.len(), 1);
        assert!(matches!(e.data.queue.items()[0].item, Outbound::Report(_)));
        assert!(tick.sleep_ms <= MAX_SLEEP_MS);
    }

    #[test]
    fn unpaired_does_nothing_and_lost_state_is_rebuilt_from_secrets() {
        let t = Scripted::new(vec![]);
        let mut e = engine(&t);
        assert_eq!(e.tick(at(1_000, "2026-10-23T07:00:00Z"), &info()), Tick { sleep_ms: MAX_SLEEP_MS, changed: false });
        assert!(t.seen.lock().unwrap().is_empty());

        let secrets = DeviceSecrets { device_id: "dev_9".into(), token: "t".into(), removal_secret: None };
        let api = Api::new(ServerUrl::parse("http://localhost:3000", true).unwrap(), Box::new(t.clone()));
        let e = Engine::new(Persisted::default(), Some(secrets), api, TrustedKeys::builtin().unwrap(), caps());
        assert_eq!(e.data.agent.as_ref().unwrap().device_id, "dev_9");
        // Before any sync, new apps wait for the parent
        assert!(e.data.agent.as_ref().unwrap().rules().policy.approval_required);
        assert!(!report::AVAILABLE.contains(&ProtectionKey::Web));
    }

    #[test]
    fn lost_secrets_keep_the_rules_in_force_and_cant_be_paired_away() {
        let t = Scripted::new(vec![]);
        let (mut e, now) = paired(&t);
        let mut first = fixture("sync-computer.json");
        first["deviceId"] = j!(e.secrets.as_ref().unwrap().device_id);
        t.answers.lock().unwrap().extend([json(200, &first), json(200, &j!({ "ok": true }))]);
        *t.catalog.lock().unwrap() = Some(fixture("catalog.json"));
        e.tick(at(1_000, &now), &info());
        let t0 = crate::clock::parse_iso_ms(&now).unwrap();
        let enforced = e.enforce_inputs();
        assert!(enforced.paired && enforced.rules.app("Counter-Strike 2").is_some());

        // secrets.bin deleted (or no longer decrypts); state.json is still there
        let api = Api::new(ServerUrl::parse("http://localhost:3000", true).unwrap(), Box::new(t.clone()));
        let mut lost = Engine::new(e.data.clone(), None, api, TrustedKeys::builtin().unwrap(), caps());
        assert!(!lost.is_paired() && lost.enforces());
        assert!(lost.take_notes().iter().any(|n| matches!(n, Note::Warn(m) if m.contains("secrets"))));
        // The same rules, time counted, scans run, accounts watched
        let inputs = lost.enforce_inputs();
        assert!(inputs.paired);
        assert_eq!(inputs.rules, enforced.rules);
        assert!(lost.scan_due(t0).is_some());
        let queued = lost.data.queue.len();
        lost.queue_enforcement(vec![DeviceEvent::AppBlocked { app: "Counter-Strike 2".into() }], vec![], t0);
        assert_eq!(lost.data.queue.len(), queued + 1);
        assert!(lost.observe_accounts(&win_accounts(), t0));
        // Shown as paired but not authorized
        let status = lost.status();
        assert!(status.paired && !status.authorized);
        // And it can't be moved to another family by pairing again
        assert_eq!(lost.pair("ABCD2345", &info()).unwrap_err(), PairError::AlreadyPaired);
        // Nothing goes out without a token
        let asked = t.seen.lock().unwrap().len();
        lost.tick(at(400_000, &now), &info());
        assert_eq!(t.seen.lock().unwrap().len(), asked);
    }

    #[test]
    fn scans_wait_for_a_verified_catalog_then_run_every_six_hours() {
        let t = Scripted::new(vec![]);
        let (mut e, now) = paired(&t);
        let t0 = crate::clock::parse_iso_ms(&now).unwrap();
        // No catalog yet: no scan, even though none ever ran
        assert!(e.scan_due(t0).is_none());

        // A catalog someone changed doesn't verify: still none
        let mut forged = fixture("catalog.json");
        forged["catalog"]["entries"][0]["match"] = j!("steam:1");
        *t.catalog.lock().unwrap() = Some(forged);
        e.tick(at(1_000, &now), &info());
        assert!(e.scan_due(t0).is_none());
        assert!(e.take_notes().iter().any(|n| matches!(n, Note::Warn(m) if m.contains("refused"))));

        *t.catalog.lock().unwrap() = Some(fixture("catalog.json"));
        e.next_catalog_mono_ms = 0;
        e.tick(at(2_000, &now), &info());
        let (classifier, cache) = e.scan_due(t0).expect("first scan due");
        assert!(cache.is_empty());

        let mut cs2 = scan::Candidate::new("Counter-Strike 2", scan::Origin::Launcher);
        cs2.ids = vec![crate::wire::AppId::new(crate::wire::AppIdKind::Steam, "730")];
        let result = scan::classify_all(&classifier, &[cs2]);
        e.apply_scan(&result, cache, t0);
        let found =
            e.data.queue.items().iter().filter(|q| matches!(&q.item, Outbound::Event(ev) if ev.event.type_name() == "APPS_FOUND")).count();
        assert_eq!(found, 1);
        assert_eq!(e.status().apps_reported, Some(1));

        // Not again until six hours have passed, or a change asks (and then not within two minutes)
        assert!(e.scan_due(t0 + 60_000).is_none());
        e.request_scan();
        assert!(e.scan_due(t0 + 60_000).is_none());
        assert!(e.scan_due(t0 + SCAN_MIN_GAP_MS).is_some());
        e.scan_requested = false;
        assert!(e.scan_due(t0 + SCAN_EVERY_MS).is_some());

        // The same apps again: nothing new to send
        e.apply_scan(&result, ExeCache::new(), t0 + SCAN_EVERY_MS);
        assert_eq!(e.data.queue.items().iter().filter(|q| matches!(q.item, Outbound::Event(_))).count(), found);

        // The kept catalog survives a restart, verified again
        let data = e.data.clone();
        let api = Api::new(ServerUrl::parse("http://localhost:3000", true).unwrap(), Box::new(t.clone()));
        let restarted = Engine::new(data, e.secrets.clone(), api, TrustedKeys::builtin().unwrap(), caps());
        assert!(restarted.catalog.is_some());
    }

    fn win_accounts() -> Vec<Account> {
        vec![
            Account { sid: "S-1-5-21-9-1001".into(), name: "Carla".into(), admin: true },
            Account { sid: "S-1-5-21-9-1002".into(), name: "Mia".into(), admin: false },
        ]
    }

    fn tampers(e: &Engine) -> Vec<TamperKind> {
        e.data
            .queue
            .items()
            .iter()
            .filter_map(|q| match &q.item {
                Outbound::Event(EventEnvelope { event: DeviceEvent::Tamper { kind }, .. }) => Some(*kind),
                _ => None,
            })
            .collect()
    }

    fn reported_accounts(e: &Engine) -> Vec<Vec<crate::wire::ReportedAccount>> {
        e.data
            .queue
            .items()
            .iter()
            .filter_map(|q| match &q.item {
                Outbound::Report(r) => r.accounts.clone(),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn the_childs_accounts_are_reported_and_a_new_one_is_news_once() {
        let t = Scripted::new(vec![json(201, &fixture("pair-response.json"))]);
        let mut e = engine(&t);
        let p = e.pair("7jx8-7r2f", &info()).unwrap();
        e.adopt(p, Some(AccountChoice::standard(&win_accounts())));
        assert!(e.account_applies("S-1-5-21-9-1002") && !e.account_applies("S-1-5-21-9-1001"));
        assert!(e.observe_accounts(&win_accounts(), 0));
        assert!(!e.observe_accounts(&win_accounts(), 1));
        let sent = reported_accounts(&e);
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].iter().map(|a| (a.name.as_str(), a.enforced)).collect::<Vec<_>>(), [("Carla", false), ("Mia", true)]);

        let mut later = win_accounts();
        later.push(Account { sid: "S-1-5-21-9-1003".into(), name: "Sneaky".into(), admin: false });
        assert!(e.observe_accounts(&later, 2));
        e.observe_accounts(&later, 3);
        assert_eq!(tampers(&e), [TamperKind::NewAccount]);
        assert!(!e.account_applies("S-1-5-21-9-1003"));
        assert_eq!(e.enforce_inputs().accounts.map(|s| s.len()), Some(1));

        // An administrator adds it on the computer
        e.set_accounts(&later, &["mia".into(), "Sneaky".into()]).unwrap();
        assert!(e.account_applies("S-1-5-21-9-1003"));
        assert!(e.set_accounts(&later, &["Nobody".into()]).is_err());
        e.observe_accounts(&later, 4);
        assert!(reported_accounts(&e).last().unwrap().iter().all(|a| a.enforced == (a.name != "Carla")));
    }

    #[test]
    fn paired_before_the_choice_every_account_is_enforced() {
        let t = Scripted::new(vec![]);
        let (mut e, _) = paired(&t);
        assert!(e.account_applies("S-1-5-21-9-1001"));
        e.observe_accounts(&win_accounts(), 0);
        assert_eq!(tampers(&e), Vec::<TamperKind>::new());
        assert!(reported_accounts(&e)[0].iter().all(|a| a.enforced));
    }

    #[test]
    fn guessing_the_removal_code_locks_it_and_tells_the_parent_once_per_lockout() {
        let t = Scripted::new(vec![]);
        let (mut e, _) = paired(&t);
        for i in 0..4 {
            assert!(matches!(e.try_removal_code("AAAAAAAA", i), Some(AttemptResult::Rejected { .. })));
        }
        assert!(matches!(e.try_removal_code("AAAAAAAA", 5), Some(AttemptResult::LockedOut { newly: true, .. })));
        assert!(matches!(e.try_removal_code("AAAAAAAA", 6), Some(AttemptResult::LockedOut { newly: false, .. })));
        assert_eq!(tampers(&e), [TamperKind::RemovalCodeGuessed]);
        // The right code works once the lockout is over
        let secret = RemovalSecret::from_base64url(e.secrets.as_ref().unwrap().removal_secret.as_deref().unwrap()).unwrap();
        let later = 5 + crate::removal::FIRST_LOCKOUT_MS;
        let code = crate::removal::code_for_window(&secret, &e.secrets.as_ref().unwrap().device_id, crate::removal::window_of(later));
        assert_eq!(e.try_removal_code(&code, later), Some(AttemptResult::Accepted));
    }

    #[test]
    fn device_info_fits_the_servers_limits() {
        let d = DeviceInfo::new(&"x".repeat(100), "  ", "Windows 11", "0.1.0-a-very-long-prerelease", Some(250));
        assert_eq!(d.name.len(), 60);
        assert_eq!(d.model, "PC");
        assert_eq!(d.app_version.len(), 20);
        assert_eq!(d.battery, None);
    }
}
