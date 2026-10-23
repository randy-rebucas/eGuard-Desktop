//! Enforcement and time on the computer (spec sections 7 and 8), without the platform.
//!
//! The platform tells the `Enforcer` what runs (`check`, for each program as it starts and again every sweep) and
//! what each signed-in session has in front of it (`heartbeat`, from the agent about once a second). The enforcer
//! answers with what to end and what each session's screen shows, counts usage, and collects the events for the
//! server. It holds its own copy of the rules and eGuard's clock, refreshed by the service's loop after every tick,
//! so ending a program never waits for a network call.
//!
//! **Which program is which app** (spec section 6): by the install folder the scan recorded (so a renamed `cs2.exe`
//! is still Steam appid 730), then by id against the child's list, then by name.
//!
//! **Never ended** (spec section 7): Microsoft-signed programs under `%SystemRoot%`, eGuard itself, accessibility
//! tools, and a trusted publisher's apps that aren't catalog games. App Approval applies to apps the scan found and
//! to unsigned programs outside Program Files, never to every program, so drivers and updaters keep working.
//! Anything else is "untracked": never ended, its time counts toward the day but not toward an app.

use crate::clock::{ClockSample, TrustedClock};
use crate::ipc::{Screen, SessionView, Warning};
use crate::localtime::{FamilyZone, LocalMoment};
use crate::rules::{self, Block, Rules, Subject, Verdict};
use crate::scan::launchers::Launcher;
use crate::scan::{self, Candidate, Classifier, ExeFacts, Origin, Place, Skip};
use crate::usage::{DayUsage, UsageApp, UsageLedger};
use crate::wire::{AppId, AppIdKind, AppRule, AppSource, Category, DeviceEvent, FoundApp, UsageReport};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap};

/// Input in the last this-many ms makes foreground time count (spec section 8).
pub const IDLE_LIMIT_MS: u64 = 2 * 60_000;
/// Heartbeats further apart than this don't count the time between them (the computer slept, the agent hung).
pub const HEARTBEAT_GAP_MS: i64 = 10_000;
/// `APP_BLOCKED` for one app at most this often (the server raises one alert an hour anyway).
pub const BLOCKED_EVENT_EVERY_MS: i64 = 10 * 60_000;
/// "Ask parent" and "Ask for more time" at most this often per app and reason (the server's own window).
pub const ASK_EVERY_MS: i64 = 10 * 60_000;
/// A block screen stays offered this long after the program was ended.
pub const NOTICE_KEEP_MS: i64 = 2 * 60_000;
/// The same app ended again this soon shows the same block screen, not a new one.
const NOTICE_MERGE_MS: i64 = 30_000;
/// Usage is queued at most this often (the server takes 120 an hour).
pub const USAGE_EVERY_MS: i64 = 5 * 60_000;
/// The server keeps 30 days of usage; older days are dropped.
const USAGE_KEEP_DAYS: i64 = 31;

/// Accessibility tools that live outside the Windows folder, by file name and the signer that must have signed them
/// (so a renamed game can't pass for one). Windows' own (Narrator, Magnifier, the on-screen keyboard, Voice Access)
/// are under `%SystemRoot%` and Microsoft-signed already.
const ACCESSIBILITY: &[(&str, &str)] = &[
    ("nvda.exe", "nv access"),
    ("nvda_slave.exe", "nv access"),
    ("nvda_ui.exe", "nv access"),
    ("jfw.exe", "freedom scientific"),
    ("zoomtext.exe", "freedom scientific"),
    ("fusion.exe", "freedom scientific"),
    ("natspeak.exe", "nuance communications"),
    ("dragonbar.exe", "nuance communications"),
];

/// What the platform knows about a running program.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Program {
    /// Full path of its executable (any case).
    pub path: String,
    pub exe: ExeFacts,
    /// Microsoft-signed (embedded or through Windows' catalogs) and under `%SystemRoot%`.
    pub windows: bool,
    /// One of eGuard's own programs, from eGuard's install folder.
    pub ours: bool,
    /// Under Program Files (where a standard account can't install).
    pub program_files: bool,
}

/// Why a program is never ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exempt {
    Ours,
    Windows,
    Accessibility,
    /// A trusted publisher's app that isn't a catalog game.
    Trusted,
}

/// A program matched to an app.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppMatch {
    /// The name on the child's list when it's there, else the name the scan or the catalog gives it.
    pub name: String,
    pub ids: Vec<AppId>,
    pub category: Category,
    /// The parent's rule for it, when it's on the child's list.
    pub rule: Option<AppRule>,
}

impl AppMatch {
    fn subject(&self) -> Subject<'_> {
        match &self.rule {
            Some(r) => Subject::Listed(r),
            None => Subject::Unlisted { name: &self.name, category: self.category },
        }
    }

    fn usage_app(&self) -> UsageApp {
        UsageApp { name: self.name.clone(), ids: self.ids.clone(), category: self.category }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolved {
    Exempt(Exempt),
    App(AppMatch),
    /// Not an app eGuard knows about, and nothing App Approval applies to: never ended.
    Untracked,
}

/// What the last scan found: apps with their ids, and where they're installed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Inventory {
    /// Deepest folder first, so a game inside a launcher's folder is the game.
    places: Vec<Place>,
    apps: BTreeMap<String, FoundApp>,
}

impl Inventory {
    pub fn new(places: &[Place], apps: Option<&BTreeMap<String, FoundApp>>) -> Self {
        let mut places = places.to_vec();
        places.sort_by(|a, b| b.dir.len().cmp(&a.dir.len()).then_with(|| a.dir.cmp(&b.dir)));
        Self { places, apps: apps.cloned().unwrap_or_default() }
    }

    fn place_of(&self, path: &str) -> Option<&Place> {
        self.places.iter().find(|p| scan::inside(path, &p.dir))
    }

    fn app_with(&self, name: &str, ids: &[AppId]) -> Option<&FoundApp> {
        self.apps.get(name).or_else(|| self.apps.values().find(|a| a.ids.iter().any(|i| ids.iter().any(|j| i.same_as(j)))))
    }
}

/// What enforcement needs from the service's state. Rebuilt after every tick of the sync loop.
#[derive(Debug, Clone)]
pub struct Inputs {
    /// Nothing is enforced on a computer that isn't paired.
    pub paired: bool,
    pub rules: Rules,
    pub zone: FamilyZone,
    pub clock: TrustedClock,
    /// `None` until a verified catalog is in: no program counts as a trusted publisher's until then.
    pub classifier: Option<Classifier>,
    pub inventory: Inventory,
}

impl Default for Inputs {
    fn default() -> Self {
        Self {
            paired: false,
            rules: Rules::default(),
            zone: FamilyZone::utc(),
            clock: TrustedClock::default(),
            classifier: None,
            inventory: Inventory::default(),
        }
    }
}

/// The launcher an id says an app came through (rule 2 of the classifier: such an app is a game, before any trust).
fn launcher_of(ids: &[AppId]) -> Option<Launcher> {
    ids.iter().find_map(|i| match i.kind {
        AppIdKind::Steam => Some(Launcher::Steam),
        AppIdKind::Epic => Some(Launcher::Epic),
        AppIdKind::Riot => Some(Launcher::Riot),
        AppIdKind::Battlenet => Some(Launcher::BattleNet),
        AppIdKind::Ea => Some(Launcher::Ea),
        AppIdKind::Ubisoft => Some(Launcher::Ubisoft),
        AppIdKind::Gog => Some(Launcher::Gog),
        _ => None,
    })
}

fn file_stem(file_name: &str) -> &str {
    file_name.strip_suffix(".exe").unwrap_or(file_name)
}

/// Which app `p` is, if any (module docs).
pub fn resolve(p: &Program, inputs: &Inputs) -> Resolved {
    if p.ours {
        return Resolved::Exempt(Exempt::Ours);
    }
    if p.windows {
        return Resolved::Exempt(Exempt::Windows);
    }
    let signed_by =
        |prefix: &str| [p.exe.signer.as_deref(), p.exe.signer_alt.as_deref()].into_iter().flatten().any(|s| s.starts_with(prefix));
    if ACCESSIBILITY.iter().any(|(file, signer)| p.exe.file_name == *file && signed_by(signer)) {
        return Resolved::Exempt(Exempt::Accessibility);
    }

    let place = inputs.inventory.place_of(&p.path);
    let listed_as = place.and_then(|pl| pl.app.as_deref()).and_then(|name| inputs.inventory.apps.get(name));
    let product = p.exe.product.as_deref().map(str::trim).filter(|s| !s.is_empty());
    let name = place
        .and_then(|pl| pl.app.clone())
        .or_else(|| product.map(str::to_owned))
        .unwrap_or_else(|| file_stem(&p.exe.file_name).to_owned());
    let mut c = Candidate::new(&name, Origin::Uninstall);
    c.ids = listed_as.map(|a| a.ids.clone()).unwrap_or_default();
    c.launcher = launcher_of(&c.ids).or_else(|| (listed_as.and_then(|a| a.source) == Some(AppSource::Launcher)).then_some(Launcher::Steam));
    c.dir = place.map(|pl| pl.dir.clone());
    c.exe = Some(p.exe.clone());

    let found = if let Some(classifier) = &inputs.classifier {
        match classifier.classify(&c) {
            // Inside a trusted publisher's app, only a catalog game is still a game
            Ok(f) if place.is_some_and(|pl| pl.app.is_none()) && f.source != Some(AppSource::Catalog) => {
                return Resolved::Exempt(Exempt::Trusted);
            }
            Ok(f) => f,
            Err(Skip::TrustedPublisher(_)) => return Resolved::Exempt(Exempt::Trusted),
            Err(Skip::BlankName) => return Resolved::Untracked,
        }
    } else {
        // No catalog yet: nothing is trusted, and nothing is known to be a game
        let mut ids = c.ids.clone();
        ids.push(AppId::exe(p.exe.signer.as_deref(), product.unwrap_or(&name)));
        FoundApp { app: name.clone(), ids, source: None, category: listed_as.and_then(|a| a.category) }
    };

    let rule = inputs.rules.apps.iter().find(|r| r.ids.iter().any(|i| found.ids.iter().any(|j| i.same_as(j)))).or_else(|| {
        [Some(found.app.as_str()), place.and_then(|pl| pl.app.as_deref()), product]
            .into_iter()
            .flatten()
            .find_map(|n| inputs.rules.apps.iter().find(|r| r.name.eq_ignore_ascii_case(n)))
    });
    if let Some(r) = rule {
        return Resolved::App(AppMatch { name: r.name.clone(), ids: found.ids, category: r.category.effective(), rule: Some(r.clone()) });
    }
    let known = place.is_some_and(|pl| pl.app.is_some()) || inputs.inventory.app_with(&found.app, &found.ids).is_some();
    let loose_unsigned = p.exe.signer.is_none() && !p.program_files;
    if known || loose_unsigned {
        let category = found.category.unwrap_or(Category::Other).effective();
        Resolved::App(AppMatch { name: found.app, ids: found.ids, category, rule: None })
    } else {
        Resolved::Untracked
    }
}

/// What to do with a running program.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// End it (and what it started).
    End { app: String, block: Block },
    /// It's an app, and usable now.
    Allow,
    /// Not subject to the parent's rules.
    Ignore,
}

/// What a session has in front of it, as the agent saw it.
#[derive(Debug, Clone, Copy)]
pub enum Seen<'a> {
    /// A program's window has the focus.
    Program(&'a Program),
    /// One of eGuard's own screens: not counted.
    Ours,
    /// No window (the desktop, nothing focused): counted toward the day while there's input.
    Nothing,
    /// No agent answers in this session though someone is signed in and it isn't locked: counted, as if in use.
    Unknown,
}

/// What the child asked for from a block screen or the overlay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ask {
    Parent {
        notice: u64,
    },
    /// From a block screen (`Some`) or the overlay.
    Time {
        notice: Option<u64>,
    },
}

/// A program ended in a session, for its block screen.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Notice {
    id: u64,
    app: String,
    block: Block,
    at_ms: i64,
    asked: Option<String>,
}

#[derive(Debug, Clone, Default)]
struct Session {
    /// eGuard time of the last heartbeat, what had the focus then, and whether that counts.
    last: Option<(i64, Option<UsageApp>, bool)>,
    notices: Vec<Notice>,
    /// Warnings already shown, by `date|threshold|what`.
    warned: BTreeSet<String>,
    /// What the overlay answered the last "Ask for more time" with, for the pause it was asked in.
    overlay_asked: Option<(Block, String)>,
}

/// What enforcement keeps across restarts.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Memo {
    /// `LIMIT_REACHED` already sent, as `date|day` or `date|<CATEGORY>`.
    #[serde(default)]
    pub limits_reported: BTreeSet<String>,
}

/// Enforcement state (module docs).
#[derive(Debug, Default)]
pub struct Enforcer {
    inputs: Inputs,
    ledger: UsageLedger,
    memo: Memo,
    sessions: BTreeMap<u32, Session>,
    events: Vec<DeviceEvent>,
    blocked_sent: HashMap<String, i64>,
    asked: HashMap<String, i64>,
    next_id: u64,
    /// Days whose totals changed since they were last queued.
    usage_dirty: BTreeSet<String>,
    usage_queued_ms: Option<i64>,
    /// Something happened that makes usage worth sending now (a limit reached).
    usage_urgent: bool,
    /// Which app each running program is, by path, while the inputs and the program's facts stay the same (the
    /// sweep checks every process every second).
    resolved: HashMap<String, (Program, Resolved)>,
}

fn category_label(c: Category) -> &'static str {
    match c.effective() {
        Category::Games => "Gaming time",
        Category::Social => "Social media time",
        Category::Video => "Video time",
        Category::Messaging => "Messaging time",
        Category::Education => "Learning time",
        Category::Creativity => "Creativity time",
        Category::Browsers => "Browser time",
        _ => "Other apps' time",
    }
}

fn category_key(c: Category) -> String {
    serde_json::to_value(c.effective()).ok().and_then(|v| v.as_str().map(str::to_owned)).unwrap_or_default()
}

fn minutes(n: u32) -> String {
    match n {
        1 => "1 minute".into(),
        n if n % 60 == 0 && n >= 60 => match n / 60 {
            1 => "1 hour".into(),
            h => format!("{h} hours"),
        },
        n => format!("{n} minutes"),
    }
}

/// The block screen for `app` paused by `block`.
fn block_screen(id: u64, app: &str, block: Block, asked: Option<String>) -> Screen {
    let (title, body) = match block {
        Block::Blocked => (format!("{app} is blocked"), "Your parent blocked this app. You can ask them to allow it.".to_owned()),
        Block::Pending => (
            format!("{app} is waiting for your parent"),
            "Your parent hasn't decided about this app yet. It opens once they allow it.".to_owned(),
        ),
        Block::NeedsApproval => (
            format!("{app} needs your parent's OK"),
            "New apps need your parent's OK first. Ask, and it opens once they allow it.".to_owned(),
        ),
        Block::Bedtime => ("It's bedtime".to_owned(), format!("{app} opens again after bedtime.")),
        Block::AppLimit { minutes: m } => (format!("Time's up for {app}"), format!("You've used today's {} of {app}.", minutes(m))),
        Block::CategoryLimit { category, minutes: m } => (
            format!("{} used up", category_label(category)),
            format!("You've used today's {} of {}.", minutes(m), category_label(category).to_lowercase()),
        ),
        Block::DailyLimit { minutes: m } => ("Screen time is up for today".to_owned(), format!("You've used today's {}.", minutes(m))),
    };
    Screen { id, title, body, ask_parent: !block.is_time(), ask_time: block.is_time(), asked }
}

/// The full-screen overlay for a paused screen.
fn overlay_screen(block: Block, asked: Option<String>, always: &[String]) -> Screen {
    let (title, body) = match block {
        Block::Bedtime => ("It's bedtime".to_owned(), "The computer is paused until bedtime ends.".to_owned()),
        Block::DailyLimit { minutes: m } => {
            let still = if always.is_empty() { String::new() } else { format!(" You can still use {}.", always.join(", ")) };
            ("Screen time is up for today".to_owned(), format!("You've used today's {}.{still}", minutes(m)))
        }
        other => return block_screen(0, "This app", other, asked),
    };
    Screen { id: 0, title, body, ask_parent: false, ask_time: true, asked }
}

fn warning_text(secs: u32, block: Block, app: Option<&str>) -> String {
    let left = minutes(secs.div_ceil(60).max(1));
    match block {
        Block::Bedtime => format!("Bedtime starts in {left}."),
        Block::AppLimit { .. } => format!("{left} of {} left today.", app.unwrap_or("this app")),
        Block::CategoryLimit { category, .. } => format!("{left} of {} left today.", category_label(category).to_lowercase()),
        _ => format!("{left} of screen time left today."),
    }
}

/// What a pause is about, for remembering warnings and limits.
fn block_key(block: Block, app: &str) -> String {
    match block {
        Block::Bedtime => "bedtime".into(),
        Block::AppLimit { .. } => format!("app:{app}"),
        Block::CategoryLimit { category, .. } => format!("category:{}", category_key(category)),
        Block::DailyLimit { .. } => "day".into(),
        other => format!("{other:?}"),
    }
}

impl Enforcer {
    /// Starts from what was saved: the usage ledger and the memo.
    pub fn new(ledger: UsageLedger, memo: Memo) -> Self {
        Self { ledger, memo, next_id: 1, ..Self::default() }
    }

    /// The service's state changed (or might have): enforce from now on with these.
    pub fn update(&mut self, inputs: Inputs) {
        self.inputs = inputs;
        self.resolved.clear();
    }

    pub fn ledger(&self) -> &UsageLedger {
        &self.ledger
    }

    pub fn memo(&self) -> &Memo {
        &self.memo
    }

    fn now(&mut self, s: ClockSample) -> (i64, LocalMoment) {
        let now = self.inputs.clock.now(s).map_or(s.wall_ms, |n| n.ms);
        (now, self.inputs.zone.local(now))
    }

    fn today(&self, at: &LocalMoment) -> DayUsage {
        self.ledger.day_or_empty(&at.date)
    }

    fn id(&mut self) -> u64 {
        self.next_id += 1;
        self.next_id
    }

    /// Which app `p` is (`resolve` with the inputs in force).
    pub fn resolve(&self, p: &Program) -> Resolved {
        if !self.inputs.paired {
            return Resolved::Untracked;
        }
        resolve(p, &self.inputs)
    }

    /// What to do with `p`, which is running. `End` queues `APP_BLOCKED` for a blocked app (once per app per
    /// `BLOCKED_EVENT_EVERY_MS`); call `ended` once it's gone, for the block screen.
    pub fn check(&mut self, p: &Program, s: ClockSample) -> Decision {
        let resolved = match self.resolved.get(&p.path) {
            Some((was, r)) if was == p => r.clone(),
            _ => {
                let r = self.resolve(p);
                self.resolved.insert(p.path.clone(), (p.clone(), r.clone()));
                r
            }
        };
        let Resolved::App(app) = resolved else { return Decision::Ignore };
        let (now, at) = self.now(s);
        let empty = DayUsage::default();
        let today = self.ledger.day(&at.date).unwrap_or(&empty);
        match rules::evaluate(&self.inputs.rules, app.subject(), today, &at, now) {
            Verdict::Allow { .. } => Decision::Allow,
            Verdict::Block(block) => {
                if block == Block::Blocked && self.blocked_sent.get(&app.name).is_none_or(|t| now - t >= BLOCKED_EVENT_EVERY_MS) {
                    self.blocked_sent.insert(app.name.clone(), now);
                    self.events.push(DeviceEvent::AppBlocked { app: app.name.clone() });
                }
                Decision::End { app: app.name, block }
            }
        }
    }

    /// A program `check` said to end is gone: the session it ran in shows the block screen.
    pub fn ended(&mut self, session: u32, app: &str, block: Block, s: ClockSample) {
        let (now, _) = self.now(s);
        let id = self.id();
        let sess = self.sessions.entry(session).or_default();
        sess.notices.retain(|n| now - n.at_ms < NOTICE_KEEP_MS);
        if let Some(n) = sess.notices.iter_mut().find(|n| n.app == app && n.block == block && now - n.at_ms < NOTICE_MERGE_MS) {
            n.at_ms = now;
            return;
        }
        sess.notices.push(Notice { id, app: app.to_owned(), block, at_ms: now, asked: None });
    }

    /// The agent in `session` reports what has the focus and how long since the last input. Counts the time since
    /// its last report, and returns what its screen should show.
    pub fn heartbeat(&mut self, session: u32, seen: Seen<'_>, idle_ms: u64, s: ClockSample) -> SessionView {
        let (now, at) = self.now(s);
        let app = match seen {
            Seen::Program(p) => match self.resolve(p) {
                Resolved::App(a) => Some(a),
                _ => None,
            },
            _ => None,
        };
        let counts = self.inputs.paired
            && match seen {
                Seen::Ours => false,
                Seen::Unknown => true,
                Seen::Program(_) | Seen::Nothing => idle_ms < IDLE_LIMIT_MS,
            };
        let sess = self.sessions.entry(session).or_default();
        let previous = sess.last.replace((now, app.as_ref().map(AppMatch::usage_app), counts));
        if let Some((then, prev_app, prev_counts)) = previous
            && prev_counts
            && (0..=HEARTBEAT_GAP_MS).contains(&(now - then))
            && now > then
        {
            self.ledger.record(&self.inputs.zone, then, now, prev_app.as_ref());
            let from = self.inputs.zone.local(then).date;
            self.usage_dirty.insert(from);
            self.usage_dirty.insert(at.date.clone());
        }
        if !self.inputs.paired {
            return SessionView::default();
        }
        self.limits_reached(now, &at);
        self.view(session, app.as_ref(), now, &at)
    }

    /// `LIMIT_REACHED` for the day's screen time and each category limit, once per day each (spec section 7).
    fn limits_reached(&mut self, now: i64, at: &LocalMoment) {
        let rules = &self.inputs.rules;
        if rules.extra_time_running(now) {
            return;
        }
        let today = self.ledger.day_or_empty(&at.date);
        let mut reached = Vec::new();
        if let Some(m) = rules.policy.daily_limit(at)
            && today.total_secs() >= m * 60
        {
            reached.push((format!("{}|day", at.date), DeviceEvent::LimitReached { minutes: m, category: None }));
        }
        for limit in &rules.category_limits {
            let c = limit.category.effective();
            if today.category_secs(c, |n, r| rules.category_of(n, r)) >= limit.daily_limit_minutes * 60 {
                reached.push((
                    format!("{}|{}", at.date, category_key(c)),
                    DeviceEvent::LimitReached { minutes: limit.daily_limit_minutes, category: Some(c) },
                ));
            }
        }
        for (key, event) in reached {
            if self.memo.limits_reported.insert(key) {
                self.events.push(event);
                self.usage_urgent = true;
            }
        }
    }

    fn view(&mut self, session: u32, app: Option<&AppMatch>, now: i64, at: &LocalMoment) -> SessionView {
        let rules = self.inputs.rules.clone();
        let today = self.today(at);
        let sess = self.sessions.entry(session).or_default();

        // The overlay: bedtime or the day used up, unless an always-allowed app that's usable has the focus
        let paused = rules::screen_paused(&rules, &today, at, now);
        let usable_here = app.is_some_and(|a| matches!(rules::evaluate(&rules, a.subject(), &today, at, now), Verdict::Allow { .. }));
        if paused.is_none() {
            sess.overlay_asked = None;
        }
        let overlay = paused.filter(|_| !usable_here).map(|b| {
            let asked = sess.overlay_asked.as_ref().filter(|(was, _)| *was == b).map(|(_, m)| m.clone());
            let always: Vec<String> = rules
                .apps
                .iter()
                .filter(|r| r.approval == crate::wire::Approval::AlwaysAllowed)
                .filter(|r| matches!(rules::evaluate(&rules, Subject::Listed(r), &today, at, now), Verdict::Allow { .. }))
                .map(|r| r.name.clone())
                .take(5)
                .collect();
            overlay_screen(b, asked, &always)
        });

        // The newest block screen in this session
        sess.notices.retain(|n| now - n.at_ms < NOTICE_KEEP_MS);
        let block = sess.notices.last().map(|n| block_screen(n.id, &n.app, n.block, n.asked.clone()));

        // A warning at 5 and at 1 minute before the next pause
        let next = match app {
            Some(a) => rules::upcoming(&rules, a.subject(), &today, at, now).map(|(secs, b)| (secs, b, Some(a.name.as_str()))),
            None => rules::upcoming_screen(&rules, &today, at, now).map(|(secs, b)| (secs, b, None)),
        };
        let warning = next.and_then(|(secs, b, name)| {
            let threshold = match secs {
                1..=60 => 1,
                61..=300 => 5,
                // Already paused, or not soon
                _ => return None,
            };
            let key = format!("{}|{threshold}|{}", at.date, block_key(b, name.unwrap_or("")));
            sess.warned.insert(key).then(|| Warning { id: 0, text: warning_text(secs, b, name) })
        });
        sess.warned.retain(|k| k.starts_with(&at.date));
        let warning = warning.map(|w| Warning { id: self.id(), ..w });
        SessionView { overlay, block, warning }
    }

    /// Whether `session` is paused right now (for the platform's backstop when the overlay keeps disappearing).
    pub fn screen_paused(&mut self, s: ClockSample) -> Option<Block> {
        if !self.inputs.paired {
            return None;
        }
        let (now, at) = self.now(s);
        let today = self.today(&at);
        rules::screen_paused(&self.inputs.rules, &today, &at, now)
    }

    /// The child pressed "Ask parent" or "Ask for more time". Queues `APP_REQUESTED` or `TIME_REQUESTED`, at most
    /// once per app and reason per `ASK_EVERY_MS`. Returns what to tell them, or why it can't be asked.
    pub fn ask(&mut self, session: u32, ask: Ask, s: ClockSample) -> Result<String, String> {
        let (now, at) = self.now(s);
        let today = self.today(&at);
        let rules = self.inputs.rules.clone();
        let sess = self.sessions.entry(session).or_default();
        let gone = || "That screen has closed. Open the app again to ask.".to_owned();
        let (key, event, message) = match ask {
            Ask::Parent { notice } => {
                let n = sess.notices.iter().find(|n| n.id == notice && now - n.at_ms < NOTICE_KEEP_MS).ok_or_else(gone)?;
                if n.block.is_time() {
                    return Err(gone());
                }
                (
                    format!("app|{}", n.app),
                    DeviceEvent::AppRequested { app: n.app.clone() },
                    format!("Asked. {} opens once your parent allows it.", n.app),
                )
            }
            Ask::Time { notice: Some(notice) } => {
                let n = sess.notices.iter().find(|n| n.id == notice && now - n.at_ms < NOTICE_KEEP_MS).ok_or_else(gone)?;
                let reason = n.block.time_request_reason().ok_or_else(gone)?;
                let app = matches!(n.block, Block::AppLimit { .. } | Block::CategoryLimit { .. }).then(|| n.app.clone());
                (
                    format!("time|{reason:?}|{}", app.as_deref().unwrap_or("")),
                    DeviceEvent::TimeRequested { app, reason: Some(reason) },
                    "Asked for more time. You'll get it if your parent says yes.".to_owned(),
                )
            }
            Ask::Time { notice: None } => {
                let b = rules::screen_paused(&rules, &today, &at, now).ok_or("The computer isn't paused any more.")?;
                let reason = b.time_request_reason().ok_or("The computer isn't paused any more.")?;
                (
                    format!("time|{reason:?}|"),
                    DeviceEvent::TimeRequested { app: None, reason: Some(reason) },
                    "Asked for more time. You'll get it if your parent says yes.".to_owned(),
                )
            }
        };
        let fresh = self.asked.get(&key).is_none_or(|t| now - t >= ASK_EVERY_MS);
        let message = if fresh {
            self.asked.insert(key, now);
            self.events.push(event);
            message
        } else {
            "You already asked. Your parent has been told.".to_owned()
        };
        let sess = self.sessions.entry(session).or_default();
        match ask {
            Ask::Parent { notice } | Ask::Time { notice: Some(notice) } => {
                if let Some(n) = sess.notices.iter_mut().find(|n| n.id == notice) {
                    n.asked = Some(message.clone());
                }
            }
            Ask::Time { notice: None } => {
                if let Some(b) = rules::screen_paused(&rules, &today, &at, now) {
                    sess.overlay_asked = Some((b, message.clone()));
                }
            }
        }
        Ok(message)
    }

    /// An event the platform noticed (a killed agent: `TAMPER` `AGENT_RESTARTED`).
    pub fn report(&mut self, event: DeviceEvent) {
        if self.inputs.paired {
            self.events.push(event);
        }
    }

    /// The session ended (signed out): forget it.
    pub fn session_gone(&mut self, session: u32) {
        self.sessions.remove(&session);
    }

    /// Events to queue for the server.
    pub fn take_events(&mut self) -> Vec<DeviceEvent> {
        std::mem::take(&mut self.events)
    }

    /// `/usage` reports to queue: the days that changed, at most every `USAGE_EVERY_MS` (sooner after a limit was
    /// reached, so the parent's numbers match the alert). Old days are dropped from the ledger.
    pub fn usage_due(&mut self, s: ClockSample) -> Vec<UsageReport> {
        let (now, _) = self.now(s);
        let due = self.usage_urgent || self.usage_queued_ms.is_none_or(|t| !(0..USAGE_EVERY_MS).contains(&(now - t)));
        if self.usage_dirty.is_empty() || !due {
            return Vec::new();
        }
        self.usage_queued_ms = Some(now);
        self.usage_urgent = false;
        let oldest = self.inputs.zone.local(now - USAGE_KEEP_DAYS * 86_400_000).date;
        self.ledger.prune_before(&oldest);
        self.memo.limits_reported.retain(|k| k.as_str() >= oldest.as_str());
        let dates = std::mem::take(&mut self.usage_dirty);
        dates.iter().filter_map(|d| self.ledger.day(d).map(|u| u.report(d))).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::parse_iso_ms;
    use crate::rules::{Bedtime, Policy};
    use crate::wire::{Approval, Catalog, CatalogEntry, CatalogKind, CategoryLimit, MatchType, TimeRequestReason};

    fn facts(file: &str, signer: Option<&str>, product: Option<&str>) -> ExeFacts {
        ExeFacts {
            file_name: file.into(),
            signer: signer.map(str::to_owned),
            signer_alt: None,
            product: product.map(str::to_owned),
            graphics: false,
        }
    }

    fn program(path: &str, signer: Option<&str>, product: Option<&str>) -> Program {
        let file = path.rsplit('\\').next().unwrap().to_lowercase();
        Program {
            path: path.into(),
            exe: facts(&file, signer, product),
            windows: false,
            ours: false,
            program_files: path.to_lowercase().starts_with(r"c:\program files"),
        }
    }

    fn rule(name: &str, approval: Approval, limit: Option<u32>, category: Category, ids: &[AppId]) -> AppRule {
        AppRule { name: name.into(), approval, daily_limit_minutes: limit, category, ids: ids.to_vec() }
    }

    fn catalog() -> Classifier {
        let entry = |kind, match_type, m: &str, name: Option<&str>| CatalogEntry {
            kind,
            match_type,
            match_value: m.into(),
            display_name: name.map(str::to_owned),
            category: Some(Category::Games),
            trending: false,
        };
        Classifier::new(&Catalog {
            kind: "eguard.desktop.catalog".into(),
            version: 1,
            entries: vec![
                entry(CatalogKind::Game, MatchType::LauncherId, "steam:730", Some("Counter-Strike 2")),
                entry(CatalogKind::Game, MatchType::Signer, "roblox corporation", Some("Roblox")),
                entry(CatalogKind::TrustedPublisher, MatchType::Signer, "google llc", None),
                entry(CatalogKind::TrustedPublisher, MatchType::Signer, "microsoft corporation", None),
            ],
        })
    }

    const STEAM_CS2: &str = r"d:\steam\steamapps\common\counter-strike global offensive";
    const PIXEL: &str = r"c:\users\mia\downloads\pixel quest";

    fn inventory() -> Inventory {
        let cs2 = FoundApp {
            app: "Counter-Strike 2".into(),
            ids: vec![AppId::new(AppIdKind::Steam, "730")],
            source: Some(AppSource::Catalog),
            category: Some(Category::Games),
        };
        let pixel = FoundApp {
            app: "Pixel Quest".into(),
            ids: vec![AppId::exe(None, "Pixel Quest")],
            source: Some(AppSource::UnknownPublisher),
            category: Some(Category::Games),
        };
        let apps: BTreeMap<String, FoundApp> = [cs2, pixel].into_iter().map(|a| (a.app.clone(), a)).collect();
        let places = [
            Place { dir: STEAM_CS2.into(), app: Some("Counter-Strike 2".into()) },
            Place { dir: PIXEL.into(), app: Some("Pixel Quest".into()) },
            Place { dir: r"c:\program files\google\chrome".into(), app: None },
            Place { dir: r"d:\steam".into(), app: None },
        ];
        Inventory::new(&places, Some(&apps))
    }

    fn inputs(rules: Rules) -> Inputs {
        Inputs {
            paired: true,
            rules,
            zone: FamilyZone::new("Asia/Manila").unwrap(),
            clock: TrustedClock::default(),
            classifier: Some(catalog()),
            inventory: inventory(),
        }
    }

    fn rules_with(apps: Vec<AppRule>) -> Rules {
        Rules { policy: Policy::default(), apps, category_limits: vec![], extra_time_until_ms: None }
    }

    /// 15:00 on Thursday 2026-10-22 in Manila, `secs` later, on a clock nobody changed.
    fn at(secs: u64) -> ClockSample {
        let wall = parse_iso_ms("2026-10-22T07:00:00Z").unwrap() + (secs * 1000) as i64;
        ClockSample { mono_ms: 1_000_000 + secs * 1000, boot_id: 1, wall_ms: wall }
    }

    fn cs2_exe(file: &str) -> Program {
        program(
            &format!(r"D:\Steam\steamapps\common\Counter-Strike Global Offensive\game\bin\win64\{file}"),
            Some("valve corp."),
            Some("Counter-Strike 2"),
        )
    }

    #[test]
    fn programs_resolve_by_folder_then_id_then_name() {
        let cs2 = rule("Counter-Strike 2", Approval::Blocked, None, Category::Games, &[AppId::new(AppIdKind::Steam, "730")]);
        let i = inputs(rules_with(vec![cs2.clone()]));
        // Acceptance test 4: renamed, it's still appid 730
        for file in ["cs2.exe", "notcs2.exe"] {
            let Resolved::App(a) = resolve(&cs2_exe(file), &i) else { panic!("{file} not resolved") };
            assert_eq!(a.rule.as_ref(), Some(&cs2), "{file}");
        }
        // Signed by Roblox: the catalog's game, matched to the list by name
        let roblox = rule("Roblox", Approval::Allowed, Some(30), Category::Games, &[]);
        let i = inputs(rules_with(vec![roblox.clone()]));
        let p = program(r"C:\Users\Mia\AppData\Local\Roblox\Versions\v1\RobloxPlayerBeta.exe", Some("roblox corporation"), Some("Roblox"));
        let Resolved::App(a) = resolve(&p, &i) else { panic!() };
        assert_eq!((a.name.as_str(), a.rule.as_ref()), ("Roblox", Some(&roblox)));
    }

    #[test]
    fn what_is_never_ended() {
        let i = inputs(rules_with(vec![]));
        let mut ours = program(r"C:\Program Files\eGuard\eguard-agent.exe", None, None);
        ours.ours = true;
        assert_eq!(resolve(&ours, &i), Resolved::Exempt(Exempt::Ours));
        let mut notepad = program(r"C:\Windows\System32\notepad.exe", Some("microsoft windows"), None);
        notepad.windows = true;
        assert_eq!(resolve(&notepad, &i), Resolved::Exempt(Exempt::Windows));
        let nvda = program(r"C:\Program Files (x86)\NVDA\nvda.exe", Some("nv access limited"), None);
        assert_eq!(resolve(&nvda, &i), Resolved::Exempt(Exempt::Accessibility));
        // A game renamed to nvda.exe isn't signed by NV Access
        let fake = program(r"C:\Users\Mia\Downloads\nvda.exe", None, None);
        assert!(matches!(resolve(&fake, &i), Resolved::App(_)));
        let chrome = program(r"C:\Program Files\Google\Chrome\Application\chrome.exe", Some("google llc"), Some("Google Chrome"));
        assert_eq!(resolve(&chrome, &i), Resolved::Exempt(Exempt::Trusted));
        // An unsigned helper inside a trusted app's folder is part of that app
        let helper = program(r"C:\Program Files\Google\Chrome\Application\helper.exe", None, None);
        assert_eq!(resolve(&helper, &i), Resolved::Exempt(Exempt::Trusted));
        // A Steam game made by a trusted publisher is still a game (launcher before trust)
        let mut ms_game = cs2_exe("cs2.exe");
        ms_game.exe.signer = Some("microsoft corporation".into());
        assert!(matches!(resolve(&ms_game, &i), Resolved::App(_)));
        // Signed by a publisher eGuard doesn't know, not found by the scan, under Program Files: a driver's tool
        let tool = program(r"C:\Program Files\Realtek\Audio\RtkAudUService64.exe", Some("realtek semiconductor corp."), None);
        assert_eq!(resolve(&tool, &i), Resolved::Untracked);
        // Unsigned outside Program Files: App Approval applies
        let loose = program(r"C:\Users\Mia\Desktop\coolgame.exe", None, None);
        assert!(matches!(resolve(&loose, &i), Resolved::App(AppMatch { ref name, rule: None, .. }) if name == "coolgame"));
    }

    #[test]
    fn nothing_is_enforced_unpaired_or_before_a_catalog_nothing_is_trusted() {
        let mut i = inputs(rules_with(vec![]));
        let chrome = program(r"C:\Program Files\Google\Chrome\Application\chrome.exe", Some("google llc"), Some("Google Chrome"));
        i.classifier = None;
        // Not trusted, but not something approval applies to either: signed, under Program Files, not in a place
        i.inventory = Inventory::default();
        assert_eq!(resolve(&chrome, &i), Resolved::Untracked);
        let mut e = Enforcer::new(UsageLedger::default(), Memo::default());
        e.update(Inputs { paired: false, ..inputs(rules_with(vec![])) });
        let loose = program(r"C:\Users\Mia\Desktop\coolgame.exe", None, None);
        assert_eq!(e.check(&loose, at(0)), Decision::Ignore);
    }

    fn enforcer(rules: Rules) -> Enforcer {
        let mut e = Enforcer::new(UsageLedger::default(), Memo::default());
        e.update(inputs(rules));
        e
    }

    #[test]
    fn a_blocked_app_is_ended_reported_once_and_can_be_asked_for() {
        // Acceptance test 3
        let cs2 = rule("Counter-Strike 2", Approval::Blocked, None, Category::Games, &[AppId::new(AppIdKind::Steam, "730")]);
        let mut e = enforcer(rules_with(vec![cs2]));
        let d = e.check(&cs2_exe("cs2.exe"), at(0));
        assert_eq!(d, Decision::End { app: "Counter-Strike 2".into(), block: Block::Blocked });
        assert_eq!(e.check(&cs2_exe("cs2.exe"), at(5)), d);
        assert_eq!(e.take_events(), vec![DeviceEvent::AppBlocked { app: "Counter-Strike 2".into() }]);

        e.ended(1, "Counter-Strike 2", Block::Blocked, at(1));
        e.ended(1, "Counter-Strike 2", Block::Blocked, at(6));
        let view = e.heartbeat(1, Seen::Ours, 0, at(7));
        let screen = view.block.unwrap();
        assert_eq!(screen.title, "Counter-Strike 2 is blocked");
        assert!(screen.ask_parent && !screen.ask_time);
        // Another session doesn't see it
        assert!(e.heartbeat(2, Seen::Ours, 0, at(7)).block.is_none());

        assert_eq!(
            e.ask(1, Ask::Parent { notice: screen.id }, at(8)).unwrap(),
            "Asked. Counter-Strike 2 opens once your parent allows it."
        );
        assert_eq!(e.ask(1, Ask::Parent { notice: screen.id }, at(9)).unwrap(), "You already asked. Your parent has been told.");
        assert_eq!(e.take_events(), vec![DeviceEvent::AppRequested { app: "Counter-Strike 2".into() }]);
        assert_eq!(
            e.heartbeat(1, Seen::Ours, 0, at(10)).block.unwrap().asked.as_deref(),
            Some("You already asked. Your parent has been told.")
        );
        // A blocked app can't be asked for as "more time", and a made-up notice is refused
        assert!(e.ask(1, Ask::Time { notice: Some(screen.id) }, at(11)).is_err());
        assert!(e.ask(1, Ask::Parent { notice: 999 }, at(11)).is_err());
        // The screen goes after a while
        assert!(e.heartbeat(1, Seen::Ours, 0, at(200)).block.is_none());
    }

    #[test]
    fn approval_and_pending() {
        let mut r = rules_with(vec![rule("Pixel Quest", Approval::Pending, None, Category::Games, &[])]);
        r.policy.approval_required = true;
        let mut e = enforcer(r);
        let pixel = program(r"C:\Users\Mia\Downloads\Pixel Quest\PixelQuest.exe", None, None);
        assert_eq!(e.check(&pixel, at(0)), Decision::End { app: "Pixel Quest".into(), block: Block::Pending });
        let new = program(r"C:\Users\Mia\Desktop\coolgame.exe", None, None);
        assert_eq!(e.check(&new, at(0)), Decision::End { app: "coolgame".into(), block: Block::NeedsApproval });
        // Only a blocked app raises APP_BLOCKED
        assert_eq!(e.take_events(), Vec::<DeviceEvent>::new());
    }

    /// Plays `app` in the foreground with input, one heartbeat a second, for `secs` seconds from `from`.
    fn play(e: &mut Enforcer, p: &Program, from: u64, secs: u64) -> Vec<SessionView> {
        (from..=from + secs).map(|t| e.heartbeat(1, Seen::Program(p), 1_000, at(t))).collect()
    }

    #[test]
    fn gaming_time_warns_then_ends_then_alerts() {
        // Acceptance test 5, with Gaming time at 6 minutes so both warnings show
        let mut r = rules_with(vec![rule("Roblox", Approval::Allowed, None, Category::Games, &[])]);
        r.category_limits = vec![CategoryLimit { category: Category::Games, daily_limit_minutes: 6 }];
        let mut e = enforcer(r);
        let roblox =
            program(r"C:\Users\Mia\AppData\Local\Roblox\Versions\v1\RobloxPlayerBeta.exe", Some("roblox corporation"), Some("Roblox"));
        let views = play(&mut e, &roblox, 0, 6 * 60);
        let warnings: Vec<String> = views.iter().filter_map(|v| v.warning.as_ref().map(|w| w.text.clone())).collect();
        assert_eq!(warnings, ["5 minutes of gaming time left today.", "1 minute of gaming time left today."]);
        assert_eq!(
            e.check(&roblox, at(6 * 60 + 1)),
            Decision::End { app: "Roblox".into(), block: Block::CategoryLimit { category: Category::Games, minutes: 6 } }
        );
        assert_eq!(e.take_events(), vec![DeviceEvent::LimitReached { minutes: 6, category: Some(Category::Games) }]);
        // Once a day
        play(&mut e, &roblox, 6 * 60 + 2, 5);
        assert_eq!(e.take_events(), Vec::<DeviceEvent>::new());
        // The block screen offers more time, which asks for CATEGORY_LIMIT on Roblox
        e.ended(1, "Roblox", Block::CategoryLimit { category: Category::Games, minutes: 6 }, at(400));
        let screen = e.heartbeat(1, Seen::Ours, 0, at(401)).block.unwrap();
        assert_eq!(screen.title, "Gaming time used up");
        assert!(screen.ask_time && !screen.ask_parent);
        e.ask(1, Ask::Time { notice: Some(screen.id) }, at(402)).unwrap();
        assert_eq!(
            e.take_events(),
            vec![DeviceEvent::TimeRequested { app: Some("Roblox".into()), reason: Some(TimeRequestReason::CategoryLimit) }]
        );
        // And the usage that goes with the alert is due now, not in five minutes
        let usage = e.usage_due(at(403));
        assert_eq!(usage.len(), 1);
        assert_eq!(usage[0].apps[0].name, "Roblox");
        assert!(usage[0].total_minutes >= 6);
    }

    #[test]
    fn only_focused_time_with_input_counts() {
        let mut e = enforcer(rules_with(vec![]));
        let pixel = program(r"C:\Users\Mia\Downloads\Pixel Quest\PixelQuest.exe", None, None);
        // Idle for three minutes: a game left running doesn't count
        for t in 0..=60 {
            e.heartbeat(1, Seen::Program(&pixel), 3 * 60_000, at(t));
        }
        // eGuard's own screens don't count either
        for t in 61..=120 {
            e.heartbeat(1, Seen::Ours, 0, at(t));
        }
        // No heartbeat for a minute (asleep): not counted
        e.heartbeat(1, Seen::Program(&pixel), 0, at(180));
        e.heartbeat(1, Seen::Program(&pixel), 0, at(240));
        assert_eq!(e.ledger().day("2026-10-22").map_or(0, DayUsage::total_secs), 0);
        play(&mut e, &pixel, 300, 60);
        let day = e.ledger().day("2026-10-22").unwrap();
        assert_eq!((day.total_secs(), day.app_secs("Pixel Quest")), (60, 60));
        // No agent in a signed-in session: counted, toward the day only
        for t in 400..=430 {
            e.heartbeat(1, Seen::Unknown, 0, at(t));
        }
        assert_eq!(e.ledger().day("2026-10-22").unwrap().total_secs(), 90);
    }

    #[test]
    fn moving_the_clock_forward_gains_nothing() {
        // Acceptance test 6: the wall clock jumps an hour, eGuard's clock doesn't
        let mut r = rules_with(vec![]);
        r.policy.screen_time = Some((2, 2));
        let mut e = enforcer(r);
        let mut i = inputs(e.inputs.rules.clone());
        i.clock.on_server_time(at(0).wall_ms, at(0));
        e.update(i);
        let pixel = program(r"C:\Users\Mia\Downloads\Pixel Quest\PixelQuest.exe", None, None);
        play(&mut e, &pixel, 0, 60);
        let mut jumped = at(61);
        jumped.wall_ms += 3_600_000;
        let v = e.heartbeat(1, Seen::Program(&pixel), 0, jumped);
        let day = e.ledger().day("2026-10-22").unwrap();
        assert_eq!(day.total_secs(), 61);
        assert!(v.overlay.is_none());
        // The minute left still counts down by real time
        play(&mut e, &pixel, 62, 60);
        assert!(e.heartbeat(1, Seen::Program(&pixel), 0, at(123)).overlay.is_some());
    }

    #[test]
    fn the_overlay_leaves_always_allowed_apps_usable() {
        let mut r = rules_with(vec![
            rule("Khan Academy", Approval::AlwaysAllowed, None, Category::Education, &[]),
            rule("Pixel Quest", Approval::Allowed, None, Category::Games, &[]),
        ]);
        r.policy.screen_time = Some((1, 1));
        let mut e = enforcer(r);
        let pixel = program(r"C:\Users\Mia\Downloads\Pixel Quest\PixelQuest.exe", None, None);
        let views = play(&mut e, &pixel, 0, 61);
        let last = views.last().unwrap().overlay.as_ref().unwrap();
        assert_eq!(last.title, "Screen time is up for today");
        assert_eq!(last.body, "You've used today's 1 minute. You can still use Khan Academy.");
        assert_eq!(e.check(&pixel, at(62)), Decision::End { app: "Pixel Quest".into(), block: Block::DailyLimit { minutes: 1 } });
        let khan = program(r"C:\Users\Mia\AppData\Local\Khan\khan.exe", None, Some("Khan Academy"));
        assert_eq!(e.check(&khan, at(62)), Decision::Allow);
        assert!(e.heartbeat(1, Seen::Program(&khan), 0, at(63)).overlay.is_none());
        assert!(e.heartbeat(1, Seen::Nothing, 0, at(64)).overlay.is_some());
        // Ask for more time from the overlay
        assert_eq!(e.screen_paused(at(65)), Some(Block::DailyLimit { minutes: 1 }));
        e.ask(1, Ask::Time { notice: None }, at(65)).unwrap();
        assert!(e.heartbeat(1, Seen::Nothing, 0, at(66)).overlay.unwrap().asked.is_some());
        let events = e.take_events();
        assert!(events.contains(&DeviceEvent::TimeRequested { app: None, reason: Some(TimeRequestReason::DailyLimit) }));
        assert!(events.contains(&DeviceEvent::LimitReached { minutes: 1, category: None }));
    }

    #[test]
    fn bedtime_pauses_everything_and_extra_time_lifts_it() {
        let mut r = rules_with(vec![rule("Khan Academy", Approval::AlwaysAllowed, None, Category::Education, &[])]);
        // 15:00 to 16:00 every day, in Manila
        r.policy.bedtime = Some(Bedtime { start_min: 15 * 60, end_min: 16 * 60, school_nights_only: false });
        let mut e = enforcer(r.clone());
        let khan = program(r"C:\Users\Mia\AppData\Local\Khan\khan.exe", None, Some("Khan Academy"));
        assert_eq!(e.check(&khan, at(0)), Decision::End { app: "Khan Academy".into(), block: Block::Bedtime });
        assert_eq!(e.heartbeat(1, Seen::Program(&khan), 0, at(1)).overlay.unwrap().title, "It's bedtime");
        r.extra_time_until_ms = Some(at(0).wall_ms + 10 * 60_000);
        e.update(inputs(r));
        assert_eq!(e.check(&khan, at(2)), Decision::Allow);
        assert!(e.heartbeat(1, Seen::Program(&khan), 0, at(3)).overlay.is_none());
    }

    #[test]
    fn bedtime_warns_from_any_window() {
        let mut r = rules_with(vec![]);
        r.policy.bedtime = Some(Bedtime { start_min: 15 * 60 + 5, end_min: 16 * 60, school_nights_only: false });
        let mut e = enforcer(r);
        let w = e.heartbeat(1, Seen::Nothing, 0, at(0)).warning.unwrap();
        assert_eq!(w.text, "Bedtime starts in 5 minutes.");
        assert!(e.heartbeat(1, Seen::Nothing, 0, at(1)).warning.is_none());
        assert_eq!(e.heartbeat(1, Seen::Nothing, 0, at(250)).warning.unwrap().text, "Bedtime starts in 1 minute.");
    }

    #[test]
    fn usage_is_queued_every_five_minutes_with_ids() {
        let cs2 = rule("Counter-Strike 2", Approval::Allowed, None, Category::Games, &[AppId::new(AppIdKind::Steam, "730")]);
        let mut e = enforcer(rules_with(vec![cs2]));
        play(&mut e, &cs2_exe("cs2.exe"), 0, 120);
        let first = e.usage_due(at(121));
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].apps[0].ids, vec![AppId::new(AppIdKind::Steam, "730"), AppId::exe(Some("valve corp."), "Counter-Strike 2")]);
        assert_eq!(first[0].hourly.unwrap()[15], 2);
        play(&mut e, &cs2_exe("cs2.exe"), 122, 30);
        assert_eq!(e.usage_due(at(160)), Vec::<UsageReport>::new());
        assert_eq!(e.usage_due(at(121 + 300)).len(), 1);
        assert_eq!(e.usage_due(at(121 + 600)), Vec::<UsageReport>::new());
    }

    #[test]
    fn texts() {
        assert_eq!(minutes(1), "1 minute");
        assert_eq!(minutes(90), "90 minutes");
        assert_eq!(minutes(120), "2 hours");
        let s = block_screen(1, "Roblox", Block::AppLimit { minutes: 60 }, None);
        assert_eq!((s.title.as_str(), s.body.as_str()), ("Time's up for Roblox", "You've used today's 1 hour of Roblox."));
        assert_eq!(block_screen(1, "X", Block::DailyLimit { minutes: 120 }, None).body, "You've used today's 2 hours.");
    }
}
