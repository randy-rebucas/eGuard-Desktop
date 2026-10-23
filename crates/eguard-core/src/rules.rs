//! What the parent's rules say about one app right now (spec section 7, child-app-spec section 7).
//!
//! - `BLOCKED`, `FILTERED` and an approval this build doesn't know are blocked; `PENDING` waits for the parent.
//! - An app not on the list waits for the parent when App Approval or Downloads approval is on.
//! - Bedtime (in the family's zone, `bedtime_active`), the app's own daily limit, its category's limit and the daily
//!   screen time pause it. `ALWAYS_ALLOWED` skips the daily and category limits only; bedtime and its own limit
//!   still apply (as the parent is told in the Apps tab, and as phones enforce it).
//! - While extra time runs, nothing pauses for time; blocked and pending apps stay blocked.
//!
//! Which processes are subject to rules at all (never system binaries, eGuard, accessibility tools or a trusted
//! publisher's non-game app) is decided before this, by the classifier.

use crate::localtime::LocalMoment;
use crate::usage::DayUsage;
use crate::wire::{
    AppRule, Approval, BedtimeDays, Category, CategoryLimit, PolicyEntry, ProtectionConfig, SyncResponse, TimeRequestReason, WebMode,
};

/// How far ahead `seconds_left` looks for a bedtime about to start (warnings are at 5 and 1 minutes).
const BEDTIME_LOOKAHEAD_SECS: u32 = 15 * 60;

/// A bedtime window, parsed. Only an enabled one with valid, different times exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bedtime {
    pub start_min: u32,
    pub end_min: u32,
    pub school_nights_only: bool,
}

impl Bedtime {
    pub fn from_config(c: &ProtectionConfig) -> Option<Self> {
        let ProtectionConfig::Bedtime { enabled: true, start, end, days } = c else { return None };
        let (start_min, end_min) = (parse_hhmm(start)?, parse_hhmm(end)?);
        (start_min != end_min).then_some(Self {
            start_min,
            end_min,
            // An unknown `days` value is read as every day: the stricter choice
            school_nights_only: *days == BedtimeDays::SchoolNights,
        })
    }
}

/// `"HH:MM"`, 24-hour, to minutes since midnight.
pub fn parse_hhmm(s: &str) -> Option<u32> {
    let (h, m) = s.split_once(':')?;
    if h.len() != 2 || m.len() != 2 {
        return None;
    }
    let (h, m) = (h.parse::<u32>().ok()?, m.parse::<u32>().ok()?);
    (h < 24 && m < 60).then_some(h * 60 + m)
}

/// Sunday (0) to Thursday (4): the evenings before a school day.
pub fn is_school_night(weekday: u8) -> bool {
    weekday <= 4
}

/// Port of `bedtimeActive` in `~/eguard/src/lib/protections.ts`. Each window belongs to a night: the evening it
/// starts on, or the evening before when it starts in the morning (before noon). So with school nights, 21:30–06:00
/// runs from Thursday 21:30 to Friday 06:00 and not on Friday or Saturday night.
pub fn bedtime_active(b: Bedtime, weekday: u8, minutes: u32) -> bool {
    let crosses = b.start_min > b.end_min;
    let inside = if crosses { minutes >= b.start_min || minutes < b.end_min } else { minutes >= b.start_min && minutes < b.end_min };
    if !inside {
        return false;
    }
    if !b.school_nights_only {
        return true;
    }
    let start_day = if crosses && minutes < b.end_min { u32::from(weekday) + 6 } else { u32::from(weekday) };
    let night = if b.start_min < 12 * 60 { start_day + 6 } else { start_day };
    is_school_night((night % 7) as u8)
}

/// The child's settings that matter for enforcement, from `/sync` `policy`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Policy {
    /// `(dailyMinutes, weekendMinutes)`; 0 means no limit.
    pub screen_time: Option<(u32, u32)>,
    pub bedtime: Option<Bedtime>,
    /// App Approval on, or Downloads "parent approval": new apps wait for the parent.
    pub approval_required: bool,
    /// Web filtering on (any mode but off, including one this build doesn't know): a browser eGuard's extension
    /// can't run in waits for the parent (spec section 9).
    pub web_filter: bool,
}

impl Policy {
    pub fn from_entries(entries: &[PolicyEntry]) -> Self {
        let mut p = Self::default();
        for e in entries {
            match &e.config {
                ProtectionConfig::ScreenTime { daily_minutes, weekend_minutes } => p.screen_time = Some((*daily_minutes, *weekend_minutes)),
                c @ ProtectionConfig::Bedtime { .. } => p.bedtime = Bedtime::from_config(c),
                ProtectionConfig::AppApproval { enabled } => p.approval_required |= *enabled,
                ProtectionConfig::Downloads { require_approval } => p.approval_required |= *require_approval,
                ProtectionConfig::Web { mode, .. } => p.web_filter = *mode != WebMode::Off,
                _ => {}
            }
        }
        p
    }

    /// Today's screen-time limit in minutes, or `None` for no limit.
    pub fn daily_limit(&self, at: &LocalMoment) -> Option<u32> {
        let (daily, weekend) = self.screen_time?;
        let limit = if at.is_weekend() { weekend } else { daily };
        (limit > 0).then_some(limit)
    }
}

/// Everything the agent enforces, as last synced. Kept on disk and enforced offline.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Rules {
    pub policy: Policy,
    pub apps: Vec<AppRule>,
    pub category_limits: Vec<CategoryLimit>,
    pub extra_time_until_ms: Option<i64>,
}

impl Rules {
    pub fn from_sync(s: &SyncResponse) -> Self {
        Self {
            policy: Policy::from_entries(&s.policy),
            apps: s.apps.clone(),
            category_limits: s.category_limits.clone(),
            extra_time_until_ms: s.extra_time_until.as_deref().and_then(crate::clock::parse_iso_ms),
        }
    }

    /// The rule for an app name, as the server lists it.
    pub fn app(&self, name: &str) -> Option<&AppRule> {
        self.apps.iter().find(|a| a.name == name)
    }

    /// The category an app counts under: its rule's, else what it was recorded with, else `Other`.
    pub fn category_of(&self, name: &str, recorded: Option<Category>) -> Category {
        self.app(name).map(|a| a.category).or(recorded).unwrap_or(Category::Other).effective()
    }

    pub fn category_limit(&self, category: Category) -> Option<u32> {
        self.category_limits.iter().find(|l| l.category.effective() == category).map(|l| l.daily_limit_minutes)
    }

    pub fn extra_time_running(&self, now_ms: i64) -> bool {
        self.extra_time_until_ms.is_some_and(|until| now_ms < until)
    }
}

/// The app being decided on.
#[derive(Debug, Clone, Copy)]
pub enum Subject<'a> {
    /// On the child's list (matched by id first, then name).
    Listed(&'a AppRule),
    /// Not on the list yet. Counts as `category` (from the scan or the catalog, else `Other`).
    Unlisted { name: &'a str, category: Category },
}

impl Subject<'_> {
    pub fn name(&self) -> &str {
        match self {
            Subject::Listed(a) => &a.name,
            Subject::Unlisted { name, .. } => name,
        }
    }
}

/// Why an app is blocked. The first four never end by themselves; the rest are about time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Block {
    /// `BLOCKED`, `FILTERED`, or an approval this build doesn't know. "Ask parent" sends `APP_REQUESTED`.
    Blocked,
    /// `PENDING`: waiting for the parent.
    Pending,
    /// Not on the list, and approval is on: send `APP_REQUESTED`, then it's pending.
    NeedsApproval,
    /// A browser eGuard's extension can't run in, not on the list while web filtering is on: like `NeedsApproval`,
    /// whether or not approval is on, since websites in it would go unfiltered.
    Browser,
    Bedtime,
    AppLimit {
        minutes: u32,
    },
    CategoryLimit {
        category: Category,
        minutes: u32,
    },
    DailyLimit {
        minutes: u32,
    },
}

impl Block {
    /// Paused for time (extra time lifts it), rather than not allowed at all.
    pub fn is_time(self) -> bool {
        !matches!(self, Block::Blocked | Block::Pending | Block::NeedsApproval | Block::Browser)
    }

    /// "Ask for more time" sends `TIME_REQUESTED` with this reason.
    pub fn time_request_reason(self) -> Option<TimeRequestReason> {
        match self {
            Block::Bedtime => Some(TimeRequestReason::Bedtime),
            Block::AppLimit { .. } => Some(TimeRequestReason::AppLimit),
            Block::CategoryLimit { .. } => Some(TimeRequestReason::CategoryLimit),
            Block::DailyLimit { .. } => Some(TimeRequestReason::DailyLimit),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Usable. `seconds_left`: until a limit, bedtime or the end of extra time would pause it, when that's soon
    /// enough to matter (for the 5- and 1-minute warnings).
    Allow {
        seconds_left: Option<u32>,
    },
    Block(Block),
}

/// Each time rule that applies to `subject` now, as (seconds left, the block once it's 0). Bedtime first, then the
/// narrowest limit: the order the block screen names them in.
fn time_rules(rules: &Rules, subject: Subject<'_>, always: bool, today: &DayUsage, at: &LocalMoment) -> Vec<(u32, Block)> {
    let mut limits: Vec<(u32, Block)> = Vec::new();
    if let Some(b) = rules.policy.bedtime {
        let left = seconds_until_bedtime(b, at);
        if left <= BEDTIME_LOOKAHEAD_SECS {
            limits.push((left, Block::Bedtime));
        }
    }
    if let Subject::Listed(AppRule { daily_limit_minutes: Some(minutes), name, .. }) = subject {
        limits.push((left(*minutes, today.app_secs(name)), Block::AppLimit { minutes: *minutes }));
    }
    if !always {
        let category = match subject {
            Subject::Listed(a) => a.category.effective(),
            Subject::Unlisted { category, .. } => category.effective(),
        };
        if let Some(minutes) = rules.category_limit(category) {
            let used = today.category_secs(category, |name, recorded| rules.category_of(name, recorded));
            limits.push((left(minutes, used), Block::CategoryLimit { category, minutes }));
        }
        if let Some(minutes) = rules.policy.daily_limit(at) {
            limits.push((left(minutes, today.total_secs()), Block::DailyLimit { minutes }));
        }
    }
    limits
}

/// The approval part of the verdict: `Err` when the app isn't allowed at all, else whether it's always allowed.
fn approval_of(rules: &Rules, subject: Subject<'_>) -> Result<bool, Block> {
    let approval = match subject {
        Subject::Listed(a) => a.approval,
        Subject::Unlisted { category, .. } if rules.policy.web_filter && category.effective() == Category::Browsers => {
            return Err(Block::Browser);
        }
        Subject::Unlisted { .. } if rules.policy.approval_required => return Err(Block::NeedsApproval),
        Subject::Unlisted { .. } => Approval::Allowed,
    };
    match approval {
        Approval::Blocked | Approval::Filtered | Approval::Unknown => Err(Block::Blocked),
        Approval::Pending => Err(Block::Pending),
        Approval::Allowed => Ok(false),
        Approval::AlwaysAllowed => Ok(true),
    }
}

/// The verdict for one app at `at` (the family's local time) and `now_ms` (eGuard's clock), given today's usage.
pub fn evaluate(rules: &Rules, subject: Subject<'_>, today: &DayUsage, at: &LocalMoment, now_ms: i64) -> Verdict {
    let always = match approval_of(rules, subject) {
        Ok(always) => always,
        Err(b) => return Verdict::Block(b),
    };
    let limits = time_rules(rules, subject, always, today, at);
    let blocked = limits.iter().find(|(secs, _)| *secs == 0).map(|(_, b)| *b);
    let soonest = limits.iter().map(|(secs, _)| *secs).min();
    let extra = rules.extra_time_until_ms.filter(|&until| now_ms < until);
    match (blocked, extra) {
        (Some(_), Some(until)) => Verdict::Allow { seconds_left: Some(secs_between(now_ms, until)) },
        (Some(b), None) => Verdict::Block(b),
        (None, Some(until)) => Verdict::Allow { seconds_left: soonest.map(|s| s.max(secs_between(now_ms, until))) },
        (None, None) => Verdict::Allow { seconds_left: soonest },
    }
}

/// What pauses a usable app next, and in how many seconds, for the 5- and 1-minute warnings. `None` when nothing
/// does soon, or the app isn't usable now. While extra time runs, it's the end of extra time (as the block it lifts,
/// or `None` when nothing would be paused then).
pub fn upcoming(rules: &Rules, subject: Subject<'_>, today: &DayUsage, at: &LocalMoment, now_ms: i64) -> Option<(u32, Block)> {
    let always = approval_of(rules, subject).ok()?;
    let limits = time_rules(rules, subject, always, today, at);
    upcoming_of(&limits, rules, now_ms)
}

/// `upcoming` for the screen as a whole (an app that isn't on the list, eGuard's own screens): daily screen time
/// and bedtime.
pub fn upcoming_screen(rules: &Rules, today: &DayUsage, at: &LocalMoment, now_ms: i64) -> Option<(u32, Block)> {
    let mut limits = Vec::new();
    if let Some(b) = rules.policy.bedtime {
        let left = seconds_until_bedtime(b, at);
        if left <= BEDTIME_LOOKAHEAD_SECS {
            limits.push((left, Block::Bedtime));
        }
    }
    if let Some(minutes) = rules.policy.daily_limit(at) {
        limits.push((left(minutes, today.total_secs()), Block::DailyLimit { minutes }));
    }
    upcoming_of(&limits, rules, now_ms)
}

fn upcoming_of(limits: &[(u32, Block)], rules: &Rules, now_ms: i64) -> Option<(u32, Block)> {
    match rules.extra_time_until_ms.filter(|&until| now_ms < until) {
        // Extra time ends: what would be paused then is whatever is used up by then (or about to be)
        Some(until) => {
            let ends = secs_between(now_ms, until);
            limits.iter().filter(|(secs, _)| *secs <= ends).min_by_key(|(secs, _)| *secs).map(|(_, b)| (ends, *b))
        }
        // Already paused: nothing to warn about
        None if limits.iter().any(|(secs, _)| *secs == 0) => None,
        None => limits.iter().min_by_key(|(secs, _)| *secs).copied(),
    }
}

/// Whether the whole screen is paused (the overlay, spec section 8): bedtime, or the day's screen time used up,
/// unless extra time runs. Only always-allowed apps stay usable under it, and only for daily screen time.
pub fn screen_paused(rules: &Rules, today: &DayUsage, at: &LocalMoment, now_ms: i64) -> Option<Block> {
    if rules.extra_time_running(now_ms) {
        return None;
    }
    if rules.policy.bedtime.is_some_and(|b| bedtime_active(b, at.weekday, at.minutes())) {
        return Some(Block::Bedtime);
    }
    let minutes = rules.policy.daily_limit(at)?;
    (left(minutes, today.total_secs()) == 0).then_some(Block::DailyLimit { minutes })
}

fn left(limit_minutes: u32, used_secs: u32) -> u32 {
    (limit_minutes * 60).saturating_sub(used_secs)
}

fn secs_between(from_ms: i64, to_ms: i64) -> u32 {
    ((to_ms - from_ms).max(0) / 1000).min(i64::from(u32::MAX)) as u32
}

/// Seconds until bedtime is in force: 0 while it is, else counted ahead minute by minute (wall-clock minutes in the
/// family's zone) up to the lookahead, and past it the lookahead plus one.
fn seconds_until_bedtime(b: Bedtime, at: &LocalMoment) -> u32 {
    if bedtime_active(b, at.weekday, at.minutes()) {
        return 0;
    }
    let into_minute = at.second_of_day % 60;
    for k in 1..=BEDTIME_LOOKAHEAD_SECS / 60 {
        let total = at.second_of_day / 60 + k;
        let (weekday, minutes) = ((u32::from(at.weekday) + total / 1440) % 7, total % 1440);
        if bedtime_active(b, weekday as u8, minutes) {
            return k * 60 - into_minute;
        }
    }
    BEDTIME_LOOKAHEAD_SECS + 1
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::usage::{DayUsage, UsageApp};

    const SUN: u8 = 0;
    const THU: u8 = 4;
    const FRI: u8 = 5;
    const SAT: u8 = 6;

    fn hm(s: &str) -> u32 {
        parse_hhmm(s).unwrap()
    }
    fn bed(school: bool, start: &str, end: &str) -> Bedtime {
        Bedtime { start_min: hm(start), end_min: hm(end), school_nights_only: school }
    }
    fn moment(weekday: u8, hhmm: &str) -> LocalMoment {
        LocalMoment { date: "2026-10-22".into(), weekday, second_of_day: hm(hhmm) * 60 }
    }

    /// The same table as `src/lib/test/device-rules.test.ts` on the server.
    #[test]
    fn bedtime_matches_the_server_reference() {
        let every = bed(false, "21:30", "06:00");
        let school = bed(true, "21:30", "06:00");
        let morning = bed(true, "00:30", "06:00");
        let cases: &[(Bedtime, u8, &str, bool)] = &[
            (every, FRI, "21:30", true),
            (every, SAT, "05:59", true),
            (every, SAT, "06:00", false),
            (every, SAT, "21:29", false),
            (school, THU, "22:00", true),
            (school, FRI, "01:00", true),
            (school, FRI, "22:00", false),
            (school, SAT, "01:00", false),
            (school, SAT, "22:00", false),
            (school, SUN, "01:00", false),
            (school, SUN, "22:00", true),
            (morning, FRI, "01:00", true),
            (morning, SAT, "01:00", false),
        ];
        for &(b, day, time, want) in cases {
            assert_eq!(bedtime_active(b, day, hm(time)), want, "{b:?} day {day} {time}");
        }
        assert!([0, 1, 2, 3, 4].into_iter().all(is_school_night));
        assert!(![5, 6].into_iter().any(is_school_night));
    }

    #[test]
    fn bedtime_off_or_invalid_never_applies() {
        let off = ProtectionConfig::Bedtime { enabled: false, start: "21:00".into(), end: "06:00".into(), days: BedtimeDays::EveryDay };
        assert_eq!(Bedtime::from_config(&off), None);
        let same = ProtectionConfig::Bedtime { enabled: true, start: "21:00".into(), end: "21:00".into(), days: BedtimeDays::EveryDay };
        assert_eq!(Bedtime::from_config(&same), None);
        for bad in ["25:00", "9:30", "21:60", "2130", ""] {
            assert_eq!(parse_hhmm(bad), None, "{bad}");
        }
        // An unknown `days` is enforced every night
        let unknown = ProtectionConfig::Bedtime { enabled: true, start: "21:00".into(), end: "06:00".into(), days: BedtimeDays::Unknown };
        assert!(!Bedtime::from_config(&unknown).unwrap().school_nights_only);
    }

    fn rule(name: &str, approval: Approval, limit: Option<u32>, category: Category) -> AppRule {
        AppRule { name: name.into(), approval, daily_limit_minutes: limit, category, ids: vec![] }
    }

    fn rules() -> Rules {
        Rules {
            policy: Policy {
                screen_time: Some((120, 180)),
                bedtime: Some(bed(true, "21:00", "07:00")),
                approval_required: false,
                web_filter: false,
            },
            apps: vec![
                rule("Roblox", Approval::Allowed, Some(60), Category::Games),
                rule("Minecraft", Approval::Allowed, None, Category::Games),
                rule("Khan Academy", Approval::AlwaysAllowed, None, Category::Education),
                rule("Duolingo", Approval::AlwaysAllowed, Some(30), Category::Education),
                rule("Counter-Strike 2", Approval::Blocked, None, Category::Games),
                rule("Shady Shooter", Approval::Pending, None, Category::Games),
                rule("Filtered App", Approval::Filtered, None, Category::Other),
                rule("Future App", Approval::Unknown, None, Category::Other),
            ],
            category_limits: vec![CategoryLimit { category: Category::Games, daily_limit_minutes: 90 }],
            extra_time_until_ms: None,
        }
    }

    /// Today's usage, filled hour by hour (an hour holds at most 60 minutes).
    fn usage(apps: &[(&str, u32, Category)]) -> DayUsage {
        let mut d = DayUsage::default();
        let (mut hour, mut used) = (0usize, 0u32);
        for &(name, minutes, category) in apps {
            let app = UsageApp { name: name.into(), ids: vec![], category };
            let mut left = minutes;
            while left > 0 {
                let take = left.min(60 - used);
                d.add(Some(&app), hour, take * 60);
                (left, used) = (left - take, used + take);
                if used == 60 {
                    (hour, used) = (hour + 1, 0);
                }
            }
        }
        d
    }

    const NOW: i64 = 1_792_740_000_000;

    fn verdict(r: &Rules, name: &str, today: &DayUsage, at: &LocalMoment) -> Verdict {
        let subject = r.app(name).map_or(Subject::Unlisted { name, category: Category::Other }, Subject::Listed);
        evaluate(r, subject, today, at, NOW)
    }

    #[test]
    fn decision_table() {
        let r = rules();
        let none = usage(&[]);
        let afternoon = moment(THU, "15:00");
        let school_night = moment(THU, "22:00");
        let friday_night = moment(FRI, "22:00");
        let saturday = moment(SAT, "15:00");
        let gamed = usage(&[("Roblox", 60, Category::Games), ("Minecraft", 20, Category::Games)]);
        let gaming_used_up = usage(&[("Roblox", 50, Category::Games), ("Minecraft", 40, Category::Games)]);
        let day_used_up = usage(&[("Minecraft", 30, Category::Games), ("Browser", 90, Category::Other)]);
        let weekend_used = usage(&[("Browser", 150, Category::Other)]);
        let duo_used = usage(&[("Duolingo", 30, Category::Education)]);

        let cases: &[(&str, &DayUsage, &LocalMoment, Verdict)] = &[
            // Approval
            ("Counter-Strike 2", &none, &afternoon, Verdict::Block(Block::Blocked)),
            ("Shady Shooter", &none, &afternoon, Verdict::Block(Block::Pending)),
            ("Filtered App", &none, &afternoon, Verdict::Block(Block::Blocked)),
            ("Future App", &none, &afternoon, Verdict::Block(Block::Blocked)),
            ("Something New", &none, &afternoon, Verdict::Allow { seconds_left: Some(120 * 60) }),
            // Per-app, category and daily limits
            ("Roblox", &none, &afternoon, Verdict::Allow { seconds_left: Some(60 * 60) }),
            ("Roblox", &gamed, &afternoon, Verdict::Block(Block::AppLimit { minutes: 60 })),
            ("Minecraft", &gamed, &afternoon, Verdict::Allow { seconds_left: Some(10 * 60) }),
            ("Minecraft", &gaming_used_up, &afternoon, Verdict::Block(Block::CategoryLimit { category: Category::Games, minutes: 90 })),
            ("Something New", &day_used_up, &afternoon, Verdict::Block(Block::DailyLimit { minutes: 120 })),
            ("Something New", &weekend_used, &saturday, Verdict::Allow { seconds_left: Some(30 * 60) }),
            ("Something New", &weekend_used, &afternoon, Verdict::Block(Block::DailyLimit { minutes: 120 })),
            // Always allowed: past the daily and category limits, not past bedtime or its own limit
            ("Khan Academy", &day_used_up, &afternoon, Verdict::Allow { seconds_left: None }),
            ("Khan Academy", &none, &school_night, Verdict::Block(Block::Bedtime)),
            ("Duolingo", &duo_used, &afternoon, Verdict::Block(Block::AppLimit { minutes: 30 })),
            // Bedtime on school nights only
            ("Minecraft", &none, &school_night, Verdict::Block(Block::Bedtime)),
            ("Minecraft", &none, &friday_night, Verdict::Allow { seconds_left: Some(90 * 60) }),
            ("Minecraft", &none, &moment(FRI, "06:30"), Verdict::Block(Block::Bedtime)),
            // Bedtime coming up counts as time left
            ("Khan Academy", &none, &moment(THU, "20:57"), Verdict::Allow { seconds_left: Some(3 * 60) }),
        ];
        for (name, today, at, want) in cases {
            assert_eq!(verdict(&r, name, today, at), *want, "{name} at {at:?}");
        }
    }

    #[test]
    fn approval_on_makes_new_apps_wait() {
        let mut r = rules();
        r.policy.approval_required = true;
        assert_eq!(verdict(&r, "Something New", &usage(&[]), &moment(THU, "15:00")), Verdict::Block(Block::NeedsApproval));
        // Listed apps are unaffected
        assert!(matches!(verdict(&r, "Minecraft", &usage(&[]), &moment(THU, "15:00")), Verdict::Allow { .. }));
    }

    #[test]
    fn web_filtering_makes_other_browsers_wait_even_without_approval() {
        let at = moment(THU, "15:00");
        let opera = |r: &Rules| evaluate(r, Subject::Unlisted { name: "Opera", category: Category::Browsers }, &usage(&[]), &at, 0);
        let mut r = rules();
        assert!(matches!(opera(&r), Verdict::Allow { .. }));
        r.policy = Policy::from_entries(&[PolicyEntry {
            key: crate::wire::ProtectionKey::Web,
            config: ProtectionConfig::Web { mode: WebMode::Filter, blocked_sites: 0 },
        }]);
        assert!(r.policy.web_filter && !r.policy.approval_required);
        assert_eq!(opera(&r), Verdict::Block(Block::Browser));
        r.policy.approval_required = true;
        assert_eq!(opera(&r), Verdict::Block(Block::Browser));
        // Another unlisted app waits only for approval
        let other = evaluate(&r, Subject::Unlisted { name: "Tool", category: Category::Other }, &usage(&[]), &at, 0);
        assert_eq!(other, Verdict::Block(Block::NeedsApproval));
        // A mode this build doesn't know still filters; off doesn't
        let web = |mode| {
            Policy::from_entries(&[PolicyEntry {
                key: crate::wire::ProtectionKey::Web,
                config: ProtectionConfig::Web { mode, blocked_sites: 0 },
            }])
        };
        assert!(web(WebMode::Unknown).web_filter && web(WebMode::Allowlist).web_filter && !web(WebMode::Off).web_filter);
        assert!(!Block::Browser.is_time());
    }

    #[test]
    fn downloads_approval_counts_as_app_approval() {
        let entries = vec![PolicyEntry {
            key: crate::wire::ProtectionKey::Downloads,
            config: ProtectionConfig::Downloads { require_approval: true },
        }];
        assert!(Policy::from_entries(&entries).approval_required);
    }

    #[test]
    fn extra_time_lifts_time_blocks_but_not_blocked_apps() {
        let mut r = rules();
        r.extra_time_until_ms = Some(NOW + 15 * 60_000);
        let gamed = usage(&[("Roblox", 60, Category::Games)]);
        assert_eq!(verdict(&r, "Roblox", &gamed, &moment(THU, "15:00")), Verdict::Allow { seconds_left: Some(15 * 60) });
        assert_eq!(verdict(&r, "Minecraft", &usage(&[]), &moment(THU, "22:00")), Verdict::Allow { seconds_left: Some(15 * 60) });
        assert_eq!(verdict(&r, "Counter-Strike 2", &usage(&[]), &moment(THU, "15:00")), Verdict::Block(Block::Blocked));
        assert_eq!(verdict(&r, "Shady Shooter", &usage(&[]), &moment(THU, "15:00")), Verdict::Block(Block::Pending));
        assert_eq!(screen_paused(&r, &usage(&[]), &moment(THU, "22:00"), NOW), None);
        // And it ends
        r.extra_time_until_ms = Some(NOW - 1);
        assert_eq!(verdict(&r, "Roblox", &gamed, &moment(THU, "15:00")), Verdict::Block(Block::AppLimit { minutes: 60 }));
    }

    #[test]
    fn the_screen_pauses_for_bedtime_and_the_day_but_not_for_one_app() {
        let r = rules();
        assert_eq!(screen_paused(&r, &usage(&[]), &moment(THU, "22:00"), NOW), Some(Block::Bedtime));
        let day = usage(&[("Browser", 120, Category::Other)]);
        assert_eq!(screen_paused(&r, &day, &moment(THU, "15:00"), NOW), Some(Block::DailyLimit { minutes: 120 }));
        let one_app = usage(&[("Roblox", 60, Category::Games)]);
        assert_eq!(screen_paused(&r, &one_app, &moment(THU, "15:00"), NOW), None);
    }

    #[test]
    fn a_category_newer_than_this_build_counts_as_other() {
        let mut r = rules();
        r.category_limits = vec![CategoryLimit { category: Category::Other, daily_limit_minutes: 10 }];
        r.apps.push(rule("Odd", Approval::Allowed, None, Category::Unknown));
        let used = usage(&[("Odd", 10, Category::Unknown)]);
        assert_eq!(
            verdict(&r, "Odd", &used, &moment(THU, "15:00")),
            Verdict::Block(Block::CategoryLimit { category: Category::Other, minutes: 10 })
        );
    }

    #[test]
    fn no_screen_time_policy_means_no_daily_limit() {
        let mut r = rules();
        r.policy.screen_time = None;
        r.policy.bedtime = None;
        r.category_limits.clear();
        assert_eq!(
            verdict(&r, "Something New", &usage(&[("Browser", 900, Category::Other)]), &moment(THU, "15:00")),
            Verdict::Allow { seconds_left: None }
        );
        r.policy.screen_time = Some((0, 0));
        assert_eq!(
            verdict(&r, "Something New", &usage(&[("Browser", 900, Category::Other)]), &moment(THU, "15:00")),
            Verdict::Allow { seconds_left: None }
        );
    }

    #[test]
    fn upcoming_names_the_next_pause_for_the_warnings() {
        let r = rules();
        let at = moment(THU, "15:00");
        let roblox = Subject::Listed(r.app("Roblox").unwrap());
        // Roblox: 55 of its 60 minutes used; the games category has 90, the day 120
        let used = usage(&[("Roblox", 55, Category::Games)]);
        assert_eq!(upcoming(&r, roblox, &used, &at, NOW), Some((5 * 60, Block::AppLimit { minutes: 60 })));
        // Minecraft: the games category is the next pause (90 - 55)
        let minecraft = Subject::Listed(r.app("Minecraft").unwrap());
        assert_eq!(
            upcoming(&r, minecraft, &used, &at, NOW),
            Some((35 * 60, Block::CategoryLimit { category: Category::Games, minutes: 90 }))
        );
        // Bedtime at 21:00 on a school night
        assert_eq!(upcoming_screen(&r, &usage(&[]), &moment(THU, "20:56"), NOW), Some((4 * 60, Block::Bedtime)));
        assert_eq!(
            upcoming_screen(&r, &usage(&[("Browser", 119, Category::Other)]), &at, NOW),
            Some((60, Block::DailyLimit { minutes: 120 }))
        );
        // A blocked app has nothing coming; neither does an app already paused
        let cs2 = Subject::Listed(r.app("Counter-Strike 2").unwrap());
        assert_eq!(upcoming(&r, cs2, &used, &at, NOW), None);
        assert_eq!(upcoming(&r, roblox, &usage(&[("Roblox", 60, Category::Games)]), &at, NOW), None);
    }

    #[test]
    fn upcoming_during_extra_time_is_its_end() {
        let mut r = rules();
        r.extra_time_until_ms = Some(NOW + 4 * 60_000);
        let roblox = Subject::Listed(r.app("Roblox").unwrap());
        let gamed = usage(&[("Roblox", 60, Category::Games)]);
        assert_eq!(upcoming(&r, roblox, &gamed, &moment(THU, "15:00"), NOW), Some((4 * 60, Block::AppLimit { minutes: 60 })));
        // Nothing used up by then: no warning about extra time ending
        assert_eq!(upcoming(&r, roblox, &usage(&[]), &moment(THU, "15:00"), NOW), None);
    }

    #[test]
    fn block_reasons_map_to_time_requests() {
        assert_eq!(Block::Bedtime.time_request_reason(), Some(TimeRequestReason::Bedtime));
        assert_eq!(Block::DailyLimit { minutes: 1 }.time_request_reason(), Some(TimeRequestReason::DailyLimit));
        assert_eq!(Block::Blocked.time_request_reason(), None);
        assert!(!Block::Pending.is_time());
    }
}
