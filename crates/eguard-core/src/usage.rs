//! Screen time as the agent counts it (spec section 8): foreground time with input in the last 2 minutes, by day
//! and local hour in the family's zone, on eGuard's clock. The platform decides what counts (focus, idle, not
//! eGuard's own screens) and calls `UsageLedger::record` for each stretch; this keeps the totals and turns them into
//! `/usage` reports.

use crate::localtime::FamilyZone;
use crate::wire::{self, AppId, Category, UsageReport};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

const HOUR_MS: u64 = 3_600_000;
const DAY_MS: u64 = 24 * HOUR_MS;

/// The app a stretch of time belongs to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsageApp {
    /// The name on the child's list when it's there, else the name the agent found.
    pub name: String,
    pub ids: Vec<AppId>,
    pub category: Category,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppTime {
    pub ms: u64,
    #[serde(default)]
    pub ids: Vec<AppId>,
    pub category: Option<Category>,
}

/// One day's totals.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DayUsage {
    total_ms: u64,
    apps: BTreeMap<String, AppTime>,
    hourly_ms: [u64; 24],
}

impl DayUsage {
    /// Adds time in one local hour. `app` is `None` for time in something that isn't an app on the list (the desktop,
    /// a system window): it counts toward the day, not toward an app.
    pub fn add(&mut self, app: Option<&UsageApp>, hour: usize, secs: u32) {
        self.add_ms(app, hour, u64::from(secs) * 1000);
    }

    fn add_ms(&mut self, app: Option<&UsageApp>, hour: usize, ms: u64) {
        // A repeated hour (clocks going back) still holds at most an hour; a day at most 24 hours
        let hour = hour.min(23);
        let ms = ms.min(HOUR_MS - self.hourly_ms[hour]).min(DAY_MS - self.total_ms);
        self.hourly_ms[hour] += ms;
        self.total_ms += ms;
        if let Some(a) = app {
            let entry = self.apps.entry(a.name.clone()).or_default();
            entry.ms += ms;
            entry.category = Some(a.category);
            for id in &a.ids {
                if !entry.ids.iter().any(|known| known.same_as(id)) {
                    entry.ids.push(id.clone());
                }
            }
        }
    }

    pub fn total_secs(&self) -> u32 {
        (self.total_ms / 1000) as u32
    }

    pub fn app_secs(&self, name: &str) -> u32 {
        self.apps.get(name).map_or(0, |a| (a.ms / 1000) as u32)
    }

    /// Time in every app that counts toward `category`. `category_of(name, recorded)` gives an app's category now
    /// (the parent may have moved it since the time was recorded).
    pub fn category_secs(&self, category: Category, category_of: impl Fn(&str, Option<Category>) -> Category) -> u32 {
        let ms: u64 = self.apps.iter().filter(|(name, a)| category_of(name, a.category) == category).map(|(_, a)| a.ms).sum();
        (ms / 1000) as u32
    }

    /// The `/usage` body for this day: whole minutes, apps with at least one minute (the 200 largest), and hourly.
    pub fn report(&self, date: &str) -> UsageReport {
        let mut apps: Vec<(&String, &AppTime)> = self.apps.iter().filter(|(_, a)| a.ms >= 60_000).collect();
        apps.sort_by(|a, b| b.1.ms.cmp(&a.1.ms).then_with(|| a.0.cmp(b.0)));
        let apps = apps
            .into_iter()
            .filter_map(|(name, a)| {
                Some(wire::UsageApp {
                    name: wire::app_name(name)?,
                    minutes: (a.ms / 60_000) as u32,
                    ids: a.ids.iter().take(wire::IDS_PER_APP_MAX).cloned().collect(),
                })
            })
            .take(wire::APPS_PER_MESSAGE_MAX)
            .collect();
        UsageReport {
            date: date.to_owned(),
            total_minutes: (self.total_ms / 60_000) as u32,
            apps,
            hourly: Some(self.hourly_ms.map(|ms| (ms / 60_000) as u32)),
        }
    }
}

/// Totals per day, kept for the days `/usage` still accepts.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsageLedger {
    days: BTreeMap<String, DayUsage>,
}

impl UsageLedger {
    /// Counts `[start_ms, end_ms)` (eGuard's clock) for `app`, split across local hours and days in `zone`.
    pub fn record(&mut self, zone: &FamilyZone, start_ms: i64, end_ms: i64, app: Option<&UsageApp>) {
        let mut t = start_ms;
        while t < end_ms {
            let stop = zone.next_hour_ms(t).min(end_ms);
            let local = zone.local(t);
            let hour = local.hour();
            self.days.entry(local.date).or_default().add_ms(app, hour, (stop - t) as u64);
            t = stop;
        }
    }

    pub fn day(&self, date: &str) -> Option<&DayUsage> {
        self.days.get(date)
    }

    /// Today's totals (empty when nothing was counted yet).
    pub fn day_or_empty(&self, date: &str) -> DayUsage {
        self.days.get(date).cloned().unwrap_or_default()
    }

    pub fn dates(&self) -> impl Iterator<Item = &str> {
        self.days.keys().map(String::as_str)
    }

    /// Drops days before `oldest` (`YYYY-MM-DD`; the server refuses totals older than 30 days).
    pub fn prune_before(&mut self, oldest: &str) {
        self.days.retain(|date, _| date.as_str() >= oldest);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::parse_iso_ms;
    use crate::wire::AppIdKind;

    fn ms(s: &str) -> i64 {
        parse_iso_ms(s).unwrap()
    }
    fn cs2() -> UsageApp {
        UsageApp { name: "Counter-Strike 2".into(), ids: vec![AppId::new(AppIdKind::Steam, "730")], category: Category::Games }
    }

    #[test]
    fn splits_by_local_hour_and_day_in_the_family_zone() {
        let manila = FamilyZone::new("Asia/Manila").unwrap();
        let mut l = UsageLedger::default();
        // 23:40 to 00:20 Manila time (15:40–16:20 UTC): 20 minutes on each day
        l.record(&manila, ms("2026-10-23T15:40:00Z"), ms("2026-10-23T16:20:00Z"), Some(&cs2()));
        let fri = l.day("2026-10-23").unwrap().report("2026-10-23");
        let sat = l.day("2026-10-24").unwrap().report("2026-10-24");
        assert_eq!((fri.total_minutes, fri.hourly.unwrap()[23]), (20, 20));
        assert_eq!((sat.total_minutes, sat.hourly.unwrap()[0]), (20, 20));
        assert_eq!(
            sat.apps,
            vec![wire::UsageApp { name: "Counter-Strike 2".into(), minutes: 20, ids: vec![AppId::new(AppIdKind::Steam, "730")] }]
        );
    }

    #[test]
    fn time_outside_apps_counts_toward_the_day_only() {
        let utc = FamilyZone::utc();
        let mut l = UsageLedger::default();
        l.record(&utc, 0, 5 * 60_000, None);
        l.record(&utc, 5 * 60_000, 7 * 60_000, Some(&cs2()));
        let r = l.day("1970-01-01").unwrap().report("1970-01-01");
        assert_eq!(r.total_minutes, 7);
        assert_eq!(r.apps.len(), 1);
        assert_eq!(r.apps[0].minutes, 2);
    }

    #[test]
    fn short_ticks_add_up_without_losing_milliseconds() {
        let utc = FamilyZone::utc();
        let mut l = UsageLedger::default();
        for i in 0..600 {
            l.record(&utc, i * 1000, i * 1000 + 999, Some(&cs2()));
        }
        assert_eq!(l.day("1970-01-01").unwrap().app_secs("Counter-Strike 2"), 599);
    }

    #[test]
    fn an_hour_holds_at_most_60_minutes_even_when_it_repeats() {
        // 2026-11-01 in New York: 01:00–02:00 happens twice
        let ny = FamilyZone::new("America/New_York").unwrap();
        let mut l = UsageLedger::default();
        l.record(&ny, ms("2026-11-01T05:00:00Z"), ms("2026-11-01T07:00:00Z"), Some(&cs2()));
        let r = l.day("2026-11-01").unwrap().report("2026-11-01");
        assert_eq!(r.hourly.unwrap()[1], 60);
        assert_eq!(r.total_minutes, 60);
    }

    #[test]
    fn reports_leave_out_apps_under_a_minute_and_keep_the_200_largest() {
        let mut d = DayUsage::default();
        for i in 0..250u32 {
            let app = UsageApp { name: format!("App {i:03}"), ids: vec![], category: Category::Other };
            d.add(Some(&app), (i % 24) as usize, 60 + i);
        }
        d.add(Some(&UsageApp { name: "Blink".into(), ids: vec![], category: Category::Other }), 0, 59);
        let r = d.report("2026-10-23");
        assert_eq!(r.apps.len(), 200);
        assert_eq!(r.apps[0].name, "App 249");
        assert!(r.apps.iter().all(|a| a.name != "Blink" && a.minutes >= 1));
    }

    #[test]
    fn category_time_follows_the_current_category() {
        let mut d = DayUsage::default();
        d.add(Some(&cs2()), 10, 600);
        d.add(Some(&UsageApp { name: "Notes".into(), ids: vec![], category: Category::Other }), 10, 300);
        assert_eq!(d.category_secs(Category::Games, |_, c| c.unwrap_or(Category::Other)), 600);
        // The parent moved Notes into Games
        assert_eq!(d.category_secs(Category::Games, |n, c| if n == "Notes" { Category::Games } else { c.unwrap() }), 900);
    }

    #[test]
    fn old_days_are_pruned_and_the_ledger_survives_a_restart() {
        let utc = FamilyZone::utc();
        let mut l = UsageLedger::default();
        l.record(&utc, 0, 60_000, None);
        l.record(&utc, 86_400_000, 86_460_000, None);
        let restored: UsageLedger = serde_json::from_str(&serde_json::to_string(&l).unwrap()).unwrap();
        assert_eq!(restored, l);
        l.prune_before("1970-01-02");
        assert_eq!(l.dates().collect::<Vec<_>>(), vec!["1970-01-02"]);
    }
}
