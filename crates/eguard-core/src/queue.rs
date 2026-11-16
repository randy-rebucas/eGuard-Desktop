//! What the agent has to send, kept on disk until the server takes it (mobile-api C4.4, child-app-spec section 8).
//!
//! - `/usage`: the newest total per day replaces an older one still waiting (the server keeps the latest anyway).
//! - `/report`: the newest config per protection wins; a report whose protections are all superseded is dropped.
//! - `/events`: every event, with its `eventId`, in order.
//!
//! Order is kept per lane (usage, report, and each event type): an item waits while an older one in its lane is
//! waiting to be retried. Lanes don't hold each other up. Failures back off from 30 seconds to 15 minutes with
//! jitter. A `400` drops the item (a bug in this build; the caller logs it). A `413` (the body is over the server's
//! limit) splits the item and sends both halves at once (`APPS_FOUND`), or sends `/usage` with fewer apps; an item that
//! can't be made smaller is dropped. A `401` never drops anything and never
//! switches protection off: the agent keeps everything and keeps retrying at the slowest pace (spec principle 5).
//! An item the server keeps failing on (5xx, 403, 404, 413…) is given up after `MAX_REJECTIONS` tries or
//! `GIVE_UP_AFTER_MS`, so it can't hold its lane forever; no network, `401` and `429` never count toward that.

use crate::wire::{DeviceEvent, EventEnvelope, ReportRequest, UsageReport};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const BACKOFF_MIN_MS: i64 = 30_000;
pub const BACKOFF_MAX_MS: i64 = 15 * 60_000;
/// After a `429`, at least this long.
pub const RATE_LIMITED_MIN_MS: i64 = 5 * 60_000;
/// Events kept at most; past it the oldest of the busiest type goes first.
pub const MAX_EVENTS: usize = 2_000;
/// An item the server has failed on this many times is given up (about half a day at the slowest backoff).
pub const MAX_REJECTIONS: u32 = 50;
/// Or once the server has been failing on it for this long, whichever comes first.
pub const GIVE_UP_AFTER_MS: i64 = 7 * 24 * 60 * 60_000;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "endpoint", content = "body", rename_all = "camelCase")]
pub enum Outbound {
    Usage(UsageReport),
    Report(ReportRequest),
    Event(EventEnvelope),
}

impl Outbound {
    /// Items in the same lane are sent in order.
    pub fn lane(&self) -> String {
        match self {
            Outbound::Usage(_) => "usage".to_owned(),
            Outbound::Report(_) => "report".to_owned(),
            Outbound::Event(e) => format!("event:{}", e.event.type_name()),
        }
    }

    /// The endpoint, under `/api/device/v1`.
    pub fn path(&self) -> &'static str {
        match self {
            Outbound::Usage(_) => "/usage",
            Outbound::Report(_) => "/report",
            Outbound::Event(_) => "/events",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Queued {
    pub seq: u64,
    pub item: Outbound,
    pub attempts: u32,
    pub not_before_ms: i64,
    /// Times the server answered and didn't take this item for a reason of its own (5xx, 403, 404, 413…). Not counted:
    /// no network, 401 and 429, which say nothing about the item.
    #[serde(default)]
    pub rejections: u32,
    /// When the server first did so (eGuard's clock).
    #[serde(default)]
    pub first_rejected_ms: Option<i64>,
}

/// How a send went, from the HTTP status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendOutcome {
    /// 2xx.
    Delivered,
    /// 400: the server refused the body. Retrying can't help.
    BadRequest,
    /// 409 (`UNINSTALL_ACK` with no removal and a wrong code). Retrying can't help.
    Conflict,
    /// 401. The device may have been removed, or someone is in the way: keep everything, retry slowly.
    Unauthorized,
    /// 429. `retry_after_secs` from the response, when it said.
    RateLimited { retry_after_secs: Option<u32> },
    /// 413: the body is over the server's limit. Split or trimmed and sent again; dropped when it can't be.
    TooLarge,
    /// The server answered with another status (5xx, 403, 404…). Counts toward giving the item up.
    Failed,
    /// No answer: no network, DNS, TLS, a timeout. Not the item's fault, so it's kept however long it takes.
    Unreachable,
}

impl SendOutcome {
    pub fn from_status(status: u16) -> Self {
        match status {
            200..=299 => Self::Delivered,
            400 => Self::BadRequest,
            409 => Self::Conflict,
            401 => Self::Unauthorized,
            429 => Self::RateLimited { retry_after_secs: None },
            413 => Self::TooLarge,
            _ => Self::Failed,
        }
    }
}

/// What happened to the item.
#[derive(Debug, Clone, PartialEq)]
pub enum Settled {
    Done,
    /// Dropped because the server refused it; log it, it's a bug.
    Dropped(Outbound),
    /// Given up after the server kept failing on it (`MAX_REJECTIONS`, `GIVE_UP_AFTER_MS`), so it no longer holds
    /// up the items behind it in its lane. Log it.
    GaveUp(Outbound),
    /// Kept; tried again at `not_before_ms`.
    Retry {
        not_before_ms: i64,
    },
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OutboundQueue {
    items: Vec<Queued>,
    next_seq: u64,
}

impl OutboundQueue {
    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    pub fn items(&self) -> &[Queued] {
        &self.items
    }

    fn push(&mut self, item: Outbound, now_ms: i64) -> u64 {
        let seq = self.next_seq;
        self.next_seq += 1;
        self.items.push(Queued { seq, item, attempts: 0, not_before_ms: now_ms, rejections: 0, first_rejected_ms: None });
        seq
    }

    /// Queues a day's totals, replacing any older totals for that day still waiting.
    pub fn push_usage(&mut self, report: UsageReport, now_ms: i64) {
        if let Some(q) = self.items.iter_mut().find(|q| matches!(&q.item, Outbound::Usage(u) if u.date == report.date)) {
            q.item = Outbound::Usage(report);
            // A new body: what the server made of the old one says nothing about it
            q.rejections = 0;
            q.first_rejected_ms = None;
            return;
        }
        self.push(Outbound::Usage(report), now_ms);
    }

    /// Queues a report. Older waiting reports lose the protections this one covers (the newest config wins), and go
    /// when nothing is left in them, unless they answered a full-report request and this one doesn't.
    pub fn push_report(&mut self, report: ReportRequest, now_ms: i64) {
        let newer: BTreeSet<_> = report.protections.iter().map(|p| p.key).collect();
        let full = report.full == Some(true);
        self.items.retain_mut(|q| {
            let Outbound::Report(old) = &mut q.item else { return true };
            if old.full == Some(true) && !full {
                return true;
            }
            old.protections.retain(|p| !newer.contains(&p.key));
            !old.protections.is_empty()
        });
        self.push(Outbound::Report(report), now_ms);
    }

    /// Queues an event (with the `eventId` it keeps on every retry).
    pub fn push_event(&mut self, event: EventEnvelope, now_ms: i64) -> u64 {
        let seq = self.push(Outbound::Event(event), now_ms);
        let events = self.items.iter().filter(|q| matches!(q.item, Outbound::Event(_))).count();
        if events > MAX_EVENTS {
            self.drop_oldest_of_busiest_event_type();
        }
        seq
    }

    fn drop_oldest_of_busiest_event_type(&mut self) {
        let mut counts: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
        for q in &self.items {
            if matches!(q.item, Outbound::Event(_)) {
                *counts.entry(q.item.lane()).or_default() += 1;
            }
        }
        if let Some((lane, _)) = counts.into_iter().max_by_key(|(_, n)| *n)
            && let Some(i) = self.items.iter().position(|q| q.item.lane() == lane)
        {
            self.items.remove(i);
        }
    }

    /// The items to send now: the oldest of each lane, when it's due. Send them, then `settle` each.
    pub fn due(&self, now_ms: i64) -> Vec<&Queued> {
        let mut seen = BTreeSet::new();
        self.items.iter().filter(|q| seen.insert(q.item.lane())).filter(|q| q.not_before_ms <= now_ms).collect()
    }

    /// When the next item will be due, for scheduling.
    pub fn next_due_ms(&self) -> Option<i64> {
        let mut seen = BTreeSet::new();
        self.items.iter().filter(|q| seen.insert(q.item.lane())).map(|q| q.not_before_ms).min()
    }

    /// Records how sending item `seq` went. `jitter` is a random number in `[0, 1)`.
    pub fn settle(&mut self, seq: u64, outcome: SendOutcome, now_ms: i64, jitter: f64) -> Option<Settled> {
        let i = self.items.iter().position(|q| q.seq == seq)?;
        match outcome {
            SendOutcome::Delivered => {
                self.items.remove(i);
                Some(Settled::Done)
            }
            SendOutcome::BadRequest | SendOutcome::Conflict => Some(Settled::Dropped(self.items.remove(i).item)),
            SendOutcome::TooLarge => {
                let Some(smaller) = self.smaller(i) else { return Some(Settled::Dropped(self.items.remove(i).item)) };
                let q = &mut self.items[i];
                q.not_before_ms = now_ms;
                if let Smaller::Split(item) = smaller {
                    // Right behind the first half, so its lane keeps its order
                    let seq = self.next_seq;
                    self.next_seq += 1;
                    let rest = Queued { seq, item, attempts: 0, not_before_ms: now_ms, rejections: 0, first_rejected_ms: None };
                    self.items.insert(i + 1, rest);
                }
                Some(Settled::Retry { not_before_ms: now_ms })
            }
            SendOutcome::Unauthorized | SendOutcome::RateLimited { .. } | SendOutcome::Failed | SendOutcome::Unreachable => {
                let q = &mut self.items[i];
                q.attempts += 1;
                // One item the server keeps failing on would hold its whole lane forever: after enough tries it goes
                if outcome == SendOutcome::Failed {
                    q.rejections += 1;
                    let first = *q.first_rejected_ms.get_or_insert(now_ms);
                    if q.rejections >= MAX_REJECTIONS || now_ms - first >= GIVE_UP_AFTER_MS {
                        return Some(Settled::GaveUp(self.items.remove(i).item));
                    }
                }
                let wait = match outcome {
                    SendOutcome::Unauthorized => BACKOFF_MAX_MS,
                    SendOutcome::RateLimited { retry_after_secs } => {
                        backoff_ms(q.attempts, jitter).max(RATE_LIMITED_MIN_MS).max(retry_after_secs.map_or(0, |s| i64::from(s) * 1000))
                    }
                    _ => backoff_ms(q.attempts, jitter),
                };
                q.not_before_ms = now_ms + wait;
                Some(Settled::Retry { not_before_ms: q.not_before_ms })
            }
        }
    }

    /// Makes item `i` smaller after a 413: `APPS_FOUND` keeps the first half of its apps (and its `eventId`, which the
    /// server never took) and returns the second half as a new event; `/usage` keeps the larger half of its apps (a
    /// day's totals replace each other on the server, so they can't be split). `None` when it can't get smaller.
    fn smaller(&mut self, i: usize) -> Option<Smaller> {
        match &mut self.items[i].item {
            Outbound::Event(EventEnvelope { event: DeviceEvent::AppsFound { apps }, .. }) if apps.len() > 1 => {
                let rest = apps.split_off(apps.len() / 2);
                Some(Smaller::Split(Outbound::Event(EventEnvelope::new(DeviceEvent::AppsFound { apps: rest }))))
            }
            Outbound::Usage(u) if !u.apps.is_empty() => {
                u.apps.truncate(u.apps.len() / 2);
                Some(Smaller::Trimmed)
            }
            _ => None,
        }
    }

    /// Drops totals for days the server no longer accepts (before `oldest`, `YYYY-MM-DD`).
    pub fn prune_usage_before(&mut self, oldest: &str) {
        self.items.retain(|q| !matches!(&q.item, Outbound::Usage(u) if u.date.as_str() < oldest));
    }

    /// Retry everything now (the network came back).
    pub fn retry_now(&mut self, now_ms: i64) {
        for q in &mut self.items {
            q.not_before_ms = q.not_before_ms.min(now_ms);
        }
    }
}

/// How an item was made smaller after a 413.
enum Smaller {
    /// It kept a part; the rest is this new item.
    Split(Outbound),
    /// It's smaller and whole (what was left out isn't sent).
    Trimmed,
}

/// Exponential backoff for the `attempts`-th failure: 30 s, 60 s, 120 s … up to 15 minutes, then between half and
/// all of that ("equal jitter"), so many computers coming back at once don't arrive together.
pub fn backoff_ms(attempts: u32, jitter: f64) -> i64 {
    let base = BACKOFF_MIN_MS.saturating_mul(1 << attempts.saturating_sub(1).min(10)).min(BACKOFF_MAX_MS);
    let jitter = jitter.clamp(0.0, 1.0);
    (base as f64 * (0.5 + 0.5 * jitter)).round() as i64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{DeviceEvent, ProtectionConfig, ReportedProtection, TamperKind};

    fn usage(date: &str, total: u32) -> UsageReport {
        UsageReport { date: date.into(), total_minutes: total, apps: vec![], hourly: None }
    }
    fn report(full: bool, configs: &[&ProtectionConfig]) -> ReportRequest {
        ReportRequest {
            protections: configs.iter().map(|c| ReportedProtection::new(c, None)).collect(),
            full: full.then_some(true),
            ..Default::default()
        }
    }
    fn tamper(kind: TamperKind) -> EventEnvelope {
        EventEnvelope::new(DeviceEvent::Tamper { kind })
    }
    fn blocked(app: &str) -> EventEnvelope {
        EventEnvelope::new(DeviceEvent::AppBlocked { app: app.into() })
    }

    #[test]
    fn backoff_grows_from_30_seconds_to_15_minutes_with_jitter() {
        assert_eq!(backoff_ms(1, 1.0), 30_000);
        assert_eq!(backoff_ms(2, 1.0), 60_000);
        assert_eq!(backoff_ms(5, 1.0), 480_000);
        assert_eq!(backoff_ms(6, 1.0), BACKOFF_MAX_MS);
        assert_eq!(backoff_ms(60, 1.0), BACKOFF_MAX_MS);
        assert_eq!(backoff_ms(1, 0.0), 15_000);
        for j in [0.0, 0.3, 0.99] {
            let d = backoff_ms(3, j);
            assert!((60_000..=120_000).contains(&d));
        }
    }

    #[test]
    fn the_newest_total_per_day_wins() {
        let mut q = OutboundQueue::default();
        q.push_usage(usage("2026-10-22", 50), 0);
        q.push_usage(usage("2026-10-23", 10), 0);
        q.push_usage(usage("2026-10-22", 75), 0);
        let totals: Vec<_> = q
            .items()
            .iter()
            .map(|i| match &i.item {
                Outbound::Usage(u) => (u.date.clone(), u.total_minutes),
                _ => unreachable!(),
            })
            .collect();
        assert_eq!(totals, vec![("2026-10-22".into(), 75), ("2026-10-23".into(), 10)]);
    }

    #[test]
    fn the_newest_report_per_protection_wins() {
        let mut q = OutboundQueue::default();
        let on = ProtectionConfig::UninstallProtection { enabled: true };
        let off = ProtectionConfig::UninstallProtection { enabled: false };
        let st = ProtectionConfig::ScreenTime { daily_minutes: 120, weekend_minutes: 180 };
        q.push_report(report(false, &[&on, &st]), 0);
        q.push_report(report(false, &[&off]), 0);
        assert_eq!(q.len(), 2);
        let Outbound::Report(first) = &q.items()[0].item else { panic!() };
        assert_eq!(first.protections.len(), 1);
        q.push_report(report(false, &[&st]), 0);
        // The first report had nothing left
        assert_eq!(q.len(), 2);
        // A full report waiting stays whole until a newer full one replaces it
        q.push_report(report(true, &[&on, &st]), 0);
        q.push_report(report(false, &[&on]), 0);
        assert!(q.items().iter().any(|i| matches!(&i.item, Outbound::Report(r) if r.full == Some(true) && r.protections.len() == 2)));
        q.push_report(report(true, &[&off, &st]), 0);
        assert_eq!(q.items().iter().filter(|i| matches!(&i.item, Outbound::Report(_))).count(), 1);
    }

    #[test]
    fn events_keep_order_per_type_and_types_dont_wait_for_each_other() {
        let mut q = OutboundQueue::default();
        let a = q.push_event(blocked("Roblox"), 0);
        let b = q.push_event(blocked("Minecraft"), 0);
        let t = q.push_event(tamper(TamperKind::ClockChanged), 0);
        let due: Vec<u64> = q.due(0).iter().map(|i| i.seq).collect();
        assert_eq!(due, vec![a, t]);
        // The first APP_BLOCKED fails: the second waits behind it; TAMPER goes on
        assert!(matches!(q.settle(a, SendOutcome::Failed, 0, 0.5), Some(Settled::Retry { .. })));
        assert_eq!(q.settle(t, SendOutcome::Delivered, 0, 0.5), Some(Settled::Done));
        assert_eq!(q.due(1_000).len(), 0);
        let later = q.next_due_ms().unwrap();
        let due: Vec<u64> = q.due(later).iter().map(|i| i.seq).collect();
        assert_eq!(due, vec![a]);
        q.settle(a, SendOutcome::Delivered, later, 0.5);
        assert_eq!(q.due(later).iter().map(|i| i.seq).collect::<Vec<_>>(), vec![b]);
    }

    #[test]
    fn a_retried_event_keeps_its_event_id() {
        let mut q = OutboundQueue::default();
        let ev = tamper(TamperKind::UninstallBlocked);
        let id = ev.event_id.clone();
        let seq = q.push_event(ev, 0);
        q.settle(seq, SendOutcome::Failed, 0, 0.0);
        let Outbound::Event(e) = &q.items()[0].item else { panic!() };
        assert_eq!(e.event_id, id);
        assert!((8..=64).contains(&id.len()));
    }

    #[test]
    fn bad_requests_are_dropped_and_401_keeps_everything() {
        let mut q = OutboundQueue::default();
        let a = q.push_event(blocked("Roblox"), 0);
        assert!(matches!(q.settle(a, SendOutcome::BadRequest, 0, 0.5), Some(Settled::Dropped(_))));
        let b = q.push_event(blocked("Roblox"), 0);
        assert_eq!(q.settle(b, SendOutcome::Unauthorized, 0, 0.5), Some(Settled::Retry { not_before_ms: BACKOFF_MAX_MS }));
        assert_eq!(q.len(), 1);
    }

    #[test]
    fn an_item_the_server_keeps_failing_on_is_given_up_and_its_lane_moves_on() {
        let mut q = OutboundQueue::default();
        let a = q.push_event(blocked("Roblox"), 0);
        let b = q.push_event(blocked("Minecraft"), 0);
        // No network, 401 and 429 aren't the item's fault: never given up for those
        for _ in 0..200 {
            for o in [SendOutcome::Unreachable, SendOutcome::Unauthorized, SendOutcome::RateLimited { retry_after_secs: None }] {
                assert!(matches!(q.settle(a, o, 0, 0.5), Some(Settled::Retry { .. })));
            }
        }
        for i in 1..MAX_REJECTIONS {
            assert!(matches!(q.settle(a, SendOutcome::Failed, i64::from(i), 0.5), Some(Settled::Retry { .. })));
        }
        assert!(matches!(q.settle(a, SendOutcome::Failed, 100, 0.5), Some(Settled::GaveUp(_))));
        assert_eq!(q.due(100).iter().map(|i| i.seq).collect::<Vec<_>>(), vec![b]);

        // Or after a week of failing, however few the tries
        assert!(matches!(q.settle(b, SendOutcome::Failed, 0, 0.5), Some(Settled::Retry { .. })));
        assert!(matches!(q.settle(b, SendOutcome::Failed, GIVE_UP_AFTER_MS, 0.5), Some(Settled::GaveUp(_))));
        assert!(q.is_empty());

        // A day's totals replaced by newer ones start counting again
        q.push_usage(usage("2026-10-23", 5), 0);
        let u = q.items()[0].seq;
        q.settle(u, SendOutcome::Failed, 0, 0.5);
        q.push_usage(usage("2026-10-23", 9), 0);
        assert_eq!((q.items()[0].rejections, q.items()[0].first_rejected_ms), (0, None));
    }

    #[test]
    fn rate_limits_wait_at_least_five_minutes_or_what_the_server_says() {
        let mut q = OutboundQueue::default();
        let a = q.push_event(blocked("Roblox"), 0);
        assert_eq!(
            q.settle(a, SendOutcome::RateLimited { retry_after_secs: None }, 0, 1.0),
            Some(Settled::Retry { not_before_ms: RATE_LIMITED_MIN_MS })
        );
        assert_eq!(
            q.settle(a, SendOutcome::RateLimited { retry_after_secs: Some(600) }, 0, 1.0),
            Some(Settled::Retry { not_before_ms: 600_000 })
        );
        assert_eq!(SendOutcome::from_status(429), SendOutcome::RateLimited { retry_after_secs: None });
        assert_eq!(SendOutcome::from_status(503), SendOutcome::Failed);
        assert_eq!(SendOutcome::from_status(201), SendOutcome::Delivered);
    }

    #[test]
    fn the_network_coming_back_retries_at_once() {
        let mut q = OutboundQueue::default();
        let a = q.push_event(blocked("Roblox"), 0);
        q.settle(a, SendOutcome::Failed, 0, 1.0);
        assert_eq!(q.due(10).len(), 0);
        q.retry_now(10);
        assert_eq!(q.due(10).len(), 1);
    }

    #[test]
    fn old_usage_is_pruned_and_the_queue_survives_a_restart() {
        let mut q = OutboundQueue::default();
        q.push_usage(usage("2026-09-01", 5), 0);
        q.push_usage(usage("2026-10-23", 5), 0);
        q.push_event(tamper(TamperKind::SafeMode), 0);
        let restored: OutboundQueue = serde_json::from_str(&serde_json::to_string(&q).unwrap()).unwrap();
        assert_eq!(restored, q);
        q.prune_usage_before("2026-09-23");
        assert_eq!(q.len(), 2);
    }

    #[test]
    fn a_flood_of_events_drops_the_busiest_type_not_tampering() {
        let mut q = OutboundQueue::default();
        q.push_event(tamper(TamperKind::FilesChanged), 0);
        for i in 0..MAX_EVENTS {
            q.push_event(blocked(&format!("App {i}")), 0);
        }
        assert_eq!(q.len(), MAX_EVENTS);
        assert!(q.items().iter().any(|i| i.item.lane() == "event:TAMPER"));
    }

    fn big_app(i: usize) -> crate::wire::FoundApp {
        use crate::wire::{AppId, AppIdKind};
        crate::wire::FoundApp {
            app: format!("App {i}"),
            ids: (0..8).map(|n| AppId::new(AppIdKind::Exe, &format!("{n}-{}", "x".repeat(190)))).collect(),
            source: None,
            category: None,
        }
    }

    #[test]
    fn apps_found_is_split_by_size_not_only_by_count() {
        let apps: Vec<_> = (0..200).map(big_app).collect();
        let events = DeviceEvent::apps_found(&apps);
        assert!(events.len() > 1, "200 apps with 8 long ids each don't fit one body");
        let mut total = 0;
        for e in &events {
            let DeviceEvent::AppsFound { apps } = e else { panic!() };
            total += apps.len();
            assert!(serde_json::to_vec(&EventEnvelope::new(e.clone())).unwrap().len() <= crate::wire::BODY_BYTES_MAX);
        }
        assert_eq!(total, 200);
    }

    #[test]
    fn a_413_splits_apps_found_and_trims_usage_and_drops_what_cant_shrink() {
        let mut q = OutboundQueue::default();
        let apps: Vec<_> = (0..4).map(big_app).collect();
        let first = EventEnvelope::new(DeviceEvent::AppsFound { apps });
        let id = first.event_id.clone();
        let a = q.push_event(first, 0);
        assert_eq!(q.settle(a, SendOutcome::from_status(413), 5, 0.0), Some(Settled::Retry { not_before_ms: 5 }));
        let found: Vec<_> = q
            .items()
            .iter()
            .map(|i| match &i.item {
                Outbound::Event(EventEnvelope { event_id, event: DeviceEvent::AppsFound { apps } }) => (event_id.clone(), apps.len()),
                _ => panic!(),
            })
            .collect();
        assert_eq!(found.len(), 2);
        assert_eq!((found[0].0.as_str(), found[0].1, found[1].1), (id.as_str(), 2, 2));
        assert_ne!(found[1].0, id);
        // Both halves are due now, the first one first
        assert_eq!(q.due(5).len(), 1);

        let mut q = OutboundQueue::default();
        let mut u = usage("2026-11-11", 90);
        u.apps = (0..10).map(|i| crate::wire::UsageApp { name: format!("A{i}"), minutes: 1, ids: vec![] }).collect();
        q.push_usage(u, 0);
        let seq = q.items()[0].seq;
        assert!(matches!(q.settle(seq, SendOutcome::TooLarge, 0, 0.0), Some(Settled::Retry { .. })));
        assert!(matches!(&q.items()[0].item, Outbound::Usage(u) if u.apps.len() == 5 && u.total_minutes == 90));

        let mut q = OutboundQueue::default();
        let t = q.push_event(tamper(TamperKind::FilesChanged), 0);
        assert!(matches!(q.settle(t, SendOutcome::TooLarge, 0, 0.0), Some(Settled::Dropped(_))));
        // 400 still drops
        assert_eq!(SendOutcome::from_status(400), SendOutcome::BadRequest);
    }

    #[test]
    fn usage_is_trimmed_to_the_body_limit_keeping_its_totals() {
        let mut u = usage("2026-11-11", 600);
        u.apps = (0..200)
            .map(|i| crate::wire::UsageApp {
                name: format!("App {i}"),
                minutes: 1,
                ids: (0..8).map(|n| crate::wire::AppId::new(crate::wire::AppIdKind::Exe, &format!("{n}{}", "y".repeat(190)))).collect(),
            })
            .collect();
        u.fit_to(crate::wire::BODY_BYTES_MAX);
        assert!(serde_json::to_vec(&u).unwrap().len() <= crate::wire::BODY_BYTES_MAX);
        assert!(!u.apps.is_empty() && u.apps.len() < 200);
        assert_eq!(u.total_minutes, 600);
    }
}
