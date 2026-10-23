//! eGuard's clock on the computer (spec section 8): days, bedtime, limits, removal codes and backoff all run on it,
//! so changing the PC's clock gains nothing.
//!
//! - Each `/sync` gives `serverTime`. The clock anchors it to the monotonic counter (time since boot, including
//!   sleep), and from then on reads `server time + monotonic elapsed`. The wall clock isn't consulted at all.
//! - The wall clock is still watched: when it moves away from the monotonic counter by more than
//!   `CHANGE_TOLERANCE_MS`, that's a clock change, reported as `TAMPER` `CLOCK_CHANGED`.
//! - After a reboot without a network the monotonic anchor is gone. The clock then starts from the wall clock plus
//!   the last known offset, never earlier than the latest eGuard time it has seen (`high_water_ms`, persisted), and
//!   is marked unverified. Moving the clock back before a reboot gains nothing; moving it forward is caught at the
//!   next `/sync`, which re-anchors and reports the change. A forward jump while offline across a reboot can end a
//!   bedtime early until then: the stated limit (docs/STATUS.md).
//!
//! The caller samples the platform (`ClockSample`) and persists `TrustedClock` (it's serde) every minute or so.

use serde::{Deserialize, Serialize};

/// A wall clock that drifts from the monotonic counter by more than this was changed.
pub const CHANGE_TOLERANCE_MS: i64 = 2 * 60_000;

/// One reading of the platform's clocks, taken together.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClockSample {
    /// Milliseconds since boot, including sleep and hibernation (Windows: `QueryInterruptTime` / `GetTickCount64`).
    pub mono_ms: u64,
    /// Changes on every boot (Windows: the `BootId` counter).
    pub boot_id: u64,
    /// The computer's own clock, Unix ms. Anyone with the right permission can change it.
    pub wall_ms: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Anchor {
    /// eGuard's time at the anchor (or the estimate, when unverified).
    trusted_ms: i64,
    mono_ms: u64,
    boot_id: u64,
    /// The wall clock at the anchor, for spotting changes.
    wall_ms: i64,
    /// From `/sync` in this boot, rather than estimated after a reboot.
    verified: bool,
}

/// A wall-clock change the agent noticed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClockChange {
    /// How far the wall clock (or, at a re-anchor, the estimate) was off, in ms. Positive: moved forward.
    pub delta_ms: i64,
}

/// eGuard's time, and whether it's anchored to `/sync` in this boot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrustedNow {
    pub ms: i64,
    pub verified: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TrustedClock {
    anchor: Option<Anchor>,
    /// `serverTime − wall clock` at the last verified anchor, used to estimate after a reboot.
    offset_ms: i64,
    /// The latest eGuard time this clock has handed out. Time never runs backwards past it.
    high_water_ms: i64,
    /// The last wall/monotonic pair checked for changes, in the current boot.
    last_check: Option<(u64, u64, i64)>,
    /// The latest eGuard time handed out while anchored to `/sync`, never an estimate. Nothing lowers it: `serverTime`
    /// isn't signed, so a forged answer mustn't be able to turn the clock back to before what eGuard already said.
    #[serde(default)]
    verified_high_ms: i64,
}

impl TrustedClock {
    /// Anchors to `/sync`'s `serverTime`. Returns a change when the clock's own reckoning was off by more than the
    /// tolerance, which happens when an estimate made after an offline reboot was wrong.
    pub fn on_server_time(&mut self, server_ms: i64, s: ClockSample) -> Option<ClockChange> {
        let estimated = self.anchor.is_some_and(|a| !a.verified);
        let change = match self.anchor {
            Some(a) if !a.verified && a.boot_id == s.boot_id => {
                let estimate = Self::reckon(a, s);
                let delta = estimate - server_ms;
                (delta.abs() > CHANGE_TOLERANCE_MS).then_some(ClockChange { delta_ms: delta })
            }
            _ => None,
        };
        self.anchor = Some(Anchor { trusted_ms: server_ms, mono_ms: s.mono_ms, boot_id: s.boot_id, wall_ms: s.wall_ms, verified: true });
        self.offset_ms = server_ms - s.wall_ms;
        // A high-water mark set by an estimate may be ahead of eGuard (a clock pushed forward before an offline
        // reboot): eGuard's word replaces it, but never below what was verified before. Otherwise the clock never
        // steps back for a late response.
        self.high_water_ms = if estimated { server_ms.max(self.verified_high_ms) } else { self.high_water_ms.max(server_ms) };
        self.verified_high_ms = self.verified_high_ms.max(server_ms);
        self.last_check = Some((s.boot_id, s.mono_ms, s.wall_ms));
        change
    }

    /// eGuard's time now. `None` before the first `/sync` ever (nothing to go on but the wall clock).
    pub fn now(&mut self, s: ClockSample) -> Option<TrustedNow> {
        let anchor = match self.anchor {
            Some(a) if a.boot_id == s.boot_id && s.mono_ms >= a.mono_ms => a,
            Some(_) => self.reanchor_after_reboot(s),
            None => return None,
        };
        let ms = Self::reckon(anchor, s).max(self.high_water_ms);
        self.high_water_ms = ms;
        if anchor.verified {
            self.verified_high_ms = self.verified_high_ms.max(ms);
        }
        Some(TrustedNow { ms, verified: anchor.verified })
    }

    /// Compares the wall clock with the monotonic counter since the last check. Call it every minute or so, and
    /// when the OS says the time changed. A change found is a `TAMPER` `CLOCK_CHANGED` to send.
    pub fn check_wall(&mut self, s: ClockSample) -> Option<ClockChange> {
        let change = match self.last_check {
            Some((boot, mono, wall)) if boot == s.boot_id && s.mono_ms >= mono => {
                let expected = wall + (s.mono_ms - mono) as i64;
                let delta = s.wall_ms - expected;
                (delta.abs() > CHANGE_TOLERANCE_MS).then_some(ClockChange { delta_ms: delta })
            }
            _ => None,
        };
        self.last_check = Some((s.boot_id, s.mono_ms, s.wall_ms));
        change
    }

    /// True once `/sync` has anchored the clock in this boot.
    pub fn is_verified(&self, s: ClockSample) -> bool {
        self.anchor.is_some_and(|a| a.verified && a.boot_id == s.boot_id)
    }

    fn reckon(a: Anchor, s: ClockSample) -> i64 {
        a.trusted_ms + s.mono_ms.saturating_sub(a.mono_ms) as i64
    }

    /// First reading in a new boot without `/sync`: wall clock plus the last offset, not before the high-water mark.
    fn reanchor_after_reboot(&mut self, s: ClockSample) -> Anchor {
        let estimate = (s.wall_ms + self.offset_ms).max(self.high_water_ms);
        let a = Anchor { trusted_ms: estimate, mono_ms: s.mono_ms, boot_id: s.boot_id, wall_ms: s.wall_ms, verified: false };
        self.anchor = Some(a);
        // Wall-clock watching starts over in this boot
        self.last_check = Some((s.boot_id, s.mono_ms, s.wall_ms));
        a
    }

    /// Whether the wall clock, read at a new boot, is earlier than eGuard time already seen (it was set back while
    /// the agent wasn't running). Call it before the first `now()` of a boot.
    pub fn wall_set_back_since_last_run(&self, s: ClockSample) -> Option<ClockChange> {
        let a = self.anchor?;
        if a.boot_id == s.boot_id {
            return None;
        }
        let delta = (s.wall_ms + self.offset_ms) - self.high_water_ms;
        (delta < -CHANGE_TOLERANCE_MS).then_some(ClockChange { delta_ms: delta })
    }
}

/// Unix ms from an ISO 8601 time with an offset (`2026-10-23T07:24:02.978Z`).
pub fn parse_iso_ms(s: &str) -> Option<i64> {
    s.parse::<jiff::Timestamp>().ok().map(jiff::Timestamp::as_millisecond)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIN: i64 = 60_000;
    const T0: i64 = 1_792_740_000_000;
    fn at(boot: u64, mono: u64, wall: i64) -> ClockSample {
        ClockSample { mono_ms: mono, boot_id: boot, wall_ms: wall }
    }

    #[test]
    fn nothing_before_the_first_sync() {
        assert_eq!(TrustedClock::default().now(at(1, 0, T0)), None);
    }

    #[test]
    fn counts_from_server_time_and_ignores_the_wall_clock() {
        let mut c = TrustedClock::default();
        // The PC's clock is 10 minutes slow; eGuard's wins
        assert_eq!(c.on_server_time(T0, at(1, 1_000, T0 - 10 * MIN)), None);
        assert_eq!(c.now(at(1, 61_000, T0 - 9 * MIN)), Some(TrustedNow { ms: T0 + MIN, verified: true }));
        // The child moves the clock forward an hour: no time gained, and it's noticed
        let moved = at(1, 121_000, T0 + 60 * MIN);
        assert_eq!(c.now(moved).unwrap().ms, T0 + 2 * MIN);
        assert_eq!(c.check_wall(at(1, 61_000, T0 - 9 * MIN)), None);
        // Expected T0 − 8 min by the counter, reads T0 + 60 min
        let change = c.check_wall(moved).unwrap();
        assert_eq!(change.delta_ms, 68 * MIN);
    }

    #[test]
    fn small_drift_is_not_a_change() {
        let mut c = TrustedClock::default();
        c.on_server_time(T0, at(1, 0, T0));
        assert_eq!(c.check_wall(at(1, 60 * MIN as u64, T0 + 60 * MIN + 30_000)), None);
        assert!(c.check_wall(at(1, 61 * MIN as u64, T0 + 61 * MIN + 30_000 - 3 * MIN)).is_some());
    }

    #[test]
    fn after_an_offline_reboot_the_clock_never_goes_back() {
        let mut c = TrustedClock::default();
        c.on_server_time(T0, at(1, 0, T0));
        assert_eq!(c.now(at(1, 30 * MIN as u64, T0 + 30 * MIN)).unwrap().ms, T0 + 30 * MIN);
        // Reboot offline, with the clock set back two hours
        let boot2 = at(2, 5_000, T0 - 90 * MIN);
        assert!(c.wall_set_back_since_last_run(boot2).is_some());
        let now = c.now(boot2).unwrap();
        assert_eq!(now, TrustedNow { ms: T0 + 30 * MIN, verified: false });
        // It then counts on from there by the monotonic counter
        assert_eq!(c.now(at(2, 5_000 + MIN as u64, T0 - 89 * MIN)).unwrap().ms, T0 + 31 * MIN);
    }

    #[test]
    fn a_forward_jump_across_an_offline_reboot_is_caught_at_the_next_sync() {
        let mut c = TrustedClock::default();
        c.on_server_time(T0, at(1, 0, T0));
        // Rebooted offline after 10 minutes, clock pushed 8 hours ahead
        let boot2 = at(2, 1_000, T0 + 10 * MIN + 8 * 60 * MIN);
        assert_eq!(c.wall_set_back_since_last_run(boot2), None);
        assert!(!c.now(boot2).unwrap().verified);
        // Back online: eGuard says it's T0 + 11 min
        let change = c.on_server_time(T0 + 11 * MIN, at(2, 1_000 + MIN as u64, T0 + 11 * MIN + 8 * 60 * MIN)).unwrap();
        assert_eq!(change.delta_ms, 8 * 60 * MIN);
        assert!(c.is_verified(at(2, 2 * MIN as u64, 0)));
        // And the clock is eGuard's again, not 8 hours ahead
        assert_eq!(c.now(at(2, 1_000 + 2 * MIN as u64, 0)).unwrap(), TrustedNow { ms: T0 + 12 * MIN, verified: true });
    }

    #[test]
    fn a_server_time_earlier_than_seen_does_not_turn_the_clock_back() {
        let mut c = TrustedClock::default();
        c.on_server_time(T0, at(1, 0, T0));
        c.now(at(1, 10 * MIN as u64, T0 + 10 * MIN));
        c.on_server_time(T0 + 5 * MIN, at(1, 10 * MIN as u64, T0 + 10 * MIN));
        assert_eq!(c.now(at(1, 10 * MIN as u64, T0 + 10 * MIN)).unwrap().ms, T0 + 10 * MIN);
    }

    #[test]
    fn a_forged_server_time_after_an_offline_reboot_cant_turn_the_clock_back_past_what_was_verified() {
        let mut c = TrustedClock::default();
        c.on_server_time(T0, at(1, 0, T0));
        assert_eq!(c.now(at(1, 120 * MIN as u64, T0 + 120 * MIN)).unwrap().ms, T0 + 120 * MIN);
        // Rebooted offline with the clock set back; then an answer claims it's T0 (serverTime isn't signed)
        let boot2 = at(2, 1_000, T0 - 300 * MIN);
        c.now(boot2);
        c.on_server_time(T0, at(2, 2_000, T0 - 300 * MIN));
        assert!(c.now(at(2, 2_000, T0 - 300 * MIN)).unwrap().ms >= T0 + 120 * MIN);
    }

    #[test]
    fn survives_a_save_and_restore() {
        let mut c = TrustedClock::default();
        c.on_server_time(T0, at(1, 0, T0));
        c.now(at(1, MIN as u64, T0 + MIN));
        let restored: TrustedClock = serde_json::from_str(&serde_json::to_string(&c).unwrap()).unwrap();
        assert_eq!(restored, c);
    }

    #[test]
    fn parses_server_times() {
        assert_eq!(parse_iso_ms("1970-01-01T00:00:01.500Z"), Some(1_500));
        assert_eq!(parse_iso_ms("2026-10-23T07:24:02.978Z"), Some(1_792_740_242_978));
        assert_eq!(parse_iso_ms("yesterday"), None);
    }
}
