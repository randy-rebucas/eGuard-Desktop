//! Days, weekends and hours in the family's time zone (`/sync` `timezone`), by eGuard's clock. The computer's own
//! zone doesn't matter: the device and the parent must agree on "today".

use jiff::tz::TimeZone;
use jiff::{Timestamp, Zoned};

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("unknown time zone {0:?}")]
pub struct UnknownZone(pub String);

/// A moment in the family's zone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalMoment {
    /// `YYYY-MM-DD`, the day `/usage` reports under.
    pub date: String,
    /// 0 = Sunday … 6 = Saturday.
    pub weekday: u8,
    /// Seconds since local midnight by the wall clock of the zone (0..86400).
    pub second_of_day: u32,
}

impl LocalMoment {
    pub fn minutes(&self) -> u32 {
        self.second_of_day / 60
    }
    pub fn hour(&self) -> usize {
        (self.second_of_day / 3600) as usize
    }
    /// Saturday or Sunday: `weekendMinutes` applies (`limitOn` on the server).
    pub fn is_weekend(&self) -> bool {
        self.weekday == 0 || self.weekday == 6
    }
}

#[derive(Debug, Clone)]
pub struct FamilyZone {
    name: String,
    tz: TimeZone,
}

impl FamilyZone {
    /// An IANA zone (`Asia/Manila`), from the database bundled into the binary.
    pub fn new(name: &str) -> Result<Self, UnknownZone> {
        let tz = TimeZone::get(name).map_err(|_| UnknownZone(name.to_owned()))?;
        Ok(Self { name: name.to_owned(), tz })
    }

    /// UTC, for a zone this build doesn't know (it keeps enforcing; days may be off by the zone's offset).
    pub fn utc() -> Self {
        Self { name: "UTC".to_owned(), tz: TimeZone::UTC }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    fn zoned(&self, unix_ms: i64) -> Zoned {
        Timestamp::from_millisecond(unix_ms).unwrap_or(Timestamp::UNIX_EPOCH).to_zoned(self.tz.clone())
    }

    pub fn local(&self, unix_ms: i64) -> LocalMoment {
        let z = self.zoned(unix_ms);
        LocalMoment {
            date: z.date().to_string(),
            weekday: z.weekday().to_sunday_zero_offset() as u8,
            second_of_day: z.hour() as u32 * 3600 + z.minute() as u32 * 60 + z.second() as u32,
        }
    }

    /// Unix ms of the next local hour boundary after `unix_ms` (where usage moves to the next hourly bucket).
    pub fn next_hour_ms(&self, unix_ms: i64) -> i64 {
        let z = self.zoned(unix_ms);
        let into_hour_ms = (i64::from(z.minute()) * 60 + i64::from(z.second())) * 1000 + i64::from(z.millisecond());
        unix_ms - into_hour_ms + 3_600_000
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::parse_iso_ms;

    fn ms(s: &str) -> i64 {
        parse_iso_ms(s).unwrap()
    }

    #[test]
    fn days_follow_the_family_zone_not_utc() {
        let manila = FamilyZone::new("Asia/Manila").unwrap();
        // 2026-10-23 is a Friday; 17:30 UTC is 01:30 Saturday in Manila
        let m = manila.local(ms("2026-10-23T17:30:00Z"));
        assert_eq!((m.date.as_str(), m.weekday, m.minutes()), ("2026-10-24", 6, 90));
        assert!(m.is_weekend());
    }

    #[test]
    fn dst_changes_in_the_family_zone() {
        let ny = FamilyZone::new("America/New_York").unwrap();
        // 2026-03-08: clocks go from 02:00 to 03:00. 06:59 UTC is 01:59 EST, 07:00 UTC is 03:00 EDT
        assert_eq!(ny.local(ms("2026-03-08T06:59:00Z")).minutes(), 119);
        assert_eq!(ny.local(ms("2026-03-08T07:00:00Z")).minutes(), 180);
        // 2026-11-01: 01:00–02:00 happens twice
        assert_eq!(ny.local(ms("2026-11-01T05:30:00Z")).minutes(), 90);
        assert_eq!(ny.local(ms("2026-11-01T06:30:00Z")).minutes(), 90);
        // The next hour boundary is an hour of real time away, either way
        let t = ms("2026-11-01T05:30:00Z");
        assert_eq!(ny.next_hour_ms(t), ms("2026-11-01T06:00:00Z"));
    }

    #[test]
    fn half_hour_zones_bucket_by_local_hour() {
        let india = FamilyZone::new("Asia/Kolkata").unwrap();
        let t = ms("2026-10-23T10:00:00Z"); // 15:30 IST
        assert_eq!(india.local(t).hour(), 15);
        assert_eq!(india.next_hour_ms(t), ms("2026-10-23T10:30:00Z"));
    }

    #[test]
    fn unknown_zones_are_refused() {
        assert_eq!(FamilyZone::new("Mars/Olympus").unwrap_err(), UnknownZone("Mars/Olympus".into()));
    }
}
