//! What `/report` says this computer applies (spec section 11; capabilities in `~/eguard/src/lib/protections.ts`).
//!
//! The server counts a reported config that matches the parent's as applied, even with an `error` beside it
//! (`evaluate` in `src/lib/health.ts`). So a protection this build doesn't enforce yet is left out of the report
//! rather than echoed back: a full report that leaves one out makes the server show "eGuard isn't applying it",
//! which is the truth. Echoing the policy would tell the parent it's on when it isn't.
//!
//! - AVAILABLE (`SCREEN_TIME`, `BEDTIME`, `APP_APPROVAL`, `DOWNLOADS`): the config in force, once this build enforces it.
//! - GUIDED: `UNINSTALL_PROTECTION` `enabled: true` only while the child's account is standard and the service is
//!   locked; `WEB` the parent's config only once the extension is forced in every browser. Otherwise the off state,
//!   with the reason.
//! - UNSUPPORTED (`APP_RESTRICTIONS`, `CONTENT`, `LOCATION`, `NOTIFICATIONS`): never reported.

use crate::wire::{ProtectionConfig, ProtectionKey, ReportRequest, ReportedProtection, SyncResponse, WebMode};
use std::collections::BTreeSet;

/// The AVAILABLE protections, in the order they're reported.
pub const AVAILABLE: [ProtectionKey; 4] =
    [ProtectionKey::ScreenTime, ProtectionKey::Bedtime, ProtectionKey::AppApproval, ProtectionKey::Downloads];

/// What this build and this computer can do right now. The platform fills it in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capabilities {
    /// AVAILABLE protections this build enforces. Anything else is left out of the report.
    pub enforced: BTreeSet<ProtectionKey>,
    /// `Ok` while removal protection holds; otherwise why not, in words a parent can read.
    pub uninstall_protection: Result<(), String>,
    /// `Ok` once eGuard's extension is forced in every browser; otherwise why not.
    pub web: Result<(), String>,
}

/// The config in force for `key`: the newest request the agent accepted, else the policy.
fn in_force(sync: &SyncResponse, key: ProtectionKey) -> Option<&ProtectionConfig> {
    sync.requests
        .iter()
        .rev()
        .find(|r| r.key == key && r.config.key() == key)
        .map(|r| &r.config)
        .or_else(|| sync.policy.iter().find(|p| p.key == key && p.config.key() == key).map(|p| &p.config))
}

/// The protections to report, for the last good `/sync`.
pub fn protections(sync: &SyncResponse, caps: &Capabilities) -> Vec<ReportedProtection> {
    let mut out = Vec::new();
    for key in AVAILABLE {
        if let (true, Some(config)) = (caps.enforced.contains(&key), in_force(sync, key)) {
            out.push(ReportedProtection::new(config, None));
        }
    }
    match &caps.uninstall_protection {
        Ok(()) => out.push(ReportedProtection::new(&ProtectionConfig::UninstallProtection { enabled: true }, None)),
        Err(why) => out.push(ReportedProtection::new(&ProtectionConfig::UninstallProtection { enabled: false }, Some(why))),
    }
    match (&caps.web, in_force(sync, ProtectionKey::Web)) {
        (Ok(()), Some(config)) => out.push(ReportedProtection::new(config, None)),
        (Ok(()), None) => {}
        (Err(why), _) => out.push(ReportedProtection::new(&ProtectionConfig::Web { mode: WebMode::Off, blocked_sites: 0 }, Some(why))),
    }
    out
}

/// A full report: it covers everything the computer can apply, so the server marks anything left out as not applied.
pub fn full_report(protections: Vec<ReportedProtection>, os_version: &str, app_version: &str, battery: Option<u8>) -> ReportRequest {
    ReportRequest {
        protections,
        full: Some(true),
        battery,
        os_version: Some(os_version.to_owned()),
        app_version: Some(app_version.to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{ConfigRequest, PolicyEntry};
    use serde_json::json;

    fn sync() -> SyncResponse {
        let policy = [
            ProtectionConfig::ScreenTime { daily_minutes: 120, weekend_minutes: 180 },
            ProtectionConfig::AppApproval { enabled: true },
            ProtectionConfig::Location { sharing: true },
            ProtectionConfig::Web { mode: WebMode::Filter, blocked_sites: 3 },
        ]
        .map(|config| PolicyEntry { key: config.key(), config })
        .to_vec();
        SyncResponse {
            device_id: "dev_1".into(),
            child_name: "Mia".into(),
            policy,
            requests: vec![ConfigRequest {
                id: "req_1".into(),
                key: ProtectionKey::ScreenTime,
                config: ProtectionConfig::ScreenTime { daily_minutes: 90, weekend_minutes: 180 },
            }],
            apps: vec![],
            category_limits: vec![],
            extra_time_until: None,
            full_report_requested: true,
            next_sync_seconds: 300,
            timezone: "UTC".into(),
            features: crate::wire::Features::default(),
            min_app_version: None,
            server_time: None,
            uninstall: None,
        }
    }

    fn not_yet() -> Capabilities {
        Capabilities { enforced: BTreeSet::new(), uninstall_protection: Err("not yet".into()), web: Err("no extension".into()) }
    }

    #[test]
    fn nothing_enforced_reports_only_the_guided_ones_as_off() {
        let p = protections(&sync(), &not_yet());
        assert_eq!(
            serde_json::to_value(&p).unwrap(),
            json!([
                { "key": "UNINSTALL_PROTECTION", "config": { "enabled": false }, "error": "not yet" },
                { "key": "WEB", "config": { "mode": "OFF", "blockedSites": 0 }, "error": "no extension" },
            ])
        );
    }

    #[test]
    fn enforced_ones_report_the_accepted_request_and_unsupported_never_appear() {
        let caps = Capabilities { enforced: AVAILABLE.into_iter().collect(), uninstall_protection: Ok(()), web: Ok(()) };
        let p = protections(&sync(), &caps);
        assert_eq!(
            serde_json::to_value(&p).unwrap(),
            json!([
                { "key": "SCREEN_TIME", "config": { "dailyMinutes": 90, "weekendMinutes": 180 } },
                { "key": "APP_APPROVAL", "config": { "enabled": true } },
                { "key": "UNINSTALL_PROTECTION", "config": { "enabled": true } },
                { "key": "WEB", "config": { "mode": "FILTER", "blockedSites": 3 } },
            ])
        );
    }

    #[test]
    fn a_full_report_has_the_shape_the_server_accepted() {
        let r = full_report(protections(&sync(), &not_yet()), "Windows 11 25H2", "0.1.0", None);
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["full"], true);
        assert_eq!(v["appVersion"], "0.1.0");
        assert!(v.get("battery").is_none());
    }
}
