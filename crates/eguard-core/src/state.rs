//! What the agent enforces between syncs, and how a `/sync` answer changes it (spec principle 5: fail closed).
//!
//! - A `/sync` that doesn't parse, or names another device, changes nothing: the last good policy stays in force.
//! - A `401` changes nothing either. The device may have been removed ("Remove without waiting"), or someone may be
//!   in the way; only eGuard's signed command or a parent's code removes eGuard, so the agent keeps enforcing.
//! - An uninstall command is acted on only once verified (`signature::verify_uninstall`).
//! - Before the first `/sync` ever, nothing is known about the parent's rules: new apps wait for approval and no time
//!   limits apply, until the first sync (normally seconds after pairing).

use crate::clock::{ClockChange, ClockSample, TrustedClock};
use crate::localtime::FamilyZone;
use crate::rules::{Policy, Rules};
use crate::signature::{TrustedKeys, UninstallCommand, VerifyError, verify_uninstall};
use crate::wire::{ConfigRequest, SyncResponse};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// `nextSyncSeconds` is honoured within these bounds.
pub const MIN_SYNC_SECS: u32 = 30;
pub const MAX_SYNC_SECS: u32 = 3_600;
/// How often to try while the server answers 401.
pub const UNAUTHORIZED_SYNC_SECS: u32 = 15 * 60;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SyncError {
    #[error("the sync response didn't parse: {0}")]
    Malformed(String),
    #[error("the sync response is for device {0}, not this one")]
    WrongDevice(String),
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "camelCase")]
pub enum AuthState {
    #[default]
    Ok,
    /// The server refuses the token. Enforcement goes on regardless.
    #[serde(rename_all = "camelCase")]
    Unauthorized { since_ms: i64 },
}

/// Persisted: the device's identity, the last good `/sync`, and eGuard's clock.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentState {
    pub device_id: String,
    pub child_name: String,
    /// The last `/sync` that parsed. What is enforced, online or not.
    pub last_sync: Option<SyncResponse>,
    pub last_sync_ms: Option<i64>,
    pub auth: AuthState,
    /// `minAppVersion` is above this build: the update screen shows, and enforcement goes on.
    pub update_required: bool,
    pub clock: TrustedClock,
}

/// What a good `/sync` asks of the agent.
#[derive(Debug, Clone, PartialEq)]
pub struct SyncOutcome {
    /// Apply, read back, report each (in order).
    pub requests: Vec<ConfigRequest>,
    /// Send a full report now.
    pub full_report_requested: bool,
    pub next_sync_secs: u32,
    /// eGuard's verified word to uninstall.
    pub uninstall: Option<UninstallCommand>,
    /// An uninstall command was there and failed verification (worth a log line; nothing is removed).
    pub uninstall_rejected: Option<VerifyError>,
    /// The clock estimate was off when the server's time arrived: send `TAMPER` `CLOCK_CHANGED`.
    pub clock_change: Option<ClockChange>,
}

impl AgentState {
    /// Right after `/pair`.
    pub fn paired(device_id: &str, child_name: &str) -> Self {
        Self {
            device_id: device_id.to_owned(),
            child_name: child_name.to_owned(),
            last_sync: None,
            last_sync_ms: None,
            auth: AuthState::Ok,
            update_required: false,
            clock: TrustedClock::default(),
        }
    }

    /// Takes a `/sync` answer (the JSON as received). On error, nothing changes.
    pub fn apply_sync(
        &mut self,
        raw: &Value,
        keys: &TrustedKeys,
        sample: ClockSample,
        app_version: &str,
    ) -> Result<SyncOutcome, SyncError> {
        let sync: SyncResponse = serde_json::from_value(raw.clone()).map_err(|e| SyncError::Malformed(e.to_string()))?;
        if sync.device_id != self.device_id {
            return Err(SyncError::WrongDevice(sync.device_id));
        }
        let clock_change =
            sync.server_time.as_deref().and_then(crate::clock::parse_iso_ms).and_then(|t| self.clock.on_server_time(t, sample));
        let now_ms = self.clock.now(sample).map_or(sample.wall_ms, |n| n.ms);

        let (uninstall, uninstall_rejected) = match raw.get("uninstall") {
            Some(envelope) if !envelope.is_null() => match verify_uninstall(keys, envelope, &self.device_id, now_ms) {
                Ok(cmd) => (Some(cmd), None),
                Err(e) => (None, Some(e)),
            },
            _ => (None, None),
        };

        let outcome = SyncOutcome {
            requests: sync.requests.clone(),
            full_report_requested: sync.full_report_requested,
            next_sync_secs: sync.next_sync_seconds.clamp(MIN_SYNC_SECS, MAX_SYNC_SECS),
            uninstall,
            uninstall_rejected,
            clock_change,
        };
        self.update_required = sync.min_app_version.as_deref().is_some_and(|min| version_below(app_version, min));
        self.child_name.clone_from(&sync.child_name);
        self.last_sync = Some(sync);
        self.last_sync_ms = Some(now_ms);
        self.auth = AuthState::Ok;
        Ok(outcome)
    }

    /// The server answered 401. Nothing is switched off; the agent tries again in `UNAUTHORIZED_SYNC_SECS`.
    pub fn on_unauthorized(&mut self, now_ms: i64) {
        if self.auth == AuthState::Ok {
            self.auth = AuthState::Unauthorized { since_ms: now_ms };
        }
    }

    /// The rules in force: the last good sync, or before any, approval for everything new.
    pub fn rules(&self) -> Rules {
        self.last_sync
            .as_ref()
            .map_or_else(|| Rules { policy: Policy { approval_required: true, ..Policy::default() }, ..Rules::default() }, Rules::from_sync)
    }

    /// The family's zone. UTC when unknown (before the first sync, or a zone this build lacks).
    pub fn zone(&self) -> FamilyZone {
        self.last_sync.as_ref().and_then(|s| FamilyZone::new(&s.timezone).ok()).unwrap_or_else(FamilyZone::utc)
    }
}

/// True when version `a` is below `b` (dotted numbers; anything after a `-` or `+` is ignored).
pub fn version_below(a: &str, b: &str) -> bool {
    fn parts(v: &str) -> Vec<u64> {
        v.trim().trim_start_matches('v').split(['-', '+']).next().unwrap_or("").split('.').map(|p| p.parse().unwrap_or(0)).collect()
    }
    let (a, b) = (parts(a), parts(b));
    for i in 0..a.len().max(b.len()) {
        let (x, y) = (a.get(i).copied().unwrap_or(0), b.get(i).copied().unwrap_or(0));
        if x != y {
            return x < y;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_compare_by_number() {
        assert!(version_below("0.1.0", "0.2.0"));
        assert!(version_below("1.9.9", "1.10.0"));
        assert!(!version_below("1.10.0", "1.9.9"));
        assert!(!version_below("1.0", "1.0.0"));
        assert!(version_below("1.0.0-beta.1", "1.0.1"));
    }

    #[test]
    fn before_the_first_sync_new_apps_wait() {
        let s = AgentState::paired("dev_1", "Mia");
        assert!(s.rules().policy.approval_required);
        assert_eq!(s.zone().name(), "UTC");
    }

    #[test]
    fn a_401_keeps_the_first_time_it_happened() {
        let mut s = AgentState::paired("dev_1", "Mia");
        s.on_unauthorized(10);
        s.on_unauthorized(20);
        assert_eq!(s.auth, AuthState::Unauthorized { since_ms: 10 });
    }
}
