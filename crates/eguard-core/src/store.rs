//! What the service keeps on disk (spec section 3), as two documents:
//!
//! - `Persisted`: the device's state, usage, the outbound queue and code attempts. One JSON file, replaced atomically
//!   by the platform, so a crash mid-write leaves the old file or the new one, never half of each.
//! - `DeviceSecrets`: the token and removal secret, encrypted by the platform (DPAPI, machine scope) in a file of its
//!   own. Written first at pairing: the server sends them once.
//!
//! The device id is in both. A state file that is lost or corrupt is rebuilt from the secrets (`Persisted::recover`),
//! so the computer stays paired and enforcing, with "approval for everything new" until the next `/sync`.

use crate::queue::OutboundQueue;
use crate::removal::CodeAttempts;
use crate::scan::ExeCache;
use crate::state::AgentState;
use crate::usage::UsageLedger;
use crate::wire::{FoundApp, ReportedProtection};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Bumped when the format changes in a way older builds can't read.
pub const STATE_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Persisted {
    pub version: u32,
    /// `None` until paired.
    pub agent: Option<AgentState>,
    #[serde(default)]
    pub usage: UsageLedger,
    #[serde(default)]
    pub queue: OutboundQueue,
    #[serde(default)]
    pub code_attempts: CodeAttempts,
    /// The protections last queued for `/report`, so an unchanged report isn't sent every sync.
    #[serde(default)]
    pub last_reported: Option<Vec<ReportedProtection>>,
    /// The last good `GET /catalog` answer, exactly as received (signature and all): verified again when loaded.
    #[serde(default)]
    pub catalog: Option<serde_json::Value>,
    /// What the last scan reported, by name. `None` until the first scan, which sends everything as `APPS_FOUND`.
    #[serde(default)]
    pub apps_reported: Option<BTreeMap<String, FoundApp>>,
    /// eGuard's time of the last scan.
    #[serde(default)]
    pub last_scan_ms: Option<i64>,
    /// Signatures and product names already checked (`scan::ExeCache`).
    #[serde(default)]
    pub exe_cache: ExeCache,
}

impl Default for Persisted {
    fn default() -> Self {
        Self {
            version: STATE_VERSION,
            agent: None,
            usage: UsageLedger::default(),
            queue: OutboundQueue::default(),
            code_attempts: CodeAttempts::default(),
            last_reported: None,
            catalog: None,
            apps_reported: None,
            last_scan_ms: None,
            exe_cache: ExeCache::new(),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum LoadError {
    #[error("the state file didn't parse: {0}")]
    Malformed(#[from] serde_json::Error),
    #[error("the state file is version {0}, newer than this build reads")]
    TooNew(u32),
}

impl Persisted {
    pub fn from_json(bytes: &[u8]) -> Result<Self, LoadError> {
        let p: Self = serde_json::from_slice(bytes)?;
        if p.version > STATE_VERSION {
            return Err(LoadError::TooNew(p.version));
        }
        Ok(p)
    }

    pub fn to_json(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_default()
    }

    /// A state for a paired computer whose state file was lost: the identity from the secrets, nothing else known.
    /// Code attempts start over, which only matters if someone also destroyed the file on purpose; they can't write
    /// to eGuard's folder without being an administrator.
    pub fn recover(secrets: &DeviceSecrets) -> Self {
        Self { agent: Some(AgentState::paired(&secrets.device_id, "")), ..Self::default() }
    }

    /// True when the state belongs to these secrets.
    pub fn matches(&self, secrets: &DeviceSecrets) -> bool {
        self.agent.as_ref().is_some_and(|a| a.device_id == secrets.device_id)
    }
}

/// The device's secrets, as `/pair` sent them.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceSecrets {
    pub device_id: String,
    pub token: String,
    /// base64url, 32 bytes. `None` if the server didn't send one (it always does for computers).
    pub removal_secret: Option<String>,
}

impl std::fmt::Debug for DeviceSecrets {
    // Secrets never reach logs
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceSecrets")
            .field("device_id", &self.device_id)
            .field("token", &"<redacted>")
            .field("removal_secret", &self.removal_secret.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

impl DeviceSecrets {
    pub fn to_json(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_default()
    }

    pub fn from_json(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secrets() -> DeviceSecrets {
        DeviceSecrets { device_id: "dev_1".into(), token: "tok-secret".into(), removal_secret: Some("rs-secret".into()) }
    }

    #[test]
    fn state_round_trips_and_newer_versions_are_refused() {
        let p = Persisted::recover(&secrets());
        assert_eq!(Persisted::from_json(&p.to_json()).unwrap(), p);
        assert!(p.matches(&secrets()));
        let newer = br#"{"version":99,"agent":null}"#;
        assert!(matches!(Persisted::from_json(newer), Err(LoadError::TooNew(99))));
        // Fields added later default when an older file is read
        assert_eq!(Persisted::from_json(br#"{"version":1,"agent":null}"#).unwrap(), Persisted::default());
    }

    #[test]
    fn secrets_stay_out_of_debug() {
        let s = format!("{:?}", secrets());
        assert!(!s.contains("tok-secret") && !s.contains("rs-secret"));
        assert_eq!(DeviceSecrets::from_json(&secrets().to_json()).unwrap(), secrets());
    }
}
