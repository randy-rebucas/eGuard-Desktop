//! eGuard's own updates (spec section 10, "Updates"; Q7): what `GET /update` must say before a new version is taken,
//! when one is wanted, and the hand-off between the service and the guard that swaps the program files and rolls a
//! bad version back.
//!
//! The manifest (`{ type: "eguard.desktop.update", version, issuedAt, files: [{ name, size, sha256, url }] }`) is
//! signed like the catalog (`signature`). One issued before the last one accepted is refused, as catalogs are. Each
//! file is then checked twice before it's used: its size and SHA-256 against the signed manifest (`check_file`), and
//! its Authenticode signer against eGuard's certificate (`SIGNER`, checked by the platform). Either alone would do
//! against a stranger; both are needed against a stolen signing key of one kind or the other.
//!
//! The service and the guard share three small files in the guard's cache folder (SYSTEM writes, nobody else):
//!
//! | File | Written by | Says |
//! |---|---|---|
//! | `update.json` (`Handoff`) | the service, then the guard | the cache holds the new version (`Swap`), then the program files do too (`Running`) |
//! | `update-health.json` (`Health`) | the new service | it synced and saved its state |
//! | `update-outcome.json` (`Outcome`) | the guard, after a rollback | which version failed and why, for the old service to keep |
//!
//! The previous version waits in `cache\previous` until the new one is healthy (`guard_action`).

use crate::signature::TrustedKeys;
use crate::state::version_below;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};

/// This build's version: `EGUARD_VERSION` at compile time (a release pipeline's, or a newer build for testing
/// updates on the VM: `tools/vm/bundle.ps1 -Version`), else the workspace's. What `/sync`, `/report` and updates
/// compare.
pub const VERSION: &str = match option_env!("EGUARD_VERSION") {
    Some(v) => v,
    None => env!("CARGO_PKG_VERSION"),
};

/// `type` of the update manifest; a catalog or a command can't stand in for it.
pub const UPDATE_TYPE: &str = "eguard.desktop.update";
/// The program files. An update carries all three, so the guard's cache is always one version.
pub const PROGRAMS: [&str; 3] = ["eguard-service.exe", "eguard-agent.exe", "eguard-guard.exe"];
/// The largest program file taken. A release build is a few MB; a debug build (the VM's) is tens.
pub const MAX_FILE_BYTES: u64 = 256 * 1024 * 1024;
/// The service stops itself once the cache holds the new version. One that hasn't stopped by then is ended.
pub const STOP_WAIT_MS: u64 = 2 * 60_000;
/// A new version that hasn't synced and saved its state by then is rolled back (spec section 10).
pub const HEALTH_WAIT_MS: u64 = 10 * 60_000;
/// The hand-off between the service and the guard, in the guard's cache folder.
pub const HANDOFF_FILE: &str = "update.json";
/// The new service's word that it works.
pub const HEALTH_FILE: &str = "update-health.json";
/// The guard's word that it rolled an update back.
pub const OUTCOME_FILE: &str = "update-outcome.json";
/// The version before the update, inside the guard's cache folder, until the new one is healthy.
pub const PREVIOUS_DIR: &str = "previous";

// A release that took updates signed by a development certificate would run whatever a developer's PC signed
#[cfg(not(debug_assertions))]
const _: () = assert!(
    option_env!("EGUARD_UPDATE_SIGNER").is_some() || option_env!("EGUARD_DEV_RELEASE").is_some(),
    "a release build needs EGUARD_UPDATE_SIGNER (the organisation on eGuard's code-signing certificate); set EGUARD_DEV_RELEASE=1 for a local build"
);

/// Whose Authenticode signature an update's files must carry: the organisation (O) on eGuard's code-signing
/// certificate, `EGUARD_UPDATE_SIGNER` at compile time. Until that certificate exists, "eGuard Dev": a self-signed
/// certificate made on the VM for testing (docs/VM-TESTS.md), which no other computer trusts.
pub const SIGNER: &str = match option_env!("EGUARD_UPDATE_SIGNER") {
    Some(s) => s,
    None => "eGuard Dev",
};

/// Whether a valid signature's names are eGuard's (`SIGNER`, either name, any case).
pub fn signed_by_eguard(organization: Option<&str>, common_name: Option<&str>) -> bool {
    [organization, common_name].into_iter().flatten().any(|n| n.trim().eq_ignore_ascii_case(SIGNER))
}

/// One program file of an update.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdateFile {
    pub name: String,
    pub size: u64,
    /// Lower-case hex.
    pub sha256: String,
    pub url: String,
}

/// A verified update manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Manifest {
    #[serde(rename = "type")]
    pub kind: String,
    pub version: String,
    /// When the server issued it (Unix ms), under the signature: a manifest issued before the last one accepted is
    /// a replay.
    pub issued_at: u64,
    pub files: Vec<UpdateFile>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum UpdateError {
    #[error("the answer isn't an update manifest")]
    Malformed,
    #[error("the signature doesn't verify against any built-in key")]
    BadSignature,
    #[error("the manifest's type is {0:?}, not the update's")]
    WrongType(String),
    #[error("the version {0:?} isn't a version number")]
    BadVersion(String),
    #[error("{0}")]
    BadFile(String),
}

/// A version eGuard writes: one to four numbers with dots, at most 20 characters (the server's `appVersion` limit).
fn valid_version(v: &str) -> bool {
    let parts: Vec<&str> = v.split('.').collect();
    v.len() <= 20 && (1..=4).contains(&parts.len()) && parts.iter().all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
}

/// Checks `GET /update`'s answer, as received: `Ok(None)` when no update is offered (`{ manifest: null }`), else
/// a manifest that carries eGuard's signature and the update's type, names each program exactly once, and gives each
/// a size, a SHA-256 and an https URL (`http://localhost` too in a development build, as for the server).
pub fn verify_manifest(keys: &TrustedKeys, response: &Value, dev_build: bool) -> Result<Option<Manifest>, UpdateError> {
    let manifest = match response.get("manifest") {
        Some(Value::Null) => return Ok(None),
        Some(m @ Value::Object(_)) => m,
        _ => return Err(UpdateError::Malformed),
    };
    let signature = response.get("signature").and_then(Value::as_str).ok_or(UpdateError::Malformed)?;
    if !keys.verify(manifest, signature, response.get("keyId").and_then(Value::as_str)) {
        return Err(UpdateError::BadSignature);
    }
    let m: Manifest = serde_json::from_value(manifest.clone()).map_err(|_| UpdateError::Malformed)?;
    if m.kind != UPDATE_TYPE {
        return Err(UpdateError::WrongType(m.kind));
    }
    if !valid_version(&m.version) {
        return Err(UpdateError::BadVersion(m.version));
    }
    let bad = |what: String| Err(UpdateError::BadFile(what));
    for p in PROGRAMS {
        let n = m.files.iter().filter(|f| f.name == p).count();
        if n != 1 {
            return bad(format!("the manifest lists {p} {n} times"));
        }
    }
    for f in &m.files {
        // A name is also a path the service writes to: only the three programs, never another name or a folder
        if !PROGRAMS.contains(&f.name.as_str()) {
            return bad(format!("the manifest lists a file that isn't eGuard's: {:?}", f.name));
        }
        if f.size == 0 || f.size > MAX_FILE_BYTES {
            return bad(format!("{} has a size of {} bytes", f.name, f.size));
        }
        if f.sha256.len() != 64 || !f.sha256.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
            return bad(format!("{}'s SHA-256 isn't 64 lower-case hex digits", f.name));
        }
        if crate::api::ServerUrl::parse(&f.url, dev_build).is_err() {
            return bad(format!("{}'s URL isn't https", f.name));
        }
    }
    Ok(Some(m))
}

/// SHA-256 as the manifest writes it: lower-case hex.
pub fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes).iter().fold(String::with_capacity(64), |mut s, b| {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// Whether a downloaded file is the one the manifest lists: its size, then its SHA-256.
pub fn check_file(bytes: &[u8], f: &UpdateFile) -> Result<(), String> {
    if bytes.len() as u64 != f.size {
        return Err(format!("{} is {} bytes, not the {} the manifest says", f.name, bytes.len(), f.size));
    }
    if sha256_hex(bytes) != f.sha256 {
        return Err(format!("{}'s SHA-256 doesn't match the manifest", f.name));
    }
    Ok(())
}

/// What the service keeps about updates, across restarts.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateRecord {
    /// `issuedAt` of the last manifest accepted.
    #[serde(default)]
    pub issued_at: Option<u64>,
    /// A version the guard rolled back: it isn't tried again (a newer one is).
    #[serde(default)]
    pub failed_version: Option<String>,
}

impl UpdateRecord {
    /// Whether `m` was issued before the last manifest accepted (a replayed older one).
    pub fn older(&self, m: &Manifest) -> bool {
        self.issued_at.is_some_and(|kept| m.issued_at < kept)
    }

    /// Whether `m` is worth installing over `own`: newer, and not the version that was rolled back.
    pub fn wanted(&self, m: &Manifest, own: &str) -> bool {
        version_below(own, &m.version) && self.failed_version.as_deref() != Some(m.version.as_str())
    }
}

/// Where an update stands between the service and the guard (`HANDOFF_FILE`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Step {
    /// The cache holds the new version; the program files are still the old one. The service stops itself, and
    /// the guard puts the cache's files in place and starts it again.
    Swap,
    /// The program files are the new version. The guard waits for its health.
    Running,
}

/// The hand-off between the service and the guard (`HANDOFF_FILE`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Handoff {
    pub from: String,
    pub to: String,
    pub step: Step,
}

/// The new service's word that it works (`HEALTH_FILE`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Health {
    pub version: String,
}

/// An update the guard rolled back (`OUTCOME_FILE`), for the old service to keep (`UpdateRecord::failed_version`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Outcome {
    pub version: String,
    pub why: String,
}

/// What the guard does about an update in progress.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuardAction {
    Wait,
    /// Put the cache's files in place, then start the service. `end_service`: it didn't stop by itself in time.
    Swap {
        end_service: bool,
    },
    /// The new version works: the previous one and the hand-off go.
    Commit,
    /// Put the previous version back in the cache and the program files, and start it.
    RollBack,
}

/// The guard's decision, from the hand-off, whether the service has stopped, how long the guard has seen this step
/// (its own clock, from when it first read it), and the version that last said it's healthy.
pub fn guard_action(h: &Handoff, service_stopped: bool, waited_ms: u64, healthy: Option<&str>) -> GuardAction {
    match h.step {
        // A swap that can't be made in this long (files that stay held, a disk that's full) goes back to the old
        // version rather than leave the computer between two
        Step::Swap if waited_ms >= HEALTH_WAIT_MS => GuardAction::RollBack,
        Step::Swap if service_stopped => GuardAction::Swap { end_service: false },
        Step::Swap if waited_ms >= STOP_WAIT_MS => GuardAction::Swap { end_service: true },
        Step::Running if healthy == Some(h.to.as_str()) => GuardAction::Commit,
        Step::Running if waited_ms >= HEALTH_WAIT_MS => GuardAction::RollBack,
        Step::Swap | Step::Running => GuardAction::Wait,
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use base64::Engine as _;
    use p256::ecdsa::{Signature, SigningKey, signature::Signer as _};
    use serde_json::json;

    /// A test key, and the build's trust in it (SPKI DER: P-256's fixed header, then the uncompressed point).
    pub(crate) fn key() -> (SigningKey, TrustedKeys) {
        let sk = SigningKey::from_slice(&[7u8; 32]).unwrap();
        let mut der = vec![
            0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03,
            0x01, 0x07, 0x03, 0x42, 0x00,
        ];
        der.extend_from_slice(sk.verifying_key().to_encoded_point(false).as_bytes());
        let b64 = base64::engine::general_purpose::STANDARD.encode(der);
        (sk, TrustedKeys::from_spki_base64(&[&b64]).unwrap())
    }

    pub(crate) fn signed(sk: &SigningKey, manifest: &Value) -> Value {
        let sig: Signature = sk.sign(crate::canonical::canonical_json(manifest).as_bytes());
        json!({ "manifest": manifest, "signature": base64::engine::general_purpose::STANDARD.encode(sig.to_bytes()), "keyId": "x" })
    }

    fn file(name: &str) -> Value {
        json!({ "name": name, "size": 3, "sha256": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", "url": format!("https://dl.eguard.app/0.2.0/{name}") })
    }

    /// A well-formed manifest for `version`, unsigned.
    pub(crate) fn manifest_for(version: &str, issued_at: u64) -> Value {
        json!({ "type": UPDATE_TYPE, "version": version, "issuedAt": issued_at, "files": PROGRAMS.map(file) })
    }

    fn manifest() -> Value {
        manifest_for("0.2.0", 1000)
    }

    #[test]
    fn a_signed_manifest_verifies_and_none_offered_is_none() {
        let (sk, keys) = key();
        let m = verify_manifest(&keys, &signed(&sk, &manifest()), false).unwrap().unwrap();
        assert_eq!((m.version.as_str(), m.issued_at, m.files.len()), ("0.2.0", 1000, 3));
        assert_eq!(verify_manifest(&keys, &json!({ "manifest": null }), false), Ok(None));
        assert_eq!(verify_manifest(&keys, &json!({}), false), Err(UpdateError::Malformed));
    }

    #[test]
    fn a_changed_or_mistyped_manifest_is_refused() {
        let (sk, keys) = key();
        let mut r = signed(&sk, &manifest());
        r["manifest"]["files"][0]["url"] = json!("https://evil.example/eguard-service.exe");
        assert_eq!(verify_manifest(&keys, &r, false), Err(UpdateError::BadSignature));

        let mut m = manifest();
        m["type"] = json!("eguard.desktop.catalog");
        assert!(matches!(verify_manifest(&keys, &signed(&sk, &m), false), Err(UpdateError::WrongType(_))));
        // Another key's signature
        let other = SigningKey::from_slice(&[9u8; 32]).unwrap();
        assert_eq!(verify_manifest(&keys, &signed(&other, &manifest()), false), Err(UpdateError::BadSignature));
    }

    #[test]
    fn every_file_must_be_one_of_the_three_programs_with_a_hash_and_an_https_url() {
        let (sk, keys) = key();
        let check = |edit: &dyn Fn(&mut Value)| {
            let mut m = manifest();
            edit(&mut m);
            verify_manifest(&keys, &signed(&sk, &m), false)
        };
        assert!(matches!(check(&|m| m["version"] = json!("0.2.0-beta; rm")), Err(UpdateError::BadVersion(_))));
        assert!(matches!(check(&|m| m["version"] = json!("")), Err(UpdateError::BadVersion(_))));
        assert!(matches!(check(&|m| m["files"].as_array_mut().unwrap().pop().map(drop).unwrap()), Err(UpdateError::BadFile(_))));
        assert!(matches!(check(&|m| m["files"].as_array_mut().unwrap().push(file("eguard-agent.exe"))), Err(UpdateError::BadFile(_))));
        assert!(matches!(check(&|m| m["files"].as_array_mut().unwrap().push(file(r"..\evil.exe"))), Err(UpdateError::BadFile(_))));
        assert!(matches!(check(&|m| m["files"][1]["size"] = json!(0)), Err(UpdateError::BadFile(_))));
        assert!(matches!(check(&|m| m["files"][1]["size"] = json!(MAX_FILE_BYTES + 1)), Err(UpdateError::BadFile(_))));
        assert!(matches!(check(&|m| m["files"][1]["sha256"] = json!("BA7816BF")), Err(UpdateError::BadFile(_))));
        assert!(matches!(check(&|m| m["files"][2]["url"] = json!("http://dl.eguard.app/x.exe")), Err(UpdateError::BadFile(_))));
        // The dev server on this machine, in a development build only
        let mut m = manifest();
        m["files"][2]["url"] = json!("http://localhost:3000/updates/eguard-guard.exe");
        assert!(verify_manifest(&keys, &signed(&sk, &m), true).unwrap().is_some());
        assert!(verify_manifest(&keys, &signed(&sk, &m), false).is_err());
    }

    #[test]
    fn this_builds_version_is_one_an_update_can_name() {
        assert!(valid_version(VERSION), "{VERSION}");
    }

    #[test]
    fn a_file_must_match_its_size_and_hash() {
        let f: UpdateFile = serde_json::from_value(file("eguard-agent.exe")).unwrap();
        assert_eq!(check_file(b"abc", &f), Ok(()));
        assert!(check_file(b"abd", &f).unwrap_err().contains("SHA-256"));
        assert!(check_file(b"abcd", &f).unwrap_err().contains("4 bytes"));
    }

    #[test]
    fn only_a_newer_version_not_rolled_back_and_not_replayed_is_wanted() {
        let m = |version: &str, issued_at| Manifest { kind: UPDATE_TYPE.into(), version: version.into(), issued_at, files: vec![] };
        let mut r = UpdateRecord::default();
        assert!(r.wanted(&m("0.2.0", 1), "0.1.0"));
        assert!(!r.wanted(&m("0.1.0", 1), "0.1.0"));
        assert!(!r.wanted(&m("0.0.9", 1), "0.1.0"));
        r.failed_version = Some("0.2.0".into());
        assert!(!r.wanted(&m("0.2.0", 1), "0.1.0"));
        assert!(r.wanted(&m("0.2.1", 1), "0.1.0"));

        assert!(!r.older(&m("0.2.0", 5)));
        r.issued_at = Some(5);
        assert!(!r.older(&m("0.2.0", 5)));
        assert!(r.older(&m("0.2.0", 4)));
    }

    #[test]
    fn signers_compare_by_name_in_any_case() {
        assert!(signed_by_eguard(Some("eguard dev"), None));
        assert!(signed_by_eguard(Some("Someone Else"), Some(SIGNER)));
        assert!(!signed_by_eguard(Some("eGuard Dev Ltd"), Some("eGuard")));
        assert!(!signed_by_eguard(None, None));
    }

    #[test]
    fn the_guard_swaps_after_the_stop_and_rolls_back_an_unhealthy_version() {
        let h = |step| Handoff { from: "0.1.0".into(), to: "0.2.0".into(), step };
        let swap = h(Step::Swap);
        assert_eq!(guard_action(&swap, false, 0, None), GuardAction::Wait);
        assert_eq!(guard_action(&swap, true, 0, None), GuardAction::Swap { end_service: false });
        assert_eq!(guard_action(&swap, false, STOP_WAIT_MS, None), GuardAction::Swap { end_service: true });
        assert_eq!(guard_action(&swap, true, HEALTH_WAIT_MS, None), GuardAction::RollBack);

        let running = h(Step::Running);
        assert_eq!(guard_action(&running, false, 0, None), GuardAction::Wait);
        // An old health file (the version before) isn't the new one's
        assert_eq!(guard_action(&running, false, 0, Some("0.1.0")), GuardAction::Wait);
        assert_eq!(guard_action(&running, false, 1, Some("0.2.0")), GuardAction::Commit);
        // Healthy wins even late: the guard may only have looked now
        assert_eq!(guard_action(&running, false, HEALTH_WAIT_MS * 2, Some("0.2.0")), GuardAction::Commit);
        assert_eq!(guard_action(&running, true, HEALTH_WAIT_MS, None), GuardAction::RollBack);
        assert_eq!(guard_action(&running, false, HEALTH_WAIT_MS - 1, None), GuardAction::Wait);
    }

    #[test]
    fn the_handoff_files_round_trip() {
        let h = Handoff { from: "0.1.0".into(), to: "0.2.0".into(), step: Step::Running };
        let s = serde_json::to_string(&h).unwrap();
        assert_eq!(s, r#"{"from":"0.1.0","to":"0.2.0","step":"running"}"#);
        assert_eq!(serde_json::from_str::<Handoff>(&s).unwrap(), h);
    }
}
