//! eGuard's signed words: the uninstall command (`/sync` `uninstall`) and the app catalog (`GET /catalog`).
//!
//! Both are signed like the browser policy: ECDSA P-256 / SHA-256 over the canonical JSON (`canonical`), the
//! signature base64 of raw `r||s`. Only public keys built into this binary are trusted (`keys`), never one that
//! arrives at runtime, and `keyId` is only a hint. Every check runs on the JSON as received, so a field this build
//! doesn't know is still covered by the signature.

use crate::canonical::canonical_json;
use crate::keys::BUILTIN_PUBLIC_KEYS;
use crate::wire::Catalog;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use p256::ecdsa::signature::Verifier as _;
use p256::ecdsa::{Signature, VerifyingKey};
use p256::pkcs8::DecodePublicKey as _;
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest as _, Sha256};

/// `type` of the uninstall command; a catalog or a policy can't stand in for it.
pub const UNINSTALL_TYPE: &str = "eguard.device.uninstall";
/// `type` of the catalog.
pub const CATALOG_TYPE: &str = "eguard.desktop.catalog";
/// How far an uninstall command's `at` may be from eGuard's clock (a stale command replayed is refused).
pub const UNINSTALL_MAX_AGE_MS: i64 = 60 * 60_000;

#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub enum VerifyError {
    #[error("a built-in public key is invalid")]
    BadKey,
    #[error("the signed payload is missing or not an object")]
    Malformed,
    #[error("the signature doesn't verify against any built-in key")]
    BadSignature,
    #[error("the payload's type is {0:?}, not the one expected")]
    WrongType(String),
    #[error("the command is for another device")]
    WrongDevice,
    #[error("the command is too old or from the future")]
    Stale,
    /// Not newer than an uninstall command already accepted: one seen before, sent again.
    #[error("the command isn't newer than one already accepted")]
    Replayed,
}

/// One key the build trusts.
#[derive(Debug, Clone)]
pub struct TrustedKey {
    /// First 16 hex chars of SHA-256 over the SPKI DER, as the server's `keyId`.
    pub key_id: String,
    key: VerifyingKey,
}

/// The keys built into this binary. During a rotation there are two (old and new).
#[derive(Debug, Clone)]
pub struct TrustedKeys(Vec<TrustedKey>);

impl TrustedKeys {
    /// The keys compiled into this build (`keys::BUILTIN_PUBLIC_KEYS`).
    pub fn builtin() -> Result<Self, VerifyError> {
        Self::from_spki_base64(&BUILTIN_PUBLIC_KEYS.split(',').filter(|k| !k.trim().is_empty()).collect::<Vec<_>>())
    }

    /// Keys from base64 SPKI DER strings (what `node scripts/browser-policy-keys.mjs` prints).
    pub fn from_spki_base64(list: &[&str]) -> Result<Self, VerifyError> {
        let keys = list
            .iter()
            .map(|b64| {
                let der = STANDARD.decode(b64.trim()).map_err(|_| VerifyError::BadKey)?;
                let key = VerifyingKey::from_public_key_der(&der).map_err(|_| VerifyError::BadKey)?;
                let key_id = hex16(&Sha256::digest(&der));
                Ok(TrustedKey { key_id, key })
            })
            .collect::<Result<Vec<_>, _>>()?;
        if keys.is_empty() {
            return Err(VerifyError::BadKey);
        }
        Ok(Self(keys))
    }

    pub fn key_ids(&self) -> impl Iterator<Item = &str> {
        self.0.iter().map(|k| k.key_id.as_str())
    }

    /// True only when `signature` is eGuard's over exactly this payload. The key named by `key_id` is tried first.
    pub fn verify(&self, payload: &Value, signature_b64: &str, key_id: Option<&str>) -> bool {
        let Ok(raw) = STANDARD.decode(signature_b64.trim()) else { return false };
        let Ok(sig) = Signature::from_slice(&raw) else { return false };
        let message = canonical_json(payload);
        let mut keys: Vec<&TrustedKey> = self.0.iter().collect();
        keys.sort_by_key(|k| Some(k.key_id.as_str()) != key_id);
        keys.iter().any(|k| k.key.verify(message.as_bytes(), &sig).is_ok())
    }
}

fn hex16(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().take(8).fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// A verified uninstall command (spec section 10).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UninstallCommand {
    pub device_id: String,
    pub requested_at: String,
    pub at: String,
    /// `at` as Unix ms: each command the server signs has a newer one, so a command not newer than the last accepted
    /// is a replay.
    pub at_ms: i64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UninstallFields {
    #[serde(rename = "type")]
    kind: String,
    device_id: String,
    requested_at: String,
    at: String,
}

/// Checks `/sync`'s `uninstall` (`{ command, signature, keyId }`, as received): eGuard's signature, the type, that
/// it names this device, and that `at` is within an hour of `now_ms`: eGuard's clock as it stood before the answer
/// that carried the command arrived (see `state::AgentState::apply_sync`), never a time from that same answer.
pub fn verify_uninstall(keys: &TrustedKeys, envelope: &Value, own_device_id: &str, now_ms: i64) -> Result<UninstallCommand, VerifyError> {
    let command = envelope.get("command").filter(|c| c.is_object()).ok_or(VerifyError::Malformed)?;
    let signature = envelope.get("signature").and_then(Value::as_str).ok_or(VerifyError::Malformed)?;
    if !keys.verify(command, signature, envelope.get("keyId").and_then(Value::as_str)) {
        return Err(VerifyError::BadSignature);
    }
    let f: UninstallFields = serde_json::from_value(command.clone()).map_err(|_| VerifyError::Malformed)?;
    if f.kind != UNINSTALL_TYPE {
        return Err(VerifyError::WrongType(f.kind));
    }
    if f.device_id != own_device_id {
        return Err(VerifyError::WrongDevice);
    }
    let at = crate::clock::parse_iso_ms(&f.at).ok_or(VerifyError::Malformed)?;
    if (now_ms - at).abs() > UNINSTALL_MAX_AGE_MS {
        return Err(VerifyError::Stale);
    }
    Ok(UninstallCommand { device_id: f.device_id, requested_at: f.requested_at, at: f.at, at_ms: at })
}

/// What `GET /catalog` brought.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CatalogUpdate {
    /// The copy already kept is the server's current one.
    Unchanged { version: String },
    /// Another catalog, verified. Keep it (with its signature) as the last good copy.
    Changed(Catalog),
}

/// Checks a `GET /catalog` answer (as received). A catalog must carry eGuard's signature and the catalog type.
/// "Unchanged" counts only for the version kept (`kept_version`, the last good copy).
///
/// The version is a hash of the entries, so it can't say which catalog is newer: a signed older catalog replayed
/// by someone who can answer for the server (a proxy with its own root certificate) is accepted. What it can do is
/// limited to the catalog's lists (a publisher removed since is trusted again) until the next real one arrives.
pub fn verify_catalog(keys: &TrustedKeys, response: &Value, kept_version: Option<&str>) -> Result<CatalogUpdate, VerifyError> {
    if response.get("unchanged").and_then(Value::as_bool) == Some(true) {
        let version = response.get("version").and_then(crate::wire::catalog_version).ok_or(VerifyError::Malformed)?;
        // The server answers "unchanged" only for the version it was sent; anything else isn't an answer about ours
        if kept_version != Some(version.as_str()) {
            return Err(VerifyError::Malformed);
        }
        return Ok(CatalogUpdate::Unchanged { version });
    }
    let catalog = response.get("catalog").filter(|c| c.is_object()).ok_or(VerifyError::Malformed)?;
    let signature = response.get("signature").and_then(Value::as_str).ok_or(VerifyError::Malformed)?;
    if !keys.verify(catalog, signature, response.get("keyId").and_then(Value::as_str)) {
        return Err(VerifyError::BadSignature);
    }
    let parsed: Catalog = serde_json::from_value(catalog.clone()).map_err(|_| VerifyError::Malformed)?;
    if parsed.kind != CATALOG_TYPE {
        return Err(VerifyError::WrongType(parsed.kind));
    }
    Ok(CatalogUpdate::Changed(parsed))
}
