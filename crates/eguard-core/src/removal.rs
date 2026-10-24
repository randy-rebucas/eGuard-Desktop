//! Offline removal codes (spec section 10) and the limit on guessing them.
//!
//! The code for a window is the first 8 bytes of `HMAC-SHA256(removalSecret, "eguard.device.remove:<deviceId>:<window>")`,
//! each byte mapped to `ALPHABET[byte % 32]`, with `window = floor(unix ms / 900000)`. Same as `removalCode` in
//! `~/eguard/src/lib/device-removal.ts`. The agent accepts the current window and the one before.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hmac::{Hmac, Mac as _};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use subtle::ConstantTimeEq as _;

/// 15 minutes. A code lasts 15 to 30 minutes.
pub const WINDOW_MS: i64 = 15 * 60_000;
/// Same letters as pairing codes: no 0/O or 1/I. 32 of them, so a byte maps without bias.
pub const ALPHABET: &[u8; 32] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
pub const CODE_LEN: usize = 8;

/// Wrong codes in a row before the input locks.
pub const MAX_FAILURES: u32 = 5;
/// The first lockout; each one after doubles it, up to `MAX_LOCKOUT_MS`.
pub const FIRST_LOCKOUT_MS: i64 = 15 * 60_000;
pub const MAX_LOCKOUT_MS: i64 = 24 * 60 * 60_000;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("the removal secret isn't base64url of 32 bytes")]
pub struct BadSecret;

/// The removal secret from `/pair` (base64url, no padding).
#[derive(Clone, PartialEq, Eq)]
pub struct RemovalSecret(Vec<u8>);

impl std::fmt::Debug for RemovalSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RemovalSecret(<redacted>)")
    }
}

impl RemovalSecret {
    pub fn from_base64url(s: &str) -> Result<Self, BadSecret> {
        let bytes = URL_SAFE_NO_PAD.decode(s.trim().trim_end_matches('=')).map_err(|_| BadSecret)?;
        if bytes.len() != 32 {
            return Err(BadSecret);
        }
        Ok(Self(bytes))
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes.to_vec())
    }
}

/// The window a time falls in.
pub fn window_of(unix_ms: i64) -> i64 {
    unix_ms.div_euclid(WINDOW_MS)
}

/// The code for one window.
///
/// # Panics
///
/// Never: HMAC takes a key of any length.
pub fn code_for_window(secret: &RemovalSecret, device_id: &str, window: i64) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(&secret.0).expect("HMAC takes any key length");
    mac.update(format!("eguard.device.remove:{device_id}:{window}").as_bytes());
    let digest = mac.finalize().into_bytes();
    digest[..CODE_LEN].iter().map(|b| ALPHABET[usize::from(b % 32)] as char).collect()
}

/// What a person typed, as a code: spaces and dashes dropped, upper case.
pub fn normalize(input: &str) -> String {
    input.chars().filter(|c| !c.is_whitespace() && *c != '-').collect::<String>().to_uppercase()
}

/// True when `input` is the code for the window of `now_ms` (eGuard's clock) or the one before.
pub fn code_matches(secret: &RemovalSecret, device_id: &str, input: &str, now_ms: i64) -> bool {
    let typed = normalize(input);
    if typed.len() != CODE_LEN {
        return false;
    }
    let w = window_of(now_ms);
    // Both compared, in constant time, so timing says nothing about which window or how many letters matched
    let current = code_for_window(secret, device_id, w).as_bytes().ct_eq(typed.as_bytes());
    let previous = code_for_window(secret, device_id, w - 1).as_bytes().ct_eq(typed.as_bytes());
    (current | previous).into()
}

/// Wrong guesses at "Remove with a code". Persist it: a restart must not reset the count or a lockout.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CodeAttempts {
    /// Wrong codes since the last lockout or success.
    pub failures: u32,
    /// Lockouts so far; each doubles the next one.
    pub lockouts: u32,
    /// While set and in the future (eGuard's clock), no code is checked.
    pub locked_until_ms: Option<i64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttemptResult {
    /// The code is right: removal is authorized.
    Accepted,
    /// Wrong; `remaining` more tries before a lockout.
    Rejected { remaining: u32 },
    /// Wrong, and that was the last try: locked until then. `newly` is true for the attempt that caused it, so the
    /// caller tells the parent once per lockout.
    LockedOut { until_ms: i64, newly: bool },
}

impl CodeAttempts {
    /// Checks a typed code, counting it against the limit.
    pub fn attempt(&mut self, secret: &RemovalSecret, device_id: &str, input: &str, now_ms: i64) -> AttemptResult {
        if let Some(until_ms) = self.locked_until_ms.filter(|&until| now_ms < until) {
            return AttemptResult::LockedOut { until_ms, newly: false };
        }
        self.locked_until_ms = None;
        if code_matches(secret, device_id, input, now_ms) {
            *self = Self::default();
            return AttemptResult::Accepted;
        }
        self.failures += 1;
        if self.failures < MAX_FAILURES {
            return AttemptResult::Rejected { remaining: MAX_FAILURES - self.failures };
        }
        let lockout = FIRST_LOCKOUT_MS.saturating_mul(1 << self.lockouts.min(16)).min(MAX_LOCKOUT_MS);
        self.failures = 0;
        self.lockouts += 1;
        let until_ms = now_ms + lockout;
        self.locked_until_ms = Some(until_ms);
        AttemptResult::LockedOut { until_ms, newly: true }
    }
}

/// eGuard's own removal, once eGuard's signed command or a right code authorized it (spec section 10). Persisted, so a
/// restart part way carries on with it rather than asking again.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Removing {
    /// The code typed, as sent with `UNINSTALL_ACK`; `None` when eGuard's signed command authorized it.
    pub code: Option<String>,
    /// eGuard's time when it was authorized.
    pub since_ms: i64,
    /// The server has heard (or can't be asked): nothing is left but removing.
    pub ready: bool,
}

/// Whether eGuard may be stopped or uninstalled (spec section 10): it protects nothing yet (`paired` false), or an
/// authorized removal is under way and the server has heard (or can't be asked).
pub fn may_be_removed(paired: bool, removing: Option<&Removing>) -> bool {
    !paired || removing.is_some_and(|r| r.ready)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SPEC_SECRET: &str = "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc";

    #[test]
    fn spec_test_vector() {
        let secret = RemovalSecret::from_base64url(SPEC_SECRET).unwrap();
        assert_eq!(secret, RemovalSecret::from_bytes([7; 32]));
        assert_eq!(code_for_window(&secret, "dev_123", 0), "XEM54CNL");
    }

    #[test]
    fn current_and_previous_window_accepted_older_rejected() {
        let secret = RemovalSecret::from_bytes([7; 32]);
        let code = code_for_window(&secret, "dev_123", 0);
        // Window 0 is [0, 900000) ms
        assert!(code_matches(&secret, "dev_123", &code, 0));
        assert!(code_matches(&secret, "dev_123", &code, WINDOW_MS - 1));
        assert!(code_matches(&secret, "dev_123", &code, WINDOW_MS));
        assert!(code_matches(&secret, "dev_123", &code, 2 * WINDOW_MS - 1));
        assert!(!code_matches(&secret, "dev_123", &code, 2 * WINDOW_MS));
        // Not before its window either
        assert!(!code_matches(&secret, "dev_123", &code, -1));
    }

    #[test]
    fn typing_is_forgiving_but_the_device_must_match() {
        let secret = RemovalSecret::from_bytes([7; 32]);
        assert!(code_matches(&secret, "dev_123", "xem5-4cnl", 10));
        assert!(code_matches(&secret, "dev_123", " XEM5 4CNL ", 10));
        assert!(!code_matches(&secret, "dev_456", "XEM54CNL", 10));
        assert!(!code_matches(&secret, "dev_123", "XEM54CN", 10));
        assert!(!code_matches(&secret, "dev_123", "", 10));
    }

    #[test]
    fn secrets_must_be_32_bytes() {
        assert_eq!(RemovalSecret::from_base64url("AAAA"), Err(BadSecret));
        assert_eq!(RemovalSecret::from_base64url("not base64!"), Err(BadSecret));
        assert!(format!("{:?}", RemovalSecret::from_bytes([7; 32])).contains("redacted"));
    }

    #[test]
    fn five_wrong_codes_lock_for_15_minutes_then_doubling() {
        let secret = RemovalSecret::from_bytes([7; 32]);
        let mut a = CodeAttempts::default();
        let t0 = 1_000_000;
        for remaining in (1..MAX_FAILURES).rev() {
            assert_eq!(a.attempt(&secret, "dev_123", "AAAAAAAA", t0), AttemptResult::Rejected { remaining });
        }
        assert_eq!(
            a.attempt(&secret, "dev_123", "AAAAAAAA", t0),
            AttemptResult::LockedOut { until_ms: t0 + FIRST_LOCKOUT_MS, newly: true }
        );
        // While locked, even the right code isn't checked
        let right = code_for_window(&secret, "dev_123", window_of(t0 + 60_000));
        assert_eq!(
            a.attempt(&secret, "dev_123", &right, t0 + 60_000),
            AttemptResult::LockedOut { until_ms: t0 + FIRST_LOCKOUT_MS, newly: false }
        );
        // After it, five more wrong ones lock for twice as long
        let t1 = t0 + FIRST_LOCKOUT_MS;
        for _ in 1..MAX_FAILURES {
            a.attempt(&secret, "dev_123", "AAAAAAAA", t1);
        }
        assert_eq!(
            a.attempt(&secret, "dev_123", "AAAAAAAA", t1),
            AttemptResult::LockedOut { until_ms: t1 + 2 * FIRST_LOCKOUT_MS, newly: true }
        );
    }

    #[test]
    fn lockouts_cap_at_a_day_and_survive_a_restart() {
        let secret = RemovalSecret::from_bytes([7; 32]);
        let mut a = CodeAttempts { failures: 4, lockouts: 30, locked_until_ms: None };
        let r = a.attempt(&secret, "dev_123", "AAAAAAAA", 0);
        assert_eq!(r, AttemptResult::LockedOut { until_ms: MAX_LOCKOUT_MS, newly: true });
        let saved = serde_json::to_string(&a).unwrap();
        let mut restored: CodeAttempts = serde_json::from_str(&saved).unwrap();
        assert!(matches!(restored.attempt(&secret, "dev_123", "AAAAAAAA", 5), AttemptResult::LockedOut { newly: false, .. }));
    }

    #[test]
    fn the_right_code_resets_the_count() {
        let secret = RemovalSecret::from_bytes([7; 32]);
        let mut a = CodeAttempts::default();
        a.attempt(&secret, "dev_123", "AAAAAAAA", 10);
        assert_eq!(a.attempt(&secret, "dev_123", "XEM54CNL", 10), AttemptResult::Accepted);
        assert_eq!(a, CodeAttempts::default());
    }
}
