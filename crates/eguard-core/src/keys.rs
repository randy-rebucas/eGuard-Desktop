//! Public keys this build trusts for eGuard's signatures (base64 SPKI DER, ECDSA P-256).
//!
//! `EGUARD_POLICY_PUBLIC_KEYS`, set at compile time, is eGuard's production key (one key, or several separated by
//! commas during a rotation). Without it the build trusts the development server's key from `~/eguard/.env.local`
//! (keyId `60da38f4c654f71a`), which is only good against a local server. A release build (no debug assertions)
//! refuses to compile without it, unless `EGUARD_DEV_RELEASE` is set: an optimized build against the dev server, for
//! measuring cost on a developer's PC. Such a build must never ship (`is_dev_build`).

const DEV_KEY: &str =
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEB6u9DcnTOpb7ePyPozlzetKBXInsPXiuOR/Y/kygaGkN/N7grMblEo4XMRLe+d4v7NL3wRUQnAfX2kvEw7zl5Q==";

// A release that silently trusted the dev key would take orders signed by whoever holds that key
#[cfg(not(debug_assertions))]
const _: () = assert!(
    option_env!("EGUARD_POLICY_PUBLIC_KEYS").is_some() || option_env!("EGUARD_DEV_RELEASE").is_some(),
    "a release build needs EGUARD_POLICY_PUBLIC_KEYS (eGuard's production public key); set EGUARD_DEV_RELEASE=1 for a local build against the dev server"
);

/// The keys compiled into this binary, separated by commas.
pub const BUILTIN_PUBLIC_KEYS: &str = match option_env!("EGUARD_POLICY_PUBLIC_KEYS") {
    Some(k) => k,
    None => DEV_KEY,
};

/// True when this build only trusts the development key: a debug build, or a release built with `EGUARD_DEV_RELEASE`.
/// Never to be shipped.
pub const fn is_dev_build() -> bool {
    option_env!("EGUARD_POLICY_PUBLIC_KEYS").is_none()
}
