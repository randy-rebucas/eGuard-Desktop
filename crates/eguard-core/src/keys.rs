//! Public keys this build trusts for eGuard's signatures (base64 SPKI DER, ECDSA P-256).
//!
//! A release build sets `EGUARD_POLICY_PUBLIC_KEYS` at compile time (one key, or several separated by commas during a
//! rotation) to eGuard's production key. Without it, the build trusts the development server's key from
//! `~/eguard/.env.local` (keyId `60da38f4c654f71a`), which is only good against a local server.

const DEV_KEY: &str =
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEB6u9DcnTOpb7ePyPozlzetKBXInsPXiuOR/Y/kygaGkN/N7grMblEo4XMRLe+d4v7NL3wRUQnAfX2kvEw7zl5Q==";

/// The keys compiled into this binary, separated by commas.
pub const BUILTIN_PUBLIC_KEYS: &str = match option_env!("EGUARD_POLICY_PUBLIC_KEYS") {
    Some(k) => k,
    None => DEV_KEY,
};

/// True when this build only trusts the development key (release checks refuse to ship it).
pub const fn is_dev_build() -> bool {
    option_env!("EGUARD_POLICY_PUBLIC_KEYS").is_none()
}
