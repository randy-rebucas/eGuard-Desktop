//! eGuard's own update, the service's half (spec section 10, "Updates"; the checks and the hand-off are
//! `eguard_core::update`):
//!
//! 1. `stage`: each file of a verified manifest is downloaded (no token), then checked: its size and SHA-256 against
//!    the signed manifest, and its Authenticode signature, which must be valid and eGuard's (`update::SIGNER`).
//! 2. `install` (service mode, with removal protection in place): the guard's cache is copied to `cache\previous`,
//!    the hand-off written (`Swap`), and the new files put in the cache. The service then stops; the guard puts the
//!    cache's files in place and starts it again (`Running`).
//! 3. `note_health`: the new version, once it has synced and saved its state. Without it, the guard puts the previous
//!    version back after 10 minutes and leaves `take_outcome` for it to read.
//!
//! Console mode downloads and checks only: nothing is installed or replaced on a developer's PC.

use crate::lockdown;
use eguard_core::update::{self, Handoff, Health, Manifest, Outcome, Step};
use eguard_win::files;
use std::path::Path;
use std::time::Duration;

/// Each step of a download (connecting, each read) may take this long.
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(60);

/// Downloads and checks every file of `m` into `dir` (emptied first). On `Ok`, `dir` holds exactly the three
/// programs, each the manifest's and signed by eGuard.
pub fn stage(m: &Manifest, dir: &Path) -> Result<(), String> {
    if dir.exists() {
        std::fs::remove_dir_all(dir).map_err(|e| format!("emptying {}: {e}", dir.display()))?;
    }
    std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let http = eguard_win::http::WinHttp::new(&format!("eGuard-Windows/{}", crate::runner::APP_VERSION)).map_err(|e| e.to_string())?;
    for f in &m.files {
        // `verify_manifest` allowed only the three programs' names, so this stays inside `dir`
        let dest = dir.join(&f.name);
        http.download(&f.url, &dest, f.size, DOWNLOAD_TIMEOUT).map_err(|e| format!("downloading {}: {e}", f.name))?;
        let bytes = std::fs::read(&dest).map_err(|e| format!("{}: {e}", dest.display()))?;
        update::check_file(&bytes, f)?;
        match eguard_win::authenticode::signer_names(&dest) {
            Some(s) if update::signed_by_eguard(s.organization.as_deref(), s.common_name.as_deref()) => {}
            Some(s) => {
                return Err(format!(
                    "{} is signed by {}, not by eGuard ({})",
                    f.name,
                    s.name().unwrap_or("someone unnamed"),
                    update::SIGNER
                ));
            }
            None => return Err(format!("{} carries no valid signature", f.name)),
        }
    }
    Ok(())
}

/// Puts the staged version in the guard's cache, the current one kept in `cache\previous`, and hands over to the
/// guard. The service must stop next (the guard swaps the program files once it has). Nothing is left half done: a
/// copy that fails puts the cache back and takes the hand-off out.
pub fn install(m: &Manifest, staged: &Path) -> Result<(), String> {
    let cache = lockdown::cache_dir();
    let previous = cache.join(update::PREVIOUS_DIR);
    let handoff = cache.join(update::HANDOFF_FILE);
    if handoff.exists() {
        return Err("an update is already under way".into());
    }
    if previous.exists() {
        std::fs::remove_dir_all(&previous).map_err(|e| format!("{}: {e}", previous.display()))?;
    }
    std::fs::create_dir_all(&previous).map_err(|e| format!("{}: {e}", previous.display()))?;
    for p in update::PROGRAMS {
        std::fs::copy(cache.join(p), previous.join(p)).map_err(|e| format!("keeping {p} as the previous version: {e}"))?;
    }
    let _ = std::fs::remove_file(cache.join(update::HEALTH_FILE));
    // The hand-off before the cache changes: if this process ends part way, the guard finds it, and the previous
    // version is there to go back to
    let h = Handoff { from: crate::runner::APP_VERSION.into(), to: m.version.clone(), step: Step::Swap };
    files::write_atomic(&handoff, &to_json(&h)).map_err(|e| format!("{}: {e}", handoff.display()))?;
    let copied = update::PROGRAMS.iter().try_for_each(|p| {
        let bytes = std::fs::read(staged.join(p)).map_err(|e| format!("{p}: {e}"))?;
        files::write_atomic(&cache.join(p), &bytes).map_err(|e| format!("putting {p} in the guard's cache: {e}"))
    });
    if let Err(e) = copied {
        for p in update::PROGRAMS {
            let _ = std::fs::read(previous.join(p)).and_then(|b| files::write_atomic(&cache.join(p), &b));
        }
        let _ = std::fs::remove_file(&handoff);
        let _ = std::fs::remove_dir_all(&previous);
        return Err(e);
    }
    let _ = std::fs::remove_dir_all(staged);
    Ok(())
}

/// This version works (it synced and saved its state): if the guard is waiting for it, it hears. True when there's
/// nothing more to tell (told, or no update waits for this version); false to be asked again at the next tick.
pub fn note_health(version: &str) -> bool {
    let cache = lockdown::cache_dir();
    let Some(h) = read::<Handoff>(&cache.join(update::HANDOFF_FILE)) else { return true };
    if h.to != version {
        return true;
    }
    // Started before the guard marked the swap done (the service manager restarted it after the guard ended the old
    // one): the guard reads health only once it has
    if h.step != Step::Running {
        return false;
    }
    match files::write_atomic(&cache.join(update::HEALTH_FILE), &to_json(&Health { version: version.into() })) {
        Ok(()) => {
            crate::log::info(&format!("eGuard {version} synced and saved its state; the guard keeps it"));
            true
        }
        Err(e) => {
            crate::log::warn(&format!("couldn't tell the guard this version works: {e}"));
            false
        }
    }
}

/// An update the guard rolled back, once (the file is taken out).
pub fn take_outcome() -> Option<Outcome> {
    let path = lockdown::cache_dir().join(update::OUTCOME_FILE);
    let outcome = read::<Outcome>(&path);
    let _ = std::fs::remove_file(&path);
    outcome
}

/// Settings › Apps shows the version that runs, not the one the installer put there.
pub fn show_version(version: &str) {
    use eguard_win::registry::{Key, Root, View};
    const ENTRY: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\eGuard";
    // Only an entry the installer made: never one created here
    let shown = Key::open(Root::LocalMachine, ENTRY, View::Native).and_then(|k| k.string("DisplayVersion"));
    if shown.is_some_and(|v| v != version)
        && let Ok(key) = Key::create(Root::LocalMachine, ENTRY, View::Native)
    {
        let _ = key.set_string("DisplayVersion", version);
    }
}

fn read<T: serde::de::DeserializeOwned>(path: &Path) -> Option<T> {
    files::read_optional(path).ok().flatten().and_then(|b| serde_json::from_slice(&b).ok())
}

fn to_json<T: serde::Serialize>(v: &T) -> Vec<u8> {
    serde_json::to_vec(v).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use eguard_core::update::{UPDATE_TYPE, UpdateFile};
    use std::io::{Read, Write};

    /// Serves `files` (path, bytes) over plain HTTP on loopback, a 404 for anything else. Returns the base URL.
    fn serve(files: Vec<(String, Vec<u8>)>) -> String {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        std::thread::spawn(move || {
            for mut s in listener.incoming().flatten() {
                let mut req = Vec::new();
                let mut buf = [0u8; 1024];
                while !req.windows(4).any(|w| w == b"\r\n\r\n") {
                    match s.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => req.extend_from_slice(&buf[..n]),
                    }
                }
                let path = String::from_utf8_lossy(&req).split_whitespace().nth(1).unwrap_or("").to_owned();
                let _ = match files.iter().find(|(p, _)| *p == path) {
                    Some((_, body)) => write!(s, "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len())
                        .and_then(|()| s.write_all(body)),
                    None => write!(s, "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"),
                };
            }
        });
        base
    }

    /// A manifest whose first file is `bytes` at `base`/first (the size and hash given), the other two never reached.
    fn manifest(base: &str, size: u64, sha256: &str) -> Manifest {
        let mut files = update::PROGRAMS
            .iter()
            .map(|p| UpdateFile { name: (*p).into(), size, sha256: sha256.into(), url: format!("{base}/{p}") })
            .collect::<Vec<_>>();
        files[0].url = format!("{base}/first");
        Manifest { kind: UPDATE_TYPE.into(), version: "9.0.0".into(), issued_at: 1, files }
    }

    fn staged(name: &str, m: &Manifest) -> Result<(), String> {
        let dir = std::env::temp_dir().join(format!("eguard-stage-{name}-{}", std::process::id()));
        let r = stage(m, &dir);
        let _ = std::fs::remove_dir_all(&dir);
        r
    }

    #[test]
    fn a_download_must_match_the_manifest_and_carry_eguards_signature() {
        let body = b"MZ not eGuard's".to_vec();
        let base = serve(vec![("/first".into(), body.clone())]);
        let hash = update::sha256_hex(&body);
        let size = body.len() as u64;
        // The right bytes, unsigned
        let e = staged("unsigned", &manifest(&base, size, &hash)).unwrap_err();
        assert!(e.contains("eguard-service.exe carries no valid signature"), "{e}");
        // Other bytes than the manifest's
        let e = staged("hash", &manifest(&base, size, &"0".repeat(64))).unwrap_err();
        assert!(e.contains("SHA-256 doesn't match"), "{e}");
        // More than the manifest's size: the download stops
        let e = staged("size", &manifest(&base, size - 1, &hash)).unwrap_err();
        assert!(e.contains("too large"), "{e}");
        // Not there
        let mut m = manifest(&base, size, &hash);
        m.files[0].url = format!("{base}/missing");
        let e = staged("missing", &m).unwrap_err();
        assert!(e.contains("answered 404"), "{e}");
    }

    #[test]
    fn a_valid_signature_that_isnt_eguards_is_refused() {
        // Edge carries an embedded Microsoft signature on every Windows 11
        let edge = std::path::Path::new(r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe");
        let Ok(body) = std::fs::read(edge) else { return };
        let (size, hash) = (body.len() as u64, update::sha256_hex(&body));
        let base = serve(vec![("/first".into(), body)]);
        let e = staged("signed", &manifest(&base, size, &hash)).unwrap_err();
        assert!(e.contains("is signed by microsoft corporation, not by eGuard"), "{e}");
    }
}
