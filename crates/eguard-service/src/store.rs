//! The data folder: `state.json` (replaced atomically) and `secrets.bin` (DPAPI, machine scope).

use crate::log;
use eguard_core::store::{DeviceSecrets, Persisted};
use eguard_win::{dpapi, files};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct Store {
    dir: PathBuf,
}

impl Store {
    /// Creates the folder. `sddl` locks it down (a real install); `None` leaves the parent folder's permissions
    /// (console mode, in the developer's own profile).
    pub fn open(dir: &Path, sddl: Option<&str>) -> std::io::Result<Self> {
        files::ensure_dir(dir, sddl)?;
        Ok(Self { dir: dir.to_owned() })
    }

    /// The folder as it is, created or changed in no way (the installer's check and `purge`, which only read it or
    /// take it out).
    pub fn at(dir: &Path) -> Self {
        Self { dir: dir.to_owned() }
    }

    /// Marks the service as running in boot `boot_id`. Returns the boot id the last run left, when it didn't end
    /// cleanly (`clear_running`): the same boot means it was killed or crashed; another means the computer lost power
    /// or restarted without stopping it, which isn't anyone's doing.
    pub fn mark_running(&self, boot_id: u64) -> Option<u64> {
        let path = self.dir.join("running");
        let left = std::fs::read_to_string(&path).ok().and_then(|s| s.trim().parse().ok());
        if let Err(e) = files::write_atomic(&path, boot_id.to_string().as_bytes()) {
            log::warn(&format!("couldn't write {}: {e}", path.display()));
        }
        left
    }

    /// The service is stopping as asked (or Windows is shutting down): the next start isn't a restart.
    pub fn clear_running(&self) {
        let _ = std::fs::remove_file(self.dir.join("running"));
    }

    /// Whether `secrets.bin` is there, readable or not.
    pub fn has_secrets(&self) -> bool {
        self.secrets_path().exists()
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn state_path(&self) -> PathBuf {
        self.dir.join("state.json")
    }

    fn secrets_path(&self) -> PathBuf {
        self.dir.join("secrets.bin")
    }

    /// The copy of the state from before the last save.
    fn prev_path(&self) -> PathBuf {
        self.dir.join("state.prev.json")
    }

    /// The state and secrets as they are on disk. A state file that's missing, doesn't parse or is too new is set
    /// aside (renamed, for a look later) and the copy from before the last save is used instead, so the day's usage,
    /// the code lockout, eGuard's clock and the queue survive; only when both are gone does the engine rebuild the
    /// state from the secrets. Secrets that exist but don't decrypt are an error worth shouting about: the computer
    /// stays paired and enforcing, without a token, until someone looks.
    pub fn load(&self) -> (Persisted, Option<DeviceSecrets>) {
        let secrets = match files::read_optional(&self.secrets_path()) {
            Ok(None) => None,
            Ok(Some(sealed)) => match dpapi::unprotect(&sealed)
                .map_err(|e| e.to_string())
                .and_then(|b| DeviceSecrets::from_json(&b).map_err(|e| e.to_string()))
            {
                Ok(s) => Some(s),
                Err(e) => {
                    log::error(&format!("secrets.bin is unreadable ({e}); this computer can't talk to eGuard until it's repaired"));
                    None
                }
            },
            Err(e) => {
                log::error(&format!("secrets.bin couldn't be read: {e}"));
                None
            }
        };
        let main = Self::read_state(&self.state_path());
        let state = match main {
            Ok(Some(s)) => s,
            main => match (Self::read_state(&self.prev_path()), main.is_err()) {
                (Ok(Some(s)), _) => {
                    log::warn("state.json was missing or unreadable; carrying on from the copy before the last save (state.prev.json)");
                    s
                }
                // A fresh install has neither
                (_, false) if secrets.is_none() => Persisted::default(),
                _ => {
                    log::error("no usable state.json or state.prev.json; starting from what the secrets say");
                    Persisted::default()
                }
            },
        };
        (state, secrets)
    }

    /// One state file: `Ok(None)` when it isn't there, `Err` when it's there but unusable (set aside, logged).
    fn read_state(path: &Path) -> Result<Option<Persisted>, ()> {
        let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        match files::read_optional(path) {
            Ok(None) => Ok(None),
            Ok(Some(bytes)) => match Persisted::from_json(&bytes) {
                Ok(s) => Ok(Some(s)),
                Err(e) => {
                    let aside = path.with_extension(format!("corrupt-{}", std::process::id()));
                    log::error(&format!("{name}: {e}; kept as {}", aside.display()));
                    let _ = std::fs::rename(path, aside);
                    Err(())
                }
            },
            Err(e) => {
                log::error(&format!("{name} couldn't be read: {e}"));
                Err(())
            }
        }
    }

    /// Saves the state. The file it replaces becomes `state.prev.json` first: if the new one is ever lost or
    /// corrupt, the next start carries on from the one before rather than from nothing. Neither holds a secret.
    pub fn save_state(&self, state: &Persisted) -> std::io::Result<()> {
        match std::fs::rename(self.state_path(), self.prev_path()) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => log::warn(&format!("couldn't keep the previous state.json as state.prev.json: {e}")),
        }
        files::write_atomic(&self.state_path(), &state.to_json())
    }

    pub fn save_secrets(&self, secrets: &DeviceSecrets) -> std::io::Result<()> {
        files::write_atomic(&self.secrets_path(), &dpapi::protect(&secrets.to_json())?)
    }

    /// eGuard is being removed: everything in the folder goes (secrets, state, the copies set aside) except `logs`,
    /// which this process is still writing to. Returns what couldn't be removed, in words.
    pub fn remove_all(&self) -> Vec<String> {
        let mut left = Vec::new();
        let entries = match std::fs::read_dir(&self.dir) {
            Ok(e) => e,
            Err(e) => return vec![format!("{}: {e}", self.dir.display())],
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if entry.file_name().eq_ignore_ascii_case("logs") {
                continue;
            }
            let removed = if path.is_dir() { std::fs::remove_dir_all(&path) } else { std::fs::remove_file(&path) };
            if let Err(e) = removed {
                left.push(format!("{}: {e}", path.display()));
            }
        }
        left
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secrets_and_state_survive_a_restart_and_a_corrupt_state_is_set_aside() {
        let dir = std::env::temp_dir().join(format!("eguard-store-{}", std::process::id()));
        let store = Store::open(&dir, None).unwrap();
        let secrets = DeviceSecrets { device_id: "dev_1".into(), token: "tok".into(), removal_secret: None };
        store.save_secrets(&secrets).unwrap();
        store.save_state(&Persisted::recover(&secrets)).unwrap();
        let (state, loaded) = store.load();
        assert_eq!(loaded.as_ref(), Some(&secrets));
        assert!(state.matches(&secrets));
        // The token isn't on disk in the clear
        assert!(!std::fs::read(dir.join("secrets.bin")).unwrap().windows(3).any(|w| w == b"tok"));

        std::fs::write(dir.join("state.json"), b"{half a fi").unwrap();
        let (state, loaded) = store.load();
        assert_eq!(state, Persisted::default());
        assert!(loaded.is_some());
        assert!(std::fs::read_dir(&dir).unwrap().any(|e| e.unwrap().file_name().to_string_lossy().starts_with("state.corrupt-")));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_lost_or_corrupt_state_falls_back_to_the_one_before() {
        let dir = std::env::temp_dir().join(format!("eguard-store-prev-{}", std::process::id()));
        let store = Store::open(&dir, None).unwrap();
        let secrets = DeviceSecrets { device_id: "dev_1".into(), token: "tok".into(), removal_secret: None };
        let older = Persisted::recover(&secrets);
        let mut newer = older.clone();
        newer.last_scan_ms = Some(42);
        store.save_state(&older).unwrap();
        store.save_state(&newer).unwrap();
        assert_eq!(store.load().0, newer);

        // Corrupt: the copy before the last save, not nothing
        std::fs::write(dir.join("state.json"), b"{half a fi").unwrap();
        assert_eq!(store.load().0, older);
        // Missing (a crash between keeping the old one and writing the new): the same
        store.save_state(&newer).unwrap();
        store.save_state(&newer).unwrap();
        std::fs::remove_file(dir.join("state.json")).unwrap();
        assert_eq!(store.load().0, newer);
        // From a newer build: set aside, and the one before used
        store.save_state(&older).unwrap();
        std::fs::write(dir.join("state.json"), br#"{"version":99,"agent":null}"#).unwrap();
        assert_eq!(store.load().0, newer);
        // Neither left: the engine starts from the secrets
        let _ = std::fs::remove_file(dir.join("state.json"));
        std::fs::remove_file(dir.join("state.prev.json")).unwrap();
        assert_eq!(store.load().0, Persisted::default());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn removal_takes_everything_but_the_log() {
        let dir = std::env::temp_dir().join(format!("eguard-store-remove-{}", std::process::id()));
        let store = Store::open(&dir, None).unwrap();
        let secrets = DeviceSecrets { device_id: "dev_1".into(), token: "tok".into(), removal_secret: None };
        store.save_secrets(&secrets).unwrap();
        store.save_state(&Persisted::recover(&secrets)).unwrap();
        store.save_state(&Persisted::recover(&secrets)).unwrap();
        std::fs::create_dir_all(dir.join("logs")).unwrap();
        std::fs::write(dir.join("logs").join("service.log"), b"x").unwrap();
        std::fs::create_dir_all(dir.join("eGuard.untrusted-1")).unwrap();
        assert_eq!(store.remove_all(), Vec::<String>::new());
        let left: Vec<String> = std::fs::read_dir(&dir).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
        assert_eq!(left, ["logs"]);
        assert_eq!(store.load().1, None);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
