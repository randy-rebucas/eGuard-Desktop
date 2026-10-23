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

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn state_path(&self) -> PathBuf {
        self.dir.join("state.json")
    }

    fn secrets_path(&self) -> PathBuf {
        self.dir.join("secrets.bin")
    }

    /// The state and secrets as they are on disk. A state file that doesn't parse is set aside (renamed, for a
    /// look later) and the engine rebuilds it from the secrets. Secrets that exist but don't decrypt are an error
    /// worth shouting about: the computer stays as paired, without a token, until someone looks.
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
        let state = match files::read_optional(&self.state_path()) {
            Ok(None) => Persisted::default(),
            Ok(Some(bytes)) => Persisted::from_json(&bytes).unwrap_or_else(|e| {
                let aside = self.state_path().with_extension(format!("corrupt-{}", std::process::id()));
                log::error(&format!("{e}; kept as {}", aside.display()));
                let _ = std::fs::rename(self.state_path(), aside);
                Persisted::default()
            }),
            Err(e) => {
                log::error(&format!("state.json couldn't be read: {e}"));
                Persisted::default()
            }
        };
        (state, secrets)
    }

    pub fn save_state(&self, state: &Persisted) -> std::io::Result<()> {
        files::write_atomic(&self.state_path(), &state.to_json())
    }

    pub fn save_secrets(&self, secrets: &DeviceSecrets) -> std::io::Result<()> {
        files::write_atomic(&self.secrets_path(), &dpapi::protect(&secrets.to_json())?)
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
}
