//! eGuard's files: replaced atomically, so a crash or power cut mid-write leaves the old file or the new one.
#![allow(unsafe_code)]

use crate::wide::wide;
use std::io::Write;
use std::os::windows::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_REPARSE_POINT, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
};

/// `%ProgramData%\eGuard`, where a real install keeps its state.
pub fn program_data_dir() -> PathBuf {
    let base = std::env::var_os("ProgramData").map_or_else(|| PathBuf::from(r"C:\ProgramData"), PathBuf::from);
    base.join("eGuard")
}

/// Creates the folder if needed. With `sddl`, also (re)sets its owner and permissions, every time.
///
/// Any user can create folders in `ProgramData`, and whoever owns one can always change its permissions back. So a
/// folder not owned by SYSTEM or administrators, or one that is a junction or link (whose target would get eGuard's
/// files and permissions), was made by someone else: it's moved aside, kept for a look, and a new one is made.
pub fn ensure_dir(path: &Path, sddl: Option<&str>) -> std::io::Result<()> {
    if let Some(sddl) = sddl
        && let Ok(meta) = std::fs::symlink_metadata(path)
    {
        let reparse = meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0;
        let owned = !reparse && crate::security::owner_of(path).is_ok_and(|o| crate::security::is_trusted_owner(&o));
        if !owned {
            let secs = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs());
            let name = path.file_name().map(|f| f.to_string_lossy().into_owned()).unwrap_or_default();
            let aside = path.with_file_name(format!("{name}.untrusted-{secs}"));
            // Renaming a junction moves the junction, never what it points to
            std::fs::rename(path, &aside).map_err(|e| {
                std::io::Error::new(e.kind(), format!("{} was made by someone else and couldn't be moved aside: {e}", path.display()))
            })?;
            // Its maker mustn't keep a folder of eGuard's old files either (a junction is left as it is)
            if !reparse {
                let _ = crate::security::set_dir_security(&aside, sddl);
            }
        }
    }
    std::fs::create_dir_all(path)?;
    if let Some(sddl) = sddl {
        crate::security::set_dir_security(path, sddl)?;
    }
    Ok(())
}

/// The file's bytes, or `None` when it doesn't exist.
pub fn read_optional(path: &Path) -> std::io::Result<Option<Vec<u8>>> {
    match std::fs::read(path) {
        Ok(b) => Ok(Some(b)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// Writes `bytes` to a new temporary file beside `path`, flushes it to disk, then moves it over `path` with
/// write-through, so the rename itself is on disk when this returns.
///
/// The temporary file is always a new one (`create_new`, a name not used before): an existing file of that name,
/// put there by someone else with their own permissions, would carry those permissions over `path`.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let tmp = path.with_extension(format!("tmp-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
    {
        let mut f = std::fs::OpenOptions::new().write(true).create_new(true).open(&tmp)?;
        f.write_all(bytes)?;
        // FlushFileBuffers: the data is on disk before the rename can be
        f.sync_all()?;
    }
    let (from, to) = (wide(&tmp.to_string_lossy()), wide(&path.to_string_lossy()));
    // SAFETY: both paths are zero-terminated and live for the call.
    let ok = unsafe { MoveFileExW(from.as_ptr(), to.as_ptr(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) };
    if ok == 0 {
        let e = crate::last_error();
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replaces_in_place_and_leaves_no_temp_file() {
        let dir = std::env::temp_dir().join(format!("eguard-files-{}", std::process::id()));
        ensure_dir(&dir, None).unwrap();
        let p = dir.join("state.json");
        assert_eq!(read_optional(&p).unwrap(), None);
        write_atomic(&p, b"one").unwrap();
        write_atomic(&p, b"two").unwrap();
        assert_eq!(read_optional(&p).unwrap().unwrap(), b"two");
        // Only state.json is left: no temporary file
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
