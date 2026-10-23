//! eGuard's files: replaced atomically, so a crash or power cut mid-write leaves the old file or the new one.
#![allow(unsafe_code)]

use crate::wide::wide;
use std::io::Write;
use std::path::{Path, PathBuf};
use windows_sys::Win32::Storage::FileSystem::{MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW};

/// `%ProgramData%\eGuard`, where a real install keeps its state.
pub fn program_data_dir() -> PathBuf {
    let base = std::env::var_os("ProgramData").map_or_else(|| PathBuf::from(r"C:\ProgramData"), PathBuf::from);
    base.join("eGuard")
}

/// Creates the folder if needed. With `sddl`, also (re)sets its permissions, every time: a folder someone else made
/// first (any user can create folders in `ProgramData`) must not keep their access.
pub fn ensure_dir(path: &Path, sddl: Option<&str>) -> std::io::Result<()> {
    std::fs::create_dir_all(path)?;
    if let Some(sddl) = sddl {
        crate::security::set_dir_dacl(path, sddl)?;
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

/// Writes `bytes` to a temporary file beside `path`, flushes it to disk, then moves it over `path` with
/// write-through, so the rename itself is on disk when this returns.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    {
        let mut f = std::fs::File::create(&tmp)?;
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
        assert!(!p.with_extension("tmp").exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
