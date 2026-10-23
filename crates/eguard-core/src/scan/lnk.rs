//! The target of a Start Menu shortcut, read from the `.lnk` file itself ([MS-SHLLINK]): the `LinkInfo` local base
//! path plus its suffix. Shortcuts with no `LinkInfo` (MSI "advertised" ones, shell items) have no file target to
//! read and are left out; their program is in the Uninstall keys anyway.

fn u16_at(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(at..at + 2)?.try_into().ok()?))
}

fn u32_at(b: &[u8], at: usize) -> Option<usize> {
    Some(u32::from_le_bytes(b.get(at..at + 4)?.try_into().ok()?) as usize)
}

/// A zero-terminated single-byte string (the shortcut's code page; read as Latin-1, which is right for paths in
/// ASCII and close enough to tell a file name otherwise).
fn ansi_at(b: &[u8], at: usize) -> Option<String> {
    let s = b.get(at..)?;
    let end = s.iter().position(|&c| c == 0)?;
    Some(s[..end].iter().map(|&c| char::from(c)).collect())
}

fn utf16_at(b: &[u8], at: usize) -> Option<String> {
    let s = b.get(at..)?;
    let units: Vec<u16> = s.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c)).take_while(|&u| u != 0).collect();
    Some(String::from_utf16_lossy(&units))
}

const HEADER_SIZE: usize = 0x4C;
const HAS_ID_LIST: usize = 0x1;
const HAS_LINK_INFO: usize = 0x2;
const VOLUME_ID_AND_LOCAL_BASE_PATH: usize = 0x1;

/// The local path a shortcut points to, if it has one.
pub fn target(b: &[u8]) -> Option<String> {
    if u32_at(b, 0)? != HEADER_SIZE {
        return None;
    }
    let flags = u32_at(b, 0x14)?;
    let mut at = HEADER_SIZE;
    if flags & HAS_ID_LIST != 0 {
        at += 2 + usize::from(u16_at(b, at)?);
    }
    if flags & HAS_LINK_INFO == 0 {
        return None;
    }
    let info = b.get(at..)?;
    let size = u32_at(info, 0)?;
    let header = u32_at(info, 4)?;
    let info = info.get(..size)?;
    if u32_at(info, 8)? & VOLUME_ID_AND_LOCAL_BASE_PATH == 0 {
        return None;
    }
    // Newer shortcuts also carry the paths in UTF-16, after a header of 0x24 bytes or more
    let (base, suffix) = if header >= 0x24 {
        (utf16_at(info, u32_at(info, 0x1C)?)?, utf16_at(info, u32_at(info, 0x20)?).unwrap_or_default())
    } else {
        (ansi_at(info, u32_at(info, 0x10)?)?, ansi_at(info, u32_at(info, 0x18)?).unwrap_or_default())
    };
    let path = format!("{base}{suffix}");
    (!path.is_empty()).then_some(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A shortcut as Windows writes it: header, no id list, a `LinkInfo` with an ANSI local base path.
    fn shortcut(path: &str) -> Vec<u8> {
        let mut b = vec![0u8; HEADER_SIZE];
        b[0..4].copy_from_slice(&(HEADER_SIZE as u32).to_le_bytes());
        b[0x14..0x18].copy_from_slice(&(HAS_LINK_INFO as u32).to_le_bytes());
        let header = 0x1Cu32;
        let base_at = header as usize;
        let suffix_at = base_at + path.len() + 1;
        let size = suffix_at + 1;
        let mut info = vec![0u8; size];
        info[0..4].copy_from_slice(&(size as u32).to_le_bytes());
        info[4..8].copy_from_slice(&header.to_le_bytes());
        info[8..12].copy_from_slice(&(VOLUME_ID_AND_LOCAL_BASE_PATH as u32).to_le_bytes());
        info[0x10..0x14].copy_from_slice(&(base_at as u32).to_le_bytes());
        info[0x18..0x1C].copy_from_slice(&(suffix_at as u32).to_le_bytes());
        info[base_at..base_at + path.len()].copy_from_slice(path.as_bytes());
        b.extend(info);
        b
    }

    #[test]
    fn reads_the_local_path() {
        assert_eq!(target(&shortcut(r"C:\Games\Pixel Quest\PixelQuest.exe")).as_deref(), Some(r"C:\Games\Pixel Quest\PixelQuest.exe"));
    }

    #[test]
    fn junk_and_truncated_files_give_nothing() {
        let good = shortcut(r"C:\x.exe");
        for n in 0..good.len() {
            assert_eq!(target(&good[..n]), None, "cut at {n}");
        }
        assert_eq!(target(b"not a shortcut at all, but long enough to have a header of seventy six bytes......"), None);
    }
}
