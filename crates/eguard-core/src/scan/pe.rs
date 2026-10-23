//! The DLLs a Windows executable imports, from its PE import table: one of the game signals (spec section 5,
//! "DirectX or Vulkan imports"). Only the normal import table is read; delay-loaded DLLs aren't a signal.

fn u16_at(b: &[u8], at: usize) -> Option<usize> {
    Some(usize::from(u16::from_le_bytes(b.get(at..at + 2)?.try_into().ok()?)))
}

fn u32_at(b: &[u8], at: usize) -> Option<usize> {
    Some(u32::from_le_bytes(b.get(at..at + 4)?.try_into().ok()?) as usize)
}

/// Most DLLs read from one import table: real ones have a few dozen.
const MAX_IMPORTS: usize = 512;

/// The imported DLL names, lower case. `None` when `b` isn't a PE file or its import table isn't inside `b`.
pub fn imports(b: &[u8]) -> Option<Vec<String>> {
    if b.get(0..2)? != b"MZ" {
        return None;
    }
    let pe = u32_at(b, 0x3C)?;
    if b.get(pe..pe + 4)? != b"PE\0\0" {
        return None;
    }
    let coff = pe + 4;
    let sections = u16_at(b, coff + 2)?;
    let optional = coff + 20;
    let optional_size = u16_at(b, coff + 16)?;
    let dirs = match u16_at(b, optional)? {
        0x10b => optional + 96,
        0x20b => optional + 112,
        _ => return None,
    };
    // Data directory 1: the import table
    let import_rva = u32_at(b, dirs + 8)?;
    if import_rva == 0 {
        return Some(Vec::new());
    }
    let table = optional + optional_size;
    let to_offset = |rva: usize| -> Option<usize> {
        (0..sections.min(96)).find_map(|i| {
            let s = table + i * 40;
            let (size, va, raw_size, raw) = (u32_at(b, s + 8)?, u32_at(b, s + 12)?, u32_at(b, s + 16)?, u32_at(b, s + 20)?);
            (rva >= va && rva < va + size.max(raw_size)).then(|| raw + (rva - va))
        })
    };
    let mut at = to_offset(import_rva)?;
    let mut out = Vec::new();
    while out.len() < MAX_IMPORTS {
        let name_rva = u32_at(b, at + 12)?;
        if name_rva == 0 {
            break;
        }
        let name_at = to_offset(name_rva)?;
        let name = b.get(name_at..)?;
        let end = name.iter().take(260).position(|&c| c == 0)?;
        out.push(String::from_utf8_lossy(&name[..end]).to_ascii_lowercase());
        at += 20;
    }
    Some(out)
}

/// DirectX (graphics and input) and Vulkan: what games link and ordinary apps rarely do.
pub fn is_graphics_import(dll: &str) -> bool {
    let d = dll.to_ascii_lowercase();
    matches!(d.as_str(), "d3d9.dll" | "d3d10.dll" | "d3d10_1.dll" | "d3d11.dll" | "d3d12.dll" | "vulkan-1.dll" | "dinput8.dll")
        || d.starts_with("d3dx9_")
        || d.starts_with("d3dx11_")
        || d.starts_with("xinput")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal PE32+ with one section holding an import table that names `dlls`.
    fn pe_with_imports(dlls: &[&str]) -> Vec<u8> {
        let mut b = vec![0u8; 0x400];
        b[0..2].copy_from_slice(b"MZ");
        let pe = 0x80usize;
        b[0x3C..0x40].copy_from_slice(&(pe as u32).to_le_bytes());
        b[pe..pe + 4].copy_from_slice(b"PE\0\0");
        let coff = pe + 4;
        b[coff + 2..coff + 4].copy_from_slice(&1u16.to_le_bytes());
        let optional_size = 240u16;
        b[coff + 16..coff + 18].copy_from_slice(&optional_size.to_le_bytes());
        let optional = coff + 20;
        b[optional..optional + 2].copy_from_slice(&0x20bu16.to_le_bytes());
        // One section: virtual 0x1000 → raw 0x200
        let section = optional + usize::from(optional_size);
        let (va, raw) = (0x1000u32, 0x200u32);
        b[section + 8..section + 12].copy_from_slice(&0x200u32.to_le_bytes());
        b[section + 12..section + 16].copy_from_slice(&va.to_le_bytes());
        b[section + 16..section + 20].copy_from_slice(&0x200u32.to_le_bytes());
        b[section + 20..section + 24].copy_from_slice(&raw.to_le_bytes());
        let dirs = optional + 112;
        b[dirs + 8..dirs + 12].copy_from_slice(&va.to_le_bytes());
        // Descriptors at the start of the section, names after them
        let mut name_at = 20 * (dlls.len() + 1);
        for (i, dll) in dlls.iter().enumerate() {
            let d = raw as usize + i * 20;
            b[d + 12..d + 16].copy_from_slice(&(va + name_at as u32).to_le_bytes());
            let n = raw as usize + name_at;
            b[n..n + dll.len()].copy_from_slice(dll.as_bytes());
            name_at += dll.len() + 1;
        }
        b
    }

    #[test]
    fn reads_the_import_table() {
        let b = pe_with_imports(&["KERNEL32.dll", "d3d11.dll", "XINPUT1_4.dll"]);
        let dlls = imports(&b).unwrap();
        assert_eq!(dlls, ["kernel32.dll", "d3d11.dll", "xinput1_4.dll"]);
        assert_eq!(dlls.iter().filter(|d| is_graphics_import(d)).count(), 2);
    }

    #[test]
    fn not_a_pe_or_cut_short_gives_nothing() {
        assert_eq!(imports(b"MZ"), None);
        assert_eq!(imports(b"hello world"), None);
        let b = pe_with_imports(&["d3d12.dll"]);
        for n in [0x40, 0x90, 0x150, 0x210] {
            assert_eq!(imports(&b[..n]), None, "cut at {n:#x}");
        }
        assert!(!is_graphics_import("user32.dll"));
    }
}
