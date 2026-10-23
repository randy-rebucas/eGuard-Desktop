//! UTF-16 strings for Win32's `W` functions.

/// `s` as UTF-16 with the terminating zero.
pub(crate) fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// A UTF-16 buffer up to its first zero (or its end), lossy.
pub(crate) fn from_wide(buf: &[u16]) -> String {
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        assert_eq!(wide("ab"), vec![97, 98, 0]);
        assert_eq!(from_wide(&wide("Mia's PC")), "Mia's PC");
        assert_eq!(from_wide(&[104, 105]), "hi");
    }
}
