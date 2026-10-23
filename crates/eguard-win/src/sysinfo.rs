//! The computer as the dashboard shows it: name, model, Windows version, battery.
#![allow(unsafe_code)]

use crate::registry::hklm_string;
use crate::wide::from_wide;
use windows_sys::Win32::System::Power::{GetSystemPowerStatus, SYSTEM_POWER_STATUS};
use windows_sys::Win32::System::SystemInformation::{ComputerNamePhysicalDnsHostname, GetComputerNameExW};

const CURRENT_VERSION: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion";
const BIOS: &str = r"HARDWARE\DESCRIPTION\System\BIOS";

/// The computer's name (`MIA-PC`).
pub fn computer_name() -> Option<String> {
    let mut buf = [0u16; 256];
    let mut len = buf.len() as u32;
    // SAFETY: `buf` is writable for `len` characters; on success `len` is the length written, without the zero.
    let ok = unsafe { GetComputerNameExW(ComputerNamePhysicalDnsHostname, buf.as_mut_ptr(), &raw mut len) } != 0;
    ok.then(|| from_wide(&buf[..len as usize])).filter(|s| !s.is_empty())
}

/// Placeholders motherboard makers leave in the BIOS; a custom-built PC has nothing better.
fn is_placeholder(s: &str) -> bool {
    let s = s.trim().to_ascii_lowercase();
    s.is_empty()
        || ["system product name", "system manufacturer", "to be filled by o.e.m.", "default string", "o.e.m.", "not applicable", "none"]
            .contains(&s.as_str())
}

/// Maker and model from the BIOS (`LENOVO 82JW`), or `Custom build` when it only has placeholders.
pub fn model() -> String {
    model_from(hklm_string(BIOS, "SystemManufacturer").as_deref(), hklm_string(BIOS, "SystemProductName").as_deref())
}

fn model_from(maker: Option<&str>, product: Option<&str>) -> String {
    let maker = maker.map(str::trim).filter(|m| !is_placeholder(m));
    let product = product.map(str::trim).filter(|p| !is_placeholder(p));
    match (maker, product) {
        (Some(m), Some(p)) if p.to_lowercase().starts_with(&m.to_lowercase()) => p.to_owned(),
        (Some(m), Some(p)) => format!("{m} {p}"),
        (None, Some(p)) => p.to_owned(),
        _ => "Custom build".to_owned(),
    }
}

/// `Windows 11 25H2 (26200)`. The registry's `ProductName` still says "Windows 10" on Windows 11, so the build
/// number decides (22000 and later is 11).
pub fn os_version() -> String {
    let build = hklm_string(CURRENT_VERSION, "CurrentBuildNumber").and_then(|b| b.parse::<u32>().ok());
    let display = hklm_string(CURRENT_VERSION, "DisplayVersion");
    os_version_from(build, display.as_deref())
}

fn os_version_from(build: Option<u32>, display: Option<&str>) -> String {
    let name = match build {
        Some(b) if b >= 22_000 => "Windows 11",
        Some(_) => "Windows 10",
        None => "Windows",
    };
    match (display, build) {
        (Some(d), Some(b)) => format!("{name} {d} ({b})"),
        (None, Some(b)) => format!("{name} ({b})"),
        _ => name.to_owned(),
    }
}

/// Battery percentage on a laptop; `None` on a desktop or when Windows doesn't know.
pub fn battery() -> Option<u8> {
    let mut s = SYSTEM_POWER_STATUS {
        ACLineStatus: 0,
        BatteryFlag: 0,
        BatteryLifePercent: 0,
        SystemStatusFlag: 0,
        BatteryLifeTime: 0,
        BatteryFullLifeTime: 0,
    };
    // SAFETY: `s` is a writable SYSTEM_POWER_STATUS.
    if unsafe { GetSystemPowerStatus(&raw mut s) } == 0 {
        return None;
    }
    // 128: no system battery; 255: unknown
    (s.BatteryFlag != 128 && s.BatteryFlag != 255 && s.BatteryLifePercent <= 100).then_some(s.BatteryLifePercent)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn this_computer_describes_itself() {
        assert!(computer_name().is_some());
        assert!(os_version().starts_with("Windows"));
        assert_ne!(model(), "");
    }

    #[test]
    fn placeholders_become_custom_build() {
        assert_eq!(model_from(Some("System manufacturer"), Some("System Product Name")), "Custom build");
        assert_eq!(model_from(Some("LENOVO"), Some("82JW")), "LENOVO 82JW");
        assert_eq!(model_from(Some("Dell Inc."), Some("Dell Inc. XPS 15")), "Dell Inc. XPS 15");
        assert_eq!(model_from(None, Some("Surface Laptop 5")), "Surface Laptop 5");
        assert_eq!(os_version_from(Some(26_200), Some("25H2")), "Windows 11 25H2 (26200)");
        assert_eq!(os_version_from(Some(19_045), Some("22H2")), "Windows 10 22H2 (19045)");
    }
}
