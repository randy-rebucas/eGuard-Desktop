//! The browser policies that force eGuard's extension (spec section 9), in the registry.
//!
//! Chrome and Edge: `ExtensionInstallForcelist`, the extension's managed policy (`3rdparty\extensions\<id>\policy`,
//! which it reads as `chrome.storage.managed`), and the settings in `web::Browser::settings`. Firefox: the same
//! through its registry policies (`ExtensionSettings`, `3rdparty\Extensions\<id>`) rather than a `policies.json`:
//! Firefox reads `SOFTWARE\Policies\Mozilla\Firefox` in every copy on the computer (Program Files, a portable one,
//! the Store's), where `policies.json` covers only the install it sits in. With registry policies present Firefox
//! ignores `policies.json`.
//!
//! The real ones live under HKLM `SOFTWARE\Policies`, which only administrators and SYSTEM can write: the service
//! writes them. Console mode writes the same layout under HKCU `Software\eGuard\Dev\Policies`, which no browser
//! reads, so a developer's own browsers are never touched.

use crate::registry::{Key, Root, View};
use eguard_core::web::{self, Browser, Extension, LINK_VALUE};
use std::io;

/// Where a set of browser policies is written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Place {
    root: Root,
    path: String,
}

impl Place {
    /// The real policies: HKLM `SOFTWARE\Policies`. Only the service (SYSTEM) writes here.
    pub fn machine() -> Self {
        Self { root: Root::LocalMachine, path: r"SOFTWARE\Policies".into() }
    }

    /// Console mode's copy, which no browser reads.
    pub fn development() -> Self {
        Self::under_current_user(r"Software\eGuard\Dev\Policies")
    }

    /// Any key under this account's own hive (tests).
    pub fn under_current_user(path: &str) -> Self {
        Self { root: Root::CurrentUser, path: path.trim_matches('\\').to_owned() }
    }

    /// Where `place` is, for the log.
    pub fn describe(&self) -> String {
        let root = match self.root {
            Root::LocalMachine => "HKLM",
            Root::Users => "HKU",
            Root::CurrentUser => "HKCU",
        };
        format!(r"{root}\{}", self.path)
    }

    fn key(&self, sub: &str) -> String {
        if sub.is_empty() { self.path.clone() } else { format!(r"{}\{sub}", self.path) }
    }

    fn create(&self, sub: &str) -> io::Result<Key> {
        Key::create(self.root, &self.key(sub), View::Native)
    }

    fn open(&self, sub: &str) -> Option<Key> {
        Key::open(self.root, &self.key(sub), View::Native)
    }
}

/// The browser's policy key, under `SOFTWARE\Policies`.
fn base(b: Browser) -> &'static str {
    match b {
        Browser::Chrome => r"Google\Chrome",
        Browser::Edge => r"Microsoft\Edge",
        Browser::Firefox => r"Mozilla\Firefox",
    }
}

/// The extension's own managed policy, relative to `base`'s parent folder.
fn link_key(b: Browser, id: &str) -> String {
    match b {
        Browser::Chrome | Browser::Edge => format!(r"{}\3rdparty\extensions\{id}\policy", base(b)),
        Browser::Firefox => format!(r"{}\3rdparty\Extensions\{id}", base(b)),
    }
}

/// The key holding the extension's managed policy, which `remove` deletes whole.
fn link_root(b: Browser, id: &str) -> String {
    match b {
        Browser::Chrome | Browser::Edge => format!(r"{}\3rdparty\extensions\{id}", base(b)),
        Browser::Firefox => link_key(b, id),
    }
}

const FORCELIST: &str = "ExtensionInstallForcelist";
const FIREFOX_SETTINGS: &str = "ExtensionSettings";

/// What's in place for one browser, read back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Status {
    /// The extension is in the force-install policy as eGuard puts it.
    pub forced: bool,
    /// Every setting in `Browser::settings` has eGuard's value.
    pub settings: bool,
    /// The link in the extension's managed policy.
    pub link: Option<String>,
}

/// Reads back what's in place for `b` at `place`.
pub fn status(place: &Place, b: Browser, ext: &Extension) -> Status {
    let main = place.open(base(b));
    let forced = match b {
        Browser::Chrome | Browser::Edge => {
            let list = place.open(&format!(r"{}\{FORCELIST}", base(b))).map(|k| k.strings()).unwrap_or_default();
            !list.is_empty() && web::forcelist(&list, ext, true) == list
        }
        Browser::Firefox => web::firefox_forced(main.as_ref().and_then(|k| k.string(FIREFOX_SETTINGS)).as_deref(), ext),
    };
    let settings = b.settings().iter().all(|(name, want)| main.as_ref().and_then(|k| k.dword(name)) == Some(*want));
    let link = place.open(&link_key(b, ext.id)).and_then(|k| k.string(LINK_VALUE));
    Status { forced, settings, link }
}

/// Puts eGuard's policies for `b` in place at `place`, with `link` (or none) as the extension's link. Only what
/// differs is written. True when anything was.
pub fn apply(place: &Place, b: Browser, ext: &Extension, link: Option<&str>) -> io::Result<bool> {
    let mut changed = false;
    let main = place.create(base(b))?;
    match b {
        Browser::Chrome | Browser::Edge => {
            let list_key = place.create(&format!(r"{}\{FORCELIST}", base(b)))?;
            changed |= write_list(&list_key, &web::forcelist(&list_key.strings(), ext, true))?;
        }
        Browser::Firefox => {
            let now = main.string(FIREFOX_SETTINGS);
            if !web::firefox_forced(now.as_deref(), ext) {
                let json = web::firefox_settings(now.as_deref(), ext, true).unwrap_or_default();
                main.set_string(FIREFOX_SETTINGS, &json)?;
                changed = true;
            }
        }
    }
    for (name, want) in b.settings() {
        if main.dword(name) != Some(*want) {
            main.set_dword(name, *want)?;
            changed = true;
        }
    }
    match link {
        Some(v) => {
            let k = place.create(&link_key(b, ext.id))?;
            if k.string(LINK_VALUE).as_deref() != Some(v) {
                k.set_string(LINK_VALUE, v)?;
                changed = true;
            }
        }
        None => {
            if let Some(k) = place.open(&link_key(b, ext.id)).filter(|k| k.string(LINK_VALUE).is_some()) {
                drop(k);
                place.create(&link_key(b, ext.id))?.delete_value(LINK_VALUE)?;
                changed = true;
            }
        }
    }
    Ok(changed)
}

/// Takes eGuard's policies for `b` out of `place` (removal, spec section 10): its forcelist entry (others' stay, the
/// list kept without gaps), its Firefox entry, its managed policy, and the settings while they still have eGuard's
/// values. A key left empty is deleted.
pub fn remove(place: &Place, b: Browser, ext: &Extension) -> io::Result<()> {
    let Some(main) = place.open(base(b)).map(|_| place.create(base(b))).transpose()? else { return Ok(()) };
    match b {
        Browser::Chrome | Browser::Edge => {
            let sub = format!(r"{}\{FORCELIST}", base(b));
            if place.open(&sub).is_some() {
                let list_key = place.create(&sub)?;
                write_list(&list_key, &web::forcelist(&list_key.strings(), ext, false))?;
                if list_key.is_empty() {
                    drop(list_key);
                    main.delete_tree(FORCELIST)?;
                }
            }
        }
        Browser::Firefox => match web::firefox_settings(main.string(FIREFOX_SETTINGS).as_deref(), ext, false) {
            Some(rest) => main.set_string(FIREFOX_SETTINGS, &rest)?,
            None => main.delete_value(FIREFOX_SETTINGS)?,
        },
    }
    // A setting someone else gave the same value can't be told from eGuard's; taking it out errs toward the browser's
    // own default, which is what the computer had before eGuard
    for (name, want) in b.settings() {
        if main.dword(name) == Some(*want) {
            main.delete_value(name)?;
        }
    }
    let policies = place.create("")?;
    policies.delete_tree(&link_root(b, ext.id))?;
    for parent in [format!(r"{}\3rdparty\extensions", base(b)), format!(r"{}\3rdparty", base(b)), base(b).to_owned()] {
        if place.open(&parent).is_some_and(|k| k.is_empty()) {
            policies.delete_tree(&parent)?;
        }
    }
    Ok(())
}

/// Makes `key`'s string values match `want`: values not in it are deleted, the rest set where they differ.
fn write_list(key: &Key, want: &std::collections::BTreeMap<String, String>) -> io::Result<bool> {
    let now = key.strings();
    let mut changed = false;
    for name in now.keys().filter(|n| !want.contains_key(*n)) {
        key.delete_value(name)?;
        changed = true;
    }
    for (name, v) in want {
        if now.get(name) != Some(v) {
            key.set_string(name, v)?;
            changed = true;
        }
    }
    Ok(changed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use eguard_core::web::{CHROME_UPDATE_URL, FIREFOX_ID};

    const CHROME: Extension = Extension { id: "abcdefghijklmnopabcdefghijklmnop", url: CHROME_UPDATE_URL };
    const FIREFOX: Extension = Extension { id: FIREFOX_ID, url: "https://example.test/eguard.xpi" };

    /// A throwaway place under this account's hive, deleted at the end.
    struct Scratch(Place);

    impl Scratch {
        fn new(name: &str) -> Self {
            Self(Place::under_current_user(&format!(r"Software\eGuard\Test\{name}-{}", std::process::id())))
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            if let Ok(k) = Key::create(Root::CurrentUser, r"Software\eGuard\Test", View::Native) {
                let leaf = self.0.path.rsplit('\\').next().unwrap_or_default().to_owned();
                let _ = k.delete_tree(&leaf);
                // The last test out takes the folder they share
                if k.is_empty() {
                    drop(k);
                    let _ = Key::create(Root::CurrentUser, r"Software\eGuard", View::Native).and_then(|e| e.delete_tree("Test"));
                }
            }
        }
    }

    #[test]
    fn chrome_policies_go_in_beside_a_schools_and_come_out_without_them() {
        let s = Scratch::new("chrome");
        let p = &s.0;
        // A school's forced extension, already there
        let list = p.create(r"Google\Chrome\ExtensionInstallForcelist").unwrap();
        list.set_string("1", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa;https://school.example/crx").unwrap();
        drop(list);

        assert!(apply(p, Browser::Chrome, &CHROME, Some("dev.1795000000000.sig")).unwrap());
        let st = status(p, Browser::Chrome, &CHROME);
        assert_eq!(st, Status { forced: true, settings: true, link: Some("dev.1795000000000.sig".into()) });
        let strings = p.open(r"Google\Chrome\ExtensionInstallForcelist").unwrap().strings();
        assert_eq!(strings.len(), 2);
        assert_eq!(strings["2"], format!("{};{CHROME_UPDATE_URL}", CHROME.id));
        assert_eq!(p.open(r"Google\Chrome").unwrap().dword("IncognitoModeAvailability"), Some(1));
        // Nothing to do the second time
        assert!(!apply(p, Browser::Chrome, &CHROME, Some("dev.1795000000000.sig")).unwrap());
        // No link (a removal waits): the value goes, the forcing stays
        assert!(apply(p, Browser::Chrome, &CHROME, None).unwrap());
        assert_eq!(status(p, Browser::Chrome, &CHROME).link, None);
        assert!(status(p, Browser::Chrome, &CHROME).forced);

        // Someone deleted a setting and our entry: put back
        p.create(r"Google\Chrome").unwrap().delete_value("BrowserGuestModeEnabled").unwrap();
        p.create(r"Google\Chrome\ExtensionInstallForcelist").unwrap().delete_value("2").unwrap();
        assert!(!status(p, Browser::Chrome, &CHROME).forced);
        assert!(apply(p, Browser::Chrome, &CHROME, None).unwrap());
        assert!(status(p, Browser::Chrome, &CHROME).forced && status(p, Browser::Chrome, &CHROME).settings);

        remove(p, Browser::Chrome, &CHROME).unwrap();
        let strings = p.open(r"Google\Chrome\ExtensionInstallForcelist").unwrap().strings();
        assert_eq!(
            strings.into_iter().collect::<Vec<_>>(),
            [("1".to_owned(), "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa;https://school.example/crx".to_owned())]
        );
        assert!(p.open(r"Google\Chrome").unwrap().dword("IncognitoModeAvailability").is_none());
        assert!(p.open(r"Google\Chrome\3rdparty").is_none());
    }

    #[test]
    fn edge_and_firefox_come_out_completely() {
        let s = Scratch::new("all");
        let p = &s.0;
        let edge = Extension { id: "ponmlkjihgfedcbaponmlkjihgfedcba", url: web::EDGE_UPDATE_URL };
        apply(p, Browser::Edge, &edge, Some("x.1.y")).unwrap();
        apply(p, Browser::Firefox, &FIREFOX, Some("x.1.y")).unwrap();
        assert_eq!(status(p, Browser::Edge, &edge), Status { forced: true, settings: true, link: Some("x.1.y".into()) });
        assert_eq!(status(p, Browser::Firefox, &FIREFOX), Status { forced: true, settings: true, link: Some("x.1.y".into()) });
        assert_eq!(p.open(r"Microsoft\Edge").unwrap().dword("InPrivateModeAvailability"), Some(1));
        assert!(p.open(&format!(r"Mozilla\Firefox\3rdparty\Extensions\{FIREFOX_ID}")).is_some());

        remove(p, Browser::Edge, &edge).unwrap();
        remove(p, Browser::Firefox, &FIREFOX).unwrap();
        assert!(p.open(r"Microsoft\Edge").is_none() && p.open(r"Mozilla\Firefox").is_none());
        // Removing what isn't there is fine
        remove(p, Browser::Firefox, &FIREFOX).unwrap();
    }
}
