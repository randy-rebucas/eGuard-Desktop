//! Web filtering on a computer (spec section 9), without the platform: which extension each browser is told to
//! install, the settings that keep it running everywhere in that browser, the computer's link, and how eGuard's
//! entries go into policies that someone else (a school, an employer) may also set.
//!
//! The filter itself is eGuard's browser extension. Its store ids are fixed at build time: Chrome and Edge assign
//! theirs when it's first published, Firefox's is the id in its manifest. A browser whose id this build lacks isn't
//! set up, and the report says so; a release build refuses to compile without all three (unless
//! `EGUARD_DEV_RELEASE`, as in `keys`).
//!
//! Besides forcing the extension, each browser's private windows (and Chrome's and Edge's Guest mode, where
//! extensions don't run) must not be a way around it: Chrome and Edge have no policy that lets an extension into
//! Incognito/InPrivate, so those are turned off; Firefox's lets eGuard's extension run in private windows, and its
//! Troubleshoot Mode (which starts without extensions) is turned off.

use crate::wire::BrowserLink;
use std::collections::BTreeMap;

/// The extension's id on Firefox (`browser_specific_settings.gecko.id` in its manifest).
pub const FIREFOX_ID: &str = "browser-extension@eguard.family";
/// Where Chrome fetches Web Store extensions from.
pub const CHROME_UPDATE_URL: &str = "https://clients2.google.com/service/update2/crx";
/// Where Edge fetches Edge Add-ons extensions from.
pub const EDGE_UPDATE_URL: &str = "https://edge.microsoft.com/extensionwebstorebase/v1/crx";
/// The managed-policy value the extension reads the link from (`chrome.storage.managed`, browser-extension-api.md).
pub const LINK_VALUE: &str = "deviceLink";

// A release that set up no extension would report web filtering as not applied forever, on every computer
#[cfg(not(debug_assertions))]
const _: () = assert!(
    (option_env!("EGUARD_CHROME_EXTENSION_ID").is_some()
        && option_env!("EGUARD_EDGE_EXTENSION_ID").is_some()
        && option_env!("EGUARD_FIREFOX_EXTENSION_URL").is_some())
        || option_env!("EGUARD_DEV_RELEASE").is_some(),
    "a release build needs EGUARD_CHROME_EXTENSION_ID, EGUARD_EDGE_EXTENSION_ID and EGUARD_FIREFOX_EXTENSION_URL; set EGUARD_DEV_RELEASE=1 for a local build"
);

/// A browser eGuard's extension runs in. Every other browser is category `BROWSERS` (`scan`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Browser {
    Chrome,
    Edge,
    Firefox,
}

impl Browser {
    pub const ALL: [Browser; 3] = [Browser::Chrome, Browser::Edge, Browser::Firefox];

    pub fn name(self) -> &'static str {
        match self {
            Browser::Chrome => "Chrome",
            Browser::Edge => "Edge",
            Browser::Firefox => "Firefox",
        }
    }

    /// Policies (name, number) besides the extension's: no private or guest windows it can't run in.
    pub fn settings(self) -> &'static [(&'static str, u32)] {
        match self {
            // 1: Incognito mode disabled. 0: Guest mode off
            Browser::Chrome => &[("IncognitoModeAvailability", 1), ("BrowserGuestModeEnabled", 0)],
            Browser::Edge => &[("InPrivateModeAvailability", 1), ("BrowserGuestModeEnabled", 0)],
            Browser::Firefox => &[("DisableSafeMode", 1)],
        }
    }
}

/// eGuard's extension in one browser's store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Extension {
    pub id: &'static str,
    /// Chrome and Edge: their store's update URL. Firefox: the `.xpi` to install from.
    pub url: &'static str,
}

/// A Chrome or Edge extension id: 32 letters `a` to `p`.
pub const fn is_chromium_id(id: &str) -> bool {
    let b = id.as_bytes();
    if b.len() != 32 {
        return false;
    }
    let mut i = 0;
    while i < b.len() {
        if b[i] < b'a' || b[i] > b'p' {
            return false;
        }
        i += 1;
    }
    true
}

const fn chromium(id: Option<&'static str>, url: &'static str) -> Option<Extension> {
    match id {
        Some(id) if is_chromium_id(id) => Some(Extension { id, url }),
        _ => None,
    }
}

const CHROME: Option<Extension> = chromium(option_env!("EGUARD_CHROME_EXTENSION_ID"), CHROME_UPDATE_URL);
const EDGE: Option<Extension> = chromium(option_env!("EGUARD_EDGE_EXTENSION_ID"), EDGE_UPDATE_URL);
const FIREFOX: Option<Extension> = match option_env!("EGUARD_FIREFOX_EXTENSION_URL") {
    Some(url) => Some(Extension { id: FIREFOX_ID, url }),
    None => None,
};

// An id given but malformed would otherwise be dropped without a word
#[cfg(not(debug_assertions))]
const _: () = assert!(
    option_env!("EGUARD_DEV_RELEASE").is_some() || (CHROME.is_some() && EDGE.is_some()),
    "EGUARD_CHROME_EXTENSION_ID and EGUARD_EDGE_EXTENSION_ID must be 32 letters a to p"
);

/// eGuard's extension for `b` in this build, or `None` when the build has no id for it.
pub const fn extension(b: Browser) -> Option<Extension> {
    match b {
        Browser::Chrome => CHROME,
        Browser::Edge => EDGE,
        Browser::Firefox => FIREFOX,
    }
}

/// The link to write into the extension's managed policy, when `/sync` sent a well-formed one. The server's is
/// `<device id>.<expiry ms>.<mac>` in URL-safe characters; anything else (or none, while a removal waits) means no
/// link, so a browser can't join a computer that's being removed.
pub fn link_value(link: Option<&BrowserLink>) -> Option<&str> {
    let v = link?.value.as_str();
    let ok = (1..=200).contains(&v.len()) && v.bytes().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'-' | b'_'));
    ok.then_some(v)
}

/// How long a written link stays before a newer one replaces it. Every `/sync` (each minute) brings a fresh link
/// that lasts 30 days; writing each one would change every browser's policies every minute.
pub const LINK_KEEP_MS: i64 = 24 * 60 * 60 * 1000;

/// Which link goes into the browsers' policies: the one written last, until it's `LINK_KEEP_MS` old, or until
/// `/sync` sends none (a removal waits) or the computer is paired again (`forget`).
#[derive(Debug, Clone, Default)]
pub struct LinkKeeper {
    /// The value written, and when (eGuard's clock).
    kept: Option<(String, i64)>,
}

impl LinkKeeper {
    /// The link to write now, given the newest from `/sync`.
    pub fn choose(&mut self, fresh: Option<&BrowserLink>, now_ms: i64) -> Option<String> {
        let Some(fresh) = link_value(fresh) else {
            self.kept = None;
            return None;
        };
        match &self.kept {
            // A clock moved back counts as old: the link is replaced rather than kept forever
            Some((v, at)) if (0..LINK_KEEP_MS).contains(&(now_ms - at)) => Some(v.clone()),
            _ => {
                self.kept = Some((fresh.to_owned(), now_ms));
                Some(fresh.to_owned())
            }
        }
    }

    /// The computer was paired again: the next link is the new pairing's.
    pub fn forget(&mut self) {
        self.kept = None;
    }
}

/// The extension id at the start of a forcelist entry (`<id>;<update url>`, or the id alone), lower case.
fn entry_id(value: &str) -> String {
    value.split(';').next().unwrap_or_default().trim().to_ascii_lowercase()
}

/// A Chromium list policy (`ExtensionInstallForcelist`) after eGuard's entry is put in (`want`) or taken out
/// (`None`), from what's there now: value name → value.
///
/// Chrome and Edge read such a list as the values named `1`, `2`, … and stop at the first missing number. So the
/// others' entries stay as they are when they can, eGuard's goes in the first free number, and when a number is
/// missing (eGuard's entry taken out, or it was so already) the entries after it are moved down so none is lost.
/// Values not named by a number aren't part of the list and are left alone. Any second entry for eGuard's id is
/// dropped.
pub fn forcelist(existing: &BTreeMap<String, String>, ext: &Extension, want: bool) -> BTreeMap<String, String> {
    let id = ext.id.to_ascii_lowercase();
    let entry = format!("{};{}", ext.id, ext.url);
    let mut numbered: Vec<(u32, &String)> =
        existing.iter().filter_map(|(k, v)| Some((k.parse::<u32>().ok().filter(|n| *n > 0)?, v))).collect();
    numbered.sort_by_key(|(n, _)| *n);
    let mut out: BTreeMap<String, String> =
        existing.iter().filter(|(k, _)| k.parse::<u32>().ok().is_none_or(|n| n == 0)).map(|(k, v)| (k.clone(), v.clone())).collect();

    let mut ours_kept = false;
    let mut list: Vec<(u32, String)> = Vec::new();
    for (n, v) in numbered {
        if entry_id(v) == id {
            if want && !ours_kept {
                list.push((n, entry.clone()));
                ours_kept = true;
            }
        } else {
            list.push((n, v.clone()));
        }
    }
    let contiguous = list.iter().enumerate().all(|(i, (n, _))| *n as usize == i + 1);
    if !contiguous {
        list = list.into_iter().enumerate().map(|(i, (_, v))| ((i + 1) as u32, v)).collect();
    }
    if want && !ours_kept {
        list.push(((list.len() + 1) as u32, entry));
    }
    out.extend(list.into_iter().map(|(n, v)| (n.to_string(), v)));
    out
}

/// Firefox's `ExtensionSettings` policy (JSON) with eGuard's extension forced (`want`) or taken out, keeping every
/// other entry. `None`: nothing is left, so the policy goes. A value that isn't a JSON object can't have been doing
/// anything (Firefox ignores it), so it's replaced.
pub fn firefox_settings(existing: Option<&str>, ext: &Extension, want: bool) -> Option<String> {
    let mut map = existing
        .and_then(|s| serde_json::from_str::<serde_json::Value>(s).ok())
        .and_then(|v| match v {
            serde_json::Value::Object(m) => Some(m),
            _ => None,
        })
        .unwrap_or_default();
    if want {
        map.insert(
            ext.id.to_owned(),
            serde_json::json!({ "installation_mode": "force_installed", "install_url": ext.url, "private_browsing": true }),
        );
    } else {
        map.remove(ext.id);
    }
    (!map.is_empty()).then(|| serde_json::Value::Object(map).to_string())
}

/// True when Firefox's `ExtensionSettings` (`existing`) already forces eGuard's extension as `firefox_settings` would.
pub fn firefox_forced(existing: Option<&str>, ext: &Extension) -> bool {
    let parsed = existing.and_then(|s| serde_json::from_str::<serde_json::Value>(s).ok());
    let wanted = firefox_settings(existing, ext, true).and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok());
    parsed.is_some() && parsed == wanted
}

/// What `/report` says about web filtering (spec section 11: its config once the extension is forced in every
/// browser), from whether this computer blocks the other browsers (`enforcing`) and how setting up each went.
pub fn capability(enforcing: bool, setup: &BTreeMap<Browser, Result<(), String>>) -> Result<(), String> {
    if !enforcing {
        return Err("eGuard runs in development mode on this computer, so it doesn't change browser settings.".into());
    }
    let missing: Vec<&str> = Browser::ALL.iter().filter(|b| !matches!(setup.get(b), Some(Ok(())))).map(|b| b.name()).collect();
    match missing.as_slice() {
        [] => Ok(()),
        [one] => Err(format!("eGuard's extension isn't set up in {one} on this computer yet.")),
        many => Err(format!("eGuard's extension isn't set up in {} on this computer yet.", join_names(many))),
    }
}

fn join_names(names: &[&str]) -> String {
    match names {
        [] => String::new(),
        [one] => (*one).to_owned(),
        [rest @ .., last] => format!("{} and {last}", rest.join(", ")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXT: Extension = Extension { id: "abcdefghijklmnopabcdefghijklmnop", url: CHROME_UPDATE_URL };
    const OURS: &str = "abcdefghijklmnopabcdefghijklmnop;https://clients2.google.com/service/update2/crx";

    fn map(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs.iter().map(|(k, v)| ((*k).to_owned(), (*v).to_owned())).collect()
    }

    #[test]
    fn chromium_ids() {
        assert!(is_chromium_id("abcdefghijklmnopabcdefghijklmnop"));
        assert!(!is_chromium_id("abcdefghijklmnopabcdefghijklmnoq"));
        assert!(!is_chromium_id("ABCDEFGHIJKLMNOPABCDEFGHIJKLMNOP"));
        assert!(!is_chromium_id("abc"));
    }

    #[test]
    fn our_entry_goes_in_the_first_free_number_and_others_stay() {
        assert_eq!(forcelist(&BTreeMap::new(), &EXT, true), map(&[("1", OURS)]));
        let school = map(&[("1", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), ("2", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb;https://x")]);
        let with = forcelist(&school, &EXT, true);
        assert_eq!(
            with,
            map(&[("1", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), ("2", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb;https://x"), ("3", OURS)])
        );
        // Already there: nothing changes
        assert_eq!(forcelist(&with, &EXT, true), with);
        // Taken out: the school's entries stay
        assert_eq!(forcelist(&with, &EXT, false), school);
    }

    #[test]
    fn a_missing_number_never_hides_the_entries_after_it() {
        // eGuard's entry in the middle, taken out: the one after it moves down
        let list = map(&[("1", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), ("2", OURS), ("3", "cccccccccccccccccccccccccccccccc")]);
        assert_eq!(
            forcelist(&list, &EXT, false),
            map(&[("1", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), ("2", "cccccccccccccccccccccccccccccccc")])
        );
        // A gap someone else left, and our entry twice (one with an old URL, in capitals): one of ours, no gap
        let messy = map(&[
            ("2", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            ("5", "ABCDEFGHIJKLMNOPABCDEFGHIJKLMNOP;https://old"),
            ("7", OURS),
            ("note", "x"),
        ]);
        assert_eq!(forcelist(&messy, &EXT, true), map(&[("1", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), ("2", OURS), ("note", "x")]));
    }

    #[test]
    fn firefox_keeps_other_extensions() {
        let ff = Extension { id: FIREFOX_ID, url: "https://example.test/eguard.xpi" };
        let set = firefox_settings(None, &ff, true).unwrap();
        assert!(firefox_forced(Some(&set), &ff));
        let v: serde_json::Value = serde_json::from_str(&set).unwrap();
        assert_eq!(v[FIREFOX_ID]["installation_mode"], "force_installed");
        assert_eq!(v[FIREFOX_ID]["private_browsing"], true);

        let school = r#"{"*":{"installation_mode":"blocked"},"ublock0@raymondhill.net":{"installation_mode":"force_installed"}}"#;
        assert!(!firefox_forced(Some(school), &ff));
        let both = firefox_settings(Some(school), &ff, true).unwrap();
        let v: serde_json::Value = serde_json::from_str(&both).unwrap();
        assert_eq!(v["*"]["installation_mode"], "blocked");
        assert_eq!(v[FIREFOX_ID]["install_url"], "https://example.test/eguard.xpi");
        // Taken out: the school's stay; nothing left: no policy
        let back: serde_json::Value = serde_json::from_str(&firefox_settings(Some(&both), &ff, false).unwrap()).unwrap();
        assert_eq!(back, serde_json::from_str::<serde_json::Value>(school).unwrap());
        assert_eq!(firefox_settings(Some(&set), &ff, false), None);
        // Not an object: replaced
        assert!(firefox_forced(firefox_settings(Some("[1,2]"), &ff, true).as_deref(), &ff));
    }

    #[test]
    fn a_written_link_is_kept_for_a_day() {
        let link = |v: &str| BrowserLink { value: v.into(), expires_at: "2026-11-22T00:00:00.000Z".into() };
        let mut k = LinkKeeper::default();
        assert_eq!(k.choose(Some(&link("dev.1.a")), 1_000).as_deref(), Some("dev.1.a"));
        // The next sync's fresh link isn't written
        assert_eq!(k.choose(Some(&link("dev.2.b")), 61_000).as_deref(), Some("dev.1.a"));
        // A day later it is
        assert_eq!(k.choose(Some(&link("dev.3.c")), 1_000 + LINK_KEEP_MS).as_deref(), Some("dev.3.c"));
        // A clock moved back: replaced
        assert_eq!(k.choose(Some(&link("dev.4.d")), 0).as_deref(), Some("dev.4.d"));
        // None (a removal waits): none, and the next one is written at once
        assert_eq!(k.choose(None, 2_000), None);
        assert_eq!(k.choose(Some(&link("dev.5.e")), 3_000).as_deref(), Some("dev.5.e"));
        k.forget();
        assert_eq!(k.choose(Some(&link("new.6.f")), 4_000).as_deref(), Some("new.6.f"));
        // A malformed one counts as none
        assert_eq!(k.choose(Some(&link("bad link")), 5_000), None);
    }

    #[test]
    fn only_a_well_formed_link_is_written() {
        let link = |v: &str| BrowserLink { value: v.into(), expires_at: "2026-11-22T00:00:00.000Z".into() };
        let good = link("cmh1x2y3z.1795000000000.AbC-dEf_0123456789abcdefghijklmnopqrstuvwxy");
        assert_eq!(link_value(Some(&good)), Some(good.value.as_str()));
        assert_eq!(link_value(None), None);
        assert_eq!(link_value(Some(&link(""))), None);
        assert_eq!(link_value(Some(&link("a\"b"))), None);
        assert_eq!(link_value(Some(&link(&"a".repeat(201)))), None);
    }

    #[test]
    fn web_is_reported_once_every_browser_is_set_up() {
        let all: BTreeMap<Browser, Result<(), String>> = Browser::ALL.iter().map(|b| (*b, Ok(()))).collect();
        assert_eq!(capability(true, &all), Ok(()));
        assert!(capability(false, &all).unwrap_err().contains("development mode"));
        let mut some = all.clone();
        some.insert(Browser::Edge, Err("access denied".into()));
        some.remove(&Browser::Firefox);
        assert_eq!(capability(true, &some), Err("eGuard's extension isn't set up in Edge and Firefox on this computer yet.".into()));
        assert_eq!(join_names(&["Chrome", "Edge", "Firefox"]), "Chrome, Edge and Firefox");
    }
}
