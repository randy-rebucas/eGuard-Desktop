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
//! Troubleshoot Mode (which starts without extensions) is turned off. Only while web filtering is on
//! (`settings_step`): with it off they get around nothing, so they're left to the browser.
//!
//! Another extension (a proxy, a VPN, a page viewer) gets around eGuard's too: an extension's own requests are out of
//! every other extension's reach. So, at the same times, new extensions are blocked in all three browsers, while
//! those already installed when the block goes in stay allowed (`ExtensionBlock`), so the family's password manager
//! keeps working. A parent who wants another one turns web filtering off for a moment: the block comes out, and the
//! next time it goes in it keeps whatever is installed by then.

use crate::wire::BrowserLink;
use std::collections::{BTreeMap, BTreeSet};

/// The extension's id on Firefox (`browser_specific_settings.gecko.id` in its manifest).
pub const FIREFOX_ID: &str = "browser-extension@eguard.family";
/// Where Chrome fetches Web Store extensions from.
pub const CHROME_UPDATE_URL: &str = "https://clients2.google.com/service/update2/crx";
/// Where Edge fetches Edge Add-ons extensions from.
pub const EDGE_UPDATE_URL: &str = "https://edge.microsoft.com/extensionwebstorebase/v1/crx";
/// The managed-policy value the extension reads the link from (`chrome.storage.managed`, browser-extension-api.md).
pub const LINK_VALUE: &str = "deviceLink";
/// The managed-policy value that tells the extension private windows are off by policy (Chrome and Edge, where eGuard
/// turns `Incognito` and `InPrivate` off), so it doesn't ask for "Allow in Incognito", which can't matter there. Only an
/// administrator or SYSTEM can write managed policy, so the extension can trust it. Present exactly while eGuard's
/// settings are (`SettingsStep`).
pub const PRIVATE_WINDOWS_VALUE: &str = "privateWindows";
/// `PRIVATE_WINDOWS_VALUE`'s value.
pub const PRIVATE_WINDOWS_OFF: &str = "off";

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
            // IE mode: tabs reloaded in Internet Explorer mode run no extensions (0: no IE integration, reloading off)
            Browser::Edge => &[
                ("InPrivateModeAvailability", 1),
                ("BrowserGuestModeEnabled", 0),
                ("InternetExplorerIntegrationLevel", 0),
                ("InternetExplorerIntegrationReloadInIEModeAllowed", 0),
            ],
            Browser::Firefox => &[("DisableSafeMode", 1)],
        }
    }
}

/// What to do this time with a browser's `Browser::settings` (and, in Chrome and Edge, the extension's
/// `PRIVATE_WINDOWS_VALUE`, which says they're in force).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettingsStep {
    /// Make them eGuard's values.
    Put,
    /// Take out the ones that still have eGuard's values, as removal does.
    TakeOut,
    /// Leave them as they are.
    Leave,
}

/// `SettingsStep` from whether web filtering is on (`Policy::web_filter`: any mode but off) and whether eGuard's
/// settings were taken out already since this browser's last `Put` (or since the service started).
///
/// With web filtering off nothing is filtered, so a private or guest window (or an IE-mode tab, or Firefox's
/// Troubleshoot Mode) gets around nothing: those settings come out, while the extension stays forced and linked so
/// turning filtering back on takes effect at once. They come out once rather than every minute: a school's policy
/// with the same value can't be told from eGuard's, and mustn't be deleted again each time it's put back.
pub fn settings_step(filtering: bool, taken_out: bool) -> SettingsStep {
    match (filtering, taken_out) {
        (true, _) => SettingsStep::Put,
        (false, false) => SettingsStep::TakeOut,
        (false, true) => SettingsStep::Leave,
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
    let entries = if want { vec![format!("{};{}", ext.id, ext.url)] } else { Vec::new() };
    numbered_list(existing, |e| e == id, &entries)
}

/// A Chromium list policy (value name → value) with eGuard's entries made `want`, the way `forcelist` describes: an
/// entry whose id (`entry_id`) `is_ours` is eGuard's, and stays at its number when `want` still has its id (as
/// `want` has it), or goes; every other entry stays; the rest of `want` goes after, in order; no number is missing.
fn numbered_list(existing: &BTreeMap<String, String>, is_ours: impl Fn(&str) -> bool, want: &[String]) -> BTreeMap<String, String> {
    let mut numbered: Vec<(u32, &String)> =
        existing.iter().filter_map(|(k, v)| Some((k.parse::<u32>().ok().filter(|n| *n > 0)?, v))).collect();
    numbered.sort_by_key(|(n, _)| *n);
    let mut out: BTreeMap<String, String> =
        existing.iter().filter(|(k, _)| k.parse::<u32>().ok().is_none_or(|n| n == 0)).map(|(k, v)| (k.clone(), v.clone())).collect();

    let mut placed = vec![false; want.len()];
    let mut list: Vec<(u32, String)> = Vec::new();
    for (n, v) in numbered {
        let id = entry_id(v);
        if is_ours(&id) {
            if let Some(i) = (0..want.len()).find(|i| !placed[*i] && entry_id(&want[*i]) == id) {
                list.push((n, want[i].clone()));
                placed[i] = true;
            }
        } else {
            list.push((n, v.clone()));
        }
    }
    let contiguous = list.iter().enumerate().all(|(i, (n, _))| *n as usize == i + 1);
    if !contiguous {
        list = list.into_iter().enumerate().map(|(i, (_, v))| ((i + 1) as u32, v)).collect();
    }
    for (i, w) in want.iter().enumerate() {
        if !placed[i] {
            list.push(((list.len() + 1) as u32, w.clone()));
        }
    }
    out.extend(list.into_iter().map(|(n, v)| (n.to_string(), v)));
    out
}

/// The entry in `ExtensionInstallBlocklist` (Chromium) and the key in `ExtensionSettings` (Firefox) that stands for
/// every extension.
pub const EVERY_EXTENSION: &str = "*";
/// Most installed extensions kept allowed in one browser while new ones are blocked: a profile the child can write
/// to mustn't make eGuard write a policy without end.
pub const MAX_KEPT_EXTENSIONS: usize = 200;

/// An id a browser's extensions can have: Chrome's and Edge's 32 letters, or a Firefox add-on id (`name@domain` or
/// `{guid}`; anything printable of a sane length, since it's only ever a JSON key).
pub fn is_extension_id(b: Browser, id: &str) -> bool {
    match b {
        Browser::Chrome | Browser::Edge => is_chromium_id(id),
        Browser::Firefox => (1..=128).contains(&id.len()) && !id.chars().any(|c| c.is_control() || c.is_whitespace()),
    }
}

/// The extensions to keep allowed in `b` while new ones are blocked, from the ids found installed on the computer:
/// well formed, each once, eGuard's own left out (it's allowed anyway), at most `MAX_KEPT_EXTENSIONS`, sorted.
pub fn kept_extensions(b: Browser, ext: &Extension, found: impl IntoIterator<Item = String>) -> Vec<String> {
    let set: BTreeSet<String> = found.into_iter().filter(|id| is_extension_id(b, id) && !id.eq_ignore_ascii_case(ext.id)).collect();
    set.into_iter().take(MAX_KEPT_EXTENSIONS).collect()
}

/// The add-ons a Firefox profile's `extensions.json` lists as installed by its user (`location` `app-profile`):
/// not Firefox's own built-in ones or system add-ons, which its policies don't block anyway.
pub fn firefox_profile_addons(json: &str) -> Vec<String> {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(json) else { return Vec::new() };
    let Some(addons) = v.get("addons").and_then(|a| a.as_array()) else { return Vec::new() };
    addons
        .iter()
        .filter(|a| a.get("location").and_then(|l| l.as_str()) == Some("app-profile"))
        .filter_map(|a| a.get("id")?.as_str())
        .filter(|id| is_extension_id(Browser::Firefox, id))
        .take(MAX_KEPT_EXTENSIONS * 4)
        .map(str::to_owned)
        .collect()
}

/// What eGuard remembers about blocking new extensions in one browser, while it's in place: the installed ones it
/// keeps allowed (found when the block went in, so one installed since, or a folder made to look like one, never
/// joins them), and the entries it added to the browser's policies (`EVERY_EXTENSION` and ids), which are all it takes
/// out again: an entry that was there before (a school's) isn't eGuard's.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ExtensionBlock {
    pub kept: Vec<String>,
    pub added: BTreeSet<String>,
}

impl ExtensionBlock {
    /// A remembered block for `b`, with anything that isn't an id (or `EVERY_EXTENSION`) dropped. `None`: not JSON.
    pub fn parse(b: Browser, s: &str) -> Option<Self> {
        let raw: Self = serde_json::from_str(s).ok()?;
        let ok = |id: &String| is_extension_id(b, id);
        Some(Self {
            kept: raw.kept.into_iter().filter(ok).take(MAX_KEPT_EXTENSIONS).collect(),
            added: raw.added.into_iter().filter(|id| id == EVERY_EXTENSION || ok(id)).take(MAX_KEPT_EXTENSIONS + 2).collect(),
        })
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }
}

/// A Chromium list policy (`ExtensionInstallAllowlist`, `ExtensionInstallBlocklist`) with eGuard's entries made
/// `want` (ids, or `EVERY_EXTENSION`), given those eGuard added before (`ours`), and the ones it has added now. An
/// entry of `want` someone else's list already has is theirs and isn't added again; numbering as in `forcelist`.
/// `want` empty takes eGuard's entries out.
pub fn chromium_list(
    existing: &BTreeMap<String, String>,
    ours: &BTreeSet<String>,
    want: &[String],
) -> (BTreeMap<String, String>, BTreeSet<String>) {
    let theirs: BTreeSet<String> = existing
        .iter()
        .filter(|(k, _)| k.parse::<u32>().is_ok_and(|n| n > 0))
        .map(|(_, v)| entry_id(v))
        .filter(|id| !ours.contains(id))
        .collect();
    let mut added = BTreeSet::new();
    let entries: Vec<String> = want.iter().map(|w| entry_id(w)).filter(|id| !theirs.contains(id) && added.insert(id.clone())).collect();
    (numbered_list(existing, |id| ours.contains(id), &entries), added)
}

/// Firefox's `ExtensionSettings` (JSON) with eGuard's block made `want`: `EVERY_EXTENSION` blocked and each other id
/// allowed. Like `chromium_list`: `ours` are the keys eGuard added before; a key someone else set (a school's `*`,
/// or its own rule for an add-on) is left as it is; every other entry (eGuard's forced extension too) stays. Returns
/// the policy (`None`: nothing left) and the keys eGuard has added now.
pub fn firefox_block(existing: Option<&str>, ours: &BTreeSet<String>, want: &[String]) -> (Option<String>, BTreeSet<String>) {
    let mut map = existing
        .and_then(|s| serde_json::from_str::<serde_json::Value>(s).ok())
        .and_then(|v| match v {
            serde_json::Value::Object(m) => Some(m),
            _ => None,
        })
        .unwrap_or_default();
    for key in ours.iter().filter(|k| !want.contains(*k)) {
        map.remove(key);
    }
    let mut added = BTreeSet::new();
    for key in want {
        if map.contains_key(key) && !ours.contains(key) {
            continue;
        }
        let mode = if key == EVERY_EXTENSION { "blocked" } else { "allowed" };
        map.insert(key.clone(), serde_json::json!({ "installation_mode": mode }));
        added.insert(key.clone());
    }
    ((!map.is_empty()).then(|| serde_json::Value::Object(map).to_string()), added)
}

/// True when two `ExtensionSettings` values are the same JSON (or both absent), however they're written.
pub fn same_json(a: Option<&str>, b: Option<&str>) -> bool {
    let parse = |s: Option<&str>| s.map(|s| serde_json::from_str::<serde_json::Value>(s).ok());
    parse(a) == parse(b)
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

    fn ids(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_owned()).collect()
    }

    const A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const C: &str = "cccccccccccccccccccccccccccccccc";

    #[test]
    fn only_well_formed_extension_ids_are_kept_and_not_too_many() {
        assert!(is_extension_id(Browser::Firefox, "ublock0@raymondhill.net"));
        assert!(is_extension_id(Browser::Firefox, "{446900e4-71c2-419f-a6a7-df9c091e268b}"));
        assert!(!is_extension_id(Browser::Firefox, ""));
        assert!(!is_extension_id(Browser::Firefox, "a b"));
        assert!(!is_extension_id(Browser::Firefox, "a\u{7}b"));
        assert!(!is_extension_id(Browser::Firefox, &"a".repeat(129)));
        assert!(!is_extension_id(Browser::Edge, "Temp"));

        // eGuard's own, the folder `Temp`, a duplicate and a capitalised id are left out; sorted
        let found = ids(&[C, "Temp", A, EXT.id, A, "ABCDEFGHIJKLMNOPABCDEFGHIJKLMNOP"]);
        assert_eq!(kept_extensions(Browser::Chrome, &EXT, found), ids(&[A, C]));
        let many = (0..1000).map(|i| format!("addon{i}@example.com"));
        let ff = Extension { id: FIREFOX_ID, url: "https://example.test/eguard.xpi" };
        assert_eq!(kept_extensions(Browser::Firefox, &ff, many).len(), MAX_KEPT_EXTENSIONS);
    }

    #[test]
    fn firefox_profile_addons_are_the_ones_its_user_installed() {
        let json = r#"{"schemaVersion":36,"addons":[
            {"id":"ublock0@raymondhill.net","location":"app-profile","type":"extension"},
            {"id":"formautofill@mozilla.org","location":"app-builtin"},
            {"id":"default-theme@mozilla.org","location":"app-builtin","type":"theme"},
            {"id":"bad id","location":"app-profile"},
            {"location":"app-profile"},
            {"id":"{e4a8a97b-f2ed-450b-b12d-ee082ba24781}","location":"app-profile"}
        ]}"#;
        assert_eq!(firefox_profile_addons(json), ids(&["ublock0@raymondhill.net", "{e4a8a97b-f2ed-450b-b12d-ee082ba24781}"]));
        assert_eq!(firefox_profile_addons("not json"), Vec::<String>::new());
        assert_eq!(firefox_profile_addons(r#"{"addons":5}"#), Vec::<String>::new());
    }

    #[test]
    fn a_remembered_block_drops_what_isnt_an_id() {
        let block = ExtensionBlock { kept: ids(&[A, B]), added: ids(&[EVERY_EXTENSION, A]).into_iter().collect() };
        assert_eq!(ExtensionBlock::parse(Browser::Chrome, &block.to_json()), Some(block));
        let tampered = r#"{"kept":["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","x"],"added":["*","../y"]}"#;
        assert_eq!(
            ExtensionBlock::parse(Browser::Edge, tampered),
            Some(ExtensionBlock { kept: ids(&[A]), added: ids(&["*"]).into_iter().collect() })
        );
        assert_eq!(ExtensionBlock::parse(Browser::Edge, "nope"), None);
    }

    #[test]
    fn the_chromium_block_goes_beside_a_schools_lists_and_comes_out_without_them() {
        let none = BTreeSet::new();
        // Nothing there: eGuard's entries in order
        let (list, ours) = chromium_list(&BTreeMap::new(), &none, &ids(&[EXT.id, A, B]));
        assert_eq!(list, map(&[("1", EXT.id), ("2", A), ("3", B)]));
        assert_eq!(ours, ids(&[EXT.id, A, B]).into_iter().collect());
        // Again: nothing changes
        assert_eq!(chromium_list(&list, &ours, &ids(&[EXT.id, A, B])), (list.clone(), ours.clone()));

        // A school allows B already and blocks everything itself: those stay the school's
        let school_allow = map(&[("1", B)]);
        let (allow, ours) = chromium_list(&school_allow, &none, &ids(&[EXT.id, A, B]));
        assert_eq!(allow, map(&[("1", B), ("2", EXT.id), ("3", A)]));
        assert_eq!(ours, ids(&[EXT.id, A]).into_iter().collect());
        let school_block = map(&[("1", "*")]);
        let (block, block_ours) = chromium_list(&school_block, &none, &ids(&[EVERY_EXTENSION]));
        assert_eq!((block, block_ours.is_empty()), (school_block.clone(), true));

        // Taken out: only eGuard's go, no number missing
        let (back, left) = chromium_list(&allow, &ours, &[]);
        assert_eq!((back, left.is_empty()), (school_allow, true));
        let mixed = map(&[("1", A), ("2", C), ("3", EXT.id)]);
        let ours_a: BTreeSet<String> = ids(&[A, EXT.id]).into_iter().collect();
        assert_eq!(chromium_list(&mixed, &ours_a, &[]).0, map(&[("1", C)]));
        // Kept set changed: one of eGuard's no longer wanted goes, a new one goes after
        let (now, ours) = chromium_list(&mixed, &ours_a, &ids(&[EXT.id, B]));
        assert_eq!(now, map(&[("1", C), ("2", EXT.id), ("3", B)]));
        assert_eq!(ours, ids(&[EXT.id, B]).into_iter().collect());
    }

    #[test]
    fn the_firefox_block_keeps_eguards_extension_and_a_schools_entries() {
        let ff = Extension { id: FIREFOX_ID, url: "https://example.test/eguard.xpi" };
        let forced = firefox_settings(None, &ff, true).unwrap();
        let none = BTreeSet::new();
        let want = ids(&[EVERY_EXTENSION, "ublock0@raymondhill.net"]);
        let (with, ours) = firefox_block(Some(forced.as_str()), &none, &want);
        let v: serde_json::Value = serde_json::from_str(with.as_deref().unwrap()).unwrap();
        assert_eq!(v["*"]["installation_mode"], "blocked");
        assert_eq!(v["ublock0@raymondhill.net"]["installation_mode"], "allowed");
        assert!(firefox_forced(with.as_deref(), &ff));
        assert_eq!(ours, want.iter().cloned().collect());
        // Again: the same
        let again = firefox_block(with.as_deref(), &ours, &want);
        assert!(same_json(again.0.as_deref(), with.as_deref()) && again.1 == ours);
        // Taken out: back to eGuard's extension alone
        let (back, left) = firefox_block(with.as_deref(), &ours, &[]);
        assert!(same_json(back.as_deref(), Some(forced.as_str())) && left.is_empty());

        // A school's `*` (with its own message) and its rule for an add-on stay as they are, and stay when taken out
        let school = r#"{"*":{"installation_mode":"blocked","blocked_install_message":"Ask IT"},"ublock0@raymondhill.net":{"installation_mode":"blocked"}}"#;
        let (with, ours) = firefox_block(Some(school), &none, &ids(&["*", "ublock0@raymondhill.net", "other@example.com"]));
        let v: serde_json::Value = serde_json::from_str(with.as_deref().unwrap()).unwrap();
        assert_eq!(v["*"]["blocked_install_message"], "Ask IT");
        assert_eq!(v["ublock0@raymondhill.net"]["installation_mode"], "blocked");
        assert_eq!(ours, ids(&["other@example.com"]).into_iter().collect());
        assert!(same_json(firefox_block(with.as_deref(), &ours, &[]).0.as_deref(), Some(school)));
        // Nothing left: no policy
        assert_eq!(firefox_block(Some(r#"{"*":{"installation_mode":"blocked"}}"#), &ids(&["*"]).into_iter().collect(), &[]).0, None);
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
    fn private_windows_stay_off_only_while_web_filtering_is_on() {
        assert_eq!(settings_step(true, false), SettingsStep::Put);
        // Turned back on after they were taken out: put back
        assert_eq!(settings_step(true, true), SettingsStep::Put);
        // Turned off: taken out once, then left alone
        assert_eq!(settings_step(false, false), SettingsStep::TakeOut);
        assert_eq!(settings_step(false, true), SettingsStep::Leave);
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
