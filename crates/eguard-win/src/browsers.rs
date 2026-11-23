//! The browser policies that force eGuard's extension (spec section 9), in the registry.
//!
//! Chrome and Edge: `ExtensionInstallForcelist`, the extension's managed policy (`3rdparty\extensions\<id>\policy`,
//! which it reads as `chrome.storage.managed`), and the settings in `web::Browser::settings`. Firefox: the same
//! through its registry policies (`ExtensionSettings`, `3rdparty\Extensions\<id>`) rather than a `policies.json`:
//! Firefox reads `SOFTWARE\Policies\Mozilla\Firefox` in every copy on the computer (Program Files, a portable one,
//! the Store's), where `policies.json` covers only the install it sits in. With registry policies present Firefox
//! ignores `policies.json`.
//!
//! While web filtering is on, new extensions are blocked too (`web` module): Chrome and Edge get `*` in
//! `ExtensionInstallBlocklist`, and eGuard's extension and the installed ones in `ExtensionInstallAllowlist`; Firefox
//! gets the same as `ExtensionSettings` entries. Which ones are installed is found in every account's profile folders
//! (`installed_extensions`), once, when the block goes in; that list and the entries eGuard added are kept beside the
//! policies (`BLOCK_RECORD`), so a restart neither looks again nor forgets what to take out.
//!
//! The real ones live under HKLM `SOFTWARE\Policies`, which only administrators and SYSTEM can write: the service
//! writes them. Console mode writes the same layout under HKCU `Software\eGuard\Dev\Policies`, which no browser
//! reads, so a developer's own browsers are never touched.

use crate::registry::{Key, Root, View};
use eguard_core::web::{
    self, Browser, EVERY_EXTENSION, Extension, ExtensionBlock, LINK_VALUE, PRIVATE_WINDOWS_OFF, PRIVATE_WINDOWS_VALUE, SettingsStep,
};
use std::collections::BTreeSet;
use std::io;
use std::os::windows::fs::MetadataExt;
use std::path::{Path, PathBuf};
use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

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
const ALLOWLIST: &str = "ExtensionInstallAllowlist";
const BLOCKLIST: &str = "ExtensionInstallBlocklist";
const FIREFOX_SETTINGS: &str = "ExtensionSettings";
/// eGuard's own key beside the browsers' (no browser reads it; only administrators and SYSTEM can write it), with one
/// value per browser while new extensions are blocked there: its `web::ExtensionBlock`.
const BLOCK_RECORD: &str = r"eGuard\ExtensionBlock";

/// What's in place for one browser, read back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Status {
    /// The extension is in the force-install policy as eGuard puts it.
    pub forced: bool,
    /// Every setting in `Browser::settings` has eGuard's value.
    pub settings: bool,
    /// The link in the extension's managed policy.
    pub link: Option<String>,
    /// While new extensions are blocked as eGuard puts it: how many installed ones it keeps allowed.
    pub kept: Option<usize>,
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
    let blocked = match b {
        Browser::Chrome | Browser::Edge => place
            .open(&format!(r"{}\{BLOCKLIST}", base(b)))
            .is_some_and(|k| k.strings().iter().any(|(n, v)| n.parse::<u32>().is_ok_and(|n| n > 0) && v.trim() == EVERY_EXTENSION)),
        Browser::Firefox => main
            .as_ref()
            .and_then(|k| k.string(FIREFOX_SETTINGS))
            .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
            .is_some_and(|v| v[EVERY_EXTENSION]["installation_mode"] == "blocked"),
    };
    let kept = if blocked { record(place, b).map(|r| r.kept.len()) } else { None };
    Status { forced, settings, link, kept }
}

/// Puts eGuard's policies for `b` in place at `place`, with `link` (or none) as the extension's link, and does
/// `settings` with `Browser::settings` and the block on new extensions (both taken out while web filtering is off,
/// `web::settings_step`). `installed`: the extensions installed on the computer now (`installed_extensions`), asked for
/// only when the block goes in. Only what differs is written. True when anything was.
pub fn apply(
    place: &Place,
    b: Browser,
    ext: &Extension,
    link: Option<&str>,
    settings: SettingsStep,
    installed: impl FnOnce() -> Vec<String>,
) -> io::Result<bool> {
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
    match settings {
        SettingsStep::Put => {
            for (name, want) in b.settings() {
                if main.dword(name) != Some(*want) {
                    main.set_dword(name, *want)?;
                    changed = true;
                }
            }
            // Chrome and Edge: private windows are off by the settings above; the extension is told so
            if matches!(b, Browser::Chrome | Browser::Edge) {
                let k = place.create(&link_key(b, ext.id))?;
                if k.string(PRIVATE_WINDOWS_VALUE).as_deref() != Some(PRIVATE_WINDOWS_OFF) {
                    k.set_string(PRIVATE_WINDOWS_VALUE, PRIVATE_WINDOWS_OFF)?;
                    changed = true;
                }
            }
            changed |= put_block(place, b, ext, installed)?;
        }
        SettingsStep::TakeOut => {
            changed |= take_out_settings(&main, b)?;
            changed |= take_out_block(place, b)?;
            // Private windows are the browser's own again: the extension mustn't be told they're off
            if let Some(k) = place.open(&link_key(b, ext.id)).filter(|k| k.string(PRIVATE_WINDOWS_VALUE).is_some()) {
                drop(k);
                place.create(&link_key(b, ext.id))?.delete_value(PRIVATE_WINDOWS_VALUE)?;
                changed = true;
            }
        }
        SettingsStep::Leave => {}
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
/// list kept without gaps), its Firefox entry, its block on new extensions, its managed policy, and the settings while
/// they still have eGuard's values. A key left empty is deleted.
pub fn remove(place: &Place, b: Browser, ext: &Extension) -> io::Result<()> {
    take_out_block(place, b)?;
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
    take_out_settings(&main, b)?;
    let policies = place.create("")?;
    policies.delete_tree(&link_root(b, ext.id))?;
    for parent in [format!(r"{}\3rdparty\extensions", base(b)), format!(r"{}\3rdparty", base(b)), base(b).to_owned()] {
        if place.open(&parent).is_some_and(|k| k.is_empty()) {
            policies.delete_tree(&parent)?;
        }
    }
    Ok(())
}

/// The block on new extensions `b` has, as eGuard remembers it, or `None` when it has none.
fn record(place: &Place, b: Browser) -> Option<ExtensionBlock> {
    place.open(BLOCK_RECORD)?.string(b.name()).and_then(|s| ExtensionBlock::parse(b, &s))
}

/// Records `added` as the entries eGuard added to `b`'s policies, when `block` (updated) doesn't say so already. True
/// when it was written.
fn save_record(records: &Key, b: Browser, block: &mut ExtensionBlock, added: BTreeSet<String>) -> io::Result<bool> {
    if block.added == added {
        return Ok(false);
    }
    block.added = added;
    records.set_string(b.name(), &block.to_json()).map(|()| true)
}

/// Blocks new extensions in `b`, keeping eGuard's allowed and the ones installed when the block went in (`installed`,
/// asked for only then). True when anything was written.
fn put_block(place: &Place, b: Browser, ext: &Extension, installed: impl FnOnce() -> Vec<String>) -> io::Result<bool> {
    let records = place.create(BLOCK_RECORD)?;
    let mut changed = false;
    let mut block = if let Some(r) = record(place, b) {
        r
    } else {
        // Remembered at once: from here on (a restart too) this list is kept, rather than looked for again under the
        // block, where a folder the child makes could pass for an extension installed before it
        let r = ExtensionBlock { kept: web::kept_extensions(b, ext, installed()), added: BTreeSet::new() };
        records.set_string(b.name(), &r.to_json())?;
        changed = true;
        r
    };
    let every = vec![EVERY_EXTENSION.to_owned()];
    match b {
        Browser::Chrome | Browser::Edge => {
            let (ours_block, ours_allow): (BTreeSet<String>, BTreeSet<String>) =
                block.added.iter().cloned().partition(|e| e == EVERY_EXTENSION);
            let allow_want: Vec<String> = std::iter::once(ext.id.to_owned()).chain(block.kept.iter().cloned()).collect();
            let allow_key = place.create(&format!(r"{}\{ALLOWLIST}", base(b)))?;
            let block_key = place.create(&format!(r"{}\{BLOCKLIST}", base(b)))?;
            let (allow, added_allow) = web::chromium_list(&allow_key.strings(), &ours_allow, &allow_want);
            let (deny, added_block) = web::chromium_list(&block_key.strings(), &ours_block, &every);
            let added: BTreeSet<String> = added_allow.into_iter().chain(added_block).collect();
            // What eGuard adds is remembered before it's written, so it's never in a policy without eGuard knowing to
            // take it out
            let both = block.added.union(&added).cloned().collect();
            changed |= save_record(&records, b, &mut block, both)?;
            // The allowlist first: `*` in the blocklist turns off every installed extension the allowlist doesn't name
            changed |= write_list(&allow_key, &allow)?;
            changed |= write_list(&block_key, &deny)?;
            changed |= save_record(&records, b, &mut block, added)?;
        }
        Browser::Firefox => {
            let main = place.create(base(b))?;
            let now = main.string(FIREFOX_SETTINGS);
            let want: Vec<String> = every.into_iter().chain(block.kept.iter().cloned()).collect();
            let (json, added) = web::firefox_block(now.as_deref(), &block.added, &want);
            let both = block.added.union(&added).cloned().collect();
            changed |= save_record(&records, b, &mut block, both)?;
            if !web::same_json(now.as_deref(), json.as_deref()) {
                match json {
                    Some(j) => main.set_string(FIREFOX_SETTINGS, &j)?,
                    None => main.delete_value(FIREFOX_SETTINGS)?,
                }
                changed = true;
            }
            changed |= save_record(&records, b, &mut block, added)?;
        }
    }
    Ok(changed)
}

/// Takes eGuard's block on new extensions out of `b`: only the entries it added (others', such as a school's own `*`,
/// stay), then its record. True when there was one.
fn take_out_block(place: &Place, b: Browser) -> io::Result<bool> {
    if place.open(BLOCK_RECORD).and_then(|k| k.string(b.name())).is_none() {
        return Ok(false);
    }
    let ours = record(place, b).unwrap_or_default().added;
    match b {
        Browser::Chrome | Browser::Edge => {
            // The blocklist first, so no installed extension is turned off in between
            for name in [BLOCKLIST, ALLOWLIST] {
                let sub = format!(r"{}\{name}", base(b));
                if place.open(&sub).is_some() {
                    let key = place.create(&sub)?;
                    write_list(&key, &web::chromium_list(&key.strings(), &ours, &[]).0)?;
                    if key.is_empty() {
                        drop(key);
                        place.create(base(b))?.delete_tree(name)?;
                    }
                }
            }
        }
        Browser::Firefox => {
            if let Some(now) = place.open(base(b)).and_then(|k| k.string(FIREFOX_SETTINGS)) {
                let main = place.create(base(b))?;
                match web::firefox_block(Some(&now), &ours, &[]).0 {
                    Some(rest) => main.set_string(FIREFOX_SETTINGS, &rest)?,
                    None => main.delete_value(FIREFOX_SETTINGS)?,
                }
            }
        }
    }
    // Forgotten last: a take-out cut short is done again from the same record
    let records = place.create(BLOCK_RECORD)?;
    records.delete_value(b.name())?;
    let empty = records.is_empty();
    drop(records);
    if empty {
        let policies = place.create("")?;
        policies.delete_tree(BLOCK_RECORD)?;
        if place.open("eGuard").is_some_and(|k| k.is_empty()) {
            policies.delete_tree("eGuard")?;
        }
    }
    Ok(true)
}

/// Most entries looked at in one folder while looking for installed extensions: a profile folder the child can fill
/// mustn't hold the service up.
const MAX_DIR_ENTRIES: usize = 2_000;
/// Most bytes of a Firefox profile's `extensions.json` read (a real one is well under a megabyte).
const MAX_EXTENSIONS_JSON: u64 = 8 * 1024 * 1024;

/// The ids of the extensions installed in `b` in every account's profile on this computer, unchecked
/// (`web::kept_extensions` checks them). Runs as SYSTEM, in folders the child can write to: only real folders are
/// followed (never a link or junction to somewhere else), and only so much is read.
pub fn installed_extensions(b: Browser) -> Vec<String> {
    let mut found = Vec::new();
    for u in crate::apps::users() {
        if crate::apps::plain_local(&u.profile) {
            installed_in(b, &u.profile, &mut found);
        }
    }
    found
}

/// `installed_extensions` in one account's profile folder (`home`).
fn installed_in(b: Browser, home: &Path, found: &mut Vec<String>) {
    match b {
        Browser::Chrome | Browser::Edge => {
            // Every channel reads the same policies, so each one's extensions are kept
            let vendor = if b == Browser::Chrome { r"Google\Chrome" } else { r"Microsoft\Edge" };
            for channel in ["", " Beta", " Dev", " SxS"] {
                let Some(user_data) = real_dir(home, &format!(r"AppData\Local\{vendor}{channel}\User Data")) else { continue };
                // `Default`, `Profile 1`, …: any folder with `Extensions` in it, whose folders are named by id
                for profile in subdirs(&user_data) {
                    if let Some(exts) = real_dir(&profile, "Extensions") {
                        found.extend(subdirs(&exts).filter_map(|d| Some(d.file_name()?.to_string_lossy().into_owned())));
                    }
                }
            }
        }
        Browser::Firefox => {
            let store = real_dir(home, r"AppData\Local\Packages")
                .and_then(|p| subdirs(&p).find(|d| d.file_name().is_some_and(|n| n.to_string_lossy().starts_with("Mozilla.Firefox_"))));
            let roots = [
                real_dir(home, r"AppData\Roaming\Mozilla\Firefox\Profiles"),
                // The Microsoft Store's Firefox keeps its profiles in its package's folder
                store.and_then(|p| real_dir(&p, r"LocalCache\Roaming\Mozilla\Firefox\Profiles")),
            ];
            for root in roots.into_iter().flatten() {
                for profile in subdirs(&root) {
                    if let Some(json) = read_bounded(&profile.join("extensions.json"), MAX_EXTENSIONS_JSON) {
                        found.extend(web::firefox_profile_addons(&json));
                    }
                }
            }
        }
    }
}

/// `dir\rel` when it and every folder on the way are real folders: not a link or junction, which the child could point
/// at a share, or at a folder of made-up extensions.
fn real_dir(dir: &Path, rel: &str) -> Option<PathBuf> {
    let mut p = dir.to_owned();
    for part in rel.split('\\') {
        p.push(part);
        let m = std::fs::symlink_metadata(&p).ok()?;
        if !m.is_dir() || m.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return None;
        }
    }
    Some(p)
}

/// The real folders in `dir` (at most `MAX_DIR_ENTRIES` entries are looked at).
fn subdirs(dir: &Path) -> impl Iterator<Item = PathBuf> {
    std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .take(MAX_DIR_ENTRIES)
        .flatten()
        .filter(|e| e.file_type().is_ok_and(|t| t.is_dir() && !t.is_symlink()))
        .map(|e| e.path())
}

/// A regular file's text, when it's at most `max` bytes (never a pipe or a device, which could hold the read).
fn read_bounded(path: &Path, max: u64) -> Option<String> {
    use std::io::Read;
    let m = std::fs::symlink_metadata(path).ok()?;
    if !m.is_file() || m.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return None;
    }
    let mut out = String::new();
    std::fs::File::open(path).ok()?.take(max + 1).read_to_string(&mut out).ok()?;
    (out.len() as u64 <= max).then_some(out)
}

/// Deletes the settings in `Browser::settings` that still have eGuard's values from `main` (the browser's policy key).
/// True when any was.
fn take_out_settings(main: &Key, b: Browser) -> io::Result<bool> {
    // A setting someone else gave the same value can't be told from eGuard's; taking it out errs toward the browser's
    // own default, which is what the computer had before eGuard
    let mut changed = false;
    for (name, want) in b.settings() {
        if main.dword(name) == Some(*want) {
            main.delete_value(name)?;
            changed = true;
        }
    }
    Ok(changed)
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

        assert!(apply(p, Browser::Chrome, &CHROME, Some("dev.1795000000000.sig"), SettingsStep::Put, Vec::new).unwrap());
        let st = status(p, Browser::Chrome, &CHROME);
        assert_eq!(st, Status { forced: true, settings: true, link: Some("dev.1795000000000.sig".into()), kept: Some(0) });
        let strings = p.open(r"Google\Chrome\ExtensionInstallForcelist").unwrap().strings();
        assert_eq!(strings.len(), 2);
        assert_eq!(strings["2"], format!("{};{CHROME_UPDATE_URL}", CHROME.id));
        assert_eq!(p.open(r"Google\Chrome").unwrap().dword("IncognitoModeAvailability"), Some(1));
        let managed = p.open(&link_key(Browser::Chrome, CHROME.id)).unwrap();
        assert_eq!(managed.string(PRIVATE_WINDOWS_VALUE).as_deref(), Some(PRIVATE_WINDOWS_OFF));
        drop(managed);
        // Nothing to do the second time
        assert!(!apply(p, Browser::Chrome, &CHROME, Some("dev.1795000000000.sig"), SettingsStep::Put, Vec::new).unwrap());
        // No link (a removal waits): the value goes, the forcing stays
        assert!(apply(p, Browser::Chrome, &CHROME, None, SettingsStep::Put, Vec::new).unwrap());
        assert_eq!(status(p, Browser::Chrome, &CHROME).link, None);
        assert!(status(p, Browser::Chrome, &CHROME).forced);

        // Someone deleted a setting and our entry: put back
        p.create(r"Google\Chrome").unwrap().delete_value("BrowserGuestModeEnabled").unwrap();
        p.create(r"Google\Chrome\ExtensionInstallForcelist").unwrap().delete_value("2").unwrap();
        assert!(!status(p, Browser::Chrome, &CHROME).forced);
        assert!(apply(p, Browser::Chrome, &CHROME, None, SettingsStep::Put, Vec::new).unwrap());
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
        apply(p, Browser::Edge, &edge, Some("x.1.y"), SettingsStep::Put, Vec::new).unwrap();
        apply(p, Browser::Firefox, &FIREFOX, Some("x.1.y"), SettingsStep::Put, Vec::new).unwrap();
        assert_eq!(status(p, Browser::Edge, &edge), Status { forced: true, settings: true, link: Some("x.1.y".into()), kept: Some(0) });
        assert_eq!(
            status(p, Browser::Firefox, &FIREFOX),
            Status { forced: true, settings: true, link: Some("x.1.y".into()), kept: Some(0) }
        );
        assert_eq!(p.open(r"Microsoft\Edge").unwrap().dword("InPrivateModeAvailability"), Some(1));
        assert!(p.open(&format!(r"Mozilla\Firefox\3rdparty\Extensions\{FIREFOX_ID}")).is_some());
        // Firefox keeps private windows (the extension runs in them), so it isn't told they're off
        let ff = p.open(&link_key(Browser::Firefox, FIREFOX.id)).unwrap();
        assert_eq!(ff.string(PRIVATE_WINDOWS_VALUE), None);
        drop(ff);

        remove(p, Browser::Edge, &edge).unwrap();
        remove(p, Browser::Firefox, &FIREFOX).unwrap();
        assert!(p.open(r"Microsoft\Edge").is_none() && p.open(r"Mozilla\Firefox").is_none());
        // Removing what isn't there is fine
        remove(p, Browser::Firefox, &FIREFOX).unwrap();
    }

    #[test]
    fn with_web_filtering_off_private_windows_come_back_and_the_extension_stays() {
        let s = Scratch::new("off");
        let p = &s.0;
        let edge = Extension { id: "ponmlkjihgfedcbaponmlkjihgfedcba", url: web::EDGE_UPDATE_URL };
        apply(p, Browser::Edge, &edge, Some("x.1.y"), SettingsStep::Put, Vec::new).unwrap();
        // Turned off: eGuard's settings come out, and the extension isn't told private windows are off
        assert!(apply(p, Browser::Edge, &edge, Some("x.1.y"), SettingsStep::TakeOut, Vec::new).unwrap());
        assert_eq!(status(p, Browser::Edge, &edge), Status { forced: true, settings: false, link: Some("x.1.y".into()), kept: None });
        let main = p.open(r"Microsoft\Edge").unwrap();
        assert!(main.dword("InPrivateModeAvailability").is_none() && main.dword("InternetExplorerIntegrationLevel").is_none());
        drop(main);
        assert_eq!(p.open(&link_key(Browser::Edge, edge.id)).unwrap().string(PRIVATE_WINDOWS_VALUE), None);
        // A school's own setting, put in afterwards, is left alone while off
        p.create(r"Microsoft\Edge").unwrap().set_dword("InPrivateModeAvailability", 1).unwrap();
        assert!(!apply(p, Browser::Edge, &edge, Some("x.1.y"), SettingsStep::Leave, Vec::new).unwrap());
        assert_eq!(p.open(r"Microsoft\Edge").unwrap().dword("InPrivateModeAvailability"), Some(1));
        // Back on: everything is put back
        assert!(apply(p, Browser::Edge, &edge, Some("x.1.y"), SettingsStep::Put, Vec::new).unwrap());
        assert!(status(p, Browser::Edge, &edge).settings);
        assert_eq!(p.open(&link_key(Browser::Edge, edge.id)).unwrap().string(PRIVATE_WINDOWS_VALUE).as_deref(), Some(PRIVATE_WINDOWS_OFF));
        remove(p, Browser::Edge, &edge).unwrap();
    }

    const A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const C: &str = "cccccccccccccccccccccccccccccccc";

    fn values(p: &Place, sub: &str) -> Vec<String> {
        p.open(sub).map(|k| k.strings().into_values().collect()).unwrap_or_default()
    }

    #[test]
    fn new_extensions_are_blocked_and_the_installed_ones_kept_while_web_filtering_is_on() {
        let s = Scratch::new("block");
        let p = &s.0;
        // A school's own allowlist entry (B, installed too) and blocklist entry
        p.create(r"Google\Chrome\ExtensionInstallAllowlist").unwrap().set_string("1", B).unwrap();
        p.create(r"Google\Chrome\ExtensionInstallBlocklist").unwrap().set_string("1", C).unwrap();
        let looked = std::cell::Cell::new(0);
        let installed = || {
            looked.set(looked.get() + 1);
            vec![A.to_owned(), B.to_owned(), "Temp".to_owned()]
        };

        assert!(apply(p, Browser::Chrome, &CHROME, None, SettingsStep::Put, installed).unwrap());
        assert_eq!(values(p, r"Google\Chrome\ExtensionInstallAllowlist"), [B, CHROME.id, A]);
        assert_eq!(values(p, r"Google\Chrome\ExtensionInstallBlocklist"), [C, "*"]);
        assert_eq!(status(p, Browser::Chrome, &CHROME).kept, Some(2));
        // Every minute after: nothing written, and the computer isn't looked at again (a restart neither)
        assert!(!apply(p, Browser::Chrome, &CHROME, None, SettingsStep::Put, installed).unwrap());
        assert_eq!(looked.get(), 1);

        // Off: only eGuard's entries go
        assert!(apply(p, Browser::Chrome, &CHROME, None, SettingsStep::TakeOut, installed).unwrap());
        assert_eq!(values(p, r"Google\Chrome\ExtensionInstallAllowlist"), [B]);
        assert_eq!(values(p, r"Google\Chrome\ExtensionInstallBlocklist"), [C]);
        assert_eq!(status(p, Browser::Chrome, &CHROME).kept, None);
        assert!(p.open(BLOCK_RECORD).is_none() && p.open("eGuard").is_none());

        // On again: looked at afresh, so an extension the parent added meanwhile is kept
        let now = || vec![A.to_owned(), "dddddddddddddddddddddddddddddddd".to_owned()];
        assert!(apply(p, Browser::Chrome, &CHROME, None, SettingsStep::Put, now).unwrap());
        assert_eq!(values(p, r"Google\Chrome\ExtensionInstallAllowlist"), [B, CHROME.id, A, "dddddddddddddddddddddddddddddddd"]);

        // Removal takes the block out with the rest; the school's entries stay
        remove(p, Browser::Chrome, &CHROME).unwrap();
        assert_eq!(values(p, r"Google\Chrome\ExtensionInstallAllowlist"), [B]);
        assert_eq!(values(p, r"Google\Chrome\ExtensionInstallBlocklist"), [C]);
        assert!(p.open("eGuard").is_none());
    }

    #[test]
    fn a_schools_own_block_is_left_in_place_when_eguards_comes_out() {
        let s = Scratch::new("school-block");
        let p = &s.0;
        let edge = Extension { id: "ponmlkjihgfedcbaponmlkjihgfedcba", url: web::EDGE_UPDATE_URL };
        p.create(r"Microsoft\Edge\ExtensionInstallBlocklist").unwrap().set_string("1", "*").unwrap();
        apply(p, Browser::Edge, &edge, None, SettingsStep::Put, || vec![A.to_owned()]).unwrap();
        assert_eq!(values(p, r"Microsoft\Edge\ExtensionInstallBlocklist"), ["*"]);
        assert_eq!(values(p, r"Microsoft\Edge\ExtensionInstallAllowlist"), [edge.id, A]);
        apply(p, Browser::Edge, &edge, None, SettingsStep::TakeOut, Vec::new).unwrap();
        assert_eq!(values(p, r"Microsoft\Edge\ExtensionInstallBlocklist"), ["*"]);
        assert!(p.open(r"Microsoft\Edge\ExtensionInstallAllowlist").is_none());
        remove(p, Browser::Edge, &edge).unwrap();
    }

    #[test]
    fn firefox_blocks_new_add_ons_beside_eguards_and_a_schools() {
        let s = Scratch::new("ff-block");
        let p = &s.0;
        let school = r#"{"school@example.com":{"installation_mode":"force_installed","install_url":"https://school.example/x.xpi"}}"#;
        p.create(r"Mozilla\Firefox").unwrap().set_string(FIREFOX_SETTINGS, school).unwrap();
        let installed = || vec!["ublock0@raymondhill.net".to_owned(), FIREFOX_ID.to_owned(), "bad id".to_owned()];
        assert!(apply(p, Browser::Firefox, &FIREFOX, None, SettingsStep::Put, installed).unwrap());
        let json: serde_json::Value = serde_json::from_str(&p.open(r"Mozilla\Firefox").unwrap().string(FIREFOX_SETTINGS).unwrap()).unwrap();
        assert_eq!(json["*"]["installation_mode"], "blocked");
        assert_eq!(json["ublock0@raymondhill.net"]["installation_mode"], "allowed");
        assert_eq!(json[FIREFOX_ID]["installation_mode"], "force_installed");
        assert_eq!(json["school@example.com"]["installation_mode"], "force_installed");
        assert_eq!(json.as_object().unwrap().len(), 4);
        assert_eq!(status(p, Browser::Firefox, &FIREFOX), Status { forced: true, settings: true, link: None, kept: Some(1) });
        assert!(!apply(p, Browser::Firefox, &FIREFOX, None, SettingsStep::Put, installed).unwrap());

        // Off: eGuard's extension and the school's stay forced
        assert!(apply(p, Browser::Firefox, &FIREFOX, None, SettingsStep::TakeOut, installed).unwrap());
        let json: serde_json::Value = serde_json::from_str(&p.open(r"Mozilla\Firefox").unwrap().string(FIREFOX_SETTINGS).unwrap()).unwrap();
        assert_eq!(json.as_object().unwrap().keys().collect::<Vec<_>>(), [FIREFOX_ID, "school@example.com"]);
        assert!(status(p, Browser::Firefox, &FIREFOX).forced);
        remove(p, Browser::Firefox, &FIREFOX).unwrap();
    }

    #[test]
    fn installed_extensions_are_found_in_every_profile() {
        let home = std::env::temp_dir().join(format!("eguard-browsers-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);
        let dir = |rel: &str| std::fs::create_dir_all(home.join(rel)).unwrap();
        dir(&format!(r"AppData\Local\Google\Chrome\User Data\Default\Extensions\{A}\1.0_0"));
        dir(&format!(r"AppData\Local\Google\Chrome\User Data\Profile 2\Extensions\{B}"));
        dir(r"AppData\Local\Google\Chrome\User Data\Profile 2\Extensions\Temp");
        dir(&format!(r"AppData\Local\Google\Chrome Beta\User Data\Default\Extensions\{C}"));
        dir(&format!(r"AppData\Local\Microsoft\Edge\User Data\Default\Extensions\{C}"));
        // A file named like an extension isn't one
        std::fs::write(home.join(r"AppData\Local\Google\Chrome\User Data\Default\Extensions\dddddddddddddddddddddddddddddddd"), b"")
            .unwrap();
        dir(r"AppData\Roaming\Mozilla\Firefox\Profiles\abc.default-release");
        std::fs::write(
            home.join(r"AppData\Roaming\Mozilla\Firefox\Profiles\abc.default-release\extensions.json"),
            r#"{"addons":[{"id":"ublock0@raymondhill.net","location":"app-profile"},{"id":"x@mozilla.org","location":"app-builtin"}]}"#,
        )
        .unwrap();

        let found = |b: Browser| {
            let mut f = Vec::new();
            installed_in(b, &home, &mut f);
            f.sort();
            f
        };
        assert_eq!(found(Browser::Chrome), ["Temp", A, B, C]);
        assert_eq!(web::kept_extensions(Browser::Chrome, &CHROME, found(Browser::Chrome)), [A, B, C]);
        assert_eq!(found(Browser::Edge), [C]);
        assert_eq!(found(Browser::Firefox), ["ublock0@raymondhill.net"]);
        // A profile without these browsers: nothing found
        let mut none = Vec::new();
        installed_in(Browser::Chrome, &home.join("nobody"), &mut none);
        assert_eq!(none, Vec::<String>::new());
        let _ = std::fs::remove_dir_all(&home);
    }
}
