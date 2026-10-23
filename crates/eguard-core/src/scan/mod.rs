//! Installed apps: what the platform found (`Candidate`), what the parent hears about (spec section 5).
//!
//! Each candidate goes through four rules, first match wins:
//! 1. A GAME entry in the catalog (launcher id, exe name, signer, product name): reported under the catalog's name.
//! 2. Installed through a game launcher: reported, as a game.
//! 3. Signed (valid Authenticode) by a `TRUSTED_PUBLISHER`: not reported, never blocked.
//! 4. Anything else: reported as from an unknown publisher; a game when it shows game signals.
//!
//! The platform has already left out what never counts: system components, updates, and anything under the
//! Windows folder (drivers and Windows' own apps live there, and a standard account can't install into it).
//!
//! Between rules 3 and 4, two kinds of candidate are left out of the report (`left_out`): what an uninstall left
//! behind (only its updater or uninstaller is there) and a driver package installed for the whole computer. Their
//! folders still count for enforcement (`classify_all`), so leaving one out never lets what runs from it go
//! unchecked.

pub mod launchers;
pub mod lnk;
pub mod pe;
pub mod vdf;

use crate::wire::{self, AppId, AppSource, Catalog, CatalogKind, Category, DeviceEvent, FoundApp, MatchType};
use launchers::Launcher;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};

/// Where a candidate was found. Also the order duplicates give way in: the earlier one keeps its name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Origin {
    Launcher,
    Store,
    Uninstall,
    Shortcut,
    UserFolder,
}

/// What the platform learned about one executable. Cached by path, size and modification time, so the 6-hourly
/// scan doesn't verify every signature again.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExeFacts {
    /// File name, lower case (`cs2.exe`).
    pub file_name: String,
    /// The signer of a valid Authenticode signature, lower case. `None`: unsigned, or a signature that doesn't
    /// verify (both are "unknown publisher").
    pub signer: Option<String>,
    /// The certificate's other name, when it has two (organisation and common name differ). Matched like `signer`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer_alt: Option<String>,
    /// From the version resource.
    pub product: Option<String>,
    /// Imports DirectX or Vulkan (`pe::is_graphics_import`).
    pub graphics: bool,
}

/// `ExeFacts` for a file as it was: a changed size or modification time means it's checked again.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CachedExe {
    pub size: u64,
    pub modified_ms: i64,
    pub facts: ExeFacts,
}

/// Facts by lower-case path. Persisted; entries a scan didn't use are dropped after it.
pub type ExeCache = BTreeMap<String, CachedExe>;

/// One app the platform found.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)] // Separate facts the platform found, each read by its own rule, not a state
pub struct Candidate {
    pub name: String,
    pub origin: Origin,
    /// Installed through this launcher (rule 2).
    pub launcher: Option<Launcher>,
    /// Launcher and Store ids. The `EXE` id is added from `exe`.
    pub ids: Vec<AppId>,
    /// The install folder, as found (any case).
    pub dir: Option<String>,
    /// The app's main executable, checked.
    pub exe: Option<ExeFacts>,
    /// A verified signer other than the exe's: the cached MSI's, or a Store package's publisher (Windows checked
    /// the package's signature when it was installed and won't run it if it changed).
    pub other_signer: Option<String>,
    /// An engine or anti-cheat file next to the executable.
    pub game_files: bool,
    /// Found where only an administrator can write (an Uninstall entry under HKLM). A standard account can make
    /// Uninstall entries of its own (HKCU), so what it says there can't make a candidate less visible.
    pub machine_wide: bool,
    /// File names (lower case) of the exes in the install folder and the folders below it. `None`: not looked at, or
    /// too many to be sure none is the app.
    pub folder_exes: Option<Vec<String>>,
    /// One of `folder_exes` imports DirectX, Vulkan or `XInput`. Only looked at when they're all installers or
    /// updaters (`left_out` is the only reader, and it reads nothing else then).
    pub folder_graphics: bool,
    /// A driver's setup information (`.inf`) is in the install folder.
    pub driver_files: bool,
    /// Every file and folder the Uninstall entry names is gone: nothing of it is installed any more.
    pub gone: bool,
}

impl Candidate {
    pub fn new(name: &str, origin: Origin) -> Self {
        Self {
            name: name.trim().to_owned(),
            origin,
            launcher: None,
            ids: Vec::new(),
            dir: None,
            exe: None,
            other_signer: None,
            game_files: false,
            machine_wide: false,
            folder_exes: None,
            folder_graphics: false,
            driver_files: false,
            gone: false,
        }
    }

    fn signers(&self) -> impl Iterator<Item = &str> {
        let exe = self.exe.as_ref();
        exe.and_then(|e| e.signer.as_deref())
            .into_iter()
            .chain(exe.and_then(|e| e.signer_alt.as_deref()))
            .chain(self.other_signer.as_deref())
    }
}

/// Why a candidate isn't reported.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Skip {
    TrustedPublisher(String),
    BlankName,
}

/// The catalog, indexed for the four rules.
#[derive(Debug, Clone, Default)]
pub struct Classifier {
    /// `(match type, match)` → (display name, category) of a GAME entry.
    games: HashMap<(MatchType, String), (Option<String>, Option<Category>)>,
    trusted: HashSet<String>,
}

/// `<kind>:<value>`, as catalog `LAUNCHER_ID` entries are written (`steam:730`).
fn launcher_key(id: &AppId) -> String {
    let kind = serde_json::to_value(id.kind).ok().and_then(|v| v.as_str().map(str::to_ascii_lowercase)).unwrap_or_default();
    format!("{kind}:{}", id.value.to_lowercase())
}

/// True when `name` has one of `words` as a word.
fn says(name: &str, words: &[&str]) -> bool {
    name.to_lowercase().split(|c: char| !c.is_alphanumeric()).any(|w| words.contains(&w))
}

/// True when `name` has "game" or "games" as a word.
fn says_game(name: &str) -> bool {
    says(name, &["game", "games"])
}

/// An installer, updater or uninstaller, by its file name (`unins000.exe`, `Uninstall.exe`, Squirrel's
/// `Update.exe`, `setup.exe`). What's left of an app when only these remain can't be used, only reinstalled or
/// removed. Narrower than "not the main exe": a crash reporter or a helper process is part of a working app.
pub fn is_maintenance_exe(file_name: &str) -> bool {
    let n = file_name.to_ascii_lowercase();
    let stem = n.strip_suffix(".exe").unwrap_or(&n);
    stem.starts_with("unins")
        || stem.contains("uninstall")
        || ["update", "updater", "setup", "install", "installer", "squirrel"].contains(&stem)
        || ["-update", "_update", "-updater", "_updater", "-setup", "_setup", "-installer", "_installer"].iter().any(|s| stem.ends_with(s))
}

/// Why a candidate rule 4 would report is left out anyway.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeftOut {
    /// What an uninstall left behind: its folder has only installers, updaters and uninstallers (Discord's
    /// `Update.exe`, which can reinstall it).
    Leftover,
    /// A driver package installed for the whole computer (a printer's, a device's).
    Driver,
}

/// Whether a candidate that rule 4 would report is left out, and why (module docs). Never anything that shows a
/// game signal or came through a launcher: those stay reported whatever else is true.
///
/// A child controls some of these facts (an HKCU Uninstall entry's name and paths, what's in their own folders), so
/// each rule needs something they can't fake cheaply, and `classify_all` keeps the folder for enforcement:
/// - Leftover: no exe that isn't an installer or updater, down three folders, and no game signal in any of them. A
///   game renamed `update.exe` to hide would still be an app where it runs, since its folder is kept.
/// - Driver: only from HKLM (a standard account can't write there; drivers install for the whole computer anyway),
///   named as one, and either with a driver's `.inf` in its folder or with nothing of it left on disk.
pub fn left_out(c: &Candidate) -> Option<LeftOut> {
    let game =
        c.launcher.is_some() || c.game_files || c.folder_graphics || c.exe.as_ref().is_some_and(|e| e.graphics) || says_game(&c.name);
    if game {
        return None;
    }
    let only_maintenance = c.folder_exes.as_ref().is_some_and(|v| !v.is_empty() && v.iter().all(|n| is_maintenance_exe(n)));
    if matches!(c.origin, Origin::Uninstall | Origin::Shortcut)
        && only_maintenance
        && c.exe.as_ref().is_none_or(|e| is_maintenance_exe(&e.file_name))
    {
        return Some(LeftOut::Leftover);
    }
    // Gone counts only when nothing else lent it an exe or a folder (a shortcut named like it, say)
    let nothing_left = c.gone && c.exe.is_none() && c.dir.is_none();
    if c.origin == Origin::Uninstall && c.machine_wide && says(&c.name, &["driver", "drivers"]) && (c.driver_files || nothing_left) {
        return Some(LeftOut::Driver);
    }
    None
}

impl Classifier {
    pub fn new(catalog: &Catalog) -> Self {
        let mut c = Self::default();
        for e in &catalog.entries {
            let m = e.match_value.trim().to_lowercase();
            match e.kind {
                CatalogKind::Game => {
                    c.games.entry((e.match_type, m)).or_insert((e.display_name.clone(), e.category));
                }
                CatalogKind::TrustedPublisher if e.match_type == MatchType::Signer => {
                    c.trusted.insert(m);
                }
                // A trusted entry that isn't a signer, or a kind this build doesn't know: no effect (stricter)
                _ => {}
            }
        }
        c
    }

    /// Adds a trusted publisher, as a catalog entry would. For trying out catalog changes (`scan --trust`).
    pub fn trust(&mut self, signer: &str) {
        self.trusted.insert(signer.trim().to_lowercase());
    }

    fn game(&self, c: &Candidate) -> Option<&(Option<String>, Option<Category>)> {
        let get = |t: MatchType, m: &str| self.games.get(&(t, m.trim().to_lowercase()));
        c.ids
            .iter()
            .find_map(|id| get(MatchType::LauncherId, &launcher_key(id)))
            .or_else(|| c.exe.as_ref().and_then(|e| get(MatchType::ExeName, &e.file_name)))
            .or_else(|| c.signers().find_map(|s| get(MatchType::Signer, s)))
            .or_else(|| c.exe.as_ref().and_then(|e| e.product.as_deref()).and_then(|p| get(MatchType::ProductName, p)))
    }

    /// The four rules (module docs).
    pub fn classify(&self, c: &Candidate) -> Result<FoundApp, Skip> {
        let mut ids = c.ids.clone();
        if let Some(exe) = &c.exe {
            let product = exe.product.as_deref().filter(|p| !p.trim().is_empty()).unwrap_or(&c.name);
            ids.push(AppId::exe(exe.signer.as_deref(), product));
        }
        let mut seen = HashSet::new();
        ids.retain(|i| !i.value.is_empty() && i.value != "|" && seen.insert((i.kind, i.value.clone())));
        ids.truncate(wire::IDS_PER_APP_MAX);

        let (name, source, category) = if let Some((display, category)) = self.game(c) {
            (display.as_deref().unwrap_or(&c.name), AppSource::Catalog, category.unwrap_or(Category::Games))
        } else if c.launcher.is_some() {
            (c.name.as_str(), AppSource::Launcher, Category::Games)
        } else if let Some(s) = c.signers().find(|s| self.trusted.contains(*s)) {
            return Err(Skip::TrustedPublisher(s.to_owned()));
        } else {
            let game = c.game_files || c.exe.as_ref().is_some_and(|e| e.graphics) || says_game(&c.name);
            (c.name.as_str(), AppSource::UnknownPublisher, if game { Category::Games } else { Category::Other })
        };
        let app = wire::app_name(name).ok_or(Skip::BlankName)?;
        Ok(FoundApp { app, ids, source: Some(source), category: Some(category) })
    }
}

/// A path as places keep it: lower case, backslashes, no trailing separator.
pub fn norm(path: &str) -> String {
    path.trim().trim_end_matches(['\\', '/']).replace('/', "\\").to_lowercase()
}

/// True when `path` is `dir` or inside it.
pub fn inside(path: &str, dir: &str) -> bool {
    let (p, d) = (norm(path), norm(dir));
    !d.is_empty() && (p == d || p.starts_with(&format!("{d}\\")))
}

fn words(s: &str) -> Vec<String> {
    s.to_lowercase().split(|c: char| !c.is_alphanumeric()).filter(|w| !w.is_empty()).map(str::to_owned).collect()
}

/// True when `short`'s words begin `long`'s ("7-Zip" begins "7-Zip 25.01 (x64)"; "Git" doesn't begin "GitHub
/// CLI"). One short word alone isn't enough to go on.
fn names_match(short: &str, long: &str) -> bool {
    let (s, l) = (words(short), words(long));
    !s.is_empty() && (s.len() >= 2 || s[0].len() >= 3) && l.starts_with(&s)
}

fn is_loose(c: &Candidate) -> bool {
    matches!(c.origin, Origin::Shortcut | Origin::UserFolder)
}

/// One candidate per app:
/// - the same install folder found twice is one app (the earlier origin's name, every id);
/// - a shortcut or loose exe inside an installed app's folder is that app;
/// - a shortcut or loose exe named like an installed app is that app (its installer left in Downloads, a Start Menu
///   entry for an app whose folder wasn't known), and lends it its exe.
pub fn merge(cands: Vec<Candidate>) -> Vec<Candidate> {
    let mut out = merge_by_dir(cands);
    let (loose, mut installed): (Vec<_>, Vec<_>) = out.drain(..).partition(is_loose);
    let mut rest = Vec::new();
    for l in loose {
        let product = l.exe.as_ref().and_then(|e| e.product.clone()).unwrap_or_default();
        match installed.iter_mut().find(|i| names_match(&l.name, &i.name) || names_match(&product, &i.name)) {
            Some(i) => {
                if i.exe.is_none() {
                    i.exe = l.exe;
                    i.game_files |= l.game_files;
                }
                if i.dir.is_none() {
                    i.dir = l.dir;
                }
            }
            None => rest.push(l),
        }
    }
    installed.extend(rest);
    installed
}

fn merge_by_dir(mut cands: Vec<Candidate>) -> Vec<Candidate> {
    cands.sort_by_key(|c| c.origin);
    let mut out: Vec<Candidate> = Vec::new();
    let mut by_dir: HashMap<String, usize> = HashMap::new();
    for c in cands {
        let loose = is_loose(&c);
        if loose {
            let covered =
                c.dir.as_deref().is_some_and(|d| out.iter().any(|o| !is_loose(o) && o.dir.as_deref().is_some_and(|od| inside(d, od))));
            if covered {
                continue;
            }
        }
        if let Some(i) = c.dir.as_deref().map(norm).and_then(|d| by_dir.get(&d).copied()) {
            let o = &mut out[i];
            o.ids.extend(c.ids);
            o.launcher = o.launcher.or(c.launcher);
            if o.exe.is_none() {
                o.exe = c.exe;
            }
            o.other_signer = o.other_signer.take().or(c.other_signer);
            o.game_files |= c.game_files;
            // Machine-wide only when both are: one found where a child can write is enough to lose it
            o.machine_wide &= c.machine_wide;
            o.folder_graphics |= c.folder_graphics;
            o.driver_files |= c.driver_files;
            o.gone &= c.gone;
            if o.folder_exes.is_none() {
                o.folder_exes = c.folder_exes;
            }
        } else {
            if let Some(d) = c.dir.as_deref() {
                by_dir.insert(norm(d), out.len());
            }
            out.push(c);
        }
    }
    out
}

/// An app's install folder, for matching a running program to its app (spec section 6: a renamed `cs2.exe` still
/// lives in Steam's folder for appid 730).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Place {
    /// Lower case, no trailing separator.
    pub dir: String,
    /// The reported app's name; `None` for a trusted publisher's app (never blocked).
    pub app: Option<String>,
}

/// A scan's outcome.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScanResult {
    /// What the parent hears about, one entry per name.
    pub found: Vec<FoundApp>,
    /// What was left out by rule 3, and why (for the log and `scan --dry-run`).
    pub skipped: Vec<(String, Skip)>,
    /// What rule 4 would have reported but `left_out` leaves out, and why.
    pub left_out: Vec<(String, LeftOut)>,
    /// Install folders of what was found and of what was left out as trusted.
    pub places: Vec<Place>,
}

/// Classifies merged candidates. Two apps reported under one name are one app on the parent's list, so they're
/// sent as one, with both sets of ids.
///
/// A candidate `left_out` leaves out keeps its place under its name: a program running from its folder is still an
/// app (one the parent hasn't listed, so App Approval holds it), not an unknown signed program that goes unchecked.
pub fn classify_all(classifier: &Classifier, cands: &[Candidate]) -> ScanResult {
    let mut found: BTreeMap<String, FoundApp> = BTreeMap::new();
    let mut skipped = Vec::new();
    let mut left = Vec::new();
    let mut places = Vec::new();
    for c in cands {
        let result = classifier.classify(c);
        if let Some(dir) = c.dir.as_deref().map(norm).filter(|d| !d.is_empty()) {
            match &result {
                Ok(app) => places.push(Place { dir, app: Some(app.app.clone()) }),
                Err(Skip::TrustedPublisher(_)) => places.push(Place { dir, app: None }),
                Err(Skip::BlankName) => {}
            }
        }
        // Only rule 4's candidates: a catalog game, a launcher's app and a trusted one are decided already
        let why = result.as_ref().ok().filter(|a| a.source == Some(AppSource::UnknownPublisher)).and_then(|_| left_out(c));
        if let Some(why) = why {
            left.push((c.name.clone(), why));
            continue;
        }
        match result {
            Ok(app) => match found.get_mut(&app.app) {
                Some(f) => {
                    for id in app.ids {
                        if f.ids.len() < wire::IDS_PER_APP_MAX && !f.ids.contains(&id) {
                            f.ids.push(id);
                        }
                    }
                    // A catalog or launcher match outranks an unknown-publisher one of the same name
                    if f.source == Some(AppSource::UnknownPublisher) && app.source != Some(AppSource::UnknownPublisher) {
                        f.source = app.source;
                        f.category = app.category;
                    }
                }
                None => {
                    found.insert(app.app.clone(), app);
                }
            },
            Err(why) => skipped.push((c.name.clone(), why)),
        }
    }
    ScanResult { found: found.into_values().collect(), skipped, left_out: left, places }
}

/// More new apps than this in one scan are sent as one `APPS_FOUND` (one alert) rather than an `APP_INSTALLED` each.
pub const NEW_APPS_AS_ONE: usize = 3;

/// What to tell the server after a scan. The first scan (no `previous`) sends everything as `APPS_FOUND`; later
/// scans send only apps not seen in the last one (spec section 5: "an ordinary `APP_INSTALLED`"). The server ignores
/// apps already on the child's list, so a repeat costs nothing but a request.
pub fn events(previous: Option<&BTreeMap<String, FoundApp>>, found: &[FoundApp]) -> Vec<DeviceEvent> {
    let new: Vec<FoundApp> = found.iter().filter(|a| previous.is_none_or(|p| !p.contains_key(&a.app))).cloned().collect();
    if new.is_empty() {
        return Vec::new();
    }
    if previous.is_none() || new.len() > NEW_APPS_AS_ONE {
        return DeviceEvent::apps_found(&new);
    }
    new.into_iter()
        .map(|a| DeviceEvent::AppInstalled { app: a.app, age_rating: None, ids: a.ids, source: a.source, category: a.category })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{AppIdKind, CatalogEntry};

    fn entry(kind: CatalogKind, match_type: MatchType, m: &str, display: Option<&str>) -> CatalogEntry {
        CatalogEntry {
            kind,
            match_type,
            match_value: m.into(),
            display_name: display.map(Into::into),
            category: display.map(|_| Category::Games),
            trending: false,
        }
    }

    fn classifier() -> Classifier {
        Classifier::new(&Catalog {
            kind: "eguard.desktop.catalog".into(),
            version: 1,
            entries: vec![
                entry(CatalogKind::Game, MatchType::LauncherId, "steam:730", Some("Counter-Strike 2")),
                entry(CatalogKind::Game, MatchType::ExeName, "robloxplayerbeta.exe", Some("Roblox")),
                entry(CatalogKind::Game, MatchType::Signer, "roblox corporation", Some("Roblox")),
                entry(CatalogKind::Game, MatchType::LauncherId, "msstore:microsoft.minecraftuwp_8wekyb3d8bbwe", Some("Minecraft")),
                entry(CatalogKind::TrustedPublisher, MatchType::Signer, "microsoft corporation", None),
                entry(CatalogKind::TrustedPublisher, MatchType::Signer, "nvidia corporation", None),
            ],
        })
    }

    #[allow(clippy::unnecessary_wraps)] // Shaped like `Candidate::exe`, to assign straight to it
    fn exe(name: &str, signer: Option<&str>, product: Option<&str>) -> Option<ExeFacts> {
        Some(ExeFacts {
            file_name: name.into(),
            signer: signer.map(Into::into),
            product: product.map(Into::into),
            graphics: false,
            ..ExeFacts::default()
        })
    }

    #[test]
    fn rule_1_catalog_games_come_first_even_from_trusted_publishers() {
        let c = classifier();
        let mut cs2 = Candidate::new("Counter-Strike Global Offensive", Origin::Launcher);
        cs2.launcher = Some(Launcher::Steam);
        cs2.ids = vec![AppId::new(AppIdKind::Steam, "730")];
        cs2.exe = exe("cs2.exe", Some("valve corp."), Some("Counter-Strike 2"));
        let app = c.classify(&cs2).unwrap();
        assert_eq!((app.app.as_str(), app.source, app.category), ("Counter-Strike 2", Some(AppSource::Catalog), Some(Category::Games)));
        assert_eq!(app.ids, vec![AppId::new(AppIdKind::Steam, "730"), AppId::exe(Some("valve corp."), "Counter-Strike 2")]);

        // Minecraft is Microsoft's (trusted), but the catalog lists it: reported
        let mut mc = Candidate::new("Minecraft for Windows", Origin::Store);
        mc.ids = vec![AppId::new(AppIdKind::Msstore, "Microsoft.MinecraftUWP_8wekyb3d8bbwe")];
        mc.other_signer = Some("microsoft corporation".into());
        assert_eq!(c.classify(&mc).unwrap().app, "Minecraft");

        // By signer, only when the signature is valid (an unsigned exe can't claim to be Roblox's)
        let mut r = Candidate::new("Roblox Player", Origin::Uninstall);
        r.exe = exe("robloxplayerlauncher.exe", Some("roblox corporation"), None);
        assert_eq!(c.classify(&r).unwrap().source, Some(AppSource::Catalog));
        r.exe = exe("robloxplayerlauncher.exe", None, None);
        assert_eq!(c.classify(&r).unwrap().source, Some(AppSource::UnknownPublisher));
    }

    #[test]
    fn rules_2_to_4() {
        let c = classifier();
        let mut steam_game = Candidate::new("Pixel Dungeon", Origin::Launcher);
        steam_game.launcher = Some(Launcher::Steam);
        steam_game.exe = exe("pd.exe", Some("microsoft corporation"), None);
        // Rule 2 before 3: through a launcher is a game, whoever signed it
        assert_eq!(c.classify(&steam_game).unwrap().source, Some(AppSource::Launcher));

        let mut office = Candidate::new("Microsoft 365", Origin::Uninstall);
        office.exe = exe("winword.exe", Some("microsoft corporation"), Some("Microsoft Office"));
        assert_eq!(c.classify(&office), Err(Skip::TrustedPublisher("microsoft corporation".into())));
        // An MSI's verified signer counts like the exe's
        let mut runtime = Candidate::new("Microsoft .NET Runtime", Origin::Uninstall);
        runtime.other_signer = Some("microsoft corporation".into());
        assert!(c.classify(&runtime).is_err());

        let mut itch = Candidate::new("Pixel Quest", Origin::UserFolder);
        itch.exe = exe("pixelquest.exe", None, Some("Pixel Quest"));
        itch.game_files = true;
        let app = c.classify(&itch).unwrap();
        assert_eq!((app.source, app.category), (Some(AppSource::UnknownPublisher), Some(Category::Games)));
        assert_eq!(app.ids, vec![AppId::new(AppIdKind::Exe, "|pixel quest")]);

        let mut tool = Candidate::new("7-Zip 25.01 (x64)", Origin::Uninstall);
        tool.exe = exe("7zfm.exe", None, Some("7-Zip"));
        assert_eq!(c.classify(&tool).unwrap().category, Some(Category::Other));
        // A signed but untrusted publisher is still unknown
        let mut tg = Candidate::new("Telegram Desktop", Origin::Uninstall);
        tg.exe = exe("telegram.exe", Some("telegram fz-llc"), Some("Telegram Desktop"));
        assert_eq!(c.classify(&tg).unwrap().source, Some(AppSource::UnknownPublisher));
        assert!(says_game("Some Game") && says_game("GAMES hub") && !says_game("Gamepad Tester"));
    }

    #[test]
    fn duplicates_merge_and_installed_apps_cover_their_shortcuts() {
        let mut un = Candidate::new("Telegram Desktop", Origin::Uninstall);
        un.dir = Some(r"C:\Users\mia\AppData\Roaming\Telegram Desktop\".into());
        let mut lnk = Candidate::new("Telegram", Origin::Shortcut);
        lnk.dir = Some(r"c:\users\mia\appdata\roaming\telegram desktop".into());
        lnk.exe = exe("telegram.exe", None, None);
        let mut loose = Candidate::new("Updater", Origin::UserFolder);
        loose.dir = Some(r"C:\Users\mia\AppData\Roaming\Telegram Desktop\tupdates".into());
        let mut other = Candidate::new("Pixel Quest", Origin::UserFolder);
        other.dir = Some(r"C:\Users\mia\Downloads\pixel-quest".into());
        let m = merge(vec![lnk, loose, other, un]);
        assert_eq!(m.iter().map(|c| c.name.as_str()).collect::<Vec<_>>(), ["Telegram Desktop", "Pixel Quest"]);

        // Same folder from two places: one app, the launcher's name, both ids
        let mut a = Candidate::new("Steam App 730", Origin::Uninstall);
        a.dir = Some(r"D:\Steam\steamapps\common\CS".into());
        a.ids = vec![AppId::new(AppIdKind::Steam, "730")];
        let mut b = Candidate::new("Counter-Strike 2", Origin::Launcher);
        b.dir = Some(r"d:\steam\steamapps\common\cs".into());
        b.launcher = Some(Launcher::Steam);
        let m = merge(vec![a, b]);
        assert_eq!(m.len(), 1);
        assert_eq!((m[0].name.as_str(), m[0].ids.len()), ("Counter-Strike 2", 1));
        assert!(inside(r"C:\A\B", r"c:\a") && !inside(r"C:\AB", r"C:\A"));
    }

    #[test]
    fn a_loose_exe_named_like_an_installed_app_is_that_app() {
        let installed = Candidate::new("7-Zip 25.01 (x64)", Origin::Uninstall);
        let mut setup = Candidate::new("7z2501-x64", Origin::UserFolder);
        setup.exe = exe("7z2501-x64.exe", None, Some("7-Zip"));
        let viber = Candidate::new("Viber", Origin::Uninstall);
        let mut lnk = Candidate::new("Viber(Compatibility Mode)", Origin::Shortcut);
        lnk.exe = exe("viber.exe", Some("viber media s.a r.l."), Some("Viber"));
        let gh = Candidate::new("GitHub CLI", Origin::Uninstall);
        let mut git = Candidate::new("Git", Origin::UserFolder);
        git.exe = exe("git-2.51.0-64-bit.exe", Some("johannes schindelin"), Some("Git"));
        let m = merge(vec![setup, lnk, git, installed, viber, gh]);
        let names: Vec<_> = m.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(names, ["7-Zip 25.01 (x64)", "Viber", "GitHub CLI", "Git"]);
        // The installed app takes the shortcut's exe, so it gets a signer and an EXE id
        assert_eq!(m[1].exe.as_ref().unwrap().file_name, "viber.exe");
        assert!(!names_match("Go", "Go Language") && names_match("Telegram", "Telegram Desktop"));
    }

    #[test]
    fn first_scan_is_one_apps_found_later_ones_only_whats_new() {
        let app =
            |n: &str| FoundApp { app: n.into(), ids: vec![], source: Some(AppSource::UnknownPublisher), category: Some(Category::Other) };
        let first = [app("A"), app("B")];
        let ev = events(None, &first);
        assert!(matches!(&ev[..], [DeviceEvent::AppsFound { apps }] if apps.len() == 2));
        let prev: BTreeMap<_, _> = first.iter().map(|a| (a.app.clone(), a.clone())).collect();
        assert_eq!(events(Some(&prev), &first), vec![]);
        let ev = events(Some(&prev), &[app("A"), app("C")]);
        assert!(matches!(&ev[..], [DeviceEvent::AppInstalled { app, .. }] if app == "C"));
        let many: Vec<_> = ["C", "D", "E", "F"].iter().map(|n| app(n)).collect();
        assert!(matches!(&events(Some(&prev), &many)[..], [DeviceEvent::AppsFound { apps }] if apps.len() == 4));

        // One name from two candidates is one app
        let c = classifier();
        let (mut x, mut y) = (Candidate::new("MongoDB Compass", Origin::Uninstall), Candidate::new("MongoDB Compass", Origin::Uninstall));
        x.dir = Some(r"C:\a".into());
        y.dir = Some(r"C:\b".into());
        assert_eq!(classify_all(&c, &[x, y]).found.len(), 1);
    }

    const DISCORD: &str = r"c:\users\mia\appdata\local\discord";

    fn names(found: &[FoundApp]) -> Vec<&str> {
        found.iter().map(|a| a.app.as_str()).collect()
    }

    #[test]
    fn installers_and_updaters_by_name() {
        for n in [
            "Update.exe",
            "updater.exe",
            "unins000.exe",
            "Uninstall.exe",
            "uninst.exe",
            "setup.exe",
            "Foo-Uninstaller.exe",
            "app_setup.exe",
        ] {
            assert!(is_maintenance_exe(n), "{n}");
        }
        for n in ["discord.exe", "crashpad_handler.exe", "setupapi-viewer.exe", "updatechecker.exe", "pixelquest.exe"] {
            assert!(!is_maintenance_exe(n), "{n}");
        }
    }

    #[test]
    fn a_squirrel_app_with_only_its_updater_left_is_left_out_but_its_folder_still_counts() {
        let c = classifier();
        // Discord uninstalled: Squirrel's Update.exe stays (it can reinstall it), the app-<version> folders are gone
        let mut leftover = Candidate::new("Discord", Origin::Shortcut);
        leftover.dir = Some(DISCORD.into());
        leftover.exe = exe("update.exe", Some("discord inc."), None);
        leftover.folder_exes = Some(vec!["update.exe".into()]);
        assert_eq!(left_out(&leftover), Some(LeftOut::Leftover));
        let r = classify_all(&c, std::slice::from_ref(&leftover));
        assert_eq!(r.found, vec![]);
        assert_eq!(r.left_out, vec![("Discord".into(), LeftOut::Leftover)]);
        // Whatever runs from there is still the app "Discord" for enforcement, not an unknown signed program
        assert_eq!(r.places, vec![Place { dir: DISCORD.into(), app: Some("Discord".into()) }]);

        // Installed: the shortcut resolves to app-1.0.9\Discord.exe, and the Uninstall entry's folder has it
        let mut lnk = Candidate::new("Discord", Origin::Shortcut);
        lnk.dir = Some(format!(r"{DISCORD}\app-1.0.9"));
        lnk.exe = exe("discord.exe", Some("discord inc."), Some("Discord"));
        lnk.folder_exes = Some(vec!["discord.exe".into()]);
        let mut un = Candidate::new("Discord", Origin::Uninstall);
        un.dir = Some(DISCORD.into());
        un.exe = exe("discord.exe", Some("discord inc."), Some("Discord"));
        un.folder_exes = Some(vec!["update.exe".into(), "discord.exe".into()]);
        assert_eq!(left_out(&lnk), None);
        assert_eq!(left_out(&un), None);
        assert_eq!(names(&classify_all(&c, &merge(vec![lnk, un])).found), ["Discord"]);
        // Even with no exe chosen, an app exe anywhere below the folder keeps it reported
        let mut no_exe = Candidate::new("Discord", Origin::Uninstall);
        no_exe.dir = Some(DISCORD.into());
        no_exe.folder_exes = Some(vec!["update.exe".into(), "discord.exe".into()]);
        assert_eq!(left_out(&no_exe), None);
    }

    #[test]
    fn a_leftover_needs_every_exe_to_be_maintenance_and_no_game_signal() {
        let mut c = Candidate::new("Pixel Quest", Origin::Uninstall);
        c.dir = Some(r"c:\users\mia\appdata\local\pq".into());
        // Not looked at, too many to tell, or none at all: not a leftover
        assert_eq!(left_out(&c), None);
        c.folder_exes = Some(vec![]);
        assert_eq!(left_out(&c), None);
        // A game renamed update.exe: its engine files or graphics imports keep it reported
        c.folder_exes = Some(vec!["update.exe".into()]);
        assert_eq!(left_out(&c), Some(LeftOut::Leftover));
        c.game_files = true;
        assert_eq!(left_out(&c), None);
        c.game_files = false;
        c.folder_graphics = true;
        assert_eq!(left_out(&c), None);
        c.folder_graphics = false;
        c.name = "Some Game".into();
        assert_eq!(left_out(&c), None);
        // A launcher's app or a loose exe never is
        c.name = "Pixel Quest".into();
        c.launcher = Some(Launcher::Steam);
        assert_eq!(left_out(&c), None);
        c.launcher = None;
        c.origin = Origin::UserFolder;
        assert_eq!(left_out(&c), None);
    }

    fn xprinter() -> Candidate {
        let mut c = Candidate::new("XPrinter Driver version 8.2", Origin::Uninstall);
        c.machine_wide = true;
        c
    }

    #[test]
    fn a_machine_wide_driver_package_is_left_out() {
        let c = classifier();
        // Its folder has the driver's .inf: left out, and the folder still counts as the app's
        let mut with_files = xprinter();
        with_files.dir = Some(r"c:\xinye pos printer driver\xprinter driver v8.2".into());
        with_files.exe = exe("xprintertool.exe", None, None);
        with_files.driver_files = true;
        let r = classify_all(&c, &[with_files]);
        assert_eq!(r.found, vec![]);
        assert_eq!(r.left_out, vec![("XPrinter Driver version 8.2".into(), LeftOut::Driver)]);
        assert_eq!(r.places[0].app.as_deref(), Some("XPrinter Driver version 8.2"));

        // Everything it names is gone (this PC's XPrinter entry): nothing to report
        let mut gone = xprinter();
        gone.gone = true;
        assert_eq!(left_out(&gone), Some(LeftOut::Driver));
        // ... unless something lent it an exe after all
        gone.exe = exe("xprinter.exe", None, None);
        assert_eq!(left_out(&gone), None);

        // Named a driver but nothing says it is one: reported
        assert_eq!(left_out(&xprinter()), None);
        // A trusted publisher's driver is still rule 3's (never blocked), not a left-out one
        let mut realtek = Candidate::new("Realtek Audio Driver", Origin::Uninstall);
        realtek.machine_wide = true;
        realtek.driver_files = true;
        realtek.exe = exe("rtkngui64.exe", Some("nvidia corporation"), None);
        assert!(matches!(c.classify(&realtek), Err(Skip::TrustedPublisher(_))));
    }

    #[test]
    fn a_child_cant_hide_a_game_by_calling_it_a_driver() {
        let c = classifier();
        // An HKCU entry (a standard account can write one) named like a driver, with an .inf beside the game
        let mut hkcu = Candidate::new("Pixel Quest Driver", Origin::Uninstall);
        hkcu.dir = Some(r"c:\users\mia\appdata\local\pq".into());
        hkcu.exe = exe("pq.exe", None, None);
        hkcu.driver_files = true;
        assert_eq!(left_out(&hkcu), None);
        // ... or one pointing at nothing
        let mut hkcu_gone = Candidate::new("Fortnite Driver", Origin::Uninstall);
        hkcu_gone.gone = true;
        assert_eq!(left_out(&hkcu_gone), None);
        // Machine-wide but with a game signal: reported, as a game
        let mut game = Candidate::new("X Driver", Origin::Uninstall);
        game.machine_wide = true;
        game.driver_files = true;
        game.exe = exe("x.exe", None, None);
        game.game_files = true;
        assert_eq!(left_out(&game), None);
        let app = c.classify(&game).unwrap();
        assert_eq!(classify_all(&c, &[hkcu, game]).found.len(), 2);
        assert_eq!(app.category, Some(Category::Games));
        // Merged with an HKCU entry for the same folder, it isn't machine-wide any more
        let mut a = xprinter();
        a.dir = Some(r"c:\d".into());
        a.driver_files = true;
        let mut b = Candidate::new("XPrinter Driver version 8.2", Origin::Uninstall);
        b.dir = Some(r"c:\d".into());
        let m = merge(vec![a, b]);
        assert_eq!((m.len(), left_out(&m[0])), (1, None));
    }
}
