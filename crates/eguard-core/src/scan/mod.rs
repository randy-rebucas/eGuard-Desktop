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

/// True when `name` has "game" or "games" as a word.
fn says_game(name: &str) -> bool {
    name.to_lowercase().split(|c: char| !c.is_alphanumeric()).any(|w| w == "game" || w == "games")
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

/// True when `dir` is under `C:\Program Files` or `C:\Program Files (x86)`, where a standard account can't write.
/// `merge`'s guess when the platform doesn't say (`merge_with`); a Windows on another drive only means more loose
/// exes are reported.
pub fn in_default_program_files(dir: &str) -> bool {
    let d = norm(dir);
    [r"c:\program files", r"c:\program files (x86)"].iter().any(|pf| d == *pf || d.starts_with(&format!(r"{pf}\")))
}

/// True when `loose`'s exe was signed by a signer of `installed`'s, so it may be taken for part of that app. An app
/// whose signer isn't known only takes an unsigned exe, or one it lends its exe to (it then reports that exe's
/// signer, so nothing is hidden).
fn signers_agree(loose: &Candidate, installed: &Candidate) -> bool {
    let theirs: Vec<&str> = installed.signers().collect();
    let mut mine = loose.signers().peekable();
    if theirs.is_empty() {
        return mine.peek().is_none() || installed.exe.is_none();
    }
    mine.any(|s| theirs.contains(&s))
}

/// True when the loose `l`, inside `installed`'s folder, is part of that app and so not reported on its own: the
/// folder is out of the child's reach (`admin_only`), or `l` carries the app's own signature. Anywhere else the child
/// can drop a game into an installed app's folder.
fn covered_by(l: &Candidate, installed: &Candidate, admin_only: &impl Fn(&str) -> bool) -> bool {
    let (Some(d), Some(od)) = (l.dir.as_deref(), installed.dir.as_deref()) else { return false };
    if is_loose(installed) || !inside(d, od) {
        return false;
    }
    admin_only(od) || (installed.signers().next().is_some() && signers_agree(l, installed))
}

/// One candidate per app:
/// - the same install folder found twice is one app (the earlier origin's name, every id);
/// - a shortcut or loose exe inside an installed app's folder is that app, when the folder is under Program Files
///   or the exe carries the app's signature (elsewhere the child could hide a game there);
/// - a shortcut or loose exe named like an installed app, signed by the same signer, is that app (its installer left
///   in Downloads, a Start Menu entry for an app whose folder wasn't known), and lends it its exe.
///
/// Program Files is guessed (`in_default_program_files`); `merge_with` takes the platform's answer.
pub fn merge(cands: Vec<Candidate>) -> Vec<Candidate> {
    merge_with(cands, in_default_program_files)
}

/// `merge`, with `admin_only` saying which folders a standard account can't write to.
pub fn merge_with(cands: Vec<Candidate>, admin_only: impl Fn(&str) -> bool) -> Vec<Candidate> {
    let mut out = merge_by_dir(cands, &admin_only);
    let (loose, mut installed): (Vec<_>, Vec<_>) = out.drain(..).partition(is_loose);
    let mut rest = Vec::new();
    for l in loose {
        let product = l.exe.as_ref().and_then(|e| e.product.clone()).unwrap_or_default();
        // A signed game renamed "Microsoft.exe" isn't Microsoft Edge
        let named_like = |i: &Candidate| (names_match(&l.name, &i.name) || names_match(&product, &i.name)) && signers_agree(&l, i);
        match installed.iter_mut().find(|i| named_like(i)) {
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

fn merge_by_dir(mut cands: Vec<Candidate>, admin_only: &impl Fn(&str) -> bool) -> Vec<Candidate> {
    cands.sort_by_key(|c| c.origin);
    let mut out: Vec<Candidate> = Vec::new();
    let mut by_dir: HashMap<String, usize> = HashMap::new();
    for c in cands {
        let loose = is_loose(&c);
        if loose && out.iter().any(|o| covered_by(&c, o, admin_only)) {
            continue;
        }
        // A loose exe that isn't covered stays its own app even in an installed app's very folder
        let same_dir = c.dir.as_deref().map(norm).and_then(|d| by_dir.get(&d).copied()).filter(|&i| !loose || is_loose(&out[i]));
        if let Some(i) = same_dir {
            let o = &mut out[i];
            o.ids.extend(c.ids);
            o.launcher = o.launcher.or(c.launcher);
            if o.exe.is_none() {
                o.exe = c.exe;
            }
            o.other_signer = o.other_signer.take().or(c.other_signer);
            o.game_files |= c.game_files;
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
    /// Install folders of what was found and of what was left out as trusted.
    pub places: Vec<Place>,
}

/// Classifies merged candidates. Two apps reported under one name are one app on the parent's list, so they're
/// sent as one, with both sets of ids.
pub fn classify_all(classifier: &Classifier, cands: &[Candidate]) -> ScanResult {
    let mut found: BTreeMap<String, FoundApp> = BTreeMap::new();
    let mut skipped = Vec::new();
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
    ScanResult { found: found.into_values().collect(), skipped, places }
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
            version: "1".into(),
            issued_at: None,
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
        let names = |m: &[Candidate]| m.iter().map(|c| c.name.clone()).collect::<Vec<_>>();
        // The folder is the child's to write to and the app's signer isn't known: the loose exe in it is still
        // reported (it may be a game put there); the shortcut, named like the app, lends it its exe
        let m = merge(vec![lnk.clone(), loose.clone(), other.clone(), un.clone()]);
        assert_eq!(names(&m), ["Telegram Desktop", "Updater", "Pixel Quest"]);
        assert_eq!(m[0].exe.as_ref().unwrap().file_name, "telegram.exe");
        // Signed by the app's signer, it's part of the app
        un.exe = exe("telegram.exe", Some("telegram fz-llc"), None);
        let mut signed = loose.clone();
        signed.exe = exe("updater.exe", Some("telegram fz-llc"), None);
        let mut game = Candidate::new("Shooter", Origin::UserFolder);
        game.dir = loose.dir.clone();
        game.exe = exe("shooter.exe", Some("shooter studio"), None);
        assert_eq!(names(&merge(vec![signed, game, un.clone()])), ["Telegram Desktop", "Shooter"]);
        // Under Program Files the child can't put anything there
        let mut pf = un.clone();
        pf.dir = Some(r"C:\Program Files\Telegram Desktop".into());
        loose.dir = Some(r"C:\Program Files\Telegram Desktop\tupdates".into());
        assert_eq!(names(&merge(vec![loose, other, pf])), ["Telegram Desktop", "Pixel Quest"]);
        assert!(in_default_program_files(r"C:\Program Files (x86)\Steam") && !in_default_program_files(r"D:\Program Files\x"));

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
    fn a_loose_exe_named_like_an_app_with_another_signer_stays_its_own() {
        let mut edge = Candidate::new("Microsoft Edge", Origin::Uninstall);
        edge.exe = exe("msedge.exe", Some("microsoft corporation"), Some("Microsoft Edge"));
        let mut signed = Candidate::new("Microsoft", Origin::UserFolder);
        signed.exe = exe("microsoft.exe", Some("shooter studio"), None);
        let mut unsigned = Candidate::new("Microsoft Edge Setup", Origin::UserFolder);
        unsigned.exe = exe("setup.exe", None, Some("Microsoft Edge"));
        let mut real = Candidate::new("MicrosoftEdgeSetup", Origin::UserFolder);
        real.exe = exe("microsoftedgesetup.exe", Some("microsoft corporation"), Some("Microsoft Edge"));
        let m = merge(vec![signed, unsigned, real, edge]);
        assert_eq!(m.iter().map(|c| c.name.as_str()).collect::<Vec<_>>(), ["Microsoft Edge", "Microsoft", "Microsoft Edge Setup"]);
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
}
