//! Finding installed apps on this computer (spec section 5, "Where the agent looks"). Everything here only reads.
//!
//! - Uninstall keys: HKLM (both views) and each signed-in user's hive. System components, updates, and entries
//!   living under the Windows folder (drivers, Windows' own) are left out.
//! - Launchers: Steam's libraries, Epic's manifests, GOG's registry, itch's apps folder; Riot, Battle.net,
//!   Ubisoft and EA through their Uninstall entries.
//! - Store packages of each signed-in user, read from their manifests.
//! - Start Menu shortcuts, and exes in each user's Downloads, Desktop and `AppData`.
//!
//! Each candidate's main exe is checked once (signature, product name, imports) and cached by path, volume and file
//! id, size and modification time. Users whose hive isn't loaded (not signed in) are seen through their folders only.

use crate::registry::{Key, Root, View};
use crate::{authenticode, version};
use eguard_core::scan::launchers::{self, Launcher};
use eguard_core::scan::{CachedExe, Candidate, ExeCache, ExeFacts, Origin, pe};
use eguard_core::wire::{AppId, AppIdKind};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

const UNINSTALL: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
const PROFILES: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList";
const STORE_REPO: &str = r"Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages";
/// Most exes looked at in users' folders in one scan. A folder full of thousands is someone's build output.
const MAX_LOOSE_EXES: usize = 3_000;
/// How much of an exe is read to find its imports: import tables sit near the start.
const PE_READ_BYTES: u64 = 32 * 1024 * 1024;

/// A Windows account with a profile.
#[derive(Debug, Clone)]
pub struct User {
    pub sid: String,
    pub profile: PathBuf,
}

/// Real accounts (`S-1-5-21-…`) with a profile folder.
pub fn users() -> Vec<User> {
    let Some(list) = Key::open(Root::LocalMachine, PROFILES, View::Native) else { return Vec::new() };
    list.subkeys()
        .into_iter()
        .filter(|sid| sid.starts_with("S-1-5-21-"))
        .filter_map(|sid| {
            let profile = PathBuf::from(list.sub(&sid, View::Native)?.string("ProfileImagePath")?);
            profile.is_dir().then_some(User { sid, profile })
        })
        .collect()
}

fn lower(p: &Path) -> String {
    p.to_string_lossy().trim_end_matches('\\').to_lowercase()
}

/// What one scan found, and how much work it took.
#[derive(Debug, Default)]
pub struct Collected {
    pub candidates: Vec<Candidate>,
    pub exes_checked: usize,
    pub cache_hits: usize,
    /// Folders whose changes mean a rescan (Steam libraries, Epic's manifests), for the watcher.
    pub watch_dirs: Vec<PathBuf>,
}

struct Collector<'a> {
    cache: &'a mut ExeCache,
    used: HashSet<String>,
    system_root: String,
    /// Folders that hold many apps, never one app's install folder.
    broad: HashSet<String>,
    out: Collected,
    loose_exes: usize,
}

/// A path from the registry: quotes off, a trailing `,0` icon index off, variables already expanded by the reader.
fn clean_path(s: &str) -> Option<PathBuf> {
    let s = s.trim().trim_matches('"');
    let s = match s.rsplit_once(',') {
        Some((p, idx)) if idx.trim().trim_start_matches('-').chars().all(|c| c.is_ascii_digit()) => p.trim().trim_matches('"'),
        _ => s,
    };
    (!s.is_empty()).then(|| PathBuf::from(s))
}

/// The program a command line runs (`"C:\x\unins000.exe" /S` → `C:\x\unins000.exe`).
fn command_exe(cmd: &str) -> Option<PathBuf> {
    let cmd = cmd.trim();
    let path = if let Some(rest) = cmd.strip_prefix('"') {
        &rest[..rest.find('"')?]
    } else {
        let end = cmd.to_ascii_lowercase().find(".exe")? + 4;
        &cmd[..end]
    };
    Some(PathBuf::from(path))
}

fn is_exe(p: &Path) -> bool {
    p.extension().is_some_and(|e| e.eq_ignore_ascii_case("exe"))
}

/// Helpers, installers and uninstallers: never an app's main exe, and not an app of their own in a user's folders.
fn is_helper(file_name: &str) -> bool {
    let n = file_name.to_ascii_lowercase();
    ["unins", "uninst", "setup", "install", "update", "crash", "helper", "elevat", "repair", "squirrel"].iter().any(|w| n.contains(w))
}

/// The generic hosts Windows runs uninstallers through: they say nothing about whose app it is.
fn is_host(p: &Path) -> bool {
    p.file_name().is_some_and(|f| matches!(f.to_string_lossy().to_ascii_lowercase().as_str(), "msiexec.exe" | "rundll32.exe"))
}

/// A Squirrel install (Discord, Wispr Flow): its shortcut runs `Update.exe`, which starts the app in the newest
/// `app-<version>` folder beside it. The app's exe is that one.
fn squirrel_app(exe: &Path) -> Option<PathBuf> {
    if !exe.file_name()?.to_string_lossy().eq_ignore_ascii_case("update.exe") {
        return None;
    }
    let root = exe.parent()?;
    let newest = std::fs::read_dir(root)
        .ok()?
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().starts_with("app-") && e.path().is_dir())
        .max_by_key(|e| e.metadata().and_then(|m| m.modified()).ok())?;
    main_exe(&newest.path(), &root.file_name()?.to_string_lossy(), 1)
}

/// A folder's name as an app's: `bin`, `x64` or `app-1.4.5` say nothing, so their parent's name instead.
fn app_folder_name(dir: &Path) -> String {
    let name = dir.file_name().map(|f| f.to_string_lossy().into_owned()).unwrap_or_default();
    let l = name.to_ascii_lowercase();
    let generic =
        l.starts_with("app-") || ["bin", "app", "x64", "x86", "win64", "win32", "release", "current", "dist"].contains(&l.as_str());
    match dir.parent().filter(|_| generic) {
        Some(parent) => parent.file_name().map_or(name, |f| f.to_string_lossy().into_owned()),
        None => name,
    }
}

/// Letters and digits only, lower case, for comparing names.
fn squash(s: &str) -> String {
    s.chars().filter(char::is_ascii_alphanumeric).collect::<String>().to_ascii_lowercase()
}

/// Exes in `dir`, down to `depth` levels.
fn exes_in(dir: &Path, depth: usize, limit: usize) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![(dir.to_owned(), 0)];
    while let Some((d, level)) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&d) else { continue };
        for e in entries.flatten() {
            let Ok(t) = e.file_type() else { continue };
            let p = e.path();
            if t.is_dir() && !t.is_symlink() && level + 1 < depth {
                stack.push((p, level + 1));
            } else if t.is_file() && is_exe(&p) {
                out.push(p);
                if out.len() >= limit {
                    return out;
                }
            }
        }
    }
    out
}

/// The app's own exe in its folder: one whose name is in the app's name, else the largest that isn't a helper.
fn main_exe(dir: &Path, name: &str, depth: usize) -> Option<PathBuf> {
    let want = squash(name);
    let mut exes: Vec<(PathBuf, u64)> = exes_in(dir, depth, 400)
        .into_iter()
        .filter(|p| p.file_name().is_some_and(|f| !is_helper(&f.to_string_lossy())))
        .map(|p| {
            let size = std::fs::metadata(&p).map_or(0, |m| m.len());
            (p, size)
        })
        .collect();
    exes.sort_by_key(|(_, size)| std::cmp::Reverse(*size));
    let named = exes.iter().find(|(p, _)| {
        let stem = squash(&p.file_stem().unwrap_or_default().to_string_lossy());
        stem.len() >= 3 && want.contains(&stem)
    });
    named.or(exes.first()).map(|(p, _)| p.clone())
}

/// Signature, product name and imports of one file, checked now (callers cache it by path, size and time).
pub fn exe_facts(path: &Path) -> ExeFacts {
    let graphics = read_head(path).and_then(|b| pe::imports(&b)).is_some_and(|dlls| dlls.iter().any(|d| pe::is_graphics_import(d)));
    let signer = authenticode::signer_names(path);
    ExeFacts {
        file_name: path.file_name().map(|f| f.to_string_lossy().to_lowercase()).unwrap_or_default(),
        signer: signer.as_ref().and_then(|s| s.name().map(str::to_owned)),
        signer_alt: signer.as_ref().and_then(|s| s.alternative().map(str::to_owned)),
        product: if is_exe(path) { version::product_name(path) } else { None },
        graphics,
    }
}

/// Which file a path names right now, and its version: what a cached verdict about a file is kept against.
///
/// Size and modification time alone can be copied onto another file (`SetFileTime` and padding), which would hand a
/// trusted file's verdict to a different one put at the same path. The volume and file id can't: a file put there
/// in place of the old one has its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileIdentity {
    /// The volume's serial number.
    pub volume: u64,
    /// The file's id on that volume (128-bit on `ReFS`; NTFS's 64-bit index otherwise).
    pub file_id: u128,
    pub size: u64,
    /// Last written, in milliseconds since 1970.
    pub modified_ms: i64,
}

impl FileIdentity {
    /// The volume and file id as text, for caches keyed by strings.
    pub fn tag(&self) -> String {
        format!("{:016x}:{:032x}", self.volume, self.file_id)
    }
}

/// The identity of the file at `path`, read from one open handle so all of it is about the same file. `None` for
/// a folder, or a file that can't be opened.
#[allow(unsafe_code)]
pub fn file_identity(path: &Path) -> Option<FileIdentity> {
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, FILE_ID_INFO, FILE_READ_ATTRIBUTES, FileIdInfo, GetFileInformationByHandle,
        GetFileInformationByHandleEx,
    };
    // Attributes only: enough for the id, and works on a file the caller may not read
    let f = std::fs::OpenOptions::new().access_mode(FILE_READ_ATTRIBUTES).open(path).ok()?;
    let meta = f.metadata().ok().filter(std::fs::Metadata::is_file)?;
    let h = f.as_raw_handle() as HANDLE;
    let mut info = FILE_ID_INFO::default();
    // SAFETY: `h` is the open file; `info` is a live FILE_ID_INFO and its size is passed.
    let ex = unsafe { GetFileInformationByHandleEx(h, FileIdInfo, (&raw mut info).cast(), size_of::<FILE_ID_INFO>() as u32) } != 0;
    let (volume, file_id) = if ex {
        (info.VolumeSerialNumber, u128::from_le_bytes(info.FileId.Identifier))
    } else {
        let mut b = BY_HANDLE_FILE_INFORMATION::default();
        // SAFETY: `h` is the open file; `b` is a live out-parameter.
        if unsafe { GetFileInformationByHandle(h, &raw mut b) } == 0 {
            return None;
        }
        (u64::from(b.dwVolumeSerialNumber), (u128::from(b.nFileIndexHigh) << 32) | u128::from(b.nFileIndexLow))
    };
    let modified_ms = meta.modified().ok().and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()).map_or(0, |d| d.as_millis() as i64);
    Some(FileIdentity { volume, file_id, size: meta.len(), modified_ms })
}

/// Engine and anti-cheat files beside an exe (spec section 5, game signals).
fn game_files(exe: &Path) -> bool {
    if exe.file_name().is_some_and(|f| f.to_string_lossy().to_ascii_lowercase().ends_with("-shipping.exe")) {
        return true;
    }
    let Some(dir) = exe.parent() else { return false };
    let Ok(entries) = std::fs::read_dir(dir) else { return false };
    entries.flatten().take(2_000).any(|e| {
        let n = e.file_name().to_string_lossy().to_ascii_lowercase();
        matches!(
            n.as_str(),
            "unityplayer.dll"
                | "gameassembly.dll"
                | "steam_api.dll"
                | "steam_api64.dll"
                | "easyanticheat"
                | "battleye"
                | "start_protected_game.exe"
        ) || ["eossdk", "ue4", "ue5", "easyanticheat", "beservice"].iter().any(|p| n.starts_with(p))
    })
}

impl Collector<'_> {
    fn under_windows(&self, p: &Path) -> bool {
        let l = lower(p);
        l == self.system_root || l.starts_with(&format!("{}\\", self.system_root))
    }

    /// An install folder worth keying an app by: exists, isn't one of the shared roots, isn't Windows'.
    fn install_dir(&self, p: &Path) -> Option<PathBuf> {
        let l = lower(p);
        (p.is_dir() && !self.broad.contains(&l) && l.len() > 3 && !self.under_windows(p)).then(|| p.to_owned())
    }

    /// Signature, product name and imports of `path`, from the cache when it's still the same file, unchanged.
    fn facts(&mut self, path: &Path) -> Option<ExeFacts> {
        let id = file_identity(path)?;
        // The file's identity is part of the key: another file put at this path is checked afresh
        let key = format!("{}|{}", lower(path), id.tag());
        self.used.insert(key.clone());
        if let Some(c) = self.cache.get(&key).filter(|c| c.size == id.size && c.modified_ms == id.modified_ms) {
            self.out.cache_hits += 1;
            return Some(c.facts.clone());
        }
        self.out.exes_checked += 1;
        let facts = exe_facts(path);
        // Kept only when the file checked is still the one identified before (not swapped while it was read)
        if file_identity(path) == Some(id) {
            self.cache.insert(key, CachedExe { size: id.size, modified_ms: id.modified_ms, facts: facts.clone() });
        }
        Some(facts)
    }

    fn with_exe(&mut self, c: &mut Candidate, exe: &Path) {
        c.exe = self.facts(exe);
        c.game_files = c.game_files || game_files(exe);
    }

    fn uninstall_keys(&mut self, key: &Key, view: View, msi_sid: &str) {
        for name in key.subkeys() {
            let Some(e) = key.sub(&name, view) else { continue };
            let Some(display) = e.string("DisplayName") else { continue };
            let release = e.string("ReleaseType").unwrap_or_default().to_ascii_lowercase();
            if e.dword("SystemComponent") == Some(1)
                || e.string("ParentKeyName").is_some()
                || release.contains("update")
                || release.contains("hotfix")
            {
                continue;
            }
            let uninstall = e.string("UninstallString").or_else(|| e.string("QuietUninstallString")).unwrap_or_default();
            // Removed by a program of Windows' own (not the generic MSI or DLL hosts): part of Windows, or a driver
            if command_exe(&uninstall).is_some_and(|p| self.under_windows(&p) && !is_host(&p)) {
                continue;
            }
            let mut c = Candidate::new(&display, Origin::Uninstall);
            if let Some((launcher, id)) = launchers::from_uninstall(&name, &uninstall, &e.string("Publisher").unwrap_or_default()) {
                c.launcher = Some(launcher);
                c.ids.extend(id);
            }
            let location = e.string("InstallLocation").map(PathBuf::from).filter(|p| p.is_dir());
            if location.as_deref().is_some_and(|p| self.under_windows(p)) {
                continue;
            }
            let icon = e.string("DisplayIcon").and_then(|s| clean_path(&s)).filter(|p| is_exe(p) && p.is_file());
            let exe = icon
                .filter(|p| p.file_name().is_some_and(|f| !is_helper(&f.to_string_lossy())))
                .or_else(|| location.as_deref().and_then(|d| main_exe(d, &display, 2)));
            if exe.as_deref().is_some_and(|p| self.under_windows(p)) {
                continue;
            }
            if let Some(exe) = &exe {
                self.with_exe(&mut c, exe);
            }
            // Evidence of who made it when the main exe says nothing: the uninstaller's signature, or the cached MSI's
            let uninstaller = command_exe(&uninstall).filter(|p| p.is_file() && !self.under_windows(p));
            let msi = (e.dword("WindowsInstaller") == Some(1)).then(|| msi_package(&name, msi_sid)).flatten();
            for evidence in [uninstaller, msi].into_iter().flatten() {
                if c.exe.as_ref().and_then(|x| x.signer.as_ref()).is_some() || c.other_signer.is_some() {
                    break;
                }
                c.other_signer = self.facts(&evidence).and_then(|f| f.signer);
            }
            c.dir = location
                .as_deref()
                .and_then(|d| self.install_dir(d))
                .or_else(|| exe.as_deref().and_then(Path::parent).and_then(|d| self.install_dir(d)))
                .map(|d| lower(&d));
            self.out.candidates.push(c);
        }
    }

    fn steam(&mut self, roots: &[PathBuf]) {
        let mut libraries: Vec<PathBuf> = Vec::new();
        for root in roots {
            let vdf = root.join("steamapps").join("libraryfolders.vdf");
            libraries.push(root.clone());
            if let Ok(text) = std::fs::read_to_string(&vdf) {
                libraries.extend(launchers::steam_libraries(&text).into_iter().map(PathBuf::from));
            }
        }
        let mut seen = HashSet::new();
        for lib in libraries.into_iter().filter(|l| seen.insert(lower(l))) {
            let apps = lib.join("steamapps");
            let Ok(entries) = std::fs::read_dir(&apps) else { continue };
            self.out.watch_dirs.push(apps.clone());
            for e in entries.flatten() {
                let n = e.file_name().to_string_lossy().to_ascii_lowercase();
                if !(n.starts_with("appmanifest_") && Path::new(&n).extension().is_some_and(|x| x.eq_ignore_ascii_case("acf"))) {
                    continue;
                }
                let Some(app) = std::fs::read_to_string(e.path()).ok().and_then(|t| launchers::steam_app(&t)) else { continue };
                let dir = apps.join("common").join(&app.installdir);
                let mut c = Candidate::new(&app.name, Origin::Launcher);
                c.launcher = Some(Launcher::Steam);
                c.ids.push(AppId::new(AppIdKind::Steam, &app.appid));
                if let Some(exe) = main_exe(&dir, &app.name, 3) {
                    self.with_exe(&mut c, &exe);
                }
                c.dir = Some(lower(&dir));
                self.out.candidates.push(c);
            }
        }
    }

    fn epic(&mut self) {
        let dir = PathBuf::from(std::env::var_os("ProgramData").unwrap_or_else(|| r"C:\ProgramData".into()))
            .join(r"Epic\EpicGamesLauncher\Data\Manifests");
        let Ok(entries) = std::fs::read_dir(&dir) else { return };
        self.out.watch_dirs.push(dir);
        for e in entries.flatten() {
            if !e.file_name().to_string_lossy().to_ascii_lowercase().ends_with(".item") {
                continue;
            }
            let Some(app) = std::fs::read(e.path()).ok().and_then(|b| launchers::epic_item(&b)) else { continue };
            let mut c = Candidate::new(&app.name, Origin::Launcher);
            c.launcher = Some(Launcher::Epic);
            c.ids.push(AppId::new(AppIdKind::Epic, &app.app_name));
            let location = PathBuf::from(&app.install_location);
            let exe = app.launch_executable.map(|x| location.join(x)).filter(|p| p.is_file()).or_else(|| main_exe(&location, &app.name, 3));
            if let Some(exe) = exe {
                self.with_exe(&mut c, &exe);
            }
            c.dir = Some(lower(&location));
            self.out.candidates.push(c);
        }
    }

    fn gog(&mut self) {
        let Some(games) = Key::open(Root::LocalMachine, r"SOFTWARE\GOG.com\Games", View::Wow32) else { return };
        for id in games.subkeys() {
            let Some(g) = games.sub(&id, View::Wow32) else { continue };
            let Some(name) = g.string("gameName") else { continue };
            let mut c = Candidate::new(&name, Origin::Launcher);
            c.launcher = Some(Launcher::Gog);
            c.ids.push(AppId::new(AppIdKind::Gog, &id));
            if let Some(exe) = g.string("exe").map(PathBuf::from).filter(|p| p.is_file()) {
                self.with_exe(&mut c, &exe);
            }
            c.dir = g.string("path").map(|p| lower(Path::new(&p)));
            self.out.candidates.push(c);
        }
    }

    fn itch(&mut self, user: &User) {
        let apps = user.profile.join(r"AppData\Roaming\itch\apps");
        let Ok(entries) = std::fs::read_dir(&apps) else { return };
        self.out.watch_dirs.push(apps);
        for e in entries.flatten().filter(|e| e.file_type().is_ok_and(|t| t.is_dir())) {
            let name = e.file_name().to_string_lossy().into_owned();
            let mut c = Candidate::new(&name, Origin::Launcher);
            c.launcher = Some(Launcher::Itch);
            if let Some(exe) = main_exe(&e.path(), &name, 3) {
                self.with_exe(&mut c, &exe);
            }
            c.dir = Some(lower(&e.path()));
            self.out.candidates.push(c);
        }
    }

    fn store(&mut self, sid: &str) {
        let Some(repo) = Key::open(Root::Users, &format!(r"{sid}_Classes\{STORE_REPO}"), View::Native) else { return };
        let mut families = HashSet::new();
        for full in repo.subkeys() {
            let Some(family) = launchers::store_family(&full) else { continue };
            let Some(pkg) = repo.sub(&full, View::Native) else { continue };
            let Some(root) = pkg.string("PackageRootFolder").map(PathBuf::from) else { continue };
            if self.under_windows(&root) || !families.insert(family.clone()) {
                continue;
            }
            let Some(m) = std::fs::read_to_string(root.join("AppxManifest.xml")).ok().and_then(|x| launchers::store_manifest(&x)) else {
                continue;
            };
            let Some(exe) = m.executable.as_ref().map(|e| root.join(e)) else { continue };
            if m.framework {
                continue;
            }
            // Signed by the Store, the publisher is a bare GUID and the Store's verified display name says who
            let signer = launchers::publisher_name(&m.publisher).or_else(|| m.publisher_display_name.as_deref().map(str::to_lowercase));
            let name = [pkg.string("DisplayName"), m.display_name.clone()]
                .into_iter()
                .flatten()
                .find_map(|d| store_text(&full, &m.name, &d))
                .unwrap_or_else(|| m.name.clone());
            let mut c = Candidate::new(&name, Origin::Store);
            c.ids.push(AppId::new(AppIdKind::Msstore, &family));
            c.other_signer.clone_from(&signer);
            if exe.is_file() {
                let mut facts = self.facts(&exe).unwrap_or_default();
                // The package's signature covers its files: an exe without its own is the publisher's
                if facts.signer.is_none() {
                    facts.signer = signer;
                }
                c.exe = Some(facts);
                c.game_files = game_files(&exe);
            }
            c.dir = Some(lower(&root));
            self.out.candidates.push(c);
        }
    }

    fn shortcuts(&mut self, dir: &Path) {
        let mut stack = vec![(dir.to_owned(), 0)];
        while let Some((d, level)) = stack.pop() {
            let Ok(entries) = std::fs::read_dir(&d) else { continue };
            for e in entries.flatten() {
                let p = e.path();
                if e.file_type().is_ok_and(|t| t.is_dir()) {
                    if level < 3 {
                        stack.push((p, level + 1));
                    }
                    continue;
                }
                if !p.extension().is_some_and(|x| x.eq_ignore_ascii_case("lnk")) {
                    continue;
                }
                let name = p.file_stem().unwrap_or_default().to_string_lossy().into_owned();
                if name.to_ascii_lowercase().contains("uninstall") {
                    continue;
                }
                let Some(target) = std::fs::read(&p).ok().and_then(|b| launchers_lnk(&b)) else { continue };
                let app = squirrel_app(&target);
                // A Squirrel updater whose app is gone: the shortcut's name is all there is to go on
                let updater_only = app.is_none() && target.file_name().is_some_and(|f| f.eq_ignore_ascii_case("update.exe"));
                let target = app.unwrap_or(target);
                if !is_exe(&target) || !target.is_file() || self.under_windows(&target) {
                    continue;
                }
                let mut c = Candidate::new(&name, Origin::Shortcut);
                self.with_exe(&mut c, &target);
                if let Some(e) = c.exe.as_mut().filter(|_| updater_only) {
                    e.product = None;
                }
                c.dir = target.parent().and_then(|d| self.install_dir(d)).map(|d| lower(&d));
                self.out.candidates.push(c);
            }
        }
    }

    /// Exes in a user's own folders, one candidate per folder (its main exe).
    fn user_folder(&mut self, root: &Path, depth: usize) {
        const SKIP: [&str; 14] = [
            "microsoft",
            "packages",
            "temp",
            "cache",
            "caches",
            "node_modules",
            ".git",
            "crashdumps",
            "d3dscache",
            "package cache",
            "npm-cache",
            "pip",
            "squirrel",
            "crashpad",
        ];
        let mut by_dir: HashMap<PathBuf, Vec<PathBuf>> = HashMap::new();
        let mut stack = vec![(root.to_owned(), 0)];
        while let Some((d, level)) = stack.pop() {
            let Ok(entries) = std::fs::read_dir(&d) else { continue };
            for e in entries.flatten() {
                if self.loose_exes >= MAX_LOOSE_EXES {
                    break;
                }
                let Ok(t) = e.file_type() else { continue };
                let p = e.path();
                let n = e.file_name().to_string_lossy().to_ascii_lowercase();
                if t.is_dir() && !t.is_symlink() {
                    if level + 1 < depth && !SKIP.contains(&n.as_str()) {
                        stack.push((p, level + 1));
                    }
                } else if t.is_file() && is_exe(&p) && !is_helper(&n) {
                    self.loose_exes += 1;
                    by_dir.entry(d.clone()).or_default().push(p);
                }
            }
        }
        for (dir, exes) in by_dir {
            let is_root = lower(&dir) == lower(root);
            // Loose in Downloads or the Desktop: each exe is its own app; in a folder of its own: the folder is one
            let groups: Vec<Vec<PathBuf>> = if is_root { exes.into_iter().map(|e| vec![e]).collect() } else { vec![exes] };
            for group in groups {
                let folder = app_folder_name(&dir);
                let exe = if group.len() == 1 { group[0].clone() } else { main_exe(&dir, &folder, 1).unwrap_or_else(|| group[0].clone()) };
                let stem = exe.file_stem().unwrap_or_default().to_string_lossy().into_owned();
                let mut c = Candidate::new(&stem, Origin::UserFolder);
                self.with_exe(&mut c, &exe);
                let product = c.exe.as_ref().and_then(|f| f.product.clone()).filter(|p| p.len() >= 2);
                c.name = product.unwrap_or(if is_root { stem } else { folder });
                c.dir = if is_root { None } else { self.install_dir(&dir).map(|d| lower(&d)) };
                self.out.candidates.push(c);
            }
        }
    }
}

/// A Store package's name as people read it. Packages name themselves with resource references: `ms-resource:Name`
/// means the package's `Resources/Name`, `ms-resource:Dir/Name` its `Dir/Name`; the shell looks them up.
fn store_text(full_name: &str, package: &str, s: &str) -> Option<String> {
    let reference = if s.starts_with('@') {
        s.to_owned()
    } else if let Some(r) = s.strip_prefix("ms-resource:") {
        let uri = if r.starts_with("//") {
            format!("ms-resource:{r}")
        } else if r.contains('/') {
            format!("ms-resource://{package}/{r}")
        } else {
            format!("ms-resource://{package}/Resources/{r}")
        };
        format!("@{{{full_name}?{uri}}}")
    } else {
        return Some(s.to_owned());
    };
    crate::shell::indirect_string(&reference).filter(|t| !t.starts_with("ms-resource:") && !t.starts_with('@'))
}

fn launchers_lnk(b: &[u8]) -> Option<PathBuf> {
    eguard_core::scan::lnk::target(b).map(PathBuf::from)
}

/// The start of a file, for its PE headers and import table.
fn read_head(path: &Path) -> Option<Vec<u8>> {
    use std::io::Read;
    let mut b = Vec::new();
    std::fs::File::open(path).ok()?.take(PE_READ_BYTES).read_to_end(&mut b).ok()?;
    Some(b)
}

/// The cached copy of an MSI product's package (`C:\Windows\Installer\*.msi`), which keeps its signature.
fn msi_package(product_code: &str, sid: &str) -> Option<PathBuf> {
    let packed = launchers::msi_packed_guid(product_code)?;
    let path = format!(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\{sid}\Products\{packed}\InstallProperties");
    let p = PathBuf::from(Key::open(Root::LocalMachine, &path, View::Native)?.string("LocalPackage")?);
    p.is_file().then_some(p)
}

/// Every installed app this account can see. `cache` is updated: entries this scan didn't use are dropped.
pub fn collect(cache: &mut ExeCache) -> Collected {
    let system_root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into()).trim_end_matches('\\').to_lowercase();
    let users = users();
    let mut broad: HashSet<String> = ["ProgramFiles", "ProgramFiles(x86)", "ProgramData", "SystemDrive"]
        .iter()
        .filter_map(std::env::var_os)
        .map(|p| lower(Path::new(&p)))
        .collect();
    broad.insert(r"c:\program files\common files".into());
    broad.insert(r"c:\program files (x86)\common files".into());
    for u in &users {
        for sub in ["", "AppData", r"AppData\Local", r"AppData\Roaming", r"AppData\Local\Programs", "Desktop", "Downloads", "Documents"] {
            broad.insert(lower(&u.profile.join(sub)));
        }
    }
    let mut c = Collector { cache, used: HashSet::new(), system_root, broad, out: Collected::default(), loose_exes: 0 };

    for view in [View::Native, View::Wow32] {
        if let Some(k) = Key::open(Root::LocalMachine, UNINSTALL, view) {
            c.uninstall_keys(&k, view, "S-1-5-18");
        }
    }
    let mut steam_roots: Vec<PathBuf> = Key::open(Root::LocalMachine, r"SOFTWARE\Valve\Steam", View::Wow32)
        .and_then(|k| k.string("InstallPath"))
        .map(PathBuf::from)
        .into_iter()
        .collect();
    for u in &users {
        // Signed-in users' hives are loaded under HKEY_USERS; others' registry can't be read without loading it
        if let Some(k) = Key::open(Root::Users, &format!(r"{}\{UNINSTALL}", u.sid), View::Native) {
            c.uninstall_keys(&k, View::Native, &u.sid);
        }
        if let Some(p) =
            Key::open(Root::Users, &format!(r"{}\Software\Valve\Steam", u.sid), View::Native).and_then(|k| k.string("SteamPath"))
        {
            steam_roots.push(PathBuf::from(p.replace('/', "\\")));
        }
        c.store(&u.sid);
    }
    c.steam(&steam_roots);
    c.epic();
    c.gog();
    let program_data = PathBuf::from(std::env::var_os("ProgramData").unwrap_or_else(|| r"C:\ProgramData".into()));
    c.shortcuts(&program_data.join(r"Microsoft\Windows\Start Menu\Programs"));
    for u in &users {
        c.itch(u);
        c.shortcuts(&u.profile.join(r"AppData\Roaming\Microsoft\Windows\Start Menu\Programs"));
        for (sub, depth) in [("Downloads", 2), ("Desktop", 2), (r"AppData\Local", 3), (r"AppData\Roaming", 3)] {
            c.user_folder(&u.profile.join(sub), depth);
        }
    }
    let used = std::mem::take(&mut c.used);
    c.cache.retain(|k, _| used.contains(k));
    c.out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_paths_and_command_lines() {
        assert_eq!(clean_path(r#""C:\Program Files\7-Zip\7zFM.exe",0"#), Some(PathBuf::from(r"C:\Program Files\7-Zip\7zFM.exe")));
        assert_eq!(clean_path(r"C:\x\app.exe,-101"), Some(PathBuf::from(r"C:\x\app.exe")));
        assert_eq!(clean_path(r"C:\Program Files, Inc\a.exe"), Some(PathBuf::from(r"C:\Program Files, Inc\a.exe")));
        assert_eq!(
            command_exe(r#""C:\Program Files\Ollama\unins000.exe" /SILENT"#),
            Some(PathBuf::from(r"C:\Program Files\Ollama\unins000.exe"))
        );
        assert_eq!(command_exe(r"C:\Program Files\Foo\uninstall.exe /S"), Some(PathBuf::from(r"C:\Program Files\Foo\uninstall.exe")));
        assert_eq!(command_exe("MsiExec.exe /X{1}"), Some(PathBuf::from("MsiExec.exe")));
        assert!(is_helper("unins000.exe") && is_helper("ChromeSetup.exe") && !is_helper("PixelQuest.exe"));
    }

    #[test]
    fn a_file_put_in_another_place_has_another_identity_even_with_the_same_size_and_time() {
        let dir = std::env::temp_dir().join(format!("eguard-identity-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (a, b) = (dir.join("a.exe"), dir.join("b.exe"));
        std::fs::write(&a, b"MZ one").unwrap();
        std::fs::write(&b, b"MZ two").unwrap();
        let first = file_identity(&a).unwrap();
        assert_eq!(file_identity(&a), Some(first));
        assert_eq!(first.size, 6);
        // b gets a's modification time, then takes a's place
        let t = std::fs::metadata(&a).unwrap().modified().unwrap();
        std::fs::File::options().write(true).open(&b).unwrap().set_modified(t).unwrap();
        std::fs::rename(&b, &a).unwrap();
        let second = file_identity(&a).unwrap();
        assert_eq!((second.size, second.modified_ms), (first.size, first.modified_ms));
        assert_ne!(second.tag(), first.tag());
        assert_eq!(file_identity(&dir), None);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn this_pc_has_users_and_apps() {
        assert!(!users().is_empty());
        let mut cache = ExeCache::new();
        let first = collect(&mut cache);
        assert!(first.candidates.len() > 10, "{}", first.candidates.len());
        assert!(first.candidates.iter().all(|c| c.dir.as_deref().is_none_or(|d| !d.starts_with(r"c:\windows\"))));
        // A second scan checks nothing again
        let second = collect(&mut cache);
        assert_eq!(second.exes_checked, 0);
        assert_eq!(second.candidates.len(), first.candidates.len());
    }
}
