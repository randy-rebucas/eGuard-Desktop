//! What game launchers leave on disk and in the registry, read without Windows (spec sections 5 and 6). The
//! platform finds the files; these functions say what they mean.

use super::vdf;
use crate::wire::{AppId, AppIdKind};

/// A game launcher. Anything installed through one is reported (rule 2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Launcher {
    Steam,
    Epic,
    Riot,
    BattleNet,
    Ea,
    Ubisoft,
    Gog,
    Itch,
}

/// Steam's library folders, from `steamapps\libraryfolders.vdf` (both the current and the pre-2021 layout).
pub fn steam_libraries(text: &str) -> Vec<String> {
    let doc = vdf::parse(text);
    let Some(folders) = doc.get("libraryfolders") else { return Vec::new() };
    folders
        .items()
        .iter()
        .filter(|(k, _)| k.chars().all(|c| c.is_ascii_digit()))
        .filter_map(|(_, v)| match v {
            vdf::Vdf::Str(path) => Some(path.clone()),
            obj @ vdf::Vdf::Obj(_) => obj.str("path").map(str::to_owned),
        })
        .collect()
}

/// One Steam app from `appmanifest_<id>.acf`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SteamApp {
    pub appid: String,
    pub name: String,
    /// The folder under `steamapps\common`.
    pub installdir: String,
}

/// Steam's own redistributables, installed with games: not an app anyone plays.
const STEAM_TOOLS: [&str; 2] = ["228980", "1070560"];

pub fn steam_app(text: &str) -> Option<SteamApp> {
    let doc = vdf::parse(text);
    let app = doc.get("appstate")?;
    let appid = app.str("appid")?.trim().to_owned();
    if appid.is_empty() || !appid.chars().all(|c| c.is_ascii_digit()) || STEAM_TOOLS.contains(&appid.as_str()) {
        return None;
    }
    Some(SteamApp { name: app.str("name").unwrap_or(&appid).trim().to_owned(), installdir: app.str("installdir")?.to_owned(), appid })
}

/// One Epic install, from `%ProgramData%\Epic\EpicGamesLauncher\Data\Manifests\*.item`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EpicApp {
    pub name: String,
    /// Epic's `AppName` (`Fortnite`, `Sugar`); the id is its lower case.
    pub app_name: String,
    pub install_location: String,
    /// Relative to `install_location`.
    pub launch_executable: Option<String>,
}

pub fn epic_item(json: &[u8]) -> Option<EpicApp> {
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "PascalCase")]
    struct Item {
        display_name: Option<String>,
        app_name: String,
        install_location: String,
        launch_executable: Option<String>,
        main_game_app_name: Option<String>,
        #[serde(rename = "bIsIncompleteInstall", default)]
        incomplete: bool,
    }
    let item: Item = serde_json::from_slice(json).ok()?;
    // DLC and add-ons carry their game's AppName as MainGameAppName: the game is reported, not each add-on
    if item.incomplete || item.main_game_app_name.as_deref().is_some_and(|m| !m.eq_ignore_ascii_case(&item.app_name)) {
        return None;
    }
    Some(EpicApp {
        name: item.display_name.unwrap_or_else(|| item.app_name.clone()),
        app_name: item.app_name,
        install_location: item.install_location,
        launch_executable: item.launch_executable.filter(|e| !e.is_empty()),
    })
}

/// `--name=value` or `--name value` from a command line.
fn flag<'a>(command: &'a str, name: &str) -> Option<&'a str> {
    let at = command.find(&format!("--{name}"))? + name.len() + 2;
    let rest = command[at..].strip_prefix('=').or_else(|| command[at..].strip_prefix(' '))?;
    let rest = rest.trim_start_matches('"');
    let end = rest.find(['"', ' ']).unwrap_or(rest.len());
    let v = &rest[..end];
    (!v.is_empty()).then_some(v)
}

/// What an Uninstall entry says about a launcher: which one installed it, and its id there when it says.
pub fn from_uninstall(key_name: &str, uninstall_string: &str, publisher: &str) -> Option<(Launcher, Option<AppId>)> {
    let key = key_name.to_ascii_lowercase();
    let cmd = uninstall_string.to_ascii_lowercase();
    if let Some(id) = key.strip_prefix("steam app ") {
        return Some((Launcher::Steam, Some(AppId::new(AppIdKind::Steam, id))));
    }
    if cmd.contains("riotclientservices.exe") {
        return Some((Launcher::Riot, flag(&cmd, "uninstall-product").map(|p| AppId::new(AppIdKind::Riot, p))));
    }
    if cmd.contains("blizzard uninstaller.exe") || cmd.contains("battle.net") && cmd.contains("--uid") {
        // `--uid=wow_enus`: the product, then the language
        let id = flag(&cmd, "uid").map(|u| u.split('_').next().unwrap_or(u).to_owned());
        return Some((Launcher::BattleNet, id.map(|p| AppId::new(AppIdKind::Battlenet, &p))));
    }
    if let Some(id) = key.strip_prefix("uplay install ") {
        return Some((Launcher::Ubisoft, Some(AppId::new(AppIdKind::Ubisoft, id))));
    }
    if publisher.eq_ignore_ascii_case("gog.com") {
        let id = key.strip_suffix("_is1").filter(|id| id.chars().all(|c| c.is_ascii_digit()));
        return Some((Launcher::Gog, id.map(|id| AppId::new(AppIdKind::Gog, id))));
    }
    if cmd.contains(r"\eainstaller\") {
        return Some((Launcher::Ea, None));
    }
    None
}

/// The registry's packed form of an MSI product code, as under `Installer\UserData\<sid>\Products`: each of the
/// first three groups reversed, then each byte of the rest with its two digits swapped.
pub fn msi_packed_guid(product_code: &str) -> Option<String> {
    let hex: String = product_code.chars().filter(char::is_ascii_hexdigit).collect();
    if hex.len() != 32 || !product_code.trim().starts_with('{') {
        return None;
    }
    let rev = |s: &str| s.chars().rev().collect::<String>();
    let mut out = format!("{}{}{}", rev(&hex[0..8]), rev(&hex[8..12]), rev(&hex[12..16]));
    for pair in hex.as_bytes()[16..].chunks(2) {
        out.push(char::from(pair[1]));
        out.push(char::from(pair[0]));
    }
    Some(out.to_ascii_uppercase())
}

/// A Store package's family name (`Name_PublisherId`) from its full name (`Name_Version_Arch_ResourceId_PublisherId`).
/// `None` for resource packages (a non-empty `ResourceId`: languages, scales), which aren't apps of their own.
pub fn store_family(full_name: &str) -> Option<String> {
    let parts: Vec<&str> = full_name.split('_').collect();
    let [name, _version, _arch, resource, publisher] = parts[..] else { return None };
    (resource.is_empty() && !name.is_empty() && !publisher.is_empty()).then(|| format!("{name}_{publisher}").to_ascii_lowercase())
}

/// The organisation in a package's publisher (`CN=Microsoft Corporation, O=Microsoft Corporation, …`), else its
/// common name, lower case. A Store-signed package's publisher is a bare GUID: that names nobody.
pub fn publisher_name(dn: &str) -> Option<String> {
    let mut cn = None;
    let mut o = None;
    // Values may be quoted and contain commas: `CN="Anthropic, PBC", O="Anthropic, PBC"`
    let mut rest = dn.trim();
    while !rest.is_empty() {
        let (key, after) = rest.split_once('=')?;
        let after = after.trim_start();
        let (value, next) = if let Some(q) = after.strip_prefix('"') {
            let end = q.find('"')?;
            (&q[..end], q[end + 1..].trim_start_matches([',', ' ']))
        } else {
            let end = after.find(',').unwrap_or(after.len());
            (after[..end].trim(), after[end..].trim_start_matches([',', ' ']))
        };
        match key.trim().to_ascii_uppercase().as_str() {
            "O" => o = Some(value),
            "CN" => cn = Some(value),
            _ => {}
        }
        rest = next;
    }
    let name = o.or(cn)?;
    let guid = name.len() == 36 && name.chars().all(|c| c.is_ascii_hexdigit() || c == '-');
    (!guid && !name.is_empty()).then(|| name.to_lowercase())
}

/// What a Store package's `AppxManifest.xml` says about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreManifest {
    pub name: String,
    /// The publisher's distinguished name (`CN=…, O=…`), as signed.
    pub publisher: String,
    pub publisher_display_name: Option<String>,
    pub display_name: Option<String>,
    /// A framework (runtime) package, not an app.
    pub framework: bool,
    /// The first application's executable, relative to the package folder.
    pub executable: Option<String>,
}

fn unescape(s: &str) -> String {
    s.replace("&quot;", "\"").replace("&apos;", "'").replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&")
}

/// `attr="value"` inside the first `<tag …>` (any namespace prefix).
fn attr(xml: &str, tag: &str, attr: &str) -> Option<String> {
    let start = xml.find(&format!("<{tag} ")).or_else(|| xml.find(&format!(":{tag} ")))?;
    let end = start + xml[start..].find('>')?;
    let el = &xml[start..end];
    let at = el.find(&format!(" {attr}=\""))? + attr.len() + 3;
    let len = el[at..].find('"')?;
    Some(unescape(&el[at..at + len]))
}

/// The text of the first `<tag>…</tag>`.
fn text(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let at = xml.find(&open)? + open.len();
    let len = xml[at..].find('<')?;
    let t = unescape(xml[at..at + len].trim());
    (!t.is_empty()).then_some(t)
}

pub fn store_manifest(xml: &str) -> Option<StoreManifest> {
    Some(StoreManifest {
        name: attr(xml, "Identity", "Name")?,
        publisher: attr(xml, "Identity", "Publisher")?,
        publisher_display_name: text(xml, "PublisherDisplayName"),
        display_name: text(xml, "DisplayName"),
        framework: text(xml, "Framework").is_some_and(|f| f.eq_ignore_ascii_case("true")),
        executable: attr(xml, "Application", "Executable"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn store_manifests() {
        let xml = r#"<?xml version="1.0"?><Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10">
  <Identity Name="Microsoft.MinecraftUWP" Publisher="CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond" Version="1.21.0.0" />
  <Properties><DisplayName>Minecraft</DisplayName><PublisherDisplayName>Microsoft Studios</PublisherDisplayName></Properties>
  <Applications><Application Id="App" Executable="Minecraft.Windows.exe" EntryPoint="x"/></Applications></Package>"#;
        let m = store_manifest(xml).unwrap();
        assert_eq!(m.name, "Microsoft.MinecraftUWP");
        assert_eq!(publisher_name(&m.publisher).as_deref(), Some("microsoft corporation"));
        assert_eq!(
            (m.display_name.as_deref(), m.executable.as_deref(), m.framework),
            (Some("Minecraft"), Some("Minecraft.Windows.exe"), false)
        );
        let fw = r#"<Package><Identity Name="Microsoft.VCLibs" Publisher="CN=Microsoft Corporation"/><Properties><Framework>true</Framework></Properties></Package>"#;
        assert!(store_manifest(fw).unwrap().framework);
        let quoted = r#"<Identity Name="Claude" Publisher="CN=&quot;Anthropic, PBC&quot;, O=&quot;Anthropic, PBC&quot;"/>"#;
        assert_eq!(publisher_name(&store_manifest(quoted).unwrap().publisher).as_deref(), Some("anthropic, pbc"));
        assert_eq!(store_manifest("<nothing/>"), None);
    }

    #[test]
    fn steam_apps_and_libraries() {
        let lib = "\"libraryfolders\" { \"contentstatsid\" \"1\" \"0\" { \"path\" \"C:\\\\Steam\" } \"1\" \"E:\\\\Old Library\" }";
        assert_eq!(steam_libraries(lib), [r"C:\Steam", r"E:\Old Library"]);
        let acf = "\"AppState\" { \"appid\" \"730\" \"name\" \"Counter-Strike 2\" \"installdir\" \"Counter-Strike Global Offensive\" }";
        assert_eq!(
            steam_app(acf).unwrap(),
            SteamApp { appid: "730".into(), name: "Counter-Strike 2".into(), installdir: "Counter-Strike Global Offensive".into() }
        );
        assert_eq!(steam_app("\"AppState\" { \"appid\" \"228980\" \"installdir\" \"Steamworks Shared\" }"), None);
    }

    #[test]
    fn epic_items_skip_add_ons_and_half_installs() {
        let game = br#"{"DisplayName":"Fortnite","AppName":"Fortnite","MainGameAppName":"Fortnite","InstallLocation":"C:\\Program Files\\Epic Games\\Fortnite","LaunchExecutable":"FortniteGame/Binaries/Win64/FortniteClient-Win64-Shipping.exe","bIsIncompleteInstall":false}"#;
        let app = epic_item(game).unwrap();
        assert_eq!((app.name.as_str(), app.app_name.as_str()), ("Fortnite", "Fortnite"));
        let dlc = br#"{"DisplayName":"Pack","AppName":"abc","MainGameAppName":"Fortnite","InstallLocation":"C:\\x"}"#;
        assert_eq!(epic_item(dlc), None);
        let half = br#"{"AppName":"Sugar","InstallLocation":"C:\\x","bIsIncompleteInstall":true}"#;
        assert_eq!(epic_item(half), None);
        assert_eq!(epic_item(b"not json"), None);
    }

    #[test]
    fn launcher_ids_from_uninstall_entries() {
        let id = |kind, v| Some(AppId::new(kind, v));
        assert_eq!(
            from_uninstall("Steam App 730", "\"C:\\Steam\\steam.exe\" steam://uninstall/730", "Valve"),
            Some((Launcher::Steam, id(AppIdKind::Steam, "730")))
        );
        assert_eq!(
            from_uninstall(
                "Riot Game valorant.live",
                r#""C:\Riot Games\Riot Client\RiotClientServices.exe" --uninstall-product=valorant --uninstall-patchline=live"#,
                "Riot Games, Inc"
            ),
            Some((Launcher::Riot, id(AppIdKind::Riot, "valorant")))
        );
        assert_eq!(
            from_uninstall(
                "World of Warcraft",
                r#""C:\ProgramData\Battle.net\Agent\Blizzard Uninstaller.exe" --lang=enUS --uid=wow_enus --displayname="World of Warcraft""#,
                "Blizzard Entertainment"
            ),
            Some((Launcher::BattleNet, id(AppIdKind::Battlenet, "wow")))
        );
        assert_eq!(from_uninstall("Uplay Install 635", "x", "Ubisoft"), Some((Launcher::Ubisoft, id(AppIdKind::Ubisoft, "635"))));
        assert_eq!(from_uninstall("1207658924_is1", "unins000.exe", "GOG.com"), Some((Launcher::Gog, id(AppIdKind::Gog, "1207658924"))));
        assert_eq!(
            from_uninstall("{A}", r"C:\Program Files\Common Files\EAInstaller\Apex\Cleanup.exe uninstall_game", "Electronic Arts"),
            Some((Launcher::Ea, None))
        );
        assert_eq!(from_uninstall("7-Zip", r"C:\Program Files\7-Zip\Uninstall.exe", "Igor Pavlov"), None);
    }

    #[test]
    fn msi_product_codes_pack_like_windows() {
        // 12345678 ABCD EF01 reversed, then 23 45 67 89 AB CD EF 01 with each pair swapped
        assert_eq!(msi_packed_guid("{12345678-ABCD-EF01-2345-6789ABCDEF01}").as_deref(), Some("87654321DCBA10FE32547698BADCFE10"));
        assert_eq!(msi_packed_guid("not a guid"), None);
    }

    #[test]
    fn store_names_and_publishers() {
        assert_eq!(
            store_family("Microsoft.MinecraftUWP_1.21.0.0_x64__8wekyb3d8bbwe").as_deref(),
            Some("microsoft.minecraftuwp_8wekyb3d8bbwe")
        );
        assert_eq!(store_family("5319275A.WhatsAppDesktop_2.2623.103.0_neutral_split.scale-100_cv1g1gvanyjgm"), None);
        assert_eq!(
            publisher_name("CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US").as_deref(),
            Some("microsoft corporation")
        );
        assert_eq!(publisher_name(r#"CN="Anthropic, PBC", O="Anthropic, PBC", L=San Francisco"#).as_deref(), Some("anthropic, pbc"));
        assert_eq!(publisher_name("CN=24803D75-212C-471A-BC57-9EF86AB91435"), None);
    }
}
