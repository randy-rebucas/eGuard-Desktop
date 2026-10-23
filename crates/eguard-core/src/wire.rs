//! The device API (`/api/device/v1`) as the eGuard server speaks it: field names, enums and casing exactly as in
//! `~/eguard/src/app/api/device/v1/*` and docs/desktop-agent-spec.md section 12.
//!
//! Responses tolerate fields this build doesn't know (the server may add some), and enums have an `Unknown`
//! fallback so one new value can't make a whole `/sync` unreadable; `SyncResponse::parse` reads the protections one
//! at a time for the same reason. What an unknown value means for enforcement is decided in `rules`, always toward
//! more protection.
//!
//! What goes out is cut to the server's limits as the server measures them: JavaScript string lengths (UTF-16 code
//! units) after JavaScript's `trim()`.

use serde::{Deserialize, Serialize};

/// The longest app name the server accepts (`/events`, `/usage`).
pub const APP_NAME_MAX: usize = 80;
/// Most apps in one `APPS_FOUND` event or one `/usage` report.
pub const APPS_PER_MESSAGE_MAX: usize = 200;
/// Most ids on one app (`AppIds` in app-identity.ts).
pub const IDS_PER_APP_MAX: usize = 8;

/// The longest app id `value` the server accepts (`AppIds` in app-identity.ts).
pub const APP_ID_MAX: usize = 200;
/// The longest `error` beside a reported protection (`/report`).
pub const REPORT_ERROR_MAX: usize = 200;

/// Whitespace as JavaScript's `String.prototype.trim()` sees it, which is what the server's `z.string().trim()` strips.
/// It differs from Rust's `char::is_whitespace`: it includes U+FEFF and leaves U+0085 alone.
pub fn is_js_whitespace(c: char) -> bool {
    matches!(
        c,
        '\u{9}'..='\u{D}'
            | ' '
            | '\u{A0}'
            | '\u{1680}'
            | '\u{2000}'..='\u{200A}'
            | '\u{2028}'
            | '\u{2029}'
            | '\u{202F}'
            | '\u{205F}'
            | '\u{3000}'
            | '\u{FEFF}'
    )
}

/// Trims `s` the way the server does (`is_js_whitespace`).
pub fn js_trim(s: &str) -> &str {
    s.trim_matches(is_js_whitespace)
}

/// The longest start of `s` that is at most `max` UTF-16 code units: the server's limits are JavaScript string
/// lengths, so a character outside the Basic Multilingual Plane (an emoji) counts as two. Cuts between characters.
pub fn cut_utf16(s: &str, max: usize) -> &str {
    let mut units = 0;
    for (i, c) in s.char_indices() {
        units += c.len_utf16();
        if units > max {
            return &s[..i];
        }
    }
    s
}

/// Trims `s` and cuts it to `max` UTF-16 units, as the server measures; `None` when nothing is left (the server
/// answers 400 for a blank string).
pub fn fit(s: &str, max: usize) -> Option<String> {
    let s = js_trim(cut_utf16(js_trim(s), max));
    (!s.is_empty()).then(|| s.to_owned())
}

/// Trims an app name and cuts it to what the server accepts. `None` for a blank name (the server answers 400).
pub fn app_name(name: &str) -> Option<String> {
    fit(name, APP_NAME_MAX)
}

/* ---------- Shared enums ---------- */

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Platform {
    Windows,
    Macos,
    Android,
    Ios,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DeviceKind {
    Phone,
    Tablet,
    Computer,
}

/// An app rule's approval. `Unknown` (a value newer than this build) is enforced as blocked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Approval {
    Allowed,
    AlwaysAllowed,
    Filtered,
    Blocked,
    Pending,
    #[serde(other)]
    Unknown,
}

/// An app's category. `Unknown` counts as `Other`, and is sent as `OTHER`: the server accepts only the categories it
/// lists (`CATEGORY_KEYS`), and one unknown value would get a whole `APPS_FOUND` refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Category {
    Games,
    Social,
    Video,
    Messaging,
    Education,
    Creativity,
    Browsers,
    Other,
    #[serde(other, rename(serialize = "OTHER"))]
    Unknown,
}

impl Category {
    #[must_use]
    /// The category a limit is counted under: an unknown one is `Other`, as for an app not on the list yet.
    pub fn effective(self) -> Self {
        if self == Self::Unknown { Self::Other } else { self }
    }
}

/// Where a stable app id comes from (`AppIdentifierKind`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AppIdKind {
    Steam,
    Epic,
    Riot,
    Battlenet,
    Ea,
    Ubisoft,
    Gog,
    Msstore,
    Exe,
    Package,
    Bundle,
    #[serde(other)]
    Unknown,
}

/// A stable identifier for an app on this platform (spec section 6). `value` is lower case; for `Exe` it is
/// `<signer>|<product name>`, with the signer empty when unsigned.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct AppId {
    pub kind: AppIdKind,
    pub value: String,
}

impl AppId {
    /// An id as the server takes it: trimmed, lower case, and cut to `APP_ID_MAX` UTF-16 units. A longer one would
    /// get the whole message refused (up to 200 apps, or the day's `/usage`), and an unsigned exe's product name is
    /// whatever its maker wrote.
    pub fn new(kind: AppIdKind, value: &str) -> Self {
        let lower = js_trim(value).to_lowercase();
        Self { kind, value: js_trim(cut_utf16(&lower, APP_ID_MAX)).to_owned() }
    }

    /// The `EXE` id: `<signer>|<product name>`, lower case, the signer empty when the exe is unsigned.
    pub fn exe(signer: Option<&str>, product: &str) -> Self {
        Self::new(AppIdKind::Exe, &format!("{}|{}", signer.unwrap_or("").trim(), product.trim()))
    }

    /// Same id, ignoring case (the server compares lower case).
    pub fn same_as(&self, other: &AppId) -> bool {
        self.kind == other.kind && self.value.eq_ignore_ascii_case(&other.value)
    }
}

/// How the agent found an app (spec section 5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AppSource {
    Catalog,
    Launcher,
    UnknownPublisher,
}

/* ---------- Protections ---------- */

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProtectionKey {
    ScreenTime,
    Bedtime,
    AppRestrictions,
    AppApproval,
    Content,
    Web,
    Downloads,
    Location,
    Notifications,
    UninstallProtection,
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BedtimeDays {
    EveryDay,
    SchoolNights,
    /// Newer than this build: enforced as `EveryDay`, the stricter reading.
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum WebMode {
    Off,
    Filter,
    Allowlist,
    #[serde(other)]
    Unknown,
}

/// One protection's settings (`ProtectionConfig` in protections.ts), tagged by `key`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "key", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProtectionConfig {
    #[serde(rename_all = "camelCase")]
    ScreenTime {
        daily_minutes: u32,
        weekend_minutes: u32,
    },
    Bedtime {
        enabled: bool,
        start: String,
        end: String,
        days: BedtimeDays,
    },
    #[serde(rename_all = "camelCase")]
    AppRestrictions {
        max_age_rating: u32,
    },
    AppApproval {
        enabled: bool,
    },
    #[serde(rename_all = "camelCase")]
    Content {
        max_age_rating: u32,
    },
    #[serde(rename_all = "camelCase")]
    Web {
        mode: WebMode,
        blocked_sites: u64,
    },
    #[serde(rename_all = "camelCase")]
    Downloads {
        require_approval: bool,
    },
    Location {
        sharing: bool,
    },
    #[serde(rename_all = "camelCase")]
    Notifications {
        quiet_during_bedtime: bool,
    },
    UninstallProtection {
        enabled: bool,
    },
    /// A protection newer than this build (only an unknown `key` lands here). Not enforced, not reported. A known
    /// protection whose fields don't parse is a serde error instead: `SyncResponse::parse` keeps the last good config.
    #[serde(other)]
    Unknown,
}

impl ProtectionConfig {
    pub fn key(&self) -> ProtectionKey {
        match self {
            Self::ScreenTime { .. } => ProtectionKey::ScreenTime,
            Self::Bedtime { .. } => ProtectionKey::Bedtime,
            Self::AppRestrictions { .. } => ProtectionKey::AppRestrictions,
            Self::AppApproval { .. } => ProtectionKey::AppApproval,
            Self::Content { .. } => ProtectionKey::Content,
            Self::Web { .. } => ProtectionKey::Web,
            Self::Downloads { .. } => ProtectionKey::Downloads,
            Self::Location { .. } => ProtectionKey::Location,
            Self::Notifications { .. } => ProtectionKey::Notifications,
            Self::UninstallProtection { .. } => ProtectionKey::UninstallProtection,
            Self::Unknown => ProtectionKey::Unknown,
        }
    }

    /// The config as `/report` wants it: the same fields without `key` (the server adds it back).
    pub fn report_config(&self) -> serde_json::Value {
        let mut v = serde_json::to_value(self).unwrap_or_default();
        if let Some(o) = v.as_object_mut() {
            o.remove("key");
        }
        v
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyEntry {
    pub key: ProtectionKey,
    pub config: ProtectionConfig,
}

/// A parent's change this device hasn't verified yet: apply, read back, report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfigRequest {
    pub id: String,
    pub key: ProtectionKey,
    pub config: ProtectionConfig,
}

/* ---------- /pair ---------- */

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PairRequest {
    pub code: String,
    pub platform: Platform,
    pub name: String,
    pub model: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<DeviceKind>,
    pub os_version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_version: Option<String>,
}

/// `201` from `/pair`. `token` and `removal_secret` are sent once: store both before anything else.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PairResponse {
    pub device_id: String,
    pub token: String,
    pub child_name: String,
    /// Computers only. base64url of 32 bytes, the key for offline removal codes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub removal_secret: Option<String>,
}

impl std::fmt::Debug for PairResponse {
    // Secrets never reach logs
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PairResponse")
            .field("device_id", &self.device_id)
            .field("token", &"<redacted>")
            .field("child_name", &self.child_name)
            .field("removal_secret", &self.removal_secret.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

/* ---------- /sync ---------- */

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub battery: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_version: Option<String>,
}

/// A rule for one app, from all of the child's devices.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppRule {
    pub name: String,
    pub approval: Approval,
    pub daily_limit_minutes: Option<u32>,
    #[serde(default = "other_category")]
    pub category: Category,
    /// Computers only: ids to match running processes against, before the name.
    #[serde(default)]
    pub ids: Vec<AppId>,
}

fn other_category() -> Category {
    Category::Other
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CategoryLimit {
    pub category: Category,
    pub daily_limit_minutes: u32,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Features {
    #[serde(default)]
    pub location_sharing: bool,
    #[serde(default)]
    pub category_limits: bool,
}

/// The signed uninstall command as `/sync` carries it. Verify with `signature::verify_uninstall` before trusting.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedEnvelope {
    pub command: serde_json::Value,
    pub signature: String,
    pub key_id: String,
}

/// `/sync`'s answer. Parse it from the raw `serde_json::Value` (keep that too: signatures are checked on the raw
/// JSON, never on a re-serialized struct).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncResponse {
    pub device_id: String,
    pub child_name: String,
    pub policy: Vec<PolicyEntry>,
    pub requests: Vec<ConfigRequest>,
    pub apps: Vec<AppRule>,
    #[serde(default)]
    pub category_limits: Vec<CategoryLimit>,
    pub extra_time_until: Option<String>,
    pub full_report_requested: bool,
    pub next_sync_seconds: u32,
    pub timezone: String,
    #[serde(default)]
    pub features: Features,
    pub min_app_version: Option<String>,
    /// Computers only: eGuard's clock (spec section 8).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_time: Option<String>,
    /// Computers only: `null`, or the signed uninstall command while a removal waits.
    #[serde(default)]
    pub uninstall: Option<SignedEnvelope>,
    /// Computers only: what the eGuard extension's managed policy carries so browsers pair as part of this computer
    /// (spec section 9). `null` while a removal waits. Phase 5 uses it.
    #[serde(default)]
    pub browser_link: Option<BrowserLink>,
}

impl SyncResponse {
    /// Reads `/sync`'s answer one protection at a time, so one bad field can't make the whole answer unreadable (and
    /// leave every change from the parent unapplied). A policy entry whose config doesn't parse keeps `previous`'s
    /// config for that key (fail closed), or with none the strict one where there is one (approval on), else is left
    /// out; a config request that doesn't parse is left out. Each is a note for the log. Anything else that doesn't
    /// parse is an error, and the last good sync stays in force.
    ///
    /// Signatures (the uninstall command) are checked on `raw` itself, never on what this returns.
    pub fn parse(raw: &serde_json::Value, previous: Option<&SyncResponse>) -> Result<(Self, Vec<String>), serde_json::Error> {
        use serde::de::Error as _;
        use serde_json::Value;
        let mut rest = raw.clone();
        let obj = rest.as_object_mut().ok_or_else(|| serde_json::Error::custom("the answer isn't an object"))?;
        let policy = obj.insert("policy".into(), Value::Array(Vec::new()));
        let requests = obj.insert("requests".into(), Value::Array(Vec::new()));
        let (Some(Value::Array(policy)), Some(Value::Array(requests))) = (policy, requests) else {
            return Err(serde_json::Error::custom("policy and requests must be lists"));
        };
        let mut sync: Self = serde_json::from_value(rest)?;
        let mut notes = Vec::new();
        for item in policy {
            let key = item_key(&item);
            match serde_json::from_value::<PolicyEntry>(normalized(item)) {
                Ok(entry) => sync.policy.push(entry),
                Err(e) => {
                    let kept = previous
                        .and_then(|p| p.policy.iter().find(|p| p.key == key && key != ProtectionKey::Unknown))
                        .cloned()
                        .or_else(|| strictest(key).map(|config| PolicyEntry { key, config }));
                    notes.push(format!(
                        "the {} protection from eGuard didn't parse ({e}); {}",
                        key_name(key),
                        if kept.is_some() { "the last good settings stay in force" } else { "left out" }
                    ));
                    sync.policy.extend(kept);
                }
            }
        }
        for item in requests {
            let key = item_key(&item);
            match serde_json::from_value::<ConfigRequest>(normalized(item)) {
                Ok(r) => sync.requests.push(r),
                Err(e) => notes.push(format!("a change to {} from eGuard didn't parse ({e}); left out", key_name(key))),
            }
        }
        Ok((sync, notes))
    }
}

/// A policy entry's or request's `key`, `Unknown` when missing or new.
fn item_key(item: &serde_json::Value) -> ProtectionKey {
    item.get("key").and_then(|k| serde_json::from_value(k.clone()).ok()).unwrap_or(ProtectionKey::Unknown)
}

/// The key as the server spells it, for log lines.
fn key_name(key: ProtectionKey) -> String {
    serde_json::to_value(key).ok().and_then(|v| v.as_str().map(str::to_owned)).unwrap_or_default()
}

/// Fills in what the server itself reads as missing: a `SCREEN_TIME` without `weekendMinutes` (stored before weekend
/// limits existed) means the daily limit every day (`weekendMinutes ?? dailyMinutes` in `~/eguard/src/lib/engine.ts`).
fn normalized(mut item: serde_json::Value) -> serde_json::Value {
    if let Some(config) = item.get_mut("config").and_then(serde_json::Value::as_object_mut)
        && config.get("key").and_then(serde_json::Value::as_str) == Some("SCREEN_TIME")
        && config.get("weekendMinutes").is_none_or(serde_json::Value::is_null)
        && let Some(daily) = config.get("dailyMinutes").cloned()
    {
        config.insert("weekendMinutes".into(), daily);
    }
    item
}

/// The config enforced when a protection's settings can't be read and none were kept: the same as before the first
/// sync (new apps wait for the parent). Time limits and bedtime have no safe guess.
fn strictest(key: ProtectionKey) -> Option<ProtectionConfig> {
    match key {
        ProtectionKey::AppApproval => Some(ProtectionConfig::AppApproval { enabled: true }),
        ProtectionKey::Downloads => Some(ProtectionConfig::Downloads { require_approval: true }),
        _ => None,
    }
}

/// `/sync` `browserLink`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserLink {
    pub value: String,
    pub expires_at: String,
}

/* ---------- /report ---------- */

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReportedProtection {
    pub key: ProtectionKey,
    /// The protection's fields without `key` (`ProtectionConfig::report_config`).
    pub config: serde_json::Value,
    /// Why it couldn't be applied, in words a parent can read (≤ 200 chars). Never `null`: left out instead.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl ReportedProtection {
    pub fn new(config: &ProtectionConfig, error: Option<&str>) -> Self {
        // A blank error would get the whole report refused: it's left out instead
        Self { key: config.key(), config: config.report_config(), error: error.and_then(|e| fit(e, REPORT_ERROR_MAX)) }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReportRequest {
    pub protections: Vec<ReportedProtection>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub full: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub battery: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub os_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_version: Option<String>,
    /// Computers: the Windows accounts and whether the child's rules apply in each.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accounts: Option<Vec<ReportedAccount>>,
}

/// One Windows account in `/report` (spec section 12): its name, and whether the child's rules apply in it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReportedAccount {
    pub name: String,
    pub enforced: bool,
}

/// `{ ok: true }`, plus `ignored` when entries didn't match their schema (a bug in this build: log it).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReportResponse {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ignored: Vec<IgnoredProtection>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IgnoredProtection {
    pub key: String,
    pub error: String,
}

/* ---------- /usage ---------- */

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsageApp {
    pub name: String,
    pub minutes: u32,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ids: Vec<AppId>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UsageReport {
    /// `YYYY-MM-DD`, the day in the family's time zone by eGuard's clock.
    pub date: String,
    pub total_minutes: u32,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub apps: Vec<UsageApp>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hourly: Option<[u32; 24]>,
}

/* ---------- /events ---------- */

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FoundApp {
    pub app: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ids: Vec<AppId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<AppSource>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub category: Option<Category>,
}

/// What the agent saw someone try (spec section 11). Each raises one alert per hour per computer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TamperKind {
    UninstallBlocked,
    ServiceStopDenied,
    FilesChanged,
    AdminAccount,
    SafeMode,
    AgentRestarted,
    ClockChanged,
    /// Five wrong removal codes in a row locked "Remove with a code" (spec section 10).
    RemovalCodeGuessed,
    /// A Windows account appeared that the child's rules don't apply in (spec section 4).
    NewAccount,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TimeRequestReason {
    DailyLimit,
    AppLimit,
    CategoryLimit,
    Bedtime,
}

/// One event for `POST /events`, tagged by `type`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DeviceEvent {
    #[serde(rename_all = "camelCase")]
    AppInstalled {
        app: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        age_rating: Option<u32>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        ids: Vec<AppId>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        source: Option<AppSource>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        category: Option<Category>,
    },
    AppsFound {
        apps: Vec<FoundApp>,
    },
    Tamper {
        kind: TamperKind,
    },
    UninstallAck {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        code: Option<String>,
    },
    AppRequested {
        app: String,
    },
    LimitReached {
        minutes: u32,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        category: Option<Category>,
    },
    AppBlocked {
        app: String,
    },
    TimeRequested {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        app: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<TimeRequestReason>,
    },
}

impl DeviceEvent {
    /// The `type` on the wire; the offline queue keeps order per type.
    pub fn type_name(&self) -> &'static str {
        match self {
            Self::AppInstalled { .. } => "APP_INSTALLED",
            Self::AppsFound { .. } => "APPS_FOUND",
            Self::Tamper { .. } => "TAMPER",
            Self::UninstallAck { .. } => "UNINSTALL_ACK",
            Self::AppRequested { .. } => "APP_REQUESTED",
            Self::LimitReached { .. } => "LIMIT_REACHED",
            Self::AppBlocked { .. } => "APP_BLOCKED",
            Self::TimeRequested { .. } => "TIME_REQUESTED",
        }
    }

    /// `APPS_FOUND` events for a scan: 1 to 200 apps each, so a big scan becomes several events.
    pub fn apps_found(apps: &[FoundApp]) -> Vec<DeviceEvent> {
        apps.chunks(APPS_PER_MESSAGE_MAX).map(|c| DeviceEvent::AppsFound { apps: c.to_vec() }).collect()
    }
}

/// An event with its `eventId`: made once, sent unchanged on every retry, so the server can drop repeats.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EventEnvelope {
    pub event_id: String,
    #[serde(flatten)]
    pub event: DeviceEvent,
}

impl EventEnvelope {
    pub fn new(event: DeviceEvent) -> Self {
        Self { event_id: uuid::Uuid::new_v4().to_string(), event }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventResponse {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duplicate: Option<bool>,
    /// `APP_REQUESTED`: the app's approval when the parent already decided.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval: Option<Approval>,
}

/// Every error body: `{ error }`. Branch on the HTTP status, not the text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorBody {
    pub error: String,
}

/* ---------- /catalog ---------- */

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CatalogKind {
    Game,
    TrustedPublisher,
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MatchType {
    /// `<kind>:<id>` as the agent's ids, lower case: `steam:730`, `msstore:<package family name>`.
    LauncherId,
    ExeName,
    Signer,
    ProductName,
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CatalogEntry {
    pub kind: CatalogKind,
    pub match_type: MatchType,
    #[serde(rename = "match")]
    pub match_value: String,
    pub display_name: Option<String>,
    pub category: Option<Category>,
    pub trending: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Catalog {
    #[serde(rename = "type")]
    pub kind: String,
    /// A hash of the entries (mobile-api, `GET /catalog`): it only tells one catalog from another, never which is
    /// newer, so it's compared as a string. Read from a number too (`catalog_version`).
    #[serde(deserialize_with = "de_catalog_version")]
    pub version: String,
    pub entries: Vec<CatalogEntry>,
}

/// A catalog's `version` as a string. The server sends a 16-character hash; earlier servers sent a number, which a
/// kept copy from then still has.
pub fn catalog_version(v: &serde_json::Value) -> Option<String> {
    match v {
        serde_json::Value::String(s) if !s.is_empty() => Some(s.clone()),
        serde_json::Value::Number(n) => n.as_u64().map(|n| n.to_string()),
        _ => None,
    }
}

fn de_catalog_version<'de, D: serde::Deserializer<'de>>(d: D) -> Result<String, D::Error> {
    catalog_version(&serde_json::Value::deserialize(d)?).ok_or_else(|| serde::de::Error::custom("a catalog version is a string"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    #[test]
    fn a_catalog_version_is_the_servers_hash_or_an_older_number() {
        let read = |version: Value| serde_json::from_value::<Catalog>(json!({ "type": "t", "version": version, "entries": [] }));
        assert_eq!(read(json!("3f9a0c1d2e4b5a6c")).unwrap().version, "3f9a0c1d2e4b5a6c");
        assert_eq!(read(json!(1_792_758_987_201_u64)).unwrap().version, "1792758987201");
        assert!(read(json!("")).is_err() && read(json!(null)).is_err() && read(json!(-1)).is_err());
    }

    fn utf16_len(s: &str) -> usize {
        s.encode_utf16().count()
    }

    fn fixture(name: &str) -> Value {
        let path = format!("{}/../../fixtures/server/{name}", env!("CARGO_MANIFEST_DIR"));
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
    }

    #[test]
    fn lengths_are_measured_as_the_server_measures_them() {
        // An emoji is two UTF-16 units: 50 of them are 100, so 40 fit in 80
        let name = app_name(&"\u{1F600}".repeat(50)).unwrap();
        assert_eq!((name.chars().count(), utf16_len(&name)), (40, 80));
        // A cut never splits a character: 79 units of "a", then an emoji that won't fit
        let name = app_name(&format!("{}\u{1F600}", "a".repeat(79))).unwrap();
        assert_eq!(name, "a".repeat(79));
        // JavaScript's trim strips U+FEFF (Rust's doesn't) and leaves U+0085 (Rust's strips it)
        assert_eq!(app_name("\u{FEFF} Pixel Quest \u{FEFF}").as_deref(), Some("Pixel Quest"));
        assert_eq!(app_name("\u{85}x").as_deref(), Some("\u{85}x"));
        assert_eq!(app_name("\u{FEFF}\u{3000}"), None);
    }

    #[test]
    fn an_app_id_is_cut_to_what_the_server_takes() {
        let id = AppId::exe(None, &"\u{1F47E}Pixel Quest ".repeat(40));
        assert!(utf16_len(&id.value) <= APP_ID_MAX);
        assert!(id.value.starts_with("|\u{1F47E}pixel quest"));
        assert_eq!(id.value, js_trim(&id.value));
        assert_eq!(AppId::new(AppIdKind::Steam, " 730 ").value, "730");
    }

    #[test]
    fn a_category_this_build_doesnt_know_goes_out_as_other() {
        let c: Category = serde_json::from_value(json!("PODCASTS")).unwrap();
        assert_eq!(c, Category::Unknown);
        assert_eq!(serde_json::to_value(c).unwrap(), json!("OTHER"));
        assert_eq!(serde_json::to_value(Category::Games).unwrap(), json!("GAMES"));
        let found = FoundApp { app: "X".into(), ids: vec![], source: None, category: Some(Category::Unknown) };
        assert_eq!(serde_json::to_value(found).unwrap()["category"], "OTHER");
    }

    #[test]
    fn a_reported_error_fits_and_a_blank_one_is_left_out() {
        let c = ProtectionConfig::AppApproval { enabled: true };
        assert_eq!(ReportedProtection::new(&c, Some("  \u{FEFF}")).error, None);
        let long = ReportedProtection::new(&c, Some(&"\u{1F600}".repeat(150))).error.unwrap();
        assert_eq!(utf16_len(&long), REPORT_ERROR_MAX);
    }

    fn screen_time_entry(sync: &mut Value) -> &mut Value {
        let policy = sync["policy"].as_array_mut().unwrap();
        policy.iter_mut().find(|p| p["key"] == "SCREEN_TIME").unwrap()
    }

    #[test]
    fn screen_time_without_weekend_minutes_means_the_daily_limit_every_day() {
        let mut raw = fixture("sync-computer.json");
        screen_time_entry(&mut raw)["config"].as_object_mut().unwrap().remove("weekendMinutes");
        // Read whole, this answer doesn't parse at all
        assert!(serde_json::from_value::<SyncResponse>(raw.clone()).is_err());
        let (sync, notes) = SyncResponse::parse(&raw, None).unwrap();
        assert_eq!(notes, Vec::<String>::new());
        let st = sync.policy.iter().find(|p| p.key == ProtectionKey::ScreenTime).unwrap();
        assert_eq!(st.config, ProtectionConfig::ScreenTime { daily_minutes: 180, weekend_minutes: 180 });
        assert_eq!(sync.policy.len(), 10);
    }

    #[test]
    fn one_bad_protection_keeps_its_last_good_settings_and_the_rest_still_applies() {
        let good = fixture("sync-computer.json");
        let (previous, _) = SyncResponse::parse(&good, None).unwrap();
        let mut raw = good.clone();
        screen_time_entry(&mut raw)["config"]["dailyMinutes"] = json!("lots");
        for p in raw["policy"].as_array_mut().unwrap() {
            if p["key"] == "APP_APPROVAL" {
                p["config"]["enabled"] = json!("maybe");
            }
            if p["key"] == "BEDTIME" {
                p["config"]["start"] = json!("22:00");
            }
        }
        raw["requests"] = json!([
            { "id": "req_1", "key": "BEDTIME", "config": { "key": "BEDTIME", "enabled": true } },
            { "id": "req_2", "key": "APP_APPROVAL", "config": { "key": "APP_APPROVAL", "enabled": false } },
        ]);

        let (sync, notes) = SyncResponse::parse(&raw, Some(&previous)).unwrap();
        let config = |s: &SyncResponse, k| s.policy.iter().find(|p| p.key == k).map(|p| p.config.clone());
        // The bad ones: as before
        assert_eq!(config(&sync, ProtectionKey::ScreenTime), config(&previous, ProtectionKey::ScreenTime));
        assert_eq!(config(&sync, ProtectionKey::AppApproval), config(&previous, ProtectionKey::AppApproval));
        // The good change still applies, and the good request comes through
        assert!(matches!(config(&sync, ProtectionKey::Bedtime), Some(ProtectionConfig::Bedtime { start, .. }) if start == "22:00"));
        assert_eq!(sync.requests.iter().map(|r| r.id.as_str()).collect::<Vec<_>>(), ["req_2"]);
        assert_eq!(notes.len(), 3);
        assert!(notes[0].contains("SCREEN_TIME") && notes[0].contains("stay in force"));

        // With nothing kept: approval is on (as before any sync), a time limit can't be guessed
        let (sync, _) = SyncResponse::parse(&raw, None).unwrap();
        assert_eq!(config(&sync, ProtectionKey::AppApproval), Some(ProtectionConfig::AppApproval { enabled: true }));
        assert_eq!(config(&sync, ProtectionKey::ScreenTime), None);

        // Anything else that's wrong still refuses the whole answer
        let mut broken = good;
        broken["apps"] = json!("none");
        assert!(SyncResponse::parse(&broken, Some(&previous)).is_err());
        assert!(SyncResponse::parse(&json!([]), None).is_err());
    }
}
