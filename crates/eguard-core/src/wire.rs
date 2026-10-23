//! The device API (`/api/device/v1`) as the eGuard server speaks it: field names, enums and casing exactly as in
//! `~/eguard/src/app/api/device/v1/*` and docs/desktop-agent-spec.md section 12.
//!
//! Responses tolerate fields this build doesn't know (the server may add some), and enums have an `Unknown`
//! fallback so one new value can't make a whole `/sync` unreadable. What an unknown value means for enforcement is
//! decided in `rules`, always toward more protection.

use serde::{Deserialize, Serialize};

/// The longest app name the server accepts (`/events`, `/usage`).
pub const APP_NAME_MAX: usize = 80;
/// Most apps in one `APPS_FOUND` event or one `/usage` report.
pub const APPS_PER_MESSAGE_MAX: usize = 200;
/// Most ids on one app (`AppIds` in app-identity.ts).
pub const IDS_PER_APP_MAX: usize = 8;

/// Trims an app name and cuts it to what the server accepts. `None` for a blank name (the server answers 400).
pub fn app_name(name: &str) -> Option<String> {
    let name = name.trim();
    if name.is_empty() {
        return None;
    }
    Some(name.chars().take(APP_NAME_MAX).collect::<String>().trim_end().to_owned())
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

/// An app's category. `Unknown` counts as `Other`.
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
    #[serde(other)]
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
    pub fn new(kind: AppIdKind, value: &str) -> Self {
        Self { kind, value: value.trim().to_lowercase() }
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
    /// A protection newer than this build, or one whose fields didn't parse. Not enforced, not reported.
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
        Self { key: config.key(), config: config.report_config(), error: error.map(|e| e.chars().take(200).collect()) }
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
    pub version: u64,
    pub entries: Vec<CatalogEntry>,
}
