//! The core against real responses from the eGuard server, captured by `tools/capture-fixtures.mjs` (the desktop
//! agent's whole flow on a test family). Signatures here were made by the server's own signing code and key.

use eguard_core::clock::{ClockSample, parse_iso_ms};
use eguard_core::removal::{self, RemovalSecret};
use eguard_core::rules::{Block, Subject, Verdict, evaluate};
use eguard_core::signature::{CatalogUpdate, TrustedKeys, VerifyError, verify_catalog, verify_uninstall};
use eguard_core::state::{AgentState, SyncError};
use eguard_core::usage::DayUsage;
use eguard_core::wire::*;
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

macro_rules! fixture {
    ($name:literal) => {
        serde_json::from_str::<Value>(include_str!(concat!("../../../fixtures/server/", $name))).unwrap()
    };
}

/// Parses `v` as `T`, and checks that writing it back gives the same JSON (no field lost, renamed or added).
fn round_trip<T: DeserializeOwned + Serialize>(v: &Value) -> T {
    let parsed: T = serde_json::from_value(v.clone()).unwrap();
    assert_eq!(&serde_json::to_value(&parsed).unwrap(), v);
    parsed
}

fn keys() -> TrustedKeys {
    TrustedKeys::builtin().unwrap()
}

fn sample_at(iso: &str) -> ClockSample {
    ClockSample { mono_ms: 1_000, boot_id: 1, wall_ms: parse_iso_ms(iso).unwrap() }
}

#[test]
fn builtin_key_is_the_servers() {
    assert_eq!(keys().key_ids().collect::<Vec<_>>(), vec!["60da38f4c654f71a"]);
}

#[test]
fn every_sync_response_round_trips() {
    for v in [fixture!("sync-first.json"), fixture!("sync-computer.json"), fixture!("sync-removal.json"), fixture!("sync-kept.json")] {
        let s: SyncResponse = round_trip(&v);
        assert_eq!(s.timezone, "Asia/Manila");
        assert!(s.server_time.is_some());
        // The server sends every protection; none is unknown to this build
        assert_eq!(s.policy.len(), 10);
        assert!(s.policy.iter().all(|p| p.key != ProtectionKey::Unknown && p.config.key() == p.key));
    }
}

#[test]
fn sync_carries_what_computers_need() {
    let s: SyncResponse = serde_json::from_value(fixture!("sync-computer.json")).unwrap();
    let cs2 = s.apps.iter().find(|a| a.name == "Counter-Strike 2").unwrap();
    assert_eq!((cs2.approval, cs2.category), (Approval::Pending, Category::Games));
    assert_eq!(cs2.ids, vec![AppId::new(AppIdKind::Steam, "730")]);
    assert_eq!(s.category_limits, vec![CategoryLimit { category: Category::Games, daily_limit_minutes: 60 }]);
    assert!(s.features.category_limits);
    // Computers always come back within a minute (no push wakes them)
    assert_eq!(s.next_sync_seconds, 60);
    assert!(s.browser_link.as_ref().is_some_and(|l| l.value.starts_with(&s.device_id)));
    assert!(s.uninstall.is_none());
    // The first sync after pairing asks for a full report
    let first: SyncResponse = serde_json::from_value(fixture!("sync-first.json")).unwrap();
    assert!(first.full_report_requested);
}

#[test]
fn requests_and_bodies_the_agent_sends_match_what_the_server_took() {
    let pair: PairRequest = round_trip(&fixture!("pair-request.json"));
    assert_eq!(pair.platform, Platform::Windows);
    let found: EventEnvelope = round_trip(&fixture!("events-apps-found-request.json"));
    assert!(
        matches!(&found.event, DeviceEvent::AppsFound { apps } if apps.len() == 3 && apps[2].source == Some(AppSource::UnknownPublisher))
    );
    let tamper: EventEnvelope = round_trip(&fixture!("events-tamper-request.json"));
    assert_eq!(tamper.event, DeviceEvent::Tamper { kind: TamperKind::ClockChanged });
    let usage: UsageReport = round_trip(&fixture!("usage-request.json"));
    assert_eq!(usage.apps[0].ids, vec![AppId::new(AppIdKind::Steam, "730")]);
    let report: ReportRequest = round_trip(&fixture!("report-request.json"));
    assert_eq!(report.protections.len(), 6);
}

#[test]
fn reports_built_from_configs_have_exactly_the_servers_fields() {
    let sent: ReportRequest = serde_json::from_value(fixture!("report-request.json")).unwrap();
    let built = ReportRequest {
        protections: vec![
            ReportedProtection::new(&ProtectionConfig::ScreenTime { daily_minutes: 120, weekend_minutes: 180 }, None),
            ReportedProtection::new(
                &ProtectionConfig::Bedtime { enabled: true, start: "21:00".into(), end: "07:00".into(), days: BedtimeDays::SchoolNights },
                None,
            ),
            ReportedProtection::new(&ProtectionConfig::AppApproval { enabled: true }, None),
            ReportedProtection::new(&ProtectionConfig::Downloads { require_approval: true }, None),
            ReportedProtection::new(
                &ProtectionConfig::UninstallProtection { enabled: false },
                Some("Your child's account is an administrator."),
            ),
            ReportedProtection::new(
                &ProtectionConfig::Web { mode: WebMode::Off, blocked_sites: 0 },
                Some("eGuard's extension isn't connected in every browser yet."),
            ),
        ],
        full: Some(true),
        app_version: Some("0.1.0".into()),
        ..Default::default()
    };
    assert_eq!(built, sent);
    // And the server took it without ignoring anything
    let r: ReportResponse = serde_json::from_value(fixture!("report-response.json")).unwrap();
    assert!(r.ok && r.ignored.is_empty());
}

#[test]
fn server_answers_parse() {
    let pair: PairResponse = serde_json::from_value(fixture!("pair-response.json")).unwrap();
    assert!(pair.removal_secret.is_some());
    let debug = format!("{pair:?}");
    assert!(!debug.contains(&pair.token) && !debug.contains(pair.removal_secret.as_deref().unwrap()));
    let dup: EventResponse = serde_json::from_value(fixture!("events-duplicate-response.json")).unwrap();
    assert_eq!(dup.duplicate, Some(true));
    let unauthorized = fixture!("sync-401.json");
    assert_eq!(unauthorized["status"], 401);
    let _: ErrorBody = serde_json::from_value(unauthorized["body"].clone()).unwrap();
    assert_eq!(fixture!("events-uninstall-ack-409.json")["status"], 409);
}

#[test]
fn the_servers_catalog_verifies() {
    let v = fixture!("catalog.json");
    let CatalogUpdate::Changed(catalog) = verify_catalog(&keys(), &v, None).unwrap() else { panic!("expected a catalog") };
    assert_eq!(catalog.kind, "eguard.desktop.catalog");
    assert!(catalog.entries.len() > 100);
    let cs2 = catalog.entries.iter().find(|e| e.match_value == "steam:730").unwrap();
    assert_eq!(
        (cs2.kind, cs2.match_type, cs2.display_name.as_deref()),
        (CatalogKind::Game, MatchType::LauncherId, Some("Counter-Strike 2"))
    );
    assert!(catalog.entries.iter().any(|e| e.kind == CatalogKind::TrustedPublisher && e.match_value == "microsoft corporation"));
    // A key order other than the server's still verifies (the signature covers canonical JSON)
    let reordered: Value = serde_json::from_str(&serde_json::to_string_pretty(&v).unwrap()).unwrap();
    assert!(verify_catalog(&keys(), &reordered, Some(&catalog.version)).is_ok());
    // Unchanged only about the version kept
    assert_eq!(
        verify_catalog(&keys(), &fixture!("catalog-unchanged.json"), Some(&catalog.version)),
        Ok(CatalogUpdate::Unchanged { version: catalog.version.clone() })
    );
    assert_eq!(verify_catalog(&keys(), &fixture!("catalog-unchanged.json"), Some("0123456789abcdef")), Err(VerifyError::Malformed));
    assert_eq!(verify_catalog(&keys(), &fixture!("catalog-unchanged.json"), None), Err(VerifyError::Malformed));
    // A version is a hash, with no order: a catalog other than the kept one is simply another one
    assert!(matches!(verify_catalog(&keys(), &v, Some("0123456789abcdef")), Ok(CatalogUpdate::Changed(_))));
}

#[test]
fn a_tampered_catalog_is_refused() {
    let mut v = fixture!("catalog.json");
    // Make Counter-Strike 2 a trusted publisher's app, so it would never be reported
    let entries = v["catalog"]["entries"].as_array_mut().unwrap();
    entries.push(json!({ "kind": "TRUSTED_PUBLISHER", "matchType": "SIGNER", "match": "valve corp.", "displayName": null, "category": null, "trending": false }));
    assert_eq!(verify_catalog(&keys(), &v, None), Err(VerifyError::BadSignature));
    let mut v = fixture!("catalog.json");
    v["signature"] = json!("AAAA");
    assert_eq!(verify_catalog(&keys(), &v, None), Err(VerifyError::BadSignature));
    let mut v = fixture!("catalog.json");
    v["catalog"]["version"] = json!(v["catalog"]["version"].as_u64().unwrap() + 1);
    assert_eq!(verify_catalog(&keys(), &v, None), Err(VerifyError::BadSignature));
}

#[test]
fn the_servers_uninstall_command_verifies_only_for_this_device_and_only_fresh() {
    let s = fixture!("sync-removal.json");
    let envelope = &s["uninstall"];
    let device = s["deviceId"].as_str().unwrap();
    let now = parse_iso_ms(s["serverTime"].as_str().unwrap()).unwrap();
    let cmd = verify_uninstall(&keys(), envelope, device, now).unwrap();
    assert_eq!(cmd.device_id, device);
    assert_eq!(verify_uninstall(&keys(), envelope, "someone-else", now), Err(VerifyError::WrongDevice));
    assert_eq!(verify_uninstall(&keys(), envelope, device, now + 2 * 60 * 60_000), Err(VerifyError::Stale));
    let mut forged = envelope.clone();
    forged["command"]["deviceId"] = json!("another-pc");
    assert_eq!(verify_uninstall(&keys(), &forged, "another-pc", now), Err(VerifyError::BadSignature));
    // A key this build doesn't trust can't sign one
    let other = TrustedKeys::from_spki_base64(&[
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAErrCDlVlG/zs+bzXdWXr7TT7hce9KBR09d9gkcV719fI5HeUT63tiQ3BvlEP2Xp1g4PhlKGPUCgadpunxThvPOg==",
    ])
    .unwrap();
    assert_eq!(verify_uninstall(&other, envelope, device, now), Err(VerifyError::BadSignature));
    // The catalog's signature is no uninstall command
    let catalog = fixture!("catalog.json");
    let swapped = json!({ "command": catalog["catalog"], "signature": catalog["signature"], "keyId": catalog["keyId"] });
    assert!(matches!(verify_uninstall(&keys(), &swapped, device, now), Err(VerifyError::Malformed | VerifyError::WrongType(_))));
}

#[test]
fn the_removal_code_matches_the_one_the_parent_saw() {
    let f = fixture!("removal-code.json");
    let secret = RemovalSecret::from_base64url(f["removalSecret"].as_str().unwrap()).unwrap();
    let device = f["deviceId"].as_str().unwrap();
    let expires = parse_iso_ms(f["removalCode"]["expiresAt"].as_str().unwrap()).unwrap();
    let window = removal::window_of(expires) - 2;
    let code = f["removalCode"]["code"].as_str().unwrap();
    assert_eq!(removal::code_for_window(&secret, device, window), code);
    assert!(removal::code_matches(&secret, device, code, window * removal::WINDOW_MS));
    assert!(removal::code_matches(&secret, device, code, expires - 1));
    assert!(!removal::code_matches(&secret, device, code, expires));
}

#[test]
fn applying_syncs_keeps_the_last_good_policy() {
    let removal = fixture!("sync-removal.json");
    let device = removal["deviceId"].as_str().unwrap();
    let mut state = AgentState::paired(device, "Mia");

    let first = state.apply_sync(&fixture!("sync-computer.json"), &keys(), sample_at("2026-10-23T07:24:00Z"), "0.1.0").unwrap();
    assert!(first.uninstall.is_none());
    assert_eq!(first.next_sync_secs, 60);
    let rules = state.rules();
    assert!(rules.policy.approval_required);
    assert_eq!(state.zone().name(), "Asia/Manila");

    // What it enforces: CS2 waits for the parent; a new game waits too (App Approval is on for a 12-year-old)
    let today = DayUsage::default();
    let at = state.zone().local(parse_iso_ms("2026-10-23T07:30:00Z").unwrap());
    let cs2 = rules.app("Counter-Strike 2").unwrap();
    assert_eq!(evaluate(&rules, Subject::Listed(cs2), &today, &at, 0), Verdict::Block(Block::Pending));
    assert_eq!(
        evaluate(&rules, Subject::Unlisted { name: "Pixel Run", category: Category::Games }, &today, &at, 0),
        Verdict::Block(Block::NeedsApproval)
    );

    // Garbage, or another device's answer, changes nothing
    let before = state.clone();
    assert!(matches!(
        state.apply_sync(&json!({ "deviceId": device }), &keys(), sample_at("2026-10-23T07:25:00Z"), "0.1.0"),
        Err(SyncError::Malformed(_))
    ));
    let mut other = fixture!("sync-computer.json");
    other["deviceId"] = json!("someone-else");
    assert!(matches!(state.apply_sync(&other, &keys(), sample_at("2026-10-23T07:25:00Z"), "0.1.0"), Err(SyncError::WrongDevice(_))));
    // A 401 changes nothing either
    state.on_unauthorized(0);
    assert_eq!(state.rules(), before.rules());

    // While a removal waits, the verified command comes through and syncs speed up
    let r = state.apply_sync(&removal, &keys(), sample_at(removal["serverTime"].as_str().unwrap()), "0.1.0").unwrap();
    assert_eq!(r.uninstall.unwrap().device_id, device);
    assert_eq!(r.next_sync_secs, 60);
    // A forged one is reported and ignored
    let mut forged = removal.clone();
    forged["uninstall"]["command"]["requestedAt"] = json!("2026-01-01T00:00:00.000Z");
    let r = state.apply_sync(&forged, &keys(), sample_at(removal["serverTime"].as_str().unwrap()), "0.1.0").unwrap();
    assert_eq!((r.uninstall, r.uninstall_rejected), (None, Some(VerifyError::BadSignature)));
    // An old build is told to update, and keeps enforcing
    let mut old = fixture!("sync-kept.json");
    old["minAppVersion"] = json!("0.2.0");
    state.apply_sync(&old, &keys(), sample_at("2026-10-23T07:26:00Z"), "0.1.0").unwrap();
    assert!(state.update_required);
    assert!(state.rules().policy.approval_required);
}

fn iso(ms: i64) -> String {
    jiff::Timestamp::from_millisecond(ms).unwrap().to_string()
}

#[test]
fn a_recorded_removal_answer_cant_be_played_back_after_an_offline_reboot() {
    const HOUR: i64 = 60 * 60_000;
    let removal = fixture!("sync-removal.json");
    let device = removal["deviceId"].as_str().unwrap();
    let signed_at = parse_iso_ms(removal["uninstall"]["command"]["at"].as_str().unwrap()).unwrap();

    // The computer last synced two hours after the command was signed (the parent kept it in between)
    let mut state = AgentState::paired(device, "Mia");
    let mut kept = fixture!("sync-computer.json");
    kept["deviceId"] = json!(device);
    kept["serverTime"] = json!(iso(signed_at + 2 * HOUR));
    state.apply_sync(&kept, &keys(), ClockSample { mono_ms: 1_000, boot_id: 1, wall_ms: signed_at + 2 * HOUR }, "0.1.0").unwrap();

    // Rebooted offline, the PC's clock set back, and the recorded answer played back, its own serverTime and all.
    // Judged by that serverTime the command would look fresh; by the clock as it stood, it's two hours old.
    let replay = ClockSample { mono_ms: 5_000, boot_id: 2, wall_ms: signed_at };
    // The service ran offline for a while first, so eGuard's clock is an estimate when the answer arrives
    state.clock.now(ClockSample { mono_ms: 2_000, ..replay });
    let r = state.apply_sync(&removal, &keys(), replay, "0.1.0").unwrap();
    assert_eq!((r.uninstall, r.uninstall_rejected), (None, Some(VerifyError::Stale)));
    // Nor did the forged serverTime turn eGuard's clock back
    assert!(state.clock.now(replay).unwrap().ms >= signed_at + 2 * HOUR);

    // A command accepted once isn't accepted again
    let mut state = AgentState::paired(device, "Mia");
    let mut before = fixture!("sync-computer.json");
    before["deviceId"] = json!(device);
    state.apply_sync(&before, &keys(), sample_at(before["serverTime"].as_str().unwrap()), "0.1.0").unwrap();
    let now = sample_at(removal["serverTime"].as_str().unwrap());
    assert!(state.apply_sync(&removal, &keys(), now, "0.1.0").unwrap().uninstall.is_some());
    let again = state.apply_sync(&removal, &keys(), now, "0.1.0").unwrap();
    assert_eq!((again.uninstall, again.uninstall_rejected), (None, Some(VerifyError::Replayed)));
    // It survives a restart
    let restored: AgentState = serde_json::from_value(serde_json::to_value(&state).unwrap()).unwrap();
    assert_eq!(restored.last_uninstall_at_ms, Some(signed_at));

    // Before the first sync ever there's no clock to judge by but the PC's: it waits for the next sync
    let mut fresh = AgentState::paired(device, "Mia");
    let r = fresh.apply_sync(&removal, &keys(), now, "0.1.0").unwrap();
    assert_eq!((r.uninstall, r.uninstall_rejected), (None, Some(VerifyError::Stale)));
}

#[test]
fn a_screen_time_without_weekend_minutes_doesnt_sink_the_sync() {
    let mut s = fixture!("sync-computer.json");
    for p in s["policy"].as_array_mut().unwrap() {
        if p["key"] == "SCREEN_TIME" {
            p["config"].as_object_mut().unwrap().remove("weekendMinutes");
        }
    }
    let mut state = AgentState::paired(s["deviceId"].as_str().unwrap(), "Mia");
    let outcome = state.apply_sync(&s, &keys(), sample_at("2026-10-23T07:24:00Z"), "0.1.0").unwrap();
    assert_eq!(outcome.notes, Vec::<String>::new());
    let rules = state.rules();
    assert_eq!(rules.policy.screen_time, Some((180, 180)));
    assert!(rules.app("Counter-Strike 2").is_some());
}

#[test]
fn the_server_time_sets_the_clock() {
    let s = fixture!("sync-computer.json");
    let mut state = AgentState::paired(s["deviceId"].as_str().unwrap(), "Mia");
    // The PC's clock is a day ahead
    let server = parse_iso_ms(s["serverTime"].as_str().unwrap()).unwrap();
    let sample = ClockSample { mono_ms: 5_000, boot_id: 3, wall_ms: server + 86_400_000 };
    state.apply_sync(&s, &keys(), sample, "0.1.0").unwrap();
    let now = state.clock.now(ClockSample { mono_ms: 65_000, ..sample }).unwrap();
    assert_eq!(now.ms, server + 60_000);
    assert!(now.verified);
}
