//! `eguard-service scan`: one scan of this computer, printed instead of sent. For checking what the parent would see
//! (Phase 3's check) without pairing or changing anything.

use eguard_core::scan::{self, Classifier, ExeCache, Skip};
use eguard_core::signature::{CatalogUpdate, TrustedKeys, verify_catalog};
use eguard_core::wire::{AppSource, DeviceEvent, EventEnvelope};
use std::path::PathBuf;

pub fn run(args: &[String]) -> Result<(), String> {
    let mut catalog_file = None;
    let mut verbose = false;
    let mut trust = Vec::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--catalog" => catalog_file = Some(PathBuf::from(it.next().ok_or("--catalog needs a file")?)),
            "--verbose" => verbose = true,
            // What a TRUSTED_PUBLISHER row on the server would do, without changing the server
            "--trust" => trust.push(it.next().ok_or("--trust needs a signer name")?.clone()),
            other => return Err(format!("unknown option {other}")),
        }
    }
    let file =
        catalog_file.ok_or("give the catalog to scan with: --catalog FILE (a GET /catalog answer, e.g. fixtures/server/catalog.json)")?;
    let raw: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&file).map_err(|e| format!("{}: {e}", file.display()))?).map_err(|e| e.to_string())?;
    let keys = TrustedKeys::builtin().map_err(|e| e.to_string())?;
    let CatalogUpdate::Changed(catalog) = verify_catalog(&keys, &raw, None).map_err(|e| format!("the catalog didn't verify: {e}"))? else {
        return Err("that file is an `unchanged` answer, not a catalog".into());
    };
    let mut classifier = Classifier::new(&catalog);
    for s in &trust {
        classifier.trust(s);
    }

    let started = std::time::Instant::now();
    let mut cache = ExeCache::new();
    let collected = eguard_win::apps::collect(&mut cache);
    let candidates = scan::merge_with(collected.candidates, crate::monitor::admin_only());
    let result = scan::classify_all(&classifier, &candidates);
    let events: Vec<EventEnvelope> = scan::events(None, &result.found).into_iter().map(EventEnvelope::new).collect();

    for e in &events {
        println!("{}", serde_json::to_string_pretty(e).unwrap_or_default());
    }
    let count = |s: AppSource| result.found.iter().filter(|a| a.source == Some(s)).count();
    eprintln!(
        "\n{} apps to report ({} catalog, {} launcher, {} unknown publisher) from {} candidates; {} left out as trusted. \
         {} files checked in {:.1} s.",
        result.found.len(),
        count(AppSource::Catalog),
        count(AppSource::Launcher),
        count(AppSource::UnknownPublisher),
        candidates.len(),
        result.skipped.len(),
        collected.exes_checked,
        started.elapsed().as_secs_f64()
    );
    if verbose {
        let mut skipped: Vec<_> = result.skipped.iter().collect();
        skipped.sort_by(|a, b| a.0.cmp(&b.0));
        for (name, why) in skipped {
            match why {
                Skip::TrustedPublisher(s) => eprintln!("  left out: {name} (signed by {s})"),
                Skip::BlankName => eprintln!("  left out: a blank name"),
            }
        }
        for c in &candidates {
            eprintln!("  candidate: {:?} {:?} dir={:?} exe={:?} other={:?}", c.origin, c.name, c.dir, c.exe, c.other_signer);
        }
    }
    if events.iter().any(|e| !matches!(e.event, DeviceEvent::AppsFound { .. })) {
        return Err("expected only APPS_FOUND for a first scan".into());
    }
    Ok(())
}
