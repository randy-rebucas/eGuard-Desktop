//! Browsers (spec section 9): the service forces eGuard's extension into Chrome, Edge and Firefox and keeps the
//! computer's link in its managed policy, after every tick (about a minute), so a policy someone deleted comes back.
//! Other browsers are the enforcer's: category BROWSERS, waiting for the parent while web filtering is on.
//!
//! The service writes the real policies (HKLM). Console mode writes the same under HKCU, which no browser reads
//! (`browsers::Place::development`), and reports web filtering as not applied.

use crate::log;
use eguard_core::web::{self, Browser, LinkKeeper};
use eguard_core::wire::BrowserLink;
use eguard_win::browsers::{self, Place};
use std::collections::BTreeMap;
use std::sync::Mutex;

/// How setting up each browser went, by browser: `Ok` once eGuard's policies are in place.
pub type Setup = BTreeMap<Browser, Result<(), String>>;

/// Puts the policies in place and remembers the last outcome, so the log says what changed rather than the same
/// thing every minute.
#[derive(Debug)]
pub struct Browsers {
    place: Place,
    last: Mutex<Setup>,
    link: Mutex<LinkKeeper>,
}

impl Browsers {
    pub fn new(place: Place) -> Self {
        Self { place, last: Mutex::new(Setup::new()), link: Mutex::new(LinkKeeper::default()) }
    }

    /// Forces the extension in each browser this build has an id for, with the link from the last `/sync` (kept for a
    /// day, `LinkKeeper`; none: taken out). `now_ms`: eGuard's clock.
    pub fn apply(&self, fresh: Option<&BrowserLink>, now_ms: i64) -> Setup {
        let link = self.link.lock().unwrap_or_else(std::sync::PoisonError::into_inner).choose(fresh, now_ms);
        let link = link.as_deref();
        let mut setup = Setup::new();
        for b in Browser::ALL {
            let outcome = match web::extension(b) {
                None => Err("this build has no extension id for it".to_owned()),
                Some(ext) => match browsers::apply(&self.place, b, &ext, link) {
                    Ok(changed) => {
                        if changed {
                            log::info(&format!("{}: eGuard's extension policies set in {}", b.name(), self.place.describe()));
                        }
                        Ok(())
                    }
                    Err(e) => Err(e.to_string()),
                },
            };
            setup.insert(b, outcome);
        }
        let mut last = self.last.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        for (b, outcome) in &setup {
            if let (Err(why), was) = (outcome, last.get(b))
                && was != Some(outcome)
            {
                log::warn(&format!("{}: eGuard's extension isn't set up ({why})", b.name()));
            }
        }
        last.clone_from(&setup);
        setup
    }

    /// The computer was paired again: its new link goes in at once.
    pub fn forget_link(&self) {
        self.link.lock().unwrap_or_else(std::sync::PoisonError::into_inner).forget();
    }
}

/// Takes eGuard's policies out of the real place (`eguard-service uninstall`).
pub fn remove_machine() -> Result<(), String> {
    let place = Place::machine();
    for b in Browser::ALL {
        if let Some(ext) = web::extension(b) {
            browsers::remove(&place, b, &ext).map_err(|e| format!("taking eGuard's policies out of {}: {e}", b.name()))?;
        }
    }
    Ok(())
}

/// `eguard-service web`: what's in place in each browser, in the real policies and in console mode's copy. Reads
/// only.
pub fn show() {
    for place in [Place::machine(), Place::development()] {
        println!("{}", place.describe());
        for b in Browser::ALL {
            match web::extension(b) {
                None => println!("  {:<8} no extension id in this build", b.name()),
                Some(ext) => {
                    let s = browsers::status(&place, b, &ext);
                    println!(
                        "  {:<8} {} {}  forced: {}  settings: {}  link: {}",
                        b.name(),
                        ext.id,
                        ext.url,
                        s.forced,
                        s.settings,
                        s.link.as_deref().map_or("none".into(), |l| format!("{}…", l.chars().take(12).collect::<String>()))
                    );
                }
            }
        }
    }
}
