//! `eguard-guard`: the watchdog (spec section 3). As a SYSTEM scheduled task at boot it will restart the service if
//! it stops and restore missing files from a protected cache. That comes with removal protection (Phase 6); this
//! build only has the binary in place, and does nothing.

fn main() {
    eprintln!("eguard-guard does nothing yet (removal protection comes in a later version)");
}
