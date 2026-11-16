//! The service's log: `logs\service.log` in the data folder, one JSON object per line, cut at 1 MB with five older
//! files kept, scrubbed of anything that looks like a secret (`eguard_core::logging`). Console mode also prints
//! each line.

use eguard_core::logging;
use std::path::Path;

/// Call once at start. `dir` is where `service.log` goes; `console` also prints each line.
pub fn init(dir: Option<&Path>, console: bool) {
    let path = dir.map(|d| d.join("service.log"));
    logging::init("service", path.as_deref(), console);
    if let Some(p) = &path {
        eguard_win::crash::log_faults_to(&"service", p);
    }
}

pub use logging::{error, info, warn};
