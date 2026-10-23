//! The service's log: `logs\service.log` in the data folder, one JSON object per line, cut at 1 MB with five older
//! files kept, scrubbed of anything that looks like a secret (`eguard_core::logging`). Console mode also prints
//! each line.

use eguard_core::logging;
use std::path::Path;

/// Call once at start. `dir` is where `service.log` goes; `console` also prints each line.
pub fn init(dir: Option<&Path>, console: bool) {
    logging::init("service", dir.map(|d| d.join("service.log")).as_deref(), console);
}

pub use logging::{error, info, warn};
