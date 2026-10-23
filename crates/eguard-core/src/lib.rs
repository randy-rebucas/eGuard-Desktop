//! The platform-neutral core of eGuard for Windows (and the Mac agent later): the device API's wire types, the
//! parent's rules, screen-time accounting on eGuard's clock, signature and removal-code checks, and the offline
//! queue. No Windows APIs here; the `windows` crate lives in the platform crate.
//!
//! The spec is `~/eguard/docs/desktop-agent-spec.md`.

pub mod canonical;
pub mod clock;
pub mod keys;
pub mod localtime;
pub mod queue;
pub mod removal;
pub mod rules;
pub mod signature;
pub mod state;
pub mod usage;
pub mod wire;
