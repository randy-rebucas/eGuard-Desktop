//! The platform-neutral core of eGuard for Windows (and the Mac agent later): the device API's wire types and client,
//! the parent's rules, enforcement, screen-time accounting on eGuard's clock, signature and removal-code checks, the offline
//! queue, and the service's sync loop. No Windows APIs here; the `windows-sys` crate lives in the platform crate.
//!
//! The spec is `~/eguard/docs/desktop-agent-spec.md`.

#![forbid(unsafe_code)]

pub mod api;
pub mod canonical;
pub mod clock;
pub mod enforce;
pub mod engine;
pub mod ipc;
pub mod keys;
pub mod localtime;
pub mod queue;
pub mod removal;
pub mod report;
pub mod rules;
pub mod scan;
pub mod signature;
pub mod state;
pub mod store;
pub mod usage;
pub mod wire;
