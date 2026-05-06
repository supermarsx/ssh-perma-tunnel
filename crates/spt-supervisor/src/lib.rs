//! Profile state machine, reconnect/instability/failover supervisor, and
//! reload reconciler for `spt`.
//!
//! See spec §11 (reconnect/keepalive/instability/failover) and §17.2
//! (orchestrator task tree). This crate ties together:
//!
//! * [`state_machine`] — the 13 profile / 8 forward states and their
//!   transitions.
//! * [`reconnect`] — full-jitter exponential backoff with `reset_after`.
//! * [`instability`] — sliding-window disconnect detector.
//! * [`failover`] — endpoint selector (priority/weight/cooldown/manual).
//! * [`reload`] — diff-driven reconciler over [`spt_config::Config`].
//! * [`profile`] — [`ProfileSupervisor`] running the state machine for one
//!   profile.
//! * [`Orchestrator`] — top-level container per spec §17.2.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![allow(
    clippy::manual_let_else,
    clippy::doc_markdown,
    clippy::map_unwrap_or,
    clippy::cast_lossless,
    clippy::ignored_unit_patterns,
    clippy::missing_fields_in_debug,
    clippy::match_same_arms
)]

pub mod failover;
pub mod instability;
pub mod orchestrator;
pub mod profile;
pub mod reconnect;
pub mod reload;
pub mod state_machine;

pub use failover::{EndpointSelector, FailoverMode, ManualOverride, SelectorError};
pub use instability::{InstabilityDetector, InstabilityWindow};
pub use orchestrator::Orchestrator;
pub use profile::{ProfileEvent, ProfileSupervisor, ProfileSupervisorConfig};
pub use reconnect::{Backoff, BackoffConfig};
pub use reload::{ReloadAction, ReloadPlan};
pub use state_machine::{ForwardEvent, ProfileEvent as SmEvent, ProfileStateMachine, ProfileStateName};
