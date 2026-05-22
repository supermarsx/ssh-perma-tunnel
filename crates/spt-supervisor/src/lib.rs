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

pub mod control;
pub mod failover;
pub mod instability;
pub mod live_connector;
pub mod mount_registry;
pub mod orchestrator;
pub mod profile;
pub mod reconnect;
pub mod reconnect_trigger;
pub mod reload;
pub mod round_robin;
pub mod session;
pub mod state_machine;
pub mod stats;

#[cfg(any(test, feature = "testing"))]
pub mod testing;

pub use control::{Control, DrainReport, EndpointKey};
pub use failover::{EndpointSelector, FailoverMode, ManualOverride, SelectorError};
pub use instability::{InstabilityDetector, InstabilityWindow};
pub use live_connector::{
    AsyncReadWrite, BoxedStream, EchoLiveConnector, LiveConnector, UdpEndpoint,
    UnavailableConnector,
};
pub use mount_registry::{MountKey, MountRegistry, MountRegistryError};
pub use orchestrator::Orchestrator;
pub use profile::{ProfileEvent, ProfileSupervisor, ProfileSupervisorConfig};
pub use reconnect::{Backoff, BackoffConfig};
pub use reconnect_trigger::{LiveReconnectTrigger, ReconnectTrigger};
pub use reload::{ReloadAction, ReloadPlan};
// t4-e4 round-robin selector layer. The trait would otherwise collide with
// the legacy `failover::EndpointSelector` struct re-exported above, so we
// alias it to `PolicySelector` for the crate-root public surface. The full
// name is available as `spt_supervisor::round_robin::EndpointSelector`.
pub use round_robin::{
    make_selector as make_policy_selector, DnsResolver, DnsRoundRobinResolver, EndpointPick,
    EndpointSelector as PolicySelector, FakeDnsResolver, FakeInstantClock, InstantClock,
    LeastErrorsSelector, RandomSelector, RoundRobinSelector, StickySelector, SystemInstantClock,
    WeightedSelector,
};
pub use session::{SessionRegistry, SessionRow, SessionState};
pub use state_machine::{
    ForwardEvent, ProfileEvent as SmEvent, ProfileStateMachine, ProfileStateName,
};
pub use stats::{ProfileStats, StatsTick, StatsTickConfig};
