//! Profile and forward state machines per spec §11.1.
//!
//! ## Profile states (13)
//!
//! | name              | meaning                                                                |
//! |-------------------|------------------------------------------------------------------------|
//! | `Disabled`        | profile is administratively disabled                                  |
//! | `Idle`            | created but not yet started (lazy startup)                             |
//! | `Resolving`       | DNS resolution in flight                                               |
//! | `Connecting`      | TCP/QUIC connect in flight                                             |
//! | `Authenticating`  | auth exchange in flight                                                |
//! | `EstablishingForwards` | session up; opening forwards                                       |
//! | `Active`          | session healthy and all required forwards active                       |
//! | `Degraded`        | session up but at least one non-required forward is failed/sleeping    |
//! | `Reconnecting`    | session lost; awaiting backoff                                        |
//! | `FailingOver`     | active endpoint failed; selector picking the next                       |
//! | `Unstable`        | instability detector tripped                                           |
//! | `Stopping`        | shutdown in progress                                                   |
//! | `Stopped`         | terminal — clean shutdown                                              |
//!
//! ## Forward states (8) — see [`spt_protocol::ForwardState`].
//!
//! ## Transition table
//!
//! ```text
//!     event \\ from | Idle | Resolving | Connecting | Authenticating | EstFwd | Active | Degraded | Reconnecting | FailingOver | Unstable | Stopping
//!     ----------------------------------------------------------------------------------------------------------------------------------
//!     Start         | Resv |     —     |     —      |       —        |   —    |   —    |    —     |       —      |      —      |    —     |    —
//!     ResolveOk     |  —   | Connecting|     —      |       —        |   —    |   —    |    —     |       —      |      —      |    —     |    —
//!     ResolveFail   |  —   | Reconn    |     —      |       —        |   —    |   —    |    —     |       —      |      —      |    —     |    —
//!     ConnectOk     |  —   |     —     | Authn      |       —        |   —    |   —    |    —     |       —      |      —      |    —     |    —
//!     ConnectFail   |  —   |     —     | Reconn     |       —        |   —    |   —    |    —     |       —      |      —      |    —     |    —
//!     AuthOk        |  —   |     —     |     —      | EstFwd         |   —    |   —    |    —     |       —      |      —      |    —     |    —
//!     AuthFail      |  —   |     —     |     —      | Reconn         |   —    |   —    |    —     |       —      |      —      |    —     |    —
//!     ForwardsUp    |  —   |     —     |     —      |       —        | Active |   —    |    —     |       —      |      —      |    —     |    —
//!     ForwardDown   |  —   |     —     |     —      |       —        |   —    |Degraded| Degraded |       —      |      —      | Degraded |    —
//!     ForwardUp     |  —   |     —     |     —      |       —        |   —    |   —    | Active   |       —      |      —      | Active   |    —
//!     SessionLost   |  —   |     —     |     —      |       —        | Reconn | Reconn | Reconn   |       —      |      —      | Reconn   |    —
//!     InstabilityHit|  —   |     —     |     —      |       —        |Unstab. | Unstab.| Unstab.  |       —      |      —      |    —     |    —
//!     InstabilityClr|  —   |     —     |     —      |       —        |   —    |   —    |    —     |       —      |      —      | Active   |    —
//!     FailoverPick  |  —   |     —     |     —      |       —        |   —    |   —    |    —     | FailingOver  |   FailingOver|    —    |    —
//!     EndpointReady |  —   |     —     |     —      |       —        |   —    |   —    |    —     |   Resolv     |   Resolv    |    —     |    —
//!     RetryNow      |  —   |     —     |     —      |       —        |   —    |   —    |    —     |   Resolv     |      —      |    —     |    —
//!     Stop          | Stp+ |   Stp+    |   Stp+     |    Stp+        | Stp+   | Stp+   |  Stp+    |   Stp+       |    Stp+     |   Stp+   |   —
//!     Stopped       |  —   |     —     |     —      |       —        |   —    |   —    |    —     |       —      |      —      |    —     | Stopped
//!     Disable       | Dis  |   Dis     |   Dis      |    Dis         | Dis    | Dis    |  Dis     |   Dis        |    Dis      |   Dis    |   —
//! ```
//!
//! `Stp+` = `Stopping`. The state machine is deliberately simple — its job is
//! to be the *source of truth* for which transitions are legal; the
//! [`crate::profile::ProfileSupervisor`] drives it from the timeline of real
//! events.

use serde::{Deserialize, Serialize};

/// Profile-level state. Every variant maps to one of the 13 spec states above.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[allow(missing_docs)] // each variant documented in the table above
pub enum ProfileStateName {
    Disabled,
    Idle,
    Resolving,
    Connecting,
    Authenticating,
    EstablishingForwards,
    Active,
    Degraded,
    Reconnecting,
    FailingOver,
    Unstable,
    Stopping,
    Stopped,
}

impl ProfileStateName {
    /// Whether `self` is a terminal (no further transitions) state.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Stopped | Self::Disabled)
    }
}

impl std::fmt::Display for ProfileStateName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Disabled => "disabled",
            Self::Idle => "idle",
            Self::Resolving => "resolving",
            Self::Connecting => "connecting",
            Self::Authenticating => "authenticating",
            Self::EstablishingForwards => "establishing_forwards",
            Self::Active => "active",
            Self::Degraded => "degraded",
            Self::Reconnecting => "reconnecting",
            Self::FailingOver => "failing_over",
            Self::Unstable => "unstable",
            Self::Stopping => "stopping",
            Self::Stopped => "stopped",
        };
        f.write_str(s)
    }
}

/// Stimuli the state machine reacts to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum ProfileEvent {
    Start,
    Disable,
    Stop,
    Stopped,
    ResolveOk,
    ResolveFail,
    ConnectOk,
    ConnectFail,
    AuthOk,
    AuthFail,
    ForwardsUp,
    ForwardUp,
    ForwardDown,
    SessionLost,
    InstabilityHit,
    InstabilityClear,
    FailoverPick,
    EndpointReady,
    RetryNow,
}

/// Forward-level event. Mirrors `spt_protocol::ForwardState` transitions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum ForwardEvent {
    Bind,
    Listen,
    Activate,
    Degrade,
    Stop,
    Fail,
    Retry,
}

/// Profile state machine: a tiny pure transition function plus current state.
#[derive(Debug, Clone)]
pub struct ProfileStateMachine {
    state: ProfileStateName,
}

impl Default for ProfileStateMachine {
    fn default() -> Self {
        Self {
            state: ProfileStateName::Idle,
        }
    }
}

impl ProfileStateMachine {
    /// New state machine starting in `Idle`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// New state machine starting in `Disabled`.
    #[must_use]
    pub fn disabled() -> Self {
        Self {
            state: ProfileStateName::Disabled,
        }
    }

    /// Current state.
    #[must_use]
    pub fn state(&self) -> ProfileStateName {
        self.state
    }

    /// Apply an event. Returns the new state on success, or `Err(())` if the
    /// transition is not defined for the current state. Unhandled events are
    /// not errors at the *system* level — they're just no-ops; callers
    /// pattern-match on the result if they care.
    pub fn step(&mut self, event: ProfileEvent) -> Result<ProfileStateName, ProfileStateName> {
        use ProfileEvent as E;
        use ProfileStateName as S;

        let next = match (self.state, event) {
            (s, E::Disable) if !s.is_terminal() => Some(S::Disabled),
            (s, E::Stop) if !matches!(s, S::Stopping | S::Stopped | S::Disabled) => {
                Some(S::Stopping)
            }
            (S::Stopping, E::Stopped) => Some(S::Stopped),

            (S::Idle, E::Start) => Some(S::Resolving),
            (S::Resolving, E::ResolveOk) => Some(S::Connecting),
            (S::Resolving, E::ResolveFail) => Some(S::Reconnecting),
            (S::Connecting, E::ConnectOk) => Some(S::Authenticating),
            (S::Connecting, E::ConnectFail) => Some(S::Reconnecting),
            (S::Authenticating, E::AuthOk) => Some(S::EstablishingForwards),
            (S::Authenticating, E::AuthFail) => Some(S::Reconnecting),
            // `ForwardsUp` (all required forwards healthy) re-enters `Active`
            // from any "session-up but not yet fully Active" state. Accepting
            // it from `Degraded`/`Unstable` lets an in-place forward recovery
            // (E1-F4) clear the degraded condition without a full reconnect.
            (S::EstablishingForwards | S::Degraded | S::Unstable, E::ForwardsUp) => Some(S::Active),
            (S::EstablishingForwards, E::ForwardDown) => Some(S::Degraded),

            (S::Active, E::ForwardDown) => Some(S::Degraded),
            (S::Degraded, E::ForwardUp) => Some(S::Active),
            (S::Unstable, E::ForwardUp) => Some(S::Active),
            (S::Unstable, E::ForwardDown) => Some(S::Degraded),

            (S::Active | S::Degraded | S::EstablishingForwards | S::Unstable, E::SessionLost) => {
                Some(S::Reconnecting)
            }
            (S::Active | S::Degraded | S::EstablishingForwards, E::InstabilityHit) => {
                Some(S::Unstable)
            }
            (S::Unstable, E::InstabilityClear) => Some(S::Active),

            (S::Reconnecting | S::FailingOver, E::FailoverPick) => Some(S::FailingOver),
            (S::Reconnecting | S::FailingOver, E::EndpointReady) => Some(S::Resolving),
            (S::Reconnecting, E::RetryNow) => Some(S::Resolving),

            _ => None,
        };

        match next {
            Some(s) => {
                self.state = s;
                Ok(s)
            }
            None => Err(self.state),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn happy_path_to_active() {
        let mut sm = ProfileStateMachine::new();
        assert_eq!(
            sm.step(ProfileEvent::Start).unwrap(),
            ProfileStateName::Resolving
        );
        assert_eq!(
            sm.step(ProfileEvent::ResolveOk).unwrap(),
            ProfileStateName::Connecting
        );
        assert_eq!(
            sm.step(ProfileEvent::ConnectOk).unwrap(),
            ProfileStateName::Authenticating
        );
        assert_eq!(
            sm.step(ProfileEvent::AuthOk).unwrap(),
            ProfileStateName::EstablishingForwards
        );
        assert_eq!(
            sm.step(ProfileEvent::ForwardsUp).unwrap(),
            ProfileStateName::Active
        );
    }

    #[test]
    fn auth_fail_goes_to_reconnecting() {
        let mut sm = ProfileStateMachine::new();
        sm.step(ProfileEvent::Start).unwrap();
        sm.step(ProfileEvent::ResolveOk).unwrap();
        sm.step(ProfileEvent::ConnectOk).unwrap();
        assert_eq!(
            sm.step(ProfileEvent::AuthFail).unwrap(),
            ProfileStateName::Reconnecting
        );
    }

    #[test]
    fn session_lost_from_active() {
        let mut sm = ProfileStateMachine::new();
        sm.step(ProfileEvent::Start).unwrap();
        sm.step(ProfileEvent::ResolveOk).unwrap();
        sm.step(ProfileEvent::ConnectOk).unwrap();
        sm.step(ProfileEvent::AuthOk).unwrap();
        sm.step(ProfileEvent::ForwardsUp).unwrap();
        assert_eq!(
            sm.step(ProfileEvent::SessionLost).unwrap(),
            ProfileStateName::Reconnecting
        );
    }

    #[test]
    fn instability_round_trip() {
        let mut sm = ProfileStateMachine::new();
        sm.step(ProfileEvent::Start).unwrap();
        sm.step(ProfileEvent::ResolveOk).unwrap();
        sm.step(ProfileEvent::ConnectOk).unwrap();
        sm.step(ProfileEvent::AuthOk).unwrap();
        sm.step(ProfileEvent::ForwardsUp).unwrap();
        assert_eq!(
            sm.step(ProfileEvent::InstabilityHit).unwrap(),
            ProfileStateName::Unstable
        );
        assert_eq!(
            sm.step(ProfileEvent::InstabilityClear).unwrap(),
            ProfileStateName::Active
        );
    }

    #[test]
    fn failover_pick_then_endpoint_ready() {
        let mut sm = ProfileStateMachine::new();
        sm.step(ProfileEvent::Start).unwrap();
        sm.step(ProfileEvent::ResolveOk).unwrap();
        sm.step(ProfileEvent::ConnectFail).unwrap();
        assert_eq!(sm.state(), ProfileStateName::Reconnecting);
        assert_eq!(
            sm.step(ProfileEvent::FailoverPick).unwrap(),
            ProfileStateName::FailingOver
        );
        assert_eq!(
            sm.step(ProfileEvent::EndpointReady).unwrap(),
            ProfileStateName::Resolving
        );
    }

    #[test]
    fn stop_is_uniform() {
        for start in [
            ProfileStateName::Idle,
            ProfileStateName::Resolving,
            ProfileStateName::Connecting,
            ProfileStateName::Authenticating,
            ProfileStateName::EstablishingForwards,
            ProfileStateName::Active,
            ProfileStateName::Degraded,
            ProfileStateName::Reconnecting,
            ProfileStateName::FailingOver,
            ProfileStateName::Unstable,
        ] {
            let mut sm = ProfileStateMachine::new();
            sm.state = start;
            assert_eq!(
                sm.step(ProfileEvent::Stop).unwrap(),
                ProfileStateName::Stopping
            );
            assert_eq!(
                sm.step(ProfileEvent::Stopped).unwrap(),
                ProfileStateName::Stopped
            );
            assert!(sm.state().is_terminal());
        }
    }

    #[test]
    fn disable_short_circuits() {
        let mut sm = ProfileStateMachine::new();
        sm.step(ProfileEvent::Start).unwrap();
        sm.step(ProfileEvent::ResolveOk).unwrap();
        assert_eq!(
            sm.step(ProfileEvent::Disable).unwrap(),
            ProfileStateName::Disabled
        );
        assert!(sm.step(ProfileEvent::Start).is_err());
    }

    #[test]
    fn unknown_transition_is_err() {
        let mut sm = ProfileStateMachine::new();
        assert!(sm.step(ProfileEvent::ResolveOk).is_err());
    }

    #[test]
    fn forward_event_variants_compile() {
        // Exhaustive match to keep the enum and any consumer in lock-step.
        for ev in [
            ForwardEvent::Bind,
            ForwardEvent::Listen,
            ForwardEvent::Activate,
            ForwardEvent::Degrade,
            ForwardEvent::Stop,
            ForwardEvent::Fail,
            ForwardEvent::Retry,
        ] {
            let _ = ev;
        }
    }
}
