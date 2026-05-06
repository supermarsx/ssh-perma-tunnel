//! Health-source trait used to gate `AnswerWhenListening` /
//! `AnswerWhenHealthy` answers on the live state of forwards.
//!
//! `spt-dns` does not depend on `spt-supervisor` (it sits in the dep arrow
//! pointing the other way: supervisor calls into dns at startup, not the
//! reverse). So we expose a trait the binary wires up at runtime.

use async_trait::async_trait;

/// Live state of a single forward, as seen by the supervisor.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ForwardHealth {
    /// At least one listener socket is bound and accepting.
    pub listening: bool,
    /// Profile + forward state machines both report healthy (running with a
    /// live session, no unrecoverable error).
    pub healthy: bool,
}

impl ForwardHealth {
    /// Convenience: both flags off.
    #[must_use]
    pub const fn down() -> Self {
        Self {
            listening: false,
            healthy: false,
        }
    }

    /// Convenience: both flags on.
    #[must_use]
    pub const fn up() -> Self {
        Self {
            listening: true,
            healthy: true,
        }
    }
}

/// A read-only window onto forward health. Implementations live in `spt-bin`
/// (production) and in tests (mocks).
#[async_trait]
pub trait HealthSource: Send + Sync + 'static {
    /// Look up health for `forward_id` (format: `<profile>/<forward>`).
    /// Unknown ids return [`ForwardHealth::down`].
    async fn forward_health(&self, forward_id: &str) -> ForwardHealth;
}

/// Always-down [`HealthSource`] used as a default when no real source is
/// wired. Records with `AnswerWhen{Listening,Healthy}` will be filtered out
/// when this source is in use. Records with `AlwaysAnswer` are unaffected.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoHealth;

#[async_trait]
impl HealthSource for NoHealth {
    async fn forward_health(&self, _forward_id: &str) -> ForwardHealth {
        ForwardHealth::down()
    }
}

/// All-up [`HealthSource`] used to make `AnswerWhen*` records always pass —
/// useful for tests and for static-zone deployments where there is no
/// supervisor.
#[derive(Debug, Default, Clone, Copy)]
pub struct AlwaysHealthy;

#[async_trait]
impl HealthSource for AlwaysHealthy {
    async fn forward_health(&self, _forward_id: &str) -> ForwardHealth {
        ForwardHealth::up()
    }
}
