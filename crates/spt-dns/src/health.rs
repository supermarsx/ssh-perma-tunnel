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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forward_health_default_is_all_down() {
        let h = ForwardHealth::default();
        assert!(!h.listening);
        assert!(!h.healthy);
        assert_eq!(h, ForwardHealth::down());
    }

    #[test]
    fn forward_health_up_and_down_constructors() {
        let up = ForwardHealth::up();
        assert!(up.listening);
        assert!(up.healthy);

        let down = ForwardHealth::down();
        assert!(!down.listening);
        assert!(!down.healthy);

        // Equality + Copy + Clone (derives) exercised.
        let copy = up;
        let cloned = up;
        assert_eq!(copy, cloned);
        assert_ne!(up, down);
    }

    #[test]
    fn forward_health_debug_renders() {
        // Just confirm Debug is wired (catches accidental removal of the derive).
        let s = format!("{:?}", ForwardHealth::up());
        assert!(s.contains("listening"));
        assert!(s.contains("healthy"));
    }

    #[test]
    fn no_health_returns_down_for_any_id() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        rt.block_on(async {
            let src = NoHealth;
            assert_eq!(src.forward_health("").await, ForwardHealth::down());
            assert_eq!(src.forward_health("p/f").await, ForwardHealth::down());
            assert_eq!(
                src.forward_health("any/garbage-id").await,
                ForwardHealth::down()
            );
        });
    }

    #[test]
    fn always_healthy_returns_up_for_any_id() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        rt.block_on(async {
            let src = AlwaysHealthy;
            assert_eq!(src.forward_health("p/f").await, ForwardHealth::up());
            assert_eq!(src.forward_health("").await, ForwardHealth::up());
        });
    }

    #[test]
    fn no_health_is_send_sync_and_usable_as_trait_object() {
        // The HealthSource trait demands Send + Sync + 'static — confirm Arc<dyn _>
        // composes cleanly so the wiring in server.rs is not silently broken.
        let _: std::sync::Arc<dyn HealthSource> = std::sync::Arc::new(NoHealth);
        let _: std::sync::Arc<dyn HealthSource> = std::sync::Arc::new(AlwaysHealthy);
    }
}
