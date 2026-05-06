//! Runtime control surface used by mutating tools.
//!
//! `spt-mcp` does not depend on `spt-bin` or the orchestrator directly.
//! Instead, the binary implements the [`Controller`] trait over its
//! supervisor channels, and hands an `Arc<dyn Controller>` to the
//! [`crate::server::McpServer`].
//!
//! # Semantics
//!
//! The trait describes intent only — implementations decide how to persist
//! and reconcile. Concretely, the production impl in `spt-bin`:
//!
//! - [`Controller::reload`] re-reads the on-disk config and calls
//!   `spt_supervisor::Orchestrator::reload(new_config)`.
//! - [`Controller::failover`] marks the current endpoint failed on the named
//!   profile and asks the supervisor to advance to the next.
//! - [`Controller::profile_start`] / [`Controller::profile_stop`] map onto
//!   `spt_supervisor::Orchestrator::start_profile` / `stop_profile`.
//! - [`Controller::forward_add`] / [`Controller::forward_remove`] write the
//!   change to the on-disk config via `spt_config::mutate::*` and trigger
//!   [`Controller::reload`]; the supervisor diff-reconciles forwards without
//!   restarting the whole profile.

use async_trait::async_trait;
use spt_config::schema::Forward;
use std::sync::Arc;

/// Runtime control operations exposed to mutating MCP tools.
///
/// Methods are ordered "least-to-most invasive". Implementations must be
/// `Send + Sync + 'static` so the server can hand them out to spawned
/// per-connection tasks under the loopback transport.
#[async_trait]
pub trait Controller: Send + Sync + 'static {
    /// Reload configuration from disk and reconcile profile state.
    async fn reload(&self) -> crate::Result<()>;

    /// Force a failover step on the named profile.
    ///
    /// `endpoint` optionally pins which endpoint to mark failed; passing
    /// `None` lets the supervisor decide.
    async fn failover(&self, profile: &str, endpoint: Option<&str>) -> crate::Result<()>;

    /// Start a profile that is currently `stopped`/`disabled`.
    async fn profile_start(&self, profile: &str) -> crate::Result<()>;

    /// Stop a profile and tear down its forwards.
    async fn profile_stop(&self, profile: &str) -> crate::Result<()>;

    /// Add a forward to a profile. Implementations are expected to persist
    /// the change through `spt_config::mutate::*` then trigger a reload.
    async fn forward_add(&self, profile: &str, forward: &Forward) -> crate::Result<()>;

    /// Remove a forward from a profile by id. Implementations are expected
    /// to persist the change and trigger a reload.
    async fn forward_remove(&self, profile: &str, forward_id: &str) -> crate::Result<()>;
}

/// Default no-op controller for embedding harnesses and tests. Every method
/// returns [`crate::Error::NotImplemented`].
#[derive(Debug, Default, Clone)]
pub struct NoopController;

#[async_trait]
impl Controller for NoopController {
    async fn reload(&self) -> crate::Result<()> {
        Err(crate::Error::NotImplemented("Controller::reload"))
    }
    async fn failover(&self, _profile: &str, _endpoint: Option<&str>) -> crate::Result<()> {
        Err(crate::Error::NotImplemented("Controller::failover"))
    }
    async fn profile_start(&self, _profile: &str) -> crate::Result<()> {
        Err(crate::Error::NotImplemented("Controller::profile_start"))
    }
    async fn profile_stop(&self, _profile: &str) -> crate::Result<()> {
        Err(crate::Error::NotImplemented("Controller::profile_stop"))
    }
    async fn forward_add(&self, _profile: &str, _forward: &Forward) -> crate::Result<()> {
        Err(crate::Error::NotImplemented("Controller::forward_add"))
    }
    async fn forward_remove(&self, _profile: &str, _forward_id: &str) -> crate::Result<()> {
        Err(crate::Error::NotImplemented("Controller::forward_remove"))
    }
}

/// Convenience alias for the boxed controller used by the server.
pub type DynController = Arc<dyn Controller>;

#[cfg(test)]
pub(crate) mod testing {
    //! Test-only fixtures.

    use super::{Controller, Forward};
    use async_trait::async_trait;
    use parking_lot::Mutex;
    use std::sync::Arc;

    /// One captured controller invocation.
    #[derive(Debug, Clone, PartialEq)]
    #[allow(clippy::large_enum_variant)]
    pub enum ControllerCall {
        Reload,
        Failover {
            profile: String,
            endpoint: Option<String>,
        },
        ProfileStart {
            profile: String,
        },
        ProfileStop {
            profile: String,
        },
        ForwardAdd {
            profile: String,
            forward: Forward,
        },
        ForwardRemove {
            profile: String,
            forward_id: String,
        },
    }

    /// In-memory recording controller used by the unit tests.
    #[derive(Debug, Default, Clone)]
    pub struct RecordingController {
        calls: Arc<Mutex<Vec<ControllerCall>>>,
    }

    impl RecordingController {
        pub fn new() -> Self {
            Self::default()
        }

        pub fn snapshot(&self) -> Vec<ControllerCall> {
            self.calls.lock().clone()
        }
    }

    #[async_trait]
    impl Controller for RecordingController {
        async fn reload(&self) -> crate::Result<()> {
            self.calls.lock().push(ControllerCall::Reload);
            Ok(())
        }
        async fn failover(&self, profile: &str, endpoint: Option<&str>) -> crate::Result<()> {
            self.calls.lock().push(ControllerCall::Failover {
                profile: profile.to_owned(),
                endpoint: endpoint.map(str::to_owned),
            });
            Ok(())
        }
        async fn profile_start(&self, profile: &str) -> crate::Result<()> {
            self.calls.lock().push(ControllerCall::ProfileStart {
                profile: profile.to_owned(),
            });
            Ok(())
        }
        async fn profile_stop(&self, profile: &str) -> crate::Result<()> {
            self.calls.lock().push(ControllerCall::ProfileStop {
                profile: profile.to_owned(),
            });
            Ok(())
        }
        async fn forward_add(&self, profile: &str, forward: &Forward) -> crate::Result<()> {
            self.calls.lock().push(ControllerCall::ForwardAdd {
                profile: profile.to_owned(),
                forward: forward.clone(),
            });
            Ok(())
        }
        async fn forward_remove(&self, profile: &str, forward_id: &str) -> crate::Result<()> {
            self.calls.lock().push(ControllerCall::ForwardRemove {
                profile: profile.to_owned(),
                forward_id: forward_id.to_owned(),
            });
            Ok(())
        }
    }
}
