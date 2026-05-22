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
use serde_json::Value;
use spt_config::schema::Forward;
use std::sync::Arc;
use tokio::sync::mpsc;

/// Runtime control operations exposed to mutating MCP tools.
///
/// Methods are ordered "least-to-most invasive". Implementations must be
/// `Send + Sync + 'static` so the server can hand them out to spawned
/// per-connection tasks under the loopback transport.
///
/// # Default behavior
///
/// Four methods have default implementations that return
/// [`crate::Error::NotImplemented`]: [`Controller::session_close`],
/// [`Controller::session_drain`], [`Controller::stats_subscribe`], and
/// [`Controller::run_benchmark`]. The defaults exist so embedders that only
/// need the read-only surface (or only the six required mutators) can adopt
/// the trait without breaking changes. Embedders SHOULD override every
/// method before exposing the controller over MCP — operators connecting a
/// stock client will otherwise see `-32003 not implemented` for the four
/// session/stats/benchmark tools.
///
/// The `it_controller_contract.rs` integration test in this crate pins the
/// default behavior (one assertion per default-impl method). The
/// `it_orchestrator_controller_contract.rs` test in `spt-bin` ensures the
/// production `OrchestratorController` overrides every default. Adding a
/// new defaulted method to this trait requires updating both tests.
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

    /// Close a single live session by id.
    async fn session_close(&self, session_id: &str) -> crate::Result<()> {
        let _ = session_id;
        Err(crate::Error::NotImplemented("Controller::session_close"))
    }

    /// Drain all forwards of `profile` with the given grace, return a JSON
    /// summary (`{"drained": N, "force_closed": N, "already_closed": N}`).
    async fn session_drain(&self, profile: &str, grace_seconds: u64) -> crate::Result<Value> {
        let _ = (profile, grace_seconds);
        Err(crate::Error::NotImplemented("Controller::session_drain"))
    }

    /// Spawn a background task that pushes `StatsTick`-shaped JSON values
    /// onto the supplied channel until the receiver drops. Returns once the
    /// task has been spawned. Implementations should respect the requested
    /// `interval_ms` (or treat 0 as "use default").
    async fn stats_subscribe(
        &self,
        interval_ms: u64,
        tx: mpsc::Sender<Value>,
    ) -> crate::Result<()> {
        let _ = (interval_ms, tx);
        Err(crate::Error::NotImplemented("Controller::stats_subscribe"))
    }

    /// Run a benchmark driver against the live tunnel. The implementation
    /// may consult the running orchestrator's `live_connector(profile,
    /// forward)`. Returns the BenchResult-shaped JSON value.
    async fn run_benchmark(&self, args: Value) -> crate::Result<Value> {
        let _ = args;
        Err(crate::Error::NotImplemented("Controller::run_benchmark"))
    }
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

#[cfg(any(test, feature = "testing"))]
pub mod testing {
    //! Test-only fixtures (in-memory recording controller).

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
        SessionClose {
            session_id: String,
        },
        SessionDrain {
            profile: String,
            grace_seconds: u64,
        },
        StatsSubscribe {
            interval_ms: u64,
        },
        RunBenchmark {
            args: serde_json::Value,
        },
    }

    /// In-memory recording controller used by the unit tests.
    #[derive(Debug, Default, Clone)]
    pub struct RecordingController {
        calls: Arc<Mutex<Vec<ControllerCall>>>,
    }

    impl RecordingController {
        /// Build an empty recording controller.
        #[must_use]
        pub fn new() -> Self {
            Self::default()
        }

        /// Snapshot of every captured call in arrival order.
        #[must_use]
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
        async fn session_close(&self, session_id: &str) -> crate::Result<()> {
            self.calls.lock().push(ControllerCall::SessionClose {
                session_id: session_id.to_owned(),
            });
            Ok(())
        }
        async fn session_drain(
            &self,
            profile: &str,
            grace_seconds: u64,
        ) -> crate::Result<serde_json::Value> {
            self.calls.lock().push(ControllerCall::SessionDrain {
                profile: profile.to_owned(),
                grace_seconds,
            });
            Ok(serde_json::json!({
                "drained": 0u32,
                "force_closed": 0u32,
                "already_closed": 0u32
            }))
        }
        async fn stats_subscribe(
            &self,
            interval_ms: u64,
            tx: tokio::sync::mpsc::Sender<serde_json::Value>,
        ) -> crate::Result<()> {
            self.calls
                .lock()
                .push(ControllerCall::StatsSubscribe { interval_ms });
            // Emit a couple of synthetic ticks so tests can observe.
            tokio::spawn(async move {
                for i in 0..3 {
                    if tx
                        .send(serde_json::json!({"tick": i, "interval_ms": interval_ms}))
                        .await
                        .is_err()
                    {
                        break;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                }
            });
            Ok(())
        }
        async fn run_benchmark(&self, args: serde_json::Value) -> crate::Result<serde_json::Value> {
            self.calls
                .lock()
                .push(ControllerCall::RunBenchmark { args: args.clone() });
            Ok(serde_json::json!({
                "ok": true,
                "args": args,
                "iterations_completed": 0,
                "iterations_attempted": 0
            }))
        }
    }
}
