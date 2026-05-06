//! Runtime control surface used by mutating tools.
//!
//! `spt-mcp` does not depend on `spt-bin` or the orchestrator directly.
//! Instead, the binary implements the [`Controller`] trait over its
//! supervisor channels, and hands an `Arc<dyn Controller>` to the
//! [`crate::server::McpServer`].

use async_trait::async_trait;
use serde_json::Value;
use std::sync::Arc;

/// Runtime control operations exposed to mutating MCP tools.
///
/// All methods take small JSON payloads so the trait stays stable as the
/// underlying orchestrator evolves. A return value of [`Value::Null`] is
/// idiomatic for "operation accepted, no payload".
#[async_trait]
pub trait Controller: Send + Sync + 'static {
    /// Reload configuration from disk and reconcile profile state.
    async fn reload(&self) -> crate::Result<Value>;

    /// Force a failover step on the named profile.
    async fn failover(&self, profile: &str) -> crate::Result<Value>;

    /// Start a profile that is currently `stopped`/`disabled`.
    async fn profile_start(&self, profile: &str) -> crate::Result<Value>;

    /// Stop a profile and tear down its forwards.
    async fn profile_stop(&self, profile: &str) -> crate::Result<Value>;

    /// Add a forward to a profile at runtime, after persisting it through the
    /// `spt-config` mutation path.
    async fn forward_add(&self, profile: &str, spec: Value) -> crate::Result<Value>;

    /// Remove a forward by id from a profile, persisting the change.
    async fn forward_remove(&self, profile: &str, forward_id: &str) -> crate::Result<Value>;
}

/// Default no-op controller for embedding harnesses and tests. Every method
/// returns [`crate::Error::NotImplemented`].
#[derive(Debug, Default, Clone)]
pub struct NoopController;

#[async_trait]
impl Controller for NoopController {
    async fn reload(&self) -> crate::Result<Value> {
        Err(crate::Error::NotImplemented("Controller::reload"))
    }
    async fn failover(&self, _profile: &str) -> crate::Result<Value> {
        Err(crate::Error::NotImplemented("Controller::failover"))
    }
    async fn profile_start(&self, _profile: &str) -> crate::Result<Value> {
        Err(crate::Error::NotImplemented("Controller::profile_start"))
    }
    async fn profile_stop(&self, _profile: &str) -> crate::Result<Value> {
        Err(crate::Error::NotImplemented("Controller::profile_stop"))
    }
    async fn forward_add(&self, _profile: &str, _spec: Value) -> crate::Result<Value> {
        Err(crate::Error::NotImplemented("Controller::forward_add"))
    }
    async fn forward_remove(&self, _profile: &str, _forward_id: &str) -> crate::Result<Value> {
        Err(crate::Error::NotImplemented("Controller::forward_remove"))
    }
}

/// Convenience alias for the boxed controller used by the server.
pub type DynController = Arc<dyn Controller>;
