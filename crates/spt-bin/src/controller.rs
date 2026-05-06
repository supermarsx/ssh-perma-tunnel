//! `spt_mcp::Controller` implementation backed by the orchestrator.
//!
//! Mutating MCP tools route runtime control operations through this trait.
//! In M0 most surface returns `NotImplemented` because hot per-forward
//! mutation isn't yet supported by `spt-supervisor`'s public API; what _is_
//! supported (`reload`, `profile_start`, `profile_stop`) goes through the
//! orchestrator directly.

use std::sync::Arc;

use async_trait::async_trait;
use serde_json::Value;
use spt_mcp::{Controller, Error as McpError, Result as McpResult};
use spt_supervisor::Orchestrator;

/// Controller backed by an [`Orchestrator`] handle.
pub struct OrchestratorController {
    inner: Arc<Orchestrator>,
}

impl OrchestratorController {
    pub fn new(inner: Arc<Orchestrator>) -> Self {
        Self { inner }
    }
}

#[async_trait]
impl Controller for OrchestratorController {
    async fn reload(&self) -> McpResult<Value> {
        // Reload requires re-reading the config file; the binary's own
        // reload pipeline owns that flow. The MCP entry point currently
        // signals the supervisor to noop-reload — wired up properly in M9.
        Err(McpError::NotImplemented(
            "Controller::reload (orchestrator reload pipeline tracked in M9)",
        ))
    }

    async fn failover(&self, _profile: &str) -> McpResult<Value> {
        Err(McpError::NotImplemented(
            "Controller::failover (manual failover tool tracked in M9)",
        ))
    }

    async fn profile_start(&self, _profile: &str) -> McpResult<Value> {
        // The orchestrator's `start_profile` requires a TunnelProtocol +
        // AuthConfig + Endpoints + ProfileSupervisorConfig — all of which
        // live in the binary's per-process wiring, not in the controller.
        // A future M9 refactor exposes a re-start entry that reads them
        // from the cached config; for now we surface NotImplemented.
        Err(McpError::NotImplemented(
            "Controller::profile_start (re-start from cached config tracked in M9)",
        ))
    }

    async fn profile_stop(&self, profile: &str) -> McpResult<Value> {
        self.inner.stop_profile(profile).await;
        Ok(Value::Null)
    }

    async fn forward_add(&self, _profile: &str, _spec: Value) -> McpResult<Value> {
        Err(McpError::NotImplemented(
            "Controller::forward_add (per-forward mutation tracked in M9)",
        ))
    }

    async fn forward_remove(&self, _profile: &str, _forward_id: &str) -> McpResult<Value> {
        Err(McpError::NotImplemented(
            "Controller::forward_remove (per-forward mutation tracked in M9)",
        ))
    }
}
