//! Thin wrapper that wires `spt_mcp::McpServer` with the binary's adapters.

use std::sync::Arc;

use spt_mcp::{Controller, McpPolicy, McpServer, NoopSources, Policy};

/// Build an MCP server with all-noop sources, given an arbitrary controller.
///
/// `[mcp]` config sources / state sources are still M9 work — we hand the
/// server `NoopSources` so resource reads return shape-only fixtures. The
/// controller, audit sink, and policy are real wiring once the caller passes
/// a real `OrchestratorController`.
pub fn build_server(policy: McpPolicy, controller: Arc<dyn Controller>) -> McpServer {
    let sources = Arc::new(NoopSources);
    McpServer::new(
        Policy::new(policy),
        Arc::new(spt_mcp::NoopAuditSink),
        controller,
        sources.clone() as spt_mcp::sources::DynConfigSource,
        sources as spt_mcp::sources::DynStateSource,
    )
}

/// Build an MCP server with all-noop sources/controller and the supplied
/// policy. Used by `spt mcp serve` when the binary has no running
/// orchestrator (i.e. ad-hoc inspection / smoke tests).
pub fn build_noop_server(policy: McpPolicy) -> McpServer {
    build_server(policy, Arc::new(spt_mcp::NoopController))
}
