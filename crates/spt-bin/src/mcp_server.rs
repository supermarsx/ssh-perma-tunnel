//! Thin wrapper that wires `spt_mcp::McpServer` with the binary's adapters.

use std::sync::Arc;

use spt_mcp::{McpPolicy, McpServer, NoopSources, Policy};

/// Build an MCP server with all-noop sources/controller and the supplied
/// policy. The binary uses the noop wiring for `mcp serve` until the full
/// adapter set is connected to the running orchestrator (tracked in M9).
pub fn build_noop_server(policy: McpPolicy) -> McpServer {
    let sources = Arc::new(NoopSources);
    McpServer::new(
        Policy::new(policy),
        Arc::new(spt_mcp::NoopAuditSink),
        Arc::new(spt_mcp::NoopController),
        sources.clone() as spt_mcp::sources::DynConfigSource,
        sources as spt_mcp::sources::DynStateSource,
    )
}
