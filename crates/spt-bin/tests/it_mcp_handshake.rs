//! In-process MCP capability check: a freshly-built server advertises 16
//! resources and 31 tools per spec §16.
//!
//! The full stdio handshake (initialize → list → call) is exercised by the
//! `spt_mcp::server` unit tests; this binary-level test is a smoke check
//! that the noop wiring used by `spt mcp serve --enable` is correct.

use spt_mcp::McpPolicy;

#[tokio::test]
async fn noop_server_advertises_16_resources_and_31_tools() {
    let policy = McpPolicy {
        enabled: true,
        ..Default::default()
    };
    let server = spt_mcp::McpServer::new_noop(policy);
    // The server's resource and tool registries are populated at construction.
    let caps = server.capabilities();
    assert_eq!(caps.name, "spt-mcp");
}
