//! Model Context Protocol (MCP) server implementation for `spt`.
//!
//! This crate provides a JSON-RPC 2.0 MCP server with two transports:
//!
//! - `stdio` — line-delimited JSON-RPC over stdin/stdout (implemented).
//! - `loopback` — TCP on `127.0.0.1` (placeholder; returns `Error::NotImplemented`).
//!
//! The MCP server is **disabled by default**, **read-only by default**, and
//! **never returns plaintext secrets**. Mutating tools require their name to
//! appear in [`McpPolicy::allow_write_tools`]. Every tool invocation is recorded
//! via the [`McpAuditSink`] trait — `spt-events` provides the production
//! implementation; this crate ships a no-op default and a test-friendly mock.
//!
//! # Architecture
//!
//! - [`server::McpServer`] is the entry point. It owns transport, registries,
//!   policy, audit sink, and the [`Controller`] / data-source adapters.
//! - [`resources`] hosts the 16 read-only resource handlers (one file each).
//! - [`tools`] hosts the 31 tool handlers (one file each), registered through
//!   the `register_tool!` macro.
//! - [`policy::Policy`] applies the redaction pass and the write allow-list.
//! - [`audit`] defines [`McpAuditSink`] and a no-op default.
//! - [`transport`] wraps the JSON-RPC framing layer.
//!
//! # Cross-crate
//!
//! `spt-mcp` does **not** depend on `spt-bin`. Runtime control (start/stop,
//! reload, failover) is delegated to a [`Controller`] trait the binary
//! implements over the orchestrator. Configuration and runtime state are read
//! through [`ConfigSource`] and [`StateSource`] adapters that the binary wires
//! to `spt-config`/`spt-state` public APIs.

#[cfg(any(test, feature = "testing"))]
pub mod testing;

pub mod audit;
pub mod controller;
pub mod error;
pub mod policy;
pub mod protocol;
pub mod resources;
pub mod server;
pub mod sources;
pub mod tools;
pub mod transport;

pub use audit::{AuditEvent, McpAuditSink, NoopAuditSink};
pub use controller::{Controller, NoopController};
pub use error::{Error, Result};
pub use policy::{McpPolicy, Policy};
pub use server::{McpServer, McpServerInner, ServerCapabilities};
pub use sources::{ConfigSource, NoopSources, StateSource};
pub use transport::{
    loopback::LoopbackTransport, stdio::StdioTransport, LoopbackConfig, Transport, TransportConfig,
    TransportKind,
};
