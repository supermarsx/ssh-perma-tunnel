//! JSON-RPC 2.0 envelope types and the small MCP method/response shapes used
//! by this server.
//!
//! Only the subset needed for the 16 resources and 31 tools listed in spec
//! §16 is modelled here — namely:
//!
//! - `initialize` (request → result with capabilities)
//! - `initialized` (notification, server has no response)
//! - `resources/list`, `resources/read`
//! - `tools/list`, `tools/call`
//! - `notifications/*` for server→client streaming
//!
//! The [`Request`] and [`Response`] envelopes follow JSON-RPC 2.0 verbatim.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// JSON-RPC 2.0 request id. Per the spec it is a number, string, or null;
/// notifications omit the field entirely.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum Id {
    /// Numeric id.
    Num(i64),
    /// String id.
    Str(String),
    /// Explicit null.
    Null,
}

/// Inbound JSON-RPC request or notification (notifications omit `id`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Request {
    /// Always `"2.0"`.
    pub jsonrpc: String,
    /// Optional id; absent means notification.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<Id>,
    /// Method name, e.g. `"resources/list"`.
    pub method: String,
    /// Optional positional/named params.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
}

impl Request {
    /// Returns true if this is a notification (no `id`).
    #[must_use]
    pub fn is_notification(&self) -> bool {
        self.id.is_none()
    }
}

/// JSON-RPC error object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcError {
    /// Numeric error code (see [`crate::error::Error::rpc_code`]).
    pub code: i64,
    /// Short human-readable message.
    pub message: String,
    /// Optional structured detail.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

/// JSON-RPC response (either result xor error).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response {
    /// Always `"2.0"`.
    pub jsonrpc: String,
    /// Echo of the request id.
    pub id: Id,
    /// Result payload on success.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    /// Error payload on failure.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<RpcError>,
}

impl Response {
    /// Build a successful response.
    #[must_use]
    pub fn ok(id: Id, result: Value) -> Self {
        Self {
            jsonrpc: "2.0".to_owned(),
            id,
            result: Some(result),
            error: None,
        }
    }

    /// Build an error response.
    #[must_use]
    pub fn err(id: Id, code: i64, message: impl Into<String>) -> Self {
        Self {
            jsonrpc: "2.0".to_owned(),
            id,
            result: None,
            error: Some(RpcError {
                code,
                message: message.into(),
                data: None,
            }),
        }
    }
}

/// MCP resource descriptor returned by `resources/list`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceDescriptor {
    /// Stable URI such as `spt://config/effective`.
    pub uri: String,
    /// Human-readable display name.
    pub name: String,
    /// Short description for client UIs.
    pub description: String,
    /// MIME type of the body returned by `resources/read`.
    #[serde(rename = "mimeType")]
    pub mime_type: String,
}

/// MCP tool descriptor returned by `tools/list`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolDescriptor {
    /// Stable tool name such as `forward_add`.
    pub name: String,
    /// Short description.
    pub description: String,
    /// JSON-Schema for the `arguments` map.
    #[serde(rename = "inputSchema")]
    pub input_schema: Value,
}
