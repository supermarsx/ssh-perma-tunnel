//! Error type for the MCP server.

use thiserror::Error;

/// Crate-wide result alias.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors produced by the MCP server.
///
/// These are translated to JSON-RPC error objects on the wire by the transport
/// layer. The numeric codes in [`Error::rpc_code`] follow the JSON-RPC 2.0
/// reserved range (-32768..=-32000) for protocol errors plus a small server
/// range (-32099..=-32000) reserved for application errors:
///
/// | Code     | Meaning                              |
/// |----------|--------------------------------------|
/// | -32700   | Parse error (malformed JSON)         |
/// | -32600   | Invalid request                      |
/// | -32601   | Method not found                     |
/// | -32602   | Invalid params                       |
/// | -32603   | Internal error                       |
/// | -32001   | Policy denied (server-side)          |
/// | -32002   | Disabled (MCP not enabled)           |
/// | -32003   | Not implemented                      |
/// | -32004   | Resource not found                   |
/// | -32005   | Tool not found                       |
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// Underlying I/O error from a transport.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    /// JSON encode/decode error.
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),

    /// Server-side policy refused the request.
    #[error("policy denied: {0}")]
    PolicyDenied(String),

    /// MCP is not enabled in the current policy.
    #[error("mcp disabled")]
    Disabled,

    /// A planned feature that is not implemented in this version.
    #[error("not implemented: {0}")]
    NotImplemented(&'static str),

    /// Resource URI does not match a known handler.
    #[error("resource not found: {0}")]
    ResourceNotFound(String),

    /// Tool name does not match a known handler.
    #[error("tool not found: {0}")]
    ToolNotFound(String),

    /// Invalid parameters (`-32602`).
    #[error("invalid params: {0}")]
    InvalidParams(String),

    /// Method is not part of the implemented MCP subset.
    #[error("method not found: {0}")]
    MethodNotFound(String),

    /// Catch-all internal error.
    #[error("internal: {0}")]
    Internal(String),
}

impl Error {
    /// Maps the error to its JSON-RPC numeric code.
    #[must_use]
    pub fn rpc_code(&self) -> i64 {
        match self {
            Self::Json(_) => -32700,
            Self::InvalidParams(_) => -32602,
            Self::MethodNotFound(_) => -32601,
            Self::PolicyDenied(_) => -32001,
            Self::Disabled => -32002,
            Self::NotImplemented(_) => -32003,
            Self::ResourceNotFound(_) => -32004,
            Self::ToolNotFound(_) => -32005,
            Self::Io(_) | Self::Internal(_) => -32603,
        }
    }
}
