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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_io() {
        let e: Error = std::io::Error::other("boom").into();
        let s = e.to_string();
        assert!(s.starts_with("io: "), "{s}");
        assert!(s.contains("boom"));
    }

    #[test]
    fn display_json() {
        // Invalid JSON triggers serde_json::Error
        let err = serde_json::from_str::<serde_json::Value>("{bad").unwrap_err();
        let e: Error = err.into();
        let s = e.to_string();
        assert!(s.starts_with("json: "), "{s}");
    }

    #[test]
    fn display_policy_denied() {
        let e = Error::PolicyDenied("nope".to_owned());
        assert_eq!(e.to_string(), "policy denied: nope");
    }

    #[test]
    fn display_disabled() {
        let e = Error::Disabled;
        assert_eq!(e.to_string(), "mcp disabled");
    }

    #[test]
    fn display_not_implemented() {
        let e = Error::NotImplemented("later");
        assert_eq!(e.to_string(), "not implemented: later");
    }

    #[test]
    fn display_resource_not_found() {
        let e = Error::ResourceNotFound("spt://nope".to_owned());
        assert_eq!(e.to_string(), "resource not found: spt://nope");
    }

    #[test]
    fn display_tool_not_found() {
        let e = Error::ToolNotFound("nope_tool".to_owned());
        assert_eq!(e.to_string(), "tool not found: nope_tool");
    }

    #[test]
    fn display_invalid_params() {
        let e = Error::InvalidParams("bad".to_owned());
        assert_eq!(e.to_string(), "invalid params: bad");
    }

    #[test]
    fn display_method_not_found() {
        let e = Error::MethodNotFound("foo/bar".to_owned());
        assert_eq!(e.to_string(), "method not found: foo/bar");
    }

    #[test]
    fn display_internal() {
        let e = Error::Internal("whoops".to_owned());
        assert_eq!(e.to_string(), "internal: whoops");
    }

    #[test]
    fn rpc_codes_cover_all_variants() {
        let cases: Vec<(Error, i64)> = vec![
            (Error::PolicyDenied("p".into()), -32001),
            (Error::Disabled, -32002),
            (Error::NotImplemented("n"), -32003),
            (Error::ResourceNotFound("r".into()), -32004),
            (Error::ToolNotFound("t".into()), -32005),
            (Error::InvalidParams("i".into()), -32602),
            (Error::MethodNotFound("m".into()), -32601),
            (Error::Internal("z".into()), -32603),
            (Error::Io(std::io::Error::other("x")), -32603),
        ];
        for (e, expected) in cases {
            assert_eq!(e.rpc_code(), expected, "{e}");
        }
    }

    #[test]
    fn rpc_code_for_json_is_parse_error() {
        let err = serde_json::from_str::<serde_json::Value>("{bad").unwrap_err();
        let e: Error = err.into();
        assert_eq!(e.rpc_code(), -32700);
    }

    #[test]
    fn from_io_error_preserves_kind() {
        let io = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "nope");
        let e: Error = io.into();
        match e {
            Error::Io(inner) => assert_eq!(inner.kind(), std::io::ErrorKind::PermissionDenied),
            other => panic!("expected Io, got {other:?}"),
        }
    }

    #[test]
    fn from_serde_json_variant() {
        let err = serde_json::from_str::<serde_json::Value>("not-json").unwrap_err();
        let e: Error = err.into();
        assert!(matches!(e, Error::Json(_)));
    }

    #[test]
    fn result_alias_round_trips() {
        fn maybe(flag: bool) -> Result<u8> {
            if flag {
                Ok(1)
            } else {
                Err(Error::Disabled)
            }
        }
        assert_eq!(maybe(true).unwrap(), 1);
        assert!(matches!(maybe(false), Err(Error::Disabled)));
    }
}
