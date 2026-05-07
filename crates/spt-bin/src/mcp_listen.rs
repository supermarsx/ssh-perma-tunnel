//! `<state_dir>/mcp-listen.json` sidecar: shape, write, read, delete.
//!
//! When `tunnel run` enables a loopback MCP listener, it writes a small JSON
//! file in the state directory recording the bound host/port plus a per-run
//! random bearer token. CLI subcommands that need to drive a running spt
//! (`spt tunnel failover`, `spt session close`, `spt session drain`, `spt
//! stats live`, live benchmark variants) read this sidecar to discover the
//! listener and authenticate `initialize`.
//!
//! The token is a base64-encoded 32-byte value, generated once per `spt
//! tunnel run` invocation. It exists in the file under the same permission
//! umbrella as the rest of the state directory (per spec, `0700` on Unix).

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use spt_core::{Error, Result};

/// File name used inside the state dir.
pub const SIDECAR_FILE: &str = "mcp-listen.json";

/// Sidecar payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpListenSidecar {
    /// Loopback host bound by the listener (`127.0.0.1` or `::1`).
    pub host: String,
    /// TCP port.
    pub port: u16,
    /// Bearer token required by the server's `initialize` step.
    pub token: String,
}

/// Path of the sidecar inside `state_dir`.
#[must_use]
pub fn sidecar_path(state_dir: &Path) -> PathBuf {
    state_dir.join(SIDECAR_FILE)
}

/// Generate a 32-byte random token, base64-encoded (URL-safe, no padding).
#[must_use]
pub fn generate_token() -> String {
    use base64::Engine;
    use rand::RngCore;
    let mut buf = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut buf);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf)
}

/// Write the sidecar atomically.
pub fn write(state_dir: &Path, sidecar: &McpListenSidecar) -> Result<()> {
    let path = sidecar_path(state_dir);
    let body = serde_json::to_string_pretty(sidecar)
        .map_err(|e| Error::RuntimeFailure(format!("serialize mcp-listen.json: {e}")))?;
    spt_state::write_atomic_string(&path, &body)
        .map_err(|e| Error::RuntimeFailure(format!("write mcp-listen.json: {e}")))?;
    Ok(())
}

/// Read the sidecar.
pub fn read(state_dir: &Path) -> Result<McpListenSidecar> {
    let path = sidecar_path(state_dir);
    let body = std::fs::read_to_string(&path).map_err(|e| {
        Error::RuntimeFailure(format!(
            "read `{}`: {e} — is `spt tunnel run` running with [mcp].listen?",
            path.display()
        ))
    })?;
    serde_json::from_str(&body)
        .map_err(|e| Error::RuntimeFailure(format!("parse mcp-listen.json: {e}")))
}

/// Best-effort delete; missing file is not an error.
pub fn remove(state_dir: &Path) {
    let _ = std::fs::remove_file(sidecar_path(state_dir));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let tmp = tempfile::tempdir().unwrap();
        let s = McpListenSidecar {
            host: "127.0.0.1".into(),
            port: 7777,
            token: generate_token(),
        };
        write(tmp.path(), &s).unwrap();
        let got = read(tmp.path()).unwrap();
        assert_eq!(got.host, s.host);
        assert_eq!(got.port, s.port);
        assert_eq!(got.token, s.token);
        remove(tmp.path());
        assert!(read(tmp.path()).is_err());
    }

    #[test]
    fn token_is_high_entropy() {
        let a = generate_token();
        let b = generate_token();
        assert_ne!(a, b);
        // 32 bytes → base64 url-safe no-pad → 43 chars
        assert_eq!(a.len(), 43);
    }
}
