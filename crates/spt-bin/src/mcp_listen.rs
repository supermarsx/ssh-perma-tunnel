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

/// Best-effort cleanup of a stale sidecar before rebinding (E8-F16).
///
/// On a crash / SIGKILL the previous `tunnel run` never ran its shutdown path,
/// so `mcp-listen.json` lingers on disk with a dead host/port + a token that no
/// longer authenticates anything. The next `tunnel run` startup calls this
/// before writing a fresh sidecar so a CLI client racing the rebind never sees
/// the old token. Returns `true` when a stale file was actually removed (for
/// an optional operator log line); missing-file is the common, non-error case.
///
/// Call site (p4-dispatch-wire): in `maybe_spawn_mcp_loopback`, immediately
/// before [`write`].
pub fn prepare_rebind(state_dir: &Path) -> bool {
    let path = sidecar_path(state_dir);
    match std::fs::remove_file(&path) {
        Ok(()) => {
            tracing::debug!(path = %path.display(), "removed stale mcp-listen.json before rebind");
            true
        }
        Err(_) => false,
    }
}

/// Reject `[mcp].expose = true` as unsupported (E8-F16).
///
/// `validate.rs` permits a non-loopback `[mcp].listen` when `expose = true`,
/// but [`crate::mcp_listen`]'s only transport — `LoopbackTransport` — refuses
/// any non-loopback bind unconditionally, so `expose` can never take effect.
/// Rather than silently ignore the operator's intent (they would expect a
/// routable listener and get a connection error), the loopback spawn path
/// fails fast with this structured error.
///
/// Call site (p4-dispatch-wire): in `maybe_spawn_mcp_loopback`, before binding,
/// `if let Err(e) = mcp_listen::reject_expose(mcp.expose) { return Err(e); }`.
pub fn reject_expose(expose: Option<bool>) -> Result<()> {
    if expose == Some(true) {
        return Err(Error::InvalidConfig(
            "[mcp].expose = true is unsupported: the MCP server binds loopback only. \
             Remove `expose` (and any non-loopback `[mcp].listen`) — CIDR-ACL'd \
             non-loopback exposure is not implemented."
                .to_owned(),
        ));
    }
    Ok(())
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
    fn prepare_rebind_removes_stale_sidecar() {
        let tmp = tempfile::tempdir().unwrap();
        let s = McpListenSidecar {
            host: "127.0.0.1".into(),
            port: 1,
            token: generate_token(),
        };
        write(tmp.path(), &s).unwrap();
        assert!(read(tmp.path()).is_ok(), "sidecar present before rebind");
        assert!(prepare_rebind(tmp.path()), "stale file should be removed");
        assert!(read(tmp.path()).is_err(), "sidecar gone after rebind");
        // Idempotent: a second call on an absent file is a no-op (false).
        assert!(!prepare_rebind(tmp.path()));
    }

    #[test]
    fn reject_expose_only_fails_on_true() {
        assert!(reject_expose(None).is_ok());
        assert!(reject_expose(Some(false)).is_ok());
        let err = reject_expose(Some(true)).unwrap_err();
        assert!(matches!(err, Error::InvalidConfig(_)), "got {err:?}");
        assert!(err.to_string().contains("loopback"));
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
