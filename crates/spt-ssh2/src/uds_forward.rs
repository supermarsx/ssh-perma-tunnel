//! Server-side UNIX socket (UDS) forwarding for the russh backend.
//!
//! This module implements the OpenSSH non-RFC extensions for forwarding
//! `AF_UNIX` sockets across an SSH connection:
//!
//! * `direct-streamlocal@openssh.com` — client opens a channel that the
//!   server dials *out* on a UNIX socket (the **`local_uds`** link kind:
//!   the listener lives on the client, the destination on the server).
//! * `streamlocal-forward@openssh.com` + `cancel-streamlocal-forward@openssh.com`
//!   — client asks the server to listen on a UNIX socket and tunnel inbound
//!   connections back over `forwarded-streamlocal@openssh.com` channels
//!   (the **`remote_uds`** link kind).
//!
//! Wire layout: OpenSSH `PROTOCOL.txt` §2.4 specifies a single
//! `string socket_path / string reserved / uint32 reserved` body for both
//! the `direct-streamlocal` channel-open and the `streamlocal-forward`
//! global-request packets. See [`encode_direct_streamlocal_body`].
//!
//! Backend constraints (codified by the planner — see `t6.md` plan
//! corrections):
//!
//! * `libssh2` 0.9 has no `channel_direct_streamlocal` and no streamlocal
//!   global-request helpers. The libssh2 path therefore surfaces
//!   [`spt_core::Error::UnsupportedPlatform`] cleanly via
//!   [`libssh2_unsupported`]. (Exit code 10 — there is no
//!   `UnsupportedBackend` variant in `spt-core`; `UnsupportedPlatform`
//!   covers backend-feature gaps semantically.)
//! * The listener side of `local_uds` requires `AF_UNIX` sockets, so the
//!   listener half is gated `#[cfg(unix)]`. Outbound channel opens (the
//!   `direct-streamlocal` channel itself) work cross-platform; only the
//!   local listener that proxies onto that channel is Unix-only.
//!
//! Runtime wiring into [`crate::Ssh2Session`] / `spt-forward::ForwardRunner`
//! is **deferred to t6-Bwire** — this module supplies the protocol-level
//! building blocks and the executor lock scope does not include the
//! supervisor surface. The exported API is intentionally minimal and
//! avoids reaching into `Ssh2Session`'s private state.

use std::sync::Arc;

use russh::client;
use russh::client::Msg;
use russh::Channel;
use spt_core::audit::{record_audit, AuditEvent, AuditSeverity};
use spt_core::{Error, Result};
use tokio::sync::Mutex as AsyncMutex;
use tracing::warn;

/// Convenience alias matching `crate::russh_backend::SharedHandle`. Held
/// outside that module so the UDS surface compiles without depending on
/// private backend internals.
pub type SharedRusshHandle<H> = Arc<AsyncMutex<client::Handle<H>>>;

/// The single audit event kind emitted on a successful UDS channel open.
pub const AUDIT_OPEN_KIND: &str = "audit.forward.uds.open";

/// The single audit event kind emitted on UDS forward close / cancel.
pub const AUDIT_CLOSE_KIND: &str = "audit.forward.uds.close";

// ---------------------------------------------------------------------------
// Wire encoding — matches `russh-0.46.0/src/client/session.rs:86-90`
// (`channel_open_direct_streamlocal` body layout) and OpenSSH
// `PROTOCOL.txt` §2.4 verbatim.
// ---------------------------------------------------------------------------

/// Encode the body of a `direct-streamlocal@openssh.com` channel-open
/// packet (OpenSSH `PROTOCOL.txt` §2.4):
///
/// ```text
///   string  socket_path
///   string  reserved (empty)
///   uint32  reserved (0)
/// ```
///
/// All strings use SSH "string" framing: `uint32 length` followed by the
/// raw bytes. Lengths are big-endian.
///
/// This function exists so the byte-exact PROTOCOL.txt §2.4 conformance
/// test has a target to assert against — production code calls
/// `russh::client::Handle::channel_open_direct_streamlocal` which performs
/// the identical layout internally (`russh-0.46.0/src/client/session.rs`
/// lines 82-91).
#[must_use]
pub fn encode_direct_streamlocal_body(socket_path: &str) -> Vec<u8> {
    let path = socket_path.as_bytes();
    let mut out = Vec::with_capacity(4 + path.len() + 4 + 4);
    out.extend_from_slice(&u32::try_from(path.len()).unwrap_or(u32::MAX).to_be_bytes());
    out.extend_from_slice(path);
    // string reserved (empty)
    out.extend_from_slice(&0u32.to_be_bytes());
    // uint32 reserved (zero)
    out.extend_from_slice(&0u32.to_be_bytes());
    out
}

/// Encode the body of a `streamlocal-forward@openssh.com` global request
/// (OpenSSH `PROTOCOL.txt` §2.4):
///
/// ```text
///   string  socket_path
/// ```
///
/// (The OpenSSH spec defines only the single `socket_path` field for the
/// forward request itself — the `SSH_MSG_GLOBAL_REQUEST` framing around it
/// is added by russh.)
#[must_use]
pub fn encode_streamlocal_forward_body(socket_path: &str) -> Vec<u8> {
    let path = socket_path.as_bytes();
    let mut out = Vec::with_capacity(4 + path.len());
    out.extend_from_slice(&u32::try_from(path.len()).unwrap_or(u32::MAX).to_be_bytes());
    out.extend_from_slice(path);
    out
}

// ---------------------------------------------------------------------------
// Path validation
// ---------------------------------------------------------------------------

/// Validate a UNIX socket path destined for the wire. Rejects:
///
/// * empty paths,
/// * relative paths (must start with `/`),
/// * paths containing interior NUL bytes (`\0`),
/// * paths longer than 4096 bytes (sanity cap — OpenSSH's own limit is
///   architecture-dependent but always below this).
///
/// The check is liberal on character set (it lets the kernel enforce
/// platform-specific filename rules) and intentionally never touches the
/// filesystem.
pub fn validate_socket_path(path: &str) -> Result<()> {
    if path.is_empty() {
        return Err(Error::InvalidConfig(
            "UDS forward socket path is empty".into(),
        ));
    }
    if !path.starts_with('/') {
        return Err(Error::InvalidConfig(format!(
            "UDS forward socket path must be absolute (start with `/`): `{path}`"
        )));
    }
    if path.contains('\0') {
        return Err(Error::InvalidConfig(format!(
            "UDS forward socket path contains NUL byte: `{}`",
            path.escape_default()
        )));
    }
    if path.len() > 4096 {
        return Err(Error::InvalidConfig(format!(
            "UDS forward socket path exceeds 4096 bytes ({} bytes)",
            path.len()
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Backend gating
// ---------------------------------------------------------------------------

/// Canonical "libssh2 cannot do this" error for both UDS link kinds.
///
/// Returned by every entry point on this module when the protocol is
/// running on the legacy libssh2 backend (`ssh2` 0.9 lacks the
/// `channel_direct_streamlocal` and streamlocal global-request APIs
/// entirely). Uses [`Error::UnsupportedPlatform`] (exit code 10) — there
/// is no `Error::UnsupportedBackend` variant in `spt-core` and adding
/// one is out of this executor's lock scope.
#[must_use]
pub fn libssh2_unsupported() -> Error {
    Error::UnsupportedPlatform(
        "UDS forwarding (direct-streamlocal / streamlocal-forward) is unavailable on the \
         libssh2 backend; switch to ssh2_backend = \"russh\" for this profile"
            .into(),
    )
}

/// Canonical platform-gated error for `local_uds` when running on a
/// non-Unix target (Windows has no `AF_UNIX` listener path here).
#[must_use]
pub fn windows_local_uds_unsupported() -> Error {
    Error::UnsupportedPlatform(
        "local_uds (client-side UNIX-socket listener) requires a Unix target; \
         outbound direct-streamlocal channels remain available, but binding the local \
         UDS listener is not supported on Windows"
            .into(),
    )
}

// ---------------------------------------------------------------------------
// Audit hooks
// ---------------------------------------------------------------------------

/// Emit a `audit.forward.uds.open` event.
///
/// Field schema (deliberately small and stable):
///
/// * `link_kind` — `local_uds` or `remote_uds`
/// * `socket_path` — the UNIX socket path (no secret bytes are ever placed
///   on a UDS at this layer, so logging the path is fine)
pub fn audit_open(link_kind: &str, socket_path: &str) {
    record_audit(
        AuditEvent::new(AUDIT_OPEN_KIND, AuditSeverity::Info)
            .with_field("link_kind", link_kind)
            .with_field("socket_path", socket_path),
    );
}

/// Emit a `audit.forward.uds.close` event. See [`audit_open`] for the
/// field schema; `reason` covers `"explicit_cancel"`, `"drop"`, etc.
pub fn audit_close(link_kind: &str, socket_path: &str, reason: &str) {
    record_audit(
        AuditEvent::new(AUDIT_CLOSE_KIND, AuditSeverity::Info)
            .with_field("link_kind", link_kind)
            .with_field("socket_path", socket_path)
            .with_field("reason", reason),
    );
}

// ---------------------------------------------------------------------------
// local_uds — outbound `direct-streamlocal@openssh.com`
// ---------------------------------------------------------------------------

/// Open a `direct-streamlocal@openssh.com` channel against the remote
/// `socket_path`. Caller owns the resulting channel and is responsible
/// for piping local I/O onto it.
///
/// Validates `socket_path` first ([`validate_socket_path`]) and emits a
/// `audit.forward.uds.open` event on success.
pub async fn open_local_uds<H>(
    handle: &SharedRusshHandle<H>,
    socket_path: &str,
) -> Result<Channel<Msg>>
where
    H: client::Handler + Send,
{
    validate_socket_path(socket_path)?;
    let channel = {
        let handle = handle.lock().await;
        handle
            .channel_open_direct_streamlocal(socket_path)
            .await
            .map_err(|e| {
                Error::RuntimeFailure(format!(
                    "russh direct-streamlocal `{socket_path}`: {e}"
                ))
            })?
    };
    audit_open("local_uds", socket_path);
    Ok(channel)
}

// ---------------------------------------------------------------------------
// remote_uds — `streamlocal-forward@openssh.com`
// ---------------------------------------------------------------------------

/// RAII handle for a server-side `streamlocal-forward@openssh.com`
/// registration.
///
/// Dropping this struct sends `cancel-streamlocal-forward@openssh.com`
/// to the peer (best-effort; failures are logged at `warn` level — they
/// indicate the session is already torn down). Explicit cancellation via
/// [`RemoteUdsForward::cancel`] is preferred when the caller can await
/// the result.
pub struct RemoteUdsForward<H>
where
    H: client::Handler + Send + 'static,
{
    handle: SharedRusshHandle<H>,
    socket_path: String,
    /// Set to `false` once `cancel()` has run so `Drop` doesn't double-cancel.
    active: bool,
}

impl<H> RemoteUdsForward<H>
where
    H: client::Handler + Send + 'static,
{
    /// Ask the server to listen on `socket_path` and forward inbound
    /// connections back as `forwarded-streamlocal@openssh.com` channels.
    ///
    /// On success, returns a [`RemoteUdsForward`] whose `Drop` impl will
    /// send `cancel-streamlocal-forward@openssh.com` for the same path.
    /// Emits a `audit.forward.uds.open` event.
    pub async fn request(handle: SharedRusshHandle<H>, socket_path: &str) -> Result<Self> {
        validate_socket_path(socket_path)?;
        {
            let mut g = handle.lock().await;
            g.streamlocal_forward(socket_path).await.map_err(|e| {
                Error::RemoteBindFailed {
                    address: socket_path.to_owned(),
                    reason: format!("russh streamlocal-forward: {e}"),
                }
            })?;
        }
        audit_open("remote_uds", socket_path);
        Ok(Self {
            handle,
            socket_path: socket_path.to_owned(),
            active: true,
        })
    }

    /// Path the server is listening on.
    #[must_use]
    pub fn socket_path(&self) -> &str {
        &self.socket_path
    }

    /// Explicitly send `cancel-streamlocal-forward@openssh.com`. After
    /// this call returns the [`RemoteUdsForward`] is inert (its `Drop`
    /// becomes a no-op) and the same `socket_path` can immediately be
    /// re-requested with [`RemoteUdsForward::request`].
    pub async fn cancel(mut self) -> Result<()> {
        self.cancel_inner("explicit_cancel").await
    }

    async fn cancel_inner(&mut self, reason: &str) -> Result<()> {
        if !self.active {
            return Ok(());
        }
        self.active = false;
        let res = {
            let g = self.handle.lock().await;
            g.cancel_streamlocal_forward(self.socket_path.clone()).await
        };
        audit_close("remote_uds", &self.socket_path, reason);
        res.map_err(|e| {
            Error::RuntimeFailure(format!(
                "russh cancel-streamlocal-forward `{}`: {e}",
                self.socket_path
            ))
        })
    }
}

impl<H> Drop for RemoteUdsForward<H>
where
    H: client::Handler + Send + 'static,
{
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        // Best-effort: spawn the cancel on the current Tokio runtime if
        // one is available. If `Drop` runs outside a runtime (e.g. during
        // shutdown after the runtime is torn down) we surface a `warn!`
        // and emit the audit close event synchronously so the audit
        // trail records the un-cancelled state.
        let handle = Arc::clone(&self.handle);
        let path = std::mem::take(&mut self.socket_path);
        self.active = false;
        let spawned = tokio::runtime::Handle::try_current().ok().map(|rt| {
            rt.spawn(async move {
                let g = handle.lock().await;
                if let Err(e) = g.cancel_streamlocal_forward(path.clone()).await {
                    warn!(
                        target: "spt_ssh2::uds_forward",
                        socket_path = %path,
                        error = %e,
                        "drop: cancel-streamlocal-forward failed (session likely gone)"
                    );
                }
                audit_close("remote_uds", &path, "drop");
            })
        });
        if spawned.is_none() {
            warn!(
                target: "spt_ssh2::uds_forward",
                "drop: no tokio runtime — skipping cancel-streamlocal-forward"
            );
            // Still record the audit close so the trail isn't silently
            // missing on shutdown paths.
            audit_close("remote_uds", "<dropped>", "drop_no_runtime");
        }
    }
}

// ---------------------------------------------------------------------------
// Unit tests for the pure-logic surface (encode helpers, validation,
// backend-gate errors, audit hooks). Russh roundtrip tests live in
// `crates/spt-ssh2/tests/uds_forward.rs` (requires the `testing` feature).
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Byte-exact match against OpenSSH `PROTOCOL.txt` §2.4.
    ///
    /// Body for `direct-streamlocal@openssh.com`:
    ///
    /// ```text
    ///   string  socket_path
    ///   string  reserved (empty)
    ///   uint32  reserved (0)
    /// ```
    ///
    /// For `socket_path = "/run/foo.sock"`:
    ///
    /// * `00 00 00 0d` — length (13)
    /// * `2f 72 75 6e 2f 66 6f 6f 2e 73 6f 63 6b` — `/run/foo.sock`
    /// * `00 00 00 00` — empty reserved string
    /// * `00 00 00 00` — reserved uint32
    ///
    /// Total: 4 + 13 + 4 + 4 = 25 bytes.
    #[test]
    fn encode_direct_streamlocal_body_byte_exact() {
        let body = encode_direct_streamlocal_body("/run/foo.sock");
        let expected: [u8; 25] = [
            0x00, 0x00, 0x00, 0x0d, // length 13
            0x2f, 0x72, 0x75, 0x6e, 0x2f, 0x66, 0x6f, 0x6f, 0x2e, 0x73, 0x6f, 0x63, 0x6b,
            0x00, 0x00, 0x00, 0x00, // reserved string (empty)
            0x00, 0x00, 0x00, 0x00, // reserved uint32
        ];
        assert_eq!(
            body, expected,
            "direct-streamlocal body must match PROTOCOL.txt §2.4 byte-for-byte"
        );
        assert_eq!(body.len(), 25);
    }

    #[test]
    fn encode_direct_streamlocal_body_empty_path_still_well_formed() {
        // Empty path is rejected by `validate_socket_path`, but the
        // encoder itself stays well-defined (length 0).
        let body = encode_direct_streamlocal_body("");
        assert_eq!(body, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn encode_streamlocal_forward_body_is_just_the_path_string() {
        let body = encode_streamlocal_forward_body("/run/bar.sock");
        let expected: [u8; 17] = [
            0x00, 0x00, 0x00, 0x0d, // length 13
            0x2f, 0x72, 0x75, 0x6e, 0x2f, 0x62, 0x61, 0x72, 0x2e, 0x73, 0x6f, 0x63, 0x6b,
        ];
        assert_eq!(body, expected);
    }

    #[test]
    fn validate_socket_path_accepts_typical_absolute_paths() {
        validate_socket_path("/run/foo.sock").unwrap();
        validate_socket_path("/tmp/some.sock").unwrap();
        validate_socket_path("/var/run/postgresql/.s.PGSQL.5432").unwrap();
    }

    #[test]
    fn validate_socket_path_rejects_empty() {
        let e = validate_socket_path("").unwrap_err();
        assert!(matches!(e, Error::InvalidConfig(ref s) if s.contains("empty")));
    }

    #[test]
    fn validate_socket_path_rejects_relative() {
        let e = validate_socket_path("foo.sock").unwrap_err();
        assert!(matches!(e, Error::InvalidConfig(ref s) if s.contains("absolute")));
        let e = validate_socket_path("./foo.sock").unwrap_err();
        assert!(matches!(e, Error::InvalidConfig(ref s) if s.contains("absolute")));
    }

    #[test]
    fn validate_socket_path_rejects_nul_bytes() {
        let e = validate_socket_path("/run/foo\0bar.sock").unwrap_err();
        assert!(matches!(e, Error::InvalidConfig(ref s) if s.contains("NUL")));
    }

    #[test]
    fn validate_socket_path_rejects_oversized() {
        let huge = format!("/{}", "a".repeat(4096));
        let e = validate_socket_path(&huge).unwrap_err();
        assert!(matches!(e, Error::InvalidConfig(ref s) if s.contains("4096")));
    }

    #[test]
    fn libssh2_unsupported_yields_unsupported_platform() {
        let e = libssh2_unsupported();
        match e {
            Error::UnsupportedPlatform(msg) => {
                assert!(msg.contains("libssh2"), "msg: {msg}");
                assert!(msg.contains("UDS"), "msg: {msg}");
                assert!(msg.contains("russh"), "msg: {msg}");
            }
            other => panic!("expected UnsupportedPlatform, got {other:?}"),
        }
    }

    #[test]
    fn windows_local_uds_unsupported_yields_unsupported_platform() {
        let e = windows_local_uds_unsupported();
        match e {
            Error::UnsupportedPlatform(msg) => {
                assert!(
                    msg.contains("Unix") || msg.contains("Windows"),
                    "msg: {msg}"
                );
                assert!(msg.contains("local_uds"), "msg: {msg}");
            }
            other => panic!("expected UnsupportedPlatform, got {other:?}"),
        }
    }

    /// Audit hooks fire on open + close and carry the documented field set.
    ///
    /// Installs a local capturing [`AuditSink`] via the process-global
    /// `register_audit_sink` slot. The sink is intentionally not cleared
    /// at the end: `spt_core::audit::clear_audit_sink_for_test` lives
    /// behind the `testing` feature on `spt-core` and that feature isn't
    /// enabled in this crate's dependency table. The slot is replaceable,
    /// so subsequent tests that install their own sink overwrite this
    /// one cleanly.
    #[test]
    fn audit_open_and_close_fire_with_expected_fields() {
        use spt_core::audit::{register_audit_sink, AuditEvent as AE, AuditSink};
        use std::sync::Mutex;

        #[derive(Debug, Default)]
        struct Recorder {
            events: Mutex<Vec<AE>>,
        }
        impl AuditSink for Recorder {
            fn record(&self, ev: AE) {
                self.events.lock().unwrap().push(ev);
            }
        }

        let rec = Arc::new(Recorder::default());
        register_audit_sink(rec.clone());

        audit_open("local_uds", "/run/foo.sock");
        audit_close("local_uds", "/run/foo.sock", "drop");

        let events = rec.events.lock().unwrap().clone();
        assert!(
            events.len() >= 2,
            "expected at least 2 audit events, got {}",
            events.len()
        );
        let open_evt = events
            .iter()
            .find(|e| e.kind == AUDIT_OPEN_KIND)
            .expect("open event recorded");
        assert_eq!(
            open_evt.fields.get("link_kind").map(String::as_str),
            Some("local_uds")
        );
        assert_eq!(
            open_evt.fields.get("socket_path").map(String::as_str),
            Some("/run/foo.sock")
        );

        let close_evt = events
            .iter()
            .find(|e| e.kind == AUDIT_CLOSE_KIND)
            .expect("close event recorded");
        assert_eq!(
            close_evt.fields.get("link_kind").map(String::as_str),
            Some("local_uds")
        );
        assert_eq!(
            close_evt.fields.get("reason").map(String::as_str),
            Some("drop")
        );
    }
}
