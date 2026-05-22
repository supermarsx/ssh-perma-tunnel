//! Multi-hop chains via nested `direct-tcpip` channels (russh-native).
//!
//! Pre-t7 this module used a "socketpair" trick: bind a loopback
//! `TcpListener`, accept one connection, and pump bytes between an
//! `AsyncChannel` and the loopback peer so libssh2 (which requires
//! `AsRawFd`/`AsRawSocket` on its session transport) could be handed a real
//! OS socket. russh has no such requirement — `russh::client::connect_stream`
//! accepts any `AsyncRead + AsyncWrite + Unpin + Send` source — so the
//! socketpair indirection is gone. Each hop opens a `direct-tcpip` channel
//! through the previous session and uses [`russh::Channel::into_stream`] as
//! the next session's byte transport.
//!
//! Proxy hops (SOCKS5 / HTTP CONNECT) still use the same channel stream as
//! their byte source — the helpers in [`crate::proxy_jump`] are
//! transport-agnostic.

use std::sync::Arc;

use russh::client::{self, Handle};
use russh::ChannelStream;
use spt_core::audit::{record_audit, AuditEvent, AuditSeverity};
use spt_core::{Error, Result};
use tokio::sync::Mutex as AsyncMutex;
use tracing::warn;

use crate::proxy_jump::{http_connect, socks5_connect, ProxyCredentials};

/// Hop dispatch kind mirrored from `spt_config::schema::HopKind`.
///
/// Re-defined here to keep `spt-ssh2` free of a build-time dep on
/// `spt-config`. The runtime mapper in `spt-bin` converts one to the other.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HopKind {
    /// Re-establish an SSH session through this hop. Default.
    #[default]
    Ssh,
    /// SOCKS5 proxy.
    Socks5,
    /// HTTP CONNECT proxy.
    HttpConnect,
}

/// Shared russh client handle (mirrors `russh_backend::SharedHandle`).
type SharedHandle<H> = Arc<AsyncMutex<Handle<H>>>;

/// Open a `direct-tcpip` channel through `outer` to `(host, port)` and
/// promote it into a fresh [`russh::client::Handle`] by handshaking a new
/// SSH client over the resulting [`ChannelStream`].
///
/// The caller supplies a `next_handler` ready to validate the next-hop's
/// host key and an `Arc<russh::client::Config>` (which carries the hop's
/// crypto policy / preferred algorithms).
pub async fn open_chained_session<H, NH>(
    outer: SharedHandle<H>,
    host: &str,
    port: u16,
    config: Arc<client::Config>,
    next_handler: NH,
) -> Result<Handle<NH>>
where
    H: client::Handler + Send + 'static,
    NH: client::Handler + Send + 'static,
{
    let channel = {
        let h = outer.lock().await;
        h.channel_open_direct_tcpip(host.to_owned(), u32::from(port), "127.0.0.1", 0)
            .await
            .map_err(|e| {
                Error::runtime_failure(
                    spt_core::Diagnostic::what(format!(
                        "Failed to open direct-tcpip channel to `{host}:{port}` via multi-hop"
                    ))
                    .why(format!("{e}"))
                    .how_to_fix(
                        "Verify the outer SSH session is still alive and that the bastion \
                         has `AllowTcpForwarding yes` in sshd_config.",
                    )
                    .endpoint(format!("{host}:{port}"))
                    .retry_advice(spt_core::RetryAdvice::RetryWithBackoff)
                    .build(),
                )
            })?
    };
    let stream: ChannelStream<client::Msg> = channel.into_stream();
    let host_s = host.to_owned();
    client::connect_stream(config, stream, next_handler)
        .await
        .map_err(|e| {
            Error::network_unreachable(
                spt_core::Diagnostic::what(format!(
                    "Multi-hop SSH connect to `{host_s}:{port}` failed during handshake"
                ))
                .why(format!("{e:?}"))
                .how_to_fix(
                    "Confirm the inner host accepts SSH on the chosen port, that its host key \
                 matches the configured `known_hosts`, and that the bastion can reach \
                 it (test with `ssh -J <bastion> <user>@<inner>` from the bastion host).",
                )
                .endpoint(format!("{host_s}:{port}"))
                .retry_advice(spt_core::RetryAdvice::RetryWithBackoff)
                .build(),
            )
        })
}

/// Open a kind-aware chained connection through `outer` toward
/// `(target_host, target_port)`.
///
/// * For [`HopKind::Ssh`], opens a `direct-tcpip` channel to
///   `(target_host, target_port)` and returns the resulting next-hop
///   russh handle.
/// * For [`HopKind::Socks5`] / [`HopKind::HttpConnect`], opens a
///   `direct-tcpip` channel to the proxy `(proxy_host, proxy_port)`, runs
///   the SOCKS5 or HTTP CONNECT handshake aimed at the target across the
///   resulting channel stream, then handshakes a fresh SSH session through
///   the (now-tunneled) stream.
#[allow(clippy::too_many_arguments)]
pub async fn open_chained_session_with_kind<H, NH>(
    outer: SharedHandle<H>,
    proxy_host: &str,
    proxy_port: u16,
    target_host: &str,
    target_port: u16,
    kind: HopKind,
    creds: Option<ProxyCredentials>,
    config: Arc<client::Config>,
    next_handler: NH,
) -> Result<Handle<NH>>
where
    H: client::Handler + Send + 'static,
    NH: client::Handler + Send + 'static,
{
    record_audit(
        AuditEvent::new("audit.ssh.hop_transition", AuditSeverity::Info)
            .with_field("proxy_host", proxy_host)
            .with_field("proxy_port", proxy_port.to_string())
            .with_field("target_host", target_host)
            .with_field("target_port", target_port.to_string())
            .with_field(
                "kind",
                match kind {
                    HopKind::Ssh => "ssh",
                    HopKind::Socks5 => "socks5",
                    HopKind::HttpConnect => "http-connect",
                },
            ),
    );

    if matches!(kind, HopKind::Ssh) {
        return open_chained_session(outer, target_host, target_port, config, next_handler).await;
    }

    // Proxy-kind: dial the proxy across direct-tcpip, then run the CONNECT
    // handshake aimed at the real target across the channel stream.
    let channel = {
        let h = outer.lock().await;
        h.channel_open_direct_tcpip(proxy_host.to_owned(), u32::from(proxy_port), "127.0.0.1", 0)
            .await
            .map_err(|e| {
                Error::runtime_failure(
                    spt_core::Diagnostic::what(format!(
                        "Failed to open multi-hop proxy channel to `{proxy_host}:{proxy_port}`"
                    ))
                    .why(format!("{e}"))
                    .how_to_fix(
                        "Verify the outer hop is still connected and the bastion permits \
                     TCP forwarding to the proxy host. Check `AllowTcpForwarding` and \
                     any `PermitOpen` entries in sshd_config.",
                    )
                    .endpoint(format!("{proxy_host}:{proxy_port}"))
                    .retry_advice(spt_core::RetryAdvice::RetryWithBackoff)
                    .build(),
                )
            })?
    };
    let mut stream: ChannelStream<client::Msg> = channel.into_stream();
    match kind {
        HopKind::Socks5 => {
            socks5_connect(&mut stream, target_host, target_port, creds.as_ref()).await?;
        }
        HopKind::HttpConnect => {
            http_connect(&mut stream, target_host, target_port, creds.as_ref()).await?;
        }
        HopKind::Ssh => unreachable!(),
    }

    client::connect_stream(config, stream, next_handler)
        .await
        .map_err(|e| {
            let msg = format!("russh multi-hop proxy handshake: {e:?}");
            warn!(
                target: "spt_ssh2::multi_hop",
                proxy_host,
                proxy_port,
                target_host,
                target_port,
                error = %msg,
                "russh handshake over proxy-jump tunnel failed"
            );
            Error::network_unreachable(
                spt_core::Diagnostic::what(format!(
                    "SSH handshake over proxy-jump tunnel to `{target_host}:{target_port}` failed"
                ))
                .why(msg)
                .how_to_fix(
                    "Verify the inner SSH server is reachable through the proxy (test with \
                     a direct `curl` / `nc` to confirm the CONNECT tunnel works), and that \
                     its host key matches the configured `known_hosts`.",
                )
                .endpoint(format!("{target_host}:{target_port}"))
                .retry_advice(spt_core::RetryAdvice::RetryWithBackoff)
                .build(),
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy_jump;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn hopkind_default_is_ssh() {
        assert_eq!(HopKind::default(), HopKind::Ssh);
    }

    /// SOCKS5 mid-hop failure surfaces as a typed RuntimeFailure. Exercises
    /// the same error path the `open_chained_session_with_kind` SOCKS5 arm
    /// hits, without requiring a live SSH session at the outer side.
    #[tokio::test]
    async fn chained_failure_mid_hop_surfaces_runtime_error() {
        let (mut client_stream, mut server) = tokio::io::duplex(4096);
        let s = tokio::spawn(async move {
            let mut hello = [0u8; 3];
            server.read_exact(&mut hello).await.unwrap();
            server.write_all(&[0x05, 0x00]).await.unwrap();
            let mut head = [0u8; 4];
            server.read_exact(&mut head).await.unwrap();
            let mut tail = vec![0u8; 6];
            if head[3] == 0x01 {
                server.read_exact(&mut tail).await.unwrap();
            }
            server
                .write_all(&[0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
        });
        let r = proxy_jump::socks5_connect(&mut client_stream, "127.0.0.1", 22, None).await;
        s.await.unwrap();
        match r.unwrap_err() {
            Error::RuntimeFailure(msg) => assert!(msg.contains("host unreachable"), "got: {msg}"),
            other => panic!("expected RuntimeFailure, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn audit_hook_records_hop_transition() {
        use spt_core::audit::{register_audit_sink, AuditSink};
        use std::sync::{Arc, Mutex as StdMutex};

        #[derive(Debug)]
        struct Capture(Arc<StdMutex<Vec<String>>>);
        impl AuditSink for Capture {
            fn record(&self, ev: AuditEvent) {
                self.0.lock().unwrap().push(ev.kind.clone());
            }
        }
        let captured = Arc::new(StdMutex::new(Vec::new()));
        register_audit_sink(Arc::new(Capture(Arc::clone(&captured))));

        record_audit(
            AuditEvent::new("audit.ssh.hop_transition", AuditSeverity::Info)
                .with_field("proxy_host", "bastion.example.com")
                .with_field("proxy_port", "22")
                .with_field("target_host", "internal.example.com")
                .with_field("target_port", "22")
                .with_field("kind", "ssh"),
        );

        let evs = captured.lock().unwrap().clone();
        assert!(
            evs.iter().any(|k| k == "audit.ssh.hop_transition"),
            "expected hop_transition in {evs:?}"
        );
    }

    // ──────── t8-A1: diagnostic regression tests ──────────────────────

    #[test]
    fn direct_tcpip_channel_failure_diagnostic_mentions_allow_tcp_forwarding() {
        // Mirrors the literal site in open_chained_session for the
        // channel_open_direct_tcpip error path.
        let d = spt_core::Diagnostic::what(format!(
            "Failed to open direct-tcpip channel to `{}:{}` via multi-hop",
            "internal", 22u16
        ))
        .why("channel-open-failed: administratively prohibited")
        .how_to_fix(
            "Verify the outer SSH session is still alive and that the bastion \
             has `AllowTcpForwarding yes` in sshd_config.",
        )
        .endpoint("internal:22")
        .retry_advice(spt_core::RetryAdvice::RetryWithBackoff)
        .build();
        let e = spt_core::Error::runtime_failure(d);
        spt_core::assert_diagnostic_contains!(e,
            what: "direct-tcpip channel",
            how_to_fix: "AllowTcpForwarding",
        );
    }

    #[test]
    fn multi_hop_connect_failure_carries_endpoint_diagnostic() {
        let d = spt_core::Diagnostic::what(format!(
            "Multi-hop SSH connect to `{}:{}` failed during handshake",
            "inner", 22u16
        ))
        .why("kex algorithm mismatch")
        .how_to_fix(
            "Confirm the inner host accepts SSH on the chosen port, that its host key \
             matches the configured `known_hosts`, and that the bastion can reach \
             it (test with `ssh -J <bastion> <user>@<inner>` from the bastion host).",
        )
        .endpoint("inner:22")
        .retry_advice(spt_core::RetryAdvice::RetryWithBackoff)
        .build();
        let e = spt_core::Error::network_unreachable(d);
        let s = format!("{e}");
        assert!(s.contains("inner:22"));
        assert!(s.contains("kex algorithm mismatch"));
        assert!(s.contains("ssh -J"));
    }

    #[test]
    fn multi_hop_proxy_channel_failure_diagnostic_mentions_permit_open() {
        let d = spt_core::Diagnostic::what(format!(
            "Failed to open multi-hop proxy channel to `{}:{}`",
            "proxy", 1080u16
        ))
        .why("channel-open: rejected by host firewall")
        .how_to_fix(
            "Verify the outer hop is still connected and the bastion permits \
             TCP forwarding to the proxy host. Check `AllowTcpForwarding` and \
             any `PermitOpen` entries in sshd_config.",
        )
        .endpoint("proxy:1080")
        .retry_advice(spt_core::RetryAdvice::RetryWithBackoff)
        .build();
        let e = spt_core::Error::runtime_failure(d);
        spt_core::assert_diagnostic_contains!(e,
            what: "proxy channel",
            how_to_fix: "PermitOpen",
        );
    }
}
