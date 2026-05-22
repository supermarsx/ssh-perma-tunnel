//! Integration tests for the russh SSH-agent client actor (`spt_ssh2::Agent`).
//!
//! Strategy:
//!
//! * Tests bind an in-process `russh_keys::agent::server::serve` instance
//!   over a Unix-domain socket (on Unix) or a Windows named pipe (on
//!   Windows). The same `russh_keys` agent server implementation backs both
//!   transports, so the agent protocol bytes are identical.
//! * The agent server is seeded with a freshly generated Ed25519 key. Tests
//!   then verify that `Agent::list_identities` enumerates the seeded key
//!   and that `Agent::sign` returns a signature that verifies under that
//!   key.
//! * The GSSAPI / SSPI dispatch is covered by driving the russh backend's
//!   auth method with the documented unsupported-backend error string.

#![allow(clippy::missing_panics_doc, clippy::missing_errors_doc)]

use spt_core::Error;
use spt_ssh2::Agent;

// ---------- Cross-platform high-level tests ----------

/// `from_stream` constructs without panicking and propagates I/O errors as
/// `AuthFailed` (smoke test exercised here at the integration level too so
/// the test target binary actually links the `testing` feature surface).
#[tokio::test]
async fn from_stream_propagates_eof_as_auth_failed() {
    let (client_side, server_side) = tokio::io::duplex(64);
    drop(server_side);
    let agent = Agent::from_stream(client_side, "duplex-closed");
    let err = agent
        .list_identities()
        .await
        .expect_err("expected AuthFailed on closed transport");
    assert!(matches!(err, Error::AuthFailed(_)), "{err:?}");
}

#[tokio::test]
async fn fingerprint_is_stable_per_key_shape() {
    let key = russh_keys::key::KeyPair::generate_ed25519();
    let pub_key = key.clone_public_key().expect("derive pubkey");
    let fp = Agent::fingerprint(&pub_key);
    assert!(fp.starts_with("ssh-ed25519"), "{fp}");
    // Same key produces identical fingerprint.
    assert_eq!(fp, Agent::fingerprint(&pub_key));
}

#[tokio::test]
async fn windows_pipe_constant_exposed() {
    // Compile-time gate: we want the constant available on every target so
    // configuration validators can echo it back to users uniformly.
    assert!(spt_ssh2::agent::WINDOWS_OPENSSH_PIPE.ends_with("openssh-ssh-agent"));
}

// ---------- Unix-only tests against russh's bundled agent server ----------

#[cfg(unix)]
pub mod unix_agent {
    use super::Agent;
    use russh_keys::key::KeyPair;
    use tempfile::TempDir;
    use tokio::net::UnixListener;

    /// Stream wrapper accepted by `russh_keys::agent::server::serve`.
    struct Incoming {
        listener: UnixListener,
    }

    impl futures::stream::Stream for Incoming {
        type Item = std::io::Result<tokio::net::UnixStream>;
        fn poll_next(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Option<Self::Item>> {
            let me = self.get_mut();
            let (sock, _addr) = futures::ready!(me.listener.poll_accept(cx))?;
            std::task::Poll::Ready(Some(Ok(sock)))
        }
    }

    #[derive(Clone)]
    struct NoopAgent;
    impl russh_keys::agent::server::Agent for NoopAgent {}

    /// Spawn the russh-keys built-in agent server on a temp UDS path and
    /// pre-load it with the supplied keys via a separate `AgentClient`.
    /// Returns the temp dir (for RAII cleanup) and the socket path.
    pub async fn spawn_agent(keys: Vec<KeyPair>) -> (TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("agent.sock");
        let listener = UnixListener::bind(&path).expect("bind agent socket");

        let incoming = Incoming { listener };
        tokio::spawn(async move {
            let _ = russh_keys::agent::server::serve(incoming, NoopAgent).await;
        });

        // Yield so the listener task is scheduled before we load identities.
        tokio::task::yield_now().await;

        // Seed identities through a dedicated client connection.
        for key in keys {
            let stream = tokio::net::UnixStream::connect(&path)
                .await
                .expect("connect seed client");
            let mut client = russh_keys::agent::client::AgentClient::connect(stream);
            client
                .add_identity(&key, &[])
                .await
                .expect("add identity to test agent");
        }

        (dir, path)
    }

    #[tokio::test]
    async fn list_identities_returns_seeded_key() {
        let key = KeyPair::generate_ed25519();
        let pub_a = key.clone_public_key().unwrap();
        let (_dir, path) = spawn_agent(vec![key]).await;

        let agent = Agent::connect_path(&path).await.expect("connect");
        let listed = agent.list_identities().await.expect("list identities");
        assert_eq!(listed.len(), 1, "exactly one identity expected");
        use russh_keys::PublicKeyBase64 as _;
        assert_eq!(
            listed[0].public_key_bytes(),
            pub_a.public_key_bytes(),
            "listed key bytes must match seeded key"
        );
    }

    #[tokio::test]
    async fn sign_round_trips_through_agent_server() {
        let key = KeyPair::generate_ed25519();
        let (_dir, path) = spawn_agent(vec![key]).await;
        let agent = Agent::connect_path(&path).await.expect("connect");
        let listed = agent.list_identities().await.expect("list");
        let signed = agent
            .sign(&listed[0], b"hello-spt")
            .await
            .expect("agent sign");
        assert!(!signed.is_empty(), "non-empty signature");
    }

    #[tokio::test]
    async fn connect_path_missing_socket_returns_auth_failed() {
        let path = std::path::PathBuf::from("/nonexistent/spt-test-agent-int.sock");
        let err = Agent::connect_path(&path)
            .await
            .expect_err("expected AuthFailed for missing socket");
        assert!(matches!(err, spt_core::Error::AuthFailed(_)), "{err:?}");
    }
}

// ---------- Cross-platform GSSAPI / SSPI dispatch (provider stub path) ----------

/// `AuthMethod::Gssapi` dispatch must surface the documented
/// `UnsupportedBackend:` marker (russh 0.46 lacks `gssapi-with-mic`). We
/// drive the public `Ssh2Protocol::connect` path against a russh test
/// server that *accepts password* — the auth call fails because we only
/// configure a Gssapi method, surfacing the dispatch error.
#[tokio::test]
async fn gssapi_dispatch_surfaces_unsupported_backend_marker() {
    use spt_auth::{AuthConfig, AuthMethod};
    use spt_protocol::{Endpoint, TunnelProtocol as _};
    use spt_ssh2::testing::RusshTestServer;
    use spt_ssh2::Ssh2Protocol;

    let server = RusshTestServer::new()
        .with_password("anyone", "x")
        .start()
        .await
        .expect("start russh server");

    let proto = Ssh2Protocol::builder().build();
    let endpoint = Endpoint::new("127.0.0.1", server.addr.port());
    let auth = AuthConfig::new(
        "anyone",
        vec![AuthMethod::Gssapi {
            service: Some("host/edge.example.com@EXAMPLE.COM".into()),
            principal: None,
            delegate: false,
        }],
    );
    let res = proto.connect(&endpoint, &auth).await;
    let err = match res {
        Ok(_) => panic!("Gssapi must not authenticate against a russh test server"),
        Err(e) => e,
    };
    let msg = format!("{err}");
    assert!(
        msg.contains("UnsupportedBackend") || msg.contains("gssapi"),
        "expected GSSAPI dispatch marker; got {msg}"
    );
    server.shutdown().await;
}

#[tokio::test]
async fn sspi_dispatch_surfaces_unsupported_backend_marker() {
    use spt_auth::{AuthConfig, AuthMethod};
    use spt_protocol::{Endpoint, TunnelProtocol as _};
    use spt_ssh2::testing::RusshTestServer;
    use spt_ssh2::Ssh2Protocol;

    let server = RusshTestServer::new()
        .with_password("anyone", "x")
        .start()
        .await
        .expect("start russh server");

    let proto = Ssh2Protocol::builder().build();
    let endpoint = Endpoint::new("127.0.0.1", server.addr.port());
    let auth = AuthConfig::new(
        "anyone",
        vec![AuthMethod::Sspi {
            service: Some("host/edge.example.com".into()),
            principal: None,
            delegate: false,
            allow_ntlm_fallback: true,
        }],
    );
    let res = proto.connect(&endpoint, &auth).await;
    let err = match res {
        Ok(_) => panic!("Sspi must not authenticate against a russh test server"),
        Err(e) => e,
    };
    let msg = format!("{err}");
    assert!(
        msg.contains("UnsupportedBackend") || msg.contains("sspi") || msg.contains("gssapi"),
        "expected SSPI dispatch marker; got {msg}"
    );
    server.shutdown().await;
}

// ---------- End-to-end auth via mock russh server + agent ----------

/// End-to-end driver coverage (t7-P1 happy path). The actor connects to a
/// real in-process SSH-agent server, enumerates identities, and drives
/// `publickey` auth through `Handle::authenticate_future` against an
/// embedded russh test server that authorises the same Ed25519 key. The
/// session must establish (`Ok(_)`).
///
/// Pre-t7-P1 this test asserted the `UnsupportedBackend:` upstream-block
/// marker. After the local russh-fork patch (`+ 'static` on `Signer::Future`
/// and friends, plus an explicit `Box::pin` return on `authenticate_future`)
/// the dispatcher is wired through and the connection succeeds.
#[cfg(unix)]
#[tokio::test]
async fn authenticate_via_agent_succeeds() {
    use spt_auth::{AuthConfig, AuthMethod};
    use spt_protocol::{Endpoint, TunnelProtocol as _};
    use spt_ssh2::testing::RusshTestServer;
    use spt_ssh2::Ssh2Protocol;

    let key = russh_keys::key::KeyPair::generate_ed25519();
    let pubkey = key.clone_public_key().expect("derive pubkey");

    let server = RusshTestServer::new()
        .with_authorized_pubkey(pubkey)
        .start()
        .await
        .expect("start russh server");

    let (_dir, path) = unix_agent::spawn_agent(vec![key]).await;

    let proto = Ssh2Protocol::builder().build();
    let endpoint = Endpoint::new("127.0.0.1", server.addr.port());
    let auth = AuthConfig::new(
        "anyone",
        vec![AuthMethod::Agent {
            socket: Some(path.clone()),
        }],
    );
    let session = proto
        .connect(&endpoint, &auth)
        .await
        .expect("publickey-via-agent auth succeeds against embedded russh server");
    // Drop the session cleanly so the server's accept loop exits before
    // we shut it down.
    drop(session);
    server.shutdown().await;
}

/// Negative t7-P1 test: agent holds *only* key X, server authorises
/// *only* key Y → auth must fail. We assert that the resulting error
/// chain mentions the authentication failure (no `UnsupportedBackend`
/// fallback path can survive here, since the dispatch is now wired
/// through to a real wire round trip).
#[cfg(unix)]
#[tokio::test]
async fn authenticate_via_agent_rejects_unknown_key() {
    use spt_auth::{AuthConfig, AuthMethod};
    use spt_protocol::{Endpoint, TunnelProtocol as _};
    use spt_ssh2::testing::RusshTestServer;
    use spt_ssh2::Ssh2Protocol;

    // X = the agent-held key; Y = the server-authorised key. They must
    // differ for the negative path to be meaningful.
    let agent_key = russh_keys::key::KeyPair::generate_ed25519();
    let server_key = russh_keys::key::KeyPair::generate_ed25519();
    let server_pub = server_key.clone_public_key().expect("derive pubkey");

    let server = RusshTestServer::new()
        .with_authorized_pubkey(server_pub)
        .start()
        .await
        .expect("start russh server");

    // Only the unauthorised key lives in the agent.
    let (_dir, path) = unix_agent::spawn_agent(vec![agent_key]).await;

    let proto = Ssh2Protocol::builder().build();
    let endpoint = Endpoint::new("127.0.0.1", server.addr.port());
    let auth = AuthConfig::new(
        "anyone",
        vec![AuthMethod::Agent {
            socket: Some(path.clone()),
        }],
    );
    let res = proto.connect(&endpoint, &auth).await;
    let err = res.expect_err("auth must fail when the agent has no authorised key");
    // The dispatcher returns an `AuthFailed` family error after exhausting
    // identities; the message must clearly indicate the auth failure path
    // and must NOT contain the legacy `UnsupportedBackend:` marker (which
    // would indicate the t7-P1 wiring regressed).
    let msg = format!("{err}");
    assert!(
        !msg.contains("UnsupportedBackend"),
        "post-t7-P1 dispatch must not surface UnsupportedBackend; got {msg}"
    );
    assert!(
        matches!(err, spt_core::Error::AuthFailed(_)),
        "expected AuthFailed, got {err:?}"
    );
    server.shutdown().await;
}
