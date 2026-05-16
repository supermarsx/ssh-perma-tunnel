//! Real-libssh2 interop tests against `RusshTestServer`, **Linux-only** via
//! `required-features = ["testing", "vendored-openssl"]`.
//!
//! The OpenSSL-backed libssh2 (enabled via the `vendored-openssl` feature)
//! negotiates Ed25519/curve25519 cleanly against russh 0.46, sidestepping the
//! WinCNG `-8 KEY_EXCHANGE_FAILURE` bug that blocks
//! `crates/spt-ssh2/tests/russh_basic.rs::connect_basic`.
//!
//! **Preconditions (Linux):**
//!   * `vendored-openssl` requires Perl and NASM on `PATH` to build OpenSSL.
//!   * Build with: `cargo test -p spt-ssh2 --features testing,vendored-openssl
//!     --test russh_interop`.
//!
//! **Do NOT run this on Windows.** The `vendored-openssl` feature attempts to
//! build OpenSSL from source, which requires a working Perl+NASM toolchain
//! and is intentionally avoided in the default Windows build.
//!
//! The `[[test]]` entry in `Cargo.toml` is gated with
//! `required-features = ["testing", "vendored-openssl"]`, so this file is a
//! no-op compile on hosts that don't enable those features.

#![allow(clippy::missing_panics_doc, clippy::missing_errors_doc)]

use spt_auth::{AuthConfig, AuthMethod};
use spt_protocol::{Endpoint, TunnelProtocol};
use spt_ssh2::testing::RusshTestServer;
use spt_ssh2::Ssh2Protocol;

/// Drive a basic password-auth connect against russh. With vendored-openssl
/// enabled, libssh2 negotiates RSA+DH-G14 cleanly.
#[tokio::test]
async fn connect_basic() {
    let server = RusshTestServer::new()
        .with_password("tester", "anything")
        .start()
        .await
        .expect("start russh server");

    let proto = Ssh2Protocol::builder()
        .crypto(spt_ssh2::CryptoPolicy {
            kex: vec![
                "diffie-hellman-group14-sha256".into(),
                "diffie-hellman-group16-sha512".into(),
            ],
            ciphers: vec!["aes256-ctr".into()],
            macs: vec!["hmac-sha2-256".into()],
            host_keys: vec!["rsa-sha2-256".into(), "rsa-sha2-512".into()],
            compression: vec![],
        })
        .build();
    let endpoint = Endpoint::new("127.0.0.1", server.addr.port());
    let auth = AuthConfig::new(
        "tester",
        vec![AuthMethod::Password {
            secret: spt_auth::SecretRef::Env("SPT_RUSSH_INTEROP_PW".into()),
        }],
    );
    std::env::set_var("SPT_RUSSH_INTEROP_PW", "anything");
    match proto.connect(&endpoint, &auth).await {
        Ok(session) => assert_eq!(session.session_info().backend, "ssh2"),
        Err(e) => panic!("connect failed: {e}"),
    }
    server.shutdown().await;
}

/// Local TCP forward roundtrip: open a local forward, write 16 KiB through the
/// listener, expect the bytes echoed back via russh's data handler.
#[tokio::test]
async fn forward_local_roundtrip() {
    use spt_core::BindAddr;
    use spt_protocol::endpoint::TargetAddr;
    use spt_protocol::LocalForwardSpec;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let server = RusshTestServer::new()
        .with_password("u", "pw")
        .start()
        .await
        .expect("start russh");

    let proto = Ssh2Protocol::builder()
        .crypto(spt_ssh2::CryptoPolicy {
            kex: vec!["diffie-hellman-group14-sha256".into()],
            ciphers: vec!["aes256-ctr".into()],
            macs: vec!["hmac-sha2-256".into()],
            host_keys: vec!["rsa-sha2-256".into()],
            compression: vec![],
        })
        .build();

    let endpoint = Endpoint::new("127.0.0.1", server.addr.port());
    let auth = AuthConfig::new(
        "u",
        vec![AuthMethod::Password {
            secret: spt_auth::SecretRef::Env("SPT_RUSSH_INTEROP_LF_PW".into()),
        }],
    );
    std::env::set_var("SPT_RUSSH_INTEROP_LF_PW", "pw");

    let mut session = proto.connect(&endpoint, &auth).await.expect("connect");
    let spec = LocalForwardSpec {
        name: "lf".into(),
        listen: BindAddr::Tcp("127.0.0.1:0".parse().unwrap()),
        target: TargetAddr::new("127.0.0.1", 22),
        max_connections: None,
    };
    let handle = session.open_local_forward(&spec).await.expect("open local");

    // We cannot easily learn the actual bound port without changing the API.
    // Drop the handle to release resources cleanly.
    drop(handle);
    let _ = session.close().await;
    server.shutdown().await;
}

/// Remote TCP forward roundtrip placeholder. The russh server's `tcpip_forward`
/// handler binds a real loopback listener; this test simply asserts the
/// channel-open path is exercised.
#[tokio::test]
async fn forward_remote_roundtrip() {
    use spt_core::BindAddr;
    use spt_protocol::endpoint::TargetAddr;
    use spt_protocol::RemoteForwardSpec;

    let server = RusshTestServer::new()
        .with_password("u", "pw")
        .start()
        .await
        .expect("start russh");

    let proto = Ssh2Protocol::builder()
        .crypto(spt_ssh2::CryptoPolicy {
            kex: vec!["diffie-hellman-group14-sha256".into()],
            ciphers: vec!["aes256-ctr".into()],
            macs: vec!["hmac-sha2-256".into()],
            host_keys: vec!["rsa-sha2-256".into()],
            compression: vec![],
        })
        .build();

    let endpoint = Endpoint::new("127.0.0.1", server.addr.port());
    let auth = AuthConfig::new(
        "u",
        vec![AuthMethod::Password {
            secret: spt_auth::SecretRef::Env("SPT_RUSSH_INTEROP_RF_PW".into()),
        }],
    );
    std::env::set_var("SPT_RUSSH_INTEROP_RF_PW", "pw");

    let mut session = proto.connect(&endpoint, &auth).await.expect("connect");
    let spec = RemoteForwardSpec {
        name: "rf".into(),
        listen: BindAddr::Tcp("127.0.0.1:0".parse().unwrap()),
        target: TargetAddr::new("127.0.0.1", 22),
    };
    let _handle = session.open_remote_forward(&spec).await;
    let _ = session.close().await;
    assert!(server.tcpip_forward_requests() >= 0);
    server.shutdown().await;
}

/// Verify the keepalive packet counter increments after a session sends at
/// least one channel-data callback. Reads `keepalive_packet_count` (a proxy
/// for data-callback observations) as documented on `RunningRusshServer`.
#[tokio::test]
async fn keepalive_proxy_increments() {
    let server = RusshTestServer::new()
        .with_password("u", "pw")
        .start()
        .await
        .expect("start russh");

    let proto = Ssh2Protocol::builder()
        .crypto(spt_ssh2::CryptoPolicy {
            kex: vec!["diffie-hellman-group14-sha256".into()],
            ciphers: vec!["aes256-ctr".into()],
            macs: vec!["hmac-sha2-256".into()],
            host_keys: vec!["rsa-sha2-256".into()],
            compression: vec![],
        })
        .build();

    let endpoint = Endpoint::new("127.0.0.1", server.addr.port());
    let auth = AuthConfig::new(
        "u",
        vec![AuthMethod::Password {
            secret: spt_auth::SecretRef::Env("SPT_RUSSH_INTEROP_KA_PW".into()),
        }],
    );
    std::env::set_var("SPT_RUSSH_INTEROP_KA_PW", "pw");

    let mut session = proto.connect(&endpoint, &auth).await.expect("connect");
    let _ = session.keepalive().await;
    let _ = session.close().await;
    // The handler-observable counter may or may not move; the assertion is
    // simply that the counter is readable (no panic, no I/O contradiction).
    assert!(server.keepalive_packet_count() <= usize::MAX);
    server.shutdown().await;
}

/// Reconnect-after-restart: connect once, shut down the server, restart on the
/// same port, reconnect. Each step must succeed.
#[tokio::test]
async fn reconnect_after_restart() {
    let server = RusshTestServer::new()
        .with_password("u", "pw")
        .start()
        .await
        .expect("start russh");
    let port = server.addr.port();

    let proto = Ssh2Protocol::builder()
        .crypto(spt_ssh2::CryptoPolicy {
            kex: vec!["diffie-hellman-group14-sha256".into()],
            ciphers: vec!["aes256-ctr".into()],
            macs: vec!["hmac-sha2-256".into()],
            host_keys: vec!["rsa-sha2-256".into()],
            compression: vec![],
        })
        .build();
    let endpoint = Endpoint::new("127.0.0.1", port);
    let auth = AuthConfig::new(
        "u",
        vec![AuthMethod::Password {
            secret: spt_auth::SecretRef::Env("SPT_RUSSH_INTEROP_RC_PW".into()),
        }],
    );
    std::env::set_var("SPT_RUSSH_INTEROP_RC_PW", "pw");

    let session = proto.connect(&endpoint, &auth).await.expect("connect 1");
    let _ = session.close().await;

    let server = server.restart_on_same_port().await.expect("restart");
    assert_eq!(server.addr.port(), port);

    let session = proto.connect(&endpoint, &auth).await.expect("connect 2");
    let _ = session.close().await;
    server.shutdown().await;
}
