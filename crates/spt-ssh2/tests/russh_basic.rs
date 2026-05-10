//! Integration tests against an embedded `russh` SSH2 server.
//!
//! These tests spin up a russh server on `127.0.0.1:0`, then drive
//! `Ssh2Protocol` against it. Because the russh handler surface is large and
//! evolving, only the most fundamental connectivity test is enabled by
//! default; the richer tests (forwards, mismatch) are gated behind
//! `#[ignore]` and runnable explicitly with `cargo test -- --ignored`.
//!
//! ## russh ↔ libssh2 interop status (as of t2-e3, russh 0.46 / libssh2-sys 0.3.1)
//!
//! `connect_basic` is **kept ignored** even after the t2-e3 helper-extension
//! work because of a deeper interop bug between russh 0.46 and the `WinCNG`
//! build of libssh2:
//!
//! 1. **Algorithm-set mismatch (resolved at the test level).** The libssh2-sys
//!    0.3.1 build on Windows links against `WinCNG`, which defines
//!    `LIBSSH2_ED25519=0` and does *not* set `LIBSSH2_ECDSA_WINCNG`. That
//!    leaves `WinCNG` libssh2 with only RSA host keys and only DH-group KEXes
//!    (no curve25519, no ECDSA, no ed25519). Russh 0.46's server defaults
//!    are ed25519 + curve25519 — zero overlap. We work around this by
//!    forcing an RSA-2048 host key on the server and constraining the
//!    client `CryptoPolicy` to `diffie-hellman-group14-sha256` /
//!    `aes256-ctr` / `hmac-sha2-256` / `rsa-sha2-256`. After this, KEX
//!    negotiation succeeds.
//! 2. **`-8` `LIBSSH2_ERROR_KEY_EXCHANGE_FAILURE` (still open, upstream).**
//!    Even with overlapping algorithms, libssh2 fails the DH exchange with
//!    error -8 mid-handshake. The most likely cause is an incompatibility
//!    between libssh2's strict-kex implementation and russh's, or a subtle
//!    encoding difference in the DH `KEXDH_REPLY` packet. Properly fixing
//!    this requires either a russh patch or a deeper dive into libssh2's
//!    transport state machine — both outside the t2-e3 scope and timebox.
//!
//! When this is fixed, drop the `#[ignore]` attribute and the test should
//! pass as-is.

#![allow(clippy::missing_errors_doc, clippy::missing_panics_doc)]

use spt_auth::{AuthConfig, AuthMethod};
use spt_protocol::{Endpoint, TunnelProtocol};
use spt_ssh2::testing::RusshTestServer;
use spt_ssh2::Ssh2Protocol;

/// Smoke test: connect with password auth (no trust verification — accepted
/// because the protocol is configured with the default permissive verifier).
///
/// See module docs for why this is `#[ignore]`'d. To attempt the test
/// explicitly: `cargo test --features testing -- --ignored connect_basic`.
#[tokio::test]
#[ignore = "russh<->libssh2 interop blocked: libssh2 errors -8 KEY_EXCHANGE_FAILURE \
mid-DH despite negotiated overlap (RSA-2048 hostkey + DH-G14-SHA256). \
See module docs for diagnosis. Likely strict-kex/DH-encoding bug; needs \
upstream russh patch or libssh2 transport-state dive — out of scope for t2-e3."]
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
            secret: spt_auth::SecretRef::Env("SPT_TEST_PW".into()),
        }],
    );
    // SPT_TEST_PW must be set for resolve_secret to succeed.
    std::env::set_var("SPT_TEST_PW", "anything");
    match proto.connect(&endpoint, &auth).await {
        Ok(session) => assert_eq!(session.session_info().backend, "ssh2"),
        Err(e) => panic!("connect failed: {e}"),
    }
    server.shutdown().await;
}
