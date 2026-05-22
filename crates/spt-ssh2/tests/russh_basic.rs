//! Integration tests against an embedded `russh` SSH2 server.
//!
//! These tests spin up a russh server on `127.0.0.1:0`, then drive
//! `Ssh2Protocol` against it.
//!
//! ## russh ↔ libssh2 interop status (resolved t3-e8, russh 0.46 / libssh2-sys 0.3.1)
//!
//! `connect_basic` is **enabled** as of t3-e8. Background:
//!
//! The earlier `#[ignore]` was attributed to an unidentified `-8`
//! `LIBSSH2_ERROR_KEY_EXCHANGE_FAILURE` mid-DH. The t3-e8 bisection
//! ([`crates/spt-ssh2/tests/russh_basic.rs`] `bisect_*` tests and
//! [`.orchestration/logs/t3-e8.md`]) demonstrated that the failure requires
//! **all three** of the following advertised by the russh server simultaneously:
//!
//! 1. `curve25519-sha256` (and/or `curve25519-sha256@libssh.org`) in the KEX list
//! 2. `ext-info-s` (RFC 8308 extension negotiation)
//! 3. `kex-strict-s-v00@openssh.com` (CVE-2023-48795 mitigation)
//!
//! Dropping **any one** of the three from the server's advertised KEX list
//! makes libssh2-WinCNG complete the handshake cleanly. Single-axis category
//! restrictions (cipher only, MAC only, or host-key only) **do not** fix it
//! while the three KEX entries above are all present — confirming the
//! interaction is at the KEX-advertisement layer specifically.
//!
//! Upstream tracking: <https://github.com/warp-tech/russh/issues/245>
//! ("Connection from libgit2 (libssh2) fails with 'Unable to exchange
//! encryption keys'") — same symptom, same client identifier
//! (`SSH-2.0-libssh2_*`), still open against russh as of t3-e8. The
//! reporter's packet capture also shows libssh2 sending ext-info-c +
//! kex-strict-c-v00@openssh.com immediately before disconnecting.
//!
//! **Workaround shipped here:** [`spt_ssh2::testing::wincng_libssh2_compatible_preferred`]
//! returns a `russh::Preferred` that pins the server's advertised KEX list
//! to `[diffie-hellman-group14-sha256, diffie-hellman-group16-sha512]`,
//! cipher to `aes256-ctr`, MAC to `hmac-sha2-256`, host-key to
//! `[rsa-sha2-256, rsa-sha2-512]`, with no extension entries. Pass it to
//! [`RusshTestServer::with_algorithm_pinning`].
//!
//! This workaround is **test-only** and does not affect the production
//! `Ssh2Protocol` path; production clients negotiate against real SSH
//! servers (OpenSSH, dropbear, etc.) where this bug does not reproduce.
//! When russh#245 is fixed, the algorithm-pinning workaround can be
//! removed and the test will still pass against the default `Preferred`.

#![allow(clippy::missing_errors_doc, clippy::missing_panics_doc)]

use spt_auth::{AuthConfig, AuthMethod};
use spt_protocol::{Endpoint, TunnelProtocol};
use spt_ssh2::testing::RusshTestServer;
use spt_ssh2::Ssh2Protocol;

/// Smoke test: connect with password auth against an embedded russh server
/// constrained to the WinCNG-compatible algorithm subset (see module docs).
#[tokio::test]
async fn connect_basic() {
    let server = RusshTestServer::new()
        .with_password("tester", "anything")
        .with_algorithm_pinning(spt_ssh2::testing::wincng_libssh2_compatible_preferred())
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
        Ok(session) => assert_eq!(session.session_info().backend, "ssh2-russh"),
        Err(e) => panic!("connect failed: {e}"),
    }
    server.shutdown().await;
}

// -----------------------------------------------------------------------------
// Bisection harness (kept as documentation): proves the precise failure
// trigger. Each trial is `#[ignore]`'d. Run with
// `cargo test -p spt-ssh2 --features testing -- --ignored --test-threads=1 bisect_`.
//
// Observed table (t3-e8, Windows libssh2-WinCNG):
//
// | server `Preferred`                                                        | result   |
// |---------------------------------------------------------------------------|----------|
// | DEFAULT (curve25519 + DH + ext-info-s + strict-kex-s)                     | Err(-8)  |
// | DEFAULT, cipher=[aes256-ctr]                                              | Err(-8)  |
// | DEFAULT, mac=[hmac-sha2-256]                                              | Err(-8)  |
// | DEFAULT, key=[rsa-sha2-256, rsa-sha2-512]                                 | Err(-8)  |
// | DEFAULT, kex drops curve25519 (DH + ext-info-s + strict-kex-s)            | Ok       |
// | DEFAULT, kex drops ext-info-s (curve25519 + DH + strict-kex-s)            | Ok       |
// | DEFAULT, kex drops strict-kex-s (curve25519 + DH + ext-info-s)            | Ok       |
// | DEFAULT, kex drops both extensions (curve25519 + DH only)                 | Ok       |
//
// Conclusion: the bug requires **all three** of curve25519 + ext-info-s +
// strict-kex-s advertised together. Any one removed fixes it. See module docs.

async fn try_connect(preferred: russh::Preferred) -> std::result::Result<(), String> {
    let server = RusshTestServer::new()
        .with_password("tester", "anything")
        .with_algorithm_pinning(preferred)
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
    std::env::set_var("SPT_TEST_PW", "anything");
    let res = proto.connect(&endpoint, &auth).await;
    server.shutdown().await;
    match res {
        Ok(_) => Ok(()),
        Err(e) => Err(e.to_string()),
    }
}

#[tokio::test]
#[ignore = "bisection trial — see module docs / .orchestration/logs/t3-e8.md"]
async fn bisect_default_reproduces_kex_failure() {
    let r = try_connect(russh::Preferred::DEFAULT).await;
    println!("bisect_default: {r:?}");
    assert!(
        r.is_err(),
        "DEFAULT Preferred should reproduce the russh#245 -8 failure; got {r:?}"
    );
}

#[tokio::test]
#[ignore = "bisection trial — see module docs / .orchestration/logs/t3-e8.md"]
async fn bisect_drop_strict_kex_only_succeeds() {
    use std::borrow::Cow;
    let mut p = russh::Preferred::DEFAULT;
    p.kex = Cow::Owned(vec![
        russh::kex::CURVE25519,
        russh::kex::CURVE25519_PRE_RFC_8731,
        russh::kex::DH_G16_SHA512,
        russh::kex::DH_G14_SHA256,
        russh::kex::EXTENSION_SUPPORT_AS_SERVER,
        // strict-kex-s dropped
    ]);
    let r = try_connect(p).await;
    println!("bisect_drop_strict_kex_only: {r:?}");
    assert!(
        r.is_ok(),
        "dropping strict-kex-s alone should fix; got {r:?}"
    );
}

#[tokio::test]
#[ignore = "bisection trial — see module docs / .orchestration/logs/t3-e8.md"]
async fn bisect_drop_ext_info_only_succeeds() {
    use std::borrow::Cow;
    let mut p = russh::Preferred::DEFAULT;
    p.kex = Cow::Owned(vec![
        russh::kex::CURVE25519,
        russh::kex::CURVE25519_PRE_RFC_8731,
        russh::kex::DH_G16_SHA512,
        russh::kex::DH_G14_SHA256,
        russh::kex::EXTENSION_OPENSSH_STRICT_KEX_AS_SERVER,
        // ext-info-s dropped
    ]);
    let r = try_connect(p).await;
    println!("bisect_drop_ext_info_only: {r:?}");
    assert!(r.is_ok(), "dropping ext-info-s alone should fix; got {r:?}");
}

#[tokio::test]
#[ignore = "bisection trial — see module docs / .orchestration/logs/t3-e8.md"]
async fn bisect_drop_curve25519_only_succeeds() {
    use std::borrow::Cow;
    let mut p = russh::Preferred::DEFAULT;
    p.kex = Cow::Owned(vec![
        russh::kex::DH_G16_SHA512,
        russh::kex::DH_G14_SHA256,
        russh::kex::EXTENSION_SUPPORT_AS_SERVER,
        russh::kex::EXTENSION_OPENSSH_STRICT_KEX_AS_SERVER,
    ]);
    let r = try_connect(p).await;
    println!("bisect_drop_curve25519_only: {r:?}");
    assert!(r.is_ok(), "dropping curve25519 alone should fix; got {r:?}");
}
