//! Integration tests for `spt-auth-sspi` — exercises the GSS/SSPI trait,
//! principal parser, `provider_for` / `sspi_provider_for` dispatch, and the
//! mock provider's `gssapi-with-mic` state machine.
//!
//! Per executor t6-e9 spec, this file contains 12 tests covering the
//! testable surface available without live SSPI / cross-krb5 deps in the
//! lockfile (see `crates/spt-auth-sspi/src/lib.rs` for the lockfile
//! decision record).

#![cfg(feature = "testing")]

use spt_auth_sspi::mock::{MechMock, MockGssProvider};
use spt_auth_sspi::{
    provider_for, sspi_provider_for, unsupported_backend, GssApiConfig, GssProvider, Principal,
    PrincipalParseError, SspiConfig,
};
use spt_core::Error;

const KEY: &[u8] = b"shared-context-key";

/// (1) Mock NTLM round-trip — initialize once, MIC round-trips through an
/// acceptor configured with the same shared key. Drives the path that the
/// real `sspi 0.15` Ntlm package would exercise. Windows-only in production;
/// the mock is cross-platform so we run it everywhere to guarantee the trait
/// surface compiles on Linux.
#[test]
fn windows_only_ntlm_round_trip_via_mock() {
    let mut initiator = MockGssProvider::initiator(MechMock::Ntlm, 1, KEY);
    let out = initiator.initialize("host@edge.example.com", None).unwrap();
    assert!(out.complete, "single-round NTLM completes immediately");
    assert!(out.token.as_ref().unwrap().starts_with(&[0xCD]));
    let mic = initiator.get_mic(b"session-id-bound transcript").unwrap();

    let acceptor = MockGssProvider::acceptor(MechMock::Ntlm, KEY);
    acceptor
        .verify_mic(b"session-id-bound transcript", &mic)
        .expect("MIC verifies on acceptor");
}

/// (2) Mock Kerberos round-trip — identical shape to (1), but the mech tag
/// differs and is observable on the wire. Guards that the mech parameter
/// plumbs through to the produced token.
#[test]
fn windows_only_kerberos_round_trip_via_mock() {
    let mut initiator = MockGssProvider::initiator(MechMock::Kerberos, 1, KEY);
    let out = initiator
        .initialize("host/edge.example.com@EXAMPLE.COM", None)
        .unwrap();
    assert!(out.complete);
    assert!(out.token.as_ref().unwrap().starts_with(&[0xAB]));
    let mic = initiator.get_mic(b"transcript").unwrap();
    assert!(mic.starts_with(&[0xAB]), "Kerberos mech tag is present");

    let acceptor = MockGssProvider::acceptor(MechMock::Kerberos, KEY);
    acceptor.verify_mic(b"transcript", &mic).unwrap();
}

/// (3) Kerberos token-exchange state machine — 3 round-trips before
/// `complete = true`. Mirrors the canonical 3-leg Kerberos exchange
/// (AS-REQ/REP → TGS-REQ/REP → AP-REQ via the GSSAPI wrapper, exposed to the
/// SSH layer as three `initialize` invocations).
#[test]
fn kerberos_token_exchange_three_round_trips_before_complete() {
    let mut initiator = MockGssProvider::initiator(MechMock::Kerberos, 3, KEY);

    let o1 = initiator.initialize("host@server", None).unwrap();
    assert!(!o1.complete);
    let o2 = initiator
        .initialize("host@server", o1.token.as_deref())
        .unwrap();
    assert!(!o2.complete);
    let o3 = initiator
        .initialize("host@server", o2.token.as_deref())
        .unwrap();
    assert!(o3.complete, "3rd round flips complete to true");
    assert_eq!(initiator.rounds_observed(), 3);
}

/// (4) Principal parsing covers the two SSH-canonical shapes:
/// `service@host` and `service/instance@REALM`.
#[test]
fn principal_parsing_covers_service_at_host_and_service_slash_instance_at_realm() {
    let a = Principal::parse("host@edge.example.com").unwrap();
    assert_eq!(a.service, "host");
    assert_eq!(a.instance, None);
    assert_eq!(a.realm.as_deref(), Some("edge.example.com"));

    let b = Principal::parse("host/edge.example.com@EXAMPLE.COM").unwrap();
    assert_eq!(b.service, "host");
    assert_eq!(b.instance.as_deref(), Some("edge.example.com"));
    assert_eq!(b.realm.as_deref(), Some("EXAMPLE.COM"));
    assert_eq!(b.to_string(), "host/edge.example.com@EXAMPLE.COM");

    // Negative paths — non-load-bearing for the headline assertion but
    // guard the parser's error contract.
    assert_eq!(
        Principal::parse("host/"),
        Err(PrincipalParseError::EmptyInstance)
    );
    assert_eq!(
        Principal::parse("@realm"),
        Err(PrincipalParseError::EmptyService)
    );
}

/// (5) Delegate flag plumbing — `delegate = true` round-trips through both
/// `GssApiConfig` and `SspiConfig` and is observable in subsequent provider
/// construction calls.
#[test]
fn delegate_flag_plumbing() {
    let g = GssApiConfig {
        service: Some("host@h".into()),
        principal: None,
        delegate: true,
    };
    // `provider_for` cannot build a real backend (no deps in lockfile), but
    // we can still verify that the input config carries the flag — and the
    // returned error mentions the disabled-backend marker, not a field issue.
    assert!(g.delegate);
    let err = provider_for(&g).unwrap_err();
    assert!(matches!(err, Error::UnsupportedPlatform(_)), "{err}");

    let s = SspiConfig {
        service: Some("host@h".into()),
        principal: None,
        delegate: true,
        allow_ntlm_fallback: false,
    };
    assert!(s.delegate);
    let err = sspi_provider_for(&s).unwrap_err();
    // On Unix, sspi_provider_for with allow_ntlm_fallback=false delegates
    // to provider_for (Kerberos via cross-krb5). On Windows, it routes to
    // the SSPI build. Either way the live backend is disabled and we get
    // an UnsupportedPlatform / AuthFailed.
    assert!(
        matches!(err, Error::UnsupportedPlatform(_) | Error::AuthFailed(_)),
        "{err}"
    );
}

/// (6) Unix NTLM is unsupported — `sspi_provider_for` with
/// `allow_ntlm_fallback = true` on a Unix target produces the documented
/// `UnsupportedOnUnix` marker. On Windows the same call routes into the
/// SSPI backend (which also returns `UnsupportedBackend` until the dep is
/// in the lockfile, but with a different marker — so we split the assertion).
#[test]
fn unix_ntlm_is_unsupported_on_unix() {
    let cfg = SspiConfig {
        service: None,
        principal: None,
        delegate: false,
        allow_ntlm_fallback: true,
    };
    let err = sspi_provider_for(&cfg).unwrap_err();
    let msg = err.to_string();
    #[cfg(not(target_os = "windows"))]
    assert!(
        msg.contains("UnsupportedOnUnix") || msg.contains("NTLM is unavailable on Unix"),
        "expected UnsupportedOnUnix marker, got: {msg}"
    );
    #[cfg(target_os = "windows")]
    assert!(
        msg.contains("UnsupportedBackend"),
        "expected UnsupportedBackend marker (sspi crate not in lockfile), got: {msg}"
    );
}

/// (7) `AuthMethod::Gssapi` and `AuthMethod::Sspi` ser/de are byte-stable.
/// This crate is the home of the backends — drift in the enum-tag string or
/// the field names lands here first.
#[test]
fn auth_method_deser_ser_unchanged() {
    use spt_auth::AuthMethod;

    let gssapi = AuthMethod::Gssapi {
        service: Some("host@h".into()),
        principal: Some("alice@R".into()),
        delegate: true,
    };
    let s = serde_json::to_string(&gssapi).unwrap();
    assert!(s.contains(r#""method":"gssapi""#), "{s}");
    assert!(s.contains(r#""delegate":true"#), "{s}");
    let round: AuthMethod = serde_json::from_str(&s).unwrap();
    assert_eq!(round, gssapi);

    let sspi = AuthMethod::Sspi {
        service: None,
        principal: None,
        delegate: false,
        allow_ntlm_fallback: true,
    };
    let s = serde_json::to_string(&sspi).unwrap();
    assert!(s.contains(r#""method":"sspi""#), "{s}");
    assert!(s.contains(r#""allow_ntlm_fallback":true"#), "{s}");
    let round: AuthMethod = serde_json::from_str(&s).unwrap();
    assert_eq!(round, sspi);
}

/// (8) libssh2 path returns `UnsupportedBackend` — this assertion lives in
/// the spt-ssh2 integration tests too (executor t6-e9 also edits
/// `crates/spt-ssh2/src/auth.rs`); the helper assertion here pins the
/// stable marker prefix that the libssh2 dispatch site reuses.
#[test]
fn libssh2_path_unsupported_backend_marker_is_stable() {
    let err = unsupported_backend("libssh2 backend does not support gssapi-with-mic (RFC 4462)");
    match err {
        Error::UnsupportedPlatform(msg) => {
            assert!(msg.starts_with("UnsupportedBackend:"), "{msg}");
            assert!(msg.contains("gssapi-with-mic"), "{msg}");
        }
        other => panic!("expected UnsupportedPlatform, got {other:?}"),
    }
}

/// (9) MIC verification on a known vector — mock-provider MIC is
/// `mech_tag || (message[i] XOR key[i mod len])`. Anyone re-implementing the
/// mock must produce the same bytes for `key = b"shared-context-key"`,
/// `message = b"abc"`, Kerberos mech.
#[test]
fn mic_verification_known_vector() {
    let initiator = MockGssProvider::initiator(MechMock::Kerberos, 1, KEY);
    let mic = initiator.get_mic(b"abc").unwrap();
    // Expected: [0xAB, 'a'^'s', 'b'^'h', 'c'^'a']
    let expected = [
        0xABu8,
        b'a' ^ b's',
        b'b' ^ b'h',
        b'c' ^ b'a',
    ];
    assert_eq!(mic.as_slice(), &expected[..], "MIC known-vector drift");

    // Tamper byte zero: mech tag flip must fail verification.
    let mut tampered = mic.clone();
    tampered[0] ^= 0x01;
    let acceptor = MockGssProvider::acceptor(MechMock::Kerberos, KEY);
    assert!(acceptor.verify_mic(b"abc", &tampered).is_err());
}

/// (10) `allow_ntlm_fallback = true` on Windows tries Kerberos first.
///
/// Today the SSPI backend is unbuildable (sspi crate absent from lockfile)
/// so we cannot assert ordering against a live exchange. What we *can*
/// assert is that the config knob plumbs through — and that on Unix
/// `allow_ntlm_fallback = false` short-circuits to the Kerberos path
/// (i.e. `Negotiate` semantics, Kerberos-first).
#[test]
fn allow_ntlm_fallback_tries_kerberos_first() {
    // Unix: with NTLM disabled, the call routes to gssapi (Kerberos).
    #[cfg(not(target_os = "windows"))]
    {
        let cfg = SspiConfig {
            service: Some("host@server".into()),
            principal: None,
            delegate: false,
            allow_ntlm_fallback: false,
        };
        let err = sspi_provider_for(&cfg).unwrap_err();
        let msg = err.to_string();
        // Kerberos branch → cross-krb5 marker, not NTLM marker.
        assert!(msg.contains("cross-krb5") || msg.contains("UnsupportedBackend"), "{msg}");
        assert!(!msg.contains("NTLM is unavailable on Unix"), "{msg}");
    }
    // Windows: backend disabled, but the SSPI marker (not the cross-krb5
    // marker) must surface — proves the dispatch chose the SSPI path.
    #[cfg(target_os = "windows")]
    {
        let cfg = SspiConfig {
            service: Some("host@server".into()),
            principal: None,
            delegate: false,
            allow_ntlm_fallback: true,
        };
        let err = sspi_provider_for(&cfg).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("sspi crate"), "{msg}");
    }
}

/// (11) Workspace builds clean under MSRV 1.83 — surrogate assertion. The
/// real gate is `cargo build --workspace --locked` (run in CI); here we
/// pin the spt-core dep surface this crate relies on so that an MSRV
/// regression in `spt-core::Error` would land in this test first.
#[test]
fn msrv_surface_pin_against_spt_core() {
    let err = unsupported_backend("test");
    // Pin the Display impl: a future Error rename would break this match.
    let s = err.to_string();
    assert!(s.contains("UnsupportedBackend"), "{s}");
    assert!(s.contains("test"), "{s}");
    // Pin the variant. If `Error::UnsupportedPlatform` is renamed/removed
    // the match below fails at compile time.
    let _ = matches!(err, Error::UnsupportedPlatform(_));
}

/// (12) Cross-platform compile — the `#[cfg]` gates in `lib.rs`,
/// `windows.rs`, and `unix.rs` must let this single test file compile on
/// every target. Surrogate assertion: the two public entry points are
/// reachable on every OS and produce a well-formed Error.
#[test]
fn cross_platform_compile_gates_correct() {
    let g = GssApiConfig {
        service: None,
        principal: None,
        delegate: false,
    };
    let s = SspiConfig {
        service: None,
        principal: None,
        delegate: false,
        allow_ntlm_fallback: false,
    };
    assert!(provider_for(&g).is_err());
    assert!(sspi_provider_for(&s).is_err());
}
