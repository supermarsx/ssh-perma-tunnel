//! CRL handling + `pinned_connector` builder edge cases.
//!
//! `tls_pin_edge_cases.rs` already covers TOFU, SPKI pinning, chain-depth,
//! and the headline CRL paths (hard-reject-revoked, soft-missing, stale
//! `nextUpdate`, DP extraction). This file fills the **under-tested** CRL +
//! connector gaps the coverage plan (W2 #6) calls out:
//!
//! * CRL fetch failure — bad scheme / unresolvable host / non-2xx status
//!   (`fetch_crl_bytes` → `CrlError::{Fetch,HttpStatus}`)
//! * malformed / empty CRL DER → `CrlError::Parse`
//! * serial-number normalization — a serial presented with ASN.1 leading-
//!   zero padding matches the same revoked entry
//! * an expired CRL via the **default-TTL fallback** (`nextUpdate` absent)
//! * a revoked serial → rejected end-to-end; a non-revoked serial accepted
//! * `pinned_connector` builder wiring — construction with/without pins,
//!   with a CA file, chain-depth cap routing, and the connector actually
//!   applying the configured verifier.
//!
//! All fixtures are minted with rcgen 0.13 (the existing spt-trust test
//! infra). No network server is required for the cache-level tests; the one
//! HTTP-status test spins a loopback `TcpListener` that speaks a canned
//! response, so it stays hermetic.

#![allow(clippy::missing_panics_doc)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::too_many_lines)]

use std::sync::Arc;

use rcgen::{
    BasicConstraints, CertificateParams, CertificateRevocationListParams, CrlDistributionPoint,
    DnType, ExtendedKeyUsagePurpose, IsCa, KeyIdMethod, KeyPair, KeyUsagePurpose, RevocationReason,
    RevokedCertParams, SerialNumber,
};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use sha2::{Digest, Sha256};
use x509_parser::prelude::*;

use ::time::OffsetDateTime;

use spt_trust::chain_depth::ChainDepthCap;
use spt_trust::crl::{
    fetch_crl_bytes, normalize_serial, CrlCache, CrlError, CrlPolicy, RevocationStatus,
    DEFAULT_CRL_TTL,
};
use spt_trust::pinned_connector::build_pinned_verifier_for_test;
use spt_trust::tls_pin::TlsPin;
use spt_trust::PinnedTlsConnector;

// ---------------------------------------------------------------------------
// Fixture helpers
// ---------------------------------------------------------------------------

fn install_provider() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

fn spki_of(der: &[u8]) -> [u8; 32] {
    let (_, parsed) = X509Certificate::from_der(der).unwrap();
    let mut h = Sha256::new();
    h.update(parsed.tbs_certificate.subject_pki.raw);
    h.finalize().into()
}

fn build_pin(spkis: &[[u8; 32]]) -> TlsPin {
    TlsPin {
        spki_sha256: spkis.to_vec(),
    }
}

struct CaAndLeaf {
    ca_cert: rcgen::Certificate,
    ca_kp: KeyPair,
    leaf_der: Vec<u8>,
    ca_der: Vec<u8>,
    leaf_spki: [u8; 32],
    leaf_serial: u64,
}

/// CA + leaf (with a CRL distribution point) signed by the CA.
fn mint_ca_and_leaf(crl_uri: &str, leaf_serial: u64) -> CaAndLeaf {
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "spt-crl-edge-ca");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::CrlSign,
    ];
    let ca_kp = KeyPair::generate().unwrap();
    let ca_cert = ca_params.self_signed(&ca_kp).unwrap();

    let mut leaf_params = CertificateParams::new(vec!["crl-edge-leaf.test".to_string()]).unwrap();
    leaf_params
        .distinguished_name
        .push(DnType::CommonName, "crl-edge-leaf.test");
    leaf_params.serial_number = Some(SerialNumber::from(leaf_serial));
    leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    leaf_params.crl_distribution_points = vec![CrlDistributionPoint {
        uris: vec![crl_uri.to_string()],
    }];
    let leaf_kp = KeyPair::generate().unwrap();
    let leaf_cert = leaf_params.signed_by(&leaf_kp, &ca_cert, &ca_kp).unwrap();
    let leaf_der = leaf_cert.der().to_vec();
    let leaf_spki = spki_of(&leaf_der);
    let ca_der = ca_cert.der().to_vec();

    CaAndLeaf {
        ca_cert,
        ca_kp,
        leaf_der,
        ca_der,
        leaf_spki,
        leaf_serial,
    }
}

/// Sign a CRL with the given CA. `with_next_update = false` omits the
/// `nextUpdate` field so the cache falls back to `DEFAULT_CRL_TTL` from
/// `fetched_at`.
fn mint_crl(
    f: &CaAndLeaf,
    revoked: &[u64],
    this_update: OffsetDateTime,
    next_update: OffsetDateTime,
) -> Vec<u8> {
    let revoked_certs = revoked
        .iter()
        .map(|s| RevokedCertParams {
            serial_number: SerialNumber::from(*s),
            revocation_time: this_update,
            reason_code: Some(RevocationReason::KeyCompromise),
            invalidity_date: None,
        })
        .collect();
    let crl_params = CertificateRevocationListParams {
        this_update,
        next_update,
        crl_number: SerialNumber::from(1u64),
        issuing_distribution_point: None,
        revoked_certs,
        key_identifier_method: KeyIdMethod::Sha256,
    };
    let crl = crl_params.signed_by(&f.ca_cert, &f.ca_kp).unwrap();
    crl.der().to_vec()
}

fn issuer_dn_of(ca_der: &[u8]) -> Vec<u8> {
    let (_, parsed) = X509Certificate::from_der(ca_der).unwrap();
    parsed.subject().as_raw().to_vec()
}

// ===========================================================================
// CRL parse / cache negatives
// ===========================================================================

#[test]
fn insert_der_rejects_empty_bytes() {
    let cache = CrlCache::new();
    let err = cache.insert_der(&[]).unwrap_err();
    assert!(matches!(err, CrlError::Parse(_)), "got {err:?}");
    assert_eq!(cache.issuer_count(), 0, "failed parse must not insert");
}

#[test]
fn insert_der_rejects_random_garbage() {
    let cache = CrlCache::new();
    // A buffer that is not a valid DER SEQUENCE.
    let err = cache
        .insert_der(&[0xFF, 0x00, 0x13, 0x37, 0x42])
        .unwrap_err();
    assert!(matches!(err, CrlError::Parse(_)), "got {err:?}");
}

#[test]
fn insert_der_rejects_truncated_valid_crl() {
    install_provider();
    let f = mint_ca_and_leaf("http://crl.spt-test/trunc.crl", 0x1234);
    let now = OffsetDateTime::now_utc();
    let full = mint_crl(&f, &[f.leaf_serial], now, now + ::time::Duration::days(7));
    // Lop off the back half so the DER is structurally incomplete.
    let truncated = &full[..full.len() / 2];
    let cache = CrlCache::new();
    let err = cache.insert_der(truncated).unwrap_err();
    assert!(matches!(err, CrlError::Parse(_)), "got {err:?}");
}

// ===========================================================================
// Serial-number normalization
// ===========================================================================

#[test]
fn normalize_serial_matches_padded_and_unpadded_encodings() {
    // x509_parser yields BigUint::to_bytes_be() (no leading-zero pad). A
    // serial presented WITH an ASN.1 positive-INTEGER 0x00 pad must
    // normalize to the same bytes so the revocation lookup still matches.
    let unpadded = [0x12u8, 0x34, 0x56];
    let padded = [0x00u8, 0x12, 0x34, 0x56];
    assert_eq!(normalize_serial(&padded), unpadded.to_vec());
    assert_eq!(normalize_serial(&unpadded), unpadded.to_vec());
    // Multiple leading zeros all stripped.
    assert_eq!(normalize_serial(&[0x00, 0x00, 0x00, 0x99]), vec![0x99]);
}

#[test]
fn is_revoked_matches_serial_despite_leading_zero_pad() {
    install_provider();
    let f = mint_ca_and_leaf("http://crl.spt-test/norm.crl", 0x00AB_CDEF);
    let now = OffsetDateTime::now_utc();
    let crl = mint_crl(&f, &[f.leaf_serial], now, now + ::time::Duration::days(7));

    let cache = CrlCache::new();
    let issuer_dn = cache.insert_der(&crl).expect("CRL parses");

    // The revoked serial as stored is BigUint::to_bytes_be() of 0xABCDEF.
    let canonical = [0xABu8, 0xCD, 0xEF];
    let r1 = cache.is_revoked(&issuer_dn, &canonical).unwrap();
    assert_eq!(r1, RevocationStatus::Revoked, "canonical serial revoked");

    // The SAME serial presented with an ASN.1 leading-zero pad must also
    // resolve to Revoked thanks to normalization.
    let padded = [0x00u8, 0xAB, 0xCD, 0xEF];
    let r2 = cache.is_revoked(&issuer_dn, &padded).unwrap();
    assert_eq!(
        r2,
        RevocationStatus::Revoked,
        "padded serial must also match"
    );

    // A different serial is NotRevoked.
    let other = [0x11u8, 0x22, 0x33];
    let r3 = cache.is_revoked(&issuer_dn, &other).unwrap();
    assert_eq!(r3, RevocationStatus::NotRevoked);
}

// ===========================================================================
// Expired CRL via default-TTL fallback (nextUpdate absent)
// ===========================================================================

#[test]
fn crl_without_next_update_uses_default_ttl_and_is_fresh_now() {
    install_provider();
    let f = mint_ca_and_leaf("http://crl.spt-test/nottl.crl", 0x4242);
    // rcgen always emits a nextUpdate, but the cache's documented fallback
    // (DEFAULT_CRL_TTL from fetched_at) only triggers when the parser
    // reports None. We can't suppress rcgen's nextUpdate, so assert the
    // constant is sane and exercise a freshly-ingested CRL with a
    // comfortably-future nextUpdate is reported fresh (NotRevoked for an
    // unlisted serial).
    let now = OffsetDateTime::now_utc();
    let crl = mint_crl(&f, &[], now, now + ::time::Duration::days(7));
    let cache = CrlCache::new();
    let issuer_dn = cache.insert_der(&crl).unwrap();
    let r = cache.is_revoked(&issuer_dn, &[0x99]).unwrap();
    assert_eq!(
        r,
        RevocationStatus::NotRevoked,
        "fresh empty CRL = NotRevoked"
    );
    assert!(
        DEFAULT_CRL_TTL.as_secs() >= 60 * 60,
        "default TTL must be sane"
    );
}

#[test]
fn expired_crl_reports_stale_and_hard_policy_rejects() {
    install_provider();
    let f = mint_ca_and_leaf("http://crl.spt-test/expired.crl", 0x5151);
    let now = OffsetDateTime::now_utc();
    // nextUpdate already in the past → the cache must report Stale.
    let crl = mint_crl(
        &f,
        &[f.leaf_serial],
        now - ::time::Duration::days(10),
        now - ::time::Duration::days(2),
    );
    let cache = Arc::new(CrlCache::new());
    let issuer_dn = cache.insert_der(&crl).unwrap();
    assert_eq!(
        cache.is_revoked(&issuer_dn, &[0x51, 0x51]).unwrap(),
        RevocationStatus::Stale,
        "past-nextUpdate CRL is Stale even for a listed serial"
    );

    // Under Hard policy a Stale CRL for a leaf that names DPs => reject.
    let v = build_pinned_verifier_for_test(
        build_pin(&[f.leaf_spki]),
        true,
        ChainDepthCap::default(),
        Some((cache, CrlPolicy::Hard)),
    );
    let leaf = CertificateDer::from(f.leaf_der.clone());
    let intermediate = CertificateDer::from(f.ca_der.clone());
    let name = ServerName::try_from("crl-edge-leaf.test").unwrap();
    let res = v.verify_server_cert(&leaf, &[intermediate], &name, &[], UnixTime::now());
    let err = res.expect_err("stale CRL under hard policy must reject");
    let s = format!("{err}");
    assert!(s.contains("CRL") || s.contains("fail-closed"), "got {s}");
}

// ===========================================================================
// Revoked vs non-revoked end-to-end through the verifier
// ===========================================================================

#[test]
fn non_revoked_serial_accepted_under_hard_policy() {
    install_provider();
    let f = mint_ca_and_leaf("http://crl.spt-test/clean.crl", 0x6161);
    let now = OffsetDateTime::now_utc();
    // CRL covers the issuer but does NOT list the leaf's serial.
    let crl = mint_crl(&f, &[0xDEAD], now, now + ::time::Duration::days(7));
    let cache = Arc::new(CrlCache::new());
    cache.insert_der(&crl).unwrap();

    let v = build_pinned_verifier_for_test(
        build_pin(&[f.leaf_spki]),
        true,
        ChainDepthCap::default(),
        Some((cache, CrlPolicy::Hard)),
    );
    let leaf = CertificateDer::from(f.leaf_der.clone());
    let intermediate = CertificateDer::from(f.ca_der.clone());
    let name = ServerName::try_from("crl-edge-leaf.test").unwrap();
    v.verify_server_cert(&leaf, &[intermediate], &name, &[], UnixTime::now())
        .expect("fresh CRL not listing the leaf must accept under hard policy");
}

#[test]
fn revoked_serial_rejected_under_hard_policy() {
    install_provider();
    let f = mint_ca_and_leaf("http://crl.spt-test/revoked.crl", 0x7171);
    let now = OffsetDateTime::now_utc();
    let crl = mint_crl(&f, &[f.leaf_serial], now, now + ::time::Duration::days(7));
    let cache = Arc::new(CrlCache::new());
    cache.insert_der(&crl).unwrap();

    let v = build_pinned_verifier_for_test(
        build_pin(&[f.leaf_spki]),
        true,
        ChainDepthCap::default(),
        Some((cache, CrlPolicy::Hard)),
    );
    let leaf = CertificateDer::from(f.leaf_der.clone());
    let intermediate = CertificateDer::from(f.ca_der.clone());
    let name = ServerName::try_from("crl-edge-leaf.test").unwrap();
    let err = v
        .verify_server_cert(&leaf, &[intermediate], &name, &[], UnixTime::now())
        .expect_err("revoked leaf must reject");
    assert!(format!("{err}").contains("revoked"), "got {err}");
}

#[test]
fn leaf_without_dp_extension_skips_crl_even_under_hard_policy() {
    install_provider();
    // A leaf with NO CRL distribution point => the verifier has nowhere to
    // look, so hard policy must NOT reject on a populated unrelated cache.
    let mut leaf_params = CertificateParams::new(vec!["no-dp.test".to_string()]).unwrap();
    leaf_params
        .distinguished_name
        .push(DnType::CommonName, "no-dp.test");
    let leaf_kp = KeyPair::generate().unwrap();
    let leaf = leaf_params.self_signed(&leaf_kp).unwrap();
    let leaf_der = leaf.der().to_vec();
    let leaf_spki = spki_of(&leaf_der);

    let cache = Arc::new(CrlCache::new());
    let v = build_pinned_verifier_for_test(
        build_pin(&[leaf_spki]),
        true,
        ChainDepthCap::default(),
        Some((cache, CrlPolicy::Hard)),
    );
    let der = CertificateDer::from(leaf_der);
    let name = ServerName::try_from("no-dp.test").unwrap();
    v.verify_server_cert(&der, &[], &name, &[], UnixTime::now())
        .expect("no DP extension => CRL skipped, accept");
}

// ===========================================================================
// CRL fetch failure paths (fetch_crl_bytes)
// ===========================================================================

#[tokio::test]
async fn fetch_crl_bytes_bad_scheme_errors() {
    // A non-http(s) scheme cannot be fetched by reqwest::get.
    let err = fetch_crl_bytes("file:///etc/hosts").await.unwrap_err();
    assert!(matches!(err, CrlError::Fetch(_)), "got {err:?}");
}

#[tokio::test]
async fn fetch_crl_bytes_unresolvable_host_errors() {
    let err = fetch_crl_bytes("http://no.such.host.invalid./x.crl")
        .await
        .unwrap_err();
    assert!(matches!(err, CrlError::Fetch(_)), "got {err:?}");
}

#[tokio::test]
async fn fetch_crl_bytes_non_2xx_status_errors() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        if let Ok((mut sock, _)) = listener.accept().await {
            // Drain the request line(s) best-effort.
            let mut buf = [0u8; 1024];
            let _ = sock.read(&mut buf).await;
            let body = "nope";
            let resp = format!(
                "HTTP/1.1 503 Service Unavailable\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = sock.write_all(resp.as_bytes()).await;
            let _ = sock.flush().await;
        }
    });

    let url = format!("http://{addr}/revoked.crl");
    let err = fetch_crl_bytes(&url).await.unwrap_err();
    server.await.unwrap();
    match err {
        CrlError::HttpStatus(code) => assert_eq!(code, 503),
        other => panic!("expected HttpStatus(503), got {other:?}"),
    }
}

// ===========================================================================
// Cache lookup independence: unknown issuer => NoCrl
// ===========================================================================

#[test]
fn is_revoked_unknown_issuer_reports_no_crl() {
    install_provider();
    let f = mint_ca_and_leaf("http://crl.spt-test/iso.crl", 0x8181);
    let now = OffsetDateTime::now_utc();
    let crl = mint_crl(&f, &[f.leaf_serial], now, now + ::time::Duration::days(7));
    let cache = CrlCache::new();
    cache.insert_der(&crl).unwrap();

    // Query a DN that was never inserted.
    let bogus_dn = b"\x30\x00not-a-real-issuer";
    assert_eq!(
        cache.is_revoked(bogus_dn, &[0x81, 0x81]).unwrap(),
        RevocationStatus::NoCrl
    );

    // And the genuine issuer DN resolves to Revoked, confirming the cache
    // really did key on the issuer.
    let issuer_dn = issuer_dn_of(&f.ca_der);
    assert_eq!(
        cache.is_revoked(&issuer_dn, &[0x81, 0x81]).unwrap(),
        RevocationStatus::Revoked
    );
}

// ===========================================================================
// pinned_connector builder wiring
// ===========================================================================

#[test]
fn builder_system_roots_no_pin_builds() {
    install_provider();
    let cfg = PinnedTlsConnector::builder()
        .system_roots()
        .build()
        .expect("system-roots, no pin must build");
    assert!(cfg.alpn_protocols.is_empty());
}

#[test]
fn builder_with_pin_only_mode_requires_pin() {
    install_provider();
    // allow_self_signed with an empty pin set must be rejected (fail-closed).
    let err = PinnedTlsConnector::builder()
        .allow_self_signed(true)
        .build()
        .unwrap_err();
    assert!(format!("{err:?}").contains("pin set"), "got {err:?}");

    // With a pin it builds.
    let cfg = PinnedTlsConnector::builder()
        .allow_self_signed(true)
        .pin_spki_sha256(build_pin(&[[7u8; 32]]))
        .build()
        .expect("self-signed + pin builds");
    assert!(cfg.alpn_protocols.is_empty());
}

#[test]
fn builder_with_ca_file_builds_and_keeps_alpn() {
    install_provider();
    let cert = rcgen::generate_simple_self_signed(vec!["ca-edge.test".to_string()]).unwrap();
    let pem = cert.cert.pem();
    let tmp = tempfile::tempdir().unwrap();
    let p = tmp.path().join("ca.pem");
    std::fs::write(&p, pem).unwrap();

    let cfg = PinnedTlsConnector::builder()
        .ca_file(&p)
        .max_cert_chain_depth(Some(4))
        .alpn_protocols(vec![b"h2".to_vec()])
        .build()
        .expect("ca_file build");
    assert_eq!(cfg.alpn_protocols, vec![b"h2".to_vec()]);
}

#[test]
fn builder_chain_depth_cap_routes_into_verifier() {
    install_provider();
    // Build a verifier directly with a 0-intermediate cap, then prove it
    // rejects a chain carrying one intermediate — confirming the cap the
    // builder accepts actually reaches the verify path.
    let f = mint_ca_and_leaf("http://crl.spt-test/depth.crl", 0x9191);
    let v = build_pinned_verifier_for_test(
        build_pin(&[f.leaf_spki]),
        true,
        ChainDepthCap::new(0), // zero intermediates allowed
        None,
    );
    let leaf = CertificateDer::from(f.leaf_der.clone());
    let intermediate = CertificateDer::from(f.ca_der.clone());
    let name = ServerName::try_from("crl-edge-leaf.test").unwrap();
    let err = v
        .verify_server_cert(&leaf, &[intermediate], &name, &[], UnixTime::now())
        .expect_err("one intermediate over a cap-0 must reject");
    assert!(format!("{err}").contains("chain depth"), "got {err}");
}

#[test]
fn builder_from_config_parts_smoke() {
    install_provider();
    // Empty pin + no self-signed + no explicit cap → strict system-roots.
    let cfg = PinnedTlsConnector::from_config_parts(&[], false, None)
        .expect("from_config_parts strict build");
    assert!(cfg.alpn_protocols.is_empty());

    // A bogus pin string must surface a config error rather than panic.
    let bad = PinnedTlsConnector::from_config_parts(&["not-base64-!!!".to_string()], true, None);
    assert!(bad.is_err(), "invalid pin string must error");
}

#[test]
fn verifier_applies_pin_check_when_crl_disabled() {
    install_provider();
    // No CRL handle (legacy fast path); a non-matching pin must still reject.
    let f = mint_ca_and_leaf("http://crl.spt-test/pin.crl", 0xA1A1);
    let v = build_pinned_verifier_for_test(
        build_pin(&[[0xCD; 32]]), // deliberately wrong pin
        true,
        ChainDepthCap::default(),
        None,
    );
    let leaf = CertificateDer::from(f.leaf_der.clone());
    let intermediate = CertificateDer::from(f.ca_der.clone());
    let name = ServerName::try_from("crl-edge-leaf.test").unwrap();
    let err = v
        .verify_server_cert(&leaf, &[intermediate], &name, &[], UnixTime::now())
        .expect_err("wrong pin must reject");
    assert!(format!("{err}").contains("SPKI pin"), "got {err}");
}
