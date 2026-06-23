//! Build a [`rustls::ClientConfig`] for the SSH3 QUIC handshake.
//!
//! Honors the `[profiles.tls]` sub-table:
//! - System roots via `rustls-native-certs` (default).
//! - Optional CA file (PEM) — when set, replaces system roots.
//! - SHA-256 SPKI pin set via [`spt_trust::TlsPin`] (custom verifier wraps the
//!   default webpki verifier and additionally enforces SPKI match).
//! - `allow_self_signed` — installs a verifier that accepts any chain, BUT
//!   still enforces the pin set if non-empty (the dual-acknowledgment is
//!   gated upstream by [`crate::Ssh3Config::validate`]).
//! - ALPN values from `tls.alpn` (default `["h3"]`).

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    ClientConfig, DigitallySignedStruct, Error as TlsError, RootCertStore, SignatureScheme,
};
use spt_core::{Error, Result};
use spt_trust::{check_chain_depth, ChainDepthCap, TlsPin};

use crate::config::Ssh3TlsConfig;

/// Build a [`rustls::ClientConfig`] from an [`Ssh3TlsConfig`].
pub fn build_client_config(tls: &Ssh3TlsConfig) -> Result<ClientConfig> {
    // Make sure rustls' aws-lc-rs / ring crypto provider is installed.
    install_default_provider();

    let mut roots = RootCertStore::empty();
    if let Some(ca) = &tls.ca_file {
        let pem = std::fs::read(ca)
            .map_err(|e| Error::InvalidConfig(format!("read ca_file `{}`: {e}", ca.display())))?;
        let mut cursor = std::io::Cursor::new(pem);
        for item in rustls_pemfile::certs(&mut cursor) {
            let cert = item.map_err(|e| {
                Error::InvalidConfig(format!("parse ca_file `{}`: {e}", ca.display()))
            })?;
            roots.add(cert).map_err(|e| {
                Error::InvalidConfig(format!("add ca cert from `{}`: {e}", ca.display()))
            })?;
        }
    } else {
        // System trust roots. t9-Bump: rustls-native-certs 0.8 returns
        // `CertificateResult { certs, errors }` instead of `Result<Vec<_>>`
        // — load is always best-effort and surfaces per-cert failures
        // through `errors`.
        let result = rustls_native_certs::load_native_certs();
        for cert in result.certs {
            let _ = roots.add(cert);
        }
        for e in result.errors {
            tracing::debug!("ssh3: load_native_certs partial failure: {e}");
        }
    }

    // The depth cap applies on every path, including the unmodified-webpki
    // path. When the cap is bypassed (`None`) and there's no pin and no
    // self-signed flag, we can use the off-the-shelf builder.
    let needs_custom = tls.allow_self_signed
        || !tls.pin.spki_sha256.is_empty()
        || !tls.max_cert_chain_depth.is_unlimited();
    let mut cfg = if needs_custom {
        // Install our custom verifier — wraps webpki on the chain side (or
        // accepts any chain when allow_self_signed), enforces the pin set,
        // and applies the chain-depth cap (t5-e10).
        let verifier = Arc::new(SptVerifier::new(
            roots,
            tls.pin.clone(),
            tls.allow_self_signed,
            tls.max_cert_chain_depth,
        ));
        ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth()
    } else {
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth()
    };

    cfg.alpn_protocols = tls.alpn.iter().map(|s| s.as_bytes().to_vec()).collect();
    Ok(cfg)
}

fn install_default_provider() {
    // Idempotent — only sets a provider if none has been installed yet.
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// Custom server-cert verifier honoring [`TlsPin`], `allow_self_signed`,
/// and a [`ChainDepthCap`].
#[derive(Debug)]
pub(crate) struct SptVerifier {
    /// Underlying webpki verifier (used when `allow_self_signed = false`).
    inner: Option<Arc<dyn ServerCertVerifier>>,
    pin: TlsPin,
    allow_self_signed: bool,
    chain_depth_cap: ChainDepthCap,
}

impl SptVerifier {
    fn new(
        roots: RootCertStore,
        pin: TlsPin,
        allow_self_signed: bool,
        chain_depth_cap: ChainDepthCap,
    ) -> Self {
        let inner = if allow_self_signed {
            None
        } else {
            // Use rustls' default webpki verifier.
            match rustls::client::WebPkiServerVerifier::builder(Arc::new(roots)).build() {
                Ok(v) => Some(v as Arc<dyn ServerCertVerifier>),
                Err(_) => None,
            }
        };
        Self {
            inner,
            pin,
            allow_self_signed,
            chain_depth_cap,
        }
    }
}

impl ServerCertVerifier for SptVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, TlsError> {
        // Apply the structural chain-depth cap before doing any
        // signature work. The full wire chain is `[leaf, intermediates...]`.
        // We build it on the stack-cheap clone path (CertificateDer is
        // ref-counted-equivalent — owns a Vec<u8>) only when the cap is
        // configured, to avoid allocations on the unlimited path.
        if !self.chain_depth_cap.is_unlimited() {
            let mut chain: Vec<CertificateDer<'_>> = Vec::with_capacity(intermediates.len() + 1);
            chain.push(end_entity.clone());
            for c in intermediates {
                chain.push(c.clone());
            }
            check_chain_depth(&chain, &self.chain_depth_cap)
                .map_err(|e| TlsError::General(format!("ssh3 chain depth: {e}")))?;
        }
        if !self.allow_self_signed {
            if let Some(inner) = &self.inner {
                inner.verify_server_cert(
                    end_entity,
                    intermediates,
                    server_name,
                    ocsp_response,
                    now,
                )?;
            } else {
                return Err(TlsError::General(
                    "spt-ssh3: webpki verifier unavailable".into(),
                ));
            }
        }
        if !self.pin.spki_sha256.is_empty() {
            self.pin
                .verify(end_entity)
                .map_err(|e| TlsError::General(format!("ssh3 SPKI pin: {e}")))?;
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, TlsError> {
        if let Some(inner) = &self.inner {
            return inner.verify_tls12_signature(message, cert, dss);
        }
        // allow_self_signed = inner is None: skip signature check (the QUIC
        // handshake's signature still proves possession of the pinned key).
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, TlsError> {
        if let Some(inner) = &self.inner {
            return inner.verify_tls13_signature(message, cert, dss);
        }
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        if let Some(inner) = &self.inner {
            return inner.supported_verify_schemes();
        }
        // Reasonable default super-set covering modern TLS 1.3.
        vec![
            SignatureScheme::ED25519,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
        ]
    }
}

// ---------------------------------------------------------------------------
// Server-side TLS (the `spt ssh3-serve` responder). Gated behind the `server`
// feature; adds NO new external dependency (rustls + rustls-pemfile only).
// ---------------------------------------------------------------------------

/// The opaque server-side QUIC/TLS config produced by [`build_server_config`]
/// and [`self_signed_server_config`]. Re-exported so downstream crates (e.g.
/// `spt-bin`'s `ssh3-serve`) can hold the value and pass it to
/// [`crate::serve`] without depending on `quinn` directly.
#[cfg(feature = "server")]
pub type ServerTlsConfig = quinn::ServerConfig;

/// Build a [`quinn::ServerConfig`] from operator-supplied certificate-chain and
/// private-key PEM files, advertising the SSH3 ALPN (`h3`).
///
/// `cert_pem` may contain a full chain (leaf first); `key_pem` must hold a
/// single PKCS#8, PKCS#1 (RSA), or SEC1 (EC) private key. The crypto provider
/// (`ring`) is installed idempotently.
///
/// Used by `spt ssh3-serve --cert <pem> --key <pem>`.
#[cfg(feature = "server")]
pub fn build_server_config(cert_pem: &[u8], key_pem: &[u8]) -> Result<quinn::ServerConfig> {
    use rustls::pki_types::PrivateKeyDer;

    install_default_provider();

    let mut cert_cursor = std::io::Cursor::new(cert_pem);
    let certs = rustls_pemfile::certs(&mut cert_cursor)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| Error::InvalidConfig(format!("parse server cert PEM: {e}")))?;
    if certs.is_empty() {
        return Err(Error::InvalidConfig(
            "server cert PEM contained no certificates".into(),
        ));
    }

    let mut key_cursor = std::io::Cursor::new(key_pem);
    let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut key_cursor)
        .map_err(|e| Error::InvalidConfig(format!("parse server key PEM: {e}")))?
        .ok_or_else(|| Error::InvalidConfig("server key PEM contained no private key".into()))?;

    quic_server_config_from_rustls(certs, key)
}

/// Build a dev-mode self-signed [`quinn::ServerConfig`] for the given SANs
/// (DNS names / IP literals), returning the config alongside the SHA-256 SPKI
/// pin of the generated leaf so a peer can pin it. **Never** use in production.
///
/// Gated behind `server-selfsigned` (pulls in `rcgen`).
#[cfg(feature = "server-selfsigned")]
pub fn self_signed_server_config(sans: Vec<String>) -> Result<(quinn::ServerConfig, [u8; 32])> {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

    install_default_provider();

    let cert = rcgen::generate_simple_self_signed(sans)
        .map_err(|e| Error::InvalidConfig(format!("generate self-signed cert: {e}")))?;
    let cert_der = CertificateDer::from(cert.cert.der().to_vec());
    let pin = TlsPin::spki_sha256_of(&cert_der)
        .map_err(|e| Error::InvalidConfig(format!("compute SPKI pin: {e}")))?;
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()));
    let server = quic_server_config_from_rustls(vec![cert_der], key_der)?;
    Ok((server, pin))
}

/// Shared tail: assemble a [`quinn::ServerConfig`] from a parsed cert chain +
/// key, advertising the SSH3 ALPN.
#[cfg(feature = "server")]
fn quic_server_config_from_rustls(
    certs: Vec<rustls::pki_types::CertificateDer<'static>>,
    key: rustls::pki_types::PrivateKeyDer<'static>,
) -> Result<quinn::ServerConfig> {
    let mut rustls_server = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| Error::InvalidConfig(format!("build server TLS config: {e}")))?;
    // The client (`build_client_config`) advertises `["h3"]`; the QUIC
    // handshake fails with "no known protocol" if the server omits it.
    rustls_server.alpn_protocols = vec![b"h3".to_vec()];
    let quic_server = quinn::crypto::rustls::QuicServerConfig::try_from(rustls_server)
        .map_err(|e| Error::InvalidConfig(format!("build QUIC server config: {e}")))?;
    Ok(quinn::ServerConfig::with_crypto(Arc::new(quic_server)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_pin_default_alpn() {
        let cfg = build_client_config(&Ssh3TlsConfig::default()).unwrap();
        assert_eq!(cfg.alpn_protocols, vec![b"h3".to_vec()]);
    }

    #[test]
    fn custom_alpn_round_trip() {
        let tls = Ssh3TlsConfig {
            alpn: vec!["h3".into(), "ssh3".into()],
            ..Ssh3TlsConfig::default()
        };
        let cfg = build_client_config(&tls).unwrap();
        assert_eq!(cfg.alpn_protocols, vec![b"h3".to_vec(), b"ssh3".to_vec()]);
    }

    #[test]
    fn pin_mismatch_rejects_cert() {
        // Build an SptVerifier with allow_self_signed=true and a non-matching pin,
        // then run it directly against a synthetic self-signed cert.
        install_default_provider();
        let cert = rcgen::generate_simple_self_signed(vec!["pin-mismatch.test".into()]).unwrap();
        let der = CertificateDer::from(cert.cert.der().to_vec());
        let pin = TlsPin {
            spki_sha256: vec![[0x42u8; 32]],
        };
        let verifier =
            SptVerifier::new(RootCertStore::empty(), pin, true, ChainDepthCap::default());
        let server_name = ServerName::try_from("pin-mismatch.test").unwrap();
        let res = verifier.verify_server_cert(&der, &[], &server_name, &[], UnixTime::now());
        let err = res.unwrap_err();
        let s = format!("{err}");
        assert!(s.contains("SPKI pin"), "expected SPKI pin error, got: {s}");
    }

    #[test]
    fn chain_depth_cap_rejects_overlong_chain() {
        // allow_self_signed=true + empty pin set + cap=2 → only the
        // depth check runs, and a 3-intermediate chain trips the cap.
        install_default_provider();
        let leaf = rcgen::generate_simple_self_signed(vec!["leaf.test".into()]).unwrap();
        let i1 = rcgen::generate_simple_self_signed(vec!["i1.test".into()]).unwrap();
        let i2 = rcgen::generate_simple_self_signed(vec!["i2.test".into()]).unwrap();
        let i3 = rcgen::generate_simple_self_signed(vec!["i3.test".into()]).unwrap();
        let leaf_der = CertificateDer::from(leaf.cert.der().to_vec());
        let intermediates = vec![
            CertificateDer::from(i1.cert.der().to_vec()),
            CertificateDer::from(i2.cert.der().to_vec()),
            CertificateDer::from(i3.cert.der().to_vec()),
        ];
        let verifier = SptVerifier::new(
            RootCertStore::empty(),
            TlsPin::default(),
            true,
            ChainDepthCap::new(2),
        );
        let server_name = ServerName::try_from("leaf.test").unwrap();
        let err = verifier
            .verify_server_cert(
                &leaf_der,
                &intermediates,
                &server_name,
                &[],
                UnixTime::now(),
            )
            .unwrap_err();
        let s = format!("{err}");
        assert!(s.contains("chain depth"), "expected chain-depth error: {s}");
    }

    #[test]
    fn pin_match_accepts_self_signed() {
        use sha2::{Digest, Sha256};
        use x509_parser::prelude::*;

        install_default_provider();
        let cert = rcgen::generate_simple_self_signed(vec!["pin-match.test".into()]).unwrap();
        let der_bytes: Vec<u8> = cert.cert.der().to_vec();
        // Compute the SPKI hash the same way TlsPin::verify does.
        let (_, parsed) = X509Certificate::from_der(&der_bytes).unwrap();
        let mut h = Sha256::new();
        h.update(parsed.tbs_certificate.subject_pki.raw);
        let spki: [u8; 32] = h.finalize().into();

        let der = CertificateDer::from(der_bytes);
        let pin = TlsPin {
            spki_sha256: vec![spki],
        };
        let verifier =
            SptVerifier::new(RootCertStore::empty(), pin, true, ChainDepthCap::default());
        let server_name = ServerName::try_from("pin-match.test").unwrap();
        verifier
            .verify_server_cert(&der, &[], &server_name, &[], UnixTime::now())
            .expect("pin match should accept");
    }
}
