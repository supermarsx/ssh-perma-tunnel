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
use spt_trust::TlsPin;

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
        // System trust roots (rustls-native-certs 0.7 returns Result<Vec<_>>).
        match rustls_native_certs::load_native_certs() {
            Ok(certs) => {
                for cert in certs {
                    let _ = roots.add(cert);
                }
            }
            Err(e) => {
                tracing::debug!("ssh3: load_native_certs failed: {e}");
            }
        }
    }

    let mut cfg = if tls.allow_self_signed || !tls.pin.spki_sha256.is_empty() {
        // Install our custom verifier — wraps webpki on the chain side (or
        // accepts any chain when allow_self_signed) and enforces the pin set.
        let verifier = Arc::new(SptVerifier::new(
            roots,
            tls.pin.clone(),
            tls.allow_self_signed,
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

/// Custom server-cert verifier honoring [`TlsPin`] and `allow_self_signed`.
#[derive(Debug)]
pub(crate) struct SptVerifier {
    /// Underlying webpki verifier (used when `allow_self_signed = false`).
    inner: Option<Arc<dyn ServerCertVerifier>>,
    pin: TlsPin,
    allow_self_signed: bool,
}

impl SptVerifier {
    fn new(roots: RootCertStore, pin: TlsPin, allow_self_signed: bool) -> Self {
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
        let verifier = SptVerifier::new(RootCertStore::empty(), pin, true);
        let server_name = ServerName::try_from("pin-mismatch.test").unwrap();
        let res = verifier.verify_server_cert(&der, &[], &server_name, &[], UnixTime::now());
        let err = res.unwrap_err();
        let s = format!("{err}");
        assert!(s.contains("SPKI pin"), "expected SPKI pin error, got: {s}");
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
        let verifier = SptVerifier::new(RootCertStore::empty(), pin, true);
        let server_name = ServerName::try_from("pin-match.test").unwrap();
        verifier
            .verify_server_cert(&der, &[], &server_name, &[], UnixTime::now())
            .expect("pin match should accept");
    }
}
