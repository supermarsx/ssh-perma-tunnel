//! Rustls server configuration builder for `spt-status-api`.
//!
//! Two flavours, selected by [`spt_config::StatusApiAuthMode`]:
//!
//! * Server-only TLS — built from `cert_file` + `key_file`. The client
//!   authentication slot uses [`rustls::server::WebPkiClientVerifier::no_client_auth`].
//! * Mutual TLS — same plus a [`rustls::server::WebPkiClientVerifier`] over
//!   the operator-supplied CA bundle. Subject-allow-list matching happens
//!   in [`crate::auth`] after the handshake succeeds.
//!
//! ## Deviation note (vs. plan §t4-e5)
//!
//! The plan named `axum-server` for hosting TLS. `axum-server` is not in
//! the workspace lockfile and adding it would force `cargo update` (banned
//! per the quality bar). We therefore build the rustls `ServerConfig` here
//! and leave the per-listener wiring to the supervisor / integration
//! layer: the supervisor wraps the standard `tokio::net::TcpListener` in a
//! `tokio_rustls::TlsAcceptor`, threads the verified peer subject into a
//! request extension, and feeds the stream into `axum::serve` via
//! `hyper_util::server::conn::auto`. The rustls config produced here is
//! the input to that pipeline. See the crate-level docs for the
//! supervisor-integration shape.

use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ServerConfig, WebPkiClientVerifier};
use rustls::RootCertStore;
use spt_config::{StatusApiAuthMode, StatusApiTlsConfig};
use thiserror::Error;

/// TLS-config errors.
#[derive(Debug, Error)]
pub enum TlsConfigError {
    /// Could not read cert or key file from disk.
    #[error("read {path}: {source}")]
    Read {
        /// File that failed to load.
        path: String,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// PEM parsing returned no certificates.
    #[error("no certificates found in {0}")]
    NoCerts(String),

    /// PEM parsing returned no private keys.
    #[error("no private key found in {0}")]
    NoKey(String),

    /// `rustls` rejected the config (key/cert mismatch, malformed chain, ...).
    #[error("rustls config error: {0}")]
    Rustls(String),

    /// CA bundle was empty.
    #[error("CA bundle {0} contained no usable certificates")]
    EmptyCaBundle(String),

    /// CA bundle was malformed.
    #[error("CA bundle {0}: {1}")]
    BadCaBundle(String, String),
}

/// Build a rustls [`ServerConfig`] from the operator config + auth mode.
///
/// For mTLS, the returned config requires a client certificate validated
/// against the configured CA bundle. The subject-DN-allow-list check is
/// performed in the auth middleware ([`crate::auth`]) after the handshake.
pub fn build_server_config(
    tls: &StatusApiTlsConfig,
    auth: &StatusApiAuthMode,
) -> Result<ServerConfig, TlsConfigError> {
    let certs = load_certs(&tls.cert_file)?;
    let key = load_key(&tls.key_file)?;

    let builder = ServerConfig::builder();

    let cfg = match auth {
        StatusApiAuthMode::MutualTls { ca_bundle, .. } => {
            let roots = load_ca_bundle(ca_bundle)?;
            let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
                .build()
                .map_err(|e| TlsConfigError::Rustls(e.to_string()))?;
            builder
                .with_client_cert_verifier(verifier)
                .with_single_cert(certs, key)
                .map_err(|e| TlsConfigError::Rustls(e.to_string()))?
        }
        _ => builder
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| TlsConfigError::Rustls(e.to_string()))?,
    };

    Ok(cfg)
}

fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>, TlsConfigError> {
    let path_str = path.display().to_string();
    let file = File::open(path).map_err(|source| TlsConfigError::Read {
        path: path_str.clone(),
        source,
    })?;
    let mut reader = BufReader::new(file);
    let certs: Vec<_> = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| TlsConfigError::Rustls(format!("PEM cert parse: {e}")))?;
    if certs.is_empty() {
        return Err(TlsConfigError::NoCerts(path_str));
    }
    Ok(certs)
}

fn load_key(path: &Path) -> Result<PrivateKeyDer<'static>, TlsConfigError> {
    let path_str = path.display().to_string();
    let file = File::open(path).map_err(|source| TlsConfigError::Read {
        path: path_str.clone(),
        source,
    })?;
    let mut reader = BufReader::new(file);
    let key = rustls_pemfile::private_key(&mut reader)
        .map_err(|e| TlsConfigError::Rustls(format!("PEM key parse: {e}")))?
        .ok_or(TlsConfigError::NoKey(path_str))?;
    Ok(key)
}

fn load_ca_bundle(path: &Path) -> Result<RootCertStore, TlsConfigError> {
    let path_str = path.display().to_string();
    let file = File::open(path).map_err(|source| TlsConfigError::Read {
        path: path_str.clone(),
        source,
    })?;
    let mut reader = BufReader::new(file);
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| TlsConfigError::BadCaBundle(path_str.clone(), e.to_string()))?;
    if certs.is_empty() {
        return Err(TlsConfigError::EmptyCaBundle(path_str));
    }
    let mut roots = RootCertStore::empty();
    for c in certs {
        roots
            .add(c)
            .map_err(|e| TlsConfigError::BadCaBundle(path_str.clone(), e.to_string()))?;
    }
    Ok(roots)
}

#[cfg(test)]
mod tests {
    use super::*;
    use spt_config::StatusApiAuthMode;
    use std::path::PathBuf;

    fn write_self_signed(tmp: &tempfile::TempDir) -> (PathBuf, PathBuf) {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_path = tmp.path().join("cert.pem");
        let key_path = tmp.path().join("key.pem");
        std::fs::write(&cert_path, cert.cert.pem()).unwrap();
        std::fs::write(&key_path, cert.key_pair.serialize_pem()).unwrap();
        (cert_path, key_path)
    }

    #[test]
    fn builds_server_only_config() {
        // Install ring crypto provider for rustls (idempotent).
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let tmp = tempfile::tempdir().unwrap();
        let (cert, key) = write_self_signed(&tmp);
        let tls = StatusApiTlsConfig {
            enabled: true,
            cert_file: cert,
            key_file: key,
        };
        let cfg = build_server_config(&tls, &StatusApiAuthMode::None).unwrap();
        // Just check ALPN list is empty (default) — we got a valid config.
        assert!(cfg.alpn_protocols.is_empty());
    }

    #[test]
    fn rejects_missing_cert_file() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let tls = StatusApiTlsConfig {
            enabled: true,
            cert_file: PathBuf::from("/no/such/cert.pem"),
            key_file: PathBuf::from("/no/such/key.pem"),
        };
        let err = build_server_config(&tls, &StatusApiAuthMode::None).unwrap_err();
        assert!(matches!(err, TlsConfigError::Read { .. }));
    }

    #[test]
    fn mtls_requires_ca_bundle() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let tmp = tempfile::tempdir().unwrap();
        let (cert, key) = write_self_signed(&tmp);
        let ca_path = tmp.path().join("ca.pem");
        // Reuse the same self-signed cert as a CA for the test.
        std::fs::copy(&cert, &ca_path).unwrap();
        let tls = StatusApiTlsConfig {
            enabled: true,
            cert_file: cert,
            key_file: key,
        };
        let auth = StatusApiAuthMode::MutualTls {
            ca_bundle: ca_path,
            allowed_subjects: vec!["CN=localhost".into()],
        };
        let cfg = build_server_config(&tls, &auth).unwrap();
        assert!(cfg.alpn_protocols.is_empty());
    }
}
