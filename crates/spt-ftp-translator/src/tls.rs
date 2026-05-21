//! AUTH TLS server-config builder.
//!
//! Mirrors `crates/spt-status-api/src/tls.rs` in shape but is much smaller:
//! the translator only ever offers server-only TLS (client certs are out
//! of scope; FTP user identity is established via USER/PASS over the
//! already-encrypted CC).

use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::ServerConfig;

use crate::config::TlsConfig;
use crate::error::TranslatorError;

/// Build a rustls [`ServerConfig`] from the operator's PEM files.
pub fn build_server_config(tls: &TlsConfig) -> Result<Arc<ServerConfig>, TranslatorError> {
    let certs = load_certs(tls.cert_file.to_string_lossy().as_ref())?;
    let key = load_key(tls.key_file.to_string_lossy().as_ref())?;
    let cfg = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| TranslatorError::Tls(format!("rustls config: {e}")))?;
    Ok(Arc::new(cfg))
}

fn load_certs(path: &str) -> Result<Vec<CertificateDer<'static>>, TranslatorError> {
    let file = File::open(path).map_err(|e| {
        TranslatorError::Tls(format!("read cert file `{path}`: {e}"))
    })?;
    let mut reader = BufReader::new(file);
    let mut out = Vec::new();
    for cert in rustls_pemfile::certs(&mut reader) {
        let cert = cert.map_err(|e| TranslatorError::Tls(format!("parse cert: {e}")))?;
        out.push(cert);
    }
    if out.is_empty() {
        return Err(TranslatorError::Tls(format!(
            "no certificates in `{path}`"
        )));
    }
    Ok(out)
}

fn load_key(path: &str) -> Result<PrivateKeyDer<'static>, TranslatorError> {
    let file = File::open(path).map_err(|e| {
        TranslatorError::Tls(format!("read key file `{path}`: {e}"))
    })?;
    let mut reader = BufReader::new(file);
    // Try PKCS#8 first, then RSA, then SEC1.
    if let Some(k) = rustls_pemfile::pkcs8_private_keys(&mut reader).next() {
        let k = k.map_err(|e| TranslatorError::Tls(format!("parse pkcs8 key: {e}")))?;
        return Ok(PrivateKeyDer::Pkcs8(k));
    }
    // Re-open: pemfile iterators are single-pass.
    let file = File::open(path).map_err(|e| {
        TranslatorError::Tls(format!("re-read key file `{path}`: {e}"))
    })?;
    let mut reader = BufReader::new(file);
    if let Some(k) = rustls_pemfile::rsa_private_keys(&mut reader).next() {
        let k = k.map_err(|e| TranslatorError::Tls(format!("parse rsa key: {e}")))?;
        return Ok(PrivateKeyDer::Pkcs1(k));
    }
    let file = File::open(path).map_err(|e| {
        TranslatorError::Tls(format!("re-read key file `{path}`: {e}"))
    })?;
    let mut reader = BufReader::new(file);
    if let Some(k) = rustls_pemfile::ec_private_keys(&mut reader).next() {
        let k = k.map_err(|e| TranslatorError::Tls(format!("parse ec key: {e}")))?;
        return Ok(PrivateKeyDer::Sec1(k));
    }
    Err(TranslatorError::Tls(format!(
        "no PKCS#8 / RSA / SEC1 key found in `{path}`"
    )))
}
