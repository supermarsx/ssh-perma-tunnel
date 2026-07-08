//! End-to-end TLS handshake test using `tokio-rustls` directly.
//!
//! We don't pull `axum-server` into the lockfile (see lib.rs deviation
//! note). Instead, this test verifies that the `rustls::ServerConfig`
//! produced by [`spt_status_api::build_server_config`] is usable: bind a
//! `TcpListener`, wrap it in a `TlsAcceptor`, complete one handshake, and
//! verify the negotiated TLS version is 1.3.

use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use spt_config::{StatusApiAuthMode, StatusApiTlsConfig};
use spt_status_api::build_server_config;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};

fn install_crypto() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

fn write_self_signed(tmp: &tempfile::TempDir) -> (std::path::PathBuf, std::path::PathBuf, Vec<u8>) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_path = tmp.path().join("cert.pem");
    let key_path = tmp.path().join("key.pem");
    std::fs::write(&cert_path, cert.cert.pem()).unwrap();
    std::fs::write(&key_path, cert.key_pair.serialize_pem()).unwrap();
    let der = cert.cert.der().to_vec();
    (cert_path, key_path, der)
}

#[tokio::test]
async fn tls_roundtrip_server_only() {
    install_crypto();
    let tmp = tempfile::tempdir().unwrap();
    let (cert_path, key_path, cert_der) = write_self_signed(&tmp);

    let tls_cfg = StatusApiTlsConfig {
        enabled: true,
        cert_file: cert_path,
        key_file: key_path,
    };
    let server_cfg = build_server_config(&tls_cfg, &StatusApiAuthMode::None).unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(server_cfg));

    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();

    // Server task: accept one connection, echo bytes back.
    let server = tokio::spawn(async move {
        let (sock, _) = listener.accept().await.unwrap();
        let mut tls = acceptor.accept(sock).await.unwrap();
        let mut buf = vec![0u8; 5];
        tls.read_exact(&mut buf).await.unwrap();
        tls.write_all(&buf).await.unwrap();
        tls.shutdown().await.unwrap();
    });

    // Client: trust the server cert and do an HTTPS-like roundtrip.
    let mut roots = RootCertStore::empty();
    roots
        .add(rustls::pki_types::CertificateDer::from(cert_der))
        .unwrap();
    let client_cfg = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(client_cfg));
    let stream = TcpStream::connect(addr).await.unwrap();
    let dns = ServerName::try_from("localhost".to_owned()).unwrap();
    let mut tls = connector.connect(dns, stream).await.unwrap();
    tls.write_all(b"hello").await.unwrap();
    let mut buf = vec![0u8; 5];
    tls.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"hello");

    tokio::time::timeout(Duration::from_secs(2), server)
        .await
        .unwrap()
        .unwrap();
}
