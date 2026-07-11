//! Build a [`rustls::ClientConfig`] for the SSH3 QUIC handshake.
//!
//! Honors the `[profiles.tls]` sub-table. Trust anchors are resolved by
//! [`load_trust_roots`] honoring `system_roots` and `ca_file` INDEPENDENTLY:
//! - `ca_file` (PEM) set → the roots are exactly those certs.
//! - else `system_roots = true` (default) → the OS trust store via
//!   `rustls-native-certs`.
//! - else (`system_roots = false`, no `ca_file`) → an EMPTY root store: the OS
//!   store is never loaded as a silent fall-back, so the only remaining anchor
//!   is the SPKI pin set.
//!
//! Verification policy ([`SptVerifier`]):
//! - `ca_file` ALWAYS enforces that the server chain validates against that CA
//!   — even when `allow_self_signed = true`. A self-signed leaf that does not
//!   chain to the `ca_file` CA is REJECTED.
//! - `allow_self_signed` with NO `ca_file` skips the webpki chain check; trust
//!   then rests on the SPKI pin set (fail-closed) when present.
//! - `allow_self_signed` with NEITHER a pin NOR a `ca_file` is genuine
//!   blind-accept: verification is DISABLED and [`build_client_config`] emits a
//!   loud `tracing::warn!` at connect (never silent).
//! - SHA-256 SPKI pin set via [`spt_trust::TlsPin`] stays fail-closed.
//! - ALPN values from `tls.alpn` (default `["h3"]`).

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{self, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    ClientConfig, DigitallySignedStruct, Error as TlsError, RootCertStore, SignatureScheme,
};
use spt_core::{Error, Result};
use spt_trust::{check_chain_depth, ChainDepthCap, TlsPin};

use crate::config::Ssh3TlsConfig;

/// Build a [`rustls::ClientConfig`] from an [`Ssh3TlsConfig`].
pub fn build_client_config(tls: &Ssh3TlsConfig) -> Result<ClientConfig> {
    // Install aws-lc-rs as the PROCESS-GLOBAL rustls provider (the single
    // workspace-wide rustls provider — status-api / syslog / reqwest all use
    // it). The ssh3 QUIC config built below carries its OWN per-config provider
    // (see `ssh3_crypto_provider`), so the PQ-vs-classical kx choice never
    // disturbs the global default. Idempotent — only installs if nothing is
    // set yet.
    install_default_provider();

    // Resolve trust anchors, honoring `ca_file` and `system_roots`
    // INDEPENDENTLY (see module docs):
    //   ca_file set            → roots are exactly the ca_file certs.
    //   else system_roots=true → the OS trust store.
    //   else                   → EMPTY (never a silent system-roots fallback).
    let has_ca = tls.ca_file.is_some();
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
    } else if tls.system_roots {
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
    // else: `system_roots = false` and no `ca_file` → the root store stays
    // empty. The OS store is NEVER loaded as a silent fall-back; the only
    // remaining anchor is the SPKI pin set (fail-closed) or `allow_self_signed`.

    let roots_empty = roots.is_empty();

    // Genuine blind-accept: `allow_self_signed` with NEITHER a pin NOR a
    // `ca_file` disables certificate verification outright. Never let that be
    // silent — emit a loud warning at connect (w2-ssh3tls, finding 1).
    if tls.allow_self_signed && !has_ca && tls.pin.spki_sha256.is_empty() {
        tracing::warn!(
            "TLS certificate verification DISABLED — self-signed accepted with no \
             pin/CA; INSECURE, dev-only"
        );
    }

    // The chain (webpki) verifier is enforced whenever we have a real trust
    // anchor to check against:
    //   * a `ca_file` ALWAYS enforces its CA — even with `allow_self_signed`,
    //     a leaf that does not chain to it is REJECTED (finding 1); and
    //   * the normal path (`!allow_self_signed`) with non-empty roots.
    // When there is no such anchor (blind-accept, or pin-only with
    // `system_roots = false`), chain verification is skipped and trust rests
    // on the pin set (fail-closed) — or, in blind-accept, nothing.
    let require_chain = has_ca || (!tls.allow_self_signed && !roots_empty);

    // The depth cap applies on every path, including the unmodified-webpki
    // path. When the cap is bypassed (`None`) and there's no pin and no
    // self-signed flag, we can use the off-the-shelf builder.
    let needs_custom = tls.allow_self_signed
        || !tls.pin.spki_sha256.is_empty()
        || !tls.max_cert_chain_depth.is_unlimited();
    // Per-config crypto provider: aws-lc-rs with `X25519MLKEM768` first when
    // `post_quantum` is on, else the same aws-lc-rs provider restricted to the
    // classical groups. QUIC is TLS-1.3-only (RFC 9001), so restrict to TLS 1.3
    // explicitly.
    let builder = ClientConfig::builder_with_provider(ssh3_crypto_provider(tls.post_quantum))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| {
            Error::InvalidConfig(format!("ssh3 TLS provider does not support TLS 1.3: {e}"))
        })?;
    let mut cfg = if needs_custom {
        // Install our custom verifier — wraps webpki on the chain side (when a
        // trust anchor is enforced), enforces the pin set, and applies the
        // chain-depth cap (t5-e10).
        let verifier = Arc::new(SptVerifier::new(
            roots,
            tls.pin.clone(),
            tls.allow_self_signed,
            require_chain,
            tls.max_cert_chain_depth,
        ));
        builder
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth()
    } else {
        builder.with_root_certificates(roots).with_no_client_auth()
    };

    cfg.alpn_protocols = tls.alpn.iter().map(|s| s.as_bytes().to_vec()).collect();
    Ok(cfg)
}

fn install_default_provider() {
    // Idempotent — only sets a provider if none has been installed yet.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

/// The *per-config* rustls crypto provider for an ssh3 QUIC handshake.
///
/// When `pq` is true, use the **aws-lc-rs** provider with the hybrid
/// post-quantum group [`X25519MLKEM768`] listed FIRST, then classical
/// fallbacks — a PQ-capable peer negotiates PQ while a classical peer still
/// connects (hybrid ⇒ never weaker than X25519). When false, use the same
/// **aws-lc-rs** provider restricted to the classical groups only (X25519,
/// secp256r1, secp384r1) — no PQ group is offered.
///
/// This provider rides on the returned `ClientConfig`/`ServerConfig` object;
/// quinn 0.11 reads it off the config (`QuicClientConfig::try_from` /
/// `QuicServerConfig::try_from` call `initial_suite_from_provider(cfg
/// .crypto_provider())`). It therefore does NOT touch `install_default()`; the
/// process-global provider is aws-lc-rs (the single workspace-wide rustls
/// provider) independent of this per-config choice.
///
/// [`X25519MLKEM768`]: rustls::crypto::aws_lc_rs::kx_group::X25519MLKEM768
fn ssh3_crypto_provider(pq: bool) -> Arc<rustls::crypto::CryptoProvider> {
    use rustls::crypto::aws_lc_rs;

    let mut provider = aws_lc_rs::default_provider();
    provider.kx_groups = if pq {
        vec![
            aws_lc_rs::kx_group::X25519MLKEM768, // hybrid PQ, offered first
            aws_lc_rs::kx_group::X25519,         // classical fallbacks
            aws_lc_rs::kx_group::SECP256R1,
            aws_lc_rs::kx_group::SECP384R1,
        ]
    } else {
        // Classical aws-lc-rs groups ONLY — no post-quantum group. Set
        // explicitly because `aws_lc_rs::DEFAULT_KX_GROUPS` still lists
        // `X25519MLKEM768` (placed last) even with `prefer-post-quantum` off,
        // so a plain `default_provider()` would leak a PQ group here.
        vec![
            aws_lc_rs::kx_group::X25519,
            aws_lc_rs::kx_group::SECP256R1,
            aws_lc_rs::kx_group::SECP384R1,
        ]
    };
    Arc::new(provider)
}

/// Custom server-cert verifier honoring [`TlsPin`], `allow_self_signed`,
/// and a [`ChainDepthCap`].
#[derive(Debug)]
pub(crate) struct SptVerifier {
    /// Underlying webpki verifier. Present iff a chain trust anchor is
    /// enforced (`require_chain`): the CA from `ca_file` (even when
    /// `allow_self_signed`), or system/CA roots on the normal path.
    inner: Option<Arc<dyn ServerCertVerifier>>,
    pin: TlsPin,
    allow_self_signed: bool,
    /// Whether the server chain MUST validate against `inner` (webpki). When
    /// `true` and `inner` is unexpectedly absent, verification FAILS CLOSED.
    require_chain: bool,
    chain_depth_cap: ChainDepthCap,
    signature_algorithms: crypto::WebPkiSupportedAlgorithms,
}

impl SptVerifier {
    fn new(
        roots: RootCertStore,
        pin: TlsPin,
        allow_self_signed: bool,
        require_chain: bool,
        chain_depth_cap: ChainDepthCap,
    ) -> Self {
        // Build the webpki verifier ONLY when a chain anchor is enforced. A
        // `ca_file` forces enforcement even under `allow_self_signed`, so the
        // discriminator is `require_chain`, not `!allow_self_signed`.
        let inner = if require_chain {
            match rustls::client::WebPkiServerVerifier::builder(Arc::new(roots)).build() {
                Ok(v) => Some(v as Arc<dyn ServerCertVerifier>),
                Err(_) => None,
            }
        } else {
            None
        };
        Self {
            inner,
            pin,
            allow_self_signed,
            require_chain,
            chain_depth_cap,
            signature_algorithms: ssh3_crypto_provider(false).signature_verification_algorithms,
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
        if self.require_chain {
            // A trust anchor (ca_file / system roots) MUST be enforced. This
            // path also runs under `allow_self_signed` when a `ca_file` is set,
            // so a self-signed leaf that does not chain to the CA is REJECTED.
            match &self.inner {
                Some(inner) => {
                    inner.verify_server_cert(
                        end_entity,
                        intermediates,
                        server_name,
                        ocsp_response,
                        now,
                    )?;
                }
                None => {
                    // Anchor was required but the webpki verifier could not be
                    // built (e.g. empty/invalid roots). Fail closed — never
                    // fall back to accepting the chain.
                    return Err(TlsError::General(
                        "spt-ssh3: certificate chain verifier unavailable — refusing".into(),
                    ));
                }
            }
        } else if !self.allow_self_signed && self.pin.spki_sha256.is_empty() {
            // No chain anchor, not allowing self-signed, and no pin → there is
            // nothing to establish trust against. Fail closed rather than
            // silently accepting (validate rejects this combo up front; this
            // is defense-in-depth).
            return Err(TlsError::General(
                "spt-ssh3: no trust anchor (no CA/system roots and no pin) — refusing".into(),
            ));
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
        // Even when chain validation is intentionally skipped (pin-only or
        // acknowledged self-signed mode), TLS CertificateVerify still must
        // prove possession of the certificate private key. Verify the
        // handshake signature directly against the presented certificate's
        // public key instead of accepting it because no WebPKI verifier exists.
        verify_tls12_signature(message, cert, dss, &self.signature_algorithms)
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
        // See the TLS 1.2 path above: pin/self-signed certificate acceptance
        // does not waive CertificateVerify authentication.
        verify_tls13_signature(message, cert, dss, &self.signature_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        if let Some(inner) = &self.inner {
            return inner.supported_verify_schemes();
        }
        self.signature_algorithms.supported_schemes()
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
/// single PKCS#8, PKCS#1 (RSA), or SEC1 (EC) private key. The process-global
/// crypto provider (aws-lc-rs) is installed idempotently.
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
    // The responder ALWAYS offers the hybrid PQ group (plus classical
    // fallbacks) so a spt↔spt ssh3 handshake negotiates `X25519MLKEM768`. This
    // is safe unconditionally: hybrid negotiation degrades to classical X25519
    // for a non-PQ client, so it is never weaker than the old ring-only path.
    // Uses the same per-config provider mechanism as the client (no global
    // provider swap). QUIC is TLS-1.3-only (RFC 9001).
    let mut rustls_server = rustls::ServerConfig::builder_with_provider(ssh3_crypto_provider(true))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| {
            Error::InvalidConfig(format!(
                "ssh3 server TLS provider does not support TLS 1.3: {e}"
            ))
        })?
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

    // --- ssh3-pq: post-quantum hybrid KEX engages when `post_quantum = true` ---

    /// Collect the `NamedGroup`s the built client config offers, in order.
    fn client_kx_groups(tls: &Ssh3TlsConfig) -> Vec<rustls::NamedGroup> {
        let cfg = build_client_config(tls).unwrap();
        cfg.crypto_provider()
            .kx_groups
            .iter()
            .map(|g| g.name())
            .collect()
    }

    #[test]
    fn post_quantum_on_offers_mlkem_first() {
        // The DEFAULT config is PQ-on: the built ClientConfig must lead its
        // kx_groups with the hybrid `X25519MLKEM768` group, with classical
        // X25519 retained as a fallback (hybrid ⇒ never weaker than X25519).
        let groups = client_kx_groups(&Ssh3TlsConfig::default());
        assert_eq!(
            groups.first().copied(),
            Some(rustls::NamedGroup::X25519MLKEM768),
            "PQ-by-default must offer X25519MLKEM768 FIRST, got {groups:?}"
        );
        assert!(
            groups.contains(&rustls::NamedGroup::X25519),
            "classical X25519 fallback must remain, got {groups:?}"
        );
    }

    #[test]
    fn post_quantum_off_offers_no_pq_group() {
        // The operator force-off switch: the classical aws-lc-rs provider must
        // NOT offer any post-quantum group, reproducing the pre-PQ behaviour.
        let tls = Ssh3TlsConfig {
            post_quantum: false,
            ..Ssh3TlsConfig::default()
        };
        let groups = client_kx_groups(&tls);
        assert!(
            !groups.contains(&rustls::NamedGroup::X25519MLKEM768),
            "post_quantum=false must NOT offer X25519MLKEM768, got {groups:?}"
        );
        assert!(
            groups.contains(&rustls::NamedGroup::X25519),
            "classical X25519 must still be present, got {groups:?}"
        );
    }

    /// Real loopback QUIC handshake proving the aws-lc-rs PQ client config
    /// interoperates with the PQ-offering server config over quinn. Both ends
    /// lead with `X25519MLKEM768`, so TLS 1.3 negotiates the hybrid group.
    /// (quinn 0.11 does not expose the negotiated `NamedGroup`, so the
    /// completed handshake with PQ-first on both ends is the regression
    /// signal; the kx_groups ORDERING is asserted directly above.)
    ///
    /// Gated on `testing` (⊃ `server`) so `quic_server_config_from_rustls` is
    /// compiled; `cargo test -p spt-ssh3` activates it via the self dev-dep.
    #[cfg(feature = "testing")]
    #[tokio::test]
    async fn pq_client_and_server_complete_real_quic_handshake() {
        use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
        use std::net::{Ipv4Addr, SocketAddr};

        install_default_provider();

        // Self-signed server leaf; pin it so the client accepts it.
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_der = CertificateDer::from(cert.cert.der().to_vec());
        let pin = TlsPin::spki_sha256_of(&cert_der).unwrap();
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()));

        // Server ALWAYS offers X25519MLKEM768 (+ classical fallbacks).
        let server_cfg = quic_server_config_from_rustls(vec![cert_der], key_der).unwrap();

        // PQ client, pinned to the server cert.
        let tls = Ssh3TlsConfig {
            allow_self_signed: true,
            pin: TlsPin {
                spki_sha256: vec![pin],
            },
            post_quantum: true,
            ..Ssh3TlsConfig::default()
        };
        let client_rustls = build_client_config(&tls).unwrap();
        assert_eq!(
            client_rustls
                .crypto_provider()
                .kx_groups
                .first()
                .map(|g| g.name()),
            Some(rustls::NamedGroup::X25519MLKEM768),
        );
        let quic_client_crypto =
            quinn::crypto::rustls::QuicClientConfig::try_from(client_rustls).unwrap();
        let client_cfg = quinn::ClientConfig::new(Arc::new(quic_client_crypto));

        let server_endpoint =
            quinn::Endpoint::server(server_cfg, (Ipv4Addr::LOCALHOST, 0).into()).unwrap();
        let server_addr: SocketAddr = server_endpoint.local_addr().unwrap();
        let mut client_endpoint = quinn::Endpoint::client((Ipv4Addr::LOCALHOST, 0).into()).unwrap();
        client_endpoint.set_default_client_config(client_cfg);

        let server_task = tokio::spawn(async move {
            let incoming = server_endpoint.accept().await.expect("incoming");
            incoming.await.expect("server-side handshake completes");
        });
        let client_conn = client_endpoint
            .connect(server_addr, "localhost")
            .unwrap()
            .await
            .expect("PQ client/server QUIC handshake must complete");
        server_task.await.unwrap();
        client_conn.close(0u32.into(), b"done");
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
        let verifier = SptVerifier::new(
            RootCertStore::empty(),
            pin,
            true,
            false,
            ChainDepthCap::default(),
        );
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
            false,
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
        let verifier = SptVerifier::new(
            RootCertStore::empty(),
            pin,
            true,
            false,
            ChainDepthCap::default(),
        );
        let server_name = ServerName::try_from("pin-match.test").unwrap();
        verifier
            .verify_server_cert(&der, &[], &server_name, &[], UnixTime::now())
            .expect("pin match should accept");
    }

    // --- w2-ssh3tls: ca_file enforcement, system_roots, blind-accept warn ---

    /// Mint a CA (self-signed, keyCertSign) usable as an explicit `ca_file`
    /// trust anchor.
    fn make_ca() -> (rcgen::Certificate, rcgen::KeyPair) {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(vec!["spt-test-ca".to_string()]).unwrap();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
            rcgen::KeyUsagePurpose::DigitalSignature,
        ];
        let cert = params.self_signed(&key).unwrap();
        (cert, key)
    }

    /// Mint a serverAuth leaf for `san` signed by `ca`/`ca_key`.
    fn make_leaf_signed_by(
        san: &str,
        ca: &rcgen::Certificate,
        ca_key: &rcgen::KeyPair,
    ) -> CertificateDer<'static> {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(vec![san.to_string()]).unwrap();
        params.is_ca = rcgen::IsCa::NoCa;
        params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
        let cert = params.signed_by(&key, ca, ca_key).unwrap();
        CertificateDer::from(cert.der().to_vec())
    }

    fn roots_with(ca: &rcgen::Certificate) -> RootCertStore {
        let mut roots = RootCertStore::empty();
        roots.add(CertificateDer::from(ca.der().to_vec())).unwrap();
        roots
    }

    #[test]
    fn ca_file_accepts_leaf_chaining_to_ca() {
        // Mirrors `build_client_config` for `ca_file` + `allow_self_signed`:
        // roots = the CA, require_chain = true. A leaf that chains to the CA
        // must be accepted.
        install_default_provider();
        let (ca, ca_key) = make_ca();
        let leaf = make_leaf_signed_by("leaf.test", &ca, &ca_key);
        let verifier = SptVerifier::new(
            roots_with(&ca),
            TlsPin::default(),
            true, // allow_self_signed
            true, // require_chain (ca_file always enforces)
            ChainDepthCap::default(),
        );
        let name = ServerName::try_from("leaf.test").unwrap();
        verifier
            .verify_server_cert(&leaf, &[], &name, &[], UnixTime::now())
            .expect("leaf chaining to the ca_file CA must be accepted");
    }

    #[test]
    fn ca_file_rejects_self_signed_leaf_not_chaining() {
        // THE security test (finding 1). Pre-fix, `allow_self_signed=true` set
        // `inner=None` and accepted ANY certificate even with a `ca_file`. Now
        // the ca_file CA is enforced: a self-signed leaf that does not chain to
        // it is REJECTED.
        install_default_provider();
        let (ca, _ca_key) = make_ca();
        let rogue = rcgen::generate_simple_self_signed(vec!["leaf.test".to_string()]).unwrap();
        let rogue_der = CertificateDer::from(rogue.cert.der().to_vec());
        let verifier = SptVerifier::new(
            roots_with(&ca),
            TlsPin::default(),
            true, // allow_self_signed
            true, // require_chain (ca_file present)
            ChainDepthCap::default(),
        );
        let name = ServerName::try_from("leaf.test").unwrap();
        verifier
            .verify_server_cert(&rogue_der, &[], &name, &[], UnixTime::now())
            .expect_err("self-signed leaf not chaining to the ca_file CA must be REJECTED");
    }

    #[test]
    fn system_roots_false_no_fallback_pin_only() {
        // Mirrors `build_client_config` for `system_roots=false` + pin (no
        // ca_file, allow_self_signed=false): the root store is EMPTY, so
        // require_chain=false and trust rests ONLY on the pin. Pre-fix the OS
        // store was loaded unconditionally and webpki would reject a leaf that
        // does not chain to a system root — proving the fall-back is gone.
        install_default_provider();
        let (ca, ca_key) = make_ca();
        let leaf = make_leaf_signed_by("leaf.test", &ca, &ca_key);
        let pin = TlsPin {
            spki_sha256: vec![TlsPin::spki_sha256_of(&leaf).unwrap()],
        };
        let verifier = SptVerifier::new(
            RootCertStore::empty(),
            pin,
            false, // allow_self_signed
            false, // require_chain (roots empty, no ca_file)
            ChainDepthCap::default(),
        );
        let name = ServerName::try_from("leaf.test").unwrap();
        verifier
            .verify_server_cert(&leaf, &[], &name, &[], UnixTime::now())
            .expect("pinned cert accepted without any system-root fall-back");
        // A different (non-pinned) cert is rejected — the system store is never
        // consulted as an alternative anchor.
        let (ca2, ca2_key) = make_ca();
        let other = make_leaf_signed_by("leaf.test", &ca2, &ca2_key);
        verifier
            .verify_server_cert(&other, &[], &name, &[], UnixTime::now())
            .expect_err("non-pinned cert must be rejected; no system-root fall-back");
    }

    #[test]
    fn pin_only_rejects_invalid_certificate_verify_signature() {
        use rustls::internal::msgs::codec::{Codec, Reader};

        install_default_provider();
        let (ca, ca_key) = make_ca();
        let leaf = make_leaf_signed_by("leaf.test", &ca, &ca_key);
        let pin = TlsPin {
            spki_sha256: vec![TlsPin::spki_sha256_of(&leaf).unwrap()],
        };
        let verifier = SptVerifier::new(
            RootCertStore::empty(),
            pin,
            false, // allow_self_signed
            false, // pin-only: no chain verifier is available
            ChainDepthCap::default(),
        );
        let name = ServerName::try_from("leaf.test").unwrap();

        verifier
            .verify_server_cert(&leaf, &[], &name, &[], UnixTime::now())
            .expect("matching pin should still accept the certificate");

        // 0x0403 = ECDSA_NISTP256_SHA256, followed by a 3-byte nonsense
        // signature. Before the fix, the no-inner pin-only path accepted this
        // unconditionally, so possession of the pinned certificate's private
        // key was not proven.
        let mut encoded_dss = vec![0x04, 0x03, 0x00, 0x03, 0xde, 0xad, 0xbe];
        let dss = DigitallySignedStruct::read(&mut Reader::init(&encoded_dss)).unwrap();
        assert!(
            verifier
                .verify_tls13_signature(b"handshake transcript", &leaf, &dss)
                .is_err(),
            "pin-only TLS 1.3 must reject invalid CertificateVerify signatures"
        );
        assert!(
            verifier
                .verify_tls12_signature(b"handshake transcript", &leaf, &dss)
                .is_err(),
            "pin-only TLS 1.2 must reject invalid CertificateVerify signatures"
        );

        // Keep the vector live until after read-derived fields are consumed.
        encoded_dss.clear();
    }

    #[test]
    fn no_anchor_no_pin_fails_closed() {
        // require_chain=false, allow_self_signed=false, empty pin → nothing to
        // trust → reject every cert (defense-in-depth; validate also errors).
        install_default_provider();
        let rogue = rcgen::generate_simple_self_signed(vec!["x.test".to_string()]).unwrap();
        let der = CertificateDer::from(rogue.cert.der().to_vec());
        let verifier = SptVerifier::new(
            RootCertStore::empty(),
            TlsPin::default(),
            false,
            false,
            ChainDepthCap::default(),
        );
        let name = ServerName::try_from("x.test").unwrap();
        let err = verifier
            .verify_server_cert(&der, &[], &name, &[], UnixTime::now())
            .unwrap_err();
        assert!(
            format!("{err}").contains("no trust anchor"),
            "expected fail-closed no-trust-anchor error, got: {err}"
        );
    }

    #[tracing_test::traced_test]
    #[test]
    fn blind_accept_warns_at_connect() {
        // allow_self_signed + NO pin + NO ca_file → build_client_config must
        // emit the loud INSECURE warning (never silent).
        let tls = Ssh3TlsConfig {
            allow_self_signed: true,
            ..Ssh3TlsConfig::default()
        };
        let _cfg = build_client_config(&tls).unwrap();
        assert!(
            logs_contain("verification DISABLED"),
            "blind-accept must log the insecure warning at connect"
        );
    }

    #[tracing_test::traced_test]
    #[test]
    fn ca_file_or_pin_does_not_warn_blind_accept() {
        // allow_self_signed WITH a pin must NOT emit the blind-accept warning
        // (the pin is a real fail-closed anchor).
        let tls = Ssh3TlsConfig {
            allow_self_signed: true,
            pin: TlsPin {
                spki_sha256: vec![[7u8; 32]],
            },
            ..Ssh3TlsConfig::default()
        };
        let _cfg = build_client_config(&tls).unwrap();
        assert!(
            !logs_contain("verification DISABLED"),
            "a pinned self-signed config must not warn that verification is disabled"
        );
    }
}
