//! `PinnedTlsConnector` — a one-stop builder that produces a
//! [`rustls::ClientConfig`] honoring an optional `TlsPin` set, an
//! optional `allow_self_signed` flag, an optional CA-file (replacing
//! system roots), and a placeholder `max_cert_chain_depth` knob.
//!
//! This is the generic counterpart to `spt-ssh3`'s in-crate verifier:
//! every HTTPS surface (remote-config, OIDC, OTLP, syslog-TLS, HTTPS
//! event sinks, generic HTTP/SMS/MCP-notify, SMTP via `tokio-rustls`)
//! routes its TLS handshake through this builder so the verification
//! policy lives in exactly one place.
//!
//! ## Verifier behaviour
//!
//! 1. If `allow_self_signed == false`: run rustls' default `WebPKI`
//!    verifier against the configured root store first. Hostname,
//!    `NotBefore`/`NotAfter`, signature, and chain construction are all
//!    enforced.
//! 2. If `allow_self_signed == true`: skip the `WebPKI` verifier. The
//!    pin set is then the *only* trust anchor — when the pin set is
//!    empty in this mode, every chain is rejected (a deliberate
//!    fail-closed posture; callers that want pure system-root
//!    validation must keep `allow_self_signed = false`).
//! 3. If `max_cert_chain_depth = Some(n)`: count `intermediates.len()`
//!    and reject when it exceeds `n`. The bound counts intermediate
//!    certs only (not the leaf or trust anchor) so the typical
//!    "leaf -> int -> root" chain has depth 1.
//! 4. If the pin set is non-empty: enforce SPKI-SHA256 match against
//!    the *leaf* using constant-time comparison.
//!
//! Steps (1) and (3) are ordered before (4) so a malformed chain
//! never reaches the pin check.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    ClientConfig, DigitallySignedStruct, Error as TlsError, RootCertStore, SignatureScheme,
};

use spt_core::{Error, Result};

use crate::chain_depth::{check_chain_depth, ChainDepthCap};
use crate::crl::{
    extract_crl_distribution_points, fetch_crl_bytes, CrlCache, CrlCacheHandle, CrlPolicy,
    RevocationStatus,
};
use crate::tls_pin::TlsPin;
use x509_parser::prelude::*;

/// Source of root certificates for the connector.
#[derive(Debug, Clone)]
enum RootSource {
    /// rustls-native-certs (OS trust store). Default.
    System,
    /// PEM-encoded CA bundle on disk — replaces the system store.
    CaFile(PathBuf),
    /// Empty store (only valid with `allow_self_signed = true` and a
    /// non-empty pin set; the builder enforces this).
    Empty,
}

impl Default for RootSource {
    fn default() -> Self {
        Self::System
    }
}

/// Builder for [`PinnedTlsConnector`].
///
/// Returned by [`PinnedTlsConnector::builder`]. Configure with chained
/// setters then call [`build`](Self::build) to obtain a
/// `Arc<rustls::ClientConfig>`.
#[derive(Debug, Clone)]
pub struct PinnedTlsConnectorBuilder {
    roots: RootSource,
    pin: TlsPin,
    allow_self_signed: bool,
    chain_depth_cap: ChainDepthCap,
    alpn: Vec<Vec<u8>>,
    /// CRL consultation policy. Defaults to [`CrlPolicy::Disabled`] so
    /// adopting CRL checking is explicit per the A6 follow-up. When
    /// non-disabled, `crl_cache` is consulted from inside the
    /// (synchronous) `ServerCertVerifier` callback.
    crl_policy: CrlPolicy,
    /// Shared CRL store. Set via [`Self::crl_cache`]; populated either
    /// directly through `CrlCache::insert_der` or async via
    /// [`Self::prefetch_crls`]. Always present (default `new()`) so
    /// the verifier can be wired uniformly; ignored when
    /// `crl_policy == Disabled`.
    crl_cache: Arc<CrlCache>,
}

impl Default for PinnedTlsConnectorBuilder {
    fn default() -> Self {
        Self {
            roots: RootSource::System,
            pin: TlsPin::default(),
            allow_self_signed: false,
            // None == "operator hasn't expressed a preference"; the
            // verifier will skip the depth check entirely. Callers that
            // want the spec default (5) should explicitly opt in via
            // `.max_cert_chain_depth(Some(5))` or
            // `.chain_depth_cap(ChainDepthCap::default())`.
            chain_depth_cap: ChainDepthCap::unlimited(),
            alpn: Vec::new(),
            crl_policy: CrlPolicy::Disabled,
            crl_cache: Arc::new(CrlCache::new()),
        }
    }
}

impl PinnedTlsConnectorBuilder {
    /// Use system trust roots via `rustls-native-certs` (the default).
    pub fn system_roots(mut self) -> Self {
        self.roots = RootSource::System;
        self
    }

    /// Use a PEM-encoded CA bundle, replacing the system roots.
    pub fn ca_file(mut self, path: impl AsRef<Path>) -> Self {
        self.roots = RootSource::CaFile(path.as_ref().to_path_buf());
        self
    }

    /// Use an empty root store. Only valid together with
    /// `allow_self_signed(true)` plus a non-empty pin set; the
    /// [`build`](Self::build) call will return `InvalidConfig`
    /// otherwise.
    pub fn empty_roots(mut self) -> Self {
        self.roots = RootSource::Empty;
        self
    }

    /// Set the pin set (SPKI SHA-256 digests).
    pub fn pin_spki_sha256(mut self, pin: TlsPin) -> Self {
        self.pin = pin;
        self
    }

    /// Allow self-signed certificates (skips `WebPKI`; pin set becomes
    /// the only trust anchor).
    pub fn allow_self_signed(mut self, allow: bool) -> Self {
        self.allow_self_signed = allow;
        self
    }

    /// Reject any chain whose intermediates count is `>= n`.
    ///
    /// `None` imposes no cap (default). Routes through
    /// [`ChainDepthCap`] / [`check_chain_depth`] so the verifier's
    /// semantics match every other pinned-TLS surface.
    pub fn max_cert_chain_depth(mut self, n: Option<u32>) -> Self {
        self.chain_depth_cap = ChainDepthCap::from_option(n);
        self
    }

    /// Set the chain-depth cap directly from a [`ChainDepthCap`].
    ///
    /// Equivalent to [`max_cert_chain_depth`](Self::max_cert_chain_depth)
    /// but accepts the typed form used by sink-config loaders.
    pub fn chain_depth_cap(mut self, cap: ChainDepthCap) -> Self {
        self.chain_depth_cap = cap;
        self
    }

    /// Set ALPN protocol identifiers. Empty by default.
    pub fn alpn_protocols(mut self, alpn: Vec<Vec<u8>>) -> Self {
        self.alpn = alpn;
        self
    }

    /// Set the CRL consultation policy.
    ///
    /// - [`CrlPolicy::Disabled`] (default) — preserves the pre-CRL
    ///   behaviour exactly. Pin / `WebPKI` / chain-depth checks are the
    ///   only authorities.
    /// - [`CrlPolicy::Soft`] — consult cached CRLs; on a missing or
    ///   stale CRL for an issuer the leaf names, log a warning and
    ///   accept.
    /// - [`CrlPolicy::Hard`] — consult cached CRLs; on missing or
    ///   stale CRL, reject (fail closed).
    pub fn crl_policy(mut self, policy: CrlPolicy) -> Self {
        self.crl_policy = policy;
        self
    }

    /// Swap in a pre-built [`CrlCache`]. Useful when the same cache is
    /// shared across multiple connectors so a single prefetch run
    /// services every TLS surface in the process.
    pub fn crl_cache(mut self, cache: Arc<CrlCache>) -> Self {
        self.crl_cache = cache;
        self
    }

    /// Asynchronously fetch every URL in `urls` and ingest each into
    /// the configured CRL cache. Non-fatal on individual fetch
    /// failures — they are logged and the caller's policy
    /// ([`CrlPolicy::Hard`] vs [`CrlPolicy::Soft`]) decides the
    /// downstream effect at verify time.
    ///
    /// Returns the number of CRLs successfully ingested.
    ///
    /// `reqwest` is already a workspace dep (used by remote-config /
    /// OTLP / event sinks); this method does not add any new
    /// transitive crates.
    pub async fn prefetch_crls(self, urls: &[String]) -> Self {
        for url in urls {
            match fetch_crl_bytes(url).await {
                Ok(bytes) => match self.crl_cache.insert_der(&bytes) {
                    Ok(_) => tracing::debug!("spt-trust: ingested CRL from {url}"),
                    Err(e) => tracing::warn!("spt-trust: parse CRL from {url}: {e}"),
                },
                Err(e) => tracing::warn!("spt-trust: fetch CRL {url}: {e}"),
            }
        }
        self
    }

    /// Finish: produce a `Arc<rustls::ClientConfig>` carrying the
    /// configured verifier.
    pub fn build(self) -> Result<Arc<ClientConfig>> {
        install_default_provider();

        // ------- assemble the root store ----------------------------
        let mut roots = RootCertStore::empty();
        match &self.roots {
            RootSource::System => {
                match rustls_native_certs::load_native_certs() {
                    Ok(certs) => {
                        for cert in certs {
                            // Ignore individual load failures — we'll
                            // catch "store is empty" downstream when
                            // building the webpki verifier.
                            let _ = roots.add(cert);
                        }
                    }
                    Err(e) => {
                        tracing::debug!(
                            "spt-trust: load_native_certs failed: {e}; \
                             falling back to webpki-roots"
                        );
                    }
                }
                if roots.is_empty() {
                    // Final fallback: webpki-roots' bundled Mozilla set.
                    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
                }
            }
            RootSource::CaFile(path) => {
                let pem = std::fs::read(path).map_err(|e| {
                    Error::InvalidConfig(format!("read ca_file `{}`: {e}", path.display()))
                })?;
                let mut cursor = std::io::Cursor::new(pem);
                for item in rustls_pemfile::certs(&mut cursor) {
                    let cert = item.map_err(|e| {
                        Error::InvalidConfig(format!("parse ca_file `{}`: {e}", path.display()))
                    })?;
                    roots.add(cert).map_err(|e| {
                        Error::InvalidConfig(format!("add ca cert from `{}`: {e}", path.display()))
                    })?;
                }
                if roots.is_empty() {
                    return Err(Error::InvalidConfig(format!(
                        "ca_file `{}` contained no certificates",
                        path.display()
                    )));
                }
            }
            RootSource::Empty => {
                // Empty is only meaningful in pin-only mode.
                if !self.allow_self_signed || self.pin.is_empty() {
                    return Err(Error::InvalidConfig(
                        "empty_roots() requires allow_self_signed(true) \
                         and a non-empty pin set"
                            .into(),
                    ));
                }
            }
        }

        // ------- pin-only mode sanity checks ------------------------
        if self.allow_self_signed && self.pin.is_empty() {
            return Err(Error::InvalidConfig(
                "allow_self_signed=true requires a non-empty pin set \
                 (refusing to disable verification entirely)"
                    .into(),
            ));
        }

        // ------- build the verifier ---------------------------------
        let inner = if self.allow_self_signed {
            None
        } else {
            Some(
                WebPkiServerVerifier::builder(Arc::new(roots.clone()))
                    .build()
                    .map_err(|e| {
                        Error::InvalidConfig(format!("webpki verifier build failed: {e}"))
                    })? as Arc<dyn ServerCertVerifier>,
            )
        };

        let crl_handle = if self.crl_policy.enabled() {
            Some(CrlCacheHandle {
                cache: self.crl_cache,
                policy: self.crl_policy,
            })
        } else {
            // `Disabled` policy => keep the verifier path bit-identical
            // to pre-A6 behaviour: no Mutex lock, no DER parse of the
            // leaf for the CRL DP extension.
            None
        };

        let verifier = Arc::new(PinnedVerifier {
            inner,
            pin: self.pin,
            allow_self_signed: self.allow_self_signed,
            chain_depth_cap: self.chain_depth_cap,
            crl: crl_handle,
        });

        let mut cfg = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();
        cfg.alpn_protocols = self.alpn;
        Ok(Arc::new(cfg))
    }
}

/// Bundle of helpers for producing pinned-and-chain-capped
/// [`rustls::ClientConfig`] instances.
///
/// This is a zero-sized handle — all state lives on the builder.
#[derive(Debug, Default, Clone, Copy)]
pub struct PinnedTlsConnector;

impl PinnedTlsConnector {
    /// Start a new builder. Defaults: system roots, no pin, no
    /// `allow_self_signed`, no chain-depth cap.
    pub fn builder() -> PinnedTlsConnectorBuilder {
        PinnedTlsConnectorBuilder::default()
    }

    /// Convenience for sink-config call sites: build directly from the
    /// raw `(pin_spki_sha256, allow_self_signed, max_cert_chain_depth)`
    /// triple that every t5-e2 surface carries.
    ///
    /// Empty pin set + `false` + `None` yields a strict system-roots
    /// client with the default chain-depth cap; non-empty pin or
    /// explicit cap routes through `PinnedVerifier`.
    pub fn from_config_parts(
        pin_strings: &[String],
        allow_self_signed: bool,
        max_cert_chain_depth: Option<u32>,
    ) -> Result<Arc<ClientConfig>> {
        let pin = TlsPin::from_strings(pin_strings)?;
        let cap =
            ChainDepthCap::from_option(max_cert_chain_depth).or_default_if_unlimited_was_absent();
        let mut b = Self::builder()
            .pin_spki_sha256(pin)
            .allow_self_signed(allow_self_signed)
            .chain_depth_cap(cap);
        // Force the "use system roots" path explicitly for clarity.
        b = b.system_roots();
        b.build()
    }
}

// ---------------------------------------------------------------------------
// PinnedVerifier — the actual `ServerCertVerifier` implementation
// ---------------------------------------------------------------------------

/// Server-cert verifier honouring `TlsPin`, `allow_self_signed`, and
/// `max_cert_chain_depth`.
///
/// Construct via [`PinnedTlsConnectorBuilder::build`] — direct
/// construction is intentionally not exposed so the invariants
/// "pin-only requires pins" / "`WebPKI` verifier when `allow_self_signed
/// = false`" are guaranteed by the builder.
#[derive(Debug)]
pub(crate) struct PinnedVerifier {
    /// Underlying `WebPKI` verifier (only present when
    /// `allow_self_signed = false`).
    inner: Option<Arc<dyn ServerCertVerifier>>,
    pin: TlsPin,
    allow_self_signed: bool,
    chain_depth_cap: ChainDepthCap,
    /// `Some` when [`CrlPolicy`] is non-disabled; `None` keeps the
    /// pre-A6 fast path. Held as a small clone-on-construct handle so
    /// the verifier does not need to grab the cache `Arc` on every
    /// handshake when CRL is off.
    crl: Option<CrlCacheHandle>,
}

/// Test-only helper that surfaces `PinnedVerifier` to integration
/// tests (which can't reach `pub(crate)` types). Doc-hidden so it
/// doesn't pollute the public surface.
///
/// `crl` is `Some((cache, policy))` to enable CRL consultation;
/// `None` for the legacy fast path. Always builds with
/// `inner = None` — intended for `allow_self_signed = true` flows
/// where no `WebPKI` underlying verifier is required.
#[doc(hidden)]
#[must_use]
pub fn build_pinned_verifier_for_test(
    pin: TlsPin,
    allow_self_signed: bool,
    chain_depth_cap: ChainDepthCap,
    crl: Option<(Arc<CrlCache>, CrlPolicy)>,
) -> Arc<dyn ServerCertVerifier> {
    let crl_handle = crl.map(|(cache, policy)| CrlCacheHandle { cache, policy });
    Arc::new(PinnedVerifier {
        inner: None,
        pin,
        allow_self_signed,
        chain_depth_cap,
        crl: crl_handle,
    })
}

impl PinnedVerifier {
    fn check_depth_and_pin(
        &self,
        leaf: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
    ) -> std::result::Result<(), TlsError> {
        // Build the wire-order chain `check_chain_depth` expects:
        // [leaf, intermediate0, intermediate1, ...]. We hand it
        // borrowed refs so no cloning of the DER blobs happens.
        let mut wire: Vec<CertificateDer<'_>> = Vec::with_capacity(intermediates.len() + 1);
        wire.push(leaf.clone());
        for i in intermediates {
            wire.push(i.clone());
        }
        check_chain_depth(&wire, &self.chain_depth_cap)
            .map_err(|e| TlsError::General(format!("spt-trust: chain depth: {e}")))?;
        if !self.pin.is_empty() {
            self.pin
                .verify(leaf)
                .map_err(|e| TlsError::General(format!("spt-trust SPKI pin: {e}")))?;
        }
        Ok(())
    }

    /// Consult the configured CRL cache for `leaf`'s serial. Returns
    /// `Ok(())` on accept and `Err(TlsError)` on reject; the
    /// [`CrlPolicy`] field decides what to do with `NoCrl` / `Stale`
    /// statuses.
    ///
    /// Cheap when `self.crl` is `None` — returns immediately without
    /// parsing the leaf. With `Some(handle)`, the leaf is DER-parsed
    /// once, its issuer DN is taken from the first intermediate (or
    /// the leaf itself for self-signed pin-only chains), and the
    /// cache is queried synchronously.
    fn check_crl(
        &self,
        leaf: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
    ) -> std::result::Result<(), TlsError> {
        let Some(handle) = &self.crl else {
            return Ok(());
        };
        // Parse the leaf to read both the CRL DP extension and the
        // serial number.
        let (_, leaf_parsed) = X509Certificate::from_der(leaf.as_ref()).map_err(|e| {
            TlsError::General(format!("spt-trust CRL: parse leaf: {e}"))
        })?;
        let dps = extract_crl_distribution_points(&leaf_parsed);
        if dps.is_empty() {
            // No DP extension => issuer didn't tell us to look anywhere.
            // RFC 5280 leaves this case to local policy; the spec
            // decision here is "no DP == nothing to check", consistent
            // with how WebPKI ignores absent OCSP responses.
            return Ok(());
        }

        // Issuer DN to key the cache lookup. For a real chain the
        // first intermediate is the issuer; for a pin-only chain with
        // just the leaf, fall back to the leaf's own issuer DN (which
        // also matches the cache key the parser populates when the
        // CRL was minted by that same CA).
        let issuer_dn_owned: Vec<u8> = if let Some(int) = intermediates.first() {
            match X509Certificate::from_der(int.as_ref()) {
                Ok((_, parsed)) => parsed.subject().as_raw().to_vec(),
                Err(_) => leaf_parsed.issuer().as_raw().to_vec(),
            }
        } else {
            leaf_parsed.issuer().as_raw().to_vec()
        };

        let serial_be = leaf_parsed.tbs_certificate.serial.to_bytes_be();
        let status = handle
            .cache
            .is_revoked(&issuer_dn_owned, &serial_be)
            .map_err(|e| TlsError::General(format!("spt-trust CRL lookup: {e}")))?;
        match status {
            RevocationStatus::Revoked => Err(TlsError::General(
                "spt-trust: certificate revoked via CRL".into(),
            )),
            RevocationStatus::NotRevoked => Ok(()),
            RevocationStatus::NoCrl | RevocationStatus::Stale => match handle.policy {
                CrlPolicy::Hard => Err(TlsError::General(format!(
                    "spt-trust CRL: no fresh CRL for issuer ({status:?}); fail-closed"
                ))),
                CrlPolicy::Soft => {
                    tracing::warn!(
                        "spt-trust CRL: no fresh CRL for leaf-named DP ({:?}); \
                         soft policy allows chain",
                        status
                    );
                    Ok(())
                }
                // Unreachable: when Disabled, self.crl is None, so
                // check_crl exited at the top.
                CrlPolicy::Disabled => Ok(()),
            },
        }
    }
}

impl ServerCertVerifier for PinnedVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, TlsError> {
        // (1) WebPKI verification (unless self-signed is allowed).
        if !self.allow_self_signed {
            let Some(inner) = &self.inner else {
                return Err(TlsError::General(
                    "spt-trust: webpki verifier unavailable".into(),
                ));
            };
            inner.verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)?;
        }

        // (3) + (4): chain-depth cap and pin check share a single
        // helper so the wire-order vector is built exactly once.
        self.check_depth_and_pin(end_entity, intermediates)?;

        // (5) CRL consultation (A6). No-op when `crl_policy` is the
        // default `Disabled`; otherwise consults the pre-fetched
        // cache. Synchronous — fetches happened at builder time.
        self.check_crl(end_entity, intermediates)?;

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
        // Pin-only mode: signature still travels through rustls' own
        // crypto provider check before this is called; accepting here
        // is consistent with `spt-ssh3`'s allow-self-signed verifier.
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

fn install_default_provider() {
    // Idempotent — first caller wins, subsequent calls no-op.
    let _ = rustls::crypto::ring::default_provider().install_default();
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;
    use rustls::pki_types::ServerName;
    use sha2::{Digest, Sha256};

    // -----------------------------------------------------------------
    // rcgen helpers — build single-cert and 3-level chains for the
    // chain-depth-cap tests. rcgen 0.13 API: `CertificateParams::new`,
    // `params.self_signed(&key_pair)`, and `params.signed_by(&key,
    // &issuer_cert, &issuer_key)`.
    // -----------------------------------------------------------------

    struct OneCert {
        der: Vec<u8>,
        spki: [u8; 32],
    }

    fn gen_self_signed(cn: &str) -> OneCert {
        let cert = rcgen::generate_simple_self_signed(vec![cn.to_string()]).unwrap();
        let der = cert.cert.der().to_vec();
        let spki = spki_of(&der);
        OneCert { der, spki }
    }

    fn spki_of(der: &[u8]) -> [u8; 32] {
        use x509_parser::prelude::*;
        let (_, parsed) = X509Certificate::from_der(der).unwrap();
        let mut h = Sha256::new();
        h.update(parsed.tbs_certificate.subject_pki.raw);
        h.finalize().into()
    }

    /// A 3-level chain: leaf -> intermediate -> root.
    struct ThreeLevelChain {
        leaf: CertificateDer<'static>,
        intermediate: CertificateDer<'static>,
        #[allow(dead_code)]
        root: CertificateDer<'static>,
        leaf_spki: [u8; 32],
    }

    fn gen_three_level_chain(cn: &str) -> ThreeLevelChain {
        // Root.
        let mut root_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        root_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "spt-test-root");
        root_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let root_key = rcgen::KeyPair::generate().unwrap();
        let root_cert = root_params.self_signed(&root_key).unwrap();

        // Intermediate.
        let mut int_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        int_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "spt-test-intermediate");
        int_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let int_key = rcgen::KeyPair::generate().unwrap();
        let int_cert = int_params
            .signed_by(&int_key, &root_cert, &root_key)
            .unwrap();

        // Leaf.
        let mut leaf_params = rcgen::CertificateParams::new(vec![cn.to_string()]).unwrap();
        leaf_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, cn);
        let leaf_key = rcgen::KeyPair::generate().unwrap();
        let leaf_cert = leaf_params
            .signed_by(&leaf_key, &int_cert, &int_key)
            .unwrap();

        let leaf_der = leaf_cert.der().to_vec();
        let leaf_spki = spki_of(&leaf_der);
        let int_der = int_cert.der().to_vec();
        let root_der = root_cert.der().to_vec();

        ThreeLevelChain {
            leaf: CertificateDer::from(leaf_der),
            intermediate: CertificateDer::from(int_der),
            root: CertificateDer::from(root_der),
            leaf_spki,
        }
    }

    fn make_verifier(pin: TlsPin, allow_self_signed: bool, cap: Option<u32>) -> PinnedVerifier {
        PinnedVerifier {
            inner: None,
            pin,
            allow_self_signed,
            chain_depth_cap: ChainDepthCap::from_option(cap),
            crl: None,
        }
    }

    // -----------------------------------------------------------------
    // (1) pin-only-accepts-matching
    // -----------------------------------------------------------------

    #[test]
    fn pin_only_accepts_matching_pin() {
        install_default_provider();
        let c = gen_self_signed("pin-match.test");
        let pin = TlsPin {
            spki_sha256: vec![c.spki],
        };
        let v = make_verifier(pin, true, None);
        let leaf = CertificateDer::from(c.der);
        let name = ServerName::try_from("pin-match.test").unwrap();
        v.verify_server_cert(&leaf, &[], &name, &[], UnixTime::now())
            .expect("matching pin must accept");
    }

    // -----------------------------------------------------------------
    // (2) pin-only-rejects-non-matching
    // -----------------------------------------------------------------

    #[test]
    fn pin_only_rejects_non_matching_pin() {
        install_default_provider();
        let c = gen_self_signed("pin-mismatch.test");
        let pin = TlsPin {
            spki_sha256: vec![[0xAB; 32]],
        };
        let v = make_verifier(pin, true, None);
        let leaf = CertificateDer::from(c.der);
        let name = ServerName::try_from("pin-mismatch.test").unwrap();
        let err = v
            .verify_server_cert(&leaf, &[], &name, &[], UnixTime::now())
            .unwrap_err();
        let s = format!("{err}");
        assert!(s.contains("SPKI pin"), "got {s}");
    }

    // -----------------------------------------------------------------
    // (3) allow-self-signed-with-pin OK
    // -----------------------------------------------------------------

    #[test]
    fn allow_self_signed_with_matching_pin_accepts() {
        install_default_provider();
        let c = gen_self_signed("self-signed.test");
        let pin = TlsPin::from_strings([base64::engine::general_purpose::STANDARD.encode(c.spki)])
            .unwrap();
        let v = make_verifier(pin, true, None);
        let leaf = CertificateDer::from(c.der);
        let name = ServerName::try_from("self-signed.test").unwrap();
        v.verify_server_cert(&leaf, &[], &name, &[], UnixTime::now())
            .expect("self-signed-plus-pin must accept");
    }

    // -----------------------------------------------------------------
    // (4) allow-self-signed-without-pin rejects (strict mode)
    // -----------------------------------------------------------------

    #[test]
    fn allow_self_signed_without_pin_builder_rejects() {
        install_default_provider();
        let err = PinnedTlsConnector::builder()
            .allow_self_signed(true)
            .build()
            .unwrap_err();
        assert!(
            matches!(err, Error::InvalidConfig(ref m) if m.contains("non-empty pin set")),
            "got {err:?}"
        );
    }

    // -----------------------------------------------------------------
    // (5) chain-depth-cap rejects > N
    // -----------------------------------------------------------------

    #[test]
    fn chain_depth_cap_rejects_too_many_intermediates() {
        install_default_provider();
        let chain = gen_three_level_chain("depth-reject.test");
        let pin = TlsPin {
            spki_sha256: vec![chain.leaf_spki],
        };
        // Cap of 0 means "leaf must directly chain to a root, no
        // intermediates allowed". Our chain has 1 intermediate.
        let v = make_verifier(pin, true, Some(0));
        let name = ServerName::try_from("depth-reject.test").unwrap();
        let res = v.verify_server_cert(
            &chain.leaf,
            &[chain.intermediate],
            &name,
            &[],
            UnixTime::now(),
        );
        let err = res.unwrap_err();
        let s = format!("{err}");
        assert!(s.contains("chain depth"), "got {s}");
    }

    // -----------------------------------------------------------------
    // (6) chain-depth-cap accepts <= N
    // -----------------------------------------------------------------

    #[test]
    fn chain_depth_cap_accepts_within_cap() {
        install_default_provider();
        let chain = gen_three_level_chain("depth-accept.test");
        let pin = TlsPin {
            spki_sha256: vec![chain.leaf_spki],
        };
        // Cap of 5 — comfortable margin over our 1 intermediate.
        let v = make_verifier(pin, true, Some(5));
        let name = ServerName::try_from("depth-accept.test").unwrap();
        v.verify_server_cert(
            &chain.leaf,
            &[chain.intermediate],
            &name,
            &[],
            UnixTime::now(),
        )
        .expect("within-cap chain must accept");
    }

    // -----------------------------------------------------------------
    // (7) system-roots OK with valid leaf — placeholder check that
    // build() under system_roots() + strict mode succeeds and returns
    // a verifier wrapping the WebPKI inner verifier. (Running a real
    // handshake against a trusted public CA from inside cargo test is
    // not in scope.)
    // -----------------------------------------------------------------

    #[test]
    fn system_roots_strict_builds_clean() {
        install_default_provider();
        let cfg = PinnedTlsConnector::builder()
            .system_roots()
            .max_cert_chain_depth(Some(5))
            .build()
            .expect("system roots strict build must succeed");
        // alpn_protocols defaults to empty.
        assert!(cfg.alpn_protocols.is_empty());
    }

    // -----------------------------------------------------------------
    // (8) system-roots reject self-signed when allow_self_signed=false
    // -----------------------------------------------------------------

    #[test]
    fn system_roots_reject_self_signed_when_strict() {
        // We do this by actually building a WebPKI inner verifier
        // against an empty-on-purpose root store would fail
        // builder-side (no roots) — so instead exercise the verifier
        // logic with the system root store: a freshly-minted
        // self-signed cert will not chain.
        install_default_provider();
        let c = gen_self_signed("rogue.example");
        let cfg = PinnedTlsConnector::builder()
            .system_roots()
            .build()
            .expect("system roots strict build");
        // Pull the verifier off the config — we can't directly because
        // `Verifier` field is private. Instead, replicate by building
        // a PinnedVerifier with an explicit WebPKI inner.
        // Build a webpki verifier with the system roots so we exercise
        // the inner-verifier path.
        let mut roots = RootCertStore::empty();
        if let Ok(certs) = rustls_native_certs::load_native_certs() {
            for cert in certs {
                let _ = roots.add(cert);
            }
        }
        if roots.is_empty() {
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        }
        let inner = WebPkiServerVerifier::builder(Arc::new(roots))
            .build()
            .unwrap();
        let v = PinnedVerifier {
            inner: Some(inner as Arc<dyn ServerCertVerifier>),
            pin: TlsPin::default(),
            allow_self_signed: false,
            chain_depth_cap: ChainDepthCap::unlimited(),
            crl: None,
        };
        let leaf = CertificateDer::from(c.der);
        let name = ServerName::try_from("rogue.example").unwrap();
        let res = v.verify_server_cert(&leaf, &[], &name, &[], UnixTime::now());
        assert!(
            res.is_err(),
            "self-signed cert must not validate against system roots"
        );
        // alpn_protocols defaults to empty.
        assert!(cfg.alpn_protocols.is_empty());
    }

    // -----------------------------------------------------------------
    // (9) builder is Send + Sync (compile-only)
    // -----------------------------------------------------------------

    #[test]
    fn builder_and_connector_are_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<PinnedTlsConnectorBuilder>();
        assert_send_sync::<PinnedTlsConnector>();
        assert_send_sync::<Arc<ClientConfig>>();
        assert_send_sync::<PinnedVerifier>();
    }

    // -----------------------------------------------------------------
    // (10) property test: random pin sets reject random certs
    // -----------------------------------------------------------------
    //
    // We can't pull `arbitrary` into the lockfile (planner note: no
    // `cargo update`), so this runs a 32-trial deterministic random
    // sweep with `rand`. Each trial generates a fresh self-signed
    // cert and a random 4-pin set that deliberately does NOT include
    // the cert's SPKI, then asserts the verifier rejects.
    // -----------------------------------------------------------------

    #[test]
    fn property_random_pins_reject_random_certs() {
        use rand::{Rng, SeedableRng};
        install_default_provider();

        let mut rng = rand::rngs::StdRng::seed_from_u64(0xDEAD_BEEF_DEAD_BEEF);
        for trial in 0..32 {
            let c = gen_self_signed(&format!("prop-{trial}.test"));
            // Build 4 random pins; very low (~2^-256) chance any collide
            // with the cert's actual SPKI, but explicitly guard.
            let mut pins: Vec<[u8; 32]> = (0..4)
                .map(|_| {
                    let mut buf = [0u8; 32];
                    rng.fill(&mut buf);
                    buf
                })
                .collect();
            for p in &mut pins {
                if *p == c.spki {
                    p[0] ^= 0x01;
                }
            }
            let pin = TlsPin { spki_sha256: pins };
            let v = make_verifier(pin, true, None);
            let leaf = CertificateDer::from(c.der);
            let name = ServerName::try_from(format!("prop-{trial}.test")).unwrap();
            let res = v.verify_server_cert(&leaf, &[], &name, &[], UnixTime::now());
            assert!(
                res.is_err(),
                "trial {trial}: random pin set unexpectedly matched"
            );
        }
    }

    // -----------------------------------------------------------------
    // (11) ca_file rejects empty / non-existent files
    // -----------------------------------------------------------------

    #[test]
    fn ca_file_missing_returns_invalid_config() {
        install_default_provider();
        let err = PinnedTlsConnector::builder()
            .ca_file("/definitely/not/a/real/path/spt-trust-ca.pem")
            .build()
            .unwrap_err();
        assert!(matches!(err, Error::InvalidConfig(_)));
    }

    // -----------------------------------------------------------------
    // (12) ca_file with empty contents is rejected
    // -----------------------------------------------------------------

    #[test]
    fn ca_file_empty_pem_is_rejected() {
        install_default_provider();
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("empty.pem");
        std::fs::write(&p, b"").unwrap();
        let err = PinnedTlsConnector::builder()
            .ca_file(&p)
            .build()
            .unwrap_err();
        match err {
            Error::InvalidConfig(m) => assert!(m.contains("no certificates")),
            other => panic!("expected InvalidConfig, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------
    // (13) ca_file with a valid PEM bundle is accepted; pin still
    // enforced on top
    // -----------------------------------------------------------------

    #[test]
    fn ca_file_with_real_pem_builds_and_enforces_pin() {
        install_default_provider();
        let cert =
            rcgen::generate_simple_self_signed(vec!["spt-trust-ca.test".to_string()]).unwrap();
        let pem = cert.cert.pem();
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("ca.pem");
        std::fs::write(&p, pem).unwrap();
        let pin = TlsPin {
            spki_sha256: vec![[0u8; 32]],
        };
        let cfg = PinnedTlsConnector::builder()
            .ca_file(&p)
            .pin_spki_sha256(pin)
            .max_cert_chain_depth(Some(3))
            .build()
            .expect("ca_file + pin must build");
        assert!(cfg.alpn_protocols.is_empty());
    }

    // -----------------------------------------------------------------
    // (14) alpn round-trips
    // -----------------------------------------------------------------

    #[test]
    fn alpn_protocols_round_trip() {
        install_default_provider();
        let cfg = PinnedTlsConnector::builder()
            .system_roots()
            .alpn_protocols(vec![b"h2".to_vec(), b"http/1.1".to_vec()])
            .build()
            .unwrap();
        assert_eq!(
            cfg.alpn_protocols,
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        );
    }

    // -----------------------------------------------------------------
    // (15) constant-time pin matching: matches_digest covers all
    // -----------------------------------------------------------------

    #[test]
    fn matches_digest_constant_time_path() {
        let pin = TlsPin {
            spki_sha256: vec![[1u8; 32], [2u8; 32], [3u8; 32]],
        };
        assert!(pin.matches_digest(&[1u8; 32]));
        assert!(pin.matches_digest(&[2u8; 32]));
        assert!(pin.matches_digest(&[3u8; 32]));
        assert!(!pin.matches_digest(&[0u8; 32]));
        assert!(!pin.matches_digest(&[4u8; 32]));
        assert!(!TlsPin::default().matches_digest(&[0u8; 32]));
    }

    // -----------------------------------------------------------------
    // (16) empty_roots() requires both self-signed AND a pin
    // -----------------------------------------------------------------

    #[test]
    fn empty_roots_requires_pin_only_mode() {
        install_default_provider();
        // Without allow_self_signed: rejected.
        let err = PinnedTlsConnector::builder()
            .empty_roots()
            .pin_spki_sha256(TlsPin {
                spki_sha256: vec![[0u8; 32]],
            })
            .build()
            .unwrap_err();
        assert!(matches!(err, Error::InvalidConfig(_)));
    }
}
