//! Certificate Revocation List (CRL) parsing and in-memory cache.
//!
//! Surfaces the missing piece called out by A6 in
//! `pinned_connector.rs:232-238`: today, operators must rotate pinned
//! SPKIs to revoke a leaf. This module gives the `PinnedVerifier`
//! (see `pinned_connector`) an offline lookup against pre-fetched CRLs
//! so a revoked-but-still-pinned cert can be rejected before the
//! handshake completes.
//!
//! ## Design
//!
//! `rustls`' `ServerCertVerifier` callback is **synchronous**. Doing
//! network I/O from inside it is either unsafe (`block_on` inside an
//! async runtime panics or deadlocks) or expensive (a fresh blocking
//! runtime per handshake). The cache therefore holds *already-parsed*
//! CRLs by issuer DN. Fetching is pushed out to
//! [`crate::pinned_connector::PinnedTlsConnectorBuilder::prefetch_crls`]
//! which runs async/await once at startup. The verifier consults the
//! cache in O(log n) and never touches the network.
//!
//! ## What gets checked
//!
//! For each leaf certificate:
//!
//! 1. Pull the leaf's `CRLDistributionPoints` extension (RFC 5280
//!    §4.2.1.13). If absent, CRL consultation is skipped — vacuously
//!    "not revoked" because no issuer told us to check anywhere.
//! 2. Look up cached CRL(s) by the *issuer DN* (DER-encoded for
//!    stable, byte-exact matching).
//! 3. Iterate revoked-serials and constant-time compare against the
//!    leaf's serial.
//!
//! ## Policy
//!
//! [`CrlPolicy`] decides what happens when the leaf names CRL DPs but
//! no cached CRL is present (fetch failed, never wired, etc.):
//!
//! - [`CrlPolicy::Disabled`] — the default. CRL state is never
//!   consulted; preserves existing behaviour for callers that have not
//!   opted in.
//! - [`CrlPolicy::Soft`] — log a warning and accept the chain (high-
//!   availability mode for flaky CRL endpoints).
//! - [`CrlPolicy::Hard`] — fail closed: missing CRL = revoked-equivalent.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use subtle::ConstantTimeEq;
use x509_parser::extensions::{DistributionPointName, GeneralName, ParsedExtension};
use x509_parser::oid_registry::OID_X509_EXT_CRL_DISTRIBUTION_POINTS;
use x509_parser::prelude::*;

/// Default TTL when a CRL omits the `nextUpdate` field (RFC 5280 §5.1).
///
/// 24 hours matches public-PKI guidance for short-lived CRLs and keeps
/// stale revocation windows bounded.
pub const DEFAULT_CRL_TTL: Duration = Duration::from_secs(24 * 60 * 60);

/// Operator-facing policy for what to do when the leaf names CRL
/// distribution points but the cache cannot answer authoritatively.
///
/// Defaults to [`Disabled`](Self::Disabled) so opting in is explicit
/// and existing trust paths remain unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CrlPolicy {
    /// CRL consultation is off. The pin / `WebPKI` / chain-depth checks
    /// behave exactly as before this module existed. This is the
    /// default — adopters must opt in.
    #[default]
    Disabled,
    /// Consult the CRL cache. If the leaf names DPs but no fresh CRL
    /// covers them, log a warning at `tracing::warn` level and accept
    /// the chain. Intended for high-availability deployments where
    /// the CRL endpoint is allowed to be flaky.
    Soft,
    /// Consult the CRL cache. If the leaf names DPs but no fresh CRL
    /// covers them, reject the chain. Fail-closed: the recommended
    /// posture for security-sensitive surfaces.
    Hard,
}

impl CrlPolicy {
    /// `true` when the verifier should actually look at the cache.
    #[must_use]
    pub fn enabled(self) -> bool {
        !matches!(self, Self::Disabled)
    }
}

/// One parsed-and-cached CRL, keyed elsewhere by issuer DN.
#[derive(Debug, Clone)]
struct CachedCrl {
    /// Original CRL DER. Kept so verifier-time checks can bind the
    /// cached revocation data to the issuer certificate that WebPKI or
    /// pinning just accepted.
    der: Vec<u8>,
    /// Revoked serials (big-endian bytes, leading zeros stripped to
    /// match `x509_parser`'s `BigUint::to_bytes_be()` output).
    revoked_serials: Vec<Vec<u8>>,
    /// When the CRL bytes were ingested (used to bound staleness when
    /// `next_update` is absent).
    fetched_at: SystemTime,
    /// `tbsCertList.nextUpdate` if present; otherwise `None` and the
    /// cache falls back to [`DEFAULT_CRL_TTL`] after `fetched_at`.
    next_update: Option<SystemTime>,
}

impl CachedCrl {
    fn is_fresh(&self, now: SystemTime) -> bool {
        match self.next_update {
            Some(nu) => now <= nu,
            None => match now.duration_since(self.fetched_at) {
                Ok(d) => d <= DEFAULT_CRL_TTL,
                Err(_) => true, // clock skew: be lenient, treat as fresh
            },
        }
    }
}

/// Errors arising from CRL parsing or lookup.
#[derive(Debug, thiserror::Error)]
pub enum CrlError {
    /// DER parsing of the CRL bytes failed.
    #[error("CRL parse error: {0}")]
    Parse(String),
    /// HTTP fetch of a distribution point failed.
    #[error("CRL fetch error: {0}")]
    Fetch(String),
    /// HTTP returned a non-2xx status.
    #[error("CRL fetch status {0}")]
    HttpStatus(u16),
}

/// Thread-safe in-memory CRL cache, indexed by DER-encoded issuer
/// distinguished name.
///
/// The cache is **append/refresh-only**: callers populate it before
/// the rustls verifier runs, typically through
/// [`crate::pinned_connector::PinnedTlsConnectorBuilder::prefetch_crls`]
/// or [`Self::insert_der`]. The verifier then queries
/// [`Self::is_revoked`] synchronously.
#[derive(Debug, Default)]
pub struct CrlCache {
    /// Map from DER-encoded issuer-DN bytes to the latest CRL for
    /// that issuer. Wrapped in a `Mutex` so prefetch + verify can run
    /// concurrently from different threads.
    entries: Mutex<HashMap<Vec<u8>, CachedCrl>>,
}

impl CrlCache {
    /// Empty cache. Use [`Self::insert_der`] or
    /// `PinnedTlsConnectorBuilder::prefetch_crls` to populate.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Parse CRL DER bytes and store under the issuer DN extracted
    /// from the CRL itself.
    ///
    /// Returns the issuer-DN bytes on success so callers can correlate
    /// with the cert chain.
    pub fn insert_der(&self, der: &[u8]) -> Result<Vec<u8>, CrlError> {
        let (_, crl) = CertificateRevocationList::from_der(der)
            .map_err(|e| CrlError::Parse(format!("from_der: {e}")))?;

        // Issuer DN: use the raw DER bytes so byte-exact lookup
        // against `X509Certificate::issuer().as_raw()` works without
        // needing a textual-equivalence comparator.
        let issuer_dn = crl.issuer().as_raw().to_vec();

        let revoked_serials = crl
            .iter_revoked_certificates()
            .map(|r| r.user_certificate.to_bytes_be())
            .collect();

        let next_update = crl.next_update().and_then(asn1_to_system_time);

        let entry = CachedCrl {
            der: der.to_vec(),
            revoked_serials,
            fetched_at: SystemTime::now(),
            next_update,
        };

        let mut guard = self
            .entries
            .lock()
            .map_err(|_| CrlError::Parse("CrlCache mutex poisoned".into()))?;
        guard.insert(issuer_dn.clone(), entry);
        Ok(issuer_dn)
    }

    /// Synchronously decide whether `serial` under `issuer_dn` is
    /// listed in any cached CRL.
    ///
    /// Returns:
    /// - `Ok(true)` — serial is on a fresh CRL for this issuer.
    /// - `Ok(false)` — no fresh CRL covers this issuer, OR the CRL
    ///   does not list this serial. The caller (policy code in
    ///   `pinned_connector`) decides what to do with "no fresh CRL"
    ///   based on [`CrlPolicy`].
    ///
    /// `serial` should be the big-endian byte representation with
    /// leading zeros stripped — match what `x509_parser` produces from
    /// `BigUint::to_bytes_be()`. The helper
    /// [`normalize_serial`] does this for raw-tag serial bytes.
    ///
    /// # Errors
    ///
    /// Returns `Err` only on internal lock poisoning; lookup itself
    /// is infallible.
    pub fn is_revoked(
        &self,
        issuer_dn: &[u8],
        serial: &[u8],
    ) -> Result<RevocationStatus, CrlError> {
        let guard = self
            .entries
            .lock()
            .map_err(|_| CrlError::Parse("CrlCache mutex poisoned".into()))?;
        let Some(entry) = guard.get(issuer_dn) else {
            return Ok(RevocationStatus::NoCrl);
        };
        if !entry.is_fresh(SystemTime::now()) {
            return Ok(RevocationStatus::Stale);
        }
        Ok(revocation_status_from_entry(entry, serial))
    }

    /// Like [`Self::is_revoked`], but first proves the cached CRL was
    /// issued by `issuer_cert`: the CRL issuer DN must match the
    /// certificate subject DN, the issuer certificate must carry the
    /// RFC 5280 `cRLSign` key usage, and the CRL signature must verify
    /// against the issuer public key.
    pub fn is_revoked_by_issuer_cert(
        &self,
        issuer_cert: &X509Certificate<'_>,
        serial: &[u8],
    ) -> Result<RevocationStatus, CrlError> {
        let issuer_dn = issuer_cert.subject().as_raw();
        let entry = {
            let guard = self
                .entries
                .lock()
                .map_err(|_| CrlError::Parse("CrlCache mutex poisoned".into()))?;
            let Some(entry) = guard.get(issuer_dn) else {
                return Ok(RevocationStatus::NoCrl);
            };
            entry.clone()
        };

        if !entry.is_fresh(SystemTime::now()) {
            return Ok(RevocationStatus::Stale);
        }

        validate_crl_authority(&entry.der, issuer_cert)?;
        Ok(revocation_status_from_entry(&entry, serial))
    }

    /// Number of issuers currently cached. Test helper.
    #[doc(hidden)]
    #[must_use]
    pub fn issuer_count(&self) -> usize {
        self.entries.lock().map(|g| g.len()).unwrap_or(0)
    }
}

fn revocation_status_from_entry(entry: &CachedCrl, serial: &[u8]) -> RevocationStatus {
    let normalized = normalize_serial(serial);
    let needle = normalized.as_slice();
    for s in &entry.revoked_serials {
        // Constant-time per-serial to avoid leaking which serial
        // matched (defensive — the entire revocation list is
        // public, but constant-time bytewise compare is cheap and
        // matches the rest of this crate's hygiene).
        if s.len() == needle.len() && s.ct_eq(needle).into() {
            return RevocationStatus::Revoked;
        }
    }
    RevocationStatus::NotRevoked
}

fn validate_crl_authority(der: &[u8], issuer_cert: &X509Certificate<'_>) -> Result<(), CrlError> {
    let (_, crl) = CertificateRevocationList::from_der(der)
        .map_err(|e| CrlError::Parse(format!("from_der: {e}")))?;

    if crl.issuer().as_raw() != issuer_cert.subject().as_raw() {
        return Err(CrlError::Parse(
            "CRL issuer does not match certificate issuer subject".into(),
        ));
    }

    let key_usage = issuer_cert
        .key_usage()
        .map_err(|e| CrlError::Parse(format!("issuer key usage: {e}")))?
        .ok_or_else(|| CrlError::Parse("issuer certificate lacks keyUsage cRLSign".into()))?;
    if !key_usage.value.crl_sign() {
        return Err(CrlError::Parse(
            "issuer certificate is not authorized for cRLSign".into(),
        ));
    }

    crl.verify_signature(&issuer_cert.tbs_certificate.subject_pki)
        .map_err(|e| CrlError::Parse(format!("CRL signature verification failed: {e}")))
}

/// Outcome of a [`CrlCache::is_revoked`] lookup. The verifier in
/// `pinned_connector` translates this into accept / reject using the
/// configured [`CrlPolicy`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevocationStatus {
    /// Issuer is known to the cache, CRL is fresh, and the serial is
    /// listed as revoked.
    Revoked,
    /// Issuer is known to the cache, CRL is fresh, and the serial is
    /// NOT listed.
    NotRevoked,
    /// No CRL is cached for this issuer at all.
    NoCrl,
    /// A CRL is cached but past its `nextUpdate` (or the default
    /// TTL when `nextUpdate` is absent).
    Stale,
}

/// Strip leading zero bytes so byte-by-byte comparison with
/// `BigUint::to_bytes_be()`-style serials succeeds. ASN.1 INTEGER
/// encodings can carry a leading 0x00 to keep the value positive; this
/// helper removes that padding while preserving a single zero for the
/// `serial == 0` edge case (which never happens in practice).
#[must_use]
pub fn normalize_serial(serial: &[u8]) -> Vec<u8> {
    let mut idx = 0;
    while idx + 1 < serial.len() && serial[idx] == 0 {
        idx += 1;
    }
    serial[idx..].to_vec()
}

/// Extract `http://...` / `https://...` CRL distribution point URIs
/// from an X.509 certificate. Returns empty if the extension is
/// absent or carries only non-URI `GeneralName`s (e.g. directoryName).
#[must_use]
pub fn extract_crl_distribution_points(cert: &X509Certificate<'_>) -> Vec<String> {
    let Some(ext) = cert
        .extensions()
        .iter()
        .find(|e| e.oid == OID_X509_EXT_CRL_DISTRIBUTION_POINTS)
    else {
        return Vec::new();
    };
    let ParsedExtension::CRLDistributionPoints(dps) = ext.parsed_extension() else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for dp in &dps.points {
        let Some(name) = &dp.distribution_point else {
            continue;
        };
        let DistributionPointName::FullName(names) = name else {
            continue;
        };
        for gn in names {
            if let GeneralName::URI(uri) = gn {
                let uri = (*uri).to_string();
                if uri.starts_with("http://") || uri.starts_with("https://") {
                    out.push(uri);
                }
            }
        }
    }
    out
}

/// Convert an `ASN1Time` to `SystemTime`. Returns `None` when the
/// underlying timestamp is outside `SystemTime`'s representable range
/// (would only happen for nonsense or far-future CRLs).
fn asn1_to_system_time(t: ASN1Time) -> Option<SystemTime> {
    let unix = t.timestamp();
    if unix < 0 {
        return None;
    }
    let secs = u64::try_from(unix).ok()?;
    SystemTime::UNIX_EPOCH.checked_add(Duration::from_secs(secs))
}

/// Async helper: fetch one CRL via `reqwest` and return the raw DER
/// bytes. Used by `PinnedTlsConnectorBuilder::prefetch_crls`; kept
/// public so operators with custom transport (proxy, mTLS to CRL
/// endpoint) can reuse the verifier-side cache directly.
///
/// `reqwest` is already a workspace dependency (it powers
/// remote-config + OTLP fetchers), so wiring it here adds zero
/// transitive crates.
pub async fn fetch_crl_bytes(url: &str) -> Result<Vec<u8>, CrlError> {
    let resp = reqwest::get(url)
        .await
        .map_err(|e| CrlError::Fetch(format!("{url}: {e}")))?;
    let status = resp.status();
    if !status.is_success() {
        return Err(CrlError::HttpStatus(status.as_u16()));
    }
    let bytes = resp
        .bytes()
        .await
        .map_err(|e| CrlError::Fetch(format!("{url} body: {e}")))?;
    Ok(bytes.to_vec())
}

/// Shared handle wrapper used by the verifier. Exists so the verifier
/// can hold a single `Arc<CrlCacheHandle>` rather than `Arc<CrlCache>`
/// + `CrlPolicy` separately, keeping the lookup site terse.
#[derive(Debug, Clone)]
pub(crate) struct CrlCacheHandle {
    pub(crate) cache: Arc<CrlCache>,
    pub(crate) policy: CrlPolicy,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `normalize_serial` strips a single leading 0x00 (the ASN.1
    /// positive-INTEGER pad) but preserves a sole zero byte.
    #[test]
    fn normalize_serial_strips_leading_pad() {
        assert_eq!(normalize_serial(&[0x00, 0x01, 0x02]), vec![0x01, 0x02]);
        assert_eq!(
            normalize_serial(&[0x01, 0x02, 0x03]),
            vec![0x01, 0x02, 0x03]
        );
        assert_eq!(normalize_serial(&[0x00]), vec![0x00]);
        assert_eq!(normalize_serial(&[]), Vec::<u8>::new());
    }

    #[test]
    fn crl_policy_default_is_disabled() {
        assert_eq!(CrlPolicy::default(), CrlPolicy::Disabled);
        assert!(!CrlPolicy::default().enabled());
        assert!(CrlPolicy::Soft.enabled());
        assert!(CrlPolicy::Hard.enabled());
    }

    #[test]
    fn empty_cache_reports_no_crl() {
        let cache = CrlCache::new();
        let r = cache.is_revoked(b"any-issuer", &[1, 2, 3]).unwrap();
        assert_eq!(r, RevocationStatus::NoCrl);
    }
}
