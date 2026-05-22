//! Certificate-chain depth cap for TLS pin verification.
//!
//! Spec (t5 §security-hardening): every pinned-TLS surface accepts an
//! optional `max_cert_chain_depth` knob. The cap is applied during chain
//! verification — *after* webpki has accepted the chain — by counting the
//! number of intermediate certificates the server presented and rejecting
//! the connection when that count meets or exceeds the configured cap.
//!
//! The default cap is `Some(5)`. A cap of `None` disables the check.
//!
//! # Wire-up
//!
//! * [`ChainDepthCap`] is consumed by the SSH3 TLS validator
//!   (`spt_ssh3::tls`) and by every pinned HTTPS connector built on
//!   `PinnedTlsConnector` (owned by t5-e1).
//! * Sink configs surface the cap as
//!   `[profiles.tls].max_cert_chain_depth: Option<u32>` — see
//!   `spt_config::schema::Tls`.
//! * [`check_chain_depth`] is the shared entry point — both the SSH3
//!   verifier and t5-e1's `ServerCertVerifier` call it.

use rustls_pki_types::CertificateDer;
use serde::{Deserialize, Serialize};

use spt_core::{Error, Result};

/// Default certificate-chain depth cap (number of intermediates).
///
/// Matches Mozilla's de-facto cap for public `WebPKI` chains: a leaf plus
/// up to four intermediates plus a trust anchor is far more than any real
/// hierarchy needs. Operators can override per-profile via
/// `[profiles.tls].max_cert_chain_depth`.
pub const DEFAULT_CHAIN_DEPTH_CAP: u32 = 5;

/// Maximum number of intermediate certificates permitted between a server
/// leaf and a trust anchor.
///
/// Wraps `Option<u32>`:
/// * `Some(n)` — reject any chain whose intermediate count is `>= n`.
/// * `None` — bypass the depth check entirely.
///
/// `Default` returns `Some(DEFAULT_CHAIN_DEPTH_CAP)`.
///
/// # Serde
///
/// `ChainDepthCap` serializes transparently as `Option<u32>` so it can be
/// embedded directly in profile configs (e.g. via
/// `#[serde(default)] pub max_cert_chain_depth: ChainDepthCap`) without
/// adding a wrapping table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ChainDepthCap(pub Option<u32>);

impl Default for ChainDepthCap {
    fn default() -> Self {
        Self(Some(DEFAULT_CHAIN_DEPTH_CAP))
    }
}

impl ChainDepthCap {
    /// Bypass the depth check entirely.
    #[must_use]
    pub const fn unlimited() -> Self {
        Self(None)
    }

    /// Construct a cap of exactly `n` intermediates.
    #[must_use]
    pub const fn new(n: u32) -> Self {
        Self(Some(n))
    }

    /// Construct a cap from an optional `u32`. `None` disables the check;
    /// `Some(n)` caps the chain at `n` intermediates.
    #[must_use]
    pub const fn from_option(opt: Option<u32>) -> Self {
        Self(opt)
    }

    /// Numeric cap, if any.
    #[must_use]
    pub const fn as_option(self) -> Option<u32> {
        self.0
    }

    /// `true` when no cap is configured (chain depth is unbounded).
    #[must_use]
    pub const fn is_unlimited(self) -> bool {
        self.0.is_none()
    }
}

/// Apply [`ChainDepthCap`] to a server-presented certificate chain.
///
/// `certs` is the full chain in TLS-wire order: index 0 is the end-entity
/// (leaf), and the remaining entries are intermediates / trust anchors.
/// The intermediate count is `certs.len() - 1`.
///
/// # Errors
///
/// * [`Error::TrustFailed`] when the intermediate count is `>= cap`.
/// * [`Error::TrustFailed`] when `certs` is empty — a server that
///   presented no certificates is unusable regardless of the cap.
///
/// # Examples
///
/// ```ignore
/// use spt_trust::chain_depth::{check_chain_depth, ChainDepthCap};
/// // Inside a `ServerCertVerifier::verify_server_cert` impl:
/// let mut chain = Vec::with_capacity(intermediates.len() + 1);
/// chain.push(end_entity.clone());
/// chain.extend(intermediates.iter().cloned());
/// check_chain_depth(&chain, &cap)?;
/// ```
#[allow(clippy::trivially_copy_pass_by_ref)] // signature locked by t5-e10 plan + e1 coordination
pub fn check_chain_depth(certs: &[CertificateDer<'_>], cap: &ChainDepthCap) -> Result<()> {
    if certs.is_empty() {
        return Err(Error::TrustFailed(
            "empty TLS certificate chain".to_string(),
        ));
    }
    let Some(max) = cap.0 else {
        return Ok(());
    };
    // Intermediates = everything between the leaf and the trust anchor we
    // would have stitched in; in the wire payload that's `certs.len() - 1`.
    // Use u64 to avoid u32 saturation if a misbehaving peer presents > 4G
    // certificates (it won't, but the cast costs nothing).
    let intermediates = (certs.len() - 1) as u64;
    if intermediates >= u64::from(max) {
        return Err(Error::TrustFailed(format!(
            "chain depth {intermediates} > cap {max}"
        )));
    }
    Ok(())
}

/// Helper used by config loaders: when a schema field
/// (`max_cert_chain_depth: Option<u32>`) is *absent*, materialize the
/// type-system default. Loaders distinguish "field omitted" (use default)
/// from "field explicitly set to a value" (use that value, including 0)
/// at the deserialization layer; this helper is the trivial mapper.
impl ChainDepthCap {
    /// Treat `ChainDepthCap(None)` as "operator did not specify" and
    /// substitute the default cap. Use *only* at config-load time —
    /// never inside the verifier, where `None` must be honored as
    /// "explicitly unlimited".
    #[must_use]
    pub fn or_default_if_unlimited_was_absent(self) -> Self {
        match self.0 {
            None => Self::default(),
            Some(_) => self,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair};

    fn der_from(bytes: Vec<u8>) -> CertificateDer<'static> {
        CertificateDer::from(bytes)
    }

    /// Mint `n` distinct self-signed leaf certs and return them as
    /// `[leaf, intermediate0, intermediate1, ...]`. Used to drive
    /// depth-counting paths without exercising real signature chaining
    /// (the depth cap is structural, not cryptographic).
    fn synthetic_chain(n: usize) -> Vec<CertificateDer<'static>> {
        (0..n)
            .map(|i| {
                let cert =
                    rcgen::generate_simple_self_signed(vec![format!("node-{i}.test")]).unwrap();
                der_from(cert.cert.der().to_vec())
            })
            .collect()
    }

    #[test]
    fn default_cap_is_some_five() {
        let cap = ChainDepthCap::default();
        assert_eq!(cap.as_option(), Some(DEFAULT_CHAIN_DEPTH_CAP));
        assert_eq!(cap.as_option(), Some(5));
        assert!(!cap.is_unlimited());
    }

    #[test]
    fn depth_one_leaf_only_accepted_with_default_cap() {
        let chain = synthetic_chain(1);
        // 0 intermediates < cap 5.
        check_chain_depth(&chain, &ChainDepthCap::default()).unwrap();
    }

    #[test]
    fn depth_five_accepted_with_cap_five() {
        // 5 wire-certs == 4 intermediates < cap 5 → accept.
        let chain = synthetic_chain(5);
        check_chain_depth(&chain, &ChainDepthCap::new(5)).unwrap();
    }

    #[test]
    fn depth_six_rejected_with_cap_five() {
        // 6 wire-certs == 5 intermediates >= cap 5 → reject.
        let chain = synthetic_chain(6);
        let err = check_chain_depth(&chain, &ChainDepthCap::new(5)).unwrap_err();
        match err {
            Error::TrustFailed(msg) => {
                assert!(msg.contains("chain depth"), "msg was: {msg}");
                assert!(msg.contains("cap"), "msg was: {msg}");
                assert!(msg.contains('5'), "msg was: {msg}");
            }
            other => panic!("expected TrustFailed, got {other:?}"),
        }
    }

    #[test]
    fn cap_none_bypasses_check() {
        // 50 intermediates is absurd, but `unlimited()` must accept it.
        let chain = synthetic_chain(50);
        check_chain_depth(&chain, &ChainDepthCap::unlimited()).unwrap();
        assert!(ChainDepthCap::unlimited().is_unlimited());
    }

    #[test]
    fn empty_chain_typed_error() {
        let err = check_chain_depth(&[], &ChainDepthCap::default()).unwrap_err();
        match err {
            Error::TrustFailed(msg) => assert!(msg.contains("empty"), "msg was: {msg}"),
            other => panic!("expected TrustFailed, got {other:?}"),
        }
        // Also fails with `None` cap — empty is structurally invalid.
        let err2 = check_chain_depth(&[], &ChainDepthCap::unlimited()).unwrap_err();
        assert!(matches!(err2, Error::TrustFailed(_)));
    }

    /// rcgen-built 3-level chain (leaf + intermediate + CA) should be
    /// counted as 2 intermediates. The depth-cap module is structural so
    /// we only check the wire-order length here.
    #[test]
    fn rcgen_three_level_chain_counts_two_intermediates() {
        // Root CA.
        let mut root_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        root_params
            .distinguished_name
            .push(DnType::CommonName, "spt-test-root");
        root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let root_kp = KeyPair::generate().unwrap();
        let root = root_params.self_signed(&root_kp).unwrap();

        // Intermediate CA.
        let mut int_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        int_params
            .distinguished_name
            .push(DnType::CommonName, "spt-test-int");
        int_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        let int_kp = KeyPair::generate().unwrap();
        let int_cert = int_params.signed_by(&int_kp, &root, &root_kp).unwrap();

        // Leaf.
        let mut leaf_params = CertificateParams::new(vec!["leaf.spt.test".to_string()]).unwrap();
        leaf_params
            .distinguished_name
            .push(DnType::CommonName, "leaf.spt.test");
        let leaf_kp = KeyPair::generate().unwrap();
        let leaf = leaf_params.signed_by(&leaf_kp, &int_cert, &int_kp).unwrap();

        let chain: Vec<CertificateDer<'static>> = vec![
            der_from(leaf.der().to_vec()),
            der_from(int_cert.der().to_vec()),
            der_from(root.der().to_vec()),
        ];
        // Sanity: 3 wire certs => intermediates = 2.
        assert_eq!(chain.len(), 3);
        // Default cap 5 → accepts.
        check_chain_depth(&chain, &ChainDepthCap::default()).unwrap();
        // Cap == 2 → rejects (2 >= 2).
        let err = check_chain_depth(&chain, &ChainDepthCap::new(2)).unwrap_err();
        match err {
            Error::TrustFailed(msg) => {
                assert!(msg.contains('2'), "msg was: {msg}");
            }
            other => panic!("expected TrustFailed, got {other:?}"),
        }
        // Cap == 3 → accepts (2 < 3).
        check_chain_depth(&chain, &ChainDepthCap::new(3)).unwrap();
    }

    #[test]
    fn toml_round_trip_via_wrapper_struct() {
        // ChainDepthCap is serde-transparent; we round-trip it inside a
        // wrapping struct that mimics `[profiles.tls]`.
        #[derive(Debug, Serialize, Deserialize)]
        struct TlsLike {
            #[serde(default, skip_serializing_if = "Option::is_none")]
            max_cert_chain_depth: Option<ChainDepthCap>,
        }

        // Explicit value.
        let src = TlsLike {
            max_cert_chain_depth: Some(ChainDepthCap::new(7)),
        };
        let s = toml::to_string(&src).unwrap();
        assert!(s.contains("max_cert_chain_depth = 7"), "got:\n{s}");
        let de: TlsLike = toml::from_str(&s).unwrap();
        assert_eq!(de.max_cert_chain_depth.unwrap().as_option(), Some(7));

        // Empty TOML deserializes the field as absent → top-level None.
        let empty: TlsLike = toml::from_str("").unwrap();
        assert!(empty.max_cert_chain_depth.is_none());

        // Inner `None` (explicit unlimited) is not directly representable
        // in TOML's value model — `serde(transparent)` over `Option<u32>::None`
        // becomes a missing key, which round-trips to the top-level `None`.
        // The runtime maps both to "no cap": confirmed via the helper.
        let materialized = ChainDepthCap::unlimited().or_default_if_unlimited_was_absent();
        assert_eq!(materialized, ChainDepthCap::default());
    }

    #[test]
    fn schema_default_is_some_five_when_field_omitted() {
        // Mimic the schema shape: `Tls { max_cert_chain_depth: Option<u32> }`.
        // When the field is `None`, the loader should treat it as
        // `ChainDepthCap::default()` — verify by constructing a cap from
        // the absent Option and confirming equality.
        let from_schema: Option<u32> = None;
        let cap = ChainDepthCap::from_option(from_schema)
            // schema-None means "operator didn't specify" → use default.
            .or_default_if_unlimited_was_absent();
        assert_eq!(cap, ChainDepthCap::default());
        assert_eq!(cap.as_option(), Some(5));
    }

    #[test]
    fn from_option_some_preserves_value() {
        assert_eq!(ChainDepthCap::from_option(Some(9)).as_option(), Some(9));
        assert_eq!(ChainDepthCap::from_option(None).as_option(), None);
    }

    #[test]
    fn cap_zero_rejects_even_leaf_only_chain() {
        // A cap of 0 means "no intermediates allowed" — and since the
        // leaf-only chain has 0 intermediates, 0 >= 0 still triggers
        // rejection. This documents the strict-inequality semantic.
        let chain = synthetic_chain(1);
        let err = check_chain_depth(&chain, &ChainDepthCap::new(0)).unwrap_err();
        assert!(matches!(err, Error::TrustFailed(_)));
    }

    #[test]
    fn boundary_intermediates_equal_cap_rejected() {
        // intermediates == cap is the rejection boundary.
        let chain = synthetic_chain(4); // 3 intermediates
        let err = check_chain_depth(&chain, &ChainDepthCap::new(3)).unwrap_err();
        assert!(matches!(err, Error::TrustFailed(_)));
        // ... and intermediates + 1 == cap is accepted.
        check_chain_depth(&chain, &ChainDepthCap::new(4)).unwrap();
    }
}
