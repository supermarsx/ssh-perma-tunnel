//! Host trust primitives: OpenSSH `known_hosts`, SHA-256 host pinning, and
//! TLS public-key (SPKI) pinning.
//!
//! Spec references: §9.13 (trust), §11 (per-attempt verification), §10.5
//! (split-horizon DNS does not bypass trust). All verification routines are
//! pure functions — no I/O beyond reading/writing the configured files —
//! and constant-time where they compare secret-equivalent material.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod chain_depth;
pub mod crl;
pub mod known_hosts;
pub mod pinned_connector;
pub mod sha256_pin;
pub mod tls_pin;

#[cfg(any(test, feature = "testing"))]
pub mod testing;

pub use chain_depth::{check_chain_depth, ChainDepthCap, DEFAULT_CHAIN_DEPTH_CAP};
pub use crl::{
    extract_crl_distribution_points, fetch_crl_bytes, normalize_serial, CrlCache, CrlError,
    CrlPolicy, RevocationStatus, DEFAULT_CRL_TTL,
};
pub use known_hosts::{KnownHosts, KnownHostsResult};
pub use pinned_connector::{PinnedTlsConnector, PinnedTlsConnectorBuilder};
pub use sha256_pin::Sha256HostPin;
pub use tls_pin::TlsPin;
