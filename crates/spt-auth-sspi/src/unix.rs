//! Unix GSSAPI backend.
//!
//! Wraps `cross-krb5 0.4` (which in turn wraps `libgssapi`) when that crate
//! is present in `Cargo.lock`. As shipped, it is not; the workspace `--locked`
//! + no-`cargo update` policy forces this entry point to return
//! [`crate::unsupported_backend`]. The full state-machine is exercised by the
//! mock provider in [`crate::mock`].
//!
//! NTLM is *not* supported on Unix even when `cross-krb5` is present —
//! callers requesting NTLM via [`crate::sspi_provider_for`] receive
//! [`spt_core::Error::AuthFailed`] with the `UnsupportedOnUnix` marker.

use spt_core::Result;

use crate::{unsupported_backend, GssApiConfig, GssProvider};

/// Real-backend entry point for [`crate::provider_for`].
///
/// Builds a `cross-krb5` initiator when the dependency is available. Today
/// the entry point unconditionally returns `UnsupportedBackend`.
pub fn build_kerberos(cfg: &GssApiConfig) -> Result<Box<dyn GssProvider>> {
    let _ = cfg;
    Err(unsupported_backend(
        "cross-krb5 0.4 not present in Cargo.lock; gssapi backend disabled",
    ))
}
