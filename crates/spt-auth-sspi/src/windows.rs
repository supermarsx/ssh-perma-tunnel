//! Windows SSPI backend.
//!
//! The intended implementation prefers `sspi 0.15` (MSRV 1.83) and falls back
//! to `sspi 0.14` if the newer release requires a higher toolchain. Both
//! versions are absent from `Cargo.lock` at the time this crate landed
//! (workspace policy forbids `cargo update`), so the live entry point
//! [`build`] degrades to [`crate::unsupported_backend`].
//!
//! Adding the dependency is a one-line workspace change plus enabling the
//! relevant `Kerberos` / `Ntlm` SSPI packages here. The full dispatch
//! state-machine is already exercised by [`crate::mock::MockGssProvider`].

use spt_core::Result;

use crate::{unsupported_backend, GssProvider, SspiConfig};

/// Real-backend entry point for [`crate::sspi_provider_for`].
///
/// When `sspi` lands in the lockfile this function selects the SSPI package
/// (`Kerberos` first; `Ntlm` second when `allow_ntlm_fallback`) and wraps it
/// in a [`GssProvider`]. Until then it returns `UnsupportedBackend` with a
/// note identifying which sspi version range was attempted.
pub fn build(cfg: &SspiConfig) -> Result<Box<dyn GssProvider>> {
    let _ = cfg;
    // Fallback chain: `sspi 0.15` → `sspi 0.14` → UnsupportedBackend. Both
    // upstream versions are absent from the workspace lockfile, so the chain
    // collapses to its final element until that is corrected.
    Err(unsupported_backend(
        "sspi crate (0.15 / 0.14) not present in Cargo.lock; SSPI backend disabled",
    ))
}
