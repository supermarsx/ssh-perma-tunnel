//! Thin wrapper that pulls policy values from the registry (or substitutes an
//! empty bundle on non-Windows) and runs the pure
//! [`spt_config::PolicyOverlay`] driver.
//!
//! Failure to read the registry is logged and treated as "no policy present"
//! — Group Policy is advisory infrastructure, not a hard runtime dependency.

use spt_config::{Config, OverlayReport, PolicyBundle, PolicyOverlay};

use crate::policy::registry;

/// Read the live policy bundle from the registry and overlay it onto `cfg`.
///
/// On non-Windows platforms the registry layer always returns an empty bundle,
/// so this becomes an inexpensive no-op.
pub fn apply(cfg: &mut Config) -> OverlayReport {
    let bundle = match registry::load() {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(error = %e, "failed to read GPO registry; continuing without overlay");
            PolicyBundle::empty()
        }
    };
    apply_with(cfg, &bundle)
}

/// Apply a pre-loaded bundle. Exposed for tests and for callers that want to
/// log or audit the bundle before merging.
pub fn apply_with(cfg: &mut Config, bundle: &PolicyBundle) -> OverlayReport {
    let report = PolicyOverlay::apply(cfg, bundle);
    if !report.applied.is_empty() {
        tracing::info!(
            applied = ?report.applied,
            locked = ?report.locked,
            unknown = ?report.unknown,
            type_mismatch = ?report.type_mismatch,
            "applied Group Policy overlay",
        );
    }
    report
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apply_with_empty_bundle_is_noop() {
        let mut cfg = Config::default();
        let r = apply_with(&mut cfg, &PolicyBundle::empty());
        assert!(r.applied.is_empty());
        assert_eq!(cfg, Config::default());
    }
}
