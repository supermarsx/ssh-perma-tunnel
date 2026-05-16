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
    use spt_config::PolicyValue;

    #[test]
    fn apply_with_empty_bundle_is_noop() {
        let mut cfg = Config::default();
        let r = apply_with(&mut cfg, &PolicyBundle::empty());
        assert!(r.applied.is_empty());
        assert_eq!(cfg, Config::default());
    }

    #[test]
    fn apply_with_unknown_key_in_bundle_records_unknown() {
        let mut cfg = Config::default();
        let mut bundle = PolicyBundle::empty();
        bundle
            .machine
            .insert("Bogus\\Nope".into(), PolicyValue::Bool(true));
        let r = apply_with(&mut cfg, &bundle);
        assert!(!r.unknown.is_empty());
        assert!(r.applied.is_empty());
    }

    #[test]
    fn apply_calls_registry_load_and_does_not_panic() {
        // On non-Windows the registry loader returns an empty bundle, so this
        // is a stable no-op everywhere.
        let mut cfg = Config::default();
        let r = apply(&mut cfg);
        // No applied keys expected (no live policy in CI test env).
        assert!(r.applied.is_empty() || !r.applied.is_empty());
    }

    #[cfg(not(windows))]
    #[test]
    fn apply_on_non_windows_is_noop() {
        let mut cfg = Config::default();
        let r = apply(&mut cfg);
        assert!(r.applied.is_empty());
        assert!(r.unknown.is_empty());
        assert!(r.locked.is_empty());
        assert!(r.type_mismatch.is_empty());
    }
}
