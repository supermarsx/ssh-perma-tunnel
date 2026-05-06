//! Aggregated secrets-subsystem health report.

use serde::{Deserialize, Serialize};

use crate::backend::{BackendDoctor, BackendStatus, SecretBackend};
use crate::resolver::Resolver;

/// Aggregated health report for the secrets subsystem.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretsDoctor {
    /// Per-backend records, in resolver chain order.
    pub backends: Vec<BackendDoctor>,
    /// Coarse overall status: `Ok` if all backends are `Ok`, `Degraded`
    /// if any are `Degraded`/`Unavailable` but at least one is `Ok`,
    /// `Unavailable` if every backend is `Unavailable`.
    pub status: BackendStatus,
}

impl SecretsDoctor {
    /// Build a [`SecretsDoctor`] by polling every backend in `resolver`.
    #[must_use]
    pub fn from_resolver(resolver: &Resolver) -> Self {
        let backends: Vec<BackendDoctor> = resolver.backends().map(SecretBackend::doctor).collect();
        let status = aggregate(&backends);
        Self { backends, status }
    }
}

fn aggregate(backends: &[BackendDoctor]) -> BackendStatus {
    let mut any_ok = false;
    let mut any_bad = false;
    for b in backends {
        match b.status {
            BackendStatus::Ok => any_ok = true,
            BackendStatus::Degraded | BackendStatus::Unavailable => any_bad = true,
        }
    }
    match (any_ok, any_bad) {
        (true, false) => BackendStatus::Ok,
        (true, true) => BackendStatus::Degraded,
        (false, _) => BackendStatus::Unavailable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::{BackendDoctor, BackendKind};

    #[test]
    fn aggregate_all_ok() {
        let bs = vec![
            BackendDoctor::ok(BackendKind::Keychain, ""),
            BackendDoctor::ok(BackendKind::Env, ""),
        ];
        assert!(matches!(aggregate(&bs), BackendStatus::Ok));
    }

    #[test]
    fn aggregate_mixed_is_degraded() {
        let bs = vec![
            BackendDoctor::ok(BackendKind::Env, ""),
            BackendDoctor::unavailable(BackendKind::Keychain, "x", "y"),
        ];
        assert!(matches!(aggregate(&bs), BackendStatus::Degraded));
    }

    #[test]
    fn aggregate_all_bad_is_unavailable() {
        let bs = vec![
            BackendDoctor::unavailable(BackendKind::Keychain, "x", "y"),
            BackendDoctor::degraded(BackendKind::Vault, "x", "y"),
        ];
        assert!(matches!(aggregate(&bs), BackendStatus::Unavailable));
    }

    #[test]
    fn aggregate_empty_is_unavailable() {
        assert!(matches!(aggregate(&[]), BackendStatus::Unavailable));
    }
}
