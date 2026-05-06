//! Vault / keychain reachability placeholder.
//!
//! Concrete keychain probing lives in `spt-secrets` (t1-e4) but is gated
//! behind a runtime unlocked vault. The diagnostic crate cannot mutate the
//! vault, so we just declare the toolset and emit `Skipped`. t1-e18 wires
//! the real probe when an effective config exists.

use async_trait::async_trait;

use crate::check::{Check, Severity, Status};
use crate::framework::{Diagnostic, DiagnosticContext};

/// Vault / keychain readiness — placeholder.
#[derive(Default, Debug)]
pub struct VaultDiagnostic;

#[async_trait]
impl Diagnostic for VaultDiagnostic {
    fn group(&self) -> &str {
        "vault"
    }
    async fn run(&self, _ctx: &DiagnosticContext) -> Vec<Check> {
        vec![
            Check::new("vault.unlock", Severity::High, Status::Skipped)
                .with_evidence("vault probe deferred to t1-e18"),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn skipped_today() {
        let r = VaultDiagnostic.run(&DiagnosticContext::default()).await;
        assert_eq!(r[0].status, Status::Skipped);
    }
}
