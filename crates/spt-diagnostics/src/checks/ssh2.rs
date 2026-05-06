//! SSH2 toolset readiness placeholder.
//!
//! Real libssh2 version + crypto policy probing requires `spt-ssh2` linkage,
//! which is owned by t1-e10. Until then we emit `Skipped` so the framework
//! shape is exercised and the report covers the toolset enumerated in
//! spec §13.12.

use async_trait::async_trait;

use crate::check::{Check, Severity, Status};
use crate::framework::{Diagnostic, DiagnosticContext};

/// Stub: declares the diagnostic group exists.
#[derive(Default, Debug)]
pub struct Ssh2Diagnostic;

#[async_trait]
impl Diagnostic for Ssh2Diagnostic {
    fn group(&self) -> &str {
        "ssh2"
    }
    async fn run(&self, _ctx: &DiagnosticContext) -> Vec<Check> {
        vec![
            Check::new("ssh2.libssh2_version", Severity::Info, Status::Skipped)
                .with_evidence("ssh2 backend probe not yet wired (deferred to t1-e18)")
                .with_remediation("run `spt key fingerprint` after the binary is wired"),
            Check::new("ssh2.crypto_policy", Severity::Low, Status::Skipped)
                .with_evidence("crypto policy enforcement validated at connect time"),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn skipped_today() {
        let r = Ssh2Diagnostic.run(&DiagnosticContext::default()).await;
        assert!(r.iter().all(|c| c.status == Status::Skipped));
    }
}
