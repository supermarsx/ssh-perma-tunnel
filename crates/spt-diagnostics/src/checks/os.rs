//! OS / kernel basics.

use async_trait::async_trait;

use crate::check::{Check, Severity, Status};
use crate::framework::{Diagnostic, DiagnosticContext};

/// Reports OS family + arch as a passing info check. Always Pass — the
/// purpose is to put this metadata into the bundle.
#[derive(Default, Debug)]
pub struct OsDiagnostic;

#[async_trait]
impl Diagnostic for OsDiagnostic {
    fn group(&self) -> &'static str {
        "os"
    }
    async fn run(&self, _ctx: &DiagnosticContext) -> Vec<Check> {
        vec![Check::new("os.family", Severity::Info, Status::Pass)
            .with_evidence(format!("os = {}", std::env::consts::OS))
            .with_evidence(format!("family = {}", std::env::consts::FAMILY))
            .with_evidence(format!("arch = {}", std::env::consts::ARCH))]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn always_pass() {
        let r = OsDiagnostic.run(&DiagnosticContext::default()).await;
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].status, Status::Pass);
        assert!(r[0].evidence.iter().any(|e| e.starts_with("os = ")));
    }
}
