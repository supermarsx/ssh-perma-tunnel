//! Permission / state-dir writability checks.

use async_trait::async_trait;

use crate::check::{Check, Severity, Status};
use crate::framework::{Diagnostic, DiagnosticContext};

/// Verifies the configured state directory is writable. Privileged-port and
/// Linux-cap checks are deferred to t1-e18 wiring (need spt-net/caps glue).
#[derive(Default, Debug)]
pub struct PermissionsDiagnostic;

#[async_trait]
impl Diagnostic for PermissionsDiagnostic {
    fn group(&self) -> &'static str {
        "permissions"
    }
    async fn run(&self, ctx: &DiagnosticContext) -> Vec<Check> {
        let Some(state_dir) = ctx.state_dir.as_ref() else {
            return vec![Check::new(
                "permissions.state_dir_writable",
                Severity::Medium,
                Status::Skipped,
            )
            .with_evidence("no state directory configured")
            .with_remediation("set `runtime.state_dir`")];
        };

        let probe = state_dir.join(".diagnose-write-probe");
        match std::fs::write(&probe, b"ok") {
            Ok(()) => {
                let _ = std::fs::remove_file(&probe);
                vec![Check::new(
                    "permissions.state_dir_writable",
                    Severity::Medium,
                    Status::Pass,
                )
                .with_evidence(format!("wrote and removed {}", probe.display()))]
            }
            Err(e) => vec![Check::new(
                "permissions.state_dir_writable",
                Severity::Critical,
                Status::Fail,
            )
            .with_evidence(format!("write to {} failed: {e}", probe.display()))
            .with_remediation("ensure the runtime user owns the state directory")],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn writable_state_dir_passes() {
        let d = tempdir().unwrap();
        let ctx = DiagnosticContext {
            state_dir: Some(d.path().to_owned()),
            ..Default::default()
        };
        let r = PermissionsDiagnostic.run(&ctx).await;
        assert_eq!(r[0].status, Status::Pass);
    }

    #[tokio::test]
    async fn no_state_dir_skips() {
        let r = PermissionsDiagnostic
            .run(&DiagnosticContext::default())
            .await;
        assert_eq!(r[0].status, Status::Skipped);
    }

    #[tokio::test]
    async fn unwritable_state_dir_fails() {
        // Use a path that doesn't exist — write must fail.
        let ctx = DiagnosticContext {
            state_dir: Some(std::path::PathBuf::from(
                "Z:/this-path-should-not-exist-or-be-unwritable-spt-test",
            )),
            ..Default::default()
        };
        let r = PermissionsDiagnostic.run(&ctx).await;
        assert_eq!(r[0].status, Status::Fail);
    }
}
