//! Service-manager status check.
//!
//! Calls [`ServiceManager::status`] for the configured service name and
//! reports installed / running / unknown. Read-only — never installs,
//! starts, or stops anything.

use async_trait::async_trait;

use spt_service::ServiceStatus;

use crate::check::{Check, Severity, Status};
use crate::framework::{Diagnostic, DiagnosticContext};

/// Service diagnostic.
#[derive(Default, Debug)]
pub struct ServiceDiagnostic;

#[async_trait]
impl Diagnostic for ServiceDiagnostic {
    fn group(&self) -> &str {
        "service"
    }
    async fn run(&self, ctx: &DiagnosticContext) -> Vec<Check> {
        let (Some(mgr), Some(name)) = (ctx.service_manager.as_ref(), ctx.service_name.as_ref())
        else {
            return vec![Check::new(
                "service.status",
                Severity::Medium,
                Status::Skipped,
            )
            .with_evidence("no ServiceManager or service name supplied")];
        };
        match mgr.status(name) {
            Ok(ServiceStatus::Running) => vec![Check::new(
                "service.status",
                Severity::Info,
                Status::Pass,
            )
            .with_evidence(format!("service `{name}` is running"))],
            Ok(ServiceStatus::Stopped) => vec![Check::new(
                "service.status",
                Severity::Medium,
                Status::Warn,
            )
            .with_evidence(format!("service `{name}` is installed but stopped"))
            .with_remediation(format!("`spt service start {name}`"))],
            Ok(ServiceStatus::NotInstalled) => vec![Check::new(
                "service.status",
                Severity::Medium,
                Status::Warn,
            )
            .with_evidence(format!("service `{name}` is not installed"))
            .with_remediation(format!("`spt service install {name}`"))],
            Ok(ServiceStatus::Unknown) => vec![Check::new(
                "service.status",
                Severity::Low,
                Status::Skipped,
            )
            .with_evidence(format!(
                "service manager could not determine status for `{name}`"
            ))],
            Err(e) => vec![Check::new("service.status", Severity::Low, Status::Skipped)
                .with_evidence(format!("status query failed: {e}"))],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use spt_core::Result;
    use spt_service::{ServiceManager, ServiceSpec};
    use std::sync::Arc;

    struct FakeMgr(ServiceStatus);
    impl ServiceManager for FakeMgr {
        fn render(&self, _: &ServiceSpec) -> Result<String> {
            Ok(String::new())
        }
        fn status(&self, _: &str) -> Result<ServiceStatus> {
            Ok(self.0)
        }
    }

    fn ctx(status: ServiceStatus) -> DiagnosticContext {
        DiagnosticContext {
            service_manager: Some(Arc::new(FakeMgr(status))),
            service_name: Some("spt".to_string()),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn skipped_without_handle() {
        let r = ServiceDiagnostic.run(&DiagnosticContext::default()).await;
        assert_eq!(r[0].status, Status::Skipped);
    }

    #[tokio::test]
    async fn running_passes() {
        let r = ServiceDiagnostic.run(&ctx(ServiceStatus::Running)).await;
        assert_eq!(r[0].status, Status::Pass);
    }

    #[tokio::test]
    async fn stopped_warns() {
        let r = ServiceDiagnostic.run(&ctx(ServiceStatus::Stopped)).await;
        assert_eq!(r[0].status, Status::Warn);
        assert!(r[0].remediation.is_some());
    }

    #[tokio::test]
    async fn not_installed_warns() {
        let r = ServiceDiagnostic
            .run(&ctx(ServiceStatus::NotInstalled))
            .await;
        assert_eq!(r[0].status, Status::Warn);
    }

    #[tokio::test]
    async fn unknown_skips() {
        let r = ServiceDiagnostic.run(&ctx(ServiceStatus::Unknown)).await;
        assert_eq!(r[0].status, Status::Skipped);
    }
}
