//! Service-manager status check.
//!
//! Calls [`spt_service::ServiceManager::status`] for the configured service name and
//! reports installed / running / unknown. Read-only — never installs,
//! starts, or stops anything.

use async_trait::async_trait;

// `ServiceStatus` is referenced from the test fakes; keep the import alive
// behind cfg(test) to satisfy clippy under `-D warnings`.
use spt_service::ServiceState;
#[cfg(test)]
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
            return vec![
                Check::new("service.status", Severity::Medium, Status::Skipped)
                    .with_evidence("no ServiceManager or service name supplied"),
            ];
        };
        match mgr.status(name).await {
            Ok(s) => match s.state {
                ServiceState::Running => {
                    vec![Check::new("service.status", Severity::Info, Status::Pass)
                        .with_evidence(format!("service `{name}` is running"))]
                }
                ServiceState::Stopped => {
                    vec![Check::new("service.status", Severity::Medium, Status::Warn)
                        .with_evidence(format!("service `{name}` is installed but stopped"))
                        .with_remediation(format!("`spt service start {name}`"))]
                }
                ServiceState::NotInstalled => {
                    vec![Check::new("service.status", Severity::Medium, Status::Warn)
                        .with_evidence(format!("service `{name}` is not installed"))
                        .with_remediation(format!("`spt service install {name}`"))]
                }
                ServiceState::Failed => {
                    vec![Check::new("service.status", Severity::High, Status::Fail)
                        .with_evidence(format!(
                            "service `{name}` is in a failed state{}",
                            s.exit_code
                                .map(|c| format!(" (last exit {c})"))
                                .unwrap_or_default()
                        ))
                        .with_remediation(format!(
                            "inspect logs and run `spt service restart {name}`"
                        ))]
                }
                ServiceState::Unknown => {
                    vec![Check::new("service.status", Severity::Low, Status::Skipped)
                        .with_evidence(format!(
                            "service manager could not determine status for `{name}`"
                        ))]
                }
            },
            Err(e) => vec![Check::new("service.status", Severity::Low, Status::Skipped)
                .with_evidence(format!("status query failed: {e}"))],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use spt_core::Result;
    use spt_service::{ServiceCapabilities, ServiceManager, ServiceSpec};
    use std::sync::Arc;

    #[derive(Debug)]
    struct FakeMgr(ServiceState);

    #[async_trait]
    impl ServiceManager for FakeMgr {
        fn name(&self) -> &'static str {
            "fake"
        }
        fn capabilities(&self) -> ServiceCapabilities {
            ServiceCapabilities::default()
        }
        async fn install(&self, _: &ServiceSpec) -> Result<()> {
            Ok(())
        }
        async fn uninstall(&self, _: &str) -> Result<()> {
            Ok(())
        }
        async fn status(&self, _: &str) -> Result<ServiceStatus> {
            Ok(ServiceStatus::new(self.0))
        }
        async fn start(&self, _: &str) -> Result<()> {
            Ok(())
        }
        async fn stop(&self, _: &str) -> Result<()> {
            Ok(())
        }
        async fn restart(&self, _: &str) -> Result<()> {
            Ok(())
        }
        async fn reload(&self, _: &str) -> Result<()> {
            Ok(())
        }
    }

    fn ctx(state: ServiceState) -> DiagnosticContext {
        DiagnosticContext {
            service_manager: Some(Arc::new(FakeMgr(state))),
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
        let r = ServiceDiagnostic.run(&ctx(ServiceState::Running)).await;
        assert_eq!(r[0].status, Status::Pass);
    }

    #[tokio::test]
    async fn stopped_warns() {
        let r = ServiceDiagnostic.run(&ctx(ServiceState::Stopped)).await;
        assert_eq!(r[0].status, Status::Warn);
        assert!(r[0].remediation.is_some());
    }

    #[tokio::test]
    async fn not_installed_warns() {
        let r = ServiceDiagnostic
            .run(&ctx(ServiceState::NotInstalled))
            .await;
        assert_eq!(r[0].status, Status::Warn);
    }

    #[tokio::test]
    async fn unknown_skips() {
        let r = ServiceDiagnostic.run(&ctx(ServiceState::Unknown)).await;
        assert_eq!(r[0].status, Status::Skipped);
    }

    #[tokio::test]
    async fn failed_fails() {
        let r = ServiceDiagnostic.run(&ctx(ServiceState::Failed)).await;
        assert_eq!(r[0].status, Status::Fail);
    }
}
