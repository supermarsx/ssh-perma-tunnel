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
    fn group(&self) -> &'static str {
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

    #[test]
    fn group_label_is_service() {
        assert_eq!(ServiceDiagnostic.group(), "service");
    }

    #[tokio::test]
    async fn skipped_when_service_manager_missing_but_name_present() {
        let ctx = DiagnosticContext {
            service_manager: None,
            service_name: Some("spt".into()),
            ..Default::default()
        };
        let r = ServiceDiagnostic.run(&ctx).await;
        assert_eq!(r[0].status, Status::Skipped);
        let evidence = r[0].evidence.join("\n");
        assert!(evidence.contains("no ServiceManager"), "got: {evidence}");
    }

    #[tokio::test]
    async fn skipped_when_service_name_missing_but_manager_present() {
        let ctx = DiagnosticContext {
            service_manager: Some(Arc::new(FakeMgr(ServiceState::Running))),
            service_name: None,
            ..Default::default()
        };
        let r = ServiceDiagnostic.run(&ctx).await;
        assert_eq!(r[0].status, Status::Skipped);
    }

    #[tokio::test]
    async fn stopped_remediation_suggests_start() {
        let r = ServiceDiagnostic.run(&ctx(ServiceState::Stopped)).await;
        let rem = r[0].remediation.as_deref().unwrap_or("");
        assert!(rem.contains("spt service start"), "rem: {rem}");
    }

    #[tokio::test]
    async fn not_installed_remediation_suggests_install() {
        let r = ServiceDiagnostic
            .run(&ctx(ServiceState::NotInstalled))
            .await;
        let rem = r[0].remediation.as_deref().unwrap_or("");
        assert!(rem.contains("spt service install"), "rem: {rem}");
    }

    #[tokio::test]
    async fn status_query_error_surfaces_as_skipped() {
        #[derive(Debug)]
        struct ErroringMgr;
        #[async_trait]
        impl ServiceManager for ErroringMgr {
            fn name(&self) -> &'static str {
                "erroring"
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
                Err(spt_core::Error::RuntimeFailure("boom".into()))
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
        let ctx = DiagnosticContext {
            service_manager: Some(Arc::new(ErroringMgr)),
            service_name: Some("spt".into()),
            ..Default::default()
        };
        let r = ServiceDiagnostic.run(&ctx).await;
        assert_eq!(r[0].status, Status::Skipped);
        let evidence = r[0].evidence.join("\n");
        assert!(evidence.contains("status query failed"), "got: {evidence}");
    }
}
