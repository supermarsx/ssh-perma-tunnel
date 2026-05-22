//! Production-impact gating (spec §13.13).
//!
//! "Benchmarks MUST refuse destructive or excessive load unless
//! `--unsafe-allow-production-impact` is provided." The gate is applied
//! before the driver runs.

use thiserror::Error;

use crate::driver::{BenchmarkDriver, ImpactLevel};

/// Refusal reason.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SafetyError {
    /// The driver targets a real production system but the user did not
    /// pass `--unsafe-allow-production-impact`.
    #[error(
        "driver `{driver}` impacts production; pass --unsafe-allow-production-impact to override"
    )]
    ProductionImpactNotAllowed {
        /// Driver name.
        driver: String,
    },
}

/// Validate that `driver` may be run given `allow_prod`. Returns `Ok(())` if
/// the driver is `Synthetic`, or if the user opted in.
pub fn check_safety(driver: &dyn BenchmarkDriver, allow_prod: bool) -> Result<(), SafetyError> {
    match driver.impact() {
        ImpactLevel::Synthetic => Ok(()),
        ImpactLevel::Production if allow_prod => Ok(()),
        ImpactLevel::Production => Err(SafetyError::ProductionImpactNotAllowed {
            driver: driver.name().to_owned(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::driver::{BenchContext, BenchmarkDriver, ImpactLevel};
    use crate::result::BenchResult;
    use async_trait::async_trait;

    struct Synth;
    #[async_trait]
    impl BenchmarkDriver for Synth {
        fn name(&self) -> &'static str {
            "synth"
        }
        fn impact(&self) -> ImpactLevel {
            ImpactLevel::Synthetic
        }
        async fn run(&self, _ctx: &BenchContext) -> BenchResult {
            BenchResult::default()
        }
    }

    struct Prod;
    #[async_trait]
    impl BenchmarkDriver for Prod {
        fn name(&self) -> &'static str {
            "prod"
        }
        fn impact(&self) -> ImpactLevel {
            ImpactLevel::Production
        }
        async fn run(&self, _ctx: &BenchContext) -> BenchResult {
            BenchResult::default()
        }
    }

    #[test]
    fn synthetic_always_ok() {
        check_safety(&Synth, false).unwrap();
        check_safety(&Synth, true).unwrap();
    }

    #[test]
    fn production_requires_flag() {
        let err = check_safety(&Prod, false).unwrap_err();
        assert!(matches!(
            err,
            SafetyError::ProductionImpactNotAllowed { .. }
        ));
        check_safety(&Prod, true).unwrap();
    }

    #[test]
    fn production_error_carries_driver_name() {
        let err = check_safety(&Prod, false).unwrap_err();
        match &err {
            SafetyError::ProductionImpactNotAllowed { driver } => {
                assert_eq!(driver, "prod");
            }
        }
    }

    #[test]
    fn error_display_mentions_override_flag() {
        let err = check_safety(&Prod, false).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("--unsafe-allow-production-impact"),
            "expected override hint, got `{msg}`"
        );
        assert!(msg.contains("prod"), "expected driver name, got `{msg}`");
    }

    #[test]
    fn error_is_clone_eq_and_debug() {
        let err = check_safety(&Prod, false).unwrap_err();
        let cloned = err.clone();
        assert_eq!(err, cloned);
        let dbg = format!("{err:?}");
        assert!(dbg.contains("ProductionImpactNotAllowed"));
    }

    #[test]
    fn safety_error_source_chain_is_none() {
        use std::error::Error;
        let err = check_safety(&Prod, false).unwrap_err();
        assert!(err.source().is_none());
    }
}
