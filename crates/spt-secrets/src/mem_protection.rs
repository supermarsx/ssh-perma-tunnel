//! Process-level memory-protection policy driven by
//! `[secrets].memory_protection` (spec §9.3 / §14.6).
//!
//! Three levels are recognised:
//!
//! * `best_effort` (default) — no process-wide action. Individual secret
//!   allocations continue to use the per-buffer best-effort
//!   `mlock`/`VirtualLock` in [`crate::mlock`] / [`crate::secret_alloc`].
//! * `strict` — attempt to lock **all** current and future process pages into
//!   RAM so no secret material can ever be paged to swap. On Unix this issues
//!   `mlockall(MCL_CURRENT | MCL_FUTURE)`; on success the whole address space
//!   (including every [`crate::SecretBytes`] the resolver hands back) is
//!   non-swappable. When the level genuinely cannot be honoured (e.g.
//!   `RLIMIT_MEMLOCK` exceeded, or the platform has no equivalent) an `ERROR`
//!   is logged and a [`ProtectionOutcome::StrictUnavailable`] is returned —
//!   never a silent no-op. Because `strict` should *mean* strict, the caller
//!   can enforce fail-closed startup by threading the outcome through
//!   [`ProtectionOutcome::into_result`] (best-effort/none always succeed).
//! * `none` — memory protection is explicitly disabled; only a `debug` line is
//!   emitted so the operator's choice is observable.
//!
//! The effect is process-global, so [`apply_once`] applies (and logs) the
//! configured level at most once per process even though the resolver builder
//! may run many times.

use std::sync::OnceLock;

use tracing::{debug, error, info, warn};

/// Configured `[secrets].memory_protection` level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryProtection {
    /// Per-allocation best effort (the default); no process-wide locking.
    BestEffort,
    /// Lock all current + future pages into RAM (`mlockall`).
    Strict,
    /// Memory protection explicitly disabled.
    None,
}

impl MemoryProtection {
    /// Parse the schema string form (`best_effort|strict|none`). Case- and
    /// separator-insensitive (`best-effort` is accepted). Returns `None` for
    /// an unrecognised value so the caller can decide how loud to be.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().replace('-', "_").as_str() {
            "best_effort" | "" => Some(Self::BestEffort),
            "strict" => Some(Self::Strict),
            "none" | "off" => Some(Self::None),
            _ => None,
        }
    }

    /// Resolve the level from an optional config value, defaulting to
    /// [`MemoryProtection::BestEffort`] when unset or unrecognised.
    #[must_use]
    pub fn from_config(value: Option<&str>) -> Self {
        match value {
            Some(v) => Self::parse(v).unwrap_or_else(|| {
                warn!(
                    value = v,
                    "unrecognised [secrets].memory_protection; falling back to best_effort"
                );
                Self::BestEffort
            }),
            None => Self::BestEffort,
        }
    }
}

/// Observable result of applying a [`MemoryProtection`] level.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtectionOutcome {
    /// `strict` requested and the process address space was locked.
    StrictApplied,
    /// `strict` requested but could not be honoured (reason attached); the
    /// process degrades to best-effort per-buffer locking.
    StrictUnavailable(String),
    /// `best_effort` — per-allocation locking only (the default).
    BestEffort,
    /// `none` — memory protection disabled.
    Disabled,
}

impl ProtectionOutcome {
    /// Whether this outcome is a `strict` request that could **not** be
    /// honoured (the address space was not locked). Callers that want `strict`
    /// to fail closed can branch on this.
    #[must_use]
    pub fn is_strict_unavailable(&self) -> bool {
        matches!(self, Self::StrictUnavailable(_))
    }

    /// Fail-closed view of the outcome: `Err(reason)` **iff** a `strict`
    /// protection request could not be honoured, and `Ok(())` otherwise
    /// (`strict` applied, `best_effort`, or `none`).
    ///
    /// A process that configured `strict` should propagate this error (refuse
    /// to start) so `strict` genuinely means strict rather than silently
    /// degrading to swappable best-effort locking. `best_effort`/`none` callers
    /// are unaffected because those outcomes always map to `Ok`.
    ///
    /// # Errors
    ///
    /// Returns the concrete reason string attached to
    /// [`ProtectionOutcome::StrictUnavailable`].
    pub fn into_result(self) -> std::result::Result<(), String> {
        match self {
            Self::StrictUnavailable(reason) => Err(reason),
            Self::StrictApplied | Self::BestEffort | Self::Disabled => Ok(()),
        }
    }
}

/// Apply `level`, logging the resulting protection state. This performs the
/// real syscall for [`MemoryProtection::Strict`]; see [`apply_once`] for the
/// process-guarded variant used by the resolver builder.
#[must_use]
pub fn apply(level: MemoryProtection) -> ProtectionOutcome {
    apply_with(level, lock_process_memory)
}

/// Inner implementation of [`apply`] with the process-lock syscall injected so
/// the fail-closed path can be unit-tested without a real `mlockall` failure.
fn apply_with(
    level: MemoryProtection,
    lock: impl FnOnce() -> Result<(), String>,
) -> ProtectionOutcome {
    match level {
        MemoryProtection::Strict => match lock() {
            Ok(()) => {
                info!(
                    target: "spt_secrets::mem_protection",
                    "strict memory protection active: all process pages locked (mlockall MCL_CURRENT|MCL_FUTURE); secret buffers cannot be paged to swap"
                );
                ProtectionOutcome::StrictApplied
            }
            Err(reason) => {
                // `strict` was explicitly configured but could not be honoured.
                // Log at ERROR (not WARN): this is a security-posture failure,
                // and the returned `StrictUnavailable` lets the caller fail
                // closed via `ProtectionOutcome::into_result`.
                error!(
                    target: "spt_secrets::mem_protection",
                    reason = %reason,
                    "strict memory protection requested but could not be honoured; secret pages may be swappable — refuse to continue if strict is required (see ProtectionOutcome::into_result)"
                );
                ProtectionOutcome::StrictUnavailable(reason)
            }
        },
        MemoryProtection::BestEffort => {
            debug!(
                target: "spt_secrets::mem_protection",
                "best-effort memory protection: individual secret allocations are locked where possible"
            );
            ProtectionOutcome::BestEffort
        }
        MemoryProtection::None => {
            debug!(
                target: "spt_secrets::mem_protection",
                "memory protection disabled by configuration ([secrets].memory_protection = \"none\")"
            );
            ProtectionOutcome::Disabled
        }
    }
}

/// Apply `level` at most once per process, caching (and logging) the first
/// outcome. Subsequent calls return the cached outcome without re-issuing the
/// syscall or re-logging — the effect is process-global.
pub fn apply_once(level: MemoryProtection) -> ProtectionOutcome {
    static APPLIED: OnceLock<ProtectionOutcome> = OnceLock::new();
    APPLIED.get_or_init(|| apply(level)).clone()
}

/// Release any process-wide lock established by [`apply`]`(Strict)`. Best
/// effort; used by tests and any teardown path that wants to undo `mlockall`.
#[cfg(unix)]
pub fn release_all() {
    // SAFETY-free: `munlockall` takes no memory arguments; it clears the
    // process-wide MCL_CURRENT/MCL_FUTURE state. Failures are ignored.
    let _ = nix::sys::mman::munlockall();
}

/// No-op on platforms without a process-wide lock.
#[cfg(not(unix))]
#[allow(clippy::missing_const_for_fn)]
pub fn release_all() {}

#[cfg(unix)]
fn lock_process_memory() -> Result<(), String> {
    use nix::sys::mman::{mlockall, MlockAllFlags};
    mlockall(MlockAllFlags::MCL_CURRENT | MlockAllFlags::MCL_FUTURE)
        .map_err(|e| format!("mlockall failed: {e}"))
}

#[cfg(windows)]
fn lock_process_memory() -> Result<(), String> {
    // Windows has no process-wide equivalent of mlockall. `VirtualLock` is
    // per-region (already used by `crate::mlock` for individual secret
    // buffers), and `SetProcessWorkingSetSize` does not prevent paging of
    // arbitrary allocations. Report honestly so the caller warns.
    Err(
        "process-wide memory locking is not available on Windows; per-secret VirtualLock remains in effect (best-effort)"
            .to_string(),
    )
}

#[cfg(not(any(unix, windows)))]
fn lock_process_memory() -> Result<(), String> {
    Err("process-wide memory locking is not supported on this platform".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_recognises_all_levels() {
        assert_eq!(
            MemoryProtection::parse("best_effort"),
            Some(MemoryProtection::BestEffort)
        );
        assert_eq!(
            MemoryProtection::parse("best-effort"),
            Some(MemoryProtection::BestEffort)
        );
        assert_eq!(
            MemoryProtection::parse("STRICT"),
            Some(MemoryProtection::Strict)
        );
        assert_eq!(
            MemoryProtection::parse("none"),
            Some(MemoryProtection::None)
        );
        assert_eq!(MemoryProtection::parse("off"), Some(MemoryProtection::None));
        assert_eq!(
            MemoryProtection::parse(""),
            Some(MemoryProtection::BestEffort)
        );
        assert_eq!(MemoryProtection::parse("bogus"), None);
    }

    #[test]
    fn from_config_defaults_to_best_effort() {
        assert_eq!(
            MemoryProtection::from_config(None),
            MemoryProtection::BestEffort
        );
        assert_eq!(
            MemoryProtection::from_config(Some("strict")),
            MemoryProtection::Strict
        );
        // Unrecognised value degrades to best-effort (warned, not an error).
        assert_eq!(
            MemoryProtection::from_config(Some("nonsense")),
            MemoryProtection::BestEffort
        );
    }

    #[test]
    fn apply_none_is_disabled_without_syscall() {
        assert_eq!(apply(MemoryProtection::None), ProtectionOutcome::Disabled);
    }

    #[test]
    fn apply_best_effort_takes_no_process_action() {
        assert_eq!(
            apply(MemoryProtection::BestEffort),
            ProtectionOutcome::BestEffort
        );
    }

    #[test]
    fn apply_strict_engages_or_warns_per_platform() {
        // strict must never silently no-op: it either locks the address space
        // (StrictApplied) or reports a concrete reason it could not
        // (StrictUnavailable) — both are honest, observable outcomes.
        let outcome = apply(MemoryProtection::Strict);
        match &outcome {
            ProtectionOutcome::StrictApplied => {
                // Undo immediately so MCL_FUTURE does not affect the rest of
                // the test binary's allocations.
                release_all();
            }
            ProtectionOutcome::StrictUnavailable(reason) => {
                assert!(!reason.is_empty(), "unavailable reason must be populated");
            }
            other => panic!("strict produced non-strict outcome: {other:?}"),
        }
    }

    #[test]
    fn strict_lock_failure_is_unavailable_and_fails_closed() {
        // Mock an mlockall failure: strict must NOT silently degrade. It must
        // surface `StrictUnavailable` and `into_result` must be an Err carrying
        // the reason so the caller can refuse to start.
        let outcome = apply_with(MemoryProtection::Strict, || {
            Err("mock mlockall EPERM".into())
        });
        assert!(outcome.is_strict_unavailable());
        assert_eq!(
            outcome,
            ProtectionOutcome::StrictUnavailable("mock mlockall EPERM".to_string())
        );
        let err = outcome.into_result().unwrap_err();
        assert!(err.contains("mock mlockall EPERM"));
    }

    #[test]
    fn strict_lock_success_is_ok_result() {
        // With the lock succeeding, strict applies and is a fail-closed Ok. The
        // injected closure avoids touching the real address space.
        let outcome = apply_with(MemoryProtection::Strict, || Ok(()));
        assert_eq!(outcome, ProtectionOutcome::StrictApplied);
        assert!(!outcome.is_strict_unavailable());
        assert!(outcome.into_result().is_ok());
    }

    #[test]
    fn best_effort_and_none_always_ok_results() {
        // Non-strict modes are behaviour-preserving: they never fail closed.
        assert!(ProtectionOutcome::BestEffort.into_result().is_ok());
        assert!(ProtectionOutcome::Disabled.into_result().is_ok());
        assert!(!ProtectionOutcome::BestEffort.is_strict_unavailable());
        // The real syscall paths for these levels also map to Ok.
        assert!(apply(MemoryProtection::BestEffort).into_result().is_ok());
        assert!(apply(MemoryProtection::None).into_result().is_ok());
    }
}
