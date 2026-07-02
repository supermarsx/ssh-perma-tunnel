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
//!   `RLIMIT_MEMLOCK` exceeded, or the platform has no equivalent) a `WARN` is
//!   logged and the process falls back to best-effort — never a silent no-op.
//! * `none` — memory protection is explicitly disabled; only a `debug` line is
//!   emitted so the operator's choice is observable.
//!
//! The effect is process-global, so [`apply_once`] applies (and logs) the
//! configured level at most once per process even though the resolver builder
//! may run many times.

use std::sync::OnceLock;

use tracing::{debug, info, warn};

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

/// Apply `level`, logging the resulting protection state. This performs the
/// real syscall for [`MemoryProtection::Strict`]; see [`apply_once`] for the
/// process-guarded variant used by the resolver builder.
#[must_use]
pub fn apply(level: MemoryProtection) -> ProtectionOutcome {
    match level {
        MemoryProtection::Strict => match lock_process_memory() {
            Ok(()) => {
                info!(
                    target: "spt_secrets::mem_protection",
                    "strict memory protection active: all process pages locked (mlockall MCL_CURRENT|MCL_FUTURE); secret buffers cannot be paged to swap"
                );
                ProtectionOutcome::StrictApplied
            }
            Err(reason) => {
                warn!(
                    target: "spt_secrets::mem_protection",
                    reason = %reason,
                    "strict memory protection requested but could not be honoured; falling back to best-effort per-secret locking (secret pages may be swappable)"
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
}
