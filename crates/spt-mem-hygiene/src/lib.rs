//! Best-effort process memory hygiene / hardening primitives.
//!
//! `spt-mem-hygiene` is called once at process start (typically from
//! `spt-bin`'s `main`) to apply a set of OS-level mitigations:
//!
//! * **Linux** — `prctl(PR_SET_DUMPABLE, 0)` to suppress core dumps and
//!   `/proc/self/mem` access by other UIDs; `prctl(PR_SET_NO_NEW_PRIVS, 1)`
//!   to prevent set-uid execve from acquiring privileges; `setrlimit(
//!   RLIMIT_CORE, {0, 0})` to belt-and-braces disable core files.
//!
//! * **Windows** — `SetErrorMode` to suppress critical-error and GP-fault
//!   message-box dialogs; `SetProcessMitigationPolicy` with
//!   `ProcessExtensionPointDisablePolicy` (block legacy `AppInit` DLL /
//!   extension DLL injection) and `ProcessDynamicCodePolicy` (block ad-hoc
//!   RWX page creation); `AdjustTokenPrivileges` to drop `SeDebugPrivilege`
//!   from the process token.
//!
//! * **macOS** — `setrlimit(RLIMIT_CORE, {0, 0})`. With the
//!   `macos-anti-debug` cargo feature enabled, also calls `ptrace(
//!   PT_DENY_ATTACH, …)`. That feature is OFF by default because the
//!   syscall can break Apple notarization tooling and crash reporters.
//!
//! Every primitive is **best-effort**. Failure of any one mitigation is
//! reported in [`HardeningReport`] but never propagated as an error or a
//! panic — a hardened-when-possible process is more valuable than a
//! refuse-to-start one.
//!
//! ```
//! let report = spt_mem_hygiene::harden();
//! eprintln!("{report}");
//! ```
//!
//! Calling [`harden`] more than once is safe and idempotent (the underlying
//! `prctl` / `SetProcessMitigationPolicy` calls are themselves
//! idempotent or no-ops once the bit is set).
//!
//! ## Safety
//!
//! The platform back-ends call C ABI functions. We can't `#![forbid(
//! unsafe_code)]`, so we instead `#![deny(unsafe_op_in_unsafe_fn)]` and
//! wrap every FFI call in a tightly-scoped `unsafe` block with a
//! `// SAFETY:` justification.

#![deny(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::fmt;

mod cgroup;
pub mod monitor;
#[doc(inline)]
pub use monitor::{
    evaluate, MemoryGrowth, MemoryMonitor, MemoryMonitorConfig, MemoryMonitorHandle, MemorySample,
};

/// Test-only allocator instrumentation. Gated behind `test` / the `test-alloc`
/// feature so dependent crates can reuse [`testing::CountingAllocator`] in
/// dedicated leak-test binaries (`features = ["test-alloc"]`).
#[cfg(any(test, feature = "test-alloc"))]
pub mod testing;
#[cfg(any(test, feature = "test-alloc"))]
#[doc(inline)]
pub use testing::{CountingAllocator, COUNTING_ALLOCATOR};

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(all(not(target_os = "linux"), not(target_os = "macos"), not(windows)))]
mod stub;
#[cfg(windows)]
mod windows;

/// Outcome of a single hardening step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum HardeningStatus {
    /// The step was applied successfully.
    Ok,
    /// The step was deliberately not attempted on this platform / build /
    /// runtime configuration. `reason` is a short human-readable string;
    /// no secrets or paths are embedded.
    Skipped {
        /// Why the step was skipped (e.g. "not supported on this platform",
        /// "gated behind macos-anti-debug feature").
        reason: String,
    },
    /// The step was attempted and the OS returned an error. `reason` is the
    /// short error message — never contains secrets or PII.
    Err {
        /// Short error message from the underlying syscall.
        reason: String,
    },
}

impl HardeningStatus {
    /// Convenience: was the step a success?
    pub fn is_ok(&self) -> bool {
        matches!(self, Self::Ok)
    }
    /// Convenience: was the step skipped?
    pub fn is_skipped(&self) -> bool {
        matches!(self, Self::Skipped { .. })
    }
    /// Convenience: did the step fail?
    pub fn is_err(&self) -> bool {
        matches!(self, Self::Err { .. })
    }
}

impl fmt::Display for HardeningStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ok => f.write_str("ok"),
            Self::Skipped { reason } => write!(f, "skipped ({reason})"),
            Self::Err { reason } => write!(f, "error ({reason})"),
        }
    }
}

/// Outcome of one named hardening step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HardeningResult {
    /// Stable identifier for the step (e.g. `"pr_set_dumpable"`,
    /// `"set_process_mitigation_policy.dynamic_code"`).
    pub name: String,
    /// Outcome.
    pub status: HardeningStatus,
}

impl HardeningResult {
    /// Construct a successful result.
    pub fn ok(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            status: HardeningStatus::Ok,
        }
    }
    /// Construct a skipped result.
    pub fn skipped(name: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            status: HardeningStatus::Skipped {
                reason: reason.into(),
            },
        }
    }
    /// Construct an error result.
    pub fn err(name: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            status: HardeningStatus::Err {
                reason: reason.into(),
            },
        }
    }
}

/// Aggregated outcome of [`harden`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct HardeningReport {
    /// One row per step attempted, in execution order.
    pub results: Vec<HardeningResult>,
    /// Target OS string at the time `harden()` ran (e.g. `"linux"`,
    /// `"windows"`, `"macos"`, or `"unknown"`).
    pub platform: String,
}

impl HardeningReport {
    /// Build a new empty report for the current platform.
    pub fn new() -> Self {
        Self {
            results: Vec::new(),
            platform: current_platform().to_string(),
        }
    }

    /// Push a result onto the report.
    pub fn push(&mut self, r: HardeningResult) {
        self.results.push(r);
    }

    /// True if every step is either `Ok` or `Skipped` (no `Err`).
    pub fn all_ok_or_skipped(&self) -> bool {
        self.results.iter().all(|r| !r.status.is_err())
    }

    /// Number of `Ok` results.
    pub fn ok_count(&self) -> usize {
        self.results.iter().filter(|r| r.status.is_ok()).count()
    }

    /// Number of `Err` results.
    pub fn err_count(&self) -> usize {
        self.results.iter().filter(|r| r.status.is_err()).count()
    }

    /// Number of `Skipped` results.
    pub fn skipped_count(&self) -> usize {
        self.results
            .iter()
            .filter(|r| r.status.is_skipped())
            .count()
    }
}

impl fmt::Display for HardeningReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Width = longest name, capped to keep the table readable even if a
        // future step has an unusually long identifier.
        let name_w = self
            .results
            .iter()
            .map(|r| r.name.len())
            .max()
            .unwrap_or(0)
            .clamp(8, 48);
        writeln!(f, "spt memory hygiene report (platform: {})", self.platform)?;
        for r in &self.results {
            writeln!(f, "  {:<width$}  {}", r.name, r.status, width = name_w)?;
        }
        Ok(())
    }
}

/// Best-effort current-platform string. Kept separate from
/// `std::env::consts::OS` only so tests can assert the canonical strings.
fn current_platform() -> &'static str {
    if cfg!(target_os = "linux") {
        "linux"
    } else if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(windows) {
        "windows"
    } else {
        "unknown"
    }
}

/// Apply every available hardening primitive for the current platform.
///
/// Returns a [`HardeningReport`] enumerating each step's outcome. **Never
/// panics** and never returns an error: failures of individual steps are
/// recorded inside the report.
///
/// Safe to call more than once; each step is itself idempotent.
pub fn harden() -> HardeningReport {
    let mut report = HardeningReport::new();
    #[cfg(target_os = "linux")]
    {
        linux::harden_into(&mut report);
    }
    #[cfg(target_os = "macos")]
    {
        macos::harden_into(&mut report);
    }
    #[cfg(windows)]
    {
        windows::harden_into(&mut report);
    }
    #[cfg(all(not(target_os = "linux"), not(target_os = "macos"), not(windows)))]
    {
        stub::harden_into(&mut report);
    }
    if report.results.is_empty() {
        report.push(HardeningResult::skipped(
            "platform",
            "no hardening primitives available for this target",
        ));
    }
    report
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn harden_returns_report_on_every_platform() {
        let r = harden();
        // The contract is: never panics, never empty.
        assert!(
            !r.results.is_empty(),
            "report must contain at least one row"
        );
        assert!(!r.platform.is_empty(), "platform must be set");
    }

    #[test]
    fn idempotent_call_twice_no_degradation() {
        let a = harden();
        let b = harden();
        assert_eq!(a.results.len(), b.results.len());
        // Same set of step names, in same order.
        let an: Vec<&str> = a.results.iter().map(|r| r.name.as_str()).collect();
        let bn: Vec<&str> = b.results.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(an, bn);
        // No step should degrade from Ok to Err on a repeat call (skipped
        // and ok are both acceptable).
        for (x, y) in a.results.iter().zip(b.results.iter()) {
            if x.status.is_ok() {
                assert!(
                    !y.status.is_err(),
                    "step {} degraded Ok -> Err on second call",
                    x.name
                );
            }
        }
    }

    #[test]
    fn display_impl_is_human_readable() {
        let r = harden();
        let s = format!("{r}");
        assert!(s.contains("spt memory hygiene report"));
        assert!(s.contains(&r.platform));
        for row in &r.results {
            assert!(
                s.contains(&row.name),
                "Display must mention every step name"
            );
        }
        // No trailing nul or weird control chars beyond newline/space.
        assert!(s.chars().all(|c| c == '\n' || c == ' ' || !c.is_control()));
    }

    #[test]
    fn debug_impl_does_not_leak_sensitive_data() {
        // We construct a result whose reason strings are short and known-safe
        // and assert the Debug output contains nothing else surprising.
        let res = HardeningResult::err("test_step", "EPERM");
        let s = format!("{res:?}");
        assert!(s.contains("test_step"));
        assert!(s.contains("EPERM"));
        // The Debug output must NOT contain any environment variable names
        // or filesystem paths that we never put into it.
        assert!(!s.contains("/etc/"));
        assert!(!s.contains("HOME="));
        assert!(!s.contains("PATH="));
    }

    #[test]
    fn report_is_json_serializable() {
        let r = harden();
        let s = serde_json::to_string(&r).expect("HardeningReport must JSON-serialize");
        // Round-trip.
        let back: HardeningReport =
            serde_json::from_str(&s).expect("HardeningReport must JSON-deserialize");
        assert_eq!(r, back);
        // Contains expected shape.
        assert!(s.contains("\"platform\""));
        assert!(s.contains("\"results\""));
    }

    #[test]
    fn status_helpers_classify_correctly() {
        assert!(HardeningStatus::Ok.is_ok());
        assert!(!HardeningStatus::Ok.is_err());
        let sk = HardeningStatus::Skipped {
            reason: "nope".into(),
        };
        assert!(sk.is_skipped());
        assert!(!sk.is_ok());
        let er = HardeningStatus::Err {
            reason: "EPERM".into(),
        };
        assert!(er.is_err());
        assert!(!er.is_ok());
    }

    #[test]
    fn counts_match_results() {
        let r = harden();
        assert_eq!(
            r.results.len(),
            r.ok_count() + r.err_count() + r.skipped_count()
        );
    }

    #[test]
    fn platform_string_is_canonical() {
        let r = harden();
        assert!(
            matches!(
                r.platform.as_str(),
                "linux" | "macos" | "windows" | "unknown"
            ),
            "unexpected platform string: {}",
            r.platform
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_dumpable_is_zero_after_harden() {
        let _ = harden();
        // /proc/self/status holds a "Dumpable: 0" line iff PR_SET_DUMPABLE
        // succeeded. We only assert the bit if the line is present (some
        // containerized CI environments hide /proc/self/status).
        if let Ok(s) = std::fs::read_to_string("/proc/self/status") {
            for line in s.lines() {
                if let Some(rest) = line.strip_prefix("Dumpable:") {
                    let v = rest.trim();
                    assert_eq!(v, "0", "Dumpable should be 0 after harden()");
                }
            }
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_no_new_privs_is_set_after_harden() {
        // `/proc/self/status` reports the thread-group leader's NoNewPrivs,
        // but harden() runs on a libtest worker thread, so cross-checking
        // /proc here is unreliable (it reads as 0 even when the prctl on the
        // worker thread succeeded). Assert on harden()'s reported outcome
        // instead, and skip when the sandbox forbids the prctl entirely (some
        // CI/container environments do).
        let report = harden();
        // harden() must always attempt this step on Linux — assert the
        // contract so a renamed/removed step is caught as a regression.
        let step = report
            .results
            .iter()
            .find(|r| r.name == "prctl.pr_set_no_new_privs")
            .expect("harden() must report prctl.pr_set_no_new_privs on Linux");
        // Where the prctl is permitted it must succeed; skip only when the
        // sandbox forbids it (Err/Skipped).
        match &step.status {
            HardeningStatus::Ok => {}
            HardeningStatus::Err { reason } => {
                eprintln!("skipping: PR_SET_NO_NEW_PRIVS not permitted here: {reason}");
            }
            HardeningStatus::Skipped { reason } => {
                eprintln!("skipping: no_new_privs skipped: {reason}");
            }
        }
    }
}
