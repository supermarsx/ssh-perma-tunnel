//! Linux-specific hardening primitives.
//!
//! All three primitives here go through `libc` rather than `nix` because
//! `nix`'s prctl/setrlimit surface in 0.29 either wraps fewer values than
//! we need or returns typed enums that hide the discriminator we want.
//!
//! Each call is wrapped in a tightly-scoped `unsafe` block with a
//! `// SAFETY:` justification.

use crate::{HardeningReport, HardeningResult};
use tracing::warn;

pub(crate) fn harden_into(report: &mut HardeningReport) {
    report.push(set_dumpable());
    report.push(set_no_new_privs());
    report.push(disable_core_dump());
}

/// `prctl(PR_SET_DUMPABLE, 0)` — make the process non-dumpable. This
/// disables core dumps, suppresses `/proc/self/mem` access by other UIDs,
/// and prevents `ptrace(PTRACE_ATTACH)` from a non-privileged UID.
fn set_dumpable() -> HardeningResult {
    // SAFETY: `prctl(2)` is a stable Linux syscall. For `PR_SET_DUMPABLE`
    // (option = 4) the kernel reads `arg2` as an integer flag
    // (0 = SUID_DUMP_DISABLE) and ignores `arg3..arg5`; no pointers are
    // dereferenced. The call is thread-safe and idempotent. On failure the
    // syscall returns -1 and sets errno, which we surface via
    // `std::io::Error::last_os_error()`. Best-effort hardening — failure
    // is reported but not fatal.
    let rc = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0_u64, 0_u64, 0_u64, 0_u64) };
    if rc == 0 {
        HardeningResult::ok("prctl.pr_set_dumpable")
    } else {
        let err = std::io::Error::last_os_error();
        warn!(error = %err, "PR_SET_DUMPABLE failed");
        HardeningResult::err("prctl.pr_set_dumpable", short_errno(&err))
    }
}

/// `prctl(PR_SET_NO_NEW_PRIVS, 1)` — once set, no `execve(2)` can grant
/// the process new privileges (setuid binaries become no-ops, file
/// capabilities are stripped). Permanent; cannot be unset.
fn set_no_new_privs() -> HardeningResult {
    // SAFETY: `prctl(2)` with `PR_SET_NO_NEW_PRIVS` (option = 38, since
    // Linux 3.5). The kernel reads `arg2 == 1` as a scalar flag and
    // ignores `arg3..arg5`; no pointers are dereferenced. The bit is
    // process-wide, thread-safe to set, and permanent (cannot be unset),
    // so repeated calls are idempotent no-ops. Returns -1/errno on
    // failure; best-effort, never panics.
    let rc = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1_u64, 0_u64, 0_u64, 0_u64) };
    if rc == 0 {
        HardeningResult::ok("prctl.pr_set_no_new_privs")
    } else {
        let err = std::io::Error::last_os_error();
        warn!(error = %err, "PR_SET_NO_NEW_PRIVS failed");
        HardeningResult::err("prctl.pr_set_no_new_privs", short_errno(&err))
    }
}

/// `setrlimit(RLIMIT_CORE, {0, 0})` — belt-and-braces disable core dumps
/// even on kernels that ignore `PR_SET_DUMPABLE` for certain paths.
fn disable_core_dump() -> HardeningResult {
    let rl = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `setrlimit(2)` is a stable POSIX/Linux syscall. We pass
    // `RLIMIT_CORE` (= 4) as the resource and a `&rl` pointing to a
    // fully-initialised `libc::rlimit` whose lifetime spans the call.
    // The kernel reads the two `rlim_t` fields and does not retain the
    // pointer. Lowering `rlim_max` to 0 is irreversible for an
    // unprivileged process, which is exactly the property we want. No
    // pointers from caller-supplied data flow into the syscall. Returns
    // -1/errno on failure; surfaced via `last_os_error`.
    let rc = unsafe { libc::setrlimit(libc::RLIMIT_CORE, &raw const rl) };
    if rc == 0 {
        HardeningResult::ok("setrlimit.rlimit_core")
    } else {
        let err = std::io::Error::last_os_error();
        warn!(error = %err, "setrlimit(RLIMIT_CORE) failed");
        HardeningResult::err("setrlimit.rlimit_core", short_errno(&err))
    }
}

/// Strip the trailing OS-error-code parenthetical from
/// `std::io::Error::to_string` so the reason is stable across libc versions.
fn short_errno(err: &std::io::Error) -> String {
    let s = err.to_string();
    // io::Error formats as "Description (os error N)" on Linux — we keep
    // the description only.
    if let Some(idx) = s.rfind(" (os error") {
        s[..idx].to_string()
    } else {
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_errno_strips_os_error_suffix() {
        let e = std::io::Error::from_raw_os_error(1);
        let s = short_errno(&e);
        assert!(!s.contains("os error"), "unexpected: {s}");
        assert!(!s.is_empty());
    }

    #[test]
    fn set_dumpable_does_not_panic() {
        // Just ensure it returns *some* result.
        let r = set_dumpable();
        assert_eq!(r.name, "prctl.pr_set_dumpable");
    }

    #[test]
    fn no_new_privs_does_not_panic() {
        let r = set_no_new_privs();
        assert_eq!(r.name, "prctl.pr_set_no_new_privs");
    }

    #[test]
    fn disable_core_dump_does_not_panic() {
        let r = disable_core_dump();
        assert_eq!(r.name, "setrlimit.rlimit_core");
    }
}
