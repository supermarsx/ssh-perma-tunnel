//! macOS-specific hardening primitives.
//!
//! * `setrlimit(RLIMIT_CORE, {0, 0})` — disable core dumps.
//! * `ptrace(PT_DENY_ATTACH, 0, NULL, 0)` — refuse `ptrace`-style attach
//!   from a debugger. Gated behind the `macos-anti-debug` cargo feature
//!   because Apple notarization, `Instruments.app`, and `lldb` integration
//!   may break or alarm users. Default OFF.

use crate::{HardeningReport, HardeningResult};
use tracing::warn;

pub(crate) fn harden_into(report: &mut HardeningReport) {
    report.push(disable_core_dump());
    report.push(pt_deny_attach());
}

fn disable_core_dump() -> HardeningResult {
    let rl = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `setrlimit(2)` on macOS (Darwin) takes an `int resource`
    // by value and a `const struct rlimit *rlp`. We pass `RLIMIT_CORE`
    // and `&rl`, a pointer to a fully-initialised `libc::rlimit` whose
    // storage outlives the call. The kernel reads the two `rlim_t`
    // fields and does not retain the pointer. No caller-supplied
    // pointers participate. Returns -1/errno on failure; surfaced via
    // `last_os_error`. See `setrlimit(2)` man page.
    let rc = unsafe { libc::setrlimit(libc::RLIMIT_CORE, &rl) };
    if rc == 0 {
        HardeningResult::ok("setrlimit.rlimit_core")
    } else {
        let err = std::io::Error::last_os_error();
        warn!(error = %err, "setrlimit(RLIMIT_CORE) failed");
        HardeningResult::err("setrlimit.rlimit_core", short_errno(&err))
    }
}

#[cfg(feature = "macos-anti-debug")]
fn pt_deny_attach() -> HardeningResult {
    // `PT_DENY_ATTACH` is value 31 on macOS (declared in <sys/ptrace.h>).
    // libc on macOS does not expose this constant in stable, so we hard-code
    // the value here. The signature is
    //   int ptrace(int request, pid_t pid, caddr_t addr, int data);
    const PT_DENY_ATTACH: libc::c_int = 31;
    // SAFETY: macOS `ptrace(2)` is invoked with request = PT_DENY_ATTACH
    // (31) per <sys/ptrace.h>. Apple's documentation specifies that for
    // PT_DENY_ATTACH the `pid`, `addr`, and `data` arguments are ignored;
    // we pass 0 / NULL / 0 anyway to match the C prototype
    // `int ptrace(int, pid_t, caddr_t, int)`. No memory is dereferenced
    // by the kernel for this request. The call is thread-safe and may
    // be made at most once per process; subsequent calls return EBUSY,
    // which we report via `HardeningResult::err` — never a panic. If a
    // debugger is already attached when this call runs the kernel will
    // SIGKILL the process, which is the intended hardening behavior.
    let rc = unsafe { libc::ptrace(PT_DENY_ATTACH, 0, std::ptr::null_mut::<libc::c_char>(), 0) };
    if rc == 0 {
        HardeningResult::ok("ptrace.pt_deny_attach")
    } else {
        let err = std::io::Error::last_os_error();
        warn!(error = %err, "ptrace(PT_DENY_ATTACH) failed");
        HardeningResult::err("ptrace.pt_deny_attach", short_errno(&err))
    }
}

#[cfg(not(feature = "macos-anti-debug"))]
fn pt_deny_attach() -> HardeningResult {
    HardeningResult::skipped(
        "ptrace.pt_deny_attach",
        "gated behind cargo feature macos-anti-debug (off by default)",
    )
}

fn short_errno(err: &std::io::Error) -> String {
    let s = err.to_string();
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
    fn disable_core_dump_does_not_panic() {
        let r = disable_core_dump();
        assert_eq!(r.name, "setrlimit.rlimit_core");
    }

    #[test]
    fn pt_deny_attach_default_is_skipped() {
        let r = pt_deny_attach();
        assert_eq!(r.name, "ptrace.pt_deny_attach");
        #[cfg(not(feature = "macos-anti-debug"))]
        assert!(r.status.is_skipped());
    }
}
