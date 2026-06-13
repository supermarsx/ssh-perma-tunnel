//! Best-effort detection of whether the current process can bind privileged
//! TCP/UDP ports (<1024 on POSIX) without an actual bind attempt.
//!
//! Heuristics by platform:
//! * Linux — `CAP_NET_BIND_SERVICE` in the effective set, *or* effective UID 0.
//! * macOS / other Unix — effective UID 0.
//! * Windows — process token elevation (`TokenElevation`).
//!
//! Validators upstream surface a friendlier error before the bind syscall.

/// True if the process is likely able to bind a privileged port.
#[must_use]
pub fn can_bind_privileged_port() -> bool {
    platform::can_bind_privileged_port()
}

#[cfg(target_os = "linux")]
mod platform {
    pub(super) fn can_bind_privileged_port() -> bool {
        if is_root() {
            return true;
        }
        matches!(
            caps::has_cap(
                None,
                caps::CapSet::Effective,
                caps::Capability::CAP_NET_BIND_SERVICE
            ),
            Ok(true)
        )
    }

    fn is_root() -> bool {
        nix::unistd::geteuid().is_root()
    }
}

#[cfg(all(unix, not(target_os = "linux")))]
mod platform {
    pub(super) fn can_bind_privileged_port() -> bool {
        nix::unistd::geteuid().is_root()
    }
}

#[cfg(windows)]
mod platform {
    use std::mem;

    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::Security::{
        GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    pub(super) fn can_bind_privileged_port() -> bool {
        is_elevated().unwrap_or(false)
    }

    fn is_elevated() -> Option<bool> {
        // SAFETY: t8-D2 single FFI block covering 4 Win32 calls. Combined
        // into one block because (1) `is_elevated` is not an `unsafe fn`,
        // so `unsafe_op_in_unsafe_fn` does not require per-call nesting,
        // and (2) the token-close invariant reads more cleanly as a single
        // linear block. Per-call invariants:
        //   * `GetCurrentProcess()` returns a pseudo-handle to the calling
        //     process — always valid, does not require closing (Win32 spec).
        //   * `OpenProcessToken` writes the opened access-token handle into
        //     `&mut token` on success. On failure it leaves `token` at its
        //     default (null) value and we early-return; the subsequent
        //     `CloseHandle` is therefore never reached on a null handle.
        //   * `elevation_ptr` is a unique mutable pointer into local stack
        //     `elevation`. `GetTokenInformation` writes
        //     `size_of::<TOKEN_ELEVATION>()` bytes through it; the length
        //     argument matches the type size exactly. `ret_len` is also a
        //     stack-local out-parameter.
        //   * `CloseHandle(token)` runs unconditionally before evaluating
        //     the `GetTokenInformation` result. If `OpenProcessToken`
        //     failed we returned earlier; otherwise `token` is the live
        //     handle just opened, and no use of `token` occurs after close.
        //   * On `GetTokenInformation` failure we discard `elevation`,
        //     which was initialised by `TOKEN_ELEVATION::default()` even
        //     if Windows did not write into it — no UB from reading
        //     uninitialised memory.
        unsafe {
            let mut token: HANDLE = HANDLE::default();
            OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut token).ok()?; // 1.88 lint: implicit raw-pointer borrow
            let mut elevation = TOKEN_ELEVATION::default();
            let mut ret_len: u32 = 0;
            let elevation_ptr: *mut TOKEN_ELEVATION = std::ptr::from_mut(&mut elevation);
            let result = GetTokenInformation(
                token,
                TokenElevation,
                Some(elevation_ptr.cast()),
                u32::try_from(mem::size_of::<TOKEN_ELEVATION>()).unwrap_or(0),
                &raw mut ret_len, // 1.88 lint: implicit raw-pointer borrow
            );
            let _ = CloseHandle(token);
            result.ok()?;
            Some(elevation.TokenIsElevated != 0)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn returns_a_bool_without_panicking() {
        // Smoke test: function must not panic on any supported OS.
        let _ = can_bind_privileged_port();
    }
}
