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
        unsafe {
            let mut token: HANDLE = HANDLE::default();
            OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).ok()?;
            let mut elevation = TOKEN_ELEVATION::default();
            let mut ret_len: u32 = 0;
            let elevation_ptr: *mut TOKEN_ELEVATION = std::ptr::from_mut(&mut elevation);
            let result = GetTokenInformation(
                token,
                TokenElevation,
                Some(elevation_ptr.cast()),
                u32::try_from(mem::size_of::<TOKEN_ELEVATION>()).unwrap_or(0),
                &mut ret_len,
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
