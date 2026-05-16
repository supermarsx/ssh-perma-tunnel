//! Best-effort memory locking helpers.
//!
//! `try_mlock(buf)` attempts to lock a byte buffer's pages into RAM so
//! they cannot be paged out to swap. The operation is best-effort:
//!
//! * On Unix it calls `mlock(2)` via `nix`.
//! * On Windows it calls `VirtualLock` via the `windows` crate.
//! * On any other platform it is a no-op returning `Ok(false)`.
//!
//! A return of `Ok(false)` means the underlying syscall reported permission
//! or quota denial (e.g. `RLIMIT_MEMLOCK` exceeded). Callers should never
//! treat that as a hard error: the requirement in spec §14.6 is that
//! locking is *attempted*, with a clear diagnostic when unavailable.
//!
//! `Ok(true)` means the lock was placed; the caller is responsible for
//! pairing with [`try_munlock`] before the buffer is freed.

use spt_core::Result;
use tracing::warn;

/// Attempt to lock `buf` into RAM. Returns `Ok(true)` on success,
/// `Ok(false)` if the platform refused (no privileges / quota exhausted /
/// unsupported), and `Err` only if a wholly unexpected failure occurred.
pub fn try_mlock(buf: &[u8]) -> Result<bool> {
    if buf.is_empty() {
        return Ok(false);
    }
    do_mlock(buf)
}

/// Pair of [`try_mlock`]; same return semantics.
pub fn try_munlock(buf: &[u8]) -> Result<bool> {
    if buf.is_empty() {
        return Ok(false);
    }
    do_munlock(buf)
}

// All `do_mlock`/`do_munlock` impls keep the `Result` return so the public
// API is stable across platforms; some platforms surface unexpected
// failures as `Err`, even though the current implementations only ever
// return `Ok`.
#[allow(clippy::unnecessary_wraps)]
#[cfg(unix)]
fn do_mlock(buf: &[u8]) -> Result<bool> {
    use std::ffi::c_void;
    let ptr = buf.as_ptr() as *const c_void;
    // SAFETY: we hold a borrow of `buf` for the duration of this call, so
    // the pointer and length describe a valid readable region.
    let res = unsafe {
        nix::sys::mman::mlock(std::ptr::NonNull::new(ptr.cast_mut()).unwrap(), buf.len())
    };
    match res {
        Ok(()) => Ok(true),
        Err(e) => {
            warn!(error = %e, "mlock failed; secret pages may be swappable");
            Ok(false)
        }
    }
}

#[allow(clippy::unnecessary_wraps)]
#[cfg(unix)]
fn do_munlock(buf: &[u8]) -> Result<bool> {
    use std::ffi::c_void;
    let ptr = buf.as_ptr() as *const c_void;
    // SAFETY: same reasoning as `do_mlock`.
    let res = unsafe {
        nix::sys::mman::munlock(std::ptr::NonNull::new(ptr.cast_mut()).unwrap(), buf.len())
    };
    match res {
        Ok(()) => Ok(true),
        Err(e) => {
            warn!(error = %e, "munlock failed");
            Ok(false)
        }
    }
}

#[allow(clippy::unnecessary_wraps)]
#[cfg(windows)]
fn do_mlock(buf: &[u8]) -> Result<bool> {
    use windows::Win32::System::Memory::VirtualLock;
    // SAFETY: `buf` is a valid readable region for its full length.
    let r = unsafe {
        VirtualLock(
            buf.as_ptr().cast::<core::ffi::c_void>().cast_mut(),
            buf.len(),
        )
    };
    match r {
        Ok(()) => Ok(true),
        Err(e) => {
            warn!(error = %e, "VirtualLock failed; secret pages may be swappable");
            Ok(false)
        }
    }
}

#[allow(clippy::unnecessary_wraps)]
#[cfg(windows)]
fn do_munlock(buf: &[u8]) -> Result<bool> {
    use windows::Win32::System::Memory::VirtualUnlock;
    // SAFETY: `buf` is a valid readable region for its full length.
    let r = unsafe {
        VirtualUnlock(
            buf.as_ptr().cast::<core::ffi::c_void>().cast_mut(),
            buf.len(),
        )
    };
    match r {
        Ok(()) => Ok(true),
        Err(e) => {
            warn!(error = %e, "VirtualUnlock failed");
            Ok(false)
        }
    }
}

#[allow(clippy::unnecessary_wraps)]
#[cfg(not(any(unix, windows)))]
fn do_mlock(_buf: &[u8]) -> Result<bool> {
    Ok(false)
}

#[allow(clippy::unnecessary_wraps)]
#[cfg(not(any(unix, windows)))]
fn do_munlock(_buf: &[u8]) -> Result<bool> {
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_buffer_is_noop() {
        assert!(matches!(try_mlock(&[]), Ok(false)));
        assert!(matches!(try_munlock(&[]), Ok(false)));
    }

    #[test]
    fn locking_succeeds_or_returns_false() {
        // The test must succeed on any platform, regardless of whether the
        // process has privileges to lock memory. The contract is "Ok(_)".
        let buf = vec![0u8; 4096];
        let locked = try_mlock(&buf).expect("mlock returns Ok regardless of privileges");
        // If we got a lock, we must be able to clean it up.
        if locked {
            try_munlock(&buf).expect("munlock pairs with mlock");
        }
    }

    #[test]
    fn small_buffer_round_trip() {
        let buf = vec![0u8; 1];
        let locked = try_mlock(&buf).expect("mlock returns Ok");
        if locked {
            try_munlock(&buf).expect("munlock pairs with mlock");
        }
    }

    #[test]
    fn munlock_unlocked_buffer_is_ok_or_false() {
        let buf = vec![0u8; 4096];
        let _ = try_munlock(&buf).expect("munlock returns Ok");
    }
}
