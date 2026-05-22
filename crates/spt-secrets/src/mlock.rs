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
//!
//! See also [`crate::secret_alloc::SecretAlloc`] for a higher-level wrapper
//! that pairs `mlock` with a guaranteed zero-on-drop and (on Linux 5.14+)
//! prefers `memfd_secret(2)` over `mlock`.

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

/// Raw-pointer variant of [`try_mlock`] used by allocators that hold a
/// `NonNull<u8>` rather than a `&[u8]` borrow (e.g.
/// [`crate::secret_alloc::SecretAlloc`]'s heap path).
///
/// # Safety
///
/// `ptr` must point to `len` bytes of memory that the caller exclusively
/// owns for the duration of the call. The contract otherwise matches
/// [`try_mlock`].
pub unsafe fn try_mlock_raw(ptr: *const u8, len: usize) -> Result<bool> {
    if len == 0 || ptr.is_null() {
        return Ok(false);
    }
    // SAFETY: `core::slice::from_raw_parts(ptr, len)` — caller's contract
    // (documented on this `unsafe fn`) guarantees `ptr` is non-null
    // (checked above as a defence-in-depth), points to `len` initialised
    // bytes of memory the caller exclusively owns for the duration of
    // the call, and `len <= isize::MAX`. The returned `&[u8]` lifetime is
    // confined to this function body, ending before we return — the
    // caller's exclusive ownership window covers the entire borrow. The
    // underlying syscall (`mlock`/`VirtualLock`) only reads the address
    // and length, not the bytes, so the init requirement is conservative
    // here but enforced by `from_raw_parts` regardless.
    let view = unsafe { core::slice::from_raw_parts(ptr, len) };
    do_mlock(view)
}

/// Pair of [`try_mlock_raw`]; same safety contract.
///
/// # Safety
///
/// `ptr` must point to `len` bytes of memory the caller exclusively owns.
pub unsafe fn try_munlock_raw(ptr: *const u8, len: usize) -> Result<bool> {
    if len == 0 || ptr.is_null() {
        return Ok(false);
    }
    // SAFETY: `core::slice::from_raw_parts(ptr, len)` — identical
    // invariants to `try_mlock_raw` above: caller guarantees `ptr` is
    // non-null, points to `len` bytes of caller-owned memory, and
    // `len <= isize::MAX`. The borrow is confined to this function.
    // `munlock`/`VirtualUnlock` reads address and length only.
    let view = unsafe { core::slice::from_raw_parts(ptr, len) };
    do_munlock(view)
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
    // SAFETY: `nix::sys::mman::mlock` wraps `mlock(2)`. We hold `buf:
    // &[u8]` for the entire syscall duration, so:
    // * The pointer is non-null and aligned for `u8` (trivially).
    // * The `[ptr, ptr+buf.len())` region is mapped, readable, and
    //   contains initialised bytes (`&[u8]` invariant).
    // * `buf.len() <= isize::MAX` (`&[u8]` invariant).
    // * The kernel does not write to the memory; it only adjusts the
    //   page residency. Concurrent reads by other threads remain sound.
    // `NonNull::new(...).unwrap()` is safe because `buf.as_ptr()` is
    // non-null for a non-empty slice (guarded by `try_mlock`'s empty
    // check). Thread safety: `mlock` is process-wide (it affects all
    // threads' view of the VMA), but the syscall itself is reentrant-safe.
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
    // SAFETY: `nix::sys::mman::munlock` wraps `munlock(2)`. Invariants
    // identical to `do_mlock`: live `&[u8]` borrow means a valid,
    // readable, in-range region. `munlock` only updates page residency
    // metadata; it does not read or write the bytes. Pairing discipline:
    // callers (e.g. `SecretSlice::Drop`) must invoke `munlock` exactly
    // once per successful `mlock`; an `munlock` on a region that is not
    // currently locked is a no-op error which we surface as `Ok(false)`
    // and log via `warn!`.
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
    // SAFETY: `VirtualLock(lpAddress, dwSize)` — Win32 FFI. We hold a
    // live `&[u8]` borrow so `[ptr, ptr+buf.len())` is a valid, mapped,
    // readable region with `buf.len() <= isize::MAX`. `VirtualLock` only
    // pins pages in the working set; it does not read or write the
    // bytes, so an `&[u8]` borrow (shared) is sufficient even though
    // the FFI signature takes `*mut c_void` (the cast via `cast_mut`
    // does not imply mutation). Thread safety: `VirtualLock` is
    // process-global; concurrent reads from other threads remain sound.
    // Failure modes: `ERROR_WORKING_SET_QUOTA` etc. — surfaced as
    // `Ok(false)` per the public contract.
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
    // SAFETY: `VirtualUnlock(lpAddress, dwSize)` — Win32 FFI. Invariants
    // identical to `do_mlock`: live `&[u8]` borrow guarantees a valid,
    // mapped, readable region within `isize::MAX`. The cast to
    // `*mut c_void` does not imply mutation; the API only updates
    // working-set residency. Pairing: must be called exactly once per
    // successful `VirtualLock`. An unlock of an unlocked region returns
    // `ERROR_NOT_LOCKED` which we surface as `Ok(false)` and log.
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
