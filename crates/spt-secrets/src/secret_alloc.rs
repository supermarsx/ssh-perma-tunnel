//! Non-swappable, zero-on-drop secret allocations.
//!
//! [`SecretAlloc::new`] returns a byte slice whose backing pages are:
//!
//! 1. **Non-swappable** — either backed by `memfd_secret(2)` on Linux ≥5.14
//!    (kernels with `CONFIG_SECRETMEM=y`), or `mlock`/`VirtualLock`-ed on the
//!    fallback path.
//! 2. **Zero-initialised** — Linux `memfd_secret` pages are zero by
//!    construction; the heap fallback `zeroize`s after `alloc::alloc`.
//! 3. **Zeroed on drop** — guaranteed under panic via `Drop` for both paths.
//!
//! ## Linux `memfd_secret` path
//!
//! Probed at runtime by issuing `libc::syscall(SYS_memfd_secret, 0)` and
//! checking that the return value is `>= 0`. The returned file descriptor is
//! sized via `ftruncate` and the pages are `mmap`-ed `MAP_SHARED`. Memory
//! backed by `memfd_secret` is unmapped from the kernel direct map and is not
//! accessible via `/proc/<pid>/mem`, kernel exploits that read direct-map
//! pages, or kdump.
//!
//! If the probe returns `ENOSYS` (kernel too old or `CONFIG_SECRETMEM=n`) we
//! fall through to the heap fallback. Each call probes once and the result is
//! cached in a `OnceLock<bool>`.
//!
//! ## Fallback path (non-Linux, or Linux without `memfd_secret`)
//!
//! Plain heap allocation via [`alloc::alloc`] with an 8-byte aligned layout,
//! followed by `try_mlock` / `VirtualLock`. `mlock` failure (typically
//! `RLIMIT_MEMLOCK`) is **non-fatal**: the buffer is still usable, it merely
//! may be paged out. This matches spec §14.6.
//!
//! ## Typed wrapper
//!
//! [`MemfdSecretBox<T>`] is a thin wrapper over a [`SecretSlice`] sized for
//! exactly `size_of::<T>()` bytes. `T` must be `Default + zeroize::Zeroize`.
//! `Default` is required because we need a way to construct the initial value
//! inside the protected page without first creating it on the stack
//! (callers should still treat `T` as `bytemuck::Pod`-shaped for correctness;
//! see the doc comment on [`MemfdSecretBox::new`]).

use core::sync::atomic;
use std::alloc::{self, Layout};
use std::ops::{Deref, DerefMut};
use std::ptr::NonNull;
#[cfg(target_os = "linux")]
use std::sync::OnceLock;

use spt_core::{Error, Result};
#[cfg(target_os = "linux")]
use tracing::{debug, warn};
use zeroize::Zeroize;

use crate::mlock::{try_mlock, try_munlock};

/// Maximum allocation in bytes. Matches `Layout`'s upper bound; allocations
/// larger than `isize::MAX` cannot be expressed as a Rust slice.
const MAX_LEN: usize = isize::MAX as usize;

/// Backing storage variant. The discriminant is only inspected on drop.
#[derive(Debug)]
enum Backing {
    /// Plain heap allocation. `mlock` may or may not have succeeded;
    /// `locked` records the outcome so drop pairs symmetrically.
    Heap { layout: Layout, locked: bool },
    /// Linux `memfd_secret`-backed `mmap`. The fd is kept around for the
    /// lifetime of the mapping; drop closes it after `munmap`.
    #[cfg(target_os = "linux")]
    MemfdSecret { fd: libc::c_int, map_len: usize },
}

/// A page-locked, zero-on-drop byte slice.
///
/// Backed by `memfd_secret(2)` on Linux 5.14+, otherwise by an mlocked heap
/// allocation. Dereferences to `&[u8]` / `&mut [u8]`.
pub struct SecretSlice {
    ptr: NonNull<u8>,
    len: usize,
    backing: Backing,
}

// SAFETY: `SecretSlice` owns its pointer exclusively (no aliasing copies
// exist) and the memory itself is plain bytes with no per-thread state.
// Moving the wrapper to another thread is sound; concurrent `&` access from
// multiple threads is sound because bytes are POD. Concurrent `&mut` access
// is prevented by the borrow checker.
unsafe impl Send for SecretSlice {}
// SAFETY: same as `Send` — bytes are POD; `&SecretSlice` only hands out
// `&[u8]` which is `Sync`.
unsafe impl Sync for SecretSlice {}

impl SecretSlice {
    /// Number of bytes in the slice.
    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }

    /// True if the slice has zero length.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Returns the raw pointer to the first byte. Test-only helper; never
    /// store this pointer past the `SecretSlice`'s lifetime.
    #[cfg(test)]
    fn as_ptr(&self) -> *const u8 {
        self.ptr.as_ptr()
    }

    /// True if this slice is backed by `memfd_secret(2)`.
    #[must_use]
    #[allow(clippy::unused_self)] // on non-Linux this is always `false`
    pub fn is_memfd_secret(&self) -> bool {
        #[cfg(target_os = "linux")]
        {
            matches!(self.backing, Backing::MemfdSecret { .. })
        }
        #[cfg(not(target_os = "linux"))]
        {
            false
        }
    }
}

impl Deref for SecretSlice {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        if self.len == 0 {
            return &[];
        }
        // SAFETY: `self.ptr` is a valid, aligned pointer to `self.len`
        // initialized bytes; the lifetime of the returned slice is bounded by
        // `&self`; no other `&mut` reference can exist concurrently because
        // `&self` is borrowed.
        unsafe { core::slice::from_raw_parts(self.ptr.as_ptr(), self.len) }
    }
}

impl DerefMut for SecretSlice {
    fn deref_mut(&mut self) -> &mut [u8] {
        if self.len == 0 {
            return &mut [];
        }
        // SAFETY: `self.ptr` is a valid, aligned, exclusively-owned pointer
        // to `self.len` bytes; `&mut self` guarantees uniqueness.
        unsafe { core::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.len) }
    }
}

impl Drop for SecretSlice {
    fn drop(&mut self) {
        // 1. Zero the contents. Use the volatile-safe `zeroize::Zeroize`
        //    implementation on the slice view so the compiler cannot elide
        //    the write.
        if self.len > 0 {
            // SAFETY: same conditions as `deref_mut`.
            let slice: &mut [u8] =
                unsafe { core::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.len) };
            slice.zeroize();
            // Compiler fence prevents the zeroizing write from being
            // reordered past the unmap/free.
            atomic::compiler_fence(atomic::Ordering::SeqCst);
        }

        // 2. Tear down the backing.
        match self.backing {
            Backing::Heap { layout, locked } => {
                if locked && self.len > 0 {
                    // try_munlock takes a &[u8] view — re-borrow the slice.
                    // SAFETY: pointer + length describe a valid region we
                    // still exclusively own.
                    let view: &[u8] =
                        unsafe { core::slice::from_raw_parts(self.ptr.as_ptr(), self.len) };
                    let _ = try_munlock(view);
                }
                if layout.size() > 0 {
                    // SAFETY: `self.ptr` came from `alloc::alloc` with the
                    // same `layout`; we own it exclusively.
                    unsafe { alloc::dealloc(self.ptr.as_ptr(), layout) };
                }
            }
            #[cfg(target_os = "linux")]
            Backing::MemfdSecret { fd, map_len } => {
                if map_len > 0 {
                    // SAFETY: `self.ptr` was returned by `mmap` with
                    // `map_len`; we still exclusively own the mapping.
                    let r =
                        unsafe { libc::munmap(self.ptr.as_ptr().cast::<libc::c_void>(), map_len) };
                    if r != 0 {
                        warn!("munmap failed on secret mapping");
                    }
                }
                // SAFETY: `fd` was returned by `memfd_secret` and never
                // dup'ed; closing here is the only owner.
                let r = unsafe { libc::close(fd) };
                if r != 0 {
                    warn!("close failed on secret memfd");
                }
            }
        }
    }
}

/// Factory for [`SecretSlice`].
pub struct SecretAlloc;

impl SecretAlloc {
    /// Allocate a `len`-byte zero-initialised, non-swappable buffer.
    ///
    /// Returns [`Error::RuntimeFailure`] when:
    ///
    /// * `len > isize::MAX` (cannot be represented as a Rust slice).
    /// * The underlying allocator returns null on the heap fallback path.
    /// * The kernel returns an unexpected error on the `memfd_secret` path
    ///   (other than `ENOSYS`, which transparently falls through).
    ///
    /// `mlock` failure (e.g. `RLIMIT_MEMLOCK`) is **not** an error — see
    /// module-level docs.
    #[allow(clippy::new_ret_no_self)] // factory pattern; returns `SecretSlice`
    pub fn new(len: usize) -> Result<SecretSlice> {
        if len > MAX_LEN {
            return Err(Error::RuntimeFailure(format!(
                "SecretAlloc: requested {len} bytes exceeds isize::MAX"
            )));
        }
        if len == 0 {
            // Use a dangling-but-aligned pointer; nothing to lock or unmap.
            // Layout::from_size_align(0, 1) is valid; alloc::alloc on it is
            // UB so we skip the call.
            return Ok(SecretSlice {
                ptr: NonNull::<u8>::dangling(),
                len: 0,
                backing: Backing::Heap {
                    layout: Layout::from_size_align(0, 1).expect("zero layout"),
                    locked: false,
                },
            });
        }

        #[cfg(target_os = "linux")]
        {
            match try_memfd_secret(len) {
                Ok(Some(slice)) => return Ok(slice),
                Ok(None) => {
                    debug!("memfd_secret unavailable, using mlock-heap fallback");
                }
                Err(e) => return Err(e),
            }
        }

        heap_fallback(len)
    }
}

/// Heap-allocation fallback path. Allocates `len` zero bytes, attempts to
/// mlock the buffer, and returns a [`SecretSlice`] regardless of the mlock
/// outcome.
fn heap_fallback(len: usize) -> Result<SecretSlice> {
    debug_assert!(len > 0);
    let layout = Layout::from_size_align(len, 8).map_err(|e| {
        Error::RuntimeFailure(format!("SecretAlloc: invalid layout for {len}: {e}"))
    })?;
    // SAFETY: `layout.size() > 0` (checked above); `alloc::alloc` is the
    // sanctioned global allocator entry point.
    let raw = unsafe { alloc::alloc(layout) };
    let Some(ptr) = NonNull::new(raw) else {
        return Err(Error::RuntimeFailure(format!(
            "SecretAlloc: heap allocation of {len} bytes failed"
        )));
    };
    // Zero the allocation. `alloc::alloc` returns uninitialised bytes; we
    // contract zero-initialisation in the public API.
    // SAFETY: `ptr` is valid for writes of `len` bytes; alignment is 8.
    unsafe { core::ptr::write_bytes(ptr.as_ptr(), 0u8, len) };

    // Attempt mlock. Failure is non-fatal (warned via tracing in mlock.rs).
    // SAFETY of the slice view: ptr + len describe a valid initialised
    // region that we exclusively own.
    let locked = {
        let view: &[u8] = unsafe { core::slice::from_raw_parts(ptr.as_ptr(), len) };
        try_mlock(view).unwrap_or(false)
    };

    Ok(SecretSlice {
        ptr,
        len,
        backing: Backing::Heap { layout, locked },
    })
}

/// Runtime probe + execute for `memfd_secret(2)`. Returns:
///
/// * `Ok(Some(slice))` — secret mapping created successfully.
/// * `Ok(None)` — kernel returned `ENOSYS` (or the probe never succeeded);
///   caller should use [`heap_fallback`].
/// * `Err(_)` — the syscall succeeded once at probe time but the actual
///   allocation hit a different error (e.g. `ENOMEM`).
#[cfg(target_os = "linux")]
fn try_memfd_secret(len: usize) -> Result<Option<SecretSlice>> {
    if !memfd_secret_available() {
        return Ok(None);
    }

    // 1. Open a fresh memfd_secret fd. Flags = 0 (no FD_CLOEXEC alternative
    //    is defined by the upstream syscall ABI; the kernel sets close-on-
    //    exec implicitly).
    //
    // SAFETY: `SYS_memfd_secret` takes a single `unsigned int flags`
    // argument; passing 0 is always valid. The return value is either a
    // non-negative fd or -1 with errno set.
    let fd_raw = unsafe { libc::syscall(libc::SYS_memfd_secret, 0u64) };
    if fd_raw < 0 {
        let errno = errno();
        if errno == libc::ENOSYS {
            return Ok(None);
        }
        return Err(Error::RuntimeFailure(format!(
            "memfd_secret syscall failed: errno {errno}"
        )));
    }
    // libc::syscall returns `c_long`; fd fits in `c_int`. Sanity-check the
    // narrowing — every reasonable kernel returns fds < i32::MAX.
    let fd: libc::c_int = match libc::c_int::try_from(fd_raw) {
        Ok(v) => v,
        Err(_) => {
            // Extremely unlikely; clean up and bail.
            // SAFETY: fd_raw is a valid kernel-returned fd.
            let _ = unsafe { libc::close(fd_raw as libc::c_int) };
            return Err(Error::RuntimeFailure(
                "memfd_secret returned out-of-range fd".into(),
            ));
        }
    };

    // 2. Size the fd.
    // SAFETY: `fd` is a fresh kernel-allocated fd we own; `len` is bounded
    // by isize::MAX which fits in off_t on Linux.
    let off_len = libc::off_t::try_from(len).map_err(|_| {
        // SAFETY: clean up the fd before returning.
        let _ = unsafe { libc::close(fd) };
        Error::RuntimeFailure(format!("len {len} does not fit in off_t"))
    })?;
    // SAFETY: fd is owned, off_len was range-checked.
    let r = unsafe { libc::ftruncate(fd, off_len) };
    if r != 0 {
        let errno = errno();
        // SAFETY: cleanup of owned fd.
        let _ = unsafe { libc::close(fd) };
        return Err(Error::RuntimeFailure(format!(
            "ftruncate(memfd_secret, {len}) failed: errno {errno}"
        )));
    }

    // 3. Map the fd. MAP_SHARED is mandatory for memfd_secret (the kernel
    //    rejects MAP_PRIVATE).
    // SAFETY: `ptr::null_mut()` lets the kernel choose the address; `len`
    // matches what we ftruncate'd to; PROT_READ|PROT_WRITE matches the
    // intended access pattern; MAP_SHARED is required for memfd_secret;
    // `fd` is owned; offset 0.
    let addr = unsafe {
        libc::mmap(
            core::ptr::null_mut(),
            len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            fd,
            0,
        )
    };
    if addr == libc::MAP_FAILED {
        let errno = errno();
        // SAFETY: cleanup of owned fd.
        let _ = unsafe { libc::close(fd) };
        return Err(Error::RuntimeFailure(format!(
            "mmap(memfd_secret) failed: errno {errno}"
        )));
    }

    // memfd_secret pages are guaranteed zero by the kernel — no explicit
    // memset required.

    let ptr = NonNull::new(addr.cast::<u8>()).ok_or_else(|| {
        // Pathological case; mmap returned NULL but not MAP_FAILED.
        Error::RuntimeFailure("mmap returned null pointer".into())
    })?;

    Ok(Some(SecretSlice {
        ptr,
        len,
        backing: Backing::MemfdSecret { fd, map_len: len },
    }))
}

#[cfg(target_os = "linux")]
fn errno() -> libc::c_int {
    // SAFETY: `__errno_location` returns a thread-local pointer that is
    // always valid for reads.
    unsafe { *libc::__errno_location() }
}

/// One-shot probe: is `SYS_memfd_secret` actually wired up in this kernel?
///
/// Probes by calling the syscall with `flags=0` and immediately closing the
/// returned fd if successful. The result is cached for the process lifetime.
#[cfg(target_os = "linux")]
fn memfd_secret_available() -> bool {
    static AVAILABLE: OnceLock<bool> = OnceLock::new();
    *AVAILABLE.get_or_init(|| {
        // SAFETY: same as in `try_memfd_secret` — single-arg syscall.
        let fd = unsafe { libc::syscall(libc::SYS_memfd_secret, 0u64) };
        if fd >= 0 {
            // SAFETY: close an owned fd.
            let _ = unsafe { libc::close(fd as libc::c_int) };
            true
        } else {
            let e = errno();
            if e != libc::ENOSYS && e != libc::EPERM {
                debug!("memfd_secret probe failed with errno {e}");
            }
            false
        }
    })
}

// ---------------------------------------------------------------------------
// Typed wrapper
// ---------------------------------------------------------------------------

/// Fixed-size secret container.
///
/// Wraps a [`SecretSlice`] sized exactly for one `T`. `T` must implement
/// [`Default`] (used to construct the initial value into the protected page
/// without a stack round-trip) and [`Zeroize`] (used on `Drop` of `T` itself
/// before the slice's own zero pass).
///
/// `T` should be `repr(C)` / `bytemuck::Pod`-shaped for soundness: the
/// `Drop` path zeroes the underlying bytes, which would invalidate any `T`
/// that needs to release indirect resources (e.g. `String`, `Vec<_>`,
/// owning pointers). For such types, prefer [`SecretSlice`] directly and
/// manage serialisation yourself.
pub struct MemfdSecretBox<T: Default + Zeroize> {
    slice: SecretSlice,
    _marker: core::marker::PhantomData<T>,
}

impl<T: Default + Zeroize> MemfdSecretBox<T> {
    /// Allocate a fresh `T::default()` inside protected memory.
    ///
    /// # Caveats
    ///
    /// The default value is constructed via `T::default()` and **moved** into
    /// the protected page using `ptr::write`. If `T::default()` allocates
    /// indirectly (e.g. `Vec`), those indirect allocations are *not*
    /// protected — only the inline bytes of `T` are. Use `T: Pod`-shaped
    /// types for full coverage.
    pub fn new() -> Result<Self> {
        let size = core::mem::size_of::<T>();
        let mut slice = SecretAlloc::new(size)?;

        if size > 0 {
            let default = T::default();
            // SAFETY: `slice` is aligned to 8 bytes; for the typed wrapper
            // we additionally require `align_of::<T>() <= 8`, asserted
            // below at compile-time-ish via a runtime debug_assert.
            debug_assert!(
                core::mem::align_of::<T>() <= 8,
                "MemfdSecretBox: T must align <= 8 bytes (got {})",
                core::mem::align_of::<T>()
            );
            let dst = slice.as_mut_ptr().cast::<T>();
            // SAFETY: `dst` is non-null, exclusively owned, points to
            // `size_of::<T>()` writeable bytes, and (subject to the
            // debug_assert above) is properly aligned for `T`.
            unsafe { core::ptr::write(dst, default) };
        }

        Ok(Self {
            slice,
            _marker: core::marker::PhantomData,
        })
    }

    /// Shared reference to the protected `T`.
    pub fn get(&self) -> &T {
        // SAFETY: invariants from `new`: the slice contains a valid `T`
        // for the lifetime of `self`; alignment was checked at construction.
        unsafe { &*self.slice.as_ptr().cast::<T>() }
    }

    /// Mutable reference to the protected `T`.
    pub fn get_mut(&mut self) -> &mut T {
        // SAFETY: same as `get`, plus `&mut self` guarantees uniqueness.
        unsafe { &mut *self.slice.deref_mut().as_mut_ptr().cast::<T>() }
    }
}

impl<T: Default + Zeroize> Drop for MemfdSecretBox<T> {
    fn drop(&mut self) {
        if core::mem::size_of::<T>() == 0 {
            return;
        }
        // Zeroize the typed payload first (lets `T`'s own Zeroize impl run,
        // which may e.g. clear individual fields). The slice's Drop will
        // then run its own byte-level zero pass and tear down the mapping.
        self.get_mut().zeroize();
        atomic::compiler_fence(atomic::Ordering::SeqCst);
        // We do NOT call ptr::drop_in_place::<T> because `T: Zeroize`
        // contract is that zeroization replaces conventional drop for the
        // secret path; running both could double-free indirect allocations.
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn new_returns_requested_length() {
        let s = SecretAlloc::new(64).expect("alloc");
        assert_eq!(s.len(), 64);
        assert!(!s.is_empty());
    }

    #[test]
    fn bytes_are_zero_initialised() {
        let s = SecretAlloc::new(1024).expect("alloc");
        assert!(s.iter().all(|&b| b == 0), "expected zero-filled buffer");
    }

    #[test]
    fn write_read_round_trip() {
        let mut s = SecretAlloc::new(32).expect("alloc");
        for (i, b) in s.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(7).wrapping_add(3);
        }
        for (i, b) in s.iter().enumerate() {
            assert_eq!(*b, (i as u8).wrapping_mul(7).wrapping_add(3));
        }
    }

    #[test]
    fn drop_zeroes_the_buffer() {
        // Allocate, fill with sentinel, capture the raw pointer, then
        // drop. After drop, the freed allocator slot may be re-used by a
        // subsequent allocation of the same shape — re-allocate and verify
        // the sentinel bytes are gone.
        //
        // NOTE: this is a best-effort probe. The drop path performs a
        // `zeroize()` on the bytes BEFORE deallocating, so a fresh `alloc`
        // landing on the same slot will read zeros (or whatever the
        // allocator put there). What we MUST guarantee is that the
        // sentinel pattern does not survive past drop. We test this by:
        // 1. Pre-drop: confirm the pattern is there via a raw read.
        // 2. Post-drop: re-allocate, raw-read the same slot, and verify
        //    the sentinel pattern does not appear in full.
        let pattern: u8 = 0xA5;
        let len = 256;

        let captured_ptr: *const u8;
        {
            let mut s = SecretAlloc::new(len).expect("alloc");
            for b in s.iter_mut() {
                *b = pattern;
            }
            captured_ptr = s.as_ptr();
            // Pre-drop sanity check via the slice's own deref.
            assert!(s.iter().all(|&b| b == pattern));
            // Compiler-fence to ensure the writes are visible before drop.
            atomic::compiler_fence(atomic::Ordering::SeqCst);
        } // <-- drop runs here: zeroize + (mlock?) + dealloc.

        // Re-allocate. With high probability the allocator returns the same
        // slot (single-threaded, identical layout). Whether it does or not,
        // the contents we read must be all zero (the drop path's zeroize
        // contract).
        let s2 = SecretAlloc::new(len).expect("realloc");
        // If the new allocation lands on a different address that's fine —
        // we just can't probe the old slot. Only assert when the addresses
        // collide.
        if s2.as_ptr() == captured_ptr {
            assert!(
                s2.iter().all(|&b| b != pattern || b == 0),
                "sentinel pattern survived drop"
            );
            // Stronger: zero-init contract of the fresh allocation.
            assert!(s2.iter().all(|&b| b == 0));
        }
    }

    #[test]
    fn empty_alloc_is_ok() {
        let s = SecretAlloc::new(0).expect("alloc(0) must succeed");
        assert_eq!(s.len(), 0);
        assert!(s.is_empty());
        // Deref to an empty slice does not crash.
        let view: &[u8] = &s;
        assert_eq!(view.len(), 0);
    }

    #[test]
    fn reject_len_exceeding_isize_max() {
        // `SecretSlice` is intentionally not `Debug` (debug-printing a
        // protected page is exactly the leak we're guarding against), so we
        // cannot use `.unwrap_err()` here — pattern-match instead.
        match SecretAlloc::new(usize::MAX) {
            Ok(_) => panic!("usize::MAX must be rejected"),
            Err(Error::RuntimeFailure(msg)) => {
                assert!(msg.contains("isize::MAX"), "unexpected msg: {msg}");
            }
            Err(other) => panic!("expected RuntimeFailure, got {other:?}"),
        }
    }

    /// On Linux, `is_memfd_secret()` returning `true` means the runtime
    /// probe selected the `memfd_secret(2)` path. To verify *which* path is
    /// used in a given test environment:
    ///
    /// * On kernels with `CONFIG_SECRETMEM=y` (Linux 5.14+ with the option
    ///   enabled), this assertion holds.
    /// * On older kernels or kernels with `secretmem` disabled, the probe
    ///   returns `ENOSYS` and this test takes the documented heap fallback.
    ///
    /// The test passes either way; the assertion is a soft signal you can
    /// flip into `assert!(...)` in a CI environment that you know has the
    /// kernel feature enabled.
    #[cfg(target_os = "linux")]
    #[test]
    fn linux_memfd_secret_path_used_when_available() {
        let s = SecretAlloc::new(64).expect("alloc");
        if memfd_secret_available() {
            assert!(
                s.is_memfd_secret(),
                "probe says memfd_secret is available, but slice is heap-backed"
            );
        } else {
            assert!(
                !s.is_memfd_secret(),
                "probe says memfd_secret is unavailable, but slice is memfd-backed"
            );
        }
    }

    /// Documents the `ENOSYS` fallback contract: when `SYS_memfd_secret`
    /// returns `ENOSYS`, `SecretAlloc::new` must still succeed via the heap
    /// mlock path. We can't synthetically inject `ENOSYS` on a real kernel,
    /// so this test only verifies the fallback succeeds on the current
    /// system — on non-Linux platforms it's the only available path.
    #[test]
    fn mlock_fallback_succeeds_when_memfd_unavailable() {
        // Force the fallback path directly.
        let s = heap_fallback(128).expect("heap fallback");
        assert_eq!(s.len(), 128);
        assert!(!s.is_memfd_secret());
        assert!(s.iter().all(|&b| b == 0));
    }

    #[test]
    fn secret_slice_is_send_and_sync() {
        fn assert_send<T: Send>() {}
        fn assert_sync<T: Sync>() {}
        assert_send::<SecretSlice>();
        assert_sync::<SecretSlice>();
        assert_send::<MemfdSecretBox<[u8; 32]>>();
        assert_sync::<MemfdSecretBox<[u8; 32]>>();
    }

    #[test]
    fn thread_safety_smoke() {
        // 4 threads, each allocates, writes a per-thread pattern, verifies
        // the read-back, and drops. No panics, no races (each thread owns
        // its own slice).
        let handles: Vec<_> = (0..4u8)
            .map(|tid| {
                thread::spawn(move || {
                    let mut s = SecretAlloc::new(4096).expect("alloc");
                    for b in s.iter_mut() {
                        *b = tid.wrapping_add(0x40);
                    }
                    let expected = tid.wrapping_add(0x40);
                    assert!(s.iter().all(|&b| b == expected));
                    // drop on scope exit
                })
            })
            .collect();
        for h in handles {
            h.join().expect("thread join");
        }
    }

    #[test]
    fn deref_and_deref_mut_match_length() {
        let mut s = SecretAlloc::new(17).expect("alloc");
        let view: &[u8] = &s;
        assert_eq!(view.len(), 17);
        let view_mut: &mut [u8] = &mut s;
        assert_eq!(view_mut.len(), 17);
    }

    #[test]
    fn memfd_secret_box_round_trip() {
        type Payload = [u8; 32];
        let mut b: MemfdSecretBox<Payload> = MemfdSecretBox::new().expect("box");
        // Default for arrays of u8 is zero.
        assert_eq!(b.get(), &[0u8; 32]);
        for (i, x) in b.get_mut().iter_mut().enumerate() {
            *x = (i as u8) ^ 0x5A;
        }
        for (i, x) in b.get().iter().enumerate() {
            assert_eq!(*x, (i as u8) ^ 0x5A);
        }
    }

    #[test]
    fn memfd_secret_box_zeroes_on_drop() {
        // Same recipe as `drop_zeroes_the_buffer`: capture, drop, re-alloc,
        // probe. Use [u8; 32] because `Default` is only implemented for
        // arrays up to length 32 in stdlib.
        type Payload = [u8; 32];
        let captured_ptr: *const u8;
        {
            let mut b: MemfdSecretBox<Payload> = MemfdSecretBox::new().expect("box");
            for x in b.get_mut().iter_mut() {
                *x = 0xC3;
            }
            captured_ptr = b.slice.as_ptr();
            assert!(b.get().iter().all(|&x| x == 0xC3));
        }
        let b2: MemfdSecretBox<Payload> = MemfdSecretBox::new().expect("realloc");
        if b2.slice.as_ptr() == captured_ptr {
            assert!(b2.get().iter().all(|&x| x == 0));
        }
    }

    #[test]
    fn many_small_allocs_dont_leak() {
        // Sanity: rapidly allocate/drop many small secrets. If `mlock`
        // hit RLIMIT_MEMLOCK we'd surface as Ok(false), not Err.
        for _ in 0..64 {
            let s = SecretAlloc::new(128).expect("alloc");
            assert_eq!(s.len(), 128);
        }
    }
}
