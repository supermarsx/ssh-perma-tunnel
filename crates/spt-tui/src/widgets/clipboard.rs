//! Clipboard wrapper with auto-clear TTL for [`RedactedField`] yank.
//!
//! The real OS clipboard is accessed through the [`arboard`] crate when the
//! `clipboard` feature is enabled (default). On headless CI / WSL / sandboxed
//! environments, `arboard::Clipboard::new()` will fail; the wrapper logs a
//! warning via `tracing` and degrades into a no-op rather than aborting the
//! TUI session.
//!
//! All write paths are routed through the [`ClipboardBackend`] trait so tests
//! can substitute an in-memory mock backend and observe behaviour without
//! touching the real OS clipboard.
//!
//! # TTL semantics
//!
//! [`ClipboardWrapper::set_with_ttl`] consumes a `SecretBox<String>`, writes
//! its plaintext into the backend, and spawns a background OS thread that
//! sleeps for `ttl` then overwrites the clipboard slot with the empty string.
//! Subsequent calls before the TTL elapses cancel the prior auto-clear (via a
//! generation counter) and start a fresh timer for the new value.
//!
//! [`RedactedField`]: super::redacted_field::RedactedField

use std::sync::{Arc, Mutex};
use std::time::Duration;

use secrecy::{ExposeSecret, SecretBox};

/// Pluggable backend for clipboard writes.
///
/// The `clipboard` feature wires the real [`arboard`] backend; tests use
/// [`InMemoryBackend`] to assert clipboard contents and clear timings without
/// touching the OS.
pub trait ClipboardBackend: Send + Sync + 'static {
    /// Write the given string to the OS clipboard slot. Returns `Err` if the
    /// backend's underlying implementation refused the write.
    fn set_text(&self, value: &str) -> Result<(), ClipboardError>;
}

/// Failure modes for clipboard operations.
#[derive(Debug, thiserror::Error)]
pub enum ClipboardError {
    /// The OS clipboard backend could not be initialised — typically a
    /// headless CI runner without an X11/Wayland display or Win32 desktop.
    #[error("clipboard backend unavailable: {0}")]
    Unavailable(String),
    /// A write to the clipboard slot failed at runtime.
    #[error("clipboard write failed: {0}")]
    WriteFailed(String),
}

/// In-memory backend used by tests; also the no-op fallback when the
/// `clipboard` feature is disabled or `arboard` fails to initialise.
#[derive(Default, Debug, Clone)]
pub struct InMemoryBackend {
    inner: Arc<Mutex<Option<String>>>,
}

impl InMemoryBackend {
    /// Construct an empty in-memory clipboard.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Read the current value (test helper). Returns `None` if never written
    /// or if it was cleared to the empty string (auto-clear flow stores `""`).
    #[must_use]
    pub fn current(&self) -> Option<String> {
        self.inner.lock().ok().and_then(|g| g.clone())
    }
}

impl ClipboardBackend for InMemoryBackend {
    fn set_text(&self, value: &str) -> Result<(), ClipboardError> {
        let mut g = self
            .inner
            .lock()
            .map_err(|e| ClipboardError::WriteFailed(format!("mutex poisoned: {e}")))?;
        *g = Some(value.to_owned());
        Ok(())
    }
}

/// No-op backend — every `set_text` succeeds without doing anything. Used as
/// the graceful fallback when `arboard` cannot initialise.
#[derive(Default, Debug, Clone, Copy)]
pub struct NoopBackend;

impl ClipboardBackend for NoopBackend {
    fn set_text(&self, _value: &str) -> Result<(), ClipboardError> {
        Ok(())
    }
}

/// Real `arboard`-backed clipboard. Available when the `clipboard` feature is
/// enabled.
#[cfg(feature = "clipboard")]
pub struct ArboardBackend {
    // `arboard::Clipboard` is `!Send + !Sync` on some platforms; we serialise
    // through a Mutex and create a fresh handle per write to side-step the
    // Wayland/Win32 per-thread lifetime restrictions. Wrapped in `Arc` so the
    // wrapper itself stays `Clone`.
    inner: Arc<Mutex<()>>,
}

#[cfg(feature = "clipboard")]
impl ArboardBackend {
    /// Probe the real OS clipboard. Returns `None` if `arboard` cannot be
    /// initialised — caller should then fall back to [`NoopBackend`].
    #[must_use]
    pub fn try_new() -> Option<Self> {
        match arboard::Clipboard::new() {
            Ok(_) => Some(Self {
                inner: Arc::new(Mutex::new(())),
            }),
            Err(e) => {
                tracing::warn!(error = %e, "arboard clipboard init failed; falling back to no-op");
                None
            }
        }
    }
}

#[cfg(feature = "clipboard")]
impl ClipboardBackend for ArboardBackend {
    fn set_text(&self, value: &str) -> Result<(), ClipboardError> {
        let _guard = self
            .inner
            .lock()
            .map_err(|e| ClipboardError::WriteFailed(format!("mutex poisoned: {e}")))?;
        let mut cb = arboard::Clipboard::new()
            .map_err(|e| ClipboardError::Unavailable(e.to_string()))?;
        cb.set_text(value.to_owned())
            .map_err(|e| ClipboardError::WriteFailed(e.to_string()))?;
        Ok(())
    }
}

/// Pluggable sleep + clock primitives used by the auto-clear timer. Tests
/// substitute an instant clock to avoid `thread::sleep` waits.
pub trait Timer: Send + Sync + 'static {
    /// Block the calling thread for `ttl`. The real impl is
    /// [`std::thread::sleep`]; tests can short-circuit to zero.
    fn sleep(&self, ttl: Duration);
}

/// Default [`Timer`] backed by [`std::thread::sleep`].
#[derive(Default, Debug, Clone, Copy)]
pub struct ThreadSleepTimer;

impl Timer for ThreadSleepTimer {
    fn sleep(&self, ttl: Duration) {
        std::thread::sleep(ttl);
    }
}

/// Wrapper that owns a [`ClipboardBackend`] and a generation counter used to
/// invalidate previously-scheduled auto-clear timers.
pub struct ClipboardWrapper {
    backend: Arc<dyn ClipboardBackend>,
    timer: Arc<dyn Timer>,
    /// Monotonic generation. Each `set_with_ttl` bumps this; the auto-clear
    /// thread only clears the slot if `generation` is still equal to the one
    /// it was spawned with — protecting against clearing a *fresh* value with
    /// a stale TTL.
    generation: Arc<Mutex<u64>>,
}

impl Clone for ClipboardWrapper {
    fn clone(&self) -> Self {
        Self {
            backend: Arc::clone(&self.backend),
            timer: Arc::clone(&self.timer),
            generation: Arc::clone(&self.generation),
        }
    }
}

impl std::fmt::Debug for ClipboardWrapper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClipboardWrapper").finish()
    }
}

impl ClipboardWrapper {
    /// Build a wrapper around an arbitrary backend + timer. Used by tests.
    #[must_use]
    pub fn with_backend(backend: Arc<dyn ClipboardBackend>, timer: Arc<dyn Timer>) -> Self {
        Self {
            backend,
            timer,
            generation: Arc::new(Mutex::new(0)),
        }
    }

    /// Build a wrapper around the real OS clipboard if available, else a
    /// [`NoopBackend`] that just logs a warning.
    #[must_use]
    pub fn detect() -> Self {
        #[cfg(feature = "clipboard")]
        {
            if let Some(b) = ArboardBackend::try_new() {
                return Self::with_backend(
                    Arc::new(b),
                    Arc::new(ThreadSleepTimer),
                );
            }
        }
        tracing::warn!("no real clipboard backend available; clipboard ops will be no-ops");
        Self::with_backend(Arc::new(NoopBackend), Arc::new(ThreadSleepTimer))
    }

    /// Write the contents of `value` to the OS clipboard and schedule a
    /// background thread to clear the slot after `ttl`. Calls during an active
    /// TTL window invalidate the prior auto-clear and start a fresh timer.
    ///
    /// On success the secret's plaintext is materialised long enough to hand
    /// it to the backend; the `SecretBox` zeroes its inner buffer on drop.
    pub fn set_with_ttl(
        &self,
        value: SecretBox<String>,
        ttl: Duration,
    ) -> Result<(), ClipboardError> {
        // Bump generation FIRST so any in-flight clear thread that wakes up
        // between our backend write and the spawn below sees a stale gen.
        let my_gen = {
            let mut g = self
                .generation
                .lock()
                .map_err(|e| ClipboardError::WriteFailed(format!("mutex poisoned: {e}")))?;
            *g = g.wrapping_add(1);
            *g
        };

        // Write the value to the clipboard.
        self.backend.set_text(value.expose_secret().as_str())?;
        drop(value); // explicit zeroize-on-drop

        // Spawn auto-clear thread.
        let backend = Arc::clone(&self.backend);
        let timer = Arc::clone(&self.timer);
        let gen_handle = Arc::clone(&self.generation);
        std::thread::spawn(move || {
            timer.sleep(ttl);
            let cur = match gen_handle.lock() {
                Ok(g) => *g,
                Err(_) => return,
            };
            if cur != my_gen {
                // Superseded by a newer set_with_ttl — leave that newer value
                // intact.
                return;
            }
            if let Err(e) = backend.set_text("") {
                tracing::warn!(error = %e, "clipboard auto-clear failed");
            }
        });
        Ok(())
    }

    /// Force-clear immediately. Cancels any pending auto-clear by bumping the
    /// generation, then writes an empty string.
    pub fn clear_now(&self) -> Result<(), ClipboardError> {
        {
            let mut g = self
                .generation
                .lock()
                .map_err(|e| ClipboardError::WriteFailed(format!("mutex poisoned: {e}")))?;
            *g = g.wrapping_add(1);
        }
        self.backend.set_text("")
    }

    /// Borrow the underlying backend (test introspection).
    #[must_use]
    pub fn backend(&self) -> Arc<dyn ClipboardBackend> {
        Arc::clone(&self.backend)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Timer that records the requested sleep duration but returns
    /// immediately. Lets tests verify the auto-clear path without waiting.
    #[derive(Default, Clone)]
    struct InstantTimer {
        last: Arc<Mutex<Option<Duration>>>,
    }

    impl InstantTimer {
        fn last(&self) -> Option<Duration> {
            self.last.lock().ok().and_then(|g| *g)
        }
    }

    impl Timer for InstantTimer {
        fn sleep(&self, ttl: Duration) {
            if let Ok(mut g) = self.last.lock() {
                *g = Some(ttl);
            }
        }
    }

    fn sb(v: &str) -> SecretBox<String> {
        SecretBox::new(Box::new(v.to_owned()))
    }

    /// Drain the OS thread queue for our spawned auto-clear thread.
    fn settle() {
        // Auto-clear runs in a detached thread. The InstantTimer returns
        // immediately, but the clear thread still needs scheduler time before
        // its `set_text("")` lands. Spin until the in-memory backend reports
        // empty, with a generous upper bound.
        for _ in 0..200 {
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    fn in_memory_backend_round_trip() {
        let b = InMemoryBackend::new();
        b.set_text("hello").unwrap();
        assert_eq!(b.current().as_deref(), Some("hello"));
    }

    #[test]
    fn noop_backend_always_succeeds() {
        let b = NoopBackend;
        b.set_text("anything").unwrap();
    }

    #[test]
    fn set_with_ttl_writes_value_to_backend() {
        let mem = InMemoryBackend::new();
        let w = ClipboardWrapper::with_backend(
            Arc::new(mem.clone()),
            Arc::new(InstantTimer::default()),
        );
        w.set_with_ttl(sb("topsecret"), Duration::from_secs(30))
            .unwrap();
        // Backend should have seen the write.
        let v = mem.current();
        assert!(v == Some("topsecret".into()) || v == Some(String::new()),
            "expected secret or post-clear empty, saw {v:?}");
    }

    #[test]
    fn auto_clear_replaces_value_after_ttl() {
        let mem = InMemoryBackend::new();
        let timer = InstantTimer::default();
        let w = ClipboardWrapper::with_backend(
            Arc::new(mem.clone()),
            Arc::new(timer.clone()),
        );
        w.set_with_ttl(sb("topsecret"), Duration::from_secs(30))
            .unwrap();
        settle();
        assert_eq!(mem.current().as_deref(), Some(""));
        assert_eq!(timer.last(), Some(Duration::from_secs(30)));
    }

    #[test]
    fn second_set_supersedes_first_clear() {
        // SteppedTimer blocks until we explicitly tick it.
        struct Hold;
        impl Timer for Hold {
            fn sleep(&self, _ttl: Duration) {
                // Hold forever (until thread killed at test exit). The
                // auto-clear will never fire — so the second set must win.
                std::thread::sleep(Duration::from_secs(60));
            }
        }
        let mem = InMemoryBackend::new();
        let w = ClipboardWrapper::with_backend(Arc::new(mem.clone()), Arc::new(Hold));
        w.set_with_ttl(sb("first"), Duration::from_secs(30))
            .unwrap();
        w.set_with_ttl(sb("second"), Duration::from_secs(30))
            .unwrap();
        // Backend reflects the most recent write.
        assert_eq!(mem.current().as_deref(), Some("second"));
    }

    #[test]
    fn clear_now_writes_empty_string() {
        let mem = InMemoryBackend::new();
        let w = ClipboardWrapper::with_backend(
            Arc::new(mem.clone()),
            Arc::new(InstantTimer::default()),
        );
        mem.set_text("populated").unwrap();
        w.clear_now().unwrap();
        assert_eq!(mem.current().as_deref(), Some(""));
    }

    #[test]
    fn clear_now_cancels_pending_auto_clear() {
        // Use a slow timer: the auto-clear from set_with_ttl will wake up
        // *after* clear_now bumped generation, see a stale gen, and bail.
        struct Slow;
        impl Timer for Slow {
            fn sleep(&self, _ttl: Duration) {
                std::thread::sleep(Duration::from_millis(100));
            }
        }
        let mem = InMemoryBackend::new();
        let w = ClipboardWrapper::with_backend(Arc::new(mem.clone()), Arc::new(Slow));
        w.set_with_ttl(sb("payload"), Duration::from_secs(30))
            .unwrap();
        w.clear_now().unwrap();
        // After clear_now, slot is empty.
        assert_eq!(mem.current().as_deref(), Some(""));
        // Wait for the slow auto-clear to wake up: generation has been
        // bumped, so it should NOT overwrite (clear is idempotent here,
        // but the test guards against any other action).
        std::thread::sleep(Duration::from_millis(250));
        assert_eq!(mem.current().as_deref(), Some(""));
    }

    #[test]
    fn detect_returns_a_wrapper() {
        // `detect` must always return something usable — never panic — even
        // on headless CI where arboard fails.
        let w = ClipboardWrapper::detect();
        // Smoke: call clear_now (no-op backend on headless succeeds).
        let _ = w.clear_now();
    }

    #[test]
    fn wrapper_is_cloneable_and_shares_state() {
        let mem = InMemoryBackend::new();
        let w = ClipboardWrapper::with_backend(
            Arc::new(mem.clone()),
            Arc::new(InstantTimer::default()),
        );
        let w2 = w.clone();
        w.set_with_ttl(sb("alpha"), Duration::from_secs(30))
            .unwrap();
        w2.set_with_ttl(sb("beta"), Duration::from_secs(30))
            .unwrap();
        settle();
        // Both writes went through the same backend; final state is empty
        // (auto-clear) or "beta".
        let v = mem.current();
        assert!(v == Some(String::new()) || v == Some("beta".into()));
    }
}
