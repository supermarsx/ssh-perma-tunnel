//! Poll-based config file watcher for `[runtime.reload].mode = "watch"`.
//!
//! The workspace does **not** depend on `notify` (confirmed absent from
//! `Cargo.lock`), so rather than pull in a new external dependency this watcher
//! polls the config file's `(mtime, size)` signature on a fixed interval. Once
//! a detected change has been *stable* for the configured debounce window (to
//! coalesce rapid multi-write saves from editors), it fires the caller's
//! reload callback.
//!
//! The callback funnels through the SAME validated-before-swap reload pipeline
//! as SIGHUP and the remote-config poller ([`crate::controller::ConfigCell`]),
//! so a reload that fails validation keeps the previously-running config
//! (fail-safe). `mode = "signal"` (SIGHUP) and `mode = "none"` are unaffected —
//! this watcher is only spawned for `mode = "watch"`.

use std::future::Future;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

use parking_lot::Mutex;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

/// A cheap change signature for a watched file: last-modified time + size.
///
/// A `None` from [`read_sig`] means the file is currently unreadable (e.g.
/// briefly absent mid-rename); the debouncer treats that as "no change to act
/// on" so a transient disappearance never triggers a reload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileSig {
    mtime: Option<SystemTime>,
    size: u64,
}

/// Read the current `(mtime, size)` signature of `path`, or `None` when the
/// file cannot be stat'd.
#[must_use]
pub fn read_sig(path: &Path) -> Option<FileSig> {
    let md = std::fs::metadata(path).ok()?;
    Some(FileSig {
        mtime: md.modified().ok(),
        size: md.len(),
    })
}

/// Pure debounce state machine for the watcher (unit-testable without tokio).
///
/// Feed it the current signature on each poll; it returns `true` exactly when
/// a change has held steady for at least `debounce`, at which point the
/// internal "applied" signature advances so the same change does not re-fire.
#[derive(Debug)]
pub struct Debouncer {
    /// Last signature we acted on (seeded with the boot signature so an
    /// unchanged file never triggers an initial reload).
    applied: Option<FileSig>,
    /// A detected-but-not-yet-stable change and when it was first seen.
    pending: Option<(FileSig, Instant)>,
    debounce: Duration,
}

impl Debouncer {
    /// New debouncer seeded with the file's initial signature.
    #[must_use]
    pub fn new(initial: Option<FileSig>, debounce: Duration) -> Self {
        Self {
            applied: initial,
            pending: None,
            debounce,
        }
    }

    /// Feed the current signature and clock. Returns `true` when a reload
    /// should fire now.
    pub fn poll(&mut self, cur: Option<FileSig>, now: Instant) -> bool {
        // Unreadable file, or unchanged from what we last applied: nothing to
        // do; drop any in-flight pending change (e.g. an edit reverted).
        match cur {
            None => {
                self.pending = None;
                false
            }
            Some(sig) if Some(sig) == self.applied => {
                self.pending = None;
                false
            }
            Some(sig) => {
                match self.pending {
                    // Same change still pending: fire once it has been stable
                    // for the debounce window.
                    Some((psig, since)) if psig == sig => {
                        if now.saturating_duration_since(since) >= self.debounce {
                            self.applied = Some(sig);
                            self.pending = None;
                            true
                        } else {
                            false
                        }
                    }
                    // New or changed pending value: (re)start the debounce
                    // timer, coalescing a burst of rapid writes.
                    _ => {
                        self.pending = Some((sig, now));
                        false
                    }
                }
            }
        }
    }
}

/// Handle to a running config watcher. Drop or [`Self::shutdown`] to stop it.
pub struct ConfigWatchHandle {
    shutdown: Mutex<Option<oneshot::Sender<()>>>,
    join: Mutex<Option<JoinHandle<()>>>,
}

impl ConfigWatchHandle {
    /// Stop the watcher and wait for its task to exit.
    pub async fn shutdown(self) {
        let tx = self.shutdown.lock().take();
        if let Some(tx) = tx {
            let _ = tx.send(());
        }
        let join = self.join.lock().take();
        if let Some(j) = join {
            let _ = j.await;
        }
    }
}

impl Drop for ConfigWatchHandle {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown.lock().take() {
            let _ = tx.send(());
        }
    }
}

/// Choose a poll interval for a given debounce window: half the debounce,
/// floored at 250 ms so we neither busy-poll nor lag far behind the debounce.
#[must_use]
pub fn poll_interval_for(debounce: Duration) -> Duration {
    (debounce / 2).max(Duration::from_millis(250))
}

/// Spawn the poll-based watcher.
///
/// `on_change` is invoked (awaited) each time a stable change is detected. It
/// is generic so tests can inject a lightweight callback; production wiring
/// passes a closure that runs the shared reload pipeline.
pub fn spawn<F, Fut>(
    path: PathBuf,
    poll_interval: Duration,
    debounce: Duration,
    on_change: F,
) -> ConfigWatchHandle
where
    F: Fn() -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let (sd_tx, mut sd_rx) = oneshot::channel::<()>();
    let join = tokio::spawn(async move {
        let mut deb = Debouncer::new(read_sig(&path), debounce);
        let mut iv = tokio::time::interval(poll_interval);
        iv.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // Consume the immediate first tick so we don't poll before an interval
        // has elapsed.
        iv.tick().await;
        loop {
            tokio::select! {
                biased;
                _ = &mut sd_rx => break,
                _ = iv.tick() => {
                    let cur = read_sig(&path);
                    if deb.poll(cur, Instant::now()) {
                        tracing::info!(
                            path = %path.display(),
                            "config file changed — triggering validated reload (mode=watch)"
                        );
                        on_change().await;
                    }
                }
            }
        }
    });
    ConfigWatchHandle {
        shutdown: Mutex::new(Some(sd_tx)),
        join: Mutex::new(Some(join)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;

    fn sig(mtime_secs: u64, size: u64) -> FileSig {
        FileSig {
            mtime: Some(SystemTime::UNIX_EPOCH + Duration::from_secs(mtime_secs)),
            size,
        }
    }

    #[test]
    fn debouncer_unchanged_never_fires() {
        let start = sig(100, 10);
        let mut d = Debouncer::new(Some(start), Duration::from_millis(100));
        let now = Instant::now();
        assert!(!d.poll(Some(start), now));
        assert!(!d.poll(Some(start), now + Duration::from_secs(10)));
    }

    #[test]
    fn debouncer_fires_after_stable_debounce() {
        let start = sig(100, 10);
        let changed = sig(101, 12);
        let mut d = Debouncer::new(Some(start), Duration::from_millis(100));
        let t0 = Instant::now();
        // First sighting of the change starts the debounce timer.
        assert!(!d.poll(Some(changed), t0));
        // Still within the window: no fire yet.
        assert!(!d.poll(Some(changed), t0 + Duration::from_millis(50)));
        // Past the window: fires once.
        assert!(d.poll(Some(changed), t0 + Duration::from_millis(150)));
        // Does not re-fire for the same (now applied) signature.
        assert!(!d.poll(Some(changed), t0 + Duration::from_millis(500)));
    }

    #[test]
    fn debouncer_resets_timer_on_rapid_successive_changes() {
        let start = sig(100, 10);
        let a = sig(101, 12);
        let b = sig(102, 15);
        let mut d = Debouncer::new(Some(start), Duration::from_millis(100));
        let t0 = Instant::now();
        assert!(!d.poll(Some(a), t0));
        // A different change before the window elapses restarts the timer.
        assert!(!d.poll(Some(b), t0 + Duration::from_millis(80)));
        // 80ms after `b` (< 100ms) still no fire even though 160ms since `a`.
        assert!(!d.poll(Some(b), t0 + Duration::from_millis(160)));
        // Now stable long enough since `b`.
        assert!(d.poll(Some(b), t0 + Duration::from_millis(200)));
    }

    #[test]
    fn debouncer_missing_file_clears_pending() {
        let start = sig(100, 10);
        let changed = sig(101, 12);
        let mut d = Debouncer::new(Some(start), Duration::from_millis(100));
        let t0 = Instant::now();
        assert!(!d.poll(Some(changed), t0));
        // File vanishes mid-rename: pending is dropped, no fire.
        assert!(!d.poll(None, t0 + Duration::from_millis(200)));
        // Re-appearance restarts the debounce rather than firing immediately.
        assert!(!d.poll(Some(changed), t0 + Duration::from_millis(210)));
        assert!(d.poll(Some(changed), t0 + Duration::from_millis(400)));
    }

    #[test]
    fn poll_interval_is_floored() {
        assert_eq!(
            poll_interval_for(Duration::from_millis(100)),
            Duration::from_millis(250)
        );
        assert_eq!(
            poll_interval_for(Duration::from_secs(2)),
            Duration::from_secs(1)
        );
    }

    #[tokio::test]
    async fn spawn_fires_callback_on_file_change() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, b"# v1\n").unwrap();

        let hits = Arc::new(AtomicU32::new(0));
        let hits_cb = hits.clone();
        let debounce = Duration::from_millis(100);
        let handle = spawn(
            path.clone(),
            poll_interval_for(debounce),
            debounce,
            move || {
                let hits = hits_cb.clone();
                async move {
                    hits.fetch_add(1, Ordering::SeqCst);
                }
            },
        );

        // Let the watcher establish its baseline, then mutate the file. Use a
        // clearly different size so the (mtime,size) signature changes even if
        // the filesystem mtime resolution is coarse.
        tokio::time::sleep(Duration::from_millis(200)).await;
        std::fs::write(&path, b"# v2 - a materially longer body to bump size\n").unwrap();

        // Poll until the callback fires (bounded), rather than a fixed sleep.
        let mut fired = false;
        for _ in 0..40 {
            if hits.load(Ordering::SeqCst) >= 1 {
                fired = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        handle.shutdown().await;
        assert!(fired, "watcher did not fire reload callback on file change");
    }

    #[tokio::test]
    async fn spawn_does_not_fire_without_change() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, b"# stable\n").unwrap();
        let hits = Arc::new(AtomicU32::new(0));
        let hits_cb = hits.clone();
        let debounce = Duration::from_millis(100);
        let handle = spawn(path, poll_interval_for(debounce), debounce, move || {
            let hits = hits_cb.clone();
            async move {
                hits.fetch_add(1, Ordering::SeqCst);
            }
        });
        tokio::time::sleep(Duration::from_millis(500)).await;
        handle.shutdown().await;
        assert_eq!(hits.load(Ordering::SeqCst), 0, "no change must not reload");
    }
}
