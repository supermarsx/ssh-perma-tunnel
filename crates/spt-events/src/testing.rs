//! Test fixtures for `spt-events`.
//!
//! Gated behind the `testing` feature. Provides:
//!
//! * [`CapturingSink`] — records every delivered event.
//! * [`AlwaysFailSink`] — fails every dispatch with a configured error.
//! * [`FlakyTransport`] — fails the first N HTTP sends, then succeeds.
//! * [`fixtures::sample_event_kinds`] — one [`Event`] per spec §13.2 kind.
//! * [`fake_bindings_single`] — convenience constructor for a one-binding
//!   wiring.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use parking_lot::Mutex;

use crate::binding::{Binding, BindingMatch, SinkRef};
use crate::event::{Event, EventKind, Severity};
use crate::sinks::http::{HttpRequest, HttpTransport};
use crate::sinks::{Sink, SinkError};

/// In-memory [`Sink`] that pushes every delivered event into a shared
/// `Vec<Event>`. Always returns `Ok(())`.
///
/// # Examples
///
/// ```
/// use std::sync::Arc;
/// use spt_events::event::{Event, Severity};
/// use spt_events::testing::CapturingSink;
/// use spt_events::Sink;
///
/// # async fn run() {
/// let sink = CapturingSink::new("alerts");
/// let ev = Event::builder("k", Severity::Info).build();
/// sink.deliver(Arc::new(ev)).await.unwrap();
/// assert_eq!(sink.received().len(), 1);
/// # }
/// # let _ = run;
/// ```
pub struct CapturingSink {
    name: String,
    received: Arc<Mutex<Vec<Event>>>,
}

impl CapturingSink {
    /// New sink with the given name.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            received: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Snapshot of currently-captured events.
    #[must_use]
    pub fn received(&self) -> Vec<Event> {
        self.received.lock().clone()
    }

    /// Number of events captured so far.
    #[must_use]
    pub fn len(&self) -> usize {
        self.received.lock().len()
    }

    /// True if no events have been captured.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.received.lock().is_empty()
    }
}

impl std::fmt::Debug for CapturingSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CapturingSink")
            .field("name", &self.name)
            .field("len", &self.len())
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl Sink for CapturingSink {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &'static str {
        "capturing"
    }

    async fn deliver(&self, event: Arc<Event>) -> Result<(), SinkError> {
        self.received.lock().push((*event).clone());
        Ok(())
    }
}

/// [`Sink`] that always fails every delivery with a clone of the configured
/// error. Useful for testing the dispatcher's spool/retry path.
///
/// # Examples
///
/// ```
/// use std::sync::Arc;
/// use spt_events::event::{Event, Severity};
/// use spt_events::testing::AlwaysFailSink;
/// use spt_events::{Sink, SinkError};
///
/// # async fn run() {
/// let sink = AlwaysFailSink::new("alerts", SinkError::Transient("network".into()));
/// let ev = Event::builder("k", Severity::Info).build();
/// assert!(sink.deliver(Arc::new(ev)).await.is_err());
/// # }
/// # let _ = run;
/// ```
pub struct AlwaysFailSink {
    name: String,
    err_template: SinkErrorTemplate,
}

#[derive(Debug, Clone)]
enum SinkErrorTemplate {
    Transient(String),
    Permanent(String),
    Config(String),
}

impl SinkErrorTemplate {
    fn from(err: &SinkError) -> Self {
        match err {
            SinkError::Transient(s) => Self::Transient(s.clone()),
            SinkError::Permanent(s) => Self::Permanent(s.clone()),
            SinkError::Config(s) => Self::Config(s.clone()),
        }
    }
    fn build(&self) -> SinkError {
        match self {
            Self::Transient(s) => SinkError::Transient(s.clone()),
            Self::Permanent(s) => SinkError::Permanent(s.clone()),
            Self::Config(s) => SinkError::Config(s.clone()),
        }
    }
}

impl AlwaysFailSink {
    /// New sink. The supplied `err` is cloned (variant + message) on each
    /// `deliver` call.
    #[must_use]
    #[allow(clippy::needless_pass_by_value)]
    pub fn new(name: impl Into<String>, err: SinkError) -> Self {
        Self {
            name: name.into(),
            err_template: SinkErrorTemplate::from(&err),
        }
    }
}

impl std::fmt::Debug for AlwaysFailSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AlwaysFailSink")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl Sink for AlwaysFailSink {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &'static str {
        "always_fail"
    }

    async fn deliver(&self, _event: Arc<Event>) -> Result<(), SinkError> {
        Err(self.err_template.build())
    }
}

/// HTTP transport that fails the first `N` calls with a transient error then
/// records and accepts every subsequent call. Models retry-spool drains.
///
/// # Examples
///
/// ```
/// use std::sync::Arc;
/// use spt_events::sinks::http::{HttpRequest, HttpAuth, HttpTransport};
/// use spt_events::testing::FlakyTransport;
///
/// # async fn run() {
/// let t = Arc::new(FlakyTransport::new(2));
/// let req = HttpRequest {
///     method: "POST".into(),
///     url: "https://x".into(),
///     content_type: "application/json".into(),
///     body: vec![],
///     auth: HttpAuth::None,
///     extra_headers: vec![],
/// };
/// assert!(t.send(req.clone()).await.is_err()); // 1st fails
/// assert!(t.send(req.clone()).await.is_err()); // 2nd fails
/// assert!(t.send(req).await.is_ok());          // 3rd succeeds
/// assert_eq!(t.attempts(), 3);
/// # }
/// # let _ = run;
/// ```
pub struct FlakyTransport {
    fails_remaining: AtomicUsize,
    attempts: AtomicUsize,
    received: Mutex<Vec<HttpRequest>>,
    transient_message: String,
}

impl FlakyTransport {
    /// New transport that will fail the first `n` calls with a transient
    /// error.
    #[must_use]
    pub fn new(n: usize) -> Self {
        Self {
            fails_remaining: AtomicUsize::new(n),
            attempts: AtomicUsize::new(0),
            received: Mutex::new(Vec::new()),
            transient_message: "FlakyTransport: simulated transient failure".into(),
        }
    }

    /// Number of `send` calls observed so far (success or failure).
    #[must_use]
    pub fn attempts(&self) -> usize {
        self.attempts.load(Ordering::SeqCst)
    }

    /// Snapshot of successfully-recorded requests.
    #[must_use]
    pub fn requests(&self) -> Vec<HttpRequest> {
        self.received.lock().clone()
    }
}

impl std::fmt::Debug for FlakyTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FlakyTransport")
            .field("attempts", &self.attempts())
            .field(
                "fails_remaining",
                &self.fails_remaining.load(Ordering::SeqCst),
            )
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl HttpTransport for FlakyTransport {
    async fn send(&self, req: HttpRequest) -> Result<(), SinkError> {
        self.attempts.fetch_add(1, Ordering::SeqCst);
        // Fetch-sub-with-floor pattern: only decrement while > 0.
        let prev = self.fails_remaining.load(Ordering::SeqCst);
        if prev > 0 {
            // Try CAS to decrement; if a racer beats us, fall through to success.
            let cas = self.fails_remaining.compare_exchange(
                prev,
                prev - 1,
                Ordering::SeqCst,
                Ordering::SeqCst,
            );
            if cas.is_ok() {
                return Err(SinkError::Transient(self.transient_message.clone()));
            }
        }
        self.received.lock().push(req);
        Ok(())
    }
}

/// Convenience: build a single [`Binding`] that matches `kind` and dispatches
/// to `sinks`.
///
/// # Examples
///
/// ```
/// use spt_events::{EventKind, SinkRef};
/// use spt_events::testing::fake_bindings_single;
///
/// let bindings = fake_bindings_single(
///     EventKind::new("forward.connection_failed"),
///     vec![SinkRef::new("alerts")],
/// );
/// assert_eq!(bindings.len(), 1);
/// assert_eq!(bindings[0].sinks.len(), 1);
/// ```
#[must_use]
#[allow(clippy::needless_pass_by_value)]
pub fn fake_bindings_single(kind: EventKind, sinks: Vec<SinkRef>) -> Vec<Binding> {
    vec![Binding {
        name: "test-binding".into(),
        r#match: BindingMatch {
            kinds: vec![kind.as_str().to_owned()],
            ..Default::default()
        },
        sinks,
        dedupe: None,
    }]
}

/// Pre-built canonical [`Event`]s used in cross-crate tests.
pub mod fixtures {
    use super::{Event, EventKind, Severity};

    /// One representative event per well-known §13.2 category.
    ///
    /// The set is intentionally non-exhaustive but covers the common-case
    /// kinds: profile lifecycle, forward lifecycle, connection lifecycle,
    /// supervisor states, and security warnings.
    ///
    /// # Examples
    ///
    /// ```
    /// use spt_events::testing::fixtures::sample_event_kinds;
    ///
    /// let evs = sample_event_kinds();
    /// assert!(evs.iter().any(|e| e.kind.as_str() == "profile.connected"));
    /// ```
    #[must_use]
    pub fn sample_event_kinds() -> Vec<Event> {
        let kinds: &[(&str, Severity)] = &[
            ("profile.connected", Severity::Info),
            ("profile.disconnected", Severity::Warn),
            ("profile.failed", Severity::Error),
            ("profile.reloaded", Severity::Info),
            ("forward.listening", Severity::Info),
            ("forward.connection_opened", Severity::Debug),
            ("forward.connection_closed", Severity::Debug),
            ("forward.connection_failed", Severity::Warn),
            ("session.opened", Severity::Info),
            ("session.closed", Severity::Info),
            ("supervisor.backoff", Severity::Warn),
            ("trust.host_pin_mismatch", Severity::Critical),
            ("auth.permission_denied", Severity::Error),
            ("config.reloaded", Severity::Info),
        ];
        kinds
            .iter()
            .map(|(k, sev)| Event::builder(EventKind::new(*k), *sev).build())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Arc;

    use crate::dispatcher::{build_for_test, DispatcherConfig};
    use crate::event::Event;
    use crate::sinks::http::{HttpAuth, HttpRequest, HttpSink};
    use tempfile::tempdir;

    fn req() -> HttpRequest {
        HttpRequest {
            method: "POST".into(),
            url: "https://x".into(),
            content_type: "application/json".into(),
            body: b"{}".to_vec(),
            auth: HttpAuth::None,
            extra_headers: vec![],
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn capturing_sink_records_event() {
        let sink = CapturingSink::new("c");
        let ev = Event::builder("k", Severity::Info).message("hi").build();
        sink.deliver(Arc::new(ev)).await.unwrap();
        let r = sink.received();
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].message, "hi");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn always_fail_sink_returns_configured_error() {
        let sink = AlwaysFailSink::new("c", SinkError::Permanent("nope".into()));
        let ev = Event::builder("k", Severity::Info).build();
        let err = sink.deliver(Arc::new(ev)).await.unwrap_err();
        assert!(matches!(err, SinkError::Permanent(s) if s == "nope"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn flaky_transport_fails_n_times_then_succeeds() {
        let t = Arc::new(FlakyTransport::new(2));
        assert!(t.send(req()).await.is_err());
        assert!(t.send(req()).await.is_err());
        assert!(t.send(req()).await.is_ok());
        assert_eq!(t.attempts(), 3);
        assert_eq!(t.requests().len(), 1);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn flaky_transport_drives_dispatcher_recovery() {
        // Dispatcher exercise: configure with FlakyTransport(2). First
        // dispatch fails (transient → spool). Two drain calls each fail
        // (re-spool). Fourth attempt succeeds.
        let tmp = tempdir().unwrap();
        let cfg = DispatcherConfig {
            spool_root: tmp.path().into(),
            ..DispatcherConfig::default()
        };
        let transport = Arc::new(FlakyTransport::new(2));
        let http = Arc::new(HttpSink::new(
            "alerts",
            "POST",
            "https://x",
            "{}",
            "application/json",
            HttpAuth::None,
            transport.clone(),
        )) as Arc<dyn Sink>;
        let mut sinks: HashMap<String, Arc<dyn Sink>> = HashMap::new();
        sinks.insert("alerts".into(), http);

        let bindings = fake_bindings_single(
            EventKind::new("forward.connection_failed"),
            vec![SinkRef::new("alerts")],
        );
        let d = build_for_test(bindings, sinks, cfg).unwrap();

        d.dispatch(Arc::new(
            Event::builder("forward.connection_failed", Severity::Error).build(),
        ))
        .await;
        assert_eq!(d.spool_len("alerts"), 1, "first attempt spools");

        d.drain_spool("alerts").await; // 2nd attempt fails → re-spools, halts
        assert_eq!(d.spool_len("alerts"), 1);

        d.drain_spool("alerts").await; // 3rd attempt succeeds, drains
        assert_eq!(d.spool_len("alerts"), 0);
        assert_eq!(transport.attempts(), 3);
    }

    #[test]
    fn fixtures_cover_common_kinds() {
        let evs = fixtures::sample_event_kinds();
        assert!(evs.len() >= 10);
        let names: Vec<_> = evs.iter().map(|e| e.kind.as_str().to_owned()).collect();
        assert!(names.contains(&"profile.connected".to_owned()));
        assert!(names.contains(&"trust.host_pin_mismatch".to_owned()));
    }

    #[test]
    fn fake_bindings_single_builds_match() {
        let bs = fake_bindings_single(
            EventKind::new("profile.failed"),
            vec![SinkRef::new("alerts"), SinkRef::new("ops")],
        );
        assert_eq!(bs[0].sinks.len(), 2);
        assert_eq!(bs[0].r#match.kinds, vec!["profile.failed".to_owned()]);
    }
}
