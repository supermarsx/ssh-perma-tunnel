//! Accept-loop helper used by protocol backends inside their local-TCP
//! `open_local_forward` implementations.
//!
//! Note: the protocol backends are the actual owners of TCP listeners — see
//! the layering note in `lib.rs`. This module provides a generic accept-loop
//! that:
//!
//! * Polls a [`tokio::net::TcpListener`].
//! * Filters peers through a [`crate::ForwardAcl`].
//! * Acquires a permit from a [`crate::ConnectionGate`] (rejecting once the
//!   per-forward cap is hit).
//! * Dispatches each accepted connection to a user-supplied closure that
//!   typically opens a tunnel-side stream and runs
//!   [`crate::copy_bidirectional_throttled`].

use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use spt_protocol::BindConflictPolicy;
use tokio::net::TcpListener;
use tokio::sync::oneshot;

use crate::acl::ForwardAcl;
use crate::limits::{ConnectionGate, RateGate};

/// Accept-loop driver.
pub struct AcceptLoop {
    listener: TcpListener,
    acl: ForwardAcl,
    gate: ConnectionGate,
    rate_gate: RateGate,
    shutdown: Option<oneshot::Receiver<()>>,
}

impl AcceptLoop {
    /// New driver wrapping `listener`. Apply `acl` and `gate` to every
    /// accepted connection.
    ///
    /// The new-connection rate gate is unlimited by default; attach one with
    /// [`Self::with_rate_gate`] to honour `max_new_conns_per_sec`.
    pub fn new(listener: TcpListener, acl: ForwardAcl, gate: ConnectionGate) -> Self {
        Self {
            listener,
            acl,
            gate,
            rate_gate: RateGate::unlimited(),
            shutdown: None,
        }
    }

    /// Attach a new-connection admission gate (`max_new_conns_per_sec`).
    ///
    /// When active, each accepted connection that fails admission is dropped
    /// (rather than blocking the accept loop), matching the connection-cap
    /// reject behaviour.
    #[must_use]
    pub fn with_rate_gate(mut self, rate_gate: RateGate) -> Self {
        self.rate_gate = rate_gate;
        self
    }

    /// Attach a shutdown signal — when the receiver fires, [`Self::run`] exits at
    /// the next accept boundary.
    #[must_use]
    pub fn with_shutdown(mut self, rx: oneshot::Receiver<()>) -> Self {
        self.shutdown = Some(rx);
        self
    }

    /// Run the accept loop. `handle` is invoked once per admitted connection;
    /// the supplied permit must outlive the connection (drop it when done).
    pub async fn run<F, Fut>(self, handle: F) -> std::io::Result<()>
    where
        F: Fn(tokio::net::TcpStream, std::net::SocketAddr, crate::limits::ConnectionPermit) -> Fut
            + Send
            + Sync
            + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let Self {
            listener,
            acl,
            gate,
            rate_gate,
            shutdown,
        } = self;
        let handle = Arc::new(handle);
        let mut shutdown = shutdown;

        loop {
            let accept = listener.accept();
            tokio::pin!(accept);

            let accept_res = if let Some(rx) = shutdown.as_mut() {
                tokio::select! {
                    res = &mut accept => res,
                    _ = rx => return Ok(()),
                }
            } else {
                accept.await
            };

            let (sock, peer) = match accept_res {
                Ok(pair) => pair,
                Err(e) if is_transient_accept_error(&e) => {
                    // E1-F9: a transient accept() error (fd exhaustion
                    // EMFILE/ENFILE, ECONNABORTED, would-block) must not kill
                    // the listener for good. Log, briefly back off to relieve
                    // fd pressure, and keep accepting.
                    tracing::warn!(error = %e, kind = ?e.kind(), "accept: transient error, retrying");
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    continue;
                }
                Err(e) => {
                    // Fatal listener error: propagate and end the loop.
                    return Err(e);
                }
            };

            if !acl.decide(peer.ip()).is_allow() {
                tracing::debug!(?peer, "acl: deny");
                drop(sock);
                continue;
            }
            if !rate_gate.admit() {
                tracing::warn!(?peer, "new-connection rate cap reached, rejecting");
                drop(sock);
                continue;
            }
            let permit = match gate.try_acquire() {
                Some(p) => p,
                None => {
                    tracing::warn!(?peer, "connection cap reached, rejecting");
                    drop(sock);
                    continue;
                }
            };

            let h = Arc::clone(&handle);
            tokio::spawn(async move {
                h(sock, peer, permit).await;
            });
        }
    }
}

/// Outcome of a [`bind_with_policy`] call: the bound listener plus the address
/// it actually bound (which may differ from the requested one under
/// [`BindConflictPolicy::NextPort`]).
#[derive(Debug)]
pub struct BoundListener {
    /// The bound TCP listener.
    pub listener: TcpListener,
    /// The address actually bound.
    pub addr: SocketAddr,
}

/// Number of `NextPort` probes (and `Retry` attempts) before giving up.
const BIND_MAX_ATTEMPTS: u16 = 64;
/// Backoff between `Retry` attempts on a still-occupied address.
const BIND_RETRY_BACKOFF: Duration = Duration::from_millis(200);

/// Bind a [`TcpListener`] on `addr`, honouring the [`BindConflictPolicy`] when
/// the address is already in use (`AddrInUse`):
///
/// * [`BindConflictPolicy::Fail`] — return the bind error immediately (the
///   pre-existing behaviour; default).
/// * [`BindConflictPolicy::Retry`] — re-attempt the *same* address up to
///   [`BIND_MAX_ATTEMPTS`] times with a short backoff (covers a peer still
///   tearing down a `TIME_WAIT`-held listener).
/// * [`BindConflictPolicy::NextPort`] — increment the port and try the next one
///   until a free port is found (up to [`BIND_MAX_ATTEMPTS`] probes).
///
/// Any non-`AddrInUse` error is returned immediately regardless of policy.
pub async fn bind_with_policy(
    addr: SocketAddr,
    policy: BindConflictPolicy,
) -> spt_core::Result<BoundListener> {
    use std::io::ErrorKind;

    let mk_err = |a: SocketAddr, e: &std::io::Error| spt_core::Error::LocalBindFailed {
        address: a.to_string(),
        reason: e.to_string(),
    };

    match policy {
        BindConflictPolicy::Fail => match TcpListener::bind(addr).await {
            Ok(listener) => {
                let bound = listener.local_addr().unwrap_or(addr);
                Ok(BoundListener {
                    listener,
                    addr: bound,
                })
            }
            Err(e) => Err(mk_err(addr, &e)),
        },
        BindConflictPolicy::Retry => {
            let mut last = None;
            for attempt in 0..BIND_MAX_ATTEMPTS {
                match TcpListener::bind(addr).await {
                    Ok(listener) => {
                        let bound = listener.local_addr().unwrap_or(addr);
                        return Ok(BoundListener {
                            listener,
                            addr: bound,
                        });
                    }
                    Err(e) if e.kind() == ErrorKind::AddrInUse => {
                        tracing::debug!(%addr, attempt, "bind in use, retrying after backoff");
                        last = Some(e);
                        tokio::time::sleep(BIND_RETRY_BACKOFF).await;
                    }
                    Err(e) => return Err(mk_err(addr, &e)),
                }
            }
            Err(mk_err(
                addr,
                &last.unwrap_or_else(|| std::io::Error::from(ErrorKind::AddrInUse)),
            ))
        }
        BindConflictPolicy::NextPort => {
            let base_port = addr.port();
            let mut last = None;
            for offset in 0..BIND_MAX_ATTEMPTS {
                let port = base_port.checked_add(offset);
                let Some(port) = port else {
                    break;
                };
                let mut candidate = addr;
                candidate.set_port(port);
                match TcpListener::bind(candidate).await {
                    Ok(listener) => {
                        let bound = listener.local_addr().unwrap_or(candidate);
                        if offset > 0 {
                            tracing::info!(
                                requested = %addr,
                                bound = %bound,
                                "bind conflict: fell forward to next free port"
                            );
                        }
                        return Ok(BoundListener {
                            listener,
                            addr: bound,
                        });
                    }
                    Err(e) if e.kind() == ErrorKind::AddrInUse => {
                        last = Some(e);
                    }
                    Err(e) => return Err(mk_err(candidate, &e)),
                }
            }
            Err(mk_err(
                addr,
                &last.unwrap_or_else(|| std::io::Error::from(ErrorKind::AddrInUse)),
            ))
        }
    }
}

/// Classify an `accept()` error as transient (retry the loop) versus fatal
/// (terminate the listener). Transient = conditions that resolve on their own:
/// connection aborted before accept completed, would-block spurious wakeups,
/// and file-descriptor exhaustion (EMFILE/ENFILE) — a brief fd-pressure spike
/// must not permanently kill a forward listener (E1-F9).
fn is_transient_accept_error(e: &std::io::Error) -> bool {
    use std::io::ErrorKind;
    if matches!(
        e.kind(),
        ErrorKind::ConnectionAborted | ErrorKind::WouldBlock | ErrorKind::Interrupted
    ) {
        return true;
    }
    // fd-exhaustion (EMFILE = 24, ENFILE = 23) has no stable ErrorKind variant
    // and surfaces as ErrorKind::Other; match the raw OS errno on unix.
    #[cfg(unix)]
    if let Some(code) = e.raw_os_error() {
        // EMFILE (per-process fd limit) / ENFILE (system-wide fd limit).
        if code == 24 || code == 23 {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn accept_dispatches_and_caps() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let counter = Arc::new(AtomicU32::new(0));
        let counter2 = Arc::clone(&counter);
        let (tx, rx) = oneshot::channel();

        let driver = AcceptLoop::new(listener, ForwardAcl::allow_all(), ConnectionGate::new(0))
            .with_shutdown(rx);

        let server = tokio::spawn(async move {
            driver
                .run(move |mut sock, _peer, permit| {
                    let c = Arc::clone(&counter2);
                    async move {
                        c.fetch_add(1, Ordering::SeqCst);
                        let _ = sock.write_all(b"hi").await;
                        let _ = sock.shutdown().await;
                        drop(permit);
                    }
                })
                .await
                .unwrap();
        });

        for _ in 0..3 {
            let mut s = tokio::net::TcpStream::connect(("127.0.0.1", port))
                .await
                .unwrap();
            let mut buf = [0u8; 2];
            s.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"hi");
        }

        let _ = tx.send(());
        let _ = server.await;
        assert!(counter.load(Ordering::SeqCst) >= 3);
    }

    #[tokio::test]
    async fn bind_with_policy_fail_succeeds_on_free_port() {
        let bound = bind_with_policy("127.0.0.1:0".parse().unwrap(), BindConflictPolicy::Fail)
            .await
            .unwrap();
        assert!(bound.addr.port() != 0);
    }

    #[tokio::test]
    async fn bind_with_policy_fail_errors_on_conflict() {
        // Occupy a port, then a Fail bind on the same addr must error.
        let occupied = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = occupied.local_addr().unwrap();
        let err = bind_with_policy(addr, BindConflictPolicy::Fail)
            .await
            .unwrap_err();
        assert!(matches!(err, spt_core::Error::LocalBindFailed { .. }));
    }

    #[tokio::test]
    async fn bind_with_policy_next_port_falls_forward() {
        // Occupy a port; NextPort must bind a *different* (higher) port.
        let occupied = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = occupied.local_addr().unwrap();
        let bound = bind_with_policy(addr, BindConflictPolicy::NextPort)
            .await
            .unwrap();
        assert_ne!(bound.addr.port(), addr.port());
        assert!(bound.addr.port() > addr.port());
    }

    #[tokio::test(start_paused = true)]
    async fn accept_loop_rate_gate_drops_excess() {
        use std::sync::atomic::{AtomicU32, Ordering};
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let counter = Arc::new(AtomicU32::new(0));
        let counter2 = Arc::clone(&counter);
        let (tx, rx) = oneshot::channel();

        // 1 conn/sec, burst 1: only the first connection in a window is served.
        let driver = AcceptLoop::new(listener, ForwardAcl::allow_all(), ConnectionGate::new(0))
            .with_rate_gate(RateGate::new(1, 1))
            .with_shutdown(rx);

        let server = tokio::spawn(async move {
            driver
                .run(move |mut sock, _peer, permit| {
                    let c = Arc::clone(&counter2);
                    async move {
                        c.fetch_add(1, Ordering::SeqCst);
                        let _ = sock.write_all(b"x").await;
                        let _ = sock.shutdown().await;
                        drop(permit);
                    }
                })
                .await
                .unwrap();
        });

        // Two near-simultaneous connections; only one passes the rate gate.
        let s1 = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        let s2 = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        drop(s1);
        drop(s2);
        // Give the accept loop time to process both under paused time.
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_millis(10)).await;
        tokio::task::yield_now().await;

        let _ = tx.send(());
        let _ = server.await;
        // At most one served in the burst window (the second is rate-dropped).
        assert!(counter.load(Ordering::SeqCst) <= 1);
    }

    #[test]
    fn transient_accept_errors_are_classified() {
        use std::io::{Error, ErrorKind};
        assert!(is_transient_accept_error(&Error::from(
            ErrorKind::ConnectionAborted
        )));
        assert!(is_transient_accept_error(&Error::from(
            ErrorKind::WouldBlock
        )));
        assert!(is_transient_accept_error(&Error::from(
            ErrorKind::Interrupted
        )));
        // A genuinely fatal error is not retried.
        assert!(!is_transient_accept_error(&Error::from(
            ErrorKind::InvalidInput
        )));
        #[cfg(unix)]
        {
            // EMFILE / ENFILE fd-exhaustion are transient.
            assert!(is_transient_accept_error(&Error::from_raw_os_error(24)));
            assert!(is_transient_accept_error(&Error::from_raw_os_error(23)));
        }
    }
}
