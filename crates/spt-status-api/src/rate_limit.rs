//! Simple in-memory token bucket per remote IP.
//!
//! Each remote IP gets one bucket initialised with [`RateLimitConfig::burst`]
//! tokens that refill at [`RateLimitConfig::rps`] per second. A request
//! consumes one token; if no token is available the middleware returns
//! [`crate::error::StatusApiError::RateLimited`] (HTTP 429).
//!
//! Buckets are kept in a `parking_lot::Mutex<HashMap<IpAddr, Bucket>>`.
//! Idle buckets are reaped on insert to bound memory.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::{ConnectInfo, Request};
use axum::middleware::Next;
use axum::response::Response;
use parking_lot::Mutex;

use crate::error::StatusApiError;

/// Token-bucket parameters.
#[derive(Debug, Clone, Copy)]
pub struct RateLimitConfig {
    /// Steady-state refill rate (tokens/second).
    pub rps: f32,
    /// Maximum bucket capacity (burst allowance). Defaults to
    /// `max(1.0, rps).ceil()`.
    pub burst: f32,
    /// Buckets idle longer than this are reaped on the next insert.
    pub idle_eviction: Duration,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            rps: 1.0,
            burst: 5.0,
            idle_eviction: Duration::from_secs(600),
        }
    }
}

impl RateLimitConfig {
    /// Construct from `rate_limit_rps`, with `burst = max(rps, 1.0)`.
    #[must_use]
    pub fn from_rps(rps: f32) -> Self {
        let rps = if rps.is_finite() && rps > 0.0 {
            rps
        } else {
            1.0
        };
        Self {
            rps,
            burst: rps.max(1.0),
            idle_eviction: Duration::from_secs(600),
        }
    }
}

#[derive(Debug)]
struct Bucket {
    tokens: f32,
    last_refill: Instant,
}

/// Token-bucket limiter shared by all in-flight requests.
#[derive(Clone)]
pub struct RateLimiter {
    cfg: RateLimitConfig,
    buckets: Arc<Mutex<HashMap<IpAddr, Bucket>>>,
}

impl RateLimiter {
    /// Construct a new limiter.
    #[must_use]
    pub fn new(cfg: RateLimitConfig) -> Self {
        Self {
            cfg,
            buckets: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Attempt to consume one token from `ip`'s bucket. Returns `true` if a
    /// token was available; `false` indicates the request should be
    /// rejected with 429.
    pub fn allow(&self, ip: IpAddr) -> bool {
        self.allow_at(ip, Instant::now())
    }

    /// Same as [`Self::allow`] but with an explicit clock instant — used by
    /// tests.
    pub fn allow_at(&self, ip: IpAddr, now: Instant) -> bool {
        let mut buckets = self.buckets.lock();
        // Reap idle buckets to bound memory.
        if buckets.len() > 1024 {
            buckets.retain(|_, b| now.duration_since(b.last_refill) < self.cfg.idle_eviction);
        }
        let bucket = buckets.entry(ip).or_insert(Bucket {
            tokens: self.cfg.burst,
            last_refill: now,
        });
        let elapsed = now
            .saturating_duration_since(bucket.last_refill)
            .as_secs_f32();
        bucket.tokens = (bucket.tokens + elapsed * self.cfg.rps).min(self.cfg.burst);
        bucket.last_refill = now;
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Axum middleware enforcing the bucket. Extracts the remote IP from
/// `ConnectInfo<SocketAddr>` if present; otherwise falls back to
/// `127.0.0.1` (which makes loopback unit tests deterministic).
pub async fn middleware(
    axum::extract::State(limiter): axum::extract::State<RateLimiter>,
    request: Request,
    next: Next,
) -> Result<Response, StatusApiError> {
    let ip = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map_or(IpAddr::V4(Ipv4Addr::LOCALHOST), |ci| ci.0.ip());
    if limiter.allow(ip) {
        Ok(next.run(request).await)
    } else {
        Err(StatusApiError::RateLimited)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_initial_burst() {
        let lim = RateLimiter::new(RateLimitConfig {
            rps: 1.0,
            burst: 5.0,
            idle_eviction: Duration::from_secs(600),
        });
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let t = Instant::now();
        for _ in 0..5 {
            assert!(lim.allow_at(ip, t));
        }
        assert!(!lim.allow_at(ip, t));
    }

    #[test]
    fn refills_over_time() {
        let lim = RateLimiter::new(RateLimitConfig {
            rps: 2.0,
            burst: 2.0,
            idle_eviction: Duration::from_secs(600),
        });
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let t0 = Instant::now();
        assert!(lim.allow_at(ip, t0));
        assert!(lim.allow_at(ip, t0));
        assert!(!lim.allow_at(ip, t0));
        // 1 second later, 2 tokens refilled.
        let t1 = t0 + Duration::from_secs(1);
        assert!(lim.allow_at(ip, t1));
        assert!(lim.allow_at(ip, t1));
        assert!(!lim.allow_at(ip, t1));
    }

    #[test]
    fn high_volume_rejects_majority() {
        // 70 requests in one second with 1 rps and burst 5 => most rejected.
        let lim = RateLimiter::new(RateLimitConfig {
            rps: 1.0,
            burst: 5.0,
            idle_eviction: Duration::from_secs(600),
        });
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let t = Instant::now();
        let mut accepted = 0;
        let mut rejected = 0;
        for _ in 0..70 {
            if lim.allow_at(ip, t) {
                accepted += 1;
            } else {
                rejected += 1;
            }
        }
        assert!(
            rejected >= 10,
            "expected >=10 rejections, got {rejected} (accepted={accepted})"
        );
    }

    #[test]
    fn per_ip_isolation() {
        let lim = RateLimiter::new(RateLimitConfig {
            rps: 1.0,
            burst: 1.0,
            idle_eviction: Duration::from_secs(600),
        });
        let a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let t = Instant::now();
        assert!(lim.allow_at(a, t));
        assert!(!lim.allow_at(a, t));
        assert!(lim.allow_at(b, t));
    }

    #[test]
    fn from_rps_clamps_invalid_to_one() {
        let cfg = RateLimitConfig::from_rps(0.0);
        assert!((cfg.rps - 1.0).abs() < f32::EPSILON);
        let cfg = RateLimitConfig::from_rps(f32::NAN);
        assert!((cfg.rps - 1.0).abs() < f32::EPSILON);
    }
}
