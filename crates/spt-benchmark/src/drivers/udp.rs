//! UDP echo driver — measures loss and jitter through a datagram channel.
//!
//! Each iteration sends a sequence-numbered packet at a fixed rate, expects
//! it echoed, and times the round-trip. Lost packets are tracked via a
//! per-iteration receive timeout; jitter is the RFC 3550 inter-arrival
//! jitter estimator over arrival times.
//!
//! The driver pulls a fresh [`crate::UdpEndpoint`] from an injected
//! [`crate::UdpConnector`]. In tests, a small loopback echo task does the
//! reflection; production callers wire a real SSH3 datagram-forwarded
//! socket pair.
//!
//! # Example
//!
//! ```no_run
//! # use std::time::Duration;
//! # use spt_benchmark::{
//! #     BenchContext, BenchmarkDriver, UdpConnector, UdpDriver, UdpEndpoint,
//! #     result::BenchEnv, driver::Connector,
//! # };
//! # async fn _doc() {
//! let connector: UdpConnector = Box::new(|| Box::pin(async {
//!     let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
//!     let target = socket.local_addr()?; // toy: bounce off itself in real use
//!     Ok(UdpEndpoint { socket, target })
//! }));
//! let driver = UdpDriver::new(connector);
//! # let _ = driver;
//! # }
//! ```

use async_trait::async_trait;
use std::time::{Duration, Instant};
use tokio::time::timeout;

use crate::driver::{BenchContext, BenchmarkDriver, ImpactLevel, UdpConnector};
use crate::result::{BenchResult, MetricSet, Percentiles};

/// UDP loss/jitter driver. Datagram round-trip against an echoer.
pub struct UdpDriver {
    connector: UdpConnector,
    /// Maximum wait for any single echo, in milliseconds.
    per_packet_timeout: Duration,
    /// Inter-packet pacing interval (sender side).
    interval: Duration,
}

impl std::fmt::Debug for UdpDriver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UdpDriver")
            .field("per_packet_timeout", &self.per_packet_timeout)
            .field("interval", &self.interval)
            .finish_non_exhaustive()
    }
}

impl UdpDriver {
    /// Build a driver against `connector` with default packet timeout
    /// (200ms) and pacing (1ms — i.e. up to 1000 pps).
    #[must_use]
    pub fn new(connector: UdpConnector) -> Self {
        Self {
            connector,
            per_packet_timeout: Duration::from_millis(200),
            interval: Duration::from_millis(1),
        }
    }

    /// Override per-packet receive timeout.
    #[must_use]
    pub fn with_per_packet_timeout(mut self, d: Duration) -> Self {
        self.per_packet_timeout = d;
        self
    }

    /// Override sender pacing interval.
    #[must_use]
    pub fn with_interval(mut self, d: Duration) -> Self {
        self.interval = d;
        self
    }
}

#[async_trait]
impl BenchmarkDriver for UdpDriver {
    fn name(&self) -> &str {
        "udp"
    }
    fn impact(&self) -> ImpactLevel {
        // Treats the path as production by default — UDP echo via a real
        // tunnel applies load. Synthetic loopback is fine because the
        // safety gate only refuses Production unless allow_prod is set,
        // and tests pass allow_prod=true.
        ImpactLevel::Production
    }
    async fn run(&self, ctx: &BenchContext) -> BenchResult {
        let started_at = chrono::Utc::now().to_rfc3339();
        let start = Instant::now();
        let mut errors = Vec::new();

        let endpoint = match (self.connector)().await {
            Ok(e) => e,
            Err(e) => {
                errors.push(format!("connect: {e}"));
                return BenchResult {
                    driver: self.name().into(),
                    duration_ms: dur_ms_u64(start.elapsed()),
                    iterations_completed: 0,
                    iterations_attempted: 0,
                    payload_size: ctx.payload_size,
                    errors,
                    metrics: MetricSet::default(),
                    throttles_applied: Vec::new(),
                    env: ctx.env.clone(),
                    started_at,
                };
            }
        };

        let payload_size = ctx.payload_size.max(8); // need 8 bytes for seq+ts
        let mut samples = Vec::with_capacity(ctx.iterations as usize);
        let mut completed = 0u64;
        let mut attempted = 0u64;

        let mut buf = vec![0u8; payload_size.max(2048)];
        let mut send_buf = vec![0xC3u8; payload_size];

        for seq in 0..ctx.iterations {
            if start.elapsed() >= ctx.max_duration {
                break;
            }
            attempted += 1;
            // Encode seq+send-time so the echo confirms identity.
            send_buf[..8].copy_from_slice(&seq.to_be_bytes());
            let t0 = Instant::now();
            if let Err(e) = endpoint.socket.send_to(&send_buf, endpoint.target).await {
                errors.push(format!("send: {e}"));
                tokio::time::sleep(self.interval).await;
                continue;
            }
            match timeout(self.per_packet_timeout, endpoint.socket.recv_from(&mut buf)).await {
                Ok(Ok((n, _peer))) => {
                    let elapsed = t0.elapsed();
                    if n >= 8 && buf[..8] == seq.to_be_bytes() {
                        samples.push(dur_ms(elapsed));
                        completed += 1;
                    } else {
                        errors.push(format!("seq mismatch at {seq}"));
                    }
                }
                Ok(Err(e)) => errors.push(format!("recv: {e}")),
                Err(_) => { /* timeout = drop */ }
            }
            tokio::time::sleep(self.interval).await;
        }

        let loss = if attempted == 0 {
            0.0
        } else {
            1.0 - (completed as f64 / attempted as f64)
        };
        let jitter = rfc3550_jitter(&samples);
        let mut samples_sorted = samples.clone();
        let percentiles = Percentiles::from_samples(&mut samples_sorted);
        let elapsed = start.elapsed();
        let secs = elapsed.as_secs_f64().max(0.000_001);
        let pps = completed as f64 / secs;

        BenchResult {
            driver: self.name().into(),
            duration_ms: dur_ms_u64(elapsed),
            iterations_completed: completed,
            iterations_attempted: attempted,
            payload_size,
            errors,
            metrics: MetricSet {
                latency: Some(percentiles),
                packets_per_sec: Some(pps),
                loss_ratio: Some(loss),
                jitter_ms: Some(jitter),
                ..Default::default()
            },
            throttles_applied: Vec::new(),
            env: ctx.env.clone(),
            started_at,
        }
    }
}

/// RFC 3550 §A.8 inter-arrival jitter estimator.
///
/// `J(i) = J(i-1) + (|D(i-1, i)| - J(i-1)) / 16`
///
/// Operates on a sequence of one-way (or, here, round-trip) latencies in
/// milliseconds; the difference between successive samples is the relative
/// transit-time deviation. Returns `0.0` for fewer than two samples.
#[must_use]
pub fn rfc3550_jitter(samples_ms: &[f64]) -> f64 {
    if samples_ms.len() < 2 {
        return 0.0;
    }
    let mut j = 0.0f64;
    for w in samples_ms.windows(2) {
        let d = (w[1] - w[0]).abs();
        j += (d - j) / 16.0;
    }
    j
}

fn dur_ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}
fn dur_ms_u64(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::driver::{BenchContext, UdpConnector, UdpEndpoint};
    use crate::result::BenchEnv;

    fn echo_connector() -> UdpConnector {
        Box::new(|| {
            Box::pin(async {
                let echo = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
                let target = echo.local_addr()?;
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 65_535];
                    while let Ok((n, peer)) = echo.recv_from(&mut buf).await {
                        let _ = echo.send_to(&buf[..n], peer).await;
                    }
                });
                let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
                Ok(UdpEndpoint {
                    socket: client,
                    target,
                })
            })
        })
    }

    fn ctx(iters: u64, allow_prod: bool) -> BenchContext {
        BenchContext {
            iterations: iters,
            payload_size: 64,
            max_duration: Duration::from_secs(5),
            connector: Box::new(|| {
                Box::pin(async {
                    Err(std::io::Error::new(
                        std::io::ErrorKind::Unsupported,
                        "tcp connector not used by udp driver",
                    ))
                })
            }),
            allow_production_impact: allow_prod,
            env: BenchEnv {
                os: "test".into(),
                arch: "test".into(),
                spt_version: "0.1.0".into(),
                ..Default::default()
            },
        }
    }

    #[tokio::test]
    async fn udp_runs_against_loopback_echo() {
        let driver = UdpDriver::new(echo_connector())
            .with_per_packet_timeout(Duration::from_millis(500))
            .with_interval(Duration::from_micros(100));
        let res = driver.run(&ctx(20, true)).await;
        assert!(res.iterations_completed >= 18, "{res:?}");
        let m = &res.metrics;
        assert!(m.loss_ratio.unwrap() <= 0.2, "{:?}", m.loss_ratio);
        assert!(m.jitter_ms.is_some());
        assert!(m.packets_per_sec.unwrap() > 0.0);
        assert!(m.latency.as_ref().unwrap().max_ms >= 0.0);
    }

    #[test]
    fn safety_blocks_prod_without_flag() {
        let driver = UdpDriver::new(echo_connector());
        let err = crate::safety::check_safety(&driver, false).unwrap_err();
        assert!(matches!(
            err,
            crate::safety::SafetyError::ProductionImpactNotAllowed { .. }
        ));
        crate::safety::check_safety(&driver, true).unwrap();
    }

    #[tokio::test]
    async fn udp_result_roundtrips_json() {
        let driver = UdpDriver::new(echo_connector()).with_interval(Duration::from_micros(100));
        let res = driver.run(&ctx(5, true)).await;
        // f64 values produced by the driver may have tiny shortest-format
        // representation drift across one JSON round-trip; compare structurally
        // by serializing both sides.
        let s1 = serde_json::to_string(&res).unwrap();
        let back: BenchResult = serde_json::from_str(&s1).unwrap();
        // After a single round-trip the float bit patterns are stable.
        let s2 = serde_json::to_string(&back).unwrap();
        let back2: BenchResult = serde_json::from_str(&s2).unwrap();
        assert_eq!(back2, back);
        assert_eq!(s2, serde_json::to_string(&back2).unwrap());
        assert_eq!(back.driver, res.driver);
        assert_eq!(back.iterations_completed, res.iterations_completed);
    }

    #[test]
    fn rfc3550_jitter_property_matches_spec() {
        // Per RFC 3550 §A.8: J(i) = J(i-1) + (|D(i-1,i)| - J(i-1))/16.
        // For samples [10, 20, 30, 25] (ms):
        //   J0 = 0
        //   J1 = 0 + (|20-10| - 0)/16        = 10/16        = 0.625
        //   J2 = J1 + (|30-20| - J1)/16      = 0.625 + (10 - 0.625)/16
        //   J3 = J2 + (|25-30| - J2)/16
        let s = [10.0, 20.0, 30.0, 25.0];
        let j1 = 10.0 / 16.0;
        let j2 = j1 + (10.0 - j1) / 16.0;
        let expected = j2 + (5.0 - j2) / 16.0;
        let got = rfc3550_jitter(&s);
        assert!((got - expected).abs() < 1e-9, "got {got}, want {expected}");
    }

    #[test]
    fn rfc3550_jitter_short_input() {
        assert!(rfc3550_jitter(&[]).abs() < f64::EPSILON);
        assert!(rfc3550_jitter(&[42.0]).abs() < f64::EPSILON);
    }
}
