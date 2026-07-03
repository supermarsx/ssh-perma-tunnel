//! DNS query-rate driver.
//!
//! Issues `iterations` concurrent queries against an injected
//! [`DnsClient`] and records per-query latency, success/failure counts,
//! and aggregate query rate (qps).
//!
//! The seam is intentionally a small async trait so tests can use a fake
//! client and production callers can plug in `hickory-resolver` (or any
//! other resolver) without spt-benchmark depending on a particular
//! resolver implementation.
//!
//! # Example
//!
//! ```no_run
//! # use std::sync::Arc;
//! # use spt_benchmark::{DnsClient, DnsDriver};
//! # struct Mock;
//! # #[async_trait::async_trait]
//! # impl DnsClient for Mock {
//! #     async fn query(&self, _: &str) -> std::io::Result<Vec<String>> {
//! #         Ok(vec!["127.0.0.1".into()])
//! #     }
//! # }
//! let driver = DnsDriver::new(Arc::new(Mock), vec!["a.example.".into()]);
//! # let _ = driver;
//! ```

use async_trait::async_trait;
use std::sync::Arc;
use std::time::Instant;

use crate::driver::{BenchContext, BenchmarkDriver, DnsClient, ImpactLevel};
use crate::result::{BenchResult, MetricSet, Percentiles};

/// DNS query-rate driver. Loops over the configured `names`, round-robin,
/// for `ctx.iterations` queries, with up to `concurrency` in flight.
pub struct DnsDriver {
    client: Arc<dyn DnsClient>,
    names: Vec<String>,
    concurrency: usize,
}

impl std::fmt::Debug for DnsDriver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DnsDriver")
            .field("names", &self.names)
            .field("concurrency", &self.concurrency)
            .finish_non_exhaustive()
    }
}

impl DnsDriver {
    /// Build a driver against `client` issuing queries from `names` (cycled).
    /// Default concurrency = 16.
    #[must_use]
    pub fn new(client: Arc<dyn DnsClient>, names: Vec<String>) -> Self {
        Self {
            client,
            names: if names.is_empty() {
                vec!["localhost.".into()]
            } else {
                names
            },
            concurrency: 16,
        }
    }

    /// Override the concurrency cap.
    #[must_use]
    pub fn with_concurrency(mut self, n: usize) -> Self {
        self.concurrency = n.max(1);
        self
    }
}

#[async_trait]
impl BenchmarkDriver for DnsDriver {
    fn name(&self) -> &'static str {
        "dns"
    }
    fn impact(&self) -> ImpactLevel {
        // Loopback resolver use is synthetic; production callers wrap a
        // real resolver and pass --unsafe-allow-production-impact.
        ImpactLevel::Synthetic
    }
    async fn run(&self, ctx: &BenchContext) -> BenchResult {
        let started_at = chrono::Utc::now().to_rfc3339();
        let start = Instant::now();
        let total = ctx.iterations;
        let sem = Arc::new(tokio::sync::Semaphore::new(self.concurrency));
        let mut handles = Vec::with_capacity(total as usize);

        for i in 0..total {
            if start.elapsed() >= ctx.max_duration {
                break;
            }
            let name = self.names[(i as usize) % self.names.len()].clone();
            let client = self.client.clone();
            let sem = sem.clone();
            handles.push(tokio::spawn(async move {
                let _permit = sem.acquire_owned().await.expect("semaphore open");
                let t0 = Instant::now();
                let r = client.query(&name).await;
                (r, t0.elapsed())
            }));
        }

        let attempted = handles.len() as u64;
        let mut samples: Vec<f64> = Vec::with_capacity(handles.len());
        let mut errors: Vec<String> = Vec::new();
        let mut successes = 0u64;

        for h in handles {
            match h.await {
                Ok((Ok(_), dt)) => {
                    samples.push(dt.as_secs_f64() * 1000.0);
                    successes += 1;
                }
                Ok((Err(e), _)) => errors.push(format!("query: {e}")),
                Err(e) => errors.push(format!("join: {e}")),
            }
        }

        let mut sorted = samples.clone();
        let percentiles = Percentiles::from_samples(&mut sorted);
        let elapsed = start.elapsed();
        let secs = elapsed.as_secs_f64().max(0.000_001);
        let qps = successes as f64 / secs;
        let failures = attempted - successes;

        BenchResult {
            driver: self.name().into(),
            duration_ms: u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX),
            iterations_completed: successes,
            iterations_attempted: attempted,
            payload_size: ctx.payload_size,
            errors,
            metrics: MetricSet {
                latency: Some(percentiles),
                packets_per_sec: Some(qps),
                extras: [
                    ("queries_succeeded".into(), successes as f64),
                    ("queries_failed".into(), failures as f64),
                    ("qps".into(), qps),
                ]
                .into_iter()
                .collect(),
                ..Default::default()
            },
            throttles_applied: Vec::new(),
            env: ctx.env.clone(),
            started_at,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::driver::BenchContext;
    use crate::result::BenchEnv;
    use std::time::Duration;

    struct MockClient {
        fail_every: u32,
        counter: std::sync::atomic::AtomicU32,
    }

    #[async_trait]
    impl DnsClient for MockClient {
        async fn query(&self, name: &str) -> std::io::Result<Vec<String>> {
            let n = self
                .counter
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            // Tiny delay to make latency non-zero.
            tokio::time::sleep(Duration::from_micros(50)).await;
            if self.fail_every != 0 && n % self.fail_every == 0 {
                Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("nx: {name}"),
                ))
            } else {
                Ok(vec![format!("127.0.0.{}", (n % 250) + 1)])
            }
        }
    }

    fn ctx(iters: u64) -> BenchContext {
        BenchContext {
            iterations: iters,
            payload_size: 0,
            max_duration: Duration::from_secs(5),
            connector: Box::new(|| {
                Box::pin(async {
                    Err(std::io::Error::new(
                        std::io::ErrorKind::Unsupported,
                        "unused",
                    ))
                })
            }),
            allow_production_impact: true,
            env: BenchEnv {
                os: "test".into(),
                arch: "test".into(),
                spt_version: "0.1.0".into(),
                ..Default::default()
            },
        }
    }

    #[tokio::test]
    async fn dns_runs_against_mock() {
        let client = Arc::new(MockClient {
            fail_every: 0,
            counter: std::sync::atomic::AtomicU32::new(0),
        });
        let driver = DnsDriver::new(client, vec!["a.example.".into(), "b.example.".into()])
            .with_concurrency(8);
        let res = driver.run(&ctx(50)).await;
        assert_eq!(res.iterations_completed, 50, "{res:?}");
        let m = &res.metrics;
        assert!(m.packets_per_sec.unwrap() > 0.0);
        assert!((m.extras["queries_failed"] - 0.0).abs() < f64::EPSILON);
    }

    #[tokio::test]
    async fn dns_records_failures() {
        let client = Arc::new(MockClient {
            fail_every: 4,
            counter: std::sync::atomic::AtomicU32::new(0),
        });
        let driver = DnsDriver::new(client, vec!["x.".into()]);
        let res = driver.run(&ctx(20)).await;
        assert!(res.iterations_completed < 20);
        assert!(res.metrics.extras["queries_failed"] >= 1.0);
        assert!(!res.errors.is_empty());
    }

    #[tokio::test]
    async fn dns_result_roundtrips_json() {
        let client = Arc::new(MockClient {
            fail_every: 0,
            counter: std::sync::atomic::AtomicU32::new(0),
        });
        let driver = DnsDriver::new(client, vec!["a.".into()]);
        let res = driver.run(&ctx(3)).await;
        let s1 = serde_json::to_string(&res).unwrap();
        let back: BenchResult = serde_json::from_str(&s1).unwrap();
        let s2 = serde_json::to_string(&back).unwrap();
        let back2: BenchResult = serde_json::from_str(&s2).unwrap();
        assert_eq!(back2, back);
        assert_eq!(back.driver, res.driver);
    }

    /// Synthetic-impact driver: `check_safety` always passes, even
    /// without `allow_prod`. Validates we're not over-gating.
    #[test]
    fn safety_synthetic_does_not_gate() {
        let client = Arc::new(MockClient {
            fail_every: 0,
            counter: std::sync::atomic::AtomicU32::new(0),
        });
        let driver = DnsDriver::new(client, vec!["a.".into()]);
        crate::safety::check_safety(&driver, false).unwrap();
    }

    /// Hickory-resolver smoke test against a hickory-server fixture.
    #[cfg(feature = "hickory-test")]
    #[tokio::test]
    async fn dns_against_hickory_resolver() {
        // Adapter from hickory-resolver to DnsClient.
        //
        // hickory 0.26: the old `TokioAsyncResolver::tokio` +
        // `ResolverConfig::new` / `NameServerConfig::new(SocketAddr, Protocol)`
        // path was removed in the 0.25 rework. Mirror spt-dns's construction:
        // assemble a `NameServerConfig` from the IP with a UDP `ConnectionConfig`
        // and build through `Resolver::builder_with_config`.
        use hickory_resolver::config::{
            ConnectionConfig, NameServerConfig, ProtocolConfig, ResolverConfig,
        };
        use hickory_resolver::net::runtime::TokioRuntimeProvider;
        use hickory_resolver::{Resolver, TokioResolver};
        struct HResolver(TokioResolver);
        #[async_trait]
        impl DnsClient for HResolver {
            async fn query(&self, name: &str) -> std::io::Result<Vec<String>> {
                let r = self
                    .0
                    .lookup_ip(name)
                    .await
                    .map_err(std::io::Error::other)?;
                Ok(r.iter().map(|i| i.to_string()).collect())
            }
        }
        // 127.0.0.1:53 UDP — `ConnectionConfig::new(Udp)` defaults to port 53.
        let ns = NameServerConfig::new(
            std::net::Ipv4Addr::LOCALHOST.into(),
            true,
            vec![ConnectionConfig::new(ProtocolConfig::Udp)],
        );
        let cfg = ResolverConfig::from_parts(None, vec![], vec![ns]);
        let resolver = Resolver::builder_with_config(cfg, TokioRuntimeProvider::default())
            .build()
            .expect("build hickory resolver");
        let client = Arc::new(HResolver(resolver));
        let driver = DnsDriver::new(client, vec!["localhost.".into()]).with_concurrency(2);
        let _res = driver.run(&ctx(2)).await;
        // Don't assert on counts; this hits the local stub resolver only when present.
    }
}
