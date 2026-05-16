//! Live-tunnel benchmark dispatch — used by both the CLI's `benchmark run`
//! path (when a running orchestrator is reachable via the loopback MCP
//! transport) and the server-side `benchmark_run` MCP tool.
//!
//! The function takes optional live adapters so it can exercise a running
//! tunnel when invoked by the MCP controller, while still supporting the
//! synthetic-loopback mode used by local smoke tests.

use std::sync::Arc;
use std::time::Duration;

use spt_benchmark::{
    check_safety, BenchContext, BenchEnv, BenchResult, BenchmarkDriver, DnsClient, DnsDriver,
    LatencyDriver, LimitsDriver, LimitsExpectations, ReconnectDriver, ReconnectTrigger,
    ThroughputDriver, UdpDriver,
};
use spt_supervisor::LiveConnector;

struct SupervisorReconnectAdapter {
    inner: spt_supervisor::LiveReconnectTrigger,
}

impl SupervisorReconnectAdapter {
    fn new(inner: spt_supervisor::LiveReconnectTrigger) -> Self {
        Self { inner }
    }
}

#[async_trait::async_trait]
impl ReconnectTrigger for SupervisorReconnectAdapter {
    async fn wait_session_up(&self) -> std::io::Result<()> {
        spt_supervisor::ReconnectTrigger::wait_session_up(&self.inner)
            .await
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))
    }

    async fn trigger_drop(&self) -> std::io::Result<()> {
        spt_supervisor::ReconnectTrigger::trigger_drop(&self.inner)
            .await
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))
    }
}

/// Build a reconnect trigger that drives a real profile supervisor.
#[must_use]
pub fn reconnect_trigger_from_supervisor(
    sup: Arc<spt_supervisor::ProfileSupervisor>,
) -> Arc<dyn ReconnectTrigger> {
    Arc::new(SupervisorReconnectAdapter::new(
        spt_supervisor::LiveReconnectTrigger::new(sup),
    ))
}

/// Drive `driver` against either a live tunnel (`live`) or a synthetic
/// loopback echo connector (`live = None`). Returns the `BenchResult`.
pub async fn run_live_benchmark(
    driver: &str,
    live: Option<Arc<dyn LiveConnector>>,
    reconnect: Option<Arc<dyn ReconnectTrigger>>,
    iterations: u64,
    max_duration_secs: u64,
    allow_production_impact: bool,
) -> Result<BenchResult, String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn tcp_connector(live: Option<Arc<dyn LiveConnector>>) -> spt_benchmark::Connector {
        if let Some(lc) = live {
            return Box::new(move || {
                let lc = lc.clone();
                Box::pin(async move {
                    let stream = lc
                        .open_tcp("bench", 0)
                        .await
                        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
                    let boxed: spt_benchmark::driver::BoxedStream = Box::pin(stream);
                    Ok(boxed)
                })
            });
        }

        Box::new(|| {
            Box::pin(async move {
                let (client_side, server_side) = tokio::io::duplex(64 * 1024);
                tokio::spawn(async move {
                    let (mut reader, mut writer) = tokio::io::split(server_side);
                    let mut buf = [0u8; 8192];
                    loop {
                        match reader.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                if writer.write_all(&buf[..n]).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                });
                let stream: spt_benchmark::driver::BoxedStream = Box::pin(client_side);
                Ok(stream)
            })
        })
    }

    fn udp_connector(live: Option<Arc<dyn LiveConnector>>) -> spt_benchmark::UdpConnector {
        if let Some(lc) = live {
            return Box::new(move || {
                let lc = lc.clone();
                Box::pin(async move {
                    let endpoint = lc
                        .open_udp()
                        .await
                        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
                    Ok(spt_benchmark::UdpEndpoint {
                        socket: endpoint.socket,
                        target: endpoint.target,
                    })
                })
            });
        }

        Box::new(move || {
            Box::pin(async move {
                let s = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
                let echo = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
                let echo_addr = echo.local_addr()?;
                tokio::spawn(async move {
                    let mut buf = [0u8; 1500];
                    while let Ok((n, peer)) = echo.recv_from(&mut buf).await {
                        let _ = echo.send_to(&buf[..n], peer).await;
                    }
                });
                Ok(spt_benchmark::UdpEndpoint {
                    socket: s,
                    target: echo_addr,
                })
            })
        })
    }

    let connector = tcp_connector(live.clone());

    let env = BenchEnv {
        os: std::env::consts::OS.into(),
        arch: std::env::consts::ARCH.into(),
        spt_version: env!("CARGO_PKG_VERSION").into(),
        ..Default::default()
    };

    let drv: Box<dyn BenchmarkDriver> = match driver {
        "latency" => Box::new(LatencyDriver),
        "throughput" => Box::new(ThroughputDriver),
        "udp" => Box::new(UdpDriver::new(udp_connector(live.clone()))),
        "reconnect" => {
            if let Some(trigger) = reconnect {
                Box::new(ReconnectDriver::new(trigger))
            } else {
                struct Noop;
                #[async_trait::async_trait]
                impl ReconnectTrigger for Noop {
                    async fn wait_session_up(&self) -> std::io::Result<()> {
                        Ok(())
                    }
                    async fn trigger_drop(&self) -> std::io::Result<()> {
                        Ok(())
                    }
                }
                Box::new(ReconnectDriver::new(Arc::new(Noop)))
            }
        }
        "dns" => {
            struct Local;
            #[async_trait::async_trait]
            impl DnsClient for Local {
                async fn query(&self, _name: &str) -> std::io::Result<Vec<String>> {
                    Ok(vec!["127.0.0.1".into()])
                }
            }
            Box::new(DnsDriver::new(Arc::new(Local), vec!["example.com".into()]))
        }
        "limits" => Box::new(LimitsDriver::new(
            tcp_connector(live.clone()),
            LimitsExpectations::default(),
        )),
        other => {
            return Err(format!(
                "unknown driver `{other}` (expected: latency, throughput, udp, reconnect, dns, limits)"
            ));
        }
    };

    check_safety(&*drv, allow_production_impact).map_err(|e| e.to_string())?;

    let ctx = BenchContext {
        iterations,
        payload_size: 256,
        max_duration: Duration::from_secs(max_duration_secs.max(1)),
        connector,
        allow_production_impact,
        env,
    };
    Ok(drv.run(&ctx).await)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct CountingLiveConnector {
        inner: spt_supervisor::EchoLiveConnector,
        tcp_calls: Arc<AtomicUsize>,
        udp_calls: Arc<AtomicUsize>,
    }

    #[async_trait::async_trait]
    impl LiveConnector for CountingLiveConnector {
        async fn open_tcp(
            &self,
            host: &str,
            port: u16,
        ) -> spt_core::Result<spt_supervisor::BoxedStream> {
            self.tcp_calls.fetch_add(1, Ordering::SeqCst);
            self.inner.open_tcp(host, port).await
        }

        async fn open_udp(&self) -> spt_core::Result<spt_supervisor::UdpEndpoint> {
            self.udp_calls.fetch_add(1, Ordering::SeqCst);
            self.inner.open_udp().await
        }
    }

    struct CountingReconnect {
        waits: Arc<AtomicUsize>,
        drops: Arc<AtomicUsize>,
    }

    #[async_trait::async_trait]
    impl ReconnectTrigger for CountingReconnect {
        async fn wait_session_up(&self) -> std::io::Result<()> {
            self.waits.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        async fn trigger_drop(&self) -> std::io::Result<()> {
            self.drops.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    fn counting_live() -> (Arc<dyn LiveConnector>, Arc<AtomicUsize>, Arc<AtomicUsize>) {
        let tcp = Arc::new(AtomicUsize::new(0));
        let udp = Arc::new(AtomicUsize::new(0));
        (
            Arc::new(CountingLiveConnector {
                inner: spt_supervisor::EchoLiveConnector::default(),
                tcp_calls: tcp.clone(),
                udp_calls: udp.clone(),
            }),
            tcp,
            udp,
        )
    }

    #[tokio::test]
    async fn live_udp_uses_live_udp_connector() {
        let (live, _tcp, udp) = counting_live();
        let result = run_live_benchmark("udp", Some(live), None, 3, 2, true)
            .await
            .unwrap();
        assert_eq!(result.driver, "udp");
        assert_eq!(udp.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn live_limits_uses_live_tcp_connector() {
        let (live, tcp, _udp) = counting_live();
        let result = run_live_benchmark("limits", Some(live), None, 3, 2, true)
            .await
            .unwrap();
        assert_eq!(result.driver, "limits");
        assert!(tcp.load(Ordering::SeqCst) >= 3);
    }

    #[tokio::test]
    async fn live_reconnect_uses_supplied_trigger() {
        let waits = Arc::new(AtomicUsize::new(0));
        let drops = Arc::new(AtomicUsize::new(0));
        let reconnect: Arc<dyn ReconnectTrigger> = Arc::new(CountingReconnect {
            waits: waits.clone(),
            drops: drops.clone(),
        });
        let result = run_live_benchmark("reconnect", None, Some(reconnect), 2, 2, true)
            .await
            .unwrap();
        assert_eq!(result.driver, "reconnect");
        assert_eq!(drops.load(Ordering::SeqCst), 2);
        assert_eq!(waits.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn unknown_driver_returns_string_error() {
        let err = run_live_benchmark("flux-capacitor", None, None, 1, 2, false)
            .await
            .unwrap_err();
        assert!(err.contains("unknown driver"), "{err}");
        assert!(err.contains("latency"), "{err}");
    }

    #[tokio::test]
    async fn synthetic_latency_against_loopback_echo() {
        // No live connector; the synthetic tcp_connector is used.
        let result = run_live_benchmark("latency", None, None, 3, 2, true)
            .await
            .unwrap();
        assert_eq!(result.driver, "latency");
    }

    #[tokio::test]
    async fn synthetic_dns_driver_returns_results() {
        let result = run_live_benchmark("dns", None, None, 2, 2, true)
            .await
            .unwrap();
        assert_eq!(result.driver, "dns");
    }

    #[tokio::test]
    async fn synthetic_udp_driver_round_trips() {
        let result = run_live_benchmark("udp", None, None, 2, 2, true)
            .await
            .unwrap();
        assert_eq!(result.driver, "udp");
    }

    #[tokio::test]
    async fn reconnect_with_no_trigger_uses_noop() {
        // No reconnect trigger supplied → falls back to the in-file Noop impl.
        let result = run_live_benchmark("reconnect", None, None, 1, 2, true)
            .await
            .unwrap();
        assert_eq!(result.driver, "reconnect");
    }
}
