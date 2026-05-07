//! Live-tunnel benchmark dispatch — used by both the CLI's `benchmark run`
//! path (when a running orchestrator is reachable via the loopback MCP
//! transport) and the server-side `benchmark_run` MCP tool.
//!
//! The function takes an optional [`spt_supervisor::LiveConnector`] so it
//! can also be exercised in synthetic-loopback mode (no live tunnel).

use std::sync::Arc;
use std::time::Duration;

use spt_benchmark::{
    BenchContext, BenchEnv, BenchResult, BenchmarkDriver, DnsClient, DnsDriver, LatencyDriver,
    LimitsDriver, LimitsExpectations, ReconnectDriver, ReconnectTrigger, ThroughputDriver,
    UdpDriver, check_safety,
};
use spt_supervisor::LiveConnector;

/// Drive `driver` against either a live tunnel (`live`) or a synthetic
/// loopback echo connector (`live = None`). Returns the `BenchResult`.
pub async fn run_live_benchmark(
    driver: &str,
    live: Option<Arc<dyn LiveConnector>>,
    iterations: u64,
    max_duration_secs: u64,
    allow_production_impact: bool,
) -> Result<BenchResult, String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // Build the per-iteration connector closure, either live-tunnel-backed or
    // synthetic loopback echo.
    let connector: spt_benchmark::Connector = if let Some(lc) = live.clone() {
        Box::new(move || {
            let lc = lc.clone();
            Box::pin(async move {
                let stream = lc
                    .open_tcp("bench", 0)
                    .await
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
                let boxed: spt_benchmark::driver::BoxedStream = Box::pin(stream);
                Ok(boxed)
            })
        })
    } else {
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
    };

    let env = BenchEnv {
        os: std::env::consts::OS.into(),
        arch: std::env::consts::ARCH.into(),
        spt_version: env!("CARGO_PKG_VERSION").into(),
        ..Default::default()
    };

    let drv: Box<dyn BenchmarkDriver> = match driver {
        "latency" => Box::new(LatencyDriver),
        "throughput" => Box::new(ThroughputDriver),
        "udp" => {
            let ud_conn: spt_benchmark::UdpConnector = Box::new(|| {
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
            });
            Box::new(UdpDriver::new(ud_conn))
        }
        "reconnect" => {
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
            Box::new(|| {
                Box::pin(async move {
                    let (a, _b) = tokio::io::duplex(1024);
                    let stream: spt_benchmark::driver::BoxedStream = Box::pin(a);
                    Ok(stream)
                })
            }),
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
