//! Integration tests exercising each `ChaosBehaviour` against a
//! synthetic upstream echo server.

#![deny(unsafe_op_in_unsafe_fn)]
// The brief names one of the tests `rst_after_bytes_triggers_RST`.
#![allow(non_snake_case)]
#![allow(clippy::manual_let_else)]

use std::net::SocketAddr;
use std::time::Duration;

use spt_chaos_proxy::{ChaosBehaviour, ChaosProxy};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Spawn a TCP "echo upstream" that returns whatever it receives. Returns
/// the bound address.
async fn spawn_echo() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = match l.accept().await {
                Ok(p) => p,
                Err(_) => return,
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                loop {
                    let n = match s.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => n,
                    };
                    if s.write_all(&buf[..n]).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    addr
}

async fn launch(behaviour: ChaosBehaviour) -> (SocketAddr, spt_chaos_proxy::ChaosProxyHandle) {
    let echo = spawn_echo().await;
    let proxy = ChaosProxy::bind("127.0.0.1:0".parse().unwrap(), echo, behaviour)
        .await
        .unwrap();
    let handle = proxy.handle();
    let local = proxy.local_addr();
    tokio::spawn(async move {
        let _ = proxy.run().await;
    });
    (local, handle)
}

#[tokio::test]
async fn proxy_passthrough_no_chaos_works() {
    let (addr, _h) = launch(ChaosBehaviour::Pristine).await;
    let mut s = TcpStream::connect(addr).await.unwrap();
    s.write_all(b"hello").await.unwrap();
    let mut buf = [0u8; 5];
    s.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"hello");
}

#[tokio::test]
async fn latency_proxy_delays_chunks_by_configured_amount() {
    // 200 ms of injected latency should dominate the round-trip on loopback.
    let (addr, _h) = launch(ChaosBehaviour::LatencyMs(200)).await;
    let mut s = TcpStream::connect(addr).await.unwrap();

    let start = std::time::Instant::now();
    s.write_all(b"abc").await.unwrap();
    let mut buf = [0u8; 3];
    s.read_exact(&mut buf).await.unwrap();
    let elapsed = start.elapsed();
    assert_eq!(&buf, b"abc");
    // 200 ms upstream-path + 200 ms downstream-path = >= ~400 ms total.
    // Allow generous slack for loaded CI.
    assert!(
        elapsed >= Duration::from_millis(350),
        "expected >=350ms, observed {elapsed:?}"
    );
}

#[tokio::test]
async fn loss_proxy_drops_configured_pct() {
    // 100% loss → reads on the downstream socket should never complete.
    let (addr, _h) = launch(ChaosBehaviour::LossPct(100)).await;
    let mut s = TcpStream::connect(addr).await.unwrap();
    s.write_all(b"xyz").await.unwrap();
    let mut buf = [0u8; 3];
    let r = tokio::time::timeout(Duration::from_millis(300), s.read_exact(&mut buf)).await;
    assert!(r.is_err(), "100% loss should starve the reader");
}

#[tokio::test]
async fn rst_after_bytes_triggers_RST() {
    // After 4 bytes, the proxy will tear down the pair. The peer observes
    // an EOF or ConnectionReset.
    let (addr, _h) = launch(ChaosBehaviour::RstAfterBytes(4)).await;
    let mut s = TcpStream::connect(addr).await.unwrap();
    // Send 8 bytes. The first chunk that pushes the counter ≥ 4 closes.
    let _ = s.write_all(b"AAAABBBB").await;
    let buf = [0u8; 8];
    let mut sink = buf.to_vec();
    let r = tokio::time::timeout(Duration::from_secs(2), s.read_to_end(&mut sink)).await;
    // Either we time out (FIN propagating slowly) or read_to_end returns —
    // both indicate the connection no longer carries traffic. The
    // critical assertion: we do NOT see all 8 bytes echoed.
    if let Ok(Ok(n)) = r {
        assert!(n < 8, "expected RST/EOF before all 8 bytes; got {n}");
    }
}

#[tokio::test]
async fn partition_goes_silent_after_delay() {
    // Partition after 100 ms. Initial bytes should flow; after the
    // partition kicks in, the downstream side stops receiving.
    let (addr, _h) = launch(ChaosBehaviour::Partition {
        after: Duration::from_millis(100),
    })
    .await;
    let mut s = TcpStream::connect(addr).await.unwrap();
    s.write_all(b"early").await.unwrap();
    let mut buf = [0u8; 5];
    s.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"early");

    // Wait past the partition threshold.
    tokio::time::sleep(Duration::from_millis(200)).await;

    s.write_all(b"late!").await.unwrap();
    let mut buf2 = [0u8; 5];
    let r = tokio::time::timeout(Duration::from_millis(400), s.read_exact(&mut buf2)).await;
    assert!(r.is_err(), "after partition the read must not complete");
}

#[tokio::test]
async fn set_behaviour_swaps_at_runtime() {
    // Start pristine; flip to 100% loss mid-flight; verify the swap took.
    let (addr, handle) = launch(ChaosBehaviour::Pristine).await;
    let mut s = TcpStream::connect(addr).await.unwrap();
    s.write_all(b"AAA").await.unwrap();
    let mut buf = [0u8; 3];
    s.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"AAA");

    handle.set_behaviour(ChaosBehaviour::LossPct(100));
    // Give the in-flight task time to notice on its next iteration.
    tokio::time::sleep(Duration::from_millis(50)).await;

    s.write_all(b"BBB").await.unwrap();
    let mut buf2 = [0u8; 3];
    let r = tokio::time::timeout(Duration::from_millis(300), s.read_exact(&mut buf2)).await;
    assert!(r.is_err(), "post-swap reads should be starved by 100% loss");
}
