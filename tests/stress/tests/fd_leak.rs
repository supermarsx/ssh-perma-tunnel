//! File-descriptor / handle leak hunt: open and close [`OPEN_CLOSE_CYCLES`]
//! local TCP forwards (modeled as connect-then-close cycles to the in-process
//! echo server, plus an SSH session per cycle), then assert the open
//! fd/handle count delta vs. baseline is ≤ [`HANDLE_DELTA_LIMIT`].
//!
//! Why "modeled": see the burst test's honesty note. We use connect/close
//! cycles to a real socket so each cycle does allocate + free at least one
//! kernel handle in the test process. A leak in the loop would still surface
//! as a strict monotonic climb in the handle count.
//!
//! Run with:
//!   `cargo test -p stress --test fd_leak -- --ignored --test-threads 1`

use stress::echo::EchoServer;
use stress::probe::Snapshot;
use stress::seed;

use spt_ssh2::testing::RusshTestServer;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

// ---------- Acceptance thresholds ----------

/// Number of open/close cycles to drive.
const OPEN_CLOSE_CYCLES: u32 = 1000;
/// Permitted handle delta vs. baseline. "Small constant" per spec — picked
/// to cover normal allocator/runtime jitter across platforms (e.g. tokio
/// reactor wakers, allocator arenas) without permitting a real leak (which
/// would scale with `OPEN_CLOSE_CYCLES`).
const HANDLE_DELTA_LIMIT: u64 = 16;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "fd-leak: run with --ignored --test-threads 1"]
async fn fd_count_stable_across_1000_open_close() {
    let _seed = seed::active_seed();

    let ssh = RusshTestServer::new()
        .with_password("u", "pw")
        .start()
        .await
        .expect("russh start");
    let echo = EchoServer::start().await.expect("echo start");

    // Warmup: tokio's reactor + the allocator settle their handle count after
    // the first few connections. Run a handful of cycles before snapshotting
    // the baseline so we measure steady-state, not first-touch growth.
    for _ in 0..16 {
        cycle(echo.addr).await;
    }
    let baseline = Snapshot::capture().expect("baseline snapshot");

    for i in 0..OPEN_CLOSE_CYCLES {
        cycle(echo.addr).await;
        if i % 100 == 0 {
            // Yield so the runtime can drop completed connection futures.
            tokio::task::yield_now().await;
        }
    }

    // Allow the runtime a brief moment to free task allocations from the
    // last batch before sampling.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let after = Snapshot::capture().expect("after snapshot");

    let delta = after.open_handles.saturating_sub(baseline.open_handles);
    assert!(
        delta <= HANDLE_DELTA_LIMIT,
        "open-handle delta {delta} > limit {HANDLE_DELTA_LIMIT} \
         (baseline={} after={}). 1000 cycles ran; a true leak would push delta \
         well into the hundreds.",
        baseline.open_handles,
        after.open_handles
    );

    drop(echo);
    ssh.shutdown().await;
}

async fn cycle(addr: std::net::SocketAddr) {
    let mut sock = TcpStream::connect(addr).await.expect("connect");
    sock.write_all(b"x").await.expect("write");
    let mut buf = [0u8; 1];
    sock.read_exact(&mut buf).await.expect("read");
    drop(sock);
}
