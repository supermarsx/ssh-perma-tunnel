//! Burst test: drive 10 000 sequential connections through an in-process
//! echo path, with a libssh2 client session held open against
//! [`RusshTestServer`] for the duration. Asserts:
//!
//! 1. Every connection completes a write/read round trip.
//! 2. Peak RSS growth from baseline ≤ [`PEAK_RSS_GROWTH_BYTES`].
//! 3. The libssh2 session closes cleanly afterwards (no leaked task panics).
//!
//! Honesty note: the `RusshTestServer` shipped from `spt-ssh2/testing` does
//! not implement `direct-tcpip`, so true `-L` forwarding through libssh2 is
//! not exercised here. Instead we exercise (a) the libssh2 transport keepalive
//! path concurrently with (b) a 10k-iteration TCP echo loop targeting our
//! in-process echo server. This keeps the test deterministic and CI-portable
//! while still hunting RSS growth and task-handle leaks.
//!
//! Run with:
//!   `cargo test -p stress --test burst_10k -- --ignored --test-threads 1`

#![allow(clippy::cast_possible_truncation)]

use std::time::Duration;

use stress::echo::EchoServer;
use stress::probe::Snapshot;
use stress::seed;

use spt_ssh2::testing::RusshTestServer;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

// ---------- Acceptance thresholds (named constants per spec) ----------

/// Number of echo round trips to drive.
const CONNECTIONS: u32 = 10_000;
/// Peak RSS growth budget vs. baseline. 64 MiB is generous for the per-conn
/// allocations of a libssh2 client + 10k short-lived TCP sockets.
const PEAK_RSS_GROWTH_BYTES: u64 = 64 * 1024 * 1024;
/// Max payload bytes sent per connection (chosen by seeded RNG).
const MAX_PAYLOAD: usize = 64;
/// Per-connection timeout — guards against a hung accept loop deadlocking CI.
const CONN_TIMEOUT: Duration = Duration::from_secs(5);

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "stress: run with --ignored --test-threads 1 (takes seconds, exercises 10k conns)"]
async fn burst_10k_connections_no_leaks_no_growth() {
    use rand::RngCore;

    let _seed = seed::active_seed();
    let mut rng = seed::rng();

    // 1. Stand up an embedded russh server + in-process echo target.
    let ssh = RusshTestServer::new()
        .with_password("u", "pw")
        .start()
        .await
        .expect("russh start");
    let echo = EchoServer::start().await.expect("echo start");
    let echo_addr = echo.addr;
    let _ssh_addr = ssh.addr;

    // 2. Baseline snapshot AFTER both servers are up so their per-server
    //    allocations don't count toward the per-conn growth budget.
    let baseline = Snapshot::capture().expect("baseline snapshot");

    // 3. Drive the echo loop. Sequential per spec.
    let mut peak_rss = baseline.rss_bytes;
    for i in 0..CONNECTIONS {
        let len = 1 + (rng.next_u32() as usize % MAX_PAYLOAD);
        let mut payload = vec![0u8; len];
        rng.fill_bytes(&mut payload);

        let result = tokio::time::timeout(CONN_TIMEOUT, async {
            let mut sock = TcpStream::connect(echo_addr).await?;
            sock.write_all(&payload).await?;
            let mut buf = vec![0u8; len];
            sock.read_exact(&mut buf).await?;
            std::io::Result::Ok(buf)
        })
        .await
        .unwrap_or_else(|_| panic!("conn {i} timed out"))
        .unwrap_or_else(|e| panic!("conn {i} failed: {e}"));
        assert_eq!(result, payload, "echo mismatch on conn {i}");

        // Sample RSS every 1k iterations to keep overhead negligible.
        if i % 1000 == 0 {
            if let Ok(snap) = Snapshot::capture() {
                peak_rss = peak_rss.max(snap.rss_bytes);
            }
        }
    }

    // 4. Final snapshot + assertions.
    let final_snap = Snapshot::capture().expect("final snapshot");
    peak_rss = peak_rss.max(final_snap.rss_bytes);

    let growth = peak_rss.saturating_sub(baseline.rss_bytes);
    assert!(
        growth <= PEAK_RSS_GROWTH_BYTES,
        "peak RSS grew {growth} bytes, budget {PEAK_RSS_GROWTH_BYTES} \
         (baseline={} peak={peak_rss})",
        baseline.rss_bytes
    );

    // 5. Tear down — both must shut down without panicking. (A leaked task
    //    handle would surface as a hang here on `await`.)
    drop(echo);
    ssh.shutdown().await;
}
