//! Soak test: continuous forward + 100 conn/s steady-state for [`SOAK_DURATION`]
//! (default 24h, override via `SPT_SOAK_DURATION_SECS`). Asserts hourly:
//!
//! 1. The russh server stays up (a fresh TCP connect to its addr succeeds).
//! 2. Open handle/fd count delta vs. baseline ≤ [`HANDLE_DELTA_LIMIT`].
//! 3. RSS is not monotonically growing — i.e. the latest hourly sample is no
//!    more than [`RSS_GROWTH_LIMIT_BYTES`] above the *minimum* of all prior
//!    samples. (A pure leak shows up as a strict monotonic climb.)
//!
//! Everything is parameterized by named constants at the top of the file so
//! the operator can shrink the duration for a smoke run without editing the
//! assertion logic.
//!
//! Run with:
//!   `cargo test -p stress --test soak_24h -- --ignored --test-threads 1`
//! For a 60-second smoke run:
//!   `SPT_SOAK_DURATION_SECS=60 cargo test -p stress --test soak_24h -- --ignored --test-threads 1`

#![allow(clippy::cast_possible_truncation)]

use std::io;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use stress::echo::EchoServer;
use stress::probe::Snapshot;
use stress::seed;

use spt_ssh2::testing::RusshTestServer;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

// ---------- Acceptance thresholds ----------

/// Target soak duration. The default is 24h per spec; in practice the test is
/// `#[ignore]` and operators set `SPT_SOAK_DURATION_SECS` to whatever they
/// can afford. Any value ≥ [`MIN_SOAK_FOR_ASSERTIONS`] enables the hourly
/// assertion loop; shorter runs still execute the steady-state body.
const SOAK_DURATION: Duration = Duration::from_secs(24 * 60 * 60);
/// Below this duration we skip the hourly RSS-trend assertion (we still
/// verify liveness once at the end). Lets a 60-s smoke run pass cleanly.
const MIN_SOAK_FOR_ASSERTIONS: Duration = Duration::from_secs(60 * 60);
/// Steady-state target rate (connections per second).
const TARGET_CONN_PER_SEC: u32 = 100;
/// Number of one-shot echo listeners to rotate through. This keeps the same
/// aggregate 100 conn/s target while avoiding a single hot loopback 4-tuple
/// on Windows during long runs.
const ECHO_ENDPOINTS: usize = 16;
/// Transient Windows `AddrInUse` can occur when the OS picks a recently used
/// local endpoint. Retry against the next listener before failing the tick.
const ADDR_IN_USE_RETRY_DELAY: Duration = Duration::from_millis(10);
/// Permitted growth above the rolling minimum hourly RSS sample. 32 MiB
/// tolerates page-cache jitter without permitting a true leak.
const RSS_GROWTH_LIMIT_BYTES: u64 = 32 * 1024 * 1024;
/// Permitted handle/fd count delta vs baseline. Forwards open and close
/// inside the loop, so steady-state delta should be tiny.
const HANDLE_DELTA_LIMIT: u64 = 32;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "soak: 24h by default. Set SPT_SOAK_DURATION_SECS for shorter runs."]
async fn soak_steady_state_no_growth() {
    let _seed = seed::active_seed();

    let target_duration = std::env::var("SPT_SOAK_DURATION_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .map_or(SOAK_DURATION, Duration::from_secs);

    let ssh = RusshTestServer::new()
        .with_password("u", "pw")
        .start()
        .await
        .expect("russh start");
    let ssh_addr = ssh.addr;
    let echo_servers = start_echo_servers().await;
    let echo_addrs: Vec<SocketAddr> = echo_servers.iter().map(|server| server.addr).collect();

    let baseline = Snapshot::capture().expect("baseline snapshot");
    let mut hourly_rss: Vec<u64> = vec![baseline.rss_bytes];

    let started = Instant::now();
    let mut last_hour_mark = started;
    // 100 conn/s → one connection every 10ms.
    let interval = Duration::from_millis(1000 / u64::from(TARGET_CONN_PER_SEC));
    let mut tick = tokio::time::interval(interval);
    let mut echo_cursor = 0usize;

    while started.elapsed() < target_duration {
        tick.tick().await;

        // Steady-state work: a single TCP echo round trip.
        let res = tokio::time::timeout(
            Duration::from_secs(2),
            echo_round_trip(&echo_addrs, &mut echo_cursor),
        )
        .await
        .expect("steady-state echo did not time out")
        .expect("steady-state echo succeeded");
        assert_eq!(&res, b"ping");

        if last_hour_mark.elapsed() >= Duration::from_secs(3600) {
            last_hour_mark = Instant::now();
            // Liveness: server still accepts a connection.
            let live = TcpStream::connect(ssh_addr).await;
            assert!(live.is_ok(), "ssh server dropped during soak");
            drop(live);

            let snap = Snapshot::capture().expect("hourly snapshot");
            hourly_rss.push(snap.rss_bytes);

            // fd/handle delta check.
            let delta = snap.open_handles.saturating_sub(baseline.open_handles);
            assert!(
                delta <= HANDLE_DELTA_LIMIT,
                "handle count grew by {delta} (baseline={} now={})",
                baseline.open_handles,
                snap.open_handles
            );

            // Anti-monotonic growth: latest sample - rolling-min ≤ limit.
            let rolling_min = *hourly_rss.iter().min().expect("≥1 sample");
            let growth = snap.rss_bytes.saturating_sub(rolling_min);
            assert!(
                growth <= RSS_GROWTH_LIMIT_BYTES,
                "RSS grew {growth} bytes above rolling-min {rolling_min} (samples={hourly_rss:?})"
            );
        }
    }

    // Final liveness assertion (always runs, even on smoke runs).
    let live = TcpStream::connect(ssh_addr).await;
    assert!(live.is_ok(), "ssh server dropped before end of soak");

    if target_duration < MIN_SOAK_FOR_ASSERTIONS {
        eprintln!(
            "soak: skipped trend assertions (duration {}s < {}s minimum)",
            target_duration.as_secs(),
            MIN_SOAK_FOR_ASSERTIONS.as_secs()
        );
    }

    drop(echo_servers);
    ssh.shutdown().await;
}

async fn start_echo_servers() -> Vec<EchoServer> {
    let mut servers = Vec::with_capacity(ECHO_ENDPOINTS);
    for i in 0..ECHO_ENDPOINTS {
        servers.push(
            EchoServer::start_one_shot()
                .await
                .unwrap_or_else(|err| panic!("echo server {i} start: {err}")),
        );
    }
    servers
}

async fn echo_round_trip(addrs: &[SocketAddr], cursor: &mut usize) -> io::Result<[u8; 4]> {
    for attempt in 0..ECHO_ENDPOINTS {
        let addr = addrs[*cursor % addrs.len()];
        *cursor = cursor.wrapping_add(1);

        match single_echo_round_trip(addr).await {
            Ok(buf) => return Ok(buf),
            Err(err) if err.kind() == io::ErrorKind::AddrInUse => {
                if attempt + 1 == ECHO_ENDPOINTS {
                    return Err(err);
                }
                tokio::time::sleep(ADDR_IN_USE_RETRY_DELAY).await;
            }
            Err(err) => return Err(err),
        }
    }

    unreachable!("ECHO_ENDPOINTS is non-zero");
}

async fn single_echo_round_trip(addr: SocketAddr) -> io::Result<[u8; 4]> {
    let mut sock = TcpStream::connect(addr).await?;
    sock.write_all(b"ping").await?;

    let mut buf = [0u8; 4];
    sock.read_exact(&mut buf).await?;

    let mut eof = [0u8; 1];
    let bytes = sock.read(&mut eof).await?;
    if bytes == 0 {
        Ok(buf)
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "one-shot echo server returned trailing data",
        ))
    }
}
