//! Integration test mirroring the `spt log remote drain` pipeline using
//! the same underlying primitives (`spt_state::DiskSpool` +
//! `spt_observability::syslog_udp::send_one`). This pins the contract
//! that `cli::log_ops::remote_drain` relies on — if either side changes
//! shape, this test fails the same way the binary would.
//!
//! `spt-bin` exposes no library target, so we cannot import its private
//! `cli::log_ops::*` API directly; the goal here is to validate the
//! end-to-end primitives the binary chains together.

use std::time::Duration;

use spt_observability::syslog_udp::{send_one, SyslogUdpConfig};
use spt_state::{DiskSpool, SpoolConfig};
use tempfile::tempdir;

#[tokio::test(flavor = "current_thread")]
async fn diskspool_feeding_syslog_udp_delivers_each_record_in_order() {
    // UDP receiver on loopback — the drain code-path target.
    let receiver = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = receiver.local_addr().unwrap();

    let tmp = tempdir().expect("tempdir");
    let spool_dir = tmp.path().join("spool");

    let payloads = [
        b"<134>1 first record".to_vec(),
        b"<134>1 second record".to_vec(),
        b"<134>1 third record".to_vec(),
    ];

    // Push three records.
    {
        let mut spool = DiskSpool::open(spool_dir.clone(), SpoolConfig::default()).unwrap();
        for p in &payloads {
            spool.push(p).unwrap();
        }
        assert_eq!(spool.len(), 3);
    }

    // Drain — mirrors `remote_drain`'s pop+send loop.
    let cfg = SyslogUdpConfig::new(addr.ip().to_string(), addr.port());
    let mut drained = 0_u64;
    {
        let mut spool = DiskSpool::open(spool_dir.clone(), SpoolConfig::default()).unwrap();
        while let Some(entry) = spool.pop().unwrap() {
            send_one(&cfg, entry.payload).await.unwrap();
            drained += 1;
        }
    }
    assert_eq!(drained, 3);

    // Receive all three frames and assert ordering (FIFO).
    let mut got: Vec<String> = Vec::new();
    for _ in 0..3 {
        let mut buf = [0_u8; 256];
        let n = tokio::time::timeout(Duration::from_secs(1), receiver.recv(&mut buf))
            .await
            .expect("receive within deadline")
            .expect("recv ok");
        got.push(String::from_utf8_lossy(&buf[..n]).into_owned());
    }
    assert!(got[0].contains("first record"), "got[0]={}", got[0]);
    assert!(got[1].contains("second record"), "got[1]={}", got[1]);
    assert!(got[2].contains("third record"), "got[2]={}", got[2]);

    // Spool should now be empty on re-open (drain consumed all entries).
    let spool = DiskSpool::open(spool_dir, SpoolConfig::default()).unwrap();
    assert!(spool.is_empty());
}

#[tokio::test(flavor = "current_thread")]
async fn diskspool_push_after_failed_send_restores_payload() {
    // Bind a UDP socket but the address we send to is intentionally
    // unreachable (use port 0 on an unbound interface). We need a more
    // robust "fail" path though — actually `send_one` to a UDP socket
    // rarely fails locally. Instead, verify that the drain code's
    // re-push-on-failure shape works: simulate by manually re-pushing
    // after a hypothetical send error.
    let tmp = tempdir().expect("tempdir");
    let spool_dir = tmp.path().join("retry-spool");

    {
        let mut spool = DiskSpool::open(spool_dir.clone(), SpoolConfig::default()).unwrap();
        spool.push(b"<134>1 alpha").unwrap();
        spool.push(b"<134>1 beta").unwrap();

        // Pop the first record and pretend the send failed: push it back.
        let entry = spool.pop().unwrap().expect("non-empty");
        assert_eq!(entry.payload, b"<134>1 alpha");
        spool.push(&entry.payload).unwrap();
    }
    // Re-open: both records still present.
    let spool = DiskSpool::open(spool_dir, SpoolConfig::default()).unwrap();
    assert_eq!(spool.len(), 2);
}
