//! Microbenchmarks for the status-snapshot hot paths.
//!
//! One bench group:
//!
//! * `status_serialize` — `serde_json::to_string` (and `to_vec_pretty`,
//!   matching what the writer task actually does) of a populated
//!   [`StatusSnapshot`] with 10 profiles × 5 forwards per profile (= 50
//!   forwards), plus a representative number of sessions, connections,
//!   DNS records, failover entries, `last_errors`, and counters. The
//!   `StatusWriter::flush` path calls `serde_json::to_vec_pretty` every
//!   tick, so both serialiser variants are benched.
//!
//! Run explicitly with:
//!
//! `cargo bench -p spt-state --features bench --bench snapshot`

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};

use chrono::{TimeZone, Utc};
use spt_state::status::{
    ConnectionStatus, Counters, DnsRecordStatus, FailoverProfileEntry, ForwardStatus, LastError,
    ProfileStatus, SessionStatus, StatusSnapshot,
};

/// Build a populated [`StatusSnapshot`] with 10 profiles × 5 forwards.
///
/// Sessions/connections counts mirror the forward count so the snapshot
/// shape matches what a moderately-loaded `spt` daemon would publish.
fn build_populated_snapshot() -> StatusSnapshot {
    let started_at = Utc.with_ymd_and_hms(2026, 5, 16, 12, 0, 0).unwrap();
    let last_activity = Utc.with_ymd_and_hms(2026, 5, 16, 12, 30, 0).unwrap();

    let mut snap = StatusSnapshot {
        pid: 4242,
        version: "0.1.0-bench".to_owned(),
        config_fingerprint_sha256: "deadbeef".repeat(8),
        started_at: Some(started_at),
        ..Default::default()
    };

    for p in 0..10u32 {
        let profile_id = format!("profile-{p:02}");
        snap.profiles.push(ProfileStatus {
            id: profile_id.clone(),
            state: "Running".to_owned(),
            active_endpoint: Some(format!("edge-{p:02}.example.com:22")),
            reconnect_count: u64::from(p),
            failover_count: u64::from(p) / 2,
            last_successful_connection_at: Some(started_at),
            last_error_category: None,
        });

        for f in 0..5u32 {
            let fwd_id = format!("{profile_id}/fwd-{f}");
            snap.forwards.push(ForwardStatus {
                id: fwd_id.clone(),
                profile: profile_id.clone(),
                state: "Connected".to_owned(),
                direction: if f % 2 == 0 { "local" } else { "remote" }.to_owned(),
                transport: if f % 3 == 0 { "udp" } else { "tcp" }.to_owned(),
                local_addr: Some(format!("127.0.0.1:{}", 10_000 + p * 100 + f)),
                remote_addr: Some(format!("10.0.{p}.{f}:22")),
                assigned_remote_port: Some(20_000 + (p * 100 + f) as u16),
                current_connections: u64::from(f) + 1,
                bytes_in: 1_000_000 + u64::from(p * 5 + f) * 1_024,
                bytes_out: 2_000_000 + u64::from(p * 5 + f) * 2_048,
                current_throughput_bps: 1_024 * (u64::from(f) + 1),
                rolling_throughput_bps: 768 * (u64::from(f) + 1),
            });

            snap.sessions.push(SessionStatus {
                id: format!("session-{p:02}-{f}"),
                profile: profile_id.clone(),
                protocol: "ssh2".to_owned(),
                endpoint: format!("edge-{p:02}.example.com:22"),
                user_redacted: Some("***".to_owned()),
                state: "Established".to_owned(),
                started_at: Some(started_at),
                last_activity_at: Some(last_activity),
                keepalive_state: "Healthy".to_owned(),
                reconnect_attempt: 0,
                bytes_in: 1_024 * (u64::from(f) + 1),
                bytes_out: 2_048 * (u64::from(f) + 1),
                packets_in: 100 * (u64::from(f) + 1),
                packets_out: 120 * (u64::from(f) + 1),
                active_forwards: 5,
            });

            snap.connections.push(ConnectionStatus {
                id: format!("conn-{p:02}-{f}"),
                profile: profile_id.clone(),
                forward: fwd_id,
                direction: "local".to_owned(),
                transport: "tcp".to_owned(),
                local_peer: Some(format!("127.0.0.1:{}", 50_000 + p * 100 + f)),
                remote_target_redacted: Some(format!("10.0.{p}.{f}:443")),
                started_at: Some(started_at),
                last_activity_at: Some(last_activity),
                bytes_in: 8_192,
                bytes_out: 16_384,
                packets_in: 32,
                packets_out: 48,
                current_rate_bps: 256_000,
                applied_throttle: None,
                close_reason: None,
            });
        }

        snap.dns_records.push(DnsRecordStatus {
            name: format!("svc-{p:02}.spt.internal"),
            kind: "A".to_owned(),
            value: format!("127.0.{p}.1"),
            healthy: p % 7 != 0,
        });

        snap.failover_state.per_profile.push(FailoverProfileEntry {
            profile: profile_id.clone(),
            current_endpoint: Some(format!("edge-{p:02}.example.com:22")),
            remaining_targets: 3 - (p % 4),
            cooldown_until: None,
        });
    }

    snap.last_errors.push(LastError {
        scope: "session".to_owned(),
        category: "Network".to_owned(),
        message: "transient connect timeout".to_owned(),
        at: Some(last_activity),
    });
    snap.last_errors.push(LastError {
        scope: "profile".to_owned(),
        category: "Auth".to_owned(),
        message: "publickey accepted after 1 retry".to_owned(),
        at: Some(last_activity),
    });

    snap.counters = Counters {
        bytes_in: 1_024_000_000,
        bytes_out: 2_048_000_000,
        sessions_opened: 1_234,
        sessions_closed: 1_200,
        connections_opened: 9_876,
        connections_closed: 9_700,
        reconnects: 42,
        failovers: 7,
    };

    // Explicit shape assertion: 10 × 5 = 50 forwards. Anchors the fixture to
    // the spec stated in the bench header so a future edit can't quietly
    // shrink the workload.
    debug_assert_eq!(snap.profiles.len(), 10);
    debug_assert_eq!(snap.forwards.len(), 50);

    snap
}

fn bench_status_serialize(c: &mut Criterion) {
    let snap = build_populated_snapshot();

    // Size the throughput report off a one-shot serialize so the bench
    // header reports MB/s for the workload, matching how the writer task
    // measures its disk write footprint.
    let baseline_len = serde_json::to_vec_pretty(&snap)
        .expect("serialize snapshot for sizing")
        .len();
    assert!(baseline_len > 0);

    let mut group = c.benchmark_group("status_serialize");
    group.throughput(Throughput::Bytes(baseline_len as u64));

    // `to_string` — what most ad-hoc consumers (CLI `status`, tests) use.
    group.bench_function("to_string", |b| {
        b.iter(|| {
            let s = serde_json::to_string(black_box(&snap)).expect("serialize snapshot");
            black_box(s);
        });
    });

    // `to_vec_pretty` — what `StatusWriter::flush` actually writes to disk.
    group.bench_function("to_vec_pretty", |b| {
        b.iter(|| {
            let v = serde_json::to_vec_pretty(black_box(&snap)).expect("serialize snapshot pretty");
            black_box(v);
        });
    });

    group.finish();
}

criterion_group!(benches, bench_status_serialize);
criterion_main!(benches);
