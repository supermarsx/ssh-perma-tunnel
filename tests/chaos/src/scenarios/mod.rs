//! Reconnect scenarios authored by **t8-C2**.
//!
//! C1 left this module empty so C2 could append scenarios without fighting
//! the C1 lock. The 12 scenarios live in their own `.rs` files; common
//! scaffolding (TCP-probe protocol, echo server, observer, helpers) lives
//! in [`common`].
//!
//! ## Running
//!
//! Ten of the twelve scenarios are deterministic and run on every PR (the
//! Linux CI `chaos` job runs the default set). The two remaining ones are
//! feature-gated — they depend on chaos-proxy behaviours that are not yet
//! implemented (`DnsAnswerRotation`, `HostKeyChurn`) — and stay `#[ignore]`'d
//! with a reason explaining what would un-block them. To run the ignored
//! pair anyway (they currently only assert plumbing):
//!
//! ```bash
//! cargo test --manifest-path tests/chaos/Cargo.toml -- --ignored
//! ```
//!
//! ## PR-gating vs ignored
//!
//! | Status | Scenarios |
//! |---|---|
//! | PR-gating (run on every PR) | `max_attempts_exhaustion`, `rst_storm_100_per_sec`, `kill_server_mid_handshake`, `kill_server_mid_data`, `network_partition_during_keepalive`, `latency_spike_10ms_to_500ms`, `slow_loris_connect`, `half_close`, `repeated_quick_reconnects`, `reset_after_stable_uptime` (10) |
//! | `#[ignore]` — feature-gated, cannot run yet | `dns_flap_ttl_1s`, `host_key_churn_after_restart` (2) |
//!
//! See `.orchestration/logs/t8-C2.md` for the full status matrix +
//! reconnect-logic bugs surfaced during scenario authoring.

pub mod common;

pub mod kill_server_mid_handshake;
pub mod kill_server_mid_data;
pub mod network_partition_during_keepalive;
pub mod latency_spike_10ms_to_500ms;
pub mod rst_storm_100_per_sec;
pub mod dns_flap_ttl_1s;
pub mod host_key_churn_after_restart;
pub mod slow_loris_connect;
pub mod half_close;
pub mod repeated_quick_reconnects;
pub mod max_attempts_exhaustion;
pub mod reset_after_stable_uptime;
