//! Reconnect scenarios authored by **t8-C2**.
//!
//! C1 left this module empty so C2 could append scenarios without fighting
//! the C1 lock. The 12 scenarios live in their own `.rs` files; common
//! scaffolding (TCP-probe protocol, echo server, observer, helpers) lives
//! in [`common`].
//!
//! ## Running
//!
//! Most scenarios are `#[ignore]`'d by default because they are timing-
//! sensitive and would flake under CI load. To run the full suite:
//!
//! ```bash
//! SPT_CHAOS_FULL=1 cargo test \
//!     --manifest-path tests/chaos/Cargo.toml -- --ignored
//! ```
//!
//! ## PR-gating vs ignored
//!
//! | Status | Scenarios |
//! |---|---|
//! | PR-gating (run on every PR) | `max_attempts_exhaustion`, `rst_storm_100_per_sec` |
//! | `#[ignore]` — runs under `SPT_CHAOS_FULL=1` | the remaining 10 |
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
