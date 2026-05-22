//! [`ChaosBehaviour::LatencyMs`](crate::ChaosBehaviour::LatencyMs) helpers.
//!
//! Just a thin wrapper around `tokio::time::sleep` so the lib.rs hot loop
//! reads as a single line per behaviour.

use std::time::Duration;

/// Sleep `ms` milliseconds. A `0` is a no-op (avoids a spurious yield).
pub async fn delay(ms: u64) {
    if ms == 0 {
        return;
    }
    tokio::time::sleep(Duration::from_millis(ms)).await;
}
