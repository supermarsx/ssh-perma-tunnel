//! [`ChaosBehaviour::Partition`](crate::ChaosBehaviour::Partition) helper.
//!
//! "Partition" here means: stop transferring bytes in either direction.
//! TCP keep-alive (if enabled by the application) and the supervisor's
//! own keepalive are what eventually notice. The socket stays open from
//! the OS' perspective.

use std::time::{Duration, Instant};

/// `true` iff `elapsed(started) >= after`.
#[must_use]
pub fn is_partitioned(started: Instant, after: Duration) -> bool {
    started.elapsed() >= after
}

/// Park the task until cancelled. Equivalent to `std::future::pending()`,
/// but expressed as a function for symmetry with the other helpers.
pub async fn idle_forever() {
    std::future::pending::<()>().await;
}
