//! [`ChaosBehaviour::RstAfterBytes`](crate::ChaosBehaviour::RstAfterBytes)
//! helper.
//!
//! Triggering a real RST cross-platform requires setting `SO_LINGER` to
//! zero before close. We can't recover a [`socket2::Socket`] from a
//! `tokio::io::WriteHalf` without unsafe, so instead we:
//!
//! 1. Shut down the write half (this is enough for the OS to send a FIN —
//!    or, with `SO_LINGER` 0 already applied at accept time, an RST).
//! 2. Drop both halves promptly so the kernel reclaims the socket.
//!
//! On platforms where `shutdown()` produces a FIN rather than an RST,
//! callers still observe a clean connection-closed signal — sufficient for
//! the supervisor's reconnect loop, which is what we're stress-testing.

use tokio::io::{AsyncWrite, AsyncWriteExt};

/// Best-effort RST. Caller drops both halves immediately after.
pub async fn force_rst<W: AsyncWrite + Unpin>(w: &mut W) {
    let _ = w.shutdown().await;
}
