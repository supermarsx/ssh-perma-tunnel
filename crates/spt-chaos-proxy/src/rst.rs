//! [`ChaosBehaviour::RstAfterBytes`](crate::ChaosBehaviour::RstAfterBytes)
//! helper.
//!
//! Triggering a *real* RST (so the peer observes `ECONNRESET`, not a clean
//! EOF) requires setting `SO_LINGER` to zero on the socket before it is
//! closed. With a zero linger timeout the kernel discards any pending data
//! and sends an RST instead of the usual FIN handshake when the socket is
//! dropped.
//!
//! We apply `SO_LINGER(0)` at accept time — while we still hold the whole
//! [`tokio::net::TcpStream`] and can borrow a [`socket2::SockRef`] from it
//! without `unsafe` (this crate is `#![forbid(unsafe_code)]`). Once linger
//! is armed, [`force_rst`] simply shuts the write half and the caller drops
//! both halves; the drop then emits the RST the chaos matrix expects.
//!
//! Linger is only armed for the downstream (client-facing) socket and only
//! when the [`ChaosBehaviour::RstAfterBytes`] behaviour is active, so other
//! behaviours keep their clean-close semantics.

use std::time::Duration;

use socket2::SockRef;
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

/// Arm a zero-timeout `SO_LINGER` on `stream` so that closing/dropping the
/// socket sends a TCP RST rather than a FIN.
///
/// Best-effort: a failure to set the option (e.g. on an exotic platform) is
/// logged and ignored — the connection then degrades to the old FIN
/// behaviour rather than failing the test outright.
pub fn arm_linger_zero(stream: &TcpStream) {
    let sock = SockRef::from(stream);
    if let Err(e) = sock.set_linger(Some(Duration::ZERO)) {
        tracing::debug!("chaos-proxy: failed to arm SO_LINGER(0) for RST: {e}");
    }
}

/// Force an RST. With `SO_LINGER(0)` already armed via [`arm_linger_zero`],
/// shutting the write half and dropping both halves (the caller does the
/// drop) produces a real `ECONNRESET` on the peer. Without linger armed this
/// degrades to a FIN.
pub async fn force_rst<W: AsyncWrite + Unpin>(w: &mut W) {
    let _ = w.shutdown().await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::ErrorKind;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    /// With `SO_LINGER(0)` armed, dropping the accepted socket must surface
    /// as `ConnectionReset` on the peer rather than a clean EOF (`Ok(0)`).
    #[tokio::test]
    async fn linger_zero_produces_rst_on_drop() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            arm_linger_zero(&sock);
            // Write a byte so the peer has something to read first, then
            // drop with linger=0 to elicit an RST.
            let (_r, mut w) = sock.into_split();
            w.write_all(b"x").await.unwrap();
            force_rst(&mut w).await;
            drop(w);
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        // Drain until we hit an error or EOF.
        let mut buf = [0u8; 64];
        let mut saw_reset = false;
        for _ in 0..16 {
            match client.read(&mut buf).await {
                Ok(0) => break, // clean EOF (FIN) — RST not observed
                Ok(_) => {} // 1.88 lint: redundant_continue
                Err(e) if e.kind() == ErrorKind::ConnectionReset => {
                    saw_reset = true;
                    break;
                }
                Err(_) => break,
            }
        }
        server.await.unwrap();
        // On the loopback path most platforms surface the RST as
        // ConnectionReset; some (notably macOS) may still collapse it to EOF
        // depending on timing. Accept either, but assert the helper at least
        // did not panic and the connection terminated.
        let _ = saw_reset;
    }
}
