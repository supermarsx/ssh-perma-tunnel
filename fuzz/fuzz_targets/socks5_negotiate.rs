#![no_main]
//! Fuzz the SOCKS5 client-side negotiation parser — must never panic.
//!
//! The plan target name is `Socks5Negotiator::parse_server_response`.
//! The current source ships `spt_ssh2::proxy_jump::socks5_connect`, an
//! async function operating on `AsyncRead + AsyncWrite`. We treat that
//! as the equivalent: a fuzzer-controlled "server" side replays `data`
//! as the byte stream the client reads, while the client's writes are
//! discarded. The harness exercises the same SOCKS5-reply parse path
//! the production code uses.
use std::pin::Pin;
use std::task::{Context, Poll};

use libfuzzer_sys::fuzz_target;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use spt_ssh2::proxy_jump::{socks5_connect, ProxyCredentials};

/// `AsyncRead` that replays a fixed byte slice; `AsyncWrite` that drops
/// every byte the client sends.
struct ReplayStream<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> ReplayStream<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }
}

impl<'a> AsyncRead for ReplayStream<'a> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let remaining = self.data.len().saturating_sub(self.pos);
        if remaining == 0 {
            // EOF — surface as Ok(0 bytes read) so the parser hits its
            // truncated-input branch.
            return Poll::Ready(Ok(()));
        }
        let n = buf.remaining().min(remaining);
        let pos = self.pos;
        buf.put_slice(&self.data[pos..pos + n]);
        self.pos += n;
        Poll::Ready(Ok(()))
    }
}

impl<'a> AsyncWrite for ReplayStream<'a> {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Poll::Ready(Ok(buf.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

fuzz_target!(|data: &[u8]| {
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("tokio runtime");
    rt.block_on(async move {
        // Exercise both no-auth and userpass code paths.
        let mut s1 = ReplayStream::new(data);
        let _ = socks5_connect(&mut s1, "fuzz.invalid", 22, None).await;

        let creds = ProxyCredentials {
            username: "u".into(),
            password: "p".into(),
        };
        let mut s2 = ReplayStream::new(data);
        let _ = socks5_connect(&mut s2, "fuzz.invalid", 22, Some(&creds)).await;
    });
});
