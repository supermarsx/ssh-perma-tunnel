#![no_main]
//! Fuzz the HTTP CONNECT client-side response parser — must never panic.
//!
//! The plan target name is `HttpConnectClient::parse_response`. The
//! current source ships `spt_ssh2::proxy_jump::http_connect`, an async
//! function operating on `AsyncRead + AsyncWrite`. We treat that as the
//! equivalent: a fuzzer-controlled "server" side replays `data` as the
//! response bytes the client reads, while the client's CONNECT request
//! is silently dropped. The harness exercises the same response-parse
//! path the production code uses (status line + headers up to
//! \r\n\r\n, 64 KiB cap).
use std::pin::Pin;
use std::task::{Context, Poll};

use libfuzzer_sys::fuzz_target;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use spt_ssh2::proxy_jump::{http_connect, ProxyCredentials};

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
        // No-auth path.
        let mut s1 = ReplayStream::new(data);
        let _ = http_connect(&mut s1, "fuzz.invalid", 443, None).await;

        // Basic-auth path (forces the Proxy-Authorization header into the
        // discarded write; the response-parse logic is unchanged).
        let creds = ProxyCredentials {
            username: "u".into(),
            password: "p".into(),
        };
        let mut s2 = ReplayStream::new(data);
        let _ = http_connect(&mut s2, "fuzz.invalid", 443, Some(&creds)).await;
    });
});
