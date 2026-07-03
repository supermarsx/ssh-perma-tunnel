//! HIGH-2 meek data-plane regression tests.
//!
//! meek is the one obfs transport whose data plane is HTTP (reqwest), so these
//! tests drive a real `MeekStream` against a minimal loopback HTTP/1.1 server
//! rather than an in-memory mock. They pin the two HIGH-2 fixes:
//!
//! * (a) an EMPTY POST response is NOT end-of-stream — an idle-but-open meek
//!   session must back off and retry, never surface a premature EOF that would
//!   half-close the tunnel; and
//! * (b) a `poll_write` issued while a read POST is in flight must issue its OWN
//!   POST carrying the data (separate in-flight slots) — it must not be swallowed
//!   by the pending read and reported as sent without transmitting anything.

#![allow(clippy::missing_panics_doc)]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use reqwest::header::HeaderMap;
use reqwest::Client;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use spt_obfs::meek::MeekStream;

/// Find `needle` in `hay`, returning the start index.
fn find_sub(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

/// Parse the `Content-Length` header value (case-insensitive) from a raw header
/// block; defaults to 0 when absent.
fn content_length(headers: &[u8]) -> usize {
    let text = String::from_utf8_lossy(headers).to_ascii_lowercase();
    for line in text.split("\r\n") {
        if let Some(rest) = line.strip_prefix("content-length:") {
            return rest.trim().parse().unwrap_or(0);
        }
    }
    0
}

/// Read one HTTP request off `sock`, returning its body bytes.
async fn read_request_body(sock: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 2048];
    let header_end = loop {
        if let Some(pos) = find_sub(&buf, b"\r\n\r\n") {
            break pos + 4;
        }
        let n = sock.read(&mut tmp).await?;
        if n == 0 {
            return Ok(Vec::new());
        }
        buf.extend_from_slice(&tmp[..n]);
    };
    let clen = content_length(&buf[..header_end]);
    let mut body = buf[header_end..].to_vec();
    while body.len() < clen {
        let n = sock.read(&mut tmp).await?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&tmp[..n]);
    }
    Ok(body)
}

/// Build a minimal `Connection: close` HTTP/1.1 response with `body`.
fn http_response(body: &[u8]) -> Vec<u8> {
    let mut r = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    r.extend_from_slice(body);
    r
}

fn meek_stream(url: String) -> MeekStream {
    let client = Client::builder()
        .build()
        .expect("reqwest client for loopback http");
    MeekStream::new(client, url, HeaderMap::new(), Vec::new())
}

// ---------------------------------------------------------------------------
// HIGH-2a: an empty POST response must NOT be read as EOF. The server returns
// an empty body to the first keepalive POST and real bytes to the second; a
// single `read` must skip the empty response (back off + retry) and deliver the
// real bytes, never returning 0 (EOF). Pre-fix, the empty response filled zero
// bytes → the copy loop would half-close.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn meek_empty_response_is_not_eof() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let hits_srv = hits.clone();

    let server = tokio::spawn(async move {
        // Serve at least two requests: first empty, then the payload.
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            let _ = read_request_body(&mut sock).await;
            let n = hits_srv.fetch_add(1, Ordering::SeqCst);
            let body: &[u8] = if n == 0 { b"" } else { b"DATA-AFTER-EMPTY" };
            let _ = sock.write_all(&http_response(body)).await;
            let _ = sock.shutdown().await;
            if n >= 1 {
                break;
            }
        }
    });

    let mut stream = meek_stream(format!("http://{addr}/"));
    let mut got = vec![0u8; b"DATA-AFTER-EMPTY".len()];
    // read_exact must succeed: the empty first response is skipped, not EOF.
    let res = tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut got)).await;
    let n = res
        .expect("read must not hang")
        .expect("read must not surface EOF/error on an empty poll response");
    assert_eq!(n, got.len());
    assert_eq!(&got, b"DATA-AFTER-EMPTY");
    assert!(
        hits.load(Ordering::SeqCst) >= 2,
        "the empty response must trigger a retry (>= 2 POSTs), not an EOF"
    );

    server.abort();
}

// ---------------------------------------------------------------------------
// HIGH-2b: a write issued while a read POST is in flight must actually transmit
// its bytes. We split the stream, spawn the read half (which parks on a slow
// keepalive POST), then write on the write half. The server must record the
// write's POST body. Pre-fix, the shared in-flight slot made poll_write poll
// the read future and report the bytes as sent WITHOUT ever POSTing them.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn meek_write_during_pending_read_is_transmitted() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let write_bodies: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
    let bodies_srv = write_bodies.clone();

    let server = tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            let bodies = bodies_srv.clone();
            tokio::spawn(async move {
                let body = read_request_body(&mut sock).await.unwrap_or_default();
                if body.is_empty() {
                    // Keepalive/read POST: stall so the read stays in flight
                    // while the write happens, then answer empty.
                    tokio::time::sleep(Duration::from_millis(600)).await;
                } else {
                    // Write POST: record the payload and answer immediately.
                    bodies.lock().unwrap().push(body);
                }
                let _ = sock.write_all(&http_response(b"")).await;
                let _ = sock.shutdown().await;
            });
        }
    });

    let stream = meek_stream(format!("http://{addr}/"));
    let (mut rd, mut wr) = tokio::io::split(stream);

    // Drive the read half in the background; it will issue an empty keepalive
    // POST and park on the slow server.
    let reader = tokio::spawn(async move {
        let mut b = [0u8; 64];
        let _ = rd.read(&mut b).await;
    });

    // Give the read POST time to reach the server and park.
    tokio::time::sleep(Duration::from_millis(150)).await;

    let payload = b"OUTBOUND-WRITE-PAYLOAD";
    let res = tokio::time::timeout(Duration::from_secs(5), wr.write_all(payload)).await;
    res.expect("write must not hang behind the pending read")
        .expect("write_all must succeed");

    // The server must have received the write payload as its own POST body.
    tokio::time::sleep(Duration::from_millis(100)).await;
    let seen = write_bodies.lock().unwrap().clone();
    assert!(
        seen.iter().any(|b| b.as_slice() == payload),
        "write payload must be transmitted as its own POST while a read is \
         pending; server saw bodies: {seen:?}"
    );

    reader.abort();
    server.abort();
}
