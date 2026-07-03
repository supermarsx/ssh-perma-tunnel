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

// ---------------------------------------------------------------------------
// P1.2 (meek large integrity): a multi-MiB payload round-trips byte-exact
// through `MeekStream` over the loopback HTTP server. The server echoes each
// POST body back in its response; MeekStream appends the write POST's response
// to its inbound buffer, so the client reads back exactly what it wrote. Writes
// are chunked <= the 4 MiB per-response body cap. A single flipped/lost/dup byte
// anywhere in >4 MiB fails the final compare.
// ---------------------------------------------------------------------------

/// Deterministic filler byte for index `i` (seed-free, reproducible).
fn filler(i: usize) -> u8 {
    ((i.wrapping_mul(2_654_435_761).wrapping_add(97) >> 5) & 0xff) as u8
}

fn make_payload(n: usize) -> Vec<u8> {
    (0..n).map(filler).collect()
}

/// Loopback server that echoes each request body back verbatim in its response.
fn spawn_echo_server(listener: TcpListener) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let body = read_request_body(&mut sock).await.unwrap_or_default();
                let _ = sock.write_all(&http_response(&body)).await;
                let _ = sock.shutdown().await;
            });
        }
    })
}

#[tokio::test]
async fn meek_multi_mib_round_trips_byte_exact() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = spawn_echo_server(listener);

    let mut stream = meek_stream(format!("http://{addr}/"));

    // > 4 MiB total, written in <= 1 MiB chunks so each echoed response body
    // stays within `MAX_MEEK_BODY_BYTES` (4 MiB).
    let total = 4 * 1024 * 1024 + 4096;
    let payload = make_payload(total);
    let chunk = 1024 * 1024;

    let write_fut = async {
        for part in payload.chunks(chunk) {
            stream.write_all(part).await.expect("meek write chunk");
        }
        // Read the whole echo back.
        let mut got = vec![0u8; total];
        stream.read_exact(&mut got).await.expect("meek read echo");
        got
    };
    let got = tokio::time::timeout(Duration::from_secs(60), write_fut)
        .await
        .expect("meek multi-MiB transfer must not hang");
    assert_eq!(got.len(), total);
    assert!(got == payload, "meek multi-MiB echo must be byte-exact");

    server.abort();
}

// ---------------------------------------------------------------------------
// P1.2 (meek slow/chunked response reassembly): a response body streamed to the
// client in many small TCP writes (with delays) must reassemble byte-exact —
// `read_body_capped` streams via `resp.chunk()`, so a reassembly bug would drop
// or reorder pieces. Uses a single read POST whose response is delivered slowly.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn meek_slow_chunked_response_reassembles_byte_exact() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let payload = make_payload(256 * 1024);
    let payload_srv = payload.clone();

    let server = tokio::spawn(async move {
        let Ok((mut sock, _)) = listener.accept().await else {
            return;
        };
        // Consume the client's (empty) keepalive/read POST.
        let _ = read_request_body(&mut sock).await;
        // Send the header, then the body in small pieces with tiny delays so
        // reqwest surfaces it across multiple `chunk()` calls.
        let header = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            payload_srv.len()
        );
        if sock.write_all(header.as_bytes()).await.is_err() {
            return;
        }
        for piece in payload_srv.chunks(4096) {
            if sock.write_all(piece).await.is_err() {
                return;
            }
            let _ = sock.flush().await;
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        let _ = sock.shutdown().await;
    });

    let mut stream = meek_stream(format!("http://{addr}/"));
    let mut got = vec![0u8; payload.len()];
    tokio::time::timeout(Duration::from_secs(30), stream.read_exact(&mut got))
        .await
        .expect("slow response read must not hang")
        .expect("read_exact the slowly-streamed body");
    assert!(
        got == payload,
        "slowly-chunked meek response must reassemble byte-exact"
    );

    server.abort();
}
