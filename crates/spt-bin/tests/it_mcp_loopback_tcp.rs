//! Loopback TCP transport for the MCP server: bind a real listener, drive
//! `initialize` over a TCP client, assert the server-info matches stdio.
//!
//! This is the binary-level smoke test the f-cli-fill task replaces the
//! prior "loopback is M8" stub with. The transport implementation lives
//! in `spt-mcp::transport::loopback`; this test only proves the wiring is
//! reachable from the binary's MCP server builder.

use std::sync::Arc;
use std::time::Duration;

use spt_mcp::{LoopbackTransport, McpPolicy, McpServer, NoopController, NoopSources, Policy};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

#[tokio::test]
async fn loopback_initialize_round_trip() {
    let policy = McpPolicy {
        enabled: true,
        ..Default::default()
    };
    let sources = Arc::new(NoopSources);
    let server = McpServer::new(
        Policy::new(policy),
        Arc::new(spt_mcp::NoopAuditSink),
        Arc::new(NoopController),
        sources.clone() as spt_mcp::sources::DynConfigSource,
        sources as spt_mcp::sources::DynStateSource,
    );

    let transport = LoopbackTransport::bind("127.0.0.1:0").await.unwrap();
    let addr = transport.local_addr().unwrap();
    let server_task = tokio::spawn(async move {
        // The serve() loop runs forever; we abort it once the test's
        // tokio::spawn drops with the test runtime.
        let _ = server.run(transport).await;
    });

    // Give the listener a moment to be accept-ready.
    tokio::time::sleep(Duration::from_millis(50)).await;
    let stream = TcpStream::connect(addr).await.unwrap();
    let (read, mut write) = stream.into_split();
    let mut reader = BufReader::new(read);

    let req = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#;
    write.write_all(req.as_bytes()).await.unwrap();
    write.write_all(b"\n").await.unwrap();
    write.flush().await.unwrap();

    let mut line = String::new();
    let read_n = tokio::time::timeout(Duration::from_secs(2), reader.read_line(&mut line))
        .await
        .expect("response within 2s");
    assert!(read_n.is_ok());
    assert!(line.contains("\"jsonrpc\":\"2.0\""));
    assert!(line.contains("\"id\":1"));
    assert!(line.contains("spt-mcp"));

    server_task.abort();
}

#[tokio::test]
async fn loopback_refuses_non_loopback_bind() {
    let err = LoopbackTransport::bind("0.0.0.0:0").await.err();
    assert!(err.is_some(), "non-loopback bind must be rejected");
}
