//! End-to-end test: spawn the loopback TCP transport, connect a client,
//! drive `initialize` → `resources/list` → `tools/list`, assert parity with
//! the in-process stdio test.

use serde_json::Value;
use spt_mcp::{LoopbackTransport, McpPolicy, McpServer};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

async fn rpc(stream: &mut tokio::net::TcpStream, frame: &Value) -> Value {
    let mut bytes = serde_json::to_vec(frame).unwrap();
    bytes.push(b'\n');
    stream.write_all(&bytes).await.unwrap();
    stream.flush().await.unwrap();

    // Read until we get one full line back.
    let (read_half, _write_half) = stream.split();
    let mut reader = BufReader::new(read_half);
    let mut line = String::new();
    tokio::time::timeout(Duration::from_secs(5), reader.read_line(&mut line))
        .await
        .expect("rpc timed out")
        .expect("read failed");
    serde_json::from_str(line.trim()).expect("invalid response json")
}

#[tokio::test]
async fn loopback_round_trip_initialize_and_list() {
    let transport = LoopbackTransport::bind("127.0.0.1:0")
        .await
        .expect("bind loopback");
    let addr = transport.local_addr().expect("local_addr");
    assert!(addr.ip().is_loopback());

    let server = McpServer::new_noop(McpPolicy {
        enabled: true,
        ..Default::default()
    });
    let handle = tokio::spawn(async move {
        // Server runs until the process exits or every client disconnects.
        // We abort it from the test once the asserts complete.
        let _ = server.run(transport).await;
    });

    // Give the listener a moment.
    tokio::time::sleep(Duration::from_millis(50)).await;

    // -- initialize --
    let mut stream = TcpStream::connect(addr).await.expect("connect");
    let init = rpc(
        &mut stream,
        &serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize"
        }),
    )
    .await;
    assert_eq!(init["id"], 1);
    assert_eq!(init["result"]["protocolVersion"], "2024-11-05");
    assert_eq!(init["result"]["serverInfo"]["name"], "spt-mcp");

    // -- resources/list --
    let res = rpc(
        &mut stream,
        &serde_json::json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "resources/list"
        }),
    )
    .await;
    assert_eq!(
        res["result"]["resources"].as_array().unwrap().len(),
        16,
        "spec §16 lists 16 resources"
    );

    // -- tools/list --
    let res = rpc(
        &mut stream,
        &serde_json::json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/list"
        }),
    )
    .await;
    assert_eq!(
        res["result"]["tools"].as_array().unwrap().len(),
        31,
        "spec §16 lists 31 tools"
    );

    drop(stream);
    handle.abort();
}

#[tokio::test]
async fn loopback_supports_multiple_concurrent_clients() {
    let transport = LoopbackTransport::bind("127.0.0.1:0")
        .await
        .expect("bind loopback");
    let addr = transport.local_addr().expect("local_addr");

    let server = McpServer::new_noop(McpPolicy {
        enabled: true,
        ..Default::default()
    });
    let handle = tokio::spawn(async move {
        let _ = server.run(transport).await;
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    let mut a = TcpStream::connect(addr).await.expect("connect a");
    let mut b = TcpStream::connect(addr).await.expect("connect b");

    let ra = rpc(
        &mut a,
        &serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": "ping"}),
    )
    .await;
    let rb = rpc(
        &mut b,
        &serde_json::json!({"jsonrpc": "2.0", "id": 2, "method": "ping"}),
    )
    .await;

    assert_eq!(ra["result"]["pong"], true);
    assert_eq!(rb["result"]["pong"], true);
    assert_eq!(ra["id"], 1);
    assert_eq!(rb["id"], 2);

    handle.abort();
}

#[tokio::test]
async fn loopback_refuses_non_loopback_bind() {
    let res = LoopbackTransport::bind("0.0.0.0:0").await;
    assert!(matches!(res, Err(spt_mcp::Error::PolicyDenied(_))));
}
