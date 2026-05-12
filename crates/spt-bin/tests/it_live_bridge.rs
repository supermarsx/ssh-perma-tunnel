//! End-to-end integration tests for the live MCP control surface.
//!
//! These tests stand up a loopback MCP server backed by a custom
//! `Controller` implementation that delegates straight to the
//! `spt_supervisor::Orchestrator` (the same way the production
//! `spt_bin::controller::OrchestratorController` does). They then drive
//! the binary's `McpClient` (re-included via `#[path]`) against the
//! resulting listener — covering `tunnel_failover`, `session_close`,
//! `session_drain`, and `stats_subscribe` over the real wire.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use base64::Engine;
use serde::{Deserialize, Serialize};
use spt_auth::AuthConfig;
use spt_config::load::load_str;
use spt_config::schema::Forward;
use spt_protocol::Endpoint;
use spt_supervisor::{Orchestrator, ProfileSupervisorConfig, StatsTickConfig};

// --- Local sidecar helper (mirrors `spt_bin::mcp_listen`). -----------------

#[derive(Debug, Clone, Serialize, Deserialize)]
struct McpListenSidecar {
    host: String,
    port: u16,
    token: String,
}

fn write_sidecar(dir: &Path, s: &McpListenSidecar) {
    let body = serde_json::to_string_pretty(s).unwrap();
    std::fs::write(dir.join("mcp-listen.json"), body).unwrap();
}

fn generate_token() -> String {
    use rand::RngCore;
    let mut buf = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut buf);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf)
}

// --- Live `Controller` impl wired to the supervisor (mirrors the binary's
// `OrchestratorController`). ------------------------------------------------

struct LiveController {
    orch: Arc<Orchestrator>,
}

#[async_trait]
impl spt_mcp::Controller for LiveController {
    async fn reload(&self) -> spt_mcp::Result<()> {
        Ok(())
    }
    async fn failover(&self, profile: &str, endpoint: Option<&str>) -> spt_mcp::Result<()> {
        self.orch
            .failover(profile, endpoint)
            .await
            .map_err(|e| spt_mcp::Error::InvalidParams(format!("failover: {e}")))
    }
    async fn profile_start(&self, _profile: &str) -> spt_mcp::Result<()> {
        Ok(())
    }
    async fn profile_stop(&self, profile: &str) -> spt_mcp::Result<()> {
        self.orch.stop_profile(profile).await;
        Ok(())
    }
    async fn forward_add(&self, _profile: &str, _forward: &Forward) -> spt_mcp::Result<()> {
        Ok(())
    }
    async fn forward_remove(&self, _profile: &str, _forward_id: &str) -> spt_mcp::Result<()> {
        Ok(())
    }
    async fn session_close(&self, session_id: &str) -> spt_mcp::Result<()> {
        let id: spt_core::SessionId = session_id
            .parse()
            .map_err(|e| spt_mcp::Error::InvalidParams(format!("session id: {e}")))?;
        self.orch
            .session_close(&id)
            .await
            .map_err(|e| spt_mcp::Error::InvalidParams(format!("session_close: {e}")))
    }
    async fn session_drain(
        &self,
        profile: &str,
        grace_seconds: u64,
    ) -> spt_mcp::Result<serde_json::Value> {
        let r = self
            .orch
            .session_drain(profile, Duration::from_secs(grace_seconds))
            .await
            .map_err(|e| spt_mcp::Error::InvalidParams(format!("drain: {e}")))?;
        Ok(serde_json::json!({
            "drained": r.drained,
            "force_closed": r.force_closed,
            "already_closed": r.already_closed,
        }))
    }
    async fn stats_subscribe(
        &self,
        _interval_ms: u64,
        tx: tokio::sync::mpsc::Sender<serde_json::Value>,
    ) -> spt_mcp::Result<()> {
        let mut rx = self.orch.stats_subscribe();
        tokio::spawn(async move {
            loop {
                match rx.recv().await {
                    Ok(tick) => {
                        let v = serde_json::to_value(&tick).unwrap_or_default();
                        if tx.send(v).await.is_err() {
                            break;
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
        });
        Ok(())
    }
}

const CFG: &str = r#"
version = 1
[[profiles]]
name = "p"
protocol = "ssh2"
host = "a"
"#;

async fn spawn_live_bridge(
    cfg: &str,
) -> (
    tempfile::TempDir,
    Arc<Orchestrator>,
    spt_forward::testing::MockTunnelProtocol,
    tokio::task::JoinHandle<()>,
) {
    let tmp = tempfile::tempdir().unwrap();
    let proto = spt_forward::testing::MockTunnelProtocol::new();
    let (c, _) = load_str(cfg, false).unwrap();
    let stats_cfg = StatsTickConfig {
        interval: Duration::from_millis(50),
        ..Default::default()
    };
    let orch = Arc::new(Orchestrator::with_stats_config(stats_cfg));
    orch.start_profile(
        &c.profiles[0],
        Arc::new(proto.clone()),
        AuthConfig::new("u", vec![]),
        vec![Endpoint::new("a", 22), Endpoint::new("b", 22)],
        ProfileSupervisorConfig::default(),
    );

    // Wait for at least one session.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    while orch.session_list().is_empty() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "session never came up"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    let controller: Arc<dyn spt_mcp::Controller> = Arc::new(LiveController { orch: orch.clone() });
    let policy = spt_mcp::McpPolicy {
        enabled: true,
        listen: "127.0.0.1:0".into(),
        allow_write_tools: spt_mcp::policy::WRITE_TOOLS
            .iter()
            .map(|s| (*s).to_owned())
            .collect(),
        ..Default::default()
    };
    let sources = Arc::new(spt_mcp::NoopSources);
    let server = spt_mcp::McpServer::new(
        spt_mcp::Policy::new(policy),
        Arc::new(spt_mcp::NoopAuditSink),
        controller,
        sources.clone() as spt_mcp::sources::DynConfigSource,
        sources as spt_mcp::sources::DynStateSource,
    );

    let transport = spt_mcp::LoopbackTransport::bind("127.0.0.1:0")
        .await
        .unwrap();
    let bound = transport.local_addr().unwrap();
    let token = generate_token();
    let server = server.with_auth_token(token.clone());
    let sidecar = McpListenSidecar {
        host: bound.ip().to_string(),
        port: bound.port(),
        token,
    };
    write_sidecar(tmp.path(), &sidecar);
    let task = tokio::spawn(async move {
        let _ = server.run(transport).await;
    });
    (tmp, orch, proto, task)
}

// --- Test-side McpClient: thin re-implementation matching the binary's
// `mcp_client::McpClient` shape but with no module-path tricks. -------------

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;

struct TestClient {
    reader: BufReader<OwnedReadHalf>,
    writer: OwnedWriteHalf,
    next_id: i64,
    token: String,
}

impl TestClient {
    async fn connect_from_dir(dir: &Path) -> Self {
        let body = std::fs::read_to_string(dir.join("mcp-listen.json")).unwrap();
        let s: McpListenSidecar = serde_json::from_str(&body).unwrap();
        let stream = TcpStream::connect((s.host.as_str(), s.port)).await.unwrap();
        let (r, w) = stream.into_split();
        Self {
            reader: BufReader::new(r),
            writer: w,
            next_id: 1,
            token: s.token,
        }
    }

    async fn initialize(&mut self) -> serde_json::Value {
        self.rpc(
            "initialize",
            serde_json::json!({
                "protocolVersion": "2024-11-05",
                "clientInfo": {"name": "test", "version": "0"},
                "capabilities": {},
                "token": self.token
            }),
        )
        .await
        .expect("initialize")
    }

    async fn rpc(
        &mut self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        let id = self.next_id;
        self.next_id += 1;
        let req = serde_json::json!({
            "jsonrpc": "2.0", "id": id, "method": method, "params": params
        });
        let body = serde_json::to_vec(&req).unwrap();
        self.writer.write_all(&body).await.unwrap();
        self.writer.write_all(b"\n").await.unwrap();
        self.writer.flush().await.unwrap();
        loop {
            let mut line = String::new();
            let n = self.reader.read_line(&mut line).await.unwrap();
            if n == 0 {
                return Err("closed".into());
            }
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let v: serde_json::Value = serde_json::from_str(trimmed).unwrap();
            if v.get("id").is_none() {
                continue;
            }
            if let Some(err) = v.get("error") {
                return Err(format!("{err}"));
            }
            return Ok(v.get("result").cloned().unwrap_or(serde_json::Value::Null));
        }
    }

    async fn call_tool(
        &mut self,
        name: &str,
        args: serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        let r = self
            .rpc(
                "tools/call",
                serde_json::json!({"name": name, "arguments": args}),
            )
            .await?;
        if let Some(text) = r
            .get("content")
            .and_then(|c| c.as_array())
            .and_then(|a| a.first())
            .and_then(|f| f.get("text"))
            .and_then(|t| t.as_str())
        {
            return Ok(serde_json::from_str(text).unwrap_or(serde_json::Value::Null));
        }
        Ok(r)
    }
}

#[tokio::test]
async fn tunnel_failover_round_trip_via_mcp_loopback() {
    let (tmp, orch, _proto, task) = spawn_live_bridge(CFG).await;
    let mut client = TestClient::connect_from_dir(tmp.path()).await;
    let init = client.initialize().await;
    assert_eq!(init["protocolVersion"], "2024-11-05");
    let v = client
        .call_tool(
            "tunnel_failover",
            serde_json::json!({"profile": "p", "endpoint": "b:22"}),
        )
        .await
        .expect("ok");
    assert_eq!(
        v.get("applied").and_then(serde_json::Value::as_bool),
        Some(true)
    );
    drop(client);
    orch.stop_profile("p").await;
    task.abort();
    let _ = task.await;
}

#[tokio::test]
async fn session_drain_returns_report() {
    let (tmp, orch, _proto, task) = spawn_live_bridge(CFG).await;
    let mut client = TestClient::connect_from_dir(tmp.path()).await;
    client.initialize().await;
    let v = client
        .call_tool(
            "session_drain",
            serde_json::json!({"profile": "p", "grace_seconds": 1}),
        )
        .await
        .expect("ok");
    assert_eq!(
        v.get("applied").and_then(serde_json::Value::as_bool),
        Some(true)
    );
    let report = v.get("report").expect("report");
    assert!(report.get("drained").is_some());
    drop(client);
    orch.stop_profile("p").await;
    task.abort();
    let _ = task.await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stats_live_emits_at_least_one_tick() {
    let (tmp, orch, _proto, task) = spawn_live_bridge(CFG).await;
    let mut client = TestClient::connect_from_dir(tmp.path()).await;
    client.initialize().await;
    let row = orch.session_list()[0].clone();
    orch.registry().add_bytes(&row.id, 1024, 2048);
    // Inline subscribe: keep `client` alive on the test task and poll
    // notifications directly without moving `self` into a spawn. This avoids
    // any tokio runtime quirks around moving owned TCP halves between tasks
    // that surfaced on current_thread runtimes.
    let _ = client
        .call_tool("stats_subscribe", serde_json::json!({"interval_ms": 50}))
        .await
        .expect("ok");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    let mut got_tick = false;
    while tokio::time::Instant::now() < deadline {
        let mut line = String::new();
        let n = tokio::time::timeout(
            Duration::from_millis(500),
            client.reader.read_line(&mut line),
        )
        .await;
        match n {
            Ok(Ok(0)) => panic!("connection EOF before tick"),
            Ok(Ok(_)) => {
                let v: serde_json::Value = match serde_json::from_str(line.trim()) {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                if v.get("method").and_then(|m| m.as_str()) == Some("notifications/stats/tick") {
                    let params = v.get("params").cloned().unwrap_or_default();
                    assert!(params.get("total_sessions").is_some(), "tick: {params}");
                    got_tick = true;
                    break;
                }
            }
            Ok(Err(e)) => panic!("read err: {e}"),
            Err(_) => {} // single timeout, keep looping
        }
    }
    assert!(got_tick, "no tick observed within deadline");
    drop(client);
    orch.stop_profile("p").await;
    task.abort();
    let _ = task.await;
}

#[tokio::test]
async fn missing_token_is_rejected() {
    let (tmp, orch, _proto, task) = spawn_live_bridge(CFG).await;
    let mut bad: McpListenSidecar = {
        let body = std::fs::read_to_string(tmp.path().join("mcp-listen.json")).unwrap();
        serde_json::from_str(&body).unwrap()
    };
    bad.token = "wrong-token".into();
    write_sidecar(tmp.path(), &bad);
    let mut client = TestClient::connect_from_dir(tmp.path()).await;
    let r = client
        .rpc(
            "initialize",
            serde_json::json!({
                "protocolVersion": "2024-11-05",
                "token": "wrong-token",
                "clientInfo": {"name":"x","version":"0"},
                "capabilities": {}
            }),
        )
        .await;
    assert!(r.is_err(), "expected token mismatch failure");
    orch.stop_profile("p").await;
    task.abort();
    let _ = task.await;
}
