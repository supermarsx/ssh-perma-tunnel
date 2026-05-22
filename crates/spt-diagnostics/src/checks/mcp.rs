//! MCP server stdio handshake check.
//!
//! When `[mcp].enabled = true` and a binary path is supplied, spawns
//! `<binary> mcp serve --stdio`, sends `initialize`, `resources/list`, and
//! `tools/list`, asserts the server reports the expected counts (16
//! resources + 31 tools per spec §13.4). The subprocess is terminated as
//! soon as the three responses are received.

use async_trait::async_trait;
use serde_json::{json, Value};
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;
use tokio::time::timeout;

use crate::check::{Check, Severity, Status};
use crate::framework::{Diagnostic, DiagnosticContext};

/// Expected resource count from spec §13.4.
const EXPECTED_RESOURCES: usize = 16;
/// Expected tool count from spec §13.4.
const EXPECTED_TOOLS: usize = 31;

/// MCP diagnostic.
#[derive(Debug)]
pub struct McpDiagnostic {
    /// Per-request response timeout.
    pub timeout: Duration,
}

impl Default for McpDiagnostic {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(5),
        }
    }
}

#[async_trait]
impl Diagnostic for McpDiagnostic {
    fn group(&self) -> &'static str {
        "mcp"
    }
    async fn run(&self, ctx: &DiagnosticContext) -> Vec<Check> {
        if !ctx.mcp_enabled {
            return vec![Check::new("mcp.enabled", Severity::Info, Status::Skipped)
                .with_evidence("[mcp].enabled = false")];
        }
        let Some(bin) = ctx.mcp_binary.as_ref() else {
            return vec![Check::new("mcp.binary", Severity::Medium, Status::Skipped)
                .with_evidence("no MCP binary path supplied via DiagnosticContext")];
        };

        match handshake(bin, self.timeout).await {
            Ok((resources, tools)) => {
                let mut out = Vec::new();
                out.push(
                    Check::new("mcp.handshake", Severity::Info, Status::Pass).with_evidence(
                        format!("stdio handshake against `{}` succeeded", bin.display()),
                    ),
                );
                out.push(check_count(
                    "mcp.resources_count",
                    resources,
                    EXPECTED_RESOURCES,
                ));
                out.push(check_count("mcp.tools_count", tools, EXPECTED_TOOLS));
                out
            }
            Err(e) => vec![Check::new("mcp.handshake", Severity::Medium, Status::Fail)
                .with_evidence(format!("handshake failed: {e}"))
                .with_remediation(
                    "verify the spt binary path and that the MCP server starts cleanly",
                )],
        }
    }
}

fn check_count(id: &str, got: usize, want: usize) -> Check {
    if got == want {
        Check::new(id, Severity::Info, Status::Pass).with_evidence(format!("count = {got}"))
    } else {
        Check::new(id, Severity::Medium, Status::Warn)
            .with_evidence(format!("expected {want}, got {got}"))
            .with_remediation(
                "update spec §13.4 expectation or investigate missing handler registration",
            )
    }
}

/// Spawn `<bin> mcp serve --stdio`, perform the three requests, return
/// `(resource_count, tool_count)`.
async fn handshake(bin: &Path, per_req: Duration) -> Result<(usize, usize), String> {
    let mut child = Command::new(bin)
        .args(["mcp", "serve", "--stdio"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| format!("spawn `{}`: {e}", bin.display()))?;

    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| "child stdin missing".to_string())?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| "child stdout missing".to_string())?;
    let mut reader = BufReader::new(stdout).lines();

    // initialize
    send(&mut stdin, 1, "initialize", json!({})).await?;
    let _init = read_response(&mut reader, per_req).await?;

    // resources/list
    send(&mut stdin, 2, "resources/list", json!({})).await?;
    let resources_resp = read_response(&mut reader, per_req).await?;
    let resources = count_array(&resources_resp, "resources");

    // tools/list
    send(&mut stdin, 3, "tools/list", json!({})).await?;
    let tools_resp = read_response(&mut reader, per_req).await?;
    let tools = count_array(&tools_resp, "tools");

    // Drop stdin → child sees EOF and exits.
    drop(stdin);
    let _ = child.kill().await;

    Ok((resources, tools))
}

async fn send<W: AsyncWriteExt + Unpin>(
    w: &mut W,
    id: u64,
    method: &str,
    params: Value,
) -> Result<(), String> {
    let req = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
    let mut bytes = serde_json::to_vec(&req).map_err(|e| e.to_string())?;
    bytes.push(b'\n');
    w.write_all(&bytes).await.map_err(|e| e.to_string())?;
    w.flush().await.map_err(|e| e.to_string())
}

async fn read_response<R: AsyncBufReadExt + Unpin>(
    lines: &mut tokio::io::Lines<R>,
    budget: Duration,
) -> Result<Value, String> {
    let line = timeout(budget, lines.next_line())
        .await
        .map_err(|_| "response timeout".to_string())?
        .map_err(|e| format!("read error: {e}"))?
        .ok_or_else(|| "EOF before response".to_string())?;
    serde_json::from_str(&line).map_err(|e| format!("malformed JSON: {e}"))
}

fn count_array(resp: &Value, key: &str) -> usize {
    resp.get("result")
        .and_then(|r| r.get(key))
        .and_then(Value::as_array)
        .map_or(0, Vec::len)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn skipped_when_disabled() {
        let r = McpDiagnostic::default()
            .run(&DiagnosticContext::default())
            .await;
        assert_eq!(r[0].status, Status::Skipped);
        assert_eq!(r[0].id, "mcp.enabled");
    }

    #[tokio::test]
    async fn skipped_when_no_binary() {
        let ctx = DiagnosticContext {
            mcp_enabled: true,
            ..Default::default()
        };
        let r = McpDiagnostic::default().run(&ctx).await;
        assert_eq!(r[0].status, Status::Skipped);
        assert_eq!(r[0].id, "mcp.binary");
    }

    #[tokio::test]
    async fn fails_when_binary_missing() {
        let ctx = DiagnosticContext {
            mcp_enabled: true,
            mcp_binary: Some(std::path::PathBuf::from(
                "this-binary-definitely-does-not-exist-x9z2",
            )),
            ..Default::default()
        };
        let r = McpDiagnostic {
            timeout: Duration::from_millis(500),
        }
        .run(&ctx)
        .await;
        assert_eq!(r[0].status, Status::Fail);
    }

    #[test]
    fn count_helper_passes_on_match() {
        let c = check_count("mcp.x", 5, 5);
        assert_eq!(c.status, Status::Pass);
    }

    #[test]
    fn count_helper_warns_on_mismatch() {
        let c = check_count("mcp.x", 4, 5);
        assert_eq!(c.status, Status::Warn);
    }

    #[test]
    fn count_array_on_well_formed_response() {
        let v = json!({"result": {"resources": [{"a":1},{"b":2},{"c":3}]}});
        assert_eq!(count_array(&v, "resources"), 3);
    }

    #[test]
    fn count_array_returns_zero_when_result_missing() {
        let v = json!({"other": "thing"});
        assert_eq!(count_array(&v, "resources"), 0);
    }

    #[test]
    fn count_array_returns_zero_when_key_missing() {
        let v = json!({"result": {"tools": []}});
        assert_eq!(count_array(&v, "resources"), 0);
    }

    #[test]
    fn count_array_returns_zero_when_value_not_array() {
        let v = json!({"result": {"resources": "not-array"}});
        assert_eq!(count_array(&v, "resources"), 0);
    }

    #[test]
    fn count_helper_for_zero_match() {
        let c = check_count("mcp.zero", 0, 0);
        assert_eq!(c.status, Status::Pass);
        assert!(!c.evidence.is_empty());
    }

    #[test]
    fn count_helper_carries_remediation_on_mismatch() {
        let c = check_count("mcp.mismatch", 12, 16);
        assert_eq!(c.status, Status::Warn);
        let joined = c.evidence.join("\n");
        assert!(joined.contains("expected 16"), "evidence: {joined}");
        assert!(c.remediation.is_some());
    }

    #[test]
    fn mcp_diagnostic_default_has_five_second_timeout() {
        let d = McpDiagnostic::default();
        assert_eq!(d.timeout, Duration::from_secs(5));
    }

    #[test]
    fn group_returns_mcp() {
        assert_eq!(McpDiagnostic::default().group(), "mcp");
    }

    #[tokio::test]
    async fn no_binary_check_evidence_explains_skip() {
        let ctx = DiagnosticContext {
            mcp_enabled: true,
            ..Default::default()
        };
        let r = McpDiagnostic::default().run(&ctx).await;
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].id, "mcp.binary");
        assert_eq!(r[0].severity, Severity::Medium);
        let evidence = r[0].evidence.join("\n");
        assert!(evidence.contains("no MCP binary"), "got: {evidence}");
    }

    #[tokio::test]
    async fn disabled_check_evidence_mentions_config() {
        let r = McpDiagnostic::default()
            .run(&DiagnosticContext::default())
            .await;
        let evidence = r[0].evidence.join("\n");
        assert!(
            evidence.contains("[mcp].enabled = false"),
            "got: {evidence}"
        );
    }

    #[tokio::test]
    async fn missing_binary_produces_remediation_hint() {
        let ctx = DiagnosticContext {
            mcp_enabled: true,
            mcp_binary: Some(std::path::PathBuf::from("definitely-not-on-path-zz")),
            ..Default::default()
        };
        let r = McpDiagnostic {
            timeout: Duration::from_millis(300),
        }
        .run(&ctx)
        .await;
        assert_eq!(r[0].status, Status::Fail);
        assert!(r[0].remediation.is_some());
        let ev = r[0].evidence.join("\n");
        assert!(ev.contains("handshake failed"), "evidence: {ev}");
    }
}
