//! Helpers for the Shadowsocks-2022 interop test crate.
//!
//! All entry points return either an `Ok(skipped)` indicator or carry
//! the spawned subprocess in an RAII guard. The test bodies in
//! `tests/ss_2022_interop.rs` use these helpers to keep the per-test
//! noise low.
//!
//! See `README.md` for the install steps required on CI Phase C runners.

#![deny(unsafe_op_in_unsafe_fn)]
#![allow(clippy::missing_errors_doc, clippy::missing_panics_doc)]

use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use anyhow::{bail, Result};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::process::{Child, Command};
use tokio::time::sleep;

/// Returns true iff `SPT_SS_INTEROP=1` is in the environment AND
/// `ssserver` is on `$PATH`. Tests should early-return when this is
/// false rather than failing.
pub fn gated() -> bool {
    if std::env::var("SPT_SS_INTEROP").ok().as_deref() != Some("1") {
        return false;
    }
    which::which("ssserver").is_ok()
}

/// Locate the `ssserver` binary, returning a clear error when missing.
pub fn ssserver_path() -> Result<PathBuf> {
    which::which("ssserver").map_err(|e| anyhow::anyhow!("ssserver not on PATH: {e}"))
}

/// RAII guard for a spawned `ssserver` subprocess. The child is killed
/// on drop so a panicking test does not leak the process.
pub struct SsServer {
    child: Option<Child>,
    /// Bound listen address (e.g. `127.0.0.1:8388`).
    pub addr: String,
}

impl SsServer {
    /// Spawn an `ssserver` subprocess on a fixed loopback port,
    /// configured with the supplied method + password. Blocks until
    /// the port answers (max ~3s).
    pub async fn spawn(method: &str, password: &str, port: u16) -> Result<Self> {
        let bin = ssserver_path()?;
        let addr = format!("127.0.0.1:{port}");
        let child = Command::new(bin)
            .arg("-s")
            .arg(&addr)
            .arg("-k")
            .arg(password)
            .arg("-m")
            .arg(method)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let mut me = Self {
            child: Some(child),
            addr: addr.clone(),
        };
        // Poll-connect: wait up to 3s for the listener.
        for _ in 0..30 {
            if TcpStream::connect(&addr).await.is_ok() {
                return Ok(me);
            }
            sleep(Duration::from_millis(100)).await;
        }
        // Timed out — kill and surface.
        if let Some(mut c) = me.child.take() {
            let _ = c.kill().await;
        }
        bail!("ssserver did not start within 3s")
    }

    /// Send `data` and read whatever bytes come back within `timeout`.
    pub async fn ping(&self, data: &[u8], timeout: Duration) -> Result<Vec<u8>> {
        let mut tcp = TcpStream::connect(&self.addr).await?;
        tcp.write_all(data).await?;
        let mut buf = vec![0u8; 4096];
        let n = tokio::time::timeout(timeout, async {
            use tokio::io::AsyncReadExt;
            tcp.read(&mut buf).await
        })
        .await
        .map_err(|_| anyhow::anyhow!("read timed out"))??;
        buf.truncate(n);
        Ok(buf)
    }
}

impl Drop for SsServer {
    fn drop(&mut self) {
        if let Some(mut c) = self.child.take() {
            // Synchronously fire-and-forget; the child will be reaped
            // by the runtime if it has time to land.
            let _ = c.start_kill();
        }
    }
}
