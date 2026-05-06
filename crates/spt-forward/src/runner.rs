//! Supervisor-facing wrapper around a single config [`spt_config::Forward`].
//!
//! `ForwardRunner::start` translates the config-level forward description into
//! the protocol-level [`LocalForwardSpec`]/[`RemoteForwardSpec`]/[`UdpForwardSpec`],
//! then asks the [`TunnelSession`] to open the forward. The returned
//! [`ForwardHandle`] is owned by the runner so the supervisor can observe
//! state and request shutdown.

use std::time::Duration;

use spt_config::schema::Forward;
use spt_core::{BindAddr, Error, Result};
use spt_protocol::{
    ForwardDirection, ForwardHandle, ForwardState, LocalForwardSpec, RemoteForwardSpec,
    TargetAddr, TunnelSession, UdpForwardSpec,
};
use thiserror::Error;
use tokio::sync::watch;

/// Errors specific to runner construction. Spec-level errors are surfaced via
/// [`spt_core::Error`].
#[derive(Debug, Error)]
pub enum ForwardRunnerError {
    /// The config forward refers to a transport (e.g. UDP) the backend does
    /// not support.
    #[error("forward `{name}`: backend lacks capability `{cap}`")]
    UnsupportedCapability {
        /// Forward name.
        name: String,
        /// Missing capability.
        cap: &'static str,
    },
    /// The config forward is malformed (missing required field).
    #[error("forward `{name}`: malformed config: {reason}")]
    Malformed {
        /// Forward name.
        name: String,
        /// What was wrong.
        reason: String,
    },
}

impl From<ForwardRunnerError> for Error {
    fn from(e: ForwardRunnerError) -> Self {
        Error::InvalidConfig(e.to_string())
    }
}

/// Runner-tunable parameters. All defaults are spec §9.14-aligned.
#[derive(Debug, Clone, Default)]
pub struct ForwardRunnerConfig {
    /// Default UDP idle timeout (used when the config forward omits one).
    pub default_udp_idle: Option<Duration>,
}

/// One forward, driven through its [`ForwardHandle`].
#[derive(Debug)]
pub struct ForwardRunner {
    name: String,
    handle: ForwardHandle,
}

impl ForwardRunner {
    /// Open the forward described by `cfg` against `session`.
    pub async fn start(
        cfg: &Forward,
        session: &mut dyn TunnelSession,
        runner_cfg: &ForwardRunnerConfig,
    ) -> Result<Self> {
        let name = cfg.name.clone();
        let listen_str = cfg
            .bind
            .as_deref()
            .or(cfg.listen.as_deref())
            .ok_or_else(|| {
                ForwardRunnerError::Malformed {
                    name: name.clone(),
                    reason: "missing `bind`/`listen`".into(),
                }
            })?;
        let target_str = cfg
            .target
            .as_deref()
            .or(cfg.connect.as_deref())
            .ok_or_else(|| {
                ForwardRunnerError::Malformed {
                    name: name.clone(),
                    reason: "missing `target`/`connect`".into(),
                }
            })?;

        let listen = BindAddr::parse(listen_str)
            .map_err(|e| ForwardRunnerError::Malformed {
                name: name.clone(),
                reason: format!("invalid listen `{listen_str}`: {e}"),
            })?;
        let target = parse_target(target_str).map_err(|e| ForwardRunnerError::Malformed {
            name: name.clone(),
            reason: format!("invalid target `{target_str}`: {e}"),
        })?;

        let direction = parse_direction(&cfg.kind).map_err(|e| ForwardRunnerError::Malformed {
            name: name.clone(),
            reason: e.to_string(),
        })?;

        let handle = match (direction, cfg.transport.as_str()) {
            (ForwardDirection::Local, "tcp") => {
                let spec = LocalForwardSpec {
                    name: name.clone(),
                    listen,
                    target,
                    max_connections: cfg.max_connections,
                };
                session.open_local_forward(&spec).await?
            }
            (ForwardDirection::Remote, "tcp") => {
                let spec = RemoteForwardSpec {
                    name: name.clone(),
                    listen,
                    target,
                    max_connections: cfg.max_connections,
                };
                session.open_remote_forward(&spec).await?
            }
            (dir, "udp") => {
                let idle_secs = cfg
                    .udp_idle_timeout
                    .as_deref()
                    .map(|s| {
                        humantime::parse_duration(s)
                            .map_err(|e| ForwardRunnerError::Malformed {
                                name: name.clone(),
                                reason: format!("udp_idle_timeout `{s}`: {e}"),
                            })
                            .map(|d| d.as_secs() as u32)
                    })
                    .transpose()?
                    .or_else(|| runner_cfg.default_udp_idle.map(|d| d.as_secs() as u32))
                    .unwrap_or(60);
                let spec = UdpForwardSpec {
                    name: name.clone(),
                    direction: dir,
                    listen,
                    target,
                    idle_timeout_secs: idle_secs,
                    max_flows: cfg.max_connections,
                };
                session.open_udp_forward(&spec).await?
            }
            (_, other) => {
                return Err(ForwardRunnerError::Malformed {
                    name: name.clone(),
                    reason: format!("unknown transport `{other}`"),
                }
                .into());
            }
        };

        Ok(Self { name, handle })
    }

    /// Forward name (config id).
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Current forward state.
    #[must_use]
    pub fn state(&self) -> ForwardState {
        self.handle.state()
    }

    /// Subscribe to state transitions.
    pub fn watch_state(&self) -> watch::Receiver<ForwardState> {
        self.handle.watch_state()
    }

    /// Stop the forward, awaiting terminal state.
    pub async fn stop(self) {
        self.handle.close().await;
    }
}

fn parse_direction(s: &str) -> Result<ForwardDirection> {
    match s {
        "local" => Ok(ForwardDirection::Local),
        "remote" => Ok(ForwardDirection::Remote),
        other => Err(Error::InvalidConfig(format!("unknown forward type `{other}`"))),
    }
}

/// Parse a target string into [`TargetAddr`]. Accepts `host:port` or
/// `[v6]:port`.
fn parse_target(s: &str) -> Result<TargetAddr> {
    let addr = BindAddr::parse(s)?;
    match addr {
        BindAddr::Tcp(sock) => Ok(TargetAddr::new(sock.ip().to_string(), sock.port())),
        BindAddr::TcpHostPort { host, port } => Ok(TargetAddr::new(host, port)),
        BindAddr::Unix(_) => Err(Error::InvalidConfig(
            "forward target cannot be a unix socket".into(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::MockTunnelSession;

    fn fwd(kind: &str, transport: &str, bind: &str, target: &str) -> Forward {
        Forward {
            name: "f1".into(),
            kind: kind.into(),
            transport: transport.into(),
            bind: Some(bind.into()),
            target: Some(target.into()),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn start_local_tcp_returns_handle_in_active_state() {
        let mut session = MockTunnelSession::new();
        let cfg = fwd("local", "tcp", "127.0.0.1:0", "203.0.113.1:22");
        let runner = ForwardRunner::start(&cfg, &mut session, &ForwardRunnerConfig::default())
            .await
            .unwrap();
        assert_eq!(runner.state(), ForwardState::Active);
        runner.stop().await;
    }

    #[tokio::test]
    async fn start_remote_tcp() {
        let mut session = MockTunnelSession::new();
        let cfg = fwd("remote", "tcp", "0.0.0.0:0", "127.0.0.1:8080");
        let runner = ForwardRunner::start(&cfg, &mut session, &ForwardRunnerConfig::default())
            .await
            .unwrap();
        runner.stop().await;
    }

    #[tokio::test]
    async fn start_udp_forward() {
        let mut session = MockTunnelSession::new();
        let mut cfg = fwd("local", "udp", "127.0.0.1:0", "127.0.0.1:53");
        cfg.udp_idle_timeout = Some("30s".into());
        let runner = ForwardRunner::start(&cfg, &mut session, &ForwardRunnerConfig::default())
            .await
            .unwrap();
        runner.stop().await;
    }

    #[tokio::test]
    async fn malformed_missing_bind() {
        let mut session = MockTunnelSession::new();
        let mut cfg = fwd("local", "tcp", "127.0.0.1:0", "1.2.3.4:5");
        cfg.bind = None;
        cfg.listen = None;
        let r = ForwardRunner::start(&cfg, &mut session, &ForwardRunnerConfig::default()).await;
        assert!(matches!(r, Err(Error::InvalidConfig(_))));
    }

    #[tokio::test]
    async fn malformed_unknown_transport() {
        let mut session = MockTunnelSession::new();
        let cfg = fwd("local", "sctp", "127.0.0.1:0", "1.2.3.4:5");
        let r = ForwardRunner::start(&cfg, &mut session, &ForwardRunnerConfig::default()).await;
        assert!(matches!(r, Err(Error::InvalidConfig(_))));
    }
}
