//! Supervisor-facing wrapper around a single config [`spt_config::Forward`].
//!
//! `ForwardRunner::start` translates the config-level forward description into
//! the protocol-level [`LocalForwardSpec`]/[`RemoteForwardSpec`]/[`UdpForwardSpec`],
//! then asks the [`TunnelSession`] to open the forward. The returned
//! [`ForwardHandle`] is owned by the runner so the supervisor can observe
//! state and request shutdown.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use spt_config::schema::Forward;
use spt_core::{BindAddr, Error, Result};
use spt_net::bind::{resolve_bind, AutoPrefer, BindMode, Family};
use spt_protocol::{
    ForwardDirection, ForwardHandle, ForwardState, LocalForwardSpec, RemoteForwardSpec, TargetAddr,
    TunnelSession, UdpForwardSpec,
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
            .ok_or_else(|| ForwardRunnerError::Malformed {
                name: name.clone(),
                reason: "missing `bind`/`listen`".into(),
            })?;
        let target_str = cfg
            .target
            .as_deref()
            .or(cfg.connect.as_deref())
            .ok_or_else(|| ForwardRunnerError::Malformed {
                name: name.clone(),
                reason: "missing `target`/`connect`".into(),
            })?;

        let listen = resolve_listen(cfg, listen_str)?;
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
        other => Err(Error::InvalidConfig(format!(
            "unknown forward type `{other}`"
        ))),
    }
}

fn resolve_listen(
    cfg: &Forward,
    listen_str: &str,
) -> std::result::Result<BindAddr, ForwardRunnerError> {
    let parsed = BindAddr::parse(listen_str).map_err(|e| ForwardRunnerError::Malformed {
        name: cfg.name.clone(),
        reason: format!("invalid listen `{listen_str}`: {e}"),
    })?;

    if cfg.bind_mode.is_none() {
        return Ok(parsed);
    }

    let (host, port) = listen_host_port(&parsed).ok_or_else(|| ForwardRunnerError::Malformed {
        name: cfg.name.clone(),
        reason: "bind_mode cannot be used with unix socket listeners".into(),
    })?;
    let original_family = listen_family(&parsed);
    let mode = bind_mode_from_forward(cfg, &host)?;
    let addrs = resolve_bind(&mode, port).map_err(|e| ForwardRunnerError::Malformed {
        name: cfg.name.clone(),
        reason: format!(
            "bind_mode `{}` could not resolve a bind address: {e}",
            cfg.bind_mode.as_deref().unwrap_or("unknown")
        ),
    })?;
    let selected =
        select_bind_addr(addrs, cfg.bind_ipv6.as_deref(), original_family).ok_or_else(|| {
            ForwardRunnerError::Malformed {
                name: cfg.name.clone(),
                reason: format!(
                    "bind_mode `{}` produced no address compatible with bind_ipv6 `{}`",
                    cfg.bind_mode.as_deref().unwrap_or("unknown"),
                    cfg.bind_ipv6.as_deref().unwrap_or("auto")
                ),
            }
        })?;
    Ok(BindAddr::Tcp(selected))
}

fn listen_host_port(addr: &BindAddr) -> Option<(String, u16)> {
    match addr {
        BindAddr::Tcp(sock) => Some((sock.ip().to_string(), sock.port())),
        BindAddr::TcpHostPort { host, port } => Some((host.clone(), *port)),
        BindAddr::Unix(_) => None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ListenFamily {
    Ipv4,
    Ipv6,
    Unknown,
}

fn listen_family(addr: &BindAddr) -> ListenFamily {
    match addr {
        BindAddr::Tcp(sock) if sock.is_ipv4() => ListenFamily::Ipv4,
        BindAddr::Tcp(sock) if sock.is_ipv6() => ListenFamily::Ipv6,
        BindAddr::TcpHostPort { host, .. } => match host.parse::<IpAddr>() {
            Ok(IpAddr::V4(_)) => ListenFamily::Ipv4,
            Ok(IpAddr::V6(_)) => ListenFamily::Ipv6,
            Err(_) => ListenFamily::Unknown,
        },
        _ => ListenFamily::Unknown,
    }
}

fn bind_mode_from_forward(
    cfg: &Forward,
    host: &str,
) -> std::result::Result<BindMode, ForwardRunnerError> {
    let family = family_from_forward(cfg);
    match cfg.bind_mode.as_deref() {
        Some("loopback") => Ok(BindMode::Loopback),
        Some("specific_ip") => {
            let ip = host
                .parse::<IpAddr>()
                .map_err(|e| ForwardRunnerError::Malformed {
                    name: cfg.name.clone(),
                    reason: format!(
                        "bind_mode specific_ip requires numeric bind host `{host}`: {e}"
                    ),
                })?;
            if matches!(family, Family::Ipv4) && ip.is_ipv6() {
                return Err(ForwardRunnerError::Malformed {
                    name: cfg.name.clone(),
                    reason:
                        "bind_mode specific_ip cannot use an IPv6 host when bind_ipv6 is disabled"
                            .into(),
                });
            }
            Ok(BindMode::SpecificIp(ip))
        }
        Some("specific_interface") => {
            let name = cfg
                .bind_interface
                .clone()
                .ok_or_else(|| ForwardRunnerError::Malformed {
                    name: cfg.name.clone(),
                    reason: "bind_mode specific_interface requires bind_interface".into(),
                })?;
            Ok(BindMode::SpecificInterface { name, family })
        }
        Some("all_interfaces") => Ok(BindMode::AllInterfaces),
        Some("auto_interface") => Ok(BindMode::AutoInterface {
            prefer: auto_prefer_from_forward(cfg, family),
        }),
        Some(other) => Err(ForwardRunnerError::Malformed {
            name: cfg.name.clone(),
            reason: format!("unknown bind_mode `{other}`"),
        }),
        None => unreachable!("caller only asks for bind mode resolution when bind_mode is set"),
    }
}

fn auto_prefer_from_forward(cfg: &Forward, family: Family) -> AutoPrefer {
    if let Some(preferences) = cfg.bind_interface_preference.clone() {
        if !preferences.is_empty() {
            return AutoPrefer::Name(preferences);
        }
    }
    if let Some(name) = cfg.bind_interface.clone() {
        if !name.is_empty() {
            return AutoPrefer::Name(vec![name]);
        }
    }
    if !matches!(family, Family::Both) {
        return AutoPrefer::Family(family);
    }
    AutoPrefer::PlatformDefault
}

fn family_from_forward(cfg: &Forward) -> Family {
    match cfg.bind_ipv6.as_deref() {
        Some("disable") => Family::Ipv4,
        _ => Family::Both,
    }
}

fn select_bind_addr(
    addrs: Vec<SocketAddr>,
    bind_ipv6: Option<&str>,
    original_family: ListenFamily,
) -> Option<SocketAddr> {
    match bind_ipv6 {
        Some("disable") => addrs.into_iter().find(SocketAddr::is_ipv4),
        Some("prefer") => addrs
            .iter()
            .copied()
            .find(SocketAddr::is_ipv6)
            .or_else(|| addrs.into_iter().next()),
        _ if matches!(original_family, ListenFamily::Ipv6) => addrs
            .iter()
            .copied()
            .find(SocketAddr::is_ipv6)
            .or_else(|| addrs.into_iter().next()),
        _ => addrs.into_iter().next(),
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
    use spt_protocol::{LocalForwardSpec, RemoteForwardSpec, SessionInfo, UdpForwardSpec};

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

    #[derive(Debug)]
    struct CapturingSession {
        inner: MockTunnelSession,
        last_listen: Option<BindAddr>,
    }

    impl CapturingSession {
        fn new() -> Self {
            Self {
                inner: MockTunnelSession::new(),
                last_listen: None,
            }
        }
    }

    #[async_trait::async_trait]
    impl TunnelSession for CapturingSession {
        async fn open_local_forward(&mut self, spec: &LocalForwardSpec) -> Result<ForwardHandle> {
            self.last_listen = Some(spec.listen.clone());
            self.inner.open_local_forward(spec).await
        }

        async fn open_remote_forward(&mut self, spec: &RemoteForwardSpec) -> Result<ForwardHandle> {
            self.last_listen = Some(spec.listen.clone());
            self.inner.open_remote_forward(spec).await
        }

        async fn open_udp_forward(&mut self, spec: &UdpForwardSpec) -> Result<ForwardHandle> {
            self.last_listen = Some(spec.listen.clone());
            self.inner.open_udp_forward(spec).await
        }

        async fn keepalive(&mut self) -> Result<()> {
            self.inner.keepalive().await
        }

        async fn close(self: Box<Self>) -> Result<()> {
            Ok(())
        }

        fn session_info(&self) -> SessionInfo {
            self.inner.session_info()
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
    async fn start_resolves_specific_interface_bind_mode() {
        let ifaces = spt_net::interfaces::list().unwrap();
        let loopback = ifaces
            .iter()
            .find(|iface| iface.is_loopback)
            .expect("loopback interface present");
        let mut session = CapturingSession::new();
        let mut cfg = fwd("local", "tcp", "127.0.0.1:0", "203.0.113.1:22");
        cfg.bind_mode = Some("specific_interface".into());
        cfg.bind_interface = Some(loopback.name.clone());

        let runner = ForwardRunner::start(&cfg, &mut session, &ForwardRunnerConfig::default())
            .await
            .unwrap();
        let listen = session.last_listen.clone().expect("listen captured");
        match listen {
            BindAddr::Tcp(sock) => assert!(sock.ip().is_loopback(), "got {sock}"),
            other => panic!("expected tcp listen address, got {other:?}"),
        }
        runner.stop().await;
    }

    #[test]
    fn specific_interface_requires_interface_name() {
        let mut cfg = fwd("local", "tcp", "127.0.0.1:0", "203.0.113.1:22");
        cfg.bind_mode = Some("specific_interface".into());

        let err = resolve_listen(&cfg, "127.0.0.1:0").unwrap_err();
        assert!(err
            .to_string()
            .contains("specific_interface requires bind_interface"));
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
