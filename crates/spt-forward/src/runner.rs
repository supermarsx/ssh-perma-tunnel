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
    DynamicForwardSpec, ForwardDirection, ForwardHandle, ForwardState, LocalForwardSpec,
    RemoteForwardSpec, TargetAddr, TunnelSession, UdpForwardSpec,
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
        let listen = resolve_listen(cfg, listen_str)?;

        let handle = match (cfg.kind.as_str(), cfg.transport.as_str()) {
            ("dynamic", "tcp") => {
                let protocols = dynamic_proxy_protocols(cfg);
                let spec = DynamicForwardSpec {
                    name: name.clone(),
                    listen,
                    max_connections: cfg.max_connections,
                    allow_socks4: protocols.socks4,
                    allow_socks4a: protocols.socks4a,
                    allow_socks5: protocols.socks5,
                    allow_http_connect: protocols.http_connect,
                };
                session.open_dynamic_forward(&spec).await?
            }
            ("dynamic", other) => {
                return Err(ForwardRunnerError::Malformed {
                    name: name.clone(),
                    reason: format!("dynamic forwards require transport `tcp`, got `{other}`"),
                }
                .into());
            }
            (kind @ ("local" | "remote"), transport) => {
                let target_str = cfg
                    .target
                    .as_deref()
                    .or(cfg.connect.as_deref())
                    .ok_or_else(|| ForwardRunnerError::Malformed {
                        name: name.clone(),
                        reason: "missing `target`/`connect`".into(),
                    })?;
                let target =
                    parse_target(target_str).map_err(|e| ForwardRunnerError::Malformed {
                        name: name.clone(),
                        reason: format!("invalid target `{target_str}`: {e}"),
                    })?;
                let direction =
                    parse_direction(kind).map_err(|e| ForwardRunnerError::Malformed {
                        name: name.clone(),
                        reason: e.to_string(),
                    })?;
                match (direction, transport) {
                    (ForwardDirection::Local, "tcp") => {
                        let spec = LocalForwardSpec {
                            name: name.clone(),
                            listen: listen.clone(),
                            target,
                            max_connections: cfg.max_connections,
                        };
                        session.open_local_forward(&spec).await?
                    }
                    (ForwardDirection::Remote, "tcp") => {
                        let spec = RemoteForwardSpec {
                            name: name.clone(),
                            listen: listen.clone(),
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
                            listen: listen.clone(),
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
                }
            }
            (other, _) => {
                return Err(ForwardRunnerError::Malformed {
                    name: name.clone(),
                    reason: format!("unknown forward type `{other}`"),
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DynamicProxyProtocols {
    socks4: bool,
    socks4a: bool,
    socks5: bool,
    http_connect: bool,
}

impl DynamicProxyProtocols {
    const ALL: Self = Self {
        socks4: true,
        socks4a: true,
        socks5: true,
        http_connect: true,
    };

    const NONE: Self = Self {
        socks4: false,
        socks4a: false,
        socks5: false,
        http_connect: false,
    };
}

fn dynamic_proxy_protocols(cfg: &Forward) -> DynamicProxyProtocols {
    let Some(values) = cfg.proxy_protocols.as_ref() else {
        return DynamicProxyProtocols::ALL;
    };
    if values
        .iter()
        .any(|value| normalize_proxy_protocol(value) == Some("all"))
    {
        return DynamicProxyProtocols::ALL;
    }

    let mut protocols = DynamicProxyProtocols::NONE;
    for value in values {
        match normalize_proxy_protocol(value) {
            Some("socks4") => protocols.socks4 = true,
            Some("socks4a") => protocols.socks4a = true,
            Some("socks5") => protocols.socks5 = true,
            Some("http_connect") => protocols.http_connect = true,
            _ => {}
        }
    }
    protocols
}

fn normalize_proxy_protocol(value: &str) -> Option<&'static str> {
    match value.trim().to_ascii_lowercase().replace('-', "_").as_str() {
        "all" => Some("all"),
        "socks4" => Some("socks4"),
        "socks4a" => Some("socks4a"),
        "socks5" => Some("socks5"),
        "http" | "http_connect" | "connect" => Some("http_connect"),
        _ => None,
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

        async fn open_dynamic_forward(
            &mut self,
            spec: &DynamicForwardSpec,
        ) -> Result<ForwardHandle> {
            self.last_listen = Some(spec.listen.clone());
            self.inner.open_dynamic_forward(spec).await
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
    async fn start_dynamic_tcp_does_not_require_target() {
        let mut session = MockTunnelSession::new();
        let mut cfg = fwd("dynamic", "tcp", "127.0.0.1:0", "ignored:1");
        cfg.target = None;
        cfg.connect = None;
        let runner = ForwardRunner::start(&cfg, &mut session, &ForwardRunnerConfig::default())
            .await
            .unwrap();
        runner.stop().await;
    }

    #[test]
    fn dynamic_proxy_protocols_default_to_all() {
        let cfg = fwd("dynamic", "tcp", "127.0.0.1:0", "ignored:1");
        assert_eq!(dynamic_proxy_protocols(&cfg), DynamicProxyProtocols::ALL);
    }

    #[test]
    fn dynamic_proxy_protocols_select_subset() {
        let mut cfg = fwd("dynamic", "tcp", "127.0.0.1:0", "ignored:1");
        cfg.proxy_protocols = Some(vec!["socks4a".into(), "http-connect".into()]);
        assert_eq!(
            dynamic_proxy_protocols(&cfg),
            DynamicProxyProtocols {
                socks4: false,
                socks4a: true,
                socks5: false,
                http_connect: true,
            }
        );
    }

    #[test]
    fn dynamic_proxy_protocols_all_overrides_subset() {
        let mut cfg = fwd("dynamic", "tcp", "127.0.0.1:0", "ignored:1");
        cfg.proxy_protocols = Some(vec!["socks5".into(), "all".into()]);
        assert_eq!(dynamic_proxy_protocols(&cfg), DynamicProxyProtocols::ALL);
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

    // ---- Extended runner state / bind_mode / target coverage ----

    #[test]
    fn runner_error_into_error() {
        let malformed = ForwardRunnerError::Malformed {
            name: "f".into(),
            reason: "r".into(),
        };
        let unsupported = ForwardRunnerError::UnsupportedCapability {
            name: "f".into(),
            cap: "udp",
        };
        let m_err: Error = malformed.into();
        let u_err: Error = unsupported.into();
        assert!(matches!(m_err, Error::InvalidConfig(_)));
        assert!(matches!(u_err, Error::InvalidConfig(_)));
        let u2 = ForwardRunnerError::UnsupportedCapability {
            name: "fwd".into(),
            cap: "udp",
        };
        assert!(u2.to_string().contains("udp"));
        let m2 = ForwardRunnerError::Malformed {
            name: "fwd".into(),
            reason: "why".into(),
        };
        assert!(m2.to_string().contains("why"));
    }

    #[tokio::test]
    async fn runner_name_accessor() {
        let mut session = MockTunnelSession::new();
        let mut cfg = fwd("local", "tcp", "127.0.0.1:0", "1.2.3.4:5");
        cfg.name = "named-fwd".into();
        let runner = ForwardRunner::start(&cfg, &mut session, &ForwardRunnerConfig::default())
            .await
            .unwrap();
        assert_eq!(runner.name(), "named-fwd");
        runner.stop().await;
    }

    #[tokio::test]
    async fn runner_state_transitions_to_stopped() {
        let mut session = MockTunnelSession::new();
        let cfg = fwd("local", "tcp", "127.0.0.1:0", "1.2.3.4:5");
        let runner = ForwardRunner::start(&cfg, &mut session, &ForwardRunnerConfig::default())
            .await
            .unwrap();
        let mut watch = runner.watch_state();
        assert_eq!(*watch.borrow(), ForwardState::Active);
        runner.stop().await;
        let final_state = if watch.borrow().is_terminal() {
            *watch.borrow()
        } else {
            watch.changed().await.unwrap();
            *watch.borrow()
        };
        assert!(final_state.is_terminal(), "got {final_state:?}");
    }

    #[tokio::test]
    async fn bind_mode_loopback_resolves() {
        let mut session = CapturingSession::new();
        let mut cfg = fwd("local", "tcp", "127.0.0.1:0", "1.2.3.4:5");
        cfg.bind_mode = Some("loopback".into());
        let runner = ForwardRunner::start(&cfg, &mut session, &ForwardRunnerConfig::default())
            .await
            .unwrap();
        match session.last_listen.clone().unwrap() {
            BindAddr::Tcp(sock) => assert!(sock.ip().is_loopback(), "got {sock}"),
            other => panic!("expected TCP listen, got {other:?}"),
        }
        runner.stop().await;
    }

    #[tokio::test]
    async fn bind_mode_specific_ip_resolves() {
        let mut session = CapturingSession::new();
        let mut cfg = fwd("local", "tcp", "127.0.0.1:0", "1.2.3.4:5");
        cfg.bind_mode = Some("specific_ip".into());
        let runner = ForwardRunner::start(&cfg, &mut session, &ForwardRunnerConfig::default())
            .await
            .unwrap();
        match session.last_listen.clone().unwrap() {
            BindAddr::Tcp(sock) => assert_eq!(sock.ip().to_string(), "127.0.0.1"),
            other => panic!("expected TCP listen, got {other:?}"),
        }
        runner.stop().await;
    }

    #[test]
    fn bind_mode_specific_ip_requires_numeric() {
        let mut cfg = fwd("local", "tcp", "example.com:443", "1.2.3.4:5");
        cfg.bind_mode = Some("specific_ip".into());
        let err = resolve_listen(&cfg, "example.com:443").unwrap_err();
        assert!(
            err.to_string().contains("specific_ip requires numeric"),
            "{err}"
        );
    }

    #[test]
    fn bind_mode_specific_ip_v6_rejected_when_disabled() {
        let mut cfg = fwd("local", "tcp", "[::1]:0", "1.2.3.4:5");
        cfg.bind_mode = Some("specific_ip".into());
        cfg.bind_ipv6 = Some("disable".into());
        let err = resolve_listen(&cfg, "[::1]:0").unwrap_err();
        assert!(err.to_string().contains("IPv6"), "{err}");
    }

    #[tokio::test]
    async fn bind_mode_all_interfaces() {
        let mut session = CapturingSession::new();
        let mut cfg = fwd("local", "tcp", "127.0.0.1:0", "1.2.3.4:5");
        cfg.bind_mode = Some("all_interfaces".into());
        let runner = ForwardRunner::start(&cfg, &mut session, &ForwardRunnerConfig::default())
            .await
            .unwrap();
        match session.last_listen.clone().unwrap() {
            BindAddr::Tcp(sock) => {
                assert!(sock.ip().is_unspecified(), "got {sock}");
            }
            other => panic!("expected TCP listen, got {other:?}"),
        }
        runner.stop().await;
    }

    #[tokio::test]
    async fn bind_mode_auto_interface() {
        let mut session = CapturingSession::new();
        let mut cfg = fwd("local", "tcp", "127.0.0.1:0", "1.2.3.4:5");
        cfg.bind_mode = Some("auto_interface".into());
        let _ = ForwardRunner::start(&cfg, &mut session, &ForwardRunnerConfig::default()).await;
    }

    #[test]
    fn bind_mode_unknown_value_rejected() {
        let mut cfg = fwd("local", "tcp", "127.0.0.1:0", "1.2.3.4:5");
        cfg.bind_mode = Some("totally-wrong".into());
        let err = resolve_listen(&cfg, "127.0.0.1:0").unwrap_err();
        assert!(err.to_string().contains("unknown bind_mode"), "{err}");
    }

    #[test]
    fn bind_mode_with_unix_listener_rejected() {
        let mut cfg = fwd("local", "tcp", "unix:///tmp/x.sock", "1.2.3.4:5");
        cfg.bind = Some("unix:///tmp/x.sock".into());
        cfg.bind_mode = Some("loopback".into());
        let err = resolve_listen(&cfg, "unix:///tmp/x.sock").unwrap_err();
        assert!(err.to_string().contains("unix socket"), "{err}");
    }

    #[tokio::test]
    async fn invalid_listen_string() {
        let mut session = MockTunnelSession::new();
        let cfg = fwd("local", "tcp", "not-a-valid-addr", "1.2.3.4:5");
        let r = ForwardRunner::start(&cfg, &mut session, &ForwardRunnerConfig::default()).await;
        assert!(matches!(r, Err(Error::InvalidConfig(_))));
    }

    #[tokio::test]
    async fn invalid_target_string() {
        let mut session = MockTunnelSession::new();
        let cfg = fwd("local", "tcp", "127.0.0.1:0", "not-a-valid-addr");
        let r = ForwardRunner::start(&cfg, &mut session, &ForwardRunnerConfig::default()).await;
        assert!(matches!(r, Err(Error::InvalidConfig(_))));
    }

    #[tokio::test]
    async fn unix_target_rejected() {
        let mut session = MockTunnelSession::new();
        let cfg = fwd("local", "tcp", "127.0.0.1:0", "unix:///tmp/x.sock");
        let r = ForwardRunner::start(&cfg, &mut session, &ForwardRunnerConfig::default()).await;
        assert!(matches!(r, Err(Error::InvalidConfig(_))));
    }

    #[tokio::test]
    async fn unknown_kind_rejected() {
        let mut session = MockTunnelSession::new();
        let cfg = fwd("sideways", "tcp", "127.0.0.1:0", "1.2.3.4:5");
        let r = ForwardRunner::start(&cfg, &mut session, &ForwardRunnerConfig::default()).await;
        assert!(matches!(r, Err(Error::InvalidConfig(_))));
    }

    #[tokio::test]
    async fn listen_connect_aliases_used() {
        let mut session = MockTunnelSession::new();
        let mut cfg = fwd("local", "tcp", "127.0.0.1:0", "1.2.3.4:5");
        cfg.bind = None;
        cfg.target = None;
        cfg.listen = Some("127.0.0.1:0".into());
        cfg.connect = Some("1.2.3.4:5".into());
        let runner = ForwardRunner::start(&cfg, &mut session, &ForwardRunnerConfig::default())
            .await
            .unwrap();
        runner.stop().await;
    }

    #[tokio::test]
    async fn malformed_missing_target() {
        let mut session = MockTunnelSession::new();
        let mut cfg = fwd("local", "tcp", "127.0.0.1:0", "1.2.3.4:5");
        cfg.target = None;
        cfg.connect = None;
        let r = ForwardRunner::start(&cfg, &mut session, &ForwardRunnerConfig::default()).await;
        assert!(matches!(r, Err(Error::InvalidConfig(_))));
    }

    #[tokio::test]
    async fn udp_bad_idle_timeout() {
        let mut session = MockTunnelSession::new();
        let mut cfg = fwd("local", "udp", "127.0.0.1:0", "1.2.3.4:5");
        cfg.udp_idle_timeout = Some("yesterday".into());
        let r = ForwardRunner::start(&cfg, &mut session, &ForwardRunnerConfig::default()).await;
        assert!(matches!(r, Err(Error::InvalidConfig(_))));
    }

    #[tokio::test]
    async fn udp_uses_runner_default_idle() {
        let mut session = MockTunnelSession::new();
        let cfg = fwd("local", "udp", "127.0.0.1:0", "1.2.3.4:5");
        let runner_cfg = ForwardRunnerConfig {
            default_udp_idle: Some(Duration::from_secs(123)),
        };
        let runner = ForwardRunner::start(&cfg, &mut session, &runner_cfg)
            .await
            .unwrap();
        runner.stop().await;
    }

    #[tokio::test]
    async fn udp_remote_direction() {
        let mut session = MockTunnelSession::new();
        let cfg = fwd("remote", "udp", "127.0.0.1:0", "1.2.3.4:5");
        let runner = ForwardRunner::start(&cfg, &mut session, &ForwardRunnerConfig::default())
            .await
            .unwrap();
        runner.stop().await;
    }

    #[test]
    fn parse_target_host_port() {
        let t = parse_target("example.com:443").unwrap();
        assert_eq!(t.host, "example.com");
        assert_eq!(t.port, 443);
    }

    #[test]
    fn parse_target_v6() {
        let t = parse_target("[::1]:9000").unwrap();
        assert_eq!(t.port, 9000);
        assert!(t.host.contains(':'));
    }

    #[test]
    fn parse_target_rejects_unix() {
        let r = parse_target("unix:///tmp/foo.sock");
        assert!(matches!(r, Err(Error::InvalidConfig(_))));
    }

    #[test]
    fn parse_direction_variants() {
        assert!(matches!(
            parse_direction("local"),
            Ok(ForwardDirection::Local)
        ));
        assert!(matches!(
            parse_direction("remote"),
            Ok(ForwardDirection::Remote)
        ));
        assert!(matches!(
            parse_direction("nowhere"),
            Err(Error::InvalidConfig(_))
        ));
    }

    #[test]
    fn specific_interface_missing_name() {
        let mut cfg = fwd("local", "tcp", "127.0.0.1:0", "1.2.3.4:5");
        cfg.bind_mode = Some("specific_interface".into());
        cfg.bind_interface = None;
        let err = resolve_listen(&cfg, "127.0.0.1:0").unwrap_err();
        assert!(
            err.to_string()
                .contains("specific_interface requires bind_interface"),
            "{err}"
        );
    }

    #[test]
    fn select_bind_addr_prefer_v6() {
        let v4: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let v6: SocketAddr = "[::1]:8080".parse().unwrap();
        let pick = select_bind_addr(vec![v4, v6], Some("prefer"), ListenFamily::Unknown);
        assert_eq!(pick, Some(v6));
    }

    #[test]
    fn select_bind_addr_disable_v6() {
        let v4: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let v6: SocketAddr = "[::1]:8080".parse().unwrap();
        let pick = select_bind_addr(vec![v4, v6], Some("disable"), ListenFamily::Unknown);
        assert_eq!(pick, Some(v4));
    }

    #[test]
    fn select_bind_addr_respects_original_family_v6() {
        let v4: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let v6: SocketAddr = "[::1]:8080".parse().unwrap();
        let pick = select_bind_addr(vec![v4, v6], None, ListenFamily::Ipv6);
        assert_eq!(pick, Some(v6));
    }

    #[test]
    fn select_bind_addr_default_to_first() {
        let v4: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let v6: SocketAddr = "[::1]:8080".parse().unwrap();
        let pick = select_bind_addr(vec![v4, v6], None, ListenFamily::Ipv4);
        assert_eq!(pick, Some(v4));
    }

    #[test]
    fn select_bind_addr_empty_list() {
        assert_eq!(
            select_bind_addr(vec![], Some("prefer"), ListenFamily::Unknown),
            None
        );
    }
}
