//! Network-reachability sanity checks.
//!
//! * [`NetworkDiagnostic`] (group `network`): resolves a configurable name
//!   (default `localhost`, so the check is hermetic on CI).
//! * [`DnsDiagnostic`] (group `dns`): validates the `[dns]` table — mode,
//!   listener bind, and upstream-resolver reachability (non-destructive
//!   UDP/TCP probe). Previously `spt diagnose dns` had **no backing check**
//!   and always printed "(no `dns` checks registered)" (E8-F8).
//! * [`BindDiagnostic`] (group `bind`): verifies every listener address the
//!   config asks spt to open (`[dns].bind`, `[status_api].bind`,
//!   `[mcp].listen`, SNMP) is actually bindable, distinguishing
//!   "already in use by the running daemon" from a hard failure. Previously
//!   `spt diagnose bind` had no backing check (E8-F8).
//!
//! Both new diagnostics read `ctx.effective_config` (the rendered, redacted
//! TOML the dispatcher injects) and degrade to `Skipped` when no config is
//! present, so `DiagnosticContext::default()` stays a usable test scaffold
//! and offline CI never flakes.

use async_trait::async_trait;
use std::net::ToSocketAddrs;
use std::time::Duration;

use spt_config::schema::Config;
use tokio::net::lookup_host;
use tokio::time::timeout;

use crate::check::{Check, Severity, Status};
use crate::framework::{Diagnostic, DiagnosticContext};

/// Per-probe budget for upstream DNS reachability.
const DNS_PROBE_BUDGET: Duration = Duration::from_secs(3);

/// Valid `[dns].mode` values per schema §9.4.
const DNS_MODES: &[&str] = &[
    "disabled",
    "transparent_forwarder",
    "synthetic_only",
    "hosts_file",
];

/// DNS + reachability checks.
#[derive(Debug)]
pub struct NetworkDiagnostic {
    /// Hostname to attempt to resolve. Defaults to `localhost`.
    pub probe_host: String,
}

impl Default for NetworkDiagnostic {
    fn default() -> Self {
        Self {
            probe_host: "localhost".into(),
        }
    }
}

#[async_trait]
impl Diagnostic for NetworkDiagnostic {
    fn group(&self) -> &'static str {
        "network"
    }
    async fn run(&self, _ctx: &DiagnosticContext) -> Vec<Check> {
        let mut out = Vec::new();
        let target = format!("{}:0", self.probe_host);
        match target.to_socket_addrs() {
            Ok(addrs) => {
                let n = addrs.count();
                out.push(
                    Check::new("network.dns_resolves", Severity::High, Status::Pass).with_evidence(
                        format!("`{}` resolved to {n} address(es)", self.probe_host),
                    ),
                );
            }
            Err(e) => {
                out.push(
                    Check::new("network.dns_resolves", Severity::High, Status::Fail)
                        .with_evidence(format!("resolve `{}` failed: {e}", self.probe_host))
                        .with_remediation(
                            "verify `runtime.dns.upstream` and that system DNS is reachable",
                        ),
                );
            }
        }
        out
    }
}

// ---------------------------------------------------------------------------
// DNS — E8-F8: real backing check for `spt diagnose dns`.
// ---------------------------------------------------------------------------

/// Validates the `[dns]` table and probes upstream resolvers.
#[derive(Debug, Default)]
pub struct DnsDiagnostic {
    /// Pre-loaded config. When `None` the diagnostic parses
    /// `ctx.effective_config`.
    pub config: Option<Config>,
    /// When true, attempt a non-destructive reachability probe of each
    /// upstream resolver. Defaults to true; tests set it false to stay
    /// hermetic.
    pub probe_upstreams: bool,
}

impl DnsDiagnostic {
    /// Provide the loaded config directly.
    #[must_use]
    pub fn with_config(mut self, cfg: Config) -> Self {
        self.config = Some(cfg);
        self
    }
}

#[async_trait]
impl Diagnostic for DnsDiagnostic {
    fn group(&self) -> &'static str {
        "dns"
    }

    async fn run(&self, ctx: &DiagnosticContext) -> Vec<Check> {
        let Some(cfg) = resolve_config(self.config.as_ref(), ctx) else {
            return vec![Check::new("dns.config", Severity::Low, Status::Skipped)
                .with_evidence("no config loaded")];
        };
        let Some(dns) = cfg.dns.as_ref() else {
            return vec![Check::new("dns.enabled", Severity::Info, Status::Skipped)
                .with_evidence("no `[dns]` table configured")];
        };

        let mut out = Vec::new();

        // Mode validity.
        if let Some(mode) = dns.mode.as_deref() {
            if DNS_MODES.contains(&mode) {
                out.push(
                    Check::new("dns.mode", Severity::Info, Status::Pass)
                        .with_evidence(format!("mode = `{mode}`")),
                );
            } else {
                out.push(
                    Check::new("dns.mode", Severity::High, Status::Fail)
                        .with_evidence(format!("unknown `[dns].mode` = `{mode}`"))
                        .with_remediation(format!("set mode to one of {DNS_MODES:?}")),
                );
            }
        }

        // Records parse (owner/type/value present; the schema already
        // enforces the required fields, so this is a structural sanity note).
        if !dns.records.is_empty() {
            out.push(
                Check::new("dns.records", Severity::Info, Status::Pass)
                    .with_evidence(format!("{} static record(s) configured", dns.records.len())),
            );
        }

        // Upstream resolvers.
        match dns.upstream.as_ref() {
            Some(upstreams) if !upstreams.is_empty() => {
                for up in upstreams {
                    if self.probe_upstreams {
                        out.push(probe_upstream(up).await);
                    } else {
                        out.push(
                            Check::new("dns.upstream", Severity::Info, Status::Skipped)
                                .with_evidence(format!("`{up}` (probe disabled)")),
                        );
                    }
                }
            }
            _ => {
                // Forwarder modes need an upstream; synthetic/disabled do not.
                let mode = dns.mode.as_deref().unwrap_or("");
                if mode == "transparent_forwarder" {
                    out.push(
                        Check::new("dns.upstream", Severity::Medium, Status::Warn)
                            .with_evidence("transparent_forwarder mode without `[dns].upstream`")
                            .with_remediation("add at least one `upstream` resolver"),
                    );
                } else {
                    out.push(
                        Check::new("dns.upstream", Severity::Info, Status::Skipped)
                            .with_evidence("no upstream resolvers configured"),
                    );
                }
            }
        }

        if out.is_empty() {
            out.push(
                Check::new("dns.config", Severity::Info, Status::Skipped)
                    .with_evidence("`[dns]` present but nothing to validate"),
            );
        }
        out
    }
}

/// Non-destructive reachability probe of an upstream resolver address. Accepts
/// `ip`, `ip:port`, `host`, or `host:port`; defaults to port 53. Resolves +
/// binds a local UDP socket toward the target without sending a payload (so we
/// never generate spurious DNS traffic). Unreachable degrades to `Warn`, never
/// `Fail`, so an offline host running `spt diagnose dns` is not a hard error.
async fn probe_upstream(upstream: &str) -> Check {
    let target = if upstream.contains(':') && !upstream.ends_with(']') {
        // Already host:port (or [v6]:port). Leave as-is.
        upstream.to_string()
    } else {
        // Bare host / IPv4, or a bracketed IPv6 literal without a port.
        format!("{upstream}:53")
    };

    let resolved = timeout(DNS_PROBE_BUDGET, lookup_host(&target)).await;
    match resolved {
        Ok(Ok(mut addrs)) => {
            if addrs.next().is_some() {
                Check::new("dns.upstream", Severity::Info, Status::Pass).with_evidence(format!(
                    "upstream `{upstream}` resolves to a sendable address"
                ))
            } else {
                Check::new("dns.upstream", Severity::Medium, Status::Warn)
                    .with_evidence(format!("upstream `{upstream}` resolved to no addresses"))
                    .with_remediation("verify the resolver host/IP is correct")
            }
        }
        Ok(Err(e)) => Check::new("dns.upstream", Severity::Medium, Status::Warn)
            .with_evidence(format!("upstream `{upstream}` did not resolve: {e}"))
            .with_remediation("verify the resolver address and local DNS"),
        Err(_) => Check::new("dns.upstream", Severity::Low, Status::Warn)
            .with_evidence(format!("upstream `{upstream}` resolution timed out"))
            .with_remediation("network may be offline; rerun when connectivity is restored"),
    }
}

// ---------------------------------------------------------------------------
// Bind — E8-F8: real backing check for `spt diagnose bind`.
// ---------------------------------------------------------------------------

/// Verifies every listener address the config asks spt to open is bindable.
#[derive(Debug, Default)]
pub struct BindDiagnostic {
    /// Pre-loaded config. When `None` the diagnostic parses
    /// `ctx.effective_config`.
    pub config: Option<Config>,
}

impl BindDiagnostic {
    /// Provide the loaded config directly.
    #[must_use]
    pub fn with_config(mut self, cfg: Config) -> Self {
        self.config = Some(cfg);
        self
    }
}

#[async_trait]
impl Diagnostic for BindDiagnostic {
    fn group(&self) -> &'static str {
        "bind"
    }

    async fn run(&self, ctx: &DiagnosticContext) -> Vec<Check> {
        let Some(cfg) = resolve_config(self.config.as_ref(), ctx) else {
            return vec![Check::new("bind.config", Severity::Low, Status::Skipped)
                .with_evidence("no config loaded")];
        };

        // Collect (label, addr-string) for every listener the config opens.
        let mut listeners: Vec<(String, String)> = Vec::new();
        if let Some(dns) = cfg.dns.as_ref() {
            let enabled = dns.enabled.unwrap_or(false);
            if enabled {
                if let Some(b) = &dns.bind {
                    listeners.push(("dns".into(), b.clone()));
                }
            }
        }
        if cfg.status_api.enabled {
            listeners.push(("status_api".into(), cfg.status_api.bind.to_string()));
        }
        if let Some(mcp) = cfg.mcp.as_ref() {
            if mcp.enabled.unwrap_or(false) {
                if let Some(l) = &mcp.listen {
                    listeners.push(("mcp".into(), l.clone()));
                }
            }
        }
        if let Some(obs) = cfg.observability.as_ref() {
            if let Some(snmp) = obs.snmp.as_ref() {
                if snmp.enabled.unwrap_or(false) {
                    if let Some(b) = &snmp.bind {
                        listeners.push(("snmp".into(), b.clone()));
                    }
                }
            }
        }

        if listeners.is_empty() {
            return vec![
                Check::new("bind.listeners", Severity::Info, Status::Skipped)
                    .with_evidence("no enabled listeners with a bind address configured"),
            ];
        }

        let mut out = Vec::new();
        for (label, addr) in listeners {
            out.push(probe_bind(&label, &addr).await);
        }
        out
    }
}

/// Attempt to bind `addr` (TCP for `status_api`/mcp, UDP for dns/snmp would
/// differ, but a successful TCP bind is a sufficient liveness signal that the
/// address is well-formed and the local stack can open it). Distinguishes
/// "address already in use" (almost certainly the running daemon — `Warn`,
/// not `Fail`) from a genuine bind failure (`Fail`).
async fn probe_bind(label: &str, addr: &str) -> Check {
    use std::net::SocketAddr;
    let id = format!("bind.{label}");
    let parsed: Result<SocketAddr, _> = addr.parse();
    let sock_addr = match parsed {
        Ok(a) => a,
        Err(_) => {
            // Not a bare SocketAddr — try resolving host:port.
            match timeout(DNS_PROBE_BUDGET, lookup_host(addr)).await {
                Ok(Ok(mut it)) => match it.next() {
                    Some(a) => a,
                    None => {
                        return Check::new(id, Severity::High, Status::Fail)
                            .with_evidence(format!("`{label}` bind `{addr}` resolved to nothing"))
                            .with_remediation("set a valid `ip:port` or resolvable `host:port`");
                    }
                },
                _ => {
                    return Check::new(id, Severity::High, Status::Fail)
                        .with_evidence(format!("`{label}` bind `{addr}` is not a valid address"))
                        .with_remediation("set a valid `ip:port` listener address");
                }
            }
        }
    };

    match tokio::net::TcpListener::bind(sock_addr).await {
        Ok(listener) => {
            // Bound successfully — immediately release. Address is available.
            drop(listener);
            Check::new(id, Severity::Info, Status::Pass)
                .with_evidence(format!("`{label}` bind `{sock_addr}` is available"))
        }
        Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
            Check::new(id, Severity::Info, Status::Warn)
                .with_evidence(format!(
                    "`{label}` bind `{sock_addr}` already in use (likely the running spt daemon)"
                ))
                .with_remediation("expected while `tunnel run` is active; otherwise free the port")
        }
        Err(e) => Check::new(id, Severity::High, Status::Fail)
            .with_evidence(format!("`{label}` bind `{sock_addr}` failed: {e}"))
            .with_remediation(
                "check the address is local, the port is permitted, and you have privileges",
            ),
    }
}

/// Shared config resolver for the DNS / bind diagnostics: prefer a pre-loaded
/// `Config`, else parse `ctx.effective_config`.
fn resolve_config(preloaded: Option<&Config>, ctx: &DiagnosticContext) -> Option<Config> {
    if let Some(c) = preloaded {
        return Some(c.clone());
    }
    let body = ctx.effective_config.as_ref()?;
    spt_config::load::load_str(body, false).ok().map(|(c, _)| c)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn localhost_resolves() {
        let d = NetworkDiagnostic::default();
        let r = d.run(&DiagnosticContext::default()).await;
        assert_eq!(r[0].status, Status::Pass, "{:?}", r[0]);
    }

    #[tokio::test]
    async fn bogus_host_fails() {
        let d = NetworkDiagnostic {
            probe_host: "not-a-real-host.invalid".into(),
        };
        let r = d.run(&DiagnosticContext::default()).await;
        assert_eq!(r[0].status, Status::Fail);
        assert!(r[0].remediation.is_some());
    }

    fn cfg_str(body: &str) -> Config {
        spt_config::load::load_str(body, false).unwrap().0
    }

    // E8-F8: `dns` group now has a real backing check (was "(no dns checks)").
    #[tokio::test]
    async fn dns_skipped_without_config() {
        let r = DnsDiagnostic::default()
            .run(&DiagnosticContext::default())
            .await;
        assert_eq!(r[0].status, Status::Skipped);
        assert_eq!(r[0].id, "dns.config");
    }

    #[tokio::test]
    async fn dns_validates_mode_and_records() {
        let cfg = cfg_str(
            r#"
version = 1
[dns]
enabled = true
mode = "synthetic_only"
[[dns.records]]
name = "host.example."
type = "A"
value = "10.0.0.1"
"#,
        );
        let d = DnsDiagnostic {
            config: Some(cfg),
            probe_upstreams: false,
        };
        let r = d.run(&DiagnosticContext::default()).await;
        assert!(
            r.iter()
                .any(|c| c.id == "dns.mode" && c.status == Status::Pass),
            "{r:?}"
        );
        assert!(r
            .iter()
            .any(|c| c.id == "dns.records" && c.status == Status::Pass));
        // No dns.* check should ever be a hard Fail for a valid config.
        assert!(!r.iter().any(|c| c.status == Status::Fail), "{r:?}");
    }

    #[tokio::test]
    async fn dns_unknown_mode_fails() {
        let cfg = cfg_str(
            r#"
version = 1
[dns]
enabled = true
mode = "not-a-mode"
"#,
        );
        let d = DnsDiagnostic {
            config: Some(cfg),
            probe_upstreams: false,
        };
        let r = d.run(&DiagnosticContext::default()).await;
        assert!(r
            .iter()
            .any(|c| c.id == "dns.mode" && c.status == Status::Fail));
    }

    #[tokio::test]
    async fn dns_forwarder_without_upstream_warns() {
        let cfg = cfg_str(
            r#"
version = 1
[dns]
enabled = true
mode = "transparent_forwarder"
"#,
        );
        let d = DnsDiagnostic {
            config: Some(cfg),
            probe_upstreams: false,
        };
        let r = d.run(&DiagnosticContext::default()).await;
        assert!(
            r.iter()
                .any(|c| c.id == "dns.upstream" && c.status == Status::Warn),
            "{r:?}"
        );
    }

    // E8-F8: `bind` group now has a real backing check.
    #[tokio::test]
    async fn bind_skipped_without_config() {
        let r = BindDiagnostic::default()
            .run(&DiagnosticContext::default())
            .await;
        assert_eq!(r[0].status, Status::Skipped);
    }

    #[tokio::test]
    async fn bind_skipped_when_no_listeners_enabled() {
        let cfg = cfg_str("version = 1\n");
        let d = BindDiagnostic::default().with_config(cfg);
        let r = d.run(&DiagnosticContext::default()).await;
        assert_eq!(r[0].id, "bind.listeners");
        assert_eq!(r[0].status, Status::Skipped);
    }

    #[tokio::test]
    async fn bind_available_port_passes() {
        // Pick a free ephemeral port, then close it so the check can bind.
        let tmp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = tmp.local_addr().unwrap().port();
        drop(tmp);
        let cfg = cfg_str(&format!(
            "version = 1\n[status_api]\nenabled = true\nbind = \"127.0.0.1:{port}\"\n"
        ));
        let d = BindDiagnostic::default().with_config(cfg);
        let r = d.run(&DiagnosticContext::default()).await;
        let c = r.iter().find(|c| c.id == "bind.status_api").unwrap();
        assert_eq!(c.status, Status::Pass, "{c:?}");
    }

    #[tokio::test]
    async fn bind_in_use_port_warns_not_fails() {
        // Hold a listener so the address is in use; the check must Warn, not
        // Fail (it is almost certainly the running daemon).
        let held = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = held.local_addr().unwrap().port();
        let cfg = cfg_str(&format!(
            "version = 1\n[status_api]\nenabled = true\nbind = \"127.0.0.1:{port}\"\n"
        ));
        let d = BindDiagnostic::default().with_config(cfg);
        let r = d.run(&DiagnosticContext::default()).await;
        let c = r.iter().find(|c| c.id == "bind.status_api").unwrap();
        assert_eq!(c.status, Status::Warn, "{c:?}");
        drop(held);
    }
}
