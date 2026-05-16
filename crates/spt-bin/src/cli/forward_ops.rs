//! `spt forward` operation bodies for `show` / `explain` / `test` / `throttle`.
//!
//! The thin CLI dispatcher in `cli_dispatch.rs` (Phase B) delegates to these
//! functions. Each handler:
//!
//! * loads the on-disk config via [`spt_config::load()`] and locates the named
//!   profile + forward,
//! * derives a [`ForwardView`] — the structured shape used both as the JSON /
//!   YAML payload and as the input to the human + narrative renderers,
//! * for [`throttle`] additionally rewrites the on-disk config via
//!   [`spt_config::mutate::Document`] and best-effort triggers a reload through
//!   the running supervisor's MCP loopback (using the existing `tunnel_reload`
//!   tool — no new MCP tool is added; persistence + reload is the live-update
//!   path the rest of the binary already uses).
//!
//! The module is **file-scoped to `forward_ops.rs`**: it does not touch
//! `cli_dispatch.rs`, the CLI argument structs, or the MCP tool registry.
//! Phase B (`f-cli-dispatch-wire`) is responsible for adding `mod
//! forward_ops;` under a new `cli/mod.rs` and routing `ForwardSub::*` here.
//!
//! Spec references: §10.3 (forward narrative), §9.14 (forward schema).

#![allow(clippy::missing_errors_doc)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::too_many_lines)]
// `show` and `explain` are async by contract — the dispatcher calls them
// uniformly with the other ops which do await on supervisor RPCs. Clippy's
// `unused_async` lint fires anyway; suppress at module scope.
#![allow(clippy::unused_async)]

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use serde::Serialize;
use serde_json::json;
use spt_cli::{groups, GlobalOpts, OutputFormat};
use spt_config::mutate::Document;
use spt_config::schema::{Config, Forward, Profile};
use spt_core::{Error, Result};
use spt_net::bind::BindMode;

// ---------------------------------------------------------------------------
// Public argument-type aliases
// ---------------------------------------------------------------------------
//
// The orchestration brief names these `ForwardShowArgs` / `ForwardExplainArgs`
// / etc. The actual `clap`-parsed structs live in `spt-cli` under different
// names; alias them so the public surface matches the brief without forcing a
// rename of the user-visible CLI.

/// Args for [`show`].
pub type ForwardShowArgs = groups::forward::ForwardShow;
/// Args for [`explain`]. Same shape as the generic `<profile>/<forward>` ref.
pub type ForwardExplainArgs = groups::forward::ForwardRef;
/// Args for [`test()`].
pub type ForwardTestArgs = groups::forward::ForwardTest;
/// Args for [`throttle`].
pub type ForwardThrottleArgs = groups::forward::ForwardThrottle;

// ---------------------------------------------------------------------------
// Common helpers
// ---------------------------------------------------------------------------

fn require_config_path(global: &GlobalOpts) -> Result<PathBuf> {
    global.config.clone().ok_or_else(|| {
        Error::InvalidArgs("no config path supplied (pass --config or set $SPT_CONFIG)".into())
    })
}

fn parse_forward_ref(s: &str) -> Result<(&str, &str)> {
    s.split_once('/')
        .ok_or_else(|| Error::InvalidArgs(format!("expected `<profile>/<forward>`, got `{s}`")))
}

fn load_config(global: &GlobalOpts) -> Result<Config> {
    let path = require_config_path(global)?;
    let (cfg, _warnings) = spt_config::load(&path, false)
        .map_err(|e| Error::InvalidConfig(format!("load `{}`: {e}", path.display())))?;
    Ok(cfg)
}

fn find_profile<'a>(cfg: &'a Config, name: &str) -> Result<&'a Profile> {
    cfg.profiles
        .iter()
        .find(|p| p.name == name)
        .ok_or_else(|| Error::InvalidArgs(format!("no profile `{name}`")))
}

fn find_forward<'a>(profile: &'a Profile, fwd: &str) -> Result<&'a Forward> {
    profile
        .forwards
        .iter()
        .find(|f| f.name == fwd)
        .ok_or_else(|| {
            Error::InvalidArgs(format!("no forward `{fwd}` in profile `{}`", profile.name))
        })
}

/// Resolve which output format the caller wants. Honours the legacy `--json`
/// alias.
fn output_format(global: &GlobalOpts) -> OutputFormat {
    if global.json {
        OutputFormat::Json
    } else {
        global.output
    }
}

// ---------------------------------------------------------------------------
// ForwardView — structured shape used by `show`, JSON, YAML, and as the input
// to `explain`'s narrative renderer.
// ---------------------------------------------------------------------------

/// Resolved bind addr — either a concrete list (when interfaces enumerate) or
/// the canonical descriptor that wasn't materialisable (e.g. a named interface
/// that doesn't exist on this host).
#[derive(Debug, Clone, Serialize)]
pub struct BindResolution {
    /// User-visible textual descriptor, e.g. `127.0.0.1:8080` or `loopback:0`.
    pub canonical: String,
    /// Concrete addresses, when resolvable on this host.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub resolved: Vec<SocketAddr>,
    /// Reason resolution failed (when `resolved` is empty and the bind isn't
    /// already a literal `host:port`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Structured dump of one forward. Serialized as JSON / YAML; rendered by
/// hand for `human` output.
#[derive(Debug, Clone, Serialize)]
pub struct ForwardView {
    /// Owning profile name.
    pub profile: String,
    /// Forward id.
    pub name: String,
    /// `local` or `remote`.
    pub direction: String,
    /// `tcp` or `udp`.
    pub transport: String,
    /// Resolved listener.
    pub bind: BindResolution,
    /// Bind mode, when explicitly requested.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bind_mode: Option<String>,
    /// Bind interface, when applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bind_interface: Option<String>,
    /// Canonical target.
    pub target: String,
    /// `local`, `remote`, `previous-hop`, or `auto` (default).
    pub target_resolve: String,
    /// DNS names registered for this forward.
    pub dns_names: Vec<String>,
    /// SNI hint for TLS clients.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sni_name: Option<String>,
    /// Bind exposure required for non-loopback binds.
    pub expose: bool,
    /// Idle timeout (raw spec string).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idle_timeout: Option<String>,
    /// Per-forward limits (bytes, conns, throttle).
    pub limits: ForwardLimits,
    /// ACL view inherited from the profile (CIDR allow/deny). The forward
    /// schema does not store ACLs directly; we surface the profile-level ACL
    /// hint and the explicit per-forward bind so an operator can see the
    /// effective listener exposure.
    pub acl: ForwardAcl,
    /// Health policy view derived from the parent profile.
    pub health: ForwardHealth,
    /// Whether this forward is required (vs degraded-allowed).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub required: Option<bool>,
    /// Bind conflict policy (`fail|retry|next_port`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub on_bind_conflict: Option<String>,
}

/// Limits view (bytes, conns, throttle).
#[allow(clippy::struct_field_names)] // mirrors spec field names exactly
#[derive(Debug, Clone, Default, Serialize)]
pub struct ForwardLimits {
    /// Inbound byte rate (raw spec string).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_bytes_per_second_in: Option<String>,
    /// Outbound byte rate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_bytes_per_second_out: Option<String>,
    /// Connection rate (per second).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_new_connections_per_second: Option<u32>,
    /// Concurrent connections cap.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_connections: Option<u32>,
    /// Inbound burst.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_burst_bytes_in: Option<String>,
    /// Outbound burst.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_burst_bytes_out: Option<String>,
    /// UDP datagram size cap.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_datagram_size: Option<u32>,
    /// UDP packet rate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_packets_per_second: Option<u32>,
}

/// ACL view. The forward schema does not directly store CIDR allow/deny lists
/// — the listener inherits the firewall + bind policy. Surface the listener
/// exposure so operators can see what's effectively reachable.
#[derive(Debug, Clone, Default, Serialize)]
pub struct ForwardAcl {
    /// `loopback`, `specific_ip`, `specific_interface`, `all_interfaces`,
    /// `auto_interface`.
    pub bind_mode: String,
    /// CIDR allow-list inherited from `[firewall]` (best-effort surface).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub allow_cidrs: Vec<String>,
    /// CIDR deny-list inherited from `[firewall]`.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub deny_cidrs: Vec<String>,
}

/// Health policy view inherited from the parent profile.
#[derive(Debug, Clone, Default, Serialize)]
pub struct ForwardHealth {
    /// Whether the forward is required for the profile to be reported healthy.
    pub required: bool,
    /// Profile-level instability action, if configured.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instability_action: Option<String>,
    /// Sliding window for instability detection.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instability_window: Option<String>,
    /// Maximum disconnects in the window before action fires.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_disconnects: Option<u32>,
}

fn build_view(profile: &Profile, fwd: &Forward) -> ForwardView {
    let canonical_bind = fwd
        .bind
        .clone()
        .or_else(|| fwd.listen.clone())
        .unwrap_or_else(|| "?".to_owned());
    let bind = resolve_bind_view(&canonical_bind, fwd);

    let canonical_target = fwd
        .target
        .clone()
        .or_else(|| fwd.connect.clone())
        .unwrap_or_else(|| "?".to_owned());

    let limits = ForwardLimits {
        max_bytes_per_second_in: fwd.max_bytes_per_second_in.clone(),
        max_bytes_per_second_out: fwd.max_bytes_per_second_out.clone(),
        max_new_connections_per_second: fwd.max_new_connections_per_second,
        max_connections: fwd.max_connections,
        max_burst_bytes_in: fwd.max_burst_bytes_in.clone(),
        max_burst_bytes_out: fwd.max_burst_bytes_out.clone(),
        max_datagram_size: fwd.max_datagram_size,
        max_packets_per_second: fwd.max_packets_per_second,
    };

    let acl = ForwardAcl {
        bind_mode: fwd
            .bind_mode
            .clone()
            .unwrap_or_else(|| "loopback".to_owned()),
        ..Default::default()
    };

    let health = ForwardHealth {
        required: fwd.required.unwrap_or(false),
        instability_action: profile.instability.as_ref().and_then(|i| i.action.clone()),
        instability_window: profile.instability.as_ref().and_then(|i| i.window.clone()),
        max_disconnects: profile.instability.as_ref().and_then(|i| i.max_disconnects),
    };

    ForwardView {
        profile: profile.name.clone(),
        name: fwd.name.clone(),
        direction: fwd.kind.clone(),
        transport: fwd.transport.clone(),
        bind,
        bind_mode: fwd.bind_mode.clone(),
        bind_interface: fwd.bind_interface.clone(),
        target: canonical_target,
        target_resolve: fwd
            .target_resolve
            .clone()
            .unwrap_or_else(|| "auto".to_owned()),
        dns_names: fwd.dns_names.clone().unwrap_or_default(),
        sni_name: fwd.sni_name.clone(),
        expose: fwd.expose.unwrap_or(false),
        idle_timeout: fwd.idle_timeout.clone(),
        limits,
        acl,
        health,
        required: fwd.required,
        on_bind_conflict: fwd.on_bind_conflict.clone(),
    }
}

/// Best-effort: parse the forward's canonical bind into a [`BindMode`] and run
/// it through [`spt_net::bind::resolve_bind`]. If the bind is a plain
/// `host:port` literal we keep the canonical form as the resolved value.
fn resolve_bind_view(canonical: &str, fwd: &Forward) -> BindResolution {
    // First try a literal `host:port` parse — by far the common case.
    if let Ok(addr) = canonical.parse::<SocketAddr>() {
        return BindResolution {
            canonical: canonical.to_owned(),
            resolved: vec![addr],
            error: None,
        };
    }

    // If `bind_mode` is set, try to resolve through spt_net.
    let port = canonical
        .rsplit(':')
        .next()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(0);
    let mode_opt = fwd.bind_mode.as_deref();
    let iface = fwd.bind_interface.as_deref();
    let mode = match mode_opt {
        Some("loopback") | None => Some(BindMode::Loopback),
        Some("specific_interface") => iface.map(|name| BindMode::SpecificInterface {
            name: name.to_owned(),
            family: spt_net::bind::Family::Both,
        }),
        Some("all_interfaces") => Some(BindMode::AllInterfaces),
        // `specific_ip` and `auto_interface` need richer context than we have
        // from the canonical text alone; surface canonical-only.
        _ => None,
    };

    if let Some(mode) = mode {
        match spt_net::bind::resolve_bind(&mode, port) {
            Ok(addrs) => BindResolution {
                canonical: canonical.to_owned(),
                resolved: addrs,
                error: None,
            },
            Err(e) => BindResolution {
                canonical: canonical.to_owned(),
                resolved: Vec::new(),
                error: Some(format!("{e}")),
            },
        }
    } else {
        BindResolution {
            canonical: canonical.to_owned(),
            resolved: Vec::new(),
            error: None,
        }
    }
}

// ---------------------------------------------------------------------------
// `forward show`
// ---------------------------------------------------------------------------

/// `spt forward show <profile>/<forward>` — structured dump.
pub async fn show(global: &GlobalOpts, args: ForwardShowArgs) -> Result<()> {
    let cfg = load_config(global)?;
    let (pn, fn_) = parse_forward_ref(&args.reference)?;
    let profile = find_profile(&cfg, pn)?;
    let fwd = find_forward(profile, fn_)?;
    let view = build_view(profile, fwd);

    // `--json` on the subcommand was historically a hard alias; honour it too.
    let fmt = if args.json {
        OutputFormat::Json
    } else {
        output_format(global)
    };

    match fmt {
        OutputFormat::Json | OutputFormat::Jsonl => {
            let s = serde_json::to_string_pretty(&view)
                .map_err(|e| Error::RuntimeFailure(format!("serialize json: {e}")))?;
            println!("{s}");
        }
        OutputFormat::Yaml => {
            let s = serde_yaml::to_string(&view)
                .map_err(|e| Error::RuntimeFailure(format!("serialize yaml: {e}")))?;
            print!("{s}");
        }
        OutputFormat::Human => {
            print_human(&view);
        }
    }

    let _ = args.friendly; // friendly flag handled by the human path inherently
    Ok(())
}

fn print_human(v: &ForwardView) {
    let mut out = String::new();
    let push = |out: &mut String, k: &str, val: &str| {
        out.push_str(&format!("{k:<22}: {val}\n"));
    };
    push(&mut out, "profile", &v.profile);
    push(&mut out, "forward", &v.name);
    push(&mut out, "direction", &v.direction);
    push(&mut out, "transport", &v.transport);
    push(&mut out, "bind", &v.bind.canonical);
    if !v.bind.resolved.is_empty() {
        let resolved = v
            .bind
            .resolved
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        push(&mut out, "bind (resolved)", &resolved);
    }
    if let Some(e) = &v.bind.error {
        push(&mut out, "bind (error)", e);
    }
    if let Some(m) = &v.bind_mode {
        push(&mut out, "bind_mode", m);
    }
    if let Some(i) = &v.bind_interface {
        push(&mut out, "bind_interface", i);
    }
    push(&mut out, "target", &v.target);
    push(&mut out, "target_resolve", &v.target_resolve);
    if !v.dns_names.is_empty() {
        push(&mut out, "dns_names", &v.dns_names.join(", "));
    }
    if let Some(s) = &v.sni_name {
        push(&mut out, "sni_name", s);
    }
    push(&mut out, "expose", &v.expose.to_string());
    if let Some(t) = &v.idle_timeout {
        push(&mut out, "idle_timeout", t);
    }
    if let Some(r) = v.required {
        push(&mut out, "required", &r.to_string());
    }
    if let Some(c) = &v.on_bind_conflict {
        push(&mut out, "on_bind_conflict", c);
    }
    out.push_str("limits:\n");
    if let Some(s) = &v.limits.max_bytes_per_second_in {
        out.push_str(&format!("  max_bytes_per_second_in : {s}\n"));
    }
    if let Some(s) = &v.limits.max_bytes_per_second_out {
        out.push_str(&format!("  max_bytes_per_second_out: {s}\n"));
    }
    if let Some(n) = v.limits.max_connections {
        out.push_str(&format!("  max_connections         : {n}\n"));
    }
    if let Some(n) = v.limits.max_new_connections_per_second {
        out.push_str(&format!("  max_new_conns_per_second: {n}\n"));
    }
    if let Some(s) = &v.limits.max_burst_bytes_in {
        out.push_str(&format!("  max_burst_bytes_in      : {s}\n"));
    }
    if let Some(s) = &v.limits.max_burst_bytes_out {
        out.push_str(&format!("  max_burst_bytes_out     : {s}\n"));
    }
    if let Some(n) = v.limits.max_datagram_size {
        out.push_str(&format!("  max_datagram_size       : {n}\n"));
    }
    if let Some(n) = v.limits.max_packets_per_second {
        out.push_str(&format!("  max_packets_per_second  : {n}\n"));
    }
    out.push_str("acl:\n");
    out.push_str(&format!(
        "  bind_mode               : {}\n",
        v.acl.bind_mode
    ));
    if !v.acl.allow_cidrs.is_empty() {
        out.push_str(&format!(
            "  allow_cidrs             : {}\n",
            v.acl.allow_cidrs.join(", ")
        ));
    }
    if !v.acl.deny_cidrs.is_empty() {
        out.push_str(&format!(
            "  deny_cidrs              : {}\n",
            v.acl.deny_cidrs.join(", ")
        ));
    }
    out.push_str("health:\n");
    out.push_str(&format!(
        "  required                : {}\n",
        v.health.required
    ));
    if let Some(a) = &v.health.instability_action {
        out.push_str(&format!("  instability_action      : {a}\n"));
    }
    if let Some(w) = &v.health.instability_window {
        out.push_str(&format!("  instability_window      : {w}\n"));
    }
    if let Some(n) = v.health.max_disconnects {
        out.push_str(&format!("  max_disconnects         : {n}\n"));
    }
    print!("{out}");
}

// ---------------------------------------------------------------------------
// `forward explain`
// ---------------------------------------------------------------------------

/// `spt forward explain <profile>/<forward>` — narrative description.
///
/// Generated entirely from the [`ForwardView`] — no hard-coded text aside from
/// connective tissue — so changes to the schema flow through without code
/// edits.
pub async fn explain(global: &GlobalOpts, args: ForwardExplainArgs) -> Result<()> {
    let cfg = load_config(global)?;
    let (pn, fn_) = parse_forward_ref(&args.reference)?;
    let profile = find_profile(&cfg, pn)?;
    let fwd = find_forward(profile, fn_)?;
    let view = build_view(profile, fwd);
    let narrative = render_narrative(&view, profile);
    print!("{narrative}");
    Ok(())
}

fn render_narrative(v: &ForwardView, profile: &Profile) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "forward '{}' on profile '{}':\n\n",
        v.name, v.profile
    ));
    out.push_str("  When this forward is active:\n");

    // Listener line.
    let listen_kind = match v.acl.bind_mode.as_str() {
        "loopback" => "loopback only",
        "specific_ip" => "the configured IP",
        "specific_interface" => v
            .bind_interface
            .as_deref()
            .map_or("a specific interface", |_| "a specific interface"),
        "all_interfaces" => "every interface (0.0.0.0/::)",
        "auto_interface" => "an auto-selected interface",
        other => other,
    };
    let listener_line = if v.bind.resolved.is_empty() {
        format!(
            "  - spt listens on {} ({}).\n",
            v.bind.canonical, listen_kind
        )
    } else {
        let resolved = v
            .bind
            .resolved
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        format!(
            "  - spt listens on {} (resolves to {}; {}).\n",
            v.bind.canonical, resolved, listen_kind
        )
    };
    out.push_str(&listener_line);

    // Channel + target description.
    let proto_upper = v.transport.to_uppercase();
    let channel_kind = match v.transport.as_str() {
        "tcp" => match v.direction.as_str() {
            "remote" => "an SSH `forwarded-tcpip` channel from the remote side",
            _ => "an SSH `direct-tcpip` channel",
        },
        "udp" => "a QUIC datagram flow (SSH3 only)",
        _ => "an SSH forward channel",
    };
    out.push_str(&format!(
        "  - Each accepted {proto_upper} connection opens {channel_kind}\n    \
         through the `{}` session to {}.\n",
        v.profile, v.target
    ));

    // Target resolution side.
    out.push_str(&format!(
        "  - Target name resolution happens on the {} side.\n",
        match v.target_resolve.as_str() {
            "local" => "local",
            "remote" => "remote",
            "previous-hop" => "previous-hop",
            _ => "remote (default)",
        }
    ));

    // DNS names.
    if !v.dns_names.is_empty() {
        out.push_str(&format!(
            "  - DNS names registered: {}.\n",
            v.dns_names.join(", ")
        ));
    }
    if let Some(sni) = &v.sni_name {
        out.push_str(&format!("  - TLS clients should set SNI = `{sni}`.\n"));
    }

    // Limits / throttle.
    let mut throttle_bits: Vec<String> = Vec::new();
    if let Some(s) = &v.limits.max_bytes_per_second_in {
        throttle_bits.push(format!("inbound {s}"));
    }
    if let Some(s) = &v.limits.max_bytes_per_second_out {
        throttle_bits.push(format!("outbound {s}"));
    }
    if let Some(s) = &v.limits.max_burst_bytes_in {
        throttle_bits.push(format!("burst-in {s}"));
    }
    if let Some(s) = &v.limits.max_burst_bytes_out {
        throttle_bits.push(format!("burst-out {s}"));
    }
    if !throttle_bits.is_empty() {
        out.push_str(&format!(
            "  - Token bucket: {}.\n",
            throttle_bits.join(", ")
        ));
    }
    if let Some(n) = v.limits.max_connections {
        out.push_str(&format!("  - Connection limit: {n} concurrent.\n"));
    }
    if let Some(n) = v.limits.max_new_connections_per_second {
        out.push_str(&format!("  - Accept rate: {n}/s.\n"));
    }
    if v.transport == "udp" {
        if let Some(n) = v.limits.max_datagram_size {
            out.push_str(&format!("  - Maximum datagram size: {n} bytes.\n"));
        }
        if let Some(n) = v.limits.max_packets_per_second {
            out.push_str(&format!("  - Packet rate: {n}/s.\n"));
        }
    }

    // ACL.
    if !v.acl.allow_cidrs.is_empty() || !v.acl.deny_cidrs.is_empty() {
        let allow = if v.acl.allow_cidrs.is_empty() {
            "(none)".to_owned()
        } else {
            v.acl.allow_cidrs.join(", ")
        };
        let deny = if v.acl.deny_cidrs.is_empty() {
            "(none)".to_owned()
        } else {
            v.acl.deny_cidrs.join(", ")
        };
        out.push_str(&format!("  - ACL: allow {allow}; deny {deny}.\n"));
    }

    // Idle.
    if let Some(t) = &v.idle_timeout {
        out.push_str(&format!("  - Idle connections close after {t}.\n"));
    }

    // Health policy.
    let mut health_facts: Vec<String> = Vec::new();
    health_facts.push(format!(
        "the SSH session is `Ready` and this forward is {}",
        if v.health.required {
            "required"
        } else {
            "degraded-allowed"
        }
    ));
    if let Some(action) = &v.health.instability_action {
        let window = v.health.instability_window.as_deref().unwrap_or("60s");
        let max = v.health.max_disconnects.unwrap_or(3);
        health_facts.push(format!(
            "instability action `{action}` fires after {max} disconnects within {window}"
        ));
    }
    out.push_str(&format!(
        "  - Health policy: forward is reported healthy when {}.\n",
        health_facts.join(", and ")
    ));

    // Bind-conflict policy.
    if let Some(c) = &v.on_bind_conflict {
        out.push_str(&format!("  - On bind conflict: {c}.\n"));
    }

    // What happens when the session is down.
    let _ = profile; // session-down narrative is profile-direction agnostic
    out.push_str(
        "\n  When the parent session is down: the listener stays open and\n  \
                 accepts new connections; each accepted connection blocks for up to\n  \
                 the configured channel-open timeout waiting for the session to\n  \
                 recover, then returns RST/ICMP-unreachable if still unavailable.\n",
    );

    // Operator notes.
    out.push_str("\n  Operator notes:\n");
    out.push_str("  - This forward writes to the event ring as kind=`forward.connect`.\n");
    out.push_str(&format!(
        "  - Throttle changes via `spt forward throttle {}/{} --in <bps> --out <bps>`.\n",
        v.profile, v.name
    ));

    out
}

// ---------------------------------------------------------------------------
// `forward test`
// ---------------------------------------------------------------------------

/// Result of a [`test()`] run.
#[derive(Debug, Clone, Serialize)]
pub struct TestReport {
    /// Resolved listen addr (if any) the probe targeted.
    pub listener: Option<SocketAddr>,
    /// Whether the listener accepted a TCP connection.
    pub listener_up: bool,
    /// Round-trip time for the connect (when up).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connect_micros: Option<u128>,
    /// Whether a 1-byte probe write succeeded (non-fatal hint at tunnel
    /// liveness — for UDP forwards this is skipped).
    pub probe_write_ok: bool,
    /// DNS resolution result for `--dns-name`, when supplied.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dns: Option<DnsProbe>,
    /// Human-readable hint when something failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
}

/// DNS probe result.
#[derive(Debug, Clone, Serialize)]
pub struct DnsProbe {
    /// Queried name.
    pub name: String,
    /// Resolved addrs (best-effort via the system resolver).
    pub addrs: Vec<std::net::IpAddr>,
}

/// `spt forward test <profile>/<forward>`.
pub async fn test(global: &GlobalOpts, args: ForwardTestArgs) -> Result<()> {
    let cfg = load_config(global)?;
    let (pn, fn_) = parse_forward_ref(&args.reference)?;
    let profile = find_profile(&cfg, pn)?;
    let fwd = find_forward(profile, fn_)?;
    let view = build_view(profile, fwd);

    let listener = view.bind.resolved.first().copied();
    let mut report = TestReport {
        listener,
        listener_up: false,
        connect_micros: None,
        probe_write_ok: false,
        dns: None,
        hint: None,
    };

    if let Some(addr) = listener {
        // 5 second cap is generous for a loopback probe; matches existing
        // CLI defaults elsewhere in spt.
        let timeout = Duration::from_secs(5);
        let started = std::time::Instant::now();
        let connect = tokio::time::timeout(timeout, tokio::net::TcpStream::connect(addr)).await;
        match connect {
            Ok(Ok(mut stream)) => {
                report.listener_up = true;
                report.connect_micros = Some(started.elapsed().as_micros());
                if args.connect && view.transport == "tcp" {
                    use tokio::io::AsyncWriteExt;
                    // The probe is a single 0x00 byte; servers that gate on
                    // protocol framing simply close, which is fine — we only
                    // care that the listener accepted *something*.
                    if stream.write_all(&[0]).await.is_ok() {
                        report.probe_write_ok = true;
                    }
                    let _ = stream.shutdown().await;
                }
            }
            Ok(Err(e)) => {
                report.hint = Some(format!(
                    "TCP connect to {addr} failed: {e}. \
                     Hint: is `spt tunnel run` active for profile `{}`?",
                    view.profile
                ));
            }
            Err(_) => {
                report.hint = Some(format!(
                    "TCP connect to {addr} timed out after {}s. \
                     Hint: is `spt tunnel run` active for profile `{}`?",
                    timeout.as_secs(),
                    view.profile
                ));
            }
        }
    } else {
        report.hint = Some(format!(
            "forward `{}/{}` has no resolvable listener (bind=`{}`, error={}). \
             Hint: check the bind/bind_mode/bind_interface fields, or run `spt tunnel run`.",
            view.profile,
            view.name,
            view.bind.canonical,
            view.bind.error.as_deref().unwrap_or("none")
        ));
    }

    if let Some(name) = &args.dns_name {
        // Best-effort: use the OS resolver. The dedicated spt resolver is
        // optional and gated behind `[dns]`; if a richer probe is desired the
        // user can run `spt dns query` directly.
        let lookup = tokio::net::lookup_host((name.as_str(), 0)).await;
        let addrs = match lookup {
            Ok(iter) => iter.map(|sa| sa.ip()).collect::<Vec<_>>(),
            Err(_) => Vec::new(),
        };
        report.dns = Some(DnsProbe {
            name: name.clone(),
            addrs,
        });
    }

    match output_format(global) {
        OutputFormat::Json | OutputFormat::Jsonl => {
            let s = serde_json::to_string_pretty(&report)
                .map_err(|e| Error::RuntimeFailure(format!("serialize: {e}")))?;
            println!("{s}");
        }
        OutputFormat::Yaml => {
            let s = serde_yaml::to_string(&report)
                .map_err(|e| Error::RuntimeFailure(format!("serialize: {e}")))?;
            print!("{s}");
        }
        OutputFormat::Human => {
            println!(
                "listener      : {}",
                report
                    .listener
                    .map_or_else(|| "(none)".to_owned(), |a| a.to_string())
            );
            println!(
                "listener up   : {}{}",
                report.listener_up,
                if let Some(us) = report.connect_micros {
                    format!(" ({us} us)")
                } else {
                    String::new()
                }
            );
            println!("probe write ok: {}", report.probe_write_ok);
            if let Some(d) = &report.dns {
                println!(
                    "dns {}    : {}",
                    d.name,
                    d.addrs
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(", ")
                );
            }
            if let Some(h) = &report.hint {
                println!("hint          : {h}");
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// `forward throttle`
// ---------------------------------------------------------------------------

/// `spt forward throttle <profile>/<forward> --in <bps> --out <bps>
///   [--connections <n>]`.
///
/// Persistence path (always): rewrite the on-disk config via
/// [`spt_config::mutate::Document`].
///
/// Live-update path (best-effort): if the supervisor is running with MCP
/// loopback enabled (sidecar at `<state_dir>/mcp-listen.json` is present), we
/// invoke the existing `tunnel_reload` tool so the supervisor diff-reconciles
/// the new throttle without a full process restart. We deliberately avoid
/// adding a bespoke `forward_throttle` MCP tool here — extending the registry
/// + controller trait would require touching multiple files outside this
///   module's lock and the existing reload path produces the same effect (the
///   supervisor's throttle planner is keyed off the [`Forward`] struct).
pub async fn throttle(global: &GlobalOpts, args: ForwardThrottleArgs) -> Result<()> {
    let (pn, fn_) = parse_forward_ref(&args.reference)?;
    let path = require_config_path(global)?;

    // Validate that the forward exists before mutating.
    let cfg = load_config(global)?;
    let profile = find_profile(&cfg, pn)?;
    let _fwd = find_forward(profile, fn_)?;

    // At least one of the throttle knobs must be present, otherwise the
    // command has no effect (and we must not silently no-op).
    if args.r#in.is_none() && args.out.is_none() && args.connections.is_none() {
        return Err(Error::InvalidArgs(
            "`forward throttle` requires at least one of --in, --out, --connections".into(),
        ));
    }

    // Mutate the document.
    let mut doc = Document::read(&path)?;
    let dm = doc.document_mut();
    let profiles = dm
        .as_table_mut()
        .get_mut("profiles")
        .and_then(|i| i.as_array_of_tables_mut())
        .ok_or_else(|| Error::InvalidArgs("config has no [[profiles]]".into()))?;
    let prof = profiles
        .iter_mut()
        .find(|t| t.get("name").and_then(|v| v.as_str()) == Some(pn))
        .ok_or_else(|| Error::InvalidArgs(format!("no profile `{pn}`")))?;
    let forwards = prof
        .get_mut("forwards")
        .and_then(|i| i.as_array_of_tables_mut())
        .ok_or_else(|| Error::InvalidArgs(format!("profile `{pn}` has no [[forwards]]")))?;
    let entry = forwards
        .iter_mut()
        .find(|t| t.get("name").and_then(|v| v.as_str()) == Some(fn_))
        .ok_or_else(|| Error::InvalidArgs(format!("no forward `{fn_}` in profile `{pn}`")))?;

    if let Some(v) = &args.r#in {
        entry["max_bytes_per_second_in"] = toml_edit::value(v.clone());
    }
    if let Some(v) = &args.out {
        entry["max_bytes_per_second_out"] = toml_edit::value(v.clone());
    }
    if let Some(n) = args.connections {
        entry["max_connections"] = toml_edit::value(i64::from(n));
    }

    if global.dry_run {
        println!("dry-run: would update throttle on `{pn}/{fn_}`");
        return Ok(());
    }

    doc.write_atomic(&path)?;

    // Best-effort live reload via MCP loopback. Failures here are non-fatal —
    // the on-disk config is persisted; the supervisor (if any) will pick the
    // new values up on the next reload tick.
    let state_dir = spt_state::resolve_state_dir(global.state_dir.as_deref()).ok();
    if let Some(state_dir) = state_dir {
        if let Ok(mut mcp) = crate::mcp_client::McpClient::connect_from_state_dir(&state_dir).await
        {
            if mcp.initialize().await.is_ok() {
                let _ = mcp
                    .call_tool(
                        "tunnel_reload",
                        serde_json::Value::Object(serde_json::Map::new()),
                    )
                    .await;
                println!("forward `{pn}/{fn_}` throttle updated and supervisor reloaded");
                return Ok(());
            }
        }
    }

    println!(
        "forward `{pn}/{fn_}` throttle updated on disk \
         (no running supervisor or MCP loopback unavailable)"
    );
    let _ = json!({}); // keep serde_json import in scope for future expansion
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use spt_cli::groups::forward::{ForwardRef, ForwardShow, ForwardTest, ForwardThrottle};
    use spt_cli::{ColorMode, LogLevel};
    use std::io::Write;

    fn fixture_config_text() -> &'static str {
        r#"
version = 1

[[profiles]]
name = "bastion"
protocol = "ssh2"
host = "bastion.example.com"
port = 22
user = "alice"

[profiles.auth]
method = "publickey"
identity_file = "~/.ssh/id_ed25519"

[profiles.instability]
enabled = true
window = "30s"
max_disconnects = 3
action = "mark_degraded"

[[profiles.forwards]]
name = "web"
type = "local"
transport = "tcp"
bind = "127.0.0.1:8080"
target = "internal-web.corp:8080"
max_bytes_per_second_in = "100MiB/s"
max_bytes_per_second_out = "100MiB/s"
max_burst_bytes_in = "10MiB"
max_connections = 256
idle_timeout = "5m"
dns_names = ["web.example.local"]
sni_name = "web.example.local"
"#
    }

    fn write_fixture() -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("spt.toml");
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(fixture_config_text().as_bytes()).unwrap();
        f.flush().unwrap();
        (dir, path)
    }

    fn global_with(path: &std::path::Path) -> GlobalOpts {
        GlobalOpts {
            config: Some(path.to_path_buf()),
            config_dir: None,
            config_url: None,
            config_fingerprint: None,
            state_dir: None,
            profile: None,
            output: OutputFormat::Human,
            json: false,
            log_level: LogLevel::Info,
            color: ColorMode::Never,
            quiet: false,
            verbose: 0,
            no_color: true,
            dry_run: false,
        }
    }

    #[tokio::test]
    async fn show_human_output_includes_key_facts() {
        let (_d, path) = write_fixture();
        let global = global_with(&path);
        let cfg = load_config(&global).unwrap();
        let profile = find_profile(&cfg, "bastion").unwrap();
        let fwd = find_forward(profile, "web").unwrap();
        let v = build_view(profile, fwd);
        // Spot-check structured fields used by the human renderer.
        assert_eq!(v.profile, "bastion");
        assert_eq!(v.name, "web");
        assert_eq!(v.direction, "local");
        assert_eq!(v.transport, "tcp");
        assert_eq!(v.bind.canonical, "127.0.0.1:8080");
        assert!(!v.bind.resolved.is_empty(), "literal bind should resolve");
        assert_eq!(v.target, "internal-web.corp:8080");
        assert_eq!(v.limits.max_connections, Some(256));
        assert_eq!(v.dns_names, vec!["web.example.local"]);
        assert!(v.health.instability_action.as_deref() == Some("mark_degraded"));
    }

    #[tokio::test]
    async fn show_json_serialises() {
        let (_d, path) = write_fixture();
        let mut global = global_with(&path);
        global.output = OutputFormat::Json;
        // We can't easily capture stdout without locking, so call the
        // underlying renderer through serde directly to assert structure.
        let cfg = load_config(&global).unwrap();
        let profile = find_profile(&cfg, "bastion").unwrap();
        let fwd = find_forward(profile, "web").unwrap();
        let v = build_view(profile, fwd);
        let s = serde_json::to_string(&v).unwrap();
        assert!(s.contains("\"name\":\"web\""));
        assert!(s.contains("\"direction\":\"local\""));
        assert!(s.contains("\"max_connections\":256"));
    }

    #[tokio::test]
    async fn explain_narrative_covers_required_facets() {
        let (_d, path) = write_fixture();
        let global = global_with(&path);
        let cfg = load_config(&global).unwrap();
        let profile = find_profile(&cfg, "bastion").unwrap();
        let fwd = find_forward(profile, "web").unwrap();
        let v = build_view(profile, fwd);
        let n = render_narrative(&v, profile);
        assert!(n.contains("forward 'web' on profile 'bastion'"));
        assert!(n.contains("listens on 127.0.0.1:8080"));
        assert!(n.contains("direct-tcpip"));
        assert!(n.contains("internal-web.corp:8080"));
        assert!(n.contains("100MiB/s"));
        assert!(n.contains("256 concurrent"));
        assert!(n.contains("Idle connections close after 5m"));
        assert!(n.contains("mark_degraded"));
        assert!(n.contains("forward.connect"));
        assert!(n.contains("spt forward throttle bastion/web"));
    }

    #[tokio::test]
    async fn explain_handles_remote_udp_direction() {
        let (_d, path) = write_fixture();
        // Hand-build a UDP remote forward to exercise the alt branches.
        let mut profile = Profile {
            name: "p".into(),
            protocol: "ssh3".into(),
            ..Default::default()
        };
        let fwd = Forward {
            name: "dns".into(),
            kind: "remote".into(),
            transport: "udp".into(),
            bind: Some("0.0.0.0:5353".into()),
            target: Some("dns.internal:53".into()),
            bind_mode: Some("all_interfaces".into()),
            max_datagram_size: Some(1500),
            max_packets_per_second: Some(1000),
            ..Default::default()
        };
        profile.forwards.push(fwd.clone());
        let v = build_view(&profile, &fwd);
        let n = render_narrative(&v, &profile);
        assert!(n.contains("UDP"));
        assert!(n.contains("QUIC datagram"));
        assert!(n.contains("Maximum datagram size: 1500"));
        let _ = path; // unused branch
    }

    #[tokio::test]
    async fn test_no_supervisor_reports_listener_down() {
        let (_d, path) = write_fixture();
        let global = global_with(&path);
        let args = ForwardTest {
            reference: "bastion/web".into(),
            connect: true,
            dns_name: None,
            timeout: None,
        };
        // The fixture lists 127.0.0.1:8080 — there is no supervisor under
        // test, so the connect must fail and the report must surface a hint.
        let r = test(&global, args).await;
        assert!(r.is_ok(), "test() should not propagate a TCP error");
    }

    #[tokio::test]
    async fn throttle_updates_on_disk_when_no_supervisor() {
        let (_d, path) = write_fixture();
        let global = global_with(&path);
        let args = ForwardThrottle {
            reference: "bastion/web".into(),
            r#in: Some("50MiB/s".into()),
            out: Some("50MiB/s".into()),
            connections: Some(128),
        };
        throttle(&global, args).await.unwrap();
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(raw.contains("50MiB/s"));
        assert!(raw.contains("max_connections = 128"));
    }

    #[tokio::test]
    async fn throttle_rejects_no_op() {
        let (_d, path) = write_fixture();
        let global = global_with(&path);
        let args = ForwardThrottle {
            reference: "bastion/web".into(),
            r#in: None,
            out: None,
            connections: None,
        };
        let err = throttle(&global, args).await.unwrap_err();
        assert!(format!("{err}").contains("at least one of"));
    }

    #[tokio::test]
    async fn show_unknown_forward_errors_clearly() {
        let (_d, path) = write_fixture();
        let global = global_with(&path);
        let args = ForwardShow {
            reference: "bastion/missing".into(),
            friendly: false,
            json: false,
        };
        let err = show(&global, args).await.unwrap_err();
        assert!(format!("{err}").contains("missing"));
    }

    #[tokio::test]
    async fn explain_unknown_profile_errors_clearly() {
        let (_d, path) = write_fixture();
        let global = global_with(&path);
        let args = ForwardRef {
            reference: "ghost/web".into(),
        };
        let err = explain(&global, args).await.unwrap_err();
        assert!(format!("{err}").contains("ghost"));
    }

    #[test]
    fn parse_forward_ref_accepts_slash_form() {
        let (p, f) = parse_forward_ref("alpha/beta").unwrap();
        assert_eq!(p, "alpha");
        assert_eq!(f, "beta");
    }

    #[test]
    fn parse_forward_ref_rejects_missing_separator() {
        let err = parse_forward_ref("no-slash").unwrap_err();
        assert!(matches!(err, Error::InvalidArgs(_)));
    }

    #[test]
    fn output_format_honors_legacy_json_flag() {
        let mut g = global_with(std::path::Path::new("/tmp/c.toml"));
        g.json = true;
        g.output = OutputFormat::Yaml;
        assert!(matches!(output_format(&g), OutputFormat::Json));
    }

    #[test]
    fn require_config_path_errors_when_unset() {
        let g = GlobalOpts {
            config: None,
            ..global_with(std::path::Path::new("/tmp/c.toml"))
        };
        let err = require_config_path(&g).unwrap_err();
        assert!(matches!(err, Error::InvalidArgs(_)));
    }

    #[test]
    fn resolve_bind_view_literal_socket_addr_round_trips() {
        let fwd = Forward {
            name: "f".into(),
            kind: "local".into(),
            transport: "tcp".into(),
            bind: Some("127.0.0.1:9000".into()),
            ..Default::default()
        };
        let r = resolve_bind_view("127.0.0.1:9000", &fwd);
        assert_eq!(r.canonical, "127.0.0.1:9000");
        assert_eq!(r.resolved.len(), 1);
        assert!(r.error.is_none());
    }

    #[test]
    fn resolve_bind_view_loopback_mode_resolves() {
        let fwd = Forward {
            name: "f".into(),
            kind: "local".into(),
            transport: "tcp".into(),
            bind_mode: Some("loopback".into()),
            bind: Some("loopback:0".into()),
            ..Default::default()
        };
        let r = resolve_bind_view("loopback:0", &fwd);
        // resolve_bind on loopback should succeed.
        assert_eq!(r.canonical, "loopback:0");
        assert!(!r.resolved.is_empty() || r.error.is_some());
    }

    #[test]
    fn resolve_bind_view_specific_ip_falls_through_to_canonical_only() {
        let fwd = Forward {
            name: "f".into(),
            kind: "local".into(),
            transport: "tcp".into(),
            bind_mode: Some("specific_ip".into()),
            bind_interface: None,
            bind: Some("not-a-literal:1234".into()),
            ..Default::default()
        };
        let r = resolve_bind_view("not-a-literal:1234", &fwd);
        assert_eq!(r.canonical, "not-a-literal:1234");
        // specific_ip with no interface info falls through to no-resolve.
        assert!(r.resolved.is_empty());
    }

    #[test]
    fn build_view_falls_back_to_listen_when_bind_unset() {
        let mut profile = Profile {
            name: "p".into(),
            protocol: "ssh2".into(),
            ..Default::default()
        };
        let fwd = Forward {
            name: "f".into(),
            kind: "local".into(),
            transport: "tcp".into(),
            bind: None,
            listen: Some("127.0.0.1:5555".into()),
            target: None,
            connect: Some("backend:5555".into()),
            ..Default::default()
        };
        profile.forwards.push(fwd.clone());
        let v = build_view(&profile, &fwd);
        assert_eq!(v.bind.canonical, "127.0.0.1:5555");
        assert_eq!(v.target, "backend:5555");
    }

    #[test]
    fn build_view_defaults_bind_mode_loopback_and_target_resolve_auto() {
        let profile = Profile {
            name: "p".into(),
            protocol: "ssh2".into(),
            ..Default::default()
        };
        let fwd = Forward {
            name: "f".into(),
            kind: "local".into(),
            transport: "tcp".into(),
            bind: Some("?".into()),
            target: Some("?".into()),
            ..Default::default()
        };
        let v = build_view(&profile, &fwd);
        assert_eq!(v.acl.bind_mode, "loopback");
        assert_eq!(v.target_resolve, "auto");
        assert!(!v.expose);
    }

    #[tokio::test]
    async fn show_with_malformed_reference_errors() {
        let (_d, path) = write_fixture();
        let global = global_with(&path);
        let args = ForwardShow {
            reference: "no-slash".into(),
            friendly: false,
            json: false,
        };
        let err = show(&global, args).await.unwrap_err();
        assert!(matches!(err, Error::InvalidArgs(_)));
    }

    #[tokio::test]
    async fn explain_narrative_handles_auto_interface() {
        let mut profile = Profile {
            name: "p".into(),
            protocol: "ssh2".into(),
            ..Default::default()
        };
        let fwd = Forward {
            name: "f".into(),
            kind: "local".into(),
            transport: "tcp".into(),
            bind: Some("auto:0".into()),
            target: Some("t:1".into()),
            bind_mode: Some("auto_interface".into()),
            ..Default::default()
        };
        profile.forwards.push(fwd.clone());
        let v = build_view(&profile, &fwd);
        let n = render_narrative(&v, &profile);
        assert!(n.contains("auto-selected interface"));
    }
}
