//! `spt firewall {status, bind-preview}` operations.
//!
//! `status` queries the per-OS planner's `query_active_rules()` (default impl
//! returns `UnsupportedPlatform`, which surfaces as a graceful error rather
//! than a panic) and prints the spt-managed rules currently installed.
//!
//! `bind-preview` loads the config, computes the rules that *would* be applied
//! were the supervisor to start, and prints them. It never shells out and does
//! not require admin.

#![allow(clippy::needless_pass_by_value)]
#![allow(clippy::missing_errors_doc)]

use std::path::PathBuf;

use serde_json::json;
use spt_cli::GlobalOpts;
use spt_config::schema::{Config, Forward, Profile};
use spt_core::{Error, Result};
use spt_firewall::{new_planner, Action, Direction, FirewallPlanner, Protocol, Rule};

/// Args for [`status`].
///
/// The Phase B dispatcher constructs this from `spt_cli::groups::firewall::FirewallStatus`.
#[derive(Debug, Default, Clone)]
pub struct FirewallStatusArgs {
    /// Emit JSON instead of plain text.
    pub json: bool,
}

/// Args for [`bind_preview`].
///
/// Per the brief: optional `--profile` and `--forward` filters. The actual
/// `spt_cli::groups::firewall::FirewallBindPreview` only carries a
/// `<profile>/<forward>` pair, which the dispatcher splits into these fields.
#[derive(Debug, Default, Clone)]
pub struct FirewallBindPreviewArgs {
    /// Filter to a single profile by id.
    pub profile: Option<String>,
    /// Filter to a single forward by id (within the profile if `profile` set).
    pub forward: Option<String>,
    /// Emit JSON instead of plain text.
    pub json: bool,
}

// ---------------------------------------------------------------------------
// Public entry points
// ---------------------------------------------------------------------------

/// `spt firewall status` — list the spt-managed rules currently active on the
/// host.
pub async fn status(_global: &GlobalOpts, args: FirewallStatusArgs) -> Result<()> {
    let planner = new_planner()?;
    match planner.query_active_rules() {
        Ok(rules) => emit_status(args.json, &rules, planner.as_ref()),
        Err(Error::UnsupportedPlatform(msg)) => {
            // Distinguish "live query unsupported" from "permission denied".
            // Either way the brief asks us to surface gracefully and exit !=0.
            Err(Error::UnsupportedPlatform(format!(
                "no permission to query active rules ({msg})"
            )))
        }
        Err(other) => Err(other),
    }
}

/// `spt firewall bind-preview` — render the rules that *would* be installed
/// for the given (profile, forward) selection without applying.
pub async fn bind_preview(global: &GlobalOpts, args: FirewallBindPreviewArgs) -> Result<()> {
    let path = require_config_path(global)?;
    let (cfg, _w) = spt_config::load(&path, false)
        .map_err(|e| Error::InvalidConfig(format!("load `{}`: {e}", path.display())))?;

    let rules = compute_rules(&cfg, args.profile.as_deref(), args.forward.as_deref());
    let planner = new_planner()?;
    let plan = planner.plan(&rules);

    if args.json {
        let v = json!({
            "manager": format!("{:?}", plan.manager),
            "rule_count": plan.rule_count,
            "tag_prefix": plan.tag_prefix,
            "rules": rules.iter().map(rule_to_json).collect::<Vec<_>>(),
            "script": plan.script,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&v).map_err(|e| Error::RuntimeFailure(e.to_string()))?
        );
    } else {
        println!("manager: {:?}", plan.manager);
        println!("rules:   {}", plan.rule_count);
        println!("tag:     {}", plan.tag_prefix);
        println!("---");
        print!("{}", plan.script);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn emit_status(json: bool, rules: &[String], planner: &dyn FirewallPlanner) -> Result<()> {
    // The planner trait is type-erased; we don't have a manager handle from
    // the empty plan here, so we render an empty plan to discover the
    // manager discriminator and tag prefix.
    let probe = planner.plan(&[]);
    if json {
        let v = json!({
            "manager": format!("{:?}", probe.manager),
            "tag_prefix": probe.tag_prefix,
            "active_rule_count": rules.len(),
            "active_rules": rules,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&v).map_err(|e| Error::RuntimeFailure(e.to_string()))?
        );
    } else {
        println!("manager: {:?}", probe.manager);
        println!("tag:     {}", probe.tag_prefix);
        println!("active:  {}", rules.len());
        for r in rules {
            println!("  {r}");
        }
        if rules.is_empty() {
            println!("(no spt-managed rules currently installed)");
        }
        println!("hint:    {}", manager_command_hint(probe.manager));
    }
    Ok(())
}

fn manager_command_hint(m: spt_firewall::Manager) -> &'static str {
    match m {
        spt_firewall::Manager::Nftables => "nft list ruleset (filtered by spt: tag)",
        spt_firewall::Manager::Iptables => "iptables -L -v -n (filtered by spt: comment)",
        spt_firewall::Manager::Pf => "pfctl -s rules -a com.spt",
        spt_firewall::Manager::WindowsFirewall => {
            "netsh advfirewall firewall show rule name=\"spt:*\""
        }
    }
}

fn rule_to_json(r: &Rule) -> serde_json::Value {
    json!({
        "id": r.id,
        "direction": r.direction.to_string(),
        "action": r.action.to_string(),
        "protocol": r.protocol.to_string(),
        "source_cidr": r.source_cidr,
        "source_port": r.source_port,
        "dest_cidr": r.dest_cidr,
        "dest_port": r.dest_port,
        "interface": r.interface,
    })
}

/// Translate `[firewall]` + bind addresses into a flat `Vec<Rule>`. We include
/// per-forward "allow inbound on listen port" rules. This is a simplified
/// preview — the supervisor's runtime computation is the source of truth for
/// the actually-applied set.
fn compute_rules(
    cfg: &Config,
    profile_filter: Option<&str>,
    forward_filter: Option<&str>,
) -> Vec<Rule> {
    let mut out = Vec::new();
    for prof in &cfg.profiles {
        if let Some(p) = profile_filter {
            if prof.name != p {
                continue;
            }
        }
        for fwd in &prof.forwards {
            if let Some(f) = forward_filter {
                if fwd.name != f {
                    continue;
                }
            }
            if let Some(rule) = forward_to_rule(prof, fwd) {
                out.push(rule);
            }
        }
    }
    out
}

fn forward_to_rule(profile: &Profile, fwd: &Forward) -> Option<Rule> {
    // Accept either `bind` (canonical) or `listen` (alias).
    let listen = fwd.bind.as_deref().or(fwd.listen.as_deref())?;
    let (host, port) = parse_host_port(listen)?;
    let protocol = if fwd.transport.eq_ignore_ascii_case("udp") {
        Protocol::Udp
    } else {
        Protocol::Tcp
    };
    let dest_cidr = if host == "0.0.0.0" || host == "*" || host == "::" {
        None
    } else {
        Some(format!("{host}/32"))
    };
    Some(Rule {
        id: format!("{}-{}", profile.name, fwd.name),
        direction: Direction::In,
        action: Action::Allow,
        protocol,
        source_cidr: None,
        source_port: None,
        dest_cidr,
        dest_port: Some(port),
        interface: None,
    })
}

fn parse_host_port(s: &str) -> Option<(String, u16)> {
    // Support "host:port" and "[v6]:port".
    if let Some(rest) = s.strip_prefix('[') {
        let close = rest.find(']')?;
        let host = &rest[..close];
        let port_str = rest[close + 1..].strip_prefix(':')?;
        let port = port_str.parse().ok()?;
        return Some((host.to_string(), port));
    }
    let (host, port) = s.rsplit_once(':')?;
    Some((host.to_string(), port.parse().ok()?))
}

fn require_config_path(global: &GlobalOpts) -> Result<PathBuf> {
    global.config.clone().ok_or_else(|| {
        Error::InvalidArgs("no config path supplied (pass --config or set $SPT_CONFIG)".into())
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use spt_cli::{ColorMode, LogLevel, OutputFormat};
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn opts(config: Option<PathBuf>) -> GlobalOpts {
        GlobalOpts {
            config,
            config_dir: None,
            config_url: None,
            config_fingerprint: None,
            state_dir: None,
            profile: None,
            output: OutputFormat::Human,
            json: false,
            log_level: LogLevel::Info,
            color: ColorMode::Never,
            quiet: true,
            verbose: 0,
            no_color: true,
            dry_run: false,
        }
    }

    fn write_min_config() -> NamedTempFile {
        let mut f = NamedTempFile::new().unwrap();
        writeln!(
            f,
            r#"
version = 1

[[profiles]]
name = "edge"
protocol = "ssh2"
host = "example.com"
port = 22
enabled = true

[[profiles.forwards]]
name = "db"
type = "local"
transport = "tcp"
listen = "127.0.0.1:5432"
target = "internal:5432"
"#
        )
        .unwrap();
        f
    }

    #[tokio::test(flavor = "current_thread")]
    async fn bind_preview_renders_rules_for_configured_forward() {
        let f = write_min_config();
        let g = opts(Some(f.path().to_path_buf()));
        let args = FirewallBindPreviewArgs {
            profile: Some("edge".to_string()),
            forward: Some("db".to_string()),
            json: true,
        };
        bind_preview(&g, args).await.expect("preview ok");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn bind_preview_errors_without_config() {
        let g = opts(None);
        let args = FirewallBindPreviewArgs::default();
        let err = bind_preview(&g, args).await.unwrap_err();
        assert!(matches!(err, Error::InvalidArgs(_)));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn status_returns_unsupported_when_planner_default_impl_used() {
        // The default `query_active_rules` impl returns UnsupportedPlatform.
        // We don't override it in any per-OS planner shipped today, so the
        // command surfaces a graceful error rather than panicking.
        let g = opts(None);
        let args = FirewallStatusArgs::default();
        let err = status(&g, args).await.unwrap_err();
        assert!(matches!(err, Error::UnsupportedPlatform(_)));
    }

    #[test]
    fn parse_host_port_accepts_v4_and_bracketed_v6() {
        assert_eq!(
            parse_host_port("127.0.0.1:5432"),
            Some(("127.0.0.1".into(), 5432))
        );
        assert_eq!(parse_host_port("[::1]:80"), Some(("::1".into(), 80)));
        assert_eq!(parse_host_port("nope"), None);
    }

    #[test]
    fn compute_rules_filters_by_profile_and_forward() {
        let s = r#"
version = 1
[[profiles]]
name = "p1"
protocol = "ssh2"
host = "h1"
port = 22
[[profiles.forwards]]
name = "f1"
type = "local"
transport = "tcp"
listen = "127.0.0.1:1111"
target = "internal:1"
[[profiles.forwards]]
name = "f2"
type = "local"
transport = "tcp"
listen = "127.0.0.1:2222"
target = "internal:2"
[[profiles]]
name = "p2"
protocol = "ssh2"
host = "h2"
port = 22
[[profiles.forwards]]
name = "f3"
type = "local"
transport = "tcp"
listen = "127.0.0.1:3333"
target = "internal:3"
"#;
        let (cfg, _) = spt_config::load_str(s, false).unwrap();
        let all = compute_rules(&cfg, None, None);
        assert_eq!(all.len(), 3);
        let only_p1 = compute_rules(&cfg, Some("p1"), None);
        assert_eq!(only_p1.len(), 2);
        let only_f3 = compute_rules(&cfg, None, Some("f3"));
        assert_eq!(only_f3.len(), 1);
        assert_eq!(only_f3[0].id, "p2-f3");
    }
}
