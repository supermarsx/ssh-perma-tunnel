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

use std::net::IpAddr;
use std::path::PathBuf;

use serde_json::json;
use spt_cli::groups::firewall::{
    FirewallGatewaySet, FirewallGatewayShow, FirewallPolicyList, FirewallPolicyScope,
    FirewallPolicySet, FirewallPolicyShow, FirewallPolicyUnset,
};
use spt_cli::GlobalOpts;
use spt_config::schema::{Config, Forward, Profile};
use spt_config::{BindingKind, PolicyValue};
use spt_core::{Error, Result};
use spt_firewall::{new_planner, Action, Direction, FirewallPlanner, Protocol, Rule};
use spt_net::bind::{resolve_bind, AutoPrefer, BindMode, Family};
use toml_edit::{value, Item, Table};

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

    let rules = compute_rules(&cfg, args.profile.as_deref(), args.forward.as_deref())?;
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

/// `spt firewall gateway show` — print configured gateway/interface policy.
pub async fn gateway_show(global: &GlobalOpts, args: FirewallGatewayShow) -> Result<()> {
    let path = require_config_path(global)?;
    let (cfg, _w) = spt_config::load(&path, false)
        .map_err(|e| Error::InvalidConfig(format!("load `{}`: {e}", path.display())))?;
    let network = cfg.network.clone().unwrap_or_default();
    let firewall = cfg.firewall.clone().unwrap_or_default();

    if args.json {
        let v = json!({
            "network": network,
            "firewall": {
                "default_interface": firewall.default_interface,
                "allow_all_interfaces": firewall.allow_all_interfaces,
                "bind_policy": firewall.bind_policy,
            },
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&v).map_err(|e| Error::RuntimeFailure(e.to_string()))?
        );
    } else {
        let interface = network.interface.as_ref();
        let gateway = network.gateway.as_ref();
        println!(
            "default interface: {}",
            interface
                .and_then(|i| i.default_interface.as_deref())
                .or(firewall.default_interface.as_deref())
                .unwrap_or("(unset)")
        );
        println!(
            "allowed interfaces: {}",
            format_list(interface.and_then(|i| i.allowed_interfaces.as_deref()))
        );
        println!(
            "allow all interfaces: {}",
            interface
                .and_then(|i| i.allow_all_interfaces)
                .or(firewall.allow_all_interfaces)
                .map_or("(unset)".to_string(), |v| v.to_string())
        );
        println!(
            "gateway: {}",
            gateway
                .and_then(|g| g.default_gateway.as_deref())
                .unwrap_or("(unset)")
        );
        println!(
            "gateway interface: {}",
            gateway
                .and_then(|g| g.interface.as_deref())
                .unwrap_or("(unset)")
        );
        println!(
            "route check target: {}",
            gateway
                .and_then(|g| g.route_check_target.as_deref())
                .unwrap_or("(unset)")
        );
        println!(
            "gateway policy: {}",
            gateway
                .and_then(|g| g.policy.as_deref())
                .unwrap_or("(unset)")
        );
    }
    Ok(())
}

/// `spt firewall gateway set` — comment-preserving update of `[network]`.
pub async fn gateway_set(global: &GlobalOpts, args: FirewallGatewaySet) -> Result<()> {
    if args.default_interface.is_none()
        && args.default_gateway.is_none()
        && args.gateway_interface.is_none()
        && args.route_check_target.is_none()
        && args.policy.is_none()
        && args.require_gateway_match.is_none()
    {
        return Err(Error::InvalidArgs(
            "provide at least one gateway/interface setting".into(),
        ));
    }

    let path = require_config_path(global)?;
    let mut doc = spt_config::mutate::Document::read(&path)?;
    let root = doc.document_mut().as_table_mut();
    let network = table_entry(root, "network")?;
    if let Some(default_interface) = args.default_interface.as_ref() {
        let interface = table_entry(network, "interface")?;
        interface["default_interface"] = value(default_interface.clone());
    }
    if args.default_gateway.is_some()
        || args.gateway_interface.is_some()
        || args.route_check_target.is_some()
        || args.policy.is_some()
        || args.require_gateway_match.is_some()
    {
        let gateway = table_entry(network, "gateway")?;
        if let Some(default_gateway) = args.default_gateway.as_ref() {
            gateway["default_gateway"] = value(default_gateway.clone());
        }
        if let Some(interface) = args.gateway_interface.as_ref() {
            gateway["interface"] = value(interface.clone());
        }
        if let Some(target) = args.route_check_target.as_ref() {
            gateway["route_check_target"] = value(target.clone());
        }
        if let Some(policy) = args.policy.as_ref() {
            gateway["policy"] = value(policy.clone());
        }
        if let Some(require) = args.require_gateway_match {
            gateway["require_gateway_match"] = value(require);
        }
    }
    doc.write_atomic(&path)?;

    if args.json {
        let v = json!({
            "updated": true,
            "path": path,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&v).map_err(|e| Error::RuntimeFailure(e.to_string()))?
        );
    } else {
        println!("updated {}", path.display());
    }
    Ok(())
}

/// `spt firewall policy list`.
pub async fn policy_list(_global: &GlobalOpts, args: FirewallPolicyList) -> Result<()> {
    if args.json {
        let rows = spt_config::BINDINGS
            .iter()
            .map(|binding| {
                json!({
                    "key": binding.key(),
                    "section": binding.section,
                    "name": binding.name,
                    "kind": binding.kind.as_str(),
                })
            })
            .collect::<Vec<_>>();
        println!(
            "{}",
            serde_json::to_string_pretty(&rows)
                .map_err(|e| Error::RuntimeFailure(e.to_string()))?
        );
    } else {
        for binding in spt_config::BINDINGS {
            println!("{}\t{}", binding.key(), binding.kind.as_str());
        }
    }
    Ok(())
}

/// `spt firewall policy show`.
pub async fn policy_show(global: &GlobalOpts, args: FirewallPolicyShow) -> Result<()> {
    let bundle = crate::policy::registry::load()
        .map_err(|e| Error::RuntimeFailure(format!("load policy registry: {e}")))?;
    let mut cfg = if let Some(path) = global.config.as_ref() {
        spt_config::load(path, false)
            .map_err(|e| Error::InvalidConfig(format!("load `{}`: {e}", path.display())))?
            .0
    } else {
        Config::default()
    };
    let report = spt_config::PolicyOverlay::apply(&mut cfg, &bundle);

    if args.json {
        let v = json!({
            "machine": policy_map_to_json(&bundle.machine),
            "user": policy_map_to_json(&bundle.user),
            "enforced": bundle.enforced.iter().cloned().collect::<Vec<_>>(),
            "overlay": {
                "applied": report.applied,
                "locked": report.locked,
                "unknown": report.unknown,
                "type_mismatch": report.type_mismatch,
            },
            "effective": {
                "network": cfg.network,
                "firewall": cfg.firewall,
                "capabilities": cfg.capabilities,
                "observability": cfg.observability,
            },
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&v).map_err(|e| Error::RuntimeFailure(e.to_string()))?
        );
    } else {
        println!("machine policies: {}", bundle.machine.len());
        for (key, value) in &bundle.machine {
            let enforced = if bundle.enforced.contains(key) {
                " enforced"
            } else {
                ""
            };
            println!("  {key} = {}{enforced}", policy_value_display(value));
        }
        println!("user policies: {}", bundle.user.len());
        for (key, value) in &bundle.user {
            println!("  {key} = {}", policy_value_display(value));
        }
        println!("applied: {}", format_list(Some(report.applied.as_slice())));
        println!("locked: {}", format_list(Some(report.locked.as_slice())));
        if !report.unknown.is_empty() {
            println!("unknown: {}", format_list(Some(report.unknown.as_slice())));
        }
        if !report.type_mismatch.is_empty() {
            println!(
                "type mismatch: {}",
                format_list(Some(report.type_mismatch.as_slice()))
            );
        }
    }
    Ok(())
}

/// `spt firewall policy set`.
pub async fn policy_set(global: &GlobalOpts, args: FirewallPolicySet) -> Result<()> {
    ensure_gpo_policy_write_allowed(global)?;
    let (section, name) = parse_policy_key(&args.key)?;
    let binding = spt_config::find_binding(&section, &name)
        .ok_or_else(|| Error::InvalidArgs(format!("unknown policy key `{}`", args.key)))?;
    let value = parse_policy_value(binding.kind, &args.value)?;
    let scope = registry_scope(args.scope);
    crate::policy::registry::set(scope, binding.section, binding.name, &value, args.enforced)
        .map_err(policy_registry_error)?;

    if args.json {
        let v = json!({
            "updated": true,
            "scope": policy_scope_name(args.scope),
            "key": binding.key(),
            "kind": binding.kind.as_str(),
            "value": policy_value_to_json(&value),
            "enforced": args.enforced,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&v).map_err(|e| Error::RuntimeFailure(e.to_string()))?
        );
    } else {
        println!(
            "set {} in {} policy{}",
            binding.key(),
            policy_scope_name(args.scope),
            if args.enforced {
                " (section enforced)"
            } else {
                ""
            }
        );
    }
    Ok(())
}

/// `spt firewall policy unset`.
pub async fn policy_unset(global: &GlobalOpts, args: FirewallPolicyUnset) -> Result<()> {
    ensure_gpo_policy_write_allowed(global)?;
    let (section, name) = parse_policy_key(&args.key)?;
    let binding = spt_config::find_binding(&section, &name)
        .ok_or_else(|| Error::InvalidArgs(format!("unknown policy key `{}`", args.key)))?;
    let scope = registry_scope(args.scope);
    crate::policy::registry::delete(scope, binding.section, binding.name, args.clear_enforced)
        .map_err(policy_registry_error)?;

    if args.json {
        let v = json!({
            "updated": true,
            "scope": policy_scope_name(args.scope),
            "key": binding.key(),
            "clear_enforced": args.clear_enforced,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&v).map_err(|e| Error::RuntimeFailure(e.to_string()))?
        );
    } else {
        println!(
            "unset {} in {} policy",
            binding.key(),
            policy_scope_name(args.scope)
        );
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

fn ensure_gpo_policy_write_allowed(global: &GlobalOpts) -> Result<()> {
    let mut cfg = if let Some(path) = global.config.as_ref() {
        spt_config::load(path, false)
            .map_err(|e| Error::InvalidConfig(format!("load `{}`: {e}", path.display())))?
            .0
    } else {
        Config::default()
    };

    if let Ok(bundle) = crate::policy::registry::load() {
        let _ = spt_config::PolicyOverlay::apply(&mut cfg, &bundle);
    }

    if matches!(
        cfg.capabilities
            .as_ref()
            .and_then(|cap| cap.allow_gpo_policy_writes),
        Some(false)
    ) {
        return Err(Error::PermissionDenied(
            "GPO policy writes are disabled by capabilities.allow_gpo_policy_writes".into(),
        ));
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

fn table_entry<'a>(table: &'a mut Table, name: &str) -> Result<&'a mut Table> {
    let item = table
        .entry(name)
        .or_insert_with(|| Item::Table(Table::new()));
    item.as_table_mut()
        .ok_or_else(|| Error::InvalidConfig(format!("[{name}] exists but is not a table")))
}

fn format_list(values: Option<&[String]>) -> String {
    match values {
        Some(values) if !values.is_empty() => values.join(","),
        _ => "(unset)".to_string(),
    }
}

fn policy_map_to_json(
    map: &std::collections::HashMap<String, PolicyValue>,
) -> serde_json::Map<String, serde_json::Value> {
    map.iter()
        .map(|(key, value)| (key.clone(), policy_value_to_json(value)))
        .collect()
}

fn policy_value_to_json(value: &PolicyValue) -> serde_json::Value {
    match value {
        PolicyValue::String(s) => json!(s),
        PolicyValue::Integer(i) => json!(i),
        PolicyValue::Bool(b) => json!(b),
        PolicyValue::MultiString(values) => json!(values),
    }
}

fn policy_value_display(value: &PolicyValue) -> String {
    match value {
        PolicyValue::String(s) => s.clone(),
        PolicyValue::Integer(i) => i.to_string(),
        PolicyValue::Bool(b) => b.to_string(),
        PolicyValue::MultiString(values) => values.join(","),
    }
}

fn parse_policy_key(key: &str) -> Result<(String, String)> {
    let (section, name) = key
        .split_once('\\')
        .or_else(|| key.split_once('/'))
        .or_else(|| key.split_once('.'))
        .ok_or_else(|| Error::InvalidArgs(format!("policy key `{key}` must be Section.Name")))?;
    if section.is_empty() || name.is_empty() {
        return Err(Error::InvalidArgs(format!(
            "policy key `{key}` must include section and name"
        )));
    }
    Ok((section.to_string(), name.to_string()))
}

fn parse_policy_value(kind: BindingKind, raw: &str) -> Result<PolicyValue> {
    match kind {
        BindingKind::String => Ok(PolicyValue::String(raw.to_string())),
        BindingKind::Bool => raw
            .parse::<bool>()
            .map(PolicyValue::Bool)
            .map_err(|_| Error::InvalidArgs(format!("`{raw}` is not a boolean"))),
        BindingKind::U32 => raw
            .parse::<u32>()
            .map(|n| PolicyValue::Integer(i64::from(n)))
            .map_err(|e| Error::InvalidArgs(format!("`{raw}` is not a u32: {e}"))),
        BindingKind::Allowlist => {
            let values = raw
                .split(',')
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_string)
                .collect::<Vec<_>>();
            if values.is_empty() {
                return Err(Error::InvalidArgs(
                    "multi-string policy values require at least one item".into(),
                ));
            }
            Ok(PolicyValue::MultiString(values))
        }
    }
}

fn registry_scope(scope: FirewallPolicyScope) -> crate::policy::registry::Scope {
    match scope {
        FirewallPolicyScope::Machine => crate::policy::registry::Scope::Machine,
        FirewallPolicyScope::User => crate::policy::registry::Scope::User,
    }
}

fn policy_scope_name(scope: FirewallPolicyScope) -> &'static str {
    match scope {
        FirewallPolicyScope::Machine => "machine",
        FirewallPolicyScope::User => "user",
    }
}

fn policy_registry_error(err: crate::policy::registry::Error) -> Error {
    match err {
        crate::policy::registry::Error::UnsupportedPlatform(msg) => Error::UnsupportedPlatform(msg),
        crate::policy::registry::Error::InvalidOperation(msg) => Error::InvalidArgs(msg),
        crate::policy::registry::Error::Io(msg) => Error::PermissionDenied(msg),
    }
}

/// Translate `[firewall]` + bind addresses into a flat `Vec<Rule>`. We include
/// per-forward "allow inbound on listen port" rules. This is a simplified
/// preview — the supervisor's runtime computation is the source of truth for
/// the actually-applied set.
fn compute_rules(
    cfg: &Config,
    profile_filter: Option<&str>,
    forward_filter: Option<&str>,
) -> Result<Vec<Rule>> {
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
            out.extend(forward_to_rules(prof, fwd)?);
        }
    }
    Ok(out)
}

fn forward_to_rules(profile: &Profile, fwd: &Forward) -> Result<Vec<Rule>> {
    // Accept either `bind` (canonical) or `listen` (alias).
    let Some(listen) = fwd.bind.as_deref().or(fwd.listen.as_deref()) else {
        return Ok(Vec::new());
    };
    let Some((host, port)) = parse_host_port(listen) else {
        return Ok(Vec::new());
    };
    let protocol = if fwd.transport.eq_ignore_ascii_case("udp") {
        Protocol::Udp
    } else {
        Protocol::Tcp
    };
    let bind_mode = bind_mode_from_forward(fwd, &host)?;
    let addrs = resolve_bind(&bind_mode, port)?;
    let interface = match &bind_mode {
        BindMode::SpecificInterface { name, .. } => Some(name.clone()),
        _ => fwd.bind_interface.clone(),
    };
    Ok(addrs
        .into_iter()
        .enumerate()
        .map(|(idx, addr)| Rule {
            id: format!("{}-{}-{}", profile.name, fwd.name, idx + 1),
            direction: Direction::In,
            action: Action::Allow,
            protocol,
            source_cidr: None,
            source_port: None,
            dest_cidr: cidr_for_ip(addr.ip()),
            dest_port: Some(port),
            interface: interface.clone(),
        })
        .collect())
}

fn bind_mode_from_forward(fwd: &Forward, host: &str) -> Result<BindMode> {
    let family = family_from_forward(fwd);
    match fwd.bind_mode.as_deref() {
        Some("loopback") => Ok(BindMode::Loopback),
        Some("specific_ip") => {
            let ip = host.parse::<IpAddr>().map_err(|e| {
                Error::InvalidConfig(format!(
                    "forward `{}` bind_mode specific_ip requires numeric bind host `{host}`: {e}",
                    fwd.name
                ))
            })?;
            Ok(BindMode::SpecificIp(ip))
        }
        Some("specific_interface") => {
            let name = fwd.bind_interface.clone().ok_or_else(|| {
                Error::InvalidConfig(format!(
                    "forward `{}` bind_mode specific_interface requires bind_interface",
                    fwd.name
                ))
            })?;
            Ok(BindMode::SpecificInterface { name, family })
        }
        Some("all_interfaces") => Ok(BindMode::AllInterfaces),
        Some("auto_interface") => Ok(BindMode::AutoInterface {
            prefer: auto_prefer_from_forward(fwd, family),
        }),
        Some(other) => Err(Error::InvalidConfig(format!(
            "forward `{}` bind_mode `{other}` is invalid",
            fwd.name
        ))),
        None if host == "*" || host == "0.0.0.0" || host == "::" => Ok(BindMode::AllInterfaces),
        None => {
            let ip = host.parse::<IpAddr>().map_err(|e| {
                Error::InvalidConfig(format!(
                    "forward `{}` bind host `{host}` must be an IP address for firewall preview: {e}",
                    fwd.name
                ))
            })?;
            Ok(BindMode::SpecificIp(ip))
        }
    }
}

fn auto_prefer_from_forward(fwd: &Forward, family: Family) -> AutoPrefer {
    if let Some(preferences) = fwd.bind_interface_preference.clone() {
        if !preferences.is_empty() {
            return AutoPrefer::Name(preferences);
        }
    }
    if let Some(name) = fwd.bind_interface.clone() {
        if !name.is_empty() {
            return AutoPrefer::Name(vec![name]);
        }
    }
    if !matches!(family, Family::Both) {
        return AutoPrefer::Family(family);
    }
    AutoPrefer::PlatformDefault
}

fn family_from_forward(fwd: &Forward) -> Family {
    match fwd.bind_ipv6.as_deref() {
        Some("disable") => Family::Ipv4,
        Some("prefer") => Family::Both,
        _ => Family::Both,
    }
}

fn cidr_for_ip(ip: IpAddr) -> Option<String> {
    if ip.is_unspecified() {
        None
    } else if ip.is_ipv6() {
        Some(format!("{ip}/128"))
    } else {
        Some(format!("{ip}/32"))
    }
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
    fn gpo_policy_write_gate_can_deny_cli_writes() {
        let mut f = NamedTempFile::new().unwrap();
        writeln!(
            f,
            r#"
version = 1

[capabilities]
allow_gpo_policy_writes = false
"#
        )
        .unwrap();
        let g = opts(Some(f.path().to_path_buf()));
        let err = ensure_gpo_policy_write_allowed(&g).unwrap_err();
        assert!(matches!(err, Error::PermissionDenied(_)));
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
        let all = compute_rules(&cfg, None, None).unwrap();
        assert_eq!(all.len(), 3);
        let only_p1 = compute_rules(&cfg, Some("p1"), None).unwrap();
        assert_eq!(only_p1.len(), 2);
        let only_f3 = compute_rules(&cfg, None, Some("f3")).unwrap();
        assert_eq!(only_f3.len(), 1);
        assert_eq!(only_f3[0].id, "p2-f3-1");
    }
}
