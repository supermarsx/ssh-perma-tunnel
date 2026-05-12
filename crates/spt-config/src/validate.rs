//! Semantic validation of a [`Config`].
//!
//! [`validate`] returns a [`Diagnostics`] bundle. Callers decide how to surface
//! the errors and warnings (CLI prints, MCP responses, status snapshots, …).
//!
//! ### Checks performed
//!
//! 1. `version == 1`.
//! 2. Profile `name` uniqueness.
//! 3. Forward `name` uniqueness within each profile.
//! 4. Endpoint `name` uniqueness within each profile.
//! 5. Protocol value (`ssh2` | `ssh3`).
//! 6. SSH3 `acknowledge_experimental = true` (spec §14.7).
//! 7. SSH2 profiles must set `host`; SSH3 profiles must set `endpoint`.
//! 8. `bind` and `target` addresses are parseable by `spt_core::BindAddr`.
//! 9. UDP transport requires `protocol = "ssh3"` (spec §10.4).
//! 10. Non-loopback binds require `expose = true` (spec §9.14).
//! 11. Secret references match `secret://<ns>/<name>` shape.
//! 12. DNS bind on a privileged port (<1024) is warned.
//! 13. Firewall planner mismatch with current OS warns.
//! 14. `forward.type` is `local|remote`; `transport` is `tcp|udp`.
//! 15. Duration / size string fields parse via `spt_core` helpers.
//! 16. `runtime.remote_config.url` (when enabled) must be an HTTPS URL with a
//!     `fingerprint_sha256` set (spec §14.3).

use spt_core::{address::BindAddr, duration::parse_duration, size::parse_size};

use crate::diagnostic::{Diagnostic, Diagnostics};
use crate::schema::{Auth, Config, Forward, Profile};

/// Validate a [`Config`]. Always returns a [`Diagnostics`] bundle — the caller
/// decides whether `errors.is_empty()` is success.
#[must_use]
pub fn validate(c: &Config) -> Diagnostics {
    let mut d = Diagnostics::new();

    check_version(&mut d, c);
    check_runtime(&mut d, c);
    check_dns(&mut d, c);
    check_firewall(&mut d, c);
    check_mcp(&mut d, c);
    check_profiles(&mut d, c);

    d
}

fn check_version(d: &mut Diagnostics, c: &Config) {
    if c.version != 1 {
        d.push(
            Diagnostic::error(
                "version_unsupported",
                format!("config version `{}` is not supported (only `1`)", c.version),
            )
            .at("version")
            .with_help("set `version = 1` at the top of the file"),
        );
    }
}

fn check_runtime(d: &mut Diagnostics, c: &Config) {
    let Some(rt) = c.runtime.as_ref() else { return };

    if let Some(rc) = rt.remote_config.as_ref() {
        if matches!(rc.enabled, Some(true)) {
            match rc.url.as_deref() {
                None | Some("") => d.push(
                    Diagnostic::error(
                        "remote_config_missing_url",
                        "remote_config.enabled = true requires `url`",
                    )
                    .at("runtime.remote_config.url"),
                ),
                Some(url) if !url.starts_with("https://") => d.push(
                    Diagnostic::error(
                        "remote_config_not_https",
                        format!("remote_config.url `{url}` must be HTTPS"),
                    )
                    .at("runtime.remote_config.url"),
                ),
                _ => {}
            }
            if rc.fingerprint_sha256.as_deref().unwrap_or("").is_empty() {
                d.push(
                    Diagnostic::warning(
                        "remote_config_no_pin",
                        "remote_config.fingerprint_sha256 is unset; unattended fetch will be refused",
                    )
                    .at("runtime.remote_config.fingerprint_sha256"),
                );
            }
        }
    }

    check_duration_field(d, rt.shutdown_grace.as_deref(), "runtime.shutdown_grace");

    if let Some(threads) = rt.threads.as_ref() {
        if let Some(model) = threads.model.as_deref() {
            if !matches!(model, "multi_thread" | "single_thread_for_tests") {
                d.push(
                    Diagnostic::error(
                        "threads_model_invalid",
                        format!("`{model}` is not a valid threading model"),
                    )
                    .at("runtime.threads.model"),
                );
            }
        }
        check_duration_field(d, threads.idle_tick.as_deref(), "runtime.threads.idle_tick");
    }

    if let Some(reload) = rt.reload.as_ref() {
        if let Some(mode) = reload.mode.as_deref() {
            if !matches!(mode, "none" | "signal" | "watch" | "service") {
                d.push(
                    Diagnostic::error(
                        "reload_mode_invalid",
                        format!("`{mode}` is not a valid reload mode"),
                    )
                    .at("runtime.reload.mode"),
                );
            }
        }
        check_duration_field(d, reload.debounce.as_deref(), "runtime.reload.debounce");
    }
}

fn check_dns(d: &mut Diagnostics, c: &Config) {
    let Some(dns) = c.dns.as_ref() else { return };

    if let Some(bind) = dns.bind.as_deref() {
        match BindAddr::parse(bind) {
            Ok(BindAddr::Tcp(sock)) => {
                if matches!(dns.enabled, Some(true)) && sock.port() < 1024 {
                    d.push(
                        Diagnostic::warning(
                            "dns_privileged_port",
                            format!(
                                "dns.bind `{bind}` uses privileged port {} — requires root/admin",
                                sock.port()
                            ),
                        )
                        .at("dns.bind")
                        .with_help("use `127.0.0.1:5353` for unprivileged operation"),
                    );
                }
            }
            Ok(_) => {}
            Err(e) => d.push(
                Diagnostic::error("dns_bind_invalid", format!("dns.bind `{bind}`: {e}"))
                    .at("dns.bind"),
            ),
        }
    }

    if let Some(mode) = dns.mode.as_deref() {
        if !matches!(
            mode,
            "disabled" | "transparent_forwarder" | "synthetic_only" | "hosts_file"
        ) {
            d.push(
                Diagnostic::error(
                    "dns_mode_invalid",
                    format!("`{mode}` is not a valid dns.mode"),
                )
                .at("dns.mode"),
            );
        }
    }

    for (i, rec) in dns.records.iter().enumerate() {
        if !matches!(rec.kind.as_str(), "A" | "AAAA" | "SRV" | "TXT") {
            d.push(
                Diagnostic::error(
                    "dns_record_kind_invalid",
                    format!("`{}` is not a valid DNS record type", rec.kind),
                )
                .at(format!("dns.records[{i}].type")),
            );
        }
    }
}

fn check_firewall(d: &mut Diagnostics, c: &Config) {
    let Some(fw) = c.firewall.as_ref() else {
        return;
    };
    let Some(plat) = fw.platform.as_ref() else {
        return;
    };

    let here = std::env::consts::OS;
    let mismatch = |key: &str, val: &Option<String>, expected: &[&str]| -> Option<Diagnostic> {
        let v = val.as_deref()?;
        if v == "auto" || v.is_empty() {
            return None;
        }
        if !expected.contains(&v) {
            return Some(
                Diagnostic::warning(
                    "firewall_platform_mismatch",
                    format!(
                        "firewall.platform.{key} = `{v}` is unusual on this OS (running on `{here}`)"
                    ),
                )
                .at(format!("firewall.platform.{key}")),
            );
        }
        None
    };

    if let Some(diag) = mismatch(
        "linux",
        &plat.linux,
        &["auto", "nftables", "iptables", "none"],
    ) {
        d.push(diag);
    }
    if let Some(diag) = mismatch("macos", &plat.macos, &["pf", "none"]) {
        d.push(diag);
    }
    if let Some(diag) = mismatch("windows", &plat.windows, &["windows_firewall", "none"]) {
        d.push(diag);
    }
}

fn check_mcp(d: &mut Diagnostics, c: &Config) {
    let Some(mcp) = c.mcp.as_ref() else { return };

    if let Some(listen) = mcp.listen.as_deref() {
        if !listen.is_empty() {
            match BindAddr::parse(listen) {
                Ok(BindAddr::Tcp(sock)) => {
                    let is_loopback = sock.ip().is_loopback();
                    if !is_loopback && !matches!(mcp.expose, Some(true)) {
                        d.push(
                            Diagnostic::error(
                                "mcp_non_loopback_requires_expose",
                                format!(
                                    "mcp.listen = `{listen}` is non-loopback; set `expose = true`"
                                ),
                            )
                            .at("mcp.listen"),
                        );
                    }
                }
                Ok(_) => {}
                Err(e) => d.push(
                    Diagnostic::error("mcp_listen_invalid", format!("mcp.listen `{listen}`: {e}"))
                        .at("mcp.listen"),
                ),
            }
        }
    }

    if matches!(mcp.allow_secret_reveal, Some(true)) {
        d.push(
            Diagnostic::error(
                "mcp_secret_reveal_disallowed",
                "mcp.allow_secret_reveal must remain false (spec §9.8/§16)",
            )
            .at("mcp.allow_secret_reveal"),
        );
    }
}

fn check_profiles(d: &mut Diagnostics, c: &Config) {
    let mut seen_names: Vec<&str> = Vec::with_capacity(c.profiles.len());
    for (i, p) in c.profiles.iter().enumerate() {
        if seen_names.contains(&p.name.as_str()) {
            d.push(
                Diagnostic::error(
                    "duplicate_profile_id",
                    format!("profile name `{}` is not unique", p.name),
                )
                .at(format!("profiles[{i}].name")),
            );
        } else {
            seen_names.push(&p.name);
        }
        check_profile(d, i, p);
    }
}

fn check_profile(d: &mut Diagnostics, i: usize, p: &Profile) {
    let prefix = format!("profiles[{i}]");

    match p.protocol.as_str() {
        "ssh2" => {
            if p.host.as_deref().unwrap_or("").is_empty() && p.endpoints.is_empty() {
                d.push(
                    Diagnostic::error(
                        "ssh2_missing_host",
                        format!(
                            "ssh2 profile `{}` requires `host` or at least one endpoint",
                            p.name
                        ),
                    )
                    .at(format!("{prefix}.host")),
                );
            }
        }
        "ssh3" => {
            if p.endpoint.as_deref().unwrap_or("").is_empty() {
                d.push(
                    Diagnostic::error(
                        "ssh3_missing_endpoint",
                        format!("ssh3 profile `{}` requires `endpoint`", p.name),
                    )
                    .at(format!("{prefix}.endpoint")),
                );
            }
            if !matches!(p.acknowledge_experimental, Some(true)) {
                d.push(
                    Diagnostic::error(
                        "ssh3_experimental_unack",
                        format!(
                            "ssh3 profile `{}` must set `acknowledge_experimental = true` (spec §14.7)",
                            p.name
                        ),
                    )
                    .at(format!("{prefix}.acknowledge_experimental")),
                );
            }
        }
        other => d.push(
            Diagnostic::error(
                "protocol_invalid",
                format!("profile `{}` has unknown protocol `{other}`", p.name),
            )
            .at(format!("{prefix}.protocol")),
        ),
    }

    // Endpoints uniqueness.
    let mut ep_names: Vec<&str> = Vec::with_capacity(p.endpoints.len());
    for (j, ep) in p.endpoints.iter().enumerate() {
        if ep_names.contains(&ep.name.as_str()) {
            d.push(
                Diagnostic::error(
                    "duplicate_endpoint_id",
                    format!(
                        "endpoint name `{}` not unique within profile `{}`",
                        ep.name, p.name
                    ),
                )
                .at(format!("{prefix}.endpoints[{j}].name")),
            );
        } else {
            ep_names.push(&ep.name);
        }
        if ep.host.is_empty() {
            d.push(
                Diagnostic::error(
                    "endpoint_missing_host",
                    format!("endpoint `{}` has empty host", ep.name),
                )
                .at(format!("{prefix}.endpoints[{j}].host")),
            );
        }
    }

    // Auth.
    if let Some(auth) = p.auth.as_ref() {
        check_auth(d, auth, &format!("{prefix}.auth"));
    }

    for (j, hop) in p.hops.iter().enumerate() {
        let hop_prefix = format!("{prefix}.hops[{j}]");
        if hop.host.is_empty() {
            d.push(
                Diagnostic::error(
                    "hop_missing_host",
                    format!("hop `{}` has empty host", hop.name),
                )
                .at(format!("{hop_prefix}.host")),
            );
        }
        if let Some(protocol) = (!hop.protocol.is_empty()).then_some(hop.protocol.as_str()) {
            if !matches!(protocol, "ssh2" | "ssh3") {
                d.push(
                    Diagnostic::error(
                        "hop_protocol_invalid",
                        format!("hop `{}` has unknown protocol `{protocol}`", hop.name),
                    )
                    .at(format!("{hop_prefix}.protocol")),
                );
            }
        }
        if let Some(resolve) = hop.target_resolve.as_deref() {
            if !matches!(resolve, "local" | "remote" | "previous-hop") {
                d.push(
                    Diagnostic::error(
                        "hop_target_resolve_invalid",
                        format!("hop `{}` has unknown target_resolve `{resolve}`", hop.name),
                    )
                    .at(format!("{hop_prefix}.target_resolve")),
                );
            }
        }
        if let Some(auth) = hop.auth.as_ref() {
            check_auth(d, auth, &format!("{hop_prefix}.auth"));
        }
    }

    // Forwards.
    let mut fwd_names: Vec<&str> = Vec::with_capacity(p.forwards.len());
    for (j, f) in p.forwards.iter().enumerate() {
        if fwd_names.contains(&f.name.as_str()) {
            d.push(
                Diagnostic::error(
                    "duplicate_forward_id",
                    format!(
                        "forward name `{}` not unique within profile `{}`",
                        f.name, p.name
                    ),
                )
                .at(format!("{prefix}.forwards[{j}].name")),
            );
        } else {
            fwd_names.push(&f.name);
        }
        check_forward(d, &p.protocol, f, i, j);
    }

    // Limits sizes.
    if let Some(l) = p.limits.as_ref() {
        check_size_field(
            d,
            l.max_bytes_per_second_in.as_deref(),
            format!("{prefix}.limits.max_bytes_per_second_in"),
        );
        check_size_field(
            d,
            l.max_bytes_per_second_out.as_deref(),
            format!("{prefix}.limits.max_bytes_per_second_out"),
        );
    }

    // Reconnect / keepalive duration parses.
    if let Some(r) = p.reconnect.as_ref() {
        check_duration_field(
            d,
            r.initial_delay.as_deref(),
            format!("{prefix}.reconnect.initial_delay"),
        );
        check_duration_field(
            d,
            r.max_delay.as_deref(),
            format!("{prefix}.reconnect.max_delay"),
        );
        check_duration_field(
            d,
            r.reset_after.as_deref(),
            format!("{prefix}.reconnect.reset_after"),
        );
    }
    if let Some(k) = p.keepalive.as_ref() {
        check_duration_field(
            d,
            k.interval.as_deref(),
            format!("{prefix}.keepalive.interval"),
        );
        check_duration_field(
            d,
            k.timeout.as_deref(),
            format!("{prefix}.keepalive.timeout"),
        );
    }
}

fn check_auth(d: &mut Diagnostics, auth: &Auth, prefix: &str) {
    for (label, val) in [
        ("passphrase", &auth.passphrase),
        ("password", &auth.password),
        ("token", &auth.token),
    ] {
        if let Some(s) = val.as_deref() {
            check_secret_ref_shape(d, s, format!("{prefix}.{label}"));
        }
    }
}

#[allow(clippy::many_single_char_names)]
fn check_forward(d: &mut Diagnostics, protocol: &str, f: &Forward, i: usize, j: usize) {
    let prefix = format!("profiles[{i}].forwards[{j}]");

    if !matches!(f.kind.as_str(), "local" | "remote") {
        d.push(
            Diagnostic::error(
                "forward_type_invalid",
                format!("forward `{}` has unknown type `{}`", f.name, f.kind),
            )
            .at(format!("{prefix}.type")),
        );
    }
    if !matches!(f.transport.as_str(), "tcp" | "udp") {
        d.push(
            Diagnostic::error(
                "forward_transport_invalid",
                format!(
                    "forward `{}` has unknown transport `{}`",
                    f.name, f.transport
                ),
            )
            .at(format!("{prefix}.transport")),
        );
    }
    if f.transport == "udp" && protocol != "ssh3" {
        d.push(
            Diagnostic::error(
                "udp_requires_ssh3",
                format!(
                    "forward `{}` is UDP but profile protocol is `{protocol}` (UDP requires `ssh3`)",
                    f.name
                ),
            )
            .at(format!("{prefix}.transport")),
        );
    }

    let bind_str = f.bind.as_deref().or(f.listen.as_deref());
    let target_str = f.target.as_deref().or(f.connect.as_deref());

    if f.kind == "remote" && bind_str.is_none() {
        d.push(
            Diagnostic::error(
                "remote_forward_missing_bind",
                format!("remote forward `{}` requires explicit `bind`", f.name),
            )
            .at(format!("{prefix}.bind")),
        );
    }

    if let Some(b) = bind_str {
        match BindAddr::parse(b) {
            Ok(BindAddr::Tcp(sock)) => {
                let exposed = matches!(f.expose, Some(true));
                if !sock.ip().is_loopback() && !sock.ip().is_unspecified() && !exposed {
                    d.push(
                        Diagnostic::warning(
                            "non_loopback_bind_without_expose",
                            format!(
                                "forward `{}` bind `{b}` is non-loopback; set `expose = true` to acknowledge",
                                f.name
                            ),
                        )
                        .at(format!("{prefix}.bind")),
                    );
                } else if sock.ip().is_unspecified() && !exposed {
                    d.push(
                        Diagnostic::error(
                            "wildcard_bind_without_expose",
                            format!(
                                "forward `{}` bind `{b}` is a wildcard address; set `expose = true`",
                                f.name
                            ),
                        )
                        .at(format!("{prefix}.bind")),
                    );
                }
            }
            Ok(_) => {}
            Err(e) => d.push(
                Diagnostic::error(
                    "forward_bind_invalid",
                    format!("forward `{}` bind `{b}`: {e}", f.name),
                )
                .at(format!("{prefix}.bind")),
            ),
        }
    } else if f.kind == "local" {
        d.push(
            Diagnostic::error(
                "local_forward_missing_bind",
                format!("local forward `{}` has no `bind`/`listen`", f.name),
            )
            .at(format!("{prefix}.bind")),
        );
    }

    if let Some(t) = target_str {
        if let Err(e) = BindAddr::parse(t) {
            d.push(
                Diagnostic::error(
                    "forward_target_invalid",
                    format!("forward `{}` target `{t}`: {e}", f.name),
                )
                .at(format!("{prefix}.target")),
            );
        }
    } else if f.kind == "local" {
        d.push(
            Diagnostic::error(
                "local_forward_missing_target",
                format!("local forward `{}` has no `target`/`connect`", f.name),
            )
            .at(format!("{prefix}.target")),
        );
    }

    if let Some(mode) = f.bind_mode.as_deref() {
        if !matches!(
            mode,
            "loopback" | "specific_ip" | "specific_interface" | "all_interfaces" | "auto_interface"
        ) {
            d.push(
                Diagnostic::error(
                    "forward_bind_mode_invalid",
                    format!("forward `{}` has unknown bind_mode `{mode}`", f.name),
                )
                .at(format!("{prefix}.bind_mode")),
            );
        }
    }

    if let Some(c) = f.on_bind_conflict.as_deref() {
        if !matches!(c, "fail" | "retry" | "next_port") {
            d.push(
                Diagnostic::error(
                    "forward_on_bind_conflict_invalid",
                    format!("forward `{}` on_bind_conflict `{c}` invalid", f.name),
                )
                .at(format!("{prefix}.on_bind_conflict")),
            );
        }
    }

    check_size_field(
        d,
        f.max_bytes_per_second_in.as_deref(),
        format!("{prefix}.max_bytes_per_second_in"),
    );
    check_size_field(
        d,
        f.max_bytes_per_second_out.as_deref(),
        format!("{prefix}.max_bytes_per_second_out"),
    );
    check_duration_field(
        d,
        f.idle_timeout.as_deref(),
        format!("{prefix}.idle_timeout"),
    );
    check_duration_field(
        d,
        f.udp_idle_timeout.as_deref(),
        format!("{prefix}.udp_idle_timeout"),
    );
}

fn check_secret_ref_shape(d: &mut Diagnostics, value: &str, path: String) {
    if !value.starts_with("secret://") {
        // Treat any inline value as a non-fatal warning; strict mode promotes
        // it via the upstream policy in spt-secrets, not here.
        d.push(
            Diagnostic::warning(
                "inline_secret",
                format!("`{path}` does not use a `secret://` reference"),
            )
            .at(path)
            .with_help("rewrite as `secret://<namespace>/<name>` and store via `spt secret set`"),
        );
        return;
    }
    let rest = value.trim_start_matches("secret://");
    let mut parts = rest.splitn(2, '/');
    let ns = parts.next().unwrap_or("");
    let name = parts.next().unwrap_or("");
    if ns.is_empty() || name.is_empty() {
        d.push(
            Diagnostic::error(
                "secret_ref_malformed",
                format!("malformed secret reference `{value}`"),
            )
            .at(path)
            .with_help("expected form: `secret://<namespace>/<name>`"),
        );
    }
}

fn check_duration_field<P: Into<String>>(d: &mut Diagnostics, val: Option<&str>, path: P) {
    if let Some(s) = val {
        if !s.is_empty() {
            if let Err(e) = parse_duration(s) {
                d.push(
                    Diagnostic::error("duration_invalid", format!("`{s}`: {e}")).at(path.into()),
                );
            }
        }
    }
}

fn check_size_field<P: Into<String>>(d: &mut Diagnostics, val: Option<&str>, path: P) {
    if let Some(s) = val {
        if !s.is_empty() {
            if let Err(e) = parse_size(s) {
                d.push(Diagnostic::error("size_invalid", format!("`{s}`: {e}")).at(path.into()));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::validate;
    use crate::load::load_str;

    #[test]
    fn ok_minimum_config() {
        let raw = r#"
            version = 1
            [[profiles]]
            name = "p"
            protocol = "ssh2"
            host = "h.example.com"
        "#;
        let (c, _) = load_str(raw, false).unwrap();
        let d = validate(&c);
        assert!(d.is_ok(), "errors: {:?}", d.errors);
    }

    #[test]
    fn duplicate_profile_id_errors() {
        let raw = r#"
            version = 1
            [[profiles]]
            name = "p"
            protocol = "ssh2"
            host = "h"
            [[profiles]]
            name = "p"
            protocol = "ssh2"
            host = "h"
        "#;
        let (c, _) = load_str(raw, false).unwrap();
        let d = validate(&c);
        assert!(!d.is_ok());
        assert!(d.errors.iter().any(|e| e.code == "duplicate_profile_id"));
    }

    #[test]
    fn ssh3_without_ack_is_error() {
        let raw = r#"
            version = 1
            [[profiles]]
            name = "p"
            protocol = "ssh3"
            endpoint = "https://x.example.com:443/ssh3"
        "#;
        let (c, _) = load_str(raw, false).unwrap();
        let d = validate(&c);
        assert!(d.errors.iter().any(|e| e.code == "ssh3_experimental_unack"));
    }

    #[test]
    fn wrong_version_errors() {
        let raw = r#"
            version = 99
            [[profiles]]
            name = "p"
            protocol = "ssh2"
            host = "h"
        "#;
        let (c, _) = load_str(raw, false).unwrap();
        let d = validate(&c);
        assert!(d.errors.iter().any(|e| e.code == "version_unsupported"));
    }

    #[test]
    fn bad_bind_address_errors() {
        let raw = r#"
            version = 1
            [[profiles]]
            name = "p"
            protocol = "ssh2"
            host = "h"
            [[profiles.forwards]]
            name = "f"
            type = "local"
            transport = "tcp"
            bind = "not_an_address"
            target = "x:22"
        "#;
        let (c, _) = load_str(raw, false).unwrap();
        let d = validate(&c);
        assert!(d.errors.iter().any(|e| e.code == "forward_bind_invalid"));
    }

    #[test]
    fn malformed_secret_ref_errors() {
        let raw = r#"
            version = 1
            [[profiles]]
            name = "p"
            protocol = "ssh2"
            host = "h"
            [profiles.auth]
            method = "password"
            password = "secret://onlyns"
        "#;
        let (c, _) = load_str(raw, false).unwrap();
        let d = validate(&c);
        assert!(d.errors.iter().any(|e| e.code == "secret_ref_malformed"));
    }

    #[test]
    fn udp_without_ssh3_errors() {
        let raw = r#"
            version = 1
            [[profiles]]
            name = "p"
            protocol = "ssh2"
            host = "h"
            [[profiles.forwards]]
            name = "f"
            type = "local"
            transport = "udp"
            bind = "127.0.0.1:53"
            target = "1.2.3.4:53"
        "#;
        let (c, _) = load_str(raw, false).unwrap();
        let d = validate(&c);
        assert!(d.errors.iter().any(|e| e.code == "udp_requires_ssh3"));
    }

    #[test]
    fn duplicate_forward_id_errors() {
        let raw = r#"
            version = 1
            [[profiles]]
            name = "p"
            protocol = "ssh2"
            host = "h"
            [[profiles.forwards]]
            name = "f"
            type = "local"
            transport = "tcp"
            bind = "127.0.0.1:1"
            target = "x:22"
            [[profiles.forwards]]
            name = "f"
            type = "local"
            transport = "tcp"
            bind = "127.0.0.1:2"
            target = "x:22"
        "#;
        let (c, _) = load_str(raw, false).unwrap();
        let d = validate(&c);
        assert!(d.errors.iter().any(|e| e.code == "duplicate_forward_id"));
    }

    #[test]
    fn dns_privileged_port_warns() {
        let raw = r#"
            version = 1
            [dns]
            enabled = true
            bind = "127.0.0.1:53"
            [[profiles]]
            name = "p"
            protocol = "ssh2"
            host = "h"
        "#;
        let (c, _) = load_str(raw, false).unwrap();
        let d = validate(&c);
        assert!(d.warnings.iter().any(|w| w.code == "dns_privileged_port"));
    }

    #[test]
    fn mcp_secret_reveal_disallowed() {
        let raw = r#"
            version = 1
            [mcp]
            allow_secret_reveal = true
            [[profiles]]
            name = "p"
            protocol = "ssh2"
            host = "h"
        "#;
        let (c, _) = load_str(raw, false).unwrap();
        let d = validate(&c);
        assert!(d
            .errors
            .iter()
            .any(|e| e.code == "mcp_secret_reveal_disallowed"));
    }
}
