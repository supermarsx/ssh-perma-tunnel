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
//! 14. `forward.type` is `local|remote|dynamic`; `transport` is `tcp|udp`.
//! 15. Duration / size string fields parse via `spt_core` helpers.
//! 16. `runtime.remote_config.url` (when enabled) must be an HTTPS URL with a
//!     `fingerprint_sha256` set (spec §14.3).
//! 17. Fleet feature gates in `[capabilities]` use known values and safe
//!     combinations.

use spt_core::{address::BindAddr, duration::parse_duration, size::parse_size};

use crate::diagnostic::{Diagnostic, Diagnostics};
use crate::schema::{Auth, Capabilities, Config, Forward, Profile, SftpMount};

const POST_QUANTUM_KEX: &[&str] = &[
    "mlkem768x25519-sha256",
    "mlkem768x25519-sha256@openssh.com",
    "mlkem768nistp256-sha256",
    "mlkem1024nistp384-sha384",
    "sntrup761x25519-sha512",
    "sntrup761x25519-sha512@openssh.com",
];

const ML_KEM_KEX: &[&str] = &[
    "mlkem768x25519-sha256",
    "mlkem768x25519-sha256@openssh.com",
    "mlkem768nistp256-sha256",
    "mlkem1024nistp384-sha384",
];

/// Validate a [`Config`]. Always returns a [`Diagnostics`] bundle — the caller
/// decides whether `errors.is_empty()` is success.
#[must_use]
pub fn validate(c: &Config) -> Diagnostics {
    let mut d = Diagnostics::new();

    check_version(&mut d, c);
    check_runtime(&mut d, c);
    check_logging(&mut d, c);
    check_dns(&mut d, c);
    check_firewall(&mut d, c);
    check_network(&mut d, c);
    check_observability(&mut d, c);
    check_mcp(&mut d, c);
    check_capabilities(&mut d, c);
    check_profiles(&mut d, c);

    d
}

fn check_logging(d: &mut Diagnostics, c: &Config) {
    let Some(logging) = c.logging.as_ref() else {
        return;
    };

    let mut seen_names: Vec<&str> = Vec::with_capacity(logging.remote.len());
    for (i, remote) in logging.remote.iter().enumerate() {
        let prefix = format!("logging.remote[{i}]");
        if seen_names.contains(&remote.name.as_str()) {
            d.push(
                Diagnostic::error(
                    "duplicate_remote_log_sink",
                    format!("remote log sink name `{}` is not unique", remote.name),
                )
                .at(format!("{prefix}.name")),
            );
        } else {
            seen_names.push(&remote.name);
        }

        if !matches!(
            remote.kind.as_str(),
            "syslog_udp"
                | "syslog-udp"
                | "syslog_tcp"
                | "syslog-tcp"
                | "syslog_tls"
                | "syslog-tls"
                | "https_jsonl"
                | "https-jsonl"
                | "otlp"
        ) {
            d.push(
                Diagnostic::error(
                    "remote_log_kind_invalid",
                    format!(
                        "remote log sink `{}` has unknown type `{}`",
                        remote.name, remote.kind
                    ),
                )
                .at(format!("{prefix}.type")),
            );
        }

        if remote.endpoint.as_deref().unwrap_or("").is_empty() {
            d.push(
                Diagnostic::error(
                    "remote_log_missing_endpoint",
                    format!("remote log sink `{}` requires `endpoint`", remote.name),
                )
                .at(format!("{prefix}.endpoint")),
            );
        }

        if let Some(facility) = remote.facility {
            if facility > 23 {
                d.push(
                    Diagnostic::error(
                        "syslog_facility_invalid",
                        format!("syslog facility `{facility}` is outside 0..23"),
                    )
                    .at(format!("{prefix}.facility")),
                );
            }
        }

        if remote.allow_invalid_certs.is_some() {
            // t5-e2: field renamed to `allow_self_signed` with a stricter
            // semantic (requires a non-empty pin set). The old name is
            // accepted but deprecated.
            d.push(
                Diagnostic::warning(
                    "remote_log_allow_invalid_certs_deprecated",
                    format!(
                        "`allow_invalid_certs` on remote log sink `{}` is deprecated; \
                         use `allow_self_signed` with a non-empty `pin_spki_sha256` set",
                        remote.name
                    ),
                )
                .at(format!("{prefix}.allow_invalid_certs")),
            );
        }
        let self_signed = remote.allow_self_signed.or(remote.allow_invalid_certs);
        if matches!(self_signed, Some(true)) {
            if matches!(remote.kind.as_str(), "syslog_tls" | "syslog-tls") {
                d.push(
                    Diagnostic::warning(
                        "syslog_tls_invalid_certs_allowed",
                        format!(
                            "remote log sink `{}` disables TLS certificate verification",
                            remote.name
                        ),
                    )
                    .at(format!("{prefix}.allow_self_signed")),
                );
            } else {
                d.push(
                    Diagnostic::warning(
                        "remote_log_tls_option_ignored",
                        "allow_self_signed only applies to syslog_tls sinks",
                    )
                    .at(format!("{prefix}.allow_self_signed")),
                );
            }
            if matches!(remote.allow_self_signed, Some(true)) && remote.pin_spki_sha256.is_empty() {
                d.push(
                    Diagnostic::error(
                        "remote_log_allow_self_signed_without_pin",
                        format!(
                            "remote log sink `{}` sets allow_self_signed=true but no \
                             `pin_spki_sha256` entries — refusing to disable verification \
                             entirely",
                            remote.name
                        ),
                    )
                    .at(format!("{prefix}.allow_self_signed")),
                );
            }
        }

        if remote.client_cert.is_some() ^ remote.client_key.is_some() {
            d.push(
                Diagnostic::error(
                    "syslog_tls_client_auth_incomplete",
                    "client_cert and client_key must be configured together",
                )
                .at(format!("{prefix}.client_cert")),
            );
        }

        if let Some(queue_max_records) = remote.queue_max_records {
            if queue_max_records == 0 {
                d.push(
                    Diagnostic::error(
                        "remote_log_queue_empty",
                        "queue_max_records must be greater than zero",
                    )
                    .at(format!("{prefix}.queue_max_records")),
                );
            }
        }

        check_duration_field(d, remote.timeout.as_deref(), format!("{prefix}.timeout"));
        check_duration_field(
            d,
            remote.reconnect_backoff.as_deref(),
            format!("{prefix}.reconnect_backoff"),
        );
        check_size_field(
            d,
            remote.spool_max_bytes.as_deref(),
            format!("{prefix}.spool_max_bytes"),
        );
    }
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

fn check_network(d: &mut Diagnostics, c: &Config) {
    let Some(network) = c.network.as_ref() else {
        return;
    };

    if let Some(interface) = network.interface.as_ref() {
        if let Some(mode) = interface.bind_ipv6.as_deref() {
            if !matches!(mode, "auto" | "prefer" | "disable") {
                d.push(
                    Diagnostic::error(
                        "network_bind_ipv6_invalid",
                        format!("network.interface.bind_ipv6 `{mode}` is invalid"),
                    )
                    .at("network.interface.bind_ipv6"),
                );
            }
        }

        if let (Some(allowed), Some(denied)) = (
            interface.allowed_interfaces.as_ref(),
            interface.denied_interfaces.as_ref(),
        ) {
            for name in allowed {
                if denied.iter().any(|denied_name| denied_name == name) {
                    d.push(
                        Diagnostic::error(
                            "network_interface_policy_conflict",
                            format!("interface `{name}` appears in both allowed and denied lists"),
                        )
                        .at("network.interface.allowed_interfaces"),
                    );
                }
            }
        }
    }

    if let Some(gateway) = network.gateway.as_ref() {
        if let Some(policy) = gateway.policy.as_deref() {
            if !matches!(
                policy,
                "disabled" | "default_route" | "interface_only" | "route_to_target"
            ) {
                d.push(
                    Diagnostic::error(
                        "network_gateway_policy_invalid",
                        format!("network.gateway.policy `{policy}` is invalid"),
                    )
                    .at("network.gateway.policy"),
                );
            }
        }
        if matches!(gateway.require_gateway_match, Some(true))
            && gateway.interface.as_deref().unwrap_or("").is_empty()
        {
            d.push(
                Diagnostic::error(
                    "network_gateway_interface_required",
                    "network.gateway.require_gateway_match requires network.gateway.interface",
                )
                .at("network.gateway.interface"),
            );
        }
    }

    if let Some(load_balance) = network.load_balance.as_ref() {
        if let Some(strategy) = load_balance.strategy.as_deref() {
            if !matches!(
                strategy,
                "priority" | "weighted" | "round_robin" | "least_connections" | "manual"
            ) {
                d.push(
                    Diagnostic::error(
                        "network_load_balance_strategy_invalid",
                        format!("network.load_balance.strategy `{strategy}` is invalid"),
                    )
                    .at("network.load_balance.strategy"),
                );
            }
        }
        if let Some(health_check) = load_balance.health_check.as_deref() {
            if !matches!(
                health_check,
                "tcp_connect" | "ssh_handshake" | "ssh_auth_preflight" | "ssh3_endpoint"
            ) {
                d.push(
                    Diagnostic::error(
                        "network_load_balance_health_check_invalid",
                        format!("network.load_balance.health_check `{health_check}` is invalid"),
                    )
                    .at("network.load_balance.health_check"),
                );
            }
        }
        if matches!(load_balance.fail_after, Some(0)) {
            d.push(
                Diagnostic::error(
                    "network_load_balance_fail_after_zero",
                    "network.load_balance.fail_after must be greater than zero",
                )
                .at("network.load_balance.fail_after"),
            );
        }
        check_duration_field(
            d,
            load_balance.restore_after.as_deref(),
            "network.load_balance.restore_after",
        );
        check_duration_field(
            d,
            load_balance.rebalance_interval.as_deref(),
            "network.load_balance.rebalance_interval",
        );
    }
}

fn check_observability(d: &mut Diagnostics, c: &Config) {
    let Some(obs) = c.observability.as_ref() else {
        return;
    };
    let Some(snmp) = obs.snmp.as_ref() else {
        return;
    };
    let snmp_enabled = snmp.enabled.unwrap_or(false);

    if snmp_enabled && snmp.enterprise_id.is_none() {
        d.push(
            Diagnostic::error(
                "snmp_enterprise_id_required",
                "enabled SNMP requires observability.snmp.enterprise_id",
            )
            .at("observability.snmp.enterprise_id")
            .with_help("set this to your registered IANA Private Enterprise Number"),
        );
    }

    if matches!(snmp.enterprise_id, Some(0)) {
        d.push(
            Diagnostic::error(
                "snmp_enterprise_id_invalid",
                "observability.snmp.enterprise_id must be greater than zero",
            )
            .at("observability.snmp.enterprise_id"),
        );
    }
    if matches!(snmp.enterprise_id, Some(99_999)) {
        let diagnostic = if snmp_enabled {
            Diagnostic::error(
                "snmp_enterprise_id_placeholder",
                "observability.snmp.enterprise_id uses the old placeholder PEN 99999",
            )
        } else {
            Diagnostic::warning(
                "snmp_enterprise_id_placeholder",
                "observability.snmp.enterprise_id uses the old placeholder PEN 99999",
            )
        };
        d.push(
            diagnostic
                .at("observability.snmp.enterprise_id")
                .with_help("set this to your registered IANA Private Enterprise Number"),
        );
    }
    if matches!(snmp.enterprise_id, Some(32_473)) {
        let diagnostic = if snmp_enabled {
            Diagnostic::error(
                "snmp_enterprise_id_documentation",
                "observability.snmp.enterprise_id uses RFC documentation PEN 32473",
            )
        } else {
            Diagnostic::warning(
                "snmp_enterprise_id_documentation",
                "observability.snmp.enterprise_id uses RFC documentation PEN 32473",
            )
        };
        d.push(
            diagnostic
                .at("observability.snmp.enterprise_id")
                .with_help("use a registered production IANA Private Enterprise Number"),
        );
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

fn check_capabilities(d: &mut Diagnostics, c: &Config) {
    let Some(cap) = c.capabilities.as_ref() else {
        return;
    };

    if let Some(backend) = cap.ssh2_backend.as_deref() {
        if !matches!(backend, "russh" | "libssh2") {
            d.push(
                Diagnostic::error(
                    "capabilities_ssh2_backend_invalid",
                    format!("capabilities.ssh2_backend `{backend}` is invalid"),
                )
                .at("capabilities.ssh2_backend"),
            );
        }
        if backend == "libssh2" {
            d.push(
                Diagnostic::warning(
                    "capabilities_ssh2_backend_libssh2_deprecated",
                    "capabilities.ssh2_backend = \"libssh2\" is legacy; russh is the production SSH2 backend target",
                )
                .at("capabilities.ssh2_backend"),
            );
            if matches!(cap.allow_libssh2, Some(false)) {
                d.push(
                    Diagnostic::error(
                        "capabilities_libssh2_disallowed",
                        "capabilities.allow_libssh2 = false conflicts with ssh2_backend = \"libssh2\"",
                    )
                    .at("capabilities.allow_libssh2"),
                );
            }
        }
    }

    if matches!(cap.require_post_quantum_kex, Some(true))
        && !matches!(cap.allow_post_quantum_kex, Some(true))
    {
        d.push(
            Diagnostic::error(
                "capabilities_pq_required_but_disabled",
                "capabilities.require_post_quantum_kex requires allow_post_quantum_kex = true",
            )
            .at("capabilities.require_post_quantum_kex"),
        );
    }

    if matches!(cap.allow_ml_kem, Some(true)) && !matches!(cap.allow_post_quantum_kex, Some(true)) {
        d.push(
            Diagnostic::warning(
                "capabilities_ml_kem_without_pq",
                "capabilities.allow_ml_kem has no effect unless allow_post_quantum_kex = true",
            )
            .at("capabilities.allow_ml_kem"),
        );
    }

    if matches!(cap.allow_windows_drive_mounts, Some(true))
        && !matches!(cap.allow_filesystem_mounts, Some(true))
    {
        d.push(
            Diagnostic::error(
                "capabilities_windows_drive_mounts_require_fs_mounts",
                "capabilities.allow_windows_drive_mounts requires allow_filesystem_mounts = true",
            )
            .at("capabilities.allow_windows_drive_mounts"),
        );
    }

    if matches!(cap.allow_writeback_cache, Some(true))
        && !matches!(cap.allow_filesystem_mounts, Some(true))
    {
        d.push(
            Diagnostic::error(
                "capabilities_writeback_requires_fs_mounts",
                "capabilities.allow_writeback_cache requires allow_filesystem_mounts = true",
            )
            .at("capabilities.allow_writeback_cache"),
        );
    }

    if matches!(cap.allow_gssapi_delegation, Some(true))
        && !matches!(cap.allow_gssapi, Some(true))
        && !matches!(cap.allow_sspi, Some(true))
    {
        d.push(
            Diagnostic::error(
                "capabilities_gssapi_delegation_requires_provider",
                "capabilities.allow_gssapi_delegation requires allow_gssapi = true or allow_sspi = true",
            )
            .at("capabilities.allow_gssapi_delegation"),
        );
    }

    if matches!(cap.allow_ntlm_fallback, Some(true)) && !matches!(cap.allow_sspi, Some(true)) {
        d.push(
            Diagnostic::error(
                "capabilities_ntlm_requires_sspi",
                "capabilities.allow_ntlm_fallback requires allow_sspi = true",
            )
            .at("capabilities.allow_ntlm_fallback"),
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
        check_profile(d, i, p, c.capabilities.as_ref());
    }
}

fn check_profile(d: &mut Diagnostics, i: usize, p: &Profile, capabilities: Option<&Capabilities>) {
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

    check_profile_crypto(d, p, capabilities, &prefix);

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
        check_forward(d, &p.protocol, capabilities, f, i, j);
    }

    // SFTP mount entries.
    let mut sftp_mount_names: Vec<&str> = Vec::with_capacity(p.sftp_mounts.len());
    for (j, mount) in p.sftp_mounts.iter().enumerate() {
        if sftp_mount_names.contains(&mount.name.as_str()) {
            d.push(
                Diagnostic::error(
                    "duplicate_sftp_mount_id",
                    format!(
                        "SFTP mount name `{}` not unique within profile `{}`",
                        mount.name, p.name
                    ),
                )
                .at(format!("{prefix}.sftp_mounts[{j}].name")),
            );
        } else {
            sftp_mount_names.push(&mount.name);
        }
        check_sftp_mount(d, &p.protocol, capabilities, mount, i, j);
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
    if let Some(failover) = p.failover.as_ref() {
        if let Some(mode) = failover.mode.as_deref() {
            if !matches!(mode, "priority" | "weighted" | "manual") {
                d.push(
                    Diagnostic::error(
                        "failover_mode_invalid",
                        format!("profile `{}` has unknown failover.mode `{mode}`", p.name),
                    )
                    .at(format!("{prefix}.failover.mode")),
                );
            }
        }
        if matches!(failover.fail_after, Some(0)) {
            d.push(
                Diagnostic::error(
                    "failover_fail_after_zero",
                    format!(
                        "profile `{}` failover.fail_after must be greater than zero",
                        p.name
                    ),
                )
                .at(format!("{prefix}.failover.fail_after")),
            );
        }
        check_duration_field(
            d,
            failover.restore_after.as_deref(),
            format!("{prefix}.failover.restore_after"),
        );
    }
}

fn check_sftp_mount(
    d: &mut Diagnostics,
    protocol: &str,
    capabilities: Option<&Capabilities>,
    mount: &SftpMount,
    i: usize,
    j: usize,
) {
    let prefix = format!("profiles[{i}].sftp_mounts[{j}]");

    if mount.name.trim().is_empty() {
        d.push(
            Diagnostic::error("sftp_mount_missing_name", "SFTP mount requires `name`")
                .at(format!("{prefix}.name")),
        );
    }
    if mount.remote_path.trim().is_empty() {
        d.push(
            Diagnostic::error(
                "sftp_mount_missing_remote_path",
                format!("SFTP mount `{}` requires `remote_path`", mount.name),
            )
            .at(format!("{prefix}.remote_path")),
        );
    }
    if protocol != "ssh2" {
        d.push(
            Diagnostic::error(
                "sftp_mount_requires_ssh2",
                format!(
                    "SFTP mount `{}` requires profile protocol `ssh2`",
                    mount.name
                ),
            )
            .at(format!("{prefix}.remote_path")),
        );
    }
    if !matches!(
        capabilities.and_then(|capabilities| capabilities.allow_sftp),
        Some(true)
    ) {
        d.push(
            Diagnostic::error(
                "sftp_capability_disabled",
                format!(
                    "SFTP mount `{}` requires capabilities.allow_sftp = true",
                    mount.name
                ),
            )
            .at("capabilities.allow_sftp"),
        );
    }
    if !matches!(
        capabilities.and_then(|capabilities| capabilities.allow_filesystem_mounts),
        Some(true)
    ) {
        d.push(
            Diagnostic::error(
                "sftp_mount_capability_disabled",
                format!(
                    "SFTP mount `{}` requires capabilities.allow_filesystem_mounts = true",
                    mount.name
                ),
            )
            .at("capabilities.allow_filesystem_mounts"),
        );
    }

    let has_mount_point = mount
        .mount_point
        .as_deref()
        .is_some_and(|value| !value.trim().is_empty());
    let has_drive_letter = mount
        .drive_letter
        .as_deref()
        .is_some_and(|value| !value.trim().is_empty());
    match (has_mount_point, has_drive_letter) {
        (true, true) => d.push(
            Diagnostic::error(
                "sftp_mount_single_local_target",
                format!(
                    "SFTP mount `{}` must set either mount_point or drive_letter, not both",
                    mount.name
                ),
            )
            .at(format!("{prefix}.mount_point")),
        ),
        (false, false) => d.push(
            Diagnostic::error(
                "sftp_mount_missing_local_target",
                format!(
                    "SFTP mount `{}` requires mount_point or drive_letter",
                    mount.name
                ),
            )
            .at(format!("{prefix}.mount_point")),
        ),
        _ => {}
    }

    if has_drive_letter {
        if !matches!(
            capabilities.and_then(|capabilities| capabilities.allow_windows_drive_mounts),
            Some(true)
        ) {
            d.push(
                Diagnostic::error(
                    "sftp_drive_capability_disabled",
                    format!(
                        "SFTP drive mount `{}` requires capabilities.allow_windows_drive_mounts = true",
                        mount.name
                    ),
                )
                .at("capabilities.allow_windows_drive_mounts"),
            );
        }
        if let Some(letter) = mount.drive_letter.as_deref() {
            let trimmed = letter.trim_end_matches(':');
            if trimmed.len() != 1 || !trimmed.as_bytes()[0].is_ascii_alphabetic() {
                d.push(
                    Diagnostic::error(
                        "sftp_drive_letter_invalid",
                        format!(
                            "SFTP drive mount `{}` has invalid drive_letter `{letter}`",
                            mount.name
                        ),
                    )
                    .at(format!("{prefix}.drive_letter")),
                );
            }
        }
    }

    if let Some(cache) = mount.cache.as_deref() {
        if !matches!(cache, "none" | "metadata" | "writeback") {
            d.push(
                Diagnostic::error(
                    "sftp_mount_cache_invalid",
                    format!(
                        "SFTP mount `{}` has unknown cache mode `{cache}`",
                        mount.name
                    ),
                )
                .at(format!("{prefix}.cache")),
            );
        }
        if cache == "writeback"
            && !matches!(
                capabilities.and_then(|capabilities| capabilities.allow_writeback_cache),
                Some(true)
            )
        {
            d.push(
                Diagnostic::error(
                    "sftp_writeback_capability_disabled",
                    format!(
                        "SFTP mount `{}` uses writeback cache but capabilities.allow_writeback_cache is not true",
                        mount.name
                    ),
                )
                .at("capabilities.allow_writeback_cache"),
            );
        }
    }
}

fn check_profile_crypto(
    d: &mut Diagnostics,
    p: &Profile,
    capabilities: Option<&Capabilities>,
    prefix: &str,
) {
    let kex_algorithms = p
        .crypto
        .as_ref()
        .and_then(|crypto| crypto.kex_algorithms.as_ref());
    let has_pq = kex_algorithms
        .is_some_and(|algorithms| contains_any_algorithm(algorithms, POST_QUANTUM_KEX));
    let has_ml_kem =
        kex_algorithms.is_some_and(|algorithms| contains_any_algorithm(algorithms, ML_KEM_KEX));

    if has_pq && p.protocol != "ssh2" {
        d.push(
            Diagnostic::error(
                "post_quantum_kex_requires_ssh2",
                format!(
                    "profile `{}` configures SSH post-quantum KEX but protocol is `{}`",
                    p.name, p.protocol
                ),
            )
            .at(format!("{prefix}.crypto.kex_algorithms")),
        );
    }
    if has_pq
        && !matches!(
            capabilities.and_then(|capabilities| capabilities.allow_post_quantum_kex),
            Some(true)
        )
    {
        d.push(
            Diagnostic::error(
                "post_quantum_kex_capability_disabled",
                format!(
                    "profile `{}` configures post-quantum KEX but capabilities.allow_post_quantum_kex is not true",
                    p.name
                ),
            )
            .at("capabilities.allow_post_quantum_kex"),
        );
    }
    if has_ml_kem
        && !matches!(
            capabilities.and_then(|capabilities| capabilities.allow_ml_kem),
            Some(true)
        )
    {
        d.push(
            Diagnostic::error(
                "ml_kem_capability_disabled",
                format!(
                    "profile `{}` configures ML-KEM KEX but capabilities.allow_ml_kem is not true",
                    p.name
                ),
            )
            .at("capabilities.allow_ml_kem"),
        );
    }

    if matches!(
        capabilities.and_then(|capabilities| capabilities.require_post_quantum_kex),
        Some(true)
    ) && p.protocol == "ssh2"
    {
        match kex_algorithms {
            Some(algorithms) if !contains_any_algorithm(algorithms, POST_QUANTUM_KEX) => d.push(
                Diagnostic::error(
                    "post_quantum_kex_required_but_absent",
                    format!(
                        "profile `{}` must include a recognized post-quantum KEX because capabilities.require_post_quantum_kex = true",
                        p.name
                    ),
                )
                .at(format!("{prefix}.crypto.kex_algorithms")),
            ),
            None => d.push(
                Diagnostic::warning(
                    "post_quantum_kex_required_without_explicit_list",
                    format!(
                        "profile `{}` relies on backend defaults while capabilities.require_post_quantum_kex = true; set profiles.crypto.kex_algorithms explicitly",
                        p.name
                    ),
                )
                .at(format!("{prefix}.crypto.kex_algorithms")),
            ),
            _ => {}
        }
    }
}

fn contains_any_algorithm(configured: &[String], known: &[&str]) -> bool {
    configured.iter().any(|algorithm| {
        known
            .iter()
            .any(|known| known.eq_ignore_ascii_case(algorithm))
    })
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
fn check_forward(
    d: &mut Diagnostics,
    protocol: &str,
    capabilities: Option<&Capabilities>,
    f: &Forward,
    i: usize,
    j: usize,
) {
    let prefix = format!("profiles[{i}].forwards[{j}]");

    if !matches!(f.kind.as_str(), "local" | "remote" | "dynamic") {
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
    if f.kind == "dynamic" {
        if f.transport != "tcp" {
            d.push(
                Diagnostic::error(
                    "dynamic_forward_requires_tcp",
                    format!("dynamic forward `{}` must use transport `tcp`", f.name),
                )
                .at(format!("{prefix}.transport")),
            );
        }
        if protocol != "ssh2" {
            d.push(
                Diagnostic::error(
                    "dynamic_forward_requires_ssh2",
                    format!(
                        "dynamic forward `{}` requires profile protocol `ssh2` (SOCKS/HTTP CONNECT over SSH2 direct-tcpip)",
                        f.name
                    ),
                )
                .at(format!("{prefix}.type")),
            );
        }
        if !matches!(
            capabilities.and_then(|capabilities| capabilities.allow_dynamic_proxy),
            Some(true)
        ) {
            d.push(
                Diagnostic::error(
                    "dynamic_proxy_capability_disabled",
                    format!(
                        "dynamic forward `{}` requires capabilities.allow_dynamic_proxy = true",
                        f.name
                    ),
                )
                .at("capabilities.allow_dynamic_proxy"),
            );
        }
        if f.target.is_some() || f.connect.is_some() {
            d.push(
                Diagnostic::warning(
                    "dynamic_forward_ignores_target",
                    format!(
                        "dynamic forward `{}` chooses targets per SOCKS/HTTP CONNECT request; remove target/connect",
                        f.name
                    ),
                )
                .at(format!("{prefix}.target")),
            );
        }
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
    } else if matches!(f.kind.as_str(), "local" | "dynamic") {
        d.push(
            Diagnostic::error(
                "local_forward_missing_bind",
                format!("{} forward `{}` has no `bind`/`listen`", f.kind, f.name),
            )
            .at(format!("{prefix}.bind")),
        );
    }

    if f.kind == "dynamic" {
        // Dynamic forwards choose a target per client request.
    } else if let Some(t) = target_str {
        if let Err(e) = BindAddr::parse(t) {
            d.push(
                Diagnostic::error(
                    "forward_target_invalid",
                    format!("forward `{}` target `{t}`: {e}", f.name),
                )
                .at(format!("{prefix}.target")),
            );
        }
    } else if matches!(f.kind.as_str(), "local" | "remote") {
        d.push(
            Diagnostic::error(
                "local_forward_missing_target",
                format!("{} forward `{}` has no `target`/`connect`", f.kind, f.name),
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

    if let Some(mode) = f.bind_ipv6.as_deref() {
        if !matches!(mode, "auto" | "prefer" | "disable") {
            d.push(
                Diagnostic::error(
                    "forward_bind_ipv6_invalid",
                    format!("forward `{}` has unknown bind_ipv6 `{mode}`", f.name),
                )
                .at(format!("{prefix}.bind_ipv6")),
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
    fn dynamic_forward_requires_capability_gate() {
        let raw = r#"
            version = 1
            [[profiles]]
            name = "p"
            protocol = "ssh2"
            host = "h"
            [[profiles.forwards]]
            name = "proxy"
            type = "dynamic"
            transport = "tcp"
            bind = "127.0.0.1:1080"
        "#;
        let (c, _) = load_str(raw, false).unwrap();
        let d = validate(&c);
        assert!(d
            .errors
            .iter()
            .any(|e| e.code == "dynamic_proxy_capability_disabled"));
    }

    #[test]
    fn dynamic_forward_valid_when_enabled() {
        let raw = r#"
            version = 1
            [capabilities]
            allow_dynamic_proxy = true
            [[profiles]]
            name = "p"
            protocol = "ssh2"
            host = "h"
            [[profiles.forwards]]
            name = "proxy"
            type = "dynamic"
            transport = "tcp"
            bind = "127.0.0.1:1080"
        "#;
        let (c, _) = load_str(raw, false).unwrap();
        let d = validate(&c);
        assert!(d.is_ok(), "errors: {:?}", d.errors);
    }

    #[test]
    fn sftp_mount_requires_capability_gates() {
        let raw = r#"
            version = 1
            [[profiles]]
            name = "p"
            protocol = "ssh2"
            host = "h"
            [[profiles.sftp_mounts]]
            name = "data"
            remote_path = "/srv/data"
            mount_point = "/mnt/data"
        "#;
        let (c, _) = load_str(raw, false).unwrap();
        let d = validate(&c);
        assert!(d
            .errors
            .iter()
            .any(|e| e.code == "sftp_capability_disabled"));
        assert!(d
            .errors
            .iter()
            .any(|e| e.code == "sftp_mount_capability_disabled"));
    }

    #[test]
    fn sftp_mount_valid_when_enabled() {
        let raw = r#"
            version = 1
            [capabilities]
            allow_sftp = true
            allow_filesystem_mounts = true
            [[profiles]]
            name = "p"
            protocol = "ssh2"
            host = "h"
            [[profiles.sftp_mounts]]
            name = "data"
            remote_path = "/srv/data"
            mount_point = "/mnt/data"
            cache = "metadata"
        "#;
        let (c, _) = load_str(raw, false).unwrap();
        let d = validate(&c);
        assert!(d.is_ok(), "errors: {:?}", d.errors);
    }

    #[test]
    fn sftp_drive_requires_drive_gate() {
        let raw = r#"
            version = 1
            [capabilities]
            allow_sftp = true
            allow_filesystem_mounts = true
            [[profiles]]
            name = "p"
            protocol = "ssh2"
            host = "h"
            [[profiles.sftp_mounts]]
            name = "data"
            remote_path = "/srv/data"
            drive_letter = "S:"
        "#;
        let (c, _) = load_str(raw, false).unwrap();
        let d = validate(&c);
        assert!(d
            .errors
            .iter()
            .any(|e| e.code == "sftp_drive_capability_disabled"));
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

    #[test]
    fn capabilities_invalid_backend_errors() {
        let raw = r#"
            version = 1
            [capabilities]
            ssh2_backend = "magic"
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
            .any(|e| e.code == "capabilities_ssh2_backend_invalid"));
    }

    #[test]
    fn capabilities_libssh2_is_warned_and_can_be_disallowed() {
        let raw = r#"
            version = 1
            [capabilities]
            ssh2_backend = "libssh2"
            allow_libssh2 = false
            [[profiles]]
            name = "p"
            protocol = "ssh2"
            host = "h"
        "#;
        let (c, _) = load_str(raw, false).unwrap();
        let d = validate(&c);
        assert!(d
            .warnings
            .iter()
            .any(|w| w.code == "capabilities_ssh2_backend_libssh2_deprecated"));
        assert!(d
            .errors
            .iter()
            .any(|e| e.code == "capabilities_libssh2_disallowed"));
    }

    #[test]
    fn post_quantum_kex_requires_capability_gate() {
        let raw = r#"
            version = 1
            [[profiles]]
            name = "p"
            protocol = "ssh2"
            host = "h"
            [profiles.crypto]
            kex_algorithms = ["sntrup761x25519-sha512@openssh.com"]
        "#;
        let (c, _) = load_str(raw, false).unwrap();
        let d = validate(&c);
        assert!(d
            .errors
            .iter()
            .any(|e| e.code == "post_quantum_kex_capability_disabled"));
    }

    #[test]
    fn ml_kem_kex_requires_ml_kem_capability_gate() {
        let raw = r#"
            version = 1
            [capabilities]
            allow_post_quantum_kex = true
            [[profiles]]
            name = "p"
            protocol = "ssh2"
            host = "h"
            [profiles.crypto]
            kex_algorithms = ["mlkem768x25519-sha256"]
        "#;
        let (c, _) = load_str(raw, false).unwrap();
        let d = validate(&c);
        assert!(d
            .errors
            .iter()
            .any(|e| e.code == "ml_kem_capability_disabled"));
    }

    #[test]
    fn required_post_quantum_kex_rejects_classical_only_list() {
        let raw = r#"
            version = 1
            [capabilities]
            allow_post_quantum_kex = true
            require_post_quantum_kex = true
            [[profiles]]
            name = "p"
            protocol = "ssh2"
            host = "h"
            [profiles.crypto]
            kex_algorithms = ["curve25519-sha256"]
        "#;
        let (c, _) = load_str(raw, false).unwrap();
        let d = validate(&c);
        assert!(d
            .errors
            .iter()
            .any(|e| e.code == "post_quantum_kex_required_but_absent"));
    }

    #[test]
    fn ml_kem_kex_validates_when_gated() {
        let raw = r#"
            version = 1
            [capabilities]
            allow_post_quantum_kex = true
            allow_ml_kem = true
            [[profiles]]
            name = "p"
            protocol = "ssh2"
            host = "h"
            [profiles.crypto]
            kex_algorithms = ["mlkem768x25519-sha256"]
        "#;
        let (c, _) = load_str(raw, false).unwrap();
        let d = validate(&c);
        assert!(
            d.is_ok(),
            "errors: {:?} warnings: {:?}",
            d.errors,
            d.warnings
        );
    }

    #[test]
    fn capabilities_reject_unsafe_combinations() {
        let raw = r#"
            version = 1
            [capabilities]
            ssh2_backend = "russh"
            require_post_quantum_kex = true
            allow_windows_drive_mounts = true
            allow_writeback_cache = true
            allow_gssapi_delegation = true
            allow_ntlm_fallback = true
            [[profiles]]
            name = "p"
            protocol = "ssh2"
            host = "h"
        "#;
        let (c, _) = load_str(raw, false).unwrap();
        let d = validate(&c);
        for code in [
            "capabilities_pq_required_but_disabled",
            "capabilities_windows_drive_mounts_require_fs_mounts",
            "capabilities_writeback_requires_fs_mounts",
            "capabilities_gssapi_delegation_requires_provider",
            "capabilities_ntlm_requires_sspi",
        ] {
            assert!(
                d.errors.iter().any(|e| e.code == code),
                "missing {code}: {:?}",
                d.errors
            );
        }
    }

    #[test]
    fn syslog_remote_kinds_validate() {
        let raw = r#"
            version = 1
            [logging]
            [[logging.remote]]
            name = "udp"
            type = "syslog_udp"
            endpoint = "127.0.0.1"
            facility = 16
            [[logging.remote]]
            name = "tcp"
            type = "syslog_tcp"
            endpoint = "127.0.0.1:514"
            spool_max_bytes = "1MiB"
            [[logging.remote]]
            name = "tls"
            type = "syslog_tls"
            endpoint = "logs.example.com"
            server_name = "logs.example.com"
            [[profiles]]
            name = "p"
            protocol = "ssh2"
            host = "h"
        "#;
        let (c, _) = load_str(raw, false).unwrap();
        let d = validate(&c);
        assert!(d.errors.is_empty(), "errors: {:?}", d.errors);
    }

    #[test]
    fn syslog_tls_invalid_certs_warns() {
        let raw = r#"
            version = 1
            [logging]
            [[logging.remote]]
            name = "tls"
            type = "syslog_tls"
            endpoint = "logs.example.com"
            allow_invalid_certs = true
            [[profiles]]
            name = "p"
            protocol = "ssh2"
            host = "h"
        "#;
        let (c, _) = load_str(raw, false).unwrap();
        let d = validate(&c);
        assert!(d
            .warnings
            .iter()
            .any(|w| w.code == "syslog_tls_invalid_certs_allowed"));
        // t5-e2: legacy field name also yields a deprecation warning.
        assert!(
            d.warnings
                .iter()
                .any(|w| w.code == "remote_log_allow_invalid_certs_deprecated"),
            "missing deprecation: {:?}",
            d.warnings
        );
    }

    // ---------- t5-e2: schema round-trip + deprecation tests ----------

    #[test]
    fn t5e2_schema_round_trip_logging_remote_new_fields() {
        let raw = r#"
            version = 1
            [logging]
            [[logging.remote]]
            name = "tls"
            type = "syslog_tls"
            endpoint = "logs.example.com"
            allow_self_signed = true
            pin_spki_sha256 = ["SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"]
            max_cert_chain_depth = 3
            [[profiles]]
            name = "p"
            protocol = "ssh2"
            host = "h"
        "#;
        let (c, _) = load_str(raw, false).unwrap();
        let r = &c.logging.as_ref().unwrap().remote[0];
        assert_eq!(r.allow_self_signed, Some(true));
        assert_eq!(r.pin_spki_sha256.len(), 1);
        assert_eq!(r.max_cert_chain_depth, Some(3));
    }

    #[test]
    fn t5e2_allow_self_signed_requires_pin_set_errors() {
        let raw = r#"
            version = 1
            [logging]
            [[logging.remote]]
            name = "tls"
            type = "syslog_tls"
            endpoint = "logs.example.com"
            allow_self_signed = true
            [[profiles]]
            name = "p"
            protocol = "ssh2"
            host = "h"
        "#;
        let (c, _) = load_str(raw, false).unwrap();
        let d = validate(&c);
        assert!(
            d.errors
                .iter()
                .any(|e| e.code == "remote_log_allow_self_signed_without_pin"),
            "expected fail-closed error, got: {:?}",
            d.errors
        );
    }

    #[test]
    fn t5e2_schema_round_trip_event_sink_new_fields() {
        let raw = r#"
            version = 1
            [events]
            [[events.sinks]]
            name = "alerts"
            type = "http"
            url = "https://example.com/alerts"
            allow_self_signed = false
            pin_spki_sha256 = ["SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"]
            max_cert_chain_depth = 7
        "#;
        let (c, _) = load_str(raw, false).unwrap();
        let s = &c.events.as_ref().unwrap().sinks[0];
        assert_eq!(s.allow_self_signed, Some(false));
        assert_eq!(
            s.pin_spki_sha256,
            vec!["SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB".to_string()]
        );
        assert_eq!(s.max_cert_chain_depth, Some(7));
    }

    #[test]
    fn t5e2_schema_round_trip_remote_config_new_fields() {
        let raw = r#"
            version = 1
            [runtime]
            [runtime.remote_config]
            enabled = true
            url = "https://example.com/cfg"
            fingerprint_sha256 = "deadbeef"
            allow_self_signed = false
            pin_spki_sha256 = ["SHA256:CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"]
            max_cert_chain_depth = 4
        "#;
        let (c, _) = load_str(raw, false).unwrap();
        let rc = c.runtime.as_ref().unwrap().remote_config.as_ref().unwrap();
        assert_eq!(rc.pin_spki_sha256.len(), 1);
        assert_eq!(rc.allow_self_signed, Some(false));
        assert_eq!(rc.max_cert_chain_depth, Some(4));
    }

    #[test]
    fn t5e2_schema_round_trip_mcp_new_fields() {
        let raw = r#"
            version = 1
            [mcp]
            enabled = true
            pin_spki_sha256 = ["SHA256:DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD"]
            allow_self_signed = false
            max_cert_chain_depth = 2
        "#;
        let (c, _) = load_str(raw, false).unwrap();
        let m = c.mcp.as_ref().unwrap();
        assert_eq!(m.pin_spki_sha256.len(), 1);
        assert_eq!(m.allow_self_signed, Some(false));
        assert_eq!(m.max_cert_chain_depth, Some(2));
    }

    #[test]
    fn duplicate_remote_log_sink_errors() {
        let raw = r#"
            version = 1
            [logging]
            [[logging.remote]]
            name = "dup"
            type = "syslog_udp"
            endpoint = "127.0.0.1"
            [[logging.remote]]
            name = "dup"
            type = "syslog_tcp"
            endpoint = "127.0.0.1"
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
            .any(|e| e.code == "duplicate_remote_log_sink"));
    }

    #[test]
    fn network_policy_validates_gateway_and_load_balance() {
        let raw = r#"
            version = 1
            [network.interface]
            default_interface = "eth0"
            allowed_interfaces = ["eth0"]
            bind_ipv6 = "auto"
            [network.gateway]
            interface = "eth0"
            route_check_target = "198.51.100.10"
            require_gateway_match = true
            policy = "route_to_target"
            [network.load_balance]
            strategy = "weighted"
            fail_after = 2
            restore_after = "30s"
            [[profiles]]
            name = "p"
            protocol = "ssh2"
            host = "h"
        "#;
        let (c, _) = load_str(raw, false).unwrap();
        let d = validate(&c);
        assert!(d.errors.is_empty(), "errors: {:?}", d.errors);
    }

    #[test]
    fn snmp_enabled_requires_enterprise_id() {
        let raw = r#"
            version = 1
            [observability.snmp]
            enabled = true
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
            .any(|e| e.code == "snmp_enterprise_id_required"));
    }

    #[test]
    fn snmp_placeholder_enterprise_errors_when_enabled() {
        let raw = r#"
            version = 1
            [observability.snmp]
            enabled = true
            enterprise_id = 99999
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
            .any(|e| e.code == "snmp_enterprise_id_placeholder"));
    }

    #[test]
    fn snmp_documentation_enterprise_warns_when_disabled() {
        let raw = r#"
            version = 1
            [observability.snmp]
            enterprise_id = 32473
            [[profiles]]
            name = "p"
            protocol = "ssh2"
            host = "h"
        "#;
        let (c, _) = load_str(raw, false).unwrap();
        let d = validate(&c);
        assert!(d
            .warnings
            .iter()
            .any(|w| w.code == "snmp_enterprise_id_documentation"));
    }
}
