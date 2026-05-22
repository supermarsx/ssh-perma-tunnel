//! Build the `(Arc<dyn TunnelProtocol>, AuthConfig, Vec<Endpoint>,
//! ProfileSupervisorConfig)` tuple expected by
//! [`spt_supervisor::Orchestrator::start_profile`] from one
//! [`spt_config::schema::Profile`].
//!
//! Kept intentionally minimal for M0:
//! - Protocol selection is by `profile.protocol` string (`"ssh2"` / `"ssh3"`).
//! - Auth methods that require deeper resolution (e.g. inline secrets vs
//!   `secret://` references) are passed through verbatim — the protocol
//!   backend resolves them at connect time using the resolver chain we
//!   bake into the protocol via the secrets bridge.
//! - Endpoint list defaults to a single `(host, port)` derived from the
//!   profile's top-level fields when `[[profiles.endpoints]]` is empty.
//! - SSH2 trust / crypto policy: defaults (M0); spec-rich policy is M3.

#![allow(clippy::needless_pass_by_value)]

use std::sync::Arc;

use spt_auth::{AuthConfig, AuthMethod, SecretRef as AuthSecretRef};
use spt_config::schema::{
    Auth as AuthCfg, Capabilities, Config, Crypto as CryptoCfg, Profile,
    ScriptConfig as SchemaScriptConfig, Trust as TrustCfg,
};
use spt_core::{Error, Result};
use spt_protocol::{Endpoint, TunnelProtocol};
use spt_scripting::{
    config::{ScriptConfig, ScriptHooks, ScriptLimits},
    ScriptEngine,
};
use spt_secrets::Resolver;
use spt_ssh2::{CryptoPolicy, Ssh2Protocol, TrustPolicy};
use spt_ssh3::{Ssh3Config, Ssh3Protocol};
use spt_supervisor::{BackoffConfig, FailoverMode, ProfileSupervisorConfig};
use spt_trust::{KnownHosts, Sha256HostPin};

/// All the bits needed to start one profile.
pub struct ProfileBundle {
    /// Protocol implementation, ready for `Orchestrator::start_profile`.
    pub protocol: Arc<dyn TunnelProtocol>,
    /// Username + ordered auth methods.
    pub auth: AuthConfig,
    /// Endpoints to try (priority/weight ordered downstream by the selector).
    pub endpoints: Vec<Endpoint>,
    /// Backoff/instability/failover/runner tuning. M0: defaults.
    pub supervisor_cfg: ProfileSupervisorConfig,
    // t6-Bwire: scripting hook engine built from `Profile::script`. `None`
    // when the profile does not declare a script. The supervisor attaches it
    // to each fresh `Ssh2Session` via `with_script_engine` (the protocol-side
    // plumbing through `Ssh2Protocol` is tracked as a follow-up; this field
    // is the construction-site half of the contract t6-e7 carved out).
    pub script_engine: Option<Arc<ScriptEngine>>,
}

/// Connection material for one-shot SFTP operations against an SSH2 profile.
pub struct SftpProfileBundle {
    /// SSH2 protocol implementation with the profile trust, crypto, hop, and
    /// secret resolver policy applied.
    pub protocol: Ssh2Protocol,
    /// Username and auth methods.
    pub auth: AuthConfig,
    /// Candidate endpoints in config order.
    pub endpoints: Vec<Endpoint>,
}

/// Build a [`ProfileBundle`] for one profile.
pub fn build(profile: &Profile, resolver: &Resolver) -> Result<ProfileBundle> {
    build_with_capabilities(profile, resolver, None)
}

/// Build a [`ProfileBundle`] for one profile using top-level config policy.
pub fn build_with_config(
    profile: &Profile,
    resolver: &Resolver,
    config: &Config,
) -> Result<ProfileBundle> {
    build_with_capabilities(profile, resolver, config.capabilities.as_ref())
}

/// Build a one-shot SFTP bundle from an SSH2 profile.
pub fn build_sftp(
    profile: &Profile,
    resolver: &Resolver,
    config: &Config,
) -> Result<SftpProfileBundle> {
    if profile.protocol != "ssh2" {
        return Err(Error::UnsupportedPlatform(format!(
            "profile `{}` uses protocol `{}`; SFTP requires SSH2",
            profile.name, profile.protocol
        )));
    }
    let capabilities = config.capabilities.as_ref();
    if !matches!(
        capabilities.and_then(|capabilities| capabilities.allow_sftp),
        Some(true)
    ) {
        return Err(Error::PermissionDenied(
            "capabilities.allow_sftp = true is required for SFTP operations".into(),
        ));
    }

    let auth = build_auth_config(profile)?;
    let endpoints = build_endpoints(profile);
    // SFTP one-shot bundle does not need scripting hooks — pass `None`.
    let protocol = build_ssh2(profile, resolver, &endpoints, capabilities, None)?;
    Ok(SftpProfileBundle {
        protocol,
        auth,
        endpoints,
    })
}

fn build_with_capabilities(
    profile: &Profile,
    resolver: &Resolver,
    capabilities: Option<&Capabilities>,
) -> Result<ProfileBundle> {
    let auth = build_auth_config(profile)?;
    let endpoints = build_endpoints(profile);

    // t6-Bwire:start — build a `ScriptEngine` from `[profiles.script]` if
    // configured. Errors at load are surfaced as `Error::InvalidConfig` so
    // the startup path fails loudly (per t6-e7 contract). The engine is
    // wrapped in `Arc` so the supervisor can clone it cheaply per session.
    let script_engine = build_script_engine(profile)?;
    // t6-Bwire:end

    let protocol: Arc<dyn TunnelProtocol> = match profile.protocol.as_str() {
        // t7-A2: thread `script_engine` into `Ssh2Protocol::builder` so the
        // protocol can clone it onto every freshly-built `Ssh2Session`.
        "ssh2" => Arc::new(build_ssh2(
            profile,
            resolver,
            &endpoints,
            capabilities,
            script_engine.clone(),
        )?),
        "ssh3" => Arc::new(build_ssh3(profile)),
        other => {
            return Err(Error::InvalidConfig(format!(
                "profile `{}`: unknown protocol `{other}` (expected ssh2|ssh3)",
                profile.name
            )));
        }
    };

    Ok(ProfileBundle {
        protocol,
        auth,
        endpoints,
        supervisor_cfg: build_supervisor_config(profile)?,
        script_engine,
    })
}

// t6-Bwire:start
/// Build the optional scripting engine from `profile.script`. Returns
/// `Ok(None)` when the profile does not declare a script.
///
/// Errors at this site are mapped to `Error::InvalidConfig` so an invalid
/// script aborts profile registration rather than silently disabling hooks.
///
/// t7-B1: the engine is wired to a [`crate::audit::ScriptAuditBridge`]
/// so every script load and hook invocation lands in the workspace
/// audit sink. Tests that need to assert against a captured sink go
/// through `spt_core::audit::register_audit_sink` (see
/// `crates/spt-bin/src/audit.rs::tests`).
pub(crate) fn build_script_engine(profile: &Profile) -> Result<Option<Arc<ScriptEngine>>> {
    let Some(script) = profile.script.as_ref() else {
        return Ok(None);
    };
    let cfg = translate_script_config(script);
    let engine = ScriptEngine::load(&cfg)
        .map_err(Error::from)?
        .with_audit_sink(crate::audit::ScriptAuditBridge::arc());
    Ok(Some(Arc::new(engine)))
}

fn translate_script_config(schema: &SchemaScriptConfig) -> ScriptConfig {
    let hooks = schema
        .hooks
        .as_ref()
        .map(|h| ScriptHooks {
            pre_connect: h.pre_connect.clone(),
            post_connect: h.post_connect.clone(),
            on_forward_state: h.on_forward_state.clone(),
            on_disconnect: h.on_disconnect.clone(),
            on_event: h.on_event.clone(),
        })
        .unwrap_or_default();
    let mut limits = ScriptLimits::default();
    if let Some(l) = schema.limits.as_ref() {
        if let Some(v) = l.max_operations {
            limits.max_operations = v;
        }
        if let Some(v) = l.max_call_levels {
            limits.max_call_levels = v as usize;
        }
        if let Some(v) = l.max_string_size {
            limits.max_string_size = v as usize;
        }
        if let Some(v) = l.max_array_size {
            limits.max_array_size = v as usize;
        }
        if let Some(v) = l.max_modules {
            limits.max_modules = v as usize;
        }
    }
    ScriptConfig {
        path: std::path::PathBuf::from(&schema.path),
        hooks,
        limits,
    }
}
// t6-Bwire:end

fn build_ssh2(
    profile: &Profile,
    resolver: &Resolver,
    endpoints: &[Endpoint],
    capabilities: Option<&Capabilities>,
    script_engine: Option<Arc<ScriptEngine>>,
) -> Result<Ssh2Protocol> {
    // Pull the resolver's backend chain into the protocol so the auth flow can
    // resolve `secret://` references at connect time.
    let final_hosts = endpoints
        .iter()
        .map(|endpoint| (endpoint.host.clone(), endpoint.port))
        .collect::<Vec<_>>();
    warn_legacy_ssh2_backend_capability(capabilities);
    let crypto = build_crypto_policy(profile.crypto.as_ref());
    reject_unsupported_post_quantum_runtime(profile, capabilities, &crypto)?;
    let mut builder = Ssh2Protocol::builder()
        .crypto(crypto)
        .trust(build_trust_policy(profile.trust.as_ref(), &final_hosts)?)
        // t7-A2: thread the scripting engine through the builder so the
        // protocol can attach it to every freshly-handshaked `Ssh2Session`.
        .script_engine(script_engine)
        // t7-Bwire: install the workspace audit bridge for GSSAPI/SSPI token
        // exchanges (closes t7-B1 follow-up #1). The bridge is zero-sized
        // and fans every event out through `spt_core::audit::record_audit`.
        .gssapi_audit_hook(Some(crate::audit::GssapiAuditBridge::arc()));
    for b in resolver.backend_arcs() {
        builder = builder.backend(Arc::clone(b));
    }
    for hop in &profile.hops {
        let hop_auth = build_auth_config_parts(
            hop.user.as_deref().or(profile.user.as_deref()),
            hop.auth.as_ref().or(profile.auth.as_ref()),
            "hops.auth",
        )?;
        let hop_trust = build_trust_policy(
            hop.trust.as_ref().or(profile.trust.as_ref()),
            &[(hop.host.clone(), hop.port)],
        )?;
        builder = builder.hop_with_auth_trust(&hop.host, hop.port, hop_auth, hop_trust);
    }
    Ok(builder.build())
}

fn reject_unsupported_post_quantum_runtime(
    profile: &Profile,
    capabilities: Option<&Capabilities>,
    crypto: &CryptoPolicy,
) -> Result<()> {
    if crypto.has_post_quantum_kex()
        || matches!(
            capabilities.and_then(|capabilities| capabilities.require_post_quantum_kex),
            Some(true)
        )
    {
        return Err(Error::UnsupportedPlatform(format!(
            "profile `{}` requests SSH post-quantum KEX, but the current SSH2 backends do not implement ML-KEM/SNTRUP KEX yet",
            profile.name
        )));
    }
    Ok(())
}

/// t7-Phase0: surface a one-shot deprecation warning when a profile still
/// pins `capabilities.ssh2_backend` or `capabilities.allow_libssh2`. Both
/// keys are accepted at load (so old configs continue to work) and
/// silently ignored at runtime — russh is the only SSH2 backend.
fn warn_legacy_ssh2_backend_capability(capabilities: Option<&Capabilities>) {
    let Some(cap) = capabilities else { return };
    if let Some(value) = cap.ssh2_backend.as_deref() {
        tracing::warn!(
            target: "spt_bin::profile_factory",
            ssh2_backend = value,
            warning_code = "capabilities_ssh2_backend_deprecated_t7",
            "capabilities.ssh2_backend is deprecated since t7-Phase0; libssh2 was removed, russh is the only backend"
        );
    }
    if cap.allow_libssh2.is_some() {
        tracing::warn!(
            target: "spt_bin::profile_factory",
            warning_code = "capabilities_ssh2_backend_deprecated_t7",
            "capabilities.allow_libssh2 is deprecated since t7-Phase0; the field is ignored"
        );
    }
}

fn build_ssh3(profile: &Profile) -> Ssh3Protocol {
    // M0: only `acknowledge_experimental` is propagated; the deeper
    // `[profiles.ssh3]` / `[profiles.tls]` knobs land with M2.
    let cfg = Ssh3Config {
        acknowledge_experimental: profile.acknowledge_experimental.unwrap_or(false),
        ..Ssh3Config::default()
    };
    Ssh3Protocol::new(cfg)
}

fn build_supervisor_config(profile: &Profile) -> Result<ProfileSupervisorConfig> {
    let mut cfg = ProfileSupervisorConfig::default();

    if let Some(reconnect) = profile.reconnect.as_ref() {
        cfg.backoff = build_backoff_config(&profile.name, reconnect)?;
    }

    if let Some(failover) = profile.failover.as_ref() {
        if let Some(mode) = failover.mode.as_deref() {
            cfg.failover_mode = match mode {
                "priority" => FailoverMode::Priority,
                "weighted" => FailoverMode::Weighted,
                "manual" => FailoverMode::Manual,
                other => {
                    return Err(Error::InvalidConfig(format!(
                        "profile `{}`: unknown failover.mode `{other}`",
                        profile.name
                    )));
                }
            };
        }
        if let Some(fail_after) = failover.fail_after {
            if fail_after == 0 {
                return Err(Error::InvalidConfig(format!(
                    "profile `{}`: failover.fail_after must be greater than zero",
                    profile.name
                )));
            }
            cfg.failover_fail_after = fail_after;
        }
        if let Some(raw) = failover.restore_after.as_deref() {
            cfg.failover_cooldown =
                parse_profile_duration(&profile.name, "failover.restore_after", raw)?;
        }
    }

    Ok(cfg)
}

fn build_backoff_config(
    profile_name: &str,
    reconnect: &spt_config::schema::Reconnect,
) -> Result<BackoffConfig> {
    let mut cfg = BackoffConfig::default();
    if let Some(raw) = reconnect.initial_delay.as_deref() {
        cfg.initial_delay = parse_profile_duration(profile_name, "reconnect.initial_delay", raw)?;
    }
    if let Some(raw) = reconnect.max_delay.as_deref() {
        cfg.max_delay = parse_profile_duration(profile_name, "reconnect.max_delay", raw)?;
    }
    if let Some(raw) = reconnect.reset_after.as_deref() {
        cfg.reset_after = parse_profile_duration(profile_name, "reconnect.reset_after", raw)?;
    }
    if let Some(raw) = reconnect.jitter.as_deref() {
        cfg.jitter = parse_jitter_ratio(profile_name, raw)?;
    }
    if let Some(max_attempts) = reconnect.max_attempts {
        cfg.max_attempts = max_attempts;
    }
    Ok(cfg)
}

fn parse_profile_duration(
    profile_name: &str,
    field: &str,
    raw: &str,
) -> Result<std::time::Duration> {
    spt_core::duration::parse_duration(raw)
        .map_err(|e| Error::InvalidConfig(format!("profile `{profile_name}`: {field}: {e}")))
}

fn parse_jitter_ratio(profile_name: &str, raw: &str) -> Result<f32> {
    let trimmed = raw.trim();
    let ratio = if let Some(percent) = trimmed.strip_suffix('%') {
        percent.trim().parse::<f32>().map(|value| value / 100.0)
    } else {
        trimmed.parse::<f32>()
    }
    .map_err(|e| {
        Error::InvalidConfig(format!(
            "profile `{profile_name}`: reconnect.jitter `{trimmed}` is invalid: {e}"
        ))
    })?;

    if (0.0..=1.0).contains(&ratio) {
        Ok(ratio)
    } else {
        Err(Error::InvalidConfig(format!(
            "profile `{profile_name}`: reconnect.jitter `{trimmed}` must be between 0% and 100%"
        )))
    }
}

fn build_crypto_policy(crypto: Option<&CryptoCfg>) -> CryptoPolicy {
    let Some(crypto) = crypto else {
        return CryptoPolicy::default();
    };
    CryptoPolicy {
        ciphers: crypto.ciphers.clone().unwrap_or_default(),
        kex: crypto.kex_algorithms.clone().unwrap_or_default(),
        macs: crypto.macs.clone().unwrap_or_default(),
        host_keys: crypto.host_key_algorithms.clone().unwrap_or_default(),
        compression: crypto.compression.clone().unwrap_or_default(),
    }
}

fn build_auth_config(profile: &Profile) -> Result<AuthConfig> {
    build_auth_config_parts(profile.user.as_deref(), profile.auth.as_ref(), "auth")
}

fn build_auth_config_parts(
    username: Option<&str>,
    auth: Option<&AuthCfg>,
    context: &str,
) -> Result<AuthConfig> {
    let username = username.unwrap_or_default();
    let methods = auth
        .map(|auth| translate_auth(auth, username, context))
        .transpose()?
        .unwrap_or_default();
    Ok(AuthConfig::new(username, methods))
}

fn translate_auth(a: &AuthCfg, username: &str, context: &str) -> Result<Vec<AuthMethod>> {
    let method = normalize_auth_method(&a.method);
    let passphrase = || {
        a.passphrase
            .as_ref()
            .map(|p| AuthSecretRef::parse(p))
            .transpose()
            .map_err(|e| Error::InvalidConfig(format!("{context}.passphrase: {e}")))
    };
    let password = || {
        let p = a
            .password
            .as_ref()
            .ok_or_else(|| Error::InvalidConfig(format!("{context}.password is required")))?;
        AuthSecretRef::parse(p).map_err(|e| {
            Error::InvalidConfig(format!("{context}.password: invalid secret reference: {e}"))
        })
    };
    let token = || {
        let p = a
            .token
            .as_ref()
            .ok_or_else(|| Error::InvalidConfig(format!("{context}.token is required")))?;
        AuthSecretRef::parse(p).map_err(|e| {
            Error::InvalidConfig(format!("{context}.token: invalid secret reference: {e}"))
        })
    };

    let method = match method.as_str() {
        "password" => {
            let secret = password()?;
            let mut methods = vec![AuthMethod::Password { secret }];
            if a.keyboard_interactive.unwrap_or(false) {
                methods.push(AuthMethod::KeyboardInteractive {
                    responder: vec![spt_auth::KbiResponder {
                        prompt_regex: "(?i)password".into(),
                        answer: spt_auth::KbiAnswer::SecretRef(password()?),
                        echo: false,
                    }],
                });
            }
            return Ok(methods);
        }
        "public_key" => {
            let key = a.identity_file.as_ref().ok_or_else(|| {
                Error::InvalidConfig(format!("{context}.identity_file is required"))
            })?;
            if let Some(cert) = a.certificate_file.as_ref() {
                AuthMethod::Certificate {
                    cert: std::path::PathBuf::from(cert),
                    key: std::path::PathBuf::from(key),
                    passphrase: passphrase()?,
                }
            } else {
                AuthMethod::PublicKey {
                    identity_file: std::path::PathBuf::from(key),
                    passphrase: passphrase()?,
                    allow_ssh_rsa_sha1: false,
                }
            }
        }
        "agent" => AuthMethod::Agent { socket: None },
        "keyboard_interactive" => AuthMethod::KeyboardInteractive {
            responder: vec![spt_auth::KbiResponder {
                prompt_regex: "(?i)password".into(),
                answer: spt_auth::KbiAnswer::SecretRef(password()?),
                echo: false,
            }],
        },
        "certificate" => AuthMethod::Certificate {
            cert: std::path::PathBuf::from(a.certificate_file.as_ref().ok_or_else(|| {
                Error::InvalidConfig(format!("{context}.certificate_file is required"))
            })?),
            key: std::path::PathBuf::from(a.identity_file.as_ref().ok_or_else(|| {
                Error::InvalidConfig(format!("{context}.identity_file is required"))
            })?),
            passphrase: passphrase()?,
        },
        "bearer" => AuthMethod::Bearer { token: token()? },
        "basic" => AuthMethod::Basic {
            username: username.to_owned(),
            password: password()?,
        },
        "oidc_device_flow" => AuthMethod::OidcDeviceFlow {
            issuer: a
                .oidc_issuer
                .as_ref()
                .ok_or_else(|| Error::InvalidConfig(format!("{context}.oidc_issuer is required")))?
                .parse()
                .map_err(|e| Error::InvalidConfig(format!("{context}.oidc_issuer: {e}")))?,
            client_id: a.oidc_client_id.clone().ok_or_else(|| {
                Error::InvalidConfig(format!("{context}.oidc_client_id is required"))
            })?,
            audience: None,
        },
        "gssapi" => AuthMethod::Gssapi {
            service: a.gssapi_service.clone(),
            principal: a.gssapi_principal.clone(),
            delegate: a.gssapi_delegate.unwrap_or(false),
        },
        "sspi" => AuthMethod::Sspi {
            service: a.sspi_service.clone(),
            principal: a.sspi_principal.clone(),
            delegate: a.sspi_delegate.unwrap_or(false),
            allow_ntlm_fallback: a.sspi_allow_ntlm_fallback.unwrap_or(false),
        },
        other => {
            return Err(Error::InvalidConfig(format!(
                "{context}.method `{other}` is not supported"
            )));
        }
    };
    Ok(vec![method])
}

fn normalize_auth_method(method: &str) -> String {
    match method.trim().to_ascii_lowercase().as_str() {
        "publickey" | "public-key" | "ssh3_public_key" => "public_key".into(),
        "bearer_token" => "bearer".into(),
        "http_basic" => "basic".into(),
        "oidc" => "oidc_device_flow".into(),
        "kerberos" | "gssapi-with-mic" | "gssapi_with_mic" => "gssapi".into(),
        "negotiate" => "sspi".into(),
        other => other.into(),
    }
}

fn build_trust_policy(trust: Option<&TrustCfg>, hosts: &[(String, u16)]) -> Result<TrustPolicy> {
    let Some(trust) = trust else {
        return Ok(TrustPolicy::default());
    };
    let known_hosts = trust
        .known_hosts_file
        .as_ref()
        .map(|path| KnownHosts::load(std::path::Path::new(path)))
        .transpose()?;

    let sha256_pins = trust.pin_sha256.as_ref().map(|pins| {
        let mut pin_map = Sha256HostPin::new();
        for (host, port) in hosts {
            for pin in pins {
                pin_map.insert(host, *port, pin.clone());
            }
        }
        pin_map
    });

    Ok(TrustPolicy {
        known_hosts,
        sha256_pins,
        strict: trust.strict.unwrap_or(false),
    })
}

fn build_endpoints(profile: &Profile) -> Vec<Endpoint> {
    if !profile.endpoints.is_empty() {
        return profile
            .endpoints
            .iter()
            .map(|e| Endpoint {
                host: e.host.clone(),
                port: e.port,
                address_family: None,
                priority: e.priority.unwrap_or(0),
                weight: e.weight.unwrap_or(1),
            })
            .collect();
    }
    let host = profile.host.clone().unwrap_or_default();
    let port = profile.port.unwrap_or(default_port_for(&profile.protocol));
    if host.is_empty() {
        // Idle profile (no endpoints) — supervisor will exhaust backoff and
        // surface a clean error on each attempt. We still register it so the
        // status snapshot lists the profile.
        return Vec::new();
    }
    vec![Endpoint::new(host, port)]
}

const fn default_port_for(protocol: &str) -> u16 {
    match protocol.as_bytes() {
        b"ssh3" => 443,
        _ => 22,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use spt_config::load::load_str;
    use spt_secrets::EnvBackend;

    fn empty_resolver() -> Resolver {
        Resolver::new(vec![Arc::new(EnvBackend::new())])
    }

    #[test]
    fn ssh2_default_endpoint_falls_back_to_host() {
        let cfg = r#"
            version = 1
            [[profiles]]
            name = "p"
            protocol = "ssh2"
            host = "example.com"
            user = "alice"
        "#;
        let (c, _) = load_str(cfg, false).unwrap();
        let bundle = build(&c.profiles[0], &empty_resolver()).unwrap();
        assert_eq!(bundle.endpoints.len(), 1);
        assert_eq!(bundle.endpoints[0].host, "example.com");
        assert_eq!(bundle.endpoints[0].port, 22);
        assert_eq!(bundle.auth.username, "alice");
        assert_eq!(bundle.protocol.name(), "ssh2");
    }

    #[test]
    fn ssh3_uses_default_443() {
        let cfg = r#"
            version = 1
            [[profiles]]
            name = "p"
            protocol = "ssh3"
            host = "h"
            user = "u"
            acknowledge_experimental = true
        "#;
        let (c, _) = load_str(cfg, false).unwrap();
        let bundle = build(&c.profiles[0], &empty_resolver()).unwrap();
        assert_eq!(bundle.endpoints[0].port, 443);
        assert_eq!(bundle.protocol.name(), "ssh3");
    }

    #[test]
    fn empty_host_yields_no_endpoints() {
        let cfg = r#"
            version = 1
            [[profiles]]
            name = "p"
            protocol = "ssh2"
        "#;
        let (c, _) = load_str(cfg, false).unwrap();
        let bundle = build(&c.profiles[0], &empty_resolver()).unwrap();
        assert!(bundle.endpoints.is_empty());
    }

    #[test]
    fn agent_method_translates_without_extra_flag() {
        let cfg = r#"
            version = 1
            [[profiles]]
            name = "p"
            protocol = "ssh2"
            host = "example.com"
            user = "alice"
            [profiles.auth]
            method = "agent"
        "#;
        let (c, _) = load_str(cfg, false).unwrap();
        let bundle = build(&c.profiles[0], &empty_resolver()).unwrap();
        assert!(matches!(bundle.auth.methods[0], AuthMethod::Agent { .. }));
    }

    #[test]
    fn gssapi_method_translates_to_explicit_auth_variant() {
        let cfg = r#"
            version = 1
            [capabilities]
            allow_gssapi = true
            [[profiles]]
            name = "p"
            protocol = "ssh2"
            host = "example.com"
            user = "alice"
            [profiles.auth]
            method = "kerberos"
            gssapi_service = "host/edge.example.com"
            gssapi_delegate = true
        "#;
        let (c, _) = load_str(cfg, false).unwrap();
        let bundle = build_with_config(&c.profiles[0], &empty_resolver(), &c).unwrap();
        match &bundle.auth.methods[0] {
            AuthMethod::Gssapi {
                service, delegate, ..
            } => {
                assert_eq!(service.as_deref(), Some("host/edge.example.com"));
                assert!(*delegate);
            }
            other => panic!("expected GSSAPI method, got {other:?}"),
        }
    }

    #[test]
    fn reconnect_and_failover_feed_supervisor_config() {
        let cfg = r#"
            version = 1
            [[profiles]]
            name = "p"
            protocol = "ssh2"
            host = "h"
            user = "u"

            [profiles.reconnect]
            initial_delay = "250ms"
            max_delay = "2s"
            reset_after = "5s"
            jitter = "25%"
            max_attempts = 7

            [profiles.failover]
            mode = "weighted"
            fail_after = 3
            restore_after = "30s"
        "#;
        let (c, _) = load_str(cfg, false).unwrap();
        let bundle = build(&c.profiles[0], &empty_resolver()).unwrap();
        assert_eq!(
            bundle.supervisor_cfg.backoff.initial_delay,
            std::time::Duration::from_millis(250)
        );
        assert_eq!(
            bundle.supervisor_cfg.backoff.max_delay,
            std::time::Duration::from_secs(2)
        );
        assert_eq!(
            bundle.supervisor_cfg.backoff.reset_after,
            std::time::Duration::from_secs(5)
        );
        assert!((bundle.supervisor_cfg.backoff.jitter - 0.25).abs() < f32::EPSILON);
        assert_eq!(bundle.supervisor_cfg.backoff.max_attempts, 7);
        assert_eq!(bundle.supervisor_cfg.failover_mode, FailoverMode::Weighted);
        assert_eq!(bundle.supervisor_cfg.failover_fail_after, 3);
        assert_eq!(
            bundle.supervisor_cfg.failover_cooldown,
            std::time::Duration::from_secs(30)
        );
    }

    #[test]
    fn crypto_table_maps_to_ssh2_policy() {
        let policy = build_crypto_policy(Some(&CryptoCfg {
            ciphers: Some(vec!["aes256-ctr".into()]),
            kex_algorithms: Some(vec!["diffie-hellman-group14-sha256".into()]),
            macs: Some(vec!["hmac-sha2-256".into()]),
            host_key_algorithms: Some(vec!["rsa-sha2-256".into()]),
            compression: Some(vec!["none".into()]),
            ..Default::default()
        }));
        assert_eq!(policy.ciphers, vec!["aes256-ctr"]);
        assert_eq!(policy.kex, vec!["diffie-hellman-group14-sha256"]);
        assert_eq!(policy.macs, vec!["hmac-sha2-256"]);
        assert_eq!(policy.host_keys, vec!["rsa-sha2-256"]);
        assert_eq!(policy.compression, vec!["none"]);
    }

    #[test]
    fn post_quantum_kex_returns_explicit_runtime_unsupported() {
        let cfg = r#"
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
        let (c, _) = load_str(cfg, false).unwrap();
        match build_with_config(&c.profiles[0], &empty_resolver(), &c) {
            Err(Error::UnsupportedPlatform(message)) => {
                assert!(message.contains("post-quantum KEX"));
            }
            Ok(_) => panic!("expected UnsupportedPlatform error"),
            Err(other) => panic!("expected UnsupportedPlatform, got {other:?}"),
        }
    }

    #[test]
    fn unknown_protocol_returns_invalid_config_error() {
        let cfg = r#"
            version = 1
            [[profiles]]
            name = "p"
            protocol = "ssh4"
            host = "h"
        "#;
        let (c, _) = load_str(cfg, false).unwrap();
        match build(&c.profiles[0], &empty_resolver()) {
            Err(Error::InvalidConfig(_)) => {}
            Ok(_) => panic!("expected InvalidConfig error"),
            Err(other) => panic!("expected InvalidConfig, got {other:?}"),
        }
    }

    #[test]
    fn explicit_endpoints_table_overrides_top_level_host() {
        let cfg = r#"
            version = 1
            [[profiles]]
            name = "p"
            protocol = "ssh2"
            host = "top.example"
            port = 22
            [[profiles.endpoints]]
            name = "primary"
            host = "ep1.example"
            port = 2222
            priority = 5
            weight = 3
            [[profiles.endpoints]]
            name = "backup"
            host = "ep2.example"
            port = 22
        "#;
        let (c, _) = load_str(cfg, false).unwrap();
        let bundle = build(&c.profiles[0], &empty_resolver()).unwrap();
        assert_eq!(bundle.endpoints.len(), 2);
        assert_eq!(bundle.endpoints[0].host, "ep1.example");
        assert_eq!(bundle.endpoints[0].port, 2222);
        assert_eq!(bundle.endpoints[0].priority, 5);
        assert_eq!(bundle.endpoints[0].weight, 3);
        // Endpoint with no priority/weight defaults to 0/1.
        assert_eq!(bundle.endpoints[1].priority, 0);
        assert_eq!(bundle.endpoints[1].weight, 1);
    }

    #[test]
    fn build_crypto_policy_none_returns_default() {
        let policy = build_crypto_policy(None);
        assert!(policy.ciphers.is_empty());
        assert!(policy.kex.is_empty());
        assert!(policy.macs.is_empty());
    }

    #[test]
    fn legacy_capabilities_ssh2_backend_key_is_accepted_at_load_with_warning() {
        // t7-Phase0: the libssh2 backend was removed. Old configs that pin
        // `capabilities.ssh2_backend` and/or `capabilities.allow_libssh2`
        // still load — the helper emits a structured warning and the
        // values are ignored at runtime.
        let caps = Capabilities {
            ssh2_backend: Some("libssh2".into()),
            allow_libssh2: Some(false),
            ..Default::default()
        };
        // Smoke: no panic, no return value to assert against — the warning
        // is observable via tracing subscribers.
        warn_legacy_ssh2_backend_capability(Some(&caps));
        warn_legacy_ssh2_backend_capability(None);
    }

    #[test]
    fn default_port_for_protocol_matches_ssh2_and_ssh3() {
        assert_eq!(default_port_for("ssh2"), 22);
        assert_eq!(default_port_for("ssh3"), 443);
        assert_eq!(default_port_for("anything-else"), 22);
    }

    #[test]
    fn unknown_failover_mode_errors() {
        let cfg = r#"
            version = 1
            [[profiles]]
            name = "p"
            protocol = "ssh2"
            host = "h"
            [profiles.failover]
            mode = "round-robin"
        "#;
        let (c, _) = load_str(cfg, false).unwrap();
        match build(&c.profiles[0], &empty_resolver()) {
            Err(Error::InvalidConfig(_)) => {}
            Ok(_) => panic!("expected InvalidConfig error"),
            Err(other) => panic!("expected InvalidConfig, got {other:?}"),
        }
    }

    #[test]
    fn fail_after_zero_errors() {
        let cfg = r#"
            version = 1
            [[profiles]]
            name = "p"
            protocol = "ssh2"
            host = "h"
            [profiles.failover]
            mode = "priority"
            fail_after = 0
        "#;
        let (c, _) = load_str(cfg, false).unwrap();
        match build(&c.profiles[0], &empty_resolver()) {
            Err(Error::InvalidConfig(_)) => {}
            Ok(_) => panic!("expected InvalidConfig error"),
            Err(other) => panic!("expected InvalidConfig, got {other:?}"),
        }
    }

    #[test]
    fn jitter_rejects_out_of_range() {
        let err = parse_jitter_ratio("p", "150%").unwrap_err();
        assert!(matches!(err, Error::InvalidConfig(_)));
        let err = parse_jitter_ratio("p", "-0.1").unwrap_err();
        assert!(matches!(err, Error::InvalidConfig(_)));
    }

    #[test]
    fn jitter_accepts_percent_and_decimal() {
        assert!((parse_jitter_ratio("p", "0%").unwrap() - 0.0).abs() < f32::EPSILON);
        assert!((parse_jitter_ratio("p", "100%").unwrap() - 1.0).abs() < f32::EPSILON);
        assert!((parse_jitter_ratio("p", "0.5").unwrap() - 0.5).abs() < f32::EPSILON);
        assert!((parse_jitter_ratio("p", "  25 %  ").unwrap() - 0.25).abs() < f32::EPSILON);
    }

    #[test]
    fn jitter_rejects_unparseable_string() {
        let err = parse_jitter_ratio("p", "not-a-number").unwrap_err();
        assert!(matches!(err, Error::InvalidConfig(_)));
    }

    #[test]
    fn parse_profile_duration_propagates_invalid() {
        let err =
            parse_profile_duration("p", "reconnect.initial_delay", "not-a-duration").unwrap_err();
        assert!(matches!(err, Error::InvalidConfig(_)));
    }

    #[test]
    fn parse_profile_duration_round_trips_basic_units() {
        assert_eq!(
            parse_profile_duration("p", "field", "500ms").unwrap(),
            std::time::Duration::from_millis(500)
        );
        assert_eq!(
            parse_profile_duration("p", "field", "2s").unwrap(),
            std::time::Duration::from_secs(2)
        );
    }

    // t6-Bwire:start
    /// `[profiles.script]` → `ScriptEngine` is constructed and the
    /// `pre_connect` hook fires when invoked. Pins the
    /// `build_script_engine` contract owned by Bwire.
    #[test]
    fn profile_script_constructs_engine_and_pre_connect_fires() {
        use spt_scripting::config::HookName;
        use spt_scripting::event::{Event, PreConnect};

        let dir = tempfile::tempdir().expect("tempdir");
        let script_path = dir.path().join("hooks.rhai");
        std::fs::write(
            &script_path,
            "fn before(event) { print(`pre-connect: ${event.host}`); }\n",
        )
        .expect("write script");

        let cfg = format!(
            r#"
            version = 1
            [[profiles]]
            name = "edge"
            protocol = "ssh2"
            host = "example.com"
            user = "alice"
            [profiles.script]
            path = {path:?}
            [profiles.script.hooks]
            pre_connect = "before"
            "#,
            path = script_path.to_string_lossy()
        );
        let (c, _) = load_str(&cfg, false).expect("load");
        let bundle =
            build_with_config(&c.profiles[0], &empty_resolver(), &c).expect("build_with_config");
        let engine = bundle
            .script_engine
            .as_ref()
            .expect("ScriptEngine must be constructed when [profiles.script] is set");

        let event = Event::PreConnect(PreConnect {
            profile: "edge".into(),
            host: "example.com".into(),
            port: 22,
            attempt: 1,
        });
        engine
            .invoke(HookName::PreConnect, &event)
            .expect("invoke pre_connect");

        let snap = engine.recorder_snapshot();
        assert_eq!(snap.calls.len(), 1, "pre_connect must fire exactly once");
        assert_eq!(snap.calls[0].0, HookName::PreConnect);
    }

    /// Absent `[profiles.script]` → `script_engine == None`.
    #[test]
    fn profile_without_script_yields_none_engine() {
        let cfg = r#"
            version = 1
            [[profiles]]
            name = "p"
            protocol = "ssh2"
            host = "h"
        "#;
        let (c, _) = load_str(cfg, false).unwrap();
        let bundle = build(&c.profiles[0], &empty_resolver()).unwrap();
        assert!(bundle.script_engine.is_none());
    }

    /// `Profile::auth.method = "sspi"` translates into the explicit
    /// `AuthMethod::Sspi` variant with all four fields populated. The
    /// runtime dispatch path from this `AuthMethod` into `spt-auth-sspi`
    /// is pinned by `crates/spt-ssh2/src/auth.rs` and exercised by the
    /// integration test in `tests/it_t6_bwire.rs`.
    #[test]
    fn sspi_auth_method_translates_to_explicit_authmethod_variant() {
        let cfg = r#"
            version = 1
            [capabilities]
            allow_libssh2 = true
            [[profiles]]
            name = "win-edge"
            protocol = "ssh2"
            host = "example.com"
            user = "alice"
            [profiles.auth]
            method = "sspi"
            sspi_service = "host/edge.example.com"
            sspi_delegate = true
            sspi_allow_ntlm_fallback = false
        "#;
        let (c, _) = load_str(cfg, false).unwrap();
        let bundle = build_with_config(&c.profiles[0], &empty_resolver(), &c).unwrap();
        match &bundle.auth.methods[0] {
            AuthMethod::Sspi {
                service,
                delegate,
                allow_ntlm_fallback,
                ..
            } => {
                assert_eq!(service.as_deref(), Some("host/edge.example.com"));
                assert!(*delegate);
                assert!(!*allow_ntlm_fallback);
            }
            other => panic!("expected AuthMethod::Sspi, got {other:?}"),
        }
    }
    // t6-Bwire:end
}
