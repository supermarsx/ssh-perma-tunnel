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
    Auth as AuthCfg, Capabilities, Config, Crypto as CryptoCfg, Profile, Trust as TrustCfg,
};
use spt_core::{Error, Result};
use spt_protocol::{Endpoint, TunnelProtocol};
use spt_secrets::Resolver;
use spt_ssh2::{CryptoPolicy, Ssh2BackendKind, Ssh2Protocol, TrustPolicy};
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

fn build_with_capabilities(
    profile: &Profile,
    resolver: &Resolver,
    capabilities: Option<&Capabilities>,
) -> Result<ProfileBundle> {
    let auth = build_auth_config(profile)?;
    let endpoints = build_endpoints(profile);

    let protocol: Arc<dyn TunnelProtocol> = match profile.protocol.as_str() {
        "ssh2" => Arc::new(build_ssh2(profile, resolver, &endpoints, capabilities)?),
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
    })
}

fn build_ssh2(
    profile: &Profile,
    resolver: &Resolver,
    endpoints: &[Endpoint],
    capabilities: Option<&Capabilities>,
) -> Result<Ssh2Protocol> {
    // Pull the resolver's backend chain into the protocol so the auth flow can
    // resolve `secret://` references at connect time.
    let final_hosts = endpoints
        .iter()
        .map(|endpoint| (endpoint.host.clone(), endpoint.port))
        .collect::<Vec<_>>();
    let mut builder = Ssh2Protocol::builder()
        .backend_kind(select_ssh2_backend(capabilities)?)
        .crypto(build_crypto_policy(profile.crypto.as_ref()))
        .trust(build_trust_policy(profile.trust.as_ref(), &final_hosts)?);
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

fn select_ssh2_backend(capabilities: Option<&Capabilities>) -> Result<Ssh2BackendKind> {
    let requested = capabilities
        .and_then(|capabilities| capabilities.ssh2_backend.as_deref())
        .unwrap_or("russh");
    let backend = requested.parse::<Ssh2BackendKind>()?;
    if backend == Ssh2BackendKind::Libssh2
        && capabilities.and_then(|cap| cap.allow_libssh2) == Some(false)
    {
        return Err(Error::PermissionDenied(
            "capabilities.allow_libssh2 = false blocks ssh2_backend = \"libssh2\"".into(),
        ));
    }
    Ok(backend)
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
    let methods = auth
        .map(|auth| translate_auth(auth, context))
        .transpose()?
        .unwrap_or_default();
    Ok(AuthConfig::new(username.unwrap_or_default(), methods))
}

fn translate_auth(a: &AuthCfg, context: &str) -> Result<Vec<AuthMethod>> {
    // `Auth` in the schema is a permissive accumulator of fields; we
    // translate the *first* declared method only in M0 and let unset
    // configs round-trip as an empty method list (the supervisor will
    // surface an `AuthFailed` on the first connect attempt).
    let mut out = Vec::new();
    if let Some(p) = &a.password {
        let secret = AuthSecretRef::parse(p).map_err(|e| {
            Error::InvalidConfig(format!("{context}.password: invalid secret reference: {e}"))
        })?;
        out.push(AuthMethod::Password { secret });
    }
    if let Some(key) = &a.identity_file {
        let passphrase = a
            .passphrase
            .as_ref()
            .map(|p| AuthSecretRef::parse(p))
            .transpose()
            .map_err(|e| Error::InvalidConfig(format!("{context}.passphrase: {e}")))?;
        out.push(AuthMethod::PublicKey {
            identity_file: std::path::PathBuf::from(key),
            passphrase,
        });
    }
    if a.agent.unwrap_or(false) {
        out.push(AuthMethod::Agent { socket: None });
    }
    Ok(out)
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
    fn ssh2_backend_selector_defaults_to_russh() {
        assert_eq!(select_ssh2_backend(None).unwrap(), Ssh2BackendKind::Russh);
    }

    #[test]
    fn ssh2_backend_selector_honors_legacy_libssh2_policy() {
        let caps = Capabilities {
            ssh2_backend: Some("libssh2".into()),
            allow_libssh2: Some(true),
            ..Default::default()
        };
        assert_eq!(
            select_ssh2_backend(Some(&caps)).unwrap(),
            Ssh2BackendKind::Libssh2
        );
    }

    #[test]
    fn ssh2_backend_selector_blocks_libssh2_when_policy_denies_it() {
        let caps = Capabilities {
            ssh2_backend: Some("libssh2".into()),
            allow_libssh2: Some(false),
            ..Default::default()
        };
        assert!(matches!(
            select_ssh2_backend(Some(&caps)),
            Err(Error::PermissionDenied(_))
        ));
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
}
