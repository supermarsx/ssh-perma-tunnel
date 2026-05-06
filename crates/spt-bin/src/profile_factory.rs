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
use spt_config::schema::{Auth as AuthCfg, Profile};
use spt_core::{Error, Result};
use spt_protocol::{Endpoint, TunnelProtocol};
use spt_secrets::Resolver;
use spt_ssh2::Ssh2Protocol;
use spt_ssh3::{Ssh3Config, Ssh3Protocol};
use spt_supervisor::ProfileSupervisorConfig;

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
    let protocol: Arc<dyn TunnelProtocol> = match profile.protocol.as_str() {
        "ssh2" => Arc::new(build_ssh2(resolver)),
        "ssh3" => Arc::new(build_ssh3(profile)),
        other => {
            return Err(Error::InvalidConfig(format!(
                "profile `{}`: unknown protocol `{other}` (expected ssh2|ssh3)",
                profile.name
            )));
        }
    };

    let auth = build_auth_config(profile)?;
    let endpoints = build_endpoints(profile);

    Ok(ProfileBundle {
        protocol,
        auth,
        endpoints,
        supervisor_cfg: ProfileSupervisorConfig::default(),
    })
}

fn build_ssh2(resolver: &Resolver) -> Ssh2Protocol {
    // Pull the resolver's backend chain into the protocol so the auth flow
    // can resolve `secret://` references at connect time. M0 ships with
    // permissive trust + default crypto; spec-rich wiring is M3.
    let mut builder = Ssh2Protocol::builder();
    for b in resolver.backend_arcs() {
        builder = builder.backend(Arc::clone(b));
    }
    builder.build()
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

fn build_auth_config(profile: &Profile) -> Result<AuthConfig> {
    let username = profile.user.clone().unwrap_or_default();
    let methods = profile
        .auth
        .as_ref()
        .map(translate_auth)
        .transpose()?
        .unwrap_or_default();
    Ok(AuthConfig::new(username, methods))
}

fn translate_auth(a: &AuthCfg) -> Result<Vec<AuthMethod>> {
    // `Auth` in the schema is a permissive accumulator of fields; we
    // translate the *first* declared method only in M0 and let unset
    // configs round-trip as an empty method list (the supervisor will
    // surface an `AuthFailed` on the first connect attempt).
    let mut out = Vec::new();
    if let Some(p) = &a.password {
        let secret = AuthSecretRef::parse(p).map_err(|e| {
            Error::InvalidConfig(format!("auth.password: invalid secret reference: {e}"))
        })?;
        out.push(AuthMethod::Password { secret });
    }
    if let Some(key) = &a.identity_file {
        let passphrase = a
            .passphrase
            .as_ref()
            .map(|p| AuthSecretRef::parse(p))
            .transpose()
            .map_err(|e| Error::InvalidConfig(format!("auth.passphrase: {e}")))?;
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
}
