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
    Auth as AuthCfg, Capabilities, Config, Connection as ConnectionCfg, Crypto as CryptoCfg,
    Hop as HopCfg, HopKind as SchemaHopKind, Limits as LimitsCfg, Profile,
    ScriptConfig as SchemaScriptConfig, Trust as TrustCfg,
};
use spt_config_crypt::KeySource;
use spt_core::{Diagnostic, DnsResolution, Error, Result};
use spt_protocol::{Endpoint, ForwardRateLimits, TargetResolve, TunnelProtocol};
use spt_scripting::{
    config::{ScriptConfig, ScriptHooks, ScriptLimits},
    ScriptEngine,
};
use spt_secrets::{Resolver, SecretRef as SecretsRef};
use spt_ssh2::{
    crypto::resolve_crypto_policy, multi_hop::HopKind, proxy_jump::ProxyCredentials,
    ConnectionPolicy, CryptoPolicy, Ssh2Protocol, TrustPolicy,
};
use spt_ssh3::{Ssh3Config, Ssh3Protocol, Ssh3TlsConfig};
use spt_supervisor::{
    BackoffConfig, FailoverMode, HealthCheckStyle, InstabilityAction, ProfileSupervisorConfig,
};
use spt_trust::{ChainDepthCap, KnownHosts, Sha256HostPin, TlsPin};

/// All the bits needed to start one profile.
pub struct ProfileBundle {
    /// Protocol implementation, ready for `Orchestrator::start_profile`.
    pub protocol: Arc<dyn TunnelProtocol>,
    /// Username + ordered auth methods. Profile-level / global default auth.
    /// Retained as the fallback used by the SFTP one-shot path and by any
    /// connect attempt for which no per-endpoint override resolves.
    pub auth: AuthConfig,
    /// Endpoints to try (priority/weight ordered downstream by the selector).
    pub endpoints: Vec<Endpoint>,
    /// Per-endpoint resolved auth, index-aligned with `endpoints` (same length
    /// and ordering). Each entry is built with the Hop-style fallback
    /// `endpoint.user.or(profile.user)` / `endpoint.auth.or(profile.auth)`, so
    /// an endpoint without its own `user`/`auth` inherits the profile-level
    /// (global) credentials, while an endpoint that sets them carries its own.
    /// The supervisor selects the right `AuthConfig` for the chosen endpoint by
    /// index. Empty exactly when `endpoints` is empty.
    pub endpoint_auth: Vec<AuthConfig>,
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
    build_with_capabilities(profile, resolver, None, None)
}

/// Build a [`ProfileBundle`] for one profile using top-level config policy.
pub fn build_with_config(
    profile: &Profile,
    resolver: &Resolver,
    config: &Config,
) -> Result<ProfileBundle> {
    build_with_options(profile, resolver, config, &BuildOptions::default())
}

/// Optional knobs for [`build_with_config`]/[`build_with_options`]. Additive so
/// existing call sites can keep using [`build_with_config`] unchanged while
/// newer (Phase-2) call sites opt into the extra plumbing.
///
/// - `config_path` anchors a relative `[profiles.script].path` to the config
///   file's parent directory (E8-F13). Under systemd/SCM the process CWD is
///   typically `/` or `%SystemRoot%`, so resolving relative to CWD breaks
///   service startup. When `None`, paths resolve against CWD (legacy
///   behaviour).
/// - `key_source` is the non-interactive [`KeySource`] used when a sealed
///   (`SPTENC1`) config must be opened without a controlling TTY (E5-F10 prep).
///   This factory does not itself load the config — the field is threaded so
///   that Phase-2's `cli_dispatch` daemon/reload paths can plumb it into the
///   `spt_config::load_with_key` call and avoid an interactive passphrase
///   prompt under a service manager. It is intentionally inert here; consuming
///   it is `p2-dispatch-security`'s job.
#[derive(Default)]
pub struct BuildOptions<'a> {
    /// Path to the loading config file (its parent dir anchors relative
    /// script paths). `None` ⇒ resolve relative to the process CWD.
    pub config_path: Option<&'a std::path::Path>,
    /// Non-interactive key source for sealed configs. Plumbed for Phase-2;
    /// not consumed by the factory itself.
    pub key_source: Option<&'a KeySource>,
}

/// Build a [`ProfileBundle`] honoring [`BuildOptions`] (config-file anchoring
/// for relative script paths, and the non-interactive [`KeySource`] seam).
pub fn build_with_options(
    profile: &Profile,
    resolver: &Resolver,
    config: &Config,
    options: &BuildOptions<'_>,
) -> Result<ProfileBundle> {
    // `key_source` is intentionally not consumed here — see `BuildOptions`.
    let _ = options.key_source;
    build_with_capabilities(
        profile,
        resolver,
        config.capabilities.as_ref(),
        options.config_path,
    )
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
    config_path: Option<&std::path::Path>,
) -> Result<ProfileBundle> {
    let auth = build_auth_config(profile)?;
    let endpoints = build_endpoints(profile);
    let endpoint_auth = build_endpoint_auths(profile)?;

    // t6-Bwire:start — build a `ScriptEngine` from `[profiles.script]` if
    // configured. Errors at load are surfaced as `Error::InvalidConfig` so
    // the startup path fails loudly (per t6-e7 contract). The engine is
    // wrapped in `Arc` so the supervisor can clone it cheaply per session.
    // E8-F13: anchor a relative script path to the config file's parent dir.
    let script_engine = build_script_engine(profile, config_path)?;
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
        "ssh3" => Arc::new(build_ssh3(profile)?),
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
        endpoint_auth,
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
pub(crate) fn build_script_engine(
    profile: &Profile,
    config_path: Option<&std::path::Path>,
) -> Result<Option<Arc<ScriptEngine>>> {
    let Some(script) = profile.script.as_ref() else {
        return Ok(None);
    };
    let cfg = translate_script_config(script, config_path);
    let engine = ScriptEngine::load(&cfg)
        .map_err(Error::from)?
        .with_audit_sink(crate::audit::ScriptAuditBridge::arc());
    Ok(Some(Arc::new(engine)))
}

/// Resolve a `[profiles.script].path`. Absolute paths are used as-is. A
/// relative path is anchored to the parent directory of the loading config
/// file when `config_path` is known (E8-F13), matching docs/scripting.md
/// ("path is resolved relative to the directory of the loading config
/// file"). When the config path is unknown the path is left relative — it
/// will resolve against the process CWD as before.
fn resolve_script_path(raw: &str, config_path: Option<&std::path::Path>) -> std::path::PathBuf {
    let candidate = std::path::PathBuf::from(raw);
    if candidate.is_absolute() {
        return candidate;
    }
    match config_path.and_then(std::path::Path::parent) {
        Some(dir) => dir.join(candidate),
        None => candidate,
    }
}

fn translate_script_config(
    schema: &SchemaScriptConfig,
    config_path: Option<&std::path::Path>,
) -> ScriptConfig {
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
        path: resolve_script_path(&schema.path, config_path),
        hooks,
        limits,
    }
}
// t6-Bwire:end

/// Map the on-disk `[profiles.transport.obfuscation]` schema enum onto the
/// engine-facing [`spt_obfs::ObfsConfig`] (E3-F2). The two enums share the
/// `#[serde(tag = "kind", rename_all = "kebab-case")]` wire shape, but the
/// schema carries hex-encoded `obfs4` key material as `String`s (parsed here)
/// and the Shadowsocks `method` as a `String` (parsed via serde). Validated
/// before it reaches the dial path.
fn map_obfs_config(schema: &spt_config::schema::ObfsConfig) -> Result<spt_obfs::ObfsConfig> {
    use spt_config::schema::ObfsConfig as S;
    let mapped = match schema {
        S::Obfs4 {
            node_id,
            public_key,
            iat_mode,
        } => {
            let nid = hex::decode(node_id)
                .map_err(|e| Error::InvalidConfig(format!("obfs4 node_id hex: {e}")))?;
            let pk = hex::decode(public_key)
                .map_err(|e| Error::InvalidConfig(format!("obfs4 public_key hex: {e}")))?;
            let node_id: [u8; 20] = nid.try_into().map_err(|_| {
                Error::InvalidConfig("obfs4 node_id must be 20 bytes (40 hex chars)".into())
            })?;
            let public_key: [u8; 32] = pk.try_into().map_err(|_| {
                Error::InvalidConfig("obfs4 public_key must be 32 bytes (64 hex chars)".into())
            })?;
            spt_obfs::ObfsConfig::Obfs4 {
                node_id,
                public_key,
                iat_mode: *iat_mode,
            }
        }
        S::MeekHttp {
            url,
            front_host,
            sni,
        } => spt_obfs::ObfsConfig::MeekHttp {
            url: url.clone(),
            front_host: front_host.clone(),
            sni: sni.clone(),
        },
        S::Websocket { url, headers } => spt_obfs::ObfsConfig::Websocket {
            url: url.clone(),
            headers: headers.clone(),
        },
        S::Shadowsocks { method, password } => {
            let method: spt_obfs::SsMethod =
                serde_json::from_value(serde_json::Value::String(method.clone())).map_err(|e| {
                    Error::InvalidConfig(format!("shadowsocks method `{method}`: {e}"))
                })?;
            spt_obfs::ObfsConfig::Shadowsocks {
                method,
                password: password.clone(),
            }
        }
        // `schema::ObfsConfig` is `#[non_exhaustive]`; reject any future
        // variant we don't yet map rather than silently dialing plain TCP.
        other => {
            return Err(Error::InvalidConfig(format!(
                "unsupported obfuscation kind in config: {other:?}"
            )))
        }
    };
    mapped
        .validate()
        .map_err(|e| Error::InvalidConfig(format!("obfuscation config: {e}")))?;
    Ok(mapped)
}

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
    let mut crypto = build_crypto_policy(profile.crypto.as_ref())?;
    apply_post_quantum_capability_policy(&mut crypto, capabilities)?;
    let mut builder = Ssh2Protocol::builder()
        .crypto(crypto)
        .trust(build_trust_policy(
            profile.trust.as_ref(),
            &final_hosts,
            &profile.name,
            "profiles.trust",
        )?)
        // t7-A2: thread the scripting engine through the builder so the
        // protocol can attach it to every freshly-handshaked `Ssh2Session`.
        .script_engine(script_engine)
        // t7-Bwire: install the workspace audit bridge for GSSAPI/SSPI token
        // exchanges (closes t7-B1 follow-up #1). The bridge is zero-sized
        // and fans every event out through `spt_core::audit::record_audit`.
        .gssapi_audit_hook(Some(crate::audit::GssapiAuditBridge::arc()))
        // E8-F1: carry the profile name into scripting lifecycle events so the
        // `profile` field of pre/post-connect / forward / disconnect payloads
        // is populated (the script-hook dispatch path was wired in
        // russh_backend but had no profile context until now).
        .profile_name(Some(profile.name.clone()));

    // E3-F2: map `[profiles.transport.obfuscation]` → `spt_obfs::ObfsConfig`
    // and feed it to the builder so the obfuscated dial path
    // (russh_backend::dial_outer) is actually reachable from config. Absent
    // → plain TCP (no-op). An obfs audit bridge fans handshake events through
    // the workspace audit seam.
    if let Some(obfs) = profile
        .transport
        .as_ref()
        .and_then(|t| t.obfuscation.as_ref())
    {
        let mapped = map_obfs_config(obfs)?;
        builder = builder.obfuscation(
            Some(Arc::new(mapped)),
            Some(crate::audit::ObfsAuditBridge::arc()),
        );
    }
    for b in resolver.backend_arcs() {
        builder = builder.backend(Arc::clone(b));
    }

    // E3-F1 / A3: feed `[profiles.keepalive]` into the russh transport
    // keepalive policy. `interval` maps to russh `keepalive_interval`;
    // `max_missed` maps to `keepalive_max` (the number of unanswered transport
    // keepalives that closes the session). `None` for either preserves russh's
    // defaults (no transport keepalive; max 3), so an absent block is a no-op.
    if let Some(keepalive) = profile.keepalive.as_ref() {
        let interval = keepalive
            .interval
            .as_deref()
            .map(|raw| parse_profile_duration(&profile.name, "keepalive.interval", raw))
            .transpose()?;
        let max_missed = keepalive.max_missed.map(|v| v as usize);
        builder = builder.keepalive(interval, max_missed);
    }

    // conn-wire: feed the *genuinely wireable* subset of `[profiles.connection]`
    // into the russh dial path. The murky SSH-level timeouts (auth/handshake/
    // read/write) have no clean russh apply site and stay parsed-and-warned in
    // spt-config validate. Absent `[profiles.connection]` → default (no-op)
    // policy, so behaviour is preserved byte-for-byte for existing profiles.
    // `[profiles.connection].dns_resolution` is profile-level (not inside the
    // `[connection]` table), and must take effect even when `[connection]` is
    // absent — so it is threaded into the policy regardless.
    let dns = parse_dns_resolution(&profile.name, profile.dns_resolution.as_deref())?;
    match profile.connection.as_ref() {
        Some(connection) => {
            let mut policy = build_connection_policy(&profile.name, connection)?;
            policy.dns = dns;
            builder = builder.connection(policy);
        }
        None if dns != DnsResolution::PerAttempt => {
            // No `[connection]` table but a non-default dns_resolution: still
            // apply it via an otherwise-default policy (a default policy is a
            // no-op for every other field).
            builder = builder.connection(ConnectionPolicy {
                dns,
                ..ConnectionPolicy::default()
            });
        }
        None => {}
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
            &profile.name,
            if hop.trust.is_some() {
                "hops.trust"
            } else {
                "profiles.trust"
            },
        )?;
        // `[profiles.hops].target_resolve = local`: resolve the hop host
        // client-side and dial the IP literal through the previous leg, instead
        // of letting the previous SSH peer resolve the name (`remote`, the
        // default — and `previous-hop`, which the peer/previous-leg handles).
        let hop_resolve = parse_target_resolve(
            &profile.name,
            &format!("hops.{}.target_resolve", hop.host),
            hop.target_resolve.as_deref(),
        )?;
        let hop_host = if hop_resolve.is_local() {
            resolve_target_local(&profile.name, &hop.host, hop.port)?
        } else {
            hop.host.clone()
        };
        // t6-e3 / A2: dispatch by the hop's transport `kind`. SSH hops keep the
        // historical `direct-tcpip` + re-handshake path; SOCKS5 / HTTP CONNECT
        // proxy hops resolve their optional proxy credentials and go through
        // `hop_with_kind` so the proxy CONNECT runs before the SSH handshake.
        match hop.kind {
            SchemaHopKind::Ssh => {
                builder = builder.hop_with_auth_trust(&hop_host, hop.port, hop_auth, hop_trust);
            }
            SchemaHopKind::Socks5 | SchemaHopKind::HttpConnect => {
                let creds = resolve_proxy_credentials(hop, resolver, &profile.name)?;
                builder = builder.hop_with_kind(
                    &hop_host,
                    hop.port,
                    map_hop_kind(hop.kind),
                    creds,
                    Some(hop_auth),
                    Some(hop_trust),
                );
            }
        }
    }
    Ok(builder.build())
}

/// Map the on-disk `[[profiles.hops]].kind` enum onto the runtime
/// [`spt_ssh2::multi_hop::HopKind`]. The two enums are intentionally distinct
/// (the ssh2 crate keeps no build-time dep on spt-config) so the mapping is
/// hand-written here.
const fn map_hop_kind(kind: SchemaHopKind) -> HopKind {
    match kind {
        SchemaHopKind::Ssh => HopKind::Ssh,
        SchemaHopKind::Socks5 => HopKind::Socks5,
        SchemaHopKind::HttpConnect => HopKind::HttpConnect,
    }
}

/// Resolve a proxy hop's optional `proxy_username` / `proxy_password_ref` into
/// [`ProxyCredentials`].
///
/// * `proxy_username` is a `RedactedString` carried verbatim in the config
///   (cleartext), exposed here for the SOCKS5 / HTTP CONNECT auth handshake.
/// * `proxy_password_ref` is a `secret://` reference resolved through the same
///   resolver chain used for SSH secrets.
///
/// Returns `None` when neither is configured (anonymous proxy). When only one
/// of the pair is present the missing half resolves to an empty string so the
/// proxy still sees a (username, password) pair.
fn resolve_proxy_credentials(
    hop: &HopCfg,
    resolver: &Resolver,
    profile_name: &str,
) -> Result<Option<ProxyCredentials>> {
    if hop.proxy_username.is_none() && hop.proxy_password_ref.is_none() {
        return Ok(None);
    }
    let username = hop
        .proxy_username
        .as_ref()
        .map(|u| u.expose().to_owned())
        .unwrap_or_default();
    let password = match hop.proxy_password_ref.as_ref() {
        Some(secret_ref) => resolve_secret_to_string(secret_ref, resolver, profile_name)?,
        None => String::new(),
    };
    Ok(Some(ProxyCredentials { username, password }))
}

/// Resolve a config [`spt_secrets::SecretRef`] to a UTF-8 `String` through the
/// resolver chain. Used for proxy-password material that the SOCKS5 / HTTP
/// CONNECT handshake needs in cleartext at connect time.
fn resolve_secret_to_string(
    secret_ref: &SecretsRef,
    resolver: &Resolver,
    profile_name: &str,
) -> Result<String> {
    use secrecy::ExposeSecret;
    let bytes = resolver.resolve(secret_ref)?;
    String::from_utf8(bytes.expose_secret().to_vec()).map_err(|e| {
        Error::InvalidConfig(format!(
            "profile `{profile_name}`: proxy_password_ref `{secret_ref}` is not valid UTF-8: {e}"
        ))
    })
}

/// Apply the `[capabilities]` post-quantum policy to the resolved crypto
/// policy's `kex` list (PQ-by-default refinement).
///
/// spt now offers the hybrid PQ KEX `mlkem768x25519-sha256` by default (it
/// leads every preset's `kex` list — see `spt_ssh2::crypto`). This step lets
/// an operator override that default via `[capabilities]`:
///
/// * `require_post_quantum_kex = true` restricts `kex` to the supported PQ KEX
///   (PQ-only, fail-closed);
/// * `allow_post_quantum_kex = false` (or `allow_ml_kem = false`) strips every
///   PQ KEX, leaving the classical fallback.
///
/// Genuinely-unsupported PQ names (e.g. `sntrup761x25519-sha512`) are already
/// rejected earlier, at `resolve_crypto_policy` time. Delegates to
/// [`spt_ssh2::crypto::apply_post_quantum_capability_policy`] for the
/// unit-tested list manipulation.
fn apply_post_quantum_capability_policy(
    crypto: &mut CryptoPolicy,
    capabilities: Option<&Capabilities>,
) -> Result<()> {
    let (allow_pq, allow_ml_kem, require_pq) = capabilities.map_or((None, None, None), |c| {
        (
            c.allow_post_quantum_kex,
            c.allow_ml_kem,
            c.require_post_quantum_kex,
        )
    });
    spt_ssh2::crypto::apply_post_quantum_capability_policy(
        crypto,
        allow_pq,
        allow_ml_kem,
        require_pq,
    )
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

/// Build the SSH3 protocol from a profile, fully consuming `[profiles.tls]`
/// and `[profiles.ssh3]` into an [`Ssh3Config`] / [`Ssh3TlsConfig`].
///
/// Returns `Err(Error::InvalidConfig)` for unparseable durations, malformed
/// TLS pins, or a `[profiles.tls].system_roots = false` without any trust
/// anchor (no `ca_file`, no pins). The assembled config is run through
/// [`Ssh3Config::validate`] before it is wrapped in the protocol, so bad
/// combinations (e.g. `allow_self_signed` without acknowledgement) fail at
/// profile-build time — matching the ssh2 path.
fn build_ssh3(profile: &Profile) -> Result<Ssh3Protocol> {
    let mut cfg = Ssh3Config {
        acknowledge_experimental: profile.acknowledge_experimental.unwrap_or(false),
        ..Ssh3Config::default()
    };

    // `[profiles.tls]` → `Ssh3Config.sni` + `Ssh3TlsConfig`.
    if let Some(tls) = profile.tls.as_ref() {
        // `server_name` → SNI / `:authority`.
        cfg.sni.clone_from(&tls.server_name);

        let mut tls_cfg = Ssh3TlsConfig {
            // `ca_file` → optional private-CA PEM bundle.
            ca_file: tls.ca_file.as_ref().map(std::path::PathBuf::from),
            // `pin_sha256` → parsed SPKI pin set (see `parse_tls_pin`).
            pin: build_tls_pin(&profile.name, tls.pin_sha256.as_deref())?,
            // `allow_self_signed` → carried verbatim; `validate()` enforces the
            // dual-acknowledgement + trust-anchor requirement.
            allow_self_signed: tls.allow_self_signed.unwrap_or(false),
            ..Ssh3TlsConfig::default()
        };
        // `max_cert_chain_depth` → `ChainDepthCap`. Omitted keeps the config's
        // current default (`ChainDepthCap::default()`, set above).
        if let Some(depth) = tls.max_cert_chain_depth {
            tls_cfg.max_cert_chain_depth = ChainDepthCap::new(depth);
        }

        // `system_roots = false` means "do not load the OS trust store". With
        // neither a `ca_file` nor a pin set that leaves no trust anchor at all,
        // which we reject up-front rather than failing opaquely at connect time.
        if tls.system_roots == Some(false)
            && tls_cfg.ca_file.is_none()
            && tls_cfg.pin.spki_sha256.is_empty()
        {
            return Err(Error::InvalidConfig(format!(
                "profile `{}`: tls.system_roots = false requires a trust anchor — \
                 set tls.ca_file or tls.pin_sha256",
                profile.name
            )));
        }

        cfg.tls = tls_cfg;
    }

    // `[profiles.ssh3]` → transport knobs.
    if let Some(ssh3) = profile.ssh3.as_ref() {
        // `idle_timeout` (duration string) → seconds.
        if let Some(raw) = ssh3.idle_timeout.as_deref() {
            let dur = parse_profile_duration(&profile.name, "ssh3.idle_timeout", raw)?;
            cfg.idle_timeout_secs = Some(saturate_u32(dur.as_secs()));
        }
        // `keepalive` (duration string) → seconds (existing field).
        if let Some(raw) = ssh3.keepalive.as_deref() {
            let dur = parse_profile_duration(&profile.name, "ssh3.keepalive", raw)?;
            cfg.keepalive_secs = saturate_u32(dur.as_secs());
        }
        // `max_streams` / `enable_datagrams` / `protocol_token` → direct map.
        if let Some(max_streams) = ssh3.max_streams {
            cfg.max_streams = Some(max_streams);
        }
        if let Some(enable_datagrams) = ssh3.enable_datagrams {
            cfg.enable_datagrams = enable_datagrams;
        }
        cfg.protocol_token.clone_from(&ssh3.protocol_token);
        // `draft` is informational (reference-draft identifier) — no runtime
        // effect; intentionally ignored.
    }

    // `[profiles.connection].dns_resolution` → client-side resolution policy.
    cfg.dns = parse_dns_resolution(&profile.name, profile.dns_resolution.as_deref())?;

    // Fail bad combinations at profile-build time, consistent with ssh2.
    cfg.validate()?;
    Ok(Ssh3Protocol::new(cfg))
}

/// Map `[profiles.connection].dns_resolution` (`per_attempt` | `once`) onto the
/// shared [`DnsResolution`] policy. `None`/absent → [`DnsResolution::PerAttempt`]
/// (default, behaviour-preserving). Unknown values are rejected with
/// [`Error::InvalidConfig`].
fn parse_dns_resolution(profile_name: &str, raw: Option<&str>) -> Result<DnsResolution> {
    match raw {
        None => Ok(DnsResolution::PerAttempt),
        Some(s) => DnsResolution::from_config_str(s).ok_or_else(|| {
            Error::InvalidConfig(format!(
                "profile `{profile_name}`: unknown dns_resolution `{s}` \
                 (expected `per_attempt` or `once`)"
            ))
        }),
    }
}

/// Map a `target_resolve` field (`remote` | `local` | `previous-hop`) onto the
/// shared [`TargetResolve`] policy. `None`/absent → [`TargetResolve::Remote`]
/// (default, behaviour-preserving). Unknown values are rejected with
/// [`Error::InvalidConfig`], naming the config path.
fn parse_target_resolve(profile_name: &str, at: &str, raw: Option<&str>) -> Result<TargetResolve> {
    match raw {
        None => Ok(TargetResolve::Remote),
        Some(s) => TargetResolve::from_config_str(s).ok_or_else(|| {
            Error::InvalidConfig(format!(
                "profile `{profile_name}`: {at} has unknown target_resolve `{s}` \
                 (expected `local`, `remote`, or `previous-hop`)"
            ))
        }),
    }
}

/// Resolve a forward/hop target host CLIENT-SIDE (for `target_resolve = local`)
/// and return the resulting IP literal as a string. The first resolved address
/// is used (matching the existing single-address dial behaviour). Resolution
/// failures surface as [`Error::DnsFailed`].
fn resolve_target_local(profile_name: &str, host: &str, port: u16) -> Result<String> {
    // `PerAttempt` here just means "resolve now via the OS resolver"; the
    // resolved literal is then pinned into the spec/hop, so no cache entry is
    // needed for the substitution itself.
    let addrs = spt_core::resolve_dns(host, port, DnsResolution::PerAttempt).map_err(|e| {
        Error::DnsFailed(format!(
            "profile `{profile_name}`: target_resolve=local could not resolve `{host}:{port}`: {e}"
        ))
    })?;
    let ip = addrs
        .into_iter()
        .next()
        .ok_or_else(|| {
            Error::DnsFailed(format!(
                "profile `{profile_name}`: target_resolve=local resolved no addresses for `{host}`"
            ))
        })?
        .ip();
    Ok(ip.to_string())
}

/// Parse the `[profiles.tls].pin_sha256` string list into a [`TlsPin`].
///
/// Each pin is a SHA-256 SPKI digest encoded as **standard base64** (44 chars
/// including padding for 32 bytes), with an optional `sha256:` prefix that is
/// stripped before decoding. Anything that does not decode to exactly 32 bytes
/// is rejected with an [`Error::InvalidConfig`] naming the offending pin.
fn build_tls_pin(profile_name: &str, pins: Option<&[String]>) -> Result<TlsPin> {
    let Some(pins) = pins else {
        return Ok(TlsPin::default());
    };
    let mut spki_sha256 = Vec::with_capacity(pins.len());
    for pin in pins {
        spki_sha256.push(parse_tls_pin(profile_name, pin)?);
    }
    Ok(TlsPin { spki_sha256 })
}

/// Decode one `[profiles.tls].pin_sha256` entry into a 32-byte SPKI digest.
///
/// Accepted format: standard base64 (with padding) of the raw 32-byte SHA-256
/// digest, optionally prefixed with a case-insensitive `sha256:` marker. The
/// decoded length MUST be exactly 32 bytes.
fn parse_tls_pin(profile_name: &str, pin: &str) -> Result<[u8; 32]> {
    use base64::Engine as _;
    let trimmed = pin.trim();
    // Strip an optional `sha256:` prefix (case-insensitive) before decoding.
    let b64 = trimmed
        .strip_prefix("sha256:")
        .or_else(|| trimmed.strip_prefix("SHA256:"))
        .unwrap_or(trimmed);
    let raw = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .map_err(|e| {
            Error::InvalidConfig(format!(
                "profile `{profile_name}`: tls.pin_sha256 entry `{pin}` is not valid base64: {e}"
            ))
        })?;
    raw.try_into().map_err(|raw: Vec<u8>| {
        Error::InvalidConfig(format!(
            "profile `{profile_name}`: tls.pin_sha256 entry `{pin}` decoded to {} bytes, \
             expected 32 (a base64-encoded SHA-256 SPKI digest)",
            raw.len()
        ))
    })
}

fn build_supervisor_config(profile: &Profile) -> Result<ProfileSupervisorConfig> {
    let mut cfg = ProfileSupervisorConfig::default();

    if let Some(reconnect) = profile.reconnect.as_ref() {
        cfg.backoff = build_backoff_config(&profile.name, reconnect)?;
    }

    // E1-F8: wire `[profiles.keepalive].interval` into the supervisor's
    // in-`run_active` health-poll cadence. Previously this stayed pinned to
    // the hard-coded 30 s default regardless of config.
    if let Some(keepalive) = profile.keepalive.as_ref() {
        if let Some(raw) = keepalive.interval.as_deref() {
            cfg.keepalive_interval =
                parse_profile_duration(&profile.name, "keepalive.interval", raw)?;
        }
        // E1-F11: the per-probe timeout is independent of the probe cadence
        // and must tolerate worst-case healthy round-trip latency, so a
        // slow-but-alive link is not misclassified as `SessionLost`. Defaults
        // to the `ProfileSupervisorConfig::default()` value (10 s) when unset.
        if let Some(raw) = keepalive.timeout.as_deref() {
            cfg.keepalive_timeout =
                parse_profile_duration(&profile.name, "keepalive.timeout", raw)?;
        }
    }

    // E1-F8: wire `[profiles.instability]` into the detector window so
    // `InstabilityCleared`/`SmEvent::InstabilityClear` become reachable and
    // the configured thresholds actually apply. The supervisor consumption
    // side (calling `tick_healthy` on healthy keepalive ticks) is owned by
    // p1-supervisor-core; this side maps the config fields.
    if let Some(instability) = profile.instability.as_ref() {
        if let Some(raw) = instability.window.as_deref() {
            cfg.instability.window =
                parse_profile_duration(&profile.name, "instability.window", raw)?;
        }
        if let Some(max_disconnects) = instability.max_disconnects {
            cfg.instability.max_disconnects = max_disconnects;
        }
        // Schema field `min_successful_uptime` is the "continuous healthy
        // time before the unstable flag clears" knob (InstabilityWindow's
        // `clear_after`).
        if let Some(raw) = instability.min_successful_uptime.as_deref() {
            cfg.instability.clear_after =
                parse_profile_duration(&profile.name, "instability.min_successful_uptime", raw)?;
        }
        // A3: detection on/off. Default `true` keeps the legacy always-on
        // behaviour; `false` makes the detector fully inert.
        if let Some(enabled) = instability.enabled {
            cfg.instability.enabled = enabled;
        }
        // A3: secondary keepalive-miss trip condition (`None` = disabled).
        if let Some(max_keepalive_misses) = instability.max_keepalive_misses {
            cfg.instability.max_keepalive_misses = Some(max_keepalive_misses);
        }
        // A3: p95 latency ceiling (`None` = disabled). The latency source is
        // wired by the supervisor wave; this side only carries the threshold.
        if let Some(raw) = instability.max_latency_p95.as_deref() {
            cfg.instability.max_latency_p95 = Some(parse_profile_duration(
                &profile.name,
                "instability.max_latency_p95",
                raw,
            )?);
        }
        // A3: action taken when the window trips. Map the schema string onto
        // the `InstabilityAction` enum; an unknown action is rejected.
        if let Some(action) = instability.action.as_deref() {
            cfg.instability.action = parse_instability_action(&profile.name, action)?;
        }
    }

    if let Some(failover) = profile.failover.as_ref() {
        // A3: failover health-check probe style. Map the schema string onto
        // `HealthCheckStyle`; an unknown style is rejected here (B2 also
        // validate-warns unimplemented styles).
        if let Some(health_check) = failover.health_check.as_deref() {
            cfg.health_check = parse_health_check_style(&profile.name, health_check)?;
        }
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

    // C1: map `[profiles.limits]` onto the forward runner's profile-level
    // default rate limits. The runner overlays per-forward limits on top of
    // this default (per-component override), so this only supplies the
    // profile-wide baseline. Absent → `ForwardRateLimits::default()`
    // (all-zero = unlimited = prior behaviour).
    if let Some(limits) = profile.limits.as_ref() {
        cfg.runner_cfg.default_limits = build_default_limits(&profile.name, limits)?;
    }

    Ok(cfg)
}

/// Map `[profiles.limits]` → the profile-level [`ForwardRateLimits`] default
/// used by the forward runner. Byte-rate strings (`max_bytes_per_second_*`)
/// are parsed with [`spt_core::size::parse_size`] (plain size, no `/s`
/// suffix); accept-rate (`max_new_connections_per_second`) maps directly.
/// Burst and per-direction caps the schema does not yet expose stay zero
/// (unlimited). The bit-rate (`max_bits_per_second_*`) keys are display-only
/// and intentionally not mapped onto the byte-rate gates.
fn build_default_limits(profile_name: &str, limits: &LimitsCfg) -> Result<ForwardRateLimits> {
    let mut out = ForwardRateLimits::default();
    if let Some(raw) = limits.max_bytes_per_second_out.as_deref() {
        out.rate_bps_up = parse_profile_size(profile_name, "limits.max_bytes_per_second_out", raw)?;
    }
    if let Some(raw) = limits.max_bytes_per_second_in.as_deref() {
        out.rate_bps_down =
            parse_profile_size(profile_name, "limits.max_bytes_per_second_in", raw)?;
    }
    if let Some(max_new) = limits.max_new_connections_per_second {
        out.max_new_conns_per_sec = max_new;
    }
    Ok(out)
}

/// Parse a spec-style byte-size string for a `[profiles.limits]` field,
/// attributing parse errors to the profile + field for actionable diagnostics.
fn parse_profile_size(profile_name: &str, field: &str, raw: &str) -> Result<u64> {
    spt_core::size::parse_size(raw)
        .map_err(|e| Error::InvalidConfig(format!("profile `{profile_name}`: {field}: {e}")))
}

/// Map the *wireable* subset of `[profiles.connection]` onto a runtime
/// [`ConnectionPolicy`] (conn-wire).
///
/// Wired here:
/// * `connect_timeout` → bounds the outermost TCP dial.
/// * `tcp_nodelay` → russh `Config::nodelay` + the dialed socket.
/// * `socket_keepalive` + `keepalive_idle`/`keepalive_interval`/
///   `keepalive_retries` → a socket-level `TcpKeepalive` on the dialed stream.
/// * `channel_window_size` / `channel_max_packet_size` → russh
///   `Config::window_size` / `maximum_packet_size` (the latter clamped to
///   russh's 65535 ceiling at apply time).
/// * `auth_timeout` / `handshake_timeout` → per-operation SSH deadlines
///   (t-tunnel-wire-2; `tokio::time::timeout` wraps in the ssh2 backend).
/// * `read_timeout` / `write_timeout` → COMBINED into a single
///   `channel_idle_timeout` (russh 0.61 has no directional per-op deadline):
///   the tighter (MIN) of the two when both are set, otherwise whichever is set.
///
/// **Deliberately NOT wired** (no clean russh 0.61 apply site; still
/// validate-warned): the channel-open timeout. Channel sizes are parsed with
/// [`spt_core::size::parse_size`] and clamped to `u32`; durations with
/// [`parse_profile_duration`].
fn build_connection_policy(
    profile_name: &str,
    connection: &ConnectionCfg,
) -> Result<ConnectionPolicy> {
    let connect_timeout = connection
        .connect_timeout
        .as_deref()
        .map(|raw| parse_profile_duration(profile_name, "connection.connect_timeout", raw))
        .transpose()?;
    let keepalive_idle = connection
        .keepalive_idle
        .as_deref()
        .map(|raw| parse_profile_duration(profile_name, "connection.keepalive_idle", raw))
        .transpose()?;
    let keepalive_interval = connection
        .keepalive_interval
        .as_deref()
        .map(|raw| parse_profile_duration(profile_name, "connection.keepalive_interval", raw))
        .transpose()?;
    let channel_window_size = connection
        .channel_window_size
        .as_deref()
        .map(|raw| {
            parse_profile_size(profile_name, "connection.channel_window_size", raw)
                .map(saturate_u32)
        })
        .transpose()?;
    let channel_max_packet_size = connection
        .channel_max_packet_size
        .as_deref()
        .map(|raw| {
            parse_profile_size(profile_name, "connection.channel_max_packet_size", raw)
                .map(saturate_u32)
        })
        .transpose()?;
    // t-tunnel-wire-2 (Phase 2, B1): per-operation SSH deadlines. Parsed exactly
    // like `connect_timeout` above (same `parse_profile_duration` humantime
    // helper, same `InvalidConfig` error path).
    let auth_timeout = connection
        .auth_timeout
        .as_deref()
        .map(|raw| parse_profile_duration(profile_name, "connection.auth_timeout", raw))
        .transpose()?;
    let handshake_timeout = connection
        .handshake_timeout
        .as_deref()
        .map(|raw| parse_profile_duration(profile_name, "connection.handshake_timeout", raw))
        .transpose()?;
    let read_timeout = connection
        .read_timeout
        .as_deref()
        .map(|raw| parse_profile_duration(profile_name, "connection.read_timeout", raw))
        .transpose()?;
    let write_timeout = connection
        .write_timeout
        .as_deref()
        .map(|raw| parse_profile_duration(profile_name, "connection.write_timeout", raw))
        .transpose()?;
    // russh 0.61 exposes no directional per-operation deadline, so `read_timeout`
    // and `write_timeout` are applied as a SINGLE combined channel-idle deadline
    // (`ConnectionPolicy.channel_idle_timeout`). When both are set we use the
    // tighter (MIN) of the two; if only one is set we use it; if neither, `None`.
    let channel_idle_timeout = match (read_timeout, write_timeout) {
        (Some(r), Some(w)) => Some(r.min(w)),
        (Some(r), None) => Some(r),
        (None, Some(w)) => Some(w),
        (None, None) => None,
    };
    Ok(ConnectionPolicy {
        tcp_nodelay: connection.tcp_nodelay,
        channel_window_size,
        channel_max_packet_size,
        connect_timeout,
        socket_keepalive: connection.socket_keepalive,
        keepalive_idle,
        keepalive_interval,
        keepalive_retries: connection.keepalive_retries,
        auth_timeout,
        handshake_timeout,
        channel_idle_timeout,
        // `dns_resolution` is profile-level, not in `[connection]`; the caller
        // (`build_ssh2`) overrides this after parsing `profile.dns_resolution`.
        dns: DnsResolution::PerAttempt,
    })
}

/// Clamp a parsed byte-size to the `u32` ceiling russh's channel-flow-control
/// fields use (values larger than `u32::MAX` saturate rather than wrap).
const fn saturate_u32(value: u64) -> u32 {
    if value > u32::MAX as u64 {
        u32::MAX
    } else {
        value as u32
    }
}

/// Map the `[profiles.instability].action` schema string onto the runtime
/// [`InstabilityAction`] enum. Unknown actions are rejected.
fn parse_instability_action(profile_name: &str, action: &str) -> Result<InstabilityAction> {
    match action.trim().to_ascii_lowercase().as_str() {
        "mark_degraded" => Ok(InstabilityAction::MarkDegraded),
        "failover" => Ok(InstabilityAction::Failover),
        "increase_keepalive" => Ok(InstabilityAction::IncreaseKeepalive),
        "increase_backoff" => Ok(InstabilityAction::IncreaseBackoff),
        "emit_event" => Ok(InstabilityAction::EmitEvent),
        "restart_session" => Ok(InstabilityAction::RestartSession),
        other => Err(Error::InvalidConfig(format!(
            "profile `{profile_name}`: unknown instability.action `{other}` (expected \
             mark_degraded|failover|increase_keepalive|increase_backoff|emit_event|restart_session)"
        ))),
    }
}

/// Map the `[profiles.failover].health_check` schema string onto the runtime
/// [`HealthCheckStyle`] enum. Unknown styles are rejected.
fn parse_health_check_style(profile_name: &str, style: &str) -> Result<HealthCheckStyle> {
    match style.trim().to_ascii_lowercase().as_str() {
        "tcp_connect" => Ok(HealthCheckStyle::TcpConnect),
        "ssh_handshake" => Ok(HealthCheckStyle::SshHandshake),
        "ssh_auth_preflight" => Ok(HealthCheckStyle::SshAuthPreflight),
        "ssh3_endpoint" => Ok(HealthCheckStyle::Ssh3Endpoint),
        other => Err(Error::InvalidConfig(format!(
            "profile `{profile_name}`: unknown failover.health_check `{other}` (expected \
             tcp_connect|ssh_handshake|ssh_auth_preflight|ssh3_endpoint)"
        ))),
    }
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
    // A3: `[profiles.reconnect].retry_auth_failures` controls whether an
    // auth-classified connect failure is treated as retryable (default
    // `false` preserves today's behaviour).
    if let Some(retry_auth_failures) = reconnect.retry_auth_failures {
        cfg.retry_auth_failures = retry_auth_failures;
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

/// Map `[profiles.crypto]` onto the runtime [`CryptoPolicy`].
///
/// The operator's explicit per-category allow-lists are resolved through
/// [`resolve_crypto_policy`], which fills empty categories from the named
/// preset (`crypto.policy`, default `"modern"`), rejects deprecated algorithms
/// unless `allow_deprecated = true`, and (when `warn_on_deprecated = true`)
/// logs a warning per deprecated algorithm that survives resolution. When no
/// `[profiles.crypto]` block is present the resolver still fills the default
/// (modern) preset so the connect path gets a non-empty, vetted allow-list.
fn build_crypto_policy(crypto: Option<&CryptoCfg>) -> Result<CryptoPolicy> {
    let (explicit, preset, allow_deprecated, warn_on_deprecated) = match crypto {
        Some(crypto) => (
            CryptoPolicy {
                ciphers: crypto.ciphers.clone().unwrap_or_default(),
                kex: crypto.kex_algorithms.clone().unwrap_or_default(),
                macs: crypto.macs.clone().unwrap_or_default(),
                host_keys: crypto.host_key_algorithms.clone().unwrap_or_default(),
                compression: crypto.compression.clone().unwrap_or_default(),
            },
            crypto.policy.clone(),
            crypto.allow_deprecated.unwrap_or(false),
            crypto.warn_on_deprecated.unwrap_or(false),
        ),
        None => (CryptoPolicy::default(), None, false, false),
    };
    resolve_crypto_policy(
        preset.as_deref(),
        &explicit,
        allow_deprecated,
        warn_on_deprecated,
    )
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
            append_agent_fallback(&mut methods, a);
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
        "agent" => AuthMethod::Agent {
            socket: agent_socket_from_env(),
            // A4: when the primary method *is* agent, the identity hint
            // selects which agent-held key to prefer.
            identity_hint: a.identity_hint.clone(),
        },
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
    let mut methods = vec![method];
    append_agent_fallback(&mut methods, a);
    Ok(methods)
}

/// Resolve the agent socket path from the environment (`SSH_AUTH_SOCK`),
/// returning `None` when unset so the agent provider falls back to its own
/// platform default (Windows named pipe / unix socket discovery).
fn agent_socket_from_env() -> Option<std::path::PathBuf> {
    std::env::var_os("SSH_AUTH_SOCK").map(std::path::PathBuf::from)
}

/// A4 / agent-bool wiring: when `[auth].agent = true` and the primary method
/// is not already an agent method, append an [`AuthMethod::Agent`] fallback so
/// the agent is tried after the primary method. The agent socket is taken from
/// `SSH_AUTH_SOCK` (or `None` for provider default) and `[auth].identity_hint`
/// selects which agent-held key to prefer. A no-op when `agent` is unset/false
/// or the methods already contain an agent method (e.g. `method = "agent"`).
fn append_agent_fallback(methods: &mut Vec<AuthMethod>, a: &AuthCfg) {
    if !a.agent.unwrap_or(false) {
        return;
    }
    if methods
        .iter()
        .any(|m| matches!(m, AuthMethod::Agent { .. }))
    {
        return;
    }
    methods.push(AuthMethod::Agent {
        socket: agent_socket_from_env(),
        identity_hint: a.identity_hint.clone(),
    });
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

fn build_trust_policy(
    trust: Option<&TrustCfg>,
    hosts: &[(String, u16)],
    profile_name: &str,
    context: &str,
) -> Result<TrustPolicy> {
    // Refuse profiles that ship no trust source whatsoever. The historical
    // `TrustPolicy::default()` fallback (no known_hosts + no pins + strict=false)
    // accepted any server key on first connect — a silent TOFU with no audit
    // trail. Operators must either configure a real source or explicitly opt
    // in to TOFU via `accept_new = true` with a `known_hosts_file` path.
    let Some(trust) = trust else {
        return Err(Error::invalid_config(
            Diagnostic::what(format!(
                "profile `{profile_name}` has no `[{context}]` block",
            ))
            .why(
                "without any trust source spt would accept any host key on first \
                 connect, defeating the whole point of host-key verification",
            )
            .how_to_fix(
                "add a `[profiles.<name>.trust]` block with either \
                 `known_hosts_file = \"...\"`, `pin_sha256 = [\"...\"]`, or \
                 `mode = \"known_hosts\"` + `accept_new = true` (TOFU)",
            )
            .build(),
        ));
    };

    // `mode` is operator-facing documentation; cross-validate it against the
    // actual sources to catch contradictory configs early.
    if let Some(mode) = trust.mode.as_deref() {
        let normalized = mode.trim().to_ascii_lowercase();
        match normalized.as_str() {
            "known_hosts" => {
                if trust.known_hosts_file.is_none() && !trust.accept_new.unwrap_or(false) {
                    return Err(Error::invalid_config(
                        Diagnostic::what(format!(
                            "profile `{profile_name}`: `{context}.mode = \"known_hosts\"` \
                             but no `known_hosts_file` and `accept_new = false`",
                        ))
                        .why(
                            "known_hosts mode requires either a populated file or \
                             explicit trust-on-first-use to obtain any host keys",
                        )
                        .how_to_fix(
                            "set `known_hosts_file = \"...\"` and/or \
                             `accept_new = true` (TOFU)",
                        )
                        .build(),
                    ));
                }
            }
            "pinned" => {
                if trust.pin_sha256.as_ref().is_none_or(Vec::is_empty) {
                    return Err(Error::invalid_config(
                        Diagnostic::what(format!(
                            "profile `{profile_name}`: `{context}.mode = \"pinned\"` \
                             but `pin_sha256` is empty or missing",
                        ))
                        .why("pinned mode rejects every host unless a pin matches")
                        .how_to_fix(
                            "set `pin_sha256 = [\"SHA256:...\"]` with at least one \
                             entry, or switch `mode` to `known_hosts`",
                        )
                        .build(),
                    ));
                }
                if trust.accept_new.unwrap_or(false) {
                    return Err(Error::invalid_config(
                        Diagnostic::what(format!(
                            "profile `{profile_name}`: `{context}.mode = \"pinned\"` is \
                             incompatible with `accept_new = true`",
                        ))
                        .why(
                            "TOFU is a known_hosts-only mode; pinned mode rejects \
                             every unknown key by design",
                        )
                        .how_to_fix("remove `accept_new`, or change `mode` to `known_hosts`")
                        .build(),
                    ));
                }
            }
            other => {
                return Err(Error::invalid_config(
                    Diagnostic::what(format!(
                        "profile `{profile_name}`: `{context}.mode = \"{other}\"` is not recognised",
                    ))
                    .why("only `known_hosts` and `pinned` are accepted")
                    .how_to_fix("set `mode` to either `known_hosts` or `pinned`")
                    .build(),
                ));
            }
        }
    }

    let accept_new = trust.accept_new.unwrap_or(false);
    let known_hosts_path = trust
        .known_hosts_file
        .as_ref()
        .map(std::path::PathBuf::from);

    if accept_new && known_hosts_path.is_none() {
        return Err(Error::invalid_config(
            Diagnostic::what(format!(
                "profile `{profile_name}`: `{context}.accept_new = true` requires \
                 `known_hosts_file`",
            ))
            .why(
                "TOFU has nowhere to persist the first-seen key without a target \
                 path — subsequent connects would re-prompt forever",
            )
            .how_to_fix(
                "set `known_hosts_file = \"/path/to/known_hosts\"` (the file will \
                 be created if missing)",
            )
            .build(),
        ));
    }

    // Empty file is fine — it materialises an empty `KnownHosts` and lets TOFU
    // populate it. A missing path with `accept_new = true` is also fine: the
    // first verify() will create it via O_APPEND.
    let known_hosts = match &known_hosts_path {
        Some(p) if p.exists() => Some(KnownHosts::load(p)?),
        _ => None,
    };

    let sha256_pins = trust.pin_sha256.as_ref().map(|pins| {
        let mut pin_map = Sha256HostPin::new();
        for (host, port) in hosts {
            for pin in pins {
                pin_map.insert(host, *port, pin.clone());
            }
        }
        pin_map
    });

    // Refuse a fully-empty policy (no sources, no TOFU) even when `[trust]`
    // is present — same reasoning as the missing-block branch above.
    if known_hosts.is_none() && sha256_pins.is_none() && !accept_new && known_hosts_path.is_none() {
        return Err(Error::invalid_config(
            Diagnostic::what(format!(
                "profile `{profile_name}`: `[{context}]` is present but configures \
                 no trust source",
            ))
            .why(
                "without `known_hosts_file`, `pin_sha256`, or `accept_new = true` \
                 (TOFU) there is nothing to verify the server key against",
            )
            .how_to_fix(
                "set at least one of `known_hosts_file`, `pin_sha256`, or \
                 `accept_new = true` (with a `known_hosts_file` target)",
            )
            .build(),
        ));
    }

    Ok(TrustPolicy {
        known_hosts,
        sha256_pins,
        known_hosts_path,
        strict: trust.strict.unwrap_or(false),
        accept_new,
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

/// Resolve a per-endpoint [`AuthConfig`] for every endpoint, index-aligned with
/// the vec returned by [`build_endpoints`] (same length and ordering).
///
/// Each entry uses the proven Hop-style whole-block fallback: an endpoint's own
/// `user`/`auth` fully override the profile-level values for that endpoint, and
/// an endpoint that sets neither inherits the profile-level (global) defaults —
/// `build_auth_config_parts(ep.user.or(profile.user), ep.auth.or(profile.auth),
/// "endpoints.auth")`.
///
/// The branching mirrors [`build_endpoints`] exactly so the two vecs stay
/// index-aligned:
/// - explicit `[[profiles.endpoints]]` → one entry per endpoint;
/// - implicit single host-derived endpoint → one entry (= profile-level auth,
///   since the synthesised endpoint has no per-endpoint override);
/// - empty host (idle profile, no endpoints) → empty vec.
fn build_endpoint_auths(profile: &Profile) -> Result<Vec<AuthConfig>> {
    if !profile.endpoints.is_empty() {
        return profile
            .endpoints
            .iter()
            .map(|ep| {
                build_auth_config_parts(
                    ep.user.as_deref().or(profile.user.as_deref()),
                    ep.auth.as_ref().or(profile.auth.as_ref()),
                    "endpoints.auth",
                )
            })
            .collect();
    }
    // No explicit endpoints: `build_endpoints` either synthesises a single
    // endpoint from the profile host (→ one profile-level auth) or yields none
    // (empty host). Match that shape so the index alignment holds.
    let host = profile.host.clone().unwrap_or_default();
    if host.is_empty() {
        return Ok(Vec::new());
    }
    Ok(vec![build_auth_config(profile)?])
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
    use std::time::Duration;

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
            [profiles.trust]
            pin_sha256 = ["SHA256:dummy"]
        "#;
        let (c, _) = load_str(cfg, false).unwrap();
        let bundle = build(&c.profiles[0], &empty_resolver()).unwrap();
        assert_eq!(bundle.endpoints.len(), 1);
        assert_eq!(bundle.endpoints[0].host, "example.com");
        assert_eq!(bundle.endpoints[0].port, 22);
        assert_eq!(bundle.auth.username, "alice");
        assert_eq!(bundle.protocol.name(), "ssh2");
    }

    // E3-F2: `map_obfs_config` maps the schema enum onto the engine enum,
    // hex-decoding obfs4 key material and validating it.
    #[test]
    fn map_obfs_websocket_and_meek() {
        let ws = spt_config::schema::ObfsConfig::Websocket {
            url: "wss://front.example/ssh".into(),
            headers: vec![],
        };
        let mapped = map_obfs_config(&ws).unwrap();
        assert!(matches!(mapped, spt_obfs::ObfsConfig::Websocket { .. }));

        let meek = spt_config::schema::ObfsConfig::MeekHttp {
            url: "https://front.example".into(),
            front_host: None,
            sni: None,
        };
        assert!(matches!(
            map_obfs_config(&meek).unwrap(),
            spt_obfs::ObfsConfig::MeekHttp { .. }
        ));
    }

    #[test]
    fn map_obfs4_hex_decodes_key_material() {
        let obfs4 = spt_config::schema::ObfsConfig::Obfs4 {
            node_id: "00".repeat(20),
            public_key: "11".repeat(32),
            iat_mode: 0,
        };
        let mapped = map_obfs_config(&obfs4).unwrap();
        match mapped {
            spt_obfs::ObfsConfig::Obfs4 {
                node_id,
                public_key,
                iat_mode,
            } => {
                assert_eq!(node_id, [0u8; 20]);
                assert_eq!(public_key, [0x11u8; 32]);
                assert_eq!(iat_mode, 0);
            }
            other => panic!("expected Obfs4, got {other:?}"),
        }
    }

    #[test]
    fn map_obfs4_rejects_bad_length() {
        let bad = spt_config::schema::ObfsConfig::Obfs4 {
            node_id: "00".into(), // 1 byte, not 20
            public_key: "11".repeat(32),
            iat_mode: 0,
        };
        assert!(map_obfs_config(&bad).is_err());
    }

    // E3-F2 + E8-F1: a profile carrying `[profiles.transport.obfuscation]`
    // builds successfully — proving the `.obfuscation(...)` + `.profile_name()`
    // builder wiring is reachable from config.
    #[test]
    fn profile_with_obfuscation_builds() {
        let cfg = r#"
            version = 1
            [[profiles]]
            name = "edge"
            protocol = "ssh2"
            host = "example.com"
            user = "alice"
            [profiles.trust]
            pin_sha256 = ["SHA256:dummy"]
            [profiles.transport.obfuscation]
            kind = "websocket"
            url = "wss://front.example/ssh"
            headers = []
        "#;
        let (c, _) = load_str(cfg, false).unwrap();
        let bundle = build(&c.profiles[0], &empty_resolver()).unwrap();
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
            [profiles.trust]
            pin_sha256 = ["SHA256:dummy"]
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
            [profiles.trust]
            pin_sha256 = ["SHA256:dummy"]
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
            [profiles.trust]
            pin_sha256 = ["SHA256:dummy"]
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

            [profiles.trust]
            pin_sha256 = ["SHA256:dummy"]
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
    fn keepalive_interval_feeds_supervisor_config() {
        // E1-F8: `[profiles.keepalive].interval` overrides the 30 s default.
        let cfg = r#"
            version = 1
            [[profiles]]
            name = "p"
            protocol = "ssh2"
            host = "h"
            user = "u"
            [profiles.keepalive]
            interval = "7s"
            [profiles.trust]
            pin_sha256 = ["SHA256:dummy"]
        "#;
        let (c, _) = load_str(cfg, false).unwrap();
        let bundle = build(&c.profiles[0], &empty_resolver()).unwrap();
        assert_eq!(
            bundle.supervisor_cfg.keepalive_interval,
            std::time::Duration::from_secs(7)
        );
    }

    #[test]
    fn keepalive_interval_defaults_to_thirty_seconds_when_absent() {
        // E1-F8: with no `[profiles.keepalive]` the supervisor keeps the
        // documented 30 s default.
        let cfg = r#"
            version = 1
            [[profiles]]
            name = "p"
            protocol = "ssh2"
            host = "h"
            user = "u"
            [profiles.trust]
            pin_sha256 = ["SHA256:dummy"]
        "#;
        let (c, _) = load_str(cfg, false).unwrap();
        let bundle = build(&c.profiles[0], &empty_resolver()).unwrap();
        assert_eq!(
            bundle.supervisor_cfg.keepalive_interval,
            std::time::Duration::from_secs(30)
        );
    }

    #[test]
    fn instability_table_feeds_supervisor_window() {
        // E1-F8: `[profiles.instability]` maps window / max_disconnects /
        // min_successful_uptime onto the detector's `InstabilityWindow`.
        let cfg = r#"
            version = 1
            [[profiles]]
            name = "p"
            protocol = "ssh2"
            host = "h"
            user = "u"
            [profiles.instability]
            window = "45s"
            max_disconnects = 9
            min_successful_uptime = "3m"
            [profiles.trust]
            pin_sha256 = ["SHA256:dummy"]
        "#;
        let (c, _) = load_str(cfg, false).unwrap();
        let bundle = build(&c.profiles[0], &empty_resolver()).unwrap();
        assert_eq!(
            bundle.supervisor_cfg.instability.window,
            std::time::Duration::from_secs(45)
        );
        assert_eq!(bundle.supervisor_cfg.instability.max_disconnects, 9);
        assert_eq!(
            bundle.supervisor_cfg.instability.clear_after,
            std::time::Duration::from_secs(180)
        );
    }

    #[test]
    fn instability_partial_table_keeps_defaults_for_unset_fields() {
        // E1-F8: only `max_disconnects` set — window and clear_after retain
        // their `InstabilityWindow::default()` values (60 s / 120 s).
        let cfg = r#"
            version = 1
            [[profiles]]
            name = "p"
            protocol = "ssh2"
            host = "h"
            user = "u"
            [profiles.instability]
            max_disconnects = 5
            [profiles.trust]
            pin_sha256 = ["SHA256:dummy"]
        "#;
        let (c, _) = load_str(cfg, false).unwrap();
        let bundle = build(&c.profiles[0], &empty_resolver()).unwrap();
        assert_eq!(bundle.supervisor_cfg.instability.max_disconnects, 5);
        assert_eq!(
            bundle.supervisor_cfg.instability.window,
            std::time::Duration::from_secs(60)
        );
        assert_eq!(
            bundle.supervisor_cfg.instability.clear_after,
            std::time::Duration::from_secs(120)
        );
    }

    #[test]
    fn jitter_ratio_is_threaded_into_backoff_config() {
        // E1-F16 (cfg side): the parsed jitter ratio lands in BackoffConfig.
        let cfg = r#"
            version = 1
            [[profiles]]
            name = "p"
            protocol = "ssh2"
            host = "h"
            user = "u"
            [profiles.reconnect]
            jitter = "0%"
            [profiles.trust]
            pin_sha256 = ["SHA256:dummy"]
        "#;
        let (c, _) = load_str(cfg, false).unwrap();
        let bundle = build(&c.profiles[0], &empty_resolver()).unwrap();
        assert!((bundle.supervisor_cfg.backoff.jitter - 0.0).abs() < f32::EPSILON);
    }

    #[test]
    fn relative_script_path_anchors_to_config_dir() {
        // E8-F13: a relative `[profiles.script].path` resolves against the
        // config file's parent directory, not the process CWD.
        let resolved = resolve_script_path(
            "hooks/edge.rhai",
            Some(std::path::Path::new("/etc/spt/config.toml")),
        );
        assert_eq!(resolved, std::path::Path::new("/etc/spt/hooks/edge.rhai"));
    }

    #[test]
    fn absolute_script_path_is_left_untouched() {
        // E8-F13: absolute paths bypass anchoring regardless of config dir.
        let abs = if cfg!(windows) {
            r"C:\scripts\edge.rhai"
        } else {
            "/scripts/edge.rhai"
        };
        let resolved = resolve_script_path(abs, Some(std::path::Path::new("/etc/spt/config.toml")));
        assert_eq!(resolved, std::path::PathBuf::from(abs));
    }

    #[test]
    fn relative_script_path_without_config_dir_stays_relative() {
        // E8-F13: when the config path is unknown, fall back to the legacy
        // CWD-relative behaviour (path returned unchanged).
        let resolved = resolve_script_path("hooks/edge.rhai", None);
        assert_eq!(resolved, std::path::PathBuf::from("hooks/edge.rhai"));
    }

    #[test]
    fn build_with_options_anchors_script_path_to_config_dir() {
        // E8-F13 end-to-end: a relative script path under a config in a temp
        // dir loads when anchored, and the engine is constructed.
        use spt_scripting::config::HookName;
        use spt_scripting::event::{Event, PreConnect};

        let dir = tempfile::tempdir().expect("tempdir");
        let script_rel = "hooks.rhai";
        std::fs::write(
            dir.path().join(script_rel),
            "fn before(event) { print(`pre-connect: ${event.host}`); }\n",
        )
        .expect("write script");
        let config_path = dir.path().join("config.toml");

        // The script path is RELATIVE — it only resolves because we anchor to
        // the config dir via BuildOptions.config_path.
        let cfg = format!(
            r#"
            version = 1
            [[profiles]]
            name = "edge"
            protocol = "ssh2"
            host = "example.com"
            user = "alice"
            [profiles.script]
            path = "{script_rel}"
            [profiles.script.hooks]
            pre_connect = "before"
            [profiles.trust]
            pin_sha256 = ["SHA256:dummy"]
            "#
        );
        std::fs::write(&config_path, &cfg).expect("write config");
        let (c, _) = load_str(&cfg, false).expect("load");
        let options = BuildOptions {
            config_path: Some(config_path.as_path()),
            key_source: None,
        };
        let bundle = build_with_options(&c.profiles[0], &empty_resolver(), &c, &options)
            .expect("build_with_options");
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
        assert_eq!(engine.recorder_snapshot().calls.len(), 1);
    }

    #[test]
    fn crypto_table_maps_to_ssh2_policy() {
        // A non-empty explicit category overrides that category only; the
        // resolver carries the operator's allow-list through verbatim.
        let policy = build_crypto_policy(Some(&CryptoCfg {
            ciphers: Some(vec!["aes256-ctr".into()]),
            kex_algorithms: Some(vec!["diffie-hellman-group14-sha256".into()]),
            macs: Some(vec!["hmac-sha2-256".into()]),
            host_key_algorithms: Some(vec!["rsa-sha2-256".into()]),
            compression: Some(vec!["none".into()]),
            ..Default::default()
        }))
        .unwrap();
        assert_eq!(policy.ciphers, vec!["aes256-ctr"]);
        assert_eq!(policy.kex, vec!["diffie-hellman-group14-sha256"]);
        assert_eq!(policy.macs, vec!["hmac-sha2-256"]);
        assert_eq!(policy.host_keys, vec!["rsa-sha2-256"]);
        assert_eq!(policy.compression, vec!["none"]);
    }

    #[test]
    fn default_ssh2_profile_offers_pq_kex_first_then_classical() {
        // (a) PQ-by-default: a plain ssh2 profile with no `[profiles.crypto]`
        // and no capability flags resolves a kex list that OFFERS
        // `mlkem768x25519-sha256` FIRST, then the classical fallback.
        let mut crypto = build_crypto_policy(None).unwrap();
        apply_post_quantum_capability_policy(&mut crypto, None).unwrap();
        assert_eq!(
            crypto.kex.first().map(String::as_str),
            Some("mlkem768x25519-sha256"),
            "default profile must offer the hybrid PQ KEX first"
        );
        assert!(
            crypto.kex[1..].iter().any(|k| k == "curve25519-sha256"),
            "classical curve25519 fallback must follow the PQ KEX"
        );
    }

    #[test]
    fn explicit_mlkem_profile_now_builds_instead_of_rejecting() {
        // Regression: this profile used to return UnsupportedPlatform. russh
        // 0.61.2 implements mlkem768x25519-sha256 end-to-end, so with the
        // enabling capabilities the profile now builds successfully.
        let cfg = r#"
            version = 1
            [capabilities]
            allow_post_quantum_kex = true
            allow_ml_kem = true
            [[profiles]]
            name = "p"
            protocol = "ssh2"
            host = "h"
            [profiles.trust]
            pin_sha256 = ["SHA256:dummy"]
            [profiles.crypto]
            kex_algorithms = ["mlkem768x25519-sha256"]
        "#;
        let (c, _) = load_str(cfg, false).unwrap();
        let bundle = build_with_config(&c.profiles[0], &empty_resolver(), &c)
            .expect("mlkem768x25519-sha256 profile must build under russh 0.61.2");
        assert_eq!(bundle.endpoints.len(), 1);
    }

    #[test]
    fn allow_post_quantum_kex_false_strips_pq_leaving_classical() {
        // (b) An explicit `allow_post_quantum_kex = false` strips every PQ KEX
        // from the resolved list, leaving the classical fallback.
        let caps = Capabilities {
            allow_post_quantum_kex: Some(false),
            ..Default::default()
        };
        let mut crypto = build_crypto_policy(None).unwrap();
        apply_post_quantum_capability_policy(&mut crypto, Some(&caps)).unwrap();
        assert!(
            !crypto.kex.iter().any(|k| k == "mlkem768x25519-sha256"),
            "PQ KEX must be stripped when allow_post_quantum_kex = false"
        );
        assert!(crypto.kex.iter().any(|k| k == "curve25519-sha256"));
    }

    #[test]
    fn require_post_quantum_kex_yields_pq_only_and_builds() {
        // (c) `require_post_quantum_kex = true` restricts the resolved list to
        // the supported PQ KEX only (fail-closed), and now SUCCEEDS.
        let caps = Capabilities {
            allow_post_quantum_kex: Some(true),
            allow_ml_kem: Some(true),
            require_post_quantum_kex: Some(true),
            ..Default::default()
        };
        let mut crypto = build_crypto_policy(None).unwrap();
        apply_post_quantum_capability_policy(&mut crypto, Some(&caps)).unwrap();
        assert_eq!(crypto.kex, vec!["mlkem768x25519-sha256".to_owned()]);

        // …and the whole profile builds through the factory.
        let cfg = r#"
            version = 1
            [capabilities]
            allow_post_quantum_kex = true
            allow_ml_kem = true
            require_post_quantum_kex = true
            [[profiles]]
            name = "p"
            protocol = "ssh2"
            host = "h"
            [profiles.trust]
            pin_sha256 = ["SHA256:dummy"]
        "#;
        let (c, _) = load_str(cfg, false).unwrap();
        build_with_config(&c.profiles[0], &empty_resolver(), &c)
            .expect("require_post_quantum_kex profile must build (PQ-only)");
    }

    #[test]
    fn unsupported_pq_kex_still_rejected_at_load_with_guidance() {
        // (d) An unsupported PQ name (sntrup761x25519-sha512) still errors at
        // config-resolution with guidance pointing at the supported KEX.
        let cfg = r#"
            version = 1
            [capabilities]
            allow_post_quantum_kex = true
            [[profiles]]
            name = "p"
            protocol = "ssh2"
            host = "h"
            [profiles.crypto]
            kex_algorithms = ["sntrup761x25519-sha512"]
        "#;
        let (c, _) = load_str(cfg, false).unwrap();
        match build_with_config(&c.profiles[0], &empty_resolver(), &c) {
            Err(Error::InvalidConfig(message)) => {
                assert!(message.contains("sntrup761x25519-sha512"), "{message}");
                assert!(message.contains("mlkem768x25519-sha256"), "{message}");
            }
            Ok(_) => panic!("expected InvalidConfig error, got Ok"),
            Err(other) => panic!("expected InvalidConfig, got {other:?}"),
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
            [profiles.trust]
            pin_sha256 = ["SHA256:dummy"]
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
    fn build_crypto_policy_none_fills_modern_preset() {
        // With no `[profiles.crypto]` block the resolver fills the default
        // (modern) preset so the connect path gets a vetted, non-empty
        // allow-list instead of russh's built-in default.
        let policy = build_crypto_policy(None).unwrap();
        assert!(!policy.ciphers.is_empty());
        assert!(!policy.kex.is_empty());
        assert!(!policy.macs.is_empty());
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
            [profiles.trust]
            pin_sha256 = ["SHA256:dummy"]
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
            [profiles.trust]
            pin_sha256 = ["SHA256:dummy"]
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
            [profiles.trust]
            pin_sha256 = ["SHA256:dummy"]
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
            [profiles.trust]
            pin_sha256 = ["SHA256:dummy"]
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
            [profiles.trust]
            pin_sha256 = ["SHA256:dummy"]
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

    // ---- trust wire-up (security audit fix #2 / #4) ------------------------
    //
    // These tests pin the load-time invariants enforced by
    // `build_trust_policy`. Each profile **must** declare a trust source;
    // historically `TrustPolicy::default()` was silently accepted, which
    // produced TOFU on first connect without any operator opt-in.

    #[test]
    fn missing_trust_block_errors_with_diagnostic() {
        let cfg = r#"
            version = 1
            [[profiles]]
            name = "p"
            protocol = "ssh2"
            host = "h"
        "#;
        let (c, _) = load_str(cfg, false).unwrap();
        let msg = match build(&c.profiles[0], &empty_resolver()) {
            Err(Error::InvalidConfigDiagnostic(d)) => d.render(),
            Ok(_) => panic!("expected InvalidConfigDiagnostic, got Ok"),
            Err(other) => panic!("expected InvalidConfigDiagnostic, got {other:?}"),
        };
        assert!(msg.contains("no `[profiles.trust]` block"), "got: {msg}");
        assert!(msg.contains("how to fix"), "missing remediation: {msg}");
    }

    #[test]
    fn mode_known_hosts_requires_file_or_accept_new() {
        let cfg = r#"
            version = 1
            [[profiles]]
            name = "p"
            protocol = "ssh2"
            host = "h"
            [profiles.trust]
            mode = "known_hosts"
            strict = true
        "#;
        let (c, _) = load_str(cfg, false).unwrap();
        let msg = match build(&c.profiles[0], &empty_resolver()) {
            Err(Error::InvalidConfigDiagnostic(d)) => d.render(),
            Ok(_) => panic!("expected InvalidConfigDiagnostic, got Ok"),
            Err(other) => panic!("expected InvalidConfigDiagnostic, got {other:?}"),
        };
        assert!(
            msg.contains("\"known_hosts\"") && msg.contains("no `known_hosts_file`"),
            "got: {msg}"
        );
    }

    #[test]
    fn mode_pinned_requires_non_empty_pins() {
        let cfg = r#"
            version = 1
            [[profiles]]
            name = "p"
            protocol = "ssh2"
            host = "h"
            [profiles.trust]
            mode = "pinned"
        "#;
        let (c, _) = load_str(cfg, false).unwrap();
        match build(&c.profiles[0], &empty_resolver()) {
            Err(Error::InvalidConfigDiagnostic(_)) => {}
            Ok(_) => panic!("expected InvalidConfigDiagnostic, got Ok"),
            Err(other) => panic!("expected InvalidConfigDiagnostic, got {other:?}"),
        }
    }

    #[test]
    fn mode_pinned_rejects_accept_new() {
        let cfg = r#"
            version = 1
            [[profiles]]
            name = "p"
            protocol = "ssh2"
            host = "h"
            [profiles.trust]
            mode = "pinned"
            pin_sha256 = ["SHA256:dummy"]
            accept_new = true
        "#;
        let (c, _) = load_str(cfg, false).unwrap();
        let msg = match build(&c.profiles[0], &empty_resolver()) {
            Err(Error::InvalidConfigDiagnostic(d)) => d.render(),
            Ok(_) => panic!("expected InvalidConfigDiagnostic, got Ok"),
            Err(other) => panic!("expected InvalidConfigDiagnostic, got {other:?}"),
        };
        assert!(
            msg.contains("incompatible with `accept_new = true`"),
            "got: {msg}"
        );
    }

    #[test]
    fn accept_new_without_path_errors() {
        let cfg = r#"
            version = 1
            [[profiles]]
            name = "p"
            protocol = "ssh2"
            host = "h"
            [profiles.trust]
            accept_new = true
        "#;
        let (c, _) = load_str(cfg, false).unwrap();
        let msg = match build(&c.profiles[0], &empty_resolver()) {
            Err(Error::InvalidConfigDiagnostic(d)) => d.render(),
            Ok(_) => panic!("expected InvalidConfigDiagnostic, got Ok"),
            Err(other) => panic!("expected InvalidConfigDiagnostic, got {other:?}"),
        };
        assert!(
            msg.contains("accept_new = true") && msg.contains("requires `known_hosts_file`"),
            "got: {msg}"
        );
    }

    #[test]
    fn accept_new_with_path_propagates_into_trust_policy() {
        let dir = tempfile::tempdir().unwrap();
        let kh = dir.path().join("known_hosts");
        // Note: file does NOT exist yet — the verifier will create it on
        // first append. The build must still succeed.
        let cfg = format!(
            r#"
            version = 1
            [[profiles]]
            name = "p"
            protocol = "ssh2"
            host = "h"
            [profiles.trust]
            mode = "known_hosts"
            accept_new = true
            known_hosts_file = {path:?}
            "#,
            path = kh.to_string_lossy()
        );
        let (c, _) = load_str(&cfg, false).unwrap();
        // Build must succeed — we can't assert on the TrustPolicy field
        // directly without exposing internals, but a successful build with
        // accept_new + a path proves the wire-up loop closed.
        let _bundle = build(&c.profiles[0], &empty_resolver()).expect("build");
    }

    #[test]
    fn unknown_mode_errors() {
        let cfg = r#"
            version = 1
            [[profiles]]
            name = "p"
            protocol = "ssh2"
            host = "h"
            [profiles.trust]
            mode = "yolo"
        "#;
        let (c, _) = load_str(cfg, false).unwrap();
        let msg = match build(&c.profiles[0], &empty_resolver()) {
            Err(Error::InvalidConfigDiagnostic(d)) => d.render(),
            Ok(_) => panic!("expected InvalidConfigDiagnostic, got Ok"),
            Err(other) => panic!("expected InvalidConfigDiagnostic, got {other:?}"),
        };
        assert!(
            msg.contains("\"yolo\"") && msg.contains("not recognised"),
            "got: {msg}"
        );
    }

    // ---- multi-auth Phase 2b: per-endpoint AuthConfig resolution -----------
    //
    // `ProfileBundle.endpoint_auth` is an index-aligned `Vec<AuthConfig>`
    // (one entry per `endpoints[i]`) built with the Hop-style whole-block
    // fallback `endpoint.user.or(profile.user)` / `endpoint.auth.or(profile.auth)`.
    // The profile-level `ProfileBundle.auth` is retained as the global default.

    /// (a) An endpoint that declares its own `[auth]` resolves to that method,
    /// independently of (and overriding) the profile-level auth.
    #[test]
    fn endpoint_with_own_auth_resolves_to_that_method() {
        let cfg = r#"
            version = 1
            [[profiles]]
            name = "p"
            protocol = "ssh2"
            host = "top.example"
            user = "alice"
            [profiles.auth]
            method = "agent"
            [[profiles.endpoints]]
            name = "primary"
            host = "ep1.example"
            port = 22
            [profiles.endpoints.auth]
            method = "password"
            password = "secret://ns/ep1pw"
            [profiles.trust]
            pin_sha256 = ["SHA256:dummy"]
        "#;
        let (c, _) = load_str(cfg, false).unwrap();
        let bundle = build(&c.profiles[0], &empty_resolver()).unwrap();
        assert_eq!(bundle.endpoints.len(), 1);
        assert_eq!(bundle.endpoint_auth.len(), bundle.endpoints.len());
        // Profile-level default is still the agent method.
        assert!(matches!(bundle.auth.methods[0], AuthMethod::Agent { .. }));
        // The endpoint's own auth overrides it with the password method.
        match &bundle.endpoint_auth[0].methods[0] {
            AuthMethod::Password { secret } => {
                assert_eq!(secret.to_string(), "secret://ns/ep1pw");
            }
            other => panic!("expected per-endpoint Password, got {other:?}"),
        }
    }

    /// (b) An endpoint without its own auth inherits the profile/global auth.
    #[test]
    fn endpoint_without_auth_inherits_profile_auth() {
        let cfg = r#"
            version = 1
            [[profiles]]
            name = "p"
            protocol = "ssh2"
            host = "top.example"
            user = "alice"
            [profiles.auth]
            method = "agent"
            [[profiles.endpoints]]
            name = "primary"
            host = "ep1.example"
            port = 22
            [profiles.trust]
            pin_sha256 = ["SHA256:dummy"]
        "#;
        let (c, _) = load_str(cfg, false).unwrap();
        let bundle = build(&c.profiles[0], &empty_resolver()).unwrap();
        assert_eq!(bundle.endpoint_auth.len(), bundle.endpoints.len());
        // Inherited from `[profiles.auth]` (agent), with the profile username.
        assert!(matches!(
            bundle.endpoint_auth[0].methods[0],
            AuthMethod::Agent { .. }
        ));
        assert_eq!(bundle.endpoint_auth[0].username, "alice");
    }

    /// (c) `endpoint.user` overrides `profile.user` for that endpoint's
    /// `AuthConfig.username`, while a sibling endpoint without `user` keeps the
    /// profile-level username.
    #[test]
    fn endpoint_user_overrides_profile_user() {
        let cfg = r#"
            version = 1
            [[profiles]]
            name = "p"
            protocol = "ssh2"
            host = "top.example"
            user = "alice"
            [profiles.auth]
            method = "agent"
            [[profiles.endpoints]]
            name = "primary"
            host = "ep1.example"
            port = 22
            user = "bob"
            [[profiles.endpoints]]
            name = "backup"
            host = "ep2.example"
            port = 22
            [profiles.trust]
            pin_sha256 = ["SHA256:dummy"]
        "#;
        let (c, _) = load_str(cfg, false).unwrap();
        let bundle = build(&c.profiles[0], &empty_resolver()).unwrap();
        assert_eq!(bundle.endpoint_auth.len(), 2);
        // Endpoint 0 overrides the username.
        assert_eq!(bundle.endpoint_auth[0].username, "bob");
        // Endpoint 1 inherits the profile-level username.
        assert_eq!(bundle.endpoint_auth[1].username, "alice");
        // Profile-level default username is unchanged.
        assert_eq!(bundle.auth.username, "alice");
    }

    /// (d) Two endpoints each carrying a DISTINCT `secret://` password ref each
    /// resolve to their own secret reference — proving the per-endpoint vec
    /// keeps credentials separate rather than collapsing onto one.
    #[test]
    fn two_endpoints_carry_distinct_secret_password_refs() {
        let cfg = r#"
            version = 1
            [[profiles]]
            name = "p"
            protocol = "ssh2"
            host = "top.example"
            user = "alice"
            [[profiles.endpoints]]
            name = "primary"
            host = "ep1.example"
            port = 22
            [profiles.endpoints.auth]
            method = "password"
            password = "secret://ns/ep1pw"
            [[profiles.endpoints]]
            name = "backup"
            host = "ep2.example"
            port = 22
            [profiles.endpoints.auth]
            method = "password"
            password = "secret://ns/ep2pw"
            [profiles.trust]
            pin_sha256 = ["SHA256:dummy"]
        "#;
        let (c, _) = load_str(cfg, false).unwrap();
        let bundle = build(&c.profiles[0], &empty_resolver()).unwrap();
        assert_eq!(bundle.endpoint_auth.len(), 2);
        let secret_of = |a: &AuthConfig| match &a.methods[0] {
            AuthMethod::Password { secret } => secret.to_string(),
            other => panic!("expected Password method, got {other:?}"),
        };
        assert_eq!(secret_of(&bundle.endpoint_auth[0]), "secret://ns/ep1pw");
        assert_eq!(secret_of(&bundle.endpoint_auth[1]), "secret://ns/ep2pw");
    }

    /// Implicit single host-derived endpoint (no `[[profiles.endpoints]]`)
    /// yields exactly one `endpoint_auth` entry = the profile-level auth, so the
    /// vec stays index-aligned with the synthesised single endpoint.
    #[test]
    fn implicit_single_endpoint_yields_one_profile_level_auth() {
        let cfg = r#"
            version = 1
            [[profiles]]
            name = "p"
            protocol = "ssh2"
            host = "top.example"
            user = "alice"
            [profiles.auth]
            method = "agent"
            [profiles.trust]
            pin_sha256 = ["SHA256:dummy"]
        "#;
        let (c, _) = load_str(cfg, false).unwrap();
        let bundle = build(&c.profiles[0], &empty_resolver()).unwrap();
        assert_eq!(bundle.endpoints.len(), 1);
        assert_eq!(bundle.endpoint_auth.len(), 1);
        assert_eq!(bundle.endpoint_auth[0].username, "alice");
        assert!(matches!(
            bundle.endpoint_auth[0].methods[0],
            AuthMethod::Agent { .. }
        ));
    }

    /// Idle profile (empty host, no endpoints) yields an empty `endpoint_auth`
    /// vec, matching the empty `endpoints` vec.
    #[test]
    fn idle_profile_yields_empty_endpoint_auth() {
        let cfg = r#"
            version = 1
            [[profiles]]
            name = "p"
            protocol = "ssh2"
            [profiles.trust]
            pin_sha256 = ["SHA256:dummy"]
        "#;
        let (c, _) = load_str(cfg, false).unwrap();
        let bundle = build(&c.profiles[0], &empty_resolver()).unwrap();
        assert!(bundle.endpoints.is_empty());
        assert!(bundle.endpoint_auth.is_empty());
    }

    // ====================================================================
    // tw-b1: factory-mapping unit tests — one per newly-wired config field
    // asserting the value reaches the runtime config / builder.
    // ====================================================================

    use spt_config::schema::{
        Crypto as CryptoCfgTy, Failover as FailoverCfg, Hop as HopCfgTy, HopKind as HopKindCfg,
        Instability as InstabilityCfg, Limits as LimitsCfgTy, Reconnect as ReconnectCfg,
    };
    use spt_secrets::backend::secret_bytes;
    use spt_secrets::{
        backend::{BackendDoctor, BackendKind, SecretBackend, SecretBytes},
        SecretRef as SecretsRefTy,
    };

    /// Minimal in-memory secret backend for proxy-password resolution tests.
    struct OneSecretBackend {
        reference: SecretsRefTy,
        value: Vec<u8>,
    }

    impl SecretBackend for OneSecretBackend {
        fn kind(&self) -> BackendKind {
            BackendKind::Env
        }
        fn get(&self, r: &SecretsRefTy) -> Result<Option<SecretBytes>> {
            if r == &self.reference {
                Ok(Some(secret_bytes(self.value.clone())))
            } else {
                Ok(None)
            }
        }
        fn set(&self, _r: &SecretsRefTy, _value: &[u8]) -> Result<()> {
            Err(Error::UnsupportedPlatform("read-only test backend".into()))
        }
        fn list(&self) -> Result<Vec<SecretsRefTy>> {
            Ok(vec![self.reference.clone()])
        }
        fn remove(&self, _r: &SecretsRefTy) -> Result<bool> {
            Ok(false)
        }
        fn doctor(&self) -> BackendDoctor {
            BackendDoctor::ok(BackendKind::Env, "test backend")
        }
    }

    fn resolver_with_secret(ns: &str, name: &str, value: &str) -> Resolver {
        let reference = SecretsRefTy::new(ns, name).unwrap();
        Resolver::new(vec![Arc::new(OneSecretBackend {
            reference,
            value: value.as_bytes().to_vec(),
        })])
    }

    // ---- 1. rate limits (incl. profile default) ------------------------

    #[test]
    fn limits_table_feeds_runner_default_limits() {
        let cfg = r#"
            version = 1
            [[profiles]]
            name = "p"
            protocol = "ssh2"
            host = "h"
            user = "u"
            [profiles.limits]
            max_bytes_per_second_out = "100MiB"
            max_bytes_per_second_in = "50MiB"
            max_new_connections_per_second = 25
            [profiles.trust]
            pin_sha256 = ["SHA256:dummy"]
        "#;
        let (c, _) = load_str(cfg, false).unwrap();
        let bundle = build(&c.profiles[0], &empty_resolver()).unwrap();
        let limits = bundle.supervisor_cfg.runner_cfg.default_limits;
        assert_eq!(limits.rate_bps_up, 100 * 1024 * 1024);
        assert_eq!(limits.rate_bps_down, 50 * 1024 * 1024);
        assert_eq!(limits.max_new_conns_per_sec, 25);
    }

    #[test]
    fn limits_absent_keeps_unlimited_default() {
        let cfg = r#"
            version = 1
            [[profiles]]
            name = "p"
            protocol = "ssh2"
            host = "h"
            user = "u"
            [profiles.trust]
            pin_sha256 = ["SHA256:dummy"]
        "#;
        let (c, _) = load_str(cfg, false).unwrap();
        let bundle = build(&c.profiles[0], &empty_resolver()).unwrap();
        assert!(bundle
            .supervisor_cfg
            .runner_cfg
            .default_limits
            .is_unlimited());
    }

    #[test]
    fn limits_partial_table_leaves_other_components_unlimited() {
        let limits = build_default_limits(
            "p",
            &LimitsCfgTy {
                max_bytes_per_second_out: Some("10MiB".into()),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(limits.rate_bps_up, 10 * 1024 * 1024);
        assert_eq!(limits.rate_bps_down, 0);
        assert_eq!(limits.max_new_conns_per_sec, 0);
    }

    #[test]
    fn limits_invalid_byte_size_rejected() {
        let err = build_default_limits(
            "p",
            &LimitsCfgTy {
                max_bytes_per_second_in: Some("not-a-size".into()),
                ..Default::default()
            },
        )
        .unwrap_err();
        assert!(matches!(err, Error::InvalidConfig(_)));
    }

    // ---- 2. keepalive.max_missed (builder transport keepalive) ---------

    #[test]
    fn keepalive_block_builds_ssh2_with_transport_keepalive() {
        // max_missed + interval are threaded into the builder's keepalive
        // policy; a successful build proves the `.keepalive(..)` call is wired
        // (the policy is builder-internal, so we assert via successful build).
        let cfg = r#"
            version = 1
            [[profiles]]
            name = "p"
            protocol = "ssh2"
            host = "h"
            user = "u"
            [profiles.keepalive]
            interval = "15s"
            max_missed = 4
            [profiles.trust]
            pin_sha256 = ["SHA256:dummy"]
        "#;
        let (c, _) = load_str(cfg, false).unwrap();
        let bundle = build(&c.profiles[0], &empty_resolver()).unwrap();
        assert_eq!(bundle.protocol.name(), "ssh2");
        // The supervisor poll cadence still picks up the same interval.
        assert_eq!(
            bundle.supervisor_cfg.keepalive_interval,
            std::time::Duration::from_secs(15)
        );
    }

    #[test]
    fn keepalive_max_missed_only_builds_without_interval() {
        let cfg = r#"
            version = 1
            [[profiles]]
            name = "p"
            protocol = "ssh2"
            host = "h"
            user = "u"
            [profiles.keepalive]
            max_missed = 2
            [profiles.trust]
            pin_sha256 = ["SHA256:dummy"]
        "#;
        let (c, _) = load_str(cfg, false).unwrap();
        let bundle = build(&c.profiles[0], &empty_resolver()).unwrap();
        assert_eq!(bundle.protocol.name(), "ssh2");
    }

    // ---- 3. reconnect.retry_auth_failures ------------------------------

    #[test]
    fn reconnect_retry_auth_failures_feeds_backoff_config() {
        let cfg = ReconnectCfg {
            retry_auth_failures: Some(true),
            ..Default::default()
        };
        let backoff = build_backoff_config("p", &cfg).unwrap();
        assert!(backoff.retry_auth_failures);
    }

    #[test]
    fn reconnect_retry_auth_failures_defaults_false() {
        let backoff = build_backoff_config("p", &ReconnectCfg::default()).unwrap();
        assert!(!backoff.retry_auth_failures);
    }

    // ---- 4. instability action / enabled / misses / p95 ----------------

    #[test]
    fn instability_enabled_false_feeds_supervisor_window() {
        let cfg = r#"
            version = 1
            [[profiles]]
            name = "p"
            protocol = "ssh2"
            host = "h"
            user = "u"
            [profiles.instability]
            enabled = false
            [profiles.trust]
            pin_sha256 = ["SHA256:dummy"]
        "#;
        let (c, _) = load_str(cfg, false).unwrap();
        let bundle = build(&c.profiles[0], &empty_resolver()).unwrap();
        assert!(!bundle.supervisor_cfg.instability.enabled);
    }

    #[test]
    fn instability_enabled_defaults_true() {
        let cfg = r#"
            version = 1
            [[profiles]]
            name = "p"
            protocol = "ssh2"
            host = "h"
            user = "u"
            [profiles.instability]
            max_disconnects = 3
            [profiles.trust]
            pin_sha256 = ["SHA256:dummy"]
        "#;
        let (c, _) = load_str(cfg, false).unwrap();
        let bundle = build(&c.profiles[0], &empty_resolver()).unwrap();
        assert!(bundle.supervisor_cfg.instability.enabled);
    }

    #[test]
    fn instability_max_keepalive_misses_feeds_window() {
        let cfg = r#"
            version = 1
            [[profiles]]
            name = "p"
            protocol = "ssh2"
            host = "h"
            user = "u"
            [profiles.instability]
            max_keepalive_misses = 6
            [profiles.trust]
            pin_sha256 = ["SHA256:dummy"]
        "#;
        let (c, _) = load_str(cfg, false).unwrap();
        let bundle = build(&c.profiles[0], &empty_resolver()).unwrap();
        assert_eq!(
            bundle.supervisor_cfg.instability.max_keepalive_misses,
            Some(6)
        );
    }

    #[test]
    fn instability_max_latency_p95_feeds_window() {
        let cfg = r#"
            version = 1
            [[profiles]]
            name = "p"
            protocol = "ssh2"
            host = "h"
            user = "u"
            [profiles.instability]
            max_latency_p95 = "250ms"
            [profiles.trust]
            pin_sha256 = ["SHA256:dummy"]
        "#;
        let (c, _) = load_str(cfg, false).unwrap();
        let bundle = build(&c.profiles[0], &empty_resolver()).unwrap();
        assert_eq!(
            bundle.supervisor_cfg.instability.max_latency_p95,
            Some(std::time::Duration::from_millis(250))
        );
    }

    #[test]
    fn instability_max_latency_p95_invalid_rejected() {
        let cfg = InstabilityCfg {
            max_latency_p95: Some("not-a-duration".into()),
            ..Default::default()
        };
        let profile = Profile {
            name: "p".into(),
            protocol: "ssh2".into(),
            instability: Some(cfg),
            ..base_profile()
        };
        assert!(matches!(
            build_supervisor_config(&profile),
            Err(Error::InvalidConfig(_))
        ));
    }

    #[test]
    fn instability_action_maps_each_variant() {
        assert_eq!(
            parse_instability_action("p", "mark_degraded").unwrap(),
            InstabilityAction::MarkDegraded
        );
        assert_eq!(
            parse_instability_action("p", "failover").unwrap(),
            InstabilityAction::Failover
        );
        assert_eq!(
            parse_instability_action("p", "increase_keepalive").unwrap(),
            InstabilityAction::IncreaseKeepalive
        );
        assert_eq!(
            parse_instability_action("p", "increase_backoff").unwrap(),
            InstabilityAction::IncreaseBackoff
        );
        assert_eq!(
            parse_instability_action("p", "emit_event").unwrap(),
            InstabilityAction::EmitEvent
        );
        assert_eq!(
            parse_instability_action("p", "restart_session").unwrap(),
            InstabilityAction::RestartSession
        );
    }

    #[test]
    fn instability_action_unknown_rejected() {
        assert!(matches!(
            parse_instability_action("p", "explode"),
            Err(Error::InvalidConfig(_))
        ));
    }

    #[test]
    fn instability_action_feeds_supervisor_window() {
        let cfg = r#"
            version = 1
            [[profiles]]
            name = "p"
            protocol = "ssh2"
            host = "h"
            user = "u"
            [profiles.instability]
            action = "failover"
            [profiles.trust]
            pin_sha256 = ["SHA256:dummy"]
        "#;
        let (c, _) = load_str(cfg, false).unwrap();
        let bundle = build(&c.profiles[0], &empty_resolver()).unwrap();
        assert_eq!(
            bundle.supervisor_cfg.instability.action,
            InstabilityAction::Failover
        );
    }

    // ---- 5. failover.health_check (+ unknown rejected) -----------------

    #[test]
    fn health_check_style_maps_each_variant() {
        assert_eq!(
            parse_health_check_style("p", "tcp_connect").unwrap(),
            HealthCheckStyle::TcpConnect
        );
        assert_eq!(
            parse_health_check_style("p", "ssh_handshake").unwrap(),
            HealthCheckStyle::SshHandshake
        );
        assert_eq!(
            parse_health_check_style("p", "ssh_auth_preflight").unwrap(),
            HealthCheckStyle::SshAuthPreflight
        );
        assert_eq!(
            parse_health_check_style("p", "ssh3_endpoint").unwrap(),
            HealthCheckStyle::Ssh3Endpoint
        );
    }

    #[test]
    fn health_check_unknown_rejected() {
        assert!(matches!(
            parse_health_check_style("p", "ping"),
            Err(Error::InvalidConfig(_))
        ));
    }

    #[test]
    fn failover_health_check_feeds_supervisor_config() {
        let cfg = r#"
            version = 1
            [[profiles]]
            name = "p"
            protocol = "ssh2"
            host = "h"
            user = "u"
            [profiles.failover]
            health_check = "tcp_connect"
            [profiles.trust]
            pin_sha256 = ["SHA256:dummy"]
        "#;
        let (c, _) = load_str(cfg, false).unwrap();
        let bundle = build(&c.profiles[0], &empty_resolver()).unwrap();
        assert_eq!(
            bundle.supervisor_cfg.health_check,
            HealthCheckStyle::TcpConnect
        );
    }

    #[test]
    fn failover_health_check_defaults_to_ssh_handshake() {
        let cfg = r#"
            version = 1
            [[profiles]]
            name = "p"
            protocol = "ssh2"
            host = "h"
            user = "u"
            [profiles.trust]
            pin_sha256 = ["SHA256:dummy"]
        "#;
        let (c, _) = load_str(cfg, false).unwrap();
        let bundle = build(&c.profiles[0], &empty_resolver()).unwrap();
        assert_eq!(
            bundle.supervisor_cfg.health_check,
            HealthCheckStyle::SshHandshake
        );
    }

    #[test]
    fn failover_unknown_health_check_errors_through_build() {
        let cfg = FailoverCfg {
            health_check: Some("ping".into()),
            ..Default::default()
        };
        let profile = Profile {
            name: "p".into(),
            protocol: "ssh2".into(),
            failover: Some(cfg),
            ..base_profile()
        };
        assert!(matches!(
            build_supervisor_config(&profile),
            Err(Error::InvalidConfig(_))
        ));
    }

    // ---- 6. crypto preset fill + deprecated-reject + warn --------------

    #[test]
    fn crypto_preset_fills_empty_categories() {
        // policy = "modern" with no explicit lists → preset fills everything.
        let policy = build_crypto_policy(Some(&CryptoCfgTy {
            policy: Some("modern".into()),
            ..Default::default()
        }))
        .unwrap();
        assert!(!policy.ciphers.is_empty());
        assert!(!policy.kex.is_empty());
        assert!(!policy.macs.is_empty());
        assert!(!policy.host_keys.is_empty());
    }

    #[test]
    fn crypto_deprecated_algo_rejected_without_allow() {
        // A deprecated cipher in the explicit list with allow_deprecated unset
        // is a hard error.
        let err = build_crypto_policy(Some(&CryptoCfgTy {
            ciphers: Some(vec!["aes256-cbc".into()]),
            ..Default::default()
        }))
        .unwrap_err();
        assert!(matches!(err, Error::InvalidConfig(_)));
    }

    #[test]
    fn crypto_deprecated_algo_allowed_with_flag() {
        // allow_deprecated = true lets the deprecated algo resolve through.
        let policy = build_crypto_policy(Some(&CryptoCfgTy {
            ciphers: Some(vec!["aes256-cbc".into()]),
            allow_deprecated: Some(true),
            ..Default::default()
        }))
        .unwrap();
        assert_eq!(policy.ciphers, vec!["aes256-cbc"]);
    }

    #[test]
    fn crypto_warn_on_deprecated_resolves_without_blocking() {
        // warn_on_deprecated is independent of allow_deprecated and never
        // blocks resolution.
        let policy = build_crypto_policy(Some(&CryptoCfgTy {
            ciphers: Some(vec!["aes256-cbc".into()]),
            allow_deprecated: Some(true),
            warn_on_deprecated: Some(true),
            ..Default::default()
        }))
        .unwrap();
        assert_eq!(policy.ciphers, vec!["aes256-cbc"]);
    }

    #[test]
    fn crypto_unknown_preset_rejected() {
        let err = build_crypto_policy(Some(&CryptoCfgTy {
            policy: Some("bananas".into()),
            ..Default::default()
        }))
        .unwrap_err();
        assert!(matches!(err, Error::InvalidConfig(_)));
    }

    // ---- 7. agent fallback + identity_hint -----------------------------

    #[test]
    fn agent_method_carries_identity_hint() {
        let cfg = r#"
            version = 1
            [[profiles]]
            name = "p"
            protocol = "ssh2"
            host = "h"
            user = "u"
            [profiles.auth]
            method = "agent"
            identity_hint = "SHA256:abc123"
            [profiles.trust]
            pin_sha256 = ["SHA256:dummy"]
        "#;
        let (c, _) = load_str(cfg, false).unwrap();
        let bundle = build(&c.profiles[0], &empty_resolver()).unwrap();
        match &bundle.auth.methods[0] {
            AuthMethod::Agent { identity_hint, .. } => {
                assert_eq!(identity_hint.as_deref(), Some("SHA256:abc123"));
            }
            other => panic!("expected Agent method, got {other:?}"),
        }
    }

    #[test]
    fn agent_bool_appends_agent_fallback_after_password() {
        let cfg = r#"
            version = 1
            [[profiles]]
            name = "p"
            protocol = "ssh2"
            host = "h"
            user = "u"
            [profiles.auth]
            method = "password"
            password = "secret://ns/pw"
            agent = true
            identity_hint = "work-key"
            [profiles.trust]
            pin_sha256 = ["SHA256:dummy"]
        "#;
        let (c, _) = load_str(cfg, false).unwrap();
        let bundle = build(&c.profiles[0], &empty_resolver()).unwrap();
        assert_eq!(bundle.auth.methods.len(), 2);
        assert!(matches!(
            bundle.auth.methods[0],
            AuthMethod::Password { .. }
        ));
        match &bundle.auth.methods[1] {
            AuthMethod::Agent { identity_hint, .. } => {
                assert_eq!(identity_hint.as_deref(), Some("work-key"));
            }
            other => panic!("expected appended Agent fallback, got {other:?}"),
        }
    }

    #[test]
    fn agent_bool_not_duplicated_when_method_is_agent() {
        let cfg = r#"
            version = 1
            [[profiles]]
            name = "p"
            protocol = "ssh2"
            host = "h"
            user = "u"
            [profiles.auth]
            method = "agent"
            agent = true
            [profiles.trust]
            pin_sha256 = ["SHA256:dummy"]
        "#;
        let (c, _) = load_str(cfg, false).unwrap();
        let bundle = build(&c.profiles[0], &empty_resolver()).unwrap();
        // Only one agent method — the bool does not append a second.
        assert_eq!(bundle.auth.methods.len(), 1);
        assert!(matches!(bundle.auth.methods[0], AuthMethod::Agent { .. }));
    }

    #[test]
    fn agent_bool_false_appends_nothing() {
        let cfg = r#"
            version = 1
            [[profiles]]
            name = "p"
            protocol = "ssh2"
            host = "h"
            user = "u"
            [profiles.auth]
            method = "password"
            password = "secret://ns/pw"
            agent = false
            [profiles.trust]
            pin_sha256 = ["SHA256:dummy"]
        "#;
        let (c, _) = load_str(cfg, false).unwrap();
        let bundle = build(&c.profiles[0], &empty_resolver()).unwrap();
        assert_eq!(bundle.auth.methods.len(), 1);
        assert!(matches!(
            bundle.auth.methods[0],
            AuthMethod::Password { .. }
        ));
    }

    // ---- 8. hop kind / creds (socks5 / http-connect / ssh-default) -----

    #[test]
    fn map_hop_kind_maps_each_variant() {
        assert_eq!(map_hop_kind(HopKindCfg::Ssh), HopKind::Ssh);
        assert_eq!(map_hop_kind(HopKindCfg::Socks5), HopKind::Socks5);
        assert_eq!(map_hop_kind(HopKindCfg::HttpConnect), HopKind::HttpConnect);
    }

    #[test]
    fn ssh_hop_builds_with_default_kind() {
        let cfg = r#"
            version = 1
            [[profiles]]
            name = "p"
            protocol = "ssh2"
            host = "h"
            user = "u"
            [profiles.auth]
            method = "agent"
            [profiles.trust]
            pin_sha256 = ["SHA256:dummy"]
            [[profiles.hops]]
            name = "bastion"
            protocol = "ssh2"
            host = "bastion.example"
            port = 22
        "#;
        let (c, _) = load_str(cfg, false).unwrap();
        // An SSH-kind hop keeps the historical hop_with_auth_trust path; a
        // successful build proves it is dispatched correctly.
        let bundle = build(&c.profiles[0], &empty_resolver()).unwrap();
        assert_eq!(bundle.protocol.name(), "ssh2");
    }

    #[test]
    fn cli_jump_chain_flows_into_transport_build() {
        // Simulate `spt tunnel run -J alice@bastion.example:2222` against a
        // profile that has NO hops in its file. The parsed chain is splatted
        // into `profile.hops`, which is exactly the field the factory's hop
        // loop (`build_hop_chain`, ~line 471) consumes to build the multi-hop
        // transport. Before this fix `-J` was parsed nowhere → direct connect.
        let cfg = r#"
            version = 1
            [[profiles]]
            name = "p"
            protocol = "ssh2"
            host = "h"
            user = "u"
            [profiles.auth]
            method = "agent"
            [profiles.trust]
            pin_sha256 = ["SHA256:dummy"]
        "#;
        let (mut c, _) = load_str(cfg, false).unwrap();
        assert!(c.profiles[0].hops.is_empty(), "fixture must start hop-less");

        let chain = crate::cli::tunnel_ops::parse_jump_chain("alice@bastion.example:2222").unwrap();
        let n = crate::cli::tunnel_ops::apply_jump_chain_to_config(&mut c, &[], &chain);
        assert_eq!(n, 1);

        // The jump host now lives in the exact field the transport reads.
        assert_eq!(c.profiles[0].hops.len(), 1);
        assert_eq!(c.profiles[0].hops[0].host, "bastion.example");
        assert_eq!(c.profiles[0].hops[0].port, 2222);
        assert_eq!(c.profiles[0].hops[0].user.as_deref(), Some("alice"));

        // A successful build proves the injected hop is dispatched through the
        // hop loop into the SSH2 transport rather than silently dropped.
        let bundle = build(&c.profiles[0], &empty_resolver()).unwrap();
        assert_eq!(bundle.protocol.name(), "ssh2");
    }

    #[test]
    fn socks5_hop_resolves_proxy_creds() {
        let hop = HopCfgTy {
            name: "proxy".into(),
            protocol: "socks5".into(),
            host: "proxy.example".into(),
            port: 1080,
            kind: HopKindCfg::Socks5,
            proxy_username: Some("proxyuser".into()),
            proxy_password_ref: Some(SecretsRefTy::new("ns", "proxypw").unwrap()),
            ..Default::default()
        };
        let resolver = resolver_with_secret("ns", "proxypw", "s3cret");
        let creds = resolve_proxy_credentials(&hop, &resolver, "p")
            .unwrap()
            .expect("expected resolved proxy credentials");
        assert_eq!(creds.username, "proxyuser");
        assert_eq!(creds.password, "s3cret");
    }

    #[test]
    fn http_connect_hop_username_only_empty_password() {
        let hop = HopCfgTy {
            name: "proxy".into(),
            protocol: "http-connect".into(),
            host: "proxy.example".into(),
            port: 8080,
            kind: HopKindCfg::HttpConnect,
            proxy_username: Some("onlyuser".into()),
            ..Default::default()
        };
        let creds = resolve_proxy_credentials(&hop, &empty_resolver(), "p")
            .unwrap()
            .expect("expected creds when username present");
        assert_eq!(creds.username, "onlyuser");
        assert_eq!(creds.password, "");
    }

    #[test]
    fn proxy_hop_without_creds_resolves_to_none() {
        let hop = HopCfgTy {
            name: "proxy".into(),
            protocol: "socks5".into(),
            host: "proxy.example".into(),
            port: 1080,
            kind: HopKindCfg::Socks5,
            ..Default::default()
        };
        let creds = resolve_proxy_credentials(&hop, &empty_resolver(), "p").unwrap();
        assert!(creds.is_none());
    }

    #[test]
    fn proxy_hop_password_ref_missing_secret_errors() {
        let hop = HopCfgTy {
            name: "proxy".into(),
            protocol: "socks5".into(),
            host: "proxy.example".into(),
            port: 1080,
            kind: HopKindCfg::Socks5,
            proxy_password_ref: Some(SecretsRefTy::new("ns", "absent").unwrap()),
            ..Default::default()
        };
        // empty_resolver has no entry → resolve returns SecretUnavailable.
        assert!(resolve_proxy_credentials(&hop, &empty_resolver(), "p").is_err());
    }

    #[test]
    fn socks5_hop_builds_through_full_factory() {
        let cfg = r#"
            version = 1
            [[profiles]]
            name = "p"
            protocol = "ssh2"
            host = "h"
            user = "u"
            [profiles.auth]
            method = "agent"
            [profiles.trust]
            pin_sha256 = ["SHA256:dummy"]
            [[profiles.hops]]
            name = "socks"
            protocol = "socks5"
            host = "proxy.example"
            port = 1080
            kind = "socks5"
            proxy_username = "u"
            proxy_password_ref = "secret://ns/proxypw"
        "#;
        let (c, _) = load_str(cfg, false).unwrap();
        let resolver = resolver_with_secret("ns", "proxypw", "pw");
        let bundle = build(&c.profiles[0], &resolver).unwrap();
        assert_eq!(bundle.protocol.name(), "ssh2");
    }

    // ---- 9. connection wired subset ------------------------------------
    //
    // No `[profiles.connection]` field has an existing builder/russh-config
    // setter on the SSH2 path (the builder exposes only crypto/trust/hops/
    // backends/keepalive/obfuscation/profile_name; the transport keepalive is
    // driven from `[profiles.keepalive]`, not `[profiles.connection]`). Per
    // the wave contract we do NOT invent setters — every connection knob is
    // left for B2 to validate-warn. This test pins that a profile carrying a
    // full `[profiles.connection]` block still builds (the fields are accepted
    // at load and simply not mapped onto a non-existent setter).

    #[test]
    fn connection_block_is_accepted_and_does_not_break_build() {
        let cfg = r#"
            version = 1
            [[profiles]]
            name = "p"
            protocol = "ssh2"
            host = "h"
            user = "u"
            [profiles.connection]
            connect_timeout = "10s"
            tcp_nodelay = true
            socket_keepalive = true
            keepalive_idle = "30s"
            keepalive_interval = "10s"
            keepalive_retries = 3
            channel_window_size = "2MiB"
            channel_max_packet_size = "32KiB"
            [profiles.trust]
            pin_sha256 = ["SHA256:dummy"]
        "#;
        let (c, _) = load_str(cfg, false).unwrap();
        let bundle = build(&c.profiles[0], &empty_resolver()).unwrap();
        assert_eq!(bundle.protocol.name(), "ssh2");
    }

    /// A minimal profile with the required fields set, for unit-testing the
    /// `build_supervisor_config` / `build_*` helpers that take a `&Profile`.
    fn base_profile() -> Profile {
        let (c, _) = load_str(
            r#"
            version = 1
            [[profiles]]
            name = "p"
            protocol = "ssh2"
            host = "h"
            user = "u"
            [profiles.trust]
            pin_sha256 = ["SHA256:dummy"]
        "#,
            false,
        )
        .unwrap();
        c.profiles.into_iter().next().unwrap()
    }

    // ---------------- conn-wire: [profiles.connection] mapping ----------------

    /// Parse a TOML snippet's first profile and return its `[profiles.connection]`.
    fn connection_from_toml(body: &str) -> ConnectionCfg {
        let raw = format!(
            r#"
            version = 1
            [[profiles]]
            name = "p"
            protocol = "ssh2"
            host = "h"
            user = "u"
            [profiles.trust]
            pin_sha256 = ["SHA256:dummy"]
            [profiles.connection]
            {body}
        "#
        );
        let (c, _) = load_str(&raw, false).unwrap();
        c.profiles
            .into_iter()
            .next()
            .unwrap()
            .connection
            .expect("connection table present")
    }

    #[test]
    fn connection_policy_maps_all_wireable_fields() {
        let conn = connection_from_toml(
            r#"
            connect_timeout = "7s"
            tcp_nodelay = true
            socket_keepalive = true
            keepalive_idle = "30s"
            keepalive_interval = "10s"
            keepalive_retries = 4
            channel_window_size = "2MiB"
            channel_max_packet_size = "32KiB"
        "#,
        );
        let policy = build_connection_policy("p", &conn).unwrap();
        assert_eq!(policy.tcp_nodelay, Some(true));
        assert_eq!(policy.socket_keepalive, Some(true));
        assert_eq!(policy.connect_timeout, Some(Duration::from_secs(7)));
        assert_eq!(policy.keepalive_idle, Some(Duration::from_secs(30)));
        assert_eq!(policy.keepalive_interval, Some(Duration::from_secs(10)));
        assert_eq!(policy.keepalive_retries, Some(4));
        assert_eq!(policy.channel_window_size, Some(2 * 1024 * 1024));
        assert_eq!(policy.channel_max_packet_size, Some(32 * 1024));
    }

    #[test]
    fn connection_policy_default_when_fields_absent() {
        // An empty `[profiles.connection]` yields a fully-default (no-op) policy.
        let conn = connection_from_toml("");
        let policy = build_connection_policy("p", &conn).unwrap();
        assert_eq!(policy, ConnectionPolicy::default());
    }

    #[test]
    fn connection_policy_nodelay_false_is_carried() {
        let conn = connection_from_toml("tcp_nodelay = false");
        let policy = build_connection_policy("p", &conn).unwrap();
        // `Some(false)` is distinct from `None` (russh default): an operator who
        // writes `tcp_nodelay = false` explicitly disables it.
        assert_eq!(policy.tcp_nodelay, Some(false));
        assert!(policy.connect_timeout.is_none());
        assert!(policy.socket_keepalive.is_none());
    }

    #[test]
    fn connection_policy_channel_size_saturates_to_u32() {
        // A size beyond u32::MAX saturates rather than wrapping.
        let conn = connection_from_toml(r#"channel_window_size = "8GiB""#);
        let policy = build_connection_policy("p", &conn).unwrap();
        assert_eq!(policy.channel_window_size, Some(u32::MAX));
    }

    #[test]
    fn connection_policy_only_connect_timeout() {
        let conn = connection_from_toml(r#"connect_timeout = "2500ms""#);
        let policy = build_connection_policy("p", &conn).unwrap();
        assert_eq!(policy.connect_timeout, Some(Duration::from_millis(2500)));
        assert!(policy.tcp_nodelay.is_none());
        assert!(policy.socket_keepalive.is_none());
    }

    #[test]
    fn connection_policy_rejects_bad_duration() {
        let conn = connection_from_toml(r#"connect_timeout = "not-a-duration""#);
        let err = build_connection_policy("p", &conn).unwrap_err();
        assert!(
            matches!(err, Error::InvalidConfig(_)),
            "expected InvalidConfig, got {err:?}"
        );
    }

    // t-tunnel-wire-2 (Phase 2, B1): per-operation SSH deadline mappings.

    #[test]
    fn connection_policy_auth_timeout_flows_into_auth_timeout() {
        let conn = connection_from_toml(r#"auth_timeout = "12s""#);
        let policy = build_connection_policy("p", &conn).unwrap();
        assert_eq!(policy.auth_timeout, Some(Duration::from_secs(12)));
        // No read/write means no combined channel-idle deadline.
        assert!(policy.handshake_timeout.is_none());
        assert!(policy.channel_idle_timeout.is_none());
    }

    #[test]
    fn connection_policy_handshake_timeout_flows_into_handshake_timeout() {
        let conn = connection_from_toml(r#"handshake_timeout = "1500ms""#);
        let policy = build_connection_policy("p", &conn).unwrap();
        assert_eq!(policy.handshake_timeout, Some(Duration::from_millis(1500)));
        assert!(policy.auth_timeout.is_none());
        assert!(policy.channel_idle_timeout.is_none());
    }

    #[test]
    fn connection_policy_read_timeout_only_becomes_channel_idle() {
        let conn = connection_from_toml(r#"read_timeout = "20s""#);
        let policy = build_connection_policy("p", &conn).unwrap();
        // read/write_timeout are folded into the single combined channel-idle
        // deadline; with only `read_timeout` set it is used directly.
        assert_eq!(policy.channel_idle_timeout, Some(Duration::from_secs(20)));
        assert!(policy.auth_timeout.is_none());
        assert!(policy.handshake_timeout.is_none());
    }

    #[test]
    fn connection_policy_write_timeout_only_becomes_channel_idle() {
        let conn = connection_from_toml(r#"write_timeout = "25s""#);
        let policy = build_connection_policy("p", &conn).unwrap();
        // With only `write_timeout` set it becomes the combined channel-idle.
        assert_eq!(policy.channel_idle_timeout, Some(Duration::from_secs(25)));
        assert!(policy.auth_timeout.is_none());
        assert!(policy.handshake_timeout.is_none());
    }

    #[test]
    fn connection_policy_read_and_write_timeout_combine_to_min() {
        // When BOTH directional timeouts are set the combined channel-idle
        // deadline is the tighter (MIN) of the two.
        let conn = connection_from_toml(
            r#"
            read_timeout = "30s"
            write_timeout = "10s"
        "#,
        );
        let policy = build_connection_policy("p", &conn).unwrap();
        assert_eq!(policy.channel_idle_timeout, Some(Duration::from_secs(10)));
    }

    #[test]
    fn connection_policy_read_and_write_timeout_min_picks_read_when_smaller() {
        // MIN selection is symmetric: read smaller than write picks read.
        let conn = connection_from_toml(
            r#"
            read_timeout = "5s"
            write_timeout = "40s"
        "#,
        );
        let policy = build_connection_policy("p", &conn).unwrap();
        assert_eq!(policy.channel_idle_timeout, Some(Duration::from_secs(5)));
    }

    #[test]
    fn connection_policy_no_read_or_write_timeout_is_none() {
        // Neither directional timeout set → no combined channel-idle deadline.
        let conn = connection_from_toml(r#"connect_timeout = "3s""#);
        let policy = build_connection_policy("p", &conn).unwrap();
        assert!(policy.channel_idle_timeout.is_none());
        assert!(policy.auth_timeout.is_none());
        assert!(policy.handshake_timeout.is_none());
    }

    #[test]
    fn connection_policy_all_three_new_timeouts_together() {
        let conn = connection_from_toml(
            r#"
            auth_timeout = "8s"
            handshake_timeout = "9s"
            read_timeout = "11s"
            write_timeout = "7s"
        "#,
        );
        let policy = build_connection_policy("p", &conn).unwrap();
        assert_eq!(policy.auth_timeout, Some(Duration::from_secs(8)));
        assert_eq!(policy.handshake_timeout, Some(Duration::from_secs(9)));
        // 11s read vs 7s write → MIN = 7s combined channel-idle.
        assert_eq!(policy.channel_idle_timeout, Some(Duration::from_secs(7)));
    }

    #[test]
    fn connection_policy_rejects_bad_auth_timeout() {
        let conn = connection_from_toml(r#"auth_timeout = "not-a-duration""#);
        let err = build_connection_policy("p", &conn).unwrap_err();
        assert!(matches!(err, Error::InvalidConfig(_)), "got {err:?}");
    }

    #[test]
    fn connection_policy_rejects_bad_handshake_timeout() {
        let conn = connection_from_toml(r#"handshake_timeout = "nope""#);
        let err = build_connection_policy("p", &conn).unwrap_err();
        assert!(matches!(err, Error::InvalidConfig(_)), "got {err:?}");
    }

    #[test]
    fn connection_policy_rejects_bad_read_timeout() {
        let conn = connection_from_toml(r#"read_timeout = "bogus""#);
        let err = build_connection_policy("p", &conn).unwrap_err();
        assert!(matches!(err, Error::InvalidConfig(_)), "got {err:?}");
    }

    #[test]
    fn profile_with_connection_table_builds() {
        // End-to-end: a profile carrying `[profiles.connection]` builds
        // successfully, proving `build_ssh2`'s `.connection(...)` wiring is
        // reachable from config (was a parsed-and-ignored table before).
        let cfg = r#"
            version = 1
            [[profiles]]
            name = "edge"
            protocol = "ssh2"
            host = "example.com"
            user = "alice"
            [profiles.trust]
            pin_sha256 = ["SHA256:dummy"]
            [profiles.connection]
            connect_timeout = "5s"
            tcp_nodelay = true
            socket_keepalive = true
            keepalive_idle = "30s"
            channel_window_size = "4MiB"
        "#;
        let (c, _) = load_str(cfg, false).unwrap();
        let bundle = build(&c.profiles[0], &empty_resolver()).unwrap();
        assert_eq!(bundle.protocol.name(), "ssh2");
    }

    // ---- t-ssh3 Wave B: `build_ssh3` config-surface mapping ------------------
    //
    // These exercise the `[profiles.tls]` / `[profiles.ssh3]` → `Ssh3Config` /
    // `Ssh3TlsConfig` flow. `build_ssh3` returns the concrete `Ssh3Protocol`, so
    // tests inspect the assembled config via `Ssh3Protocol::config()`.

    /// A 32-byte SPKI digest (all `0xAB`) in standard base64. Decodes to
    /// exactly 32 bytes so `build_tls_pin` accepts it.
    const VALID_PIN_B64: &str = "q6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6s=";

    fn ssh3_profile(extra: &str) -> spt_config::schema::Profile {
        let cfg = format!(
            r#"
                version = 1
                [[profiles]]
                name = "p"
                protocol = "ssh3"
                host = "h"
                user = "u"
                acknowledge_experimental = true
{extra}
            "#
        );
        let (c, _) = load_str(&cfg, false).unwrap();
        c.profiles.into_iter().next().unwrap()
    }

    #[test]
    fn ssh3_tls_server_name_maps_to_sni() {
        let p = ssh3_profile(
            "                [profiles.tls]\n                server_name = \"vhost.example\"",
        );
        let proto = build_ssh3(&p).unwrap();
        assert_eq!(proto.config().sni.as_deref(), Some("vhost.example"));
    }

    #[test]
    fn ssh3_tls_ca_file_maps() {
        let p = ssh3_profile(
            "                [profiles.tls]\n                ca_file = \"/etc/spt/ca.pem\"",
        );
        let proto = build_ssh3(&p).unwrap();
        assert_eq!(
            proto.config().tls.ca_file,
            Some(std::path::PathBuf::from("/etc/spt/ca.pem"))
        );
    }

    #[test]
    fn ssh3_tls_pin_base64_parses() {
        let p = ssh3_profile(&format!(
            "                [profiles.tls]\n                pin_sha256 = [\"{VALID_PIN_B64}\"]"
        ));
        let proto = build_ssh3(&p).unwrap();
        assert_eq!(proto.config().tls.pin.spki_sha256, vec![[0xABu8; 32]]);
    }

    #[test]
    fn ssh3_tls_pin_accepts_sha256_prefix() {
        let p = ssh3_profile(&format!(
            "                [profiles.tls]\n                pin_sha256 = [\"sha256:{VALID_PIN_B64}\"]"
        ));
        let proto = build_ssh3(&p).unwrap();
        assert_eq!(proto.config().tls.pin.spki_sha256, vec![[0xABu8; 32]]);
    }

    #[test]
    fn ssh3_tls_pin_rejects_bad_base64() {
        let p = ssh3_profile(
            "                [profiles.tls]\n                pin_sha256 = [\"!!!not-base64!!!\"]",
        );
        let err = build_ssh3(&p).unwrap_err();
        assert!(matches!(err, Error::InvalidConfig(m) if m.contains("not valid base64")));
    }

    #[test]
    fn ssh3_tls_pin_rejects_wrong_length() {
        // Valid base64 but only 3 bytes (`AAAA` = 3 zero bytes), not 32.
        let p =
            ssh3_profile("                [profiles.tls]\n                pin_sha256 = [\"AAAA\"]");
        let err = build_ssh3(&p).unwrap_err();
        assert!(matches!(err, Error::InvalidConfig(m) if m.contains("expected 32")));
    }

    #[test]
    fn ssh3_tls_allow_self_signed_maps_with_anchor() {
        // `allow_self_signed` needs a pin (or ca_file) + ack to pass validate().
        let p = ssh3_profile(&format!(
            "                [profiles.tls]\n                allow_self_signed = true\n                pin_sha256 = [\"{VALID_PIN_B64}\"]"
        ));
        let proto = build_ssh3(&p).unwrap();
        assert!(proto.config().tls.allow_self_signed);
    }

    #[test]
    fn ssh3_tls_chain_depth_maps() {
        let p = ssh3_profile(
            "                [profiles.tls]\n                max_cert_chain_depth = 2",
        );
        let proto = build_ssh3(&p).unwrap();
        assert_eq!(
            proto.config().tls.max_cert_chain_depth,
            ChainDepthCap::new(2)
        );
    }

    #[test]
    fn ssh3_tls_chain_depth_default_when_absent() {
        let p = ssh3_profile("                [profiles.tls]\n                server_name = \"h\"");
        let proto = build_ssh3(&p).unwrap();
        assert_eq!(
            proto.config().tls.max_cert_chain_depth,
            ChainDepthCap::default()
        );
    }

    #[test]
    fn ssh3_tls_system_roots_false_without_anchor_errors() {
        let p =
            ssh3_profile("                [profiles.tls]\n                system_roots = false");
        let err = build_ssh3(&p).unwrap_err();
        assert!(matches!(err, Error::InvalidConfig(m) if m.contains("system_roots")));
    }

    #[test]
    fn ssh3_tls_system_roots_false_with_pin_ok() {
        let p = ssh3_profile(&format!(
            "                [profiles.tls]\n                system_roots = false\n                pin_sha256 = [\"{VALID_PIN_B64}\"]"
        ));
        let proto = build_ssh3(&p).unwrap();
        assert_eq!(proto.config().tls.pin.spki_sha256.len(), 1);
    }

    #[test]
    fn ssh3_idle_timeout_and_keepalive_durations_map() {
        let p = ssh3_profile(
            "                [profiles.ssh3]\n                idle_timeout = \"45s\"\n                keepalive = \"15s\"",
        );
        let proto = build_ssh3(&p).unwrap();
        assert_eq!(proto.config().idle_timeout_secs, Some(45));
        assert_eq!(proto.config().keepalive_secs, 15);
    }

    #[test]
    fn ssh3_idle_timeout_bad_duration_errors() {
        let p = ssh3_profile(
            "                [profiles.ssh3]\n                idle_timeout = \"not-a-duration\"",
        );
        assert!(build_ssh3(&p).is_err());
    }

    #[test]
    fn ssh3_max_streams_maps() {
        let p = ssh3_profile("                [profiles.ssh3]\n                max_streams = 128");
        let proto = build_ssh3(&p).unwrap();
        assert_eq!(proto.config().max_streams, Some(128));
    }

    #[test]
    fn ssh3_enable_datagrams_defaults_true() {
        // No `[profiles.ssh3]` block at all → datagrams stay enabled.
        let p = ssh3_profile("");
        let proto = build_ssh3(&p).unwrap();
        assert!(proto.config().enable_datagrams);
    }

    #[test]
    fn ssh3_enable_datagrams_explicit_false() {
        let p = ssh3_profile(
            "                [profiles.ssh3]\n                enable_datagrams = false",
        );
        let proto = build_ssh3(&p).unwrap();
        assert!(!proto.config().enable_datagrams);
    }

    #[test]
    fn ssh3_protocol_token_maps() {
        let p = ssh3_profile(
            "                [profiles.ssh3]\n                protocol_token = \"ssh3-next\"",
        );
        let proto = build_ssh3(&p).unwrap();
        assert_eq!(proto.config().protocol_token.as_deref(), Some("ssh3-next"));
    }

    #[test]
    fn ssh3_acknowledge_experimental_preserved() {
        // No tls/ssh3 blocks: behaviour-preserving — only ack flows through.
        let p = ssh3_profile("");
        let proto = build_ssh3(&p).unwrap();
        assert!(proto.config().acknowledge_experimental);
        assert_eq!(proto.config().sni, None);
        assert!(proto.config().tls.pin.spki_sha256.is_empty());
    }

    // ---- t-ssh3 Wave D2: dns_resolution + target_resolve ---------------------

    #[test]
    fn parse_dns_resolution_maps_known_values() {
        assert_eq!(
            parse_dns_resolution("p", None).unwrap(),
            DnsResolution::PerAttempt
        );
        assert_eq!(
            parse_dns_resolution("p", Some("per_attempt")).unwrap(),
            DnsResolution::PerAttempt
        );
        assert_eq!(
            parse_dns_resolution("p", Some("once")).unwrap(),
            DnsResolution::Once
        );
    }

    #[test]
    fn parse_dns_resolution_rejects_unknown() {
        let err = parse_dns_resolution("p", Some("forever")).unwrap_err();
        assert!(matches!(err, Error::InvalidConfig(m) if m.contains("unknown dns_resolution")));
    }

    #[test]
    fn ssh3_profile_default_dns_is_per_attempt() {
        let p = ssh3_profile("");
        let proto = build_ssh3(&p).unwrap();
        assert_eq!(proto.config().dns, DnsResolution::PerAttempt);
    }

    #[test]
    fn ssh3_profile_dns_resolution_once_maps() {
        let p = ssh3_profile("                dns_resolution = \"once\"");
        let proto = build_ssh3(&p).unwrap();
        assert_eq!(proto.config().dns, DnsResolution::Once);
    }

    #[test]
    fn ssh3_profile_dns_resolution_unknown_rejected() {
        let p = ssh3_profile("                dns_resolution = \"forever\"");
        let err = build_ssh3(&p).unwrap_err();
        assert!(matches!(err, Error::InvalidConfig(m) if m.contains("unknown dns_resolution")));
    }

    #[test]
    fn parse_target_resolve_maps_known_values() {
        assert_eq!(
            parse_target_resolve("p", "at", None).unwrap(),
            TargetResolve::Remote
        );
        assert_eq!(
            parse_target_resolve("p", "at", Some("remote")).unwrap(),
            TargetResolve::Remote
        );
        assert_eq!(
            parse_target_resolve("p", "at", Some("local")).unwrap(),
            TargetResolve::Local
        );
        assert_eq!(
            parse_target_resolve("p", "at", Some("previous-hop")).unwrap(),
            TargetResolve::PreviousHop
        );
    }

    #[test]
    fn parse_target_resolve_rejects_unknown() {
        let err = parse_target_resolve("p", "hops.x.target_resolve", Some("sideways")).unwrap_err();
        assert!(matches!(err, Error::InvalidConfig(m) if m.contains("unknown target_resolve")));
    }

    #[test]
    fn resolve_target_local_returns_ip_literal() {
        // A loopback literal resolves to itself — asserts the client-side
        // substitution produces an IP string, not the hostname.
        let ip = resolve_target_local("p", "127.0.0.1", 22).unwrap();
        assert_eq!(ip, "127.0.0.1");
        // `localhost` resolves to a loopback IP literal (never the name).
        let ip = resolve_target_local("p", "localhost", 22).unwrap();
        assert!(
            ip.parse::<std::net::IpAddr>().is_ok(),
            "expected IP, got {ip}"
        );
        assert!(ip != "localhost");
    }
}
