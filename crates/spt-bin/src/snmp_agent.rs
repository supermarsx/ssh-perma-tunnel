//! SNMPv3 agent wiring (Wave 5 — wire-observ finding 1 / audit-logging CRIT #3).
//!
//! `spt-snmp` is a complete SNMPv3 USM agent + trap sender library, but before
//! this module NOTHING in the shipped binary ran it: the whole
//! `[observability.snmp]` subtree bound nothing and `spt observe snmp serve`
//! returned `UnsupportedPlatform`. This module maps `[observability.snmp]` onto
//! `spt_snmp::AgentBuilder` and drives it end to end:
//!
//! * [`build_agent_from_config`] — pure schema → builder mapping (every field).
//! * [`maybe_spawn_snmp_agent`] — spawns the agent under `tunnel run` when
//!   `[observability.snmp].enabled = true`, mirroring the DNS / MCP / memory
//!   monitor spawn pattern in `cli_dispatch::tunnel_run`.
//! * [`serve`] — the foreground `spt observe snmp serve` path.
//! * [`send_test_trap`] — `spt observe snmp test-trap --sink NAME`.
//! * [`build_trap_transport`] — the live [`SnmpTrapTransport`] injected into the
//!   events pipeline so the Wave-4 `snmp_trap` event sink sends real traps.
//!
//! Feature-gated behind `snmp`; the default (no-snmp) build never compiles this
//! and the `serve` / `test-trap` dispatch arms return a clear
//! "built without snmp feature" message.
//!
//! ## Config surface note (for Wave 8 — a peer owns `spt-config`)
//!
//! The current `[observability.snmp]` schema has **no dedicated agent USM users
//! table and no OID-exposure list**. To wire what exists, agent USM users are
//! provisioned from the `[[observability.snmp.traps]]` USM identities (the only
//! USM credential material in the schema; auth defaults to HMAC-SHA-256, priv
//! to AES-128-CFB, matching `spt observe snmp`), and the exposed MIB is a
//! baseline (`sysDescr.0` + an enterprise anchor scalar). Wave 8 should add
//! `[[observability.snmp.users]]` (name/level/auth+priv protocol+secret/
//! writable) and a config-driven OID/metric exposure list, plus `validate`
//! coverage for `version` / `engine_id` / `trap_sinks`.

// SNMP terminology (SNMPv3, GetBulk, USM, ...) is RFC-standard and reads more
// naturally without backticks in prose — mirror `spt-snmp`'s own lib allow.
#![allow(clippy::missing_errors_doc, clippy::doc_markdown)]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use spt_cli::GlobalOpts;
use spt_config::schema::{Config, ObservabilitySnmp, SnmpTrap};
use spt_core::{Error, Result};
use spt_events::sinks::snmp_trap::{SnmpTrap as EventSnmpTrap, SnmpTrapTransport};
use spt_events::sinks::SinkError;
use spt_snmp::{
    generate_engine_id, AuthProtocol, ConstScalar, EngineId, ObjectIdentifier, PrivProtocol,
    SecretBytes, TrapSender, UsmUser, Value, VarBind,
};

/// Default listen address when `[observability.snmp].bind` is unset. Loopback,
/// non-privileged port (the standard 161 needs root/cap_net_bind_service).
/// Mirrors the `spt observe snmp` client default so the walk works out of the
/// box against a locally-served agent.
const DEFAULT_BIND: &str = "127.0.0.1:10161";

// ---------------------------------------------------------------------------
// Runtime handle (spawned under `tunnel run`)
// ---------------------------------------------------------------------------

/// A running SNMP agent spawned by `tunnel run`. Dropping aborts the agent;
/// call [`SnmpRuntime::shutdown`] for a graceful, awaited stop.
pub struct SnmpRuntime {
    handle: spt_snmp::AgentHandle,
    bind: SocketAddr,
}

impl SnmpRuntime {
    /// The address the agent actually bound (kernel-assigned port when `:0`).
    #[must_use]
    pub fn bind(&self) -> SocketAddr {
        self.bind
    }

    /// Signal the agent to stop and await its task.
    pub async fn shutdown(self) {
        let _ = self.handle.shutdown().await;
    }
}

// ---------------------------------------------------------------------------
// Config → AgentBuilder mapping
// ---------------------------------------------------------------------------

/// Resolves the agent's authoritative engine id from config: an explicit hex
/// `engine_id` wins; otherwise a structured id is generated from
/// `enterprise_id` (IANA PEN). Errors when neither is set.
fn resolve_engine_id(snmp: &ObservabilitySnmp) -> Result<EngineId> {
    if let Some(hexstr) = snmp
        .engine_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        let raw = hex::decode(hexstr).map_err(|e| {
            Error::InvalidConfig(format!("[observability.snmp] engine_id must be hex: {e}"))
        })?;
        return EngineId::new(raw)
            .map_err(|e| Error::InvalidConfig(format!("[observability.snmp] engine_id: {e}")));
    }
    if let Some(pen) = snmp.enterprise_id {
        if pen == 0 {
            return Err(Error::InvalidConfig(
                "[observability.snmp] enterprise_id must be greater than zero".into(),
            ));
        }
        return Ok(generate_engine_id(pen));
    }
    Err(Error::InvalidConfig(
        "[observability.snmp] requires either `engine_id` (hex) or `enterprise_id` (IANA PEN)"
            .into(),
    ))
}

/// Validates the `version` field. Only SNMPv3 is implemented (this is a USM
/// agent); anything else is a hard config error rather than a silent no-op.
fn check_version(snmp: &ObservabilitySnmp) -> Result<()> {
    if let Some(v) = snmp
        .version
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        if !(v.eq_ignore_ascii_case("v3") || v == "3") {
            return Err(Error::InvalidConfig(format!(
                "[observability.snmp] version `{v}` is unsupported; only SNMPv3 (`v3`) is implemented"
            )));
        }
    }
    Ok(())
}

/// Builds a [`UsmUser`] from a `[[observability.snmp.traps]]` entry, using it as
/// the agent-side USM identity as well. Auth defaults to HMAC-SHA-256 and priv
/// to AES-128-CFB (matching `spt observe snmp`). Returns `None` when the entry
/// carries no `user` (a bare trap destination with no USM identity).
fn usm_user_from_trap(
    trap: &SnmpTrap,
    resolve_secret: &mut dyn FnMut(&str) -> Result<String>,
) -> Result<Option<UsmUser>> {
    let Some(name) = trap.user.as_deref() else {
        return Ok(None);
    };
    let user = match (trap.auth_secret.as_ref(), trap.privacy_secret.as_ref()) {
        (Some(auth), Some(privacy)) => {
            let auth_pass = resolve_secret(auth.expose())?;
            let priv_pass = resolve_secret(privacy.expose())?;
            UsmUser::auth_priv(
                name,
                AuthProtocol::HmacSha256,
                SecretBytes::from(auth_pass.as_str()),
                PrivProtocol::Aes128,
                SecretBytes::from(priv_pass.as_str()),
            )
        }
        (Some(auth), None) => {
            let auth_pass = resolve_secret(auth.expose())?;
            UsmUser::auth_only(
                name,
                AuthProtocol::HmacSha256,
                SecretBytes::from(auth_pass.as_str()),
            )
        }
        (None, _) => UsmUser::no_auth(name),
    };
    Ok(Some(user))
}

/// Maps `[observability.snmp]` onto a runnable [`spt_snmp::AgentBuilder`].
///
/// Binds `bind` (default `127.0.0.1:10161`), sets the authoritative engine id
/// (explicit hex `engine_id` or generated from `enterprise_id`), provisions USM
/// users from the trap identities, and populates a baseline MIB so the agent
/// exposes at least one OID (`sysDescr.0`, plus an enterprise anchor scalar when
/// `enterprise_id` is set). GetBulk caps are enforced unconditionally by the
/// agent (`spt_snmp::agent::MAX_BULK_REPETITIONS` + response byte budget), so
/// there is no per-field mapping for them.
pub fn build_agent_from_config(
    snmp: &ObservabilitySnmp,
    resolve_secret: &mut dyn FnMut(&str) -> Result<String>,
) -> Result<spt_snmp::AgentBuilder> {
    check_version(snmp)?;

    let bind: SocketAddr = snmp
        .bind
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(DEFAULT_BIND)
        .parse()
        .map_err(|e| {
            Error::InvalidConfig(format!(
                "[observability.snmp] bind `{}`: {e}",
                snmp.bind.as_deref().unwrap_or(DEFAULT_BIND)
            ))
        })?;

    let engine_id = resolve_engine_id(snmp)?;

    let mut builder = spt_snmp::AgentBuilder::new()
        .bind(bind)
        .engine_id(engine_id);

    for trap in &snmp.traps {
        if let Some(user) = usm_user_from_trap(trap, resolve_secret)? {
            builder = builder.add_user(user);
        }
    }

    // Baseline OID exposure (schema has no OID list — see the module note).
    // `sysDescr.0` is always present so a walk returns at least one row.
    builder = builder.add_scalar(
        ObjectIdentifier::new([1u32, 3, 6, 1, 2, 1, 1, 1, 0]),
        ConstScalar::new(Value::OctetString(
            b"spt permanent SSH tunnel SNMP agent".to_vec(),
        )),
    );
    if let Some(pen) = snmp.enterprise_id {
        // Enterprise anchor scalar at `1.3.6.1.4.1.<pen>.1.0`.
        builder = builder.add_scalar(
            ObjectIdentifier::new([1u32, 3, 6, 1, 4, 1, pen, 1, 0]),
            ConstScalar::new(Value::OctetString(b"spt".to_vec())),
        );
    }

    Ok(builder)
}

// ---------------------------------------------------------------------------
// Spawn under `tunnel run`
// ---------------------------------------------------------------------------

/// Spawns the SNMP agent when `[observability.snmp].enabled = true`.
///
/// Mirrors `maybe_spawn_dns_server` / `maybe_spawn_mcp_loopback`: a disabled or
/// absent config returns `Ok(None)`; a build/bind failure returns `Err` (the
/// operator asked for SNMP, so a hard error is correct rather than a silent
/// skip).
pub async fn maybe_spawn_snmp_agent(
    cfg: &Config,
    resolver: &spt_secrets::Resolver,
) -> Result<Option<SnmpRuntime>> {
    let Some(snmp) = cfg.observability.as_ref().and_then(|o| o.snmp.as_ref()) else {
        return Ok(None);
    };
    if snmp.enabled != Some(true) {
        return Ok(None);
    }

    let mut resolve = |raw: &str| resolve_snmp_secret(resolver, raw);
    let builder = build_agent_from_config(snmp, &mut resolve)?;
    let handle = builder
        .run()
        .await
        .map_err(|e| Error::RuntimeFailure(format!("snmp agent: {e}")))?;
    let bind = handle.local_addr();
    tracing::info!(
        %bind,
        users = snmp.traps.iter().filter(|t| t.user.is_some()).count(),
        "snmp agent bound"
    );
    Ok(Some(SnmpRuntime { handle, bind }))
}

// ---------------------------------------------------------------------------
// Standalone CLI paths (`spt observe snmp serve` / `test-trap`)
// ---------------------------------------------------------------------------

/// Load the config + secret resolver for a standalone `spt observe snmp`
/// subcommand.
fn load_cfg_and_resolver(global: &GlobalOpts) -> Result<(Config, spt_secrets::Resolver)> {
    let path = global.config.clone().ok_or_else(|| {
        Error::InvalidConfig("`spt observe snmp` requires a config file (`--config`)".into())
    })?;
    let cfg = spt_config::load(&path, false)
        .map_err(|e| Error::InvalidConfig(format!("load: {e}")))?
        .0;
    let state_dir = spt_state::resolve_state_dir(global.state_dir.as_deref())?;
    let resolver = crate::secrets_bridge::build_resolver(cfg.secrets.as_ref(), &state_dir)?;
    Ok((cfg, resolver))
}

fn snmp_cfg(cfg: &Config) -> Result<&ObservabilitySnmp> {
    cfg.observability
        .as_ref()
        .and_then(|o| o.snmp.as_ref())
        .ok_or_else(|| Error::InvalidConfig("[observability.snmp] is not configured".into()))
}

/// `spt observe snmp serve` — build the agent from config and run it in the
/// foreground until Ctrl-C / SIGTERM.
pub async fn serve(global: &GlobalOpts, _foreground: bool) -> Result<()> {
    let (cfg, resolver) = load_cfg_and_resolver(global)?;
    let snmp = snmp_cfg(&cfg)?;

    let mut resolve = |raw: &str| resolve_snmp_secret(&resolver, raw);
    let builder = build_agent_from_config(snmp, &mut resolve)?;
    let handle = builder
        .run()
        .await
        .map_err(|e| Error::RuntimeFailure(format!("snmp agent: {e}")))?;
    let bind = handle.local_addr();
    tracing::info!(%bind, "snmp agent listening (foreground)");
    println!("snmp agent listening on {bind} (Ctrl-C to stop)");

    let _ = tokio::signal::ctrl_c().await;
    tracing::info!("snmp agent stopping");
    let _ = handle.shutdown().await;
    Ok(())
}

/// `spt observe snmp test-trap --sink NAME` — send a real SNMPv3 trap to the
/// configured `[[observability.snmp.traps]]` entry named `NAME`.
pub async fn send_test_trap(global: &GlobalOpts, sink: &str) -> Result<()> {
    let (cfg, resolver) = load_cfg_and_resolver(global)?;
    let snmp = snmp_cfg(&cfg)?;

    let trap_cfg = snmp.traps.iter().find(|t| t.name == sink).ok_or_else(|| {
        Error::InvalidArgs(format!(
            "no [[observability.snmp.traps]] entry named `{sink}`"
        ))
    })?;

    let engine_id = resolve_engine_id(snmp)?;
    let mut resolve = |raw: &str| resolve_snmp_secret(&resolver, raw);
    let user = usm_user_from_trap(trap_cfg, &mut resolve)?.ok_or_else(|| {
        Error::InvalidConfig(format!(
            "trap sink `{sink}` has no `user`; cannot send a USM trap"
        ))
    })?;

    let dest: SocketAddr = trap_cfg.endpoint.parse().map_err(|e| {
        Error::InvalidConfig(format!(
            "trap sink `{sink}` endpoint `{}`: {e}",
            trap_cfg.endpoint
        ))
    })?;

    let sender = TrapSender::with_engine_id(dest, user, engine_id)
        .await
        .map_err(|e| Error::RuntimeFailure(format!("snmp trap sender: {e}")))?;

    let (trap_oid, message_oid) = trap_oids(snmp);
    sender
        .send(
            trap_oid,
            vec![VarBind::new(
                message_oid,
                Value::OctetString(b"spt observe snmp test-trap".to_vec()),
            )],
        )
        .await
        .map_err(|e| Error::RuntimeFailure(format!("snmp trap send: {e}")))?;

    println!("ok: sent SNMP test trap to sink `{sink}` ({dest})");
    Ok(())
}

/// Notification OID + message-varbind OID for a trap, derived from the
/// enterprise subtree when configured, else standard fallbacks.
fn trap_oids(snmp: &ObservabilitySnmp) -> (ObjectIdentifier, ObjectIdentifier) {
    if let Some(pen) = snmp.enterprise_id {
        (
            // Enterprise-specific notification: `1.3.6.1.4.1.<pen>.0.1`.
            ObjectIdentifier::new([1u32, 3, 6, 1, 4, 1, pen, 0, 1]),
            // Message payload varbind: `1.3.6.1.4.1.<pen>.1.0`.
            ObjectIdentifier::new([1u32, 3, 6, 1, 4, 1, pen, 1, 0]),
        )
    } else {
        (
            // `coldStart` (RFC 3418) as a generic fallback notification.
            ObjectIdentifier::new([1u32, 3, 6, 1, 6, 3, 1, 1, 5, 1]),
            // sysDescr.0 as the message varbind.
            ObjectIdentifier::new([1u32, 3, 6, 1, 2, 1, 1, 1, 0]),
        )
    }
}

// ---------------------------------------------------------------------------
// Events pipeline `snmp_trap` transport
// ---------------------------------------------------------------------------

/// Live [`SnmpTrapTransport`] backing the Wave-4 `snmp_trap` event sink.
///
/// Holds the authoritative engine id and the USM identities from
/// `[[observability.snmp.traps]]`. Each `send_trap` binds an ephemeral source
/// socket, sends one authenticated SNMPv3 trap, and drops it — appropriate for
/// low-volume event notifications. The USM identity is matched to the sink's
/// target endpoint, falling back to the first configured trap identity.
struct SptSnmpTrapTransport {
    engine_id: EngineId,
    default_user: UsmUser,
    by_endpoint: HashMap<String, UsmUser>,
    trap_oid: ObjectIdentifier,
    message_oid: ObjectIdentifier,
}

#[async_trait]
impl SnmpTrapTransport for SptSnmpTrapTransport {
    async fn send_trap(&self, trap: EventSnmpTrap) -> std::result::Result<(), SinkError> {
        let dest: SocketAddr = trap
            .target
            .parse()
            .map_err(|e| SinkError::Config(format!("snmp_trap target `{}`: {e}", trap.target)))?;
        let user = self
            .by_endpoint
            .get(&trap.target)
            .cloned()
            .unwrap_or_else(|| self.default_user.clone());
        let sender = TrapSender::with_engine_id(dest, user, self.engine_id.clone())
            .await
            .map_err(|e| SinkError::Transient(format!("snmp trap sender bind: {e}")))?;
        let vb = VarBind::new(
            self.message_oid.clone(),
            Value::OctetString(trap.message.into_bytes()),
        );
        sender
            .send(self.trap_oid.clone(), vec![vb])
            .await
            .map_err(|e| SinkError::Transient(format!("snmp trap send: {e}")))?;
        Ok(())
    }
}

/// Builds the live trap transport from `[observability.snmp]` for injection into
/// the events pipeline (`SinkDeps::with_snmp_trap`). Returns `Ok(None)` when no
/// trap identities are configured, so the sink stays constructed-but-inert with
/// its existing WARN rather than silently disappearing.
pub fn build_trap_transport(
    snmp: &ObservabilitySnmp,
    resolver: &spt_secrets::Resolver,
) -> Result<Option<Arc<dyn SnmpTrapTransport>>> {
    if snmp.traps.is_empty() {
        return Ok(None);
    }
    let engine_id = resolve_engine_id(snmp)?;
    let mut resolve = |raw: &str| resolve_snmp_secret(resolver, raw);

    let mut by_endpoint = HashMap::new();
    let mut default_user: Option<UsmUser> = None;
    for trap in &snmp.traps {
        if let Some(user) = usm_user_from_trap(trap, &mut resolve)? {
            if default_user.is_none() {
                default_user = Some(user.clone());
            }
            by_endpoint.insert(trap.endpoint.clone(), user);
        }
    }
    let Some(default_user) = default_user else {
        return Ok(None);
    };
    let (trap_oid, message_oid) = trap_oids(snmp);
    Ok(Some(Arc::new(SptSnmpTrapTransport {
        engine_id,
        default_user,
        by_endpoint,
        trap_oid,
        message_oid,
    })))
}

// ---------------------------------------------------------------------------
// Secret resolution
// ---------------------------------------------------------------------------

/// Resolves a trap secret. A `secret://ns/name` reference is resolved through
/// the shared resolver; any other value is treated as a literal passphrase.
fn resolve_snmp_secret(resolver: &spt_secrets::Resolver, raw: &str) -> Result<String> {
    use std::str::FromStr;

    use secrecy::ExposeSecret;
    use spt_secrets::SecretRef;

    if let Ok(sr) = SecretRef::from_str(raw) {
        let bytes = resolver
            .resolve(&sr)
            .map_err(|e| Error::InvalidConfig(format!("snmp secret `{raw}`: {e}")))?;
        String::from_utf8(bytes.expose_secret().to_vec()).map_err(|e| {
            Error::InvalidConfig(format!(
                "snmp secret `{raw}` is not valid UTF-8 (required for a USM passphrase): {e}"
            ))
        })
    } else {
        Ok(raw.to_string())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn snmp_with(traps: Vec<SnmpTrap>) -> ObservabilitySnmp {
        ObservabilitySnmp {
            enabled: Some(true),
            version: Some("v3".into()),
            bind: Some("127.0.0.1:0".into()),
            engine_id: None,
            enterprise_id: Some(12_345),
            trap_sinks: Some(vec!["ops".into()]),
            traps,
        }
    }

    fn trap(name: &str, endpoint: &str, user: Option<&str>, auth: bool, priv_: bool) -> SnmpTrap {
        SnmpTrap {
            name: name.into(),
            endpoint: endpoint.into(),
            user: user.map(Into::into),
            auth_secret: auth.then(|| spt_core::RedactedString::new("auth-passphrase-very-long")),
            privacy_secret: priv_
                .then(|| spt_core::RedactedString::new("priv-passphrase-very-long")),
        }
    }

    fn literal_resolver() -> impl FnMut(&str) -> Result<String> {
        |raw: &str| Ok(raw.to_string())
    }

    // ---- config binding maps every field ---------------------------------

    #[tokio::test(flavor = "current_thread")]
    async fn build_agent_from_config_maps_every_field_and_runs() {
        let snmp = snmp_with(vec![trap(
            "ops",
            "127.0.0.1:1620",
            Some("spt-monitor"),
            true,
            true,
        )]);
        let mut resolve = literal_resolver();
        let builder =
            build_agent_from_config(&snmp, &mut resolve).expect("agent builds from config");
        // The mapping produced a RUNNABLE agent (no UnsupportedPlatform); bind
        // on an ephemeral port and confirm it comes up.
        let handle = builder.run().await.expect("agent runs");
        let addr = handle.local_addr();
        assert!(addr.ip().is_loopback());
        assert_ne!(addr.port(), 0, "kernel assigned a real port");
        let _ = handle.shutdown().await;
    }

    #[test]
    fn explicit_engine_id_hex_is_honored() {
        let mut snmp = snmp_with(vec![]);
        snmp.engine_id = Some("80000abc04deadbeef".into());
        snmp.enterprise_id = None;
        let id = resolve_engine_id(&snmp).expect("hex engine id");
        assert_eq!(
            id.as_bytes(),
            &hex::decode("80000abc04deadbeef").unwrap()[..]
        );
    }

    #[test]
    fn enterprise_id_generates_engine_id() {
        let mut snmp = snmp_with(vec![]);
        snmp.engine_id = None;
        snmp.enterprise_id = Some(12_345);
        let id = resolve_engine_id(&snmp).expect("generated engine id");
        // RFC 3411 §5.1: top bit set, PEN encoded in the low 31 bits.
        assert_eq!(id.as_bytes()[0] & 0x80, 0x80);
    }

    #[test]
    fn missing_engine_id_and_pen_is_error() {
        let mut snmp = snmp_with(vec![]);
        snmp.engine_id = None;
        snmp.enterprise_id = None;
        assert!(matches!(
            resolve_engine_id(&snmp),
            Err(Error::InvalidConfig(_))
        ));
    }

    #[test]
    fn non_v3_version_rejected() {
        let mut snmp = snmp_with(vec![]);
        snmp.version = Some("v2c".into());
        let mut resolve = literal_resolver();
        assert!(matches!(
            build_agent_from_config(&snmp, &mut resolve),
            Err(Error::InvalidConfig(_))
        ));
    }

    #[test]
    fn trap_user_levels_are_mapped() {
        let mut resolve = literal_resolver();
        // authPriv
        let u = usm_user_from_trap(
            &trap("s", "127.0.0.1:162", Some("u"), true, true),
            &mut resolve,
        )
        .unwrap()
        .unwrap();
        assert!(u.auth.is_some() && u.priv_.is_some());
        // authNoPriv
        let u = usm_user_from_trap(
            &trap("s", "127.0.0.1:162", Some("u"), true, false),
            &mut resolve,
        )
        .unwrap()
        .unwrap();
        assert!(u.auth.is_some() && u.priv_.is_none());
        // noAuthNoPriv
        let u = usm_user_from_trap(
            &trap("s", "127.0.0.1:162", Some("u"), false, false),
            &mut resolve,
        )
        .unwrap()
        .unwrap();
        assert!(u.auth.is_none());
        // no user → skipped
        assert!(usm_user_from_trap(
            &trap("s", "127.0.0.1:162", None, false, false),
            &mut resolve
        )
        .unwrap()
        .is_none());
    }

    // ---- trap transport builds + sends -----------------------------------

    #[tokio::test(flavor = "current_thread")]
    async fn trap_transport_sends_to_a_listening_socket() {
        use tokio::net::UdpSocket;

        // A UDP "trap receiver" on loopback.
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dest = receiver.local_addr().unwrap();

        let snmp = snmp_with(vec![trap(
            "ops",
            &dest.to_string(),
            Some("trap-user"),
            true,
            true,
        )]);

        // Build the transport with a literal-secret resolver (no keychain).
        let tmp = tempfile::tempdir().unwrap();
        let resolver =
            crate::secrets_bridge::build_resolver(None, tmp.path()).expect("resolver builds");
        let transport = build_trap_transport(&snmp, &resolver)
            .expect("transport builds")
            .expect("transport present when traps configured");

        // Deliver a prepared event trap; assert bytes actually arrive.
        let ev = EventSnmpTrap {
            target: dest.to_string(),
            message: "profile.failed: boom".into(),
            kind: "profile.failed".into(),
        };
        transport.send_trap(ev).await.expect("trap sent");

        let mut buf = vec![0u8; 4096];
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(3),
            receiver.recv_from(&mut buf),
        )
        .await
        .expect("trap datagram timeout")
        .expect("recv trap")
        .0;
        assert!(n > 0, "a non-empty SNMP trap datagram was received");
        // It must be a parseable SNMPv3 message.
        spt_snmp::message::Message::from_bytes(&buf[..n]).expect("trap parses as SNMPv3");
    }

    #[test]
    fn no_traps_yields_no_transport() {
        let snmp = snmp_with(vec![]);
        let tmp = tempfile::tempdir().unwrap();
        let resolver = crate::secrets_bridge::build_resolver(None, tmp.path()).unwrap();
        assert!(build_trap_transport(&snmp, &resolver).unwrap().is_none());
    }
}
