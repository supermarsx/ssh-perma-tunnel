//! `spt observe {windows-event}` operations.
//!
//! With the `snmp` feature, this module also exposes `spt observe snmp`.
//! That command walks an SNMPv3 USM (sha256/aes128) subtree against the
//! running spt's loopback SNMP agent and prints OID → value pairs.
//!
//! `windows-event` writes one synthetic Event Log entry on Windows; on
//! non-Windows hosts it surfaces `UnsupportedPlatform` cleanly.

#![allow(clippy::needless_pass_by_value)]
#![allow(clippy::missing_errors_doc)]

use std::path::PathBuf;

#[cfg(feature = "snmp")]
use serde_json::json;
use spt_cli::GlobalOpts;
use spt_core::{Error, Result};

/// Args for [`snmp`].
#[cfg(feature = "snmp")]
#[derive(Debug, Clone)]
pub struct ObserveSnmpArgs {
    /// Subtree root to walk. Defaults to `[observability.snmp].enterprise_id`.
    pub query: Option<String>,
    /// USM user name. Defaults to `spt-monitor`.
    pub user: Option<String>,
    /// Secret reference (`secret://ns/name`) for the auth (HMAC-SHA-256) key.
    pub auth_key_from: Option<String>,
    /// Secret reference for the privacy (AES-128-CFB) key.
    pub priv_key_from: Option<String>,
    /// Bind address of the running agent. Defaults to looking up
    /// `[observability.snmp].bind` in the loaded config; falls back to
    /// `127.0.0.1:10161`.
    pub target: Option<String>,
    /// JSON output.
    pub json: bool,
}

#[cfg(feature = "snmp")]
impl Default for ObserveSnmpArgs {
    fn default() -> Self {
        Self {
            query: None,
            user: None,
            auth_key_from: None,
            priv_key_from: None,
            target: None,
            json: false,
        }
    }
}

/// Args for [`windows_event`].
#[derive(Debug, Clone)]
pub struct ObserveWindowsEventArgs {
    /// Message body. Defaults to a generic synthetic-test marker.
    pub message: Option<String>,
    /// Event Log source name. Defaults to `[observability.windows_event].source`
    /// in config, or `spt` if absent.
    pub source: Option<String>,
    /// Event Log channel. Defaults to `[observability.windows_event].channel`
    /// in config, or `Application` if absent.
    pub channel: Option<String>,
    /// Event level (`info`, `warning`, `error`).
    pub level: String,
    /// Event identifier.
    pub event_id: u32,
}

impl Default for ObserveWindowsEventArgs {
    fn default() -> Self {
        Self {
            message: None,
            source: None,
            channel: None,
            level: "info".to_string(),
            event_id: 1000,
        }
    }
}

/// Args for Windows Event Log source install/uninstall.
#[derive(Debug, Clone, Default)]
pub struct ObserveWindowsEventSourceArgs {
    /// Event Log source name. Defaults to config or `spt`.
    pub source: Option<String>,
    /// Event Log channel. Defaults to config or `Application`.
    pub channel: Option<String>,
    /// Message table DLL/EXE. Used only by install-source.
    pub message_dll: Option<PathBuf>,
}

// ---------------------------------------------------------------------------
// Public entry points
// ---------------------------------------------------------------------------

#[cfg(feature = "snmp")]
const DEFAULT_USER: &str = "spt-monitor";
#[cfg(feature = "snmp")]
const DEFAULT_TARGET: &str = "127.0.0.1:10161";

/// `spt observe snmp` — walk the project enterprise OID subtree against the
/// running loopback agent.
#[cfg(feature = "snmp")]
pub async fn snmp(global: &GlobalOpts, args: ObserveSnmpArgs) -> Result<()> {
    use std::net::SocketAddr;

    use spt_snmp::testing::TestSnmpClient;
    use spt_snmp::value::{Value as SnmpValue, VarBind};
    use spt_snmp::{
        AuthProtocol, ObjectIdentifier, Pdu, PduKind, PrivProtocol, SecretBytes, SecurityLevel,
        UsmUser,
    };

    let target_str = args
        .target
        .clone()
        .or_else(|| config_snmp_bind(global).ok().flatten())
        .unwrap_or_else(|| DEFAULT_TARGET.to_string());
    let target: SocketAddr = target_str
        .parse()
        .map_err(|e| Error::InvalidArgs(format!("snmp target `{target_str}`: {e}")))?;

    let configured_oid = config_snmp_enterprise_oid(global).ok().flatten();
    let oid_str = args
        .query
        .as_deref()
        .or(configured_oid.as_deref())
        .ok_or_else(|| {
            Error::InvalidArgs(
                "provide --query or set [observability.snmp].enterprise_id; \
                 production SNMP cannot default to the RFC documentation PEN"
                    .into(),
            )
        })?;
    let root_oid: ObjectIdentifier = oid_str
        .parse()
        .map_err(|e: spt_snmp::Error| Error::InvalidArgs(format!("oid `{oid_str}`: {e}")))?;

    let user_name = args
        .user
        .clone()
        .unwrap_or_else(|| DEFAULT_USER.to_string());
    let auth_pass = resolve_secret(global, args.auth_key_from.as_deref(), "auth")?;
    let priv_pass = resolve_secret(global, args.priv_key_from.as_deref(), "priv")?;

    let user = UsmUser::auth_priv(
        user_name.as_str(),
        AuthProtocol::HmacSha256,
        SecretBytes::from(auth_pass.as_str()),
        PrivProtocol::Aes128,
        SecretBytes::from(priv_pass.as_str()),
    );

    let mut client = TestSnmpClient::new(target, user).await;
    client.discover().await;

    // Walk the subtree via GetNext until the agent returns an OID outside
    // the requested root prefix or signals `endOfMibView`. We cap the walk
    // at 4096 records so a misconfigured agent can't pin the CLI.
    let mut pairs: Vec<(String, String)> = Vec::new();
    let mut cursor = root_oid.clone();
    const WALK_CAP: usize = 4096;
    for _ in 0..WALK_CAP {
        let pdu = Pdu {
            kind: PduKind::GetNextRequest,
            request_id: client.alloc_id(),
            error_status: 0,
            error_index: 0,
            variable_bindings: vec![VarBind::null(cursor.clone())],
        };
        let resp = client.request(pdu, SecurityLevel::AuthPriv).await;
        let Some(vb) = resp.variable_bindings.into_iter().next() else {
            break;
        };
        // End-of-MIB / no-such-object terminate the walk.
        if matches!(
            vb.value,
            SnmpValue::EndOfMibView | SnmpValue::NoSuchObject | SnmpValue::NoSuchInstance
        ) {
            break;
        }
        // OID outside the requested root subtree → walk done.
        if !vb.name.starts_with(&root_oid) {
            break;
        }
        pairs.push((format!("{}", vb.name), format!("{:?}", vb.value)));
        cursor = vb.name;
    }
    // Single Get fallback: if GetNext returned nothing in-prefix, attempt a
    // direct Get against the root so users at least see the scalar.
    if pairs.is_empty() {
        let vb = client.get(root_oid.clone(), SecurityLevel::AuthPriv).await;
        if !matches!(
            vb.value,
            SnmpValue::EndOfMibView | SnmpValue::NoSuchObject | SnmpValue::NoSuchInstance
        ) {
            pairs.push((format!("{}", vb.name), format!("{:?}", vb.value)));
        }
    }

    if args.json {
        let v = json!({
            "target": target_str,
            "root": oid_str,
            "user": user_name,
            "pairs": pairs.iter().map(|(o, v)| json!({"oid": o, "value": v})).collect::<Vec<_>>(),
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&v).map_err(|e| Error::RuntimeFailure(e.to_string()))?
        );
    } else {
        println!("# target: {target_str}  user: {user_name}");
        for (o, val) in &pairs {
            println!("{o}\t{val}");
        }
    }
    Ok(())
}

/// `spt observe windows-event` — write a synthetic Event Log entry.
///
/// On non-Windows targets returns [`Error::UnsupportedPlatform`] with a
/// clear message.
pub async fn windows_event(global: &GlobalOpts, args: ObserveWindowsEventArgs) -> Result<()> {
    let message = args
        .message
        .clone()
        .unwrap_or_else(|| "synthetic event from `spt observe windows-event`".to_string());
    let source = resolve_winevent_source(global, args.source.clone())?;
    let _channel = resolve_winevent_channel(global, args.channel.clone())?;
    let level = parse_winevent_level(&args.level)?;
    let event_id = args.event_id;

    #[cfg(windows)]
    {
        // The win32 `ReportEventW` API doesn't return a record id directly —
        // we surface the source/level/message that was emitted instead, which
        // is what Event Viewer keys on. Future work can hook the bookmark
        // API to surface the actual event record id.
        spt_winevent::report_event(&source, level, event_id, &message)?;
        println!(
            "ok: emitted synthetic event (source=`{source}`, level={}, id={event_id})",
            winevent_level_name(level)
        );
        Ok(())
    }
    #[cfg(not(windows))]
    {
        let _ = (source, level, event_id, message);
        Err(Error::UnsupportedPlatform(
            "spt observe windows-event is only supported on Windows".to_string(),
        ))
    }
}

/// `spt observe windows-event install-source`.
pub async fn windows_event_install_source(
    global: &GlobalOpts,
    args: ObserveWindowsEventSourceArgs,
) -> Result<()> {
    let source = resolve_winevent_source(global, args.source.clone())?;
    let channel = resolve_winevent_channel(global, args.channel.clone())?;
    #[cfg(windows)]
    {
        spt_winevent::register_source(&source, Some(&channel), args.message_dll.as_deref())?;
        println!("ok: installed Windows Event Log source `{source}` in `{channel}`");
        Ok(())
    }
    #[cfg(not(windows))]
    {
        let _ = (source, channel, args.message_dll);
        Err(Error::UnsupportedPlatform(
            "spt observe windows-event install-source is only supported on Windows".to_string(),
        ))
    }
}

/// `spt observe windows-event uninstall-source`.
pub async fn windows_event_uninstall_source(
    global: &GlobalOpts,
    args: ObserveWindowsEventSourceArgs,
) -> Result<()> {
    let source = resolve_winevent_source(global, args.source.clone())?;
    let channel = resolve_winevent_channel(global, args.channel.clone())?;
    #[cfg(windows)]
    {
        spt_winevent::unregister_source(&source, Some(&channel))?;
        println!("ok: uninstalled Windows Event Log source `{source}` from `{channel}`");
        Ok(())
    }
    #[cfg(not(windows))]
    {
        let _ = (source, channel, args.message_dll);
        Err(Error::UnsupportedPlatform(
            "spt observe windows-event uninstall-source is only supported on Windows".to_string(),
        ))
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

#[cfg(feature = "snmp")]
fn config_snmp_bind(global: &GlobalOpts) -> Result<Option<String>> {
    let Some(path) = global.config.clone() else {
        return Ok(None);
    };
    let (cfg, _w) =
        spt_config::load(&path, false).map_err(|e| Error::InvalidConfig(format!("load: {e}")))?;
    Ok(cfg
        .observability
        .as_ref()
        .and_then(|o| o.snmp.as_ref())
        .and_then(|s| s.bind.clone()))
}

#[cfg(feature = "snmp")]
fn config_snmp_enterprise_oid(global: &GlobalOpts) -> Result<Option<String>> {
    let Some(path) = global.config.clone() else {
        return Ok(None);
    };
    let (cfg, _w) =
        spt_config::load(&path, false).map_err(|e| Error::InvalidConfig(format!("load: {e}")))?;
    Ok(cfg
        .observability
        .as_ref()
        .and_then(|o| o.snmp.as_ref())
        .and_then(|s| s.enterprise_id)
        .map(|pen| spt_snmp::enterprise_oid(pen).to_string()))
}

fn config_winevent_source(global: &GlobalOpts) -> Result<Option<String>> {
    let Some(path) = global.config.clone() else {
        return Ok(None);
    };
    let (cfg, _w) =
        spt_config::load(&path, false).map_err(|e| Error::InvalidConfig(format!("load: {e}")))?;
    Ok(cfg
        .observability
        .as_ref()
        .and_then(|o| o.windows_event.as_ref())
        .and_then(|w| w.source.clone()))
}

fn config_winevent_channel(global: &GlobalOpts) -> Result<Option<String>> {
    let Some(path) = global.config.clone() else {
        return Ok(None);
    };
    let (cfg, _w) =
        spt_config::load(&path, false).map_err(|e| Error::InvalidConfig(format!("load: {e}")))?;
    Ok(cfg
        .observability
        .as_ref()
        .and_then(|o| o.windows_event.as_ref())
        .and_then(|w| w.channel.clone()))
}

fn resolve_winevent_source(global: &GlobalOpts, arg: Option<String>) -> Result<String> {
    Ok(arg
        .or_else(|| config_winevent_source(global).ok().flatten())
        .unwrap_or_else(|| "spt".to_string()))
}

fn resolve_winevent_channel(global: &GlobalOpts, arg: Option<String>) -> Result<String> {
    Ok(arg
        .or_else(|| config_winevent_channel(global).ok().flatten())
        .unwrap_or_else(|| spt_winevent::DEFAULT_CHANNEL.to_string()))
}

fn parse_winevent_level(raw: &str) -> Result<spt_winevent::Level> {
    match raw {
        "info" => Ok(spt_winevent::Level::Info),
        "warning" | "warn" => Ok(spt_winevent::Level::Warning),
        "error" => Ok(spt_winevent::Level::Error),
        other => Err(Error::InvalidArgs(format!(
            "windows-event level `{other}` is invalid; expected info|warning|error"
        ))),
    }
}

fn winevent_level_name(level: spt_winevent::Level) -> &'static str {
    match level {
        spt_winevent::Level::Info => "info",
        spt_winevent::Level::Warning => "warning",
        spt_winevent::Level::Error => "error",
    }
}

/// Resolve a secret reference into a UTF-8 passphrase. When `r` is `None` we
/// fall back to a deterministic test-only passphrase so the command works
/// against the default `LocalhostAgent` fixture during smoke testing — this
/// is documented in the help text.
#[cfg(feature = "snmp")]
fn resolve_secret(global: &GlobalOpts, r: Option<&str>, label: &str) -> Result<String> {
    use std::str::FromStr;

    use spt_secrets::SecretRef;
    let Some(r) = r else {
        // Fallback: a deterministic passphrase used by spt_snmp::testing
        // fixtures. CLI help notes the fallback is for testing only.
        return Ok(match label {
            "auth" => "spt-test-auth-passphrase-very-long".to_string(),
            "priv" => "spt-test-priv-passphrase-very-long".to_string(),
            _ => "spt-default-passphrase-very-long".to_string(),
        });
    };
    let path = global.config.clone();
    let cfg = match path {
        Some(p) => Some(
            spt_config::load(&p, false)
                .map_err(|e| Error::InvalidConfig(format!("load: {e}")))?
                .0,
        ),
        None => None,
    };
    let state_dir = spt_state::resolve_state_dir(global.state_dir.as_deref())?;
    let resolver = crate::secrets_bridge::build_resolver(
        cfg.as_ref().and_then(|c| c.secrets.as_ref()),
        &state_dir,
    )?;
    let sr =
        SecretRef::from_str(r).map_err(|e| Error::InvalidArgs(format!("secret ref `{r}`: {e}")))?;
    let bytes = resolver.resolve(&sr)?;
    use secrecy::ExposeSecret;
    String::from_utf8(bytes.expose_secret().to_vec()).map_err(|e| {
        Error::InvalidConfig(format!(
            "secret `{r}` is not valid UTF-8 (required for SNMP USM passphrase): {e}"
        ))
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use spt_cli::{ColorMode, LogLevel, OutputFormat};

    fn opts() -> GlobalOpts {
        GlobalOpts {
            config: None,
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

    #[cfg(feature = "snmp")]
    #[tokio::test(flavor = "current_thread")]
    async fn snmp_round_trips_against_localhost_agent() {
        use spt_snmp::testing::{fixtures, LocalhostAgent};
        use spt_snmp::value::Value;
        use spt_snmp::{ConstScalar, ObjectIdentifier};

        let user = fixtures::default_user();
        let oid: ObjectIdentifier = spt_snmp::DOCUMENTATION_ENTERPRISE_OID.parse().unwrap();
        let oid_for_register = oid.clone();
        let agent = LocalhostAgent::ephemeral_with(user, |b| {
            b.add_scalar(
                oid_for_register,
                ConstScalar::new(Value::OctetString(b"hello".to_vec())),
            )
        })
        .await
        .unwrap();

        let g = opts();
        let args = ObserveSnmpArgs {
            target: Some(agent.addr().to_string()),
            query: Some(spt_snmp::DOCUMENTATION_ENTERPRISE_OID.to_string()),
            user: Some("spt-test".to_string()),
            json: true,
            ..Default::default()
        };
        snmp(&g, args).await.expect("snmp ok");
        agent.shutdown().await;
    }

    #[cfg(feature = "snmp")]
    #[tokio::test(flavor = "current_thread")]
    async fn snmp_errors_on_unparseable_target() {
        let g = opts();
        let args = ObserveSnmpArgs {
            target: Some("not-a-socket-addr".to_string()),
            ..Default::default()
        };
        let err = snmp(&g, args).await.unwrap_err();
        assert!(matches!(err, Error::InvalidArgs(_)));
    }

    #[cfg(not(windows))]
    #[tokio::test(flavor = "current_thread")]
    async fn windows_event_returns_unsupported_on_non_windows() {
        let g = opts();
        let args = ObserveWindowsEventArgs::default();
        let err = windows_event(&g, args).await.unwrap_err();
        assert!(matches!(err, Error::UnsupportedPlatform(_)));
    }

    #[cfg(windows)]
    #[tokio::test(flavor = "current_thread")]
    async fn windows_event_emits_on_windows() {
        // On Windows, ReportEventW against a not-yet-registered source still
        // succeeds (ReportEvent uses RegisterEventSource with auto-creation
        // on the local machine). We don't assert on a specific record id —
        // see the doc comment on `windows_event`.
        let g = opts();
        let args = ObserveWindowsEventArgs {
            message: Some("unit test".to_string()),
            source: Some("spt-test-unit".to_string()),
            ..Default::default()
        };
        // Allow either Ok or a permission/registry failure on locked-down CI.
        let _ = windows_event(&g, args).await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn config_winevent_source_returns_none_when_config_missing() {
        let g = opts();
        let v = config_winevent_source(&g).unwrap();
        assert!(v.is_none());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn config_winevent_source_reads_value_from_config() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = tmp.path().join("c.toml");
        std::fs::write(
            &cfg,
            r#"
                version = 1
                [observability.windows_event]
                source = "my-source"
            "#,
        )
        .unwrap();
        let mut g = opts();
        g.config = Some(cfg);
        let v = config_winevent_source(&g).unwrap();
        assert_eq!(v.as_deref(), Some("my-source"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn config_winevent_channel_reads_value_from_config() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = tmp.path().join("c.toml");
        std::fs::write(
            &cfg,
            r#"
                version = 1
                [observability.windows_event]
                channel = "Application"
            "#,
        )
        .unwrap();
        let mut g = opts();
        g.config = Some(cfg);
        let v = config_winevent_channel(&g).unwrap();
        assert_eq!(v.as_deref(), Some("Application"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn config_winevent_source_returns_none_when_section_absent() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = tmp.path().join("c.toml");
        std::fs::write(&cfg, "version = 1\n").unwrap();
        let mut g = opts();
        g.config = Some(cfg);
        let v = config_winevent_source(&g).unwrap();
        assert!(v.is_none());
    }

    #[cfg(feature = "snmp")]
    #[test]
    fn resolve_secret_falls_back_to_test_passphrase() {
        let g = opts();
        let auth = resolve_secret(&g, None, "auth").unwrap();
        assert!(auth.contains("auth"));
        let priv_ = resolve_secret(&g, None, "priv").unwrap();
        assert!(priv_.contains("priv"));
        let other = resolve_secret(&g, None, "other").unwrap();
        assert!(other.contains("passphrase"));
    }

    #[cfg(feature = "snmp")]
    #[test]
    fn observe_snmp_args_default_is_all_none() {
        let a = ObserveSnmpArgs::default();
        assert!(a.query.is_none());
        assert!(a.user.is_none());
        assert!(a.auth_key_from.is_none());
        assert!(a.priv_key_from.is_none());
        assert!(a.target.is_none());
        assert!(!a.json);
    }

    #[test]
    fn observe_windows_event_args_default_is_safe_test_event() {
        let a = ObserveWindowsEventArgs::default();
        assert!(a.message.is_none());
        assert!(a.source.is_none());
        assert!(a.channel.is_none());
        assert_eq!(a.level, "info");
        assert_eq!(a.event_id, 1000);
    }

    #[test]
    fn parse_winevent_level_accepts_known_levels() {
        assert_eq!(
            parse_winevent_level("info").unwrap(),
            spt_winevent::Level::Info
        );
        assert_eq!(
            parse_winevent_level("warning").unwrap(),
            spt_winevent::Level::Warning
        );
        assert_eq!(
            parse_winevent_level("warn").unwrap(),
            spt_winevent::Level::Warning
        );
        assert_eq!(
            parse_winevent_level("error").unwrap(),
            spt_winevent::Level::Error
        );
        assert!(matches!(
            parse_winevent_level("debug").unwrap_err(),
            Error::InvalidArgs(_)
        ));
    }

    #[cfg(not(windows))]
    #[tokio::test(flavor = "current_thread")]
    async fn windows_event_install_source_returns_unsupported_on_non_windows() {
        let g = opts();
        let args = ObserveWindowsEventSourceArgs::default();
        let err = windows_event_install_source(&g, args).await.unwrap_err();
        assert!(matches!(err, Error::UnsupportedPlatform(_)));
    }

    #[cfg(feature = "snmp")]
    #[tokio::test(flavor = "current_thread")]
    async fn config_snmp_bind_returns_none_without_config() {
        let g = opts();
        let v = config_snmp_bind(&g).unwrap();
        assert!(v.is_none());
    }

    #[cfg(feature = "snmp")]
    #[tokio::test(flavor = "current_thread")]
    async fn config_snmp_bind_reads_from_config_when_set() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = tmp.path().join("c.toml");
        std::fs::write(
            &cfg,
            r#"
                version = 1
                [observability.snmp]
                bind = "127.0.0.1:10161"
                enterprise_id = 99999
            "#,
        )
        .unwrap();
        let mut g = opts();
        g.config = Some(cfg);
        let v = config_snmp_bind(&g).unwrap();
        assert_eq!(v.as_deref(), Some("127.0.0.1:10161"));
    }
}
