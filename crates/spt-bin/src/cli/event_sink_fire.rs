//! Shared event-sink construct-and-fire helper used by both `spt event test`
//! (`cli_dispatch::event_test` / `event_sink_test`) and `spt event replay`
//! (`cli::event_ops::replay`).
//!
//! Both commands need to turn a parsed [`spt_config::schema::EventSink`] (any
//! kind) into a live [`spt_events::Sink`] and push exactly one event through
//! it. This module is the single owner of that construct-and-fire path so the
//! per-sink-kind match is not duplicated.
//!
//! Construction mirrors the production pipeline in
//! `cli_dispatch::build_event_sinks`: every kind is built through
//! [`spt_events::build_sink`] with real transports (a pooled HTTPS transport
//! honouring the sink's own TLS-pin posture, a per-sink SMTP transport for
//! `email` that rejects unsupported SMTP pinning config, a child-process
//! runner for `command`), and `secret://` references are resolved through the
//! same [`spt_secrets::Resolver`] the rest of the binary uses. The MCP notifier
//! is the inert [`spt_events::NoopMcpNotifier`]:
//! a one-shot CLI invocation has no live MCP broadcast channel, so a
//! `mcp_notify` sink constructs and "delivers" without erroring (no frame is
//! actually broadcast — there are no subscribers in a CLI context).
//!
//! The historical `kind = "webpush"` config form is normalised onto the
//! generic `push` builder (which produces a `WebPushSink` when subscriptions +
//! a VAPID key are present), preserving the previously-working webpush path.

use std::sync::Arc;

use spt_cli::GlobalOpts;
use spt_config::schema::{EventCommand, EventSink};
use spt_core::Result;
use spt_events::event::Event;

/// Build the sink described by `sink_cfg` and deliver `evt` through it.
///
/// Returns `Err(message)` on either construction failure (bad URL, missing
/// secret, unsupported kind, …) or delivery failure. Errors are stringified so
/// the caller can record a per-sink result without aborting the run — both
/// callers fan over several sinks and isolate failures per sink.
///
/// `commands` is the `[[events.commands]]` table (needed to back a `command`
/// sink); pass an empty slice when irrelevant.
pub async fn fire_event_through_sink(
    global: &GlobalOpts,
    sink_cfg: &EventSink,
    commands: &[EventCommand],
    evt: Arc<Event>,
) -> std::result::Result<(), String> {
    let sink = build_one_sink(global, sink_cfg, commands).map_err(|e| e.to_string())?;
    sink.deliver(evt).await.map_err(|e| e.to_string())
}

/// Construct a single live sink from its config, resolving secrets and
/// injecting real transports. Shared by both fire paths.
fn build_one_sink(
    global: &GlobalOpts,
    sink_cfg: &EventSink,
    commands: &[EventCommand],
) -> std::result::Result<Box<dyn spt_events::Sink>, String> {
    // `kind = "webpush"` is the legacy spelling of a push sink that carries
    // subscriptions + a VAPID key; the generic `push` builder produces a
    // `WebPushSink` in that case. Normalise so a single `build_sink` call
    // covers both spellings.
    let normalized;
    let effective: &EventSink = if sink_cfg.kind == "webpush" {
        normalized = EventSink {
            kind: "push".to_string(),
            ..sink_cfg.clone()
        };
        &normalized
    } else {
        sink_cfg
    };

    let resolver = build_resolver_for(global).map_err(|e| e.to_string())?;
    let deps = build_sink_deps(effective, &resolver).map_err(|e| e.to_string())?;

    spt_events::build_sink(effective, commands, &deps, &resolver).map_err(|e| e.to_string())
}

/// Build a secrets [`spt_secrets::Resolver`] from the `[secrets]` config table,
/// rooted at the resolved state dir — the same chain the rest of the binary
/// uses to resolve `secret://` references.
fn build_resolver_for(global: &GlobalOpts) -> Result<spt_secrets::Resolver> {
    let state_dir = spt_state::resolve_state_dir(global.state_dir.as_deref())?;
    // The sinks resolve only `secret://` refs they carry; the `[secrets]`
    // table is loaded best-effort from the config when present. A failure to
    // read the config is non-fatal here because callers already loaded it; we
    // build the default chain when it is unavailable.
    let secrets_cfg = global
        .config
        .as_deref()
        .and_then(|p| spt_config::load(p, false).ok())
        .and_then(|(cfg, _)| cfg.secrets.clone());
    crate::secrets_bridge::build_resolver(secrets_cfg.as_ref(), &state_dir)
}

/// Assemble the [`spt_events::SinkDeps`] needed to construct `sink_cfg`,
/// honouring the sink's own TLS-pin posture for HTTPS-backed kinds and building
/// a per-sink SMTP transport for `email`. Mirrors
/// `cli_dispatch::build_event_sinks`.
fn build_sink_deps(
    sink_cfg: &EventSink,
    resolver: &spt_secrets::Resolver,
) -> Result<spt_events::SinkDeps> {
    use spt_core::Error;

    let mut deps = spt_events::SinkDeps::none()
        .with_command(Arc::new(spt_events::sinks::command::ProcessRunner)
            as Arc<dyn spt_events::sinks::command::CommandRunner>)
        .with_mcp(Arc::new(spt_events::NoopMcpNotifier) as Arc<dyn spt_events::McpNotifier>);

    // HTTPS transport for http/webhook_post/sms/push, honouring per-sink TLS
    // pinning / self-signed posture.
    let timeout = sink_cfg
        .timeout
        .as_deref()
        .and_then(|d| spt_core::duration::parse_duration(d).ok())
        .unwrap_or(spt_events::sinks::build::DEFAULT_SINK_TIMEOUT);
    let http = spt_events::sinks::http::reqwest_transport::ReqwestTransport::with_pin(
        timeout,
        &sink_cfg.pin_spki_sha256,
        sink_cfg.allow_self_signed.unwrap_or(false),
        sink_cfg.max_cert_chain_depth.or(Some(5)),
    )
    .map_err(|e| Error::RuntimeFailure(format!("http transport: {e}")))?;
    deps = deps.with_http(Arc::new(http) as Arc<dyn spt_events::sinks::http::HttpTransport>);

    if sink_cfg.kind == "email" {
        let email = build_email_transport(sink_cfg, resolver)?;
        deps = deps.with_email(email);
    }

    Ok(deps)
}

/// Build a production SMTP transport for an `email` sink from its config.
///
/// `smtp` is `host` or `host:port` (default port 587, STARTTLS). The optional
/// `auth` field is a `user:pass` pair (each half may be a `secret://` ref
/// resolved through the shared resolver). Kept in sync with the equivalent in
/// `cli_dispatch`.
fn build_email_transport(
    sc: &EventSink,
    resolver: &spt_secrets::Resolver,
) -> Result<Arc<dyn spt_events::sinks::email::EmailTransport>> {
    use spt_core::Error;
    reject_unsupported_email_pinned_tls(sc)?;
    let endpoint = sc
        .smtp
        .as_deref()
        .ok_or_else(|| Error::InvalidConfig(format!("email sink `{}` has no `smtp`", sc.name)))?;
    let (host, port) = match endpoint.rsplit_once(':') {
        Some((h, p)) => (
            h.to_string(),
            p.parse::<u16>().map_err(|e| {
                Error::InvalidConfig(format!("email sink `{}` smtp port: {e}", sc.name))
            })?,
        ),
        None => (endpoint.to_string(), 587u16),
    };
    let user_pass = match sc.auth.as_deref() {
        Some(raw) => {
            let resolved = spt_events::resolve_secret(raw, resolver)
                .map_err(|e| Error::InvalidConfig(format!("email sink `{}` auth: {e}", sc.name)))?;
            resolved
                .split_once(':')
                .map(|(u, p)| (u.to_string(), p.to_string()))
        }
        None => None,
    };
    let transport = spt_events::sinks::email::smtp::SmtpTransport::build(&host, port, user_pass)
        .map_err(|e| Error::InvalidConfig(format!("email sink `{}` smtp: {e}", sc.name)))?;
    Ok(Arc::new(transport) as Arc<dyn spt_events::sinks::email::EmailTransport>)
}

/// SMTP delivery currently uses lettre's STARTTLS transport, which does not
/// expose the per-sink pinned-TLS controls accepted for HTTPS sinks. Fail
/// closed instead of silently downgrading a configured SMTP authenticity
/// policy to ordinary CA validation.
fn reject_unsupported_email_pinned_tls(sc: &EventSink) -> Result<()> {
    use spt_core::Error;

    if !sc.pin_spki_sha256.is_empty()
        || sc.allow_self_signed.is_some()
        || sc.max_cert_chain_depth.is_some()
    {
        return Err(Error::InvalidConfig(format!(
            "email sink `{}` configures pinned TLS for SMTP, but SMTP pinning \
             is not supported by this transport; remove pin_spki_sha256, \
             allow_self_signed, and max_cert_chain_depth or use an HTTPS sink",
            sc.name
        )));
    }
    Ok(())
}

/// Build the canonical synthetic event used by `spt event test`.
#[must_use]
pub fn synthetic_event() -> Arc<Event> {
    use spt_events::event::{EventBuilder, EventKind, Severity};
    Arc::new(
        EventBuilder::new(EventKind::new("synthetic.test"), Severity::Info)
            .message("synthetic event from `spt event test`")
            .build(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use spt_cli::{ColorMode, LogLevel, OutputFormat};
    use spt_config::schema::EventSink;
    use std::path::PathBuf;
    use tempfile::tempdir;

    fn opts(state: PathBuf) -> GlobalOpts {
        GlobalOpts {
            config: None,
            config_dir: None,
            config_url: None,
            config_fingerprint: None,
            state_dir: Some(state),
            profile: None,
            portable: false,
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

    fn sink(name: &str, kind: &str) -> EventSink {
        EventSink {
            name: name.into(),
            kind: kind.into(),
            ..Default::default()
        }
    }

    // mcp_notify constructs against the inert Noop notifier and "delivers"
    // without erroring (no subscribers in a CLI context).
    #[tokio::test(flavor = "current_thread")]
    async fn mcp_notify_sink_constructs_and_fires() {
        let tmp = tempdir().unwrap();
        let g = opts(tmp.path().to_path_buf());
        let sc = sink("mcp", "mcp_notify");
        let res = fire_event_through_sink(&g, &sc, &[], synthetic_event()).await;
        assert!(res.is_ok(), "mcp_notify should fire: {res:?}");
    }

    // An http sink with no URL is a per-sink construction error (reported, not
    // a panic) — confirms errors surface as `Err(String)`.
    #[tokio::test(flavor = "current_thread")]
    async fn http_sink_without_url_reports_error() {
        let tmp = tempdir().unwrap();
        let g = opts(tmp.path().to_path_buf());
        let sc = sink("alerts", "http");
        let res = fire_event_through_sink(&g, &sc, &[], synthetic_event()).await;
        assert!(res.is_err());
        assert!(res.unwrap_err().contains("url"));
    }

    // Unsupported-but-config-valid kinds (snmp_trap/windows_event/remote_log)
    // are not handled by `build_sink`; the helper reports a per-sink error
    // rather than aborting.
    #[tokio::test(flavor = "current_thread")]
    async fn unsupported_kind_reports_error_not_panic() {
        let tmp = tempdir().unwrap();
        let g = opts(tmp.path().to_path_buf());
        for kind in ["snmp_trap", "windows_event", "remote_log"] {
            let sc = sink("x", kind);
            let res = fire_event_through_sink(&g, &sc, &[], synthetic_event()).await;
            assert!(res.is_err(), "{kind} should report an error");
        }
    }

    // A command sink without a matching allow-entry is a per-sink error.
    #[tokio::test(flavor = "current_thread")]
    async fn command_sink_without_entry_reports_error() {
        let tmp = tempdir().unwrap();
        let g = opts(tmp.path().to_path_buf());
        let sc = sink("notify", "command");
        let res = fire_event_through_sink(&g, &sc, &[], synthetic_event()).await;
        assert!(res.is_err());
    }

    // An email sink without `smtp` configured fails transport construction
    // (per-sink error), not a panic.
    #[tokio::test(flavor = "current_thread")]
    async fn email_sink_without_smtp_reports_error() {
        let tmp = tempdir().unwrap();
        let g = opts(tmp.path().to_path_buf());
        let mut sc = sink("ops", "email");
        sc.from = Some("spt@example.com".into());
        sc.to = Some(vec!["sre@example.com".into()]);
        let res = fire_event_through_sink(&g, &sc, &[], synthetic_event()).await;
        assert!(res.is_err());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn email_sink_with_smtp_pins_reports_error() {
        let tmp = tempdir().unwrap();
        let g = opts(tmp.path().to_path_buf());
        let mut sc = sink("ops", "email");
        sc.smtp = Some("smtp.example.com:587".into());
        sc.from = Some("spt@example.com".into());
        sc.to = Some(vec!["sre@example.com".into()]);
        sc.pin_spki_sha256 = vec!["SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into()];

        let err = fire_event_through_sink(&g, &sc, &[], synthetic_event())
            .await
            .unwrap_err();

        assert!(err.contains("SMTP pinning is not supported"), "{err}");
    }

    // `webpush` kind is normalised onto the push builder. Without
    // subscriptions/vapid it falls back to a generic push sink, which needs a
    // url — so this reports a clean error rather than the old "not yet wired".
    #[tokio::test(flavor = "current_thread")]
    async fn webpush_kind_is_normalised_to_push_builder() {
        let tmp = tempdir().unwrap();
        let g = opts(tmp.path().to_path_buf());
        let sc = sink("wp", "webpush");
        let res = fire_event_through_sink(&g, &sc, &[], synthetic_event()).await;
        // No url + no subscriptions => push builder reports missing url (NOT
        // the legacy "not yet wired" message).
        let err = res.unwrap_err();
        assert!(err.contains("url") || err.contains("vapid") || err.contains("push"));
    }
}
