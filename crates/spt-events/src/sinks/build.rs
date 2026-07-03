//! Config-driven sink construction.
//!
//! This module is the single ergonomic seam the runtime (spt-bin's
//! `cli_dispatch::build_event_sinks`) calls to turn a parsed
//! [`spt_config::schema::EventSink`] (any kind) + the `[[events.commands]]`
//! table into a live [`Sink`] trait object — **without** the historical
//! warn-and-skip for the secret/transport-heavy kinds.
//!
//! # What it covers
//!
//! | config `type`                | sink built              |
//! |------------------------------|-------------------------|
//! | `http` / `webhook_post`      | [`HttpSink`]            |
//! | `email`                      | [`EmailSink`]           |
//! | `sms`                        | [`SmsSink`]             |
//! | `push`                       | [`PushSink`] or [`WebPushSink`] (when `subscriptions` + VAPID present) |
//! | `mcp_notify`                 | [`McpNotifySink`]       |
//! | `command`                    | [`CommandSink`]         |
//! | `snmp_trap`                  | [`SnmpTrapSink`] (transport injected in Wave 5) |
//! | `windows_event`              | [`WindowsEventSink`] (`cfg(windows)` transport injected) |
//! | `remote_log`                 | [`HttpSink`] — explicit alias for an HTTP POST to a remote log collector (distinct from the `[logging]` remote sinks) |
//!
//! # Transport injection
//!
//! HTTPS-backed sinks (`http`/`webhook_post`/`sms`/`push`) share a single
//! [`HttpTransport`]; SMTP-backed `email` sinks share an [`EmailTransport`].
//! The caller supplies these through [`SinkDeps`] so that **unit tests can
//! pass `RecordingTransport`/`RecordingEmailTransport`** and no real network
//! or SMTP I/O happens during `cargo test`. The production wiring in spt-bin
//! supplies `reqwest`/`lettre` transports built with the per-sink pinned-TLS
//! parameters (mirroring the existing `http` construction path).
//!
//! # Secret resolution
//!
//! `auth` / `vapid_private_key` / per-subscription `auth` fields may be a
//! literal value **or** a `secret://ns/name` reference. [`resolve_secret`]
//! consults the supplied [`spt_secrets::Resolver`] (the same chain used by the
//! rest of the binary) when the string carries the `secret://` scheme,
//! otherwise it is treated as a literal — matching how the rest of the config
//! surface resolves secrets.
//!
//! # `mcp_notify` seam
//!
//! The `McpNotifier` implementation lives outside this crate (in spt-mcp /
//! spt-bin, to avoid a dependency cycle — see [`crate::mcp_notifier`]). The
//! caller therefore hands a ready `Arc<dyn McpNotifier>` in [`SinkDeps`]; this
//! module wires it into the [`McpNotifySink`]. To deliver real MCP
//! notifications (instead of the inert [`crate::NoopMcpNotifier`]) Wave-2
//! supplies the live notifier here.

use std::sync::Arc;
use std::time::Duration;

use secrecy::ExposeSecret;
use spt_config::schema::{EventCommand, EventSink};
use spt_secrets::{Resolver, SecretRef};

use crate::mcp_notifier::McpNotifier;
use crate::sinks::command::{CommandRunner, CommandSink};
use crate::sinks::email::{EmailSink, EmailTransport};
use crate::sinks::http::{HttpAuth, HttpSink, HttpTransport};
use crate::sinks::mcp_notify::McpNotifySink;
use crate::sinks::push::{PushSink, Subscription, VapidIdentity, WebPushSink};
use crate::sinks::sms::SmsSink;
use crate::sinks::snmp_trap::{SnmpTrapSink, SnmpTrapTransport};
use crate::sinks::windows_event::{WindowsEventSink, WindowsEventTransport};
use crate::sinks::{Sink, SinkError};

/// Default per-sink delivery timeout when the config omits `timeout`.
pub const DEFAULT_SINK_TIMEOUT: Duration = Duration::from_secs(10);
/// Default body template when a sink omits `body_template`.
pub const DEFAULT_BODY_TEMPLATE: &str = "{{event}}";

/// Transports + cross-crate dependencies that config-driven sinks need.
///
/// The caller constructs these once and reuses them for every sink so a
/// single pooled `reqwest`/`lettre`/MCP client backs the whole pipeline.
/// Fields are `Option` so a caller that only uses a subset of sink kinds need
/// not build transports it will never use — [`build_sink`] returns a
/// [`SinkError::Config`] if a sink kind is requested without its transport.
#[derive(Clone)]
pub struct SinkDeps {
    /// Shared HTTPS transport for `http`/`webhook_post`/`sms`/`push`.
    pub http: Option<Arc<dyn HttpTransport>>,
    /// Shared SMTP transport for `email`.
    pub email: Option<Arc<dyn EmailTransport>>,
    /// Child-process runner for `command` sinks.
    pub command: Option<Arc<dyn CommandRunner>>,
    /// MCP notifier for `mcp_notify` (real notifier or [`crate::NoopMcpNotifier`]).
    pub mcp: Option<Arc<dyn McpNotifier>>,
    /// SNMP trap sender for `snmp_trap` sinks. `None` until the Wave-5 SNMP
    /// integration supplies one — the sink is still built but WARNs.
    pub snmp_trap: Option<Arc<dyn SnmpTrapTransport>>,
    /// Windows Event Log writer for `windows_event` sinks. `None` on
    /// non-Windows targets / until wired — the sink is still built but WARNs.
    pub windows_event: Option<Arc<dyn WindowsEventTransport>>,
}

impl SinkDeps {
    /// Empty deps — every kind will fail with a `Config` error until the
    /// relevant transport is set. Useful as a builder base.
    #[must_use]
    pub fn none() -> Self {
        Self {
            http: None,
            email: None,
            command: None,
            mcp: None,
            snmp_trap: None,
            windows_event: None,
        }
    }

    /// Set the HTTPS transport (chainable).
    #[must_use]
    pub fn with_http(mut self, t: Arc<dyn HttpTransport>) -> Self {
        self.http = Some(t);
        self
    }

    /// Set the SMTP transport (chainable).
    #[must_use]
    pub fn with_email(mut self, t: Arc<dyn EmailTransport>) -> Self {
        self.email = Some(t);
        self
    }

    /// Set the command runner (chainable).
    #[must_use]
    pub fn with_command(mut self, r: Arc<dyn CommandRunner>) -> Self {
        self.command = Some(r);
        self
    }

    /// Set the MCP notifier (chainable).
    #[must_use]
    pub fn with_mcp(mut self, n: Arc<dyn McpNotifier>) -> Self {
        self.mcp = Some(n);
        self
    }

    /// Set the SNMP trap sender (chainable).
    #[must_use]
    pub fn with_snmp_trap(mut self, t: Arc<dyn SnmpTrapTransport>) -> Self {
        self.snmp_trap = Some(t);
        self
    }

    /// Set the Windows Event Log writer (chainable).
    #[must_use]
    pub fn with_windows_event(mut self, t: Arc<dyn WindowsEventTransport>) -> Self {
        self.windows_event = Some(t);
        self
    }
}

/// Resolve a config string that is **either** a literal value **or** a
/// `secret://ns/name` reference. References are resolved through the supplied
/// [`Resolver`] (the same chain the rest of the binary uses); anything that
/// does not carry the `secret://` scheme is returned verbatim.
///
/// Returns [`SinkError::Config`] when a reference is malformed or the resolver
/// cannot find it (so a typo'd `secret://` surfaces loudly rather than being
/// silently treated as a literal credential).
pub fn resolve_secret(value: &str, resolver: &Resolver) -> Result<String, SinkError> {
    if let Some(stripped) = value.strip_prefix("secret://") {
        let _ = stripped; // scheme detection only; full parse below
        let r: SecretRef = value
            .parse()
            .map_err(|e| SinkError::Config(format!("secret ref `{value}`: {e}")))?;
        let bytes = resolver
            .resolve(&r)
            .map_err(|e| SinkError::Config(format!("resolve {value}: {e}")))?;
        let s = std::str::from_utf8(bytes.expose_secret())
            .map_err(|e| SinkError::Config(format!("secret {value} not utf-8: {e}")))?;
        Ok(s.to_string())
    } else {
        Ok(value.to_string())
    }
}

/// Resolve the optional `auth` field into an [`HttpAuth`].
///
/// The (possibly secret-referencing) string is the bearer token. A value of
/// the form `basic:<base64>` selects [`HttpAuth::Basic`]; otherwise the
/// resolved value is used as a [`HttpAuth::Bearer`] token. `None` ⇒
/// [`HttpAuth::None`].
fn resolve_http_auth(auth: Option<&String>, resolver: &Resolver) -> Result<HttpAuth, SinkError> {
    match auth {
        None => Ok(HttpAuth::None),
        Some(raw) => {
            let resolved = resolve_secret(raw, resolver)?;
            if let Some(b64) = resolved.strip_prefix("basic:") {
                Ok(HttpAuth::Basic(b64.to_string()))
            } else {
                Ok(HttpAuth::Bearer(resolved))
            }
        }
    }
}

fn sink_timeout(sink: &EventSink) -> Duration {
    sink.timeout
        .as_deref()
        .and_then(|d| spt_core::duration::parse_duration(d).ok())
        .unwrap_or(DEFAULT_SINK_TIMEOUT)
}

fn body_template(sink: &EventSink) -> String {
    sink.body_template
        .clone()
        .unwrap_or_else(|| DEFAULT_BODY_TEMPLATE.to_string())
}

/// Build one [`Sink`] from a config [`EventSink`] (any kind) + the
/// `[[events.commands]]` table.
///
/// This is the single entry point the Wave-2 integrator calls in place of the
/// per-kind `match` with its warn-and-skip arm. Transports and the MCP
/// notifier are injected via [`SinkDeps`]; secrets are resolved through
/// `resolver`.
///
/// # Errors
///
/// Returns [`SinkError::Config`] when the sink is misconfigured (missing url,
/// unknown kind, unresolvable secret, missing required transport for the
/// kind, or a `command` sink referencing an absent/`allow_exec=false` command
/// entry).
pub fn build_sink(
    sink: &EventSink,
    commands: &[EventCommand],
    deps: &SinkDeps,
    resolver: &Resolver,
) -> Result<Box<dyn Sink>, SinkError> {
    match sink.kind.as_str() {
        // `remote_log` is an explicit alias for an HTTP POST to a remote log
        // collector — distinct from the `[logging]` remote sinks (which live in
        // spt-observability). Wiring it to the HTTP sink makes a configured
        // `remote_log` deliver rather than validate-clean-then-drop.
        "http" | "webhook_post" | "remote_log" => build_http(sink, deps, resolver),
        "email" => build_email(sink, deps, resolver),
        "sms" => build_sms(sink, deps, resolver),
        // `push` auto-detects the WebPush flavour when `subscriptions` + a VAPID
        // key are present; `webpush` is accepted by the validator (validate.rs)
        // as an explicit kind, so route it here too rather than
        // validate-clean-then-drop.
        "push" | "webpush" => build_push(sink, deps, resolver),
        "mcp_notify" => build_mcp_notify(sink, deps),
        "command" => build_command(sink, commands, deps),
        "snmp_trap" => Ok(build_snmp_trap(sink, deps)),
        "windows_event" => Ok(build_windows_event(sink, deps)),
        other => Err(SinkError::Config(format!(
            "unsupported event sink kind `{other}` for sink `{}`",
            sink.name
        ))),
    }
}

fn http_transport(deps: &SinkDeps, kind: &str) -> Result<Arc<dyn HttpTransport>, SinkError> {
    deps.http
        .clone()
        .ok_or_else(|| SinkError::Config(format!("{kind} sink requires an http transport")))
}

fn build_http(
    sink: &EventSink,
    deps: &SinkDeps,
    resolver: &Resolver,
) -> Result<Box<dyn Sink>, SinkError> {
    let url = sink
        .url
        .clone()
        .or_else(|| sink.endpoint.clone())
        .ok_or_else(|| {
            SinkError::Config(format!("sink `{}` (http) has no url/endpoint", sink.name))
        })?;
    let transport = http_transport(deps, "http")?;
    let method = sink.method.clone().unwrap_or_else(|| "POST".into());
    let content_type = sink
        .content_type
        .clone()
        .unwrap_or_else(|| "application/json".into());
    let auth = resolve_http_auth(sink.auth.as_ref(), resolver)?;
    Ok(Box::new(HttpSink::new(
        sink.name.clone(),
        method,
        url,
        body_template(sink),
        content_type,
        auth,
        transport,
    )))
}

fn build_email(
    sink: &EventSink,
    deps: &SinkDeps,
    resolver: &Resolver,
) -> Result<Box<dyn Sink>, SinkError> {
    let transport = deps
        .email
        .clone()
        .ok_or_else(|| SinkError::Config("email sink requires an smtp transport".into()))?;
    let from = sink
        .from
        .clone()
        .ok_or_else(|| SinkError::Config(format!("email sink `{}` has no `from`", sink.name)))?;
    let to = sink.to.clone().filter(|t| !t.is_empty()).ok_or_else(|| {
        SinkError::Config(format!("email sink `{}` has no recipients", sink.name))
    })?;
    // `auth` is resolved (and validated) here even though SMTP credentials are
    // applied when the caller builds the transport — this surfaces a bad
    // secret reference at construction time rather than first-send time.
    if let Some(a) = sink.auth.as_ref() {
        let _ = resolve_secret(a, resolver)?;
    }
    let subject = crate::sinks::email::resolve_subject_template(sink.subject_template.clone());
    Ok(Box::new(EmailSink::new(
        sink.name.clone(),
        from,
        to,
        subject,
        body_template(sink),
        transport,
    )))
}

fn build_sms(
    sink: &EventSink,
    deps: &SinkDeps,
    resolver: &Resolver,
) -> Result<Box<dyn Sink>, SinkError> {
    let url = sink
        .url
        .clone()
        .or_else(|| sink.endpoint.clone())
        .ok_or_else(|| {
            SinkError::Config(format!("sms sink `{}` has no url/endpoint", sink.name))
        })?;
    let transport = http_transport(deps, "sms")?;
    let provider = sink.provider.clone().unwrap_or_default();
    let auth = resolve_http_auth(sink.auth.as_ref(), resolver)?;
    Ok(Box::new(SmsSink::new(
        sink.name.clone(),
        provider,
        url,
        body_template(sink),
        auth,
        transport,
    )))
}

fn build_push(
    sink: &EventSink,
    deps: &SinkDeps,
    resolver: &Resolver,
) -> Result<Box<dyn Sink>, SinkError> {
    let transport = http_transport(deps, "push")?;
    // WebPush flavour when subscriptions + a VAPID key are supplied; otherwise
    // the generic JSON-POST PushSink.
    let subs = sink.subscriptions.clone().unwrap_or_default();
    let has_webpush = !subs.is_empty() && sink.vapid_private_key.is_some();
    if has_webpush {
        let vapid_key_raw = sink
            .vapid_private_key
            .as_ref()
            .map(|k| k.expose().to_string())
            .expect("checked above");
        let vapid_key = resolve_secret(&vapid_key_raw, resolver)?;
        let subject = sink.vapid_subject.clone().ok_or_else(|| {
            SinkError::Config(format!(
                "push sink `{}` (webpush) has no vapid_subject",
                sink.name
            ))
        })?;
        let vapid = VapidIdentity::from_base64url(&vapid_key, subject)
            .map_err(|e| SinkError::Config(format!("push sink `{}` vapid: {e}", sink.name)))?;
        let subscriptions: Vec<Subscription> = subs
            .iter()
            .map(|s| Subscription {
                endpoint: s.endpoint.clone(),
                p256dh_key: s.p256dh.clone(),
                auth_secret: s.auth.expose().to_string(),
            })
            .collect();
        Ok(Box::new(WebPushSink::new(
            sink.name.clone(),
            body_template(sink),
            subscriptions,
            vapid,
            transport,
        )))
    } else {
        let url = sink
            .url
            .clone()
            .or_else(|| sink.endpoint.clone())
            .ok_or_else(|| {
                SinkError::Config(format!("push sink `{}` has no url/endpoint", sink.name))
            })?;
        let auth = resolve_http_auth(sink.auth.as_ref(), resolver)?;
        Ok(Box::new(PushSink::new(
            sink.name.clone(),
            url,
            body_template(sink),
            auth,
            transport,
        )))
    }
}

fn build_snmp_trap(sink: &EventSink, deps: &SinkDeps) -> Box<dyn Sink> {
    // Trap target is the sink url/endpoint (`host:port`); may be empty until a
    // real transport (Wave 5) validates it. The sink WARNs at construction if
    // no transport is injected — never a silent drop.
    let target = sink
        .url
        .clone()
        .or_else(|| sink.endpoint.clone())
        .unwrap_or_default();
    Box::new(SnmpTrapSink::new(
        sink.name.clone(),
        target,
        body_template(sink),
        deps.snmp_trap.clone(),
    ))
}

fn build_windows_event(sink: &EventSink, deps: &SinkDeps) -> Box<dyn Sink> {
    // Event Log source name: the sink `provider`, else the sink name.
    let source = sink.provider.clone().unwrap_or_else(|| sink.name.clone());
    Box::new(WindowsEventSink::new(
        sink.name.clone(),
        source,
        body_template(sink),
        deps.windows_event.clone(),
    ))
}

fn build_mcp_notify(sink: &EventSink, deps: &SinkDeps) -> Result<Box<dyn Sink>, SinkError> {
    let notifier = deps
        .mcp
        .clone()
        .ok_or_else(|| SinkError::Config("mcp_notify sink requires an McpNotifier".into()))?;
    Ok(Box::new(McpNotifySink::new(sink.name.clone(), notifier)))
}

fn build_command(
    sink: &EventSink,
    commands: &[EventCommand],
    deps: &SinkDeps,
) -> Result<Box<dyn Sink>, SinkError> {
    let runner = deps
        .command
        .clone()
        .ok_or_else(|| SinkError::Config("command sink requires a CommandRunner".into()))?;
    // A `command` sink is wired to the `[[events.commands]]` entry whose
    // `name` matches the sink name. The entry MUST opt in with
    // `allow_exec = true` (spec §9.7) before we register the sink.
    let cmd = commands
        .iter()
        .find(|c| c.name == sink.name)
        .ok_or_else(|| {
            SinkError::Config(format!(
                "command sink `{}` has no matching [[events.commands]] entry",
                sink.name
            ))
        })?;
    if !cmd.allow_exec.unwrap_or(false) {
        return Err(SinkError::Config(format!(
            "command sink `{}` is not enabled (set allow_exec = true)",
            sink.name
        )));
    }
    let timeout = cmd
        .timeout
        .as_deref()
        .and_then(|d| spt_core::duration::parse_duration(d).ok())
        .unwrap_or_else(|| sink_timeout(sink));
    Ok(Box::new(CommandSink::new(
        sink.name.clone(),
        std::path::PathBuf::from(&cmd.command),
        cmd.args.clone().unwrap_or_default(),
        timeout,
        runner,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mcp_notifier::NoopMcpNotifier;
    use crate::sinks::command::RecordingRunner;
    use crate::sinks::email::RecordingEmailTransport;
    use crate::sinks::http::RecordingTransport;
    use spt_config::schema::{EventCommand, EventSinkSubscription};
    use spt_core::redacted_string::RedactedString;
    use spt_secrets::backend::secret_bytes;
    use spt_secrets::backend::{BackendDoctor, BackendKind, SecretBackend, SecretBytes};
    use spt_secrets::reference::SecretRef as Ref;

    // --- a minimal in-memory secret backend for resolver tests -----------
    struct MemBackend(parking_lot::Mutex<std::collections::HashMap<String, Vec<u8>>>);
    impl MemBackend {
        fn with(r: &Ref, v: &[u8]) -> Self {
            let mut m = std::collections::HashMap::new();
            m.insert(r.to_string(), v.to_vec());
            Self(parking_lot::Mutex::new(m))
        }
    }
    impl SecretBackend for MemBackend {
        fn kind(&self) -> BackendKind {
            BackendKind::Env
        }
        fn get(&self, r: &Ref) -> spt_core::Result<Option<SecretBytes>> {
            Ok(self.0.lock().get(&r.to_string()).cloned().map(secret_bytes))
        }
        fn set(&self, _r: &Ref, _v: &[u8]) -> spt_core::Result<()> {
            Ok(())
        }
        fn list(&self) -> spt_core::Result<Vec<Ref>> {
            Ok(Vec::new())
        }
        fn remove(&self, _r: &Ref) -> spt_core::Result<bool> {
            Ok(false)
        }
        fn doctor(&self) -> BackendDoctor {
            BackendDoctor::ok(self.kind(), "mem")
        }
    }

    fn empty_resolver() -> Resolver {
        Resolver::new(vec![])
    }

    fn sink(name: &str, kind: &str) -> EventSink {
        EventSink {
            name: name.into(),
            kind: kind.into(),
            ..Default::default()
        }
    }

    fn full_deps() -> SinkDeps {
        use crate::sinks::snmp_trap::RecordingSnmpTrapTransport;
        use crate::sinks::windows_event::RecordingWindowsEventTransport;
        SinkDeps::none()
            .with_http(Arc::new(RecordingTransport::new()))
            .with_email(Arc::new(RecordingEmailTransport::new()))
            .with_command(Arc::new(RecordingRunner::new()))
            .with_mcp(Arc::new(NoopMcpNotifier))
            .with_snmp_trap(Arc::new(RecordingSnmpTrapTransport::new()))
            .with_windows_event(Arc::new(RecordingWindowsEventTransport::new()))
    }

    #[test]
    fn build_http_sink_from_config() {
        let mut sc = sink("alerts", "http");
        sc.url = Some("https://example.com/hook".into());
        let s = build_sink(&sc, &[], &full_deps(), &empty_resolver()).unwrap();
        assert_eq!(s.name(), "alerts");
        assert_eq!(s.kind(), "http");
    }

    #[test]
    fn build_webhook_post_alias() {
        let mut sc = sink("wh", "webhook_post");
        sc.endpoint = Some("https://example.com/wh".into());
        let s = build_sink(&sc, &[], &full_deps(), &empty_resolver()).unwrap();
        assert_eq!(s.kind(), "http");
    }

    #[test]
    fn build_email_sink_from_config() {
        let mut sc = sink("ops", "email");
        sc.from = Some("spt@example.com".into());
        sc.to = Some(vec!["sre@example.com".into()]);
        let s = build_sink(&sc, &[], &full_deps(), &empty_resolver()).unwrap();
        assert_eq!(s.kind(), "email");
    }

    #[test]
    fn build_sms_sink_from_config() {
        let mut sc = sink("oncall", "sms");
        sc.url = Some("https://api.twilio.com/Messages".into());
        sc.provider = Some("twilio".into());
        let s = build_sink(&sc, &[], &full_deps(), &empty_resolver()).unwrap();
        assert_eq!(s.kind(), "sms");
    }

    #[test]
    fn build_generic_push_sink_from_config() {
        let mut sc = sink("mobile", "push");
        sc.url = Some("https://push.example.com/send".into());
        let s = build_sink(&sc, &[], &full_deps(), &empty_resolver()).unwrap();
        assert_eq!(s.kind(), "push");
    }

    #[test]
    fn build_webpush_sink_when_subscriptions_and_vapid_present() {
        use base64ct::{Base64UrlUnpadded, Encoding};
        use web_push_native::jwt_simple::algorithms::ES256KeyPair;
        let kp = ES256KeyPair::generate();
        let vapid_b64 = Base64UrlUnpadded::encode_string(&kp.to_bytes());

        let mut sc = sink("mobile", "push");
        sc.vapid_private_key = Some(RedactedString::new(vapid_b64));
        sc.vapid_subject = Some("mailto:ops@example.com".into());
        sc.subscriptions = Some(vec![EventSinkSubscription {
            endpoint: "https://push.example.com/abc".into(),
            p256dh: Base64UrlUnpadded::encode_string(&[4u8; 65]),
            auth: RedactedString::new(Base64UrlUnpadded::encode_string(&[0u8; 16])),
        }]);
        let s = build_sink(&sc, &[], &full_deps(), &empty_resolver()).unwrap();
        assert_eq!(s.kind(), "webpush");
    }

    #[test]
    fn build_webpush_kind_routes_to_push_builder() {
        // `type = "webpush"` is accepted by the validator; the factory must
        // build it (as a generic PushSink here, since no subscriptions/VAPID are
        // supplied) rather than validate-clean-then-drop.
        let mut sc = sink("mobile", "webpush");
        sc.url = Some("https://push.example.com/send".into());
        let s = build_sink(&sc, &[], &full_deps(), &empty_resolver()).unwrap();
        assert_eq!(s.kind(), "push");
    }

    #[test]
    fn build_mcp_notify_sink_from_config() {
        let sc = sink("mcp", "mcp_notify");
        let s = build_sink(&sc, &[], &full_deps(), &empty_resolver()).unwrap();
        assert_eq!(s.kind(), "mcp_notify");
    }

    #[test]
    fn build_command_sink_from_config() {
        let sc = sink("notify", "command");
        let cmds = vec![EventCommand {
            name: "notify".into(),
            command: "/usr/local/bin/notify".into(),
            args: Some(vec!["--kind".into(), "{{kind}}".into()]),
            allow_exec: Some(true),
            timeout: Some("5s".into()),
        }];
        let s = build_sink(&sc, &cmds, &full_deps(), &empty_resolver()).unwrap();
        assert_eq!(s.kind(), "command");
        assert_eq!(s.name(), "notify");
    }

    #[test]
    fn command_sink_without_allow_exec_is_config_error() {
        let sc = sink("notify", "command");
        let cmds = vec![EventCommand {
            name: "notify".into(),
            command: "/bin/true".into(),
            allow_exec: Some(false),
            ..Default::default()
        }];
        assert!(matches!(
            build_sink(&sc, &cmds, &full_deps(), &empty_resolver()),
            Err(SinkError::Config(_))
        ));
    }

    #[test]
    fn command_sink_without_matching_entry_is_config_error() {
        let sc = sink("notify", "command");
        assert!(matches!(
            build_sink(&sc, &[], &full_deps(), &empty_resolver()),
            Err(SinkError::Config(_))
        ));
    }

    // ---- W4-1: snmp_trap / windows_event / remote_log now build --------

    #[test]
    fn build_snmp_trap_sink_from_config() {
        let mut sc = sink("traps", "snmp_trap");
        sc.url = Some("10.0.0.1:162".into());
        let s = build_sink(&sc, &[], &full_deps(), &empty_resolver()).unwrap();
        assert_eq!(s.kind(), "snmp_trap");
        assert_eq!(s.name(), "traps");
    }

    #[test]
    fn build_snmp_trap_without_transport_still_builds_not_dropped() {
        // No trap transport (Wave-5 not yet wired): the sink must still be
        // built (WARN at construction), never silently skipped.
        let mut sc = sink("traps", "snmp_trap");
        sc.url = Some("10.0.0.1:162".into());
        let deps = SinkDeps::none().with_http(Arc::new(RecordingTransport::new()));
        let s = build_sink(&sc, &[], &deps, &empty_resolver()).unwrap();
        assert_eq!(s.kind(), "snmp_trap");
    }

    #[test]
    fn build_windows_event_sink_from_config() {
        let mut sc = sink("eventlog", "windows_event");
        sc.provider = Some("spt".into());
        let s = build_sink(&sc, &[], &full_deps(), &empty_resolver()).unwrap();
        assert_eq!(s.kind(), "windows_event");
    }

    #[test]
    fn build_remote_log_sink_is_http_alias() {
        // `remote_log` wires to an HTTP POST (explicit alias) rather than
        // validating-clean-then-dropping.
        let mut sc = sink("collector", "remote_log");
        sc.url = Some("https://logs.example.com/ingest".into());
        let s = build_sink(&sc, &[], &full_deps(), &empty_resolver()).unwrap();
        assert_eq!(s.kind(), "http");
        assert_eq!(s.name(), "collector");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn built_snmp_trap_sink_delivers_through_injected_transport() {
        use crate::event::{Event, Severity};
        use crate::sinks::snmp_trap::RecordingSnmpTrapTransport;
        let t = Arc::new(RecordingSnmpTrapTransport::new());
        let deps = SinkDeps::none().with_snmp_trap(t.clone());
        let mut sc = sink("traps", "snmp_trap");
        sc.url = Some("10.0.0.1:162".into());
        sc.body_template = Some("{{kind}}".into());
        let s = build_sink(&sc, &[], &deps, &empty_resolver()).unwrap();
        s.deliver(Arc::new(
            Event::builder("profile.failed", Severity::Error).build(),
        ))
        .await
        .unwrap();
        let traps = t.traps();
        assert_eq!(traps.len(), 1);
        assert!(traps[0].message.contains("profile.failed"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn built_windows_event_sink_delivers_through_injected_transport() {
        use crate::event::{Event, Severity};
        use crate::sinks::windows_event::RecordingWindowsEventTransport;
        let t = Arc::new(RecordingWindowsEventTransport::new());
        let deps = SinkDeps::none().with_windows_event(t.clone());
        let mut sc = sink("eventlog", "windows_event");
        sc.body_template = Some("{{kind}}".into());
        let s = build_sink(&sc, &[], &deps, &empty_resolver()).unwrap();
        s.deliver(Arc::new(
            Event::builder("profile.failed", Severity::Error).build(),
        ))
        .await
        .unwrap();
        assert_eq!(t.records().len(), 1);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn built_remote_log_sink_delivers_through_http_transport() {
        use crate::event::{Event, Severity};
        let t = Arc::new(RecordingTransport::new());
        let deps = SinkDeps::none().with_http(t.clone());
        let mut sc = sink("collector", "remote_log");
        sc.url = Some("https://logs.example.com/ingest".into());
        sc.body_template = Some(r#"{"k":"{{kind}}"}"#.into());
        let s = build_sink(&sc, &[], &deps, &empty_resolver()).unwrap();
        s.deliver(Arc::new(
            Event::builder("profile.failed", Severity::Error).build(),
        ))
        .await
        .unwrap();
        let reqs = t.requests();
        assert_eq!(reqs.len(), 1);
        assert!(std::str::from_utf8(&reqs[0].body)
            .unwrap()
            .contains("profile.failed"));
    }

    #[test]
    fn unknown_kind_is_config_error() {
        let sc = sink("x", "carrier-pigeon");
        assert!(matches!(
            build_sink(&sc, &[], &full_deps(), &empty_resolver()),
            Err(SinkError::Config(_))
        ));
    }

    #[test]
    fn missing_transport_is_config_error() {
        let mut sc = sink("alerts", "http");
        sc.url = Some("https://x/".into());
        assert!(matches!(
            build_sink(&sc, &[], &SinkDeps::none(), &empty_resolver()),
            Err(SinkError::Config(_))
        ));
    }

    #[test]
    fn http_sink_without_url_is_config_error() {
        let sc = sink("alerts", "http");
        assert!(matches!(
            build_sink(&sc, &[], &full_deps(), &empty_resolver()),
            Err(SinkError::Config(_))
        ));
    }

    #[test]
    fn resolve_secret_passes_through_literal() {
        let r = empty_resolver();
        assert_eq!(resolve_secret("plain-token", &r).unwrap(), "plain-token");
    }

    #[test]
    fn resolve_secret_resolves_reference() {
        let rref = Ref::new("events", "token").unwrap();
        let resolver = Resolver::new(vec![Arc::new(MemBackend::with(&rref, b"sekret"))]);
        let got = resolve_secret("secret://events/token", &resolver).unwrap();
        assert_eq!(got, "sekret");
    }

    #[test]
    fn resolve_secret_missing_reference_is_config_error() {
        let resolver = empty_resolver();
        let err = resolve_secret("secret://events/absent", &resolver).unwrap_err();
        assert!(matches!(err, SinkError::Config(_)));
    }

    #[test]
    fn http_auth_secret_reference_is_resolved_to_bearer() {
        let rref = Ref::new("events", "bearer").unwrap();
        let resolver = Resolver::new(vec![Arc::new(MemBackend::with(&rref, b"abc123"))]);
        let mut sc = sink("alerts", "http");
        sc.url = Some("https://x/".into());
        sc.auth = Some("secret://events/bearer".into());
        // Build should succeed (auth resolved without error).
        let s = build_sink(&sc, &[], &full_deps(), &resolver).unwrap();
        assert_eq!(s.kind(), "http");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn built_http_sink_delivers_through_injected_transport() {
        use crate::event::{Event, Severity};
        let transport = Arc::new(RecordingTransport::new());
        let deps = SinkDeps::none().with_http(transport.clone());
        let mut sc = sink("alerts", "http");
        sc.url = Some("https://example.com/hook".into());
        sc.body_template = Some(r#"{"k":"{{kind}}"}"#.into());
        let s = build_sink(&sc, &[], &deps, &empty_resolver()).unwrap();
        let ev = Event::builder("profile.failed", Severity::Error).build();
        s.deliver(Arc::new(ev)).await.unwrap();
        let reqs = transport.requests();
        assert_eq!(reqs.len(), 1);
        assert!(std::str::from_utf8(&reqs[0].body)
            .unwrap()
            .contains("profile.failed"));
    }
}
