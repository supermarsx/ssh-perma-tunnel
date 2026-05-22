//! Audit-event bridges that forward crate-local audit hooks into the
//! workspace [`spt_core::audit`] sink (t7-B1).
//!
//! Three crate-local hook traits exist in the workspace:
//!
//! * [`spt_obfs::AuditHook`] — fires once per `ObfsTransport::connect`
//!   with the transport name + target.
//! * [`spt_auth_sspi::AuditHook`] — fires per GSSAPI / SSPI token
//!   exchange, MIC issuance, and MIC verification.
//! * [`spt_scripting::AuditSink`] — fires once per script load (with the
//!   SHA-256 of the source bytes) and once per hook invocation (with the
//!   wall-clock duration + outcome).
//!
//! Each subsystem keeps its hook surface in its own crate so the trait
//! shape can evolve without dragging the workspace [`spt_core::audit`]
//! taxonomy through every change. This module owns the bridges that
//! translate from each crate-local hook into the canonical
//! [`spt_core::audit::AuditEvent`] schema and dispatch through
//! [`spt_core::audit::record_audit`] — the single seam wired to the
//! operator log / event bus at startup.
//!
//! ## Event kinds emitted
//!
//! | Kind                                  | Source crate           | Fields                                     |
//! |---------------------------------------|------------------------|--------------------------------------------|
//! | `audit.obfs.connect`                  | `spt-obfs`             | `transport`, `target`                      |
//! | `audit.auth.gssapi.token_exchange`    | `spt-auth-sspi`        | `package`, `round`, `complete`             |
//! | `audit.auth.gssapi.mic_issued`        | `spt-auth-sspi`        | `package`, `mic_len`                       |
//! | `audit.auth.gssapi.mic_verified`      | `spt-auth-sspi`        | `package`, `ok`                            |
//! | `audit.script.loaded`                 | `spt-scripting`        | `path`, `sha256`                           |
//! | `audit.script.invoked`                | `spt-scripting`        | `hook`, `duration_us`, `outcome`           |
//! | `audit.sftp.umount`                   | `spt-bin::cli::sftp_ops` | `mountpoint`, `reason`                   |
//!
//! All fields are stringified — [`spt_core::audit::AuditEvent::fields`]
//! is keyed by `String → String` by contract. Booleans serialise as
//! `"true"`/`"false"`, integers via `Display`.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use spt_core::audit::{record_audit, AuditEvent, AuditSeverity};

/// Bridge from [`spt_obfs::AuditHook`] to the workspace audit sink.
///
/// Constructed by the supervisor build path and threaded into
/// [`spt_obfs::transport_for_with_audit`] (or its consumers in
/// `spt-ssh2`) so every obfuscated-connect attempt lands in
/// `audit.obfs.connect` with the canonical transport name + target.
#[derive(Debug, Default, Clone, Copy)]
pub struct ObfsAuditBridge;

impl ObfsAuditBridge {
    /// Construct the bridge.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Convenience: build an `Arc<dyn spt_obfs::AuditHook>` ready for
    /// `transport_for_with_audit`.
    #[must_use]
    pub fn arc() -> Arc<dyn spt_obfs::AuditHook> {
        Arc::new(Self)
    }
}

impl spt_obfs::AuditHook for ObfsAuditBridge {
    fn on_connect(&self, transport: &'static str, target: &str) {
        record_audit(
            AuditEvent::new("audit.obfs.connect", AuditSeverity::Info)
                .with_field("transport", transport)
                .with_field("target", target),
        );
    }
}

/// Bridge from [`spt_auth_sspi::AuditHook`] to the workspace audit sink.
///
/// Constructed by `profile_factory::build_sspi_audit_bridge` and
/// installed into [`spt_auth_sspi::GssApiConfig::audit_hook`] /
/// [`spt_auth_sspi::SspiConfig::audit_hook`] so every token round-trip
/// and MIC issue/verify lands in the audit trail.
#[derive(Debug, Default, Clone, Copy)]
pub struct GssapiAuditBridge;

impl GssapiAuditBridge {
    /// Construct the bridge.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Convenience: build an `Arc<dyn spt_auth_sspi::AuditHook>`.
    #[must_use]
    pub fn arc() -> Arc<dyn spt_auth_sspi::AuditHook> {
        Arc::new(Self)
    }
}

impl spt_auth_sspi::AuditHook for GssapiAuditBridge {
    fn on_event(&self, event: &spt_auth_sspi::AuditEvent) {
        match event {
            spt_auth_sspi::AuditEvent::TokenExchange {
                package,
                round,
                complete,
            } => {
                record_audit(
                    AuditEvent::new("audit.auth.gssapi.token_exchange", AuditSeverity::Info)
                        .with_field("package", *package)
                        .with_field("round", round.to_string())
                        .with_field("complete", bool_str(*complete)),
                );
            }
            spt_auth_sspi::AuditEvent::MicIssued { package, mic_len } => {
                record_audit(
                    AuditEvent::new("audit.auth.gssapi.mic_issued", AuditSeverity::Info)
                        .with_field("package", *package)
                        .with_field("mic_len", mic_len.to_string()),
                );
            }
            spt_auth_sspi::AuditEvent::MicVerified { package, ok } => {
                // Verify failure is operator-visible elevated risk.
                let severity = if *ok {
                    AuditSeverity::Info
                } else {
                    AuditSeverity::Warning
                };
                record_audit(
                    AuditEvent::new("audit.auth.gssapi.mic_verified", severity)
                        .with_field("package", *package)
                        .with_field("ok", bool_str(*ok)),
                );
            }
        }
    }
}

/// Bridge from [`spt_scripting::AuditSink`] to the workspace audit
/// sink.
///
/// Wired by `profile_factory::build_script_engine` so every script
/// load (with the SHA-256 of the source) and every hook invocation
/// (with duration + outcome) lands in the audit trail.
#[derive(Debug, Default, Clone, Copy)]
pub struct ScriptAuditBridge;

impl ScriptAuditBridge {
    /// Construct the bridge.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Convenience: build an `Arc<dyn spt_scripting::AuditSink>`.
    #[must_use]
    pub fn arc() -> Arc<dyn spt_scripting::AuditSink> {
        Arc::new(Self)
    }
}

impl spt_scripting::AuditSink for ScriptAuditBridge {
    fn on_loaded(&self, path: &Path, sha256: &[u8; 32]) {
        record_audit(
            AuditEvent::new("audit.script.loaded", AuditSeverity::Info)
                .with_field("path", path.display().to_string())
                .with_field("sha256", hex_lower(sha256)),
        );
    }

    fn on_invoked(
        &self,
        hook: spt_scripting::HookName,
        duration: Duration,
        outcome: spt_scripting::HookOutcome,
    ) {
        let severity = match outcome {
            spt_scripting::HookOutcome::Err => AuditSeverity::Warning,
            _ => AuditSeverity::Info,
        };
        record_audit(
            AuditEvent::new("audit.script.invoked", severity)
                .with_field("hook", hook.as_str())
                .with_field(
                    "duration_us",
                    u64::try_from(duration.as_micros())
                        .unwrap_or(u64::MAX)
                        .to_string(),
                )
                .with_field("outcome", outcome.as_str()),
        );
    }
}

/// Emit a single `audit.sftp.umount` event. The `reason` field is one
/// of the documented enum strings (`"operator_request"`,
/// `"shutdown"`); the [`spt_bin::cli::sftp_ops::mount_stop`] CLI path
/// calls this with `"operator_request"`.
pub fn emit_sftp_umount(mountpoint: &Path, reason: &str) {
    record_audit(
        AuditEvent::new("audit.sftp.umount", AuditSeverity::Info)
            .with_field("mountpoint", mountpoint.display().to_string())
            .with_field("reason", reason),
    );
}

fn bool_str(b: bool) -> &'static str {
    if b {
        "true"
    } else {
        "false"
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut s, "{b:02x}");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    use spt_core::audit::{
        clear_audit_sink_for_test, register_audit_sink, AuditEvent as CoreEvent,
        AuditSink as CoreAuditSink,
    };

    // The global audit sink slot is process-wide; serialise every test
    // in this module via a guard so concurrent ones don't fight.
    fn test_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: Mutex<()> = Mutex::new(());
        match LOCK.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        }
    }

    #[derive(Default, Debug)]
    struct MockSink {
        events: Mutex<Vec<CoreEvent>>,
    }

    impl CoreAuditSink for MockSink {
        fn record(&self, ev: CoreEvent) {
            self.events.lock().unwrap().push(ev);
        }
    }

    impl MockSink {
        fn events(&self) -> Vec<CoreEvent> {
            self.events.lock().unwrap().clone()
        }
    }

    fn install_mock_sink() -> Arc<MockSink> {
        clear_audit_sink_for_test();
        let sink = Arc::new(MockSink::default());
        register_audit_sink(sink.clone());
        sink
    }

    /// `mount_stop`-style `emit_sftp_umount` records the canonical
    /// kind and fields. Tracks Bwire follow-up #3.
    #[test]
    fn sftp_mount_stopped_event_fired() {
        let _g = test_lock();
        let sink = install_mock_sink();
        emit_sftp_umount(Path::new("/mnt/data"), "operator_request");
        let evs = sink.events();
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0].kind, "audit.sftp.umount");
        assert_eq!(
            evs[0].fields.get("mountpoint").map(String::as_str),
            Some("/mnt/data")
        );
        assert_eq!(
            evs[0].fields.get("reason").map(String::as_str),
            Some("operator_request")
        );
        clear_audit_sink_for_test();
    }

    /// `ScriptAuditBridge::on_loaded` records `audit.script.loaded`
    /// with the SHA-256 as a 64-char hex string.
    #[test]
    fn script_loaded_event_includes_hash() {
        use spt_scripting::AuditSink as _;
        let _g = test_lock();
        let sink = install_mock_sink();
        let bridge = ScriptAuditBridge::new();
        let sha: [u8; 32] = [0xab; 32];
        bridge.on_loaded(Path::new("/tmp/h.rhai"), &sha);
        let evs = sink.events();
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0].kind, "audit.script.loaded");
        let hex = evs[0].fields.get("sha256").cloned().unwrap();
        assert_eq!(hex.len(), 64);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(hex, "ab".repeat(32));
        clear_audit_sink_for_test();
    }

    /// `ScriptAuditBridge::on_invoked` records duration and outcome.
    #[test]
    fn script_invoked_records_duration() {
        use spt_scripting::AuditSink as _;
        let _g = test_lock();
        let sink = install_mock_sink();
        let bridge = ScriptAuditBridge::new();
        bridge.on_invoked(
            spt_scripting::HookName::PreConnect,
            Duration::from_micros(123),
            spt_scripting::HookOutcome::Ok,
        );
        let evs = sink.events();
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0].kind, "audit.script.invoked");
        assert_eq!(
            evs[0].fields.get("hook").map(String::as_str),
            Some("pre_connect")
        );
        assert_eq!(
            evs[0].fields.get("duration_us").map(String::as_str),
            Some("123")
        );
        assert_eq!(evs[0].fields.get("outcome").map(String::as_str), Some("ok"));
        assert_eq!(evs[0].severity, AuditSeverity::Info);
        clear_audit_sink_for_test();
    }

    /// Err outcome elevates severity to `Warning`.
    #[test]
    fn script_invoked_records_error_outcome() {
        use spt_scripting::AuditSink as _;
        let _g = test_lock();
        let sink = install_mock_sink();
        let bridge = ScriptAuditBridge::new();
        bridge.on_invoked(
            spt_scripting::HookName::OnDisconnect,
            Duration::from_millis(5),
            spt_scripting::HookOutcome::Err,
        );
        let evs = sink.events();
        assert_eq!(evs.len(), 1);
        assert_eq!(
            evs[0].fields.get("outcome").map(String::as_str),
            Some("err")
        );
        assert_eq!(evs[0].severity, AuditSeverity::Warning);
        clear_audit_sink_for_test();
    }

    /// GSSAPI bridge fans out a `TokenExchange` event into
    /// `audit.auth.gssapi.token_exchange` with `package` / `round` /
    /// `complete` fields.
    #[test]
    fn gssapi_token_exchange_event_relayed() {
        use spt_auth_sspi::{AuditEvent as AE, AuditHook as _};
        let _g = test_lock();
        let sink = install_mock_sink();
        let bridge = GssapiAuditBridge::new();
        bridge.on_event(&AE::TokenExchange {
            package: "kerberos",
            round: 2,
            complete: false,
        });
        let evs = sink.events();
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0].kind, "audit.auth.gssapi.token_exchange");
        assert_eq!(
            evs[0].fields.get("package").map(String::as_str),
            Some("kerberos")
        );
        assert_eq!(evs[0].fields.get("round").map(String::as_str), Some("2"));
        assert_eq!(
            evs[0].fields.get("complete").map(String::as_str),
            Some("false")
        );
        clear_audit_sink_for_test();
    }

    /// MIC verified bridge with `ok = false` lands at `Warning`.
    #[test]
    fn gssapi_mic_verified_event_relayed() {
        use spt_auth_sspi::{AuditEvent as AE, AuditHook as _};
        let _g = test_lock();
        let sink = install_mock_sink();
        let bridge = GssapiAuditBridge::new();
        bridge.on_event(&AE::MicVerified {
            package: "negotiate",
            ok: true,
        });
        bridge.on_event(&AE::MicVerified {
            package: "ntlm",
            ok: false,
        });
        let evs = sink.events();
        assert_eq!(evs.len(), 2);
        assert_eq!(evs[0].kind, "audit.auth.gssapi.mic_verified");
        assert_eq!(evs[0].severity, AuditSeverity::Info);
        assert_eq!(evs[0].fields.get("ok").map(String::as_str), Some("true"));
        assert_eq!(evs[1].severity, AuditSeverity::Warning);
        assert_eq!(evs[1].fields.get("ok").map(String::as_str), Some("false"));
        clear_audit_sink_for_test();
    }

    /// Obfs bridge → `audit.obfs.connect` with transport + target.
    #[test]
    fn obfs_connect_event_relayed() {
        use spt_obfs::AuditHook as _;
        let _g = test_lock();
        let sink = install_mock_sink();
        let bridge = ObfsAuditBridge::new();
        bridge.on_connect("ssh-over-shadowsocks", "edge.example:22");
        let evs = sink.events();
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0].kind, "audit.obfs.connect");
        assert_eq!(
            evs[0].fields.get("transport").map(String::as_str),
            Some("ssh-over-shadowsocks")
        );
        assert_eq!(
            evs[0].fields.get("target").map(String::as_str),
            Some("edge.example:22")
        );
        clear_audit_sink_for_test();
    }

    /// Registering a swap-out sink replaces the previous receiver
    /// atomically. Pins the contract the bridges depend on.
    #[test]
    fn audit_sink_can_be_replaced_for_testing() {
        let _g = test_lock();
        let first = install_mock_sink();
        // Fire one event into the first sink.
        emit_sftp_umount(Path::new("/a"), "operator_request");
        assert_eq!(first.events().len(), 1);
        // Swap the sink and fire another event — only `second` sees it.
        let second = Arc::new(MockSink::default());
        register_audit_sink(second.clone());
        emit_sftp_umount(Path::new("/b"), "shutdown");
        assert_eq!(first.events().len(), 1, "first must not see post-swap");
        assert_eq!(second.events().len(), 1, "second must capture post-swap");
        clear_audit_sink_for_test();
    }

    /// GSSAPI bridge MIC-issued path produces `mic_len` as a numeric
    /// string and stays at `Info` severity. Bonus #9.
    #[test]
    fn gssapi_mic_issued_event_relayed() {
        use spt_auth_sspi::{AuditEvent as AE, AuditHook as _};
        let _g = test_lock();
        let sink = install_mock_sink();
        GssapiAuditBridge::new().on_event(&AE::MicIssued {
            package: "kerberos",
            mic_len: 64,
        });
        let evs = sink.events();
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0].kind, "audit.auth.gssapi.mic_issued");
        assert_eq!(evs[0].fields.get("mic_len").map(String::as_str), Some("64"));
        assert_eq!(evs[0].severity, AuditSeverity::Info);
        clear_audit_sink_for_test();
    }
}
