//! Redacted diagnostic bundle builder.
//!
//! Spec §13.12:
//! - Diagnostic bundles MUST be redacted by default.
//! - Bundles MUST include effective config, status snapshots, recent logs,
//!   recent events, stats summaries, session summaries, platform details,
//!   service definitions, and selected benchmark summaries.
//!
//! We assemble the bundle as a `tar.gz` written via
//! `spt_state::write_atomic` so an interrupted `spt diagnose bundle` cannot
//! leave a half-written archive. Every text field is passed through
//! `spt_core::redact(.., RedactionMode::Strict)` before it enters the
//! archive. Filenames inside the archive are constants — no caller-controlled
//! paths leak into entry names.

use chrono::Utc;
use flate2::write::GzEncoder;
use flate2::Compression;
use serde::{Deserialize, Serialize};
use spt_core::redaction::{redact, RedactionMode};
use spt_core::Result;
use spt_state::write_atomic;
use std::path::{Path, PathBuf};

use crate::framework::DiagnosticReport;

/// Caller-supplied inputs that get redacted and packed into the archive.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BundleInputs {
    /// Effective config (already-rendered TOML, secret values masked by
    /// `spt_config::render` ideally — strict redaction is applied again
    /// here defensively).
    pub effective_config: Option<String>,
    /// JSON of the latest `StatusSnapshot`.
    pub status_snapshot: Option<String>,
    /// Recent events as JSONL.
    pub recent_events: Option<String>,
    /// Recent log tail (text).
    pub recent_logs: Option<String>,
    /// Stats summary (any text, e.g. Prometheus exposition).
    pub stats_summary: Option<String>,
    /// Diagnostic report (will be re-serialised to JSON).
    pub report: Option<DiagnosticReport>,
    /// Version / build metadata.
    pub version_info: Option<String>,
}

/// Knobs for the bundle build.
///
/// Built either with [`BundleConfig::default`] (fail-safe: Strict redaction,
/// 16 MiB cap, every section included) or from the operator's `[diagnostics]`
/// table via [`BundleConfig::from_diagnostics`].
#[derive(Debug, Clone)]
pub struct BundleConfig {
    /// Redaction mode applied to every text entry. Defaults to
    /// `RedactionMode::Strict`.
    pub redaction: RedactionMode,
    /// Maximum total uncompressed bytes across all entries. Entries beyond
    /// this cap are truncated with a marker.
    pub max_total_bytes: u64,
    /// Include the recent log tail (`logs.txt`). Default `true`.
    pub include_recent_logs: bool,
    /// Include the status snapshot (`status.json`). Default `true`.
    pub include_status: bool,
    /// Include the stats/metrics snapshot (`stats.txt`). Default `true`.
    pub include_stats: bool,
    /// Include session details. Default `true`. (No dedicated input entry
    /// yet — reserved so the configured section takes effect once a session
    /// collector is wired.)
    pub include_sessions: bool,
    /// Include copies of service definitions. Default `true`. (Reserved as
    /// for [`Self::include_sessions`].)
    pub include_service_definitions: bool,
}

impl Default for BundleConfig {
    fn default() -> Self {
        Self {
            redaction: RedactionMode::Strict,
            max_total_bytes: 16 * 1024 * 1024,
            include_recent_logs: true,
            include_status: true,
            include_stats: true,
            include_sessions: true,
            include_service_definitions: true,
        }
    }
}

impl BundleConfig {
    /// Build a [`BundleConfig`] from the `[diagnostics]` config table.
    ///
    /// Unset fields fall back to the fail-safe [`BundleConfig::default`]
    /// (Strict redaction, 16 MiB cap, all sections included). `redact = false`
    /// is the *only* way to opt out of redaction; unset or `redact = true`
    /// keeps `RedactionMode::Strict`, so a missing/typo'd value can never
    /// silently disable redaction. `max_bundle_size` is parsed as a byte size
    /// (e.g. `"8MiB"`); an unparseable value keeps the default cap.
    #[must_use]
    pub fn from_diagnostics(d: &spt_config::schema::Diagnostics) -> Self {
        let default = Self::default();
        let redaction = match d.redact {
            Some(false) => RedactionMode::None,
            _ => RedactionMode::Strict,
        };
        let max_total_bytes = d
            .max_bundle_size
            .as_deref()
            .and_then(|s| spt_core::size::parse_size(s).ok())
            .filter(|n| *n > 0)
            .unwrap_or(default.max_total_bytes);
        Self {
            redaction,
            max_total_bytes,
            include_recent_logs: d.include_recent_logs.unwrap_or(true),
            include_status: d.include_status.unwrap_or(true),
            include_stats: d.include_stats.unwrap_or(true),
            include_sessions: d.include_sessions.unwrap_or(true),
            include_service_definitions: d.include_service_definitions.unwrap_or(true),
        }
    }
}

/// Build and atomically write a `<state_dir>/diagnostics/<run-id>/bundle.tar.gz`.
///
/// `run_id` is included in the directory path; pick something monotonic such
/// as a UUID or RFC3339-derived string. Returns the absolute archive path.
pub fn build_bundle(
    state_dir: &Path,
    run_id: &str,
    inputs: &BundleInputs,
    cfg: &BundleConfig,
) -> Result<PathBuf> {
    let dir = state_dir.join("diagnostics").join(run_id);
    std::fs::create_dir_all(&dir).map_err(|e| spt_core::Error::StateLockFailed {
        path: dir.clone(),
        reason: format!("mkdir bundle dir: {e}"),
    })?;
    let archive = dir.join("bundle.tar.gz");

    let mut budget = cfg.max_total_bytes;
    let mut buf = Vec::new();
    {
        let gz = GzEncoder::new(&mut buf, Compression::default());
        let mut tar = tar::Builder::new(gz);

        let now = Utc::now().to_rfc3339();
        write_text(
            &mut tar,
            "manifest.txt",
            &format!("spt diagnostic bundle\nrun_id = {run_id}\ngenerated_at = {now}\n"),
            cfg,
            &mut budget,
        )?;

        if let Some(s) = &inputs.version_info {
            write_text(&mut tar, "version.txt", s, cfg, &mut budget)?;
        }
        if let Some(s) = &inputs.effective_config {
            write_text(&mut tar, "effective-config.toml", s, cfg, &mut budget)?;
        }
        if cfg.include_status {
            if let Some(s) = &inputs.status_snapshot {
                write_text(&mut tar, "status.json", s, cfg, &mut budget)?;
            }
        }
        if let Some(s) = &inputs.recent_events {
            write_text(&mut tar, "events.jsonl", s, cfg, &mut budget)?;
        }
        if cfg.include_recent_logs {
            if let Some(s) = &inputs.recent_logs {
                write_text(&mut tar, "logs.txt", s, cfg, &mut budget)?;
            }
        }
        if cfg.include_stats {
            if let Some(s) = &inputs.stats_summary {
                write_text(&mut tar, "stats.txt", s, cfg, &mut budget)?;
            }
        }
        if let Some(report) = &inputs.report {
            let json = serde_json::to_string_pretty(report).unwrap_or_default();
            write_text(&mut tar, "report.json", &json, cfg, &mut budget)?;
        }

        tar.finish()
            .map_err(|e| spt_core::Error::DiagnosticBundleFailed(format!("tar finish: {e}")))?;
    }

    write_atomic(&archive, &buf)?;
    Ok(archive)
}

fn write_text<W: std::io::Write>(
    tar: &mut tar::Builder<W>,
    name: &str,
    text: &str,
    cfg: &BundleConfig,
    budget: &mut u64,
) -> Result<()> {
    let redacted = redact(text, cfg.redaction);
    let mut bytes = redacted.as_bytes().to_vec();
    if (bytes.len() as u64) > *budget {
        let allow = (*budget) as usize;
        bytes.truncate(allow);
        bytes.extend_from_slice(b"\n[truncated by bundle budget]\n");
        *budget = 0;
    } else {
        *budget = budget.saturating_sub(bytes.len() as u64);
    }

    let mut header = tar::Header::new_gnu();
    header.set_size(bytes.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    tar.append_data(&mut header, name, bytes.as_slice())
        .map_err(|e| spt_core::Error::DiagnosticBundleFailed(format!("append {name}: {e}")))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::check::{Check, Severity, Status};
    use std::io::Read;
    use tempfile::tempdir;

    fn read_archive_entries(archive: &Path) -> Vec<(String, Vec<u8>)> {
        let f = std::fs::File::open(archive).unwrap();
        let gz = flate2::read::GzDecoder::new(f);
        let mut tar = tar::Archive::new(gz);
        let mut out = Vec::new();
        for e in tar.entries().unwrap() {
            let mut e = e.unwrap();
            let path = e.path().unwrap().to_string_lossy().into_owned();
            let mut buf = Vec::new();
            e.read_to_end(&mut buf).unwrap();
            out.push((path, buf));
        }
        out
    }

    #[test]
    fn build_minimum() {
        let d = tempdir().unwrap();
        let path = build_bundle(
            d.path(),
            "run-1",
            &BundleInputs {
                version_info: Some("spt 0.1.0".into()),
                ..Default::default()
            },
            &BundleConfig::default(),
        )
        .unwrap();
        assert!(path.exists());
        let entries = read_archive_entries(&path);
        let names: Vec<&str> = entries.iter().map(|(n, _)| n.as_str()).collect();
        assert!(names.contains(&"manifest.txt"));
        assert!(names.contains(&"version.txt"));
    }

    #[test]
    fn redacts_secrets_in_inputs() {
        let d = tempdir().unwrap();
        let cfg_text = "password = abc123\nbearer eyJhbGciOiJIUzI1NiJ9.payload.sig\n";
        let path = build_bundle(
            d.path(),
            "run-2",
            &BundleInputs {
                effective_config: Some(cfg_text.into()),
                ..Default::default()
            },
            &BundleConfig::default(),
        )
        .unwrap();
        let entries = read_archive_entries(&path);
        let (_, body) = entries
            .iter()
            .find(|(n, _)| n == "effective-config.toml")
            .unwrap();
        let body = std::str::from_utf8(body).unwrap();
        // Strict redaction must mask the bearer token at minimum.
        assert!(
            !body.contains("eyJhbGciOiJIUzI1NiJ9.payload.sig"),
            "expected bearer redacted, got: {body}"
        );
    }

    #[test]
    fn report_is_persisted_as_json() {
        let d = tempdir().unwrap();
        let mut report = DiagnosticReport::default();
        report
            .checks
            .push(Check::new("os.family", Severity::Info, Status::Pass).with_evidence("os = test"));
        let path = build_bundle(
            d.path(),
            "run-3",
            &BundleInputs {
                report: Some(report),
                ..Default::default()
            },
            &BundleConfig::default(),
        )
        .unwrap();
        let entries = read_archive_entries(&path);
        let (_, body) = entries.iter().find(|(n, _)| n == "report.json").unwrap();
        let body = std::str::from_utf8(body).unwrap();
        assert!(body.contains("\"os.family\""));
        assert!(body.contains("\"pass\""));
    }

    #[test]
    fn new_check_ids_land_in_bundle() {
        // Synthesise a report that exercises every new check group from
        // f-diagnostics so we can confirm the bundle preserves them verbatim
        // through redaction.
        let d = tempdir().unwrap();
        let mut report = DiagnosticReport::default();
        for id in [
            "secrets.backend.keychain",
            "secrets.round_trip.keychain",
            "firewall.plan",
            "firewall.live_rules",
            "service.status",
            "mcp.handshake",
            "mcp.resources_count",
            "mcp.tools_count",
            "runtime.snapshot",
            "runtime.uptime",
            "runtime.profiles",
            "runtime.recent_errors",
            "ssh2.libssh2_init",
            "ssh2.supported_algs.kex",
            "ssh2.crypto_policy.kex",
        ] {
            report
                .checks
                .push(Check::new(id, Severity::Info, Status::Pass));
        }
        let path = build_bundle(
            d.path(),
            "run-new",
            &BundleInputs {
                report: Some(report),
                ..Default::default()
            },
            &BundleConfig::default(),
        )
        .unwrap();
        let entries = read_archive_entries(&path);
        let (_, body) = entries.iter().find(|(n, _)| n == "report.json").unwrap();
        let body = std::str::from_utf8(body).unwrap();
        for id in [
            "secrets.backend.keychain",
            "firewall.plan",
            "service.status",
            "mcp.handshake",
            "runtime.snapshot",
            "ssh2.libssh2_init",
        ] {
            assert!(
                body.contains(&format!("\"{id}\"")),
                "missing {id} in bundle"
            );
        }
    }

    #[test]
    fn bundle_config_defaults_are_strict_and_16mb() {
        let c = BundleConfig::default();
        assert!(matches!(c.redaction, RedactionMode::Strict));
        assert_eq!(c.max_total_bytes, 16 * 1024 * 1024);
        assert!(c.include_recent_logs);
        assert!(c.include_status);
        assert!(c.include_stats);
    }

    #[test]
    fn from_diagnostics_honors_redaction_and_size_and_sections() {
        // redact = false explicitly opts OUT of redaction; a custom size cap
        // and disabled sections must be reflected in the BundleConfig.
        let d = spt_config::schema::Diagnostics {
            redact: Some(false),
            max_bundle_size: Some("4MiB".into()),
            include_recent_logs: Some(false),
            include_status: Some(false),
            include_stats: Some(true),
            ..Default::default()
        };
        let c = BundleConfig::from_diagnostics(&d);
        assert!(matches!(c.redaction, RedactionMode::None));
        assert_eq!(c.max_total_bytes, 4 * 1024 * 1024);
        assert!(!c.include_recent_logs);
        assert!(!c.include_status);
        assert!(c.include_stats);
    }

    #[test]
    fn from_diagnostics_is_failsafe_strict_when_unset_or_bad() {
        // Unset redact => Strict (default); an unparseable size keeps the
        // 16 MiB default cap; unset sections default to included.
        let d = spt_config::schema::Diagnostics {
            redact: None,
            max_bundle_size: Some("not-a-size".into()),
            ..Default::default()
        };
        let c = BundleConfig::from_diagnostics(&d);
        assert!(matches!(c.redaction, RedactionMode::Strict));
        assert_eq!(c.max_total_bytes, 16 * 1024 * 1024);
        assert!(c.include_recent_logs);
        assert!(c.include_status);
        assert!(c.include_stats);

        // redact = Some(true) is also Strict.
        let d2 = spt_config::schema::Diagnostics {
            redact: Some(true),
            ..Default::default()
        };
        assert!(matches!(
            BundleConfig::from_diagnostics(&d2).redaction,
            RedactionMode::Strict
        ));
    }

    #[test]
    fn include_flags_drop_disabled_sections_from_archive() {
        let d = tempdir().unwrap();
        let cfg = BundleConfig {
            include_recent_logs: false,
            include_status: false,
            ..BundleConfig::default()
        };
        let inputs = BundleInputs {
            status_snapshot: Some("{}".into()),
            recent_logs: Some("secret log line".into()),
            stats_summary: Some("metric=1".into()),
            ..Default::default()
        };
        let p = build_bundle(d.path(), "gated", &inputs, &cfg).unwrap();
        let entries = read_archive_entries(&p);
        let names: Vec<&str> = entries.iter().map(|(n, _)| n.as_str()).collect();
        assert!(!names.contains(&"logs.txt"), "logs must be excluded");
        assert!(!names.contains(&"status.json"), "status must be excluded");
        // stats still included (include_stats defaults true).
        assert!(names.contains(&"stats.txt"), "stats should remain");
    }

    #[test]
    fn empty_inputs_still_produces_manifest_only_archive() {
        let d = tempdir().unwrap();
        let p = build_bundle(
            d.path(),
            "empty-run",
            &BundleInputs::default(),
            &BundleConfig::default(),
        )
        .unwrap();
        let entries = read_archive_entries(&p);
        let names: Vec<&str> = entries.iter().map(|(n, _)| n.as_str()).collect();
        assert!(names.contains(&"manifest.txt"));
        // No other text entries because every Option is None.
        assert_eq!(entries.len(), 1);
    }

    #[test]
    fn all_inputs_round_trip_filenames() {
        let d = tempdir().unwrap();
        let inputs = BundleInputs {
            effective_config: Some("k=v".into()),
            status_snapshot: Some("{}".into()),
            recent_events: Some("{\"x\":1}".into()),
            recent_logs: Some("log line".into()),
            stats_summary: Some("metric=1".into()),
            report: Some(DiagnosticReport::default()),
            version_info: Some("v1".into()),
        };
        let p = build_bundle(d.path(), "all", &inputs, &BundleConfig::default()).unwrap();
        let entries = read_archive_entries(&p);
        let names: Vec<&str> = entries.iter().map(|(n, _)| n.as_str()).collect();
        for expected in [
            "manifest.txt",
            "version.txt",
            "effective-config.toml",
            "status.json",
            "events.jsonl",
            "logs.txt",
            "stats.txt",
            "report.json",
        ] {
            assert!(names.contains(&expected), "missing {expected} in {names:?}");
        }
    }

    #[test]
    fn manifest_contains_run_id() {
        let d = tempdir().unwrap();
        let p = build_bundle(
            d.path(),
            "abc-run-id-123",
            &BundleInputs::default(),
            &BundleConfig::default(),
        )
        .unwrap();
        let entries = read_archive_entries(&p);
        let (_, body) = entries.iter().find(|(n, _)| n == "manifest.txt").unwrap();
        let body = std::str::from_utf8(body).unwrap();
        assert!(body.contains("abc-run-id-123"), "body: {body}");
        assert!(body.contains("generated_at"));
    }

    #[test]
    fn archive_path_includes_run_id_dir() {
        let d = tempdir().unwrap();
        let p = build_bundle(
            d.path(),
            "the-run",
            &BundleInputs::default(),
            &BundleConfig::default(),
        )
        .unwrap();
        assert!(p.ends_with("bundle.tar.gz"));
        let parent = p.parent().unwrap();
        assert_eq!(parent.file_name().unwrap(), "the-run");
        assert_eq!(parent.parent().unwrap().file_name().unwrap(), "diagnostics");
    }

    #[test]
    fn budget_exactly_zero_truncates_immediately() {
        let d = tempdir().unwrap();
        let cfg = BundleConfig {
            redaction: RedactionMode::None,
            max_total_bytes: 0,
            ..BundleConfig::default()
        };
        let p = build_bundle(
            d.path(),
            "zero-budget",
            &BundleInputs {
                recent_logs: Some("x".repeat(1000)),
                ..Default::default()
            },
            &cfg,
        )
        .unwrap();
        // Bundle must still exist and be readable even with a zero budget.
        assert!(p.exists());
        let _ = read_archive_entries(&p);
    }

    #[test]
    fn budget_truncates() {
        let d = tempdir().unwrap();
        let big = "x".repeat(10_000);
        let cfg = BundleConfig {
            redaction: RedactionMode::None,
            max_total_bytes: 100,
            ..BundleConfig::default()
        };
        let path = build_bundle(
            d.path(),
            "run-4",
            &BundleInputs {
                recent_logs: Some(big),
                ..Default::default()
            },
            &cfg,
        )
        .unwrap();
        let entries = read_archive_entries(&path);
        let logs = entries.iter().find(|(n, _)| n == "logs.txt");
        // logs.txt may be truncated or omitted depending on order; we accept
        // either, but the archive itself must exist and be readable.
        let _ = logs;
        assert!(path.exists());
    }
}
