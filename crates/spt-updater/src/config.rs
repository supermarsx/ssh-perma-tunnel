//! Typed view of `[updater]` with every default applied at construction
//! time. The schema (`spt-config::schema::Updater`) is an Option-soup; this
//! is the runtime form the updater actually reads.

use std::path::PathBuf;
use std::time::Duration;

use spt_config::schema::Updater as SchemaUpdater;

use crate::error::{UpdaterError, UpdaterResult};

/// Default cron schedule: 06:00 UTC every day.
pub const DEFAULT_SCHEDULE: &str = "0 6 * * *";

/// Default GitHub repo for the `github` source.
pub const DEFAULT_GITHUB_REPO: &str = "supermarsx/ssh-perma-tunnel";

/// Default `keep_last` for the staging directory.
pub const DEFAULT_KEEP_LAST: u32 = 3;

/// Resolved + validated runtime view of `[updater]`.
#[derive(Debug, Clone)]
pub struct UpdaterConfig {
    /// Master switch — spawn the background thread.
    pub enabled: bool,
    /// What the thread does when it ticks.
    pub mode: UpdateMode,
    /// Resolved scheduler (cron expression or interval).
    pub schedule: ScheduleKind,
    /// Release source backend.
    pub source: SourceKind,
    /// Verification policy.
    pub verify: VerifyConfig,
    /// Action policy (post-install hooks, restart).
    pub action: ActionConfig,
    /// Staging directory + retention.
    pub staging: StagingConfig,
    /// Optional install window.
    pub window: Option<WindowConfig>,
}

/// What the background thread does when it ticks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum UpdateMode {
    /// Don't poll, don't install. The supervisor refuses to spawn the
    /// thread when this is set even with `enabled = true`.
    Off,
    /// Poll only. Expose `update_available` via `spt update status`.
    Check,
    /// Poll + emit a tracing-warn + audit event when an update is
    /// available. Don't install.
    Warn,
    /// Poll + download + verify + atomic install + supervisor restart.
    Auto,
}

/// Polling schedule.
#[derive(Debug, Clone)]
pub enum ScheduleKind {
    /// Cron 5-field expression (minute hour dom month dow).
    Cron(String),
    /// Simple fixed interval.
    Interval(Duration),
}

/// Source backend kind.
#[derive(Debug, Clone)]
pub enum SourceKind {
    /// GitHub Releases API for `<owner>/<repo>`.
    GitHub {
        /// `<owner>/<repo>`.
        repo: String,
        /// `stable` or `prerelease`.
        channel: ReleaseChannel,
    },
    /// HTTPS GET against a `release-manifest.json` URL with an SHA-256 pin.
    Url {
        /// Artifact URL template (`{version}` + `{target}` placeholders).
        url: String,
        /// Manifest URL.
        index: String,
        /// SHA-256 pin for the manifest body.
        fingerprint: String,
    },
    /// `file://` directory of release artifacts (offline mirrors, tests).
    Static {
        /// Absolute path to a directory laid out like `dist/<version>/`.
        dir: PathBuf,
    },
}

/// GitHub release channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReleaseChannel {
    /// Skip pre-releases.
    Stable,
    /// Include pre-releases.
    Prerelease,
}

/// Verification floor. `require_minisign = true` by default.
#[derive(Debug, Clone)]
pub struct VerifyConfig {
    /// Refuse to install without a valid minisign signature.
    pub require_minisign: bool,
    /// Trusted minisign public key path. Required iff `require_minisign`.
    pub minisign_pubkey: Option<PathBuf>,
    /// Refuse to install if the artifact's SHA-256 doesn't match SHA256SUMS.
    pub require_sha256sums: bool,
    /// Optional GPG key for the SHA256SUMS.asc detached signature.
    pub gpg_pubkey: Option<PathBuf>,
}

/// Post-install action policy.
#[derive(Debug, Clone)]
pub struct ActionConfig {
    /// Trigger a supervisor restart after a successful install.
    pub restart_supervisor: bool,
    /// Emit a structured audit event for each install.
    pub notify_audit: bool,
    /// Optional post-install hook (executable path).
    pub post_install_hook: Option<PathBuf>,
}

/// Staging directory + retention.
#[derive(Debug, Clone)]
pub struct StagingConfig {
    /// Where to land downloaded artifacts before swap.
    pub dir: Option<PathBuf>,
    /// How many past builds to keep.
    pub keep_last: u32,
}

/// Auto-install maintenance window.
#[derive(Debug, Clone)]
pub struct WindowConfig {
    /// HH:MM start (24-hour).
    pub allow_from: String,
    /// HH:MM end (24-hour).
    pub allow_to: String,
    /// IANA timezone (`"UTC"`, `"America/Los_Angeles"`).
    pub timezone: String,
}

impl UpdaterConfig {
    /// Build a runtime config from the schema. Applies every default
    /// documented in `docs/updater.md`. Returns an error only when the
    /// config is *unsalvageable* — the schema validator catches most
    /// cases at load time, so this is a thin secondary check.
    pub fn from_schema(s: &SchemaUpdater) -> UpdaterResult<Self> {
        let mode = parse_mode(s.mode.as_deref().unwrap_or("off"))?;

        let schedule = if let Some(iv) = s.interval.as_deref() {
            let dur: humantime::Duration = iv
                .parse()
                .map_err(|e| UpdaterError::Config(format!("updater.interval `{iv}`: {e}")))?;
            ScheduleKind::Interval(dur.into())
        } else {
            ScheduleKind::Cron(
                s.schedule
                    .clone()
                    .unwrap_or_else(|| DEFAULT_SCHEDULE.to_string()),
            )
        };

        let source = match s.source.as_deref().unwrap_or("github") {
            "github" => SourceKind::GitHub {
                repo: s
                    .github_repo
                    .clone()
                    .unwrap_or_else(|| DEFAULT_GITHUB_REPO.to_string()),
                channel: match s.github_channel.as_deref().unwrap_or("stable") {
                    "prerelease" => ReleaseChannel::Prerelease,
                    _ => ReleaseChannel::Stable,
                },
            },
            "url" => {
                let url = s
                    .url
                    .clone()
                    .ok_or_else(|| UpdaterError::Config("updater.url required".into()))?;
                let index = s.url_index.clone().unwrap_or_else(|| {
                    // Best-effort default: strip everything after the last `/`.
                    if let Some(idx) = url.rfind('/') {
                        format!("{}/release-manifest.json", &url[..idx])
                    } else {
                        format!("{url}/release-manifest.json")
                    }
                });
                let fingerprint = s.url_fingerprint.clone().ok_or_else(|| {
                    UpdaterError::Config("updater.url_fingerprint required".into())
                })?;
                SourceKind::Url {
                    url,
                    index,
                    fingerprint,
                }
            }
            "static" => {
                let dir = s
                    .static_dir
                    .clone()
                    .ok_or_else(|| UpdaterError::Config("updater.static_dir required".into()))?;
                SourceKind::Static {
                    dir: PathBuf::from(dir),
                }
            }
            other => {
                return Err(UpdaterError::Config(format!(
                    "updater.source `{other}` is not recognised"
                )));
            }
        };

        let verify = s
            .verify
            .as_ref()
            .map(|v| VerifyConfig {
                require_minisign: v.require_minisign.unwrap_or(true),
                minisign_pubkey: v.minisign_pubkey.clone().map(PathBuf::from),
                require_sha256sums: v.require_sha256sums.unwrap_or(true),
                gpg_pubkey: v.gpg_pubkey.clone().map(PathBuf::from),
            })
            .unwrap_or_else(|| VerifyConfig {
                require_minisign: true,
                minisign_pubkey: None,
                require_sha256sums: true,
                gpg_pubkey: None,
            });

        let action = s
            .action
            .as_ref()
            .map(|a| ActionConfig {
                restart_supervisor: a.restart_supervisor.unwrap_or(true),
                notify_audit: a.notify_audit.unwrap_or(true),
                post_install_hook: a.post_install_hook.clone().map(PathBuf::from),
            })
            .unwrap_or_else(|| ActionConfig {
                restart_supervisor: true,
                notify_audit: true,
                post_install_hook: None,
            });

        let staging = s
            .staging
            .as_ref()
            .map(|sx| StagingConfig {
                dir: sx.dir.clone().map(PathBuf::from),
                keep_last: sx.keep_last.unwrap_or(DEFAULT_KEEP_LAST),
            })
            .unwrap_or_else(|| StagingConfig {
                dir: None,
                keep_last: DEFAULT_KEEP_LAST,
            });

        let window =
            s.window
                .as_ref()
                .and_then(|w| match (w.allow_from.clone(), w.allow_to.clone()) {
                    (Some(from), Some(to)) => Some(WindowConfig {
                        allow_from: from,
                        allow_to: to,
                        timezone: w.timezone.clone().unwrap_or_else(|| "UTC".into()),
                    }),
                    _ => None,
                });

        Ok(Self {
            enabled: s.enabled.unwrap_or(false),
            mode,
            schedule,
            source,
            verify,
            action,
            staging,
            window,
        })
    }
}

fn parse_mode(s: &str) -> UpdaterResult<UpdateMode> {
    match s {
        "off" => Ok(UpdateMode::Off),
        "check" => Ok(UpdateMode::Check),
        "warn" => Ok(UpdateMode::Warn),
        "auto" => Ok(UpdateMode::Auto),
        other => Err(UpdaterError::Config(format!(
            "updater.mode `{other}` is not recognised"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_schema_yields_disabled_off() {
        let s = SchemaUpdater::default();
        let cfg = UpdaterConfig::from_schema(&s).unwrap();
        assert!(!cfg.enabled);
        assert_eq!(cfg.mode, UpdateMode::Off);
        // The default schedule is the documented cron.
        match cfg.schedule {
            ScheduleKind::Cron(c) => assert_eq!(c, DEFAULT_SCHEDULE),
            ScheduleKind::Interval(_) => panic!("expected default Cron"),
        }
        // Default source is the canonical github repo.
        match cfg.source {
            SourceKind::GitHub { repo, channel } => {
                assert_eq!(repo, DEFAULT_GITHUB_REPO);
                assert_eq!(channel, ReleaseChannel::Stable);
            }
            other => panic!("expected GitHub default, got {other:?}"),
        }
        // Verification is strict by default.
        assert!(cfg.verify.require_minisign);
        assert!(cfg.verify.require_sha256sums);
    }

    #[test]
    fn interval_overrides_cron() {
        let s = SchemaUpdater {
            interval: Some("12h".into()),
            ..Default::default()
        };
        let cfg = UpdaterConfig::from_schema(&s).unwrap();
        match cfg.schedule {
            ScheduleKind::Interval(d) => assert_eq!(d, Duration::from_secs(12 * 3600)),
            ScheduleKind::Cron(_) => panic!("expected Interval"),
        }
    }

    #[test]
    fn url_source_requires_url_and_fingerprint() {
        let s = SchemaUpdater {
            source: Some("url".into()),
            ..Default::default()
        };
        let err = UpdaterConfig::from_schema(&s).unwrap_err();
        assert_eq!(err.code(), "updater_config");
    }
}
