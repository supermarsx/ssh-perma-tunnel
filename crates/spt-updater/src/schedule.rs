//! Cron / interval scheduler.
//!
//! Wraps the `cron` crate (5-field cron spec) and `humantime`-parsed
//! durations behind a single [`Scheduler`] type so the main loop in
//! `lib.rs` doesn't care which one the operator picked.

use std::str::FromStr;
use std::time::Duration;

use chrono::Utc;
use cron::Schedule as CronSchedule;
use tracing::warn;

use crate::config::{ScheduleKind, UpdaterConfig};

/// Polling scheduler. Tracks the next fire time and gates `should_fire_now`
/// from the main loop.
#[derive(Debug)]
pub struct Scheduler {
    inner: SchedulerInner,
    /// Last computed fire instant (UTC seconds since epoch). Reset after
    /// every fire so we don't double-fire on the same tick.
    last_fire_epoch: parking_lot::Mutex<i64>,
}

// 1.88 lint: large_enum_variant — `Cron(CronSchedule)` is far larger than the
// other arms. There is exactly one `SchedulerInner` per `Scheduler` (long-lived,
// not collection-stored), so the size disparity has no practical cost; boxing
// would only add an indirection on the hot tick path.
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
enum SchedulerInner {
    Cron(CronSchedule),
    Interval(Duration),
    /// Fall-back for unparseable cron expressions — the loop just sleeps
    /// 1h between ticks and never fires. Surfaces a tracing-warn at
    /// construction time.
    Invalid,
}

impl Scheduler {
    /// Build from the runtime config.
    #[must_use]
    pub fn from_config(cfg: &UpdaterConfig) -> Self {
        let inner = match &cfg.schedule {
            ScheduleKind::Cron(expr) => match CronSchedule::from_str(&expand_5_to_6(expr)) {
                Ok(s) => SchedulerInner::Cron(s),
                Err(e) => {
                    warn!(
                        target: "spt_updater::schedule",
                        expr = %expr,
                        error = %e,
                        "cron expression failed to parse; scheduler disabled"
                    );
                    SchedulerInner::Invalid
                }
            },
            ScheduleKind::Interval(d) => SchedulerInner::Interval(*d),
        };
        Self {
            inner,
            last_fire_epoch: parking_lot::Mutex::new(0),
        }
    }

    /// Compute how long the loop should sleep before checking again,
    /// capped to `max`. The main loop wakes on whichever happens first:
    /// this sleep elapsing or a control message arriving.
    #[must_use]
    pub fn next_tick_within(&self, max: Duration) -> Duration {
        let raw = match &self.inner {
            SchedulerInner::Cron(s) => {
                let now = Utc::now();
                match s.upcoming(Utc).next() {
                    Some(next) => {
                        let secs = (next - now).num_seconds().max(0) as u64;
                        Duration::from_secs(secs)
                    }
                    None => Duration::from_secs(3600),
                }
            }
            SchedulerInner::Interval(d) => *d,
            SchedulerInner::Invalid => Duration::from_secs(3600),
        };
        raw.min(max)
    }

    /// Returns true when the main loop should run a check on this wake-up.
    /// Idempotent within the same second.
    #[must_use]
    pub fn should_fire_now(&self) -> bool {
        let now = Utc::now().timestamp();
        let mut last = self.last_fire_epoch.lock();
        match &self.inner {
            SchedulerInner::Cron(s) => {
                let due = s
                    .upcoming(Utc)
                    .next()
                    .is_some_and(|next| (next - Utc::now()).num_seconds() <= 0);
                if due && *last != now {
                    *last = now;
                    true
                } else {
                    false
                }
            }
            SchedulerInner::Interval(d) => {
                let secs = d.as_secs() as i64;
                if *last == 0 || now - *last >= secs {
                    *last = now;
                    true
                } else {
                    false
                }
            }
            SchedulerInner::Invalid => false,
        }
    }
}

/// `cron` 0.12 expects 6-field expressions (seconds first). Standard
/// 5-field crontabs (the form everyone writes) need a leading `0 ` for
/// "seconds = 0".
fn expand_5_to_6(s: &str) -> String {
    let trimmed = s.trim();
    if trimmed.split_whitespace().count() == 5 {
        format!("0 {trimmed}")
    } else {
        trimmed.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ScheduleKind, UpdateMode};

    fn cfg_with(kind: ScheduleKind) -> UpdaterConfig {
        UpdaterConfig {
            enabled: true,
            mode: UpdateMode::Check,
            schedule: kind,
            source: crate::config::SourceKind::GitHub {
                repo: "x/y".into(),
                channel: crate::config::ReleaseChannel::Stable,
            },
            verify: crate::config::VerifyConfig {
                require_minisign: false,
                minisign_pubkey: None,
                require_sha256sums: false,
                gpg_pubkey: None,
            },
            action: crate::config::ActionConfig {
                restart_supervisor: false,
                notify_audit: false,
                post_install_hook: None,
            },
            staging: crate::config::StagingConfig {
                dir: None,
                keep_last: 1,
            },
            window: None,
        }
    }

    #[test]
    fn cron_5_field_is_accepted() {
        let s = Scheduler::from_config(&cfg_with(ScheduleKind::Cron("0 6 * * *".into())));
        assert!(matches!(s.inner, SchedulerInner::Cron(_)));
    }

    #[test]
    fn invalid_cron_is_degraded_not_panicked() {
        let s = Scheduler::from_config(&cfg_with(ScheduleKind::Cron("not a cron".into())));
        assert!(matches!(s.inner, SchedulerInner::Invalid));
        // `next_tick_within` returns the cap (1h) even when invalid.
        assert_eq!(
            s.next_tick_within(Duration::from_secs(60)),
            Duration::from_secs(60)
        );
        assert!(!s.should_fire_now());
    }

    #[test]
    fn interval_fires_on_first_tick() {
        let s =
            Scheduler::from_config(&cfg_with(ScheduleKind::Interval(Duration::from_secs(3600))));
        // First call after construction fires unconditionally (last_fire == 0).
        assert!(s.should_fire_now());
        // Immediate re-check doesn't refire.
        assert!(!s.should_fire_now());
    }
}
