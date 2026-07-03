//! Auto-install maintenance window evaluation.
//!
//! `[updater.window]` (`allow_from` / `allow_to` / `timezone`) constrains
//! **auto** installs to a time-of-day window (e.g. "only self-update between
//! 02:00 and 04:00"). Before this module the window was parsed into
//! [`WindowConfig`] but never read — auto-install fired on any scheduled tick
//! regardless (wire-observ finding 6). This module is the missing consumer;
//! [`crate::auto_install_allowed`] gates the background auto path on it.
//!
//! # Timezone
//!
//! A full IANA timezone database is **not** in the dependency tree (and adding
//! one is out of scope — the crate must not grow `Cargo.lock`). The window is
//! therefore evaluated in **UTC**. A non-`UTC` `timezone` value is honored as a
//! request but evaluated in UTC with a `warn!`, rather than silently pretending
//! to apply an offset we cannot compute.

use chrono::{DateTime, Timelike, Utc};
use tracing::warn;

use crate::config::WindowConfig;

/// Parse an `"HH:MM"` string into minutes-since-midnight (`0..=1439`).
fn parse_hhmm(s: &str) -> Option<u32> {
    let (h, m) = s.trim().split_once(':')?;
    let h: u32 = h.trim().parse().ok()?;
    let m: u32 = m.trim().parse().ok()?;
    if h > 23 || m > 59 {
        return None;
    }
    Some(h * 60 + m)
}

/// Returns `true` when `now` (interpreted in UTC) falls inside the configured
/// maintenance window.
///
/// * A window where `allow_from <= allow_to` is a same-day span
///   (`from..=to`).
/// * A window where `allow_from > allow_to` **wraps past midnight**
///   (e.g. `22:00`–`04:00`), so both `>= from` and `<= to` are inside.
/// * Malformed `HH:MM` bounds cannot be evaluated; rather than defer forever
///   on a config typo, we **fail open** (allow) with a `warn!`.
#[must_use]
pub fn is_within_window(w: &WindowConfig, now: DateTime<Utc>) -> bool {
    if !w.timezone.eq_ignore_ascii_case("UTC") {
        warn!(
            target: "spt_updater::window",
            timezone = %w.timezone,
            "maintenance window timezone other than UTC is not supported without a \
             timezone database; evaluating the window in UTC"
        );
    }
    let (Some(from), Some(to)) = (parse_hhmm(&w.allow_from), parse_hhmm(&w.allow_to)) else {
        warn!(
            target: "spt_updater::window",
            allow_from = %w.allow_from,
            allow_to = %w.allow_to,
            "maintenance window has malformed HH:MM bounds; ignoring the window (allowing install)"
        );
        return true;
    };
    let cur = now.hour() * 60 + now.minute();
    if from <= to {
        (from..=to).contains(&cur)
    } else {
        cur >= from || cur <= to
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn at(hh: u32, mm: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 6, 11, hh, mm, 0).unwrap()
    }

    fn win(from: &str, to: &str, tz: &str) -> WindowConfig {
        WindowConfig {
            allow_from: from.into(),
            allow_to: to.into(),
            timezone: tz.into(),
        }
    }

    #[test]
    fn parses_hhmm() {
        assert_eq!(parse_hhmm("02:30"), Some(150));
        assert_eq!(parse_hhmm("00:00"), Some(0));
        assert_eq!(parse_hhmm("23:59"), Some(1439));
        assert_eq!(parse_hhmm("24:00"), None);
        assert_eq!(parse_hhmm("garbage"), None);
    }

    #[test]
    fn same_day_window_includes_and_excludes() {
        let w = win("02:00", "04:00", "UTC");
        assert!(is_within_window(&w, at(3, 0)));
        assert!(is_within_window(&w, at(2, 0)));
        assert!(is_within_window(&w, at(4, 0)));
        assert!(!is_within_window(&w, at(1, 59)));
        assert!(!is_within_window(&w, at(12, 0)));
    }

    #[test]
    fn window_wrapping_past_midnight() {
        let w = win("22:00", "04:00", "UTC");
        assert!(is_within_window(&w, at(23, 0)));
        assert!(is_within_window(&w, at(0, 30)));
        assert!(is_within_window(&w, at(3, 59)));
        assert!(!is_within_window(&w, at(12, 0)));
        assert!(!is_within_window(&w, at(21, 59)));
    }

    #[test]
    fn malformed_bounds_fail_open() {
        let w = win("nonsense", "04:00", "UTC");
        assert!(is_within_window(&w, at(12, 0)));
    }

    #[test]
    fn non_utc_timezone_is_evaluated_in_utc() {
        // Honored as a request but evaluated in UTC (no tz database).
        let w = win("02:00", "04:00", "America/Los_Angeles");
        assert!(is_within_window(&w, at(3, 0)));
        assert!(!is_within_window(&w, at(12, 0)));
    }
}
