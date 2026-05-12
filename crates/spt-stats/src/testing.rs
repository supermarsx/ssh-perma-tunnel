//! Reusable test fixtures for `spt-stats`.
//!
//! Gated behind the `testing` feature (always on under `cfg(test)`).
//! Helpers are deterministic by default — every time-aware fixture is
//! driven by an injectable [`TestClock`].

use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, TimeZone, Utc};

use spt_core::{ConnectionId, ForwardId, ProfileId, SessionId};

use crate::clock::TestClock;
use crate::counters::RollingCounter;
use crate::ewma::Ewma;
use crate::tables::{ConnectionEntry, ConnectionTable, SessionEntry, SessionTable};

/// Build a [`RollingCounter`] of width `window` (with 10 buckets) and feed it
/// `ticks` driven by an internal [`TestClock`].
///
/// The `ticks` slice is interpreted as `(offset_from_start, value)` pairs:
/// the first tick lands at `t0`, subsequent ticks advance the test clock by
/// `offset[i] - offset[i-1]`. Offsets MUST be monotonically non-decreasing.
///
/// The clock is left advanced to the last tick offset, so callers can read
/// `sum_over_window()` against a known-current "now".
///
/// # Panics
/// Panics if `offsets` are not monotonic (clock cannot move backwards).
///
/// # Examples
///
/// ```
/// use std::time::Duration;
/// use spt_stats::testing::populated_counter;
///
/// let c = populated_counter(
///     Duration::from_secs(60),
///     &[
///         (Duration::ZERO, 1),
///         (Duration::from_secs(1), 2),
///         (Duration::from_secs(2), 3),
///     ],
/// );
/// assert_eq!(c.sum_over_window(), 6);
/// ```
#[must_use]
pub fn populated_counter(window: Duration, ticks: &[(Duration, u64)]) -> RollingCounter {
    let clock = Arc::new(TestClock::at_now());
    let counter = RollingCounter::with_clock(window, 10, clock.clone());
    let mut last = Duration::ZERO;
    for (offset, value) in ticks {
        assert!(*offset >= last, "tick offsets must be monotonic");
        let delta = *offset - last;
        if !delta.is_zero() {
            clock.advance(delta);
        }
        counter.add(*value);
        last = *offset;
    }
    counter
}

/// Synthetic [`SessionTable`] with `rows` deterministic entries.
///
/// Each row uses ids `s0, s1, …`, profile `p`, and a fixed opening timestamp
/// at the Unix epoch. Useful for exercising eviction logic, snapshot sizing,
/// and downstream consumers that just need "some sessions".
///
/// # Panics
/// Panics if any constructed id violates the validation rules in `spt_core`.
///
/// # Examples
///
/// ```
/// use spt_stats::testing::populated_table;
///
/// let t = populated_table(3);
/// assert_eq!(t.len(), 3);
/// ```
#[must_use]
pub fn populated_table(rows: usize) -> SessionTable {
    let table = SessionTable::new();
    let opened: DateTime<Utc> = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
    for i in 0..rows {
        let sid = SessionId::new(format!("s{i}")).expect("synthetic session id");
        table.insert(SessionEntry {
            session_id: sid,
            profile_id: ProfileId::new("p").expect("synthetic profile id"),
            opened_at: opened,
            remote_endpoint: format!("host{i}:22"),
            last_activity: opened + chrono::Duration::seconds(i as i64),
            bytes_in: u64::try_from(i).unwrap_or(0) * 100,
            bytes_out: u64::try_from(i).unwrap_or(0) * 200,
        });
    }
    table
}

/// Synthetic [`ConnectionTable`] with `rows` entries.
///
/// All connections share the same session id `s0`; each entry's
/// `forward_id` cycles through `f0..=f2`.
///
/// # Panics
/// Panics if any constructed id violates `spt_core` validation.
///
/// # Examples
///
/// ```
/// use spt_stats::testing::populated_connection_table;
///
/// let t = populated_connection_table(4);
/// assert_eq!(t.len(), 4);
/// ```
#[must_use]
pub fn populated_connection_table(rows: usize) -> ConnectionTable {
    let table = ConnectionTable::new();
    let opened: DateTime<Utc> = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
    for i in 0..rows {
        let cid = ConnectionId::new(format!("c{i}")).expect("synthetic conn id");
        let fid = ForwardId::new(format!("f{}", i % 3)).expect("synthetic forward id");
        table.insert(ConnectionEntry {
            connection_id: cid,
            session_id: SessionId::new("s0").expect("synthetic session id"),
            forward_id: fid,
            opened_at: opened,
            peer: format!("10.0.0.{}:55000", i % 250),
            local: "127.0.0.1:5000".into(),
            bytes_in: 0,
            bytes_out: 0,
        });
    }
    table
}

/// Build an [`Ewma`] with a 1-second time constant and feed it `values`,
/// each spaced 1 second apart.
///
/// # Examples
///
/// ```
/// use spt_stats::testing::fake_ewma;
///
/// let e = fake_ewma(&[10.0, 10.0, 10.0]);
/// // After three identical samples the EWMA has converged toward 10.0.
/// assert!((e.value().unwrap() - 10.0).abs() < 1.0);
/// ```
#[must_use]
pub fn fake_ewma(values: &[f64]) -> Ewma {
    let e = Ewma::new(Duration::from_secs(1));
    for v in values {
        e.sample(*v, Duration::from_secs(1));
    }
    e
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn populated_counter_sums_ticks() {
        let c = populated_counter(
            Duration::from_secs(30),
            &[
                (Duration::ZERO, 5),
                (Duration::from_secs(1), 10),
                (Duration::from_secs(2), 15),
            ],
        );
        assert_eq!(c.sum_over_window(), 30);
    }

    #[test]
    fn populated_counter_drops_old_ticks() {
        let c = populated_counter(
            Duration::from_secs(5),
            &[(Duration::ZERO, 7), (Duration::from_secs(10), 3)],
        );
        // The first tick fell off the 5s window; only the second remains.
        assert_eq!(c.sum_over_window(), 3);
    }

    #[test]
    fn populated_table_has_expected_rows() {
        let t = populated_table(5);
        assert_eq!(t.len(), 5);
        let s = t.snapshot();
        assert_eq!(s.len(), 5);
        // Order is unspecified; check by id collection.
        let mut ids: Vec<_> = s
            .iter()
            .map(|e| e.session_id.as_str().to_string())
            .collect();
        ids.sort();
        assert_eq!(ids, vec!["s0", "s1", "s2", "s3", "s4"]);
    }

    #[test]
    fn populated_connection_table_cycles_forward_ids() {
        let t = populated_connection_table(6);
        let f0 = t.for_forward(&ForwardId::new("f0").unwrap());
        let f1 = t.for_forward(&ForwardId::new("f1").unwrap());
        let f2 = t.for_forward(&ForwardId::new("f2").unwrap());
        assert_eq!(f0.len() + f1.len() + f2.len(), 6);
    }

    #[test]
    fn fake_ewma_primes_first_sample() {
        let e = fake_ewma(&[42.0]);
        assert_eq!(e.value(), Some(42.0));
    }
}
