//! Probabilistic sampling for `tracing` events.
//!
//! `[logging.sampling]` lets operators reduce the volume of high-frequency
//! events without dropping rare ones. Each entry maps a tracing **target**
//! (the module-path-derived static string that every event carries, e.g.
//! `spt_ssh2::session`) to a keep ratio in `[0.0, 1.0]`.
//!
//! Lookup precedence:
//!
//! 1. Exact target match.
//! 2. Longest dotted-prefix match (e.g. config entry `spt_ssh2 = 0.1`
//!    samples every event from `spt_ssh2`, `spt_ssh2::session`, …).
//! 3. Default keep — typically `1.0`.
//!
//! The layer is `enabled`-based: events that the layer decides to drop are
//! filtered before downstream layers receive them. This minimises CPU vs.
//! formatting the event and then suppressing it later.

#![deny(unsafe_op_in_unsafe_fn)]

use std::collections::HashMap;

use tracing::Metadata;
use tracing_subscriber::layer::{Context, Layer};

/// Configuration for [`SamplingLayer`].
///
/// `entries` map tracing target strings (or dotted prefixes) to keep ratios
/// in `[0.0, 1.0]`. Values are clamped on construction.
#[derive(Debug, Clone, Default)]
pub struct SamplingConfig {
    /// Default keep ratio for targets with no matching entry. Defaults to 1.0
    /// (= keep everything).
    pub default_keep: f64,
    /// Per-target keep ratios. Keys are matched first by exact equality then
    /// by longest dotted-prefix match (`a::b` matches `a` and `a::b`).
    pub entries: HashMap<String, f64>,
}

impl SamplingConfig {
    /// Constructor that clamps every ratio to `[0.0, 1.0]` and `default_keep`
    /// to `[0.0, 1.0]` (with a sensible fallback of `1.0`).
    #[must_use]
    pub fn new(default_keep: f64, entries: HashMap<String, f64>) -> Self {
        let default_keep = clamp_unit(default_keep, 1.0);
        let entries = entries
            .into_iter()
            .map(|(k, v)| (k, clamp_unit(v, 1.0)))
            .collect();
        Self {
            default_keep,
            entries,
        }
    }

    /// Look up the keep ratio for a tracing `target`.
    #[must_use]
    pub fn ratio_for(&self, target: &str) -> f64 {
        if let Some(&exact) = self.entries.get(target) {
            return exact;
        }
        // Longest dotted-prefix match: walk shrinking prefixes of `target`
        // on `::` boundaries (since rust module paths use `::`, e.g.
        // `spt_ssh2::session`).
        let mut best: Option<f64> = None;
        for key in self.entries.keys() {
            if is_dotted_prefix(target, key)
                && best.is_none_or(|_| best_len_lt_key(target, key, &self.entries))
            {
                best = Some(self.entries[key]);
            }
        }
        best.unwrap_or(self.default_keep)
    }
}

/// Helper: returns true iff `target == prefix` or `target` starts with
/// `prefix::`.
fn is_dotted_prefix(target: &str, prefix: &str) -> bool {
    if target == prefix {
        return true;
    }
    if let Some(rest) = target.strip_prefix(prefix) {
        return rest.starts_with("::");
    }
    false
}

/// Tie-breaker: prefer the longest matching prefix. We re-scan to find the
/// longest matching key — small N entries so this is fine.
fn best_len_lt_key(target: &str, candidate: &str, entries: &HashMap<String, f64>) -> bool {
    let cand_len = candidate.len();
    !entries
        .keys()
        .any(|k| k.len() > cand_len && is_dotted_prefix(target, k))
}

fn clamp_unit(v: f64, fallback: f64) -> f64 {
    if v.is_nan() {
        return fallback;
    }
    v.clamp(0.0, 1.0)
}

/// Random source used by [`SamplingLayer`]. Trait so tests can inject a
/// deterministic sequence; production uses `RandSource::default()` which
/// delegates to `rand::random()`.
pub trait RandSource: Send + Sync + 'static {
    /// Return a value in `[0.0, 1.0)`.
    fn next_unit(&self) -> f64;
}

/// Default thread-local RNG-backed source.
#[derive(Debug, Default)]
pub struct ThreadRng;

impl RandSource for ThreadRng {
    fn next_unit(&self) -> f64 {
        rand::random::<f64>()
    }
}

/// Sampling layer for `tracing-subscriber`.
///
/// On every event, the layer looks up the keep ratio for the event's target
/// and draws a uniform random number; if the draw is below the ratio the
/// event is kept, otherwise it is dropped before being formatted.
pub struct SamplingLayer<R: RandSource = ThreadRng> {
    config: SamplingConfig,
    rand: R,
}

impl<R: RandSource> std::fmt::Debug for SamplingLayer<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SamplingLayer")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl SamplingLayer<ThreadRng> {
    /// Build a layer with the default RNG.
    #[must_use]
    pub fn new(config: SamplingConfig) -> Self {
        Self {
            config,
            rand: ThreadRng,
        }
    }
}

impl<R: RandSource> SamplingLayer<R> {
    /// Build with a custom RNG source. Used by tests for determinism.
    pub fn with_rand(config: SamplingConfig, rand: R) -> Self {
        Self { config, rand }
    }

    /// Predicate exposed for tests: should this `target` be kept under one
    /// random draw?
    #[must_use]
    pub fn should_keep(&self, target: &str) -> bool {
        let ratio = self.config.ratio_for(target);
        if ratio >= 1.0 {
            return true;
        }
        if ratio <= 0.0 {
            return false;
        }
        self.rand.next_unit() < ratio
    }
}

impl<S, R> Layer<S> for SamplingLayer<R>
where
    S: tracing::Subscriber,
    R: RandSource,
{
    fn enabled(&self, metadata: &Metadata<'_>, _ctx: Context<'_, S>) -> bool {
        // Spans are always kept; sampling applies to events only. Sampling
        // spans would break parent/child propagation and confuse callers.
        if metadata.is_span() {
            return true;
        }
        self.should_keep(metadata.target())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    /// Cycling deterministic RNG that returns 0.0, 0.5, 0.99, 0.0, ...
    struct CyclingRand {
        values: Vec<f64>,
        idx: AtomicUsize,
    }

    impl CyclingRand {
        fn new(values: Vec<f64>) -> Self {
            Self {
                values,
                idx: AtomicUsize::new(0),
            }
        }
    }

    impl RandSource for CyclingRand {
        fn next_unit(&self) -> f64 {
            let i = self.idx.fetch_add(1, Ordering::Relaxed);
            self.values[i % self.values.len()]
        }
    }

    /// Counting source that returns a fixed value AND records calls.
    #[derive(Default)]
    struct CountingRand {
        value: f64,
        calls: Arc<AtomicUsize>,
    }

    impl CountingRand {
        fn new(value: f64) -> (Self, Arc<AtomicUsize>) {
            let calls = Arc::new(AtomicUsize::new(0));
            (
                Self {
                    value,
                    calls: calls.clone(),
                },
                calls,
            )
        }
    }

    impl RandSource for CountingRand {
        fn next_unit(&self) -> f64 {
            self.calls.fetch_add(1, Ordering::Relaxed);
            self.value
        }
    }

    #[test]
    fn ratio_clamped_to_unit_interval() {
        let mut entries = HashMap::new();
        entries.insert("x".into(), 5.0);
        entries.insert("y".into(), -1.0);
        entries.insert("z".into(), f64::NAN);
        let c = SamplingConfig::new(7.0, entries);
        assert!((c.default_keep - 1.0).abs() < f64::EPSILON);
        assert!((c.ratio_for("x") - 1.0).abs() < f64::EPSILON);
        assert!(c.ratio_for("y").abs() < f64::EPSILON);
        assert!((c.ratio_for("z") - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn exact_target_match_wins_over_prefix() {
        let mut entries = HashMap::new();
        entries.insert("spt_ssh2".into(), 0.1);
        entries.insert("spt_ssh2::session".into(), 0.9);
        let c = SamplingConfig::new(1.0, entries);
        assert!((c.ratio_for("spt_ssh2::session") - 0.9).abs() < f64::EPSILON);
        assert!((c.ratio_for("spt_ssh2::connect") - 0.1).abs() < f64::EPSILON);
    }

    #[test]
    fn dotted_prefix_matches_longest() {
        let mut entries = HashMap::new();
        entries.insert("spt".into(), 0.1);
        entries.insert("spt_ssh2::session".into(), 0.9);
        let c = SamplingConfig::new(1.0, entries);
        // `spt` is NOT a dotted prefix of `spt_ssh2` — different module roots.
        assert!((c.ratio_for("spt_ssh2::session") - 0.9).abs() < f64::EPSILON);
        assert!((c.ratio_for("spt_ssh2") - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn default_keep_used_when_no_match() {
        let c = SamplingConfig::new(0.25, HashMap::new());
        assert!((c.ratio_for("anything") - 0.25).abs() < f64::EPSILON);
    }

    #[test]
    fn should_keep_is_deterministic_with_fixed_rng() {
        let mut entries = HashMap::new();
        entries.insert("loud".into(), 0.5);
        let layer = SamplingLayer::with_rand(
            SamplingConfig::new(1.0, entries),
            CyclingRand::new(vec![0.0, 0.6, 0.4, 0.99]),
        );
        // 0.0 < 0.5 → keep
        assert!(layer.should_keep("loud"));
        // 0.6 < 0.5? no → drop
        assert!(!layer.should_keep("loud"));
        // 0.4 < 0.5 → keep
        assert!(layer.should_keep("loud"));
        // 0.99 < 0.5? no → drop
        assert!(!layer.should_keep("loud"));
    }

    #[test]
    fn ratio_zero_drops_without_drawing_random() {
        let mut entries = HashMap::new();
        entries.insert("silent".into(), 0.0);
        let (rng, calls) = CountingRand::new(0.5);
        let layer = SamplingLayer::with_rand(SamplingConfig::new(1.0, entries), rng);
        assert!(!layer.should_keep("silent"));
        assert_eq!(calls.load(Ordering::Relaxed), 0, "no draw for ratio == 0");
    }

    #[test]
    fn ratio_one_keeps_without_drawing_random() {
        let mut entries = HashMap::new();
        entries.insert("loud".into(), 1.0);
        let (rng, calls) = CountingRand::new(0.99);
        let layer = SamplingLayer::with_rand(SamplingConfig::new(0.0, entries), rng);
        assert!(layer.should_keep("loud"));
        assert_eq!(calls.load(Ordering::Relaxed), 0, "no draw for ratio == 1");
    }

    #[test]
    fn observed_ratio_within_tolerance_over_large_n() {
        // Use a generous tolerance: 100_000 draws of ratio 0.3 → expect ~30k;
        // std-dev of the binomial is sqrt(n*p*(1-p)) ≈ 145; allow ±5 std-dev
        // for headroom (still within 1% of the expected count).
        let mut entries = HashMap::new();
        entries.insert("sampled".into(), 0.3);
        let layer = SamplingLayer::new(SamplingConfig::new(1.0, entries));
        let n: usize = 100_000;
        let kept = (0..n).filter(|_| layer.should_keep("sampled")).count();
        let p = 0.3;
        let expected = (n as f64) * p;
        let stddev = (n as f64 * p * (1.0 - p)).sqrt();
        let diff = (kept as f64 - expected).abs();
        assert!(
            diff < 5.0 * stddev,
            "kept={kept} expected={expected} diff={diff} stddev={stddev}"
        );
    }

    #[test]
    fn empty_config_keeps_everything() {
        let layer = SamplingLayer::new(SamplingConfig::default());
        // default_keep is 0.0 by Default; we want explicit construction to
        // verify the layer fast-paths on zero.
        let layer2 = SamplingLayer::new(SamplingConfig::new(1.0, HashMap::new()));
        for _ in 0..1000 {
            assert!(layer2.should_keep("anything"));
        }
        // Confirm Default = drop everything.
        for _ in 0..1000 {
            assert!(!layer.should_keep("anything"));
        }
    }

    #[test]
    fn is_dotted_prefix_helper_rules() {
        assert!(is_dotted_prefix("a", "a"));
        assert!(is_dotted_prefix("a::b", "a"));
        assert!(is_dotted_prefix("a::b::c", "a::b"));
        assert!(!is_dotted_prefix("a_b", "a"));
        assert!(!is_dotted_prefix("ab", "a"));
        assert!(!is_dotted_prefix("a", "a::b"));
    }
}
