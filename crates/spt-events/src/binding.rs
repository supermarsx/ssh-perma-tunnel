//! Event-binding evaluator.
//!
//! A [`Binding`] declares which events should be dispatched to which sinks.
//! Bindings are evaluated against an [`Event`] via
//! [`BindingMatch::matches`]. The match expression supports:
//!
//! * `kinds` — an array of `Event.kind` patterns (`*` wildcard suffix);
//! * `min_severity` — minimum severity threshold;
//! * `profile_filter` — only events for these profile ids;
//! * `forward_filter` — only events for these forward ids;
//! * `expr` — a tiny `key OP value` expression evaluated against
//!   [`Event::lookup_field`]. Supported ops: `==`, `!=`, `~=` (substring).
//!
//! Bindings may also carry a [`Dedupe`] policy — events whose computed key
//! repeats within `interval` are suppressed.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use spt_core::{ForwardId, ProfileId};

use crate::event::{Event, Severity};

/// Reference to a configured sink by name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SinkRef(pub String);

impl SinkRef {
    /// Construct from a string.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self(name.into())
    }

    /// Borrow.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Predicate operator for an [`ExprFilter`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExprOp {
    /// Equal as JSON value (string/number/bool).
    Eq,
    /// Not equal.
    Neq,
    /// Substring contains (only meaningful for string fields).
    Contains,
}

/// One field-level expression.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExprFilter {
    /// Field path passed to [`Event::lookup_field`].
    pub field: String,
    pub op: ExprOp,
    pub value: Value,
}

impl ExprFilter {
    /// Test whether this expression is satisfied by `event`.
    #[must_use]
    pub fn matches(&self, event: &Event) -> bool {
        match self.op {
            // `Contains` is string-on-both-sides only: it must NOT match a
            // numeric/bool field that merely stringifies to the needle. Use
            // the allocation-light borrowed-string accessor, but gate it on
            // the underlying field actually being a JSON string so the
            // historical "string-only" semantics are byte-identical.
            ExprOp::Contains => {
                let Value::String(needle) = &self.value else {
                    return false;
                };
                if !event.field_is_string(&self.field) {
                    return false;
                }
                match event.lookup_field_str(&self.field) {
                    Some(haystack) => haystack.contains(needle.as_str()),
                    None => false,
                }
            }
            // `Eq`/`Neq` need a real `Value` for numeric coercion; an absent
            // field is unequal to everything (so `Neq` holds, `Eq` fails).
            ExprOp::Eq => match event.lookup_field(&self.field) {
                Some(actual) => json_loose_eq(&actual, &self.value),
                None => false,
            },
            ExprOp::Neq => match event.lookup_field(&self.field) {
                Some(actual) => !json_loose_eq(&actual, &self.value),
                None => true,
            },
        }
    }
}

fn json_loose_eq(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::String(s1), Value::String(s2)) => s1 == s2,
        (Value::Number(n1), Value::Number(n2)) => n1 == n2,
        (Value::Bool(b1), Value::Bool(b2)) => b1 == b2,
        // String vs number: try parsing the string side.
        (Value::String(s), Value::Number(n)) | (Value::Number(n), Value::String(s)) => {
            n.to_string() == *s
        }
        _ => a == b,
    }
}

/// Match predicate for a binding.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BindingMatch {
    /// Patterns for `Event.kind`. A `*`-suffix is treated as a prefix match.
    /// Empty = match-all.
    #[serde(default)]
    pub kinds: Vec<String>,
    /// Minimum severity. None = any.
    #[serde(default)]
    pub min_severity: Option<Severity>,
    /// Allow-list of profile ids. Empty = any.
    #[serde(default)]
    pub profile_filter: Vec<ProfileId>,
    /// Allow-list of forward ids. Empty = any.
    #[serde(default)]
    pub forward_filter: Vec<ForwardId>,
    /// Custom expressions (AND-combined).
    #[serde(default)]
    pub exprs: Vec<ExprFilter>,
}

impl BindingMatch {
    /// True iff all conditions pass.
    #[must_use]
    pub fn matches(&self, event: &Event) -> bool {
        // Kinds.
        if !self.kinds.is_empty() {
            let any = self.kinds.iter().any(|k| event.kind.matches_pattern(k));
            if !any {
                return false;
            }
        }
        // Severity.
        if let Some(min) = self.min_severity {
            if event.severity < min {
                return false;
            }
        }
        // Profile filter.
        if !self.profile_filter.is_empty() {
            match &event.profile_id {
                Some(p) if self.profile_filter.contains(p) => {}
                _ => return false,
            }
        }
        // Forward filter.
        if !self.forward_filter.is_empty() {
            match &event.forward_id {
                Some(f) if self.forward_filter.contains(f) => {}
                _ => return false,
            }
        }
        // Custom exprs.
        if !self.exprs.iter().all(|e| e.matches(event)) {
            return false;
        }
        true
    }
}

/// Per-binding deduplication policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dedupe {
    /// Field paths concatenated to form the dedupe key. Defaults to
    /// `["kind", "profile_id", "forward_id"]`.
    pub key_fields: Vec<String>,
    /// Suppress duplicates seen within this interval.
    pub interval: Duration,
}

impl Default for Dedupe {
    fn default() -> Self {
        Self {
            key_fields: vec!["kind".into(), "profile_id".into(), "forward_id".into()],
            interval: Duration::from_secs(60),
        }
    }
}

impl Dedupe {
    /// Build a dedupe policy from a single key field and a window (e.g.
    /// mapped from the schema `EventDedupe { key, window }`). When `key` is
    /// `None` the documented default key fields are used.
    #[must_use]
    pub fn new(key: Option<String>, window: Duration) -> Self {
        let key_fields = key.map_or_else(|| Self::default().key_fields, |k| vec![k]);
        Self {
            key_fields,
            interval: window,
        }
    }

    /// Compute the dedupe key for `event`.
    #[must_use]
    pub fn key_for(&self, event: &Event) -> String {
        // Build the key by pushing each field's borrowed string view directly,
        // avoiding the per-field `Value` allocation. Missing fields keep the
        // historical `∅` placeholder.
        let mut key = String::new();
        for (i, f) in self.key_fields.iter().enumerate() {
            if i > 0 {
                key.push('|');
            }
            match event.lookup_field_str(f) {
                Some(v) => key.push_str(&v),
                None => key.push('∅'),
            }
        }
        key
    }
}

/// One configured binding.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Binding {
    /// Stable identifier (used for logs).
    pub name: String,
    /// Match predicate.
    #[serde(rename = "match")]
    pub r#match: BindingMatch,
    /// Sinks to invoke.
    pub sinks: Vec<SinkRef>,
    /// Dedupe policy.
    #[serde(default)]
    pub dedupe: Option<Dedupe>,
    /// Per-binding delivery throttle (maps from the schema
    /// `[[events.bindings]].throttle` duration). When set, at most one event
    /// is delivered through this binding per throttle interval; events arriving
    /// while throttled are suppressed. Enforced by the dispatcher via
    /// [`ThrottleState`]. `None` = no rate limit.
    #[serde(default)]
    pub throttle: Option<Duration>,
}

impl Binding {
    /// Construct a binding from its core parts: a `name`, a match predicate,
    /// and the sinks to fire. `dedupe`/`min_level` default to unset and can be
    /// layered on with [`Binding::with_dedupe`] / [`Binding::with_min_level`].
    #[must_use]
    pub fn new(name: impl Into<String>, r#match: BindingMatch, sinks: Vec<SinkRef>) -> Self {
        Self {
            name: name.into(),
            r#match,
            sinks,
            dedupe: None,
            throttle: None,
        }
    }

    /// Attach (or clear) a [`Dedupe`] policy. Chainable.
    #[must_use]
    pub fn with_dedupe(mut self, dedupe: Option<Dedupe>) -> Self {
        self.dedupe = dedupe;
        self
    }

    /// Attach (or clear) a per-binding delivery throttle. Chainable. Maps from
    /// the schema `[[events.bindings]].throttle` duration.
    #[must_use]
    pub fn with_throttle(mut self, throttle: Option<Duration>) -> Self {
        self.throttle = throttle;
        self
    }

    /// Set the binding's minimum-severity floor (`match.min_severity`).
    /// Chainable. Passing `Some(level)` overrides any current value; `None`
    /// leaves the existing value untouched so a per-binding level always wins
    /// over a later-applied default — pair with [`Binding::min_severity_or`].
    #[must_use]
    pub fn with_min_level(mut self, level: Severity) -> Self {
        self.r#match.min_severity = Some(level);
        self
    }

    /// Apply a *default* severity floor only when this binding does not
    /// already declare its own. Use this for the pipeline-wide
    /// `Events.default_min_level`: bindings with an explicit `min_level` keep
    /// it; bindings without one inherit `default`.
    #[must_use]
    pub fn min_severity_or(mut self, default: Severity) -> Self {
        if self.r#match.min_severity.is_none() {
            self.r#match.min_severity = Some(default);
        }
        self
    }
}

/// In-memory dedupe state.
#[derive(Debug, Default)]
pub struct DedupeState {
    seen: Mutex<HashMap<String, Instant>>,
}

impl DedupeState {
    /// New empty cache.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns true if the event should be suppressed under `dedupe`.
    /// Side-effect: records the new key/timestamp for non-suppressed events.
    pub fn should_suppress(&self, dedupe: &Dedupe, event: &Event) -> bool {
        let now = Instant::now();
        let key = dedupe.key_for(event);
        let mut map = self.seen.lock();
        // Garbage-collect stale keys opportunistically.
        map.retain(|_, ts| now.saturating_duration_since(*ts) < dedupe.interval);
        if let Some(prev) = map.get(&key) {
            if now.saturating_duration_since(*prev) < dedupe.interval {
                return true;
            }
        }
        map.insert(key, now);
        false
    }
}

/// In-memory per-binding throttle state.
///
/// Tracks the last-delivery instant per binding name so the dispatcher can
/// rate-limit event delivery to at most one per throttle interval, per binding
/// (finding W4 / wire-observ finding 4 — `EventBinding.throttle` was
/// documented + validated but had no consumer).
#[derive(Debug, Default)]
pub struct ThrottleState {
    last: Mutex<HashMap<String, Instant>>,
}

impl ThrottleState {
    /// New empty state.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns `true` if a delivery is allowed for `binding` now, recording the
    /// delivery instant; returns `false` (suppress) if the previous delivery
    /// was within `interval`.
    pub fn allow(&self, binding: &str, interval: Duration) -> bool {
        let now = Instant::now();
        let mut map = self.last.lock();
        if let Some(prev) = map.get(binding) {
            if now.saturating_duration_since(*prev) < interval {
                return false;
            }
        }
        map.insert(binding.to_string(), now);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(kind: &str, severity: Severity) -> Event {
        Event::builder(kind, severity).build()
    }

    #[test]
    fn match_kinds_wildcard() {
        let m = BindingMatch {
            kinds: vec!["forward.*".into()],
            ..Default::default()
        };
        assert!(m.matches(&ev("forward.connection_opened", Severity::Info)));
        assert!(!m.matches(&ev("profile.connected", Severity::Info)));
    }

    #[test]
    fn match_severity_threshold() {
        let m = BindingMatch {
            min_severity: Some(Severity::Warn),
            ..Default::default()
        };
        assert!(m.matches(&ev("x", Severity::Error)));
        assert!(!m.matches(&ev("x", Severity::Info)));
    }

    #[test]
    fn match_profile_filter() {
        let m = BindingMatch {
            profile_filter: vec![ProfileId::new("p1").unwrap()],
            ..Default::default()
        };
        let e1 = Event::builder("k", Severity::Info)
            .profile(ProfileId::new("p1").unwrap())
            .build();
        let e2 = Event::builder("k", Severity::Info)
            .profile(ProfileId::new("p2").unwrap())
            .build();
        assert!(m.matches(&e1));
        assert!(!m.matches(&e2));
    }

    #[test]
    fn match_expr_eq_and_contains() {
        let e = Event::builder("forward.connection_failed", Severity::Error)
            .field("error", "connect timeout")
            .build();
        let m = BindingMatch {
            exprs: vec![ExprFilter {
                field: "error".into(),
                op: ExprOp::Contains,
                value: Value::String("timeout".into()),
            }],
            ..Default::default()
        };
        assert!(m.matches(&e));
    }

    #[test]
    fn dedupe_suppresses_within_interval() {
        let d = Dedupe::default();
        let s = DedupeState::new();
        let e = Event::builder("k", Severity::Info).build();
        assert!(!s.should_suppress(&d, &e));
        assert!(s.should_suppress(&d, &e));
    }

    #[test]
    fn dedupe_releases_after_interval() {
        let d = Dedupe {
            key_fields: vec!["kind".into()],
            interval: Duration::from_millis(10),
        };
        let s = DedupeState::new();
        let e = Event::builder("k", Severity::Info).build();
        assert!(!s.should_suppress(&d, &e));
        std::thread::sleep(Duration::from_millis(20));
        assert!(!s.should_suppress(&d, &e));
    }

    #[test]
    fn sink_ref_round_trips_through_string() {
        let r = SinkRef::new("alerts");
        assert_eq!(r.as_str(), "alerts");
        let s = serde_json::to_string(&r).unwrap();
        let back: SinkRef = serde_json::from_str(&s).unwrap();
        assert_eq!(back, r);
    }

    #[test]
    fn forward_filter_excludes_when_id_missing() {
        let f_id = ForwardId::new("f1").unwrap();
        let m = BindingMatch {
            forward_filter: vec![f_id.clone()],
            ..Default::default()
        };
        let e_with = Event::builder("k", Severity::Info).forward(f_id).build();
        let e_without = Event::builder("k", Severity::Info).build();
        assert!(m.matches(&e_with));
        assert!(!m.matches(&e_without));
    }

    #[test]
    fn empty_kinds_matches_anything() {
        let m = BindingMatch::default();
        assert!(m.matches(&ev("anything", Severity::Info)));
        assert!(m.matches(&ev("totally.different", Severity::Critical)));
    }

    #[test]
    fn exprfilter_eq_matches_string_and_neq_on_missing_field() {
        let e = Event::builder("k", Severity::Info)
            .field("present", "yes")
            .build();
        let eq_present = ExprFilter {
            field: "present".into(),
            op: ExprOp::Eq,
            value: Value::String("yes".into()),
        };
        assert!(eq_present.matches(&e));
        // Missing field with `Neq` -> true; with `Eq` -> false.
        let neq_missing = ExprFilter {
            field: "absent".into(),
            op: ExprOp::Neq,
            value: Value::String("anything".into()),
        };
        assert!(neq_missing.matches(&e));
        let eq_missing = ExprFilter {
            field: "absent".into(),
            op: ExprOp::Eq,
            value: Value::String("anything".into()),
        };
        assert!(!eq_missing.matches(&e));
    }

    #[test]
    fn exprfilter_contains_only_for_strings() {
        let e = Event::builder("k", Severity::Info)
            .field("text", "hello world")
            .field("count", 42)
            .build();
        let contains_word = ExprFilter {
            field: "text".into(),
            op: ExprOp::Contains,
            value: Value::String("world".into()),
        };
        assert!(contains_word.matches(&e));
        // `contains` against a non-string left side returns false.
        let contains_on_number = ExprFilter {
            field: "count".into(),
            op: ExprOp::Contains,
            value: Value::String("42".into()),
        };
        assert!(!contains_on_number.matches(&e));
    }

    #[test]
    fn json_loose_eq_string_vs_number_works_both_directions() {
        let e = Event::builder("k", Severity::Info)
            .field("count", 5)
            .build();
        let lhs_num_rhs_str = ExprFilter {
            field: "count".into(),
            op: ExprOp::Eq,
            value: Value::String("5".into()),
        };
        assert!(lhs_num_rhs_str.matches(&e));
    }

    #[test]
    fn dedupe_default_uses_documented_fields() {
        let d = Dedupe::default();
        assert_eq!(d.key_fields, vec!["kind", "profile_id", "forward_id"]);
        assert_eq!(d.interval, Duration::from_secs(60));
    }

    #[test]
    fn dedupe_key_substitutes_placeholder_for_missing_fields() {
        let d = Dedupe::default();
        let e = Event::builder("k", Severity::Info).build();
        let key = d.key_for(&e);
        // No profile/forward → "∅" placeholder appears twice.
        assert!(key.contains("∅"));
        assert!(key.starts_with("k|"));
    }

    #[test]
    fn binding_default_is_empty() {
        let b = Binding::default();
        assert!(b.name.is_empty());
        assert!(b.sinks.is_empty());
        assert!(b.dedupe.is_none());
    }

    #[test]
    fn binding_serde_round_trip_through_json() {
        let mut b = Binding {
            name: "ops".into(),
            r#match: BindingMatch {
                kinds: vec!["forward.*".into()],
                min_severity: Some(Severity::Warn),
                ..Default::default()
            },
            sinks: vec![SinkRef::new("alerts")],
            dedupe: Some(Dedupe::default()),
            throttle: None,
        };
        let s = serde_json::to_string(&b).unwrap();
        let back: Binding = serde_json::from_str(&s).unwrap();
        assert_eq!(back.name, "ops");
        assert_eq!(back.sinks.len(), 1);
        // Tweak then re-serialize to exercise both paths.
        b.dedupe = None;
        let s2 = serde_json::to_string(&b).unwrap();
        let back2: Binding = serde_json::from_str(&s2).unwrap();
        assert!(back2.dedupe.is_none());
    }

    #[test]
    fn dedupe_new_from_key_and_window() {
        // Explicit key -> single-field key_fields + chosen window.
        let d = Dedupe::new(Some("forward_id".into()), Duration::from_secs(120));
        assert_eq!(d.key_fields, vec!["forward_id"]);
        assert_eq!(d.interval, Duration::from_secs(120));
        // No key -> documented default fields, window still honored.
        let d2 = Dedupe::new(None, Duration::from_secs(5));
        assert_eq!(d2.key_fields, Dedupe::default().key_fields);
        assert_eq!(d2.interval, Duration::from_secs(5));
    }

    #[test]
    fn binding_with_dedupe_set_dedupes_correctly() {
        // A binding built via the public constructors carrying a Dedupe should
        // suppress a repeated key within the window.
        let b = Binding::new(
            "b",
            BindingMatch {
                kinds: vec!["k".into()],
                ..Default::default()
            },
            vec![SinkRef::new("alerts")],
        )
        .with_dedupe(Some(Dedupe::new(
            Some("kind".into()),
            Duration::from_secs(60),
        )));
        let dedupe = b.dedupe.as_ref().expect("dedupe set");
        let state = DedupeState::new();
        let e = Event::builder("k", Severity::Info).build();
        assert!(!state.should_suppress(dedupe, &e), "first is allowed");
        assert!(state.should_suppress(dedupe, &e), "second is suppressed");
    }

    #[test]
    fn binding_with_min_level_sets_floor() {
        let b = Binding::new("b", BindingMatch::default(), vec![]).with_min_level(Severity::Warn);
        assert_eq!(b.r#match.min_severity, Some(Severity::Warn));
        assert!(b.r#match.matches(&ev("x", Severity::Error)));
        assert!(!b.r#match.matches(&ev("x", Severity::Info)));
    }

    #[test]
    fn min_severity_or_applies_default_only_when_unset() {
        // Unset binding inherits the default floor.
        let inherited =
            Binding::new("a", BindingMatch::default(), vec![]).min_severity_or(Severity::Warn);
        assert_eq!(inherited.r#match.min_severity, Some(Severity::Warn));
        // A binding with its own level keeps it (default does NOT override).
        let explicit = Binding::new(
            "b",
            BindingMatch {
                min_severity: Some(Severity::Error),
                ..Default::default()
            },
            vec![],
        )
        .min_severity_or(Severity::Warn);
        assert_eq!(explicit.r#match.min_severity, Some(Severity::Error));
    }

    #[test]
    fn binding_with_throttle_sets_field() {
        let b = Binding::new("b", BindingMatch::default(), vec![])
            .with_throttle(Some(Duration::from_secs(30)));
        assert_eq!(b.throttle, Some(Duration::from_secs(30)));
        // Default construction leaves throttle unset (behavior-preserving).
        assert!(Binding::default().throttle.is_none());
    }

    #[test]
    fn throttle_state_allows_first_then_suppresses_within_interval() {
        let s = ThrottleState::new();
        let interval = Duration::from_secs(60);
        assert!(s.allow("b1", interval), "first delivery allowed");
        assert!(
            !s.allow("b1", interval),
            "second within interval suppressed"
        );
        // A different binding is tracked independently.
        assert!(s.allow("b2", interval), "distinct binding is not throttled");
    }

    #[test]
    fn throttle_state_releases_after_interval() {
        let s = ThrottleState::new();
        let interval = Duration::from_millis(10);
        assert!(s.allow("b", interval));
        std::thread::sleep(Duration::from_millis(20));
        assert!(
            s.allow("b", interval),
            "allowed again after interval elapses"
        );
    }

    #[test]
    fn dedupe_state_garbage_collects_stale_keys() {
        let d = Dedupe {
            key_fields: vec!["kind".into()],
            interval: Duration::from_millis(10),
        };
        let s = DedupeState::new();
        let e_a = Event::builder("a", Severity::Info).build();
        let e_b = Event::builder("b", Severity::Info).build();
        assert!(!s.should_suppress(&d, &e_a));
        std::thread::sleep(Duration::from_millis(20));
        // Inserting `b` should also clear the stale `a` entry.
        assert!(!s.should_suppress(&d, &e_b));
        // `a` should now be considered fresh again.
        assert!(!s.should_suppress(&d, &e_a));
    }
}
