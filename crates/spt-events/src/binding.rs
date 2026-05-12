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
        let Some(actual) = event.lookup_field(&self.field) else {
            return matches!(self.op, ExprOp::Neq);
        };
        match self.op {
            ExprOp::Eq => json_loose_eq(&actual, &self.value),
            ExprOp::Neq => !json_loose_eq(&actual, &self.value),
            ExprOp::Contains => match (&actual, &self.value) {
                (Value::String(a), Value::String(b)) => a.contains(b.as_str()),
                _ => false,
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
    /// Compute the dedupe key for `event`.
    #[must_use]
    pub fn key_for(&self, event: &Event) -> String {
        let parts: Vec<String> = self
            .key_fields
            .iter()
            .map(|f| match event.lookup_field(f) {
                Some(Value::String(s)) => s,
                Some(other) => other.to_string(),
                None => String::from("∅"),
            })
            .collect();
        parts.join("|")
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
}
