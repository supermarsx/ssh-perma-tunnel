//! Canonical `Event` type emitted by every spt subsystem.
//!
//! This is a richer type than `spt_state::Event`: it has a typed [`EventKind`]
//! enumerating the categories from spec §13.2, structured fields keyed by
//! string, and an explicit [`Severity`]. A converter [`Event::to_state_event`]
//! is provided so the bus can persist events through `spt-state::EventRing`.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use spt_core::{ConnectionId, EventId, ForwardId, ProfileId, SessionId};

/// Severity tier for an event. Matches spec §13.2 + §13.11.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
    Critical,
}

impl Severity {
    /// Parse a configuration string. Returns `None` on unknown input.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "trace" => Some(Self::Trace),
            "debug" => Some(Self::Debug),
            "info" => Some(Self::Info),
            "warn" | "warning" => Some(Self::Warn),
            "error" => Some(Self::Error),
            "critical" | "crit" | "fatal" => Some(Self::Critical),
            _ => None,
        }
    }

    /// Short string used in logs/JSON.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Trace => "trace",
            Self::Debug => "debug",
            Self::Info => "info",
            Self::Warn => "warn",
            Self::Error => "error",
            Self::Critical => "critical",
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Canonical event kind enumeration. We use a `String`-backed variant
/// instead of an exhaustive enum because the binding language (`on = [...]`)
/// has to support arbitrary user-defined kinds in addition to the well-known
/// ones from spec §13.2.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EventKind(String);

impl EventKind {
    /// Construct from a string.
    #[must_use]
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    /// Borrow.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// True if this event's kind matches a glob-style pattern.
    /// Supported wildcards: `*` at end matches any suffix; otherwise exact
    /// match.
    #[must_use]
    pub fn matches_pattern(&self, pat: &str) -> bool {
        if let Some(prefix) = pat.strip_suffix('*') {
            self.0.starts_with(prefix)
        } else {
            self.0 == pat
        }
    }
}

impl<S: Into<String>> From<S> for EventKind {
    fn from(s: S) -> Self {
        Self::new(s)
    }
}

impl std::fmt::Display for EventKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// One emitted event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    /// Globally-unique event identifier.
    #[serde(default = "EventId::new_v4")]
    pub id: EventId,
    /// Wall-clock UTC timestamp.
    pub ts: DateTime<Utc>,
    /// Event category (e.g. `"profile.connected"`).
    pub kind: EventKind,
    /// Severity.
    pub severity: Severity,
    /// Optional originating profile.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub profile_id: Option<ProfileId>,
    /// Optional originating forward.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub forward_id: Option<ForwardId>,
    /// Optional originating session.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub session_id: Option<SessionId>,
    /// Optional originating connection.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub connection_id: Option<ConnectionId>,
    /// Free-form structured fields. Keys MUST be ASCII-printable; values can
    /// be any JSON.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub fields: BTreeMap<String, Value>,
    /// Human-readable message.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub message: String,
}

impl Event {
    /// Start an event builder.
    #[must_use]
    pub fn builder(kind: impl Into<EventKind>, severity: Severity) -> EventBuilder {
        EventBuilder::new(kind, severity)
    }

    /// Convert to the simpler `spt_state::Event` for persistence in the
    /// daily JSONL ring.
    #[must_use]
    pub fn to_state_event(&self) -> spt_state::Event {
        let mut extra = serde_json::Map::new();
        extra.insert("id".into(), Value::String(self.id.as_str().to_owned()));
        if let Some(p) = &self.profile_id {
            extra.insert("profile_id".into(), Value::String(p.as_str().to_owned()));
        }
        if let Some(f) = &self.forward_id {
            extra.insert("forward_id".into(), Value::String(f.as_str().to_owned()));
        }
        if let Some(s) = &self.session_id {
            extra.insert("session_id".into(), Value::String(s.as_str().to_owned()));
        }
        if let Some(c) = &self.connection_id {
            extra.insert("connection_id".into(), Value::String(c.as_str().to_owned()));
        }
        for (k, v) in &self.fields {
            extra.entry(k.clone()).or_insert_with(|| v.clone());
        }
        if !self.message.is_empty() {
            extra
                .entry("message".to_string())
                .or_insert_with(|| Value::String(self.message.clone()));
        }
        spt_state::Event {
            ts: self.ts,
            kind: self.kind.as_str().to_owned(),
            severity: self.severity.as_str().to_owned(),
            extra: Value::Object(extra),
        }
    }

    /// Look up a field by dotted path (e.g. `"profile_id"`, `"fields.foo"`).
    /// Returns `None` if not found. Used by [`crate::template`] and binding
    /// expressions.
    #[must_use]
    pub fn lookup_field(&self, path: &str) -> Option<Value> {
        match path {
            "id" => Some(Value::String(self.id.as_str().to_owned())),
            "ts" => Some(Value::String(self.ts.to_rfc3339())),
            "kind" => Some(Value::String(self.kind.as_str().to_owned())),
            "severity" => Some(Value::String(self.severity.as_str().to_owned())),
            "message" => Some(Value::String(self.message.clone())),
            "profile_id" => self
                .profile_id
                .as_ref()
                .map(|p| Value::String(p.as_str().to_owned())),
            "forward_id" => self
                .forward_id
                .as_ref()
                .map(|f| Value::String(f.as_str().to_owned())),
            "session_id" => self
                .session_id
                .as_ref()
                .map(|s| Value::String(s.as_str().to_owned())),
            "connection_id" => self
                .connection_id
                .as_ref()
                .map(|c| Value::String(c.as_str().to_owned())),
            other => self.fields.get(other).cloned(),
        }
    }
}

/// Fluent builder for [`Event`].
#[derive(Debug)]
pub struct EventBuilder {
    inner: Event,
}

impl EventBuilder {
    /// Start at the given kind/severity.
    #[must_use]
    pub fn new(kind: impl Into<EventKind>, severity: Severity) -> Self {
        Self {
            inner: Event {
                id: EventId::new_v4(),
                ts: Utc::now(),
                kind: kind.into(),
                severity,
                profile_id: None,
                forward_id: None,
                session_id: None,
                connection_id: None,
                fields: BTreeMap::new(),
                message: String::new(),
            },
        }
    }

    /// Set the timestamp.
    #[must_use]
    pub fn ts(mut self, ts: DateTime<Utc>) -> Self {
        self.inner.ts = ts;
        self
    }
    #[must_use]
    pub fn profile(mut self, p: ProfileId) -> Self {
        self.inner.profile_id = Some(p);
        self
    }
    #[must_use]
    pub fn forward(mut self, f: ForwardId) -> Self {
        self.inner.forward_id = Some(f);
        self
    }
    #[must_use]
    pub fn session(mut self, s: SessionId) -> Self {
        self.inner.session_id = Some(s);
        self
    }
    #[must_use]
    pub fn connection(mut self, c: ConnectionId) -> Self {
        self.inner.connection_id = Some(c);
        self
    }
    #[must_use]
    pub fn message(mut self, msg: impl Into<String>) -> Self {
        self.inner.message = msg.into();
        self
    }
    /// Add a JSON field; later same-key calls overwrite.
    #[must_use]
    pub fn field(mut self, key: impl Into<String>, value: impl Into<Value>) -> Self {
        self.inner.fields.insert(key.into(), value.into());
        self
    }

    /// Finish.
    #[must_use]
    pub fn build(self) -> Event {
        self.inner
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn severity_parse_round_trip() {
        for s in ["trace", "debug", "info", "warn", "error", "critical"] {
            let sev = Severity::parse(s).unwrap();
            assert_eq!(sev.as_str(), s);
        }
        assert!(Severity::parse("nope").is_none());
    }

    #[test]
    fn severity_ordered_by_severity() {
        assert!(Severity::Trace < Severity::Info);
        assert!(Severity::Info < Severity::Error);
        assert!(Severity::Error < Severity::Critical);
    }

    #[test]
    fn kind_pattern_match() {
        let k = EventKind::new("forward.connection_opened");
        assert!(k.matches_pattern("forward.connection_opened"));
        assert!(k.matches_pattern("forward.*"));
        assert!(!k.matches_pattern("profile.*"));
    }

    #[test]
    fn builder_chains_and_fields() {
        let p = ProfileId::new("p1").unwrap();
        let e = Event::builder("profile.connected", Severity::Info)
            .ts(Utc.with_ymd_and_hms(2026, 5, 5, 10, 0, 0).unwrap())
            .profile(p.clone())
            .field("count", 7)
            .message("up")
            .build();
        assert_eq!(e.kind.as_str(), "profile.connected");
        assert_eq!(e.severity, Severity::Info);
        assert_eq!(e.profile_id, Some(p));
        assert_eq!(e.fields.get("count"), Some(&Value::from(7)));
        assert_eq!(e.message, "up");
    }

    #[test]
    fn to_state_event_carries_ids_in_extra() {
        let p = ProfileId::new("p1").unwrap();
        let f = ForwardId::new("f1").unwrap();
        let e = Event::builder("forward.listening", Severity::Info)
            .profile(p)
            .forward(f)
            .build();
        let s = e.to_state_event();
        let obj = s.extra.as_object().unwrap();
        assert_eq!(obj.get("profile_id").unwrap().as_str().unwrap(), "p1");
        assert_eq!(obj.get("forward_id").unwrap().as_str().unwrap(), "f1");
        assert_eq!(s.kind, "forward.listening");
        assert_eq!(s.severity, "info");
    }

    #[test]
    fn lookup_field_named_and_extra() {
        let e = Event::builder("k", Severity::Info)
            .field("foo", "bar")
            .build();
        assert_eq!(e.lookup_field("kind"), Some(Value::from("k")));
        assert_eq!(e.lookup_field("foo"), Some(Value::from("bar")));
        assert!(e.lookup_field("missing").is_none());
    }

    #[test]
    fn severity_display_matches_as_str() {
        for s in [
            Severity::Trace,
            Severity::Debug,
            Severity::Info,
            Severity::Warn,
            Severity::Error,
            Severity::Critical,
        ] {
            assert_eq!(format!("{s}"), s.as_str());
        }
    }

    #[test]
    fn severity_parses_alias_forms() {
        assert_eq!(Severity::parse("WARNING"), Some(Severity::Warn));
        assert_eq!(Severity::parse("Crit"), Some(Severity::Critical));
        assert_eq!(Severity::parse("FATAL"), Some(Severity::Critical));
    }

    #[test]
    fn kind_display_matches_as_str() {
        let k = EventKind::new("forward.connection_opened");
        assert_eq!(format!("{k}"), k.as_str());
    }

    #[test]
    fn kind_from_str_impl() {
        let k: EventKind = "x.y".into();
        assert_eq!(k.as_str(), "x.y");
    }

    #[test]
    fn lookup_field_handles_all_id_columns() {
        let prof = ProfileId::new("p").unwrap();
        let fwd = ForwardId::new("f").unwrap();
        let sess = SessionId::new("s1").unwrap();
        let conn = ConnectionId::new("c1").unwrap();
        let e = Event::builder("k", Severity::Info)
            .profile(prof)
            .forward(fwd)
            .session(sess)
            .connection(conn)
            .message("hi")
            .build();
        assert!(e.lookup_field("profile_id").is_some());
        assert!(e.lookup_field("forward_id").is_some());
        assert!(e.lookup_field("session_id").is_some());
        assert!(e.lookup_field("connection_id").is_some());
        assert_eq!(e.lookup_field("message"), Some(Value::from("hi")));
        assert!(e.lookup_field("ts").is_some());
        assert!(e.lookup_field("id").is_some());
        assert_eq!(e.lookup_field("severity"), Some(Value::from("info")));
    }

    #[test]
    fn lookup_field_returns_none_for_unset_optional_ids() {
        let e = Event::builder("k", Severity::Info).build();
        assert!(e.lookup_field("profile_id").is_none());
        assert!(e.lookup_field("forward_id").is_none());
        assert!(e.lookup_field("session_id").is_none());
        assert!(e.lookup_field("connection_id").is_none());
    }

    #[test]
    fn event_serde_round_trip_through_json() {
        let p = ProfileId::new("p").unwrap();
        let e = Event::builder("k", Severity::Warn)
            .profile(p)
            .field("n", 7)
            .message("hi")
            .build();
        let s = serde_json::to_string(&e).unwrap();
        let back: Event = serde_json::from_str(&s).unwrap();
        assert_eq!(back.kind, e.kind);
        assert_eq!(back.severity, e.severity);
        assert_eq!(back.profile_id, e.profile_id);
        assert_eq!(back.message, e.message);
        assert_eq!(back.fields.get("n"), e.fields.get("n"));
    }

    #[test]
    fn to_state_event_carries_message_and_session_connection_ids() {
        let s_id = SessionId::new("s").unwrap();
        let c_id = ConnectionId::new("c").unwrap();
        let e = Event::builder("k", Severity::Info)
            .session(s_id)
            .connection(c_id)
            .message("hello")
            .build();
        let s = e.to_state_event();
        let obj = s.extra.as_object().unwrap();
        assert!(obj.contains_key("session_id"));
        assert!(obj.contains_key("connection_id"));
        assert_eq!(obj.get("message").unwrap().as_str().unwrap(), "hello");
    }

    #[test]
    fn matches_pattern_handles_empty_pattern() {
        let k = EventKind::new("anything");
        // Empty pattern with `*` suffix renders as "" → starts_with("") is true.
        assert!(k.matches_pattern("*"));
    }
}
