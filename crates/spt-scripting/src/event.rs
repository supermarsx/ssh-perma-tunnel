//! Structured event payloads delivered to the scripting engine.
//!
//! Each event type maps one-to-one to a hook slot:
//!
//! * [`PreConnect`]  → `pre_connect`
//! * [`PostConnect`] → `post_connect`
//! * [`ForwardState`]→ `on_forward_state`
//! * [`Disconnect`]  → `on_disconnect`
//! * [`Generic`]     → `on_event`
//!
//! Events are constructed by `spt-ssh2` (the hook call sites) and serialise
//! into a Rhai-friendly value via [`Event::into_dynamic`] (under the
//! `engine` feature) or [`Event::to_json`] (always available — used by
//! the no-op stub interpreter and for audit logging).

use serde::{Deserialize, Serialize};

/// Sum-type enumerating every possible event payload. Hook dispatch never
/// needs `Box<dyn Any>` — the dispatcher matches on this enum.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Event {
    /// `pre_connect` payload.
    PreConnect(PreConnect),
    /// `post_connect` payload.
    PostConnect(PostConnect),
    /// `on_forward_state` payload.
    ForwardState(ForwardState),
    /// `on_disconnect` payload.
    Disconnect(Disconnect),
    /// Generic catch-all payload.
    Generic(Generic),
}

impl Event {
    /// JSON serialisation, used both by audit hooks and by the no-op stub
    /// interpreter (which logs the event without executing any script).
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| "{}".to_owned())
    }
}

/// `pre_connect` event — fired before the TCP/QUIC connect attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreConnect {
    /// Profile name.
    pub profile: String,
    /// Remote host (DNS name or literal IP).
    pub host: String,
    /// Remote port.
    pub port: u16,
    /// Connection attempt counter (1-indexed).
    pub attempt: u32,
}

/// `post_connect` event — fired after successful authentication.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PostConnect {
    /// Profile name.
    pub profile: String,
    /// Remote host.
    pub host: String,
    /// Remote port.
    pub port: u16,
    /// Authentication method tag (e.g. `"publickey"`, `"password"`,
    /// `"keyboard-interactive"`, `"gssapi-with-mic"`).
    pub auth_method: String,
    /// Negotiated SSH protocol version banner.
    pub server_banner: Option<String>,
}

/// `on_forward_state` event — fired on every forward state-machine
/// transition (Pending → Active → Paused → Closed, etc).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForwardState {
    /// Profile name.
    pub profile: String,
    /// Forward id (configuration `name`, or `kind:bind` if anonymous).
    pub forward_id: String,
    /// Transition.
    pub transition: ForwardStateTransition,
}

/// Forward state-machine transitions reported to `on_forward_state`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ForwardStateTransition {
    /// Forward bound and accepting connections.
    Listening,
    /// First end-to-end channel established.
    Active,
    /// Listener torn down for backoff / re-arm.
    Paused,
    /// Listener fully closed; no further transitions expected.
    Closed,
    /// Transient failure recorded; the supervisor will retry.
    Failed,
}

/// `on_disconnect` event — fired after the session terminates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Disconnect {
    /// Profile name.
    pub profile: String,
    /// Stable reason code (e.g. `"keepalive_timeout"`, `"peer_eof"`,
    /// `"user_request"`, `"auth_failed"`).
    pub reason: String,
    /// Session lifetime in milliseconds.
    pub duration_ms: u64,
}

/// Generic catch-all delivered to `on_event` when no more specific hook
/// applies. Useful for ad-hoc telemetry without growing the typed event
/// taxonomy.
///
/// The `tag` field is renamed at the serde boundary to avoid colliding
/// with the `#[serde(tag = "kind")]` discriminator on [`Event`] itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Generic {
    /// Profile name.
    pub profile: String,
    /// Stable tag (free-form, `snake_case`). Serialised as `tag` so it
    /// does not collide with the outer-enum `kind` discriminator.
    #[serde(rename = "tag")]
    pub kind: String,
    /// JSON payload as a string. The script-side adapter is responsible
    /// for parsing if structured access is required.
    pub payload_json: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pre_connect_round_trips_through_json() {
        let e = Event::PreConnect(PreConnect {
            profile: "edge".into(),
            host: "203.0.113.7".into(),
            port: 22,
            attempt: 1,
        });
        let j = e.to_json();
        let back: Event = serde_json::from_str(&j).unwrap();
        assert_eq!(back, e);
        assert!(j.contains(r#""kind":"pre_connect""#), "{j}");
        assert!(j.contains(r#""host":"203.0.113.7""#), "{j}");
        assert!(j.contains(r#""port":22"#), "{j}");
    }

    #[test]
    fn forward_state_includes_transition() {
        let e = Event::ForwardState(ForwardState {
            profile: "p".into(),
            forward_id: "local:8080".into(),
            transition: ForwardStateTransition::Active,
        });
        let j = e.to_json();
        assert!(j.contains(r#""transition":"active""#), "{j}");
    }

    #[test]
    fn disconnect_carries_reason_and_duration() {
        let e = Event::Disconnect(Disconnect {
            profile: "p".into(),
            reason: "keepalive_timeout".into(),
            duration_ms: 12_345,
        });
        let j = e.to_json();
        assert!(j.contains(r#""reason":"keepalive_timeout""#), "{j}");
        assert!(j.contains(r#""duration_ms":12345"#), "{j}");
    }

    #[test]
    fn generic_carries_kind_and_opaque_payload() {
        let e = Event::Generic(Generic {
            profile: "p".into(),
            kind: "anything".into(),
            payload_json: r#"{"x":1}"#.into(),
        });
        let j = e.to_json();
        let back: Event = serde_json::from_str(&j).unwrap();
        assert_eq!(back, e);
    }
}
