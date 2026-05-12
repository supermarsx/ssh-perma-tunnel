//! Strongly-typed identifier newtypes used across the workspace.
//!
//! Every identifier wraps a [`String`] (so the wire/log format is exactly the
//! string the user or runtime chose) and exposes:
//!
//! * [`std::fmt::Display`] / [`std::str::FromStr`] for round-trip text conversion,
//! * `serde::Serialize` / `serde::Deserialize` derived as `transparent` so the
//!   on-disk representation is just the string,
//! * `new_v4` constructors for the variants that are normally generated at runtime
//!   (sessions, connections, runs, events).

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::Error;

macro_rules! id_newtype {
    (
        $(#[$meta:meta])*
        $name:ident, $kind:literal
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            /// Construct an id from an existing string.
            ///
            /// Returns [`Error::InvalidArgs`] if the string is empty or
            /// contains an ASCII control character.
            pub fn new(value: impl Into<String>) -> crate::error::Result<Self> {
                let v = value.into();
                if v.is_empty() {
                    return Err(Error::InvalidArgs(format!(
                        "{} must not be empty",
                        $kind
                    )));
                }
                if v.chars().any(|c| c.is_ascii_control()) {
                    return Err(Error::InvalidArgs(format!(
                        "{} must not contain control characters",
                        $kind
                    )));
                }
                Ok(Self(v))
            }

            /// Generate a new v4 UUID-backed id.
            #[must_use]
            pub fn new_v4() -> Self {
                Self(Uuid::new_v4().to_string())
            }

            /// Borrow the raw string.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }

            /// Consume the id and return the inner string.
            #[must_use]
            pub fn into_inner(self) -> String {
                self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl FromStr for $name {
            type Err = Error;
            fn from_str(s: &str) -> crate::error::Result<Self> {
                Self::new(s.to_owned())
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                &self.0
            }
        }
    };
}

id_newtype!(
    /// Identifier for a long-lived SSH/SSH3 session.
    SessionId,
    "session id"
);
id_newtype!(
    /// Identifier for a single forwarded TCP/UDP connection.
    ConnectionId,
    "connection id"
);
id_newtype!(
    /// Identifier for a configuration-defined profile.
    ProfileId,
    "profile id"
);
id_newtype!(
    /// Identifier for a configuration-defined forward.
    ForwardId,
    "forward id"
);
id_newtype!(
    /// Identifier for a single supervisor run / process invocation.
    RunId,
    "run id"
);
id_newtype!(
    /// Identifier for an emitted event record.
    EventId,
    "event id"
);

#[cfg(test)]
mod tests {
    use super::{ConnectionId, EventId, ForwardId, ProfileId, RunId, SessionId};
    use std::str::FromStr;

    #[test]
    fn new_rejects_empty() {
        assert!(SessionId::new("").is_err());
    }

    #[test]
    fn new_rejects_control() {
        assert!(ProfileId::new("hi\nthere").is_err());
    }

    #[test]
    fn round_trip_display_from_str() {
        let id = ProfileId::new("smtp-relay").unwrap();
        let s = id.to_string();
        let parsed = ProfileId::from_str(&s).unwrap();
        assert_eq!(id, parsed);
    }

    #[test]
    fn new_v4_is_unique() {
        let a = SessionId::new_v4();
        let b = SessionId::new_v4();
        assert_ne!(a, b);
        assert_eq!(a.as_str().len(), 36);
    }

    #[test]
    fn serde_is_transparent() {
        let id = ConnectionId::new("c-42").unwrap();
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(json, "\"c-42\"");
        let back: ConnectionId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, back);
    }

    #[test]
    fn forward_id_basic() {
        let f = ForwardId::new("fwd-1").unwrap();
        assert_eq!(f.as_str(), "fwd-1");
    }

    #[test]
    fn run_id_uuid() {
        let r = RunId::new_v4();
        assert!(uuid::Uuid::parse_str(r.as_str()).is_ok());
    }

    #[test]
    fn event_id_into_inner() {
        let e = EventId::new("evt-9").unwrap();
        assert_eq!(e.into_inner(), "evt-9");
    }
}
