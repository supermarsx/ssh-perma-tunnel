//! Spec-style duration parsing and serde glue.
//!
//! Strings such as `"5m"`, `"1h30m"`, `"500ms"` and `"2s 200ms"` are accepted —
//! the underlying parser is [`humantime`].

use std::time::Duration;

use crate::error::{Error, Result};

/// Parse a spec-style duration string (e.g. `"5m"`, `"1h30m"`, `"500ms"`).
///
/// The empty string is rejected explicitly.
pub fn parse_duration(s: &str) -> Result<Duration> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return Err(Error::InvalidArgs("duration must not be empty".into()));
    }
    humantime::parse_duration(trimmed)
        .map_err(|e| Error::InvalidArgs(format!("invalid duration `{trimmed}`: {e}")))
}

/// Render a [`Duration`] using `humantime` formatting (e.g. `1h 30m`).
#[must_use]
pub fn format_duration(d: Duration) -> String {
    humantime::format_duration(d).to_string()
}

/// `serde` helper for `#[serde(with = "spt_core::duration::serde_duration")]`.
///
/// Serializes a [`Duration`] as a human-readable string, deserializes from a
/// string using [`parse_duration`].
pub mod serde_duration {
    use std::time::Duration;

    use serde::{de::Error as DeError, Deserialize, Deserializer, Serializer};

    /// Serialize a [`Duration`] as a `humantime` string.
    #[allow(clippy::trivially_copy_pass_by_ref)] // serde requires &T
    pub fn serialize<S: Serializer>(value: &Duration, ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(&super::format_duration(*value))
    }

    /// Deserialize a [`Duration`] from a `humantime` string.
    pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<Duration, D::Error> {
        let s = String::deserialize(de)?;
        super::parse_duration(&s).map_err(D::Error::custom)
    }
}

/// `serde` helper for `Option<Duration>` fields.
pub mod serde_duration_opt {
    use std::time::Duration;

    use serde::{de::Error as DeError, Deserialize, Deserializer, Serializer};

    /// Serialize `Option<Duration>`; `None` becomes `null`.
    #[allow(clippy::ref_option)] // serde requires &T
    pub fn serialize<S: Serializer>(value: &Option<Duration>, ser: S) -> Result<S::Ok, S::Error> {
        match value {
            Some(d) => ser.serialize_str(&super::format_duration(*d)),
            None => ser.serialize_none(),
        }
    }

    /// Deserialize `Option<Duration>` from an optional `humantime` string.
    pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<Option<Duration>, D::Error> {
        let s: Option<String> = Option::deserialize(de)?;
        match s {
            Some(s) => super::parse_duration(&s)
                .map(Some)
                .map_err(D::Error::custom),
            None => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{format_duration, parse_duration, serde_duration, serde_duration_opt};
    use std::time::Duration;

    #[test]
    fn parses_minutes() {
        assert_eq!(parse_duration("5m").unwrap(), Duration::from_secs(300));
    }

    #[test]
    fn parses_compound() {
        assert_eq!(
            parse_duration("1h30m").unwrap(),
            Duration::from_secs(60 * 60 + 30 * 60)
        );
    }

    #[test]
    fn parses_milliseconds() {
        assert_eq!(parse_duration("500ms").unwrap(), Duration::from_millis(500));
    }

    #[test]
    fn rejects_empty() {
        assert!(parse_duration("").is_err());
        assert!(parse_duration("   ").is_err());
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse_duration("not-a-duration").is_err());
    }

    #[test]
    fn format_round_trip() {
        let d = Duration::from_secs(3 * 3600 + 25 * 60 + 7);
        let s = format_duration(d);
        assert_eq!(parse_duration(&s).unwrap(), d);
    }

    #[derive(serde::Serialize, serde::Deserialize, PartialEq, Eq, Debug)]
    struct Wrap {
        #[serde(with = "serde_duration")]
        d: Duration,
    }

    #[test]
    fn serde_helper_round_trips() {
        let w = Wrap {
            d: Duration::from_secs(90),
        };
        let json = serde_json::to_string(&w).unwrap();
        // humantime renders 90s as "1m 30s"
        assert!(json.contains("1m"));
        let back: Wrap = serde_json::from_str(&json).unwrap();
        assert_eq!(w, back);
    }

    #[derive(serde::Serialize, serde::Deserialize, PartialEq, Eq, Debug)]
    struct WrapOpt {
        #[serde(with = "serde_duration_opt", default)]
        d: Option<Duration>,
    }

    #[test]
    fn serde_helper_opt_some() {
        let w = WrapOpt {
            d: Some(Duration::from_secs(2)),
        };
        let json = serde_json::to_string(&w).unwrap();
        let back: WrapOpt = serde_json::from_str(&json).unwrap();
        assert_eq!(w, back);
    }

    #[test]
    fn serde_helper_opt_none() {
        let w = WrapOpt { d: None };
        let json = serde_json::to_string(&w).unwrap();
        assert_eq!(json, "{\"d\":null}");
        let back: WrapOpt = serde_json::from_str(&json).unwrap();
        assert_eq!(w, back);
    }
}
