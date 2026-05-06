//! Spec-style byte-size parsing and serde glue.
//!
//! Strings such as `"20MiB"`, `"1.5GB"`, `"512KiB"` are accepted via the
//! [`bytesize`] crate.

use std::str::FromStr;

use bytesize::ByteSize;

use crate::error::{Error, Result};

/// Parse a spec-style byte-size string into an absolute byte count.
///
/// Accepts both SI (`KB`, `MB`, ...) and IEC (`KiB`, `MiB`, ...) suffixes.
pub fn parse_size(s: &str) -> Result<u64> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return Err(Error::InvalidArgs("size must not be empty".into()));
    }
    ByteSize::from_str(trimmed)
        .map(|bs| bs.0)
        .map_err(|e| Error::InvalidArgs(format!("invalid size `{trimmed}`: {e}")))
}

/// Render a byte count in IEC form (`MiB`, `GiB`, ...).
#[must_use]
pub fn format_size(bytes: u64) -> String {
    ByteSize::b(bytes).to_string_as(true)
}

/// `serde` helper for `#[serde(with = "spt_core::size::serde_size")]`.
pub mod serde_size {
    use serde::{de::Error as DeError, Deserialize, Deserializer, Serializer};

    /// Serialize `u64` as a human-readable IEC byte-size string.
    #[allow(clippy::trivially_copy_pass_by_ref)] // serde requires &T
    pub fn serialize<S: Serializer>(value: &u64, ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(&super::format_size(*value))
    }

    /// Deserialize `u64` from a byte-size string.
    pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<u64, D::Error> {
        let s = String::deserialize(de)?;
        super::parse_size(&s).map_err(D::Error::custom)
    }
}

/// `serde` helper for `Option<u64>` byte-size fields.
pub mod serde_size_opt {
    use serde::{de::Error as DeError, Deserialize, Deserializer, Serializer};

    /// Serialize `Option<u64>` as an optional byte-size string.
    #[allow(clippy::ref_option)] // serde requires &T
    pub fn serialize<S: Serializer>(value: &Option<u64>, ser: S) -> Result<S::Ok, S::Error> {
        match value {
            Some(v) => ser.serialize_str(&super::format_size(*v)),
            None => ser.serialize_none(),
        }
    }

    /// Deserialize `Option<u64>` from an optional byte-size string.
    pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<Option<u64>, D::Error> {
        let s: Option<String> = Option::deserialize(de)?;
        match s {
            Some(s) => super::parse_size(&s).map(Some).map_err(D::Error::custom),
            None => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{format_size, parse_size, serde_size};

    #[test]
    fn parses_mib() {
        assert_eq!(parse_size("20MiB").unwrap(), 20 * 1024 * 1024);
    }

    #[test]
    fn parses_decimal_gb() {
        // 1.5 GB = 1.5 * 1_000_000_000 = 1_500_000_000
        assert_eq!(parse_size("1.5GB").unwrap(), 1_500_000_000);
    }

    #[test]
    fn parses_bare_bytes() {
        assert_eq!(parse_size("512").unwrap(), 512);
    }

    #[test]
    fn rejects_empty() {
        assert!(parse_size("").is_err());
        assert!(parse_size("   ").is_err());
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse_size("not-a-size").is_err());
    }

    #[test]
    fn format_renders_iec() {
        let s = format_size(2 * 1024 * 1024);
        assert!(s.contains("MiB"));
    }

    #[derive(serde::Serialize, serde::Deserialize, PartialEq, Eq, Debug)]
    struct Wrap {
        #[serde(with = "serde_size")]
        b: u64,
    }

    #[test]
    fn serde_round_trip() {
        let w = Wrap { b: 4 * 1024 * 1024 };
        let json = serde_json::to_string(&w).unwrap();
        let back: Wrap = serde_json::from_str(&json).unwrap();
        assert_eq!(w, back);
    }
}
