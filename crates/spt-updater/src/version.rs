//! Version parsing + comparison.
//!
//! spt's rolling-release scheme uses `YY.N` user-facing tags backed by
//! `0.YY.N` semver in Cargo.toml. We treat the cargo form as the
//! canonical comparable thing; the bare tag is normalised by prepending
//! `0.` before parsing.

use semver::Version as SemVer;

use crate::error::{UpdaterError, UpdaterResult};

/// Currently-running spt version, captured from `CARGO_PKG_VERSION` at
/// compile time. Newtype so callers can't accidentally feed a string
/// through.
#[derive(Debug, Clone)]
pub struct CurrentVersion(pub Version);

impl CurrentVersion {
    /// Build from the `CARGO_PKG_VERSION` baked into spt-updater itself
    /// (= the workspace version, since every member inherits it).
    #[must_use]
    pub fn from_build() -> Self {
        Self(Version::parse(env!("CARGO_PKG_VERSION")).expect("CARGO_PKG_VERSION parses"))
    }
}

/// Parsed semver version with the spt-specific rolling-tag awareness.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Version(SemVer);

impl Version {
    /// Parse an `x.y.z` semver string.
    pub fn parse(s: &str) -> UpdaterResult<Self> {
        SemVer::parse(s)
            .map(Self)
            .map_err(|e| UpdaterError::Config(format!("version `{s}`: {e}")))
    }

    /// Parse a bare rolling tag (`26.4`) by prepending `0.`.
    pub fn parse_tag(s: &str) -> UpdaterResult<Self> {
        let tag = s.trim_start_matches('v');
        let cargo_form = if tag.split('.').count() == 2 {
            format!("0.{tag}")
        } else {
            tag.to_string()
        };
        Self::parse(&cargo_form)
    }

    /// Comparator: is this version newer than `other`?
    #[must_use]
    pub fn is_newer_than(&self, other: &Self) -> bool {
        self.0 > other.0
    }

    /// Render back to the cargo `0.YY.N` form.
    #[must_use]
    pub fn to_cargo_string(&self) -> String {
        self.0.to_string()
    }

    /// Render to the bare tag (`YY.N`) by stripping the `0.` prefix when
    /// present, otherwise return the cargo form verbatim.
    #[must_use]
    pub fn to_tag_string(&self) -> String {
        let s = self.0.to_string();
        s.strip_prefix("0.").unwrap_or(&s).to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_tag_normalises_rolling_form() {
        let v = Version::parse_tag("26.4").unwrap();
        assert_eq!(v.to_cargo_string(), "0.26.4");
        assert_eq!(v.to_tag_string(), "26.4");
    }

    #[test]
    fn parse_tag_accepts_v_prefix() {
        let v = Version::parse_tag("v26.4").unwrap();
        assert_eq!(v.to_cargo_string(), "0.26.4");
    }

    #[test]
    fn parse_tag_passes_through_full_semver() {
        let v = Version::parse_tag("0.26.4").unwrap();
        assert_eq!(v.to_cargo_string(), "0.26.4");
    }

    #[test]
    fn newer_than_compares_correctly() {
        let a = Version::parse_tag("26.4").unwrap();
        let b = Version::parse_tag("26.5").unwrap();
        assert!(b.is_newer_than(&a));
        assert!(!a.is_newer_than(&b));
        assert!(!a.is_newer_than(&a));
    }
}
