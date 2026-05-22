//! Structured operator-facing diagnostics.
//!
//! A [`Diagnostic`] captures the three pieces an operator needs to act on a
//! failure:
//!
//! * `what` — a short imperative description of the failed operation.
//! * `why`  — the underlying cause (optional, but typically supplied).
//! * `how_to_fix` — concrete remediation steps (optional but encouraged).
//!
//! On top of that, optional location hints (`file_path`, `line_no`, `endpoint`)
//! and a [`RetryAdvice`] hint enable richer rendering by the top-level error
//! printer in `spt-bin`.
//!
//! # Compatibility
//!
//! The companion `*Diagnostic` variants on [`crate::Error`] live alongside
//! existing `String`-payload variants — adding `Diagnostic` is therefore
//! purely additive and does not break any existing caller. New code that
//! wants the richer experience should prefer the builder:
//!
//! ```
//! use spt_core::diagnostic::{Diagnostic, RetryAdvice};
//!
//! let d = Diagnostic::what("Failed to validate `bastion.host`")
//!     .why("value is empty")
//!     .how_to_fix("Set `bastion.host = \"<fqdn>\"` in your config")
//!     .retry_advice(RetryAdvice::NotRetryable)
//!     .build();
//!
//! assert!(format!("{d}").contains("Failed to validate"));
//! assert!(format!("{d}").contains("value is empty"));
//! assert!(format!("{d}").contains("how to fix"));
//! ```

use std::borrow::Cow;
use std::fmt;
use std::path::PathBuf;
use std::time::Duration;

use miette::Diagnostic as MietteDiagnostic;

/// Retry-policy hint attached to a [`Diagnostic`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RetryAdvice {
    /// Retrying will not help (bad config, auth failure, ...).
    NotRetryable,
    /// Retry after the suggested duration (e.g. server-side rate limit).
    RetryAfter(Duration),
    /// A transient blip — retry right away.
    RetryImmediately,
    /// Retry with exponential / full-jitter backoff.
    RetryWithBackoff,
}

impl fmt::Display for RetryAdvice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotRetryable => f.write_str("not retryable"),
            Self::RetryAfter(d) => write!(f, "retry after {}s", d.as_secs()),
            Self::RetryImmediately => f.write_str("retry immediately"),
            Self::RetryWithBackoff => f.write_str("retry with backoff"),
        }
    }
}

/// A structured diagnostic explaining what failed, why, and how to fix.
///
/// Construct via [`Diagnostic::what`] which returns a [`DiagnosticBuilder`].
/// Existing call-sites that only have a `String` reason can call
/// [`Diagnostic::from`] (via `impl From<String>`) to wrap the legacy message
/// without rewriting it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diagnostic {
    /// Short imperative summary of the failed operation.
    pub what: String,
    /// Underlying cause, when known.
    pub why: Option<String>,
    /// Suggested remediation.
    pub how_to_fix: Option<String>,
    /// Config file the failure relates to.
    pub file_path: Option<PathBuf>,
    /// 1-based line number inside `file_path`.
    pub line_no: Option<u32>,
    /// Endpoint (host:port, URL, secret reference, ...) the failure touched.
    pub endpoint: Option<String>,
    /// Retry hint for callers wrapping this in a backoff loop.
    pub retry_advice: Option<RetryAdvice>,
}

impl Diagnostic {
    /// Start building a diagnostic with the mandatory `what` field.
    pub fn what(s: impl Into<String>) -> DiagnosticBuilder {
        DiagnosticBuilder {
            inner: Diagnostic {
                what: s.into(),
                why: None,
                how_to_fix: None,
                file_path: None,
                line_no: None,
                endpoint: None,
                retry_advice: None,
            },
        }
    }

    /// Render the diagnostic to a single multi-line operator-facing message.
    ///
    /// Format (only present fields are emitted):
    ///
    /// ```text
    /// <what>
    ///   why: <why>
    ///   how to fix: <how_to_fix>
    ///   at: <file_path>:<line_no>
    ///   endpoint: <endpoint>
    ///   retry: <retry_advice>
    /// ```
    #[must_use]
    pub fn render(&self) -> String {
        let mut out = self.what.clone();
        if let Some(why) = &self.why {
            out.push_str("\n  why: ");
            out.push_str(why);
        }
        if let Some(fix) = &self.how_to_fix {
            out.push_str("\n  how to fix: ");
            out.push_str(fix);
        }
        match (&self.file_path, self.line_no) {
            (Some(p), Some(l)) => {
                out.push_str(&format!("\n  at: {}:{l}", p.display()));
            }
            (Some(p), None) => {
                out.push_str(&format!("\n  at: {}", p.display()));
            }
            (None, Some(l)) => {
                out.push_str(&format!("\n  at line {l}"));
            }
            (None, None) => {}
        }
        if let Some(ep) = &self.endpoint {
            out.push_str("\n  endpoint: ");
            out.push_str(ep);
        }
        if let Some(r) = &self.retry_advice {
            out.push_str("\n  retry: ");
            out.push_str(&r.to_string());
        }
        out
    }
}

impl fmt::Display for Diagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.render())
    }
}

impl std::error::Error for Diagnostic {}

// `miette::Diagnostic` is automatically satisfied via blanket Display/Error
// impls, but we provide a hand-rolled impl so the `help()` channel surfaces
// the `how_to_fix` field in miette-formatted output (used by spt-bin).
impl MietteDiagnostic for Diagnostic {
    fn help<'a>(&'a self) -> Option<Box<dyn fmt::Display + 'a>> {
        self.how_to_fix
            .as_ref()
            .map(|s| Box::new(s.clone()) as Box<dyn fmt::Display + 'a>)
    }

    fn url<'a>(&'a self) -> Option<Box<dyn fmt::Display + 'a>> {
        None
    }
}

/// Builder for [`Diagnostic`]. Obtain via [`Diagnostic::what`].
#[derive(Debug, Clone)]
#[must_use = "call .build() to finalise the diagnostic"]
pub struct DiagnosticBuilder {
    inner: Diagnostic,
}

impl DiagnosticBuilder {
    /// Set the `why` (underlying cause).
    pub fn why(mut self, s: impl Into<String>) -> Self {
        self.inner.why = Some(s.into());
        self
    }

    /// Set the `how_to_fix` (remediation hint).
    pub fn how_to_fix(mut self, s: impl Into<String>) -> Self {
        self.inner.how_to_fix = Some(s.into());
        self
    }

    /// Attach a config file path the failure relates to.
    pub fn file_path(mut self, p: impl Into<PathBuf>) -> Self {
        self.inner.file_path = Some(p.into());
        self
    }

    /// Attach a 1-based line number inside `file_path`.
    pub fn line_no(mut self, l: u32) -> Self {
        self.inner.line_no = Some(l);
        self
    }

    /// Attach an endpoint (host:port, URL, secret ref, ...).
    pub fn endpoint(mut self, s: impl Into<String>) -> Self {
        self.inner.endpoint = Some(s.into());
        self
    }

    /// Attach a retry-policy hint.
    pub fn retry_advice(mut self, r: RetryAdvice) -> Self {
        self.inner.retry_advice = Some(r);
        self
    }

    /// Finalise the builder into a [`Diagnostic`].
    #[must_use]
    pub fn build(self) -> Diagnostic {
        self.inner
    }
}

/// Bridge for legacy `String`-only call-sites: wraps the message in a
/// diagnostic whose `what` is the original string and whose other fields
/// are empty. This lets `?` / `.into()` keep working through the migration.
impl From<String> for Diagnostic {
    fn from(s: String) -> Self {
        Diagnostic::what(s).build()
    }
}

impl From<&str> for Diagnostic {
    fn from(s: &str) -> Self {
        Diagnostic::what(s).build()
    }
}

impl<'a> From<Cow<'a, str>> for Diagnostic {
    fn from(s: Cow<'a, str>) -> Self {
        Diagnostic::what(s.into_owned()).build()
    }
}

/// Assert that the rendered Display form of an `Error` contains the
/// supplied `what` / `why` / `how_to_fix` substrings. Any of the three
/// substring fields may be omitted.
///
/// ```ignore
/// assert_diagnostic_contains!(err,
///     what: "Failed to validate",
///     why: "value is empty",
///     how_to_fix: "Set `bastion.host`",
/// );
/// ```
#[macro_export]
macro_rules! assert_diagnostic_contains {
    ($err:expr $(, what: $what:expr)? $(, why: $why:expr)? $(, how_to_fix: $how:expr)? $(,)?) => {{
        let rendered = format!("{}", $err);
        $(
            assert!(
                rendered.contains($what),
                "rendered diagnostic missing `what` substring `{}`; got:\n{}",
                $what, rendered,
            );
        )?
        $(
            assert!(
                rendered.contains($why),
                "rendered diagnostic missing `why` substring `{}`; got:\n{}",
                $why, rendered,
            );
        )?
        $(
            assert!(
                rendered.contains($how),
                "rendered diagnostic missing `how_to_fix` substring `{}`; got:\n{}",
                $how, rendered,
            );
        )?
    }};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_chains_what_why_how() {
        let d = Diagnostic::what("Failed to do X")
            .why("Y went sideways")
            .how_to_fix("Try Z")
            .build();
        let s = d.to_string();
        assert!(s.contains("Failed to do X"));
        assert!(s.contains("why: Y went sideways"));
        assert!(s.contains("how to fix: Try Z"));
    }

    #[test]
    fn builder_omits_unset_fields() {
        let d = Diagnostic::what("only what").build();
        assert_eq!(d.to_string(), "only what");
    }

    #[test]
    fn renders_file_and_line() {
        let d = Diagnostic::what("bad value")
            .file_path("/etc/spt.toml")
            .line_no(42)
            .build();
        assert!(d.to_string().contains("/etc/spt.toml:42"));
    }

    #[test]
    fn renders_file_without_line() {
        let d = Diagnostic::what("bad value")
            .file_path("/etc/spt.toml")
            .build();
        let s = d.to_string();
        assert!(s.contains("/etc/spt.toml"));
        assert!(!s.contains(":42"));
    }

    #[test]
    fn endpoint_and_retry_render() {
        let d = Diagnostic::what("connect failed")
            .endpoint("bastion.example.com:22")
            .retry_advice(RetryAdvice::RetryAfter(Duration::from_secs(30)))
            .build();
        let s = d.to_string();
        assert!(s.contains("endpoint: bastion.example.com:22"));
        assert!(s.contains("retry: retry after 30s"));
    }

    #[test]
    fn retry_advice_display_variants() {
        assert_eq!(RetryAdvice::NotRetryable.to_string(), "not retryable");
        assert_eq!(RetryAdvice::RetryImmediately.to_string(), "retry immediately");
        assert_eq!(
            RetryAdvice::RetryWithBackoff.to_string(),
            "retry with backoff"
        );
        assert_eq!(
            RetryAdvice::RetryAfter(Duration::from_secs(5)).to_string(),
            "retry after 5s"
        );
    }

    #[test]
    fn from_string_wraps_legacy_message() {
        let d: Diagnostic = String::from("legacy reason").into();
        assert_eq!(d.what, "legacy reason");
        assert!(d.why.is_none());
        assert!(d.how_to_fix.is_none());
    }

    #[test]
    fn from_str_wraps_legacy_message() {
        let d: Diagnostic = "legacy reason".into();
        assert_eq!(d.what, "legacy reason");
    }

    #[test]
    fn miette_help_surfaces_how_to_fix() {
        let d = Diagnostic::what("X").how_to_fix("Do Y").build();
        let help = MietteDiagnostic::help(&d)
            .map(|h| h.to_string())
            .unwrap_or_default();
        assert_eq!(help, "Do Y");
    }

    #[test]
    fn miette_help_absent_when_unset() {
        let d = Diagnostic::what("X").build();
        assert!(MietteDiagnostic::help(&d).is_none());
    }
}
