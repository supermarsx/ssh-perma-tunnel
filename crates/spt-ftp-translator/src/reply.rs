//! Single-line FTP reply formatter.
//!
//! Multi-line replies (`code-` continuation) are not produced by this
//! translator — every supported verb has a one-line response. FEAT is
//! special-cased in [`crate::verbs`].

use std::fmt;

/// FTP reply: a 3-digit code plus a free-form message. The message is
/// **single line** (no CR/LF inside); the formatter appends `\r\n`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reply {
    /// 3-digit status code.
    pub code: u16,
    /// Single-line message body.
    pub text: String,
}

impl Reply {
    /// Construct.
    pub fn new(code: u16, text: impl Into<String>) -> Self {
        let mut text = text.into();
        // Defensive: replace any embedded CR/LF with single spaces so the
        // wire stays well-formed.
        if text.contains('\r') || text.contains('\n') {
            text = text.replace(['\r', '\n'], " ");
        }
        Self { code, text }
    }

    /// Render the wire form including trailing CRLF.
    #[must_use]
    pub fn wire(&self) -> String {
        format!("{} {}\r\n", self.code, self.text)
    }

    /// Convenience constructors for the most common codes.
    pub fn ok_220(text: impl Into<String>) -> Self {
        Self::new(220, text)
    }
    pub fn ok_200(text: impl Into<String>) -> Self {
        Self::new(200, text)
    }
    pub fn err_502(text: impl Into<String>) -> Self {
        Self::new(502, text)
    }
    pub fn err_503(text: impl Into<String>) -> Self {
        Self::new(503, text)
    }
    pub fn err_504(text: impl Into<String>) -> Self {
        Self::new(504, text)
    }
    pub fn err_530(text: impl Into<String>) -> Self {
        Self::new(530, text)
    }
    pub fn err_550(text: impl Into<String>) -> Self {
        Self::new(550, text)
    }
}

impl fmt::Display for Reply {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.code, self.text)
    }
}

/// Multi-line FEAT reply, per RFC 2389 §3.2: lines bracketed by
/// `211-Features:` / `211 End`, each feature prefixed with a single space.
pub fn feat_block(features: &[&str]) -> String {
    let mut out = String::from("211-Features:\r\n");
    for f in features {
        out.push(' ');
        out.push_str(f);
        out.push_str("\r\n");
    }
    out.push_str("211 End\r\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_format() {
        let r = Reply::ok_220("hi");
        assert_eq!(r.wire(), "220 hi\r\n");
    }

    #[test]
    fn embedded_crlf_neutralised() {
        let r = Reply::new(550, "oops\r\nINJECT");
        assert!(!r.text.contains('\r') && !r.text.contains('\n'));
        assert_eq!(r.wire(), "550 oops  INJECT\r\n");
    }

    #[test]
    fn feat_block_brackets() {
        let s = feat_block(&["UTF8", "MLST type*;size*;modify*;", "AUTH TLS"]);
        assert!(s.starts_with("211-Features:\r\n"));
        assert!(s.contains(" UTF8\r\n"));
        assert!(s.ends_with("211 End\r\n"));
    }
}
