//! Keyboard-interactive (KBI) responder primitives.

use serde::{Deserialize, Serialize};

use crate::secret_ref::SecretRef;

/// One scripted answer for SSH2 keyboard-interactive auth.
///
/// Matching is performed by `spt-ssh2` against the prompt sent by the server;
/// `pattern` is a substring match (case-insensitive). The response value is a
/// [`SecretRef`] so passwords don't appear inline in config — spec §9.12.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KbiAnswer {
    /// Substring to match against the server-supplied prompt.
    pub pattern: String,
    /// Secret reference whose resolved value is sent in response.
    pub response: SecretRef,
    /// Whether the server flagged the prompt as echoing user input.
    /// Optional metadata; spt-ssh2 logs a warning if echo state mismatches.
    #[serde(default)]
    pub echo: bool,
}
