//! Bridges spt-auth's [`KbiAnswer`] script and a per-prompt secret resolver
//! to libssh2's [`KeyboardInteractivePrompt`] callback.

use secrecy::ExposeSecret;
use spt_auth::KbiAnswer;
use spt_secrets::SecretBackend;
use ssh2::{KeyboardInteractivePrompt, Prompt};
use tracing::warn;

use crate::auth::resolve_secret;

/// Prompter that consults a scripted answer table; falls back to an empty
/// response when no pattern matches.
pub struct ScriptedPrompter<'a> {
    answers: &'a [KbiAnswer],
    backends: &'a [&'a dyn SecretBackend],
    /// Populated with any prompt whose echo flag mismatched the script's
    /// declared expectation (a soft warning per spec §9.12).
    pub echo_mismatches: Vec<String>,
}

impl<'a> ScriptedPrompter<'a> {
    /// Construct a new prompter.
    #[must_use]
    pub fn new(answers: &'a [KbiAnswer], backends: &'a [&'a dyn SecretBackend]) -> Self {
        Self {
            answers,
            backends,
            echo_mismatches: Vec::new(),
        }
    }
}

impl KeyboardInteractivePrompt for ScriptedPrompter<'_> {
    fn prompt(
        &mut self,
        _username: &str,
        _instructions: &str,
        prompts: &[Prompt<'_>],
    ) -> Vec<String> {
        prompts
            .iter()
            .map(|p| {
                let prompt_text = p.text.as_ref();
                if let Some(ans) = self
                    .answers
                    .iter()
                    .find(|a| prompt_text.to_lowercase().contains(&a.pattern.to_lowercase()))
                {
                    if ans.echo != p.echo {
                        let msg = format!(
                            "kbi prompt `{prompt_text}` echo state {} != script expectation {}",
                            p.echo, ans.echo
                        );
                        warn!(target: "spt_ssh2::kbi", "{msg}");
                        self.echo_mismatches.push(msg);
                    }
                    match resolve_secret(self.backends, &ans.response) {
                        Ok(bytes) => {
                            String::from_utf8(bytes.expose_secret().to_vec()).unwrap_or_default()
                        }
                        Err(e) => {
                            warn!(target: "spt_ssh2::kbi", "kbi secret resolve failed: {e}");
                            String::new()
                        }
                    }
                } else {
                    warn!(target: "spt_ssh2::kbi", "no scripted answer for kbi prompt `{prompt_text}`");
                    String::new()
                }
            })
            .collect()
    }
}
