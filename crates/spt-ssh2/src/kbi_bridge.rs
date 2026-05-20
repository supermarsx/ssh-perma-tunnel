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

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    use spt_auth::SecretRef as AuthSecretRef;

    use super::*;

    /// In-memory `SecretBackend` whose `get` returns a canned byte string for
    /// any `secret://` reference. Used to drive `resolve_secret` through the
    /// `Vault` arm without touching the real backend chain.
    struct CannedBackend(Vec<u8>);

    impl SecretBackend for CannedBackend {
        fn kind(&self) -> spt_secrets::BackendKind {
            spt_secrets::BackendKind::Env
        }
        fn get(
            &self,
            _r: &spt_secrets::SecretRef,
        ) -> spt_core::Result<Option<spt_secrets::SecretBytes>> {
            Ok(Some(spt_secrets::backend::secret_bytes(self.0.clone())))
        }
        fn set(&self, _r: &spt_secrets::SecretRef, _value: &[u8]) -> spt_core::Result<()> {
            Ok(())
        }
        fn list(&self) -> spt_core::Result<Vec<spt_secrets::SecretRef>> {
            Ok(vec![])
        }
        fn remove(&self, _r: &spt_secrets::SecretRef) -> spt_core::Result<bool> {
            Ok(false)
        }
        fn doctor(&self) -> spt_secrets::BackendDoctor {
            spt_secrets::BackendDoctor::ok(spt_secrets::BackendKind::Env, "test")
        }
    }

    fn prompt(text: &str, echo: bool) -> Prompt<'_> {
        Prompt {
            text: Cow::Borrowed(text),
            echo,
        }
    }

    fn env_answer(pattern: &str, env: &str, echo: bool) -> KbiAnswer {
        KbiAnswer {
            pattern: pattern.to_owned(),
            response: AuthSecretRef::Env(env.into()),
            echo,
        }
    }

    #[test]
    fn returns_empty_response_when_no_pattern_matches() {
        let backends: Vec<&dyn SecretBackend> = vec![];
        let mut p = ScriptedPrompter::new(&[], &backends);
        let prompts = vec![prompt("Verification code", false)];
        let out = p.prompt("u", "i", &prompts);
        assert_eq!(out, vec![String::new()]);
        assert!(p.echo_mismatches.is_empty());
    }

    #[test]
    fn matches_pattern_case_insensitively_via_env() {
        std::env::set_var("SPT_TEST_KBI_PW", "shibboleth");
        let answers = vec![env_answer("password", "SPT_TEST_KBI_PW", false)];
        let backends: Vec<&dyn SecretBackend> = vec![];
        let mut p = ScriptedPrompter::new(&answers, &backends);
        let prompts = vec![prompt("PASSWORD: ", false)];
        let out = p.prompt("u", "i", &prompts);
        assert_eq!(out, vec!["shibboleth".to_owned()]);
        assert!(p.echo_mismatches.is_empty());
        std::env::remove_var("SPT_TEST_KBI_PW");
    }

    #[test]
    fn records_echo_mismatch() {
        std::env::set_var("SPT_TEST_KBI_ECHO", "v");
        let answers = vec![env_answer("code", "SPT_TEST_KBI_ECHO", true)];
        let backends: Vec<&dyn SecretBackend> = vec![];
        let mut p = ScriptedPrompter::new(&answers, &backends);
        // Prompt's echo flag is `false`, but the script declared `echo: true`.
        let prompts = vec![prompt("Enter code:", false)];
        let _ = p.prompt("u", "i", &prompts);
        assert_eq!(p.echo_mismatches.len(), 1);
        assert!(p.echo_mismatches[0].contains("Enter code:"));
        std::env::remove_var("SPT_TEST_KBI_ECHO");
    }

    #[test]
    fn unresolved_secret_yields_empty_string() {
        // env var not set → resolve_secret errors → prompter returns "".
        let answers = vec![env_answer("totp", "SPT_TEST_KBI_DOES_NOT_EXIST", false)];
        let backends: Vec<&dyn SecretBackend> = vec![];
        let mut p = ScriptedPrompter::new(&answers, &backends);
        let prompts = vec![prompt("TOTP: ", false)];
        let out = p.prompt("u", "i", &prompts);
        assert_eq!(out, vec![String::new()]);
    }

    #[test]
    fn handles_multiple_prompts_in_one_call() {
        std::env::set_var("SPT_TEST_KBI_PW2", "pw");
        std::env::set_var("SPT_TEST_KBI_TOTP", "123456");
        let answers = vec![
            env_answer("password", "SPT_TEST_KBI_PW2", false),
            env_answer("token", "SPT_TEST_KBI_TOTP", true),
        ];
        let backends: Vec<&dyn SecretBackend> = vec![];
        let mut p = ScriptedPrompter::new(&answers, &backends);
        let prompts = vec![prompt("Password: ", false), prompt("Token: ", true)];
        let out = p.prompt("u", "i", &prompts);
        assert_eq!(out, vec!["pw".to_owned(), "123456".to_owned()]);
        assert!(p.echo_mismatches.is_empty());
        std::env::remove_var("SPT_TEST_KBI_PW2");
        std::env::remove_var("SPT_TEST_KBI_TOTP");
    }

    #[test]
    fn vault_backend_arm_resolves_via_provided_backend() {
        let canned = CannedBackend(b"vaultsecret".to_vec());
        let backends: Vec<&dyn SecretBackend> = vec![&canned];
        let answers = vec![KbiAnswer {
            pattern: "code".into(),
            response: AuthSecretRef::Vault {
                namespace: "ns".into(),
                name: "n".into(),
            },
            echo: false,
        }];
        let mut p = ScriptedPrompter::new(&answers, &backends);
        let prompts = vec![prompt("Enter code:", false)];
        let out = p.prompt("u", "i", &prompts);
        assert_eq!(out, vec!["vaultsecret".to_owned()]);
    }

    #[test]
    fn substring_match_anywhere_in_prompt() {
        std::env::set_var("SPT_TEST_KBI_X", "yy");
        let answers = vec![env_answer("middle", "SPT_TEST_KBI_X", false)];
        let backends: Vec<&dyn SecretBackend> = vec![];
        let mut p = ScriptedPrompter::new(&answers, &backends);
        let prompts = vec![prompt("Some MIDDLE prompt", false)];
        let out = p.prompt("u", "i", &prompts);
        assert_eq!(out, vec!["yy".to_owned()]);
        std::env::remove_var("SPT_TEST_KBI_X");
    }

    #[test]
    fn no_answers_no_prompts_yields_empty_vec() {
        let backends: Vec<&dyn SecretBackend> = vec![];
        let mut p = ScriptedPrompter::new(&[], &backends);
        let out = p.prompt("u", "i", &[]);
        assert!(out.is_empty());
    }
}
