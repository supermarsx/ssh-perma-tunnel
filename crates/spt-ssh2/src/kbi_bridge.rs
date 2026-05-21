//! Bridges spt-auth's keyboard-interactive [`KbiResponder`] script and a
//! per-prompt secret resolver to libssh2's [`KeyboardInteractivePrompt`]
//! callback.
//!
//! Matching is **regex-based and first-match-wins** (spec §9.12). Each
//! responder carries a compiled `Regex`; on a successful match the answer
//! source ([`KbiAnswer`]) is evaluated — static literal, secret ref, RFC 6238
//! TOTP, or `YubiKey` OATH-TOTP.

use std::time::{SystemTime, UNIX_EPOCH};

use regex::Regex;
use secrecy::ExposeSecret;
use spt_auth::{KbiAnswer, KbiResponder};
use spt_secrets::SecretBackend;
use ssh2::{KeyboardInteractivePrompt, Prompt};
use tracing::warn;

use crate::auth::resolve_secret;

/// Prompter that consults a scripted responder table; falls back to an empty
/// response when no regex matches.
pub struct ScriptedPrompter<'a> {
    responders: &'a [KbiResponder],
    compiled: Vec<Regex>,
    backends: &'a [&'a dyn SecretBackend],
    /// Populated with any prompt whose echo flag mismatched the script's
    /// declared expectation (a soft warning per spec §9.12).
    pub echo_mismatches: Vec<String>,
}

impl<'a> ScriptedPrompter<'a> {
    /// Construct a new prompter, compiling each `prompt_regex` up front.
    /// Returns an error if any regex is invalid (callers can also rely on
    /// `spt-auth::validate` to surface this earlier at config-load time).
    pub fn new(
        responders: &'a [KbiResponder],
        backends: &'a [&'a dyn SecretBackend],
    ) -> spt_core::Result<Self> {
        let compiled = responders
            .iter()
            .map(KbiResponder::compile)
            .collect::<spt_core::Result<Vec<_>>>()?;
        Ok(Self {
            responders,
            compiled,
            backends,
            echo_mismatches: Vec::new(),
        })
    }

    fn find_match(&self, text: &str) -> Option<usize> {
        self.compiled.iter().position(|r| r.is_match(text))
    }
}

/// Evaluate one [`KbiAnswer`] to the UTF-8 string sent back to the server.
///
/// Used by both the libssh2 and russh bridges so the dispatch lives in one
/// place. Returns `Ok(String::new())` and logs a warning on resolution
/// failure for `Static`/`SecretRef` (those map onto best-effort prompts).
/// `Totp` and `YubikeyOath` propagate typed errors so the auth layer can
/// surface them — they are credential-equivalent and silent failure would
/// be worse than a clear refusal.
pub fn evaluate_answer(
    answer: &KbiAnswer,
    backends: &[&dyn SecretBackend],
) -> spt_core::Result<String> {
    match answer {
        KbiAnswer::Static(s) => Ok(s.clone()),
        KbiAnswer::SecretRef(r) => {
            let bytes = resolve_secret(backends, r)?;
            String::from_utf8(bytes.expose_secret().to_vec()).map_err(|_| {
                spt_core::Error::AuthFailed("keyboard-interactive secret is not utf-8".into())
            })
        }
        KbiAnswer::Totp {
            secret_ref,
            digits,
            period,
            algo,
        } => {
            let bytes = resolve_secret(backends, secret_ref)?;
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|e| spt_core::Error::RuntimeFailure(format!("system clock: {e}")))?
                .as_secs();
            spt_auth::totp::generate(
                bytes.expose_secret(),
                u64::from(*period),
                *digits,
                *algo,
                now,
            )
        }
        KbiAnswer::YubikeyOath { serial, oath_name } => {
            spt_auth::yubikey_oath::fetch_code(serial.as_deref(), oath_name)
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
                let Some(idx) = self.find_match(prompt_text) else {
                    warn!(
                        target: "spt_ssh2::kbi",
                        "no scripted answer for kbi prompt `{prompt_text}`"
                    );
                    return String::new();
                };
                let r = &self.responders[idx];
                if r.echo != p.echo {
                    let msg = format!(
                        "kbi prompt `{prompt_text}` echo state {} != script expectation {}",
                        p.echo, r.echo
                    );
                    warn!(target: "spt_ssh2::kbi", "{msg}");
                    self.echo_mismatches.push(msg);
                }
                match evaluate_answer(&r.answer, self.backends) {
                    Ok(s) => s,
                    Err(e) => {
                        warn!(
                            target: "spt_ssh2::kbi",
                            "kbi answer evaluation failed for prompt `{prompt_text}`: {e}"
                        );
                        String::new()
                    }
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    use spt_auth::{KbiAnswer, KbiResponder, SecretRef as AuthSecretRef};

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

    fn env_resp(prompt_regex: &str, env: &str, echo: bool) -> KbiResponder {
        KbiResponder {
            prompt_regex: prompt_regex.into(),
            answer: KbiAnswer::SecretRef(AuthSecretRef::Env(env.into())),
            echo,
        }
    }

    #[test]
    fn returns_empty_response_when_no_pattern_matches() {
        let backends: Vec<&dyn SecretBackend> = vec![];
        let mut p = ScriptedPrompter::new(&[], &backends).unwrap();
        let prompts = vec![prompt("Verification code", false)];
        let out = p.prompt("u", "i", &prompts);
        assert_eq!(out, vec![String::new()]);
        assert!(p.echo_mismatches.is_empty());
    }

    #[test]
    fn matches_regex_case_insensitively_via_env() {
        std::env::set_var("SPT_TEST_KBI_PW", "shibboleth");
        let responders = vec![env_resp("(?i)password", "SPT_TEST_KBI_PW", false)];
        let backends: Vec<&dyn SecretBackend> = vec![];
        let mut p = ScriptedPrompter::new(&responders, &backends).unwrap();
        let prompts = vec![prompt("PASSWORD: ", false)];
        let out = p.prompt("u", "i", &prompts);
        assert_eq!(out, vec!["shibboleth".to_owned()]);
        assert!(p.echo_mismatches.is_empty());
        std::env::remove_var("SPT_TEST_KBI_PW");
    }

    #[test]
    fn records_echo_mismatch() {
        std::env::set_var("SPT_TEST_KBI_ECHO", "v");
        let responders = vec![env_resp("(?i)code", "SPT_TEST_KBI_ECHO", true)];
        let backends: Vec<&dyn SecretBackend> = vec![];
        let mut p = ScriptedPrompter::new(&responders, &backends).unwrap();
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
        let responders = vec![env_resp("(?i)totp", "SPT_TEST_KBI_DOES_NOT_EXIST", false)];
        let backends: Vec<&dyn SecretBackend> = vec![];
        let mut p = ScriptedPrompter::new(&responders, &backends).unwrap();
        let prompts = vec![prompt("TOTP: ", false)];
        let out = p.prompt("u", "i", &prompts);
        assert_eq!(out, vec![String::new()]);
    }

    #[test]
    fn ordered_first_match_wins() {
        std::env::set_var("SPT_TEST_KBI_FIRST", "first");
        std::env::set_var("SPT_TEST_KBI_SECOND", "second");
        let responders = vec![
            env_resp("(?i)code", "SPT_TEST_KBI_FIRST", false),
            // Second responder *also* matches "code" — but the first should win.
            env_resp("(?i).*code.*", "SPT_TEST_KBI_SECOND", false),
        ];
        let backends: Vec<&dyn SecretBackend> = vec![];
        let mut p = ScriptedPrompter::new(&responders, &backends).unwrap();
        let prompts = vec![prompt("Enter code:", false)];
        let out = p.prompt("u", "i", &prompts);
        assert_eq!(out, vec!["first".to_owned()]);
        std::env::remove_var("SPT_TEST_KBI_FIRST");
        std::env::remove_var("SPT_TEST_KBI_SECOND");
    }

    #[test]
    fn static_answer_evaluates_to_literal() {
        let responders = vec![KbiResponder {
            prompt_regex: "(?i)acknowledge".into(),
            answer: KbiAnswer::Static("yes".into()),
            echo: false,
        }];
        let backends: Vec<&dyn SecretBackend> = vec![];
        let mut p = ScriptedPrompter::new(&responders, &backends).unwrap();
        let prompts = vec![prompt("Please acknowledge:", false)];
        let out = p.prompt("u", "i", &prompts);
        assert_eq!(out, vec!["yes".to_owned()]);
    }

    #[test]
    fn vault_backend_arm_resolves_via_provided_backend() {
        let canned = CannedBackend(b"vaultsecret".to_vec());
        let backends: Vec<&dyn SecretBackend> = vec![&canned];
        let responders = vec![KbiResponder {
            prompt_regex: "(?i)code".into(),
            answer: KbiAnswer::SecretRef(AuthSecretRef::Vault {
                namespace: "ns".into(),
                name: "n".into(),
            }),
            echo: false,
        }];
        let mut p = ScriptedPrompter::new(&responders, &backends).unwrap();
        let prompts = vec![prompt("Enter code:", false)];
        let out = p.prompt("u", "i", &prompts);
        assert_eq!(out, vec!["vaultsecret".to_owned()]);
    }

    #[test]
    fn totp_answer_dispatches_and_produces_six_digit_code() {
        // Use a raw 20-byte ASCII secret matching RFC 6238 §B.
        let canned = CannedBackend(b"12345678901234567890".to_vec());
        let backends: Vec<&dyn SecretBackend> = vec![&canned];
        let responders = vec![KbiResponder {
            prompt_regex: "(?i)otp.*code:".into(),
            answer: KbiAnswer::Totp {
                secret_ref: AuthSecretRef::Vault {
                    namespace: "ssh".into(),
                    name: "totp".into(),
                },
                digits: 6,
                period: 30,
                algo: spt_auth::TotpAlgo::Sha1,
            },
            echo: false,
        }];
        let mut p = ScriptedPrompter::new(&responders, &backends).unwrap();
        let prompts = vec![prompt("OTP verification code: ", false)];
        let out = p.prompt("u", "i", &prompts);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].len(), 6);
        assert!(out[0].chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn yubikey_answer_without_feature_yields_empty() {
        // YubikeyOath without the `yubikey` Cargo feature in spt-auth returns
        // UnsupportedPlatform — surfaced here as an empty answer + warn log.
        // spt-ssh2 does not enable the spt-auth/yubikey feature, so this
        // test exercises the disabled-path unconditionally.
        let responders = vec![KbiResponder {
            prompt_regex: "(?i)yubi".into(),
            answer: KbiAnswer::YubikeyOath {
                serial: None,
                oath_name: "github".into(),
            },
            echo: false,
        }];
        let backends: Vec<&dyn SecretBackend> = vec![];
        let mut p = ScriptedPrompter::new(&responders, &backends).unwrap();
        let prompts = vec![prompt("Yubikey OATH code:", false)];
        let out = p.prompt("u", "i", &prompts);
        assert_eq!(out, vec![String::new()]);
    }

    #[test]
    fn no_answers_no_prompts_yields_empty_vec() {
        let backends: Vec<&dyn SecretBackend> = vec![];
        let mut p = ScriptedPrompter::new(&[], &backends).unwrap();
        let out = p.prompt("u", "i", &[]);
        assert!(out.is_empty());
    }

    #[test]
    fn invalid_regex_surfaces_typed_error_at_construction() {
        let responders = vec![KbiResponder {
            prompt_regex: "(unclosed".into(),
            answer: KbiAnswer::Static("x".into()),
            echo: false,
        }];
        let backends: Vec<&dyn SecretBackend> = vec![];
        match ScriptedPrompter::new(&responders, &backends) {
            Ok(_) => panic!("expected invalid-regex error"),
            Err(e) => assert!(matches!(e, spt_core::Error::InvalidConfig(_))),
        }
    }
}
