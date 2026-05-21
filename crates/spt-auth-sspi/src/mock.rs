//! In-process mock GSS / SSPI provider for tests.
//!
//! [`MockGssProvider`] drives the same [`GssProvider`] state machine that a
//! real backend would, but with deterministic token bytes and a simple
//! XOR-based MIC. It is feature-gated behind `testing` so production builds
//! never link it.
//!
//! The mock supports two roles to drive a complete `gssapi-with-mic` round
//! trip in a single test:
//!
//! * **Initiator** — produced via [`MockGssProvider::initiator`]. Drives
//!   `initialize` for `rounds` calls and then declares `complete = true`.
//! * **Acceptor** — produced via [`MockGssProvider::acceptor`]. Verifies
//!   MICs that an initiator computed under the same shared seed.

use spt_core::{Error, Result};

use crate::{GssOutput, GssProvider};

/// Which side of the security context this mock represents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Calls `initialize` (i.e. the SSH client side).
    Initiator,
    /// Receives tokens (i.e. the SSH server side).
    Acceptor,
}

/// Which mechanism the mock simulates. The trait surface is identical for
/// both; the variant only changes the token-prefix byte so a test asserting
/// on the wire bytes can tell them apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MechMock {
    /// Pretend we are Kerberos v5.
    Kerberos,
    /// Pretend we are SSPI `NTLMv2`.
    Ntlm,
}

/// A scriptable [`GssProvider`].
#[derive(Debug, Clone)]
pub struct MockGssProvider {
    role: Role,
    mech: MechMock,
    /// Shared seed used by both sides to compute MICs deterministically.
    mic_key: Vec<u8>,
    /// Number of `initialize` round-trips before declaring `complete`.
    rounds: u8,
    /// Calls observed so far.
    observed: u8,
    /// Last target we were asked to authenticate to. Available to tests.
    last_target: Option<String>,
    /// Last input token observed by `initialize`.
    last_input: Option<Vec<u8>>,
}

impl MockGssProvider {
    /// Construct an initiator. `rounds = 1` is the fast happy-path (single
    /// `initialize` call returns `complete = true`); higher values force the
    /// caller to loop.
    pub fn initiator(mech: MechMock, rounds: u8, mic_key: &[u8]) -> Self {
        Self {
            role: Role::Initiator,
            mech,
            mic_key: mic_key.to_vec(),
            rounds: rounds.max(1),
            observed: 0,
            last_target: None,
            last_input: None,
        }
    }

    /// Construct an acceptor. The acceptor only services MIC verification —
    /// `initialize` is unused but defined for trait completeness.
    pub fn acceptor(mech: MechMock, mic_key: &[u8]) -> Self {
        Self {
            role: Role::Acceptor,
            mech,
            mic_key: mic_key.to_vec(),
            rounds: 1,
            observed: 0,
            last_target: None,
            last_input: None,
        }
    }

    /// Inspect the target supplied to the last `initialize` call.
    pub fn last_target(&self) -> Option<&str> {
        self.last_target.as_deref()
    }

    /// Inspect the input token supplied to the last `initialize` call.
    pub fn last_input(&self) -> Option<&[u8]> {
        self.last_input.as_deref()
    }

    /// Number of `initialize` calls observed.
    pub fn rounds_observed(&self) -> u8 {
        self.observed
    }

    fn mech_tag(&self) -> u8 {
        match self.mech {
            MechMock::Kerberos => 0xAB,
            MechMock::Ntlm => 0xCD,
        }
    }

    fn compute_mic(&self, message: &[u8]) -> Vec<u8> {
        // Deterministic, key-dependent — adequate for tests. NOT cryptographic.
        let mut out = Vec::with_capacity(message.len() + 1);
        out.push(self.mech_tag());
        for (i, b) in message.iter().enumerate() {
            let k = self.mic_key[i % self.mic_key.len().max(1)];
            out.push(b ^ k);
        }
        out
    }
}

impl GssProvider for MockGssProvider {
    fn initialize(&mut self, target: &str, input_token: Option<&[u8]>) -> Result<GssOutput> {
        if self.role != Role::Initiator {
            return Err(Error::AuthFailed(
                "MockGssProvider acceptor cannot call initialize".into(),
            ));
        }
        self.last_target = Some(target.to_owned());
        self.last_input = input_token.map(<[u8]>::to_vec);
        self.observed = self.observed.saturating_add(1);

        let mut token = vec![self.mech_tag(), self.observed];
        token.extend_from_slice(target.as_bytes());
        if let Some(t) = input_token {
            token.extend_from_slice(t);
        }
        let complete = self.observed >= self.rounds;
        Ok(GssOutput {
            token: Some(token),
            complete,
        })
    }

    fn get_mic(&self, message: &[u8]) -> Result<Vec<u8>> {
        Ok(self.compute_mic(message))
    }

    fn verify_mic(&self, message: &[u8], mic: &[u8]) -> Result<()> {
        let expected = self.compute_mic(message);
        if expected == mic {
            Ok(())
        } else {
            Err(Error::AuthFailed("MockGssProvider: MIC mismatch".into()))
        }
    }
}
