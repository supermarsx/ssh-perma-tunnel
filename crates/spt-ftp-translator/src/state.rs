//! Per-session state machine.

use std::sync::Arc;

use tokio::net::TcpListener;

/// Where the session is in the USER/PASS login sequence.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum LoginPhase {
    /// Awaiting USER.
    Anonymous,
    /// USER seen; awaiting PASS.
    AwaitingPass,
    /// Fully authenticated.
    LoggedIn,
}

/// Transfer type negotiated via the TYPE verb.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TransferType {
    /// ASCII (RFC 959 §3.1.1.1) — accepted only when the codepage is
    /// compatible; otherwise rejected with 504.
    Ascii,
    /// Binary / image. The default.
    Image,
}

/// Transfer mode (MODE verb). Only `S` (stream) is supported.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TransferMode {
    /// Stream mode. The only one we accept.
    Stream,
}

/// Whether the control channel is currently wrapped in TLS.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ControlState {
    /// Plaintext control channel.
    Plain,
    /// AUTH TLS has been completed; CC is encrypted.
    Encrypted,
}

/// Per-session state. Owned by the session task; mutated only from there
/// (no interior mutability needed).
///
/// Deliberately NOT `Clone`: it owns the session's pending passive
/// [`TcpListener`], which must never be duplicated or shared across sessions
/// (see [`Self::pending_listener`]).
pub struct SessionState {
    /// Login phase.
    pub login: LoginPhase,
    /// Last USER value seen (between USER and PASS).
    pub pending_user: Option<String>,
    /// Authenticated username (only set in `LoggedIn`).
    pub user: Option<String>,
    /// Active transfer type.
    pub ttype: TransferType,
    /// Active transfer mode.
    pub mode: TransferMode,
    /// Control channel encryption status.
    pub control: ControlState,
    /// `PBSZ 0` issued? Required before `PROT P` per RFC 4217.
    pub pbsz_set: bool,
    /// `PROT P` issued? Data channels honour PROT P only when the
    /// control channel is encrypted and PBSZ was set.
    pub prot_private: bool,
    /// Current working directory (relative to the SFTP root).
    pub cwd: String,
    /// Pending rename source (RNFR → RNTO).
    pub rnfr: Option<String>,
    /// The SFTP client opened on behalf of `user`. `None` until login
    /// completes successfully.
    pub sftp: Option<Arc<spt_sftp::SftpClient>>,
    /// Pending passive-mode data listener bound by `PASV`/`EPSV`, consumed by
    /// the next data-transfer verb (LIST/RETR/STOR/APPE/...).
    ///
    /// H1: this lives in the per-session state — NOT a shared thread-local —
    /// so two sessions multiplexed onto the same Tokio worker thread can never
    /// observe or overwrite each other's data channel. A session can only ever
    /// use the listener it bound itself.
    pub pending_listener: Option<TcpListener>,
}

impl Default for SessionState {
    fn default() -> Self {
        Self {
            login: LoginPhase::Anonymous,
            pending_user: None,
            user: None,
            ttype: TransferType::Image,
            mode: TransferMode::Stream,
            control: ControlState::Plain,
            pbsz_set: false,
            prot_private: false,
            cwd: "/".to_string(),
            rnfr: None,
            sftp: None,
            pending_listener: None,
        }
    }
}

impl SessionState {
    /// New state machine in its initial position.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Quick predicate: is the session ready to issue file ops?
    #[must_use]
    pub fn is_logged_in(&self) -> bool {
        matches!(self.login, LoginPhase::LoggedIn) && self.sftp.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_anonymous_phase() {
        let s = SessionState::new();
        assert_eq!(s.login, LoginPhase::Anonymous);
        assert_eq!(s.ttype, TransferType::Image);
        assert_eq!(s.mode, TransferMode::Stream);
        assert_eq!(s.control, ControlState::Plain);
        assert!(!s.is_logged_in());
    }
}
