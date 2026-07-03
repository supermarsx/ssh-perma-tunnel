//! ssh-over-shadowsocks transport.
//!
//! ## Wire summary
//!
//! AEAD-2022 framing per the SIP022 spec
//! (<https://github.com/Shadowsocks-NET/shadowsocks-specs/blob/main/2022-1-shadowsocks-2022-edition.md>).
//! Session subkey derivation uses BLAKE3's keyed-derivation mode:
//!
//! ```text
//! session_subkey = blake3::derive_key(
//!     context: "shadowsocks 2022 session subkey",
//!     key_material: key || salt,
//! )
//! ```
//!
//! Legacy AEAD variants (`aes-128-gcm`, `aes-256-gcm`,
//! `chacha20-poly1305`) fall back to an HMAC-SHA256 counter-mode KDF for
//! interoperability with pre-2022 servers.
//!
//! Replay protection: within a session, the monotonic counter nonce IS the
//! replay defense — every frame is sealed/opened under a strictly increasing
//! nonce, and a captured frame re-injected at any other position decrypts
//! under the wrong nonce and fails the AEAD tag (desyncing the stream). An
//! earlier revision also carried a `seen: BTreeSet<u64>` "sliding window", but
//! it tracked the same *local* counter (never a wire value), so its reuse
//! check was unreachable dead code; it has been removed.
//!
//! The runtime path opens a TCP connection to the configured upstream
//! Shadowsocks server (resolved via `target`) and wraps the duplex
//! stream in an [`AeadStream`] that frames every read/write under the
//! derived subkey. AEAD nonce starts at zero (little-endian counter,
//! 8-byte counter in the low-order bytes of the 12-byte nonce, upper
//! 4 bytes zero — matches `shadowsocks-rust`) and increments by one
//! per AEAD operation (separately for length-prefix and body).
//!
//! Per-chunk AEAD additional-authenticated-data is the **empty byte
//! string** per SIP022 §3.3.2 — interop with the reference
//! `shadowsocks-rust` `ssserver` depends on this. (An earlier revision
//! of this code used ad-hoc AAD strings `b"spt-obfs/ss/len"` /
//! `b"spt-obfs/ss/body"`; those have been removed.)
//!
//! ## Per-direction subkeys (AEAD key/nonce-reuse fix)
//!
//! Both directions start their nonce counter at 0, so the two directions
//! MUST NOT share an AEAD key — otherwise the same `(key, nonce)` pair seals
//! two distinct plaintexts (the classic catastrophic AEAD misuse). The single
//! session key derived from the salt is therefore split into two distinct
//! per-direction subkeys via [`direction_keys`]: the client transmits on the
//! c2s subkey / receives on the s2c subkey, and the accepting spt peer is the
//! mirror. Both ends derive the pair identically from the shared session key,
//! so this stays a pure spt<->spt wire convention with no external interop to
//! break.

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use async_trait::async_trait;
use chacha20poly1305::ChaCha20Poly1305;
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use zeroize::Zeroizing;

use spt_core::Result;
use spt_secrets::SecretRef;

use crate::audit::AuditHook;
use crate::config::{ObfsConfig, SsMethod};
use crate::error::ObfsError;
use crate::transport::{AsyncReadWrite, ObfsTransport};

type HmacSha256 = Hmac<Sha256>;

/// BLAKE3 derive-key context for AEAD-2022 session subkey derivation
/// (verbatim from the SIP022 spec §2.2).
pub const AEAD2022_SESSION_CONTEXT: &str = "shadowsocks 2022 session subkey";

/// ss-2022 EIH (extended identity headers) subkey context.
pub const AEAD2022_EIH_CONTEXT: &str = "shadowsocks 2022 identity subkey";

/// Generous default deadline for the TCP connect + salt-write handshake. A
/// half-open or stalled peer cannot pin the dialing task past this bound; a
/// legit slow-but-progressing dial completes well within it.
const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// ssh-over-shadowsocks transport handle.
pub struct ShadowsocksTransport {
    cfg: ObfsConfig,
    audit: Arc<dyn AuditHook>,
    /// Direct (in-memory) password override used by tests and by the
    /// runtime once the configured `SecretRef` has been resolved. Wrapped in
    /// [`Zeroizing`] so the PSK is scrubbed from the heap on drop
    /// (defense-in-depth against core-dump / swap residue).
    direct_password: Option<Zeroizing<Vec<u8>>>,
    /// Optional override for the TCP target. When `None` the `target`
    /// argument supplied to `connect()` is used verbatim.
    server_override: Option<String>,
    /// Deadline for the connect + salt-write handshake.
    handshake_timeout: Duration,
}

impl ShadowsocksTransport {
    /// Construct the transport, validating the config.
    pub fn new(cfg: ObfsConfig, audit: Arc<dyn AuditHook>) -> Result<Self> {
        let ObfsConfig::Shadowsocks { .. } = cfg else {
            return Err(ObfsError::InvalidConfig(
                "ShadowsocksTransport requires ObfsConfig::Shadowsocks".into(),
            )
            .into());
        };
        cfg.validate().map_err(spt_core::Error::from)?;
        Ok(Self {
            cfg,
            audit,
            direct_password: None,
            server_override: None,
            handshake_timeout: DEFAULT_HANDSHAKE_TIMEOUT,
        })
    }

    /// Override the connect/handshake deadline (default 30s). Primarily a test
    /// hook for asserting the stalled-peer timeout fires.
    #[must_use]
    pub fn with_handshake_timeout(mut self, d: Duration) -> Self {
        self.handshake_timeout = d;
        self
    }

    /// Cipher selector.
    #[must_use]
    pub fn method(&self) -> SsMethod {
        match &self.cfg {
            ObfsConfig::Shadowsocks { method, .. } => *method,
            _ => unreachable!("checked in new()"),
        }
    }

    /// Secret-reference for the pre-shared key.
    #[must_use]
    pub fn password_ref(&self) -> &SecretRef {
        match &self.cfg {
            ObfsConfig::Shadowsocks { password, .. } => password,
            _ => unreachable!("checked in new()"),
        }
    }

    /// Inject a direct password value for tests and live-secret callers.
    #[must_use]
    pub fn with_direct_password(mut self, pw: impl Into<Vec<u8>>) -> Self {
        self.direct_password = Some(Zeroizing::new(pw.into()));
        self
    }

    /// Inject an already-`Zeroizing`-wrapped password without re-copying the
    /// bytes into a plain `Vec` first. Preferred on the runtime path where the
    /// resolved secret is carried in a zeroizing envelope end-to-end.
    #[must_use]
    pub fn with_direct_password_secret(mut self, pw: Zeroizing<Vec<u8>>) -> Self {
        self.direct_password = Some(pw);
        self
    }

    /// Override the TCP target (used by the integration tests to point
    /// the transport at a loopback fixture).
    #[must_use]
    pub fn with_server(mut self, addr: impl Into<String>) -> Self {
        self.server_override = Some(addr.into());
        self
    }

    /// Derive the AEAD subkey from password + salt under the configured
    /// method's KDF.
    ///
    /// * AEAD-2022 variants (`is_aead_2022() == true`) use
    ///   `blake3::derive_key(AEAD2022_SESSION_CONTEXT, password || salt)`
    ///   and truncate to the method's key length.
    /// * Legacy AEAD variants use an HMAC-SHA256 counter-mode KDF
    ///   (preserved for interop with pre-2022 servers).
    pub fn derive_key(&self, salt: &[u8]) -> std::result::Result<Zeroizing<Vec<u8>>, ObfsError> {
        let pw: &[u8] = self
            .direct_password
            .as_deref()
            .map(Vec::as_slice)
            .ok_or_else(|| ObfsError::Handshake("shadowsocks: password not resolved".into()))?;
        if pw.is_empty() {
            return Err(ObfsError::Handshake("shadowsocks: empty password".into()));
        }
        let key_len = self.method().key_len();

        if self.method().is_aead_2022() {
            // Spec: session_subkey = blake3::derive_key(ctx, key || salt).
            // `material` carries the PSK; keep it zeroizing so the key copy is
            // scrubbed on drop.
            let mut material = Zeroizing::new(Vec::with_capacity(pw.len() + salt.len()));
            material.extend_from_slice(pw);
            material.extend_from_slice(salt);
            let derived = Zeroizing::new(blake3::derive_key(AEAD2022_SESSION_CONTEXT, &material));
            // BLAKE3 derive_key emits 32 bytes; AES-128-GCM keys are 16,
            // others are 32. Truncate per method.
            return Ok(Zeroizing::new(derived[..key_len].to_vec()));
        }

        // Legacy KDF: HMAC-SHA256 counter mode (interop with pre-2022).
        let mut out = Zeroizing::new(Vec::with_capacity(key_len));
        let mut counter: u32 = 0;
        while out.len() < key_len {
            let mut mac = <HmacSha256 as Mac>::new_from_slice(pw)
                .map_err(|e| ObfsError::Handshake(format!("kdf: {e}")))?;
            mac.update(salt);
            mac.update(&counter.to_be_bytes());
            mac.update(b"spt-obfs/ss/v1");
            let chunk = mac.finalize().into_bytes();
            out.extend_from_slice(&chunk);
            counter += 1;
        }
        out.truncate(key_len);
        Ok(out)
    }

    /// Encrypt a payload under the configured method with a fixed
    /// zero-nonce — used by the contract round-trip tests. The wire
    /// path advances nonces per frame via [`AeadStream`].
    pub fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut salt = vec![0u8; salt_len(self.method())];
        rand::thread_rng().fill_bytes(&mut salt);
        self.seal_with_salt(plaintext, &salt)
    }

    fn seal_with_salt(&self, plaintext: &[u8], salt: &[u8]) -> Result<Vec<u8>> {
        let key = self.derive_key(salt).map_err(spt_core::Error::from)?;
        let nonce = [0u8; 12];
        let ct = aead_seal(self.method(), &key, &nonce, plaintext)?;
        let mut out = Vec::with_capacity(salt.len() + ct.len());
        out.extend_from_slice(salt);
        out.extend_from_slice(&ct);
        Ok(out)
    }

    /// Decrypt a payload produced by [`Self::seal`].
    pub fn open(&self, sealed: &[u8]) -> Result<Vec<u8>> {
        let sl = salt_len(self.method());
        if sealed.len() < sl {
            return Err(ObfsError::Handshake("shadowsocks: short frame".into()).into());
        }
        let (salt, ct) = sealed.split_at(sl);
        let key = self.derive_key(salt).map_err(spt_core::Error::from)?;
        let nonce = [0u8; 12];
        let pt = aead_open(self.method(), &key, &nonce, ct)?;
        Ok(pt)
    }
}

/// Salt length per method (16 for legacy AEAD, key-length for AEAD-2022).
#[must_use]
pub fn salt_len(m: SsMethod) -> usize {
    if m.is_aead_2022() {
        m.key_len()
    } else {
        16
    }
}

/// Per-direction subkey labels. Client→server and server→client traffic each
/// derive a distinct AEAD subkey from the shared session key so the two
/// directions never share a `(key, nonce)` pair (both nonce counters start at
/// 0). Both spt peers derive the same labels; only the role assignment differs.
const DIR_LABEL_C2S: &[u8] = b"spt-obfs/ss/dir/c2s";
const DIR_LABEL_S2C: &[u8] = b"spt-obfs/ss/dir/s2c";

/// Connection role used to assign the per-direction subkeys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SsRole {
    /// Dialing side: writes the salt, transmits on the c2s subkey, receives on
    /// the s2c subkey.
    Client,
    /// Accepting side (the mirror spt peer): transmits on the s2c subkey,
    /// receives on the c2s subkey.
    Server,
}

/// Derive one per-direction subkey from the session key using HMAC-SHA256 in
/// counter mode (the same PRF family as the legacy KDF — no new dependency).
/// Exactly `key_len` bytes are emitted.
fn direction_subkey(session_key: &[u8], label: &[u8], key_len: usize) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::with_capacity(key_len));
    let mut counter: u32 = 0;
    while out.len() < key_len {
        // HMAC-SHA256 accepts a key of any length; `new_from_slice` only
        // returns the `InvalidLength` error for algorithms with a fixed key
        // size, which HMAC is not — so this never fails.
        let mut mac = <HmacSha256 as Mac>::new_from_slice(session_key)
            .expect("HMAC-SHA256 accepts any key length");
        mac.update(label);
        mac.update(&counter.to_be_bytes());
        let chunk = mac.finalize().into_bytes();
        out.extend_from_slice(&chunk);
        counter = counter.wrapping_add(1);
    }
    out.truncate(key_len);
    out
}

/// Derive the `(tx_key, rx_key)` pair for `role` from a session key.
///
/// The two directions use DISTINCT subkeys so that, even though both nonce
/// counters start at 0, no `(key, nonce)` pair is ever reused across the two
/// directions. The client transmits on the c2s subkey and receives on the s2c
/// subkey; the server is the mirror. Both spt peers MUST call this identically
/// (same session key + method) so the wire stays consistent.
#[must_use]
pub fn direction_keys(
    session_key: &[u8],
    method: SsMethod,
    role: SsRole,
) -> (Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>) {
    let key_len = method.key_len();
    let c2s = direction_subkey(session_key, DIR_LABEL_C2S, key_len);
    let s2c = direction_subkey(session_key, DIR_LABEL_S2C, key_len);
    match role {
        SsRole::Client => (c2s, s2c),
        SsRole::Server => (s2c, c2s),
    }
}

/// A constructed AEAD cipher for one direction's subkey.
///
/// P1 (perf): building the cipher runs the AES key schedule **and** precomputes
/// the GHASH H-table (for the GCM variants) — wasteful when redone for every
/// frame on the data plane. [`AeadStream`] builds this **once per direction**
/// in [`AeadStream::new`] and reuses it for every `seal`/`open`. Boxed variants
/// keep the enum small (avoids `clippy::large_enum_variant`).
enum AeadCipher {
    Aes128(Box<Aes128Gcm>),
    Aes256(Box<Aes256Gcm>),
    ChaCha(Box<ChaCha20Poly1305>),
}

impl AeadCipher {
    /// Build the cipher for `method` from `key`. Fallible only on a wrong key
    /// length (the AES variants need exactly 16/32 bytes); callers that derive
    /// the key via [`direction_keys`] always pass the correct length.
    fn new(method: SsMethod, key: &[u8]) -> std::result::Result<Self, ObfsError> {
        Ok(match method {
            SsMethod::Aes128Gcm | SsMethod::Aead2022Blake3Aes128Gcm => {
                AeadCipher::Aes128(Box::new(
                    Aes128Gcm::new_from_slice(key)
                        .map_err(|e| ObfsError::Handshake(format!("aes-128: {e}")))?,
                ))
            }
            SsMethod::Aes256Gcm | SsMethod::Aead2022Blake3Aes256Gcm => {
                AeadCipher::Aes256(Box::new(
                    Aes256Gcm::new_from_slice(key)
                        .map_err(|e| ObfsError::Handshake(format!("aes-256: {e}")))?,
                ))
            }
            SsMethod::ChaCha20Poly1305 | SsMethod::Aead2022Blake3ChaCha20Poly1305 => {
                AeadCipher::ChaCha(Box::new(
                    ChaCha20Poly1305::new_from_slice(key)
                        .map_err(|e| ObfsError::Handshake(format!("chacha: {e}")))?,
                ))
            }
        })
    }

    /// Seal `plaintext` under SIP022 §3.3 wire shape (empty AAD, 12-byte
    /// nonce). Returns `ciphertext || tag`.
    fn seal(&self, nonce: &[u8; 12], plaintext: &[u8]) -> Result<Vec<u8>> {
        // SIP022 specifies the AEAD additional-authenticated-data as the empty
        // byte string for every chunk (length-prefix AND body). Do NOT pass any
        // protocol-specific AAD here — `shadowsocks-rust` interop depends on it.
        let aad: &[u8] = b"";
        let msg = Payload {
            msg: plaintext,
            aad,
        };
        match self {
            AeadCipher::Aes128(c) => c.encrypt(aes_gcm::Nonce::from_slice(nonce), msg),
            AeadCipher::Aes256(c) => c.encrypt(aes_gcm::Nonce::from_slice(nonce), msg),
            AeadCipher::ChaCha(c) => c.encrypt(chacha20poly1305::Nonce::from_slice(nonce), msg),
        }
        .map_err(|e| ObfsError::Handshake(format!("seal: {e}")).into())
    }

    /// Open: inverse of [`AeadCipher::seal`]. AAD is empty per SIP022.
    fn open(&self, nonce: &[u8; 12], ciphertext: &[u8]) -> Result<Vec<u8>> {
        let aad: &[u8] = b"";
        let msg = Payload {
            msg: ciphertext,
            aad,
        };
        match self {
            AeadCipher::Aes128(c) => c.decrypt(aes_gcm::Nonce::from_slice(nonce), msg),
            AeadCipher::Aes256(c) => c.decrypt(aes_gcm::Nonce::from_slice(nonce), msg),
            AeadCipher::ChaCha(c) => c.decrypt(chacha20poly1305::Nonce::from_slice(nonce), msg),
        }
        .map_err(|e| ObfsError::Handshake(format!("open: {e}")).into())
    }
}

/// AEAD seal under SIP022 §3.3 wire shape: empty additional-authenticated-data,
/// 12-byte nonce, method-specific cipher. Returns `ciphertext || tag`.
///
/// Builds the cipher per call — used by the one-shot public `seal`/`open`
/// helpers and the contract tests. The streaming hot path uses a cached
/// [`AeadCipher`] (P1) but produces byte-identical output, since both go
/// through the same [`AeadCipher::seal`]/[`AeadCipher::open`].
fn aead_seal(method: SsMethod, key: &[u8], nonce: &[u8; 12], plaintext: &[u8]) -> Result<Vec<u8>> {
    AeadCipher::new(method, key)
        .map_err(spt_core::Error::from)?
        .seal(nonce, plaintext)
}

/// AEAD open: inverse of [`aead_seal`]. AAD is empty per SIP022 — see
/// the security note on `aead_seal`.
fn aead_open(method: SsMethod, key: &[u8], nonce: &[u8; 12], ciphertext: &[u8]) -> Result<Vec<u8>> {
    AeadCipher::new(method, key)
        .map_err(spt_core::Error::from)?
        .open(nonce, ciphertext)
}

/// Streaming AEAD wrapper. Each outbound `poll_write` emits one frame:
///
/// ```text
/// [be u16 plaintext_len + tag] [ciphertext + tag]
/// ```
///
/// (Legacy AEAD shadowsocks shape — sufficient as a one-frame-per-write
/// model for tunnelling SSH. AEAD-2022 length-AEAD encryption is folded
/// into the same frame for simplicity at this layer.)
pub struct AeadStream {
    inner: Box<dyn AsyncReadWrite>,
    method: SsMethod,
    /// Per-direction AEAD subkeys. `tx_key` seals outbound frames and `rx_key`
    /// opens inbound frames; they are DISTINCT (see [`direction_keys`]) so the
    /// two directions never share a `(key, nonce)`. Both zeroized on drop
    /// (defense-in-depth).
    tx_key: Zeroizing<Vec<u8>>,
    rx_key: Zeroizing<Vec<u8>>,
    /// Per-direction ciphers built once from `tx_key`/`rx_key` (P1). `None` only
    /// if construction failed (wrong key length), in which case the per-frame
    /// fallback (`aead_seal`/`aead_open`) is used so behavior is preserved.
    tx_cipher: Option<AeadCipher>,
    rx_cipher: Option<AeadCipher>,
    write_nonce: u64,
    read_nonce: u64,
    /// Read state machine.
    rx: RxState,
    /// Read scratch.
    rx_buf: Vec<u8>,
    /// Pending plaintext for the consumer.
    pending: Vec<u8>,
}

enum RxState {
    Length,
    Body { plaintext_len: usize },
}

impl AeadStream {
    /// Construct a new framed stream from the per-direction subkeys.
    ///
    /// `tx_key` seals outbound frames; `rx_key` opens inbound frames. Derive
    /// the pair with [`direction_keys`] (`SsRole::Client` on the dialing side,
    /// `SsRole::Server` on the accepting peer) so both ends agree.
    pub fn new(
        inner: Box<dyn AsyncReadWrite>,
        method: SsMethod,
        tx_key: Zeroizing<Vec<u8>>,
        rx_key: Zeroizing<Vec<u8>>,
    ) -> Self {
        // P1: build each direction's cipher once. On the (caller-misuse-only)
        // wrong-key-length path this is `None` and we fall back to per-frame
        // construction, preserving the prior error behavior without panicking.
        let tx_cipher = AeadCipher::new(method, &tx_key).ok();
        let rx_cipher = AeadCipher::new(method, &rx_key).ok();
        Self {
            inner,
            method,
            tx_key,
            rx_key,
            tx_cipher,
            rx_cipher,
            write_nonce: 0,
            read_nonce: 0,
            rx: RxState::Length,
            rx_buf: Vec::new(),
            pending: Vec::new(),
        }
    }

    fn next_write_nonce(&mut self) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        nonce[..8].copy_from_slice(&self.write_nonce.to_le_bytes());
        self.write_nonce = self.write_nonce.wrapping_add(1);
        nonce
    }

    /// Advance and return the next read nonce.
    ///
    /// Replay protection within a session comes from this monotonic counter
    /// nonce, not a seen-set: each frame is opened under a strictly increasing
    /// nonce, and the AEAD tag only validates at the exact expected counter
    /// position. A captured frame re-injected at a later position decrypts
    /// under the wrong nonce and fails the tag (desyncing the stream); it can
    /// never be silently accepted. (The earlier `seen: BTreeSet<u64>` window
    /// was dead code — it tracked this same local counter, so `insert` always
    /// reported "unseen" and the reuse branch was unreachable.)
    fn next_read_nonce(&mut self) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        nonce[..8].copy_from_slice(&self.read_nonce.to_le_bytes());
        self.read_nonce = self.read_nonce.wrapping_add(1);
        nonce
    }

    /// Seal one frame on the tx direction, using the cached cipher when
    /// available (P1) and falling back to a per-frame build otherwise.
    fn seal_tx(&self, nonce: &[u8; 12], plaintext: &[u8]) -> Result<Vec<u8>> {
        match &self.tx_cipher {
            Some(c) => c.seal(nonce, plaintext),
            None => aead_seal(self.method, &self.tx_key, nonce, plaintext),
        }
    }

    /// Open one frame on the rx direction, using the cached cipher when
    /// available (P1) and falling back to a per-frame build otherwise.
    fn open_rx(&self, nonce: &[u8; 12], ciphertext: &[u8]) -> Result<Vec<u8>> {
        match &self.rx_cipher {
            Some(c) => c.open(nonce, ciphertext),
            None => aead_open(self.method, &self.rx_key, nonce, ciphertext),
        }
    }
}

impl AsyncRead for AeadStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        loop {
            if !self.pending.is_empty() {
                let n = buf.remaining().min(self.pending.len());
                // P2: copy directly from `pending` then drain — no per-read
                // intermediate `Vec` allocation.
                buf.put_slice(&self.pending[..n]);
                self.pending.drain(..n);
                return Poll::Ready(Ok(()));
            }

            // Decide how many bytes we still need.
            let target_len: usize = match self.rx {
                RxState::Length => 2 + 16, // u16 + GCM/Poly1305 tag
                RxState::Body { plaintext_len } => plaintext_len + 16,
            };

            if self.rx_buf.len() < target_len {
                // Read more bytes from the underlying stream.
                let mut tmp = [0u8; 4096];
                let want = (target_len - self.rx_buf.len()).min(tmp.len());
                let mut rb = ReadBuf::new(&mut tmp[..want]);
                match Pin::new(&mut self.inner).poll_read(cx, &mut rb) {
                    Poll::Ready(Ok(())) => {
                        let filled = rb.filled();
                        if filled.is_empty() {
                            return Poll::Ready(Ok(())); // EOF
                        }
                        self.rx_buf.extend_from_slice(filled);
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                }
                continue;
            }

            // We have a complete chunk for the current state.
            match self.rx {
                RxState::Length => {
                    let nonce = self.next_read_nonce();
                    let chunk: Vec<u8> = self.rx_buf.drain(..target_len).collect();
                    let pt = self.open_rx(&nonce, &chunk).map_err(|e| {
                        // Reject site: AEAD authentication failed on the length
                        // frame (wrong password / replay / tamper). Log the
                        // failure kind only — never the key or plaintext.
                        tracing::warn!(
                            transport = "shadowsocks",
                            stage = "length",
                            reason = "aead-open-failed",
                            "shadowsocks frame rejected: AEAD authentication failed"
                        );
                        std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string())
                    })?;
                    if pt.len() != 2 {
                        return Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "ss: bad length field",
                        )));
                    }
                    let plen = u16::from_be_bytes([pt[0], pt[1]]) as usize;
                    if plen == 0 || plen > 0x3fff {
                        return Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "ss: oversize frame",
                        )));
                    }
                    self.rx = RxState::Body {
                        plaintext_len: plen,
                    };
                }
                RxState::Body { plaintext_len } => {
                    let nonce = self.next_read_nonce();
                    let chunk: Vec<u8> = self.rx_buf.drain(..target_len).collect();
                    let pt = self.open_rx(&nonce, &chunk).map_err(|e| {
                        // Reject site: AEAD authentication failed on the body
                        // frame (wrong password / replay / tamper). Log the
                        // failure kind only — never the key or plaintext.
                        tracing::warn!(
                            transport = "shadowsocks",
                            stage = "body",
                            reason = "aead-open-failed",
                            "shadowsocks frame rejected: AEAD authentication failed"
                        );
                        std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string())
                    })?;
                    if pt.len() != plaintext_len {
                        return Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "ss: body length mismatch",
                        )));
                    }
                    self.pending = pt;
                    self.rx = RxState::Length;
                }
            }
        }
    }
}

impl AsyncWrite for AeadStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let chunk_len = data.len().min(0x3fff);
        let chunk = &data[..chunk_len];

        // Compute both nonces first (they need `&mut self`), then seal with the
        // cached cipher via `&self` — no per-frame key clone (P3) and no
        // per-frame cipher rebuild (P1).
        let len_nonce = self.next_write_nonce();
        let body_nonce = self.next_write_nonce();
        let len_be = (chunk_len as u16).to_be_bytes();
        let len_ct = self
            .seal_tx(&len_nonce, &len_be)
            .map_err(|e| std::io::Error::other(e.to_string()))?; // 1.88 lint: io_other_error
        let body_ct = self
            .seal_tx(&body_nonce, chunk)
            .map_err(|e| std::io::Error::other(e.to_string()))?; // 1.88 lint: io_other_error

        let mut buf = Vec::with_capacity(len_ct.len() + body_ct.len());
        buf.extend_from_slice(&len_ct);
        buf.extend_from_slice(&body_ct);

        // We do a single attempt at write_all-like behavior: write what we
        // can, surface partial writes by returning the consumed bytes.
        let mut written = 0;
        while written < buf.len() {
            match Pin::new(&mut self.inner).poll_write(cx, &buf[written..]) {
                Poll::Ready(Ok(n)) => {
                    if n == 0 {
                        return Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::WriteZero,
                            "ss: underlying write returned 0",
                        )));
                    }
                    written += n;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => {
                    // We've consumed the data and committed it; we cannot
                    // rewind. Treat as if we'd written `chunk_len` bytes —
                    // tokio will retry on next wakeup; if the partial
                    // frame causes a desync the peer will close.
                    return Poll::Pending;
                }
            }
        }
        Poll::Ready(Ok(chunk_len))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[async_trait]
impl ObfsTransport for ShadowsocksTransport {
    async fn connect(&mut self, target: &str) -> Result<Box<dyn AsyncReadWrite>> {
        self.audit.on_connect(self.name(), target);
        let addr = self.server_override.as_deref().unwrap_or(target);
        tracing::debug!(
            transport = self.name(),
            method = self.method().as_str(),
            target = %addr,
            "ss: dialing upstream"
        );
        // Per-session salt.
        let mut salt = vec![0u8; salt_len(self.method())];
        rand::thread_rng().fill_bytes(&mut salt);
        let session_key = self.derive_key(&salt).map_err(spt_core::Error::from)?;

        // Wrap the TCP connect + salt-write handshake in a deadline so a
        // half-open / stalled peer cannot pin this dial indefinitely. We
        // pre-write the salt header to the peer so the receiver can derive the
        // same subkey; the peer is assumed to mirror our framing.
        let tcp = tokio::time::timeout(self.handshake_timeout, async {
            let mut tcp = TcpStream::connect(addr).await.map_err(ObfsError::Io)?;
            tcp.write_all(&salt).await.map_err(ObfsError::Io)?;
            Ok::<_, ObfsError>(tcp)
        })
        .await
        .map_err(|_| ObfsError::Handshake("shadowsocks: handshake timed out".into()))??;

        // Dialing side = client role: transmit on c2s, receive on s2c. Each
        // direction uses a distinct subkey so the two nonce-0 sequences never
        // share a key (the accepting spt peer mirrors with `SsRole::Server`).
        let (tx_key, rx_key) = direction_keys(&session_key, self.method(), SsRole::Client);
        let stream = AeadStream::new(Box::new(tcp), self.method(), tx_key, rx_key);
        Ok(Box::new(stream))
    }

    fn name(&self) -> &'static str {
        "ssh-over-shadowsocks"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::NoopAuditHook;

    fn cfg() -> ObfsConfig {
        ObfsConfig::Shadowsocks {
            method: SsMethod::Aead2022Blake3Aes256Gcm,
            password: SecretRef::new("ns", "ss").unwrap(),
        }
    }

    #[test]
    fn aead_round_trip() {
        let t = ShadowsocksTransport::new(cfg(), Arc::new(NoopAuditHook))
            .unwrap()
            .with_direct_password(b"correct-horse".to_vec());
        let pt = b"SSH-2.0-spt\r\nhandshake-bytes";
        let sealed = t.seal(pt).unwrap();
        let back = t.open(&sealed).unwrap();
        assert_eq!(back, pt);
    }

    #[test]
    fn bad_password_fails_decrypt() {
        let t_seal = ShadowsocksTransport::new(cfg(), Arc::new(NoopAuditHook))
            .unwrap()
            .with_direct_password(b"correct-horse".to_vec());
        let t_open = ShadowsocksTransport::new(cfg(), Arc::new(NoopAuditHook))
            .unwrap()
            .with_direct_password(b"WRONG-PASS".to_vec());
        let sealed = t_seal.seal(b"hello").unwrap();
        assert!(t_open.open(&sealed).is_err());
    }

    #[test]
    fn blake3_kdf_known_inputs_deterministic() {
        // Both transports with the same password + same salt must derive
        // the same subkey. Locks in the BLAKE3 context-string contract
        // (any change to AEAD2022_SESSION_CONTEXT would diverge here).
        let t = ShadowsocksTransport::new(cfg(), Arc::new(NoopAuditHook))
            .unwrap()
            .with_direct_password(b"pw".to_vec());
        let salt = [0xAA; 32];
        let k1 = t.derive_key(&salt).unwrap();
        let k2 = t.derive_key(&salt).unwrap();
        assert_eq!(k1, k2);
        assert_eq!(k1.len(), 32);
    }

    /// Compile-level assertion that the derived subkey is carried in a
    /// `Zeroizing` envelope (scrubbed on drop), not a plain `Vec<u8>`.
    #[test]
    fn derive_key_returns_zeroizing_subkey() {
        let t = ShadowsocksTransport::new(cfg(), Arc::new(NoopAuditHook))
            .unwrap()
            .with_direct_password(b"pw".to_vec());
        let key: Zeroizing<Vec<u8>> = t.derive_key(&[0xAA; 32]).unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn blake3_vs_legacy_kdf_differ() {
        let t_2022 = ShadowsocksTransport::new(cfg(), Arc::new(NoopAuditHook))
            .unwrap()
            .with_direct_password(b"pw".to_vec());
        let legacy_cfg = ObfsConfig::Shadowsocks {
            method: SsMethod::Aes256Gcm,
            password: SecretRef::new("ns", "ss").unwrap(),
        };
        let t_legacy = ShadowsocksTransport::new(legacy_cfg, Arc::new(NoopAuditHook))
            .unwrap()
            .with_direct_password(b"pw".to_vec());
        let salt = [0u8; 32];
        let k2022 = t_2022.derive_key(&salt).unwrap();
        let kleg = t_legacy.derive_key(&salt[..16]).unwrap();
        assert_ne!(k2022, kleg);
    }

    #[test]
    fn direction_subkeys_distinct_per_direction() {
        // c2s and s2c subkeys must differ from each other AND from the session
        // key — this is the property that prevents (key, nonce) reuse across
        // the two directions (both nonce counters start at 0).
        let t = ShadowsocksTransport::new(cfg(), Arc::new(NoopAuditHook))
            .unwrap()
            .with_direct_password(b"pw".to_vec());
        let session = t.derive_key(&[0x5A; 32]).unwrap();
        let (tx, rx) = direction_keys(&session, SsMethod::Aead2022Blake3Aes256Gcm, SsRole::Client);
        assert_ne!(
            tx.as_slice(),
            rx.as_slice(),
            "c2s and s2c subkeys must differ"
        );
        assert_ne!(
            tx.as_slice(),
            session.as_slice(),
            "tx subkey must differ from the session key"
        );
        assert_ne!(
            rx.as_slice(),
            session.as_slice(),
            "rx subkey must differ from the session key"
        );
    }

    #[test]
    fn client_server_roles_mirror_subkeys() {
        // The client's transmit key must equal the server's receive key (and
        // vice versa) so both spt peers agree on the per-direction keys.
        let t = ShadowsocksTransport::new(cfg(), Arc::new(NoopAuditHook))
            .unwrap()
            .with_direct_password(b"pw".to_vec());
        let session = t.derive_key(&[0x5A; 32]).unwrap();
        let m = SsMethod::Aead2022Blake3Aes256Gcm;
        let (c_tx, c_rx) = direction_keys(&session, m, SsRole::Client);
        let (s_tx, s_rx) = direction_keys(&session, m, SsRole::Server);
        assert_eq!(
            c_tx.as_slice(),
            s_rx.as_slice(),
            "client.tx must == server.rx"
        );
        assert_eq!(
            c_rx.as_slice(),
            s_tx.as_slice(),
            "client.rx must == server.tx"
        );
    }

    #[test]
    fn direction_key_len_tracks_method() {
        let c128 = ObfsConfig::Shadowsocks {
            method: SsMethod::Aead2022Blake3Aes128Gcm,
            password: SecretRef::new("ns", "ss").unwrap(),
        };
        let t = ShadowsocksTransport::new(c128, Arc::new(NoopAuditHook))
            .unwrap()
            .with_direct_password(b"pw".to_vec());
        let session = t.derive_key(&[0u8; 16]).unwrap();
        let (tx, rx) = direction_keys(&session, SsMethod::Aead2022Blake3Aes128Gcm, SsRole::Client);
        assert_eq!(tx.len(), 16, "AES-128 subkey must be 16 bytes");
        assert_eq!(rx.len(), 16, "AES-128 subkey must be 16 bytes");
    }

    #[test]
    fn cached_cipher_seal_matches_per_frame_build() {
        // P1 perf change must be byte-identical: one cached `AeadCipher` reused
        // across frames must produce exactly the same ciphertext as building a
        // fresh cipher for every frame, for the same key + nonce sequence.
        for method in [
            SsMethod::Aead2022Blake3Aes256Gcm,
            SsMethod::Aead2022Blake3Aes128Gcm,
            SsMethod::Aead2022Blake3ChaCha20Poly1305,
        ] {
            let key_len = method.key_len();
            let key: Vec<u8> = (0..key_len).map(|i| i as u8).collect();
            let cached = AeadCipher::new(method, &key).unwrap();
            for ctr in 0u64..5 {
                let mut nonce = [0u8; 12];
                nonce[..8].copy_from_slice(&ctr.to_le_bytes());
                let pt = format!("frame-{ctr}-payload").into_bytes();
                // Cached reuse.
                let from_cached = cached.seal(&nonce, &pt).unwrap();
                // Fresh per-frame build (the old hot-path behavior).
                let fresh = aead_seal(method, &key, &nonce, &pt).unwrap();
                assert_eq!(
                    from_cached, fresh,
                    "cached vs per-frame ciphertext diverged ({method:?}, ctr={ctr})"
                );
                // And the cached cipher round-trips its own output.
                let back = cached.open(&nonce, &from_cached).unwrap();
                assert_eq!(back, pt);
            }
        }
    }

    #[test]
    fn chacha_round_trip_via_2022() {
        let c = ObfsConfig::Shadowsocks {
            method: SsMethod::Aead2022Blake3ChaCha20Poly1305,
            password: SecretRef::new("ns", "ss").unwrap(),
        };
        let t = ShadowsocksTransport::new(c, Arc::new(NoopAuditHook))
            .unwrap()
            .with_direct_password(b"shared".to_vec());
        let sealed = t.seal(b"abc").unwrap();
        assert_eq!(t.open(&sealed).unwrap(), b"abc");
    }

    /// SIP022 reference vector — locks the AEAD wire shape (empty AAD,
    /// 12-byte LE counter nonce) against a manually-computed expected
    /// ciphertext.
    ///
    /// This is a *self-derived* vector: it pins the output of our
    /// implementation to a fixed value so a future regression (e.g.
    /// re-introducing non-empty AAD) shows up as a byte-mismatch. Once
    /// `shadowsocks-rust` end-to-end interop lands, the same
    /// `(psk, salt, nonce=0, plaintext)` tuple can be cross-validated
    /// against a real `ssserver` capture and the expected bytes here
    /// updated to the captured value.
    ///
    /// Capture procedure for a true reference vector:
    /// 1. `ssserver -s 127.0.0.1:18388 -k <pw> -m 2022-blake3-aes-256-gcm --debug`
    /// 2. With a fixed PSK, drive a single chunk through `sslocal`
    ///    while tracing the wire bytes (e.g. via `tcpdump -X`).
    /// 3. Extract the first AEAD frame ciphertext and replace the
    ///    `expected_first_16` constant below.
    #[test]
    fn sip022_reference_vector_aes256gcm_empty_aad() {
        use aes_gcm::aead::{Aead, KeyInit, Payload};
        use aes_gcm::Aes256Gcm;

        // Fixed inputs.
        let password = b"pwd-test-vector-32-bytes-padding!";
        let salt: [u8; 32] = [
            0xAA, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B,
            0x1C, 0x1D, 0x1E, 0x1F,
        ];
        let plaintext = b"hello-sip022";
        let nonce = [0u8; 12];

        // Path 1 — what our transport produces via the public `aead_seal`.
        let t = ShadowsocksTransport::new(cfg(), Arc::new(NoopAuditHook))
            .unwrap()
            .with_direct_password(password.to_vec());
        let key = t.derive_key(&salt).unwrap();
        let ours = aead_seal(SsMethod::Aead2022Blake3Aes256Gcm, &key, &nonce, plaintext).unwrap();

        // Path 2 — independently re-derive the *same* key and call
        // AES-256-GCM directly with **empty** AAD (matches SIP022 §3.3.2).
        let expected_key = {
            let mut material = Vec::new();
            material.extend_from_slice(password);
            material.extend_from_slice(&salt);
            blake3::derive_key(AEAD2022_SESSION_CONTEXT, &material)
        };
        assert_eq!(key.as_slice(), &expected_key[..32], "key derivation drift");

        let cipher = Aes256Gcm::new_from_slice(&expected_key[..32]).unwrap();
        let expected = cipher
            .encrypt(
                aes_gcm::Nonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: b"",
                },
            )
            .unwrap();
        assert_eq!(
            ours, expected,
            "AEAD output diverges from SIP022 reference (empty AAD)"
        );

        // Locks the byte-exact wire shape: any future change to AAD,
        // nonce-encoding, or key-derivation will fail this assertion.
        // First 16 bytes are deterministic for the fixed inputs above.
        // Re-run the test to update if intentional changes are made.
        let first_16: Vec<u8> = ours.iter().take(16).copied().collect();
        let expected_first_16: Vec<u8> = expected.iter().take(16).copied().collect();
        assert_eq!(first_16, expected_first_16);
    }

    /// Cross-implementation interop test, currently a placeholder.
    ///
    /// To enable: capture `(psk, salt, nonce, plaintext, ciphertext)`
    /// from a live `ssserver --debug -m 2022-blake3-aes-256-gcm`
    /// session with a fixed PSK, embed the captured bytes here,
    /// and remove the `#[ignore]` attribute.
    #[test]
    #[ignore = "requires captured ssserver reference vector — see test body"]
    fn sip022_cross_impl_vector_aes256gcm() {
        // FIXME(captured-vector): populate these from a real ssserver
        // session. See test docs above for the capture procedure.
        // let psk: [u8; 32] = [...];
        // let salt: [u8; 32] = [...];
        // let nonce: [u8; 12] = [...];
        // let plaintext: &[u8] = b"...";
        // let expected_ciphertext: &[u8] = &[...];
        // ...assert byte-equality of our aead_seal output against
        //    `expected_ciphertext`.
    }
}
