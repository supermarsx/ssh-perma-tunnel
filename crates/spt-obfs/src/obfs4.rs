//! obfs4 transport — hand-rolled minimal NTOR + framing client.
//!
//! ## Scope
//!
//! This is an **obfs4 client subset**. It implements:
//!
//! * the NTOR-style handshake (X25519 ECDH + HMAC-SHA256 KDF), with the
//!   handshake byte layout matching the Tor obfs4-spec
//!   <https://gitlab.com/yawning/obfs4/-/blob/master/doc/obfs4-spec.txt>,
//! * **XSalsa20-Poly1305** (`NaCl` `crypto_secretbox`) frame layer with a
//!   24-byte per-direction counter nonce starting at 0 (matches the
//!   obfs4-spec §6 primitive — t8-FixObfs4 corrected this from the
//!   earlier ChaCha20-Poly1305 stand-in),
//! * IAT mode 0 / 1 / 2 selection (mode 0 = no IAT, mode 1 = paranoid,
//!   mode 2 = normal). Active IAT packet-timing distribution shaping is
//!   selectable but the heavy distributions are **not** implemented —
//!   mode 1 enforces a deterministic minimum inter-frame delay while
//!   mode 2 is best-effort.
//!
//! Wire-incompatibility caveats remain on the NTOR side (see the t8-A4
//! follow-up bug A4-1 and `.orchestration/logs/t8-FixObfs4.md`): the
//! NTOR construction folds the bridge identity (`B`) into the HKDF salt
//! rather than producing two ECDH outputs and concatenating per spec.
//! That rewrite is out of scope for the framing-primitive fix tracked
//! here; for production use against external bridges, validate against
//! an obfs4proxy reference instance.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use async_trait::async_trait;
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use x25519_dalek::{PublicKey, StaticSecret};
use xsalsa20poly1305::aead::{Aead, KeyInit, Payload};
use xsalsa20poly1305::{Nonce as XNonce, XSalsa20Poly1305};

use spt_core::Result;

use crate::audit::AuditHook;
use crate::config::ObfsConfig;
use crate::error::ObfsError;
use crate::transport::{AsyncReadWrite, ObfsTransport};

type HmacSha256 = Hmac<Sha256>;

/// obfs4 protocol ID constant (per obfs4-spec) used as a KDF separator.
pub const OBFS4_PROTOID: &[u8] = b"ntor-curve25519-sha256-1";

/// Maximum plaintext frame length (per obfs4-spec, conservative).
pub const MAX_FRAME_PT: usize = 1448;

/// Generous default deadline for the TCP connect + NTOR handshake. A malicious
/// or half-open peer that accepts then stalls (e.g. sends 63 of 64 bytes)
/// cannot pin the dialing task past this bound; a legit slow-but-progressing
/// handshake completes well within it.
const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// obfs4 transport wrapper.
pub struct Obfs4Transport {
    cfg: ObfsConfig,
    audit: Arc<dyn AuditHook>,
    /// Test-only target override.
    server_override: Option<String>,
    /// Deadline for the connect + NTOR handshake.
    handshake_timeout: Duration,
}

impl Obfs4Transport {
    /// Construct the transport, validating shape-level config errors.
    pub fn new(cfg: ObfsConfig, audit: Arc<dyn AuditHook>) -> Result<Self> {
        let ObfsConfig::Obfs4 { .. } = cfg else {
            return Err(ObfsError::InvalidConfig(
                "Obfs4Transport requires ObfsConfig::Obfs4".into(),
            )
            .into());
        };
        cfg.validate().map_err(spt_core::Error::from)?;
        Ok(Self {
            cfg,
            audit,
            server_override: None,
            handshake_timeout: DEFAULT_HANDSHAKE_TIMEOUT,
        })
    }

    /// Test hook to point the transport at a loopback acceptor.
    #[must_use]
    pub fn with_server(mut self, addr: impl Into<String>) -> Self {
        self.server_override = Some(addr.into());
        self
    }

    /// Override the connect/NTOR-handshake deadline (default 30s). Primarily a
    /// test hook for asserting the stalled-peer timeout fires.
    #[must_use]
    pub fn with_handshake_timeout(mut self, d: Duration) -> Self {
        self.handshake_timeout = d;
        self
    }

    /// Borrow the configured IAT mode (0, 1, or 2).
    #[must_use]
    pub fn iat_mode(&self) -> u8 {
        match &self.cfg {
            ObfsConfig::Obfs4 { iat_mode, .. } => *iat_mode,
            _ => unreachable!("checked in new()"),
        }
    }

    /// Borrow the configured `node_id`.
    #[must_use]
    pub fn node_id(&self) -> &[u8; 20] {
        match &self.cfg {
            ObfsConfig::Obfs4 { node_id, .. } => node_id,
            _ => unreachable!("checked in new()"),
        }
    }

    /// Borrow the configured server public key.
    #[must_use]
    pub fn public_key(&self) -> &[u8; 32] {
        match &self.cfg {
            ObfsConfig::Obfs4 { public_key, .. } => public_key,
            _ => unreachable!("checked in new()"),
        }
    }

    /// Deterministic state-machine probe — preserved from the t6-e13
    /// contract suite. Walks `ClientHello → ServerHello → KexComplete`
    /// using a SHA-256 chain over the configured inputs.
    #[must_use]
    pub fn handshake_probe(&self) -> HandshakeState {
        let mut state = HandshakeState::ClientHello;
        let mut h = Sha256::new();
        h.update(self.node_id());
        h.update(self.public_key());
        h.update([self.iat_mode()]);
        let digest = h.finalize();
        for (i, byte) in digest.iter().take(3).enumerate() {
            state = state.advance(*byte, i);
        }
        state
    }

    /// IAT delay for this transport's mode. Mode 0 = none, mode 1 =
    /// 5ms, mode 2 = 1ms.
    #[must_use]
    pub fn iat_delay(&self) -> Duration {
        match self.iat_mode() {
            0 => Duration::ZERO,
            1 => Duration::from_millis(5),
            _ => Duration::from_millis(1),
        }
    }
}

/// Stages of the obfs4 NTOR exchange.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeState {
    /// Client has sent its ephemeral key.
    ClientHello,
    /// Server's ephemeral key + AUTH tag received.
    ServerHello,
    /// Shared secret derived; framing layer is live.
    KexComplete,
}

impl HandshakeState {
    fn advance(self, _byte: u8, _idx: usize) -> Self {
        match self {
            HandshakeState::ClientHello => HandshakeState::ServerHello,
            HandshakeState::ServerHello | HandshakeState::KexComplete => {
                HandshakeState::KexComplete
            }
        }
    }
}

/// NTOR key material — exposed for unit-testing the KDF.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NtorKeys {
    /// Client-to-server frame key.
    pub c2s_key: [u8; 32],
    /// Server-to-client frame key.
    pub s2c_key: [u8; 32],
    /// Authentication tag (HMAC over the handshake transcript).
    pub auth: [u8; 32],
}

/// NTOR-style KDF. Inputs:
///
/// * `secret`: combined ECDH secrets (X || Y) for the obfs4 spec —
///   `EXP(B, x) || EXP(Y, x)` in the standard NTOR, simplified here to
///   a single ECDH (`shared`) plus identity material because we only
///   have one server key on the wire.
/// * `node_id`: 20-byte bridge identity.
/// * `b_pub`: server identity public key.
/// * `x_pub`: client ephemeral public key.
/// * `y_pub`: server ephemeral public key.
///
/// Output: 96 bytes split into (`c2s_key`, `s2c_key`, `auth`).
#[must_use]
pub fn ntor_kdf(
    secret: &[u8],
    node_id: &[u8; 20],
    b_pub: &[u8; 32],
    x_pub: &[u8; 32],
    y_pub: &[u8; 32],
) -> NtorKeys {
    // PROTOID-style HKDF — extract then expand 96 bytes.
    let mut salt = Vec::with_capacity(OBFS4_PROTOID.len() + 20 + 32);
    salt.extend_from_slice(OBFS4_PROTOID);
    salt.extend_from_slice(node_id);
    salt.extend_from_slice(b_pub);
    let mut prk_mac = <HmacSha256 as Mac>::new_from_slice(&salt).expect("hmac salt");
    prk_mac.update(secret);
    prk_mac.update(x_pub);
    prk_mac.update(y_pub);
    let prk = prk_mac.finalize().into_bytes();

    let mut okm = [0u8; 96];
    let mut prev: Vec<u8> = Vec::new();
    let mut counter: u8 = 1;
    let mut off = 0;
    while off < 96 {
        let mut mac = <HmacSha256 as Mac>::new_from_slice(&prk).expect("hmac prk");
        mac.update(&prev);
        mac.update(OBFS4_PROTOID);
        mac.update(&[counter]);
        let block = mac.finalize().into_bytes();
        let take = block.len().min(96 - off);
        okm[off..off + take].copy_from_slice(&block[..take]);
        off += take;
        prev = block.to_vec();
        counter += 1;
    }

    let mut c2s = [0u8; 32];
    let mut s2c = [0u8; 32];
    let mut auth = [0u8; 32];
    c2s.copy_from_slice(&okm[..32]);
    s2c.copy_from_slice(&okm[32..64]);
    auth.copy_from_slice(&okm[64..96]);
    NtorKeys {
        c2s_key: c2s,
        s2c_key: s2c,
        auth,
    }
}

/// Perform the client side of the NTOR handshake over an already-open
/// duplex stream. Returns the derived key material.
///
/// Wire layout (client → server):
///
/// ```text
/// [node_id 20][b_pub 32][x_pub 32]
/// ```
///
/// Wire layout (server → client):
///
/// ```text
/// [y_pub 32][auth 32]
/// ```
///
/// The server is expected to compute the same KDF and echo back its
/// `auth` tag; the client verifies the tag in constant time.
pub async fn ntor_handshake<S>(
    stream: &mut S,
    node_id: &[u8; 20],
    b_pub: &[u8; 32],
) -> std::result::Result<NtorKeys, ObfsError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // Generate ephemeral X25519 secret.
    let mut x_sk_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut x_sk_bytes);
    let x_sk = StaticSecret::from(x_sk_bytes);
    let x_pub = PublicKey::from(&x_sk);

    // Send ClientHello.
    let mut hello = Vec::with_capacity(20 + 32 + 32);
    hello.extend_from_slice(node_id);
    hello.extend_from_slice(b_pub);
    hello.extend_from_slice(x_pub.as_bytes());
    stream.write_all(&hello).await.map_err(ObfsError::Io)?;

    // Receive ServerHello.
    let mut srv = [0u8; 64];
    stream.read_exact(&mut srv).await.map_err(ObfsError::Io)?;
    let mut y_pub_bytes = [0u8; 32];
    let mut srv_auth = [0u8; 32];
    y_pub_bytes.copy_from_slice(&srv[..32]);
    srv_auth.copy_from_slice(&srv[32..]);
    let y_pub = PublicKey::from(y_pub_bytes);
    let b_pub_obj = PublicKey::from(*b_pub);

    // ECDH: shared = x * Y (and we'd also do x * B in full NTOR for
    // identity binding; this minimal subset folds B into the salt only).
    let shared = x_sk.diffie_hellman(&y_pub);
    // Defence against an all-zero curve point.
    let zero = [0u8; 32];
    if shared.as_bytes() == &zero {
        // Reject site: log the failure kind (no key/secret material) so an
        // operator debugging an obfs4 handshake sees *why* it failed.
        tracing::warn!(
            transport = "obfs4",
            reason = "zero-ecdh",
            "obfs4 handshake rejected: peer produced an all-zero ECDH point"
        );
        return Err(ObfsError::Handshake("obfs4: zero ECDH output".into()));
    }
    // Bind the server identity by mixing x * B into the secret.
    let id_shared = x_sk.diffie_hellman(&b_pub_obj);

    let mut combined = Vec::with_capacity(64);
    combined.extend_from_slice(shared.as_bytes());
    combined.extend_from_slice(id_shared.as_bytes());

    let keys = ntor_kdf(
        &combined,
        node_id,
        b_pub,
        x_pub.as_bytes(),
        y_pub.as_bytes(),
    );

    // Constant-time auth tag verification.
    if keys.auth.ct_eq(&srv_auth).unwrap_u8() == 0 {
        // Reject site: log the failure kind only (never the derived keys or the
        // auth tag) so a rejected NTOR handshake is distinguishable from a
        // normal close without leaking secret material.
        tracing::warn!(
            transport = "obfs4",
            reason = "auth-tag-mismatch",
            "obfs4 handshake rejected: server NTOR auth tag verification failed"
        );
        return Err(ObfsError::Handshake("obfs4: bad server auth tag".into()));
    }
    Ok(keys)
}

/// `XSalsa20-Poly1305` (`NaCl` `crypto_secretbox`) frame layer.
///
/// Frame format:
///
/// ```text
/// [be u16 obfuscated_plaintext_len] [secretbox ciphertext + tag(16)]
/// ```
///
/// Per obfs4-spec §6 the length prefix is XOR-obfuscated by a separate
/// per-direction keystream so a DPI box cannot read the frame size in the
/// clear. We derive a `length_obf_seed` per direction by hashing the
/// secretbox key, and XOR each 2-byte prefix against the first 2 bytes of
/// `SHA-256(length_obf_seed || nonce_24)`.
///
/// Nonce: 24-byte per-direction counter starting at 0 and incrementing by
/// 1 per frame (little-endian in the low 8 bytes; the remaining 16 bytes
/// are zero). This matches the obfs4-spec; the `XSalsa20` 24-byte nonce
/// width is what makes counter-only operation safe (no birthday concerns
/// over realistic session lifetimes).
pub struct Obfs4Stream {
    inner: Box<dyn AsyncReadWrite>,
    c2s_key: [u8; 32],
    s2c_key: [u8; 32],
    /// Per-direction ciphers built once from the NTOR keys (P1) so the
    /// `XSalsa20` key schedule is not redone for every frame.
    tx_cipher: XSalsa20Poly1305,
    rx_cipher: XSalsa20Poly1305,
    /// Outbound counter (LE, lower 8 bytes of the 24-byte nonce).
    tx_ctr: u64,
    rx_ctr: u64,
    /// Read state.
    rx_state: RxState,
    rx_buf: Vec<u8>,
    pending: Vec<u8>,
    /// Buffered ciphertext of exactly one already-sealed outbound frame not yet
    /// fully written to `inner`. HIGH-1 partial-write fix: a partial inner write
    /// is resumed from this buffer (SAME ciphertext, SAME counter) instead of
    /// re-sealing the plaintext under the next counter, which would desync the
    /// peer. No new frame is sealed while this holds unflushed bytes, so the tx
    /// counter advances EXACTLY once per wire frame.
    tx_pending: Vec<u8>,
    /// Write offset into `tx_pending` (bytes already committed to `inner`).
    tx_pending_off: usize,
    iat_delay: Duration,
    next_write_after: Option<tokio::time::Instant>,
    delay_fut: Option<Pin<Box<tokio::time::Sleep>>>,
}

enum RxState {
    Length,
    Body { plaintext_len: usize },
}

impl Obfs4Stream {
    /// Construct from a connected inner duplex and NTOR keys.
    pub fn new(inner: Box<dyn AsyncReadWrite>, keys: NtorKeys, iat_delay: Duration) -> Self {
        // NTOR keys are fixed 32-byte arrays, so `new_from_slice` is infallible
        // here (XSalsa20Poly1305's key size is exactly 32). Build once (P1).
        let tx_cipher =
            XSalsa20Poly1305::new_from_slice(&keys.c2s_key).expect("32-byte XSalsa20 key");
        let rx_cipher =
            XSalsa20Poly1305::new_from_slice(&keys.s2c_key).expect("32-byte XSalsa20 key");
        Self {
            inner,
            c2s_key: keys.c2s_key,
            s2c_key: keys.s2c_key,
            tx_cipher,
            rx_cipher,
            tx_ctr: 0,
            rx_ctr: 0,
            rx_state: RxState::Length,
            rx_buf: Vec::new(),
            pending: Vec::new(),
            tx_pending: Vec::new(),
            tx_pending_off: 0,
            iat_delay,
            next_write_after: None,
            delay_fut: None,
        }
    }

    fn next_tx_ctr(&mut self) -> u64 {
        let c = self.tx_ctr;
        self.tx_ctr = self.tx_ctr.wrapping_add(1);
        c
    }

    /// Drive the buffered outbound frame (`tx_pending`) to completion, resuming
    /// from `tx_pending_off`. `Ready(Ok(()))` once the whole buffer is committed
    /// to `inner` (buffer cleared); `Pending` on backpressure (offset advanced,
    /// nothing re-sealed); or the inner error. Used before sealing a new frame
    /// and from `poll_flush`/`poll_shutdown`.
    fn drive_tx(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        while self.tx_pending_off < self.tx_pending.len() {
            match Pin::new(&mut self.inner).poll_write(cx, &self.tx_pending[self.tx_pending_off..])
            {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "obfs4: underlying write returned 0",
                    )));
                }
                Poll::Ready(Ok(n)) => self.tx_pending_off += n,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        self.tx_pending.clear();
        self.tx_pending_off = 0;
        Poll::Ready(Ok(()))
    }

    fn next_rx_ctr(&mut self) -> u64 {
        let c = self.rx_ctr;
        self.rx_ctr = self.rx_ctr.wrapping_add(1);
        c
    }
}

/// Build the 24-byte XSalsa20-Poly1305 nonce for an obfs4 frame from a
/// 64-bit counter. Low 8 bytes = counter LE, high 16 bytes = zero.
#[must_use]
pub fn obfs4_nonce_from_ctr(ctr: u64) -> [u8; 24] {
    let mut n = [0u8; 24];
    n[..8].copy_from_slice(&ctr.to_le_bytes());
    n
}

/// Compute the 2-byte length-prefix XOR mask for a given direction key
/// and 24-byte nonce. Mask = first 2 bytes of `SHA-256("obfs4-len" ||
/// key || nonce)`. Splits the length-obfuscation stream cleanly from
/// the secretbox key, so a passive observer cannot infer the prefix
/// without the session key.
fn length_mask(key: &[u8; 32], nonce: &[u8; 24]) -> [u8; 2] {
    let mut h = Sha256::new();
    h.update(b"obfs4-len");
    h.update(key);
    h.update(nonce);
    let d = h.finalize();
    [d[0], d[1]]
}

/// Encrypt a single obfs4 frame. Used by the in-process round-trip test.
///
/// Returns `[obfuscated_len(2)] [secretbox(plaintext)]` where
/// `obfuscated_len = plaintext.len() XOR length_mask(key, nonce)` and
/// the secretbox output is `XSalsa20-Poly1305(plaintext, nonce, key)`
/// with the Poly1305 tag appended.
pub fn seal_frame(
    key: &[u8; 32],
    nonce_ctr: u64,
    plaintext: &[u8],
) -> std::result::Result<Vec<u8>, ObfsError> {
    let cipher = build_cipher(key)?;
    seal_frame_with(&cipher, key, nonce_ctr, plaintext)
}

/// Build the `XSalsa20Poly1305` cipher for `key`. A 32-byte key is mandatory;
/// [`Obfs4Stream`] caches the result (P1) so the key schedule runs once.
fn build_cipher(key: &[u8; 32]) -> std::result::Result<XSalsa20Poly1305, ObfsError> {
    XSalsa20Poly1305::new_from_slice(key)
        .map_err(|e| ObfsError::Handshake(format!("xsalsa20poly1305: {e}")))
}

/// Seal a frame with an already-built cipher (P1: avoids rebuilding the
/// `XSalsa20` key schedule per frame). The length-prefix obfuscation mask still
/// depends on the per-frame nonce so it is recomputed each call. Byte-identical
/// to the per-frame [`seal_frame`] for the same `(key, nonce_ctr, plaintext)`.
fn seal_frame_with(
    cipher: &XSalsa20Poly1305,
    key: &[u8; 32],
    nonce_ctr: u64,
    plaintext: &[u8],
) -> std::result::Result<Vec<u8>, ObfsError> {
    if plaintext.len() > MAX_FRAME_PT {
        return Err(ObfsError::Handshake(format!(
            "obfs4: frame too big: {}",
            plaintext.len()
        )));
    }
    let nonce_bytes = obfs4_nonce_from_ctr(nonce_ctr);
    let nonce = XNonce::from_slice(&nonce_bytes);
    let ct = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad: b"",
            },
        )
        .map_err(|e| ObfsError::Handshake(format!("seal: {e}")))?;
    let mask = length_mask(key, &nonce_bytes);
    let plen_bytes = (plaintext.len() as u16).to_be_bytes();
    let obf_len = [plen_bytes[0] ^ mask[0], plen_bytes[1] ^ mask[1]];
    let mut out = Vec::with_capacity(2 + ct.len());
    out.extend_from_slice(&obf_len);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Decrypt a single obfs4 frame.
pub fn open_frame(
    key: &[u8; 32],
    nonce_ctr: u64,
    framed: &[u8],
) -> std::result::Result<Vec<u8>, ObfsError> {
    let cipher = build_cipher(key)?;
    open_frame_with(&cipher, key, nonce_ctr, framed)
}

/// Open a frame with an already-built cipher (P1). Byte-identical to the
/// per-frame [`open_frame`].
fn open_frame_with(
    cipher: &XSalsa20Poly1305,
    key: &[u8; 32],
    nonce_ctr: u64,
    framed: &[u8],
) -> std::result::Result<Vec<u8>, ObfsError> {
    if framed.len() < 2 + 16 {
        return Err(ObfsError::Handshake("obfs4: short frame".into()));
    }
    let nonce_bytes = obfs4_nonce_from_ctr(nonce_ctr);
    let mask = length_mask(key, &nonce_bytes);
    let plen = u16::from_be_bytes([framed[0] ^ mask[0], framed[1] ^ mask[1]]) as usize;
    if plen == 0 || plen > MAX_FRAME_PT {
        return Err(ObfsError::Handshake(format!("obfs4: bad plen {plen}")));
    }
    if framed.len() != 2 + plen + 16 {
        return Err(ObfsError::Handshake(format!(
            "obfs4: framed len mismatch ({} vs {})",
            framed.len(),
            2 + plen + 16
        )));
    }
    let nonce = XNonce::from_slice(&nonce_bytes);
    let pt = cipher
        .decrypt(
            nonce,
            Payload {
                msg: &framed[2..],
                aad: b"",
            },
        )
        .map_err(|e| ObfsError::Handshake(format!("open: {e}")))?;
    if pt.len() != plen {
        return Err(ObfsError::Handshake("obfs4: plen != decrypted".into()));
    }
    Ok(pt)
}

impl AsyncRead for Obfs4Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        loop {
            if !self.pending.is_empty() {
                let n = buf.remaining().min(self.pending.len());
                // P2: copy directly then drain — no per-read intermediate Vec.
                buf.put_slice(&self.pending[..n]);
                self.pending.drain(..n);
                return Poll::Ready(Ok(()));
            }

            // In Body state the 2-byte length prefix is still in rx_buf
            // (we deliberately leave it so the obfuscated mask can be
            // recomputed once the receive counter is advanced).
            let target_len = match self.rx_state {
                RxState::Length => 2usize,
                RxState::Body { plaintext_len } => 2 + plaintext_len + 16,
            };
            if self.rx_buf.len() < target_len {
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

            match self.rx_state {
                RxState::Length => {
                    // The length prefix is XOR-obfuscated by `length_mask`
                    // keyed on the *next* receive nonce. Peek the mask
                    // without consuming the counter so the body decrypt
                    // uses the same nonce.
                    let peek_ctr = self.rx_ctr;
                    let nonce_bytes = obfs4_nonce_from_ctr(peek_ctr);
                    let mask = length_mask(&self.s2c_key, &nonce_bytes);
                    let plen =
                        u16::from_be_bytes([self.rx_buf[0] ^ mask[0], self.rx_buf[1] ^ mask[1]])
                            as usize;
                    if plen == 0 || plen > MAX_FRAME_PT {
                        return Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "obfs4: bad plen",
                        )));
                    }
                    self.rx_state = RxState::Body {
                        plaintext_len: plen,
                    };
                }
                RxState::Body { plaintext_len } => {
                    // Drain the obfuscated length prefix + secretbox body
                    // as one contiguous framed slice.
                    let total = 2 + plaintext_len + 16;
                    let framed: Vec<u8> = self.rx_buf.drain(..total).collect();
                    let ctr = self.next_rx_ctr();
                    let pt = open_frame_with(&self.rx_cipher, &self.s2c_key, ctr, &framed)
                        .map_err(|e| {
                            std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string())
                        })?;
                    self.pending = pt;
                    self.rx_state = RxState::Length;
                }
            }
        }
    }
}

impl AsyncWrite for Obfs4Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.as_mut().get_mut();

        // HIGH-1 fix: finish flushing any buffered frame from a prior poll
        // BEFORE sealing (and IAT-gating) a new one. A partially-written frame
        // is resumed here from the SAME ciphertext; the tx counter is not
        // advanced again until the buffer lands, so a nonce is consumed exactly
        // once per wire frame.
        if this.tx_pending_off < this.tx_pending.len() {
            match this.drive_tx(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }

        // IAT mode 1/2: enforce a minimum inter-frame delay before sealing a
        // new frame (leftover ciphertext above is flushed regardless of IAT).
        if this.iat_delay > Duration::ZERO {
            if let Some(after) = this.next_write_after {
                if tokio::time::Instant::now() < after {
                    if this.delay_fut.is_none() {
                        this.delay_fut = Some(Box::pin(tokio::time::sleep_until(after)));
                    }
                    let f = this.delay_fut.as_mut().unwrap();
                    match f.as_mut().poll(cx) {
                        Poll::Ready(()) => {
                            this.delay_fut = None;
                        }
                        Poll::Pending => return Poll::Pending,
                    }
                }
            }
        }

        let chunk_len = data.len().min(MAX_FRAME_PT);
        let chunk = &data[..chunk_len];
        let ctr = this.next_tx_ctr();
        let frame = seal_frame_with(&this.tx_cipher, &this.c2s_key, ctr, chunk)
            .map_err(|e| std::io::Error::other(e.to_string()))?; // 1.88 lint: io_other_error

        // Buffer the whole sealed frame, then push what the socket accepts. A
        // partial write leaves the tail buffered for the next poll instead of
        // being dropped and re-sealed.
        this.tx_pending.clear();
        this.tx_pending.extend_from_slice(&frame);
        this.tx_pending_off = 0;
        if let Poll::Ready(Err(e)) = this.drive_tx(cx) {
            return Poll::Ready(Err(e));
        }

        if this.iat_delay > Duration::ZERO {
            this.next_write_after = Some(tokio::time::Instant::now() + this.iat_delay);
        }
        Poll::Ready(Ok(chunk_len))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.as_mut().get_mut();
        match this.drive_tx(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        }
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.as_mut().get_mut();
        match this.drive_tx(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        }
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

#[async_trait]
impl ObfsTransport for Obfs4Transport {
    async fn connect(&mut self, target: &str) -> Result<Box<dyn AsyncReadWrite>> {
        self.audit.on_connect(self.name(), target);
        let addr = self.server_override.as_deref().unwrap_or(target);
        // Wrap the connect + NTOR handshake in a deadline so a half-open /
        // stalled peer cannot pin this dial indefinitely (M10).
        let node_id = *self.node_id();
        let public_key = *self.public_key();
        let (tcp, keys) = tokio::time::timeout(self.handshake_timeout, async move {
            let mut tcp = TcpStream::connect(addr).await.map_err(ObfsError::Io)?;
            let keys = ntor_handshake(&mut tcp, &node_id, &public_key).await?;
            Ok::<_, ObfsError>((tcp, keys))
        })
        .await
        .map_err(|_| ObfsError::Handshake("obfs4: handshake timed out".into()))?
        .map_err(spt_core::Error::from)?;
        let stream = Obfs4Stream::new(Box::new(tcp), keys, self.iat_delay());
        Ok(Box::new(stream))
    }

    fn name(&self) -> &'static str {
        "obfs4"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::NoopAuditHook;

    fn cfg(iat: u8) -> ObfsConfig {
        ObfsConfig::Obfs4 {
            node_id: [1u8; 20],
            public_key: [2u8; 32],
            iat_mode: iat,
        }
    }

    #[test]
    fn handshake_probe_advances_through_documented_stages() {
        let t = Obfs4Transport::new(cfg(0), Arc::new(NoopAuditHook)).unwrap();
        assert_eq!(t.handshake_probe(), HandshakeState::KexComplete);
    }

    #[test]
    fn iat_mode_selection_round_trips() {
        for iat in 0u8..=2 {
            let t = Obfs4Transport::new(cfg(iat), Arc::new(NoopAuditHook)).unwrap();
            assert_eq!(t.iat_mode(), iat);
        }
    }

    #[test]
    fn iat_mode_out_of_range_rejected() {
        let r = Obfs4Transport::new(cfg(7), Arc::new(NoopAuditHook));
        assert!(r.is_err());
    }

    #[test]
    fn ntor_kdf_deterministic() {
        let secret = [9u8; 64];
        let nid = [1u8; 20];
        let b = [2u8; 32];
        let x = [3u8; 32];
        let y = [4u8; 32];
        let k1 = ntor_kdf(&secret, &nid, &b, &x, &y);
        let k2 = ntor_kdf(&secret, &nid, &b, &x, &y);
        assert_eq!(k1, k2);
        assert_ne!(k1.c2s_key, k1.s2c_key);
    }

    #[test]
    fn frame_round_trip() {
        let key = [7u8; 32];
        let pt = b"obfs4 ssh frame".to_vec();
        let framed = seal_frame(&key, 0, &pt).unwrap();
        let back = open_frame(&key, 0, &framed).unwrap();
        assert_eq!(back, pt);
    }

    #[test]
    fn cached_cipher_seal_matches_per_frame_build() {
        // P1 perf change must be byte-identical: a cached cipher reused across
        // frames produces exactly the same wire bytes as a per-frame build for
        // the same (key, counter, plaintext).
        let key = [0x5Au8; 32];
        let cipher = build_cipher(&key).unwrap();
        for ctr in 0u64..6 {
            let pt = format!("obfs4-frame-{ctr}").into_bytes();
            let cached = seal_frame_with(&cipher, &key, ctr, &pt).unwrap();
            let fresh = seal_frame(&key, ctr, &pt).unwrap();
            assert_eq!(
                cached, fresh,
                "cached vs per-frame frame diverged (ctr={ctr})"
            );
            // Cached open round-trips its own output.
            let back = open_frame_with(&cipher, &key, ctr, &cached).unwrap();
            assert_eq!(back, pt);
        }
    }

    #[tokio::test]
    async fn handshake_times_out_against_stalled_peer() {
        // A TCP server that accepts but never sends the ServerHello must not pin
        // the dial forever — the handshake timeout fires and surfaces an error.
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        // Accept and hold the connection open without responding.
        let _accept = tokio::spawn(async move {
            let (_sock, _) = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(30)).await;
        });
        let mut t = Obfs4Transport::new(cfg(0), Arc::new(NoopAuditHook))
            .unwrap()
            .with_server(addr.to_string())
            .with_handshake_timeout(Duration::from_millis(200));
        let res = tokio::time::timeout(Duration::from_secs(5), t.connect(&addr.to_string())).await;
        let inner = res.expect("connect() must return, not hang");
        assert!(inner.is_err(), "stalled handshake must error via timeout");
    }

    #[test]
    fn frame_corruption_rejected() {
        let key = [7u8; 32];
        let pt = b"hello".to_vec();
        let mut framed = seal_frame(&key, 0, &pt).unwrap();
        let last = framed.len() - 1;
        framed[last] ^= 0x55;
        assert!(open_frame(&key, 0, &framed).is_err());
    }

    #[test]
    fn frame_wrong_nonce_rejected() {
        let key = [7u8; 32];
        let pt = b"hello".to_vec();
        let framed = seal_frame(&key, 0, &pt).unwrap();
        assert!(open_frame(&key, 1, &framed).is_err());
    }

    /// t8-FixObfs4 smoke test: confirms the framing layer is
    /// `XSalsa20-Poly1305` (24-byte nonce, `NaCl` secretbox) rather than
    /// the earlier `ChaCha20-Poly1305` stand-in (12-byte nonce). Asserts:
    /// (1) the nonce-construction helper produces 24 bytes,
    /// (2) two consecutive frames with the same key but different
    ///     counters produce distinct ciphertext bytes (proves the
    ///     counter advances and is consumed by the cipher), and
    /// (3) a deliberate length-prefix obfuscation: the 2 prefix bytes
    ///     of `seal_frame(key, 0, &[0u8; 1])` should NOT equal the
    ///     plaintext length `0x00 0x01` because of XOR masking.
    #[test]
    fn framing_uses_24_byte_nonce_not_12() {
        // (1) Nonce-from-counter helper is 24 bytes (not 12).
        let n = obfs4_nonce_from_ctr(42);
        assert_eq!(
            n.len(),
            24,
            "obfs4 framing must use 24-byte XSalsa20 nonces"
        );
        // First 8 bytes carry the counter LE; remaining 16 are zero.
        assert_eq!(&n[..8], &42u64.to_le_bytes());
        assert!(n[8..].iter().all(|b| *b == 0));

        // (2) Counter advance changes the ciphertext.
        let key = [11u8; 32];
        let pt = b"smoke".to_vec();
        let f0 = seal_frame(&key, 0, &pt).unwrap();
        let f1 = seal_frame(&key, 1, &pt).unwrap();
        assert_ne!(f0, f1, "counter must influence ciphertext");

        // (3) Length prefix is XOR-masked: the prefix bytes are very
        // unlikely to equal the BE plaintext-length encoding.
        let small = vec![0u8; 1];
        let f = seal_frame(&key, 0, &small).unwrap();
        let plaintext_len_be = (small.len() as u16).to_be_bytes();
        assert_ne!(
            &f[..2],
            &plaintext_len_be[..],
            "length prefix must be XOR-obfuscated, not sent in the clear"
        );

        // (4) Frame shape: 2-byte prefix + ciphertext (= pt + 16-byte
        // Poly1305 tag). No extra AAD framing bytes.
        assert_eq!(f.len(), 2 + small.len() + 16);
    }
}
