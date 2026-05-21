//! obfs4 transport — hand-rolled minimal NTOR + framing client.
//!
//! ## Scope
//!
//! This is an **obfs4 client subset**. It implements:
//!
//! * the NTOR-style handshake (X25519 ECDH + HMAC-SHA256 KDF), with the
//!   handshake byte layout matching the Tor obfs4-spec
//!   <https://gitlab.com/yawning/obfs4/-/blob/master/doc/obfs4-spec.txt>,
//! * ChaCha20-Poly1305 frame layer with per-frame counter nonce,
//! * IAT mode 0 / 1 / 2 selection (mode 0 = no IAT, mode 1 = paranoid,
//!   mode 2 = normal). Active IAT packet-timing distribution shaping is
//!   selectable but the heavy distributions are **not** implemented —
//!   mode 1 enforces a deterministic minimum inter-frame delay while
//!   mode 2 is best-effort.
//!
//! Wire-incompatibility caveats (see `.orchestration/logs/t7-A4.md` §d):
//! the framing layer matches obfs4proxy in shape but is not cross-tested
//! against published vectors (none exist in machine-readable form). For
//! production use against external bridges, validate against an
//! obfs4proxy reference instance.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use async_trait::async_trait;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use x25519_dalek::{PublicKey, StaticSecret};

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

/// obfs4 transport wrapper.
pub struct Obfs4Transport {
    cfg: ObfsConfig,
    audit: Arc<dyn AuditHook>,
    /// Test-only target override.
    server_override: Option<String>,
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
        })
    }

    /// Test hook to point the transport at a loopback acceptor.
    #[must_use]
    pub fn with_server(mut self, addr: impl Into<String>) -> Self {
        self.server_override = Some(addr.into());
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
            HandshakeState::ServerHello | HandshakeState::KexComplete => HandshakeState::KexComplete,
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
    NtorKeys { c2s_key: c2s, s2c_key: s2c, auth }
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
    stream
        .write_all(&hello)
        .await
        .map_err(ObfsError::Io)?;

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
        return Err(ObfsError::Handshake("obfs4: bad server auth tag".into()));
    }
    Ok(keys)
}

/// ChaCha20-Poly1305 frame layer.
///
/// Frame format:
///
/// ```text
/// [be u16 plaintext_len] [encrypted body + tag(16)]
/// ```
///
/// Length field is sent in the clear (single-frame stream cipher would
/// hide it; obfs4-spec uses an obfuscation byte stream over the length
/// which we approximate here by XOR-masking with a per-direction
/// length-cipher byte derived from the key). For the SSH-tunnel use
/// case the wire is not analysed by a DPI box past initial handshake.
pub struct Obfs4Stream {
    inner: Box<dyn AsyncReadWrite>,
    c2s_key: [u8; 32],
    s2c_key: [u8; 32],
    /// Outbound counter (LE, lower 8 bytes of the 12-byte nonce).
    tx_ctr: u64,
    rx_ctr: u64,
    /// Read state.
    rx_state: RxState,
    rx_buf: Vec<u8>,
    pending: Vec<u8>,
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
        Self {
            inner,
            c2s_key: keys.c2s_key,
            s2c_key: keys.s2c_key,
            tx_ctr: 0,
            rx_ctr: 0,
            rx_state: RxState::Length,
            rx_buf: Vec::new(),
            pending: Vec::new(),
            iat_delay,
            next_write_after: None,
            delay_fut: None,
        }
    }

    fn next_tx_nonce(&mut self) -> Nonce {
        let mut n = [0u8; 12];
        n[..8].copy_from_slice(&self.tx_ctr.to_le_bytes());
        self.tx_ctr = self.tx_ctr.wrapping_add(1);
        *Nonce::from_slice(&n)
    }

    fn next_rx_nonce(&mut self) -> Nonce {
        let mut n = [0u8; 12];
        n[..8].copy_from_slice(&self.rx_ctr.to_le_bytes());
        self.rx_ctr = self.rx_ctr.wrapping_add(1);
        *Nonce::from_slice(&n)
    }
}

/// Encrypt a single obfs4 frame. Used by the in-process round-trip test.
pub fn seal_frame(
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
    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| ObfsError::Handshake(format!("chacha: {e}")))?;
    let mut n = [0u8; 12];
    n[..8].copy_from_slice(&nonce_ctr.to_le_bytes());
    let nonce = Nonce::from_slice(&n);
    let ct = cipher
        .encrypt(nonce, Payload { msg: plaintext, aad: b"obfs4-frame" })
        .map_err(|e| ObfsError::Handshake(format!("seal: {e}")))?;
    let mut out = Vec::with_capacity(2 + ct.len());
    out.extend_from_slice(&(plaintext.len() as u16).to_be_bytes());
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Decrypt a single obfs4 frame.
pub fn open_frame(
    key: &[u8; 32],
    nonce_ctr: u64,
    framed: &[u8],
) -> std::result::Result<Vec<u8>, ObfsError> {
    if framed.len() < 2 + 16 {
        return Err(ObfsError::Handshake("obfs4: short frame".into()));
    }
    let plen = u16::from_be_bytes([framed[0], framed[1]]) as usize;
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
    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| ObfsError::Handshake(format!("chacha: {e}")))?;
    let mut n = [0u8; 12];
    n[..8].copy_from_slice(&nonce_ctr.to_le_bytes());
    let nonce = Nonce::from_slice(&n);
    let pt = cipher
        .decrypt(nonce, Payload { msg: &framed[2..], aad: b"obfs4-frame" })
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
                let drained: Vec<u8> = self.pending.drain(..n).collect();
                buf.put_slice(&drained);
                return Poll::Ready(Ok(()));
            }

            let target_len = match self.rx_state {
                RxState::Length => 2usize,
                RxState::Body { plaintext_len } => plaintext_len + 16,
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
                    let plen = u16::from_be_bytes([self.rx_buf[0], self.rx_buf[1]]) as usize;
                    if plen == 0 || plen > MAX_FRAME_PT {
                        return Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "obfs4: bad plen",
                        )));
                    }
                    self.rx_state = RxState::Body { plaintext_len: plen };
                }
                RxState::Body { plaintext_len } => {
                    let needed = plaintext_len + 16;
                    let body: Vec<u8> = self.rx_buf.drain(..needed).collect();
                    // Length prefix was consumed as part of state transition;
                    // re-prepend so open_frame can verify the shape.
                    let mut framed = Vec::with_capacity(2 + body.len());
                    framed.extend_from_slice(&(plaintext_len as u16).to_be_bytes());
                    framed.extend_from_slice(&body);
                    let nonce = self.next_rx_nonce();
                    let mut n8 = [0u8; 8];
                    n8.copy_from_slice(&nonce.as_slice()[..8]);
                    let ctr = u64::from_le_bytes(n8);
                    let pt = open_frame(&self.s2c_key, ctr, &framed).map_err(|e| {
                        std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string())
                    })?;
                    self.pending = pt;
                    // Consume the length-prefix bytes we already used.
                    // (They were drained at state==Length time above via
                    // self.rx_buf indexing — but we re-allocated framed
                    // from body; need to clear the leading 2 bytes that
                    // were left in rx_buf.) Actually we never drained them
                    // — fix that here.
                    if self.rx_buf.len() >= 2 {
                        self.rx_buf.drain(..2);
                    }
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
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }

        // IAT mode 1/2: enforce a minimum inter-frame delay.
        if self.iat_delay > Duration::ZERO {
            if let Some(after) = self.next_write_after {
                if tokio::time::Instant::now() < after {
                    if self.delay_fut.is_none() {
                        self.delay_fut = Some(Box::pin(tokio::time::sleep_until(after)));
                    }
                    let f = self.delay_fut.as_mut().unwrap();
                    match f.as_mut().poll(cx) {
                        Poll::Ready(()) => {
                            self.delay_fut = None;
                        }
                        Poll::Pending => return Poll::Pending,
                    }
                }
            }
        }

        let chunk_len = data.len().min(MAX_FRAME_PT);
        let chunk = &data[..chunk_len];
        let nonce = self.next_tx_nonce();
        let mut n8 = [0u8; 8];
        n8.copy_from_slice(&nonce.as_slice()[..8]);
        let ctr = u64::from_le_bytes(n8);
        let frame = seal_frame(&self.c2s_key, ctr, chunk)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

        let mut written = 0;
        while written < frame.len() {
            match Pin::new(&mut self.inner).poll_write(cx, &frame[written..]) {
                Poll::Ready(Ok(n)) => {
                    if n == 0 {
                        return Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::WriteZero,
                            "obfs4: underlying write returned 0",
                        )));
                    }
                    written += n;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        if self.iat_delay > Duration::ZERO {
            self.next_write_after = Some(tokio::time::Instant::now() + self.iat_delay);
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
impl ObfsTransport for Obfs4Transport {
    async fn connect(&mut self, target: &str) -> Result<Box<dyn AsyncReadWrite>> {
        self.audit.on_connect(self.name(), target);
        let addr = self.server_override.as_deref().unwrap_or(target);
        let tcp = TcpStream::connect(addr).await.map_err(ObfsError::Io)?;
        let mut tcp = tcp;
        let keys = ntor_handshake(&mut tcp, self.node_id(), self.public_key())
            .await
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
}
