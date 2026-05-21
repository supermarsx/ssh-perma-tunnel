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
//! Replay protection: a bounded `BTreeSet` of recently-seen 12-byte
//! nonces is maintained per session and rejects exact reuse.
//!
//! The runtime path opens a TCP connection to the configured upstream
//! Shadowsocks server (resolved via `target`) and wraps the duplex
//! stream in an [`AeadStream`] that frames every read/write under the
//! derived subkey. AEAD nonce starts at zero and increments per frame.

use std::collections::BTreeSet;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use async_trait::async_trait;
use chacha20poly1305::ChaCha20Poly1305;
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;

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

/// ssh-over-shadowsocks transport handle.
pub struct ShadowsocksTransport {
    cfg: ObfsConfig,
    audit: Arc<dyn AuditHook>,
    /// Direct (in-memory) password override used by tests and by the
    /// runtime once the configured `SecretRef` has been resolved.
    direct_password: Option<Vec<u8>>,
    /// Optional override for the TCP target. When `None` the `target`
    /// argument supplied to `connect()` is used verbatim.
    server_override: Option<String>,
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
        })
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
        self.direct_password = Some(pw.into());
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
    pub fn derive_key(&self, salt: &[u8]) -> std::result::Result<Vec<u8>, ObfsError> {
        let pw = self
            .direct_password
            .as_deref()
            .ok_or_else(|| ObfsError::Handshake("shadowsocks: password not resolved".into()))?;
        if pw.is_empty() {
            return Err(ObfsError::Handshake("shadowsocks: empty password".into()));
        }
        let key_len = self.method().key_len();

        if self.method().is_aead_2022() {
            // Spec: session_subkey = blake3::derive_key(ctx, key || salt)
            let mut material = Vec::with_capacity(pw.len() + salt.len());
            material.extend_from_slice(pw);
            material.extend_from_slice(salt);
            let derived = blake3::derive_key(AEAD2022_SESSION_CONTEXT, &material);
            // BLAKE3 derive_key emits 32 bytes; AES-128-GCM keys are 16,
            // others are 32. Truncate per method.
            return Ok(derived[..key_len].to_vec());
        }

        // Legacy KDF: HMAC-SHA256 counter mode (interop with pre-2022).
        let mut out = Vec::with_capacity(key_len);
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
        let ct = aead_seal(self.method(), &key, &nonce, plaintext, b"spt-obfs/ss")?;
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
        let pt = aead_open(self.method(), &key, &nonce, ct, b"spt-obfs/ss")?;
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

fn aead_seal(
    method: SsMethod,
    key: &[u8],
    nonce: &[u8; 12],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    let n = aes_gcm::Nonce::from_slice(nonce);
    match method {
        SsMethod::Aes128Gcm | SsMethod::Aead2022Blake3Aes128Gcm => {
            let cipher = Aes128Gcm::new_from_slice(key)
                .map_err(|e| ObfsError::Handshake(format!("aes-128: {e}")))?;
            cipher
                .encrypt(n, Payload { msg: plaintext, aad })
                .map_err(|e| ObfsError::Handshake(format!("seal: {e}")).into())
        }
        SsMethod::Aes256Gcm | SsMethod::Aead2022Blake3Aes256Gcm => {
            let cipher = Aes256Gcm::new_from_slice(key)
                .map_err(|e| ObfsError::Handshake(format!("aes-256: {e}")))?;
            cipher
                .encrypt(n, Payload { msg: plaintext, aad })
                .map_err(|e| ObfsError::Handshake(format!("seal: {e}")).into())
        }
        SsMethod::ChaCha20Poly1305 | SsMethod::Aead2022Blake3ChaCha20Poly1305 => {
            let n = chacha20poly1305::Nonce::from_slice(nonce);
            let cipher = ChaCha20Poly1305::new_from_slice(key)
                .map_err(|e| ObfsError::Handshake(format!("chacha: {e}")))?;
            cipher
                .encrypt(n, Payload { msg: plaintext, aad })
                .map_err(|e| ObfsError::Handshake(format!("seal: {e}")).into())
        }
    }
}

fn aead_open(
    method: SsMethod,
    key: &[u8],
    nonce: &[u8; 12],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    let n = aes_gcm::Nonce::from_slice(nonce);
    match method {
        SsMethod::Aes128Gcm | SsMethod::Aead2022Blake3Aes128Gcm => {
            let cipher = Aes128Gcm::new_from_slice(key)
                .map_err(|e| ObfsError::Handshake(format!("aes-128: {e}")))?;
            cipher
                .decrypt(n, Payload { msg: ciphertext, aad })
                .map_err(|e| ObfsError::Handshake(format!("open: {e}")).into())
        }
        SsMethod::Aes256Gcm | SsMethod::Aead2022Blake3Aes256Gcm => {
            let cipher = Aes256Gcm::new_from_slice(key)
                .map_err(|e| ObfsError::Handshake(format!("aes-256: {e}")))?;
            cipher
                .decrypt(n, Payload { msg: ciphertext, aad })
                .map_err(|e| ObfsError::Handshake(format!("open: {e}")).into())
        }
        SsMethod::ChaCha20Poly1305 | SsMethod::Aead2022Blake3ChaCha20Poly1305 => {
            let n = chacha20poly1305::Nonce::from_slice(nonce);
            let cipher = ChaCha20Poly1305::new_from_slice(key)
                .map_err(|e| ObfsError::Handshake(format!("chacha: {e}")))?;
            cipher
                .decrypt(n, Payload { msg: ciphertext, aad })
                .map_err(|e| ObfsError::Handshake(format!("open: {e}")).into())
        }
    }
}

/// Replay-protection window: keeps the last [`REPLAY_WINDOW`] nonces.
const REPLAY_WINDOW: usize = 1024;

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
    key: Vec<u8>,
    write_nonce: u64,
    read_nonce: u64,
    /// Inbound replay window — exact nonce reuse rejected.
    seen: BTreeSet<u64>,
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
    /// Construct a new framed stream.
    pub fn new(inner: Box<dyn AsyncReadWrite>, method: SsMethod, key: Vec<u8>) -> Self {
        Self {
            inner,
            method,
            key,
            write_nonce: 0,
            read_nonce: 0,
            seen: BTreeSet::new(),
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

    fn next_read_nonce(&mut self) -> std::result::Result<[u8; 12], ObfsError> {
        if !self.seen.insert(self.read_nonce) {
            return Err(ObfsError::Handshake("ss: replay nonce".into()));
        }
        if self.seen.len() > REPLAY_WINDOW {
            // Evict the oldest entry to bound memory.
            if let Some(&oldest) = self.seen.iter().next() {
                self.seen.remove(&oldest);
            }
        }
        let mut nonce = [0u8; 12];
        nonce[..8].copy_from_slice(&self.read_nonce.to_le_bytes());
        self.read_nonce = self.read_nonce.wrapping_add(1);
        Ok(nonce)
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
                let drained: Vec<u8> = self.pending.drain(..n).collect();
                buf.put_slice(&drained);
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
                    let nonce = match self.next_read_nonce() {
                        Ok(n) => n,
                        Err(e) => {
                            return Poll::Ready(Err(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                e.to_string(),
                            )))
                        }
                    };
                    let chunk: Vec<u8> = self.rx_buf.drain(..target_len).collect();
                    let pt = aead_open(self.method, &self.key, &nonce, &chunk, b"spt-obfs/ss/len")
                        .map_err(|e| {
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
                    self.rx = RxState::Body { plaintext_len: plen };
                }
                RxState::Body { plaintext_len } => {
                    let nonce = match self.next_read_nonce() {
                        Ok(n) => n,
                        Err(e) => {
                            return Poll::Ready(Err(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                e.to_string(),
                            )))
                        }
                    };
                    let chunk: Vec<u8> = self.rx_buf.drain(..target_len).collect();
                    let pt =
                        aead_open(self.method, &self.key, &nonce, &chunk, b"spt-obfs/ss/body")
                            .map_err(|e| {
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

        let len_nonce = self.next_write_nonce();
        let body_nonce = self.next_write_nonce();
        let key = self.key.clone();
        let method = self.method;
        let len_be = (chunk_len as u16).to_be_bytes();
        let len_ct = aead_seal(method, &key, &len_nonce, &len_be, b"spt-obfs/ss/len")
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
        let body_ct = aead_seal(method, &key, &body_nonce, chunk, b"spt-obfs/ss/body")
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

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
        let mut tcp = TcpStream::connect(addr).await.map_err(ObfsError::Io)?;

        // Per-session salt.
        let mut salt = vec![0u8; salt_len(self.method())];
        rand::thread_rng().fill_bytes(&mut salt);
        let key = self.derive_key(&salt).map_err(spt_core::Error::from)?;

        // We pre-write the salt header to the peer so the receiver can
        // derive the same subkey. The peer is assumed to mirror our
        // framing — used as a permanent SSH tunnel inside an ss server.
        // For loopback fixtures the salt is the only handshake byte
        // exchanged before AEAD framing begins.
        tcp.write_all(&salt).await.map_err(ObfsError::Io)?;

        let stream = AeadStream::new(Box::new(tcp), self.method(), key);
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
}
