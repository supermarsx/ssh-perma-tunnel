//! Reject-path logging (finding: obfs handshake/AEAD/front rejects were
//! swallowed — returned as `Err` with no log, making a rejected handshake
//! indistinguishable from a normal close).
//!
//! Each test installs a thread-local `tracing` subscriber that records WARN
//! events, drives a transport into its reject path on a *current-thread*
//! runtime (so every poll runs on the subscribed thread), and asserts a WARN
//! fired at the reject site. These fail against the pre-fix code, which logged
//! nothing.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

use tracing::span::{Attributes, Id, Record};
use tracing::{Event, Level, Metadata, Subscriber};

use spt_obfs::config::ObfsConfig;
use spt_obfs::meek::MeekHttpTransport;
use spt_obfs::shadowsocks::{direction_keys, AeadStream, SsRole};
use spt_obfs::{NoopAuditHook, ObfsTransport, SsMethod};

/// Minimal `tracing::Subscriber` that records whether any WARN event fired.
/// Implemented with only the `tracing` crate (no `tracing-subscriber` dep).
#[derive(Clone, Default)]
struct WarnCapture {
    warned: Arc<AtomicBool>,
    count: Arc<AtomicUsize>,
}

impl Subscriber for WarnCapture {
    fn enabled(&self, _meta: &Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, _attrs: &Attributes<'_>) -> Id {
        Id::from_u64(1)
    }
    fn record(&self, _id: &Id, _values: &Record<'_>) {}
    fn record_follows_from(&self, _id: &Id, _follows: &Id) {}
    fn event(&self, event: &Event<'_>) {
        if *event.metadata().level() == Level::WARN {
            self.warned.store(true, Ordering::SeqCst);
            self.count.fetch_add(1, Ordering::SeqCst);
        }
    }
    fn enter(&self, _id: &Id) {}
    fn exit(&self, _id: &Id) {}
}

fn current_thread_rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

#[test]
fn meek_non_2xx_front_logs_warn() {
    let cap = WarnCapture::default();
    let rt = current_thread_rt();
    tracing::subscriber::with_default(cap.clone(), || {
        rt.block_on(async {
            let cfg = ObfsConfig::MeekHttp {
                url: "https://front.example/p".into(),
                front_host: None,
                sni: None,
            };
            let mut t = MeekHttpTransport::new(cfg, Arc::new(NoopAuditHook)).unwrap();
            t.set_simulated_status(502);
            let res = t.connect("front.example:443").await;
            assert!(res.is_err(), "non-2xx front must surface an error");
        });
    });
    assert!(
        cap.warned.load(Ordering::SeqCst),
        "meek non-2xx front reject must log a WARN, not swallow it"
    );
}

#[test]
fn obfs4_handshake_reject_logs_warn() {
    let cap = WarnCapture::default();
    let rt = current_thread_rt();
    tracing::subscriber::with_default(cap.clone(), || {
        rt.block_on(async {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let (mut client, mut server) = tokio::io::duplex(1024);
            // Server: read the 84-byte ClientHello, then reply with a bogus
            // 64-byte ServerHello so the NTOR handshake is rejected (either the
            // zero-ECDH guard or the auth-tag mismatch — both now log a WARN).
            let srv = tokio::spawn(async move {
                let mut hello = [0u8; 84];
                server.read_exact(&mut hello).await.unwrap();
                server.write_all(&[0xABu8; 64]).await.unwrap();
                // Hold the server end open until the handshake completes.
                let mut sink = Vec::new();
                let _ = server.read_to_end(&mut sink).await;
            });
            let node_id = [1u8; 20];
            let b_pub = [2u8; 32];
            let res = spt_obfs::obfs4::ntor_handshake(&mut client, &node_id, &b_pub).await;
            assert!(res.is_err(), "bogus ServerHello must fail the handshake");
            drop(client);
            let _ = srv.await;
        });
    });
    assert!(
        cap.warned.load(Ordering::SeqCst),
        "obfs4 handshake reject must log a WARN, not swallow it"
    );
}

#[test]
fn shadowsocks_aead_open_failure_logs_warn() {
    let cap = WarnCapture::default();
    let rt = current_thread_rt();
    tracing::subscriber::with_default(cap.clone(), || {
        rt.block_on(async {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let method = SsMethod::Aead2022Blake3Aes256Gcm;
            let (tx_key, rx_key) = direction_keys(&[0x42u8; 32], method, SsRole::Client);
            let (mut peer, inner) = tokio::io::duplex(1024);
            let mut stream = AeadStream::new(Box::new(inner), method, tx_key, rx_key);
            // Feed a full length frame (2-byte len + 16-byte tag) of bytes that
            // cannot authenticate under rx_key -> AEAD open fails.
            peer.write_all(&[0u8; 18]).await.unwrap();
            let mut out = [0u8; 64];
            let res = stream.read(&mut out).await;
            assert!(res.is_err(), "unauthenticated frame must be rejected");
        });
    });
    assert!(
        cap.warned.load(Ordering::SeqCst),
        "shadowsocks AEAD-open reject must log a WARN, not swallow it"
    );
}
