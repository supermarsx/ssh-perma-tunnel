#![no_main]
//! Fuzz the Shadowsocks AEAD decrypt path — must reject any malformed
//! ciphertext without panicking.
//!
//! The plan target name is `decrypt_chunk`; the equivalent in the
//! current source is `ShadowsocksTransport::open`, which performs
//! salt-split + KDF + AEAD-open. A fixed-known password is injected so
//! the fuzzer concentrates on ciphertext shape and salt parsing rather
//! than re-discovering the PSK.
use std::sync::{Arc, OnceLock};

use libfuzzer_sys::fuzz_target;

use spt_obfs::audit::NoopAuditHook;
use spt_obfs::config::{ObfsConfig, SsMethod};
use spt_obfs::shadowsocks::ShadowsocksTransport;
use spt_secrets::SecretRef;

static TRANSPORT: OnceLock<ShadowsocksTransport> = OnceLock::new();

fn transport() -> &'static ShadowsocksTransport {
    TRANSPORT.get_or_init(|| {
        let password = SecretRef::new("fuzz", "ss").expect("valid SecretRef");
        let cfg = ObfsConfig::Shadowsocks {
            method: SsMethod::ChaCha20Poly1305,
            password,
        };
        ShadowsocksTransport::new(cfg, Arc::new(NoopAuditHook))
            .expect("ss transport constructs")
            .with_direct_password(*b"fuzz-fixed-password-32-bytes-OK!")
    })
}

fuzz_target!(|data: &[u8]| {
    let _ = transport().open(data);
});
