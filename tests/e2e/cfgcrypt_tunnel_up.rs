//! e2e: config-encryption **publish → fetch → decrypt → connect** loop.
//!
//! This is the config-crypt true end-to-end test (`t-e2e` Wave A). The peer
//! crate `spt-config-crypt` already proves seal/unseal in unit tests, and
//! `spt-bin`'s `it_remote_config.rs` proves fetch+pin over the *sealed* bytes.
//! What was missing — and what this file proves — is the **whole loop**: a real
//! profile is rendered to TOML, sealed (PSK and X25519 modes), hosted via the
//! remote-config fetcher with the fingerprint pin computed over the sealed
//! bytes, fetched + pin-verified, decrypted back to the plaintext TOML, parsed
//! into a `Config`, and then used to bring up a **real tunnel** against the
//! embedded `RusshTestServer`, asserting a byte payload round-trips through the
//! *decrypted* profile's forward.
//!
//! ## What drives what
//!
//! * **Fetch + pin** is the real [`spt_remote_config::fetch`] against a
//!   `FixedFetcher` (the same in-process seam `it_remote_config.rs` uses) —
//!   hermetic, no HTTP, no port flakiness.
//! * **Decrypt** replicates the production `decrypt_if_sealed` hook
//!   (`spt-bin config_ops.rs`, which is `pub(crate)` and so cannot be called
//!   from this crate) using the *public* `spt-config-crypt` API: `peek_meta` to
//!   select PSK vs X25519, then `unseal`. The key ref is resolved by the test
//!   (env / raw bytes) exactly as the production resolver would.
//! * **Tunnel-up** drives the real `Ssh2Protocol` (pure russh 0.61) built from
//!   the **decrypted** profile's endpoint / user / auth / forward fields, and
//!   asserts a multi-KiB payload round-trips through the forward — the proof the
//!   whole loop produced a working profile. A sibling assertion also drives the
//!   `OrchestratorBuilder` / `wait_for_state` lifecycle to `Active` with the
//!   decrypted profile, proving the supervisor accepts it.
//!
//! Library-path (not CLI-subprocess) by design: the `seal` / `fetch` /
//! `unseal` / orchestrator wiring is deterministic and avoids subprocess /
//! editor / filesystem flakiness. `decrypt_if_sealed` is `pub(crate)`, so the
//! subprocess `config pull` path is covered by the peer's `cli_dispatch` tests;
//! here we exercise the identical crypto + fetch + tunnel chain in-process.

#![allow(clippy::missing_panics_doc, clippy::missing_errors_doc)]

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use secrecy::ExposeSecret as _;
use spt_auth::{AuthConfig, AuthMethod, SecretRef};
use spt_config::schema::{Config, Profile};
use spt_config_crypt::{
    generate_psk, generate_x25519, is_sealed, peek_meta, seal, unseal, KeySource,
};
use spt_core::BindAddr;
use spt_protocol::{
    BindConflictPolicy, Endpoint, ForwardRateLimits, LocalForwardSpec, TargetAddr, TunnelProtocol,
};
use spt_remote_config::{
    fetch, http::HttpError, FetchOutcome, HttpFetcher, HttpResponse, RemoteConfigSpec,
};
use spt_ssh2::testing::RusshTestServer;
use spt_ssh2::Ssh2Protocol;
use spt_supervisor::testing::{
    wait_for_state, OrchestratorBuilder, ProfileStateName, ProfileSupervisorConfig,
};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};

// -----------------------------------------------------------------------------
// In-process fetcher (mirrors it_remote_config.rs's seam)
// -----------------------------------------------------------------------------

/// Serves a fixed body, ignoring conditional-GET headers. Exactly the seam the
/// binary-level `it_remote_config.rs` uses; replicated here because it is a test
/// fixture, not part of any crate's public surface.
struct FixedFetcher {
    status: u16,
    body: Vec<u8>,
}

#[async_trait]
impl HttpFetcher for FixedFetcher {
    async fn get(
        &self,
        _url: &str,
        _if_none_match: Option<&str>,
        _max_size: u64,
        _timeout: Duration,
    ) -> Result<HttpResponse, HttpError> {
        Ok(HttpResponse {
            status: self.status,
            body: self.body.clone(),
            etag: None,
        })
    }
}

fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(data);
    hex::encode(h.finalize())
}

/// Host `body` via [`FixedFetcher`] with the fingerprint pin computed over the
/// exact bytes supplied (the caller decides whether that's the sealed blob, a
/// tampered blob, or — wrongly — the plaintext). Returns the fetched body or the
/// fetch error (pin mismatch, bad status, …).
async fn fetch_pinned(body: &[u8], pin_over: &[u8]) -> Result<Vec<u8>, String> {
    let tmp = unique_state_dir();
    let spec = RemoteConfigSpec {
        url: "https://example.invalid/cfg".into(),
        fingerprint_sha256: sha256_hex(pin_over),
        allow_cached_on_failure: false,
        max_size_bytes: None,
        etag_cache: None,
    };
    let fetcher = FixedFetcher {
        status: 200,
        body: body.to_vec(),
    };
    let res = match fetch(&spec, &tmp, &fetcher).await {
        Ok(res) => {
            assert!(matches!(res.outcome, FetchOutcome::Fresh));
            Ok(res.body)
        }
        Err(e) => Err(e.to_string()),
    };
    let _ = std::fs::remove_dir_all(&tmp);
    res
}

/// A unique, ephemeral state dir under the OS temp root. Avoids a `tempfile`
/// dev-dep edge (keeps Cargo.lock churn to the unavoidable crypto/fetch crates).
fn unique_state_dir() -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let dir = std::env::temp_dir().join(format!("spt-cfgcrypt-e2e-{pid}-{n}-{nanos}"));
    std::fs::create_dir_all(&dir).expect("create state dir");
    dir
}

// -----------------------------------------------------------------------------
// Decrypt hook (replicates spt-bin's pub(crate) `decrypt_if_sealed`)
// -----------------------------------------------------------------------------

/// The test's stand-in for `[runtime.remote_config].encryption_key_from`: the
/// raw key material a production resolver would yield from the env/file/secret
/// ref named by that field. PSK = the 32 raw bytes; X25519 = the private scalar.
enum KeyRef {
    Psk([u8; 32]),
    X25519Secret([u8; 32]),
}

/// Faithful re-implementation of `spt-bin`'s `decrypt_if_sealed`: if the body is
/// a sealed `SPTENC1` envelope, select the key source from the envelope's
/// declared kdf and `unseal`; if cleartext, honor `require_encrypted`. The
/// production hook resolves `key_ref` to bytes first — that resolution is the
/// test's job here ([`KeyRef`]); the crypto path is identical.
fn decrypt_if_sealed(
    body: &[u8],
    key_ref: Option<&KeyRef>,
    require_encrypted: bool,
) -> Result<Vec<u8>, String> {
    if is_sealed(body) {
        let key_ref = key_ref.ok_or_else(|| {
            "fetched config is sealed but no encryption_key_from is configured".to_string()
        })?;
        let meta = peek_meta(body).map_err(|e| e.to_string())?;
        let key = match (meta.kdf.as_str(), key_ref) {
            ("psk", KeyRef::Psk(p)) => KeySource::Psk(*p),
            ("x25519", KeyRef::X25519Secret(s)) => KeySource::X25519Secrets(vec![*s]),
            (other, _) => {
                return Err(format!(
                    "sealed kdf `{other}` not decryptable via the configured key ref"
                ))
            }
        };
        let pt = unseal(body, &key).map_err(|e| e.to_string())?;
        Ok(pt.expose_secret().as_slice().to_vec())
    } else {
        if require_encrypted {
            return Err("fetched config is cleartext but require_encrypted = true".into());
        }
        Ok(body.to_vec())
    }
}

// -----------------------------------------------------------------------------
// Profile / config authoring + extraction
// -----------------------------------------------------------------------------

async fn free_loopback_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    let port = listener.local_addr().expect("local addr").port();
    drop(listener);
    port
}

/// Render a real, working cleartext config TOML targeting the russh server on
/// `server_port`, with one local TCP forward listening on `listen_port` and
/// targeting the server's `server-side-echo:7` sentinel backend. This is the
/// plaintext that gets sealed and hosted.
fn render_cleartext_config(server_port: u16, listen_port: u16) -> String {
    format!(
        r#"version = 1

[[profiles]]
name = "sealed-tunnel"
enabled = true
protocol = "ssh2"
host = "127.0.0.1"
port = {server_port}
user = "tester"

[profiles.auth]
method = "password"
password = "env://SPT_TEST_CFGCRYPT_PW"

[profiles.trust]
mode = "tofu"
accept_new = true

[[profiles.forwards]]
name = "echo"
type = "local"
transport = "tcp"
bind = "127.0.0.1:{listen_port}"
target = "server-side-echo:7"
target_resolve = "remote"
required = true
"#
    )
}

/// Pull the single profile out of a parsed `Config`.
fn only_profile(cfg: &Config) -> &Profile {
    assert_eq!(cfg.profiles.len(), 1, "fixture config has one profile");
    &cfg.profiles[0]
}

/// Build the connect `Endpoint` from the decrypted profile's host/port.
fn endpoint_of(p: &Profile) -> Endpoint {
    Endpoint::new(
        p.host.as_deref().expect("profile.host"),
        p.port.expect("profile.port"),
    )
}

/// Build the `LocalForwardSpec` from the decrypted profile's first forward.
fn local_forward_of(p: &Profile) -> LocalForwardSpec {
    let f = p.forwards.first().expect("profile has a forward");
    let bind = f.bind.as_deref().expect("forward.bind");
    let target = f.target.as_deref().expect("forward.target");
    let (thost, tport) = target.rsplit_once(':').expect("target host:port");
    LocalForwardSpec {
        name: f.name.clone(),
        listen: BindAddr::parse(bind).expect("parse bind"),
        target: TargetAddr::new(thost, tport.parse().expect("target port")),
        max_connections: Some(4),
        limits: ForwardRateLimits::default(),
        idle_timeout: None,
        on_bind_conflict: BindConflictPolicy::default(),
        required: true,
    }
}

/// Drive the real `Ssh2Protocol` from the decrypted profile's fields and assert
/// a multi-KiB payload round-trips through the forward. This is the proof that
/// the publish→fetch→decrypt loop produced a *working* profile.
async fn assert_tunnel_roundtrip_from_profile(profile: &Profile) {
    // The decrypted profile authenticates via env://SPT_TEST_CFGCRYPT_PW.
    std::env::set_var("SPT_TEST_CFGCRYPT_PW", "anything");

    let proto = Ssh2Protocol::builder()
        .trust(spt_ssh2::testing::tofu_trust_verifier())
        .build();
    let endpoint = endpoint_of(profile);
    let auth = AuthConfig::new(
        profile.user.as_deref().expect("profile.user"),
        vec![AuthMethod::Password {
            secret: SecretRef::Env("SPT_TEST_CFGCRYPT_PW".into()),
        }],
    );
    let mut session = proto
        .connect(&endpoint, &auth)
        .await
        .expect("russh backend connects with decrypted profile auth");

    let spec = local_forward_of(profile);
    let listen_port = match &spec.listen {
        BindAddr::Tcp(sa) => sa.port(),
        other => panic!("expected a TCP listen bind, got {other:?}"),
    };
    let handle = session
        .open_local_forward(&spec)
        .await
        .expect("open local forward from decrypted profile");

    let payload: Vec<u8> = (0..4096u32).map(|i| (i % 251) as u8).collect();
    let mut sock = TcpStream::connect(("127.0.0.1", listen_port))
        .await
        .expect("connect decrypted-profile forward listener");
    sock.write_all(&payload)
        .await
        .expect("write through forward");

    let mut echoed = vec![0u8; payload.len()];
    tokio::time::timeout(Duration::from_secs(5), sock.read_exact(&mut echoed))
        .await
        .expect("timely echo")
        .expect("read echo");
    assert_eq!(
        echoed, payload,
        "bytes must round-trip through the decrypted profile's forward"
    );

    handle.close().await;
    session.close().await.expect("close session");
}

/// Drive the supervisor lifecycle to `Active` with the decrypted profile and
/// the real `Ssh2Protocol`, proving the orchestrator accepts the decrypted
/// profile end-to-end (not just the direct protocol path).
async fn assert_orchestrator_reaches_active(profile: &Profile) {
    std::env::set_var("SPT_TEST_CFGCRYPT_PW", "anything");
    let proto = Arc::new(
        Ssh2Protocol::builder()
            .trust(spt_ssh2::testing::tofu_trust_verifier())
            .build(),
    );
    let endpoint = endpoint_of(profile);
    let auth = AuthConfig::new(
        profile.user.as_deref().expect("profile.user"),
        vec![AuthMethod::Password {
            secret: SecretRef::Env("SPT_TEST_CFGCRYPT_PW".into()),
        }],
    );
    let orch = OrchestratorBuilder::new()
        .with_profile(
            profile.clone(),
            proto as Arc<dyn TunnelProtocol>,
            auth,
            vec![endpoint],
            ProfileSupervisorConfig::default(),
        )
        .build();
    wait_for_state(
        &orch,
        &profile.name,
        ProfileStateName::Active,
        Duration::from_secs(10),
    )
    .await
    .expect("supervisor brings the decrypted profile to Active");
    orch.shutdown().await;
}

/// Stand up the russh server and produce the cleartext config TOML targeting
/// it. Returns `(server, cleartext_toml)`. Caller seals + hosts the TOML.
async fn server_and_cleartext() -> (spt_ssh2::testing::RunningRusshServer, String) {
    let server = RusshTestServer::new()
        .with_password("tester", "anything")
        .start()
        .await
        .expect("start russh server");
    let listen_port = free_loopback_port().await;
    let toml = render_cleartext_config(server.addr.port(), listen_port);
    (server, toml)
}

// =============================================================================
// Happy path — both modes
// =============================================================================

/// PSK mode: render → seal(PSK) → host(pin over sealed) → fetch+pin → decrypt →
/// parse → tunnel-up byte round-trip through the decrypted profile's forward.
#[tokio::test]
async fn psk_publish_fetch_decrypt_tunnel_up() {
    let (server, cleartext) = server_and_cleartext().await;

    // Generate key + seal the rendered TOML.
    let psk = generate_psk();
    let sealed = seal(cleartext.as_bytes(), &KeySource::Psk(psk)).expect("seal psk");
    assert!(is_sealed(&sealed));

    // Host the SEALED blob, pin over the SEALED bytes; fetch + pin-verify.
    let fetched = fetch_pinned(&sealed, &sealed).await.expect("fetch+pin");
    assert!(
        is_sealed(&fetched),
        "fetcher returns the sealed body verbatim"
    );

    // Decrypt with the configured key ref (PSK), yielding the plaintext TOML.
    let plaintext = decrypt_if_sealed(&fetched, Some(&KeyRef::Psk(psk)), true)
        .expect("decrypt_if_sealed yields plaintext");
    assert_eq!(
        plaintext,
        cleartext.as_bytes(),
        "decrypt round-trips the TOML"
    );

    // Parse + bring up the tunnel from the decrypted profile.
    let (cfg, _warns) = spt_config::load_str(std::str::from_utf8(&plaintext).unwrap(), false)
        .expect("decrypted TOML parses as a Config");
    let profile = only_profile(&cfg).clone();

    assert_tunnel_roundtrip_from_profile(&profile).await;
    assert_orchestrator_reaches_active(&profile).await;

    server.shutdown().await;
}

/// X25519 mode: render → seal(recipient pubkey) → host(pin over sealed) →
/// fetch+pin → decrypt(private scalar) → parse → tunnel-up byte round-trip.
#[tokio::test]
async fn x25519_publish_fetch_decrypt_tunnel_up() {
    let (server, cleartext) = server_and_cleartext().await;

    let (secret, public) = generate_x25519();
    let sealed = seal(
        cleartext.as_bytes(),
        &KeySource::X25519Recipients(vec![public]),
    )
    .expect("seal x25519");
    assert!(is_sealed(&sealed));
    assert_eq!(
        peek_meta(&sealed).unwrap().kdf,
        "x25519",
        "envelope advertises x25519 kdf"
    );

    let fetched = fetch_pinned(&sealed, &sealed).await.expect("fetch+pin");

    let plaintext = decrypt_if_sealed(&fetched, Some(&KeyRef::X25519Secret(secret)), true)
        .expect("decrypt_if_sealed yields plaintext");
    assert_eq!(plaintext, cleartext.as_bytes());

    let (cfg, _warns) =
        spt_config::load_str(std::str::from_utf8(&plaintext).unwrap(), false).expect("parse");
    let profile = only_profile(&cfg).clone();

    assert_tunnel_roundtrip_from_profile(&profile).await;
    assert_orchestrator_reaches_active(&profile).await;

    server.shutdown().await;
}

// =============================================================================
// Negatives
// =============================================================================

/// Wrong PSK → `decrypt_if_sealed` errors (InvalidConfig class); no tunnel.
#[tokio::test]
async fn wrong_psk_fails_decrypt_no_tunnel() {
    let (server, cleartext) = server_and_cleartext().await;
    let psk = generate_psk();
    let wrong = generate_psk();
    let sealed = seal(cleartext.as_bytes(), &KeySource::Psk(psk)).expect("seal");

    let fetched = fetch_pinned(&sealed, &sealed).await.expect("fetch+pin");
    let err = decrypt_if_sealed(&fetched, Some(&KeyRef::Psk(wrong)), true)
        .expect_err("wrong PSK must fail decrypt");
    assert!(
        err.contains("wrong PSK") || err.to_lowercase().contains("tampered"),
        "wrong-PSK error should be an AEAD/InvalidConfig failure, got: {err}"
    );
    server.shutdown().await;
}

/// Wrong X25519 secret → no recipient matches → decrypt errors; no tunnel.
#[tokio::test]
async fn wrong_x25519_secret_fails_decrypt_no_tunnel() {
    let (server, cleartext) = server_and_cleartext().await;
    let (_secret, public) = generate_x25519();
    let (wrong_secret, _wrong_pub) = generate_x25519();
    let sealed = seal(
        cleartext.as_bytes(),
        &KeySource::X25519Recipients(vec![public]),
    )
    .expect("seal");

    let fetched = fetch_pinned(&sealed, &sealed).await.expect("fetch+pin");
    let err = decrypt_if_sealed(&fetched, Some(&KeyRef::X25519Secret(wrong_secret)), true)
        .expect_err("wrong x25519 secret must fail decrypt");
    assert!(
        err.to_lowercase().contains("no supplied x25519 secret")
            || err.to_lowercase().contains("matched"),
        "wrong-secret error should report no matching recipient, got: {err}"
    );
    server.shutdown().await;
}

/// `require_encrypted = true` + a CLEARTEXT (unsealed) body → hard error before
/// any tunnel work.
#[tokio::test]
async fn require_encrypted_rejects_cleartext_body() {
    let (server, cleartext) = server_and_cleartext().await;
    // Host the cleartext TOML directly (NOT sealed); pin over the cleartext.
    let fetched = fetch_pinned(cleartext.as_bytes(), cleartext.as_bytes())
        .await
        .expect("cleartext fetch+pin ok (pin is over what we host)");
    assert!(!is_sealed(&fetched), "body is cleartext");

    // require_encrypted = true → reject.
    let err = decrypt_if_sealed(&fetched, None, true)
        .expect_err("require_encrypted must reject a cleartext body");
    assert!(err.contains("require_encrypted"), "got: {err}");

    // Sanity: with require_encrypted = false the same cleartext is accepted as-is.
    let pass = decrypt_if_sealed(&fetched, None, false).expect("cleartext passthrough");
    assert_eq!(pass, cleartext.as_bytes());
    server.shutdown().await;
}

/// Tampered sealed blob, layer 1: flip a ciphertext byte and host it with the
/// ORIGINAL pin (over the untampered sealed bytes). The fingerprint pin catches
/// the tamper at fetch time — decrypt is never reached.
#[tokio::test]
async fn tampered_blob_caught_by_pin() {
    let (server, cleartext) = server_and_cleartext().await;
    let psk = generate_psk();
    let sealed = seal(cleartext.as_bytes(), &KeySource::Psk(psk)).expect("seal");

    // Flip a byte near the end (inside the base64 ciphertext region).
    let mut tampered = sealed.clone();
    let idx = tampered.len() - 4;
    tampered[idx] ^= 0x01;
    assert_ne!(tampered, sealed);

    // Host the TAMPERED body but pin over the ORIGINAL sealed bytes → mismatch.
    let err = fetch_pinned(&tampered, &sealed)
        .await
        .expect_err("pin must reject the tampered body");
    assert!(
        err.to_lowercase().contains("fingerprint") || err.to_lowercase().contains("mismatch"),
        "expected a fingerprint mismatch, got: {err}"
    );
    server.shutdown().await;
}

/// Tampered sealed blob, layer 2: corrupt a byte INSIDE the AEAD ciphertext
/// (not the framing) AND recompute the pin over the tampered bytes (defeating
/// the pin). The pin no longer protects us — the AEAD tag is the last line of
/// defense and `unseal` fails on tag mismatch. Covers the second rejection
/// layer. We flip a character within the `ciphertext_b64` base64 string to a
/// *different but still valid* base64 character so the envelope still parses and
/// the decoded ciphertext is what the AEAD must reject.
#[tokio::test]
async fn tampered_blob_past_pin_caught_by_aead() {
    let (server, cleartext) = server_and_cleartext().await;
    let psk = generate_psk();
    let sealed = seal(cleartext.as_bytes(), &KeySource::Psk(psk)).expect("seal");

    let tampered = flip_ciphertext_b64_char(&sealed);
    assert_ne!(tampered, sealed, "tamper changed the blob");
    // The envelope must still parse (framing + base64 intact) so the failure is
    // the AEAD tag, not a structural/decode error.
    assert!(
        peek_meta(&tampered).is_ok(),
        "tampered envelope still parses"
    );

    // Pin OVER the tampered bytes → fetch passes the pin.
    let fetched = fetch_pinned(&tampered, &tampered)
        .await
        .expect("pin over tampered bytes passes fetch");

    // …but the AEAD tag catches the tamper at decrypt time.
    let err = decrypt_if_sealed(&fetched, Some(&KeyRef::Psk(psk)), true)
        .expect_err("AEAD tag must reject the tampered envelope");
    assert!(
        err.to_lowercase().contains("tampered")
            || err.to_lowercase().contains("wrong psk")
            || err.to_lowercase().contains("aead")
            || err.to_lowercase().contains("decrypt"),
        "expected an AEAD-tag failure, got: {err}"
    );
    server.shutdown().await;
}

/// Find the `ciphertext_b64 = "<b64>"` value inside a sealed envelope's body
/// block and mutate one character in the middle of the base64 string to a
/// different valid base64 character. Keeps base64 length/validity (so the
/// envelope parses) while changing a decoded ciphertext byte (so the AEAD tag
/// fails). Returns the tampered blob.
fn flip_ciphertext_b64_char(sealed: &[u8]) -> Vec<u8> {
    let needle = b"ciphertext_b64 = \"";
    let start = sealed
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|p| p + needle.len())
        .expect("locate ciphertext_b64 value");
    // The base64 value runs until the closing quote.
    let end = start
        + sealed[start..]
            .iter()
            .position(|&c| c == b'"')
            .expect("closing quote");
    // Pick a character well inside the value (avoid the trailing `=` padding).
    let mid = start + (end - start) / 2;
    let orig = sealed[mid];
    // Map to a *different* valid base64 alphabet character.
    let replacement = if orig == b'A' { b'B' } else { b'A' };
    let mut out = sealed.to_vec();
    out[mid] = replacement;
    out
}

/// Pin-over-plaintext sanity: a sealed body whose pin was (wrongly) computed
/// over the PLAINTEXT does not match the hosted sealed bytes → fetch rejects.
/// Mirrors `it_remote_config.rs` but in the full-loop file, asserting no tunnel.
#[tokio::test]
async fn pin_over_plaintext_rejected_at_fetch() {
    let (server, cleartext) = server_and_cleartext().await;
    let psk = generate_psk();
    let sealed = seal(cleartext.as_bytes(), &KeySource::Psk(psk)).expect("seal");

    // Host the sealed blob but pin over the PLAINTEXT → mismatch.
    let err = fetch_pinned(&sealed, cleartext.as_bytes())
        .await
        .expect_err("pin computed over plaintext must not verify the sealed body");
    assert!(
        err.to_lowercase().contains("fingerprint") || err.to_lowercase().contains("mismatch"),
        "expected a fingerprint mismatch, got: {err}"
    );
    server.shutdown().await;
}

/// Cross-mode key mismatch: a PSK-sealed blob with an X25519 key ref configured
/// is rejected by the kdf guard before any AEAD work — the decrypt hook refuses
/// to feed an x25519 secret to a psk envelope.
#[tokio::test]
async fn psk_blob_with_x25519_keyref_rejected() {
    let (server, cleartext) = server_and_cleartext().await;
    let psk = generate_psk();
    let (wrong_secret, _pub) = generate_x25519();
    let sealed = seal(cleartext.as_bytes(), &KeySource::Psk(psk)).expect("seal");

    let fetched = fetch_pinned(&sealed, &sealed).await.expect("fetch+pin");
    let err = decrypt_if_sealed(&fetched, Some(&KeyRef::X25519Secret(wrong_secret)), true)
        .expect_err("x25519 key ref must not decrypt a psk envelope");
    assert!(
        err.to_lowercase().contains("not decryptable") || err.to_lowercase().contains("kdf"),
        "expected a kdf-mismatch rejection, got: {err}"
    );
    server.shutdown().await;
}
