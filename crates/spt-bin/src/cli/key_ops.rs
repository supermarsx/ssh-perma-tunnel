//! Implementations of `spt key` subcommands beyond `generate`/`inspect`.
//!
//! Public surface (per the `cli-fill-final` plan, `key_ops` section):
//!
//! * [`public`]            — print the OpenSSH public key for a private key.
//! * [`change_passphrase`] — re-encrypt a private key with a new passphrase.
//! * [`sign_cert`]         — issue an OpenSSH user/host certificate.
//! * [`verify_cert`]       — validate a certificate against a pinned CA list.
//! * [`install_public`]    — append a public key to a remote `~/.ssh/authorized_keys`.
//!
//! Each entry point takes a small plain-data `*Args` struct; the Phase B
//! dispatch wirer in `cli_dispatch.rs` is responsible for translating the
//! `clap`-parsed `groups::key::*` types into these.

#![allow(clippy::missing_errors_doc)]
#![allow(clippy::module_name_repetitions)]

use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use spt_cli::GlobalOpts;
use spt_core::{Error, Result};
use spt_key::cert::{CertOptions, CertType, Certificate};
use spt_key::{KeyPair, PublicKey};

// ---------------------------------------------------------------------------
// Args structs (filled in by `cli_dispatch`).
// ---------------------------------------------------------------------------

/// Args for [`public`].
#[derive(Debug, Clone)]
pub struct KeyPublicArgs {
    /// Private-key path.
    pub key: PathBuf,
    /// If set, write the public key to this path (otherwise stdout).
    pub out: Option<PathBuf>,
}

/// Args for [`change_passphrase`].
#[derive(Debug, Clone)]
pub struct KeyChangePassphraseArgs {
    /// Private-key path.
    pub key: PathBuf,
    /// Optional secret-ref (e.g. `env:NEW_PW`) for the new passphrase. If
    /// `None` the function prompts on stdin.
    pub new_passphrase_from: Option<String>,
}

/// Args for [`sign_cert`].
#[derive(Debug, Clone)]
pub struct KeySignCertArgs {
    /// CA private-key path.
    pub ca: PathBuf,
    /// Subject *public* key path.
    pub subject: PathBuf,
    /// Allowed principals (`valid_principals`). Must be non-empty.
    pub principals: Vec<String>,
    /// Validity duration (parsed via [`spt_core::duration::parse_duration`]).
    /// Defaults to 24 hours when `None`.
    pub validity: Option<String>,
    /// Optional serial number.
    pub serial: Option<u64>,
    /// Certificate kind. Defaults to `user` when `None`.
    pub cert_type: Option<CertTypeArg>,
    /// Optional key identifier.
    pub key_id: Option<String>,
    /// Output certificate path. If `None`, derive `<subject>-cert.pub`.
    pub out: Option<PathBuf>,
}

/// CLI-side `--cert-type` choice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertTypeArg {
    /// User certificate (default).
    User,
    /// Host certificate.
    Host,
}

impl From<CertTypeArg> for CertType {
    fn from(c: CertTypeArg) -> Self {
        match c {
            CertTypeArg::User => Self::User,
            CertTypeArg::Host => Self::Host,
        }
    }
}

/// Args for [`verify_cert`].
#[derive(Debug, Clone)]
pub struct KeyVerifyCertArgs {
    /// Certificate path (OpenSSH `*-cert.pub` format).
    pub cert: PathBuf,
    /// Path to a file containing one OpenSSH-format CA public key per line.
    pub trusted_cas: PathBuf,
}

/// Args for [`install_public`].
#[derive(Debug, Clone)]
pub struct KeyInstallPublicArgs {
    /// Public-key path (must end with `.pub` or be in OpenSSH format).
    pub key: PathBuf,
    /// `user@host[:port]`. Either this or `profile` must be set.
    pub target: Option<String>,
    /// Profile name to dispatch through (uses the running supervisor's
    /// session if the profile is connected).
    pub profile: Option<String>,
}

// ---------------------------------------------------------------------------
// `key public`
// ---------------------------------------------------------------------------

/// Print the OpenSSH public key for `args.key`.
///
/// If the on-disk private key is encrypted, the passphrase is taken from
/// `SPT_KEY_PASSPHRASE` (env) or, failing that, prompted on stderr / read
/// from stdin.
#[allow(clippy::needless_pass_by_value)]
pub async fn public(_global: &GlobalOpts, args: KeyPublicArgs) -> Result<()> {
    let kp = load_with_passphrase_chain(&args.key)?;
    let line = render_public_line(&kp)?;
    if let Some(p) = args.out {
        write_atomic(&p, line.as_bytes())?;
    } else {
        let mut out = std::io::stdout().lock();
        out.write_all(line.as_bytes())
            .map_err(|e| Error::RuntimeFailure(format!("stdout write: {e}")))?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// `key change-passphrase`
// ---------------------------------------------------------------------------

/// Re-encrypt the private key at `args.key` with a new passphrase.
///
/// Procedure:
/// 1. Load with the current passphrase (env or prompt).
/// 2. Resolve the new passphrase from `--new-passphrase-from` or prompt+confirm.
/// 3. Atomic write via `spt_key::change_passphrase` (creates `<key>.bak`).
/// 4. Round-trip verify by re-loading the new file with the new passphrase.
#[allow(clippy::needless_pass_by_value)]
pub async fn change_passphrase(global: &GlobalOpts, args: KeyChangePassphraseArgs) -> Result<()> {
    if !args.key.exists() {
        return Err(Error::InvalidArgs(format!(
            "key file `{}` not found",
            args.key.display()
        )));
    }

    let old_pw = passphrase_from_env_or_prompt("current passphrase: ")?;
    // Pre-load to surface a clean error if the old passphrase is wrong before
    // we touch the new one.
    let _ = spt_key::load(&args.key, Some(&old_pw))?;

    let new_pw = match args.new_passphrase_from {
        Some(reference) => resolve_secret_ref_to_string(global, &reference)?,
        None => {
            let a = prompt_passphrase("new passphrase: ")?;
            let b = prompt_passphrase("confirm new passphrase: ")?;
            if a != b {
                return Err(Error::InvalidArgs(
                    "passphrase confirmation did not match".into(),
                ));
            }
            a
        }
    };

    spt_key::change_passphrase(&args.key, Some(&old_pw), Some(&new_pw))?;

    // Round-trip: must decrypt with the new passphrase.
    let _ = spt_key::load(&args.key, Some(&new_pw)).map_err(|e| {
        Error::KeyFailure(format!(
            "post-write verification failed for `{}`: {e}",
            args.key.display()
        ))
    })?;

    println!(
        "passphrase updated for {} (backup: {}.bak)",
        args.key.display(),
        args.key.display()
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// `key sign-cert`
// ---------------------------------------------------------------------------

/// Sign a subject public key with `args.ca`, producing an OpenSSH certificate.
#[allow(clippy::needless_pass_by_value)]
pub async fn sign_cert(_global: &GlobalOpts, args: KeySignCertArgs) -> Result<()> {
    if args.principals.is_empty() {
        return Err(Error::InvalidArgs(
            "sign-cert: at least one --principal is required".into(),
        ));
    }
    let ca = load_with_passphrase_chain(&args.ca)?;
    let subject = read_public_key_file(&args.subject)?;

    let lifetime = match args.validity.as_deref() {
        Some(s) => spt_core::duration::parse_duration(s)?,
        None => Duration::from_secs(24 * 60 * 60),
    };

    let cert_type = args.cert_type.map_or(CertType::User, Into::into);
    let key_id = args.key_id.unwrap_or_else(|| {
        // Reasonable default: first principal + cert kind.
        let kind = match cert_type {
            CertType::User => "user",
            CertType::Host => "host",
        };
        format!("{}@spt-{}", args.principals[0], kind)
    });

    let opts = CertOptions {
        cert_type,
        key_id,
        principals: args.principals.clone(),
        all_principals: false,
        valid_after: None,
        valid_before: None,
        default_lifetime: lifetime,
        serial: args.serial.unwrap_or(0),
        comment: String::new(),
        critical_options: Vec::new(),
        extensions: default_extensions_for(cert_type),
    };

    let cert = spt_key::cert::sign_cert(&ca, &subject, opts)?;
    let pem = cert
        .to_openssh()
        .map_err(|e| Error::KeyFailure(format!("encode certificate: {e}")))?;

    let out = args.out.unwrap_or_else(|| derive_cert_path(&args.subject));
    write_atomic(&out, pem.as_bytes())?;
    println!(
        "wrote certificate {} (serial {}, principals: {})",
        out.display(),
        cert.serial(),
        args.principals.join(",")
    );
    Ok(())
}

fn default_extensions_for(t: CertType) -> Vec<(String, String)> {
    match t {
        CertType::User => vec![
            ("permit-pty".into(), String::new()),
            ("permit-user-rc".into(), String::new()),
        ],
        CertType::Host => Vec::new(),
    }
}

fn derive_cert_path(subject: &Path) -> PathBuf {
    let stem = subject
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "subject".to_string());
    let parent = subject
        .parent()
        .map_or_else(PathBuf::new, Path::to_path_buf);
    parent.join(format!("{stem}-cert.pub"))
}

// ---------------------------------------------------------------------------
// `key verify-cert`
// ---------------------------------------------------------------------------

/// Verify an OpenSSH certificate against a pinned CA list.
#[allow(clippy::needless_pass_by_value)]
pub async fn verify_cert(_global: &GlobalOpts, args: KeyVerifyCertArgs) -> Result<()> {
    let cert_str = fs::read_to_string(&args.cert)
        .map_err(|e| Error::InvalidArgs(format!("read `{}`: {e}", args.cert.display())))?;
    let cert = Certificate::from_openssh(&cert_str)
        .map_err(|e| Error::InvalidConfig(format!("parse certificate: {e}")))?;

    let cas = load_trusted_cas(&args.trusted_cas)?;
    if cas.is_empty() {
        return Err(Error::InvalidArgs(format!(
            "no CA public keys found in `{}`",
            args.trusted_cas.display()
        )));
    }

    spt_key::cert::verify_cert(&cert, &cas)?;

    let ca_fp = cert.signature_key().fingerprint(ssh_key::HashAlg::Sha256);
    println!("certificate ok");
    println!(
        "  type        : {}",
        match cert.cert_type() {
            ssh_key::certificate::CertType::User => "user",
            ssh_key::certificate::CertType::Host => "host",
        }
    );
    println!("  serial      : {}", cert.serial());
    println!("  key-id      : {}", cert.key_id());
    println!("  principals  : {}", cert.valid_principals().join(", "));
    println!("  valid-after : {}", cert.valid_after());
    println!("  valid-before: {}", cert.valid_before());
    println!("  ca-fp       : {ca_fp}");
    Ok(())
}

fn load_trusted_cas(path: &Path) -> Result<Vec<PublicKey>> {
    let text = fs::read_to_string(path)
        .map_err(|e| Error::InvalidArgs(format!("read trusted-cas `{}`: {e}", path.display())))?;
    let mut out = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let pk = PublicKey::from_openssh(line).map_err(|e| {
            Error::InvalidConfig(format!(
                "{}:{}: not an OpenSSH public key: {e}",
                path.display(),
                i + 1
            ))
        })?;
        out.push(pk);
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// `key install-public`
// ---------------------------------------------------------------------------

/// Append a public key to the remote host's `~/.ssh/authorized_keys`.
///
/// **Status**: scaffolded. The end-to-end test is gated behind `#[ignore]`
/// pending a controlled SSH server fixture (the russh-server-based one used
/// by `spt-ssh2`'s integration suite). The function returns a structured
/// error when neither `--target` nor `--profile` is given.
#[allow(clippy::needless_pass_by_value)]
pub async fn install_public(global: &GlobalOpts, args: KeyInstallPublicArgs) -> Result<()> {
    let public_line = read_public_key_line(&args.key)?;

    if args.profile.is_none() && args.target.is_none() {
        return Err(Error::InvalidArgs(
            "install-public: either --profile or --target <user@host[:port]> is required".into(),
        ));
    }

    if let Some(profile) = args.profile.as_deref() {
        // Resolve the named profile from config to its connection target
        // (host/user/port), then perform the install through the SAME path the
        // `--target` flow uses (`install_public_via_direct_ssh`). This is the
        // mechanism profile-targeting key ops use: the profile's endpoint
        // config is the source of truth for where the key lands. `--target`
        // and `--profile` are mutually exclusive (clap enforces), so a profile
        // never combines with an explicit target.
        let parsed = resolve_profile_target(global, profile)?;
        return install_public_via_direct_ssh(&parsed, &public_line).await;
    }

    let target = args
        .target
        .as_deref()
        .ok_or_else(|| Error::InvalidArgs("missing --target".into()))?;
    let parsed = parse_user_host_port(target)?;

    install_public_via_direct_ssh(&parsed, &public_line).await
}

/// Resolve a `--profile <name>` to its connection target by loading the
/// configured profile and reading its endpoint config.
///
/// The target host/user/port come from the profile's top-level
/// `host`/`user`/`port` fields, falling back to its first
/// `[[profiles.endpoints]]` entry (the same precedence the connect flow uses
/// to pick a primary endpoint). A profile with no resolvable host, or an
/// `ssh3`-only profile (URL endpoint, no host), is rejected with a clear
/// error.
fn resolve_profile_target(global: &GlobalOpts, profile: &str) -> Result<UserHostPort> {
    let path = global.config.clone().ok_or_else(|| {
        Error::InvalidArgs(
            "install-public --profile requires a config (pass --config or set $SPT_CONFIG)".into(),
        )
    })?;
    let (cfg, _) =
        spt_config::load(&path, false).map_err(|e| Error::InvalidConfig(format!("load: {e}")))?;
    let p = cfg
        .profiles
        .iter()
        .find(|p| p.name == profile)
        .ok_or_else(|| Error::InvalidArgs(format!("no profile `{profile}` in config")))?;

    // Primary endpoint precedence: top-level host, else first endpoint.
    let (host, port, ep_user) = if let Some(h) = p.host.clone() {
        (h, p.port.unwrap_or(22), None)
    } else if let Some(ep) = p.endpoints.first() {
        (ep.host.clone(), ep.port, ep.user.clone())
    } else {
        return Err(Error::InvalidConfig(format!(
            "profile `{profile}` has no host/endpoint to install the key on \
             (ssh3 URL-only profiles are not supported by install-public; use --target)"
        )));
    };

    let user = p
        .user
        .clone()
        .or(ep_user)
        .ok_or_else(|| Error::InvalidConfig(format!("profile `{profile}` has no `user`")))?;

    Ok(UserHostPort { user, host, port })
}

#[derive(Debug, Clone)]
struct UserHostPort {
    user: String,
    host: String,
    port: u16,
}

fn parse_user_host_port(s: &str) -> Result<UserHostPort> {
    let (user, rest) = s.split_once('@').ok_or_else(|| {
        Error::InvalidArgs(format!("--target must be `user@host[:port]`, got `{s}`"))
    })?;
    if user.is_empty() {
        return Err(Error::InvalidArgs(format!("--target user empty in `{s}`")));
    }
    let (host, port) = match rest.rsplit_once(':') {
        Some((h, p)) => {
            // distinguish "host:port" from a bracketed v6 like "[::1]:22"
            // ssh hostnames cannot legally contain `:`, so treat ":" as port
            // separator unconditionally for this CLI.
            let port: u16 = p
                .parse()
                .map_err(|e| Error::InvalidArgs(format!("invalid port `{p}`: {e}")))?;
            (h.to_string(), port)
        }
        None => (rest.to_string(), 22u16),
    };
    if host.is_empty() {
        return Err(Error::InvalidArgs(format!("--target host empty in `{s}`")));
    }
    Ok(UserHostPort {
        user: user.to_string(),
        host,
        port,
    })
}

async fn install_public_via_direct_ssh(_target: &UserHostPort, _key: &str) -> Result<()> {
    // The direct-SSH install path requires channel-exec wiring (not yet
    // exposed by `spt-ssh2::Ssh2Session`). Wiring lands together with the
    // integration-test fixture in this group's follow-up — the unit test
    // covering the happy path is correspondingly `#[ignore]`-d. The
    // function is intentionally a clear, typed error so the CLI exits with
    // a usable code in the meantime.
    Err(Error::UnsupportedPlatform(
        "install-public --target: direct-SSH install path is not yet enabled in this build \
         (tracked in f-cli-key follow-up; see plans/cli-fill-final.md)"
            .into(),
    ))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn render_public_line(kp: &KeyPair) -> Result<String> {
    let pubk = kp.public_ref();
    let line = pubk
        .to_openssh()
        .map_err(|e| Error::KeyFailure(format!("encode public key: {e}")))?;
    Ok(format!("{line}\n"))
}

fn read_public_key_file(path: &Path) -> Result<PublicKey> {
    let text = fs::read_to_string(path)
        .map_err(|e| Error::InvalidArgs(format!("read public key `{}`: {e}", path.display())))?;
    let line = text
        .lines()
        .find(|l| !l.trim().is_empty() && !l.trim_start().starts_with('#'))
        .ok_or_else(|| {
            Error::InvalidArgs(format!("public key file `{}` is empty", path.display()))
        })?;
    PublicKey::from_openssh(line.trim())
        .map_err(|e| Error::InvalidConfig(format!("parse public key: {e}")))
}

fn read_public_key_line(path: &Path) -> Result<String> {
    let text = fs::read_to_string(path)
        .map_err(|e| Error::InvalidArgs(format!("read `{}`: {e}", path.display())))?;
    let line = text
        .lines()
        .find(|l| !l.trim().is_empty() && !l.trim_start().starts_with('#'))
        .ok_or_else(|| {
            Error::InvalidArgs(format!("public key file `{}` is empty", path.display()))
        })?;
    // Sanity-check that it parses.
    let _ = PublicKey::from_openssh(line.trim())
        .map_err(|e| Error::InvalidConfig(format!("not an OpenSSH public key: {e}")))?;
    Ok(line.trim().to_string())
}

fn load_with_passphrase_chain(path: &Path) -> Result<KeyPair> {
    // Pre-flight: if the file doesn't exist, fail fast instead of falling
    // through to the interactive prompt path. Without this check, a missing
    // key file causes `spt_key::load` to return Err, then we'd block on
    // stdin in non-interactive contexts (tests, batch jobs).
    if !path.exists() {
        return Err(Error::InvalidArgs(format!(
            "key file `{}` not found",
            path.display()
        )));
    }
    // Try unencrypted first.
    if let Ok(kp) = spt_key::load(path, None) {
        return Ok(kp);
    }
    // Then env, then stdin prompt.
    if let Ok(pw) = std::env::var("SPT_KEY_PASSPHRASE") {
        return spt_key::load(path, Some(&pw));
    }
    let pw = prompt_passphrase(&format!("passphrase for {}: ", path.display()))?;
    spt_key::load(path, Some(&pw))
}

fn passphrase_from_env_or_prompt(prompt: &str) -> Result<String> {
    if let Ok(pw) = std::env::var("SPT_KEY_PASSPHRASE") {
        return Ok(pw);
    }
    prompt_passphrase(prompt)
}

fn prompt_passphrase(prompt: &str) -> Result<String> {
    use std::io::{self, BufRead};
    eprint!("{prompt}");
    let _ = io::stderr().flush();
    let mut buf = String::new();
    io::stdin()
        .lock()
        .read_line(&mut buf)
        .map_err(|e| Error::RuntimeFailure(format!("read passphrase: {e}")))?;
    Ok(buf
        .trim_end_matches(|c: char| c == '\n' || c == '\r')
        .to_string())
}

fn resolve_secret_ref_to_string(global: &GlobalOpts, reference: &str) -> Result<String> {
    use spt_auth::SecretRef;
    let r = SecretRef::parse(reference).map_err(|e| {
        Error::InvalidArgs(format!("invalid --new-passphrase-from `{reference}`: {e}"))
    })?;
    match r {
        SecretRef::Env(name) => std::env::var(&name).map_err(|e| Error::SecretUnavailable {
            reference: format!("env:{name}"),
            reason: e.to_string(),
        }),
        SecretRef::File(p) => fs::read_to_string(&p)
            .map(|s| {
                s.trim_end_matches(|c: char| c == '\n' || c == '\r')
                    .to_string()
            })
            .map_err(|e| Error::SecretUnavailable {
                reference: format!("file://{p}"),
                reason: e.to_string(),
            }),
        // `secret://ns/name` references resolve through the same multi-backend
        // resolver the rest of the binary uses (built from the `[secrets]`
        // config table, rooted at the state dir).
        SecretRef::Vault { .. } => resolve_vault_ref_to_string(global, &r),
    }
}

/// Resolve a `secret://ns/name` reference to a UTF-8 passphrase string using
/// the shared [`spt_secrets::Resolver`]. Unsupported / unresolvable references
/// surface a clear [`Error::SecretUnavailable`].
fn resolve_vault_ref_to_string(
    global: &GlobalOpts,
    auth_ref: &spt_auth::SecretRef,
) -> Result<String> {
    use secrecy::ExposeSecret as _;

    let resolver_ref = crate::secrets_bridge::auth_ref_to_resolver_ref(auth_ref)?;
    let state_dir = spt_state::resolve_state_dir(global.state_dir.as_deref())?;
    let secrets_cfg = global
        .config
        .as_deref()
        .and_then(|p| spt_config::load(p, false).ok())
        .and_then(|(cfg, _)| cfg.secrets.clone());
    let resolver = crate::secrets_bridge::build_resolver(secrets_cfg.as_ref(), &state_dir)?;
    let bytes = resolver.resolve(&resolver_ref)?;
    let s = std::str::from_utf8(bytes.expose_secret()).map_err(|e| Error::SecretUnavailable {
        reference: auth_ref.to_string(),
        reason: format!("secret is not valid UTF-8: {e}"),
    })?;
    Ok(s.trim_end_matches(|c: char| c == '\n' || c == '\r')
        .to_string())
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    use atomicwrites::{AtomicFile, OverwriteBehavior};
    let af = AtomicFile::new(path, OverwriteBehavior::AllowOverwrite);
    af.write(|f| f.write_all(bytes))
        .map_err(|e| Error::RuntimeFailure(format!("atomic write `{}`: {e}", path.display())))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use spt_cli::{ColorMode, GlobalOpts, LogLevel, OutputFormat};
    use spt_key::testing::deterministic_keypair;
    use spt_key::KeyAlgorithm;
    use tempfile::tempdir;

    /// Serialises tests that mutate the process-global `SPT_KEY_PASSPHRASE` /
    /// `SPT_KEY_NEW` env vars (read back by `change_passphrase`). Held across
    /// the awaited call so the values are stable for the whole flow — lets
    /// `cargo test -p spt-bin` pass without `--test-threads=1`.
    fn key_env_lock() -> &'static std::sync::Mutex<()> {
        static L: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
        L.get_or_init(|| std::sync::Mutex::new(()))
    }

    fn opts() -> GlobalOpts {
        GlobalOpts {
            config: None,
            config_dir: None,
            config_url: None,
            config_fingerprint: None,
            state_dir: None,
            profile: None,
            portable: false,
            output: OutputFormat::Human,
            json: false,
            log_level: LogLevel::Info,
            color: ColorMode::Never,
            quiet: true,
            verbose: 0,
            no_color: true,
            dry_run: false,
        }
    }

    #[tokio::test]
    async fn public_writes_matching_fingerprint() {
        let kp = deterministic_keypair(42, KeyAlgorithm::Ed25519).unwrap();
        let dir = tempdir().unwrap();
        let priv_p = dir.path().join("id");
        let out_p = dir.path().join("id.pub");
        spt_key::save_encrypted(&kp, &priv_p, None).unwrap();

        super::public(
            &opts(),
            KeyPublicArgs {
                key: priv_p.clone(),
                out: Some(out_p.clone()),
            },
        )
        .await
        .unwrap();

        let written = fs::read_to_string(&out_p).unwrap();
        let parsed = PublicKey::from_openssh(written.trim()).unwrap();
        let expected = spt_key::fingerprint_sha256(kp.public_ref());
        let got = spt_key::fingerprint_sha256(&parsed);
        assert_eq!(got, expected);
    }

    #[tokio::test]
    async fn change_passphrase_round_trip_via_env() {
        let _env = key_env_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let kp = deterministic_keypair(7, KeyAlgorithm::Ed25519).unwrap();
        let dir = tempdir().unwrap();
        let p = dir.path().join("id");
        spt_key::save_encrypted(&kp, &p, Some("old-pw")).unwrap();

        // Old passphrase: env. New passphrase: --new-passphrase-from env:NEW.
        // The `key_env_lock` guard serialises the env mutation below.
        let old = std::env::var("SPT_KEY_PASSPHRASE").ok();
        let new = std::env::var("SPT_KEY_NEW").ok();
        std::env::set_var("SPT_KEY_PASSPHRASE", "old-pw");
        std::env::set_var("SPT_KEY_NEW", "new-pw");

        let r = super::change_passphrase(
            &opts(),
            KeyChangePassphraseArgs {
                key: p.clone(),
                new_passphrase_from: Some("env:SPT_KEY_NEW".into()),
            },
        )
        .await;

        // Restore env regardless of test outcome.
        match old {
            Some(v) => std::env::set_var("SPT_KEY_PASSPHRASE", v),
            None => std::env::remove_var("SPT_KEY_PASSPHRASE"),
        }
        match new {
            Some(v) => std::env::set_var("SPT_KEY_NEW", v),
            None => std::env::remove_var("SPT_KEY_NEW"),
        }
        r.unwrap();

        // Old passphrase should no longer decrypt.
        assert!(spt_key::load(&p, Some("old-pw")).is_err());
        // New one should.
        let loaded = spt_key::load(&p, Some("new-pw")).unwrap();
        assert_eq!(
            spt_key::fingerprint_sha256(loaded.public_ref()),
            spt_key::fingerprint_sha256(kp.public_ref())
        );
        // Backup created.
        assert!(p.with_extension("bak").exists() || dir.path().join("id.bak").exists());
    }

    #[tokio::test]
    async fn sign_and_verify_round_trip() {
        let ca = deterministic_keypair(42, KeyAlgorithm::Ed25519).unwrap();
        let subject = deterministic_keypair(43, KeyAlgorithm::Ed25519).unwrap();

        let dir = tempdir().unwrap();
        let ca_path = dir.path().join("ca");
        let subj_pub_path = dir.path().join("user.pub");
        let cert_path = dir.path().join("user-cert.pub");
        let cas_path = dir.path().join("trusted_cas");

        spt_key::save_encrypted(&ca, &ca_path, None).unwrap();

        // Write subject public key in OpenSSH single-line form.
        let subj_line = subject.public_ref().to_openssh().unwrap();
        fs::write(&subj_pub_path, format!("{subj_line}\n")).unwrap();

        // Trusted CAs file: one OpenSSH-format line.
        let ca_line = ca.public_ref().to_openssh().unwrap();
        fs::write(&cas_path, format!("{ca_line}\n# comment\n")).unwrap();

        super::sign_cert(
            &opts(),
            KeySignCertArgs {
                ca: ca_path.clone(),
                subject: subj_pub_path.clone(),
                principals: vec!["alice".into()],
                validity: Some("1h".into()),
                serial: Some(1234),
                cert_type: Some(CertTypeArg::User),
                key_id: Some("alice@spt".into()),
                out: Some(cert_path.clone()),
            },
        )
        .await
        .unwrap();

        super::verify_cert(
            &opts(),
            KeyVerifyCertArgs {
                cert: cert_path.clone(),
                trusted_cas: cas_path.clone(),
            },
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn verify_cert_rejects_untrusted_ca() {
        let ca = deterministic_keypair(1, KeyAlgorithm::Ed25519).unwrap();
        let other_ca = deterministic_keypair(2, KeyAlgorithm::Ed25519).unwrap();
        let subject = deterministic_keypair(3, KeyAlgorithm::Ed25519).unwrap();

        let dir = tempdir().unwrap();
        let ca_path = dir.path().join("ca");
        let subj_pub_path = dir.path().join("user.pub");
        let cert_path = dir.path().join("user-cert.pub");
        let cas_path = dir.path().join("trusted_cas");
        spt_key::save_encrypted(&ca, &ca_path, None).unwrap();
        fs::write(
            &subj_pub_path,
            format!("{}\n", subject.public_ref().to_openssh().unwrap()),
        )
        .unwrap();
        fs::write(
            &cas_path,
            format!("{}\n", other_ca.public_ref().to_openssh().unwrap()),
        )
        .unwrap();

        super::sign_cert(
            &opts(),
            KeySignCertArgs {
                ca: ca_path,
                subject: subj_pub_path,
                principals: vec!["bob".into()],
                validity: None,
                serial: None,
                cert_type: None,
                key_id: None,
                out: Some(cert_path.clone()),
            },
        )
        .await
        .unwrap();

        let r = super::verify_cert(
            &opts(),
            KeyVerifyCertArgs {
                cert: cert_path,
                trusted_cas: cas_path,
            },
        )
        .await;
        assert!(matches!(r, Err(Error::TrustFailed(_))));
    }

    #[test]
    fn parse_user_host_port_variants() {
        let p = parse_user_host_port("alice@host.example").unwrap();
        assert_eq!(p.user, "alice");
        assert_eq!(p.host, "host.example");
        assert_eq!(p.port, 22);

        let p = parse_user_host_port("bob@10.0.0.1:2222").unwrap();
        assert_eq!(p.host, "10.0.0.1");
        assert_eq!(p.port, 2222);

        assert!(parse_user_host_port("nohost").is_err());
        assert!(parse_user_host_port("@host").is_err());
        assert!(parse_user_host_port("u@host:notaport").is_err());
    }

    #[tokio::test]
    async fn install_public_requires_target_or_profile() {
        let dir = tempdir().unwrap();
        let kp = deterministic_keypair(42, KeyAlgorithm::Ed25519).unwrap();
        let pub_path = dir.path().join("id.pub");
        fs::write(
            &pub_path,
            format!("{}\n", kp.public_ref().to_openssh().unwrap()),
        )
        .unwrap();

        let r = super::install_public(
            &opts(),
            KeyInstallPublicArgs {
                key: pub_path,
                target: None,
                profile: None,
            },
        )
        .await;
        assert!(matches!(r, Err(Error::InvalidArgs(_))));
    }

    // ------------------------------------------------------------------
    // B1: install-public --profile resolves the profile's endpoint config
    // and routes through the same install path as --target.
    // ------------------------------------------------------------------

    fn opts_with_config(config: PathBuf) -> GlobalOpts {
        GlobalOpts {
            config: Some(config),
            ..opts()
        }
    }

    fn write_pubkey(dir: &Path) -> PathBuf {
        let kp = deterministic_keypair(42, KeyAlgorithm::Ed25519).unwrap();
        let pub_path = dir.join("id.pub");
        fs::write(
            &pub_path,
            format!("{}\n", kp.public_ref().to_openssh().unwrap()),
        )
        .unwrap();
        pub_path
    }

    #[test]
    fn resolve_profile_target_uses_top_level_host_user_port() {
        let dir = tempdir().unwrap();
        let cfg = dir.path().join("c.toml");
        fs::write(
            &cfg,
            "version = 1\n\
             [[profiles]]\n\
             name = \"prod\"\n\
             protocol = \"ssh2\"\n\
             host = \"host.example\"\n\
             port = 2200\n\
             user = \"deploy\"\n",
        )
        .unwrap();
        let g = opts_with_config(cfg);
        let t = super::resolve_profile_target(&g, "prod").unwrap();
        assert_eq!(t.host, "host.example");
        assert_eq!(t.port, 2200);
        assert_eq!(t.user, "deploy");
    }

    #[test]
    fn resolve_profile_target_falls_back_to_first_endpoint() {
        let dir = tempdir().unwrap();
        let cfg = dir.path().join("c.toml");
        fs::write(
            &cfg,
            "version = 1\n\
             [[profiles]]\n\
             name = \"ha\"\n\
             protocol = \"ssh2\"\n\
             user = \"svc\"\n\
             [[profiles.endpoints]]\n\
             name = \"ep1\"\n\
             host = \"ep1.example\"\n\
             port = 2022\n",
        )
        .unwrap();
        let g = opts_with_config(cfg);
        let t = super::resolve_profile_target(&g, "ha").unwrap();
        assert_eq!(t.host, "ep1.example");
        assert_eq!(t.port, 2022);
        assert_eq!(t.user, "svc");
    }

    #[test]
    fn resolve_profile_target_unknown_profile_errors() {
        let dir = tempdir().unwrap();
        let cfg = dir.path().join("c.toml");
        fs::write(&cfg, "version = 1\n").unwrap();
        let g = opts_with_config(cfg);
        let err = super::resolve_profile_target(&g, "nope").unwrap_err();
        assert!(matches!(err, Error::InvalidArgs(_)));
    }

    #[test]
    fn resolve_profile_target_no_host_errors() {
        let dir = tempdir().unwrap();
        let cfg = dir.path().join("c.toml");
        fs::write(
            &cfg,
            "version = 1\n\
             [[profiles]]\n\
             name = \"u\"\n\
             protocol = \"ssh3\"\n\
             endpoint = \"https://x/\"\n\
             user = \"u\"\n",
        )
        .unwrap();
        let g = opts_with_config(cfg);
        let err = super::resolve_profile_target(&g, "u").unwrap_err();
        assert!(matches!(err, Error::InvalidConfig(_)));
    }

    #[tokio::test]
    async fn install_public_profile_routes_through_install_path() {
        // A resolvable profile reaches the shared direct-SSH install path
        // (which today returns a typed UnsupportedPlatform until channel-exec
        // lands) — proving --profile is wired through the install path rather
        // than the old "not yet wired (Phase B)" RuntimeFailure.
        let dir = tempdir().unwrap();
        let cfg = dir.path().join("c.toml");
        fs::write(
            &cfg,
            "version = 1\n\
             [[profiles]]\n\
             name = \"prod\"\n\
             protocol = \"ssh2\"\n\
             host = \"host.example\"\n\
             user = \"deploy\"\n",
        )
        .unwrap();
        let pub_path = write_pubkey(dir.path());
        let g = opts_with_config(cfg);
        let r = super::install_public(
            &g,
            KeyInstallPublicArgs {
                key: pub_path,
                target: None,
                profile: Some("prod".into()),
            },
        )
        .await;
        // Routed to the install path: the error is the shared install path's
        // typed error, NOT the legacy Phase-B RuntimeFailure.
        match r {
            Err(Error::UnsupportedPlatform(_)) => {}
            other => panic!("expected UnsupportedPlatform from install path, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn install_public_unknown_profile_errors() {
        let dir = tempdir().unwrap();
        let cfg = dir.path().join("c.toml");
        fs::write(&cfg, "version = 1\n").unwrap();
        let pub_path = write_pubkey(dir.path());
        let g = opts_with_config(cfg);
        let r = super::install_public(
            &g,
            KeyInstallPublicArgs {
                key: pub_path,
                target: None,
                profile: Some("ghost".into()),
            },
        )
        .await;
        assert!(matches!(r, Err(Error::InvalidArgs(_))));
    }

    // ------------------------------------------------------------------
    // B2: secret:// resolution in `key change-passphrase`.
    // ------------------------------------------------------------------

    /// Write a secret to the file backend at `<state_dir>/secrets/<ns>/<name>`
    /// with owner-only permissions so the resolver's Unix mode check passes.
    fn put_file_secret(state_dir: &Path, ns: &str, name: &str, value: &[u8]) {
        let p = state_dir.join("secrets").join(ns).join(name);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(&p, value).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).unwrap();
        }
    }

    fn opts_with_state(state: PathBuf) -> GlobalOpts {
        GlobalOpts {
            state_dir: Some(state),
            ..opts()
        }
    }

    #[test]
    fn resolve_secret_ref_resolves_vault_reference_from_file_backend() {
        let dir = tempdir().unwrap();
        put_file_secret(dir.path(), "keys", "newpw", b"vault-passphrase\n");
        let g = opts_with_state(dir.path().to_path_buf());
        let got = super::resolve_secret_ref_to_string(&g, "secret://keys/newpw").unwrap();
        // Trailing newline trimmed.
        assert_eq!(got, "vault-passphrase");
    }

    #[test]
    fn resolve_secret_ref_rejects_unresolvable_vault_reference() {
        let dir = tempdir().unwrap();
        let g = opts_with_state(dir.path().to_path_buf());
        let err = super::resolve_secret_ref_to_string(&g, "secret://keys/absent").unwrap_err();
        assert!(matches!(err, Error::SecretUnavailable { .. }));
    }

    #[test]
    fn resolve_secret_ref_rejects_malformed_reference() {
        let dir = tempdir().unwrap();
        let g = opts_with_state(dir.path().to_path_buf());
        // A malformed secret:// ref (empty name) is rejected up front.
        let err = super::resolve_secret_ref_to_string(&g, "secret://").unwrap_err();
        assert!(matches!(err, Error::InvalidArgs(_)));
    }

    #[tokio::test]
    async fn change_passphrase_resolves_secret_ref_for_new_passphrase() {
        let kp = deterministic_keypair(11, KeyAlgorithm::Ed25519).unwrap();
        let dir = tempdir().unwrap();
        let p = dir.path().join("id");
        spt_key::save_encrypted(&kp, &p, Some("old-pw")).unwrap();
        put_file_secret(dir.path(), "keys", "newpw", b"resolved-new-pw");

        // The `key_env_lock` guard serialises the env mutation below.
        let _env = key_env_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let old = std::env::var("SPT_KEY_PASSPHRASE").ok();
        std::env::set_var("SPT_KEY_PASSPHRASE", "old-pw");
        let g = opts_with_state(dir.path().to_path_buf());
        let r = super::change_passphrase(
            &g,
            KeyChangePassphraseArgs {
                key: p.clone(),
                new_passphrase_from: Some("secret://keys/newpw".into()),
            },
        )
        .await;
        match old {
            Some(v) => std::env::set_var("SPT_KEY_PASSPHRASE", v),
            None => std::env::remove_var("SPT_KEY_PASSPHRASE"),
        }
        r.unwrap();

        // New passphrase (from the vault secret) decrypts; old one no longer does.
        assert!(spt_key::load(&p, Some("resolved-new-pw")).is_ok());
        assert!(spt_key::load(&p, Some("old-pw")).is_err());
    }

    /// End-to-end install against a real SSH server. Needs a russh-server
    /// fixture; tracked in the `f-cli-key` follow-up.
    #[tokio::test]
    #[ignore = "needs a controlled SSH server fixture (see plans/cli-fill-final.md)"]
    async fn install_public_appends_to_authorized_keys() {
        let dir = tempdir().unwrap();
        let kp = deterministic_keypair(42, KeyAlgorithm::Ed25519).unwrap();
        let pub_path = dir.path().join("id.pub");
        fs::write(
            &pub_path,
            format!("{}\n", kp.public_ref().to_openssh().unwrap()),
        )
        .unwrap();

        // Spin up server, point --target at it, expect Ok(()).
        let _ = super::install_public(
            &opts(),
            KeyInstallPublicArgs {
                key: pub_path,
                target: Some("test@127.0.0.1:2222".into()),
                profile: None,
            },
        )
        .await;
    }
}
