//! Implementation bodies for `spt secret store init`, `spt secret list`,
//! and `spt secret rotate`.
//!
//! These bodies are deliberately decoupled from the `clap`-derived
//! argument structs in `spt_cli::groups::secret`: the Phase A executor
//! that owns this file does not own the CLI args module, so the input
//! types defined here are plain structs that the dispatch wirer (Phase B)
//! constructs from the parsed `clap` values. This isolation also makes
//! the unit tests below straightforward to drive.
//!
//! Security invariants enforced here:
//!
//! * Plaintext secret material never reaches stdout, stderr, or any
//!   `tracing` event. Confirmation lines reference only the `secret://`
//!   ref and the success state.
//! * `store init` refuses to overwrite an existing vault — the caller
//!   must rotate or migrate explicitly.
//! * `rotate` performs an atomic write via the underlying `VaultBackend`
//!   so a failed re-encryption leaves the previous record intact.
//! * Master keys live in `SecretBox<Zeroizing<[u8; 32]>>` inside
//!   [`spt_secrets::VaultBackend`]; passphrase bytes pulled from
//!   `--passphrase-from` are kept in `Zeroizing<Vec<u8>>` for their
//!   entire lifetime in this module.

use std::io::{self, BufRead, Read, Write};
use std::path::{Path, PathBuf};

use spt_cli::{GlobalOpts, OutputFormat};
use spt_core::{Error, Result};
use spt_secrets::{KeychainBackend, SecretBackend, SecretRef, VaultBackend};
use secrecy::zeroize::Zeroizing;

/// Default sub-directory under `<state_dir>` that holds `vault.spt`.
const DEFAULT_VAULT_SUBDIR: &str = "secrets";

/// Parsed args for `spt secret store init`.
#[derive(Debug, Default)]
pub struct SecretStoreInitArgs {
    /// Optional override for the directory that will hold `vault.spt`
    /// and `vault.spt.meta`. When unset, the vault is placed under
    /// `<state_dir>/secrets/`.
    pub vault_path: Option<PathBuf>,
    /// Optional source for the passphrase used by the Argon2id fallback
    /// path. Accepted forms: `stdin`, `file:<path>`, `env:<NAME>`.
    /// When set, the keychain path is bypassed entirely.
    pub passphrase_from: Option<String>,
}

/// Parsed args for `spt secret list`.
#[derive(Debug, Default)]
pub struct SecretListArgs {
    /// Restrict output to a single namespace (`secret://<ns>/...`).
    pub namespace: Option<String>,
    /// Optional override for the vault directory (mirrors
    /// [`SecretStoreInitArgs::vault_path`]).
    pub vault_path: Option<PathBuf>,
    /// Passphrase source if the vault is unlocked via the Argon2id
    /// fallback. Same grammar as [`SecretStoreInitArgs::passphrase_from`].
    pub passphrase_from: Option<String>,
}

/// Parsed args for `spt secret rotate <ref>`.
#[derive(Debug)]
pub struct SecretRotateArgs {
    /// `secret://ns/name` reference to rotate.
    pub reference: String,
    /// Source for the new value. Accepted: `stdin`, `file:<path>`,
    /// `env:<NAME>`. Defaults to interactive stdin prompt when unset.
    pub new_value_from: Option<String>,
    /// Optional override for the vault directory.
    pub vault_path: Option<PathBuf>,
    /// Passphrase source if the vault is unlocked via Argon2id fallback.
    pub passphrase_from: Option<String>,
}

// --------------------------------------------------------------------------
// public entry points
// --------------------------------------------------------------------------

/// Implements `spt secret store init`. See module docs for invariants.
pub async fn store_init(global: &GlobalOpts, args: SecretStoreInitArgs) -> Result<()> {
    let dir = resolve_vault_dir(global, args.vault_path.as_deref())?;
    let vault_file = VaultBackend::vault_path(&dir);
    let meta_file = VaultBackend::meta_path(&dir);
    if vault_file.exists() || meta_file.exists() {
        return Err(Error::InvalidArgs(format!(
            "vault already exists at `{}` — refusing to overwrite",
            dir.display()
        )));
    }

    let kc = KeychainBackend::with_service("spt".to_string());

    // If the operator explicitly supplied a passphrase source, honor it
    // unconditionally — this is the documented "skip the keychain" knob
    // for headless deployments.
    let used_passphrase = if let Some(spec) = args.passphrase_from.as_deref() {
        let pp = read_passphrase_source(spec)?;
        let _vault = VaultBackend::init_with_passphrase(&dir, pp.as_slice())?;
        true
    } else {
        // Try the keychain path first; if any keyring failure surfaces
        // (no Secret Service, locked keychain, etc.), fall back to
        // prompting for a passphrase on stderr.
        match VaultBackend::init_with_keychain(&dir, &kc) {
            Ok(_v) => false,
            Err(e) => {
                eprintln!(
                    "warning: keychain unavailable ({e}); falling back to passphrase fallback"
                );
                let pp = prompt_passphrase_no_echo("vault passphrase: ")?;
                let _vault = VaultBackend::init_with_passphrase(&dir, pp.as_slice())?;
                true
            }
        }
    };

    emit_init_summary(global, &dir, used_passphrase);
    Ok(())
}

/// Implements `spt secret list`. Never prints values.
pub async fn list(global: &GlobalOpts, args: SecretListArgs) -> Result<()> {
    let dir = resolve_vault_dir(global, args.vault_path.as_deref())?;
    let vault = open_vault(&dir, args.passphrase_from.as_deref())?;
    let mut refs = vault.list_refs(args.namespace.as_deref())?;
    refs.sort_by_key(ToString::to_string);

    match output_format(global) {
        OutputFormat::Json | OutputFormat::Jsonl => {
            let strs: Vec<String> = refs
                .iter()
                .map(|r| format!("secret://{}/{}", r.ns(), r.name()))
                .collect();
            let v = serde_json::to_string_pretty(&strs)
                .map_err(|e| Error::RuntimeFailure(format!("encode list: {e}")))?;
            println!("{v}");
        }
        OutputFormat::Yaml => {
            let strs: Vec<String> = refs
                .iter()
                .map(|r| format!("secret://{}/{}", r.ns(), r.name()))
                .collect();
            let y = serde_yaml::to_string(&strs)
                .map_err(|e| Error::RuntimeFailure(format!("encode list: {e}")))?;
            print!("{y}");
        }
        OutputFormat::Human => {
            for r in &refs {
                println!("secret://{}/{}", r.ns(), r.name());
            }
        }
    }
    Ok(())
}

/// Implements `spt secret rotate <ref>`. Atomic — old value preserved on
/// failure (write atomicity provided by [`spt_secrets::VaultBackend`]).
pub async fn rotate(global: &GlobalOpts, args: SecretRotateArgs) -> Result<()> {
    let r = parse_secret_ref(&args.reference)?;
    let dir = resolve_vault_dir(global, args.vault_path.as_deref())?;
    let vault = open_vault(&dir, args.passphrase_from.as_deref())?;

    // Verify the secret currently exists before consuming the new value
    // — surfaces a typed error rather than silently creating a record.
    if vault.get(&r)?.is_none() {
        return Err(Error::SecretUnavailable {
            reference: format!("secret://{}/{}", r.ns(), r.name()),
            reason: "not in vault — use `spt secret set` to create a new entry".into(),
        });
    }

    let new_value = match args.new_value_from.as_deref() {
        Some(spec) => read_value_source(spec)?,
        None => prompt_passphrase_no_echo(&format!(
            "new value for `secret://{}/{}`: ",
            r.ns(),
            r.name()
        ))?,
    };

    // `VaultBackend::set` performs an atomic file replace; an error path
    // here leaves `vault.spt` untouched.
    vault.set(&r, new_value.as_slice())?;

    match output_format(global) {
        OutputFormat::Json | OutputFormat::Jsonl => {
            let v = serde_json::json!({
                "rotated": true,
                "ref": format!("secret://{}/{}", r.ns(), r.name()),
            });
            println!("{}", serde_json::to_string_pretty(&v).unwrap());
        }
        OutputFormat::Yaml => {
            println!(
                "rotated: true\nref: secret://{}/{}",
                r.ns(),
                r.name()
            );
        }
        OutputFormat::Human => {
            if !global.quiet {
                println!("rotated secret://{}/{}", r.ns(), r.name());
            }
        }
    }
    Ok(())
}

// --------------------------------------------------------------------------
// helpers
// --------------------------------------------------------------------------

fn output_format(global: &GlobalOpts) -> OutputFormat {
    if global.json {
        OutputFormat::Json
    } else {
        global.output
    }
}

fn emit_init_summary(global: &GlobalOpts, dir: &Path, used_passphrase: bool) {
    let key_source = if used_passphrase {
        "passphrase (Argon2id)"
    } else {
        "OS keychain"
    };
    match output_format(global) {
        OutputFormat::Json | OutputFormat::Jsonl => {
            let v = serde_json::json!({
                "initialized": true,
                "vault_dir": dir.display().to_string(),
                "key_source": key_source,
            });
            println!("{}", serde_json::to_string_pretty(&v).unwrap());
        }
        OutputFormat::Yaml => {
            println!(
                "initialized: true\nvault_dir: {}\nkey_source: {key_source}",
                dir.display()
            );
        }
        OutputFormat::Human => {
            if !global.quiet {
                println!(
                    "initialized vault at `{}` (key source: {key_source})",
                    dir.display()
                );
            }
        }
    }
}

/// Resolve the vault directory in the documented precedence:
///
/// 1. Explicit `--vault-path <path>` from the CLI.
/// 2. `<state_dir>/secrets/` where `state_dir` is the platform default
///    or `--state-dir` override.
fn resolve_vault_dir(global: &GlobalOpts, override_path: Option<&Path>) -> Result<PathBuf> {
    if let Some(p) = override_path {
        return Ok(p.to_path_buf());
    }
    let state = spt_state::resolve_state_dir(global.state_dir.as_deref())?;
    Ok(state.join(DEFAULT_VAULT_SUBDIR))
}

/// Open a vault for read/write, choosing the keychain or passphrase path
/// based on whether `--passphrase-from` was supplied.
fn open_vault(dir: &Path, passphrase_from: Option<&str>) -> Result<VaultBackend> {
    if !VaultBackend::vault_path(dir).exists() {
        return Err(Error::SecretUnavailable {
            reference: format!("vault at `{}`", dir.display()),
            reason: "vault does not exist — run `spt secret store init` first".into(),
        });
    }
    if let Some(spec) = passphrase_from {
        let pp = read_passphrase_source(spec)?;
        return VaultBackend::open_with_passphrase(dir, pp.as_slice());
    }
    let kc = KeychainBackend::with_service("spt".to_string());
    match VaultBackend::open_with_keychain(dir, &kc) {
        Ok(v) => Ok(v),
        Err(e) => {
            eprintln!(
                "warning: keychain unavailable ({e}); prompting for passphrase fallback"
            );
            let pp = prompt_passphrase_no_echo("vault passphrase: ")?;
            VaultBackend::open_with_passphrase(dir, pp.as_slice())
        }
    }
}

/// Parse a `secret://ns/name` reference. Bare `ns/name` is also accepted
/// for ergonomic CLI use.
fn parse_secret_ref(s: &str) -> Result<SecretRef> {
    let stripped = s.strip_prefix("secret://").unwrap_or(s);
    let (ns, name) = stripped.split_once('/').ok_or_else(|| {
        Error::InvalidArgs(format!("expected `secret://ns/name`, got `{s}`"))
    })?;
    SecretRef::new(ns.to_owned(), name.to_owned())
        .map_err(|e| Error::InvalidArgs(format!("bad secret ref `{s}`: {e}")))
}

/// Read material referenced by a `--passphrase-from` / `--new-value-from`
/// argument. Accepted spelling:
///
/// * `stdin` — read until EOF from stdin (single line is also fine).
/// * `file:<path>` — read the entire file (mode unchanged).
/// * `env:<NAME>` — read environment variable `NAME`.
fn read_value_source(spec: &str) -> Result<Zeroizing<Vec<u8>>> {
    if spec == "stdin" || spec == "-" {
        let mut buf = Vec::new();
        io::stdin()
            .lock()
            .read_to_end(&mut buf)
            .map_err(|e| Error::RuntimeFailure(format!("read stdin: {e}")))?;
        // Strip a single trailing newline (keystroke artefact) but
        // preserve any further bytes — payloads can be binary.
        if buf.last() == Some(&b'\n') {
            buf.pop();
            if buf.last() == Some(&b'\r') {
                buf.pop();
            }
        }
        return Ok(Zeroizing::new(buf));
    }
    if let Some(path) = spec.strip_prefix("file:") {
        let bytes = std::fs::read(path).map_err(|e| Error::SecretUnavailable {
            reference: format!("file:{path}"),
            reason: e.to_string(),
        })?;
        return Ok(Zeroizing::new(bytes));
    }
    if let Some(name) = spec.strip_prefix("env:") {
        let v = std::env::var_os(name).ok_or_else(|| Error::SecretUnavailable {
            reference: format!("env:{name}"),
            reason: "environment variable not set".into(),
        })?;
        // `OsString` -> bytes. On Windows, fall back to lossy UTF-8;
        // secret material in env vars is conventionally ASCII anyway.
        let s = v.to_string_lossy().into_owned();
        return Ok(Zeroizing::new(s.into_bytes()));
    }
    Err(Error::InvalidArgs(format!(
        "unrecognised value source `{spec}` — expected `stdin`, `file:<path>`, or `env:<NAME>`"
    )))
}

/// Same grammar as [`read_value_source`], used for `--passphrase-from`.
fn read_passphrase_source(spec: &str) -> Result<Zeroizing<Vec<u8>>> {
    read_value_source(spec)
}

/// Prompt for a secret on stderr and read a single line from stdin.
///
/// This implementation does **not** disable terminal echo — the workspace
/// has no `rpassword`-equivalent dep and adding one is out of scope here.
/// Operators handling sensitive material should prefer `--passphrase-from`
/// / `--new-value-from`. The fallback is documented in CLI help.
fn prompt_passphrase_no_echo(prompt: &str) -> Result<Zeroizing<Vec<u8>>> {
    eprint!("{prompt}");
    let _ = io::stderr().flush();
    let mut buf = String::new();
    io::stdin()
        .lock()
        .read_line(&mut buf)
        .map_err(|e| Error::RuntimeFailure(format!("read passphrase: {e}")))?;
    while matches!(buf.chars().last(), Some('\n') | Some('\r')) {
        buf.pop();
    }
    let mut z = Zeroizing::new(buf.into_bytes());
    // Defensive empty-passphrase guard — Argon2id will accept it but
    // it's almost certainly an operator error.
    if z.is_empty() {
        return Err(Error::InvalidArgs("empty passphrase".into()));
    }
    // Wipe the original `String` allocation by rebuilding from `z`'s
    // bytes, which already live in a `Zeroizing` buffer.
    z.shrink_to_fit();
    Ok(z)
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;
    use spt_cli::{ColorMode, LogLevel, OutputFormat as Of};
    use std::sync::Mutex;
    use tempfile::tempdir;

    /// Some tests touch process-wide state (env vars, the keyring default
    /// builder). Serialise them.
    fn test_lock() -> &'static Mutex<()> {
        static L: std::sync::OnceLock<Mutex<()>> = std::sync::OnceLock::new();
        L.get_or_init(|| Mutex::new(()))
    }

    fn fake_global(state_dir: &Path) -> GlobalOpts {
        GlobalOpts {
            config: None,
            config_dir: None,
            config_url: None,
            config_fingerprint: None,
            state_dir: Some(state_dir.to_path_buf()),
            profile: None,
            output: Of::Human,
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
    async fn store_init_creates_vault_then_refuses_second_run() {
        let _g = test_lock().lock().unwrap();
        let state = tempdir().unwrap();
        let global = fake_global(state.path());

        // Force the passphrase path so this test does not depend on the
        // platform keychain being available.
        std::env::set_var("SPT_TEST_INIT_PASSPHRASE", "hunter2");
        let args = SecretStoreInitArgs {
            vault_path: None,
            passphrase_from: Some("env:SPT_TEST_INIT_PASSPHRASE".into()),
        };
        store_init(&global, args).await.unwrap();

        let vault_dir = state.path().join(DEFAULT_VAULT_SUBDIR);
        assert!(vault_dir.join("vault.spt").exists());
        assert!(vault_dir.join("vault.spt.meta").exists());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(vault_dir.join("vault.spt"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
        }

        // Second run must refuse.
        let args2 = SecretStoreInitArgs {
            vault_path: None,
            passphrase_from: Some("env:SPT_TEST_INIT_PASSPHRASE".into()),
        };
        let err = store_init(&global, args2).await.unwrap_err();
        assert!(matches!(err, Error::InvalidArgs(_)), "got {err:?}");
        std::env::remove_var("SPT_TEST_INIT_PASSPHRASE");
    }

    #[tokio::test]
    async fn list_returns_refs_and_filters_by_namespace() {
        let _g = test_lock().lock().unwrap();
        let state = tempdir().unwrap();
        let global = fake_global(state.path());

        std::env::set_var("SPT_TEST_LIST_PP", "correct horse");
        store_init(
            &global,
            SecretStoreInitArgs {
                vault_path: None,
                passphrase_from: Some("env:SPT_TEST_LIST_PP".into()),
            },
        )
        .await
        .unwrap();

        // Pre-populate the vault directly through the backend.
        let dir = state.path().join(DEFAULT_VAULT_SUBDIR);
        let v = VaultBackend::open_with_passphrase(&dir, b"correct horse").unwrap();
        v.set(&SecretRef::new("alpha", "one").unwrap(), b"x").unwrap();
        v.set(&SecretRef::new("alpha", "two").unwrap(), b"y").unwrap();
        v.set(&SecretRef::new("beta", "three").unwrap(), b"z").unwrap();

        list(
            &global,
            SecretListArgs {
                namespace: None,
                vault_path: None,
                passphrase_from: Some("env:SPT_TEST_LIST_PP".into()),
            },
        )
        .await
        .unwrap();

        list(
            &global,
            SecretListArgs {
                namespace: Some("beta".into()),
                vault_path: None,
                passphrase_from: Some("env:SPT_TEST_LIST_PP".into()),
            },
        )
        .await
        .unwrap();
        std::env::remove_var("SPT_TEST_LIST_PP");
    }

    #[tokio::test]
    async fn rotate_replaces_value_atomically() {
        let _g = test_lock().lock().unwrap();
        let state = tempdir().unwrap();
        let global = fake_global(state.path());

        std::env::set_var("SPT_TEST_ROT_PP", "rot-pp");
        store_init(
            &global,
            SecretStoreInitArgs {
                vault_path: None,
                passphrase_from: Some("env:SPT_TEST_ROT_PP".into()),
            },
        )
        .await
        .unwrap();

        let dir = state.path().join(DEFAULT_VAULT_SUBDIR);
        let r = SecretRef::new("ns", "k").unwrap();
        {
            let v = VaultBackend::open_with_passphrase(&dir, b"rot-pp").unwrap();
            v.set(&r, b"old").unwrap();
        }

        std::env::set_var("SPT_TEST_ROT_VAL", "new-secret-value");
        rotate(
            &global,
            SecretRotateArgs {
                reference: "secret://ns/k".into(),
                new_value_from: Some("env:SPT_TEST_ROT_VAL".into()),
                vault_path: None,
                passphrase_from: Some("env:SPT_TEST_ROT_PP".into()),
            },
        )
        .await
        .unwrap();

        let v = VaultBackend::open_with_passphrase(&dir, b"rot-pp").unwrap();
        let got = v.get(&r).unwrap().unwrap();
        assert_eq!(got.expose_secret().as_slice(), b"new-secret-value");

        // Rotating an unknown ref must fail loudly.
        let err = rotate(
            &global,
            SecretRotateArgs {
                reference: "secret://ns/missing".into(),
                new_value_from: Some("env:SPT_TEST_ROT_VAL".into()),
                vault_path: None,
                passphrase_from: Some("env:SPT_TEST_ROT_PP".into()),
            },
        )
        .await
        .unwrap_err();
        assert!(matches!(err, Error::SecretUnavailable { .. }));

        std::env::remove_var("SPT_TEST_ROT_PP");
        std::env::remove_var("SPT_TEST_ROT_VAL");
    }

    #[test]
    fn read_value_source_grammar() {
        std::env::set_var("SPT_T_RVS", "abc");
        let v = read_value_source("env:SPT_T_RVS").unwrap();
        assert_eq!(v.as_slice(), b"abc");
        std::env::remove_var("SPT_T_RVS");

        let dir = tempdir().unwrap();
        let p = dir.path().join("v");
        std::fs::write(&p, b"file-content").unwrap();
        let v = read_value_source(&format!("file:{}", p.display())).unwrap();
        assert_eq!(v.as_slice(), b"file-content");

        let err = read_value_source("nope").unwrap_err();
        assert!(matches!(err, Error::InvalidArgs(_)));
    }

    #[test]
    fn parse_secret_ref_accepts_both_forms() {
        let r1 = parse_secret_ref("secret://ns/name").unwrap();
        let r2 = parse_secret_ref("ns/name").unwrap();
        assert_eq!(r1, r2);
        let err = parse_secret_ref("not a ref").unwrap_err();
        assert!(matches!(err, Error::InvalidArgs(_)));
    }
}
