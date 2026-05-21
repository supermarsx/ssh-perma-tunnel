//! `spt ftp` operation bodies (t6-e6).
//!
//! Currently only `translator serve` is implemented. The body constructs
//! a [`spt_ftp_translator::TranslatorConfig`] from the parsed CLI args
//! and runs `spt_ftp_translator::serve` against an
//! [`spt_ftp_translator::SftpFactory`] resolved from the operator's
//! profile.
//!
//! The factory wiring is **deferred to t6-Bwire** — the spt-bin
//! `profile_factory.rs` will gain an `Ssh2SftpFactory` that mints
//! `SftpClient` handles per authenticated FTP user from the same SSH
//! session the rest of the binary uses. Until then this op returns a
//! clean `Error::InvalidConfig` documenting the missing wiring so the
//! CLI surface exits with the right code.

#![allow(clippy::missing_errors_doc)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::unused_async)]
#![allow(clippy::needless_pass_by_value)]

use std::str::FromStr;
use std::time::Duration;

use spt_cli::{groups, GlobalOpts};
use spt_core::{Error, Result};

type FtpServeArgs = groups::ftp::FtpServeArgs;

/// `spt ftp translator serve`.
pub async fn translator_serve(global: &GlobalOpts, args: FtpServeArgs) -> Result<()> {
    let _ = global;
    // Parse + validate the CLI surface synchronously so misconfigurations
    // exit at code `InvalidConfig` rather than `RuntimeFailure`.
    let (lo, hi) = args
        .parse_pasv_range()
        .map_err(|e| Error::InvalidConfig(format!("ftp translator: {e}")))?;
    let idle = parse_duration(&args.idle_timeout)
        .map_err(|e| Error::InvalidConfig(format!("ftp translator: {e}")))?;
    let external_addr = match &args.external_ip {
        Some(s) => Some(std::net::IpAddr::from_str(s).map_err(|e| {
            Error::InvalidConfig(format!("ftp translator: --external-ip `{s}`: {e}"))
        })?),
        None => None,
    };
    let tls = match (&args.tls_cert, &args.tls_key) {
        (Some(c), Some(k)) => Some(spt_ftp_translator::TlsConfig {
            cert_file: c.clone(),
            key_file: k.clone(),
            require_tls: args.tls_required,
        }),
        _ => None,
    };
    let cfg = spt_ftp_translator::TranslatorConfig {
        bind_addr: args.bind,
        passive_port_range: (lo, hi),
        external_addr,
        welcome_banner: args
            .welcome_banner
            .clone()
            .unwrap_or_else(|| "spt-ftp-translator ready (passive-only)".into()),
        auth: spt_ftp_translator::AuthPolicy::Deny,
        tls,
        max_clients: args.max_clients,
        idle_timeout: idle,
    };
    cfg.validate()
        .map_err(|e| Error::InvalidConfig(format!("ftp translator: {e}")))?;

    // Factory wiring is owned by t6-Bwire (see crate doc). Surfacing the
    // gap as InvalidConfig keeps the CLI surface honest under
    // `cargo build/test --workspace --locked` today.
    let _ = args.profile;
    Err(Error::InvalidConfig(
        "ftp translator: SFTP factory wiring is owned by t6-Bwire \
         (profile_factory.rs::Ssh2SftpFactory). This op is reachable via the CLI but \
         not yet runnable end-to-end."
            .into(),
    ))
}

fn parse_duration(s: &str) -> std::result::Result<Duration, String> {
    // Accept the same shorthand the rest of the CLI uses: bare seconds,
    // or suffixed `s`/`m`/`h`.
    let s = s.trim();
    if s.is_empty() {
        return Err("empty duration".into());
    }
    let (num, unit) = match s.chars().last().unwrap() {
        c if c.is_ascii_digit() => (&s[..], "s"),
        _ => {
            let (num, unit) = s.split_at(s.len() - 1);
            (num, unit)
        }
    };
    let n: u64 = num
        .parse()
        .map_err(|e| format!("invalid number `{num}`: {e}"))?;
    let secs = match unit {
        "s" => n,
        "m" => n * 60,
        "h" => n * 3600,
        other => return Err(format!("unsupported unit `{other}`")),
    };
    Ok(Duration::from_secs(secs))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_duration_supports_units() {
        assert_eq!(parse_duration("30s").unwrap(), Duration::from_secs(30));
        assert_eq!(parse_duration("5m").unwrap(), Duration::from_secs(300));
        assert_eq!(parse_duration("1h").unwrap(), Duration::from_secs(3600));
        assert_eq!(parse_duration("12").unwrap(), Duration::from_secs(12));
        assert!(parse_duration("").is_err());
        assert!(parse_duration("5x").is_err());
    }
}
