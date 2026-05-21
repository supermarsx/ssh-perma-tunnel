//! `spt ftp` — FTP→SFTP translator service (t6-e6).
//!
//! The translator exposes a passive-only RFC 959/3659 FTP control channel
//! and forwards every supported verb to the configured SFTP backend.
//! Active mode (PORT/EPRT) is refused by security policy — see
//! `docs/ftp-translator.md`.
//!
//! Wiring of [`FtpCmd`] into the top-level [`crate::Command`] enum is
//! owned by **t6-Bwire**; this module ships the clap surface so the
//! command is ready to register with a one-line edit.

use std::net::SocketAddr;
use std::path::PathBuf;

use clap::{Args, Subcommand};

const EXAMPLES: &str = "EXAMPLES:
  spt ftp translator serve --bind 0.0.0.0:2121 --pasv-range 50000-50100 --profile edge
  spt ftp translator serve --bind 127.0.0.1:21 \\
      --pasv-range 50000-50100 \\
      --tls-cert /etc/spt/ftp.crt --tls-key /etc/spt/ftp.key \\
      --profile edge";

/// `spt ftp` group.
#[derive(Args, Debug)]
#[command(after_help = EXAMPLES)]
pub struct FtpCmd {
    /// Subcommand.
    #[command(subcommand)]
    pub command: FtpSub,
}

/// Subcommands of `spt ftp`.
#[derive(Subcommand, Debug)]
pub enum FtpSub {
    /// Run / manage the FTP→SFTP translator service.
    Translator(FtpTranslatorCmd),
}

/// `spt ftp translator`.
#[derive(Args, Debug)]
pub struct FtpTranslatorCmd {
    /// Translator subcommand.
    #[command(subcommand)]
    pub command: FtpTranslatorSub,
}

/// Subcommands of `spt ftp translator`.
#[derive(Subcommand, Debug)]
pub enum FtpTranslatorSub {
    /// Start the FTP translator listening on `--bind`.
    Serve(FtpServeArgs),
}

/// `spt ftp translator serve`.
#[derive(Args, Debug)]
pub struct FtpServeArgs {
    /// Control-channel listen address (`host:port`).
    #[arg(long, value_name = "ADDR", default_value = "0.0.0.0:21")]
    pub bind: SocketAddr,
    /// Inclusive passive-port range, formatted `lo-hi`.
    #[arg(long, value_name = "LO-HI", default_value = "50000-50100")]
    pub pasv_range: String,
    /// Optional external IP to advertise in PASV replies (defaults to the
    /// control connection's local address).
    #[arg(long, value_name = "IP")]
    pub external_ip: Option<String>,
    /// Welcome banner sent on connect.
    #[arg(long, value_name = "TEXT")]
    pub welcome_banner: Option<String>,
    /// Maximum concurrent control sessions.
    #[arg(long, value_name = "N", default_value_t = 32)]
    pub max_clients: usize,
    /// Idle timeout for the control channel, e.g. `5m`, `300s`.
    #[arg(long, value_name = "DURATION", default_value = "5m")]
    pub idle_timeout: String,
    /// PEM file with the TLS certificate chain.
    #[arg(long, value_name = "PATH", requires = "tls_key")]
    pub tls_cert: Option<PathBuf>,
    /// PEM file with the TLS private key.
    #[arg(long, value_name = "PATH", requires = "tls_cert")]
    pub tls_key: Option<PathBuf>,
    /// Require TLS before accepting USER/PASS.
    #[arg(long, requires = "tls_cert")]
    pub tls_required: bool,
    /// Profile name used to open the SFTP backend.
    #[arg(long, value_name = "NAME")]
    pub profile: Option<String>,
    /// JSON output.
    #[arg(long)]
    pub json: bool,
}

impl FtpServeArgs {
    /// Parse `--pasv-range LO-HI` into a `(u16, u16)` tuple.
    pub fn parse_pasv_range(&self) -> Result<(u16, u16), String> {
        let (lo, hi) = self
            .pasv_range
            .split_once('-')
            .ok_or_else(|| format!("--pasv-range `{}` must be LO-HI", self.pasv_range))?;
        let lo: u16 = lo
            .trim()
            .parse()
            .map_err(|e| format!("--pasv-range lo `{lo}`: {e}"))?;
        let hi: u16 = hi
            .trim()
            .parse()
            .map_err(|e| format!("--pasv-range hi `{hi}`: {e}"))?;
        if lo == 0 || hi == 0 || lo > hi {
            return Err(format!(
                "--pasv-range {lo}-{hi} invalid (require 0 < lo <= hi)"
            ));
        }
        Ok((lo, hi))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    struct Probe {
        #[command(subcommand)]
        cmd: FtpSub,
    }

    #[test]
    fn parses_serve_with_defaults() {
        let p = Probe::try_parse_from(["spt-ftp", "translator", "serve"]).unwrap();
        match p.cmd {
            FtpSub::Translator(c) => match c.command {
                FtpTranslatorSub::Serve(args) => {
                    assert_eq!(args.pasv_range, "50000-50100");
                    assert_eq!(args.max_clients, 32);
                    let (lo, hi) = args.parse_pasv_range().unwrap();
                    assert_eq!((lo, hi), (50000, 50100));
                }
            },
        }
    }

    #[test]
    fn rejects_inverted_range() {
        let p = Probe::try_parse_from([
            "spt-ftp",
            "translator",
            "serve",
            "--pasv-range",
            "60000-50000",
        ])
        .unwrap();
        let FtpSub::Translator(c) = p.cmd;
        let FtpTranslatorSub::Serve(args) = c.command;
        assert!(args.parse_pasv_range().is_err());
    }

    #[test]
    fn tls_cert_requires_key() {
        let r = Probe::try_parse_from([
            "spt-ftp",
            "translator",
            "serve",
            "--tls-cert",
            "/tmp/c",
        ]);
        assert!(r.is_err());
    }
}
