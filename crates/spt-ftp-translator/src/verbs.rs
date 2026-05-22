//! RFC 959 / RFC 3659 verb dispatch.
//!
//! Verbs are parsed via [`parse_command`]; the higher-level
//! `crate::session` module (inside `server.rs`) drives the actual SFTP
//! calls. PORT and EPRT are explicitly recognised here so the rejection
//! message stays stable across releases.
//!
//! The full set of verbs we accept matches the t6.md scope:
//!
//! * Login / session: USER, PASS, ACCT, CWD, CDUP, QUIT, REIN
//! * Directory: PWD, LIST, NLST, MLSD, MLST
//! * File metadata: MDTM, SIZE
//! * Transfer-parameter: TYPE (A/I), MODE (S), STRU (F)
//! * File transfer: RETR, STOR, STOU, APPE, DELE, RNFR, RNTO, MKD, RMD
//! * Data channel: PASV, EPSV (PORT/EPRT → 502)
//! * Extensions: FEAT, OPTS UTF8 ON, AUTH TLS, PBSZ, PROT
//!
//! Anything outside this set returns 500 / 502 depending on whether the
//! verb is "known but unimplemented" (502) or "unrecognised" (500).

use std::str::FromStr;

/// Parsed FTP verb. Stored as an enum so the dispatcher is a `match` with
/// exhaustive coverage and clippy-clean arms.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verb {
    User(String),
    Pass(String),
    Acct(String),
    Cwd(String),
    Cdup,
    Quit,
    Rein,
    Pwd,
    List(Option<String>),
    Nlst(Option<String>),
    Mlsd(Option<String>),
    Mlst(Option<String>),
    Mdtm(String),
    Size(String),
    Type(String),
    Mode(String),
    Stru(String),
    Retr(String),
    Stor(String),
    Stou(Option<String>),
    Appe(String),
    Dele(String),
    Rnfr(String),
    Rnto(String),
    Mkd(String),
    Rmd(String),
    Pasv,
    Epsv(Option<String>),
    /// PORT — always rejected with 502.
    Port(String),
    /// EPRT — always rejected with 502.
    Eprt(String),
    Feat,
    Opts(String),
    Auth(String),
    Pbsz(String),
    Prot(String),
    Noop,
    /// `verb [args]` for anything we don't recognise.
    Unknown {
        /// Uppercased verb token.
        verb: String,
    },
}

impl Verb {
    /// Stable 4-letter (or 3-letter) tag, used for logging.
    #[must_use]
    pub fn tag(&self) -> &'static str {
        match self {
            Self::User(_) => "USER",
            Self::Pass(_) => "PASS",
            Self::Acct(_) => "ACCT",
            Self::Cwd(_) => "CWD",
            Self::Cdup => "CDUP",
            Self::Quit => "QUIT",
            Self::Rein => "REIN",
            Self::Pwd => "PWD",
            Self::List(_) => "LIST",
            Self::Nlst(_) => "NLST",
            Self::Mlsd(_) => "MLSD",
            Self::Mlst(_) => "MLST",
            Self::Mdtm(_) => "MDTM",
            Self::Size(_) => "SIZE",
            Self::Type(_) => "TYPE",
            Self::Mode(_) => "MODE",
            Self::Stru(_) => "STRU",
            Self::Retr(_) => "RETR",
            Self::Stor(_) => "STOR",
            Self::Stou(_) => "STOU",
            Self::Appe(_) => "APPE",
            Self::Dele(_) => "DELE",
            Self::Rnfr(_) => "RNFR",
            Self::Rnto(_) => "RNTO",
            Self::Mkd(_) => "MKD",
            Self::Rmd(_) => "RMD",
            Self::Pasv => "PASV",
            Self::Epsv(_) => "EPSV",
            Self::Port(_) => "PORT",
            Self::Eprt(_) => "EPRT",
            Self::Feat => "FEAT",
            Self::Opts(_) => "OPTS",
            Self::Auth(_) => "AUTH",
            Self::Pbsz(_) => "PBSZ",
            Self::Prot(_) => "PROT",
            Self::Noop => "NOOP",
            Self::Unknown { .. } => "UNK",
        }
    }
}

/// Parse one CRLF-terminated command line into a [`Verb`]. The trailing
/// CRLF must already have been stripped by the caller.
///
/// Lines longer than 8 KiB should be rejected at the read layer (the
/// session enforces this). Empty lines parse as [`Verb::Noop`] for
/// resilience against telnet clients that send bare CRLF.
pub fn parse_command(line: &str) -> Verb {
    let trimmed = line.trim_matches(['\r', '\n']);
    let mut parts = trimmed.splitn(2, ' ');
    let verb = parts.next().unwrap_or("").to_ascii_uppercase();
    let args = parts.next().unwrap_or("").trim_start().to_string();
    if verb.is_empty() {
        return Verb::Noop;
    }
    match verb.as_str() {
        "USER" => Verb::User(args),
        "PASS" => Verb::Pass(args),
        "ACCT" => Verb::Acct(args),
        "CWD" => Verb::Cwd(args),
        "XCWD" => Verb::Cwd(args), // RFC 775 alias
        "CDUP" | "XCUP" => Verb::Cdup,
        "QUIT" => Verb::Quit,
        "REIN" => Verb::Rein,
        "PWD" | "XPWD" => Verb::Pwd,
        "LIST" => Verb::List(opt(&args)),
        "NLST" => Verb::Nlst(opt(&args)),
        "MLSD" => Verb::Mlsd(opt(&args)),
        "MLST" => Verb::Mlst(opt(&args)),
        "MDTM" => Verb::Mdtm(args),
        "SIZE" => Verb::Size(args),
        "TYPE" => Verb::Type(args.to_ascii_uppercase()),
        "MODE" => Verb::Mode(args.to_ascii_uppercase()),
        "STRU" => Verb::Stru(args.to_ascii_uppercase()),
        "RETR" => Verb::Retr(args),
        "STOR" => Verb::Stor(args),
        "STOU" => Verb::Stou(opt(&args)),
        "APPE" => Verb::Appe(args),
        "DELE" => Verb::Dele(args),
        "RNFR" => Verb::Rnfr(args),
        "RNTO" => Verb::Rnto(args),
        "MKD" | "XMKD" => Verb::Mkd(args),
        "RMD" | "XRMD" => Verb::Rmd(args),
        "PASV" => Verb::Pasv,
        "EPSV" => Verb::Epsv(opt(&args)),
        "PORT" => Verb::Port(args),
        "EPRT" => Verb::Eprt(args),
        "FEAT" => Verb::Feat,
        "OPTS" => Verb::Opts(args),
        "AUTH" => Verb::Auth(args.to_ascii_uppercase()),
        "PBSZ" => Verb::Pbsz(args),
        "PROT" => Verb::Prot(args.to_ascii_uppercase()),
        "NOOP" => Verb::Noop,
        _ => Verb::Unknown { verb },
    }
}

fn opt(s: &str) -> Option<String> {
    if s.is_empty() {
        None
    } else {
        Some(s.to_string())
    }
}

/// Helper: parse an EPRT argument per RFC 2428 §2. We only need it to
/// reject the verb with a stable diagnostic, but exposing the parser
/// keeps the rejection message structured.
pub fn parse_eprt(args: &str) -> Option<EprtSpec> {
    // Format: `|af|addr|port|` (delimiter is the first character)
    let mut chars = args.chars();
    let delim = chars.next()?;
    let rest: String = chars.collect();
    let mut parts = rest.split(delim);
    let af = parts.next()?.to_string();
    let addr = parts.next()?.to_string();
    let port = parts.next()?.parse::<u16>().ok()?;
    Some(EprtSpec { af, addr, port })
}

/// Parsed EPRT arg.
#[derive(Debug, PartialEq, Eq)]
pub struct EprtSpec {
    /// Address family — `"1"` for IPv4, `"2"` for IPv6.
    pub af: String,
    /// Numeric address.
    pub addr: String,
    /// Port.
    pub port: u16,
}

impl FromStr for EprtSpec {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        parse_eprt(s).ok_or(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_simple_user() {
        assert_eq!(parse_command("USER alice"), Verb::User("alice".into()));
    }

    #[test]
    fn parse_case_insensitive() {
        assert_eq!(parse_command("user alice"), Verb::User("alice".into()));
        assert_eq!(parse_command("Pass s3"), Verb::Pass("s3".into()));
    }

    #[test]
    fn parse_no_args() {
        assert_eq!(parse_command("PASV"), Verb::Pasv);
        assert_eq!(parse_command("PWD"), Verb::Pwd);
        assert_eq!(parse_command("FEAT"), Verb::Feat);
    }

    #[test]
    fn parse_type_uppercases() {
        assert_eq!(parse_command("TYPE i"), Verb::Type("I".into()));
        assert_eq!(parse_command("TYPE A"), Verb::Type("A".into()));
    }

    #[test]
    fn parse_unknown() {
        match parse_command("XYZZY garbage") {
            Verb::Unknown { verb } => assert_eq!(verb, "XYZZY"),
            _ => panic!("expected Unknown"),
        }
    }

    #[test]
    fn parse_eprt_ipv6() {
        let s = parse_eprt("|2|::1|50001|").unwrap();
        assert_eq!(s.af, "2");
        assert_eq!(s.addr, "::1");
        assert_eq!(s.port, 50001);
    }

    #[test]
    fn parse_port_yields_port_verb() {
        match parse_command("PORT 127,0,0,1,195,80") {
            Verb::Port(s) => assert!(s.contains("127,0,0,1")),
            _ => panic!("expected Port"),
        }
    }

    #[test]
    fn parse_empty_is_noop() {
        assert_eq!(parse_command(""), Verb::Noop);
        assert_eq!(parse_command("   "), Verb::Noop);
    }
}
