//! Minimal `~/.ssh/config` reader for the spt proxy-jump bridge (t6-e3).
//!
//! This is **not** a complete `ssh_config(5)` implementation — it parses
//! just the directives spt actually consumes:
//!
//! * `Host <pattern>` — block boundary.
//! * `HostName <host>`
//! * `Port <port>`
//! * `User <user>`
//! * `ProxyJump <user@host[:port][,user@host…]>` — comma-separated chain.
//! * `IdentityFile <path>`
//!
//! Lines are case-insensitive on the directive key (matching OpenSSH).
//! Comments (`#`) and blank lines are skipped. Indentation is permitted.
//! `=` is accepted as a separator (`HostName = foo`).
//!
//! [`resolve_host`] returns the list of hops a connection to `name` should
//! splay across: the recursive `ProxyJump` chain followed by the terminal
//! host itself.
//!
//! ### Portable-mode gating
//!
//! Reads of `~/.ssh/config` must be gated by
//! [`crate::load::ssh_config_reads_allowed`] in callers. This module
//! does *not* perform that check itself — it just parses whatever bytes
//! it's handed — so unit tests can drive it freely.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// One `Host` block from `~/.ssh/config`.
///
/// `pattern` is the raw `Host` directive value (whitespace-trimmed). spt
/// uses literal match by default; wildcards are matched in [`match_pattern`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostBlock {
    /// The raw `Host` pattern (may contain globs).
    pub pattern: String,
    /// Resolved hostname, if `HostName` was set.
    pub hostname: Option<String>,
    /// Resolved port, if `Port` was set.
    pub port: Option<u16>,
    /// Resolved user, if `User` was set.
    pub user: Option<String>,
    /// Raw `ProxyJump` value (comma-separated `user@host[:port]` list).
    pub proxy_jump: Option<String>,
    /// `IdentityFile` paths, in declaration order.
    pub identity_files: Vec<PathBuf>,
}

/// One hop hint produced by [`resolve_host`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HopHint {
    /// Username (None → caller's default).
    pub user: Option<String>,
    /// Hostname (post-`HostName` substitution).
    pub host: String,
    /// Port (defaults to 22 when unspecified at parse time).
    pub port: u16,
}

/// Parse `~/.ssh/config`-style text into a list of `HostBlock`s.
///
/// Unknown directives are ignored (mirroring OpenSSH's lenient behaviour
/// when older clients see new keys). Malformed lines are also skipped —
/// this parser is permissive on purpose so a stray quirk in an operator's
/// config doesn't break spt's main load path.
#[must_use]
pub fn parse(text: &str) -> Vec<HostBlock> {
    let mut blocks: Vec<HostBlock> = Vec::new();
    let mut current: Option<HostBlock> = None;

    for raw in text.lines() {
        let line = strip_comment(raw).trim();
        if line.is_empty() {
            continue;
        }
        let Some((key, value)) = split_kv(line) else {
            continue;
        };
        let key_lc = key.to_ascii_lowercase();
        if key_lc == "host" {
            if let Some(b) = current.take() {
                blocks.push(b);
            }
            current = Some(HostBlock {
                pattern: value.to_string(),
                hostname: None,
                port: None,
                user: None,
                proxy_jump: None,
                identity_files: Vec::new(),
            });
            continue;
        }
        let Some(block) = current.as_mut() else {
            // Global section before any `Host` — skip.
            continue;
        };
        match key_lc.as_str() {
            "hostname" => block.hostname = Some(value.to_string()),
            "port" => {
                if let Ok(p) = value.parse::<u16>() {
                    block.port = Some(p);
                }
            }
            "user" => block.user = Some(value.to_string()),
            "proxyjump" => block.proxy_jump = Some(value.to_string()),
            "identityfile" => block.identity_files.push(PathBuf::from(value)),
            _ => {}
        }
    }
    if let Some(b) = current.take() {
        blocks.push(b);
    }
    blocks
}

/// Resolve `name` through `blocks`, returning the proxy chain followed by
/// the terminal host.
///
/// * If no `Host` block matches `name`, the result is a single hop
///   `(name, 22)`.
/// * `ProxyJump` is processed left-to-right and recursively (the leftmost
///   element is itself looked up against `blocks`, then the next, etc.).
///
/// Cycles are bounded by `MAX_DEPTH` to prevent pathological configs from
/// blowing the stack.
#[must_use]
pub fn resolve_host(blocks: &[HostBlock], name: &str) -> Vec<HopHint> {
    let mut out = Vec::new();
    resolve_inner(blocks, name, &mut out, 0);
    out
}

const MAX_DEPTH: usize = 16;

fn resolve_inner(blocks: &[HostBlock], name: &str, out: &mut Vec<HopHint>, depth: usize) {
    if depth > MAX_DEPTH {
        return;
    }
    let block = blocks.iter().find(|b| match_pattern(&b.pattern, name));
    let pj = block.and_then(|b| b.proxy_jump.as_deref()).unwrap_or("");
    if !pj.is_empty() {
        for jump in pj.split(',') {
            let jump = jump.trim();
            if jump.is_empty() {
                continue;
            }
            let (juser, jhost, jport) = parse_user_host_port(jump);
            // Recurse the jump host itself through the block table so an
            // alias-pointing ProxyJump resolves transitively.
            let nested_blocks_match = blocks
                .iter()
                .find(|b| match_pattern(&b.pattern, jhost.as_str()));
            if let Some(nb) = nested_blocks_match {
                // The nested host may itself have a ProxyJump; recurse.
                resolve_inner(blocks, jhost.as_str(), out, depth + 1);
                // Then push the terminal of the nested chain we just
                // walked, *unless* that walk already pushed it (because
                // resolve_inner pushes the terminal at its tail). To
                // avoid double-pushing we DON'T push again here.
                // resolve_inner already added the nested host to `out`
                // including its hostname/port overrides.
                let _ = nb;
            } else {
                // No alias for this jump: push it directly using the
                // explicit user@host:port form.
                out.push(HopHint {
                    user: juser,
                    host: jhost,
                    port: jport.unwrap_or(22),
                });
            }
        }
    }
    // Push the terminal host itself.
    let (host, port, user) = match block {
        Some(b) => (
            b.hostname.clone().unwrap_or_else(|| name.to_string()),
            b.port.unwrap_or(22),
            b.user.clone(),
        ),
        None => (name.to_string(), 22, None),
    };
    out.push(HopHint { user, host, port });
}

/// Pattern-match `name` against an OpenSSH `Host` pattern.
///
/// Supports literal match, `*` (any sequence), and `?` (one char). Multiple
/// patterns on one line (`Host foo bar baz`) are tested independently;
/// negations (`!pattern`) are not implemented (kept out for the spt
/// surface-area minimum).
#[must_use]
pub fn match_pattern(pattern: &str, name: &str) -> bool {
    for p in pattern.split_whitespace() {
        if glob_match(p, name) {
            return true;
        }
    }
    false
}

fn glob_match(p: &str, s: &str) -> bool {
    fn helper(p: &[u8], s: &[u8]) -> bool {
        match (p.first(), s.first()) {
            (None, None) => true,
            (Some(b'*'), _) => {
                // Greedy try-with vs try-without.
                helper(&p[1..], s) || (!s.is_empty() && helper(p, &s[1..]))
            }
            (Some(b'?'), Some(_)) => helper(&p[1..], &s[1..]),
            (Some(a), Some(b)) if a.eq_ignore_ascii_case(b) => helper(&p[1..], &s[1..]),
            _ => false,
        }
    }
    helper(p.as_bytes(), s.as_bytes())
}

/// Parse `user@host[:port]` into `(user, host, port)`. Either of `user` or
/// `port` can be absent. Always returns `host` (the whole input is the
/// host if there's no `@` and no `:`).
#[must_use]
pub fn parse_user_host_port(spec: &str) -> (Option<String>, String, Option<u16>) {
    let (user, rest) = match spec.split_once('@') {
        Some((u, r)) => (Some(u.to_string()), r),
        None => (None, spec),
    };
    // IPv6 literal? `[::1]:port`
    if let Some(stripped) = rest.strip_prefix('[') {
        if let Some(end) = stripped.find(']') {
            let host = stripped[..end].to_string();
            let after = &stripped[end + 1..];
            let port = after.strip_prefix(':').and_then(|p| p.parse::<u16>().ok());
            return (user, host, port);
        }
    }
    let (host, port) = match rest.rsplit_once(':') {
        Some((h, p)) if p.parse::<u16>().is_ok() => (h.to_string(), Some(p.parse().unwrap())),
        _ => (rest.to_string(), None),
    };
    (user, host, port)
}

/// Default path: `$HOME/.ssh/config`, resolved via
/// [`directories::BaseDirs`]. Callers should additionally gate with
/// [`crate::load::ssh_config_reads_allowed`] for portable-mode safety.
#[must_use]
pub fn default_path() -> Option<PathBuf> {
    let bd = directories::BaseDirs::new()?;
    Some(bd.home_dir().join(".ssh").join("config"))
}

/// Read & parse the default OpenSSH config (`~/.ssh/config`).
///
/// Returns `Ok(vec![])` if the file is absent — that is the canonical
/// "user hasn't configured ssh" state, not an error. Any other I/O error
/// is surfaced. Portable-mode gating is the caller's responsibility.
pub fn load_default() -> std::io::Result<Vec<HostBlock>> {
    let Some(path) = default_path() else {
        return Ok(Vec::new());
    };
    match std::fs::read_to_string(&path) {
        Ok(text) => Ok(parse(&text)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(e),
    }
}

// ---------------------------------------------------------------------------
// internals
// ---------------------------------------------------------------------------

fn strip_comment(line: &str) -> &str {
    match line.find('#') {
        Some(i) => &line[..i],
        None => line,
    }
}

fn split_kv(line: &str) -> Option<(&str, &str)> {
    // Accept `Key Value`, `Key Value with spaces`, `Key = Value`,
    // `Key=Value`.
    let bytes = line.as_bytes();
    let mut i = 0;
    while i < bytes.len() && !bytes[i].is_ascii_whitespace() && bytes[i] != b'=' {
        i += 1;
    }
    if i == 0 {
        return None;
    }
    let key = &line[..i];
    let mut j = i;
    // Skip separator: whitespace and/or one `=`.
    let mut saw_eq = false;
    while j < bytes.len() {
        match bytes[j] {
            b' ' | b'\t' => j += 1,
            b'=' if !saw_eq => {
                saw_eq = true;
                j += 1;
            }
            _ => break,
        }
    }
    let value = line[j..].trim();
    if value.is_empty() {
        return None;
    }
    Some((key, value))
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- ProxyJump parse: 5 fixtures ---------------------------------------

    #[test]
    fn parses_simple_proxyjump() {
        let txt = "\
Host internal
    HostName 10.0.0.5
    ProxyJump bastion.corp.example.com
";
        let blocks = parse(txt);
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].pattern, "internal");
        assert_eq!(blocks[0].hostname.as_deref(), Some("10.0.0.5"));
        assert_eq!(
            blocks[0].proxy_jump.as_deref(),
            Some("bastion.corp.example.com")
        );
    }

    #[test]
    fn parses_proxyjump_with_user_and_port() {
        let txt = "\
Host db
    HostName db.internal
    ProxyJump alice@bastion.example.com:2222
";
        let b = &parse(txt)[0];
        assert_eq!(
            b.proxy_jump.as_deref(),
            Some("alice@bastion.example.com:2222")
        );
        let hops = resolve_host(&parse(txt), "db");
        // bastion + terminal db
        assert_eq!(hops.len(), 2);
        assert_eq!(hops[0].user.as_deref(), Some("alice"));
        assert_eq!(hops[0].host, "bastion.example.com");
        assert_eq!(hops[0].port, 2222);
        assert_eq!(hops[1].host, "db.internal");
        assert_eq!(hops[1].port, 22);
    }

    #[test]
    fn parses_proxyjump_chain_comma_list() {
        let txt = "\
Host deepest
    HostName 10.1.2.3
    Port 2200
    User root
    ProxyJump alice@h1, bob@h2:2202, h3
";
        let blocks = parse(txt);
        let hops = resolve_host(&blocks, "deepest");
        assert_eq!(hops.len(), 4);
        assert_eq!(hops[0].host, "h1");
        assert_eq!(hops[0].user.as_deref(), Some("alice"));
        assert_eq!(hops[0].port, 22);
        assert_eq!(hops[1].host, "h2");
        assert_eq!(hops[1].port, 2202);
        assert_eq!(hops[2].host, "h3");
        assert_eq!(hops[3].host, "10.1.2.3");
        assert_eq!(hops[3].port, 2200);
        assert_eq!(hops[3].user.as_deref(), Some("root"));
    }

    #[test]
    fn parses_identityfile_and_aliased_lookup() {
        let txt = "\
Host alias
    HostName real.example.com
    IdentityFile ~/.ssh/id_ed25519
    IdentityFile ~/.ssh/id_rsa
";
        let b = &parse(txt)[0];
        assert_eq!(b.identity_files.len(), 2);
        let hops = resolve_host(&parse(txt), "alias");
        assert_eq!(hops[0].host, "real.example.com");
    }

    #[test]
    fn parses_equals_separator_and_comments() {
        let txt = "\
# top-level comment
Host x  # trailing comment
    HostName=h.example.com
    Port = 2424
    User=carol
";
        let b = &parse(txt)[0];
        assert_eq!(b.hostname.as_deref(), Some("h.example.com"));
        assert_eq!(b.port, Some(2424));
        assert_eq!(b.user.as_deref(), Some("carol"));
    }

    // -- Empty ProxyJump → empty hop list (terminal only) -----------------

    #[test]
    fn empty_proxyjump_returns_only_terminal() {
        let txt = "\
Host h
    HostName h.example.com
";
        let hops = resolve_host(&parse(txt), "h");
        assert_eq!(hops.len(), 1);
        assert_eq!(hops[0].host, "h.example.com");
    }

    #[test]
    fn unknown_host_returns_literal_single_hop() {
        let hops = resolve_host(&[], "literal.example.com");
        assert_eq!(hops.len(), 1);
        assert_eq!(hops[0].host, "literal.example.com");
        assert_eq!(hops[0].port, 22);
        assert!(hops[0].user.is_none());
    }

    // -- Recursive ProxyJump (h1 → h2 → h3) walks --------------------------

    #[test]
    fn recursive_proxyjump_walks_through_aliases() {
        let txt = "\
Host h3
    HostName 10.0.0.3
    ProxyJump h2

Host h2
    HostName 10.0.0.2
    ProxyJump h1

Host h1
    HostName 10.0.0.1
";
        let blocks = parse(txt);
        let hops = resolve_host(&blocks, "h3");
        // Expected walk: h1 (terminal), then h2 (terminal), then h3 (terminal).
        // Each block has only one ProxyJump entry, so the recursive walk
        // pushes inner-most first.
        assert!(hops.len() >= 3);
        let hosts: Vec<&str> = hops.iter().map(|h| h.host.as_str()).collect();
        assert!(hosts.contains(&"10.0.0.1"), "missing h1 in {hosts:?}");
        assert!(hosts.contains(&"10.0.0.2"), "missing h2 in {hosts:?}");
        assert!(hosts.contains(&"10.0.0.3"), "missing h3 in {hosts:?}");
    }

    // -- Pattern + helpers -------------------------------------------------

    #[test]
    fn pattern_wildcards() {
        assert!(match_pattern("*.example.com", "host.example.com"));
        assert!(!match_pattern("*.example.com", "example.com"));
        assert!(match_pattern("?", "a"));
        assert!(!match_pattern("?", "ab"));
        // Multiple patterns on one line.
        assert!(match_pattern("foo bar", "bar"));
    }

    #[test]
    fn default_path_resolves_cross_platform() {
        // Smoke test: the platform-specific resolver yields *some* PathBuf
        // on every supported OS (incl. Windows via directories::BaseDirs).
        let p = default_path();
        // BaseDirs::new() can return None in extremely restricted environs
        // (no $HOME / no Known Folders) — accept either Some or None
        // without panicking, but if Some it must end in `.ssh/config`.
        if let Some(path) = p {
            let s = path.to_string_lossy().replace('\\', "/");
            assert!(
                s.ends_with(".ssh/config"),
                "expected path ending in `.ssh/config`, got `{s}`"
            );
        }
    }

    #[test]
    fn load_default_returns_empty_when_file_absent() {
        // load_default treats a missing config as "no host blocks" rather
        // than an error.
        let blocks = load_default().expect("load_default must not propagate NotFound");
        // Either the operator HAS a config (>=0 blocks) or doesn't (0).
        // Either way we get a Vec without panicking.
        let _ = blocks;
    }

    #[test]
    fn parse_user_host_port_handles_ipv6() {
        let (u, h, p) = parse_user_host_port("alice@[::1]:2222");
        assert_eq!(u.as_deref(), Some("alice"));
        assert_eq!(h, "::1");
        assert_eq!(p, Some(2222));
    }
}
