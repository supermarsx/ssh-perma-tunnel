//! Test facilities for `spt-config`.
//!
//! Behind the `testing` feature flag (and automatically under `cfg(test)`).
//! Provides:
//!
//! * [`ConfigBuilder`], [`ProfileBuilder`], [`ForwardBuilder`] — fluent
//!   constructors for the schema's most-used types.
//! * [`fixtures`] — pre-built canonical [`Config`] values mirroring the
//!   `examples/*.toml` files shipped with the repository.
//! * [`canonical_toml`] — wrapper around [`crate::render::render`] that
//!   forces [`spt_core::RedactionMode::None`] for golden-snapshot tests.
//! * [`assert_validates`] — panics with a formatted diagnostic dump if
//!   validation fails.
//!
//! All fixtures validate clean (`assert_validates(&fixture)` is part of the
//! crate's own test suite). Builders with no overrides produce a minimal
//! valid `Config` with `version = 1` and one ssh2 profile.

use spt_core::RedactionMode;

use crate::render;
use crate::schema::{
    Auth, Config, Endpoint, Forward, Logging, Mcp, Profile, Reconnect, Runtime, Ssh3, Trust,
};
use crate::validate;

// ---------------------------------------------------------------------------
// Builders
// ---------------------------------------------------------------------------

/// Fluent builder for [`Config`].
///
/// Default produces a config with `version = 1`, no profiles, no tables.
/// Use [`ConfigBuilder::add_profile`] to attach profiles.
///
/// # Examples
///
/// ```
/// use spt_config::testing::ConfigBuilder;
/// let c = ConfigBuilder::default().build();
/// assert_eq!(c.version, 1);
/// ```
#[derive(Debug, Clone)]
pub struct ConfigBuilder {
    inner: Config,
}

impl Default for ConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl ConfigBuilder {
    /// New builder with `version = 1` and otherwise empty config.
    ///
    /// # Examples
    ///
    /// ```
    /// use spt_config::testing::ConfigBuilder;
    /// let c = ConfigBuilder::new().build();
    /// assert!(c.profiles.is_empty());
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Config {
                version: 1,
                ..Config::default()
            },
        }
    }

    /// Attach a `[runtime]` table.
    ///
    /// # Examples
    ///
    /// ```
    /// use spt_config::testing::ConfigBuilder;
    /// use spt_config::schema::Runtime;
    /// let c = ConfigBuilder::new().runtime(Runtime::default()).build();
    /// assert!(c.runtime.is_some());
    /// ```
    #[must_use]
    pub fn runtime(mut self, r: Runtime) -> Self {
        self.inner.runtime = Some(r);
        self
    }

    /// Attach a `[logging]` table.
    ///
    /// # Examples
    ///
    /// ```
    /// use spt_config::testing::ConfigBuilder;
    /// use spt_config::schema::Logging;
    /// let mut l = Logging::default();
    /// l.level = Some("info".into());
    /// let c = ConfigBuilder::new().with_logging(l).build();
    /// assert!(c.logging.is_some());
    /// ```
    #[must_use]
    pub fn with_logging(mut self, l: Logging) -> Self {
        self.inner.logging = Some(l);
        self
    }

    /// Attach an `[mcp]` table.
    ///
    /// # Examples
    ///
    /// ```
    /// use spt_config::testing::ConfigBuilder;
    /// use spt_config::schema::Mcp;
    /// let mut m = Mcp::default();
    /// m.enabled = Some(true);
    /// let c = ConfigBuilder::new().mcp(m).build();
    /// assert!(c.mcp.is_some());
    /// ```
    #[must_use]
    pub fn mcp(mut self, m: Mcp) -> Self {
        self.inner.mcp = Some(m);
        self
    }

    /// Append a `[[profiles]]` entry.
    ///
    /// # Examples
    ///
    /// ```
    /// use spt_config::testing::{ConfigBuilder, ProfileBuilder};
    /// let c = ConfigBuilder::new()
    ///     .add_profile(ProfileBuilder::new("p1").build())
    ///     .build();
    /// assert_eq!(c.profiles.len(), 1);
    /// ```
    #[must_use]
    pub fn add_profile(mut self, p: Profile) -> Self {
        self.inner.profiles.push(p);
        self
    }

    /// Replace the schema version (default `1`).
    ///
    /// # Examples
    ///
    /// ```
    /// use spt_config::testing::ConfigBuilder;
    /// let c = ConfigBuilder::new().version(1).build();
    /// assert_eq!(c.version, 1);
    /// ```
    #[must_use]
    pub fn version(mut self, v: u32) -> Self {
        self.inner.version = v;
        self
    }

    /// Finalise the [`Config`].
    ///
    /// # Examples
    ///
    /// ```
    /// use spt_config::testing::ConfigBuilder;
    /// let c = ConfigBuilder::default().build();
    /// assert_eq!(c.version, 1);
    /// ```
    #[must_use]
    pub fn build(self) -> Config {
        self.inner
    }
}

/// Fluent builder for [`Profile`].
///
/// Defaults: `protocol = "ssh2"`, `enabled = true`, no auth (set via
/// [`ProfileBuilder::auth_pubkey`] / [`ProfileBuilder::auth_agent`]).
///
/// # Examples
///
/// ```
/// use spt_config::testing::ProfileBuilder;
/// let p = ProfileBuilder::new("p1").endpoint("example.com", 22).build();
/// assert_eq!(p.name, "p1");
/// assert_eq!(p.host.as_deref(), Some("example.com"));
/// ```
#[derive(Debug, Clone)]
pub struct ProfileBuilder {
    inner: Profile,
}

impl ProfileBuilder {
    /// New profile builder with the given name.
    ///
    /// # Examples
    ///
    /// ```
    /// use spt_config::testing::ProfileBuilder;
    /// let p = ProfileBuilder::new("alpha").build();
    /// assert_eq!(p.name, "alpha");
    /// ```
    #[must_use]
    pub fn new(name: &str) -> Self {
        Self {
            inner: Profile {
                name: name.to_owned(),
                protocol: "ssh2".to_owned(),
                enabled: Some(true),
                trust: Some(Trust {
                    mode: Some("known_hosts".into()),
                    strict: Some(true),
                    ..Trust::default()
                }),
                ..Profile::default()
            },
        }
    }

    /// Replace the profile id.
    ///
    /// # Examples
    ///
    /// ```
    /// use spt_config::testing::ProfileBuilder;
    /// let p = ProfileBuilder::new("a").id("b").build();
    /// assert_eq!(p.name, "b");
    /// ```
    #[must_use]
    pub fn id(mut self, name: &str) -> Self {
        name.clone_into(&mut self.inner.name);
        self
    }

    /// Set protocol (default `ssh2`).
    ///
    /// # Examples
    ///
    /// ```
    /// use spt_config::testing::ProfileBuilder;
    /// let p = ProfileBuilder::new("a").protocol("ssh3").build();
    /// assert_eq!(p.protocol, "ssh3");
    /// ```
    #[must_use]
    pub fn protocol(mut self, p: &str) -> Self {
        p.clone_into(&mut self.inner.protocol);
        self
    }

    /// SSH2 host:port endpoint.
    ///
    /// # Examples
    ///
    /// ```
    /// use spt_config::testing::ProfileBuilder;
    /// let p = ProfileBuilder::new("a").endpoint("h", 22).build();
    /// assert_eq!(p.port, Some(22));
    /// ```
    #[must_use]
    pub fn endpoint(mut self, host: &str, port: u16) -> Self {
        self.inner.host = Some(host.to_owned());
        self.inner.port = Some(port);
        self
    }

    /// SSH3 endpoint URL — also flips `acknowledge_experimental = true`.
    ///
    /// # Examples
    ///
    /// ```
    /// use spt_config::testing::ProfileBuilder;
    /// let p = ProfileBuilder::new("a")
    ///     .protocol("ssh3")
    ///     .ssh3_endpoint("https://h:443/ssh3?user={username}")
    ///     .build();
    /// assert_eq!(p.acknowledge_experimental, Some(true));
    /// ```
    #[must_use]
    pub fn ssh3_endpoint(mut self, url: &str) -> Self {
        self.inner.endpoint = Some(url.to_owned());
        self.inner.acknowledge_experimental = Some(true);
        self.inner.ssh3 = self.inner.ssh3.or(Some(Ssh3 {
            enable_datagrams: Some(true),
            ..Ssh3::default()
        }));
        self
    }

    /// Set remote user.
    ///
    /// # Examples
    ///
    /// ```
    /// use spt_config::testing::ProfileBuilder;
    /// let p = ProfileBuilder::new("a").user("alice").build();
    /// assert_eq!(p.user.as_deref(), Some("alice"));
    /// ```
    #[must_use]
    pub fn user(mut self, u: &str) -> Self {
        self.inner.user = Some(u.to_owned());
        self
    }

    /// Configure `[profiles.auth]` for public-key auth.
    ///
    /// # Examples
    ///
    /// ```
    /// use spt_config::testing::ProfileBuilder;
    /// let p = ProfileBuilder::new("a").auth_pubkey("~/.ssh/id_ed25519").build();
    /// assert_eq!(p.auth.as_ref().unwrap().method, "public_key");
    /// ```
    #[must_use]
    pub fn auth_pubkey(mut self, path: &str) -> Self {
        self.inner.auth = Some(Auth {
            method: "public_key".into(),
            identity_file: Some(path.to_owned()),
            ..Auth::default()
        });
        self
    }

    /// Configure `[profiles.auth]` for agent auth.
    ///
    /// # Examples
    ///
    /// ```
    /// use spt_config::testing::ProfileBuilder;
    /// let p = ProfileBuilder::new("a").auth_agent().build();
    /// assert_eq!(p.auth.as_ref().unwrap().method, "agent");
    /// ```
    #[must_use]
    pub fn auth_agent(mut self) -> Self {
        self.inner.auth = Some(Auth {
            method: "agent".into(),
            agent: Some(true),
            ..Auth::default()
        });
        self
    }

    /// Configure `[profiles.auth]` for SSH3 bearer token.
    ///
    /// # Examples
    ///
    /// ```
    /// use spt_config::testing::ProfileBuilder;
    /// let p = ProfileBuilder::new("a")
    ///     .auth_bearer_token("secret://ns/n")
    ///     .build();
    /// assert_eq!(p.auth.as_ref().unwrap().method, "bearer_token");
    /// ```
    #[must_use]
    pub fn auth_bearer_token(mut self, token_ref: &str) -> Self {
        self.inner.auth = Some(Auth {
            method: "bearer_token".into(),
            token: Some(token_ref.to_owned()),
            ..Auth::default()
        });
        self
    }

    /// Append a `[[profiles.forwards]]` entry.
    ///
    /// # Examples
    ///
    /// ```
    /// use spt_config::testing::{ForwardBuilder, ProfileBuilder};
    /// let f = ForwardBuilder::local_tcp("web", "127.0.0.1:8080", "h:80").build();
    /// let p = ProfileBuilder::new("a").add_forward(f).build();
    /// assert_eq!(p.forwards.len(), 1);
    /// ```
    #[must_use]
    pub fn add_forward(mut self, f: Forward) -> Self {
        self.inner.forwards.push(f);
        self
    }

    /// Append a `[[profiles.endpoints]]` entry (failover).
    ///
    /// # Examples
    ///
    /// ```
    /// use spt_config::testing::ProfileBuilder;
    /// use spt_config::schema::Endpoint;
    /// let p = ProfileBuilder::new("a").add_endpoint(Endpoint {
    ///     name: "primary".into(), host: "h".into(), port: 22, priority: Some(1), weight: None,
    /// }).build();
    /// assert_eq!(p.endpoints.len(), 1);
    /// ```
    #[must_use]
    pub fn add_endpoint(mut self, e: Endpoint) -> Self {
        self.inner.endpoints.push(e);
        self
    }

    /// Set a `[profiles.reconnect]` table.
    ///
    /// # Examples
    ///
    /// ```
    /// use spt_config::testing::ProfileBuilder;
    /// use spt_config::schema::Reconnect;
    /// let mut r = Reconnect::default();
    /// r.initial_delay = Some("1s".into());
    /// let p = ProfileBuilder::new("a").reconnect(r).build();
    /// assert!(p.reconnect.is_some());
    /// ```
    #[must_use]
    pub fn reconnect(mut self, r: Reconnect) -> Self {
        self.inner.reconnect = Some(r);
        self
    }

    /// Finalise.
    ///
    /// # Examples
    ///
    /// ```
    /// use spt_config::testing::ProfileBuilder;
    /// let _ = ProfileBuilder::new("a").build();
    /// ```
    #[must_use]
    pub fn build(self) -> Profile {
        self.inner
    }
}

/// Fluent builder for [`Forward`].
///
/// Use the named constructors [`ForwardBuilder::local_tcp`],
/// [`ForwardBuilder::remote_tcp`], or [`ForwardBuilder::local_udp`] for
/// sensible defaults; tweak with the `with_*` setters.
///
/// # Examples
///
/// ```
/// use spt_config::testing::ForwardBuilder;
/// let f = ForwardBuilder::local_tcp("web", "127.0.0.1:8080", "h:80").build();
/// assert_eq!(f.kind, "local");
/// assert_eq!(f.transport, "tcp");
/// ```
#[derive(Debug, Clone)]
pub struct ForwardBuilder {
    inner: Forward,
}

impl ForwardBuilder {
    /// Local TCP forward.
    ///
    /// # Examples
    ///
    /// ```
    /// use spt_config::testing::ForwardBuilder;
    /// let f = ForwardBuilder::local_tcp("svc", "127.0.0.1:1234", "h:80").build();
    /// assert_eq!(f.bind.as_deref(), Some("127.0.0.1:1234"));
    /// ```
    #[must_use]
    pub fn local_tcp(name: &str, bind: &str, target: &str) -> Self {
        Self {
            inner: Forward {
                name: name.to_owned(),
                kind: "local".into(),
                transport: "tcp".into(),
                bind: Some(bind.to_owned()),
                target: Some(target.to_owned()),
                target_resolve: Some("remote".into()),
                required: Some(true),
                ..Forward::default()
            },
        }
    }

    /// Remote (reverse) TCP forward.
    ///
    /// # Examples
    ///
    /// ```
    /// use spt_config::testing::ForwardBuilder;
    /// let f = ForwardBuilder::remote_tcp("rev", "127.0.0.1:8081", "127.0.0.1:80").build();
    /// assert_eq!(f.kind, "remote");
    /// ```
    #[must_use]
    pub fn remote_tcp(name: &str, bind: &str, target: &str) -> Self {
        Self {
            inner: Forward {
                name: name.to_owned(),
                kind: "remote".into(),
                transport: "tcp".into(),
                bind: Some(bind.to_owned()),
                target: Some(target.to_owned()),
                target_resolve: Some("local".into()),
                required: Some(true),
                ..Forward::default()
            },
        }
    }

    /// Local UDP forward (requires SSH3 protocol on the parent profile).
    ///
    /// # Examples
    ///
    /// ```
    /// use spt_config::testing::ForwardBuilder;
    /// let f = ForwardBuilder::local_udp("dns", "127.0.0.1:1053", "dns:53").build();
    /// assert_eq!(f.transport, "udp");
    /// ```
    #[must_use]
    pub fn local_udp(name: &str, bind: &str, target: &str) -> Self {
        Self {
            inner: Forward {
                name: name.to_owned(),
                kind: "local".into(),
                transport: "udp".into(),
                bind: Some(bind.to_owned()),
                target: Some(target.to_owned()),
                target_resolve: Some("remote".into()),
                required: Some(true),
                udp_idle_timeout: Some("30s".into()),
                ..Forward::default()
            },
        }
    }

    /// Mark this forward as `required`.
    ///
    /// # Examples
    ///
    /// ```
    /// use spt_config::testing::ForwardBuilder;
    /// let f = ForwardBuilder::local_tcp("a", "127.0.0.1:1", "h:1").required(false).build();
    /// assert_eq!(f.required, Some(false));
    /// ```
    #[must_use]
    pub fn required(mut self, r: bool) -> Self {
        self.inner.required = Some(r);
        self
    }

    /// Set `dns_names`.
    ///
    /// # Examples
    ///
    /// ```
    /// use spt_config::testing::ForwardBuilder;
    /// let f = ForwardBuilder::local_tcp("a", "127.0.0.1:1", "h:1")
    ///     .dns_names(&["a.spt.local"]).build();
    /// assert_eq!(f.dns_names.as_deref().unwrap()[0], "a.spt.local");
    /// ```
    #[must_use]
    pub fn dns_names(mut self, names: &[&str]) -> Self {
        self.inner.dns_names = Some(names.iter().map(|s| (*s).to_owned()).collect());
        self
    }

    /// Set `expose = true` (mandatory for non-loopback binds).
    ///
    /// # Examples
    ///
    /// ```
    /// use spt_config::testing::ForwardBuilder;
    /// let f = ForwardBuilder::local_tcp("a", "0.0.0.0:1", "h:1").expose().build();
    /// assert_eq!(f.expose, Some(true));
    /// ```
    #[must_use]
    pub fn expose(mut self) -> Self {
        self.inner.expose = Some(true);
        self
    }

    /// Finalise.
    ///
    /// # Examples
    ///
    /// ```
    /// use spt_config::testing::ForwardBuilder;
    /// let _ = ForwardBuilder::local_tcp("a", "127.0.0.1:1", "h:1").build();
    /// ```
    #[must_use]
    pub fn build(self) -> Forward {
        self.inner
    }
}

// ---------------------------------------------------------------------------
// Fixtures (mirror examples/*.toml)
// ---------------------------------------------------------------------------

/// Pre-built canonical [`Config`] values, one per `examples/*.toml` file.
///
/// Each fixture parses through [`crate::load::load_str`] from the bundled
/// example file at compile time, so the fixtures stay in sync with the
/// canonical `examples/` corpus.
pub mod fixtures {
    use super::Config;

    fn parse_example(raw: &str, label: &str) -> Config {
        crate::load::load_str(raw, false)
            .unwrap_or_else(|e| panic!("fixture `{label}` failed to parse: {e}"))
            .0
    }

    /// `examples/minimal.toml`.
    ///
    /// # Examples
    ///
    /// ```
    /// use spt_config::testing::fixtures::minimal;
    /// let c = minimal();
    /// assert_eq!(c.profiles.len(), 1);
    /// ```
    #[must_use]
    pub fn minimal() -> Config {
        parse_example(include_str!("../../../examples/minimal.toml"), "minimal")
    }

    /// `examples/smtp-relay.toml`.
    ///
    /// # Examples
    ///
    /// ```
    /// use spt_config::testing::fixtures::smtp_relay;
    /// assert!(smtp_relay().runtime.is_some());
    /// ```
    #[must_use]
    pub fn smtp_relay() -> Config {
        parse_example(
            include_str!("../../../examples/smtp-relay.toml"),
            "smtp-relay",
        )
    }

    /// `examples/jump-host.toml` (multi-hop chain).
    ///
    /// # Examples
    ///
    /// ```
    /// use spt_config::testing::fixtures::jump_host;
    /// assert!(!jump_host().profiles[0].hops.is_empty());
    /// ```
    #[must_use]
    pub fn jump_host() -> Config {
        parse_example(
            include_str!("../../../examples/jump-host.toml"),
            "jump-host",
        )
    }

    /// `examples/reverse.toml` (remote forward).
    ///
    /// # Examples
    ///
    /// ```
    /// use spt_config::testing::fixtures::reverse;
    /// assert_eq!(reverse().profiles[0].forwards[0].kind, "remote");
    /// ```
    #[must_use]
    pub fn reverse() -> Config {
        parse_example(include_str!("../../../examples/reverse.toml"), "reverse")
    }

    /// `examples/ssh3.toml` (SSH3 + UDP forward).
    ///
    /// # Examples
    ///
    /// ```
    /// use spt_config::testing::fixtures::ssh3;
    /// assert_eq!(ssh3().profiles[0].acknowledge_experimental, Some(true));
    /// ```
    #[must_use]
    pub fn ssh3() -> Config {
        parse_example(include_str!("../../../examples/ssh3.toml"), "ssh3")
    }

    /// `examples/dns-split-horizon.toml`.
    ///
    /// # Examples
    ///
    /// ```
    /// use spt_config::testing::fixtures::dns_split_horizon;
    /// assert!(dns_split_horizon().dns.is_some());
    /// ```
    #[must_use]
    pub fn dns_split_horizon() -> Config {
        parse_example(
            include_str!("../../../examples/dns-split-horizon.toml"),
            "dns-split-horizon",
        )
    }

    /// `examples/mcp.toml`.
    ///
    /// # Examples
    ///
    /// ```
    /// use spt_config::testing::fixtures::mcp;
    /// assert!(mcp().mcp.is_some());
    /// ```
    #[must_use]
    pub fn mcp() -> Config {
        parse_example(include_str!("../../../examples/mcp.toml"), "mcp")
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Render a [`Config`] as canonical TOML with no redaction. Useful for
/// `insta::assert_snapshot!`-style golden tests.
///
/// # Examples
///
/// ```
/// use spt_config::testing::{canonical_toml, ConfigBuilder};
/// let c = ConfigBuilder::new().build();
/// let toml = canonical_toml(&c);
/// assert!(toml.contains("version = 1"));
/// ```
#[must_use]
pub fn canonical_toml(c: &Config) -> String {
    render::render(c, RedactionMode::None)
}

/// Run [`crate::validate::validate`] on `c` and panic with a formatted
/// diagnostic dump if there are any errors. Warnings are tolerated.
///
/// # Examples
///
/// ```
/// use spt_config::testing::{assert_validates, fixtures};
/// assert_validates(&fixtures::minimal());
/// ```
///
/// # Panics
///
/// Panics if validation produces any error-severity diagnostic.
pub fn assert_validates(c: &Config) {
    let d = validate::validate(c);
    if !d.errors.is_empty() {
        let mut msg = String::from("config failed validation:\n");
        for e in &d.errors {
            msg.push_str(&format!("  - {e}\n"));
        }
        panic!("{msg}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_builder_default_validates() {
        // Empty config (version=1, no profiles) is valid: validation only flags
        // duplicates and shape errors, not "missing profiles".
        let c = ConfigBuilder::default().build();
        assert_validates(&c);
    }

    #[test]
    fn profile_builder_smoke() {
        let p = ProfileBuilder::new("p1")
            .endpoint("h", 22)
            .user("alice")
            .auth_agent()
            .add_forward(
                ForwardBuilder::local_tcp("svc", "127.0.0.1:1234", "h:80").build(),
            )
            .build();
        let c = ConfigBuilder::new().add_profile(p).build();
        assert_validates(&c);
    }

    #[test]
    fn ssh3_profile_validates() {
        let p = ProfileBuilder::new("ssh3-x")
            .protocol("ssh3")
            .ssh3_endpoint("https://h:443/ssh3?user={username}")
            .auth_bearer_token("secret://ns/tok")
            .add_forward(
                ForwardBuilder::local_udp("dns", "127.0.0.1:1053", "dns:53").build(),
            )
            .build();
        let c = ConfigBuilder::new().add_profile(p).build();
        assert_validates(&c);
    }

    #[test]
    fn all_fixtures_validate_clean() {
        assert_validates(&fixtures::minimal());
        assert_validates(&fixtures::smtp_relay());
        assert_validates(&fixtures::jump_host());
        assert_validates(&fixtures::reverse());
        assert_validates(&fixtures::ssh3());
        assert_validates(&fixtures::dns_split_horizon());
        assert_validates(&fixtures::mcp());
    }

    #[test]
    fn canonical_toml_is_round_trippable() {
        let c = fixtures::minimal();
        let toml = canonical_toml(&c);
        let (parsed, _) = crate::load::load_str(&toml, false).expect("re-parse");
        assert_eq!(parsed.version, c.version);
        assert_eq!(parsed.profiles.len(), c.profiles.len());
    }

    #[test]
    #[should_panic(expected = "config failed validation")]
    fn assert_validates_panics_on_error() {
        let mut c = Config {
            version: 999,
            ..Config::default()
        };
        c.version = 999;
        assert_validates(&c);
    }
}
