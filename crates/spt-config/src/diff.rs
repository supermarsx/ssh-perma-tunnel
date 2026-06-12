//! Field-level diff between two [`Config`] values.
//!
//! Used by the reload reconciler in `spt-supervisor` to decide which profiles
//! and forwards need to be restarted versus reconfigured in place.

use serde::{Deserialize, Serialize};

use crate::schema::{Config, Forward, Profile};

/// What kind of change a [`Change`] represents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeKind {
    /// Item added (present in `b`, absent in `a`).
    Added,
    /// Item removed (present in `a`, absent in `b`).
    Removed,
    /// Item modified (present in both, value differs).
    Modified,
}

/// A single change between two configs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Change {
    /// What kind of change.
    pub kind: ChangeKind,
    /// Dotted path of the changed field/section.
    pub path: String,
}

impl Change {
    fn new(kind: ChangeKind, path: impl Into<String>) -> Self {
        Self {
            kind,
            path: path.into(),
        }
    }
}

/// Compute the field-level diff between `a` (old) and `b` (new).
///
/// The diff is "structural": it reports the smallest enclosing path that
/// captures the change. Two equal configs produce an empty `Vec`.
#[must_use]
pub fn diff(a: &Config, b: &Config) -> Vec<Change> {
    let mut changes = Vec::new();

    if a.version != b.version {
        changes.push(Change::new(ChangeKind::Modified, "version"));
    }

    macro_rules! diff_top {
        ($field:ident) => {
            if a.$field != b.$field {
                changes.push(Change::new(ChangeKind::Modified, stringify!($field)));
            }
        };
    }
    diff_top!(runtime);
    diff_top!(logging);
    diff_top!(secrets);
    diff_top!(dns);
    diff_top!(firewall);
    diff_top!(network);
    diff_top!(observability);
    diff_top!(events);
    diff_top!(mcp);
    diff_top!(updater);
    diff_top!(diagnostics);
    diff_top!(benchmark);
    diff_top!(capabilities);
    diff_top!(round_robin);
    diff_top!(status_api);

    diff_profiles(a, b, &mut changes);

    changes
}

/// The set of top-level [`Config`] field names covered by [`diff`]'s
/// `diff_top!` invocations, plus `version` and `profiles` (handled
/// separately). Kept adjacent to the macro so the
/// [`tests::diff_top_covers_every_schema_field`] enumeration test can fail
/// loudly when a new top-level table is added to the schema without a
/// matching `diff_top!` line — see E5-F3.
#[cfg(test)]
const DIFF_TOP_COVERED: &[&str] = &[
    "version",
    "runtime",
    "logging",
    "secrets",
    "dns",
    "firewall",
    "network",
    "observability",
    "events",
    "mcp",
    "updater",
    "diagnostics",
    "benchmark",
    "capabilities",
    "round_robin",
    "status_api",
    "profiles",
];

fn diff_profiles(a: &Config, b: &Config, out: &mut Vec<Change>) {
    let a_names: Vec<&str> = a.profiles.iter().map(|p| p.name.as_str()).collect();
    let b_names: Vec<&str> = b.profiles.iter().map(|p| p.name.as_str()).collect();

    for name in &a_names {
        if !b_names.contains(name) {
            out.push(Change::new(
                ChangeKind::Removed,
                format!("profiles[{name}]"),
            ));
        }
    }
    for name in &b_names {
        if !a_names.contains(name) {
            out.push(Change::new(ChangeKind::Added, format!("profiles[{name}]")));
        }
    }
    for ap in &a.profiles {
        if let Some(bp) = b.profiles.iter().find(|p| p.name == ap.name) {
            diff_profile(ap, bp, out);
        }
    }
}

fn diff_profile(a: &Profile, b: &Profile, out: &mut Vec<Change>) {
    let p = format!("profiles[{}]", a.name);

    macro_rules! field {
        ($f:ident) => {
            if a.$f != b.$f {
                out.push(Change::new(
                    ChangeKind::Modified,
                    format!("{p}.{}", stringify!($f)),
                ));
            }
        };
    }
    field!(description);
    field!(enabled);
    field!(protocol);
    field!(host);
    field!(port);
    field!(endpoint);
    field!(acknowledge_experimental);
    field!(user);
    field!(connect_timeout);
    field!(dns_resolution);
    field!(network_change_reconnect);
    field!(startup);
    field!(failure_policy);
    field!(tags);
    field!(connection);
    field!(crypto);
    field!(auth);
    field!(trust);
    field!(tls);
    field!(ssh3);
    field!(keepalive);
    field!(reconnect);
    field!(instability);
    field!(failover);
    field!(limits);
    field!(endpoints);
    field!(hops);
    field!(sftp_mounts);
    field!(script);
    field!(transport);

    diff_forwards(&p, &a.forwards, &b.forwards, out);
}

/// Profile field names covered by [`diff_profile`] (and `forwards`, handled
/// by [`diff_forwards`]). `name` is the identity key and is not a diffable
/// value. Kept adjacent to the function so
/// [`tests::diff_profile_covers_every_schema_field`] fails loudly when a new
/// profile field is added without diff coverage — see E5-F3.
#[cfg(test)]
const DIFF_PROFILE_COVERED: &[&str] = &[
    "name",
    "description",
    "enabled",
    "protocol",
    "host",
    "port",
    "endpoint",
    "acknowledge_experimental",
    "user",
    "connect_timeout",
    "dns_resolution",
    "network_change_reconnect",
    "startup",
    "failure_policy",
    "tags",
    "connection",
    "crypto",
    "auth",
    "trust",
    "tls",
    "ssh3",
    "keepalive",
    "reconnect",
    "instability",
    "failover",
    "limits",
    "endpoints",
    "hops",
    "forwards",
    "sftp_mounts",
    "script",
    "transport",
];

fn diff_forwards(prefix: &str, a: &[Forward], b: &[Forward], out: &mut Vec<Change>) {
    let a_names: Vec<&str> = a.iter().map(|f| f.name.as_str()).collect();
    let b_names: Vec<&str> = b.iter().map(|f| f.name.as_str()).collect();

    for name in &a_names {
        if !b_names.contains(name) {
            out.push(Change::new(
                ChangeKind::Removed,
                format!("{prefix}.forwards[{name}]"),
            ));
        }
    }
    for name in &b_names {
        if !a_names.contains(name) {
            out.push(Change::new(
                ChangeKind::Added,
                format!("{prefix}.forwards[{name}]"),
            ));
        }
    }
    for af in a {
        if let Some(bf) = b.iter().find(|f| f.name == af.name) {
            if af != bf {
                out.push(Change::new(
                    ChangeKind::Modified,
                    format!("{prefix}.forwards[{}]", af.name),
                ));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{diff, ChangeKind, DIFF_PROFILE_COVERED, DIFF_TOP_COVERED};
    use crate::load::load_str;

    const A: &str = r#"
        version = 1
        [[profiles]]
        name = "p"
        protocol = "ssh2"
        host = "h"
    "#;

    #[test]
    fn equal_configs_have_empty_diff() {
        let (a, _) = load_str(A, false).unwrap();
        let (b, _) = load_str(A, false).unwrap();
        assert!(diff(&a, &b).is_empty());
    }

    #[test]
    fn rename_host_is_modified() {
        let (a, _) = load_str(A, false).unwrap();
        let mut b = a.clone();
        b.profiles[0].host = Some("other".into());
        let changes = diff(&a, &b);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].kind, ChangeKind::Modified);
        assert!(changes[0].path.contains("host"));
    }

    #[test]
    fn add_profile_reports_added() {
        let (a, _) = load_str(A, false).unwrap();
        let mut b = a.clone();
        b.profiles.push(crate::schema::Profile {
            name: "q".into(),
            protocol: "ssh2".into(),
            host: Some("h2".into()),
            ..Default::default()
        });
        let ch = diff(&a, &b);
        assert!(ch.iter().any(|c| c.kind == ChangeKind::Added));
    }

    /// Serialize `value` to a `toml::Table` and return its top-level keys.
    ///
    /// Fields with `#[serde(skip_serializing_if = ...)]` only appear when
    /// populated, so the caller must hand in a fully-populated value for the
    /// key set to be exhaustive.
    fn serialized_keys<T: serde::Serialize>(value: &T) -> Vec<String> {
        let toml_value = toml::Value::try_from(value).expect("serialize to toml::Value");
        match toml_value {
            toml::Value::Table(table) => table.keys().cloned().collect(),
            other => panic!("expected a table, got {other:?}"),
        }
    }

    /// A config TOML that populates *every* top-level table so that every
    /// top-level key serializes. When a new top-level table is added to the
    /// schema, this fixture must be extended too — and the coverage assertion
    /// below forces a matching `diff_top!` line. See E5-F3.
    const FULL_TOP: &str = r#"
        version = 1

        [runtime]
        state_dir = "/var/lib/spt"

        [logging]
        level = "info"

        [secrets]
        backend = "auto"

        [dns]
        enabled = false

        [firewall]
        [firewall.platform]
        linux = "auto"

        [network]
        [network.interface]
        bind_ipv6 = "auto"

        [observability]
        [observability.snmp]
        enabled = false

        [events]

        [mcp]
        enabled = false

        [updater]
        enabled = false

        [diagnostics]

        [benchmark]

        [capabilities]
        allow_sftp = false

        # round_robin and status_api are `skip_serializing_if` default — set a
        # non-default value so the key actually serializes for the coverage scan.
        [round_robin]
        enabled = true

        [status_api]
        enabled = true

        [[profiles]]
        name = "p"
        protocol = "ssh2"
        host = "h"
    "#;

    /// A profile TOML that populates *every* profile field so the serialized
    /// key set is exhaustive. New profile fields must be added here, which
    /// forces a matching `field!`/`diff_forwards` line via the assertion. E5-F3.
    const FULL_PROFILE: &str = r#"
        version = 1

        [[profiles]]
        name = "p"
        description = "d"
        enabled = true
        protocol = "ssh2"
        host = "h"
        port = 22
        endpoint = "https://x:443/ssh3"
        acknowledge_experimental = true
        user = "u"
        connect_timeout = "10s"
        dns_resolution = "once"
        network_change_reconnect = true
        startup = "eager"
        failure_policy = "retry"
        tags = ["a"]

        [profiles.connection]

        [profiles.crypto]

        [profiles.auth]
        method = "password"

        [profiles.trust]

        [profiles.tls]

        [profiles.ssh3]

        [profiles.keepalive]
        interval = "10s"

        [profiles.reconnect]

        [profiles.instability]

        [profiles.failover]

        [profiles.limits]

        [[profiles.endpoints]]
        name = "e"
        host = "eh"
        port = 22

        [[profiles.hops]]
        name = "hop"
        protocol = "ssh2"
        host = "hh"
        port = 22

        [[profiles.forwards]]
        name = "f"
        type = "local"
        transport = "tcp"
        bind = "127.0.0.1:1"
        target = "x:22"

        [[profiles.sftp_mounts]]
        name = "m"
        remote_path = "/r"
        mount_point = "/l"

        [profiles.script]
        path = "s.rhai"

        [profiles.transport]
        [profiles.transport.obfuscation]
        kind = "meek-http"
        url = "https://front.example/"
    "#;

    #[test]
    fn diff_top_covers_every_schema_field() {
        let (cfg, _) = load_str(FULL_TOP, false).unwrap();
        let keys = serialized_keys(&cfg);
        for key in &keys {
            assert!(
                DIFF_TOP_COVERED.contains(&key.as_str()),
                "top-level config field `{key}` is serialized but not covered by \
                 diff()'s diff_top! list — add it to the diff macro AND to \
                 DIFF_TOP_COVERED so reload diffs do not silently miss it (E5-F3)"
            );
        }
        // Every covered name must still exist on the schema, so the guard can
        // never rot into stale entries that pass vacuously.
        for covered in DIFF_TOP_COVERED {
            assert!(
                keys.iter().any(|k| k == covered),
                "DIFF_TOP_COVERED lists `{covered}` but the schema fixture does not \
                 serialize it — remove the stale entry or extend FULL_TOP"
            );
        }
        // Sanity: the schema really does expose all 15 tables + version + profiles.
        assert_eq!(keys.len(), DIFF_TOP_COVERED.len());
    }

    #[test]
    fn diff_profile_covers_every_schema_field() {
        let (cfg, _) = load_str(FULL_PROFILE, false).unwrap();
        let profile = &cfg.profiles[0];
        let keys = serialized_keys(profile);
        for key in &keys {
            assert!(
                DIFF_PROFILE_COVERED.contains(&key.as_str()),
                "profile field `{key}` is serialized but not covered by \
                 diff_profile()/diff_forwards() — add a `field!({key})` line AND an \
                 entry in DIFF_PROFILE_COVERED so reload diffs do not silently miss \
                 it (E5-F3)"
            );
        }
        for covered in DIFF_PROFILE_COVERED {
            assert!(
                keys.iter().any(|k| k == covered),
                "DIFF_PROFILE_COVERED lists `{covered}` but the schema fixture does \
                 not serialize it — remove the stale entry or extend FULL_PROFILE"
            );
        }
        assert_eq!(keys.len(), DIFF_PROFILE_COVERED.len());
    }

    #[test]
    fn transport_change_is_detected() {
        let (a, _) = load_str(FULL_PROFILE, false).unwrap();
        let mut b = a.clone();
        // Flip the obfuscation URL — a connection-level transport change that
        // previously produced zero diff entries (E5-F3).
        if let Some(transport) = b.profiles[0].transport.as_mut() {
            if let Some(crate::schema::ObfsConfig::MeekHttp { url, .. }) =
                transport.obfuscation.as_mut()
            {
                *url = "https://other.example/".into();
            }
        }
        let changes = diff(&a, &b);
        assert!(
            changes.iter().any(|c| c.path.contains("transport")),
            "changing transport.obfuscation must surface a diff entry, got {changes:?}"
        );
    }

    #[test]
    fn status_api_change_is_detected() {
        let (a, _) = load_str(FULL_TOP, false).unwrap();
        let mut b = a.clone();
        b.status_api.enabled = !b.status_api.enabled;
        let changes = diff(&a, &b);
        assert!(
            changes.iter().any(|c| c.path == "status_api"),
            "changing [status_api] must surface a diff entry, got {changes:?}"
        );
    }

    #[test]
    fn remove_forward_reports_removed() {
        let raw = r#"
            version = 1
            [[profiles]]
            name = "p"
            protocol = "ssh2"
            host = "h"
            [[profiles.forwards]]
            name = "f"
            type = "local"
            transport = "tcp"
            bind = "127.0.0.1:1"
            target = "x:22"
        "#;
        let (a, _) = load_str(raw, false).unwrap();
        let mut b = a.clone();
        b.profiles[0].forwards.clear();
        let changes = diff(&a, &b);
        assert!(changes
            .iter()
            .any(|c| c.kind == ChangeKind::Removed && c.path.contains("forwards[f]")));
    }
}
