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
    diff_top!(observability);
    diff_top!(events);
    diff_top!(mcp);
    diff_top!(diagnostics);
    diff_top!(benchmark);

    diff_profiles(a, b, &mut changes);

    changes
}

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
            out.push(Change::new(
                ChangeKind::Added,
                format!("profiles[{name}]"),
            ));
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

    diff_forwards(&p, &a.forwards, &b.forwards, out);
}

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
    use super::{diff, ChangeKind};
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
        assert!(changes.iter().any(|c| c.kind == ChangeKind::Removed && c.path.contains("forwards[f]")));
    }
}
