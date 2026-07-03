//! Atomic, comment-preserving save path.
//!
//! [`save`] takes the edited [`Profile`] from a
//! [`Model`], serializes it through `toml_edit`'s serde adapter, and replaces
//! the matching `[[profiles]]` entry in the round-trip document. Bytes
//! *outside* that profile (header comments, other profiles, other top-level
//! tables) are preserved byte-for-byte. Comments *inside* the replaced
//! profile are lost — that is the consequence of treating the profile as the
//! editable unit of granularity.
//!
//! The write itself is atomic via
//! [`spt_config::mutate::Document::write_atomic`].

use std::path::{Path, PathBuf};

use spt_config::mutate::Document;
use spt_config::schema::{Dns, Events, Profile};
use spt_core::{Error, Result};
use toml_edit::{ArrayOfTables, Item, Table};

use crate::model::Model;

/// Every top-level key the schema-backed [`Profile`] struct understands.
///
/// The wizard edits a [`Profile`] and re-serializes the whole struct on save
/// (see [`profile_to_table`]). Because `Profile` has **no**
/// `#[serde(deny_unknown_fields)]` and no catch-all/`flatten` field, any key
/// present in the *source* `[[profiles]]` table that is not in this set is
/// silently dropped on a round-trip edit (E4-F15). [`unknown_keys`] diffs the
/// source table against this list so the operator can be warned before the
/// data loss happens.
///
/// Keep this in lockstep with `spt_config::schema::Profile`'s field names.
/// `profile_table_keys_are_known` (test below) guards against drift by
/// round-tripping a maximally-populated profile through serde and asserting
/// every emitted key is listed here.
const KNOWN_PROFILE_KEYS: &[&str] = &[
    // Scalars / top-level fields.
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
    // `[profiles.*]` sub-tables.
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
    // `[[profiles.*]]` arrays-of-tables.
    "endpoints",
    "hops",
    "forwards",
    "sftp_mounts",
    "script",
    "transport",
];

/// Keys whose presence on a profile is **not** reachable from the 13-page
/// wizard. Surfaced read-only on the Review page so operators can at least
/// *see* settings they cannot yet edit (E4-F15). These are all valid schema
/// keys (so they survive save), unlike [`unknown_keys`] which finds keys the
/// schema would drop entirely.
pub const NON_WIZARD_TABLE_KEYS: &[&str] = &["sftp_mounts", "script", "enabled"];

/// Return the names of the non-wizard tables/fields that are actually present
/// on the given profile's *source* `[[profiles]]` table, in
/// [`NON_WIZARD_TABLE_KEYS`] order.
///
/// Reads the round-trip [`Document`] (not the parsed [`Profile`]) so the
/// Review page reflects what the operator wrote, byte-for-byte presence-wise.
#[must_use]
pub fn present_non_wizard_keys(model: &Model) -> Vec<&'static str> {
    let Some(table) = source_profile_table(model) else {
        return Vec::new();
    };
    NON_WIZARD_TABLE_KEYS
        .iter()
        .copied()
        .filter(|k| table.contains_key(k))
        .collect()
}

/// Return the top-level keys present in the source profile table that the
/// schema-backed [`Profile`] does **not** recognise and would therefore drop
/// on a wizard save (E4-F15 data-loss guard).
///
/// Returns an empty vec when the profile is new (not yet in the source
/// document) or when every key is known.
#[must_use]
pub fn unknown_keys(model: &Model) -> Vec<String> {
    let Some(table) = source_profile_table(model) else {
        return Vec::new();
    };
    let mut out: Vec<String> = table
        .iter()
        .map(|(k, _)| k.to_string())
        .filter(|k| !KNOWN_PROFILE_KEYS.contains(&k.as_str()))
        .collect();
    out.sort();
    out
}

/// Parse the model's *source* TOML and return the `[[profiles]]` table whose
/// `name` matches the selected profile.
///
/// We re-parse `original_toml()` rather than reach into the round-trip
/// [`Document`] so this stays self-contained within the TUI crate (the
/// `Document` type exposes only a `&mut` accessor). The source TOML is small
/// (a single config file) so the parse cost is negligible and only paid when
/// the Review page renders or a save runs.
fn source_profile_table(model: &Model) -> Option<Table> {
    let doc: toml_edit::DocumentMut = model.original_toml().parse().ok()?;
    // Match by the profile's original (source-document) name so an in-flight
    // `id` rename still locates the on-disk block.
    let name = model
        .selected_original_name()
        .map_or_else(|| model.profile().name.clone(), str::to_owned);
    let Item::ArrayOfTables(arr) = doc.get("profiles")? else {
        return None;
    };
    for t in arr {
        if t.get("name")
            .and_then(toml_edit::Item::as_str)
            .is_some_and(|s| s == name)
        {
            return Some(t.clone());
        }
    }
    None
}

/// Write the model's selected profile back to its source file.
///
/// On success the model's dirty flag is cleared and `last_saved()` points at
/// the written path.
pub fn save(model: &mut Model) -> Result<PathBuf> {
    let path = model.path().to_path_buf();
    save_to(model, &path)
}

/// Like [`save`] but writes to an alternate path. Used by the review page's
/// "save as" affordance and by tests.
pub fn save_to(model: &mut Model, target: &Path) -> Result<PathBuf> {
    // 0. Warn before any write if the source profile holds keys the
    //    schema-backed `Profile` doesn't recognise — re-serializing the
    //    struct silently drops them (E4-F15). The save still proceeds; this
    //    is an advisory so a round-trip edit doesn't lose data unnoticed.
    let dropped = unknown_keys(model);
    if !dropped.is_empty() {
        tracing::warn!(
            profile = %model.profile().name,
            keys = %dropped.join(", "),
            "saving will drop {} unrecognised key(s) from profile `{}`: {} \
             (not understood by the current schema)",
            dropped.len(),
            model.profile().name,
            dropped.join(", "),
        );
    }

    // 1. Decide whether `[events]` needs to be (re)written. We only splice
    //    the global events table when it was *specifically* mutated (via
    //    `events_mut`/`config_mut`, tracked by `is_events_dirty`) *and* the
    //    config actually carries an `[events]` table. Gating on the
    //    events-specific flag — not the global `is_dirty` — means a
    //    profile-only save (which still flips `is_dirty`) leaves the source
    //    `[events]` block byte-for-byte, and a config that never had events
    //    keeps `[events]` absent.
    let write_events = model.is_events_dirty() && model.events().is_some();
    let events = write_events.then(|| model.events().cloned()).flatten();

    // 1b. Same gate for `[dns]`: splice only when it was specifically mutated
    //    (via `dns_mut`/`config_mut`, tracked by `is_dns_dirty`) *and* the
    //    config carries a `[dns]` table. Keeps a profile-only save from
    //    reordering/canonicalizing an untouched `[dns]` block.
    let write_dns = model.is_dns_dirty() && model.dns().is_some();
    let dns = write_dns.then(|| model.dns().cloned()).flatten();

    // 2. Clone the document so failures don't leave the model half-edited.
    //    Match the block to replace by the profile's *original* (source) name
    //    so renaming its `id` updates the existing block in place (HC3 F4).
    let original_name = model.selected_original_name().map(str::to_owned);
    let mut document = model.document_mut().clone();
    splice_profile(&mut document, model.profile(), original_name.as_deref())?;
    if let Some(events) = events.as_ref() {
        splice_events(&mut document, events);
    }
    if let Some(dns) = dns.as_ref() {
        splice_dns(&mut document, dns);
    }
    document.write_atomic(target)?;
    model.mark_saved(document, target.to_path_buf());
    Ok(target.to_path_buf())
}

/// Splice an edited [`Profile`] into a round-trip [`Document`].
///
/// Locates the `[[profiles]]` entry to replace by `match_name` — the profile's
/// name *in the source document* (its on-disk `id`), passed via
/// `original_name` — and replaces it with a freshly-serialized table. When the
/// operator has renamed the profile (edited its `id`), `original_name` is the
/// pre-edit name, so the existing block is updated **in place** (a rename)
/// rather than the renamed struct being appended as a duplicate `[[profiles]]`
/// (HC3 F4). When `original_name` is `None` (or matches nothing — e.g. a
/// brand-new profile) the new table is appended.
pub fn splice_profile(
    document: &mut Document,
    profile: &Profile,
    original_name: Option<&str>,
) -> Result<()> {
    let new_table = profile_to_table(profile)?;
    let match_name = original_name.unwrap_or(profile.name.as_str());
    let inner = document.document_mut();

    // Ensure `profiles` exists as ArrayOfTables.
    let entry = inner
        .entry("profiles")
        .or_insert_with(|| Item::ArrayOfTables(ArrayOfTables::new()));
    let arr = match entry {
        Item::ArrayOfTables(a) => a,
        _ => {
            return Err(Error::InvalidConfig(
                "`profiles` must be an array of tables".into(),
            ))
        }
    };

    // Find existing by the *original* (source-document) name so a rename of the
    // profile's `id` updates the matched block in place instead of appending.
    let mut found: Option<usize> = None;
    for (i, t) in arr.iter().enumerate() {
        if t.get("name")
            .and_then(|v| v.as_str())
            .is_some_and(|s| s == match_name)
        {
            found = Some(i);
            break;
        }
    }

    if let Some(i) = found {
        // Replace in place. ArrayOfTables doesn't expose set-by-index, so we
        // rebuild from a Vec while preserving relative ordering.
        let mut rebuilt = ArrayOfTables::new();
        for (j, t) in arr.iter().enumerate() {
            if j == i {
                rebuilt.push(new_table.clone());
            } else {
                rebuilt.push(t.clone());
            }
        }
        *arr = rebuilt;
    } else {
        arr.push(new_table);
    }

    Ok(())
}

/// Splice the global `[events]` table into a round-trip [`Document`].
///
/// Mirrors [`splice_profile`] but for the single top-level `[events]` item:
/// the whole [`Events`] struct is re-serialized via `toml_edit::ser` and the
/// existing `events` item — table plus its `[[events.sinks]]`,
/// `[[events.bindings]]` and `[[events.commands]]` arrays-of-tables — is
/// replaced wholesale. Bytes *outside* `[events]` (header comments, profiles,
/// other tables) are untouched; comments *inside* `[events]` are not
/// preserved (same granularity trade-off as `splice_profile`).
///
/// Re-serializing the parsed struct preserves *deferred* fields (email
/// `smtp`, push `vapid_private_key`, `[[events.commands]]`, pinned-TLS keys)
/// that the TUI doesn't edit, because they round-trip through serde even
/// though no editor surfaces them. `RedactedString` secrets serialize
/// transparently here (redaction is a render-time concern), so they survive
/// the round-trip byte-for-byte.
///
/// This never errors in practice — `Events` is a plain serde struct — but the
/// serializer is fallible, so a serialization failure is logged and the
/// `[events]` item is left as-is rather than panicking mid-save.
pub fn splice_events(document: &mut Document, events: &Events) {
    let new_item = match events_to_item(events) {
        Ok(item) => item,
        Err(e) => {
            tracing::warn!("serialize events: {e}; leaving [events] unchanged");
            return;
        }
    };
    let inner = document.document_mut();
    inner.insert("events", new_item);
}

/// Serialize an [`Events`] struct to a round-trip [`Item`] via
/// `toml_edit::ser`. The emitted document's root table *is* the contents of
/// `[events]`, so we wrap it back into a `Table` item.
fn events_to_item(events: &Events) -> Result<Item> {
    let doc = toml_edit::ser::to_document(events)
        .map_err(|e| Error::InvalidConfig(format!("serialize events: {e}")))?;
    Ok(Item::Table(doc.as_table().clone()))
}

/// Splice the global `[dns]` table into a round-trip [`Document`].
///
/// Mirrors [`splice_events`] but for the single top-level `[dns]` item: the
/// whole [`Dns`] struct is re-serialized via `toml_edit::ser` and the existing
/// `dns` item — table plus its `[[dns.records]]` array-of-tables — is replaced
/// wholesale. Bytes *outside* `[dns]` (header comments, profiles, other
/// tables) are untouched; comments *inside* `[dns]` are not preserved (same
/// granularity trade-off as `splice_profile`/`splice_events`).
///
/// Re-serializing the parsed struct preserves *deferred* scalars
/// (`enabled`/`mode`/`bind`/`zone`/`ttl`/`auto_records`/`upstream`/
/// `hosts_file`/`hosts_file_mode`) that the TUI doesn't edit, because they
/// round-trip through serde even though no editor surfaces them.
///
/// This never errors in practice — `Dns` is a plain serde struct — but the
/// serializer is fallible, so a serialization failure is logged and the
/// `[dns]` item is left as-is rather than panicking mid-save.
pub fn splice_dns(document: &mut Document, dns: &Dns) {
    let new_item = match dns_to_item(dns) {
        Ok(item) => item,
        Err(e) => {
            tracing::warn!("serialize dns: {e}; leaving [dns] unchanged");
            return;
        }
    };
    let inner = document.document_mut();
    inner.insert("dns", new_item);
}

/// Serialize a [`Dns`] struct to a round-trip [`Item`] via `toml_edit::ser`.
/// The emitted document's root table *is* the contents of `[dns]`, so we wrap
/// it back into a `Table` item.
fn dns_to_item(dns: &Dns) -> Result<Item> {
    let doc = toml_edit::ser::to_document(dns)
        .map_err(|e| Error::InvalidConfig(format!("serialize dns: {e}")))?;
    Ok(Item::Table(doc.as_table().clone()))
}

/// Serialize a [`Profile`] to a [`Table`] via `toml_edit::ser`.
fn profile_to_table(profile: &Profile) -> Result<Table> {
    // toml_edit's `ser::to_document` emits a DocumentMut; we extract its
    // root table.
    let doc = toml_edit::ser::to_document(profile)
        .map_err(|e| Error::InvalidConfig(format!("serialize profile: {e}")))?;
    Ok(doc.as_table().clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Model;

    const RAW: &str = r#"# top-level comment
version = 1

# logging
[logging]
level = "info"

[[profiles]]
# profile p comment
name = "p"
protocol = "ssh2"
host = "h.example.com"

[[profiles]]
name = "q"
protocol = "ssh3"
endpoint = "https://q.example.com"
"#;

    #[test]
    fn splice_preserves_other_profiles_and_header() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("c.toml");
        std::fs::write(&path, RAW).unwrap();

        let mut model = Model::load(&path).unwrap();
        model.select_profile_by_name("p").unwrap();
        model.profile_mut().user = Some("alice".into());

        let written = save(&mut model).unwrap();
        assert_eq!(written, path);

        let out = std::fs::read_to_string(&path).unwrap();
        // Top-level comment kept.
        assert!(out.contains("# top-level comment"));
        // Logging section kept.
        assert!(out.contains("[logging]"));
        // Other profile kept.
        assert!(out.contains("name = \"q\""));
        assert!(out.contains("https://q.example.com"));
        // Edit applied.
        assert!(out.contains("user = \"alice\""));
        // Model is no longer dirty.
        assert!(!model.is_dirty());
    }

    #[test]
    fn splice_appends_when_profile_is_new() {
        let mut model = Model::from_str(RAW);
        model.create_profile("brand-new", "ssh2");
        model.profile_mut().host = Some("new.example.com".into());

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("c.toml");
        save_to(&mut model, &path).unwrap();
        let out = std::fs::read_to_string(&path).unwrap();
        assert!(out.contains(r#"name = "brand-new""#));
        assert!(out.contains("new.example.com"));
        // Existing profiles still there.
        assert!(out.contains(r#"name = "p""#));
        assert!(out.contains(r#"name = "q""#));
    }

    /// HC3 F4: renaming a profile's `id` (i.e. editing `Profile::name`) must
    /// update the existing `[[profiles]]` block *in place* — not append a new
    /// block and orphan the old one.
    #[test]
    fn renaming_profile_id_updates_existing_block_no_orphan() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("c.toml");
        std::fs::write(&path, RAW).unwrap();

        let mut model = Model::load(&path).unwrap();
        model.select_profile_by_name("p").unwrap();
        // Rename the profile's id (Basics `id` maps to `Profile::name`).
        model.profile_mut().name = "renamed".into();
        save(&mut model).unwrap();

        let out = std::fs::read_to_string(&path).unwrap();
        // New name present, old name gone (renamed in place).
        assert!(
            out.contains(r#"name = "renamed""#),
            "new id must be written"
        );
        assert!(
            !out.contains(r#"name = "p""#),
            "old id must be gone, not left as an orphan: {out}"
        );
        // No duplicate/orphan: exactly two profiles remain (renamed + q).
        let (cfg, _w) = spt_config::load_str(&out, false).unwrap();
        assert_eq!(
            cfg.profiles.len(),
            2,
            "rename must not add a profile: {out}"
        );
        assert_eq!(cfg.profiles[0].name, "renamed");
        assert_eq!(cfg.profiles[1].name, "q");
        // The other profile is untouched.
        assert!(out.contains("https://q.example.com"));
    }

    /// A second rename in the same session (after a save) must also rename in
    /// place — the post-save original name is refreshed by `mark_saved`.
    #[test]
    fn second_rename_after_save_still_renames_in_place() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("c.toml");
        std::fs::write(&path, RAW).unwrap();

        let mut model = Model::load(&path).unwrap();
        model.select_profile_by_name("p").unwrap();
        model.profile_mut().name = "first".into();
        save(&mut model).unwrap();
        model.profile_mut().name = "second".into();
        save(&mut model).unwrap();

        let out = std::fs::read_to_string(&path).unwrap();
        let (cfg, _w) = spt_config::load_str(&out, false).unwrap();
        assert_eq!(cfg.profiles.len(), 2, "no orphan after two renames: {out}");
        assert!(!out.contains(r#"name = "p""#));
        assert!(!out.contains(r#"name = "first""#));
        assert!(out.contains(r#"name = "second""#));
    }

    #[test]
    fn save_clears_dirty_and_records_last_saved() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("c.toml");
        std::fs::write(&path, RAW).unwrap();
        let mut model = Model::load(&path).unwrap();
        model.profile_mut().user = Some("eve".into());
        assert!(model.is_dirty());
        save(&mut model).unwrap();
        assert!(!model.is_dirty());
        assert_eq!(model.last_saved(), Some(path.as_path()));
    }

    #[test]
    fn save_to_alternate_path_does_not_touch_loaded_path() {
        let dir = tempfile::tempdir().unwrap();
        let primary = dir.path().join("primary.toml");
        let alt = dir.path().join("alt.toml");
        std::fs::write(&primary, RAW).unwrap();
        let mut model = Model::load(&primary).unwrap();
        model.profile_mut().user = Some("alice".into());
        save_to(&mut model, &alt).unwrap();
        // Primary unchanged.
        let primary_now = std::fs::read_to_string(&primary).unwrap();
        assert!(!primary_now.contains("alice"));
        // Alt got the new bytes.
        let alt_now = std::fs::read_to_string(&alt).unwrap();
        assert!(alt_now.contains("alice"));
    }

    #[test]
    fn splice_profile_appends_into_empty_profiles_array() {
        let mut doc = spt_config::mutate::Document::parse("version = 1\n").unwrap();
        let p = Profile {
            name: "fresh".into(),
            protocol: "ssh2".into(),
            ..Default::default()
        };
        splice_profile(&mut doc, &p, None).unwrap();
        let rendered = doc.to_string();
        assert!(rendered.contains(r#"name = "fresh""#));
        assert!(rendered.contains(r#"protocol = "ssh2""#));
    }

    #[test]
    fn splice_profile_rejects_non_array_profiles() {
        let mut doc = spt_config::mutate::Document::parse("profiles = \"not-an-array\"\n").unwrap();
        let p = Profile {
            name: "x".into(),
            protocol: "ssh2".into(),
            ..Default::default()
        };
        let err = splice_profile(&mut doc, &p, None).unwrap_err();
        let s = format!("{err}");
        assert!(s.contains("array of tables"));
    }

    #[test]
    fn save_atomic_keeps_top_comment_after_repeated_edits() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("c.toml");
        std::fs::write(&path, RAW).unwrap();
        let mut model = Model::load(&path).unwrap();
        // First save: edit user.
        model.profile_mut().user = Some("eve".into());
        save(&mut model).unwrap();
        // Second save: edit host.
        model.profile_mut().host = Some("h2.example.com".into());
        save(&mut model).unwrap();
        let out = std::fs::read_to_string(&path).unwrap();
        // The top-of-file comment is preserved across both saves.
        assert!(out.contains("# top-level comment"));
        assert!(out.contains("eve"));
        assert!(out.contains("h2.example.com"));
    }

    #[test]
    fn save_returns_target_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("c.toml");
        std::fs::write(&path, RAW).unwrap();
        let mut model = Model::load(&path).unwrap();
        model.profile_mut().user = Some("alice".into());
        let returned = save(&mut model).unwrap();
        assert_eq!(returned, path);
    }

    // ---- Unknown-key / data-loss guard (E4-F15) ----------------------

    /// A source profile carrying a key the schema doesn't know about must
    /// be reported by [`unknown_keys`] — that key is silently dropped on a
    /// wizard save.
    #[test]
    fn unknown_keys_detects_unrecognised_key() {
        let raw = r#"version = 1
[[profiles]]
name = "p"
protocol = "ssh2"
host = "h.example.com"
totally_made_up = "boom"
another_typo = 42
"#;
        let model = Model::from_str(raw);
        let keys = unknown_keys(&model);
        assert_eq!(keys, vec!["another_typo", "totally_made_up"]);
    }

    /// A profile using only schema-recognised keys (including the
    /// non-wizard tables) must report *no* unknown keys.
    #[test]
    fn unknown_keys_empty_for_all_known_keys() {
        let raw = r#"version = 1
[[profiles]]
name = "p"
protocol = "ssh2"
host = "h.example.com"
enabled = true

[[profiles.hops]]
name = "jump"
protocol = "ssh2"
host = "jump.example.com"
port = 22

[profiles.script]
path = "hooks.rhai"

[profiles.transport]
"#;
        let model = Model::from_str(raw);
        assert!(
            unknown_keys(&model).is_empty(),
            "known keys must not be flagged: {:?}",
            unknown_keys(&model)
        );
    }

    /// A save that would drop unknown keys still succeeds (the warning is
    /// advisory), and the round-trip indeed loses the unknown key — which
    /// is exactly why the operator is warned.
    #[test]
    fn save_with_unknown_key_warns_but_succeeds_and_drops_key() {
        let raw = r#"version = 1
[[profiles]]
name = "p"
protocol = "ssh2"
host = "h.example.com"
mystery_key = "value"
"#;
        let mut model = Model::from_str(raw);
        // Precondition: the unknown key is detected pre-save.
        assert_eq!(unknown_keys(&model), vec!["mystery_key"]);

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("c.toml");
        // Touch a field so the edited profile is re-serialized on save.
        model.profile_mut().user = Some("alice".into());
        save_to(&mut model, &path).unwrap();

        let out = std::fs::read_to_string(&path).unwrap();
        assert!(out.contains("alice"), "edit must be applied");
        // The schema-unknown key is gone after the wizard round-trip — the
        // data loss the warning announces.
        assert!(
            !out.contains("mystery_key"),
            "unknown key is dropped by the whole-struct re-serialize"
        );
    }

    /// New profiles (not present in the source document) have no source
    /// table, so neither helper should panic or report anything.
    #[test]
    fn unknown_keys_empty_for_brand_new_profile() {
        let mut model = Model::from_str(RAW);
        model.create_profile("fresh", "ssh2");
        assert!(unknown_keys(&model).is_empty());
        assert!(present_non_wizard_keys(&model).is_empty());
    }

    /// `present_non_wizard_keys` lists only the non-wizard tables actually
    /// present, in the canonical [`NON_WIZARD_TABLE_KEYS`] order.
    #[test]
    fn present_non_wizard_keys_lists_present_tables_in_order() {
        let raw = r#"version = 1
[[profiles]]
name = "p"
protocol = "ssh2"
host = "h.example.com"
enabled = false

[profiles.transport]

[[profiles.hops]]
name = "jump"
protocol = "ssh2"
host = "jump.example.com"
port = 22
"#;
        let model = Model::from_str(raw);
        // `hops` and `transport` are now wizard-editable (Hops / Transport
        // pages), so they are no longer surfaced as non-wizard. Only the
        // still-unreachable `enabled` scalar remains.
        assert_eq!(present_non_wizard_keys(&model), vec!["enabled"]);
    }

    /// A wizard-only profile (no non-wizard tables) reports an empty list,
    /// which keeps the Review page's extra section hidden and the existing
    /// snapshot byte-identical.
    #[test]
    fn present_non_wizard_keys_empty_for_plain_profile() {
        let model = Model::from_str(RAW);
        assert!(present_non_wizard_keys(&model).is_empty());
    }

    /// Drift guard: round-trip a maximally-populated profile through serde
    /// and assert every emitted top-level key is in `KNOWN_PROFILE_KEYS`.
    /// If a new field is added to `Profile`, this fails until the constant
    /// is updated — preventing `unknown_keys` from false-positiving on a
    /// legitimate new field.
    #[test]
    fn known_profile_keys_cover_full_schema() {
        // Serialize a Profile with every Option/Vec field populated so
        // `skip_serializing_if` doesn't hide any key.
        let mut p = Profile {
            name: "p".into(),
            protocol: "ssh2".into(),
            ..Default::default()
        };
        p.description = Some("d".into());
        p.enabled = Some(true);
        p.host = Some("h".into());
        p.port = Some(22);
        p.endpoint = Some("https://x".into());
        p.acknowledge_experimental = Some(true);
        p.user = Some("u".into());
        p.connect_timeout = Some("10s".into());
        p.dns_resolution = Some("once".into());
        p.network_change_reconnect = Some(true);
        p.startup = Some("eager".into());
        p.failure_policy = Some("retry".into());
        p.tags = Some(vec!["t".into()]);

        let table = profile_to_table(&p).unwrap();
        for (key, _) in &table {
            assert!(
                KNOWN_PROFILE_KEYS.contains(&key),
                "Profile emits top-level key `{key}` not listed in \
                 KNOWN_PROFILE_KEYS — update the constant (and the Review \
                 page's non-wizard list if relevant)"
            );
        }
    }

    // ---- [events] round-trip / preservation (t-events-tui E1) --------

    /// Config with an `[events]` table (a sink + a binding). Editing the
    /// events via `events_mut` and saving must round-trip the new shape.
    const EVENTS_RAW: &str = r#"version = 1
[[profiles]]
name = "p"
protocol = "ssh2"
host = "h.example.com"

[[events.sinks]]
name = "webhook"
type = "http"
url = "https://hook.example.com"

[[events.bindings]]
name = "on-fail"
on = ["profile.failed"]
actions = ["webhook"]
"#;

    #[test]
    fn events_round_trip_through_save() {
        use spt_config::schema::{EventBinding, EventSink};

        let mut model = Model::from_str(EVENTS_RAW);
        // Edit an existing sink + add a new sink and binding.
        {
            let ev = model.events_mut();
            ev.sinks[0].method = Some("POST".into());
            ev.sinks.push(EventSink {
                name: "log".into(),
                kind: "mcp_notify".into(),
                url: Some("https://log.example.com".into()),
                ..Default::default()
            });
            ev.bindings.push(EventBinding {
                name: "on-connect".into(),
                on: vec!["profile.connected".into()],
                actions: vec!["log".into()],
                min_level: Some("info".into()),
                ..Default::default()
            });
        }

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("c.toml");
        save_to(&mut model, &path).unwrap();

        // Reparse the written file and assert the expected Events.
        let out = std::fs::read_to_string(&path).unwrap();
        let (cfg, _w) = spt_config::load_str(&out, false).unwrap();
        let ev = cfg.events.expect("events present after save");
        assert_eq!(ev.sinks.len(), 2);
        assert_eq!(ev.sinks[0].name, "webhook");
        assert_eq!(ev.sinks[0].method.as_deref(), Some("POST"));
        assert_eq!(ev.sinks[1].name, "log");
        assert_eq!(ev.sinks[1].kind, "mcp_notify");
        assert_eq!(ev.bindings.len(), 2);
        assert_eq!(ev.bindings[1].name, "on-connect");
        assert_eq!(ev.bindings[1].actions, vec!["log".to_string()]);
        assert_eq!(ev.bindings[1].min_level.as_deref(), Some("info"));
        // Profile bytes untouched.
        assert!(out.contains("h.example.com"));
    }

    /// Fields the TUI will never edit (email `smtp`, a push sink's
    /// `vapid_private_key`) must survive an unrelated binding edit + save:
    /// still present after re-serialize, secret value carried verbatim in
    /// the serialized form, and redacted by the render path.
    #[test]
    fn events_deferred_fields_survive_unrelated_edit() {
        let raw = r#"version = 1
[[profiles]]
name = "p"
protocol = "ssh2"

[[events.sinks]]
name = "mail"
type = "email"
smtp = "smtp://mail.example.com:587"
from = "alerts@example.com"
to = ["ops@example.com"]

[[events.sinks]]
name = "push"
type = "push"
url = "https://push.example.com"
vapid_private_key = "super-secret-vapid-key"
vapid_subject = "mailto:ops@example.com"

[[events.bindings]]
name = "b"
on = ["profile.failed"]
actions = ["mail"]
"#;
        let mut model = Model::from_str(raw);
        // Unrelated edit: tweak a binding's min_level.
        model.events_mut().bindings[0].min_level = Some("error".into());

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("c.toml");
        save_to(&mut model, &path).unwrap();

        let out = std::fs::read_to_string(&path).unwrap();
        let (cfg, _w) = spt_config::load_str(&out, false).unwrap();
        let ev = cfg.events.expect("events present");

        // Deferred email fields preserved.
        let mail = ev.sinks.iter().find(|s| s.name == "mail").unwrap();
        assert_eq!(mail.smtp.as_deref(), Some("smtp://mail.example.com:587"));
        assert_eq!(mail.from.as_deref(), Some("alerts@example.com"));
        assert_eq!(
            mail.to.as_deref(),
            Some(&["ops@example.com".to_string()][..])
        );

        // Deferred push secret preserved (value carried verbatim through the
        // transparent RedactedString serialize).
        let push = ev.sinks.iter().find(|s| s.name == "push").unwrap();
        let key = push.vapid_private_key.as_ref().expect("vapid key present");
        assert_eq!(key, &"super-secret-vapid-key");
        assert_eq!(
            push.vapid_subject.as_deref(),
            Some("mailto:ops@example.com")
        );

        // The edit landed.
        assert_eq!(ev.bindings[0].min_level.as_deref(), Some("error"));

        // The secret is held in a `RedactedString`: serialize is transparent
        // (so the value survives the round-trip in the file verbatim), but the
        // `Debug` surface every log/render path formats through hides it.
        assert!(out.contains("super-secret-vapid-key"));
        assert_eq!(
            format!("{:?}", push.vapid_private_key),
            "Some(<redacted>)",
            "vapid secret must redact in Debug"
        );
    }

    /// Editing ONLY a profile (events untouched) must leave the `[events]`
    /// table byte-identical: the dirty+present gate keeps `splice_events`
    /// from firing and re-emitting `[events]` in canonical (reordered) form.
    #[test]
    fn profile_only_save_leaves_events_byte_identical() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("c.toml");
        std::fs::write(&path, EVENTS_RAW).unwrap();
        let mut model = Model::load(&path).unwrap();

        // Edit only the profile.
        model.profile_mut().user = Some("alice".into());
        save_to(&mut model, &path).unwrap();

        let out = std::fs::read_to_string(&path).unwrap();
        // Edit applied.
        assert!(out.contains("user = \"alice\""));
        // The `[events]` block is preserved verbatim from the source, in its
        // original `[[events.sinks]]`-then-`[[events.bindings]]` order and
        // with the original key spelling/quoting.
        let events_block = &EVENTS_RAW[EVENTS_RAW.find("[[events.sinks]]").unwrap()..];
        assert!(
            out.contains(events_block.trim_end()),
            "events block must be byte-identical; got:\n{out}"
        );
    }

    // ---- [dns] round-trip / preservation (t-dns-forward-tui E1) ------

    /// Config with a `[dns]` table carrying deferred scalars + a record.
    /// Editing the records via `dns_mut` and saving must round-trip the new
    /// shape while preserving the untouched scalars.
    const DNS_RAW: &str = r#"version = 1
[[profiles]]
name = "p"
protocol = "ssh2"
host = "h.example.com"

[dns]
enabled = true
mode = "transparent_forwarder"
bind = "127.0.0.1:53"
zone = "internal."
upstream = ["1.1.1.1", "8.8.8.8"]
hosts_file = "/etc/hosts.spt"

[[dns.records]]
name = "a.example.com"
type = "A"
value = "10.0.0.1"
"#;

    #[test]
    fn dns_round_trip_through_save() {
        use spt_config::schema::DnsRecord;

        let mut model = Model::from_str(DNS_RAW);
        // Edit the existing record + add a new one.
        {
            let dns = model.dns_mut();
            dns.records[0].value = "10.0.0.2".into();
            dns.records[0].ttl = Some("600".into());
            dns.records.push(DnsRecord {
                name: "srv.example.com".into(),
                kind: "SRV".into(),
                value: "target.example.com".into(),
                priority: Some(10),
                weight: Some(5),
                port: Some(443),
                ..Default::default()
            });
        }

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("c.toml");
        save_to(&mut model, &path).unwrap();

        // Reparse the written file and assert the expected Dns.
        let out = std::fs::read_to_string(&path).unwrap();
        let (cfg, _w) = spt_config::load_str(&out, false).unwrap();
        let dns = cfg.dns.expect("dns present after save");

        // Records changed.
        assert_eq!(dns.records.len(), 2);
        assert_eq!(dns.records[0].name, "a.example.com");
        assert_eq!(dns.records[0].value, "10.0.0.2");
        assert_eq!(dns.records[0].ttl.as_deref(), Some("600"));
        assert_eq!(dns.records[1].name, "srv.example.com");
        assert_eq!(dns.records[1].kind, "SRV");
        assert_eq!(dns.records[1].priority, Some(10));
        assert_eq!(dns.records[1].weight, Some(5));
        assert_eq!(dns.records[1].port, Some(443));

        // Deferred scalars survived the re-serialize.
        assert_eq!(dns.enabled, Some(true));
        assert_eq!(dns.mode.as_deref(), Some("transparent_forwarder"));
        assert_eq!(dns.bind.as_deref(), Some("127.0.0.1:53"));
        assert_eq!(dns.zone.as_deref(), Some("internal."));
        assert_eq!(
            dns.upstream.as_deref(),
            Some(&["1.1.1.1".to_string(), "8.8.8.8".to_string()][..])
        );
        assert_eq!(dns.hosts_file.as_deref(), Some("/etc/hosts.spt"));

        // Profile bytes untouched.
        assert!(out.contains("h.example.com"));
    }

    /// Editing ONLY a profile (dns untouched) must leave the `[dns]` table
    /// byte-identical: the dirty+present gate keeps `splice_dns` from firing
    /// and re-emitting `[dns]` in canonical (reordered) form.
    #[test]
    fn profile_only_save_leaves_dns_byte_identical() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("c.toml");
        std::fs::write(&path, DNS_RAW).unwrap();
        let mut model = Model::load(&path).unwrap();

        // Edit only the profile.
        model.profile_mut().user = Some("alice".into());
        save_to(&mut model, &path).unwrap();

        let out = std::fs::read_to_string(&path).unwrap();
        // Edit applied.
        assert!(out.contains("user = \"alice\""));
        // The `[dns]` block is preserved verbatim from the source, in its
        // original scalar-then-`[[dns.records]]` order and with the original
        // key spelling/quoting.
        let dns_block = &DNS_RAW[DNS_RAW.find("[dns]").unwrap()..];
        assert!(
            out.contains(dns_block.trim_end()),
            "dns block must be byte-identical; got:\n{out}"
        );
    }
}
