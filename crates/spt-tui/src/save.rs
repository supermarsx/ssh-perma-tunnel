//! Atomic, comment-preserving save path.
//!
//! [`save`] takes the edited [`Profile`](spt_config::schema::Profile) from a
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
use spt_config::schema::Profile;
use spt_core::{Error, Result};
use toml_edit::{ArrayOfTables, Item, Table};

use crate::model::Model;

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
    // 1. Clone the document so failures don't leave the model half-edited.
    let mut document = model.document_mut().clone();
    splice_profile(&mut document, model.profile())?;
    document.write_atomic(target)?;
    model.mark_saved(document, target.to_path_buf());
    Ok(target.to_path_buf())
}

/// Splice an edited [`Profile`] into a round-trip [`Document`].
///
/// Locates the `[[profiles]]` entry whose `name` matches `profile.name` and
/// replaces it with a freshly-serialized table. If no entry matches, the new
/// table is appended.
pub fn splice_profile(document: &mut Document, profile: &Profile) -> Result<()> {
    let new_table = profile_to_table(profile)?;
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

    // Find existing.
    let mut found: Option<usize> = None;
    for (i, t) in arr.iter().enumerate() {
        if t.get("name")
            .and_then(|v| v.as_str())
            .is_some_and(|s| s == profile.name)
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
}
