//! Comment-preserving mutators for TOML configs.
//!
//! All mutators operate on [`Document`] (a wrapper around [`toml_edit::DocumentMut`])
//! so user comments and formatting survive `add_profile`, `set_profile_field`,
//! `add_forward`, and `remove_forward`.
//!
//! After mutating, callers use [`Document::write_atomic`] to persist the file
//! atomically via the `atomicwrites` crate.

use std::path::Path;

use spt_core::{Error, Result};
use toml_edit::{value, ArrayOfTables, DocumentMut, Item, Table};

/// A wrapper around [`DocumentMut`] that preserves comments/formatting.
#[derive(Debug, Clone)]
pub struct Document {
    inner: DocumentMut,
}

impl Document {
    /// Parse TOML text into a [`Document`].
    pub fn parse(raw: &str) -> Result<Self> {
        let inner: DocumentMut = raw
            .parse()
            .map_err(|e| Error::InvalidConfig(format!("toml_edit parse: {e}")))?;
        Ok(Self { inner })
    }

    /// Read a config file from disk.
    pub fn read(path: &Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path)
            .map_err(|e| Error::InvalidConfig(format!("read `{}`: {e}", path.display())))?;
        Self::parse(&raw)
    }

    /// Borrow the inner [`DocumentMut`] for advanced operations.
    pub fn document_mut(&mut self) -> &mut DocumentMut {
        &mut self.inner
    }

    /// Atomically write the document to `path` via [`atomicwrites`].
    pub fn write_atomic(&self, path: &Path) -> Result<()> {
        use atomicwrites::{AllowOverwrite, AtomicFile};
        use std::io::Write;

        let af = AtomicFile::new(path, AllowOverwrite);
        let rendered = self.inner.to_string();
        af.write(|f| f.write_all(rendered.as_bytes())).map_err(|e| {
            let io = match e {
                atomicwrites::Error::Internal(io) | atomicwrites::Error::User(io) => io,
            };
            Error::InvalidConfig(format!("atomic write `{}`: {io}", path.display()))
        })
    }

    // ---- Profile-level mutators -------------------------------------------

    /// Add a new profile with the given `name` and `protocol`. Errors if a
    /// profile with that name already exists.
    pub fn add_profile(&mut self, name: &str, protocol: &str) -> Result<()> {
        if self.find_profile_index(name).is_some() {
            return Err(Error::InvalidConfig(format!(
                "profile `{name}` already exists"
            )));
        }
        let arr = self.profiles_array_mut();
        let mut tbl = Table::new();
        tbl["name"] = value(name);
        tbl["protocol"] = value(protocol);
        arr.push(tbl);
        Ok(())
    }

    /// Remove the profile named `name`. Returns `true` if removed.
    pub fn remove_profile(&mut self, name: &str) -> bool {
        let Some(idx) = self.find_profile_index(name) else {
            return false;
        };
        let arr = self.profiles_array_mut();
        arr.remove(idx);
        true
    }

    /// Set a top-level profile field to a string value.
    pub fn set_profile_field(&mut self, profile: &str, field: &str, val: &str) -> Result<()> {
        let idx = self
            .find_profile_index(profile)
            .ok_or_else(|| Error::InvalidConfig(format!("profile `{profile}` does not exist")))?;
        let arr = self.profiles_array_mut();
        let tbl = arr
            .get_mut(idx)
            .ok_or_else(|| Error::InvalidConfig("profile index disappeared".into()))?;
        tbl[field] = value(val);
        Ok(())
    }

    // ---- Forward-level mutators -------------------------------------------

    /// Add a forward to a profile.
    pub fn add_forward(
        &mut self,
        profile: &str,
        name: &str,
        kind: &str,
        transport: &str,
        bind: &str,
        target: &str,
    ) -> Result<()> {
        let idx = self
            .find_profile_index(profile)
            .ok_or_else(|| Error::InvalidConfig(format!("profile `{profile}` does not exist")))?;
        let arr = self.profiles_array_mut();
        let prof_tbl = arr
            .get_mut(idx)
            .ok_or_else(|| Error::InvalidConfig("profile index disappeared".into()))?;

        // Reject duplicate forward name.
        if let Some(Item::ArrayOfTables(forwards)) = prof_tbl.get("forwards") {
            for entry in forwards {
                if entry
                    .get("name")
                    .and_then(|v| v.as_str())
                    .is_some_and(|s| s == name)
                {
                    return Err(Error::InvalidConfig(format!(
                        "forward `{name}` already exists in profile `{profile}`"
                    )));
                }
            }
        }

        let forwards: &mut ArrayOfTables = match prof_tbl
            .entry("forwards")
            .or_insert_with(|| Item::ArrayOfTables(ArrayOfTables::new()))
        {
            Item::ArrayOfTables(arr) => arr,
            _ => {
                return Err(Error::InvalidConfig(
                    "`forwards` exists but is not an array of tables".into(),
                ))
            }
        };

        let mut tbl = Table::new();
        tbl["name"] = value(name);
        tbl["type"] = value(kind);
        tbl["transport"] = value(transport);
        tbl["bind"] = value(bind);
        tbl["target"] = value(target);
        forwards.push(tbl);
        Ok(())
    }

    /// Remove a forward. Returns `Ok(true)` if removed.
    pub fn remove_forward(&mut self, profile: &str, forward: &str) -> Result<bool> {
        let idx = self
            .find_profile_index(profile)
            .ok_or_else(|| Error::InvalidConfig(format!("profile `{profile}` does not exist")))?;
        let arr = self.profiles_array_mut();
        let prof_tbl = arr
            .get_mut(idx)
            .ok_or_else(|| Error::InvalidConfig("profile index disappeared".into()))?;
        let Some(Item::ArrayOfTables(forwards)) = prof_tbl.get_mut("forwards") else {
            return Ok(false);
        };
        let mut found: Option<usize> = None;
        for (i, entry) in forwards.iter().enumerate() {
            if entry
                .get("name")
                .and_then(|v| v.as_str())
                .is_some_and(|s| s == forward)
            {
                found = Some(i);
                break;
            }
        }
        if let Some(i) = found {
            forwards.remove(i);
            Ok(true)
        } else {
            Ok(false)
        }
    }

    // ---- Internals --------------------------------------------------------

    fn profiles_array_mut(&mut self) -> &mut ArrayOfTables {
        let entry = self
            .inner
            .entry("profiles")
            .or_insert_with(|| Item::ArrayOfTables(ArrayOfTables::new()));
        match entry {
            Item::ArrayOfTables(arr) => arr,
            _ => unreachable!("profiles must be an array of tables"),
        }
    }

    fn find_profile_index(&self, name: &str) -> Option<usize> {
        let item = self.inner.get("profiles")?;
        let Item::ArrayOfTables(arr) = item else {
            return None;
        };
        for (i, t) in arr.iter().enumerate() {
            if t.get("name")
                .and_then(|v| v.as_str())
                .is_some_and(|s| s == name)
            {
                return Some(i);
            }
        }
        None
    }
}

/// Friendly trait impl for `print!` etc.
impl std::fmt::Display for Document {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.inner.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::Document;

    const RAW: &str = r#"# header comment
version = 1

[[profiles]]
# profile comment
name = "p"
protocol = "ssh2"
host = "h"
"#;

    #[test]
    fn comment_preserved_after_mutation() {
        let mut doc = Document::parse(RAW).unwrap();
        doc.set_profile_field("p", "user", "alice").unwrap();
        let out = doc.to_string();
        assert!(out.contains("# header comment"));
        assert!(out.contains("# profile comment"));
        assert!(out.contains(r#"user = "alice""#));
    }

    #[test]
    fn add_profile_unique() {
        let mut doc = Document::parse(RAW).unwrap();
        doc.add_profile("q", "ssh2").unwrap();
        assert!(doc.add_profile("q", "ssh2").is_err());
        let out = doc.to_string();
        assert!(out.contains(r#"name = "q""#));
    }

    #[test]
    fn add_and_remove_forward() {
        let mut doc = Document::parse(RAW).unwrap();
        doc.add_forward("p", "f1", "local", "tcp", "127.0.0.1:1", "x:22")
            .unwrap();
        let out = doc.to_string();
        assert!(out.contains(r#"name = "f1""#));
        assert!(doc
            .add_forward("p", "f1", "local", "tcp", "x", "y")
            .is_err());
        assert!(doc.remove_forward("p", "f1").unwrap());
        assert!(!doc.remove_forward("p", "f1").unwrap());
    }

    #[test]
    fn remove_profile() {
        let mut doc = Document::parse(RAW).unwrap();
        assert!(doc.remove_profile("p"));
        assert!(!doc.remove_profile("p"));
    }

    #[test]
    fn write_atomic_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("c.toml");
        let mut doc = Document::parse(RAW).unwrap();
        doc.set_profile_field("p", "user", "alice").unwrap();
        doc.write_atomic(&path).unwrap();
        let read = std::fs::read_to_string(&path).unwrap();
        assert!(read.contains("alice"));
    }
}
