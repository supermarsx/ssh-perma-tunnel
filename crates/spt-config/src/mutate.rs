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

/// Parameters for adding one `[[profiles.sftp_mounts]]` entry.
#[derive(Debug, Clone, Copy)]
pub struct SftpMountMutation<'a> {
    /// Owning profile.
    pub profile: &'a str,
    /// Mount name.
    pub name: &'a str,
    /// Remote SFTP path.
    pub remote_path: &'a str,
    /// Local filesystem mount point.
    pub mount_point: Option<&'a str>,
    /// Windows drive letter.
    pub drive_letter: Option<&'a str>,
    /// Read-only mount flag.
    pub read_only: bool,
    /// Cache mode.
    pub cache: Option<&'a str>,
}

impl Document {
    /// Parse TOML text into a [`Document`].
    pub fn parse(raw: &str) -> Result<Self> {
        let inner: DocumentMut = raw.parse().map_err(|e| {
            Error::invalid_config(
                spt_core::Diagnostic::what("Failed to parse config for in-place edit")
                    .why(format!("toml_edit could not parse the document: {e}"))
                    .how_to_fix(
                        "Fix TOML syntax errors before running mutating subcommands like \
                         `spt config set`, `spt profile add`, etc.",
                    )
                    .build(),
            )
        })?;
        Ok(Self { inner })
    }

    /// Read a config file from disk.
    pub fn read(path: &Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path).map_err(|e| {
            Error::invalid_config(
                spt_core::Diagnostic::what(format!(
                    "Failed to read config file `{}` for in-place edit",
                    path.display()
                ))
                .why(format!("{e}"))
                .how_to_fix("Verify the file exists and the calling user has read access.")
                .file_path(path)
                .build(),
            )
        })?;
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
            Error::invalid_config(
                spt_core::Diagnostic::what(format!(
                    "Failed to atomically write config to `{}`",
                    path.display()
                ))
                .why(format!("{io}"))
                .how_to_fix(
                    "Check disk space, the file's permissions, and that the parent \
                     directory is writable (atomic writes rename a sibling tempfile).",
                )
                .file_path(path)
                .build(),
            )
        })
    }

    // ---- Profile-level mutators -------------------------------------------

    /// Add a new profile with the given `name` and `protocol`. Errors if a
    /// profile with that name already exists.
    pub fn add_profile(&mut self, name: &str, protocol: &str) -> Result<()> {
        if self.find_profile_index(name).is_some() {
            return Err(Error::invalid_config(
                spt_core::Diagnostic::what(format!(
                    "Profile `{name}` already exists in config"
                ))
                .why("profile names must be unique within a single config file or merged config dir")
                .how_to_fix(format!(
                    "Pick a different name, or delete the existing profile first \
                     (`spt profile remove {name}`).",
                ))
                .build(),
            ));
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

    /// Set a top-level profile field, preserving the value's TOML type.
    ///
    /// M3: the value string is coerced to its natural TOML type
    /// (`bool` / integer / float / string) via [`coerce_toml_value`] so a typed
    /// field — e.g. `acknowledge_experimental` (bool) or a numeric field — is
    /// written as the correct type rather than always as a quoted string (which
    /// would fail to deserialize on the next load). Renaming via `field ==
    /// "name"` is rejected when the new name collides with another profile, so
    /// `set` can never create a duplicate-name config (mirrors `add_profile`).
    pub fn set_profile_field(&mut self, profile: &str, field: &str, val: &str) -> Result<()> {
        let idx = self.find_profile_index(profile).ok_or_else(|| {
            Error::invalid_config(
                spt_core::Diagnostic::what(format!(
                    "Profile `{profile}` does not exist"
                ))
                .why(format!("no `[[profiles]]` entry has `name = \"{profile}\"`"))
                .how_to_fix(
                    "Run `spt profile list` to see the available profiles, or `spt profile add` \
                     to create one first.",
                )
                .build(),
            )
        })?;
        // M3: reject a rename that would collide with an existing profile name.
        if field == "name" && val != profile {
            if let Some(other) = self.find_profile_index(val) {
                if other != idx {
                    return Err(Error::invalid_config(
                        spt_core::Diagnostic::what(format!(
                            "Cannot rename profile `{profile}` to `{val}`"
                        ))
                        .why(
                            "another `[[profiles]]` entry already uses that name; profile \
                             names must be unique within a config",
                        )
                        .how_to_fix(format!(
                            "Pick a different name, or remove the existing `{val}` profile first \
                             (`spt profile remove {val}`).",
                        ))
                        .build(),
                    ));
                }
            }
        }
        let coerced = coerce_toml_value(field, val);
        let arr = self.profiles_array_mut();
        let tbl = arr.get_mut(idx).ok_or_else(|| {
            Error::invalid_config(
                spt_core::Diagnostic::what("Internal: profile index disappeared mid-edit")
                    .why("the profile was found but the underlying ArrayOfTables shrank")
                    .how_to_fix(
                        "Retry the command. If the failure persists, file a bug — this \
                         indicates a concurrent mutation of the in-memory document.",
                    )
                    .build(),
            )
        })?;
        tbl[field] = coerced;
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
                    return Err(Error::invalid_config(
                        spt_core::Diagnostic::what(format!(
                            "Forward `{name}` already exists in profile `{profile}`"
                        ))
                        .why("forward names must be unique within a profile")
                        .how_to_fix(format!(
                            "Pick a different forward name, or remove the existing one with \
                             `spt forward remove --profile {profile} --name {name}`.",
                        ))
                        .build(),
                    ));
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

    /// Add an SFTP-backed mount to a profile.
    pub fn add_sftp_mount(&mut self, spec: SftpMountMutation<'_>) -> Result<()> {
        let idx = self.find_profile_index(spec.profile).ok_or_else(|| {
            Error::InvalidConfig(format!("profile `{}` does not exist", spec.profile))
        })?;
        let arr = self.profiles_array_mut();
        let prof_tbl = arr
            .get_mut(idx)
            .ok_or_else(|| Error::InvalidConfig("profile index disappeared".into()))?;

        if let Some(Item::ArrayOfTables(mounts)) = prof_tbl.get("sftp_mounts") {
            for entry in mounts {
                if entry
                    .get("name")
                    .and_then(|v| v.as_str())
                    .is_some_and(|s| s == spec.name)
                {
                    return Err(Error::InvalidConfig(format!(
                        "SFTP mount `{}` already exists in profile `{}`",
                        spec.name, spec.profile
                    )));
                }
            }
        }

        let mounts: &mut ArrayOfTables = match prof_tbl
            .entry("sftp_mounts")
            .or_insert_with(|| Item::ArrayOfTables(ArrayOfTables::new()))
        {
            Item::ArrayOfTables(arr) => arr,
            _ => {
                return Err(Error::InvalidConfig(
                    "`sftp_mounts` exists but is not an array of tables".into(),
                ))
            }
        };

        let mut tbl = Table::new();
        tbl["name"] = value(spec.name);
        tbl["remote_path"] = value(spec.remote_path);
        if let Some(mount_point) = spec.mount_point {
            tbl["mount_point"] = value(mount_point);
        }
        if let Some(drive_letter) = spec.drive_letter {
            tbl["drive_letter"] = value(drive_letter);
        }
        tbl["read_only"] = value(spec.read_only);
        if let Some(cache) = spec.cache {
            tbl["cache"] = value(cache);
        }
        mounts.push(tbl);
        Ok(())
    }

    /// Remove an SFTP-backed mount. Returns `Ok(true)` if removed.
    pub fn remove_sftp_mount(&mut self, profile: &str, mount: &str) -> Result<bool> {
        let idx = self
            .find_profile_index(profile)
            .ok_or_else(|| Error::InvalidConfig(format!("profile `{profile}` does not exist")))?;
        let arr = self.profiles_array_mut();
        let prof_tbl = arr
            .get_mut(idx)
            .ok_or_else(|| Error::InvalidConfig("profile index disappeared".into()))?;
        let Some(Item::ArrayOfTables(mounts)) = prof_tbl.get_mut("sftp_mounts") else {
            return Ok(false);
        };
        let mut found: Option<usize> = None;
        for (i, entry) in mounts.iter().enumerate() {
            if entry
                .get("name")
                .and_then(|v| v.as_str())
                .is_some_and(|s| s == mount)
            {
                found = Some(i);
                break;
            }
        }
        if let Some(i) = found {
            mounts.remove(i);
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

/// Declared scalar type of a top-level `[[profiles]]` field, used to drive
/// type-correct coercion in [`coerce_toml_value`]. Fields not listed here
/// (string-typed fields like `host`/`user`/`endpoint`, and any unknown key)
/// are treated as [`ScalarKind::Str`] and written verbatim — never
/// numerically reinterpreted.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ScalarKind {
    /// Boolean-typed field (`enabled`, `acknowledge_experimental`, ...).
    Bool,
    /// Integer-typed field (`port`).
    Int,
    /// String-typed field (default): keep the value verbatim.
    Str,
}

/// Declared scalar type of a top-level `[[profiles]]` field per the schema
/// (`spt_config::schema::Profile`). Only `bool`- and integer-typed fields are
/// listed; everything else (string fields and unknown keys) falls through to
/// [`ScalarKind::Str`].
fn profile_field_kind(field: &str) -> ScalarKind {
    match field {
        // `Option<bool>` fields on `Profile`.
        "enabled" | "acknowledge_experimental" | "network_change_reconnect" => ScalarKind::Bool,
        // `Option<u16>` field on `Profile`.
        "port" => ScalarKind::Int,
        // `name`, `host`, `user`, `endpoint`, `protocol`, `connect_timeout`,
        // `dns_resolution`, `startup`, `failure_policy`, `description`, and any
        // unrecognized key are string-destined → keep verbatim.
        _ => ScalarKind::Str,
    }
}

/// Coerce a CLI-supplied string into the TOML value type declared by the
/// target field's schema (M-4).
///
/// `spt config set` passes every value as a string, but writing a typed field
/// as a quoted string corrupts the config (e.g. `acknowledge_experimental =
/// "true"` fails to deserialize as a bool). Coercion is **schema-driven**: it
/// consults [`profile_field_kind`] for the target field's declared type and
/// only narrows to `bool` / integer when that is the field's actual type. A
/// string-typed field (or any unknown key) keeps the verbatim string — so
/// `spt config set p user 0123` stays `user = "0123"` (no leading-zero loss,
/// no type flip) and `spt config set p host 123` stays `host = "123"`. A
/// bool-typed field only narrows for the literal `true`/`false`; anything else
/// is preserved verbatim.
fn coerce_toml_value(field: &str, val: &str) -> Item {
    match profile_field_kind(field) {
        ScalarKind::Bool => match val {
            "true" => value(true),
            "false" => value(false),
            // Not a bool literal — keep verbatim rather than guess.
            _ => value(val),
        },
        ScalarKind::Int => match val.parse::<i64>() {
            Ok(i) => value(i),
            // Not parseable as an integer — keep verbatim (validation will
            // surface the type error rather than us silently mangling it).
            Err(_) => value(val),
        },
        ScalarKind::Str => value(val),
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
    use super::{Document, SftpMountMutation};

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
    fn add_and_remove_sftp_mount() {
        let mut doc = Document::parse(RAW).unwrap();
        doc.add_sftp_mount(SftpMountMutation {
            profile: "p",
            name: "data",
            remote_path: "/srv/data",
            mount_point: Some("/mnt/data"),
            drive_letter: None,
            read_only: true,
            cache: Some("metadata"),
        })
        .unwrap();
        let out = doc.to_string();
        assert!(out.contains(r#"name = "data""#));
        assert!(out.contains(r#"remote_path = "/srv/data""#));
        assert!(out.contains(r#"mount_point = "/mnt/data""#));
        assert!(doc
            .add_sftp_mount(SftpMountMutation {
                profile: "p",
                name: "data",
                remote_path: "/srv/data",
                mount_point: Some("/mnt/data"),
                drive_letter: None,
                read_only: true,
                cache: None,
            })
            .is_err());
        assert!(doc.remove_sftp_mount("p", "data").unwrap());
        assert!(!doc.remove_sftp_mount("p", "data").unwrap());
    }

    #[test]
    fn remove_profile() {
        let mut doc = Document::parse(RAW).unwrap();
        assert!(doc.remove_profile("p"));
        assert!(!doc.remove_profile("p"));
    }

    #[test]
    fn set_field_preserves_bool_type() {
        // M3: a bool value must be written as a TOML boolean, not a string
        // (a quoted "true" fails to deserialize as a bool on next load).
        let mut doc = Document::parse(RAW).unwrap();
        doc.set_profile_field("p", "acknowledge_experimental", "true")
            .unwrap();
        let out = doc.to_string();
        assert!(
            out.contains("acknowledge_experimental = true"),
            "bool not preserved: {out}"
        );
        assert!(!out.contains(r#"acknowledge_experimental = "true""#));
    }

    #[test]
    fn set_field_preserves_integer_type() {
        // M3/M-4: an integer-typed schema field (`port`) must be written as a
        // TOML integer, not a quoted string.
        let mut doc = Document::parse(RAW).unwrap();
        doc.set_profile_field("p", "port", "2222").unwrap();
        let out = doc.to_string();
        assert!(out.contains("port = 2222"), "int not preserved: {out}");
        assert!(!out.contains(r#"port = "2222""#));
    }

    #[test]
    fn set_field_keeps_string_for_textual_values() {
        let mut doc = Document::parse(RAW).unwrap();
        doc.set_profile_field("p", "host", "bastion.example.com")
            .unwrap();
        let out = doc.to_string();
        assert!(out.contains(r#"host = "bastion.example.com""#));
    }

    // ──────── M-4: schema-driven coercion (no string-field over-coercion) ────

    #[test]
    fn set_string_field_numeric_value_keeps_leading_zero_string() {
        // M-4 regression: `user` is a STRING-typed field. A numeric-looking
        // value like `0123` must NOT be coerced to the integer `123` (which
        // drops the leading zero AND flips the type so the next load fails to
        // deserialize the `String` field). Fails against the over-coercing
        // code; passes after the schema-driven fix.
        let mut doc = Document::parse(RAW).unwrap();
        doc.set_profile_field("p", "user", "0123").unwrap();
        let out = doc.to_string();
        assert!(
            out.contains(r#"user = "0123""#),
            "string field over-coerced: {out}"
        );
        assert!(!out.contains("user = 123"), "user flipped to int: {out}");
    }

    #[test]
    fn set_string_field_plain_integer_stays_string() {
        // M-4 regression: `host` is string-typed; a bare `123` must stay the
        // string "123", not become the integer 123.
        let mut doc = Document::parse(RAW).unwrap();
        doc.set_profile_field("p", "host", "123").unwrap();
        let out = doc.to_string();
        assert!(out.contains(r#"host = "123""#), "host coerced: {out}");
        assert!(!out.contains("host = 123\n"), "host flipped to int: {out}");
    }

    #[test]
    fn set_string_field_bool_literal_stays_string() {
        // M-4 regression: a string-typed field whose value happens to be
        // `true`/`false` must remain a quoted string (a user literally named
        // "true" is a string, not a bool).
        let mut doc = Document::parse(RAW).unwrap();
        doc.set_profile_field("p", "user", "true").unwrap();
        let out = doc.to_string();
        assert!(
            out.contains(r#"user = "true""#),
            "user coerced to bool: {out}"
        );
    }

    #[test]
    fn set_int_field_non_numeric_value_stays_string() {
        // M-4: an int-typed field given a non-numeric value is preserved
        // verbatim (validation surfaces the type error, we don't mangle it).
        let mut doc = Document::parse(RAW).unwrap();
        doc.set_profile_field("p", "port", "auto").unwrap();
        let out = doc.to_string();
        assert!(out.contains(r#"port = "auto""#), "port mangled: {out}");
    }

    #[test]
    fn set_bool_field_non_bool_value_stays_string() {
        // M-4: a bool-typed field given a non-bool value is preserved verbatim
        // rather than guessed.
        let mut doc = Document::parse(RAW).unwrap();
        doc.set_profile_field("p", "enabled", "maybe").unwrap();
        let out = doc.to_string();
        assert!(
            out.contains(r#"enabled = "maybe""#),
            "enabled mangled: {out}"
        );
    }

    #[test]
    fn set_name_stays_string_even_if_numeric() {
        // M3: `name` is an identifier — never coerced to an int, even "123".
        let mut doc = Document::parse(RAW).unwrap();
        doc.set_profile_field("p", "name", "123").unwrap();
        let out = doc.to_string();
        assert!(
            out.contains(r#"name = "123""#),
            "name coerced wrongly: {out}"
        );
    }

    #[test]
    fn rename_to_existing_name_rejected() {
        // M3: renaming a profile onto another profile's name must be rejected.
        let mut doc = Document::parse(RAW).unwrap();
        doc.add_profile("q", "ssh2").unwrap();
        let err = doc.set_profile_field("p", "name", "q").unwrap_err();
        assert!(
            format!("{err}").contains("Cannot rename"),
            "unexpected error: {err}"
        );
        // The original name is untouched.
        let out = doc.to_string();
        assert!(out.contains(r#"name = "p""#));
    }

    #[test]
    fn rename_to_unique_name_allowed() {
        let mut doc = Document::parse(RAW).unwrap();
        doc.set_profile_field("p", "name", "renamed").unwrap();
        let out = doc.to_string();
        assert!(out.contains(r#"name = "renamed""#));
    }

    #[test]
    fn rename_to_self_is_noop_allowed() {
        // Setting name to the current name must not be rejected as a duplicate.
        let mut doc = Document::parse(RAW).unwrap();
        doc.set_profile_field("p", "name", "p").unwrap();
        let out = doc.to_string();
        assert!(out.contains(r#"name = "p""#));
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
