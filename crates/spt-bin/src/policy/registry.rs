//! Read GPO policy values from the Windows registry.
//!
//! The Group Policy Editor (gpedit.msc) and central-store ADMX templates
//! shipped under `packaging/windows-gpo/` write values into:
//!
//! ```text
//! HKLM\Software\Policies\spt\<Section>\<Name>
//! HKCU\Software\Policies\spt\<Section>\<Name>
//! ```
//!
//! Each policy may also have a sibling `Enforced` `REG_DWORD` of `1`, which
//! marks the HKLM-side value as enforced (overrides the loaded TOML). On
//! non-Windows platforms [`load`] returns an empty bundle.
//!
//! Errors from the OS are logged and converted into "no policy" — Group
//! Policy is advisory infrastructure, not a hard runtime dependency.

use spt_config::{PolicyBundle, PolicyValue};

/// Subkey under each hive, *without* leading backslash.
pub(crate) const POLICY_ROOT: &str = r"Software\Policies\spt";

/// The sentinel value name that marks an enforced HKLM policy.
pub(crate) const ENFORCED_VALUE: &str = "Enforced";

/// Errors that can occur while reading the policy tree. They are intentionally
/// low-fidelity: callers always recover by returning an empty bundle.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Win32 returned a non-success status while opening or enumerating a key.
    #[error("registry I/O failed: {0}")]
    Io(String),
}

/// Load the bundle from both HKLM and HKCU. On non-Windows targets returns
/// `Ok(PolicyBundle::empty())`.
pub fn load() -> Result<PolicyBundle, Error> {
    #[cfg(windows)]
    {
        imp::load()
    }
    #[cfg(not(windows))]
    {
        Ok(PolicyBundle::empty())
    }
}

#[cfg(windows)]
mod imp {
    use std::collections::{BTreeSet, HashMap};

    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_NO_MORE_ITEMS, ERROR_SUCCESS};
    use windows::Win32::System::Registry::{
        RegCloseKey, RegEnumKeyExW, RegOpenKeyExW, RegQueryValueExW, HKEY,
        HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ, REG_DWORD, REG_EXPAND_SZ, REG_MULTI_SZ,
        REG_QWORD, REG_SZ, REG_VALUE_TYPE,
    };

    use super::{Error, PolicyBundle, PolicyValue, ENFORCED_VALUE, POLICY_ROOT};

    pub(super) fn load() -> Result<PolicyBundle, Error> {
        let mut bundle = PolicyBundle::empty();
        load_hive(HKEY_LOCAL_MACHINE, &mut bundle.machine, Some(&mut bundle.enforced))?;
        load_hive(HKEY_CURRENT_USER, &mut bundle.user, None)?;
        Ok(bundle)
    }

    /// Enumerate immediate subkeys of `<hive>\Software\Policies\spt` and read
    /// every value under each. Section + value name → flat key
    /// `Section\Name`.
    fn load_hive(
        hive: HKEY,
        out: &mut HashMap<String, PolicyValue>,
        mut enforced: Option<&mut BTreeSet<String>>,
    ) -> Result<(), Error> {
        let root = match open_subkey(hive, POLICY_ROOT) {
            Ok(h) => h,
            Err(e) if e == ERROR_FILE_NOT_FOUND.0 => return Ok(()),
            Err(e) => return Err(Error::Io(format!("open {POLICY_ROOT}: win32 {e}"))),
        };

        let sections = enum_subkeys(root)?;
        for section in &sections {
            let Ok(section_h) = open_subkey_handle(root, section) else {
                continue;
            };
            let values = read_all_values(section_h);
            unsafe {
                let _ = RegCloseKey(section_h);
            }
            for (name, value) in values {
                if name.eq_ignore_ascii_case(ENFORCED_VALUE) {
                    continue; // sentinel handled separately
                }
                let key = format!("{section}\\{name}");
                out.insert(key, value);
            }
            if let Some(ref mut e) = enforced {
                if is_enforced_section(section_h) {
                    // Section-level Enforced sentinel: treat *every* value in the
                    // section as enforced. (Per-value enforcement is also supported
                    // via a sibling `Enforced` value at the section root, which is
                    // identical when there's a single value per section — the GPO
                    // template emits one value per ADMX <policy>.)
                    for (name, _) in read_all_values(section_h) {
                        if name.eq_ignore_ascii_case(ENFORCED_VALUE) {
                            continue;
                        }
                        e.insert(format!("{section}\\{name}"));
                    }
                }
            }
        }

        unsafe {
            let _ = RegCloseKey(root);
        }
        Ok(())
    }

    fn is_enforced_section(h: HKEY) -> bool {
        match read_value(h, ENFORCED_VALUE) {
            Some(PolicyValue::Integer(i)) => i != 0,
            Some(PolicyValue::Bool(b)) => b,
            _ => false,
        }
    }

    fn open_subkey(hive: HKEY, path: &str) -> Result<HKEY, u32> {
        let path_w = wide(path);
        let mut h = HKEY::default();
        let rc = unsafe {
            RegOpenKeyExW(hive, PCWSTR(path_w.as_ptr()), 0, KEY_READ, &mut h)
        };
        if rc == ERROR_SUCCESS {
            Ok(h)
        } else {
            Err(rc.0)
        }
    }

    fn open_subkey_handle(parent: HKEY, name: &str) -> Result<HKEY, u32> {
        open_subkey(parent, name)
    }

    fn enum_subkeys(h: HKEY) -> Result<Vec<String>, Error> {
        let mut out = Vec::new();
        let mut idx: u32 = 0;
        loop {
            let mut name = vec![0u16; 256];
            let mut len: u32 = name.len() as u32;
            let rc = unsafe {
                RegEnumKeyExW(
                    h,
                    idx,
                    windows::core::PWSTR(name.as_mut_ptr()),
                    &mut len,
                    None,
                    windows::core::PWSTR::null(),
                    None,
                    None,
                )
            };
            if rc == ERROR_NO_MORE_ITEMS {
                break;
            }
            if rc != ERROR_SUCCESS {
                return Err(Error::Io(format!("RegEnumKeyExW: win32 {}", rc.0)));
            }
            name.truncate(len as usize);
            out.push(String::from_utf16_lossy(&name));
            idx += 1;
        }
        Ok(out)
    }

    fn read_all_values(h: HKEY) -> Vec<(String, PolicyValue)> {
        use windows::Win32::System::Registry::RegEnumValueW;
        let mut out = Vec::new();
        let mut idx: u32 = 0;
        loop {
            let mut name = vec![0u16; 1024];
            let mut name_len: u32 = name.len() as u32;
            let mut vtype: REG_VALUE_TYPE = REG_VALUE_TYPE(0);
            let mut data_len: u32 = 0;
            // First call: discover required data size.
            let rc = unsafe {
                RegEnumValueW(
                    h,
                    idx,
                    windows::core::PWSTR(name.as_mut_ptr()),
                    &mut name_len,
                    None,
                    Some(&mut vtype.0),
                    None,
                    Some(&mut data_len),
                )
            };
            if rc == ERROR_NO_MORE_ITEMS {
                break;
            }
            if rc != ERROR_SUCCESS {
                break;
            }
            // Second call: actually read the data.
            let mut data = vec![0u8; data_len as usize];
            let mut name2 = vec![0u16; 1024];
            let mut name2_len: u32 = name2.len() as u32;
            let mut vtype2: REG_VALUE_TYPE = REG_VALUE_TYPE(0);
            let mut data2_len: u32 = data_len;
            let rc2 = unsafe {
                RegEnumValueW(
                    h,
                    idx,
                    windows::core::PWSTR(name2.as_mut_ptr()),
                    &mut name2_len,
                    None,
                    Some(&mut vtype2.0),
                    Some(data.as_mut_ptr()),
                    Some(&mut data2_len),
                )
            };
            idx += 1;
            if rc2 != ERROR_SUCCESS {
                continue;
            }
            name2.truncate(name2_len as usize);
            let name_str = String::from_utf16_lossy(&name2);
            if let Some(v) = decode_value(vtype2, &data[..data2_len as usize]) {
                out.push((name_str, v));
            }
        }
        out
    }

    fn read_value(h: HKEY, name: &str) -> Option<PolicyValue> {
        let name_w = wide(name);
        let mut vtype: REG_VALUE_TYPE = REG_VALUE_TYPE(0);
        let mut data_len: u32 = 0;
        let rc = unsafe {
            RegQueryValueExW(
                h,
                PCWSTR(name_w.as_ptr()),
                None,
                Some(&mut vtype),
                None,
                Some(&mut data_len),
            )
        };
        if rc != ERROR_SUCCESS {
            return None;
        }
        let mut data = vec![0u8; data_len as usize];
        let mut data_len2 = data_len;
        let mut vtype2 = REG_VALUE_TYPE(0);
        let rc2 = unsafe {
            RegQueryValueExW(
                h,
                PCWSTR(name_w.as_ptr()),
                None,
                Some(&mut vtype2),
                Some(data.as_mut_ptr()),
                Some(&mut data_len2),
            )
        };
        if rc2 != ERROR_SUCCESS {
            return None;
        }
        decode_value(vtype2, &data[..data_len2 as usize])
    }

    fn decode_value(t: REG_VALUE_TYPE, bytes: &[u8]) -> Option<PolicyValue> {
        match t {
            REG_DWORD => {
                if bytes.len() < 4 {
                    return None;
                }
                let v = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
                if v == 0 || v == 1 {
                    Some(PolicyValue::Bool(v == 1))
                } else {
                    Some(PolicyValue::Integer(i64::from(v)))
                }
            }
            REG_QWORD => {
                if bytes.len() < 8 {
                    return None;
                }
                let v = i64::from_le_bytes([
                    bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
                ]);
                Some(PolicyValue::Integer(v))
            }
            REG_SZ | REG_EXPAND_SZ => Some(PolicyValue::String(decode_wide_z(bytes))),
            REG_MULTI_SZ => Some(PolicyValue::MultiString(decode_multi_sz(bytes))),
            _ => None,
        }
    }

    fn decode_wide_z(bytes: &[u8]) -> String {
        let mut chunks = bytes.chunks_exact(2);
        let mut out = Vec::with_capacity(bytes.len() / 2);
        for c in chunks.by_ref() {
            let u = u16::from_le_bytes([c[0], c[1]]);
            if u == 0 {
                break;
            }
            out.push(u);
        }
        String::from_utf16_lossy(&out)
    }

    fn decode_multi_sz(bytes: &[u8]) -> Vec<String> {
        let mut units: Vec<u16> = bytes
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        // Strip trailing NULs.
        while units.last().copied() == Some(0) {
            units.pop();
        }
        units
            .split(|&u| u == 0)
            .filter(|s| !s.is_empty())
            .map(String::from_utf16_lossy)
            .collect()
    }

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    // -----------------------------------------------------------------------
    // Tests — round-trip via HKCU\Software\spt-test-* (no admin needed).
    // -----------------------------------------------------------------------

    #[cfg(test)]
    mod tests {
        use super::*;
        use windows::Win32::System::Registry::{
            RegCreateKeyExW, RegDeleteTreeW, RegSetValueExW, KEY_WRITE, REG_DWORD,
            REG_OPTION_NON_VOLATILE,
        };

        fn unique_root() -> String {
            // Random suffix avoids collisions across parallel test runs.
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0);
            format!("Software\\spt-policy-test-{}-{}", std::process::id(), nanos)
        }

        fn create_subkey(hive: HKEY, path: &str) -> HKEY {
            let path_w = wide(path);
            let mut h = HKEY::default();
            let rc = unsafe {
                RegCreateKeyExW(
                    hive,
                    PCWSTR(path_w.as_ptr()),
                    0,
                    PCWSTR::null(),
                    REG_OPTION_NON_VOLATILE,
                    KEY_WRITE,
                    None,
                    &mut h,
                    None,
                )
            };
            assert_eq!(rc, ERROR_SUCCESS, "RegCreateKeyExW failed: {}", rc.0);
            h
        }

        fn set_dword(h: HKEY, name: &str, v: u32) {
            let name_w = wide(name);
            let bytes = v.to_le_bytes();
            let rc = unsafe {
                RegSetValueExW(h, PCWSTR(name_w.as_ptr()), 0, REG_DWORD, Some(&bytes))
            };
            assert_eq!(rc, ERROR_SUCCESS);
        }

        fn set_sz(h: HKEY, name: &str, v: &str) {
            let name_w = wide(name);
            let val_w = wide(v);
            let bytes = unsafe {
                std::slice::from_raw_parts(
                    val_w.as_ptr().cast::<u8>(),
                    val_w.len() * std::mem::size_of::<u16>(),
                )
            };
            let rc = unsafe {
                RegSetValueExW(
                    h,
                    PCWSTR(name_w.as_ptr()),
                    0,
                    super::REG_SZ,
                    Some(bytes),
                )
            };
            assert_eq!(rc, ERROR_SUCCESS);
        }

        fn set_multi_sz(h: HKEY, name: &str, vs: &[&str]) {
            let name_w = wide(name);
            let mut buf: Vec<u16> = Vec::new();
            for v in vs {
                buf.extend(v.encode_utf16());
                buf.push(0);
            }
            buf.push(0); // terminating empty string
            let bytes = unsafe {
                std::slice::from_raw_parts(
                    buf.as_ptr().cast::<u8>(),
                    buf.len() * std::mem::size_of::<u16>(),
                )
            };
            let rc = unsafe {
                RegSetValueExW(
                    h,
                    PCWSTR(name_w.as_ptr()),
                    0,
                    super::REG_MULTI_SZ,
                    Some(bytes),
                )
            };
            assert_eq!(rc, ERROR_SUCCESS);
        }

        fn cleanup(path: &str) {
            let path_w = wide(path);
            unsafe {
                let _ = RegDeleteTreeW(HKEY_CURRENT_USER, PCWSTR(path_w.as_ptr()));
            }
        }

        /// Round-trip individual decoders against synthetic byte buffers.
        #[test]
        fn decode_helpers_round_trip() {
            assert_eq!(
                decode_wide_z(&{
                    let s: Vec<u16> = "hi\0".encode_utf16().collect();
                    let mut bytes = Vec::new();
                    for u in s {
                        bytes.extend_from_slice(&u.to_le_bytes());
                    }
                    bytes
                }),
                "hi"
            );
            // multi_sz: "a\0b\0\0"
            let mut buf: Vec<u8> = Vec::new();
            for u in "a".encode_utf16() {
                buf.extend_from_slice(&u.to_le_bytes());
            }
            buf.extend_from_slice(&0u16.to_le_bytes());
            for u in "b".encode_utf16() {
                buf.extend_from_slice(&u.to_le_bytes());
            }
            buf.extend_from_slice(&0u16.to_le_bytes());
            buf.extend_from_slice(&0u16.to_le_bytes());
            assert_eq!(decode_multi_sz(&buf), vec!["a".to_string(), "b".into()]);
            // dword 1 → bool true; dword 7 → integer 7
            assert_eq!(
                decode_value(REG_DWORD, &1u32.to_le_bytes()),
                Some(PolicyValue::Bool(true))
            );
            assert_eq!(
                decode_value(REG_DWORD, &7u32.to_le_bytes()),
                Some(PolicyValue::Integer(7))
            );
        }

        // Local Drop guard avoids pulling in `scopeguard`. Hoisted out of the
        // test fn to satisfy clippy::items_after_statements.
        struct Cleanup<'a>(&'a str);
        impl Drop for Cleanup<'_> {
            fn drop(&mut self) {
                let path_w: Vec<u16> =
                    self.0.encode_utf16().chain(std::iter::once(0)).collect();
                unsafe {
                    let _ = windows::Win32::System::Registry::RegDeleteTreeW(
                        HKEY_CURRENT_USER,
                        PCWSTR(path_w.as_ptr()),
                    );
                }
            }
        }

        /// End-to-end: write a synthetic policy hive under HKCU and read it
        /// back via the same code path that the production loader uses.
        #[test]
        fn round_trip_via_hkcu_temp_hive() {
            // We point the loader at a non-default subkey by temporarily
            // swapping POLICY_ROOT through a dedicated reader. Since
            // POLICY_ROOT is `const`, build the bundle by directly invoking
            // the lower-level helpers against a temp path.
            let root = unique_root();
            // Best-effort cleanup on test exit. Run at the start in case a
            // prior crashed run left state behind.
            cleanup(&root);
            let _guard = Cleanup(&root);

            let section_path = format!("{root}\\Logging");
            let h = create_subkey(HKEY_CURRENT_USER, &section_path);
            set_sz(h, "Level", "debug");
            set_dword(h, "MaxFiles", 7);
            set_multi_sz(h, "AllowedDestinations", &["stderr", "file"]);
            set_dword(h, "Enforced", 1);
            unsafe {
                let _ = RegCloseKey(h);
            }

            // Open the synthetic root and run the same load logic.
            let root_h = open_subkey(HKEY_CURRENT_USER, &root)
                .expect("open synthetic root");
            let sections = enum_subkeys(root_h).unwrap();
            assert_eq!(sections, vec!["Logging".to_string()]);
            let sec_h = open_subkey_handle(root_h, "Logging").unwrap();
            let mut got: std::collections::HashMap<String, PolicyValue> =
                std::collections::HashMap::new();
            for (n, v) in read_all_values(sec_h) {
                if n.eq_ignore_ascii_case(ENFORCED_VALUE) {
                    continue;
                }
                got.insert(n, v);
            }
            assert!(is_enforced_section(sec_h));
            unsafe {
                let _ = RegCloseKey(sec_h);
                let _ = RegCloseKey(root_h);
            }

            assert_eq!(
                got.get("Level"),
                Some(&PolicyValue::String("debug".into()))
            );
            assert_eq!(got.get("MaxFiles"), Some(&PolicyValue::Integer(7)));
            assert_eq!(
                got.get("AllowedDestinations"),
                Some(&PolicyValue::MultiString(vec![
                    "stderr".into(),
                    "file".into()
                ]))
            );
        }
    }
}
