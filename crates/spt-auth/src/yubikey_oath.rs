//! `YubiKey` OATH-TOTP code retrieval via the `ykman` CLI.
//!
//! This module shells out to `ykman oath accounts code <oath_name>` (with an
//! optional `--device <serial>` selector). It is feature-gated behind
//! `yubikey`; without the feature, [`fetch_code`] always returns
//! [`spt_core::Error::UnsupportedPlatform`].

use spt_core::{Error, Result};

/// Retrieve the current OATH-TOTP code for `oath_name` from a connected
/// `YubiKey`. `serial` disambiguates between multiple attached keys.
///
/// Without the `yubikey` Cargo feature this returns
/// [`Error::UnsupportedPlatform`] unconditionally — at no point is `ykman`
/// invoked, so build environments without a `YubiKey` or `ykman` binary remain
/// fully functional.
#[allow(unused_variables)]
pub fn fetch_code(serial: Option<&str>, oath_name: &str) -> Result<String> {
    #[cfg(feature = "yubikey")]
    {
        let mut cmd = std::process::Command::new("ykman");
        if let Some(s) = serial {
            cmd.args(["--device", s]);
        }
        cmd.args(["oath", "accounts", "code", "-s", oath_name]);
        let out = cmd
            .output()
            .map_err(|e| Error::UnsupportedPlatform(format!("ykman invocation failed: {e}")))?;
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            return Err(Error::AuthFailed(format!(
                "ykman oath accounts code returned non-zero ({}): {stderr}",
                out.status
            )));
        }
        let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if stdout.is_empty() {
            return Err(Error::AuthFailed(
                "ykman oath accounts code returned empty output".into(),
            ));
        }
        return Ok(stdout);
    }
    #[cfg(not(feature = "yubikey"))]
    {
        Err(Error::UnsupportedPlatform(
            "YubiKey OATH-TOTP requires the `yubikey` Cargo feature".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(not(feature = "yubikey"))]
    fn without_feature_returns_unsupported() {
        let e = fetch_code(None, "anything").unwrap_err();
        assert!(matches!(e, Error::UnsupportedPlatform(_)));
    }
}
