//! Non-Windows stub: every operation returns
//! [`spt_core::error::Error::UnsupportedPlatform`].

use spt_core::error::{Error, Result};

pub(crate) fn unsupported(op: &str) -> Result<()> {
    Err(Error::UnsupportedPlatform(format!(
        "spt-winevent::{op} requires Windows"
    )))
}
