//! Path-string expansion: `~`, `$VAR` / `${VAR}` (Unix), `%VAR%` (Windows).
//!
//! Expansion is intentionally permissive — undefined variables are passed
//! through unchanged so that diagnostics can flag them later instead of the
//! parser exploding here.

use std::path::PathBuf;

/// Expand a path string to a [`PathBuf`].
///
/// * A leading `~` (alone or followed by `/` / `\\`) is expanded to the user's
///   home directory if known. If the home cannot be determined, `~` is left
///   in place.
/// * `$VAR` and `${VAR}` are expanded from the environment on all platforms.
/// * `%VAR%` is expanded from the environment on Windows only.
/// * Unknown variables are left as the literal substring.
#[must_use]
pub fn expand(s: &str) -> PathBuf {
    let with_home = expand_home(s);
    let expanded = expand_vars(&with_home);
    PathBuf::from(expanded)
}

fn expand_home(s: &str) -> String {
    if !s.starts_with('~') {
        return s.to_owned();
    }
    let after = &s[1..];
    // Only `~` or `~/...` / `~\...` are recognized; `~user` is not supported.
    if !after.is_empty() && !after.starts_with('/') && !after.starts_with('\\') {
        return s.to_owned();
    }
    let Some(home) = home_dir() else {
        return s.to_owned();
    };
    let mut out = home.to_string_lossy().into_owned();
    out.push_str(after);
    out
}

#[cfg(unix)]
fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

#[cfg(windows)]
fn home_dir() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("USERPROFILE") {
        return Some(PathBuf::from(p));
    }
    match (std::env::var_os("HOMEDRIVE"), std::env::var_os("HOMEPATH")) {
        (Some(d), Some(p)) => {
            let mut s = d.into_string().unwrap_or_default();
            s.push_str(&p.into_string().unwrap_or_default());
            Some(PathBuf::from(s))
        }
        _ => std::env::var_os("HOME").map(PathBuf::from),
    }
}

#[cfg(not(any(unix, windows)))]
fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

fn expand_vars(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i] as char;
        if c == '$' {
            if let Some((name, consumed)) = read_dollar_var(&s[i..]) {
                if let Ok(val) = std::env::var(name) {
                    out.push_str(&val);
                } else {
                    out.push_str(&s[i..i + consumed]);
                }
                i += consumed;
                continue;
            }
        }
        if cfg!(windows) && c == '%' {
            if let Some((name, consumed)) = read_percent_var(&s[i..]) {
                if let Ok(val) = std::env::var(name) {
                    out.push_str(&val);
                } else {
                    out.push_str(&s[i..i + consumed]);
                }
                i += consumed;
                continue;
            }
        }
        out.push(c);
        i += c.len_utf8();
    }
    out
}

/// Returns `(name, consumed_bytes)` for `$NAME` or `${NAME}` starting at `s`.
fn read_dollar_var(s: &str) -> Option<(&str, usize)> {
    let bytes = s.as_bytes();
    debug_assert_eq!(bytes.first(), Some(&b'$'));
    if bytes.get(1) == Some(&b'{') {
        let end = s.find('}')?;
        let name = &s[2..end];
        if name.is_empty() || !is_var_name(name) {
            return None;
        }
        return Some((name, end + 1));
    }
    let mut end = 1;
    while end < bytes.len() {
        let c = bytes[end] as char;
        if !is_var_name_char(c) {
            break;
        }
        end += 1;
    }
    if end == 1 {
        return None;
    }
    Some((&s[1..end], end))
}

/// Returns `(name, consumed_bytes)` for `%NAME%` starting at `s`.
fn read_percent_var(s: &str) -> Option<(&str, usize)> {
    let bytes = s.as_bytes();
    debug_assert_eq!(bytes.first(), Some(&b'%'));
    let rest = &s[1..];
    let end_rel = rest.find('%')?;
    let name = &rest[..end_rel];
    if name.is_empty() || !is_var_name(name) {
        return None;
    }
    Some((name, 1 + end_rel + 1))
}

fn is_var_name(s: &str) -> bool {
    s.chars().all(is_var_name_char)
}

fn is_var_name_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

#[cfg(test)]
mod tests {
    use super::expand;
    use std::path::PathBuf;

    /// Serialises tests that mutate the process-global `HOME`/`USERPROFILE`
    /// env vars so `cargo test -p spt-core` is race-free WITHOUT
    /// `--test-threads=1`.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn lock_env() -> std::sync::MutexGuard<'static, ()> {
        ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    #[test]
    fn passthrough_when_no_specials() {
        assert_eq!(expand("/a/b/c"), PathBuf::from("/a/b/c"));
    }

    #[test]
    fn expands_tilde_with_home() {
        let _guard = lock_env();
        let prev = std::env::var_os("HOME");
        let prev_userprofile = std::env::var_os("USERPROFILE");
        std::env::set_var("HOME", "/h");
        if cfg!(windows) {
            std::env::set_var("USERPROFILE", "/h");
        }
        let got = expand("~/cfg.toml");
        assert_eq!(got, PathBuf::from("/h/cfg.toml"));
        match prev {
            Some(v) => std::env::set_var("HOME", v),
            None => std::env::remove_var("HOME"),
        }
        match prev_userprofile {
            Some(v) => std::env::set_var("USERPROFILE", v),
            None => {
                if cfg!(windows) {
                    std::env::remove_var("USERPROFILE");
                }
            }
        }
    }

    #[test]
    fn tilde_only_at_start() {
        assert_eq!(expand("/a/~/b"), PathBuf::from("/a/~/b"));
    }

    #[test]
    fn dollar_var_expands() {
        std::env::set_var("SPT_TEST_PATH_VAR_A", "alpha");
        assert_eq!(
            expand("/x/$SPT_TEST_PATH_VAR_A/y"),
            PathBuf::from("/x/alpha/y")
        );
        std::env::remove_var("SPT_TEST_PATH_VAR_A");
    }

    #[test]
    fn dollar_brace_var_expands() {
        std::env::set_var("SPT_TEST_PATH_VAR_B", "beta");
        assert_eq!(
            expand("/x/${SPT_TEST_PATH_VAR_B}y"),
            PathBuf::from("/x/betay")
        );
        std::env::remove_var("SPT_TEST_PATH_VAR_B");
    }

    #[test]
    fn unknown_var_is_passthrough() {
        std::env::remove_var("SPT_DEFINITELY_UNSET_X");
        assert_eq!(
            expand("/$SPT_DEFINITELY_UNSET_X/end"),
            PathBuf::from("/$SPT_DEFINITELY_UNSET_X/end")
        );
    }

    #[cfg(windows)]
    #[test]
    fn percent_var_on_windows() {
        std::env::set_var("SPT_TEST_PATH_VAR_C", "gamma");
        assert_eq!(
            expand("X:\\%SPT_TEST_PATH_VAR_C%\\y"),
            PathBuf::from("X:\\gamma\\y")
        );
        std::env::remove_var("SPT_TEST_PATH_VAR_C");
    }

    #[test]
    fn empty_input_is_empty_path() {
        assert_eq!(expand(""), PathBuf::from(""));
    }
}
