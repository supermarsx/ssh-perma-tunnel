//! Dependency-free ANSI color helper for human-facing CLI output.
//!
//! A [`Styler`] is constructed from a single `enabled` bool — typically
//! `Styler::new(crate::color_enabled(global))`, or via the
//! [`crate::styler`] convenience. When `enabled == false` every method
//! returns the plain, un-escaped string, so piped / `--no-color` /
//! `NO_COLOR` / non-tty output stays clean.
//!
//! The helpers wrap raw ANSI SGR sequences (`\x1b[<code>m … \x1b[0m`); no
//! external crate is pulled in. [`Styler::state`] maps the common lifecycle
//! labels this CLI prints (daemon / profile / forward / subsystem / service
//! states) onto a green / yellow / red / dim palette so callers don't have to
//! re-implement that classification at every render site.

/// Reset sequence appended after every colored span.
const RESET: &str = "\x1b[0m";

/// ANSI color/attribute helper.
///
/// Cheap to construct and `Copy`; pass it by value into renderers.
#[derive(Clone, Copy, Debug)]
pub struct Styler {
    enabled: bool,
}

impl Styler {
    /// Construct a styler. When `enabled` is false all methods are no-ops
    /// that return the plain input string.
    #[must_use]
    pub fn new(enabled: bool) -> Self {
        Self { enabled }
    }

    /// Whether this styler emits escape sequences.
    #[must_use]
    pub fn enabled(self) -> bool {
        self.enabled
    }

    /// Wrap `s` in the SGR code `code` (e.g. `"1"` for bold) when enabled.
    fn wrap(self, code: &str, s: &str) -> String {
        if self.enabled {
            format!("\x1b[{code}m{s}{RESET}")
        } else {
            s.to_string()
        }
    }

    /// Bold (SGR 1).
    #[must_use]
    pub fn bold(self, s: &str) -> String {
        self.wrap("1", s)
    }

    /// Dim / faint (SGR 2).
    #[must_use]
    pub fn dim(self, s: &str) -> String {
        self.wrap("2", s)
    }

    /// Green foreground (SGR 32).
    #[must_use]
    pub fn green(self, s: &str) -> String {
        self.wrap("32", s)
    }

    /// Yellow foreground (SGR 33).
    #[must_use]
    pub fn yellow(self, s: &str) -> String {
        self.wrap("33", s)
    }

    /// Red foreground (SGR 31).
    #[must_use]
    pub fn red(self, s: &str) -> String {
        self.wrap("31", s)
    }

    /// Cyan foreground (SGR 36).
    #[must_use]
    pub fn cyan(self, s: &str) -> String {
        self.wrap("36", s)
    }

    /// Color a lifecycle/state label by its common meaning.
    ///
    /// The classification is case-insensitive on the leading word so that
    /// composite labels like `"NOT RUNNING (crashed — pid not alive)"` or
    /// `"running (systemd, scope=system)"` still pick the right palette. The
    /// returned string preserves `label` verbatim — only escapes are added.
    ///
    /// * green  — Active / Running / healthy / bound / enabled / ok / on
    /// * yellow — Degraded / `RetryWait` / Stopped / Connecting / stale / pending
    /// * red    — Failed / NOT RUNNING / dead / error / `NotInstalled`
    /// * dim    — unknown / disabled / none / off / absent
    #[must_use]
    pub fn state(self, label: &str) -> String {
        if !self.enabled {
            return label.to_string();
        }
        let key = label.trim().to_ascii_lowercase();
        // Match on the most specific multi-word phrases first, then fall back
        // to a leading-word classification.
        let leading = key
            .split(|c: char| !c.is_ascii_alphanumeric())
            .next()
            .unwrap_or("");

        // Red: hard-failure / absent states. "not running" / "not installed"
        // need the two-word check before the leading-word "not".
        if key.starts_with("not running")
            || key.starts_with("not installed")
            || matches!(
                leading,
                "failed" | "dead" | "error" | "notinstalled" | "crashed" | "fatal"
            )
        {
            return self.red(label);
        }

        // Green: healthy / present states.
        if matches!(
            leading,
            "active" | "running" | "healthy" | "bound" | "enabled" | "ok" | "on" | "up" | "live"
        ) {
            return self.green(label);
        }

        // Yellow: transitional / degraded states.
        if matches!(
            leading,
            "degraded"
                | "retrywait"
                | "stopped"
                | "connecting"
                | "stale"
                | "pending"
                | "reconnecting"
                | "starting"
                | "warn"
                | "warning"
        ) {
            return self.yellow(label);
        }

        // Dim: unknown / disabled / inert states.
        if matches!(
            leading,
            "unknown" | "disabled" | "none" | "off" | "absent" | ""
        ) {
            return self.dim(label);
        }

        // Default: leave uncolored rather than guess.
        label.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enabled_emits_ansi() {
        let s = Styler::new(true);
        assert_eq!(s.bold("x"), "\x1b[1mx\x1b[0m");
        assert_eq!(s.dim("x"), "\x1b[2mx\x1b[0m");
        assert_eq!(s.green("x"), "\x1b[32mx\x1b[0m");
        assert_eq!(s.yellow("x"), "\x1b[33mx\x1b[0m");
        assert_eq!(s.red("x"), "\x1b[31mx\x1b[0m");
        assert_eq!(s.cyan("x"), "\x1b[36mx\x1b[0m");
    }

    #[test]
    fn disabled_is_plain() {
        let s = Styler::new(false);
        assert_eq!(s.bold("x"), "x");
        assert_eq!(s.dim("x"), "x");
        assert_eq!(s.green("x"), "x");
        assert_eq!(s.yellow("x"), "x");
        assert_eq!(s.red("x"), "x");
        assert_eq!(s.cyan("x"), "x");
        assert_eq!(s.state("RUNNING"), "RUNNING");
        assert!(!s.enabled());
    }

    #[test]
    fn state_maps_green() {
        let s = Styler::new(true);
        for label in [
            "Active", "Running", "RUNNING", "healthy", "bound", "enabled",
        ] {
            assert!(
                s.state(label).starts_with("\x1b[32m"),
                "{label} should be green"
            );
        }
    }

    #[test]
    fn state_maps_yellow() {
        let s = Styler::new(true);
        for label in ["Degraded", "RetryWait", "Stopped", "Connecting", "stale"] {
            assert!(
                s.state(label).starts_with("\x1b[33m"),
                "{label} should be yellow"
            );
        }
    }

    #[test]
    fn state_maps_red() {
        let s = Styler::new(true);
        for label in ["Failed", "NOT RUNNING", "dead", "error", "NotInstalled"] {
            assert!(
                s.state(label).starts_with("\x1b[31m"),
                "{label} should be red"
            );
        }
    }

    #[test]
    fn state_maps_dim() {
        let s = Styler::new(true);
        for label in ["unknown", "disabled", "none"] {
            assert!(
                s.state(label).starts_with("\x1b[2m"),
                "{label} should be dim"
            );
        }
    }

    #[test]
    fn state_preserves_label_text() {
        let s = Styler::new(true);
        let out = s.state("NOT RUNNING (crashed — pid not alive)");
        assert!(out.contains("NOT RUNNING (crashed — pid not alive)"));
        assert!(out.starts_with("\x1b[31m"));
        assert!(out.ends_with("\x1b[0m"));
    }
}
