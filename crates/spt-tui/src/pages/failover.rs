//! "Reconnect / instability / failover" page.
//!
//! Combines spec §11.2 (reconnect), §9.11 (instability), §11.5 (failover).

use crossterm::event::KeyEvent;
use ratatui::buffer::Buffer;
use ratatui::layout::Rect;

use crate::model::Model;
use crate::pages::field::{opt_bool_with_help, opt_choice_with_help, opt_text, opt_u32, FieldList};
use crate::pages::Page;

/// Mode options for `[profiles.failover].mode`. Order is load-bearing —
/// the IT test `failover_mode_option_help_matches_schema` asserts that
/// this array contains exactly the three values defined in
/// `spt-config/src/schema.rs::Failover::mode`.
pub(crate) const FAILOVER_MODES: &[&str] = &["priority", "weighted", "manual"];
/// Per-option help for [`FAILOVER_MODES`]. Surfaced in the page footer
/// as the operator rotates the cursor in edit mode. Phrasing keeps the
/// lowercase hyphenated discriminators (`lowest-priority-number`,
/// `random-weighted`, `pinned endpoint`) mid-sentence so the
/// case-sensitive IT footer assertions match.
pub(crate) const FAILOVER_MODES_HELP: &[&str] = &[
    "Pick the lowest-priority-number endpoint that's not cooling down. Strict ordering.",
    "Random-weighted pick within the lowest-priority tier. Set `weight` per endpoint.",
    "Only use a pinned endpoint via admin override. Failover effectively disabled.",
];
const HEALTH_CHECKS: &[&str] = &[
    "tcp_connect",
    "ssh_handshake",
    "ssh_auth_preflight",
    "ssh3_endpoint",
];
const HEALTH_CHECKS_HELP: &[&str] = &[
    "TCP three-way handshake only. Cheapest probe — detects routing/firewall outages.",
    "Full SSH transport handshake. Catches host-key and kex regressions, no auth.",
    "Handshake + auth preflight. Catches stale agent/identity issues before failover.",
    "SSH3 HTTP/3 Extended-CONNECT preflight. Use for SSH3 endpoints only.",
];
const INSTABILITY_ACTIONS: &[&str] = &[
    "mark_degraded",
    "failover",
    "increase_keepalive",
    "increase_backoff",
    "emit_event",
    "restart_session",
];
const INSTABILITY_ACTIONS_HELP: &[&str] = &[
    "Flag the profile `degraded` but keep it running. Surfaces in stats/audit.",
    "Trigger failover to the next eligible endpoint immediately.",
    "Tighten keepalive interval — react faster to the next stall.",
    "Lengthen reconnect backoff so a flapping endpoint can't hot-loop the daemon.",
    "Emit a `profile.unstable` event for downstream sinks (no behavioural change).",
    "Tear down and recreate the SSH session in place. Heavy hammer — last resort.",
];

/// Reconnect, instability, failover.
pub struct FailoverPage {
    list: FieldList,
}

impl FailoverPage {
    /// Build the page.
    pub fn new() -> Self {
        let fields = vec![
            opt_text(
                "reconnect.initial_delay",
                "First retry delay (e.g. `1s`)",
                |p| p.reconnect.as_ref().and_then(|r| r.initial_delay.clone()),
                |p, v| {
                    p.reconnect
                        .get_or_insert_with(Default::default)
                        .initial_delay = v;
                },
            ),
            opt_text(
                "reconnect.max_delay",
                "Maximum retry delay (cap)",
                |p| p.reconnect.as_ref().and_then(|r| r.max_delay.clone()),
                |p, v| p.reconnect.get_or_insert_with(Default::default).max_delay = v,
            ),
            opt_text(
                "reconnect.jitter",
                "Jitter percentage (e.g. `20%`)",
                |p| p.reconnect.as_ref().and_then(|r| r.jitter.clone()),
                |p, v| p.reconnect.get_or_insert_with(Default::default).jitter = v,
            ),
            opt_text(
                "reconnect.reset_after",
                "Stable time before backoff resets",
                |p| p.reconnect.as_ref().and_then(|r| r.reset_after.clone()),
                |p, v| p.reconnect.get_or_insert_with(Default::default).reset_after = v,
            ),
            opt_u32(
                "reconnect.max_attempts",
                "Maximum retries (`0` = unlimited)",
                |p| p.reconnect.as_ref().and_then(|r| r.max_attempts),
                |p, v| {
                    p.reconnect
                        .get_or_insert_with(Default::default)
                        .max_attempts = v;
                },
            ),
            opt_bool_with_help(
                "reconnect.retry_auth_failures",
                "Retry on authentication failure",
                "Auth failures stop retries immediately. Default — auth bugs should be loud.",
                "Even auth failures get retried (rare; usually means a temporary key/agent glitch).",
                |p| p.reconnect.as_ref().and_then(|r| r.retry_auth_failures),
                |p, v| {
                    p.reconnect
                        .get_or_insert_with(Default::default)
                        .retry_auth_failures = v;
                },
            ),
            opt_bool_with_help(
                "instability.enabled",
                "Enable instability detection",
                "Disconnects are independent events — no aggregate instability state is tracked.",
                "Slide a window over disconnects; >`max_disconnects` within `window` fires `action`.",
                |p| p.instability.as_ref().and_then(|i| i.enabled),
                |p, v| p.instability.get_or_insert_with(Default::default).enabled = v,
            ),
            opt_text(
                "instability.window",
                "Sliding-window length",
                |p| p.instability.as_ref().and_then(|i| i.window.clone()),
                |p, v| p.instability.get_or_insert_with(Default::default).window = v,
            ),
            opt_u32(
                "instability.max_disconnects",
                "Max disconnects within window",
                |p| p.instability.as_ref().and_then(|i| i.max_disconnects),
                |p, v| {
                    p.instability
                        .get_or_insert_with(Default::default)
                        .max_disconnects = v;
                },
            ),
            opt_choice_with_help(
                "instability.action",
                "Action when threshold tripped",
                INSTABILITY_ACTIONS,
                INSTABILITY_ACTIONS_HELP,
                |p| p.instability.as_ref().and_then(|i| i.action.clone()),
                |p, v| p.instability.get_or_insert_with(Default::default).action = v,
            ),
            opt_choice_with_help(
                "failover.mode",
                "Multi-endpoint selection mode",
                FAILOVER_MODES,
                FAILOVER_MODES_HELP,
                |p| p.failover.as_ref().and_then(|f| f.mode.clone()),
                |p, v| p.failover.get_or_insert_with(Default::default).mode = v,
            ),
            opt_choice_with_help(
                "failover.health_check",
                "Health-check style",
                HEALTH_CHECKS,
                HEALTH_CHECKS_HELP,
                |p| p.failover.as_ref().and_then(|f| f.health_check.clone()),
                |p, v| p.failover.get_or_insert_with(Default::default).health_check = v,
            ),
            opt_u32(
                "failover.fail_after",
                "Trigger failover after N consecutive failures",
                |p| p.failover.as_ref().and_then(|f| f.fail_after),
                |p, v| p.failover.get_or_insert_with(Default::default).fail_after = v,
            ),
            opt_text(
                "failover.restore_after",
                "Restore window before failback",
                |p| p.failover.as_ref().and_then(|f| f.restore_after.clone()),
                |p, v| {
                    p.failover
                        .get_or_insert_with(Default::default)
                        .restore_after = v;
                },
            ),
        ];
        Self {
            list: FieldList::new(fields),
        }
    }
}

impl Page for FailoverPage {
    fn render(&mut self, area: Rect, buf: &mut Buffer, model: &Model) {
        self.list.render(area, buf, model.profile());
    }
    fn on_key(&mut self, key: KeyEvent, model: &mut Model) -> bool {
        if self.list.editing {
            let changed = self.list.on_edit_key(key, model.profile_mut_silent());
            if changed {
                model.mark_dirty();
            }
            changed
        } else {
            self.list.on_nav_key(key, model.profile());
            false
        }
    }

    fn focused_help(&self) -> Option<&str> {
        self.list.focused_help()
    }
    fn focused_help_dynamic(&self, model: &Model) -> Option<&str> {
        self.list.focused_help_dynamic(model.profile())
    }
    fn focused_position(&self) -> Option<(usize, usize)> {
        self.list.focus_position()
    }
    fn is_editing(&self) -> bool {
        self.list.editing
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use ratatui::buffer::Buffer;
    use ratatui::layout::Rect;

    fn k(c: KeyCode) -> KeyEvent {
        KeyEvent::new(c, KeyModifiers::NONE)
    }

    fn model() -> Model {
        Model::from_str(
            r#"version = 1
[[profiles]]
name = "p"
protocol = "ssh2"
"#,
        )
    }

    #[test]
    fn builds_with_reconnect_and_failover_fields() {
        let p = FailoverPage::new();
        let labels: Vec<&str> = p.list.fields.iter().map(|f| f.def.label).collect();
        assert!(labels.contains(&"reconnect.initial_delay"));
        assert!(labels.contains(&"reconnect.max_attempts"));
        assert!(labels.contains(&"instability.enabled"));
        assert!(labels.contains(&"failover.mode"));
    }

    #[test]
    fn renders_without_panic() {
        let mut p = FailoverPage::new();
        let m = model();
        let area = Rect::new(0, 0, 100, 60);
        let mut buf = Buffer::empty(area);
        p.render(area, &mut buf, &m);
    }

    #[test]
    fn initial_delay_round_trip() {
        let mut p = FailoverPage::new();
        let mut m = model();
        p.on_key(k(KeyCode::Enter), &mut m);
        for c in "2s".chars() {
            p.on_key(k(KeyCode::Char(c)), &mut m);
        }
        p.on_key(k(KeyCode::Enter), &mut m);
        assert_eq!(
            m.profile()
                .reconnect
                .as_ref()
                .and_then(|r| r.initial_delay.clone())
                .as_deref(),
            Some("2s")
        );
    }

    #[test]
    fn instability_toggle_via_space_then_enter() {
        let mut p = FailoverPage::new();
        let mut m = model();
        // instability.enabled is index 6.
        for _ in 0..6 {
            p.on_key(k(KeyCode::Down), &mut m);
        }
        p.on_key(k(KeyCode::Enter), &mut m); // begin edit on a Bool (buf=false)
        p.on_key(k(KeyCode::Char(' ')), &mut m); // Space flips edit_buf false -> true
        p.on_key(k(KeyCode::Enter), &mut m); // Enter commits the (now-true) value
        assert_eq!(
            m.profile().instability.as_ref().and_then(|i| i.enabled),
            Some(true)
        );
    }

    #[test]
    fn instability_toggle_via_t_then_enter() {
        // `t` is the new mnemonic toggle key. Same end state as Space.
        let mut p = FailoverPage::new();
        let mut m = model();
        for _ in 0..6 {
            p.on_key(k(KeyCode::Down), &mut m);
        }
        p.on_key(k(KeyCode::Enter), &mut m); // begin edit
        p.on_key(k(KeyCode::Char('t')), &mut m); // t flips
        p.on_key(k(KeyCode::Enter), &mut m); // commit
        assert_eq!(
            m.profile().instability.as_ref().and_then(|i| i.enabled),
            Some(true)
        );
    }

    /// Schema-realism guard: the `failover.mode` option list must
    /// exactly mirror `spt-config/src/schema.rs::Failover::mode`'s
    /// documented enum (`priority|weighted|manual`). The IT test that
    /// asserts the page-footer per-option help also depends on this
    /// order, so changes here must be reflected in
    /// [`FAILOVER_MODES_HELP`] too.
    #[test]
    fn failover_mode_option_help_matches_schema() {
        assert_eq!(FAILOVER_MODES, &["priority", "weighted", "manual"]);
        assert_eq!(FAILOVER_MODES_HELP.len(), 3);
        // Each entry is non-empty and concise (≤ ~110 chars so the
        // footer's single visible row doesn't truncate the asserted
        // substring at typical 100-cell test widths).
        for (mode, help) in FAILOVER_MODES.iter().zip(FAILOVER_MODES_HELP.iter()) {
            assert!(!help.is_empty(), "{mode} help string must not be empty");
            assert!(
                help.chars().count() <= 110,
                "{mode} help is too long for the footer's single row: {help}"
            );
        }
    }
}
