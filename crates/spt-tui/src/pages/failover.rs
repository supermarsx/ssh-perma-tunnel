//! "Reconnect / instability / failover" page.
//!
//! Combines spec §11.2 (reconnect), §9.11 (instability), §11.5 (failover).

use crossterm::event::KeyEvent;
use ratatui::buffer::Buffer;
use ratatui::layout::Rect;

use crate::model::Model;
use crate::pages::field::{opt_bool, opt_choice, opt_text, opt_u32, FieldList};
use crate::pages::Page;

const FAILOVER_MODES: &[&str] = &["priority", "weighted", "manual"];
const HEALTH_CHECKS: &[&str] = &[
    "tcp_connect",
    "ssh_handshake",
    "ssh_auth_preflight",
    "ssh3_endpoint",
];
const INSTABILITY_ACTIONS: &[&str] = &[
    "mark_degraded",
    "failover",
    "increase_keepalive",
    "increase_backoff",
    "emit_event",
    "restart_session",
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
            opt_bool(
                "reconnect.retry_auth_failures",
                "Retry on authentication failure",
                |p| p.reconnect.as_ref().and_then(|r| r.retry_auth_failures),
                |p, v| {
                    p.reconnect
                        .get_or_insert_with(Default::default)
                        .retry_auth_failures = v;
                },
            ),
            opt_bool(
                "instability.enabled",
                "Enable instability detection",
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
            opt_choice(
                "instability.action",
                "Action when threshold tripped",
                INSTABILITY_ACTIONS,
                |p| p.instability.as_ref().and_then(|i| i.action.clone()),
                |p, v| p.instability.get_or_insert_with(Default::default).action = v,
            ),
            opt_choice(
                "failover.mode",
                "Multi-endpoint selection mode",
                FAILOVER_MODES,
                |p| p.failover.as_ref().and_then(|f| f.mode.clone()),
                |p, v| p.failover.get_or_insert_with(Default::default).mode = v,
            ),
            opt_choice(
                "failover.health_check",
                "Health-check style",
                HEALTH_CHECKS,
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
            self.list.on_edit_key(key, model.profile_mut())
        } else {
            self.list.on_nav_key(key, model.profile());
            false
        }
    }

    fn focused_help(&self) -> Option<&str> {
        self.list.focused_help()
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
    fn instability_toggle_via_enter_then_enter() {
        let mut p = FailoverPage::new();
        let mut m = model();
        // instability.enabled is index 6.
        for _ in 0..6 {
            p.on_key(k(KeyCode::Down), &mut m);
        }
        p.on_key(k(KeyCode::Enter), &mut m); // begin edit on a Bool (buf=false)
                                             // Second Enter: Toggle flips false→true, then commits.
        p.on_key(k(KeyCode::Enter), &mut m);
        assert_eq!(
            m.profile().instability.as_ref().and_then(|i| i.enabled),
            Some(true)
        );
    }
}
