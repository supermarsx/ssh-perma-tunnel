//! "Transport" page — `[profiles.transport.obfuscation]` (obfs, t6-e13).
//!
//! Single-object editor (no list) built on a [`FieldList`] whose field set is
//! gated on the currently-selected obfuscation `kind`, rebuilt when the kind
//! changes (mirroring the Endpoints page's auth-override rebuild).
//!
//! Editable:
//! * `none`      — plain TCP (clears `[profiles.transport]`).
//! * `obfs4`     — `node_id`, `public_key`, `iat_mode`.
//! * `meek-http` — `url`, `front_host`, `sni`.
//! * `websocket` — `url` (extra `headers` remain TOML-only).
//! * `shadowsocks` — `method` is editable; the `password` (a
//!   `spt_secrets::SecretRef`) is preserved but not editable, and a fresh
//!   shadowsocks block cannot be *created* here (that secret type is not
//!   constructible from the TUI crate without a new dependency). Selecting
//!   `shadowsocks` when none exists is a no-op.

use crossterm::event::KeyEvent;
use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use spt_config::schema::{ObfsConfig, Profile, Transport};

use crate::model::Model;
use crate::pages::field::{FieldDef, FieldList, FieldValue};
use crate::pages::Page;

const KINDS: &[&str] = &["none", "obfs4", "meek-http", "websocket", "shadowsocks"];
const KINDS_HELP: &[&str] = &[
    "Plain TCP — no obfuscation. Clears [profiles.transport].",
    "Tor pluggable-transport obfs4 bridge. Set node_id, public_key, iat_mode.",
    "meek-style HTTPS-CONNECT fronting. Set url (+ optional front_host / sni).",
    "SSH over a WebSocket upgrade. Set url (ws:// or wss://).",
    "SSH over Shadowsocks AEAD. method editable; password/create are TOML-only.",
];

/// Borrow the active [`ObfsConfig`], if any.
fn obfs(p: &Profile) -> Option<&ObfsConfig> {
    p.transport.as_ref().and_then(|t| t.obfuscation.as_ref())
}

/// Mutably borrow the active [`ObfsConfig`], if any.
fn obfs_mut(p: &mut Profile) -> Option<&mut ObfsConfig> {
    p.transport.as_mut().and_then(|t| t.obfuscation.as_mut())
}

/// Canonical kind string for the current obfuscation (or `"none"`).
fn kind_str(p: &Profile) -> &'static str {
    match obfs(p) {
        None => "none",
        Some(ObfsConfig::Obfs4 { .. }) => "obfs4",
        Some(ObfsConfig::MeekHttp { .. }) => "meek-http",
        Some(ObfsConfig::Websocket { .. }) => "websocket",
        Some(ObfsConfig::Shadowsocks { .. }) => "shadowsocks",
        // `ObfsConfig` is `#[non_exhaustive]`; a future variant renders as
        // "none" in the selector but its bytes still round-trip on save.
        Some(_) => "none",
    }
}

/// Switch the obfuscation to `kind`, constructing a fresh default variant.
/// No-op when the kind is unchanged (so existing field values are preserved)
/// or when the target cannot be constructed (`shadowsocks`, which needs a
/// `SecretRef`).
fn set_kind(p: &mut Profile, kind: &str) {
    if kind_str(p) == kind {
        return;
    }
    let new = match kind {
        "none" => None,
        "obfs4" => Some(ObfsConfig::Obfs4 {
            node_id: String::new(),
            public_key: String::new(),
            iat_mode: 0,
        }),
        "meek-http" => Some(ObfsConfig::MeekHttp {
            url: String::new(),
            front_host: None,
            sni: None,
        }),
        "websocket" => Some(ObfsConfig::Websocket {
            url: String::new(),
            headers: Vec::new(),
        }),
        // Cannot build a Shadowsocks block (needs a SecretRef password).
        _ => return,
    };
    match new {
        None => p.transport = None,
        Some(o) => {
            p.transport
                .get_or_insert_with(Transport::default)
                .obfuscation = Some(o);
        }
    }
}

/// Build the field list for the current obfuscation kind of `profile`.
fn transport_fields(profile: &Profile) -> Vec<FieldDef> {
    let kind = kind_str(profile);
    let mut fields = vec![FieldDef {
        label: "kind",
        help: "Obfuscation transport (none / obfs4 / meek-http / websocket / shadowsocks)",
        get: Box::new(|p: &Profile| FieldValue::Choice {
            value: kind_str(p).to_owned(),
            options: KINDS,
            display: None,
            option_help: Some(KINDS_HELP),
        }),
        set: Box::new(|p, v| {
            if let FieldValue::Choice { value, .. } = v {
                set_kind(p, &value);
            }
        }),
        validate: None,
        bool_option_help: None,
    }];

    match kind {
        "obfs4" => {
            fields.push(FieldDef {
                label: "obfs4.node_id",
                help: "Hex-encoded 20-byte server node id",
                get: Box::new(|p: &Profile| {
                    FieldValue::Text(match obfs(p) {
                        Some(ObfsConfig::Obfs4 { node_id, .. }) => node_id.clone(),
                        _ => String::new(),
                    })
                }),
                set: Box::new(|p, v| {
                    if let FieldValue::Text(s) = v {
                        if let Some(ObfsConfig::Obfs4 { node_id, .. }) = obfs_mut(p) {
                            *node_id = s;
                        }
                    }
                }),
                validate: None,
                bool_option_help: None,
            });
            fields.push(FieldDef {
                label: "obfs4.public_key",
                help: "Hex-encoded 32-byte server identity public key",
                get: Box::new(|p: &Profile| {
                    FieldValue::Text(match obfs(p) {
                        Some(ObfsConfig::Obfs4 { public_key, .. }) => public_key.clone(),
                        _ => String::new(),
                    })
                }),
                set: Box::new(|p, v| {
                    if let FieldValue::Text(s) = v {
                        if let Some(ObfsConfig::Obfs4 { public_key, .. }) = obfs_mut(p) {
                            *public_key = s;
                        }
                    }
                }),
                validate: None,
                bool_option_help: None,
            });
            fields.push(FieldDef {
                label: "obfs4.iat_mode",
                help: "IAT mode (0, 1, or 2)",
                get: Box::new(|p: &Profile| {
                    FieldValue::Numeric(match obfs(p) {
                        Some(ObfsConfig::Obfs4 { iat_mode, .. }) => iat_mode.to_string(),
                        _ => String::new(),
                    })
                }),
                set: Box::new(|p, v| {
                    if let FieldValue::Numeric(s) = v {
                        if let Ok(n) = s.parse::<u8>() {
                            if let Some(ObfsConfig::Obfs4 { iat_mode, .. }) = obfs_mut(p) {
                                *iat_mode = n;
                            }
                        }
                    }
                }),
                validate: Some(Box::new(|v| {
                    if let FieldValue::Numeric(s) = v {
                        if !s.is_empty() && s.parse::<u8>().map_or(true, |n| n > 2) {
                            return Some(format!("`{s}` must be 0, 1, or 2"));
                        }
                    }
                    None
                })),
                bool_option_help: None,
            });
        }
        "meek-http" => {
            fields.push(meek_text(
                "meek.url",
                "Fronting URL (HTTPS)",
                MeekField::Url,
            ));
            fields.push(meek_text(
                "meek.front_host",
                "Optional Host: header override (domain fronting)",
                MeekField::FrontHost,
            ));
            fields.push(meek_text(
                "meek.sni",
                "Optional explicit SNI override",
                MeekField::Sni,
            ));
        }
        "websocket" => {
            fields.push(FieldDef {
                label: "ws.url",
                help: "WebSocket endpoint URL (ws:// or wss://)",
                get: Box::new(|p: &Profile| {
                    FieldValue::Text(match obfs(p) {
                        Some(ObfsConfig::Websocket { url, .. }) => url.clone(),
                        _ => String::new(),
                    })
                }),
                set: Box::new(|p, v| {
                    if let FieldValue::Text(s) = v {
                        if let Some(ObfsConfig::Websocket { url, .. }) = obfs_mut(p) {
                            *url = s;
                        }
                    }
                }),
                validate: None,
                bool_option_help: None,
            });
        }
        "shadowsocks" => {
            fields.push(FieldDef {
                label: "ss.method",
                help: "Shadowsocks cipher (password stays TOML-only)",
                get: Box::new(|p: &Profile| {
                    FieldValue::Text(match obfs(p) {
                        Some(ObfsConfig::Shadowsocks { method, .. }) => method.clone(),
                        _ => String::new(),
                    })
                }),
                set: Box::new(|p, v| {
                    if let FieldValue::Text(s) = v {
                        if let Some(ObfsConfig::Shadowsocks { method, .. }) = obfs_mut(p) {
                            *method = s;
                        }
                    }
                }),
                validate: None,
                bool_option_help: None,
            });
        }
        _ => {}
    }

    fields
}

/// Which optional meek field an editor targets.
#[derive(Clone, Copy)]
enum MeekField {
    Url,
    FrontHost,
    Sni,
}

/// Build a meek-http field editor. `url` is a required `String`; `front_host`
/// and `sni` are `Option<String>` (blank clears).
fn meek_text(label: &'static str, help: &'static str, which: MeekField) -> FieldDef {
    FieldDef {
        label,
        help,
        get: Box::new(move |p: &Profile| {
            let val = match obfs(p) {
                Some(ObfsConfig::MeekHttp {
                    url,
                    front_host,
                    sni,
                }) => match which {
                    MeekField::Url => url.clone(),
                    MeekField::FrontHost => front_host.clone().unwrap_or_default(),
                    MeekField::Sni => sni.clone().unwrap_or_default(),
                },
                _ => String::new(),
            };
            FieldValue::Text(val)
        }),
        set: Box::new(move |p, v| {
            if let FieldValue::Text(s) = v {
                if let Some(ObfsConfig::MeekHttp {
                    url,
                    front_host,
                    sni,
                }) = obfs_mut(p)
                {
                    match which {
                        MeekField::Url => *url = s,
                        MeekField::FrontHost => {
                            *front_host = if s.is_empty() { None } else { Some(s) };
                        }
                        MeekField::Sni => *sni = if s.is_empty() { None } else { Some(s) },
                    }
                }
            }
        }),
        validate: None,
        bool_option_help: None,
    }
}

/// Obfuscation transport editor page.
pub struct TransportPage {
    list: FieldList,
    /// The kind the current `list` was built for; drives lazy rebuilds.
    built_kind: String,
}

impl TransportPage {
    /// Build the page. The field list is (re)synced to the model's actual
    /// obfuscation kind on the first render / key event.
    pub fn new() -> Self {
        let p = Profile::default();
        Self {
            list: FieldList::new(transport_fields(&p)),
            built_kind: kind_str(&p).to_owned(),
        }
    }

    /// Rebuild the field list when the profile's obfuscation kind no longer
    /// matches what the list was built for. Skipped while a field is being
    /// edited so an in-flight edit is never dropped mid-keystroke.
    fn sync(&mut self, profile: &Profile) {
        if self.list.editing {
            return;
        }
        let cur = kind_str(profile);
        if cur != self.built_kind {
            let focus = self.list.focus;
            self.list = FieldList::new(transport_fields(profile));
            self.list.focus = focus.min(self.list.fields.len().saturating_sub(1));
            self.built_kind = cur.to_owned();
        }
    }
}

impl Default for TransportPage {
    fn default() -> Self {
        Self::new()
    }
}

impl Page for TransportPage {
    fn render(&mut self, area: Rect, buf: &mut Buffer, model: &Model) {
        self.sync(model.profile());
        self.list.render(area, buf, model.profile());
    }

    fn on_key(&mut self, key: KeyEvent, model: &mut Model) -> bool {
        self.sync(model.profile());
        if self.list.editing {
            let changed = self.list.on_edit_key(key, model.profile_mut_silent());
            if changed {
                model.mark_dirty();
                // A committed kind change flips the variant; rebuild so the
                // gated variant fields appear/disappear on the next render.
                self.sync(model.profile());
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
name = "demo"
protocol = "ssh2"
host = "h.example.com"
"#,
        )
    }

    #[test]
    fn default_kind_is_none_single_field() {
        let p = Profile::default();
        let fields = transport_fields(&p);
        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].label, "kind");
    }

    #[test]
    fn selecting_obfs4_creates_block_and_gates_fields() {
        let mut page = TransportPage::new();
        let mut m = model();
        // Focus is on `kind`. Begin edit, rotate to obfs4, commit.
        page.on_key(k(KeyCode::Enter), &mut m); // begin edit
        page.on_key(k(KeyCode::Right), &mut m); // → obfs4
        page.on_key(k(KeyCode::Enter), &mut m); // commit
        assert!(matches!(
            super::obfs(m.profile()),
            Some(ObfsConfig::Obfs4 { .. })
        ));
        // Rendering must now surface the gated obfs4 fields.
        let area = Rect::new(0, 0, 100, 30);
        let mut buf = Buffer::empty(area);
        page.render(area, &mut buf, &m);
        assert!(page
            .list
            .fields
            .iter()
            .any(|f| f.def.label == "obfs4.node_id"));
    }

    #[test]
    fn obfs4_node_id_round_trip() {
        let mut page = TransportPage::new();
        let mut m = model();
        page.on_key(k(KeyCode::Enter), &mut m);
        page.on_key(k(KeyCode::Right), &mut m); // obfs4
        page.on_key(k(KeyCode::Enter), &mut m); // commit → rebuild
                                                // Render to force the sync/rebuild so node_id is present.
        let area = Rect::new(0, 0, 100, 30);
        let mut buf = Buffer::empty(area);
        page.render(area, &mut buf, &m);
        // Move to node_id (index 1), edit.
        page.on_key(k(KeyCode::Down), &mut m);
        page.on_key(k(KeyCode::Enter), &mut m);
        for c in "abcd".chars() {
            page.on_key(k(KeyCode::Char(c)), &mut m);
        }
        page.on_key(k(KeyCode::Enter), &mut m);
        match super::obfs(m.profile()) {
            Some(ObfsConfig::Obfs4 { node_id, .. }) => assert_eq!(node_id, "abcd"),
            other => panic!("expected obfs4, got {other:?}"),
        }
    }

    #[test]
    fn switching_to_none_clears_transport() {
        let mut m = Model::from_str(
            r#"version = 1
[[profiles]]
name = "demo"
protocol = "ssh2"
host = "h.example.com"

[profiles.transport.obfuscation]
kind = "websocket"
url = "wss://front.example.com/ws"
"#,
        );
        let mut page = TransportPage::new();
        // Sync picks up websocket on first render.
        let area = Rect::new(0, 0, 100, 30);
        let mut buf = Buffer::empty(area);
        page.render(area, &mut buf, &m);
        assert_eq!(page.built_kind, "websocket");
        // Edit kind, rotate up (Left) once from websocket (index 3) → meek-http,
        // twice → obfs4, three times → none, then commit.
        page.on_key(k(KeyCode::Enter), &mut m); // begin edit on kind (seeded at websocket)
        page.on_key(k(KeyCode::Left), &mut m); // → meek-http
        page.on_key(k(KeyCode::Left), &mut m); // → obfs4
        page.on_key(k(KeyCode::Left), &mut m); // → none
        page.on_key(k(KeyCode::Enter), &mut m); // commit → none
        assert!(m.profile().transport.is_none());
    }

    #[test]
    fn selecting_shadowsocks_without_existing_is_noop() {
        let mut page = TransportPage::new();
        let mut m = model();
        page.on_key(k(KeyCode::Enter), &mut m); // begin edit kind
                                                // Rotate Left from none wraps to shadowsocks (last option).
        page.on_key(k(KeyCode::Left), &mut m);
        page.on_key(k(KeyCode::Enter), &mut m); // commit
                                                // Cannot construct shadowsocks — obfuscation stays absent.
        assert!(super::obfs(m.profile()).is_none());
    }

    #[test]
    fn existing_shadowsocks_method_editable() {
        let mut m = Model::from_str(
            r#"version = 1
[[profiles]]
name = "demo"
protocol = "ssh2"
host = "h.example.com"

[profiles.transport.obfuscation]
kind = "shadowsocks"
method = "aes-256-gcm"
password = "secret://ss/pw"
"#,
        );
        let mut page = TransportPage::new();
        let area = Rect::new(0, 0, 100, 30);
        let mut buf = Buffer::empty(area);
        page.render(area, &mut buf, &m);
        assert_eq!(page.built_kind, "shadowsocks");
        // Move to ss.method (index 1), rewrite it.
        page.on_key(k(KeyCode::Down), &mut m);
        page.on_key(k(KeyCode::Enter), &mut m);
        page.on_key(k(KeyCode::End), &mut m);
        for _ in 0..20 {
            page.on_key(k(KeyCode::Backspace), &mut m);
        }
        for c in "chacha20-ietf-poly1305".chars() {
            page.on_key(k(KeyCode::Char(c)), &mut m);
        }
        page.on_key(k(KeyCode::Enter), &mut m);
        match super::obfs(m.profile()) {
            Some(ObfsConfig::Shadowsocks { method, .. }) => {
                assert_eq!(method, "chacha20-ietf-poly1305");
            }
            other => panic!("expected shadowsocks, got {other:?}"),
        }
    }
}
