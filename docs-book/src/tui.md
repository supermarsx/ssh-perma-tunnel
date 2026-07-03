# TUI Configurator

`spt` ships an interactive terminal-UI profile configurator built with
[ratatui](https://github.com/ratatui-org/ratatui) and
[crossterm](https://github.com/crossterm-rs/crossterm). It provides a
multi-page wizard for editing a single profile at a time, writing the result
back through `spt-config`'s comment-preserving mutation path so operator
comments and field ordering are retained.

## Launching

The TUI is invoked via `spt profile configure`:

```sh
# Open the TUI on a specific profile in the default config.
spt profile configure --tui --name edge

# Open the TUI on the first profile in a custom config file.
spt profile configure --tui --config /etc/spt/spt.toml

# Open the TUI; if the config has no profiles, seeds a new "new-profile" entry.
spt profile configure --tui --config /etc/spt/spt.toml
```

`--tui` and `--no-tui` are mutually exclusive. When neither is passed the
default behaviour depends on whether a terminal is attached. Pass `--tui`
explicitly in scripts to ensure the wizard runs.

If `--name` is omitted and the config contains at least one profile, the first
profile is selected automatically. If the config file is empty, a new profile
named `new-profile` is seeded so the wizard has something to edit.

The `--from-template NAME` flag pre-fills the new profile from a built-in
template. The `--field KEY=VALUE` flag applies one or more key-value overrides
non-interactively (implies `--no-tui`).

## Page layout

The wizard is split into 15 pages, navigable by tab order or number key. A
status bar across the bottom shows the current connection state and any pending
unsaved changes.

| # | Page tab title | What it covers |
|---|---------------|----------------|
| 1 | Basics | Profile id, description, protocol (ssh2 / ssh3), host, port, user, connect timeout, startup policy, failure policy |
| 2 | Endpoints | Multi-target failover endpoint list (host/port pairs); **two-pane layout** — left pane lists endpoints, right pane edits the selected entry; navigate panes with `Left` / `Right` |
| 3 | Hops | Multi-hop / ProxyJump chain entries (per-hop host, user, auth) |
| 4 | Auth | Authentication method, identity file, passphrase, GSSAPI / SSPI / TOTP settings, secret references |
| 5 | Trust | Host-key trust mode (`known_hosts`, `pinned`, `tofu`, `insecure`), known\_hosts file path, SHA-256 pins |
| 6 | Crypto | Cipher, key-exchange, MAC, and host-key algorithm allow-lists |
| 7 | Timings & Keepalive | Connection-setup timeouts (auth, handshake, TCP) plus session keepalive interval, timeout, and missed-keepalive threshold |
| 8 | Reconnect/Failover | Reconnect policy (initial delay, max delay, jitter, max attempts), instability detection thresholds, failover trigger settings |
| 9 | Limits | Per-forward and per-profile connection caps and throttle settings |
| 10 | Forwards | Local, remote, and UDP forward entries; **two-pane layout** — left pane lists forwards, right pane edits the selected forward's fields; navigate panes with `Left` / `Right` |
| 11 | Transport | Obfuscation transport selection and parameters (obfs4, meek-http, websocket, shadowsocks) |
| 12 | DNS | Managed DNS record bindings for this profile |
| 13 | Events | Per-profile event-bus binding tags |
| 14 | Diagnostics | Per-profile observability labels and metrics tags |
| 15 | Review & Save | Scrollable preview of the canonical TOML as it will be written; save from here |

The two-pane pages (Endpoints and Forwards) use `Left` / `Right` to move focus
between the list pane and the edit pane. Other pages use the standard
single-pane field list.

## Navigation keybindings

These bindings apply when no field is in edit mode.

| Key | Action |
|-----|--------|
| `↑` / `k` | Move focus up one field |
| `↓` / `j` | Move focus down one field |
| `←` / `→` | Switch pane (Endpoints and Forwards pages only) |
| `Tab` / `]` / `l` | Next page |
| `Shift-Tab` / `[` / `h` | Previous page |
| `1` – `9` | Jump to page by number (pages 1–9) |
| `Enter` | Begin editing the focused field |
| `?` | Toggle keyboard-help overlay |
| `Ctrl-S` | Save (atomic, comment-preserving) |
| `q` | Quit (press twice if there are unsaved changes) |
| `Ctrl-C` | Force quit without saving |

## Editing keybindings

### Universal (any field in edit mode)

| Key | Action |
|-----|--------|
| `Enter` | Commit the current edit |
| `Esc` | Cancel the current edit without saving |

### Boolean fields and multi-select tickboxes

| Key | Action |
|-----|--------|
| `Space` | Flip the focused tickbox |
| `t` | Flip the focused tickbox (alternative) |
| `Enter` | Commit without flipping |
| `s` | Commit a Multi field (alternative to `Enter`) |

Only `Space` and `t` flip a tickbox. `Enter`, `y`, `n`, and any other key
leave the underlying value unchanged. This makes the commit gesture (`Enter`)
safe: you can navigate through a multi-select list and press `Enter` without
accidentally toggling an option you just reviewed.

### Choice fields and multi-select cursor

| Key | Action |
|-----|--------|
| `←` / `→` | Rotate the cursor through available options (wraps) |
| `↑` / `↓` | Rotate the cursor through available options (wraps) |
| `Space` / `t` | (Multi only) flip the cursor option's tickbox |
| `Enter` | Commit the currently displayed cursor value |

## Review & Save page

The final page renders the canonical TOML and is scrollable when the content
exceeds the viewport height. The title bar shows the current scroll position
(e.g. `line 12/87`).

| Key | Action |
|-----|--------|
| `↑` / `k` | Scroll up one line |
| `↓` / `j` | Scroll down one line |
| `PageUp` / `PageDown` | Scroll one screen |
| `Home` / `End` | Jump to start / end of the preview |
| `Ctrl-S` | Save |

## What the wizard writes

On save, the profile is round-tripped through `toml_edit` so operator comments
and field ordering are preserved. Validation runs synchronously before the
write; an invalid edit is rejected and the wizard returns to the offending
field with an inline error message. The write itself is atomic (write to a
temporary file, then rename) so a crash during save cannot corrupt the config.

The TUI writes only the profile it was given — it does not reorder or rewrite
other profiles, top-level config tables, or comments that belong to other
sections.

## Non-interactive alternatives

If you prefer not to use the TUI:

- `spt profile set <name> KEY=VALUE ...` — apply one or more key-value
  overrides without opening the wizard.
- `spt profile configure --no-tui --field KEY=VALUE` — the same override
  mechanism via the `configure` subcommand.
- Edit `spt.toml` directly; run `spt config validate` to check the result.

See [Configuration Reference](configuration-reference.md) for the complete
field reference and [CLI Reference](cli-reference.md) for `spt profile`
subcommand details.
