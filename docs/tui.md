# TUI

`spt profile configure --tui` is an interactive ratatui+crossterm wizard
for editing a profile in the loaded config. Changes are written back through
the canonical `spt-config` mutation path, preserving comments and ordering.

## Launching

    spt profile configure --tui --config /etc/spt/spt.toml --name edge

If `--name` is omitted and the config has at least one profile, the first
is selected. If the config is empty, a new `new-profile` is seeded.

## Panels

- Profile list (left).
- Profile details (right): connection, auth, trust, keepalive, reconnect,
  failover, limits, forwards.
- Status bar with current state and pending changes.

## Keybindings

| Key            | Action                                  |
|----------------|-----------------------------------------|
| `Tab` / `S-Tab`| Move between fields.                    |
| `Enter`        | Edit field / confirm.                   |
| `s`            | Save and exit.                          |
| `q`            | Quit without saving.                    |
| `?`            | Show context help.                      |

## Output

On save, the underlying TOML is round-tripped through `toml_edit` so
operator comments are preserved. Validation runs synchronously before
write; an invalid edit is rejected and the wizard returns to the field.
