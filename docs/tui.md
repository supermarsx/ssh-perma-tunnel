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

### Navigation (no field in edit mode)

| Key                  | Action                                         |
|----------------------|------------------------------------------------|
| `↑` / `k`            | Move focus up                                  |
| `↓` / `j`            | Move focus down                                |
| `Tab` / `]` / `l`    | Next page                                      |
| `BackTab` / `[` / `h`| Previous page                                  |
| `1`-`9`              | Jump to page by number                         |
| `Enter`              | Begin editing the focused field                |
| `?`                  | Toggle keyboard-help overlay                   |
| `Ctrl-S`             | Save (atomic, comment-preserving)              |
| `q`                  | Quit (press twice to discard unsaved changes)  |
| `Ctrl-C`             | Force quit                                     |

### Editing — universal

| Key       | Action                                |
|-----------|---------------------------------------|
| `Enter`   | Commit the current edit               |
| `Esc`     | Cancel the current edit               |

### Editing — tickboxes (Bool fields and Multi options)

| Key       | Action                                |
|-----------|---------------------------------------|
| `Space`   | Flip the focused tickbox              |
| `t`       | Flip the focused tickbox (alt)        |
| `Enter`   | Commit (does **not** flip)            |
| `s`       | Commit a Multi (alternative to Enter) |

Only `Space` and `t` flip a tickbox. Every other key — including `Enter`,
`y`, and `n` — leaves the underlying value unchanged. This keeps the
commit gesture (`Enter`) safe and predictable.

### Editing — selectors (Choice fields and Multi cursor)

| Key                | Action                                          |
|--------------------|-------------------------------------------------|
| `←` / `→`          | Rotate cursor through options (wraps)           |
| `↑` / `↓`          | Rotate cursor through options (wraps)           |
| `Space` / `t`      | (Multi only) flip the cursor option's tickbox   |
| `Enter`            | Commit the displayed cursor value               |

## Output

On save, the underlying TOML is round-tripped through `toml_edit` so
operator comments are preserved. Validation runs synchronously before
write; an invalid edit is rejected and the wizard returns to the field.
