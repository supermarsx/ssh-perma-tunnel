# `assets/`

Canonical brand + packaging assets for `spt`.

## Files

| File                                           | Purpose                                                     |
|------------------------------------------------|-------------------------------------------------------------|
| `icon.svg`                                     | **Canonical source.** All raster formats derive from this.  |
| `icon-{16,32,48,64,128,256,512,1024}.png`      | Square PNG at every standard size. Linux `.desktop`, Snap, Flathub, GHCR README, social previews. |
| `icon.ico`                                     | Multi-resolution Windows icon (16/32/48/64/128/256). Consumed by `packaging/msi/main.wxs`. |
| `icon.icns`                                    | macOS icon (16…1024 + retina variants). Consumed by `scripts/package/pack-pkg-macos.sh`. |

## Regenerating

The PNG / ICO / ICNS files are **derived** — never hand-edit them. Edit
`icon.svg`, then regenerate from the repo root:

```sh
cargo run --manifest-path tools/icon-build/Cargo.toml --release
```

`tools/icon-build` is a small standalone Rust binary (`resvg` + `ico` + `icns`).
It lives outside the main workspace so its image-codec dependency tree doesn't
hit `cargo {check,test,clippy} --workspace`.

## Design

- **Palette** — `#1f2933` slate background, `#cbd5e1` outline for the terminal
  glyph, `#5eead4 → #34d399` teal/green gradient for the tunnel stroke.
- **Form** — a stylised terminal-prompt block (the "local" end) connected to a
  tunnel-arrow that exits toward the bottom-right corner (the "remote" end).
  Conveys the project tagline without text.
- **Stroke geometry** — 45° / orthogonal, so the shape stays crisp at 16/32 px
  without sub-pixel artefacts.

If a wordmark variant is needed (e.g. for the README header or social cards),
add `assets/wordmark.svg` and extend `tools/icon-build` to rasterise it too.
