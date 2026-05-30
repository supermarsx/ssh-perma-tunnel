//! Rasterise `assets/icon.svg` into every format the packaging recipes consume.
//!
//! Outputs (under `assets/`):
//!
//! - `icon-{16,32,48,64,128,256,512,1024}.png`
//! - `icon.ico`  — multi-resolution Windows icon (16/32/48/64/128/256)
//! - `icon.icns` — macOS icon (16/32/64/128/256/512/1024 + @2x variants)
//!
//! Idempotent. Run from the repo root:
//!
//! ```sh
//! cargo run --manifest-path tools/icon-build/Cargo.toml
//! ```

use anyhow::{anyhow, Context, Result};
use resvg::tiny_skia;
use std::fs;
use std::path::PathBuf;

const PNG_SIZES: &[u32] = &[16, 32, 48, 64, 128, 256, 512, 1024];
const ICO_SIZES: &[u32] = &[16, 32, 48, 64, 128, 256];

/// macOS icon entries — (filename suffix used by `iconutil` if we ever ship
/// an .iconset, size in px). The `icns` crate maps the size to the right
/// OSType tag internally; we hand it the rendered bitmap.
const ICNS_SIZES: &[u32] = &[16, 32, 64, 128, 256, 512, 1024];

fn main() -> Result<()> {
    let repo_root = repo_root()?;
    let svg_path = repo_root.join("assets/icon.svg");
    let out_dir = repo_root.join("assets");
    let svg_bytes = fs::read(&svg_path)
        .with_context(|| format!("read svg source: {}", svg_path.display()))?;

    let opts = usvg::Options::default();
    let tree = usvg::Tree::from_data(&svg_bytes, &opts)
        .map_err(|e| anyhow!("parse svg: {e}"))?;

    // --- PNGs ---------------------------------------------------------------
    for &size in PNG_SIZES {
        let png = render(&tree, size)?;
        let path = out_dir.join(format!("icon-{size}.png"));
        fs::write(&path, &png).with_context(|| format!("write {}", path.display()))?;
        println!("  wrote {}", path.display());
    }

    // --- ICO (multi-resolution) --------------------------------------------
    let mut ico = ico::IconDir::new(ico::ResourceType::Icon);
    for &size in ICO_SIZES {
        let png = render(&tree, size)?;
        let image = ico::IconImage::read_png(std::io::Cursor::new(&png))
            .map_err(|e| anyhow!("ico read_png at {size}px: {e}"))?;
        ico.add_entry(ico::IconDirEntry::encode(&image)
            .map_err(|e| anyhow!("ico encode at {size}px: {e}"))?);
    }
    let ico_path = out_dir.join("icon.ico");
    let mut ico_file = fs::File::create(&ico_path)
        .with_context(|| format!("create {}", ico_path.display()))?;
    ico.write(&mut ico_file).with_context(|| "write ico")?;
    println!("  wrote {}", ico_path.display());

    // --- ICNS (macOS) ------------------------------------------------------
    let mut family = icns::IconFamily::new();
    for &size in ICNS_SIZES {
        let png = render(&tree, size)?;
        let image = icns::Image::read_png(std::io::Cursor::new(&png))
            .map_err(|e| anyhow!("icns read_png at {size}px: {e}"))?;
        family.add_icon(&image)
            .map_err(|e| anyhow!("icns add_icon at {size}px: {e}"))?;
    }
    let icns_path = out_dir.join("icon.icns");
    let icns_file = fs::File::create(&icns_path)
        .with_context(|| format!("create {}", icns_path.display()))?;
    family.write(icns_file).with_context(|| "write icns")?;
    println!("  wrote {}", icns_path.display());

    Ok(())
}

/// Render the SVG to a `size x size` PNG byte buffer.
fn render(tree: &usvg::Tree, size: u32) -> Result<Vec<u8>> {
    let mut pixmap = tiny_skia::Pixmap::new(size, size)
        .ok_or_else(|| anyhow!("alloc {size}x{size} pixmap"))?;
    let scale = size as f32 / 1024.0;
    let transform = tiny_skia::Transform::from_scale(scale, scale);
    resvg::render(tree, transform, &mut pixmap.as_mut());
    let png = pixmap.encode_png().map_err(|e| anyhow!("encode png at {size}: {e}"))?;
    Ok(png)
}

/// Walk upward until we find Cargo.toml + assets/icon.svg. Lets us run from
/// any subdirectory of the repo.
fn repo_root() -> Result<PathBuf> {
    let mut dir = std::env::current_dir()?;
    loop {
        if dir.join("assets/icon.svg").exists() && dir.join("Cargo.toml").exists() {
            return Ok(dir);
        }
        if !dir.pop() {
            return Err(anyhow!("could not locate repo root with assets/icon.svg"));
        }
    }
    #[allow(unreachable_code)]
    Ok(PathBuf::new())
}
