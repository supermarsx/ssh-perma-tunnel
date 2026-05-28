#!/usr/bin/env bash
# Verify the Linux `package` job path: build the binary, install prebuilt
# cargo-deb/cargo-generate-rpm (as taiki-e/install-action would), then run the
# pack scripts against the prebuilt binary (--no-build).
set -u
T=x86_64-unknown-linux-gnu
apt-get update -qq >/dev/null 2>&1
apt-get install -y -qq pkg-config libssl-dev libdbus-1-dev libkrb5-dev clang libclang-dev curl >/dev/null 2>&1
rustup target add "$T" >/dev/null 2>&1

echo "===== build binary ====="
cargo build --locked --release --target "$T" -p spt-bin --bin spt 2>&1 | tail -3
# Mirror the package job: place the binary at the repo-relative path the pack
# scripts read (the job downloads the build artifact to target/<t>/release/).
mkdir -p "target/$T/release"
cp "${CARGO_TARGET_DIR:-target}/$T/release/spt" "target/$T/release/spt"
ls -la "target/$T/release/spt" || { echo "NO BINARY"; exit 1; }

echo "===== install prebuilt cargo-deb / cargo-generate-rpm (cargo-binstall) ====="
curl -sSL https://raw.githubusercontent.com/cargo-bins/cargo-binstall/main/install-from-binstall-release.sh | bash >/dev/null 2>&1
export PATH="$HOME/.cargo/bin:$PATH"
cargo binstall -y cargo-deb cargo-generate-rpm >/dev/null 2>&1
cargo deb --version; cargo generate-rpm --version

echo "===== pack-tarball ====="; bash scripts/package/pack-tarball.sh "$T" 2>&1 | tail -3; echo "tarball exit=${PIPESTATUS[0]}"
echo "===== pack-deb ====="; bash scripts/package/pack-deb.sh "$T" 2>&1 | tail -5; echo "deb exit=${PIPESTATUS[0]}"
echo "===== pack-rpm ====="; bash scripts/package/pack-rpm.sh "$T" 2>&1 | tail -5; echo "rpm exit=${PIPESTATUS[0]}"
echo "===== dist/ ====="; find dist -type f 2>/dev/null
