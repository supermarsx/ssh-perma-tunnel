#!/usr/bin/env bash
# Verify the CI Linux dep set on a BARE ubuntu:24.04 (mimics the GitHub runner,
# which — unlike the official `rust` image's buildpack-deps base — does NOT
# ship libkrb5-dev). Installs the runner baseline + the CI-added deps, then
# runs the exact clippy/check commands.
set -u
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null 2>&1
# Runner baseline (already present on ubuntu-latest) + CI-added deps.
apt-get install -y -qq \
  build-essential curl ca-certificates git \
  pkg-config libssl-dev clang \
  libdbus-1-dev libkrb5-dev libclang-dev >/dev/null 2>&1
echo "gssapi.h locations:"; find / -name 'gssapi.h' 2>/dev/null | head
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain 1.85.0 --profile minimal --component clippy >/dev/null 2>&1
. "$HOME/.cargo/env"
rustc --version
cd /work
echo "===== CHECK ====="
cargo check --workspace --locked 2>&1 | tail -15
echo "CHECK_EXIT=${PIPESTATUS[0]}"
echo "===== CLIPPY ====="
cargo clippy --workspace --all-targets --locked -- -D warnings 2>&1 | tail -15
echo "CLIPPY_EXIT=${PIPESTATUS[0]}"
