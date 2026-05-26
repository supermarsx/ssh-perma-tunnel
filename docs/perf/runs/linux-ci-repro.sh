#!/usr/bin/env bash
# Reproduces the Linux-only CI Rust gates (clippy / doc / msrv check) that
# cannot run on the Windows dev box. Invoked inside a rust:1.85 container.
set -u
apt-get update -qq >/dev/null 2>&1
apt-get install -y -qq pkg-config libssl-dev libdbus-1-dev clang libclang-dev >/dev/null 2>&1
rustup component add clippy >/dev/null 2>&1

echo "===== MSRV CHECK ====="
cargo check --workspace --locked 2>&1 | tail -40
echo "CHECK_EXIT=${PIPESTATUS[0]}"

echo "===== CLIPPY ====="
cargo clippy --workspace --all-targets --locked -- -D warnings 2>&1 | tail -80
echo "CLIPPY_EXIT=${PIPESTATUS[0]}"

echo "===== DOC ====="
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked 2>&1 | tail -50
echo "DOC_EXIT=${PIPESTATUS[0]}"
