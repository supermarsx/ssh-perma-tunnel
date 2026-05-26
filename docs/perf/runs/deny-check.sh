#!/usr/bin/env bash
# Verifies the CI `security` gate: run a prebuilt cargo-deny (matching what
# taiki-e/install-action installs — latest 0.19.x) against the repo deny.toml,
# to confirm the 0.18 -> 0.19 bump didn't break the config schema.
set -u
apt-get update -qq >/dev/null 2>&1
apt-get install -y -qq curl ca-certificates >/dev/null 2>&1
ver="${CARGO_DENY_VER:-0.19.7}"
base="cargo-deny-${ver}-x86_64-unknown-linux-musl"
curl -sSL "https://github.com/EmbarkStudios/cargo-deny/releases/download/${ver}/${base}.tar.gz" | tar xz
"./${base}/cargo-deny" --version
echo "===== cargo deny check ====="
"./${base}/cargo-deny" check 2>&1 | tail -50
echo "DENY_EXIT=${PIPESTATUS[0]}"
