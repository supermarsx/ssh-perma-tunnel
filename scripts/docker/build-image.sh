#!/usr/bin/env bash
# build-image.sh — multi-arch docker buildx for spt.
#
# Stages the per-target Linux musl binaries into a scratch context dir
# laid out as:
#   <ctx>/dist/spt-amd64
#   <ctx>/dist/spt-arm64
#   <ctx>/Dockerfile (copied from scripts/docker/Dockerfile)
# Then runs `docker buildx build --platform linux/amd64,linux/arm64`.

set -euo pipefail

# shellcheck source=../build/_common.sh
source "$(dirname "$(readlink -f "${BASH_SOURCE[0]}" 2>/dev/null || echo "${BASH_SOURCE[0]}")")/../build/_common.sh"

usage() {
  cat <<EOF
Usage: scripts/docker/build-image.sh [--push] [--tag <ref> ...] [--registry <prefix>]

Builds a multi-arch container image (linux/amd64 + linux/arm64) from the
already-built musl binaries in target/.

Options:
  --push                docker push after build (otherwise --load is implied
                        only on single-arch hosts; for multi-arch we use
                        --output type=image without push)
  --tag <ref>           additional image ref (repeatable)
  --registry <prefix>   default: ghcr.io/spt/spt
  --dry-run             print the buildx command and exit
  -h, --help            show this help

Required tools: docker, docker buildx.
EOF
  print_help_footer
}

push=0
dry_run=0
extra_tags=()
registry=ghcr.io/spt/spt

while [[ $# -gt 0 ]]; do
  case $1 in
    -h|--help) usage; exit 0 ;;
    --push) push=1; shift ;;
    --tag) extra_tags+=("$2"); shift 2 ;;
    --tag=*) extra_tags+=("${1#*=}"); shift ;;
    --registry) registry=$2; shift 2 ;;
    --registry=*) registry=${1#*=}; shift ;;
    --dry-run) dry_run=1; shift ;;
    *) die "unknown flag: $1" ;;
  esac
done

have_cmd docker || die "docker not on PATH"
docker buildx version >/dev/null 2>&1 || die "docker buildx unavailable"

root=$(repo_root)
version=$(version_from_cargo)

amd64_bin="$root/target/x86_64-unknown-linux-musl/release/spt"
arm64_bin="$root/target/aarch64-unknown-linux-musl/release/spt"
[[ -f "$amd64_bin" ]] || die "missing musl amd64 binary: $amd64_bin"
[[ -f "$arm64_bin" ]] || die "missing musl arm64 binary: $arm64_bin"

ctx=$(mktemp -d -t spt-docker-ctx.XXXXXX)
trap 'rm -rf "$ctx"' EXIT

mkdir -p "$ctx/dist"
cp "$amd64_bin" "$ctx/dist/spt-amd64"
cp "$arm64_bin" "$ctx/dist/spt-arm64"
chmod 0755 "$ctx/dist/spt-amd64" "$ctx/dist/spt-arm64"
cp "$root/scripts/docker/Dockerfile" "$ctx/Dockerfile"

tags=(--tag "$registry:$version" --tag "$registry:latest")
for t in "${extra_tags[@]}"; do tags+=(--tag "$t"); done

cmd=(docker buildx build
     --platform linux/amd64,linux/arm64
     --file "$ctx/Dockerfile"
     "${tags[@]}")
if (( push )); then
  cmd+=(--push)
else
  warn "no --push; multi-arch image stays in the build cache only"
fi
cmd+=("$ctx")

info "command: ${cmd[*]}"
if (( dry_run )); then exit 0; fi
"${cmd[@]}"
