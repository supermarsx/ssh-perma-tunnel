# syntax=docker/dockerfile:1.6
#
# Multi-arch scratch container for spt. Built per-arch by build-image.sh,
# which stages the appropriate per-target binary at build context root as
# `dist/spt-${TARGETARCH}` so this COPY resolves correctly under both
# `linux/amd64` and `linux/arm64` buildx platforms.
#
# Usage (from build-image.sh):
#   docker buildx build --platform linux/amd64,linux/arm64 \
#       --tag ghcr.io/spt/spt:<version> \
#       --file scripts/docker/Dockerfile <staged-context>
FROM scratch

ARG TARGETARCH
COPY dist/spt-${TARGETARCH} /spt

ENTRYPOINT ["/spt"]
