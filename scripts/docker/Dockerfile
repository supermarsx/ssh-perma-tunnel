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
ARG VERSION=unknown
ARG REVISION=unknown
ARG BUILD_DATE=unknown

COPY dist/spt-${TARGETARCH} /spt

# OCI image annotations (https://github.com/opencontainers/image-spec).
# These surface on ghcr.io's web UI and are consumed by tools like
# `docker inspect`, `crane`, `cosign`. Keep title/description short —
# rendered inline on the registry page. The dynamic values are populated
# from the release workflow's `docker buildx build --build-arg ...`.
LABEL org.opencontainers.image.title="spt"
LABEL org.opencontainers.image.description="Permanent SSH2/SSH3 tunnels with reconnect, observability, and service integration."
LABEL org.opencontainers.image.url="https://github.com/supermarsx/ssh-perma-tunnel"
LABEL org.opencontainers.image.source="https://github.com/supermarsx/ssh-perma-tunnel"
LABEL org.opencontainers.image.documentation="https://github.com/supermarsx/ssh-perma-tunnel/tree/main/docs"
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.authors="Mariana"
LABEL org.opencontainers.image.vendor="supermarsx"
LABEL org.opencontainers.image.version="${VERSION}"
LABEL org.opencontainers.image.revision="${REVISION}"
LABEL org.opencontainers.image.created="${BUILD_DATE}"
LABEL org.opencontainers.image.base.name="scratch"

ENTRYPOINT ["/spt"]
