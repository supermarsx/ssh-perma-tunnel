# syntax=docker/dockerfile:1.7
#
# packaging/docker/Dockerfile — production runtime image for `spt`.
#
# Multi-stage build:
#   - builder: rust:1.83-slim-bookworm, builds `spt` with --release --locked
#     against system libssh2 + vendored OpenSSL (glibc target).
#   - runtime: debian:bookworm-slim, copies the binary + man pages + license,
#     creates non-root spt:1000, prepares /etc/spt and /var/lib/spt.
#
# Build from the repository root:
#   docker build -f packaging/docker/Dockerfile -t spt:local .
#
# The image is the default target for packaging/docker/docker-compose.yml.

# ---------------------------------------------------------------------------
# Stage 1 — builder
# ---------------------------------------------------------------------------
FROM rust:1.83-slim-bookworm AS builder

# Build deps:
#   - pkg-config + libssh2-1-dev + libssl-dev + zlib1g-dev: link spt-ssh2.
#   - perl + make: required to build the vendored OpenSSL used by
#     the `ssh2-vendored-openssl` feature.
#   - ca-certificates: needed by `cargo` when fetching the registry.
#   - git: cargo may need it for some VCS metadata.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        git \
        libssh2-1-dev \
        libssl-dev \
        make \
        perl \
        pkg-config \
        zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy the full workspace. We intentionally do not pre-warm dependencies via
# a dummy main.rs trick because the workspace is large and Cargo.lock-locked
# builds are deterministic; the BuildKit cache mounts below give us most of
# the speedup with none of the staleness pitfalls.
COPY . .

# `--locked` enforces the committed Cargo.lock. We do NOT enable the
# `ssh2-vendored-openssl` feature here because we already link the
# distro-provided libssh2/openssl; the result is a smaller, faster build
# that still ships a glibc-friendly runtime.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/build/target \
    cargo build --release --locked -p spt-bin --bin spt \
    && cp /build/target/release/spt /usr/local/bin/spt \
    && strip /usr/local/bin/spt

# ---------------------------------------------------------------------------
# Stage 2 — runtime
# ---------------------------------------------------------------------------
FROM debian:bookworm-slim AS runtime

ARG SPT_UID=1000
ARG SPT_GID=1000

# Runtime deps mirror the libraries the binary was linked against.
# tini gives us PID-1 signal handling without bringing in systemd.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        libssh2-1 \
        libssl3 \
        tini \
        zlib1g \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid "${SPT_GID}" spt \
    && useradd  --system --uid "${SPT_UID}" --gid "${SPT_GID}" \
                --home-dir /var/lib/spt --shell /usr/sbin/nologin spt \
    && install -d -m 0750 -o spt -g spt /etc/spt \
    && install -d -m 0750 -o spt -g spt /var/lib/spt \
    && install -d -m 0750 -o spt -g spt /run/spt

COPY --from=builder /usr/local/bin/spt /usr/local/bin/spt
COPY license.md                         /usr/share/doc/spt/license.md
COPY packaging/man/                     /usr/share/man/

# Default config lives in /etc/spt/spt.toml; operators bind-mount their own.
# State (known_hosts, supervisor lock, snapshots) is persisted under /var/lib/spt.
ENV SPT_CONFIG_PATH=/etc/spt/spt.toml \
    SPT_STATE_DIR=/var/lib/spt \
    SPT_LOG_LEVEL=info \
    RUST_BACKTRACE=1

USER spt:spt
WORKDIR /var/lib/spt

# Healthcheck hits the same code path as `spt tunnel health` on the CLI.
# Start-period gives the supervisor time for the first connect attempt.
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD ["/usr/local/bin/spt", "tunnel", "health", "--output", "json"]

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/spt"]
CMD ["tunnel", "run", "--foreground", \
     "--config", "/etc/spt/spt.toml", \
     "--state-dir", "/var/lib/spt"]

LABEL org.opencontainers.image.title="spt" \
      org.opencontainers.image.description="Permanent SSH2/SSH3 tunnels with reconnect, observability, and service integration." \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.source="https://github.com/Mariana/ssh-perma-tunnel" \
      org.opencontainers.image.documentation="https://github.com/Mariana/ssh-perma-tunnel/blob/main/packaging/docker/README.md"
