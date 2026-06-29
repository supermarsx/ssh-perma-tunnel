# syntax=docker/dockerfile:1.7
#
# Dockerfile — HARDENED, minimal-attack-surface runtime image for `spt`.
#
# This is the canonical *secure* container image. It is intentionally
# different from the packaging/docker/* images:
#
#   * It builds `spt` with the crate DEFAULT feature set — no libssh2 FFI, no
#     vendored OpenSSL, no FUSE. The default SSH2 backend is pure-Rust russh
#     (rustls + ring), so the binary does not link OpenSSL.
#   * The runtime stage is debian:bookworm-slim hardened with an explicit
#     non-root user, the absolute minimum runtime libraries, and a tini init.
#
# WHY debian-slim and NOT distroless:
#   `ldd` on the built binary shows it links two system libs pulled in by
#   always-on crates: `libdbus-1.so.3` (spt-secrets' keyring
#   `sync-secret-service` backend) and `libgssapi_krb5.so.2` (spt-auth-sspi's
#   Unix GSSAPI backend), each dragging a transitive chain (libsystemd, libcap,
#   libgcrypt, libkrb5*, liblzma, libzstd, …). gcr.io/distroless/cc-debian12
#   ships none of these, and hand-copying the whole chain into distroless is
#   brittle and easy to get subtly wrong. The task explicitly sanctions falling
#   back to debian:bookworm-slim + a non-root user when distroless cannot
#   satisfy a runtime lib; that is exactly this case. We install only those two
#   libs (+ ca-certs + tini; apt resolves their chains), create a non-root user,
#   and keep every other hardening control (read-only rootfs, cap_drop ALL,
#   no-new-privileges) in docker-compose.yml.
#
# NOTE: libgssapi/libkrb5 are LINKED but GSSAPI auth is not usable out of the
# box — there is no krb5.conf / keytab in the image. Mount those at runtime if
# you actually use Kerberos. FUSE mounts are likewise not built in (they need
# libfuse + the SYS_ADMIN capability). For those, use the
# packaging/docker/Dockerfile variant or a custom image.
#
# Build from the repository root (uses the committed Cargo.lock via --locked):
#   docker build -t spt:hardened .
#
# Run (prints version; confirms the binary works and runs as non-root):
#   docker run --rm spt:hardened --version
#
# See docs/docker.md for the full hardened deployment guide.

# ---------------------------------------------------------------------------
# Stage 1 — builder
# ---------------------------------------------------------------------------
# rust:1.88 matches the workspace MSRV (rust-version = "1.88"). The full image
# (not -slim) already carries the C toolchain that `ring`/build scripts use, so
# we avoid an apt step entirely; ca-certificates is present for the registry.
FROM rust:1.88-bookworm AS builder

# Build deps for the DEFAULT feature set. The default build links libdbus
# (spt-secrets' keyring sync-secret-service backend) and libgssapi (spt-auth-sspi
# Unix backend); libgssapi's own dev package is provided by the vendored fork,
# so the only system -dev package we add is D-Bus:
#   - libdbus-1-dev + pkg-config: locate and link libdbus.
#   - clang + libclang: `libdbus-sys`'s build script runs `bindgen`, which needs
#     libclang to parse the D-Bus headers.
# (No libssh2 / OpenSSL / FUSE — those are opt-in features, not built here.)
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        clang \
        libclang-dev \
        libdbus-1-dev \
        pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy the whole workspace. We do not use a dummy-main dependency pre-warm
# because the BuildKit cache mounts below give the bulk of the speedup with no
# risk of a stale split between the manifest copy and the source copy. The
# Cargo.lock is the committed one; --locked makes the build fail rather than
# silently re-resolve.
COPY . .

# DEFAULT FEATURES ONLY. No --features flag → no FUSE (mount-fuse),
# no ssh2-vendored-openssl, no snmp. Build just the `spt` binary, strip it,
# and stage it. (keyring + libgssapi are always-on crate deps — see the
# runtime stage's lib install.)
#
# The cache mounts speed up repeat builds locally; they are not part of the
# final image. The release binary is copied OUT of the cache-mounted target/
# dir before the mount is released (a bind cache mount is not readable in later
# layers), then stripped of symbols to shrink it.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/build/target \
    cargo build --release --locked -p spt-bin --bin spt \
    && cp /build/target/release/spt /usr/local/bin/spt \
    && strip /usr/local/bin/spt

# ---------------------------------------------------------------------------
# Stage 2 — runtime (debian:bookworm-slim, non-root, minimal libs)
# ---------------------------------------------------------------------------
FROM debian:bookworm-slim AS runtime

ARG SPT_UID=65532
ARG SPT_GID=65532

# Install ONLY what the default-feature binary needs at runtime. The `ldd`
# output on the built binary shows two system libraries pulled in by always-on
# crates (apt resolves each one's transitive chain — libsystemd, libcap,
# libgcrypt, libkrb5*, liblzma, libzstd, … — automatically):
#   - libdbus-1-3:        keyring `sync-secret-service` backend (spt-secrets).
#   - libgssapi-krb5-2:   the `libgssapi` (GSSAPI/Kerberos) link from
#                         spt-auth-sspi's Unix backend.
#   - ca-certificates:    rustls needs the CA bundle to validate any HTTPS
#                         observability sink (OTLP / HTTPS-JSONL).
#   - tini:               clean PID-1 signal forwarding / zombie reaping.
# Then create a non-root system user and the config/state dirs it owns.
# apt lists are removed to keep the layer (and CVE surface) small.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        libdbus-1-3 \
        libgssapi-krb5-2 \
        tini \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid "${SPT_GID}" spt \
    && useradd  --system --uid "${SPT_UID}" --gid "${SPT_GID}" \
                --home-dir /var/lib/spt --shell /usr/sbin/nologin spt \
    && install -d -m 0750 -o spt -g spt /etc/spt \
    && install -d -m 0750 -o spt -g spt /var/lib/spt

# Copy ONLY the binary. No source, no build tools, no secrets enter the image.
COPY --from=builder /usr/local/bin/spt /usr/local/bin/spt

# Config and state locations. Operators MUST bind-mount these at runtime:
#   * /etc/spt/spt.toml — config, mounted READ-ONLY. No secrets are baked in.
#   * /var/lib/spt      — writable state (known_hosts, supervisor lock,
#                         snapshots). Mount a writable volume here; the
#                         compose read-only rootfs makes everything else
#                         immutable.
ENV SPT_CONFIG_PATH=/etc/spt/spt.toml \
    SPT_STATE_DIR=/var/lib/spt \
    SPT_LOG_LEVEL=info \
    RUST_BACKTRACE=1

# Run as the non-root user. Belt-and-suspenders: the compose profile also sets
# `user:` and `no-new-privileges`.
USER spt:spt
WORKDIR /var/lib/spt

# `tunnel health --output json` exercises the same liveness code path as the
# CLI; start-period lets the supervisor make its first connect attempt.
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD ["/usr/local/bin/spt", "tunnel", "health", "--output", "json"]

# tini as PID 1 forwards SIGTERM/SIGINT to spt and reaps zombies; spt installs
# its own graceful-shutdown handlers behind it.
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/spt"]

# Sensible default: run configured tunnels in the foreground against the
# bind-mounted config + state dir. Override `command:`/CMD for one-shot CLI use
# (e.g. `docker run --rm spt:hardened --version`).
CMD ["tunnel", "run", "--foreground", \
     "--config", "/etc/spt/spt.toml", \
     "--state-dir", "/var/lib/spt"]

LABEL org.opencontainers.image.title="spt" \
      org.opencontainers.image.description="Permanent SSH2/SSH3 tunnels — hardened debian-slim image (default features, non-root)." \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.source="https://github.com/supermarsx/ssh-perma-tunnel" \
      org.opencontainers.image.documentation="https://github.com/supermarsx/ssh-perma-tunnel/blob/main/docs/docker.md" \
      org.opencontainers.image.base.name="debian:bookworm-slim"
