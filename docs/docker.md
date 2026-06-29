# Docker — Hardened Container Deployment

This guide covers the **hardened, secure** container image for `spt`, defined by
the repository-root [`Dockerfile`](../Dockerfile) and
[`docker-compose.yml`](../docker-compose.yml).

It is the recommended way to run `spt` in a container. If you need optional
features that this minimal image deliberately omits (FUSE mounts, OS keychain,
GSSAPI/Kerberos), see [Optional features](#optional-features-and-limitations)
and the fatter [`packaging/docker/`](../packaging/docker/readme.md) images.

## What makes this image "hardened"

| Property | How |
| --- | --- |
| Minimal runtime | `debian:bookworm-slim` with **only** `libdbus-1-3`, `libgssapi-krb5-2`, `ca-certificates`, and `tini` installed |
| Non-root | Runs as the system user `spt` (UID/GID `65532`); `USER` set in the image and re-asserted in compose |
| Smallest dependency set | Built with **default features only**: pure-Rust russh SSH (rustls/ring) — no libssh2 FFI, no OpenSSL, no FUSE |
| Binary only | The final image contains just the `spt` binary + the runtime libs above — **no source, no build tools, no secrets** |
| Reproducible | `cargo build --release --locked` against the committed `Cargo.lock` |
| Read-only rootfs | compose sets `read_only: true`; only an explicit state volume + `/tmp` tmpfs are writable |
| No privilege escalation | `security_opt: no-new-privileges:true`, `cap_drop: [ALL]` |
| Bounded blast radius | `mem_limit`, `pids_limit`, `cpus`, `ulimits`, capped JSON logs |

### Why debian-slim and not distroless

The first choice was `gcr.io/distroless/cc-debian12:nonroot` (no shell, no
package manager). It does not work for the **default** build. `ldd` on the built
binary shows it links two system libraries pulled in by always-on crates:

- `libdbus-1.so.3` — `spt-secrets` unconditionally enables the `keyring` crate's
  `sync-secret-service` backend.
- `libgssapi_krb5.so.2` — `spt-auth-sspi`'s Unix GSSAPI/Kerberos backend.

Each drags a transitive chain (libsystemd, libcap, libgcrypt, libkrb5*, liblzma,
libzstd, …). Distroless cc ships none of them, and hand-copying the whole chain
in and keeping it in sync is brittle. So the image uses `debian:bookworm-slim`
with a non-root user and installs *only* those two libs (+ ca-certs + tini; apt
resolves their chains), while every other hardening control lives in
`docker-compose.yml`. This is the sanctioned fallback when distroless cannot
satisfy a runtime library.

The tradeoff vs distroless: the slim base retains a shell and `apt` (the apt
package lists are removed to shrink the layer). The read-only rootfs,
`cap_drop: ALL`, and `no-new-privileges` in the compose profile are what
neutralise that surface at runtime — an attacker on a read-only, capability-less,
no-escalation container cannot meaningfully use the shell or package manager. If
you want a fatter image with libssh2/OpenSSL but the same non-distroless
posture, see [`packaging/docker/`](../packaging/docker/readme.md).

## Build

From the repository root:

```bash
docker build -t spt:hardened .
```

This is a full release compile of the workspace — it is slow on the first run.
BuildKit cache mounts make repeat builds fast. The `--locked` flag (baked into
the Dockerfile) makes the build fail rather than silently re-resolve
dependencies, so the image matches the committed lockfile exactly.

Confirm the binary works and the image is non-root:

```bash
docker run --rm spt:hardened --version
docker run --rm spt:hardened tunnel --help
```

## Run with Docker Compose (hardened profile)

```bash
docker build -t spt:hardened .
mkdir -p config
cp packaging/docker/example-config/spt.toml config/spt.toml   # or your own
docker compose up -d
docker compose logs -f
```

Validate the compose file without starting anything:

```bash
docker compose -f docker-compose.yml config
```

### The hardening flags, explained

Every security-relevant line in `docker-compose.yml` is commented inline. The
key ones:

- **`read_only: true`** — the container's root filesystem is immutable. An
  attacker who lands code execution cannot modify the image, drop a binary, or
  persist. Everything that must be writable is an explicit mount.
- **`tmpfs: /tmp` with `noexec,nosuid,nodev`** — scratch space that cannot be
  used to execute dropped binaries or escalate privileges, and is size-capped so
  it cannot exhaust host memory.
- **`cap_drop: [ALL]`** — removes every Linux capability. `spt` needs none for
  forwards that bind ports `>= 1024`. Only add back `NET_BIND_SERVICE` if `spt`
  must bind a privileged (`< 1024`) source port *inside* the container; most
  deployments map host ports instead and need nothing.
- **`security_opt: [no-new-privileges:true]`** — the process and all children
  can never gain privileges via setuid/setgid binaries.
- **`user: "65532:65532"`** — runs as the image's non-root user (minimal
  debian-slim, non-root), in addition
  to the image's own `USER` directive.
- **`mem_limit` / `pids_limit` / `cpus` / `ulimits`** — cap memory, process
  count (fork-bomb protection), CPU, and file descriptors so a compromised or
  buggy container cannot starve the host.
- **`logging` max-size/max-file** — bounds on-disk logs so a chatty or attacked
  container cannot fill the host disk.
- **loopback-bound `ports`** — forwards are published to `127.0.0.1` on the host
  by default, not `0.0.0.0`, so they are not world-reachable.

## Required mounts

| Path in container | Purpose | Mount as |
| --- | --- | --- |
| `/etc/spt/spt.toml` | Configuration | **read-only** bind mount (`./config` → `/etc/spt`) |
| `/var/lib/spt` | State: known_hosts cache, supervisor lock, snapshots | **writable** named volume (`spt-state`) |
| `/tmp` | Scratch | tmpfs (compose-provided) |
| `/run/secrets` (optional) | Key/token files referenced by config | **read-only** bind mount |

The read-only rootfs means `/var/lib/spt` **must** be a writable volume or the
supervisor cannot persist its lock/known_hosts and will fail to start cleanly.

## Supplying secrets safely

**No secrets are ever baked into the image or committed to any file.** The image
contains only the `spt` binary and CA certificates. Provide secrets at runtime:

- **File mount (recommended):** mount a host directory of key/token files
  read-only at `/run/secrets` and reference them from `spt.toml` (e.g. a private
  key path or a bearer-token file). Uncomment the `secrets` bind mount in
  `docker-compose.yml`.
- **Environment variable:** for the sealed-config passphrase, pass
  `SPT_CONFIG_PASSPHRASE` via your orchestrator's secret mechanism (Docker
  secrets, Kubernetes Secret, etc.) — never via a committed `.env`.
- **Never** put secrets in the `Dockerfile`, in `environment:` literals, or in a
  committed `.env`. The `.dockerignore` excludes `.env*`, `*.pem`, and `*.key`
  so local credentials cannot leak into the build context, but the operator is
  responsible for how they inject secrets at runtime.

The OS keychain / secret-service backend will not function in this image: there
is no secret-service daemon (e.g. gnome-keyring) running in the container. Use
the file or env secret backends instead.

## Healthcheck

The image declares a `HEALTHCHECK` that runs `spt tunnel health --output json`
in exec (JSON-array) form — no shell dependency. The compose file re-declares it
so `docker compose ps` shows health status and the start-period applies during
rolling updates.

## Optional features and limitations

This image is built with **default features only** for the smallest, most
portable, least-privileged runtime. The following are intentionally **not**
included; each needs a fatter base image, extra runtime libraries, and (for
FUSE) extra capabilities:

| Feature | What it adds | Why it's excluded here |
| --- | --- | --- |
| `mount-fuse` (SFTP mount) | `fuser` + `libfuse`; needs `--cap-add SYS_ADMIN` and `--device /dev/fuse` | Requires kernel FUSE access — incompatible with the locked-down, cap-dropped profile |
| keychain / secret-service | `libdbus` / secret-service at runtime | Distroless has no D-Bus; use file/env secret backends instead |
| GSSAPI / Kerberos | linked (`libgssapi-krb5-2`), but needs a `krb5.conf` + keytab to function | The libs are present; mount your Kerberos config/keytab at runtime if you use it — nothing is preconfigured |
| `ssh2-vendored-openssl` | vendored OpenSSL + system libssh2 | The default build uses pure-Rust russh — no OpenSSL needed |

If you need any of these, use the Debian/Alpine images under
[`packaging/docker/`](../packaging/docker/readme.md) (which link libssh2 +
OpenSSL and run on a non-distroless base), or build a custom image with the
required `--features` and runtime libraries. Those images trade attack surface
for capability; prefer this hardened image whenever the default feature set
suffices.

## CI

[`.github/workflows/docker.yml`](../.github/workflows/docker.yml) builds this
image (on push to `main`, on tags, and on manual dispatch) and runs a
[Trivy](https://github.com/aquasecurity/trivy) vulnerability scan against the
built image, failing on **HIGH/CRITICAL** findings with an available fix. It
does **not** push to any registry (no credentials assumed) — the image is loaded
locally purely so it can be scanned.
