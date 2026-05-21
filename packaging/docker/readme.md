# spt — Docker / Compose

Production-shaped containerization for `spt` ("ssh-perma-tunnel"). Two
runtime images are shipped from this directory:

| File                    | Base image            | Approx. size | When to pick it                              |
|-------------------------|-----------------------|--------------|----------------------------------------------|
| `Dockerfile`            | `debian:bookworm-slim`| ~80 MB       | Default. glibc, friendly to libssh2/OpenSSL. |
| `Dockerfile.alpine`     | `alpine:3.20`         | ~15 MB       | Smaller surface, fewer base-image CVEs.      |

Both images run `spt` as non-root user `spt` (uid/gid `1000`), expose the
HEALTHCHECK at `spt tunnel health --output json`, and default to:

```text
spt tunnel run --foreground --config /etc/spt/spt.toml --state-dir /var/lib/spt
```

## Quickstart

```bash
# 1. Pull a release image (or build locally; see below).
docker pull ghcr.io/mariana/spt:latest

# 2. From this directory:
cp .env.example .env
mkdir -p config secrets
cp example-config/spt.toml config/spt.toml      # edit for your bastion
# place SSH private keys under ./secrets (mode 0600 on the host)

# 3. Start it.
docker compose up -d

# 4. Tail logs and check health.
docker compose logs -f spt
docker compose exec spt spt tunnel health --output json
```

To test a host-side forward (using the bundled example):

```bash
curl -fsS http://127.0.0.1:8080/
```

## Pulling from GHCR

Release images are published to GitHub Container Registry:

```bash
docker pull ghcr.io/mariana/spt:0.1.0     # pinned (recommended for prod)
docker pull ghcr.io/mariana/spt:latest    # rolling
docker pull ghcr.io/mariana/spt:0.1.0-alpine
```

Multi-arch manifests cover `linux/amd64` and `linux/arm64`.

## Building locally

`docker build` must run from the **repository root** so the build context
covers the whole workspace:

```bash
# glibc image (default)
docker build -f packaging/docker/Dockerfile -t spt:local .

# alpine slim variant
docker build -f packaging/docker/Dockerfile.alpine -t spt:local-alpine .
```

Both Dockerfiles use BuildKit cache mounts; first build is slow (~5 min on
a fast box), subsequent builds re-use the registry/target caches.

## Compose layout

`docker-compose.yml` is the production-shaped baseline. The dev overlay
`docker-compose.dev.yml` adds:

- live bind-mount of `target/release/spt` for tight iteration loops,
- `read_only: false` rootfs so you can `exec` and poke,
- verbose logging (`RUST_LOG=spt=debug,info`).

```bash
docker compose \
  -f docker-compose.yml \
  -f docker-compose.dev.yml \
  up --build
```

### Mounts

| Mount                          | Type           | Purpose                                                |
|--------------------------------|----------------|--------------------------------------------------------|
| `./config:/etc/spt:ro`         | bind, RO       | TOML config (`spt.toml`).                              |
| `spt-state:/var/lib/spt`       | named volume   | known_hosts, supervisor lock, durable snapshots.       |
| `./secrets:/run/secrets:ro`    | bind, RO       | Private keys / bearer tokens for the secret vault.     |
| `tmpfs /tmp`                   | tmpfs, 64 MiB  | Scratch (read-only rootfs requires this).              |
| `tmpfs /run/spt`               | tmpfs, 16 MiB  | Runtime sockets / pid files.                           |

### Ports

Forward host ports through the `ports:` block. Default mapping in
`docker-compose.yml` exposes `127.0.0.1:8080` → container `:8080`,
matching `example-config/spt.toml`. Add one mapping per forward.

To bind a privileged port (<1024) **inside the container**, uncomment the
`NET_BIND_SERVICE` capability in `docker-compose.yml`. Most users won't
need this — the forward's *host-side* port is decided by the `ports:`
mapping, which already has full access to host privileged ports as long
as the Docker daemon runs as root.

## Production hardening

The baseline compose file already applies:

- `read_only: true` rootfs + tmpfs for the two writable scratch paths.
- `cap_drop: [ALL]` — no Linux capabilities at all by default.
- `security_opt: [no-new-privileges:true]` — `setuid` bits become inert.
- Non-root user `spt:1000` (enforced inside the image, not relying on
  `user:` in compose).
- Resource caps (`mem_limit`, `cpus`, `pids_limit`, `ulimits.nofile`).
- `json-file` logging driver with rotation (10 MB × 5).

Additional steps recommended for hostile environments:

1. **Seccomp profile.** Docker's default profile already covers the spt
   syscall set. To go tighter, render a custom profile from
   `docker run --security-opt seccomp=unconfined --rm ghcr.io/mariana/spt strace`
   under representative load and feed it back via
   `security_opt: ["seccomp=./spt-seccomp.json"]`.
2. **AppArmor / SELinux.** Confine to the `docker-default` AppArmor
   profile or label-restrict via `security_opt: ["label=type:spt_t"]`
   under SELinux.
3. **Read-only secrets.** Mount the SSH private keys with mode 0400 on
   the host; the bind-mount preserves the mode inside the container.
4. **Image signing.** Verify the GHCR tag against the project's cosign
   key before pulling into production. (Signed images are out of scope
   for this release — see RELEASING.md.)
5. **Network namespace.** Use a dedicated user-defined network if you
   run multiple stacks; never reuse the default `bridge` for sensitive
   tunnels.

## Healthcheck

The image declares:

```dockerfile
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD spt tunnel health --output json
```

`spt tunnel health` exits non-zero when no profile is in
`Ready`/`Forwarding` state. The 30-second `--start-period` keeps the
container from flapping while the first SSH handshake completes.

## Troubleshooting

- **`Permission denied` writing to `/var/lib/spt`.** A pre-existing
  named volume created by an older image may belong to root. Recreate
  it: `docker compose down -v && docker compose up -d`.
- **`HEALTHCHECK` says `unhealthy` forever.** Check `docker compose logs
  spt` — most often a missing private key under `./secrets/` or a typo
  in `spt.toml`. Run `docker compose exec spt spt config validate` to
  re-run the validator inside the container.
- **`bind: address already in use`.** Another process owns the host port
  named in `.env`; change `SPT_FORWARD_PORT_1`.
