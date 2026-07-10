# CLI Reference

Full command reference for `spt` 26.46. Every flag listed here is derived
directly from the clap-derived command tree in `spt-cli`. The source of truth
for any individual invocation is always `spt <group> <subcommand> --help`.

See [cli.md](cli.md) for the global flags and invocation shape that apply to
every command. See [security.md](security.md) for the stable exit-code table.

---

## config

Manage configuration files. The `config` group handles the full lifecycle of
`spt` config files: creating starter configs, validating them, rendering the
effective merged config, diffing two versions, migrating between schema
versions, reloading a running service, pulling remote configs, managing trust
pins, and encrypting/decrypting sealed config envelopes.

```
spt config init --example smtp --path /etc/ssh-perma-tunnel/config.toml
spt config validate --strict
spt config render --redacted
spt config diff --from old.toml --to new.toml
spt config pull --url https://cfg.example/spt.toml --fingerprint <sha256> --cache
```

### config init

Create a new config file from a built-in template.

**Synopsis:** `spt config init [--example EXAMPLE] [--path PATH]`

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| `--example` | `smtp\|jump\|reverse\|ssh3\|dns\|observability\|mcp` | — | Template to seed the new config from. |
| `--path` | `PATH` | stdout | Destination file. |

### config validate

Validate config syntax, schema, and common mistakes. Exits 0 on success, 2 on
failure.

**Synopsis:** `spt config validate [--strict]`

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| `--strict` | | off | Reject unknown fields and friendly-alias keys. |

### config doctor

Run environment checks against the loaded config: network connectivity, service
manager availability, secret backend health, DNS resolver, and observability
sinks. All checks run by default; pass the relevant flag to restrict.

**Synopsis:** `spt config doctor [--network] [--service] [--secrets] [--dns] [--observability]`

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| `--network` | | off | Run network connectivity checks. |
| `--service` | | off | Run service-manager checks. |
| `--secrets` | | off | Run secret backend checks. |
| `--dns` | | off | Run DNS resolver checks. |
| `--observability` | | off | Run observability sink checks. |

### config render

Render the canonical, fully-merged effective config as TOML or JSON. Useful
for debugging which settings are actually active after all sources are merged.

**Synopsis:** `spt config render [--redacted] [--json]`

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| `--redacted` | | off | Mask secret values with `***`. |
| `--json` | | off | Render as JSON instead of canonical TOML. |

### config diff

Diff two config files and print the structural differences.

**Synopsis:** `spt config diff --from PATH --to PATH`

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| `--from` | `PATH` | required | Base config. |
| `--to` | `PATH` | required | Candidate config. |

### config migrate

Migrate a config file between schema versions.

**Synopsis:** `spt config migrate --from-version N --to-version N`

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| `--from-version` | `N` | required | Source schema version number. |
| `--to-version` | `N` | required | Target schema version number. |

### config reload

Signal or instruct the running service to reload its configuration.

**Synopsis:** `spt config reload [--mode MODE] [--wait]`

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| `--mode` | `signal\|watch\|service\|none` | auto | Reload mechanism. |
| `--wait` | | off | Block until the reload completes. |

### config pull

Pull a remote config over HTTPS with optional SHA-256 fingerprint pinning.

**Synopsis:** `spt config pull --url URL [--fingerprint SHA256] [--out PATH] [--cache]`

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| `--url` | `URL` | required | HTTPS URL to fetch. |
| `--fingerprint` | `SHA256` | — | SHA-256 pin; verified before the file is written. |
| `--out` | `PATH` | stdout | Output path. |
| `--cache` | | off | Update the local atomic cache so tunnels can start offline. |

### config trust

Manage remote-config trust pins.

#### config trust add-url

Pin a remote-config URL so it can be used without passing `--config-fingerprint` on every invocation.

**Synopsis:** `spt config trust add-url --url URL --fingerprint SHA256`

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| `--url` | `URL` | required | HTTPS URL to trust. |
| `--fingerprint` | `SHA256` | required | SHA-256 fingerprint pin. |

### config encrypt

Encrypt a plaintext TOML config into a sealed `SPTENC1` envelope. The envelope
can be decrypted by any holder of the matching passphrase, X25519 private key,
or PSK.

**Synopsis:** `spt config encrypt IN [--out PATH] [--passphrase-from REF] [--recipient PUBKEY] [--psk-from REF] [--use-vault-master] [--vault-path PATH] [--vault-passphrase-from SOURCE] [--force]`

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| (positional) | `IN` | required | Plaintext config path. |
| `--out` | `PATH` | `<IN>.sealed` | Output path for the sealed envelope. |
| `--passphrase-from` | `REF` | — | Read passphrase from a secret reference (e.g. `secret://env/SPT_PP`). |
| `--recipient` | `PUBKEY` | — | X25519 recipient public key (base64); repeatable. |
| `--psk-from` | `REF` | — | Seal under a 32-byte PSK from a secret reference (`secret://ns/name`, `env:NAME`, `file:PATH`). |
| `--use-vault-master` | | off | Seal under the keychain-resident vault master key. |
| `--vault-path` | `PATH` | — | Vault directory or `vault.spt` file. |
| `--vault-passphrase-from` | `SOURCE` | — | Vault unlock source (`stdin`, `env:NAME`, `file:<path>`). |
| `--force` | | off | Overwrite an existing output file. |

### config decrypt

Decrypt a sealed `SPTENC1` envelope back to plaintext TOML.

**Synopsis:** `spt config decrypt IN [--out PATH] [--passphrase-from REF] [--recipient-key PATH] [--psk-from REF] [--vault-path PATH] [--vault-passphrase-from SOURCE]`

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| (positional) | `IN` | required | Sealed config path. |
| `--out` | `PATH` | stdout | Output path; omit to write cleartext to stdout. |
| `--passphrase-from` | `REF` | — | Secret reference for the passphrase. |
| `--recipient-key` | `PATH` | — | X25519 private key file (raw 32 bytes or base64 line). |
| `--psk-from` | `REF` | — | Unseal using a PSK from a secret reference. |
| `--vault-path` | `PATH` | — | Vault directory or `vault.spt` file. |
| `--vault-passphrase-from` | `SOURCE` | — | Vault unlock source. |

### config edit

Open a sealed config in `$EDITOR`, then re-seal on save.

**Synopsis:** `spt config edit SEALED [--passphrase-from REF] [--vault-path PATH] [--vault-passphrase-from SOURCE]`

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| (positional) | `SEALED` | required | Sealed config path. |
| `--passphrase-from` | `REF` | — | Secret reference for the unsealing passphrase. |
| `--vault-path` | `PATH` | — | Vault directory or `vault.spt` file. |
| `--vault-passphrase-from` | `SOURCE` | — | Vault unlock source. |

### config crypt rotate

Re-seal a sealed config under a new key (key rotation). The old envelope is
unsealed with the current key and immediately re-sealed under the new key.

**Synopsis:** `spt config crypt rotate SEALED [--new-passphrase-from REF] [--new-recipient PUBKEY] [--old-psk-from REF] [--new-psk-from REF] [--vault-path PATH] [--vault-passphrase-from SOURCE]`

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| (positional) | `SEALED` | required | Sealed config path. |
| `--new-passphrase-from` | `REF` | — | New passphrase secret reference. |
| `--new-recipient` | `PUBKEY` | — | New X25519 recipient public key (repeatable). |
| `--old-psk-from` | `REF` | — | PSK for the existing envelope. |
| `--new-psk-from` | `REF` | — | PSK to seal the new envelope under. |
| `--vault-path` | `PATH` | — | Vault directory or `vault.spt` file. |
| `--vault-passphrase-from` | `SOURCE` | — | Vault unlock source. |

### config gen-key

Generate a config-encryption key: either an X25519 keypair or a raw 32-byte
PSK.

**Synopsis:** `spt config gen-key --type TYPE [--out PATH] [--hex] [--force]`

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| `--type` | `x25519\|psk` | required | Key kind to mint. |
| `--out` | `PATH` | stdout | Output path. For `x25519` the private scalar is written here and the public key to `<PATH>.pub`; for `psk` the key is written here or to stdout when omitted. |
| `--hex` | | off | Encode the PSK as hex instead of base64 (PSK only). |
| `--force` | | off | Overwrite existing output file(s). |

---

## profile

Manage SSH2 and SSH3 tunnel profiles. A profile defines a remote endpoint, the
transport protocol, authentication method, reconnect policy, keepalive timings,
and associated forwards.

```
spt profile add edge --protocol ssh2 --host gw.example --user ubuntu
spt profile configure --tui --name edge
spt profile set edge keepalive.interval=30s reconnect.max_backoff=2m
spt profile enable edge
spt profile test edge --connect-only
```

### profile list

List all configured profiles.

**Synopsis:** `spt profile list [--json]`

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| `--json` | | off | JSON output. |

### profile show

Show the resolved (merged) settings for one profile.

**Synopsis:** `spt profile show NAME [--redacted] [--json]`

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| (positional) | `NAME` | required | Profile name. |
| `--redacted` | | off | Mask secret fields with `***`. |
| `--json` | | off | JSON output. |

### profile add

Add a new profile with the minimal required fields. Use `spt profile configure`
or `spt profile set` to fill in additional settings after creation.

**Synopsis:** `spt profile add NAME --protocol PROTOCOL --host HOST --user USER`

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| (positional) | `NAME` | required | Profile name (must be unique). |
| `--protocol` | `ssh2\|ssh3` | required | Transport protocol. |
| `--host` | `HOST` | required | Remote hostname or IP. |
| `--user` | `USER` | required | SSH username. |

### profile configure

Interactively configure a profile through the TUI wizard, or apply non-interactive
field overrides.

**Synopsis:** `spt profile configure [--name NAME] [--tui] [--no-tui] [--from-template NAME] [--field KEY=VALUE] [--from PATH]`

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| `--name` | `NAME` | — | Profile name; created if missing. |
| `--tui` | | off | Force the TUI wizard (conflicts with `--no-tui`). |
| `--no-tui` | | off | Disable the TUI; apply `--field` overrides non-interactively. |
| `--from-template` | `NAME` | — | Seed from a built-in template. |
| `--field` | `KEY=VALUE` | — | One or more key=value field overrides (repeatable). Implies `--no-tui` semantics for `--field` updates. |
| `--from` | `PATH` | — | Apply a TOML patch file to the profile (non-interactive). The file may be a bare key/value document or contain a `[profile]` table. |

### profile set

Apply one or more `key=value` overrides to a profile's stored settings.

**Synopsis:** `spt profile set NAME KEY=VALUE [KEY=VALUE …]`

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| (positional 1) | `NAME` | required | Profile name. |
| (positional 2…) | `KEY=VALUE` | required | One or more `dotted.key=value` pairs. |

### profile enable

Enable a disabled profile so it is picked up at the next tunnel start or reload.

**Synopsis:** `spt profile enable NAME`

### profile disable

Disable a profile without removing it.

**Synopsis:** `spt profile disable NAME`

### profile remove

Permanently remove a profile and its associated config entries.

**Synopsis:** `spt profile remove NAME`

### profile test

Run targeted tests against a profile to verify connectivity, bind, auth, trust
(host-key or TLS pin), and DNS resolution.

The `-J`/`--jump` flag accepts a proxy-jump chain in the same format as OpenSSH
`-J`: a comma-separated list of `user@host[:port]` bastion hops. When supplied,
the provided chain replaces any `hops` configured in the profile for the
duration of the test, so the full bastion path is exercised end-to-end.

**Synopsis:** `spt profile test NAME [--connect-only] [--bind-only] [--auth-only] [--trust-only] [--dns-only] [-J JUMP_CHAIN]`

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| (positional) | `NAME` | required | Profile name. |
| `--connect-only` | | off | Only test TCP/QUIC connect (group: scope). |
| `--bind-only` | | off | Only test local bind (group: scope). |
| `--auth-only` | | off | Only test authentication (group: scope). |
| `--trust-only` | | off | Only test host-key or TLS pin verification (group: scope). |
| `--dns-only` | | off | Only test DNS resolution (group: scope). |
| `-J`, `--jump` | `JUMP_CHAIN` | — | Ad-hoc proxy-jump chain `user@host[:port][,user@host…]` to preflight. Replaces the profile's configured hops for the test. |

---

## forward

Manage forwards attached to profiles. A forward describes a local, remote, or
dynamic tunnel endpoint. Forwards reference their owning profile and can be
throttled and tested independently.

```
spt forward add local --profile edge --listen 127.0.0.1:5432 --to db:5432 --tcp
spt forward add remote --profile edge --listen 0.0.0.0:8080 --to web:80 --tcp
spt forward add dynamic --profile edge --listen 127.0.0.1:1080
spt forward throttle edge/db --in 10MiB/s --out 10MiB/s --connections 64
spt forward test edge/db --connect --dns-name db.local
spt forward remove edge/db
```

### forward list

List all configured forwards across all profiles, optionally filtered.

**Synopsis:** `spt forward list [--profile NAME] [--json]`

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| `--profile` | `NAME` | — | Filter to a specific profile. |
| `--json` | | off | JSON output. |

### forward show

Show the detailed configuration for a single forward.

**Synopsis:** `spt forward show PROFILE/FORWARD [--friendly] [--json]`

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| (positional) | `PROFILE/FORWARD` | required | `<profile>/<forward>` reference. |
| `--friendly` | | off | Textual human-friendly layout. |
| `--json` | | off | JSON output. |

### forward add local

Add a local forward (`-L` in OpenSSH). Traffic arriving on `--listen` on the
local machine is forwarded through the tunnel to `--to` on the remote side.

**Synopsis:** `spt forward add local --profile NAME --listen ADDR:PORT --to HOST:PORT [--tcp] [--udp]`

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| `--profile` | `NAME` | required | Owning profile. |
| `--listen` | `ADDR:PORT` | required | Local listen address and port (e.g. `127.0.0.1:5432`). |
| `--to` | `HOST:PORT` | required | Remote target host and port. |
| `--tcp` | | (default) | TCP forward (mutually exclusive with `--udp`). |
| `--udp` | | off | UDP forward — SSH3 transport only. |

### forward add remote

Add a remote forward (`-R` in OpenSSH). Traffic arriving on `--listen` on the
remote side is forwarded back through the tunnel to `--to` on the local side.

**Synopsis:** `spt forward add remote --profile NAME --listen ADDR:PORT --to HOST:PORT [--tcp] [--udp]`

Flags are identical to `forward add local`.

### forward add dynamic

Add a dynamic SOCKS/HTTP-CONNECT proxy forward (`-D` in OpenSSH). `spt` listens
locally and proxies outbound connections using the tunnel as transport.

**Synopsis:** `spt forward add dynamic --profile NAME --listen ADDR:PORT [--connections N] [--proxy-protocol PROTO]`

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| `--profile` | `NAME` | required | Owning profile. |
| `--listen` | `ADDR:PORT` | required | Local proxy listen address. |
| `--connections` | `N` | — | Per-forward concurrent connection limit. |
| `--proxy-protocol` | `all\|socks4\|socks4a\|socks5\|http-connect` | all | Proxy protocols to accept; repeat to restrict to a subset. `http-connect` aliases `http`. |

### forward explain

Print a human-readable explanation of how a forward is plumbed through the
tunnel.

**Synopsis:** `spt forward explain PROFILE/FORWARD`

### forward test

Run targeted tests against a forward.

**Synopsis:** `spt forward test PROFILE/FORWARD [--connect] [--dns-name NAME] [--timeout DURATION]`

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| (positional) | `PROFILE/FORWARD` | required | `<profile>/<forward>` reference. |
| `--connect` | | off | Probe with a TCP connect to the listen address. |
| `--dns-name` | `NAME` | — | Probe with a DNS resolution through the tunnel. |
| `--timeout` | `DURATION` | — | Timeout for the connect probe (e.g. `10s`). |

### forward throttle

Update the bandwidth and connection limits for a forward at runtime without
restarting the tunnel.

**Synopsis:** `spt forward throttle PROFILE/FORWARD [--in RATE] [--out RATE] [--connections N]`

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| (positional) | `PROFILE/FORWARD` | required | `<profile>/<forward>` reference. |
| `--in` | `RATE` | — | Inbound rate cap (e.g. `10MiB/s`). |
| `--out` | `RATE` | — | Outbound rate cap. |
| `--connections` | `N` | — | Per-forward concurrent connection limit. |

### forward remove

Remove a forward from the config.

**Synopsis:** `spt forward remove PROFILE/FORWARD`

---

## tunnel

Start, stop, inspect, and control active tunnels. The `tunnel` group is the
primary entrypoint for bringing tunnels up and managing them at runtime.

```
spt tunnel run --foreground
spt tunnel run --once --profiles edge,backup
spt tunnel status --watch --json
spt tunnel failover edge --to dr --reason "primary degraded"
spt tunnel reload --wait
```

### tunnel run

Start all configured (enabled) tunnels, or a filtered subset.

The `-J`/`--jump` flag injects a proxy-jump bastion chain into every selected
profile at startup, overriding any `hops` table in the config. This mirrors the
OpenSSH `-J` flag and is useful for testing or ad-hoc bastion chaining without
editing the config.

**Synopsis:** `spt tunnel run [--foreground] [--once] [--profiles A,B,C] [-J JUMP_CHAIN]`

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| `--foreground` | | off | Run in the foreground; log to stderr; exit when all tunnels stop. Without this flag `tunnel run` hands off to the background supervisor. |
| `--once` | | off | Start once; exit non-zero if any tunnel fails to establish on the first attempt. |
| `--profiles` | `A,B,C` | all enabled | Comma-separated profile filter. |
| `-J`, `--jump` | `JUMP_CHAIN` | — | Proxy-jump chain `user@host[:port][,user@host…]` spliced into every selected profile's `hops` table at startup. |

### tunnel status

Show the current status of all tunnels and profiles.

**Synopsis:** `spt tunnel status [--watch] [--json]`

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| `--watch` | | off | Continuously refresh the display. |
| `--json` | | off | JSON output. |

### tunnel stats

Show per-profile and per-forward throughput and error counters.

**Synopsis:** `spt tunnel stats [--profile NAME] [--forward NAME] [--interval DURATION] [--json]`

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| `--profile` | `NAME` | — | Filter to a profile. |
| `--forward` | `NAME` | — | Filter to a forward. |
| `--interval` | `DURATION` | — | Live refresh interval (e.g. `2s`). |
| `--json` | | off | JSON output. |

### tunnel sessions

List active sessions across all tunnels.

**Synopsis:** `spt tunnel sessions [--profile NAME] [--forward NAME] [--json]`

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| `--profile` | `NAME` | — | Filter to a profile. |
| `--forward` | `NAME` | — | Filter to a forward. |
| `--json` | | off | JSON output. |

### tunnel stop

Stop running tunnels gracefully, optionally waiting for in-flight connections
to drain.

**Synopsis:** `spt tunnel stop [--profile NAME] [--grace DURATION]`

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| `--profile` | `NAME` | — | Stop only the named profile; omit to stop all. |
| `--grace` | `DURATION` | — | Grace period for in-flight connections (e.g. `10s`). |

### tunnel reload

Signal the running supervisor to reload its configuration from disk.

**Synopsis:** `spt tunnel reload [--wait]`

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| `--wait` | | off | Block until the reload has completed. |

### tunnel health

Print a health summary for all active tunnels.

**Synopsis:** `spt tunnel health [--json]`

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| `--json` | | off | JSON output. |

### tunnel failover

Manually trigger failover for a profile, optionally to a specific endpoint.

**Synopsis:** `spt tunnel failover PROFILE [--to ENDPOINT] [--reason TEXT]`

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| (positional) | `PROFILE` | required | Profile name. |
| `--to`, `--endpoint` | `ENDPOINT` | — | Override target as `host:port`. |
| `--reason` | `TEXT` | — | Free-form reason recorded in the audit log. |

---

## service

Install and control `spt` as a native OS service (systemd, OpenRC, SysV,
launchd, or Windows SCM). Service units are generated from the active config
and can be previewed with `render` before installation.

```
spt service install --config /etc/ssh-perma-tunnel/config.toml --system
spt service start --config /etc/ssh-perma-tunnel/config.toml --system
spt service status --config /etc/ssh-perma-tunnel/config.toml --json
spt service render --config config.toml --format unit
spt service uninstall --config config.toml --user
```

The `--user` and `--system` scope flags are mutually exclusive. `--user`
installs a user-scoped service (no root required); `--system` installs a
system-wide service (typically requires administrator or root privileges).

### service install

Generate and register a service unit. The unit is shaped by the
unit-shaping options below.

**Synopsis:** `spt service install --config PATH [--user] [--system] [--name NAME] [unit opts]`

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| `--config` | `PATH` | required | Config file backing the service. |
| `--user` | | off | User-scoped service (mutually exclusive with `--system`). |
| `--system` | | off | System-scoped service. |
| `--name` | `NAME` | — | Override the generated service unit name. |
| `--run-as-user` | `USER` | — | Run the service as this user (system scope). Maps to systemd `User=` / OpenRC `command_user` / launchd `UserName`. |
| `--run-as-group` | `GROUP` | — | Run the service as this group (system scope). Maps to systemd `Group=`. |
| `--restart` | `always\|on-failure\|never` | `on-failure` | Restart policy. |
| `--sd-notify` | | off | Enable systemd `Type=notify` (daemon sends READY=1/STOPPING=1). |
| `--watchdog-sec` | `SECONDS` | — | systemd `WatchdogSec=` interval; `0` disables. |
| `--stdout` | `PATH` | — | Redirect stdout to this path (launchd / SysV). |
| `--stderr` | `PATH` | — | Redirect stderr to this path (launchd / SysV). |
| `--env` | `KEY=VALUE` | — | Extra environment variable for the unit (repeatable). |
| `--description` | `TEXT` | — | Override the unit description string. |

### service uninstall

Remove the service unit.

**Synopsis:** `spt service uninstall --config PATH [--user] [--system] [--name NAME]`

Flags are identical to `service install` (scope flags only; unit-shaping opts are ignored).

### service start

Start the service.

**Synopsis:** `spt service start --config PATH [--user] [--system] [--name NAME]`

### service stop

Stop the service.

**Synopsis:** `spt service stop --config PATH [--user] [--system] [--name NAME]`

### service restart

Restart the service.

**Synopsis:** `spt service restart --config PATH [--user] [--system] [--name NAME]`

### service status

Show the current status of the service.

**Synopsis:** `spt service status --config PATH [--user] [--system] [--name NAME] [--json]`

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| `--config` | `PATH` | required | Config file. |
| `--user` / `--system` | | — | Scope selector. |
| `--name` | `NAME` | — | Service unit name override. |
| `--json` | | off | JSON output. |

### service render

Preview the service unit without installing it. Supports the same unit-shaping
options as `install` so the preview exactly matches what would be installed.

**Synopsis:** `spt service render --config PATH [--user] [--system] [--name NAME] [--format FORMAT] [unit opts]`

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| `--config` | `PATH` | required | Config file. |
| `--user` / `--system` | | — | Scope selector. |
| `--name` | `NAME` | — | Service unit name override. |
| `--format` | `unit\|plist\|windows` | auto-detect | Render format: `unit` (systemd/OpenRC/SysV), `plist` (launchd), `windows`. |
| (unit-shaping opts) | | | Same as `service install`. |

---

## key

Generate, inspect, sign, verify, and install SSH keys and OpenSSH certificates.

```
spt key generate --type ed25519 --out ~/.ssh/spt_ed25519 --comment spt
spt key inspect ~/.ssh/spt_ed25519 --fingerprint sha256
spt key sign-cert --ca-key ca --public-key user.pub --principal alice --out user-cert.pub
spt key install-public --profile edge --key ~/.ssh/spt_ed25519.pub
spt key change-passphrase ~/.ssh/spt_ed25519
```

### key generate

Generate a new SSH keypair. Ed25519 is the recommended algorithm.

**Synopsis:** `spt key generate --type TYPE --out PATH [--bits N] [--comment TEXT] [--encrypt]`

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| `--type` | `ed25519\|ecdsa-p256\|rsa` | required | Key algorithm. |
| `--out` | `PATH` | required | Private key output path; public key is written to `<PATH>.pub`. |
| `--bits` | `N` | — | RSA bit length (only meaningful for `--type rsa`). |
| `--comment` | `TEXT` | — | Optional comment embedded in the key. |
| `--encrypt` | | off | Encrypt the private key at rest with a passphrase (prompted interactively). |

### key inspect

Inspect a key file and print its metadata.

**Synopsis:** `spt key inspect PATH [--fingerprint ALGO] [--json]`

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| (positional) | `PATH` | required | Key or certificate file path. |
| `--fingerprint` | `sha256\|md5` | — | Fingerprint hash algorithm to print. |
| `--json` | | off | JSON output. |

### key public

Extract and print the public key from a private key file.

**Synopsis:** `spt key public PATH [--out PATH]`

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| (positional) | `PATH` | required | Private key path. |
| `--out` | `PATH` | stdout | Output file. |

### key change-passphrase

Change the passphrase protecting a private key.

**Synopsis:** `spt key change-passphrase PATH [--new-passphrase-from SOURCE]`

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| (positional) | `PATH` | required | Private key path. |
| `--new-passphrase-from` | `SOURCE` | interactive | Read the new passphrase from a value source (`stdin`, `file:<path>`, `env:<NAME>`). |

### key sign-cert

Sign a public key to produce an OpenSSH certificate using a CA key.

**Synopsis:** `spt key sign-cert --ca-key PATH --public-key PATH --principal NAME [--validity DURATION] [--serial N] [--cert-type user|host] [--key-id TEXT] [--out PATH]`

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| `--ca-key` | `PATH` | required | Signing CA private key. |
| `--public-key` | `PATH` | required | Public key to sign. |
| `--principal` | `NAME` | required | Principal name(s); repeat or comma-separated. |
| `--validity` | `DURATION` | — | Validity duration (e.g. `1d`, `52w`). |
| `--serial` | `N` | — | Serial number to embed. |
| `--cert-type` | `user\|host` | — | Certificate type. |
| `--key-id` | `TEXT` | — | Free-form key ID embedded in the certificate. |
| `--out` | `PATH` | — | Output certificate path. |

### key verify-cert

Verify an OpenSSH certificate against a set of trusted CA public keys.

**Synopsis:** `spt key verify-cert PATH --trusted-cas PATH`

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| (positional) | `PATH` | required | Certificate file path. |
| `--trusted-cas` | `PATH` | required | File containing trusted CA public keys (one per line). |

### key install-public

Install a public key into the `authorized_keys` file on a remote host.

**Synopsis:** `spt key install-public --key PATH [--profile NAME] [--target USER@HOST] [--remote-command COMMAND]`

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| `--key` | `PATH` | required | Public key file to install. |
| `--profile` | `NAME` | — | Destination profile (mutually exclusive with `--target`). |
| `--target` | `USER@HOST` | — | Override target as `user@host[:port]`. |
| `--remote-command` | `COMMAND` | — | Override the remote install command. |

---

## secret

Manage the secret vault and OS keychain references. Secrets are referenced in
config using `secret://ns/name` URIs. The vault is a local encrypted store;
alternatively, secrets may be stored in the OS keychain (macOS Keychain,
Windows Credential Manager, or a GNOME/KDE keyring).

```
spt secret store init --backend keychain
spt secret set db/password --prompt
spt secret set db/password --from-env DB_PASSWORD
spt secret set api/token --from-file ~/.tokens/api
spt secret rotate db/password
spt secret remove db/password
```

### secret store init

Initialize the secret store.

**Synopsis:** `spt secret store init [--backend BACKEND] [--vault-path PATH] [--passphrase-from SOURCE]`

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| `--backend` | `auto\|keychain\|vault` | `auto` | Preferred backend. |
| `--vault-path` | `PATH` | — | Vault directory or `vault.spt` file location. |
| `--passphrase-from` | `SOURCE` | interactive | Read the vault passphrase from `stdin`, `file:<path>`, or `env:<NAME>`. |

### secret set

Store a secret value. Exactly one of `--prompt`, `--from-env`, or `--from-file`
must be provided as the value source.

**Synopsis:** `spt secret set NAME [--prompt] [--from-env ENV] [--from-file PATH] [--vault-path PATH] [--passphrase-from SOURCE]`

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| (positional) | `NAME` | required | Secret name as `namespace/name`. |
| `--prompt` | | off | Read value interactively from a TTY prompt (mutually exclusive with other sources). |
| `--from-env` | `ENV` | — | Read value from environment variable. |
| `--from-file` | `PATH` | — | Read value from a file (permissions are checked). |
| `--vault-path` | `PATH` | — | Vault directory or `vault.spt` file. |
| `--passphrase-from` | `SOURCE` | — | Vault unlock source. |

### secret get

Retrieve a secret. By default the value is redacted; pass `--reveal` to print
the plaintext.

**Synopsis:** `spt secret get NAME [--reveal] [--vault-path PATH] [--passphrase-from SOURCE]`

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| (positional) | `NAME` | required | Secret name. |
| `--reveal` | | off | Print the plaintext value. |
| `--vault-path` | `PATH` | — | Vault directory or `vault.spt` file. |
| `--passphrase-from` | `SOURCE` | — | Vault unlock source. |

### secret list

List known secret names, optionally filtered to a namespace.

**Synopsis:** `spt secret list [--namespace NS] [--vault-path PATH] [--passphrase-from SOURCE] [--json]`

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| `--namespace` | `NS` | — | Restrict listing to this namespace. |
| `--vault-path` | `PATH` | — | Vault directory or `vault.spt` file. |
| `--passphrase-from` | `SOURCE` | — | Vault unlock source. |
| `--json` | | off | JSON output. |

### secret rotate

Replace a secret with a new value. Supply `--new-value-from` for non-interactive
rotation; omit it to be prompted.

**Synopsis:** `spt secret rotate NAME [--new-value-from SOURCE] [--vault-path PATH] [--passphrase-from SOURCE]`

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| (positional) | `NAME` | required | Secret name (`namespace/name` or `secret://…`). |
| `--new-value-from` | `SOURCE` | interactive | New value source (`stdin`, `file:<path>`, `env:<NAME>`). |
| `--vault-path` | `PATH` | — | Vault directory or `vault.spt` file. |
| `--passphrase-from` | `SOURCE` | — | Vault unlock source. |

### secret remove

Remove a secret permanently.

**Synopsis:** `spt secret remove NAME [--vault-path PATH] [--passphrase-from SOURCE]`

Flags are as for `secret rotate`.

### secret doctor

Run secret-backend health checks (connectivity, permissions, vault integrity).

**Synopsis:** `spt secret doctor`

---

## auth

Authentication helpers.

### auth test

Test authentication for a profile by attempting a real credential exchange with
the remote host. Prints the authentication method used and the outcome.

**Synopsis:** `spt auth test PROFILE`

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| (positional) | `PROFILE` | required | Profile name. |

### auth ssh3-login

Run an SSH3 OIDC device-flow login and optionally persist the resulting token
to the secret backend.

**Synopsis:** `spt auth ssh3-login --issuer URL --client-id ID [--audience AUD] [--scope SCOPE] [--save-as secret://ns/name] [--json]`

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| `--issuer` | `URL` | required | OIDC issuer URL (parent of `.well-known/openid-configuration`). |
| `--client-id` | `ID` | required | OAuth client ID registered with the issuer. |
| `--audience` | `AUD` | — | Optional OAuth audience. |
| `--scope` | `SCOPE` | `openid offline_access` | Space-separated OAuth scope. |
| `--save-as` | `secret://ns/name` | — | Persist the access (and refresh) token at this secret ref. |
| `--json` | | off | JSON output. |

---

## dns

Built-in DNS resolver and hosts-file management. The resolver can serve as a
stub forwarder with managed records, and can render or apply an enriched
`/etc/hosts`-style file for environments that cannot use a custom DNS server.

```
spt dns serve --foreground
spt dns record add svc.local --addr 10.0.0.1 --ttl 5m
spt dns hosts render --out /etc/hosts.spt
spt dns hosts apply --backup
spt dns hosts restore --backup /var/lib/spt/hosts/backup-2024-01-01
```

### dns serve

Start the built-in DNS resolver.

**Synopsis:** `spt dns serve [--foreground] [--config PATH]`

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| `--foreground` | | off | Run in the foreground. |
| `--config` | `PATH` | — | Override config path. |

### dns status

Show the running resolver's status.

**Synopsis:** `spt dns status [--json]`

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| `--json` | | off | JSON output. |

### dns query

Issue a DNS query against the configured resolver.

**Synopsis:** `spt dns query NAME [--type TYPE]`

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| (positional) | `NAME` | required | Name to resolve. |
| `--type` | `a\|aaaa\|srv\|txt` | — | Record type. |

### dns upstream set

Replace the resolver's upstream list.

**Synopsis:** `spt dns upstream set ADDR:PORT [ADDR:PORT …]`

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| (positional) | `ADDR:PORT` | required | One or more upstream resolver addresses. |

### dns record add

Add a managed A or AAAA record to the built-in resolver.

**Synopsis:** `spt dns record add NAME --addr ADDR [--ttl DURATION]`

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| (positional) | `NAME` | required | Record name (e.g. `svc.local`). |
| `--addr` | `ADDR` | required | IP address (IPv4 or IPv6). |
| `--ttl` | `DURATION` | — | TTL (e.g. `5m`, `300s`). |

### dns record remove

Remove a managed record.

**Synopsis:** `spt dns record remove NAME`

### dns hosts render

Render the would-be hosts file to stdout or a file, without applying it.

**Synopsis:** `spt dns hosts render [--out PATH]`

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| `--out` | `PATH` | stdout | Output path. |

### dns hosts apply

Apply the rendered hosts file to the system.

**Synopsis:** `spt dns hosts apply [--path PATH] [--backup]`

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| `--path` | `PATH` | — | Target hosts file path (defaults to the OS standard). |
| `--backup` | | off | Take a timestamped backup of the current hosts file before applying. |

### dns hosts restore

Restore a previously backed-up hosts file.

**Synopsis:** `spt dns hosts restore [--backup PATH]`

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| `--backup` | `PATH` | — | Path to the specific backup to restore; omit to restore the most recent. |

---

## firewall

Inspect and manage OS firewall and packet-filter rules for `spt` binds and
forwards. Rules are planned from the active config and applied idempotently.
The `gateway` and `policy` subgroups manage `[network]` config sections and
GPO-style registry policy overlays (Windows).

```
spt firewall plan --profile edge --json
spt firewall apply --system --dry-run
spt firewall apply --system --yes
spt firewall remove --user
spt firewall bind-preview --forward edge/db
spt firewall gateway show --json
spt firewall gateway set --default-interface Ethernet --tcp-nodelay true
spt firewall gateway set --load-balance-strategy weighted --load-balance-fail-after 3
spt firewall policy list --json
spt firewall policy set Network.DefaultInterface Ethernet --scope user
```

### firewall plan

Plan firewall rules without applying them.

**Synopsis:** `spt firewall plan [--profile NAME] [--forward NAME] [--json]`

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| `--profile` | `NAME` | — | Filter to a profile. |
| `--forward` | `NAME` | — | Filter to a forward. |
| `--json` | | off | JSON output. |

### firewall apply

Apply firewall rules (idempotent). Requires `--yes` or `--dry-run` to guard
against accidental live mutation.

**Synopsis:** `spt firewall apply [--profile NAME] [--forward NAME] [--user] [--system] [--dry-run] [-y]`

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| `--profile` | `NAME` | — | Filter to a profile. |
| `--forward` | `NAME` | — | Filter to a forward. |
| `--user` | | off | User-scoped rules (mutually exclusive with `--system`). |
| `--system` | | off | System-scoped rules. |
| `--dry-run` | | off | Print actions without mutating system state. |
| `-y`, `--yes` | | off | Confirm and perform live firewall mutation (required outside `--dry-run`). |

### firewall remove

Remove previously applied firewall rules.

**Synopsis:** `spt firewall remove [--profile NAME] [--forward NAME] [--user] [--system] [--dry-run] [-y]`

Flags are identical to `firewall apply`.

### firewall status

Show the currently applied firewall state.

**Synopsis:** `spt firewall status [--json]`

### firewall interfaces

List available network interfaces and their bind-target suitability.

**Synopsis:** `spt firewall interfaces [--json]`

### firewall bind-preview

Preview the interface and address that a specific forward would bind to.

**Synopsis:** `spt firewall bind-preview --forward PROFILE/FORWARD [--json]`

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| `--forward` | `PROFILE/FORWARD` | required | `<profile>/<forward>` reference. |
| `--json` | | off | JSON output. |

### firewall gateway show

Show the configured interface and gateway policy.

**Synopsis:** `spt firewall gateway show [--json]`

### firewall gateway set

Update interface, gateway, offload, and load-balance policy in the config.

**Synopsis:** `spt firewall gateway set [options] [--json]`

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| `--default-interface` | `IFACE` | — | Set `[network.interface].default_interface`. |
| `--allowed-interface` | `IFACE` | — | Set `[network.interface].allowed_interfaces` (comma-separated, repeatable). |
| `--denied-interface` | `IFACE` | — | Set `[network.interface].denied_interfaces` (comma-separated, repeatable). |
| `--require-explicit-interface` | `BOOL` | — | Set `[network.interface].require_explicit_interface`. |
| `--allow-all-interfaces` | `BOOL` | — | Set `[network.interface].allow_all_interfaces`. |
| `--bind-ipv6` | `MODE` | — | Set `[network.interface].bind_ipv6` (`auto\|prefer\|disable`). |
| `--default-gateway` | `ADDR` | — | Set `[network.gateway].default_gateway`. |
| `--gateway-interface` | `IFACE` | — | Set `[network.gateway].interface`. |
| `--route-check-target` | `HOST_OR_IP` | — | Set `[network.gateway].route_check_target`. |
| `--policy` | `POLICY` | — | Set `[network.gateway].policy`. |
| `--require-gateway-match` | `BOOL` | — | Set `[network.gateway].require_gateway_match`. |
| `--tcp-nodelay` | `BOOL` | — | Set `[network.offload].tcp_nodelay`. |
| `--socket-keepalive` | `BOOL` | — | Set `[network.offload].socket_keepalive`. |
| `--tcp-fast-open` | `BOOL` | — | Set `[network.offload].tcp_fast_open`. |
| `--reuse-port` | `BOOL` | — | Set `[network.offload].reuse_port`. |
| `--io-uring` | `BOOL` | — | Set `[network.offload].io_uring`. |
| `--zerocopy` | `BOOL` | — | Set `[network.offload].zerocopy`. |
| `--sendfile` | `BOOL` | — | Set `[network.offload].sendfile`. |
| `--checksum-offload` | `BOOL` | — | Set `[network.offload].checksum_offload`. |
| `--large-send-offload` | `BOOL` | — | Set `[network.offload].large_send_offload`. |
| `--load-balance-strategy` | `STRATEGY` | — | Set `[network.load_balance].strategy`. |
| `--sticky-sessions` | `BOOL` | — | Set `[network.load_balance].sticky_sessions`. |
| `--health-check` | `MODE` | — | Set `[network.load_balance].health_check`. |
| `--load-balance-fail-after` | `N` | — | Set `[network.load_balance].fail_after`. |
| `--load-balance-restore-after` | `DURATION` | — | Set `[network.load_balance].restore_after`. |
| `--rebalance-interval` | `DURATION` | — | Set `[network.load_balance].rebalance_interval`. |
| `--json` | | off | JSON output. |

### firewall policy list

List known GPO-style policy bindings.

**Synopsis:** `spt firewall policy list [--json]`

### firewall policy show

Show the live registry policy overlay and the effective network/firewall fields.

**Synopsis:** `spt firewall policy show [--json]`

### firewall policy set

Write a policy value to the Windows registry (HKCU or HKLM).

**Synopsis:** `spt firewall policy set SECTION.NAME VALUE [--scope user|machine] [--enforced] [--json]`

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| (positional 1) | `SECTION.NAME` | required | Policy key in `Section.Name` or `Section\Name` form. |
| (positional 2) | `VALUE` | required | Policy value; lists use comma-separated values. |
| `--scope` | `user\|machine` | `user` | Target registry hive (HKCU = user, HKLM = machine). |
| `--enforced` | | off | Mark the containing machine-policy section as enforced. |
| `--json` | | off | JSON output. |

### firewall policy unset

Remove a policy value from the Windows registry.

**Synopsis:** `spt firewall policy unset SECTION.NAME [--scope user|machine] [--clear-enforced] [--json]`

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| (positional) | `SECTION.NAME` | required | Policy key. |
| `--scope` | `user\|machine` | `user` | Target registry hive. |
| `--clear-enforced` | | off | Also clear the section-level `Enforced` sentinel. |
| `--json` | | off | JSON output. |

---

## log

Log tailing, remote sink testing, and structured log export.

```
spt log tail --follow --profile edge --since 15m
spt log test --sink remote-syslog
spt log remote list
spt log remote test --sink remote-syslog --send-test-record
spt log export --format jsonl --since 24h
spt log tail --since 1h --json
spt log export --format jsonl --since 7d
```

### log tail

Tail the `spt` log stream.

**Synopsis:** `spt log tail [--follow] [--profile NAME] [--since DURATION] [--json]`

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| `--follow` | | off | Follow mode: stream new entries as they arrive. |
| `--profile` | `NAME` | — | Filter to entries from a specific profile. |
| `--since` | `DURATION` | — | Lookback window (e.g. `15m`, `2h`). |
| `--json` | | off | JSON output (one record per line). |

### log test

Probe a configured log sink by name.

**Synopsis:** `spt log test --sink NAME`

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| `--sink` | `NAME` | required | Sink name from config. |

### log remote list

List all configured remote log sinks.

**Synopsis:** `spt log remote list [--json]`

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| `--json` | | off | JSON output. |

### log remote test

Probe a remote log sink and optionally send a synthetic test record.

**Synopsis:** `spt log remote test --sink NAME [--send-test-record] [--json]`

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| `--sink` | `NAME` | required | Sink name. |
| `--send-test-record` | | off | Send a real synthetic record instead of a connectivity-only probe. |
| `--json` | | off | JSON output. |

### log remote status

Show the local delivery status and spool depth for a remote log sink.

**Synopsis:** `spt log remote status --sink NAME [--json]`

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| `--sink` | `NAME` | required | Sink name. |
| `--json` | | off | JSON output. |

### log remote drain

Flush the on-disk spool for a remote log sink.

**Synopsis:** `spt log remote drain --sink NAME [--json]`

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| `--sink` | `NAME` | required | Sink name. |
| `--json` | | off | JSON output. |

### log export

Export a time-windowed slice of logs to a structured format.

**Synopsis:** `spt log export --format FORMAT --since DURATION`

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| `--format` | `jsonl\|csv` | required | Output format. |
| `--since` | `DURATION` | required | Lookback window (e.g. `24h`, `7d`). |

---

## observe

Metrics, SNMP agent, and Windows Event Log integration.

The `snmp` subcommand is only available in builds compiled with the `snmp`
Cargo feature. Attempting to invoke it in a non-snmp build exits with a parse
error.

```
spt observe metrics --format prometheus
spt observe snmp serve --foreground          # snmp feature only
spt observe snmp test-trap --sink ops        # snmp feature only
spt observe windows-event install-source --source SshPermaTunnel
spt observe windows-event test --source SshPermaTunnel
```

### observe metrics

Print current metrics.

**Synopsis:** `spt observe metrics [--format FORMAT]`

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| `--format` | `prometheus\|json` | — | Output format. |

### observe snmp serve

Start the SNMP agent in the foreground. (Requires the `snmp` feature.)

**Synopsis:** `spt observe snmp serve [--foreground]`

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| `--foreground` | | off | Run in the foreground. |

### observe snmp test-trap

Send a test trap to a named SNMP sink. (Requires the `snmp` feature.)

**Synopsis:** `spt observe snmp test-trap --sink NAME`

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| `--sink` | `NAME` | required | Sink name from config. |

### observe windows-event install-source

Register an `spt` event source in the Windows Event Log.

**Synopsis:** `spt observe windows-event install-source [--source NAME] [--channel CHANNEL] [--message-dll PATH]`

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| `--source` | `NAME` | config default | Event source name. |
| `--channel` | `CHANNEL` | `Application` | Target Event Log channel. |
| `--message-dll` | `PATH` | — | Message table DLL or EXE for source registration. |

### observe windows-event uninstall-source

Unregister the `spt` event source from the Windows Event Log.

**Synopsis:** `spt observe windows-event uninstall-source [--source NAME] [--channel CHANNEL] [--message-dll PATH]`

Flags are identical to `windows-event install-source`.

### observe windows-event test

Emit a test event into the Windows Event Log.

**Synopsis:** `spt observe windows-event test [--source NAME] [--channel CHANNEL] [--level LEVEL] [--event-id ID] [--message TEXT]`

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| `--source` | `NAME` | config default | Event source name. |
| `--channel` | `CHANNEL` | — | Event Log channel. |
| `--level` | `info\|warning\|error` | `info` | Event severity. |
| `--event-id` | `ID` | `1000` | Event identifier. |
| `--message` | `TEXT` | — | Event message. |

---

## event

List, test, and replay event bindings; manage event sinks.

```
spt event list --json
spt event test ops-pager
spt event replay --since 1h --binding ops-pager
spt event sink test smtp-primary --json
spt event sink list
```

### event list

List all configured event bindings.

**Synopsis:** `spt event list [--json]`

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| `--json` | | off | JSON output. |

### event test

Fire a binding by name to verify it works end-to-end.

**Synopsis:** `spt event test BINDING-NAME`

### event replay

Replay historical events through a binding.

**Synopsis:** `spt event replay --since DURATION --binding NAME`

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| `--since` | `DURATION` | required | Lookback window (e.g. `1h`, `10m`). |
| `--binding` | `NAME` | required | Binding name. |

### event sink list

List configured event sinks.

**Synopsis:** `spt event sink list [--json]`

### event sink test

Test an event sink by sending a synthetic event.

**Synopsis:** `spt event sink test SINK-NAME [--json]`

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| (positional) | `SINK-NAME` | required | Sink name. |
| `--json` | | off | JSON output. |

---

## stats

Statistics summaries and live counters for tunnels, forwards, and sessions.

### stats summary

Print a snapshot summary of all active counters.

**Synopsis:** `spt stats summary [--profile NAME] [--forward NAME] [--json]`

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| `--profile` | `NAME` | — | Filter to a profile. |
| `--forward` | `NAME` | — | Filter to a forward. |
| `--json` | | off | JSON output. |

### stats live

Show live-updating counters.

**Synopsis:** `spt stats live [--profile NAME] [--forward NAME] [--interval DURATION]`

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| `--profile` | `NAME` | — | Filter to a profile. |
| `--forward` | `NAME` | — | Filter to a forward. |
| `--interval` | `DURATION` | — | Refresh interval (e.g. `1s`). |

### stats connections

Print the current connection table.

**Synopsis:** `spt stats connections [--profile NAME] [--forward NAME] [--json]`

Flags are the same as `stats summary`.

### stats throughput

Print throughput windows (rolling byte rates).

**Synopsis:** `spt stats throughput [--profile NAME] [--forward NAME] [--window DURATION] [--json]`

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| `--profile` | `NAME` | — | Filter to a profile. |
| `--forward` | `NAME` | — | Filter to a forward. |
| `--window` | `DURATION` | — | Rolling window size (e.g. `1m`). |
| `--json` | | off | JSON output. |

### stats errors

Print recent errors with timestamps and context.

**Synopsis:** `spt stats errors [--since DURATION] [--profile NAME] [--json]`

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| `--since` | `DURATION` | — | Lookback window. |
| `--profile` | `NAME` | — | Filter to a profile. |
| `--json` | | off | JSON output. |

### stats export

Export stats to a file.

**Synopsis:** `spt stats export --format FORMAT --since DURATION`

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| `--format` | `json\|jsonl\|csv\|prometheus` | required | Output format. |
| `--since` | `DURATION` | required | Lookback window. |

---

## session

Inspect and manage active forwarded sessions (individual TCP or UDP flows
multiplexed through a tunnel).

```
spt session list --profile edge
spt session show abc123 --json
spt session close abc123 --grace 5s --reason "drain"
spt session drain edge --timeout 30s
spt session top --sort bytes --limit 20
```

### session list

List active sessions.

**Synopsis:** `spt session list [--profile NAME] [--forward NAME] [--json]`

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| `--profile` | `NAME` | — | Filter to a profile. |
| `--forward` | `NAME` | — | Filter to a forward. |
| `--json` | | off | JSON output. |

### session show

Show detailed information for one session.

**Synopsis:** `spt session show SESSION-ID [--json]`

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| (positional) | `SESSION-ID` | required | Session identifier. |
| `--json` | | off | JSON output. |

### session close

Close a single session.

**Synopsis:** `spt session close SESSION-ID [--grace DURATION] [--reason TEXT]`

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| (positional) | `SESSION-ID` | required | Session identifier. |
| `--grace` | `DURATION` | — | Grace period before the session is forcibly closed (e.g. `5s`). |
| `--reason` | `TEXT` | — | Free-form reason recorded in the audit log. |

### session drain

Drain all sessions for a profile, waiting for in-flight connections to finish.

**Synopsis:** `spt session drain PROFILE [--forward NAME] [--grace DURATION]`

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| (positional) | `PROFILE` | required | Profile name. |
| `--forward` | `NAME` | — | Restrict drain to a specific forward. |
| `--grace`, `--timeout` | `DURATION` | — | Drain timeout / grace period. |

### session top

Live top-style view of active sessions, sorted by the chosen key.

**Synopsis:** `spt session top [--sort KEY] [--limit N]`

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| `--sort` | `age\|bytes\|rate\|errors` | — | Sort key. |
| `--limit` | `N` | — | Maximum rows to display. |

---

## ftp

RFC 959/3659 FTP-to-SFTP translator service. The translator exposes a
passive-only FTP control channel and proxies every supported verb to the
configured SFTP backend over the tunnel. Active mode (PORT/EPRT) is refused by
security policy.

```
spt ftp translator serve --bind 0.0.0.0:2121 --pasv-range 50000-50100 --profile edge
spt ftp translator serve --bind 127.0.0.1:21 \
    --pasv-range 50000-50100 \
    --tls-cert /etc/spt/ftp.crt --tls-key /etc/spt/ftp.key \
    --profile edge
```

### ftp translator serve

Start the FTP-to-SFTP translator.

**Synopsis:** `spt ftp translator serve [--bind ADDR] [--pasv-range LO-HI] [--external-ip IP] [--welcome-banner TEXT] [--max-clients N] [--idle-timeout DURATION] [--tls-cert PATH --tls-key PATH] [--tls-required] [--profile NAME] [--json]`

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| `--bind` | `ADDR` | `0.0.0.0:21` | Control-channel listen address. |
| `--pasv-range` | `LO-HI` | `50000-50100` | Inclusive passive-port range (e.g. `50000-50050`). |
| `--external-ip` | `IP` | local address | External IP advertised in PASV replies. |
| `--welcome-banner` | `TEXT` | — | Banner sent to clients on connect. |
| `--max-clients` | `N` | `32` | Maximum concurrent control sessions. |
| `--idle-timeout` | `DURATION` | `5m` | Idle timeout for the control channel. |
| `--tls-cert` | `PATH` | — | PEM certificate chain (requires `--tls-key`). |
| `--tls-key` | `PATH` | — | PEM private key (requires `--tls-cert`). |
| `--tls-required` | | off | Reject `USER`/`PASS` before TLS upgrade (requires `--tls-cert`). |
| `--profile` | `NAME` | — | Profile name used to open the SFTP backend. |
| `--json` | | off | JSON output. |

---

## sftp

One-shot SFTP file operations over a profile's tunnel and FUSE/WinFsp
mount management. All subcommands require `--profile` to identify the
tunnel connection.

```
spt sftp test --profile edge
spt sftp list --profile edge /var/log --json
spt sftp get --profile edge /etc/app/config.toml --out ./config.toml
spt sftp put --profile edge ./build.tar.gz /tmp/build.tar.gz
spt sftp cat --profile edge /etc/hostname
spt sftp tail --profile edge /var/log/app.log --bytes 4096
spt sftp chmod --profile edge --mode 0640 /tmp/build.tar.gz
spt sftp symlink --profile edge --target /opt/app/current /opt/app/live
spt sftp readlink --profile edge /opt/app/live
spt sftp realpath --profile edge ./reports
spt sftp put-recursive --profile edge ./dist /srv/app --bps 5MiB --checksum sha256
spt sftp get-recursive --profile edge /srv/app ./mirror --resume
spt sftp mount add --profile edge --name data --remote /srv/data --mount-point /mnt/spt-data
spt sftp drive add --profile edge --name data --remote /srv/data --letter S:
```

### sftp test

Open an SFTP session and verify connectivity.

**Synopsis:** `spt sftp test --profile NAME [--json]`

### sftp list

List a remote directory.

**Synopsis:** `spt sftp list --profile NAME PATH [--json]`

### sftp stat

Show metadata (size, permissions, timestamps) for a remote path.

**Synopsis:** `spt sftp stat --profile NAME PATH [--json]`

### sftp get

Download a remote file.

**Synopsis:** `spt sftp get --profile NAME REMOTE --out PATH`

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| `--profile` | `NAME` | required | Profile name. |
| (positional) | `REMOTE` | required | Remote file path. |
| `--out` | `PATH` | required | Local output path. |

### sftp put

Upload a local file.

**Synopsis:** `spt sftp put --profile NAME LOCAL REMOTE`

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| `--profile` | `NAME` | required | Profile name. |
| (positional 1) | `LOCAL` | required | Local file path. |
| (positional 2) | `REMOTE` | required | Remote destination path. |

### sftp mkdir

Create a remote directory.

**Synopsis:** `spt sftp mkdir --profile NAME PATH [--json]`

### sftp rm

Remove a remote file.

**Synopsis:** `spt sftp rm --profile NAME PATH [--json]`

### sftp rmdir

Remove a remote directory (must be empty).

**Synopsis:** `spt sftp rmdir --profile NAME PATH [--json]`

### sftp rename

Rename a remote file or directory.

**Synopsis:** `spt sftp rename --profile NAME OLD_PATH NEW_PATH`

### sftp cat

Print a remote file to stdout with a configurable byte cap.

**Synopsis:** `spt sftp cat --profile NAME PATH [--size-cap BYTES]`

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| `--profile` | `NAME` | required | Profile name. |
| (positional) | `PATH` | required | Remote file path. |
| `--size-cap` | `BYTES` | `4194304` (4 MiB) | Maximum bytes to read before truncating. |

### sftp tail

Print the trailing bytes of a remote file.

**Synopsis:** `spt sftp tail --profile NAME PATH [--bytes N]`

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| `--profile` | `NAME` | required | Profile name. |
| (positional) | `PATH` | required | Remote file path. |
| `--bytes` | `N` | `4096` | Number of trailing bytes to print. |

### sftp chmod

Change POSIX permissions on a remote path.

**Synopsis:** `spt sftp chmod --profile NAME --mode OCTAL PATH`

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| `--profile` | `NAME` | required | Profile name. |
| `--mode` | `OCTAL` | required | Octal mode string, e.g. `0640`. |
| (positional) | `PATH` | required | Remote path. |

### sftp symlink

Create a remote symbolic link.

**Synopsis:** `spt sftp symlink --profile NAME --target TARGET LINKPATH`

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| `--profile` | `NAME` | required | Profile name. |
| `--target` | `TARGET` | required | Target path the link should point to. |
| (positional) | `LINKPATH` | required | Link path to create. |

### sftp readlink

Read the target of a remote symbolic link.

**Synopsis:** `spt sftp readlink --profile NAME PATH [--json]`

### sftp realpath

Canonicalise a remote path (resolve `..` and symlinks).

**Synopsis:** `spt sftp realpath --profile NAME PATH [--json]`

### sftp put-recursive

Mirror a local directory tree onto the server.

**Synopsis:** `spt sftp put-recursive --profile NAME SOURCE DESTINATION [--resume] [--bps RATE] [--checksum ALGO] [--follow-symlinks]`

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| `--profile` | `NAME` | required | Profile name. |
| (positional 1) | `SOURCE` | required | Local source directory. |
| (positional 2) | `DESTINATION` | required | Remote destination directory. |
| `--resume` | | off | Seek into existing target files instead of truncating. |
| `--bps` | `RATE` | `0` (unlimited) | Bandwidth cap (e.g. `5MiB`); `0` disables. |
| `--checksum` | `none\|sha256` | `none` | Post-transfer integrity verification. |
| `--follow-symlinks` | | off | Follow symbolic links during the directory walk (loops are still detected). |

### sftp get-recursive

Mirror a remote directory tree to the local filesystem.

**Synopsis:** `spt sftp get-recursive --profile NAME SOURCE DESTINATION [--resume] [--bps RATE] [--checksum ALGO] [--follow-symlinks]`

Flags are identical to `put-recursive`. `SOURCE` is the remote directory;
`DESTINATION` is the local directory.

### sftp mount list

List configured SFTP-backed filesystem mount entries.

**Synopsis:** `spt sftp mount list [--profile NAME] [--json]`

### sftp mount add

Add a FUSE/WinFsp filesystem mount entry to the config.

**Synopsis:** `spt sftp mount add --profile NAME --name NAME --remote PATH --mount-point PATH [--read-only] [--cache MODE]`

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| `--profile` | `NAME` | required | Profile name. |
| `--name` | `NAME` | required | Mount name (used to reference the mount later). |
| `--remote` | `PATH` | required | Remote SFTP path to expose. |
| `--mount-point` | `PATH` | required | Local mountpoint. |
| `--read-only` | | off | Mount read-only. |
| `--cache` | `none\|metadata\|writeback` | — | Local cache mode. |

### sftp mount remove

Remove a filesystem mount entry.

**Synopsis:** `spt sftp mount remove PROFILE/MOUNT`

### sftp mount plan

Preview the platform mount plan for a configured or proposed mount.

**Synopsis:** `spt sftp mount plan --profile NAME [--name NAME] [--remote PATH] [--mount-point PATH] [--cache MODE] [--read-only] [--json]`

### sftp mount start

Activate a filesystem mount.

**Synopsis:** `spt sftp mount start [--profile NAME] [--local PATH] [--remote PATH] [--read-only] [--volume NAME] [--json]`

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| `--profile` | `NAME` | — | Profile name; overrides any configured value. |
| `--local` | `PATH` | — | Local mountpoint override. |
| `--remote` | `PATH` | — | Remote SFTP path override. |
| `--read-only` | | off | Mount read-only. |
| `--volume` | `NAME` | — | Volume label (Windows only). |
| `--json` | | off | JSON output. |

### sftp mount stop

Tear down a filesystem mount.

**Synopsis:** `spt sftp mount stop PATH [--json]`

### sftp umount

Shorthand for `spt sftp mount stop PATH`.

**Synopsis:** `spt sftp umount PATH [--json]`

### sftp drive list

List configured Windows drive mount entries.

**Synopsis:** `spt sftp drive list [--profile NAME] [--json]`

### sftp drive add

Add a WinFsp Windows drive mount entry to the config.

**Synopsis:** `spt sftp drive add --profile NAME --name NAME --remote PATH --letter LETTER [--read-only] [--cache MODE]`

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| `--profile` | `NAME` | required | Profile name. |
| `--name` | `NAME` | required | Mount name. |
| `--remote` | `PATH` | required | Remote SFTP path. |
| `--letter` | `LETTER` | required | Windows drive letter, e.g. `S` or `S:`. |
| `--read-only` | | off | Mount read-only. |
| `--cache` | `none\|metadata\|writeback` | — | Local cache mode. |

### sftp drive remove

Remove a Windows drive mount entry.

**Synopsis:** `spt sftp drive remove PROFILE/MOUNT`

### sftp drive plan

Preview the platform plan for a configured or proposed Windows drive mount.

**Synopsis:** `spt sftp drive plan --profile NAME [--name NAME] [--remote PATH] [--letter LETTER] [--cache MODE] [--read-only] [--json]`

---

## diagnose

Targeted diagnostics: individual checks for network, auth, trust, DNS, bind,
port reachability, service-manager integration, secret backend health, and
observability sinks. Also builds redacted support bundles.

```
spt diagnose run --all --report report.json
spt diagnose port --host db --port 5432 --tcp --autodetect-service
spt diagnose bundle --out support.tgz --redacted --since 24h
spt diagnose service --config /etc/ssh-perma-tunnel/config.toml --system
spt diagnose dns --name db.local
```

### diagnose run

Run a battery of diagnostic checks.

**Synopsis:** `spt diagnose run [--all] [--offline] [--online] [--profile NAME] [--report PATH] [--json]`

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| `--all` | | off | Run every check. |
| `--offline` | | off | Restrict to offline-only checks (mutually exclusive with `--online`). |
| `--online` | | off | Restrict to online-only checks. |
| `--profile` | `NAME` | — | Filter to a profile. |
| `--report` | `PATH` | — | Write a structured JSON report to this path. |
| `--json` | | off | JSON output to stdout. |

### diagnose network

Run network-connectivity checks.

**Synopsis:** `spt diagnose network [--profile NAME] [--endpoint NAME] [--json]`

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| `--profile` | `NAME` | — | Filter to a profile. |
| `--endpoint` | `NAME` | — | Filter to an endpoint. |
| `--json` | | off | JSON output. |

### diagnose auth

Run authentication checks for a profile.

**Synopsis:** `spt diagnose auth [PROFILE] [--probe] [--json]`

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| (positional) | `PROFILE` | all profiles | Profile name; omit for all. |
| `--probe` | | off | Run a live connect probe. |
| `--json` | | off | JSON output. |

### diagnose trust

Run host-key and TLS trust checks for a profile.

**Synopsis:** `spt diagnose trust [PROFILE] [--probe] [--json]`

Flags are identical to `diagnose auth`.

### diagnose dns

Run DNS resolution checks.

**Synopsis:** `spt diagnose dns [--name NAME] [--json]`

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| `--name` | `NAME` | — | Name to test. |
| `--json` | | off | JSON output. |

### diagnose bind

Run local bind checks for forwards.

**Synopsis:** `spt diagnose bind [--profile NAME] [--forward NAME] [--json]`

### diagnose port

Probe a host:port for reachability.

**Synopsis:** `spt diagnose port --host HOST --port PORT [--tcp] [--udp] [--autodetect-service] [--json]`

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| `--host` | `HOST` | required | Target host. |
| `--port` | `PORT` | required | Target port. |
| `--tcp` | | off | TCP probe (mutually exclusive with `--udp`). |
| `--udp` | | off | UDP probe. |
| `--autodetect-service` | | off | Attempt to identify the protocol running on the port. |
| `--json` | | off | JSON output. |

### diagnose service

Run service-manager integration checks.

**Synopsis:** `spt diagnose service --config PATH [--user] [--system] [--json]`

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| `--config` | `PATH` | required | Config file path. |
| `--user` | | off | Check user-scoped service. |
| `--system` | | off | Check system-scoped service. |
| `--json` | | off | JSON output. |

### diagnose secrets

Run secret-backend health checks.

**Synopsis:** `spt diagnose secrets [--json]`

### diagnose observability

Run observability-sink checks.

**Synopsis:** `spt diagnose observability [--sink NAME] [--json]`

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| `--sink` | `NAME` | — | Filter to a specific sink. |
| `--json` | | off | JSON output. |

### diagnose mcp

Run MCP server checks.

**Synopsis:** `spt diagnose mcp [--json]`

### diagnose bundle

Build a redacted support bundle containing logs, config (secrets stripped),
diagnostic output, and system metadata.

**Synopsis:** `spt diagnose bundle --out PATH [--redacted] [--since DURATION]`

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| `--out` | `PATH` | required | Output path (e.g. `support.tgz`). |
| `--redacted` | | off | Strip secrets and PII before bundling. |
| `--since` | `DURATION` | — | Lookback window for included log/event data. |

---

## benchmark

Controlled benchmarking against forwards. All benchmark drivers require the
forward being tested to be live. Use `--unsafe-allow-production-impact` and the
matching config flag to permit drivers that generate significant load.

```
spt benchmark run --profile edge --forward db --duration 30s --connections 16
spt benchmark latency --profile edge --forward db --samples 1000
spt benchmark throughput --profile edge --forward db --duration 60s --payload-size 64KiB
spt benchmark report compare --baseline base.json --candidate cand.json
spt benchmark report export --format markdown --out report.md
```

### benchmark run

Run any benchmark driver by name.

**Synopsis:** `spt benchmark run --driver NAME [--profile NAME] [--forward NAME] [--duration DURATION] [--connections N] [--count N] [--unsafe-allow-production-impact] [--json]`

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| `--driver` | `NAME` | required | Driver name: `latency`, `throughput`, `udp`, `reconnect`, `dns`, or `limits`. |
| `--profile` | `NAME` | — | Profile name (optional for synthetic drivers like `dns`). |
| `--forward` | `NAME` | — | Forward name. |
| `--duration` | `DURATION` | — | Benchmark duration (e.g. `30s`). |
| `--connections` | `N` | — | Concurrent connections. |
| `--count` | `N` | — | Iteration or sample count override. |
| `--unsafe-allow-production-impact` | | off | Allow drivers that may impact production. Also requires `[benchmark].allow_production_impact = true` in config. |
| `--json` | | off | JSON output. |

### benchmark latency

Latency-focused benchmark: measures round-trip time distribution.

**Synopsis:** `spt benchmark latency --profile NAME --forward NAME [--samples N] [--unsafe-allow-production-impact] [--json]`

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| `--profile` | `NAME` | required | Profile name. |
| `--forward` | `NAME` | required | Forward name. |
| `--samples` | `N` | — | Sample count. |
| `--unsafe-allow-production-impact` | | off | See above. |
| `--json` | | off | JSON output. |

### benchmark throughput

Throughput-focused benchmark: measures sustained transfer rate.

**Synopsis:** `spt benchmark throughput --profile NAME --forward NAME [--duration DURATION] [--payload-size SIZE] [--unsafe-allow-production-impact] [--json]`

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| `--profile` | `NAME` | required | Profile name. |
| `--forward` | `NAME` | required | Forward name. |
| `--duration` | `DURATION` | — | Duration (e.g. `60s`). |
| `--payload-size` | `SIZE` | — | Payload block size (e.g. `64KiB`). |
| `--unsafe-allow-production-impact` | | off | See above. |
| `--json` | | off | JSON output. |

### benchmark udp

UDP datagram benchmark (SSH3 forwards only).

**Synopsis:** `spt benchmark udp --profile NAME --forward NAME [--duration DURATION] [--packet-size SIZE] [--pps N] [--unsafe-allow-production-impact] [--json]`

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| `--profile` | `NAME` | required | Profile name. |
| `--forward` | `NAME` | required | Forward name. |
| `--duration` | `DURATION` | — | Duration. |
| `--packet-size` | `SIZE` | — | Datagram size. |
| `--pps` | `N` | — | Target packets per second. |
| `--unsafe-allow-production-impact` | | off | See above. |
| `--json` | | off | JSON output. |

### benchmark reconnect

Reconnect-latency benchmark: repeatedly disconnects and measures time to re-establish.

**Synopsis:** `spt benchmark reconnect --profile NAME [--iterations N] [--unsafe-allow-production-impact] [--json]`

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| `--profile` | `NAME` | required | Profile name. |
| `--iterations` | `N` | — | Number of disconnect/reconnect cycles. |
| `--unsafe-allow-production-impact` | | off | See above. |
| `--json` | | off | JSON output. |

### benchmark dns

DNS resolution benchmark.

**Synopsis:** `spt benchmark dns --name NAME [--samples N] [--json]`

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| `--name` | `NAME` | required | Name to resolve. |
| `--samples` | `N` | — | Sample count. |
| `--json` | | off | JSON output. |

### benchmark limits

Probe and report the effective rate and connection limits for a forward.

**Synopsis:** `spt benchmark limits --profile NAME --forward NAME [--unsafe-allow-production-impact] [--json]`

### benchmark report compare

Compare two benchmark result files side-by-side.

**Synopsis:** `spt benchmark report compare --baseline PATH --candidate PATH`

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| `--baseline` | `PATH` | required | Baseline result file. |
| `--candidate` | `PATH` | required | Candidate result file. |

### benchmark report export

Export a saved benchmark run to a formatted file.

**Synopsis:** `spt benchmark report export RUN-ID --format FORMAT --out PATH`

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| (positional) | `RUN-ID` | required | Run ID (basename of `<state_dir>/benchmarks/<run-id>.json`). |
| `--format` | `json\|jsonl\|csv\|markdown` | required | Output format. |
| `--out` | `PATH` | required | Output path. |

---

## mcp

Built-in Model Context Protocol (MCP) server controls. The MCP server exposes
`spt` capabilities as MCP tools and resources that LLM agents can call. It is
disabled by default; pass `--enable` or set `[mcp].enabled = true` in config.

```
spt mcp serve --stdio --read-only --enable
spt mcp serve --listen 127.0.0.1:9095 --read-only --enable
spt mcp inspect --json
spt mcp policy show
spt mcp policy set allow_write_tools=profile.set,event.test
```

### mcp serve

Start the MCP server. One of `--stdio` or `--listen` is required to select the
transport.

**Synopsis:** `spt mcp serve [--stdio] [--listen 127.0.0.1:PORT] [--read-only] [--config PATH] [--enable]`

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| `--stdio` | | off | Speak MCP over stdin/stdout (mutually exclusive with `--listen`). |
| `--listen` | `127.0.0.1:PORT` | — | Listen on a loopback TCP address. |
| `--read-only` | | off | Expose only read tools; refuse all write/mutating tools. |
| `--config` | `PATH` | — | Override config path. |
| `--enable` | | off | Explicit enable toggle (required unless `[mcp].enabled = true` in config). |

### mcp inspect

Inspect the MCP server's exposed capabilities, tools, and resources.

**Synopsis:** `spt mcp inspect [--json]`

### mcp policy show

Show the current MCP access policy.

**Synopsis:** `spt mcp policy show`

### mcp policy set

Update one or more MCP policy keys.

**Synopsis:** `spt mcp policy set KEY=VALUE [KEY=VALUE …]`

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| (positional) | `KEY=VALUE` | required | One or more policy key=value pairs. |

---

## ssh3-serve

Run the `spt` SSH3 (QUIC/HTTP3) server — the responder half of an spt-to-spt
SSH3 tunnel. The server binds a QUIC/UDP listener, accepts connections, and
processes `direct-tcp` channel opens from peer `spt` clients using the spt
SSH3 framing. Interop with the upstream francoismichel/ssh3 reference server is
explicitly out of scope.

See [transports.md](transports.md) for the spt SSH3 transport architecture.

```
spt ssh3-serve --listen 0.0.0.0:443 --cert server.pem --key server.key
spt ssh3-serve --listen 127.0.0.1:8443 --self-signed
spt ssh3-serve --cert chain.pem --key key.pem --allow-target db.internal:5432
spt ssh3-serve --cert chain.pem --key key.pem --fixed-target dns.internal:53 --require-authorization-file /run/credentials/spt.ssh3.authz
spt ssh3-serve --cert chain.pem --key key.pem --protocol-token ssh3
```

**Synopsis:** `spt ssh3-serve [--listen ADDR:PORT] [--cert PEM --key PEM] [--self-signed] [--self-signed-san NAME] [--protocol-token TOKEN] [--allow-target HOST:PORT] [--fixed-target HOST:PORT] [--require-authorization TOKEN | --require-authorization-file PATH]`

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| `--listen` | `ADDR:PORT` | `0.0.0.0:443` | QUIC/UDP bind address. |
| `--cert` | `PEM` | — | TLS certificate chain (PEM, leaf first). Required unless `--self-signed`. |
| `--key` | `PEM` | — | TLS private key (PEM: PKCS#8, PKCS#1, or SEC1). Required unless `--self-signed`. |
| `--self-signed` | | off | Generate a self-signed certificate at startup (dev mode only; requires the `server-selfsigned` feature). Mutually exclusive with `--cert`/`--key`. |
| `--self-signed-san` | `NAME` | `localhost` | DNS name(s) / IP literal(s) to embed as SANs in the self-signed cert. Repeat for multiple. Only meaningful with `--self-signed`. |
| `--protocol-token` | `TOKEN` | `ssh3` | `:protocol` token required on the HTTP/3 Extended-CONNECT. Mismatches are rejected with HTTP 421. |
| `--allow-target` | `HOST:PORT` | — | Allow-listed forward target. Repeat for multiple. Empty list = open relay (use with care). |
| `--fixed-target` | `HOST:PORT` | — | Pin every forward to this single target regardless of what the peer requests. Mutually exclusive with `--allow-target`. |
| `--require-authorization` | `TOKEN` | — | Require this bearer value in the `Authorization` header; mismatches rejected with HTTP 401. Prefer `--require-authorization-file` for production so secrets do not appear in process arguments. |
| `--require-authorization-file` | `PATH` | — | Read the required `Authorization` header value from a file. Trailing CR/LF is ignored. |

---

## status

One-shot or live overview of the entire `spt` application: daemon/supervisor
state, tunnel and profile health, forwards, and optional subsystem health
(status API, MCP, DNS, metrics, remote config, events, services).

```
spt status
spt status --detail
spt status --json
spt status --output yaml
spt status --watch
```

**Synopsis:** `spt status [--output FORMAT] [--json] [--detail] [--watch]`

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| `--output` | `human\|json\|jsonl\|yaml` | — | Output format (overrides the global `--output`). |
| `--json` | | off | Convenience alias for `--output json`. |
| `--detail` | | off | Show verbose per-component state (resolved bind addresses, auth modes, last-error detail, per-forward counters). |
| `--watch` | | off | Continuously refresh the overview in place instead of printing once. |

---

## status-api

Controls for the read-only HTTP status API. The supervisor normally hosts the
API inline when `[status_api].enabled = true` in config. The `serve` subcommand
is a foreground fallback for environments where the supervisor is not running.

```
spt status-api show
spt status-api show --output json
spt status-api serve --config /etc/spt/spt.toml
spt status-api token rotate
```

### status-api serve

Start the status API server in the foreground.

**Synopsis:** `spt status-api serve [--config PATH] [--bind HOST:PORT]`

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| `--config` | `PATH` | — | Override config path. |
| `--bind` | `HOST:PORT` | from config | Override the bind address (`[status_api].bind`). |

### status-api show

Show whether the status API is bound and how to reach it.

**Synopsis:** `spt status-api show [--detail]`

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| `--detail` | | off | Show the resolved auth mode and TLS state in addition to the bind address. |

### status-api token rotate

Rotate the bearer token used for status API authentication. Requires
`auth.mode = "bearer"` and a writable secret backend for the configured
`token_from` reference.

**Synopsis:** `spt status-api token rotate [--print-token] [--bytes N]`

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| `--print-token` | | off | Print the new token to stdout (default: print success message and SecretRef only). |
| `--bytes` | `N` | `32` | Length in bytes of the random token before base64 encoding (256-bit default). |

---

## completion

Generate shell completion scripts from the live clap command tree. Because the
scripts are generated at runtime, they always reflect the exact build in use.

### completion generate

Print a completion script for the requested shell to stdout.

**Synopsis:** `spt completion generate SHELL`

| Argument | Values | Description |
|----------|--------|-------------|
| `SHELL` | `bash`, `zsh`, `fish`, `powershell`, `elvish` | Target shell. |

**Installation examples:**

```
# Bash (system-wide)
spt completion generate bash | sudo tee /etc/bash_completion.d/spt

# Zsh
spt completion generate zsh > ~/.zsh/completions/_spt

# Fish
spt completion generate fish > ~/.config/fish/completions/spt.fish

# PowerShell (append to profile)
spt completion generate powershell >> $PROFILE

# Elvish
spt completion generate elvish > ~/.config/elvish/completions/spt.elv
```

---

## about

List bundled libraries, their licenses, and export attribution data. All data
is captured at build time from `cargo metadata`; there is no network access or
runtime dependency on Cargo. The inventory is baked into the binary.

Invoked bare (`spt about`) prints a quick version and top-dependency overview.

```
spt about                              # overview: spt version + top 20 deps
spt about list                         # full library list
spt about list --format json           # structured array
spt about list --format markdown       # distribution-friendly attribution
spt about list --license MIT           # filter by SPDX substring (case-insensitive)
spt about list --include-dev           # include dev/test deps (default: runtime-only)
spt about show clap                    # detailed view for one library
spt about licenses                     # SPDX-grouped histogram (compliance audits)
spt about export attribution.md        # write attribution data to a file
```

### about list

List every bundled library, one line per entry.

**Synopsis:** `spt about list [--format FORMAT] [--license SUBSTRING] [--include-dev]`

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| `--format` | `text\|json\|markdown` | `text` | Output format. |
| `--license` | `SUBSTRING` | — | Filter by SPDX license substring (case-insensitive). |
| `--include-dev` | | off | Include dev and test dependencies (default: runtime-only). |

### about show

Show detailed information for a single bundled library.

**Synopsis:** `spt about show CRATE`

| Argument | Description |
|----------|-------------|
| `CRATE` | Crate name. |

### about licenses

Group bundled libraries by SPDX license with per-license counts. Useful for
license-compliance audits.

**Synopsis:** `spt about licenses`

### about export

Write attribution data to a file. The output format is inferred from the file
extension: `.md` produces Markdown, `.json` produces JSON, and anything else
produces plain text.

**Synopsis:** `spt about export PATH`

| Argument | Description |
|----------|-------------|
| `PATH` | Destination file path. |

---

## kill

Terminate every running `spt` instance on this host. Processes are matched by
executable basename (`spt` on Unix, `spt.exe` on Windows) using `sysinfo` for
cross-platform enumeration. The calling `spt` process is excluded by default.

```
spt kill                           # graceful SIGTERM / TerminateProcess, 5s grace
spt kill --force                   # SIGKILL / unconditional TerminateProcess
spt kill --dry-run                 # list would-be targets, signal nothing
spt kill --include-self            # also kill the calling spt
spt kill --name spt-bin            # substring override (case-insensitive)
spt kill --timeout 30s             # extend the terminate grace window
```

**Synopsis:** `spt kill [--force] [--include-self] [--dry-run] [--name NAME] [--timeout DURATION]`

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| `--force` | | off | Skip the graceful signal and go straight to a hard kill (`SIGKILL` / `TerminateProcess`). |
| `--include-self` | | off | Include the calling `spt` process in the kill list. |
| `--dry-run` | | off | Print what would be killed without signalling anything. |
| `--name` | `NAME` | `spt` / `spt.exe` | Basename substring override; case-insensitive. |
| `--timeout` | `DURATION` | `5s` | Per-process grace window. On Unix, `SIGTERM` is asynchronous; the timeout is honoured on Windows via `WaitForSingleObject`. |

---

## update

Embedded auto-updater. The background polling thread is only spawned when
`[updater].enabled = true` in config. All manual subcommands below work
regardless of whether the background thread is enabled.

Invoked bare (`spt update`) defaults to `spt update status`.

### update check

Check whether a newer release is available.

**Synopsis:** `spt update check [--source KIND]`

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| `--source` | `github\|url\|static` | from config | Override the configured update source for this one-off probe. |

### update download

Download the latest release artifact to the staging directory without installing it.

**Synopsis:** `spt update download [--target TRIPLE]`

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| `--target` | `TRIPLE` | current build | Rust target triple to fetch. |

### update apply

Install the staged artifact via an atomic swap, then optionally restart the supervisor.

**Synopsis:** `spt update apply [--no-restart]`

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| `--no-restart` | | off | Skip the post-install restart even when `[updater.action].restart_supervisor = true`. |

### update now

Run `check` + `download` + `apply` in one step.

**Synopsis:** `spt update now [--no-restart]`

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| `--no-restart` | | off | Skip the post-install restart. |

### update status

Print the updater status: enabled flag, time of last check, latest known
version, next scheduled poll, and staged artifact if any.

**Synopsis:** `spt update status [--json]`

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| `--json` | | off | JSON output. |

### update history

Show past update events from the audit log.

**Synopsis:** `spt update history [--limit N]`

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| `--limit` | `N` | `10` | Number of past events to display. |
