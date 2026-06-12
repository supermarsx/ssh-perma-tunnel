# Profiles

A profile is the unit of tunnel lifecycle in `spt`. Each profile has a
single SSH session (or pool of failover sessions) and one or more forwards
multiplexed over it.

## Anatomy of a profile

    [[profiles]]
    name = "edge"
    enabled = true
    protocol = "ssh2"
    host = "edge.example.com"
    port = 22
    user = "tunnel"

    [profiles.auth]
    method = "public_key"
    identity_file = "/etc/spt/id_ed25519"

    [profiles.trust]
    mode = "known_hosts"
    known_hosts_file = "/etc/spt/known_hosts"
    strict = true

    [profiles.keepalive]
    interval = "30s"
    timeout = "10s"
    max_missed = 3

    [profiles.reconnect]
    initial_delay = "1s"
    max_delay = "5m"
    jitter = "20%"
    reset_after = "10m"

    [profiles.instability]
    enabled = true
    window = "10m"
    max_disconnects = 5
    action = "mark_degraded"

    [profiles.failover]
    mode = "priority"          # priority | weighted | manual
    health_check = "tcp_connect"
    fail_after = 3
    restore_after = "2m"

    [[profiles.endpoints]]
    name = "primary"
    host = "edge.example.com"
    port = 22
    priority = 0

    [[profiles.endpoints]]
    name = "dr"
    host = "edge-dr.example.com"
    port = 22
    priority = 10

**Legacy single-endpoint compat**: profiles may also set top-level `host` and
`port` (and optionally `user`) directly. This is retained for v0 config-file
compatibility; the runtime synthesizes a single `Endpoint` from these fields
when `[[profiles.endpoints]]` is absent. New profiles should declare
`[[profiles.endpoints]]` blocks directly so failover and per-endpoint
priority/weight work.

## Per-endpoint authentication

By default every endpoint in a profile authenticates with the profile-level
`[profiles.auth]` block and the profile-level `user` — this is the **global**
case. A profile that declares only `[profiles.auth]` and no per-endpoint auth
behaves exactly as it always has: the same credentials are used for every
endpoint. No change is required for existing configs (the new fields are
omitted entirely when unset).

Each `[[profiles.endpoints]]` block may optionally carry its **own**
credentials by adding an inline `[profiles.endpoints.auth]` block and/or a
`user` field. When present, that endpoint uses its own credentials; when
absent, it inherits the profile-level `[profiles.auth]` (and `user`).

### Precedence: whole-block override, not field merge

Per-endpoint auth is a **whole-block override**, not a field-level merge:

- If an endpoint declares `[profiles.endpoints.auth]`, that block **fully
  replaces** the profile-level `[profiles.auth]` for that endpoint. You
  cannot inherit the profile auth and override only one field (for example,
  keep the profile key but swap the username inside the auth block) — restate
  the complete auth block on the endpoint.
- `endpoint.user` overrides `profile.user` **for that endpoint only**. (The
  username is resolved independently of the auth block, so you can keep the
  global `[profiles.auth]` and still vary just the login user per endpoint by
  setting `user` on the endpoint without an `[profiles.endpoints.auth]` block.)

This mirrors the existing per-hop `[profiles.hops.auth]` fallback semantics: a
hop with its own `auth`/`user` overrides the profile-level credentials for that
hop, and inherits them when unset. Per-endpoint auth resolves identically.

Secrets in a per-endpoint `[profiles.endpoints.auth]` block use the same
`secret://` references as profile auth (see [Secrets](secrets.md)); two
endpoints may point at distinct secret refs and the resolver resolves each
independently at connect time.

### Example: one endpoint inherits, one overrides

    [[profiles]]
    name = "edge"
    enabled = true
    protocol = "ssh2"
    user = "tunnel"

    # Profile-level (global) credentials — used by any endpoint that does
    # not declare its own [profiles.endpoints.auth].
    [profiles.auth]
    method = "public_key"
    identity_file = "/etc/spt/id_ed25519"

    # Inherits the global user (`tunnel`) and the global public_key auth above.
    [[profiles.endpoints]]
    name = "primary"
    host = "edge.example.com"
    port = 22
    priority = 0

    # Overrides with its own user AND its own full auth block — this endpoint
    # logs in as `dr-svc` with a different key and passphrase, ignoring the
    # profile-level [profiles.auth] entirely.
    [[profiles.endpoints]]
    name = "dr"
    host = "edge-dr.example.com"
    port = 22
    priority = 10
    user = "dr-svc"

    [profiles.endpoints.auth]
    method = "public_key"
    identity_file = "/etc/spt/id_dr_ed25519"
    passphrase = "secret://ssh/edge-dr/passphrase"

### TUI editing

The override is editable from the TUI **Endpoints** page: each endpoint has an
auth-override toggle. With the toggle off, the endpoint inherits the global
`[profiles.auth]` (and `user`); turning it on reveals the per-endpoint `user`
and auth fields, which write an inline `[profiles.endpoints.auth]` block for
that endpoint. The **Auth** page continues to edit the profile-level
(global/default) `[profiles.auth]`.

    [[profiles.forwards]]
    name = "db"
    type = "local"
    transport = "tcp"
    bind = "127.0.0.1:5432"
    target = "db.internal:5432"
    target_resolve = "remote"

## State machine

13 profile states (per spec §11):

    Disabled -> Initialising -> Resolving -> Connecting -> Authenticating
    -> Negotiating -> Ready -> Degraded -> Reconnecting
    -> CooldownAfterFailure -> FailingOver -> Stopped (-> Disposed)

Forwards have their own 8-state machine (see [Forwards](forwards.md)).

## Reconnect

Full-jitter exponential backoff: `delay = rand_uniform(0, min(cap, base * 2^attempt))`.
After `reset_after` of stable connectivity, the attempt counter resets.

## Instability detection

A sliding-window detector counts disconnects in `[profiles.instability].window`.
Crossing `disconnect_threshold` flips the profile to `Degraded` and emits an
`profile.degraded` event.

## Failover

Endpoints have priority and weight. The selector picks the highest-priority
healthy endpoint (lowest numeric priority); `weighted` mode randomly distributes
between endpoints with equal priority by `weight`. A failed endpoint is marked
unhealthy after `fail_after` consecutive health-check failures and is
re-evaluated for failback after the `restore_after` window. `manual` mode
disables automatic selection — operators trigger transitions via
`spt tunnel failover <profile> --to <endpoint>`.

## Hot reload

`spt config reload` (or SIGHUP under `[runtime.reload].mode = "signal"`)
recomputes a `ReloadPlan` of {start, stop, restart, add-forward,
remove-forward, restart-forward} actions and applies them via the
orchestrator. `restart_changed_profiles = true` restarts only the profiles
whose canonical TOML changed.

## See also

- [Forwards](forwards.md)
- [Authentication](auth.md)
- [Trust](trust.md)
- [Service Integration](service-integration.md)
