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
    method = "pubkey"
    private_key = "/etc/spt/id_ed25519"

    [profiles.trust]
    mode = "known_hosts"
    known_hosts = "/etc/spt/known_hosts"
    strict = true

    [profiles.keepalive]
    interval = "30s"
    timeout = "10s"
    max_misses = 3

    [profiles.reconnect]
    initial_backoff = "1s"
    max_backoff = "5m"
    jitter = 0.5
    reset_after = "10m"

    [profiles.instability]
    window = "10m"
    disconnect_threshold = 5

    [profiles.failover]
    mode = "priority"          # priority | weighted | manual
    cooldown = "2m"

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
between endpoints with equal priority by `weight`. A failed endpoint enters
`cooldown` for the configured period before being reconsidered. `manual` mode
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
