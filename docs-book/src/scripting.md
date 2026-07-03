# Scripting

`spt` runs operator-supplied Rhai scripts at five lifecycle points on every
SSH2 session. Scripts are useful for emitting custom telemetry, gating
behaviour on policy decisions, integrating with external secret rotation, or
annotating audit events with deployment metadata.

The engine is `rhai 1.19` (pure-Rust, MSRV 1.66) compiled with
`default-features = false` plus `std`, `sync`, and `serde`. Scripting is
**opt-in per profile**: a profile without `[profiles.script]` pays exactly
zero per-event overhead.

## Hook points

| Hook | Trigger | Event struct |
|------|---------|--------------|
| `pre_connect` | Before the TCP or QUIC connect attempt. | `PreConnect` |
| `post_connect` | After successful authentication. | `PostConnect` |
| `on_forward_state` | Every forward state-machine transition. | `ForwardState` |
| `on_disconnect` | After the session terminates. | `Disconnect` |
| `on_event` | Generic catch-all for any structured event. | `Generic` |

Each hook slot is independently opt-in. If a slot is unset in
`[profiles.script.hooks]`, the corresponding lifecycle point short-circuits and
never enters the engine. The engine handle itself is `Option<Arc<ScriptEngine>>`,
so an unset `[profiles.script]` block costs nothing at runtime.

The hooks are wired into the russh SSH2 session path and invoked via
`spawn_blocking`. A configured hook slot is called at its lifecycle point.

## Configuration

```toml
[profiles.script]
path = "/etc/spt/hooks.rhai"

[profiles.script.hooks]
pre_connect      = "before_dial"
post_connect     = "after_auth"
on_forward_state = "on_forward"
on_disconnect    = "after_disconnect"
on_event         = "any_event"

[profiles.script.limits]
max_operations  = 1_000_000   # default
max_call_levels = 32          # default
max_string_size = 65_536      # default
max_array_size  = 4_096       # default
max_modules     = 0           # default; import is forbidden
```

`path` is resolved relative to the directory of the loading config file. The
script is read once at engine load time and compiled to an AST; syntax errors,
references to disabled symbols (`eval`, `import`), and missing hook function
names are caught at startup, not at first hook fire.

## Sandbox

The engine is constructed via `Engine::new_raw`, so only `CorePackage` is
registered. There is no filesystem access, no network access, and no module
loading. Additional constraints:

- `engine.disable_symbol("eval")` and `engine.disable_symbol("import")` are
  applied before the AST is built. A script that mentions either token fails
  to load.
- All five `set_max_*` bounds from `[profiles.script.limits]` are applied
  before AST registration. Exceeding any bound during a hook invocation aborts
  that invocation with `ScriptError::LimitExceeded`; the SSH session continues.
- Every hook invocation runs against a **fresh** `rhai::Scope`. The AST is the
  only shared state, eliminating any mutable carry-over between invocations.
  Use the event payload to pass data in; use return values to pass data out.
- An uncaught `throw` inside a script body is classified as
  `ScriptError::HookFailed`.

## Event payload fields

Event payloads are delivered as `rhai::Dynamic` values built via
`rhai::serde::to_dynamic`. Fields are accessed by name from the script side
(`event.host`, `event.attempt`, etc.).

### `PreConnect`

```
profile     // String — profile name
host        // String — remote host (DNS or literal IP)
port        // i64    — remote port
attempt     // i64    — connection attempt counter (1-indexed)
```

### `PostConnect`

```
profile         // String
host            // String
port            // i64
auth_method     // String — "publickey" | "password" | "keyboard-interactive" | ...
server_banner   // String? — negotiated SSH banner, if available
```

### `ForwardState`

```
profile      // String
forward_id   // String — config `name`, or "kind:bind" for anonymous forwards
transition   // String — "listening" | "active" | "paused" | "closed" | "failed"
```

### `Disconnect`

```
profile      // String
reason       // String — stable code: "keepalive_timeout" | "peer_eof" |
             //          "user_request" | "auth_failed" | ...
duration_ms  // i64 — session lifetime in milliseconds
```

### `Generic`

```
profile        // String
tag            // String — free-form snake_case event tag
payload_json   // String — opaque JSON payload; parse with parse_json() if needed
```

## Example

```rhai
// /etc/spt/hooks.rhai

fn before_dial(event) {
    print(`[spt] ${event.profile}: dialling ${event.host}:${event.port} (attempt ${event.attempt})`);
}

fn after_auth(event) {
    print(`[spt] ${event.profile}: authed via ${event.auth_method}`);
}

fn on_forward(event) {
    if event.transition == "failed" {
        print(`[spt] ${event.profile}: forward ${event.forward_id} FAILED — investigate`);
    }
}

fn after_disconnect(event) {
    let secs = event.duration_ms / 1000;
    print(`[spt] ${event.profile}: session ended after ${secs}s — reason=${event.reason}`);
}

fn any_event(event) {
    // Catch-all: surface unusual tags.
    if event.tag == "audit_anomaly" {
        print(`[spt] anomaly on ${event.profile}: ${event.payload_json}`);
    }
}
```

With `[profiles.script.hooks]` mapped as shown in the configuration section
above, `spt` calls `before_dial` before each connect attempt, `after_auth`
after authentication, `on_forward` on each forward transition, `after_disconnect`
when the session ends, and `any_event` for every generic structured event.

## Failure modes

| Error | Cause | Effect |
|-------|-------|--------|
| `ScriptError::CompileFailed` | Syntax error, reserved-keyword use, missing function. | `tunnel run` fails at startup (exit 1). |
| `ScriptError::LimitExceeded` | One of the five `set_max_*` bounds tripped. | Hook invocation aborted; session continues. |
| `ScriptError::HookFailed` | Uncaught `throw` inside the hook body. | Hook invocation aborted; session continues. |
| `ScriptError::DisabledSymbol` | Script mentions `eval` or `import`. | `tunnel run` fails at startup (exit 1). |

Script failures **never** abort the underlying SSH session. The supervisor
treats script hooks as advisory. To fail a session programmatically, use
a custom supervisor controller, not a script hook.

## Audit

Engine load and every hook invocation emit structured audit events through the
workspace audit pipeline. Hook outcomes (`Ok`, `LimitExceeded`, `HookFailed`,
`DisabledSymbol`) are recorded with the hook name and elapsed duration.

See [Security](security.md) for the security posture of the scripting sandbox.
