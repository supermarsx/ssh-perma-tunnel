# Scripting hooks (`spt-scripting`)

`spt` runs operator-supplied Rhai scripts at five lifecycle points on every
SSH2 session. Scripts are useful for emitting custom telemetry, gating
forwards on policy decisions, integrating with external secret rotation,
or annotating audit events with deployment metadata.

The engine is `rhai 1.19` (pure-Rust, MSRV 1.66) compiled with
`default-features = false` + `std` + `sync` + `serde`. As of t7-A2 the
engine is real — the t6 byte-count stub interpreter is gone.

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
max_modules     = 0           # default — `import` is forbidden
```

`path` is resolved relative to the directory of the loading config file.
The script is read once at `ScriptEngine::load` time and compiled to an
AST; syntax errors and disabled-symbol references (`eval`, `import`)
fail at startup, not at first hook fire.

A hook slot is *opt-in*: if a slot is unset in `[profiles.script.hooks]`,
the corresponding lifecycle event short-circuits and never enters the
engine. The engine handle itself is `Option<Arc<ScriptEngine>>`, so a
profile without `[profiles.script]` pays exactly zero per-event cost.

## Sandbox

The engine is built via `Engine::new_raw` so only the `CorePackage` is
registered — no filesystem, no network, no module loading. In addition:

- `engine.disable_symbol("eval")` and `engine.disable_symbol("import")`
  are applied before AST compilation. A script that mentions either
  token fails to load.
- All five `set_max_*` bounds from `[profiles.script.limits]` are
  honoured by `rhai` natively. Exceeding `max_operations`,
  `max_call_levels`, `max_string_size`, `max_array_size`, or
  `max_modules` aborts the script with `ScriptError::LimitExceeded`.
- Every hook invocation runs against a **fresh** `rhai::Scope` — the AST
  is the only shared state, eliminating mutable carry-over between
  hooks. Use the event payload to pass state in, and return values from
  the hook to pass state out.
- Uncaught `throw` inside a script aborts the invocation and is
  classified as `ScriptError::HookFailed`.

## Hook entry points

| Hook              | Trigger                                          | Event struct                |
|-------------------|--------------------------------------------------|-----------------------------|
| `pre_connect`     | before the TCP/QUIC connect attempt              | `event::PreConnect`         |
| `post_connect`    | after successful authentication                  | `event::PostConnect`        |
| `on_forward_state`| every forward state-machine transition           | `event::ForwardState`       |
| `on_disconnect`   | after the session terminates                     | `event::Disconnect`         |
| `on_event`        | generic catch-all for any structured event       | `event::Generic`            |

The event payload is delivered as a `rhai::Dynamic` value built via
`rhai::serde::to_dynamic` — fields are accessed by name from the script
side (`event.host`, `event.attempt`, etc.).

### `PreConnect`

```text
profile     // String — profile name
host        // String — remote host (DNS or literal IP)
port        // i64    — remote port
attempt     // i64    — connection attempt counter (1-indexed)
```

### `PostConnect`

```text
profile         // String
host            // String
port            // i64
auth_method     // String — "publickey" | "password" | "keyboard-interactive"
                //          | "gssapi-with-mic" | ...
server_banner   // String? — negotiated SSH banner if available
```

### `ForwardState`

```text
profile      // String
forward_id   // String — config `name`, or `kind:bind` if anonymous
transition   // String — "listening" | "active" | "paused" | "closed" | "failed"
```

### `Disconnect`

```text
profile      // String
reason       // String — stable reason code, e.g. "keepalive_timeout",
             //          "peer_eof", "user_request", "auth_failed"
duration_ms  // i64 — session lifetime in milliseconds
```

### `Generic`

```text
profile        // String
tag            // String — free-form snake_case event tag
payload_json   // String — opaque JSON payload (parse via parse_json if needed)
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
    // Catch-all: surface unusual tags loudly.
    if event.tag == "audit_anomaly" {
        print(`[spt] anomaly on ${event.profile}: ${event.payload_json}`);
    }
}
```

## Audit

Engine load and every hook invocation emit structured audit events via
the workspace audit pipeline. See [Events](events.md) and
`crates/spt-scripting/src/audit.rs` for the event taxonomy. Hook outcomes
(`Ok`, `LimitExceeded`, `HookFailed`, `DisabledSymbol`) are recorded with
the hook name and the elapsed duration.

## Failure modes

| Error                          | Cause                                           | CLI exit code |
|--------------------------------|-------------------------------------------------|---------------|
| `ScriptError::CompileFailed`   | Syntax error, reserved-keyword use, missing fn  | 1 (RuntimeFailure) — surfaces at `tunnel run` startup |
| `ScriptError::LimitExceeded`   | One of the five `set_max_*` bounds tripped      | log + abort the hook; session continues |
| `ScriptError::HookFailed`      | Uncaught `throw` inside the hook body           | log + abort the hook; session continues |
| `ScriptError::DisabledSymbol`  | Script mentions `eval` or `import`              | 1 (RuntimeFailure) at `load` time |

Script failures **never** abort the SSH session itself; the supervisor
treats them as advisory. To force-fail an SSH session, return a
non-success status code from a custom controller, not from a script.

## See also

- [Configuration](configuration.md) — `[profiles.script]` schema.
- [Events](events.md) — event delivery and the audit sink surface.
- `crates/spt-scripting/` — engine, error, and event reference docs.
