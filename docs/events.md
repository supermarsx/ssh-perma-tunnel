# Events

The event subsystem fans typed lifecycle events to a configurable set of
sinks. Bindings filter and template events; the dispatcher persists failed
deliveries to disk for retry.

## Event shape

Each `Event` carries:

- `kind` — e.g. `profile.degraded`, `forward.bind_failed`,
  `auth.failed`, `mcp.tool_called`.
- `severity` — info | warn | error.
- `fields` — a string-keyed map of event-specific data (already-redacted).
- `timestamp_ms` — Unix epoch milliseconds.

## Bindings

    [[events.bindings]]
    name = "ops-pager"
    match = { kind = "profile.degraded", severity = "error" }
    sinks = ["pagerduty", "slack"]
    dedupe = "5m"

`match` is a flat predicate; multiple keys AND together. `dedupe` suppresses
re-fires of identical events within the window.

## Sinks

    [[events.sinks]]
    name = "slack"
    type = "https"               # https|smtp|sms|push|command|mcp_notify
    endpoint = "https://hooks.slack.com/..."
    template = "{{kind}} on {{profile}}: {{message}}"

Templates use mustache-like `{{field}}` substitution. Unknown fields render
as the empty string.

## Delivery & retries

Failed deliveries are spooled to `<state_dir>/spool/<sink>/` and retried
with exponential backoff. The spool size is bounded; oldest entries are
dropped first.

## Replay

    spt event replay --since 1h --binding ops-pager

Re-runs historical events through one binding for testing.
