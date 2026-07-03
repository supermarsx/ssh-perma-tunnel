
using namespace System.Management.Automation
using namespace System.Management.Automation.Language

Register-ArgumentCompleter -Native -CommandName 'spt' -ScriptBlock {
    param($wordToComplete, $commandAst, $cursorPosition)

    $commandElements = $commandAst.CommandElements
    $command = @(
        'spt'
        for ($i = 1; $i -lt $commandElements.Count; $i++) {
            $element = $commandElements[$i]
            if ($element -isnot [StringConstantExpressionAst] -or
                $element.StringConstantType -ne [StringConstantType]::BareWord -or
                $element.Value.StartsWith('-') -or
                $element.Value -eq $wordToComplete) {
                break
        }
        $element.Value
    }) -join ';'

    $completions = @(switch ($command) {
        'spt' {
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('config', 'config', [CompletionResultType]::ParameterValue, 'Manage configuration files (init, validate, diff, render, reload)')
            [CompletionResult]::new('profile', 'profile', [CompletionResultType]::ParameterValue, 'Manage SSH/SSH3 tunnel profiles')
            [CompletionResult]::new('forward', 'forward', [CompletionResultType]::ParameterValue, 'Manage forwards (local/remote TCP, UDP)')
            [CompletionResult]::new('tunnel', 'tunnel', [CompletionResultType]::ParameterValue, 'Run, inspect, and control tunnels')
            [CompletionResult]::new('service', 'service', [CompletionResultType]::ParameterValue, 'Install and control native services')
            [CompletionResult]::new('key', 'key', [CompletionResultType]::ParameterValue, 'Generate, inspect, and install SSH keys')
            [CompletionResult]::new('secret', 'secret', [CompletionResultType]::ParameterValue, 'Manage the secret vault and OS keychain references')
            [CompletionResult]::new('auth', 'auth', [CompletionResultType]::ParameterValue, 'Authentication helpers')
            [CompletionResult]::new('dns', 'dns', [CompletionResultType]::ParameterValue, 'Built-in DNS resolver and hosts-file management')
            [CompletionResult]::new('firewall', 'firewall', [CompletionResultType]::ParameterValue, 'Inspect and manage OS firewall / packet-filter rules')
            [CompletionResult]::new('log', 'log', [CompletionResultType]::ParameterValue, 'Log tailing, sink testing, and export')
            [CompletionResult]::new('observe', 'observe', [CompletionResultType]::ParameterValue, 'Metrics and Windows Event Log helpers')
            [CompletionResult]::new('event', 'event', [CompletionResultType]::ParameterValue, 'Event bindings and sinks')
            [CompletionResult]::new('stats', 'stats', [CompletionResultType]::ParameterValue, 'Statistics summaries and live counters')
            [CompletionResult]::new('session', 'session', [CompletionResultType]::ParameterValue, 'Inspect and manage active sessions')
            [CompletionResult]::new('ftp', 'ftp', [CompletionResultType]::ParameterValue, 'FTP→SFTP translator service')
            [CompletionResult]::new('sftp', 'sftp', [CompletionResultType]::ParameterValue, 'SFTP file operations and mount planning')
            [CompletionResult]::new('diagnose', 'diagnose', [CompletionResultType]::ParameterValue, 'Targeted diagnostics and support bundles')
            [CompletionResult]::new('benchmark', 'benchmark', [CompletionResultType]::ParameterValue, 'Controlled benchmarking against forwards')
            [CompletionResult]::new('mcp', 'mcp', [CompletionResultType]::ParameterValue, 'Built-in MCP server controls')
            [CompletionResult]::new('ssh3-serve', 'ssh3-serve', [CompletionResultType]::ParameterValue, 'Run the in-repo SSH3 (QUIC + HTTP/3) server end — the responder half of an spt↔spt SSH3 tunnel')
            [CompletionResult]::new('status', 'status', [CompletionResultType]::ParameterValue, 'Show overall app status — daemon, tunnels/profiles, forwards, and subsystems (status API, MCP, DNS, metrics, remote-config, events, services)')
            [CompletionResult]::new('status-api', 'status-api', [CompletionResultType]::ParameterValue, 'Controls for the read-only HTTP status API')
            [CompletionResult]::new('completion', 'completion', [CompletionResultType]::ParameterValue, 'Generate shell completions')
            [CompletionResult]::new('about', 'about', [CompletionResultType]::ParameterValue, 'List bundled libraries and their licenses')
            [CompletionResult]::new('kill', 'kill', [CompletionResultType]::ParameterValue, 'Terminate every running `spt` instance on this host')
            [CompletionResult]::new('update', 'update', [CompletionResultType]::ParameterValue, 'Embedded auto-updater (off by default). Manual commands work regardless of the `[updater].enabled` flag; the background polling thread is only spawned when explicitly enabled')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'spt;config' {
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('init', 'init', [CompletionResultType]::ParameterValue, 'Initialize a new config file from a template')
            [CompletionResult]::new('validate', 'validate', [CompletionResultType]::ParameterValue, 'Validate config syntax, schema, and obvious mistakes')
            [CompletionResult]::new('doctor', 'doctor', [CompletionResultType]::ParameterValue, 'Run environment checks against the loaded config')
            [CompletionResult]::new('render', 'render', [CompletionResultType]::ParameterValue, 'Render the canonical (optionally redacted) config')
            [CompletionResult]::new('diff', 'diff', [CompletionResultType]::ParameterValue, 'Diff two config files')
            [CompletionResult]::new('migrate', 'migrate', [CompletionResultType]::ParameterValue, 'Migrate a config between schema versions')
            [CompletionResult]::new('reload', 'reload', [CompletionResultType]::ParameterValue, 'Reload the running service''s config')
            [CompletionResult]::new('pull', 'pull', [CompletionResultType]::ParameterValue, 'Pull a remote config over HTTPS with pinning')
            [CompletionResult]::new('trust', 'trust', [CompletionResultType]::ParameterValue, 'Manage remote-config trust pins')
            [CompletionResult]::new('encrypt', 'encrypt', [CompletionResultType]::ParameterValue, 'Encrypt a plaintext config to a sealed `SPTENC1` envelope')
            [CompletionResult]::new('decrypt', 'decrypt', [CompletionResultType]::ParameterValue, 'Decrypt a sealed `SPTENC1` envelope back to plaintext TOML')
            [CompletionResult]::new('edit', 'edit', [CompletionResultType]::ParameterValue, 'Open a sealed config in `$EDITOR`; re-seal on save')
            [CompletionResult]::new('crypt', 'crypt', [CompletionResultType]::ParameterValue, 'Re-seal a sealed config under a new key (key rotation)')
            [CompletionResult]::new('gen-key', 'gen-key', [CompletionResultType]::ParameterValue, 'Generate a config-encryption key (X25519 keypair or raw PSK)')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'spt;config;init' {
            [CompletionResult]::new('--path', '--path', [CompletionResultType]::ParameterName, 'Output path for the generated config')
            [CompletionResult]::new('--example', '--example', [CompletionResultType]::ParameterName, 'Template to seed the config from')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;config;validate' {
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--strict', '--strict', [CompletionResultType]::ParameterName, 'Reject unknown fields and friendly aliases')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;config;doctor' {
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--network', '--network', [CompletionResultType]::ParameterName, 'Run network checks')
            [CompletionResult]::new('--service', '--service', [CompletionResultType]::ParameterName, 'Run service-manager checks')
            [CompletionResult]::new('--secrets', '--secrets', [CompletionResultType]::ParameterName, 'Run secret backend checks')
            [CompletionResult]::new('--dns', '--dns', [CompletionResultType]::ParameterName, 'Run DNS checks')
            [CompletionResult]::new('--observability', '--observability', [CompletionResultType]::ParameterName, 'Run observability sink checks')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;config;render' {
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--redacted', '--redacted', [CompletionResultType]::ParameterName, 'Redact secret values')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Render as JSON instead of canonical TOML')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;config;diff' {
            [CompletionResult]::new('--from', '--from', [CompletionResultType]::ParameterName, 'Base config')
            [CompletionResult]::new('--to', '--to', [CompletionResultType]::ParameterName, 'Candidate config')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;config;migrate' {
            [CompletionResult]::new('--from-version', '--from-version', [CompletionResultType]::ParameterName, 'Source schema version')
            [CompletionResult]::new('--to-version', '--to-version', [CompletionResultType]::ParameterName, 'Target schema version')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;config;reload' {
            [CompletionResult]::new('--mode', '--mode', [CompletionResultType]::ParameterName, 'Reload mechanism to use')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--wait', '--wait', [CompletionResultType]::ParameterName, 'Wait for reload to complete')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;config;pull' {
            [CompletionResult]::new('--url', '--url', [CompletionResultType]::ParameterName, 'HTTPS URL to fetch')
            [CompletionResult]::new('--fingerprint', '--fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Output path')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--cache', '--cache', [CompletionResultType]::ParameterName, 'Update the local atomic cache')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;config;trust' {
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('add-url', 'add-url', [CompletionResultType]::ParameterValue, 'Add a pinned remote-config URL')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'spt;config;trust;add-url' {
            [CompletionResult]::new('--url', '--url', [CompletionResultType]::ParameterName, 'HTTPS URL to trust')
            [CompletionResult]::new('--fingerprint', '--fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;config;trust;help' {
            [CompletionResult]::new('add-url', 'add-url', [CompletionResultType]::ParameterValue, 'Add a pinned remote-config URL')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'spt;config;trust;help;add-url' {
            break
        }
        'spt;config;trust;help;help' {
            break
        }
        'spt;config;encrypt' {
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Output path (default: `<IN>.sealed`)')
            [CompletionResult]::new('--passphrase-from', '--passphrase-from', [CompletionResultType]::ParameterName, 'Read passphrase from a secret reference (e.g. `secret://env/SPT_PP`)')
            [CompletionResult]::new('--recipient', '--recipient', [CompletionResultType]::ParameterName, 'One or more X25519 recipient public keys (base64)')
            [CompletionResult]::new('--psk-from', '--psk-from', [CompletionResultType]::ParameterName, 'Seal under a raw 32-byte PSK resolved from a secret reference (`secret://ns/name`, `env:NAME`, or `file:PATH`). The bytes may be raw-32, base64, or hex')
            [CompletionResult]::new('--vault-path', '--vault-path', [CompletionResultType]::ParameterName, 'Vault directory or `vault.spt` file used for `secret://` passphrases and `--use-vault-master`')
            [CompletionResult]::new('--vault-passphrase-from', '--vault-passphrase-from', [CompletionResultType]::ParameterName, 'Unlock the vault with a passphrase source instead of the keychain (`stdin`, `env:NAME`, `file:<path>`, or `file:///path`)')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--use-vault-master', '--use-vault-master', [CompletionResultType]::ParameterName, 'Use the keychain-resident vault master key')
            [CompletionResult]::new('--force', '--force', [CompletionResultType]::ParameterName, 'Overwrite an existing output file')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;config;decrypt' {
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Output path. If unset, write the cleartext to stdout')
            [CompletionResult]::new('--passphrase-from', '--passphrase-from', [CompletionResultType]::ParameterName, 'Read passphrase from a secret reference')
            [CompletionResult]::new('--recipient-key', '--recipient-key', [CompletionResultType]::ParameterName, 'Path to an X25519 private-key file (32 raw bytes or base64 line)')
            [CompletionResult]::new('--psk-from', '--psk-from', [CompletionResultType]::ParameterName, 'Unseal under a raw 32-byte PSK resolved from a secret reference (`secret://ns/name`, `env:NAME`, or `file:PATH`). The bytes may be raw-32, base64, or hex')
            [CompletionResult]::new('--vault-path', '--vault-path', [CompletionResultType]::ParameterName, 'Vault directory or `vault.spt` file used for `secret://` passphrases and vault-master envelopes')
            [CompletionResult]::new('--vault-passphrase-from', '--vault-passphrase-from', [CompletionResultType]::ParameterName, 'Unlock the vault with a passphrase source instead of the keychain')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;config;edit' {
            [CompletionResult]::new('--passphrase-from', '--passphrase-from', [CompletionResultType]::ParameterName, 'Read passphrase from a secret reference')
            [CompletionResult]::new('--vault-path', '--vault-path', [CompletionResultType]::ParameterName, 'Vault directory or `vault.spt` file used for `secret://` passphrases and vault-master envelopes')
            [CompletionResult]::new('--vault-passphrase-from', '--vault-passphrase-from', [CompletionResultType]::ParameterName, 'Unlock the vault with a passphrase source instead of the keychain')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;config;crypt' {
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('rotate', 'rotate', [CompletionResultType]::ParameterValue, 'Re-seal a sealed config under a new key')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'spt;config;crypt;rotate' {
            [CompletionResult]::new('--new-passphrase-from', '--new-passphrase-from', [CompletionResultType]::ParameterName, 'New passphrase, read from a secret reference')
            [CompletionResult]::new('--new-recipient', '--new-recipient', [CompletionResultType]::ParameterName, 'New X25519 recipient public keys (base64)')
            [CompletionResult]::new('--old-psk-from', '--old-psk-from', [CompletionResultType]::ParameterName, 'Unseal the *current* envelope using a raw 32-byte PSK resolved from a secret reference (when the existing config was sealed under a PSK)')
            [CompletionResult]::new('--new-psk-from', '--new-psk-from', [CompletionResultType]::ParameterName, 'Re-seal under a raw 32-byte PSK resolved from a secret reference (`secret://ns/name`, `env:NAME`, or `file:PATH`). The bytes may be raw-32, base64, or hex')
            [CompletionResult]::new('--vault-path', '--vault-path', [CompletionResultType]::ParameterName, 'Vault directory or `vault.spt` file used for `secret://` passphrases and vault-master envelopes')
            [CompletionResult]::new('--vault-passphrase-from', '--vault-passphrase-from', [CompletionResultType]::ParameterName, 'Unlock the vault with a passphrase source instead of the keychain')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;config;crypt;help' {
            [CompletionResult]::new('rotate', 'rotate', [CompletionResultType]::ParameterValue, 'Re-seal a sealed config under a new key')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'spt;config;crypt;help;rotate' {
            break
        }
        'spt;config;crypt;help;help' {
            break
        }
        'spt;config;gen-key' {
            [CompletionResult]::new('--type', '--type', [CompletionResultType]::ParameterName, 'Key kind to mint')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Output path. For `x25519` the private scalar is written here and the public key to `<PATH>.pub`. For `psk` the key is written here, or to stdout when omitted')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--hex', '--hex', [CompletionResultType]::ParameterName, 'Encode the PSK as hex instead of base64 (psk only)')
            [CompletionResult]::new('--force', '--force', [CompletionResultType]::ParameterName, 'Overwrite existing output file(s)')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;config;help' {
            [CompletionResult]::new('init', 'init', [CompletionResultType]::ParameterValue, 'Initialize a new config file from a template')
            [CompletionResult]::new('validate', 'validate', [CompletionResultType]::ParameterValue, 'Validate config syntax, schema, and obvious mistakes')
            [CompletionResult]::new('doctor', 'doctor', [CompletionResultType]::ParameterValue, 'Run environment checks against the loaded config')
            [CompletionResult]::new('render', 'render', [CompletionResultType]::ParameterValue, 'Render the canonical (optionally redacted) config')
            [CompletionResult]::new('diff', 'diff', [CompletionResultType]::ParameterValue, 'Diff two config files')
            [CompletionResult]::new('migrate', 'migrate', [CompletionResultType]::ParameterValue, 'Migrate a config between schema versions')
            [CompletionResult]::new('reload', 'reload', [CompletionResultType]::ParameterValue, 'Reload the running service''s config')
            [CompletionResult]::new('pull', 'pull', [CompletionResultType]::ParameterValue, 'Pull a remote config over HTTPS with pinning')
            [CompletionResult]::new('trust', 'trust', [CompletionResultType]::ParameterValue, 'Manage remote-config trust pins')
            [CompletionResult]::new('encrypt', 'encrypt', [CompletionResultType]::ParameterValue, 'Encrypt a plaintext config to a sealed `SPTENC1` envelope')
            [CompletionResult]::new('decrypt', 'decrypt', [CompletionResultType]::ParameterValue, 'Decrypt a sealed `SPTENC1` envelope back to plaintext TOML')
            [CompletionResult]::new('edit', 'edit', [CompletionResultType]::ParameterValue, 'Open a sealed config in `$EDITOR`; re-seal on save')
            [CompletionResult]::new('crypt', 'crypt', [CompletionResultType]::ParameterValue, 'Re-seal a sealed config under a new key (key rotation)')
            [CompletionResult]::new('gen-key', 'gen-key', [CompletionResultType]::ParameterValue, 'Generate a config-encryption key (X25519 keypair or raw PSK)')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'spt;config;help;init' {
            break
        }
        'spt;config;help;validate' {
            break
        }
        'spt;config;help;doctor' {
            break
        }
        'spt;config;help;render' {
            break
        }
        'spt;config;help;diff' {
            break
        }
        'spt;config;help;migrate' {
            break
        }
        'spt;config;help;reload' {
            break
        }
        'spt;config;help;pull' {
            break
        }
        'spt;config;help;trust' {
            [CompletionResult]::new('add-url', 'add-url', [CompletionResultType]::ParameterValue, 'Add a pinned remote-config URL')
            break
        }
        'spt;config;help;trust;add-url' {
            break
        }
        'spt;config;help;encrypt' {
            break
        }
        'spt;config;help;decrypt' {
            break
        }
        'spt;config;help;edit' {
            break
        }
        'spt;config;help;crypt' {
            [CompletionResult]::new('rotate', 'rotate', [CompletionResultType]::ParameterValue, 'Re-seal a sealed config under a new key')
            break
        }
        'spt;config;help;crypt;rotate' {
            break
        }
        'spt;config;help;gen-key' {
            break
        }
        'spt;config;help;help' {
            break
        }
        'spt;profile' {
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('list', 'list', [CompletionResultType]::ParameterValue, 'List configured profiles')
            [CompletionResult]::new('show', 'show', [CompletionResultType]::ParameterValue, 'Show the resolved profile (optionally redacted)')
            [CompletionResult]::new('add', 'add', [CompletionResultType]::ParameterValue, 'Add a new profile')
            [CompletionResult]::new('configure', 'configure', [CompletionResultType]::ParameterValue, 'Interactive TUI configurator')
            [CompletionResult]::new('set', 'set', [CompletionResultType]::ParameterValue, 'Set one or more `key=value` overrides')
            [CompletionResult]::new('enable', 'enable', [CompletionResultType]::ParameterValue, 'Enable a profile')
            [CompletionResult]::new('disable', 'disable', [CompletionResultType]::ParameterValue, 'Disable a profile')
            [CompletionResult]::new('remove', 'remove', [CompletionResultType]::ParameterValue, 'Remove a profile')
            [CompletionResult]::new('test', 'test', [CompletionResultType]::ParameterValue, 'Run targeted profile tests')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'spt;profile;list' {
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'JSON output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;profile;show' {
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--redacted', '--redacted', [CompletionResultType]::ParameterName, 'Redact secret fields')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'JSON output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;profile;add' {
            [CompletionResult]::new('--protocol', '--protocol', [CompletionResultType]::ParameterName, 'Protocol selector')
            [CompletionResult]::new('--host', '--host', [CompletionResultType]::ParameterName, 'Remote host')
            [CompletionResult]::new('--user', '--user', [CompletionResultType]::ParameterName, 'SSH user')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;profile;configure' {
            [CompletionResult]::new('--name', '--name', [CompletionResultType]::ParameterName, 'Profile name (created if missing)')
            [CompletionResult]::new('--from-template', '--from-template', [CompletionResultType]::ParameterName, 'Seed from a built-in template')
            [CompletionResult]::new('--field', '--field', [CompletionResultType]::ParameterName, 'One or more `KEY=VALUE` field overrides applied non-interactively. Implies `--no-tui` semantics for `--field` updates. Repeatable')
            [CompletionResult]::new('--from', '--from', [CompletionResultType]::ParameterName, 'Apply a TOML patch from `<file.toml>` to the profile (non-interactive). The file may contain a single `[profile]` table or a bare key/value document; both shapes are merged into the addressed `[[profiles]]` entry')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--tui', '--tui', [CompletionResultType]::ParameterName, 'Force the TUI wizard')
            [CompletionResult]::new('--no-tui', '--no-tui', [CompletionResultType]::ParameterName, 'Disable the TUI wizard (non-interactive)')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;profile;set' {
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;profile;enable' {
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;profile;disable' {
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;profile;remove' {
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;profile;test' {
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--connect-only', '--connect-only', [CompletionResultType]::ParameterName, 'Only test connect')
            [CompletionResult]::new('--bind-only', '--bind-only', [CompletionResultType]::ParameterName, 'Only test bind')
            [CompletionResult]::new('--auth-only', '--auth-only', [CompletionResultType]::ParameterName, 'Only test auth')
            [CompletionResult]::new('--trust-only', '--trust-only', [CompletionResultType]::ParameterName, 'Only test trust (host-key/TLS pin)')
            [CompletionResult]::new('--dns-only', '--dns-only', [CompletionResultType]::ParameterName, 'Only test DNS')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;profile;help' {
            [CompletionResult]::new('list', 'list', [CompletionResultType]::ParameterValue, 'List configured profiles')
            [CompletionResult]::new('show', 'show', [CompletionResultType]::ParameterValue, 'Show the resolved profile (optionally redacted)')
            [CompletionResult]::new('add', 'add', [CompletionResultType]::ParameterValue, 'Add a new profile')
            [CompletionResult]::new('configure', 'configure', [CompletionResultType]::ParameterValue, 'Interactive TUI configurator')
            [CompletionResult]::new('set', 'set', [CompletionResultType]::ParameterValue, 'Set one or more `key=value` overrides')
            [CompletionResult]::new('enable', 'enable', [CompletionResultType]::ParameterValue, 'Enable a profile')
            [CompletionResult]::new('disable', 'disable', [CompletionResultType]::ParameterValue, 'Disable a profile')
            [CompletionResult]::new('remove', 'remove', [CompletionResultType]::ParameterValue, 'Remove a profile')
            [CompletionResult]::new('test', 'test', [CompletionResultType]::ParameterValue, 'Run targeted profile tests')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'spt;profile;help;list' {
            break
        }
        'spt;profile;help;show' {
            break
        }
        'spt;profile;help;add' {
            break
        }
        'spt;profile;help;configure' {
            break
        }
        'spt;profile;help;set' {
            break
        }
        'spt;profile;help;enable' {
            break
        }
        'spt;profile;help;disable' {
            break
        }
        'spt;profile;help;remove' {
            break
        }
        'spt;profile;help;test' {
            break
        }
        'spt;profile;help;help' {
            break
        }
        'spt;forward' {
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('list', 'list', [CompletionResultType]::ParameterValue, 'List configured forwards')
            [CompletionResult]::new('show', 'show', [CompletionResultType]::ParameterValue, 'Show a forward')
            [CompletionResult]::new('add', 'add', [CompletionResultType]::ParameterValue, 'Add a forward')
            [CompletionResult]::new('explain', 'explain', [CompletionResultType]::ParameterValue, 'Explain how a forward is plumbed')
            [CompletionResult]::new('test', 'test', [CompletionResultType]::ParameterValue, 'Run targeted forward tests')
            [CompletionResult]::new('throttle', 'throttle', [CompletionResultType]::ParameterValue, 'Update throttle/limit knobs at runtime')
            [CompletionResult]::new('remove', 'remove', [CompletionResultType]::ParameterValue, 'Remove a forward')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'spt;forward;list' {
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Filter by profile name')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'JSON output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;forward;show' {
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--friendly', '--friendly', [CompletionResultType]::ParameterName, 'Friendly textual layout')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'JSON output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;forward;add' {
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('local', 'local', [CompletionResultType]::ParameterValue, 'Local forward (`-L`)')
            [CompletionResult]::new('remote', 'remote', [CompletionResultType]::ParameterValue, 'Remote forward (`-R`)')
            [CompletionResult]::new('dynamic', 'dynamic', [CompletionResultType]::ParameterValue, 'Dynamic SOCKS4/SOCKS4A/SOCKS5/HTTP CONNECT proxy (`-D`)')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'spt;forward;add;local' {
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Owning profile name')
            [CompletionResult]::new('--listen', '--listen', [CompletionResultType]::ParameterName, 'Listen address (`host:port` or `[::1]:port`)')
            [CompletionResult]::new('--to', '--to', [CompletionResultType]::ParameterName, 'Target address forwarded to')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--tcp', '--tcp', [CompletionResultType]::ParameterName, 'TCP forward (default)')
            [CompletionResult]::new('--udp', '--udp', [CompletionResultType]::ParameterName, 'UDP forward (SSH3 only)')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;forward;add;remote' {
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Owning profile name')
            [CompletionResult]::new('--listen', '--listen', [CompletionResultType]::ParameterName, 'Listen address (`host:port` or `[::1]:port`)')
            [CompletionResult]::new('--to', '--to', [CompletionResultType]::ParameterName, 'Target address forwarded to')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--tcp', '--tcp', [CompletionResultType]::ParameterName, 'TCP forward (default)')
            [CompletionResult]::new('--udp', '--udp', [CompletionResultType]::ParameterName, 'UDP forward (SSH3 only)')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;forward;add;dynamic' {
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Owning profile name')
            [CompletionResult]::new('--listen', '--listen', [CompletionResultType]::ParameterName, 'Local proxy listen address (`host:port` or `[::1]:port`)')
            [CompletionResult]::new('--connections', '--connections', [CompletionResultType]::ParameterName, 'Per-forward concurrent connection limit')
            [CompletionResult]::new('--proxy-protocol', '--proxy-protocol', [CompletionResultType]::ParameterName, 'Proxy protocol to accept. Repeat to select a subset; default accepts all')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;forward;add;help' {
            [CompletionResult]::new('local', 'local', [CompletionResultType]::ParameterValue, 'Local forward (`-L`)')
            [CompletionResult]::new('remote', 'remote', [CompletionResultType]::ParameterValue, 'Remote forward (`-R`)')
            [CompletionResult]::new('dynamic', 'dynamic', [CompletionResultType]::ParameterValue, 'Dynamic SOCKS4/SOCKS4A/SOCKS5/HTTP CONNECT proxy (`-D`)')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'spt;forward;add;help;local' {
            break
        }
        'spt;forward;add;help;remote' {
            break
        }
        'spt;forward;add;help;dynamic' {
            break
        }
        'spt;forward;add;help;help' {
            break
        }
        'spt;forward;explain' {
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;forward;test' {
            [CompletionResult]::new('--dns-name', '--dns-name', [CompletionResultType]::ParameterName, 'Probe with a DNS resolution')
            [CompletionResult]::new('--timeout', '--timeout', [CompletionResultType]::ParameterName, 'Timeout for the connect probe (e.g. `10s`)')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--connect', '--connect', [CompletionResultType]::ParameterName, 'Probe with a TCP connect')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;forward;throttle' {
            [CompletionResult]::new('--in', '--in', [CompletionResultType]::ParameterName, 'Inbound rate (e.g. `10MiB/s`)')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Outbound rate')
            [CompletionResult]::new('--connections', '--connections', [CompletionResultType]::ParameterName, 'Per-forward connection limit')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;forward;remove' {
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;forward;help' {
            [CompletionResult]::new('list', 'list', [CompletionResultType]::ParameterValue, 'List configured forwards')
            [CompletionResult]::new('show', 'show', [CompletionResultType]::ParameterValue, 'Show a forward')
            [CompletionResult]::new('add', 'add', [CompletionResultType]::ParameterValue, 'Add a forward')
            [CompletionResult]::new('explain', 'explain', [CompletionResultType]::ParameterValue, 'Explain how a forward is plumbed')
            [CompletionResult]::new('test', 'test', [CompletionResultType]::ParameterValue, 'Run targeted forward tests')
            [CompletionResult]::new('throttle', 'throttle', [CompletionResultType]::ParameterValue, 'Update throttle/limit knobs at runtime')
            [CompletionResult]::new('remove', 'remove', [CompletionResultType]::ParameterValue, 'Remove a forward')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'spt;forward;help;list' {
            break
        }
        'spt;forward;help;show' {
            break
        }
        'spt;forward;help;add' {
            [CompletionResult]::new('local', 'local', [CompletionResultType]::ParameterValue, 'Local forward (`-L`)')
            [CompletionResult]::new('remote', 'remote', [CompletionResultType]::ParameterValue, 'Remote forward (`-R`)')
            [CompletionResult]::new('dynamic', 'dynamic', [CompletionResultType]::ParameterValue, 'Dynamic SOCKS4/SOCKS4A/SOCKS5/HTTP CONNECT proxy (`-D`)')
            break
        }
        'spt;forward;help;add;local' {
            break
        }
        'spt;forward;help;add;remote' {
            break
        }
        'spt;forward;help;add;dynamic' {
            break
        }
        'spt;forward;help;explain' {
            break
        }
        'spt;forward;help;test' {
            break
        }
        'spt;forward;help;throttle' {
            break
        }
        'spt;forward;help;remove' {
            break
        }
        'spt;forward;help;help' {
            break
        }
        'spt;tunnel' {
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('run', 'run', [CompletionResultType]::ParameterValue, 'Run configured tunnels')
            [CompletionResult]::new('status', 'status', [CompletionResultType]::ParameterValue, 'Show overall tunnel status')
            [CompletionResult]::new('stats', 'stats', [CompletionResultType]::ParameterValue, 'Live or one-shot stats')
            [CompletionResult]::new('sessions', 'sessions', [CompletionResultType]::ParameterValue, 'List active sessions')
            [CompletionResult]::new('stop', 'stop', [CompletionResultType]::ParameterValue, 'Stop tunnels')
            [CompletionResult]::new('reload', 'reload', [CompletionResultType]::ParameterValue, 'Reload running configuration')
            [CompletionResult]::new('health', 'health', [CompletionResultType]::ParameterValue, 'Health summary')
            [CompletionResult]::new('failover', 'failover', [CompletionResultType]::ParameterValue, 'Manually trigger failover for a profile')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'spt;tunnel;run' {
            [CompletionResult]::new('--profiles', '--profiles', [CompletionResultType]::ParameterName, 'Comma-separated profile filter')
            [CompletionResult]::new('-J', '-J ', [CompletionResultType]::ParameterName, 'Proxy-jump chain `user@host[:port][,user@host…]`. When set, the chain is splatted into every selected profile''s `hops` table at startup (CLI values take precedence over profile-file hops). Mirrors the OpenSSH `-J` flag')
            [CompletionResult]::new('--jump', '--jump', [CompletionResultType]::ParameterName, 'Proxy-jump chain `user@host[:port][,user@host…]`. When set, the chain is splatted into every selected profile''s `hops` table at startup (CLI values take precedence over profile-file hops). Mirrors the OpenSSH `-J` flag')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--foreground', '--foreground', [CompletionResultType]::ParameterName, 'Run in the foreground')
            [CompletionResult]::new('--once', '--once', [CompletionResultType]::ParameterName, 'Start once and exit non-zero on startup failure')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;tunnel;status' {
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--watch', '--watch', [CompletionResultType]::ParameterName, 'Continuously refresh')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'JSON output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;tunnel;stats' {
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Filter by profile')
            [CompletionResult]::new('--forward', '--forward', [CompletionResultType]::ParameterName, 'Filter by forward')
            [CompletionResult]::new('--interval', '--interval', [CompletionResultType]::ParameterName, 'Refresh interval')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'JSON output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;tunnel;sessions' {
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Filter by profile')
            [CompletionResult]::new('--forward', '--forward', [CompletionResultType]::ParameterName, 'Filter by forward')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'JSON output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;tunnel;stop' {
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Stop a specific profile (or all if absent)')
            [CompletionResult]::new('--grace', '--grace', [CompletionResultType]::ParameterName, 'Grace period for in-flight connections')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;tunnel;reload' {
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--wait', '--wait', [CompletionResultType]::ParameterName, 'Block until reload finishes')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;tunnel;health' {
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'JSON output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;tunnel;failover' {
            [CompletionResult]::new('--endpoint', '--endpoint', [CompletionResultType]::ParameterName, 'Override target endpoint as `host:port`. Synonym: `--to`')
            [CompletionResult]::new('--reason', '--reason', [CompletionResultType]::ParameterName, 'Free-form reason for audit')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;tunnel;help' {
            [CompletionResult]::new('run', 'run', [CompletionResultType]::ParameterValue, 'Run configured tunnels')
            [CompletionResult]::new('status', 'status', [CompletionResultType]::ParameterValue, 'Show overall tunnel status')
            [CompletionResult]::new('stats', 'stats', [CompletionResultType]::ParameterValue, 'Live or one-shot stats')
            [CompletionResult]::new('sessions', 'sessions', [CompletionResultType]::ParameterValue, 'List active sessions')
            [CompletionResult]::new('stop', 'stop', [CompletionResultType]::ParameterValue, 'Stop tunnels')
            [CompletionResult]::new('reload', 'reload', [CompletionResultType]::ParameterValue, 'Reload running configuration')
            [CompletionResult]::new('health', 'health', [CompletionResultType]::ParameterValue, 'Health summary')
            [CompletionResult]::new('failover', 'failover', [CompletionResultType]::ParameterValue, 'Manually trigger failover for a profile')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'spt;tunnel;help;run' {
            break
        }
        'spt;tunnel;help;status' {
            break
        }
        'spt;tunnel;help;stats' {
            break
        }
        'spt;tunnel;help;sessions' {
            break
        }
        'spt;tunnel;help;stop' {
            break
        }
        'spt;tunnel;help;reload' {
            break
        }
        'spt;tunnel;help;health' {
            break
        }
        'spt;tunnel;help;failover' {
            break
        }
        'spt;tunnel;help;help' {
            break
        }
        'spt;service' {
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('install', 'install', [CompletionResultType]::ParameterValue, 'Install a service for a config file')
            [CompletionResult]::new('uninstall', 'uninstall', [CompletionResultType]::ParameterValue, 'Uninstall a service')
            [CompletionResult]::new('start', 'start', [CompletionResultType]::ParameterValue, 'Start a service')
            [CompletionResult]::new('stop', 'stop', [CompletionResultType]::ParameterValue, 'Stop a service')
            [CompletionResult]::new('restart', 'restart', [CompletionResultType]::ParameterValue, 'Restart a service')
            [CompletionResult]::new('status', 'status', [CompletionResultType]::ParameterValue, 'Show service status')
            [CompletionResult]::new('render', 'render', [CompletionResultType]::ParameterValue, 'Render the would-be service unit')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'spt;service;install' {
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to the config file backing the service')
            [CompletionResult]::new('--name', '--name', [CompletionResultType]::ParameterName, 'Override the service unit name')
            [CompletionResult]::new('--run-as-user', '--run-as-user', [CompletionResultType]::ParameterName, 'Run the service as this user (system scope). Maps to systemd `User=` / OpenRC `command_user` / launchd `UserName` / SysV `DAEMON_USER`')
            [CompletionResult]::new('--run-as-group', '--run-as-group', [CompletionResultType]::ParameterName, 'Run the service as this group (system scope). Maps to systemd `Group=`')
            [CompletionResult]::new('--restart', '--restart', [CompletionResultType]::ParameterName, 'Restart policy for the generated unit')
            [CompletionResult]::new('--watchdog-sec', '--watchdog-sec', [CompletionResultType]::ParameterName, 'systemd `WatchdogSec=` interval in seconds. `0` disables the watchdog; omitted uses a sane default')
            [CompletionResult]::new('--stdout', '--stdout', [CompletionResultType]::ParameterName, 'Redirect service stdout to this path (launchd / SysV)')
            [CompletionResult]::new('--stderr', '--stderr', [CompletionResultType]::ParameterName, 'Redirect service stderr to this path (launchd / SysV)')
            [CompletionResult]::new('--env', '--env', [CompletionResultType]::ParameterName, 'Extra environment variable `KEY=VALUE` (repeatable)')
            [CompletionResult]::new('--description', '--description', [CompletionResultType]::ParameterName, 'Override the unit description')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--user', '--user', [CompletionResultType]::ParameterName, 'User-scoped service')
            [CompletionResult]::new('--system', '--system', [CompletionResultType]::ParameterName, 'System-scoped service')
            [CompletionResult]::new('--sd-notify', '--sd-notify', [CompletionResultType]::ParameterName, 'Enable systemd `Type=notify` (the daemon sends READY=1/STOPPING=1)')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;service;uninstall' {
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to the config file backing the service')
            [CompletionResult]::new('--name', '--name', [CompletionResultType]::ParameterName, 'Override the service unit name')
            [CompletionResult]::new('--run-as-user', '--run-as-user', [CompletionResultType]::ParameterName, 'Run the service as this user (system scope). Maps to systemd `User=` / OpenRC `command_user` / launchd `UserName` / SysV `DAEMON_USER`')
            [CompletionResult]::new('--run-as-group', '--run-as-group', [CompletionResultType]::ParameterName, 'Run the service as this group (system scope). Maps to systemd `Group=`')
            [CompletionResult]::new('--restart', '--restart', [CompletionResultType]::ParameterName, 'Restart policy for the generated unit')
            [CompletionResult]::new('--watchdog-sec', '--watchdog-sec', [CompletionResultType]::ParameterName, 'systemd `WatchdogSec=` interval in seconds. `0` disables the watchdog; omitted uses a sane default')
            [CompletionResult]::new('--stdout', '--stdout', [CompletionResultType]::ParameterName, 'Redirect service stdout to this path (launchd / SysV)')
            [CompletionResult]::new('--stderr', '--stderr', [CompletionResultType]::ParameterName, 'Redirect service stderr to this path (launchd / SysV)')
            [CompletionResult]::new('--env', '--env', [CompletionResultType]::ParameterName, 'Extra environment variable `KEY=VALUE` (repeatable)')
            [CompletionResult]::new('--description', '--description', [CompletionResultType]::ParameterName, 'Override the unit description')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--user', '--user', [CompletionResultType]::ParameterName, 'User-scoped service')
            [CompletionResult]::new('--system', '--system', [CompletionResultType]::ParameterName, 'System-scoped service')
            [CompletionResult]::new('--sd-notify', '--sd-notify', [CompletionResultType]::ParameterName, 'Enable systemd `Type=notify` (the daemon sends READY=1/STOPPING=1)')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;service;start' {
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to the config file backing the service')
            [CompletionResult]::new('--name', '--name', [CompletionResultType]::ParameterName, 'Override the service unit name')
            [CompletionResult]::new('--run-as-user', '--run-as-user', [CompletionResultType]::ParameterName, 'Run the service as this user (system scope). Maps to systemd `User=` / OpenRC `command_user` / launchd `UserName` / SysV `DAEMON_USER`')
            [CompletionResult]::new('--run-as-group', '--run-as-group', [CompletionResultType]::ParameterName, 'Run the service as this group (system scope). Maps to systemd `Group=`')
            [CompletionResult]::new('--restart', '--restart', [CompletionResultType]::ParameterName, 'Restart policy for the generated unit')
            [CompletionResult]::new('--watchdog-sec', '--watchdog-sec', [CompletionResultType]::ParameterName, 'systemd `WatchdogSec=` interval in seconds. `0` disables the watchdog; omitted uses a sane default')
            [CompletionResult]::new('--stdout', '--stdout', [CompletionResultType]::ParameterName, 'Redirect service stdout to this path (launchd / SysV)')
            [CompletionResult]::new('--stderr', '--stderr', [CompletionResultType]::ParameterName, 'Redirect service stderr to this path (launchd / SysV)')
            [CompletionResult]::new('--env', '--env', [CompletionResultType]::ParameterName, 'Extra environment variable `KEY=VALUE` (repeatable)')
            [CompletionResult]::new('--description', '--description', [CompletionResultType]::ParameterName, 'Override the unit description')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--user', '--user', [CompletionResultType]::ParameterName, 'User-scoped service')
            [CompletionResult]::new('--system', '--system', [CompletionResultType]::ParameterName, 'System-scoped service')
            [CompletionResult]::new('--sd-notify', '--sd-notify', [CompletionResultType]::ParameterName, 'Enable systemd `Type=notify` (the daemon sends READY=1/STOPPING=1)')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;service;stop' {
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to the config file backing the service')
            [CompletionResult]::new('--name', '--name', [CompletionResultType]::ParameterName, 'Override the service unit name')
            [CompletionResult]::new('--run-as-user', '--run-as-user', [CompletionResultType]::ParameterName, 'Run the service as this user (system scope). Maps to systemd `User=` / OpenRC `command_user` / launchd `UserName` / SysV `DAEMON_USER`')
            [CompletionResult]::new('--run-as-group', '--run-as-group', [CompletionResultType]::ParameterName, 'Run the service as this group (system scope). Maps to systemd `Group=`')
            [CompletionResult]::new('--restart', '--restart', [CompletionResultType]::ParameterName, 'Restart policy for the generated unit')
            [CompletionResult]::new('--watchdog-sec', '--watchdog-sec', [CompletionResultType]::ParameterName, 'systemd `WatchdogSec=` interval in seconds. `0` disables the watchdog; omitted uses a sane default')
            [CompletionResult]::new('--stdout', '--stdout', [CompletionResultType]::ParameterName, 'Redirect service stdout to this path (launchd / SysV)')
            [CompletionResult]::new('--stderr', '--stderr', [CompletionResultType]::ParameterName, 'Redirect service stderr to this path (launchd / SysV)')
            [CompletionResult]::new('--env', '--env', [CompletionResultType]::ParameterName, 'Extra environment variable `KEY=VALUE` (repeatable)')
            [CompletionResult]::new('--description', '--description', [CompletionResultType]::ParameterName, 'Override the unit description')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--user', '--user', [CompletionResultType]::ParameterName, 'User-scoped service')
            [CompletionResult]::new('--system', '--system', [CompletionResultType]::ParameterName, 'System-scoped service')
            [CompletionResult]::new('--sd-notify', '--sd-notify', [CompletionResultType]::ParameterName, 'Enable systemd `Type=notify` (the daemon sends READY=1/STOPPING=1)')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;service;restart' {
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to the config file backing the service')
            [CompletionResult]::new('--name', '--name', [CompletionResultType]::ParameterName, 'Override the service unit name')
            [CompletionResult]::new('--run-as-user', '--run-as-user', [CompletionResultType]::ParameterName, 'Run the service as this user (system scope). Maps to systemd `User=` / OpenRC `command_user` / launchd `UserName` / SysV `DAEMON_USER`')
            [CompletionResult]::new('--run-as-group', '--run-as-group', [CompletionResultType]::ParameterName, 'Run the service as this group (system scope). Maps to systemd `Group=`')
            [CompletionResult]::new('--restart', '--restart', [CompletionResultType]::ParameterName, 'Restart policy for the generated unit')
            [CompletionResult]::new('--watchdog-sec', '--watchdog-sec', [CompletionResultType]::ParameterName, 'systemd `WatchdogSec=` interval in seconds. `0` disables the watchdog; omitted uses a sane default')
            [CompletionResult]::new('--stdout', '--stdout', [CompletionResultType]::ParameterName, 'Redirect service stdout to this path (launchd / SysV)')
            [CompletionResult]::new('--stderr', '--stderr', [CompletionResultType]::ParameterName, 'Redirect service stderr to this path (launchd / SysV)')
            [CompletionResult]::new('--env', '--env', [CompletionResultType]::ParameterName, 'Extra environment variable `KEY=VALUE` (repeatable)')
            [CompletionResult]::new('--description', '--description', [CompletionResultType]::ParameterName, 'Override the unit description')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--user', '--user', [CompletionResultType]::ParameterName, 'User-scoped service')
            [CompletionResult]::new('--system', '--system', [CompletionResultType]::ParameterName, 'System-scoped service')
            [CompletionResult]::new('--sd-notify', '--sd-notify', [CompletionResultType]::ParameterName, 'Enable systemd `Type=notify` (the daemon sends READY=1/STOPPING=1)')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;service;status' {
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to the config file')
            [CompletionResult]::new('--name', '--name', [CompletionResultType]::ParameterName, 'Override the service unit name')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--user', '--user', [CompletionResultType]::ParameterName, 'User-scoped service')
            [CompletionResult]::new('--system', '--system', [CompletionResultType]::ParameterName, 'System-scoped service')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'JSON output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;service;render' {
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to the config file')
            [CompletionResult]::new('--name', '--name', [CompletionResultType]::ParameterName, 'Override the service unit name')
            [CompletionResult]::new('--run-as-user', '--run-as-user', [CompletionResultType]::ParameterName, 'Run the service as this user (system scope). Maps to systemd `User=` / OpenRC `command_user` / launchd `UserName` / SysV `DAEMON_USER`')
            [CompletionResult]::new('--run-as-group', '--run-as-group', [CompletionResultType]::ParameterName, 'Run the service as this group (system scope). Maps to systemd `Group=`')
            [CompletionResult]::new('--restart', '--restart', [CompletionResultType]::ParameterName, 'Restart policy for the generated unit')
            [CompletionResult]::new('--watchdog-sec', '--watchdog-sec', [CompletionResultType]::ParameterName, 'systemd `WatchdogSec=` interval in seconds. `0` disables the watchdog; omitted uses a sane default')
            [CompletionResult]::new('--stdout', '--stdout', [CompletionResultType]::ParameterName, 'Redirect service stdout to this path (launchd / SysV)')
            [CompletionResult]::new('--stderr', '--stderr', [CompletionResultType]::ParameterName, 'Redirect service stderr to this path (launchd / SysV)')
            [CompletionResult]::new('--env', '--env', [CompletionResultType]::ParameterName, 'Extra environment variable `KEY=VALUE` (repeatable)')
            [CompletionResult]::new('--description', '--description', [CompletionResultType]::ParameterName, 'Override the unit description')
            [CompletionResult]::new('--format', '--format', [CompletionResultType]::ParameterName, 'Output format')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--user', '--user', [CompletionResultType]::ParameterName, 'User-scoped service')
            [CompletionResult]::new('--system', '--system', [CompletionResultType]::ParameterName, 'System-scoped service')
            [CompletionResult]::new('--sd-notify', '--sd-notify', [CompletionResultType]::ParameterName, 'Enable systemd `Type=notify` (the daemon sends READY=1/STOPPING=1)')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;service;help' {
            [CompletionResult]::new('install', 'install', [CompletionResultType]::ParameterValue, 'Install a service for a config file')
            [CompletionResult]::new('uninstall', 'uninstall', [CompletionResultType]::ParameterValue, 'Uninstall a service')
            [CompletionResult]::new('start', 'start', [CompletionResultType]::ParameterValue, 'Start a service')
            [CompletionResult]::new('stop', 'stop', [CompletionResultType]::ParameterValue, 'Stop a service')
            [CompletionResult]::new('restart', 'restart', [CompletionResultType]::ParameterValue, 'Restart a service')
            [CompletionResult]::new('status', 'status', [CompletionResultType]::ParameterValue, 'Show service status')
            [CompletionResult]::new('render', 'render', [CompletionResultType]::ParameterValue, 'Render the would-be service unit')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'spt;service;help;install' {
            break
        }
        'spt;service;help;uninstall' {
            break
        }
        'spt;service;help;start' {
            break
        }
        'spt;service;help;stop' {
            break
        }
        'spt;service;help;restart' {
            break
        }
        'spt;service;help;status' {
            break
        }
        'spt;service;help;render' {
            break
        }
        'spt;service;help;help' {
            break
        }
        'spt;key' {
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('generate', 'generate', [CompletionResultType]::ParameterValue, 'Generate a new keypair')
            [CompletionResult]::new('inspect', 'inspect', [CompletionResultType]::ParameterValue, 'Inspect a key file')
            [CompletionResult]::new('public', 'public', [CompletionResultType]::ParameterValue, 'Print a public key (optionally to a file)')
            [CompletionResult]::new('change-passphrase', 'change-passphrase', [CompletionResultType]::ParameterValue, 'Change the passphrase on a private key')
            [CompletionResult]::new('sign-cert', 'sign-cert', [CompletionResultType]::ParameterValue, 'Sign an OpenSSH certificate')
            [CompletionResult]::new('verify-cert', 'verify-cert', [CompletionResultType]::ParameterValue, 'Verify an OpenSSH certificate')
            [CompletionResult]::new('install-public', 'install-public', [CompletionResultType]::ParameterValue, 'Install a public key on a remote host')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'spt;key;generate' {
            [CompletionResult]::new('--type', '--type', [CompletionResultType]::ParameterName, 'Algorithm')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Output path (private key; public is `<path>.pub`)')
            [CompletionResult]::new('--bits', '--bits', [CompletionResultType]::ParameterName, 'RSA bit length (only meaningful for `--type rsa`)')
            [CompletionResult]::new('--comment', '--comment', [CompletionResultType]::ParameterName, 'Optional comment to embed')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--encrypt', '--encrypt', [CompletionResultType]::ParameterName, 'Encrypt the private key at rest with a passphrase')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;key;inspect' {
            [CompletionResult]::new('--fingerprint', '--fingerprint', [CompletionResultType]::ParameterName, 'Fingerprint hash to print')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'JSON output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;key;public' {
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Output file (otherwise stdout)')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;key;change-passphrase' {
            [CompletionResult]::new('--new-passphrase-from', '--new-passphrase-from', [CompletionResultType]::ParameterName, 'Read the new passphrase from a value source (`stdin`, `file:<path>`, or `env:<NAME>`)')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;key;sign-cert' {
            [CompletionResult]::new('--ca-key', '--ca-key', [CompletionResultType]::ParameterName, 'Path to the signing CA private key')
            [CompletionResult]::new('--public-key', '--public-key', [CompletionResultType]::ParameterName, 'Public key to sign')
            [CompletionResult]::new('--principal', '--principal', [CompletionResultType]::ParameterName, 'One or more principal names (repeat or comma-separated)')
            [CompletionResult]::new('--validity', '--validity', [CompletionResultType]::ParameterName, 'Certificate validity duration (e.g. `1d`, `52w`)')
            [CompletionResult]::new('--serial', '--serial', [CompletionResultType]::ParameterName, 'Serial number to embed')
            [CompletionResult]::new('--cert-type', '--cert-type', [CompletionResultType]::ParameterName, 'Certificate type (user/host)')
            [CompletionResult]::new('--key-id', '--key-id', [CompletionResultType]::ParameterName, 'Free-form key id to embed in the certificate')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Output certificate path')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;key;verify-cert' {
            [CompletionResult]::new('--trusted-cas', '--trusted-cas', [CompletionResultType]::ParameterName, 'File containing trusted CA public keys (one per line)')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;key;install-public' {
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Owning profile')
            [CompletionResult]::new('--target', '--target', [CompletionResultType]::ParameterName, 'Override target as `user@host[:port]`')
            [CompletionResult]::new('--key', '--key', [CompletionResultType]::ParameterName, 'Public key path')
            [CompletionResult]::new('--remote-command', '--remote-command', [CompletionResultType]::ParameterName, 'Override the remote install command')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;key;help' {
            [CompletionResult]::new('generate', 'generate', [CompletionResultType]::ParameterValue, 'Generate a new keypair')
            [CompletionResult]::new('inspect', 'inspect', [CompletionResultType]::ParameterValue, 'Inspect a key file')
            [CompletionResult]::new('public', 'public', [CompletionResultType]::ParameterValue, 'Print a public key (optionally to a file)')
            [CompletionResult]::new('change-passphrase', 'change-passphrase', [CompletionResultType]::ParameterValue, 'Change the passphrase on a private key')
            [CompletionResult]::new('sign-cert', 'sign-cert', [CompletionResultType]::ParameterValue, 'Sign an OpenSSH certificate')
            [CompletionResult]::new('verify-cert', 'verify-cert', [CompletionResultType]::ParameterValue, 'Verify an OpenSSH certificate')
            [CompletionResult]::new('install-public', 'install-public', [CompletionResultType]::ParameterValue, 'Install a public key on a remote host')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'spt;key;help;generate' {
            break
        }
        'spt;key;help;inspect' {
            break
        }
        'spt;key;help;public' {
            break
        }
        'spt;key;help;change-passphrase' {
            break
        }
        'spt;key;help;sign-cert' {
            break
        }
        'spt;key;help;verify-cert' {
            break
        }
        'spt;key;help;install-public' {
            break
        }
        'spt;key;help;help' {
            break
        }
        'spt;secret' {
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('store', 'store', [CompletionResultType]::ParameterValue, 'Initialize the secret store')
            [CompletionResult]::new('set', 'set', [CompletionResultType]::ParameterValue, 'Set a secret')
            [CompletionResult]::new('get', 'get', [CompletionResultType]::ParameterValue, 'Get a secret (redacted unless `--reveal`)')
            [CompletionResult]::new('list', 'list', [CompletionResultType]::ParameterValue, 'List known secret names')
            [CompletionResult]::new('rotate', 'rotate', [CompletionResultType]::ParameterValue, 'Rotate a secret')
            [CompletionResult]::new('remove', 'remove', [CompletionResultType]::ParameterValue, 'Remove a secret')
            [CompletionResult]::new('doctor', 'doctor', [CompletionResultType]::ParameterValue, 'Run secret backend health checks')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'spt;secret;store' {
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('init', 'init', [CompletionResultType]::ParameterValue, 'Initialize a secret store')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'spt;secret;store;init' {
            [CompletionResult]::new('--backend', '--backend', [CompletionResultType]::ParameterName, 'Preferred backend')
            [CompletionResult]::new('--vault-path', '--vault-path', [CompletionResultType]::ParameterName, 'Vault directory or `vault.spt` file location')
            [CompletionResult]::new('--passphrase-from', '--passphrase-from', [CompletionResultType]::ParameterName, 'Read the vault passphrase from a value source (`stdin`, `file:<path>`, `env:<NAME>`)')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;secret;store;help' {
            [CompletionResult]::new('init', 'init', [CompletionResultType]::ParameterValue, 'Initialize a secret store')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'spt;secret;store;help;init' {
            break
        }
        'spt;secret;store;help;help' {
            break
        }
        'spt;secret;set' {
            [CompletionResult]::new('--from-env', '--from-env', [CompletionResultType]::ParameterName, 'Read from an environment variable')
            [CompletionResult]::new('--from-file', '--from-file', [CompletionResultType]::ParameterName, 'Read from a file (mode-checked)')
            [CompletionResult]::new('--vault-path', '--vault-path', [CompletionResultType]::ParameterName, 'Vault directory or `vault.spt` file when writing to the local vault')
            [CompletionResult]::new('--passphrase-from', '--passphrase-from', [CompletionResultType]::ParameterName, 'Unlock the vault with a passphrase source (`stdin`, `env:NAME`, `file:<path>`, or `file:///path`)')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--prompt', '--prompt', [CompletionResultType]::ParameterName, 'Read from a TTY prompt')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;secret;get' {
            [CompletionResult]::new('--vault-path', '--vault-path', [CompletionResultType]::ParameterName, 'Vault directory or `vault.spt` file when reading from the local vault')
            [CompletionResult]::new('--passphrase-from', '--passphrase-from', [CompletionResultType]::ParameterName, 'Unlock the vault with a passphrase source')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--reveal', '--reveal', [CompletionResultType]::ParameterName, 'Print the plaintext value')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;secret;list' {
            [CompletionResult]::new('--namespace', '--namespace', [CompletionResultType]::ParameterName, 'Restrict to a single namespace')
            [CompletionResult]::new('--vault-path', '--vault-path', [CompletionResultType]::ParameterName, 'Vault directory or `vault.spt` file location')
            [CompletionResult]::new('--passphrase-from', '--passphrase-from', [CompletionResultType]::ParameterName, 'Read the vault passphrase from a value source')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'JSON output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;secret;rotate' {
            [CompletionResult]::new('--new-value-from', '--new-value-from', [CompletionResultType]::ParameterName, 'New value source for `rotate` (`stdin`, `file:<path>`, `env:<NAME>`)')
            [CompletionResult]::new('--vault-path', '--vault-path', [CompletionResultType]::ParameterName, 'Vault directory or `vault.spt` file location')
            [CompletionResult]::new('--passphrase-from', '--passphrase-from', [CompletionResultType]::ParameterName, 'Read the vault passphrase from a value source')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;secret;remove' {
            [CompletionResult]::new('--new-value-from', '--new-value-from', [CompletionResultType]::ParameterName, 'New value source for `rotate` (`stdin`, `file:<path>`, `env:<NAME>`)')
            [CompletionResult]::new('--vault-path', '--vault-path', [CompletionResultType]::ParameterName, 'Vault directory or `vault.spt` file location')
            [CompletionResult]::new('--passphrase-from', '--passphrase-from', [CompletionResultType]::ParameterName, 'Read the vault passphrase from a value source')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;secret;doctor' {
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;secret;help' {
            [CompletionResult]::new('store', 'store', [CompletionResultType]::ParameterValue, 'Initialize the secret store')
            [CompletionResult]::new('set', 'set', [CompletionResultType]::ParameterValue, 'Set a secret')
            [CompletionResult]::new('get', 'get', [CompletionResultType]::ParameterValue, 'Get a secret (redacted unless `--reveal`)')
            [CompletionResult]::new('list', 'list', [CompletionResultType]::ParameterValue, 'List known secret names')
            [CompletionResult]::new('rotate', 'rotate', [CompletionResultType]::ParameterValue, 'Rotate a secret')
            [CompletionResult]::new('remove', 'remove', [CompletionResultType]::ParameterValue, 'Remove a secret')
            [CompletionResult]::new('doctor', 'doctor', [CompletionResultType]::ParameterValue, 'Run secret backend health checks')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'spt;secret;help;store' {
            [CompletionResult]::new('init', 'init', [CompletionResultType]::ParameterValue, 'Initialize a secret store')
            break
        }
        'spt;secret;help;store;init' {
            break
        }
        'spt;secret;help;set' {
            break
        }
        'spt;secret;help;get' {
            break
        }
        'spt;secret;help;list' {
            break
        }
        'spt;secret;help;rotate' {
            break
        }
        'spt;secret;help;remove' {
            break
        }
        'spt;secret;help;doctor' {
            break
        }
        'spt;secret;help;help' {
            break
        }
        'spt;auth' {
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('test', 'test', [CompletionResultType]::ParameterValue, 'Test authentication for a profile')
            [CompletionResult]::new('ssh3-login', 'ssh3-login', [CompletionResultType]::ParameterValue, 'Run an SSH3 OIDC device-flow login and optionally store the token')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'spt;auth;test' {
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;auth;ssh3-login' {
            [CompletionResult]::new('--issuer', '--issuer', [CompletionResultType]::ParameterName, 'OIDC issuer URL (the `.well-known/openid-configuration` parent)')
            [CompletionResult]::new('--client-id', '--client-id', [CompletionResultType]::ParameterName, 'OAuth client id registered with the issuer')
            [CompletionResult]::new('--audience', '--audience', [CompletionResultType]::ParameterName, 'Optional OAuth audience')
            [CompletionResult]::new('--scope', '--scope', [CompletionResultType]::ParameterName, 'Optional space-separated scope (defaults to `openid offline_access`)')
            [CompletionResult]::new('--save-as', '--save-as', [CompletionResultType]::ParameterName, 'If set, persist the resulting access (and refresh) token through the configured secret backend at this `secret://ns/name` ref')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'JSON output (machine-readable)')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;auth;help' {
            [CompletionResult]::new('test', 'test', [CompletionResultType]::ParameterValue, 'Test authentication for a profile')
            [CompletionResult]::new('ssh3-login', 'ssh3-login', [CompletionResultType]::ParameterValue, 'Run an SSH3 OIDC device-flow login and optionally store the token')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'spt;auth;help;test' {
            break
        }
        'spt;auth;help;ssh3-login' {
            break
        }
        'spt;auth;help;help' {
            break
        }
        'spt;dns' {
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('serve', 'serve', [CompletionResultType]::ParameterValue, 'Run the resolver')
            [CompletionResult]::new('status', 'status', [CompletionResultType]::ParameterValue, 'Resolver status')
            [CompletionResult]::new('query', 'query', [CompletionResultType]::ParameterValue, 'Issue a query against the configured resolver')
            [CompletionResult]::new('upstream', 'upstream', [CompletionResultType]::ParameterValue, 'Manage upstream resolvers')
            [CompletionResult]::new('record', 'record', [CompletionResultType]::ParameterValue, 'Manage managed records')
            [CompletionResult]::new('hosts', 'hosts', [CompletionResultType]::ParameterValue, 'Manage hosts-file rendering / apply / restore')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'spt;dns;serve' {
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Override config path')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--foreground', '--foreground', [CompletionResultType]::ParameterName, 'Run in the foreground')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;dns;status' {
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'JSON output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;dns;query' {
            [CompletionResult]::new('--type', '--type', [CompletionResultType]::ParameterName, 'Record type')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;dns;upstream' {
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('set', 'set', [CompletionResultType]::ParameterValue, 'Replace the upstream list')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'spt;dns;upstream;set' {
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;dns;upstream;help' {
            [CompletionResult]::new('set', 'set', [CompletionResultType]::ParameterValue, 'Replace the upstream list')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'spt;dns;upstream;help;set' {
            break
        }
        'spt;dns;upstream;help;help' {
            break
        }
        'spt;dns;record' {
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('add', 'add', [CompletionResultType]::ParameterValue, 'Add a managed record')
            [CompletionResult]::new('remove', 'remove', [CompletionResultType]::ParameterValue, 'Remove a managed record')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'spt;dns;record;add' {
            [CompletionResult]::new('--addr', '--addr', [CompletionResultType]::ParameterName, 'IP address')
            [CompletionResult]::new('--ttl', '--ttl', [CompletionResultType]::ParameterName, 'TTL (e.g. `5m`)')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;dns;record;remove' {
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;dns;record;help' {
            [CompletionResult]::new('add', 'add', [CompletionResultType]::ParameterValue, 'Add a managed record')
            [CompletionResult]::new('remove', 'remove', [CompletionResultType]::ParameterValue, 'Remove a managed record')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'spt;dns;record;help;add' {
            break
        }
        'spt;dns;record;help;remove' {
            break
        }
        'spt;dns;record;help;help' {
            break
        }
        'spt;dns;hosts' {
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('render', 'render', [CompletionResultType]::ParameterValue, 'Render the would-be hosts file')
            [CompletionResult]::new('apply', 'apply', [CompletionResultType]::ParameterValue, 'Apply the rendered hosts file')
            [CompletionResult]::new('restore', 'restore', [CompletionResultType]::ParameterValue, 'Restore a previous hosts backup')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'spt;dns;hosts;render' {
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Output path (otherwise stdout)')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;dns;hosts;apply' {
            [CompletionResult]::new('--path', '--path', [CompletionResultType]::ParameterName, 'Hosts file to write')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--backup', '--backup', [CompletionResultType]::ParameterName, 'Take a timestamped backup first')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;dns;hosts;restore' {
            [CompletionResult]::new('--backup', '--backup', [CompletionResultType]::ParameterName, 'Specific backup to restore')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;dns;hosts;help' {
            [CompletionResult]::new('render', 'render', [CompletionResultType]::ParameterValue, 'Render the would-be hosts file')
            [CompletionResult]::new('apply', 'apply', [CompletionResultType]::ParameterValue, 'Apply the rendered hosts file')
            [CompletionResult]::new('restore', 'restore', [CompletionResultType]::ParameterValue, 'Restore a previous hosts backup')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'spt;dns;hosts;help;render' {
            break
        }
        'spt;dns;hosts;help;apply' {
            break
        }
        'spt;dns;hosts;help;restore' {
            break
        }
        'spt;dns;hosts;help;help' {
            break
        }
        'spt;dns;help' {
            [CompletionResult]::new('serve', 'serve', [CompletionResultType]::ParameterValue, 'Run the resolver')
            [CompletionResult]::new('status', 'status', [CompletionResultType]::ParameterValue, 'Resolver status')
            [CompletionResult]::new('query', 'query', [CompletionResultType]::ParameterValue, 'Issue a query against the configured resolver')
            [CompletionResult]::new('upstream', 'upstream', [CompletionResultType]::ParameterValue, 'Manage upstream resolvers')
            [CompletionResult]::new('record', 'record', [CompletionResultType]::ParameterValue, 'Manage managed records')
            [CompletionResult]::new('hosts', 'hosts', [CompletionResultType]::ParameterValue, 'Manage hosts-file rendering / apply / restore')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'spt;dns;help;serve' {
            break
        }
        'spt;dns;help;status' {
            break
        }
        'spt;dns;help;query' {
            break
        }
        'spt;dns;help;upstream' {
            [CompletionResult]::new('set', 'set', [CompletionResultType]::ParameterValue, 'Replace the upstream list')
            break
        }
        'spt;dns;help;upstream;set' {
            break
        }
        'spt;dns;help;record' {
            [CompletionResult]::new('add', 'add', [CompletionResultType]::ParameterValue, 'Add a managed record')
            [CompletionResult]::new('remove', 'remove', [CompletionResultType]::ParameterValue, 'Remove a managed record')
            break
        }
        'spt;dns;help;record;add' {
            break
        }
        'spt;dns;help;record;remove' {
            break
        }
        'spt;dns;help;hosts' {
            [CompletionResult]::new('render', 'render', [CompletionResultType]::ParameterValue, 'Render the would-be hosts file')
            [CompletionResult]::new('apply', 'apply', [CompletionResultType]::ParameterValue, 'Apply the rendered hosts file')
            [CompletionResult]::new('restore', 'restore', [CompletionResultType]::ParameterValue, 'Restore a previous hosts backup')
            break
        }
        'spt;dns;help;hosts;render' {
            break
        }
        'spt;dns;help;hosts;apply' {
            break
        }
        'spt;dns;help;hosts;restore' {
            break
        }
        'spt;dns;help;help' {
            break
        }
        'spt;firewall' {
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('plan', 'plan', [CompletionResultType]::ParameterValue, 'Plan rules without applying')
            [CompletionResult]::new('apply', 'apply', [CompletionResultType]::ParameterValue, 'Apply rules (idempotent)')
            [CompletionResult]::new('remove', 'remove', [CompletionResultType]::ParameterValue, 'Remove rules')
            [CompletionResult]::new('status', 'status', [CompletionResultType]::ParameterValue, 'Show current applied state')
            [CompletionResult]::new('interfaces', 'interfaces', [CompletionResultType]::ParameterValue, 'List interfaces / bind targets')
            [CompletionResult]::new('bind-preview', 'bind-preview', [CompletionResultType]::ParameterValue, 'Preview the bind for a forward')
            [CompletionResult]::new('gateway', 'gateway', [CompletionResultType]::ParameterValue, 'Manage gateway/interface defaults in config')
            [CompletionResult]::new('policy', 'policy', [CompletionResultType]::ParameterValue, 'Inspect and manage GPO-style policy values')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'spt;firewall;plan' {
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Filter by profile')
            [CompletionResult]::new('--forward', '--forward', [CompletionResultType]::ParameterName, 'Filter by forward')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'JSON output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;firewall;apply' {
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Filter by profile')
            [CompletionResult]::new('--forward', '--forward', [CompletionResultType]::ParameterName, 'Filter by forward')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--user', '--user', [CompletionResultType]::ParameterName, 'User-scoped scope')
            [CompletionResult]::new('--system', '--system', [CompletionResultType]::ParameterName, 'System-scoped scope')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Print actions without changing system state')
            [CompletionResult]::new('-y', '-y', [CompletionResultType]::ParameterName, 'Confirm and perform live firewall mutation (required for apply outside --dry-run)')
            [CompletionResult]::new('--yes', '--yes', [CompletionResultType]::ParameterName, 'Confirm and perform live firewall mutation (required for apply outside --dry-run)')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;firewall;remove' {
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Filter by profile')
            [CompletionResult]::new('--forward', '--forward', [CompletionResultType]::ParameterName, 'Filter by forward')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--user', '--user', [CompletionResultType]::ParameterName, 'User-scoped scope')
            [CompletionResult]::new('--system', '--system', [CompletionResultType]::ParameterName, 'System-scoped scope')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Print actions without changing system state')
            [CompletionResult]::new('-y', '-y', [CompletionResultType]::ParameterName, 'Confirm and perform live firewall mutation (required for apply outside --dry-run)')
            [CompletionResult]::new('--yes', '--yes', [CompletionResultType]::ParameterName, 'Confirm and perform live firewall mutation (required for apply outside --dry-run)')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;firewall;status' {
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'JSON output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;firewall;interfaces' {
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'JSON output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;firewall;bind-preview' {
            [CompletionResult]::new('--forward', '--forward', [CompletionResultType]::ParameterName, '`<profile>/<forward>`')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'JSON output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;firewall;gateway' {
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('show', 'show', [CompletionResultType]::ParameterValue, 'Show configured interface/gateway policy')
            [CompletionResult]::new('set', 'set', [CompletionResultType]::ParameterValue, 'Update configured interface/gateway policy')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'spt;firewall;gateway;show' {
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'JSON output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;firewall;gateway;set' {
            [CompletionResult]::new('--default-interface', '--default-interface', [CompletionResultType]::ParameterName, 'Set `[network.interface].default_interface`')
            [CompletionResult]::new('--allowed-interface', '--allowed-interface', [CompletionResultType]::ParameterName, 'Set `[network.interface].allowed_interfaces`')
            [CompletionResult]::new('--denied-interface', '--denied-interface', [CompletionResultType]::ParameterName, 'Set `[network.interface].denied_interfaces`')
            [CompletionResult]::new('--require-explicit-interface', '--require-explicit-interface', [CompletionResultType]::ParameterName, 'Set `[network.interface].require_explicit_interface`')
            [CompletionResult]::new('--allow-all-interfaces', '--allow-all-interfaces', [CompletionResultType]::ParameterName, 'Set `[network.interface].allow_all_interfaces`')
            [CompletionResult]::new('--bind-ipv6', '--bind-ipv6', [CompletionResultType]::ParameterName, 'Set `[network.interface].bind_ipv6` (`auto|prefer|disable`)')
            [CompletionResult]::new('--default-gateway', '--default-gateway', [CompletionResultType]::ParameterName, 'Set `[network.gateway].default_gateway`')
            [CompletionResult]::new('--gateway-interface', '--gateway-interface', [CompletionResultType]::ParameterName, 'Set `[network.gateway].interface`')
            [CompletionResult]::new('--route-check-target', '--route-check-target', [CompletionResultType]::ParameterName, 'Set `[network.gateway].route_check_target`')
            [CompletionResult]::new('--policy', '--policy', [CompletionResultType]::ParameterName, 'Set `[network.gateway].policy`')
            [CompletionResult]::new('--require-gateway-match', '--require-gateway-match', [CompletionResultType]::ParameterName, 'Set `[network.gateway].require_gateway_match`')
            [CompletionResult]::new('--tcp-nodelay', '--tcp-nodelay', [CompletionResultType]::ParameterName, 'Set `[network.offload].tcp_nodelay`')
            [CompletionResult]::new('--socket-keepalive', '--socket-keepalive', [CompletionResultType]::ParameterName, 'Set `[network.offload].socket_keepalive`')
            [CompletionResult]::new('--tcp-fast-open', '--tcp-fast-open', [CompletionResultType]::ParameterName, 'Set `[network.offload].tcp_fast_open`')
            [CompletionResult]::new('--reuse-port', '--reuse-port', [CompletionResultType]::ParameterName, 'Set `[network.offload].reuse_port`')
            [CompletionResult]::new('--io-uring', '--io-uring', [CompletionResultType]::ParameterName, 'Set `[network.offload].io_uring`')
            [CompletionResult]::new('--zerocopy', '--zerocopy', [CompletionResultType]::ParameterName, 'Set `[network.offload].zerocopy`')
            [CompletionResult]::new('--sendfile', '--sendfile', [CompletionResultType]::ParameterName, 'Set `[network.offload].sendfile`')
            [CompletionResult]::new('--checksum-offload', '--checksum-offload', [CompletionResultType]::ParameterName, 'Set `[network.offload].checksum_offload`')
            [CompletionResult]::new('--large-send-offload', '--large-send-offload', [CompletionResultType]::ParameterName, 'Set `[network.offload].large_send_offload`')
            [CompletionResult]::new('--load-balance-strategy', '--load-balance-strategy', [CompletionResultType]::ParameterName, 'Set `[network.load_balance].strategy`')
            [CompletionResult]::new('--sticky-sessions', '--sticky-sessions', [CompletionResultType]::ParameterName, 'Set `[network.load_balance].sticky_sessions`')
            [CompletionResult]::new('--health-check', '--health-check', [CompletionResultType]::ParameterName, 'Set `[network.load_balance].health_check`')
            [CompletionResult]::new('--load-balance-fail-after', '--load-balance-fail-after', [CompletionResultType]::ParameterName, 'Set `[network.load_balance].fail_after`')
            [CompletionResult]::new('--load-balance-restore-after', '--load-balance-restore-after', [CompletionResultType]::ParameterName, 'Set `[network.load_balance].restore_after`')
            [CompletionResult]::new('--rebalance-interval', '--rebalance-interval', [CompletionResultType]::ParameterName, 'Set `[network.load_balance].rebalance_interval`')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'JSON output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;firewall;gateway;help' {
            [CompletionResult]::new('show', 'show', [CompletionResultType]::ParameterValue, 'Show configured interface/gateway policy')
            [CompletionResult]::new('set', 'set', [CompletionResultType]::ParameterValue, 'Update configured interface/gateway policy')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'spt;firewall;gateway;help;show' {
            break
        }
        'spt;firewall;gateway;help;set' {
            break
        }
        'spt;firewall;gateway;help;help' {
            break
        }
        'spt;firewall;policy' {
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('list', 'list', [CompletionResultType]::ParameterValue, 'List known policy bindings')
            [CompletionResult]::new('show', 'show', [CompletionResultType]::ParameterValue, 'Show live registry policy overlay and effective network/firewall fields')
            [CompletionResult]::new('set', 'set', [CompletionResultType]::ParameterValue, 'Set a policy value in HKCU/HKLM')
            [CompletionResult]::new('unset', 'unset', [CompletionResultType]::ParameterValue, 'Remove a policy value from HKCU/HKLM')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'spt;firewall;policy;list' {
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'JSON output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;firewall;policy;show' {
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'JSON output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;firewall;policy;set' {
            [CompletionResult]::new('--scope', '--scope', [CompletionResultType]::ParameterName, 'Target registry hive')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--enforced', '--enforced', [CompletionResultType]::ParameterName, 'Mark the containing machine-policy section enforced')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'JSON output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;firewall;policy;unset' {
            [CompletionResult]::new('--scope', '--scope', [CompletionResultType]::ParameterName, 'Target registry hive')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--clear-enforced', '--clear-enforced', [CompletionResultType]::ParameterName, 'Also clear the section-level `Enforced` sentinel')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'JSON output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;firewall;policy;help' {
            [CompletionResult]::new('list', 'list', [CompletionResultType]::ParameterValue, 'List known policy bindings')
            [CompletionResult]::new('show', 'show', [CompletionResultType]::ParameterValue, 'Show live registry policy overlay and effective network/firewall fields')
            [CompletionResult]::new('set', 'set', [CompletionResultType]::ParameterValue, 'Set a policy value in HKCU/HKLM')
            [CompletionResult]::new('unset', 'unset', [CompletionResultType]::ParameterValue, 'Remove a policy value from HKCU/HKLM')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'spt;firewall;policy;help;list' {
            break
        }
        'spt;firewall;policy;help;show' {
            break
        }
        'spt;firewall;policy;help;set' {
            break
        }
        'spt;firewall;policy;help;unset' {
            break
        }
        'spt;firewall;policy;help;help' {
            break
        }
        'spt;firewall;help' {
            [CompletionResult]::new('plan', 'plan', [CompletionResultType]::ParameterValue, 'Plan rules without applying')
            [CompletionResult]::new('apply', 'apply', [CompletionResultType]::ParameterValue, 'Apply rules (idempotent)')
            [CompletionResult]::new('remove', 'remove', [CompletionResultType]::ParameterValue, 'Remove rules')
            [CompletionResult]::new('status', 'status', [CompletionResultType]::ParameterValue, 'Show current applied state')
            [CompletionResult]::new('interfaces', 'interfaces', [CompletionResultType]::ParameterValue, 'List interfaces / bind targets')
            [CompletionResult]::new('bind-preview', 'bind-preview', [CompletionResultType]::ParameterValue, 'Preview the bind for a forward')
            [CompletionResult]::new('gateway', 'gateway', [CompletionResultType]::ParameterValue, 'Manage gateway/interface defaults in config')
            [CompletionResult]::new('policy', 'policy', [CompletionResultType]::ParameterValue, 'Inspect and manage GPO-style policy values')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'spt;firewall;help;plan' {
            break
        }
        'spt;firewall;help;apply' {
            break
        }
        'spt;firewall;help;remove' {
            break
        }
        'spt;firewall;help;status' {
            break
        }
        'spt;firewall;help;interfaces' {
            break
        }
        'spt;firewall;help;bind-preview' {
            break
        }
        'spt;firewall;help;gateway' {
            [CompletionResult]::new('show', 'show', [CompletionResultType]::ParameterValue, 'Show configured interface/gateway policy')
            [CompletionResult]::new('set', 'set', [CompletionResultType]::ParameterValue, 'Update configured interface/gateway policy')
            break
        }
        'spt;firewall;help;gateway;show' {
            break
        }
        'spt;firewall;help;gateway;set' {
            break
        }
        'spt;firewall;help;policy' {
            [CompletionResult]::new('list', 'list', [CompletionResultType]::ParameterValue, 'List known policy bindings')
            [CompletionResult]::new('show', 'show', [CompletionResultType]::ParameterValue, 'Show live registry policy overlay and effective network/firewall fields')
            [CompletionResult]::new('set', 'set', [CompletionResultType]::ParameterValue, 'Set a policy value in HKCU/HKLM')
            [CompletionResult]::new('unset', 'unset', [CompletionResultType]::ParameterValue, 'Remove a policy value from HKCU/HKLM')
            break
        }
        'spt;firewall;help;policy;list' {
            break
        }
        'spt;firewall;help;policy;show' {
            break
        }
        'spt;firewall;help;policy;set' {
            break
        }
        'spt;firewall;help;policy;unset' {
            break
        }
        'spt;firewall;help;help' {
            break
        }
        'spt;log' {
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('tail', 'tail', [CompletionResultType]::ParameterValue, 'Tail logs')
            [CompletionResult]::new('remote', 'remote', [CompletionResultType]::ParameterValue, 'Manage configured remote log sinks')
            [CompletionResult]::new('test', 'test', [CompletionResultType]::ParameterValue, 'Probe a configured sink')
            [CompletionResult]::new('export', 'export', [CompletionResultType]::ParameterValue, 'Export logs to a structured format')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'spt;log;tail' {
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Filter by profile')
            [CompletionResult]::new('--since', '--since', [CompletionResultType]::ParameterName, 'Lookback window (e.g. `1h`)')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--follow', '--follow', [CompletionResultType]::ParameterName, 'Follow mode')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'JSON output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;log;remote' {
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('list', 'list', [CompletionResultType]::ParameterValue, 'List configured remote log sinks')
            [CompletionResult]::new('test', 'test', [CompletionResultType]::ParameterValue, 'Probe a configured remote log sink')
            [CompletionResult]::new('status', 'status', [CompletionResultType]::ParameterValue, 'Show local delivery status for a remote log sink')
            [CompletionResult]::new('drain', 'drain', [CompletionResultType]::ParameterValue, 'Drain a remote log sink''s disk spool')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'spt;log;remote;list' {
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'JSON output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;log;remote;test' {
            [CompletionResult]::new('--sink', '--sink', [CompletionResultType]::ParameterName, 'Sink name')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--send-test-record', '--send-test-record', [CompletionResultType]::ParameterName, 'Send a real synthetic record instead of only probing reachability')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'JSON output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;log;remote;status' {
            [CompletionResult]::new('--sink', '--sink', [CompletionResultType]::ParameterName, 'Sink name')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'JSON output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;log;remote;drain' {
            [CompletionResult]::new('--sink', '--sink', [CompletionResultType]::ParameterName, 'Sink name')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'JSON output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;log;remote;help' {
            [CompletionResult]::new('list', 'list', [CompletionResultType]::ParameterValue, 'List configured remote log sinks')
            [CompletionResult]::new('test', 'test', [CompletionResultType]::ParameterValue, 'Probe a configured remote log sink')
            [CompletionResult]::new('status', 'status', [CompletionResultType]::ParameterValue, 'Show local delivery status for a remote log sink')
            [CompletionResult]::new('drain', 'drain', [CompletionResultType]::ParameterValue, 'Drain a remote log sink''s disk spool')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'spt;log;remote;help;list' {
            break
        }
        'spt;log;remote;help;test' {
            break
        }
        'spt;log;remote;help;status' {
            break
        }
        'spt;log;remote;help;drain' {
            break
        }
        'spt;log;remote;help;help' {
            break
        }
        'spt;log;test' {
            [CompletionResult]::new('--sink', '--sink', [CompletionResultType]::ParameterName, 'Sink name')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;log;export' {
            [CompletionResult]::new('--format', '--format', [CompletionResultType]::ParameterName, 'Output format')
            [CompletionResult]::new('--since', '--since', [CompletionResultType]::ParameterName, 'Lookback window')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;log;help' {
            [CompletionResult]::new('tail', 'tail', [CompletionResultType]::ParameterValue, 'Tail logs')
            [CompletionResult]::new('remote', 'remote', [CompletionResultType]::ParameterValue, 'Manage configured remote log sinks')
            [CompletionResult]::new('test', 'test', [CompletionResultType]::ParameterValue, 'Probe a configured sink')
            [CompletionResult]::new('export', 'export', [CompletionResultType]::ParameterValue, 'Export logs to a structured format')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'spt;log;help;tail' {
            break
        }
        'spt;log;help;remote' {
            [CompletionResult]::new('list', 'list', [CompletionResultType]::ParameterValue, 'List configured remote log sinks')
            [CompletionResult]::new('test', 'test', [CompletionResultType]::ParameterValue, 'Probe a configured remote log sink')
            [CompletionResult]::new('status', 'status', [CompletionResultType]::ParameterValue, 'Show local delivery status for a remote log sink')
            [CompletionResult]::new('drain', 'drain', [CompletionResultType]::ParameterValue, 'Drain a remote log sink''s disk spool')
            break
        }
        'spt;log;help;remote;list' {
            break
        }
        'spt;log;help;remote;test' {
            break
        }
        'spt;log;help;remote;status' {
            break
        }
        'spt;log;help;remote;drain' {
            break
        }
        'spt;log;help;test' {
            break
        }
        'spt;log;help;export' {
            break
        }
        'spt;log;help;help' {
            break
        }
        'spt;observe' {
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('metrics', 'metrics', [CompletionResultType]::ParameterValue, 'Print metrics')
            [CompletionResult]::new('windows-event', 'windows-event', [CompletionResultType]::ParameterValue, 'Windows Event Log integration')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'spt;observe;metrics' {
            [CompletionResult]::new('--format', '--format', [CompletionResultType]::ParameterName, 'Output format')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;observe;windows-event' {
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('install-source', 'install-source', [CompletionResultType]::ParameterValue, 'Install a Windows Event Log source')
            [CompletionResult]::new('uninstall-source', 'uninstall-source', [CompletionResultType]::ParameterValue, 'Uninstall a Windows Event Log source')
            [CompletionResult]::new('test', 'test', [CompletionResultType]::ParameterValue, 'Emit a test event')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'spt;observe;windows-event;install-source' {
            [CompletionResult]::new('--source', '--source', [CompletionResultType]::ParameterName, 'Source name')
            [CompletionResult]::new('--channel', '--channel', [CompletionResultType]::ParameterName, 'Event Log channel. Defaults to `[observability.windows_event].channel` or `Application`')
            [CompletionResult]::new('--message-dll', '--message-dll', [CompletionResultType]::ParameterName, 'Message table DLL or EXE for source registration')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;observe;windows-event;uninstall-source' {
            [CompletionResult]::new('--source', '--source', [CompletionResultType]::ParameterName, 'Source name')
            [CompletionResult]::new('--channel', '--channel', [CompletionResultType]::ParameterName, 'Event Log channel. Defaults to `[observability.windows_event].channel` or `Application`')
            [CompletionResult]::new('--message-dll', '--message-dll', [CompletionResultType]::ParameterName, 'Message table DLL or EXE for source registration')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;observe;windows-event;test' {
            [CompletionResult]::new('--source', '--source', [CompletionResultType]::ParameterName, 'Source name')
            [CompletionResult]::new('--channel', '--channel', [CompletionResultType]::ParameterName, 'Event Log channel. Used for config/default resolution')
            [CompletionResult]::new('--level', '--level', [CompletionResultType]::ParameterName, 'Event severity (`info`, `warning`, `error`)')
            [CompletionResult]::new('--event-id', '--event-id', [CompletionResultType]::ParameterName, 'Event identifier')
            [CompletionResult]::new('--message', '--message', [CompletionResultType]::ParameterName, 'Event message')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;observe;windows-event;help' {
            [CompletionResult]::new('install-source', 'install-source', [CompletionResultType]::ParameterValue, 'Install a Windows Event Log source')
            [CompletionResult]::new('uninstall-source', 'uninstall-source', [CompletionResultType]::ParameterValue, 'Uninstall a Windows Event Log source')
            [CompletionResult]::new('test', 'test', [CompletionResultType]::ParameterValue, 'Emit a test event')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'spt;observe;windows-event;help;install-source' {
            break
        }
        'spt;observe;windows-event;help;uninstall-source' {
            break
        }
        'spt;observe;windows-event;help;test' {
            break
        }
        'spt;observe;windows-event;help;help' {
            break
        }
        'spt;observe;help' {
            [CompletionResult]::new('metrics', 'metrics', [CompletionResultType]::ParameterValue, 'Print metrics')
            [CompletionResult]::new('windows-event', 'windows-event', [CompletionResultType]::ParameterValue, 'Windows Event Log integration')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'spt;observe;help;metrics' {
            break
        }
        'spt;observe;help;windows-event' {
            [CompletionResult]::new('install-source', 'install-source', [CompletionResultType]::ParameterValue, 'Install a Windows Event Log source')
            [CompletionResult]::new('uninstall-source', 'uninstall-source', [CompletionResultType]::ParameterValue, 'Uninstall a Windows Event Log source')
            [CompletionResult]::new('test', 'test', [CompletionResultType]::ParameterValue, 'Emit a test event')
            break
        }
        'spt;observe;help;windows-event;install-source' {
            break
        }
        'spt;observe;help;windows-event;uninstall-source' {
            break
        }
        'spt;observe;help;windows-event;test' {
            break
        }
        'spt;observe;help;help' {
            break
        }
        'spt;event' {
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('list', 'list', [CompletionResultType]::ParameterValue, 'List configured event bindings')
            [CompletionResult]::new('test', 'test', [CompletionResultType]::ParameterValue, 'Trigger a binding by name')
            [CompletionResult]::new('replay', 'replay', [CompletionResultType]::ParameterValue, 'Replay historical events through a binding')
            [CompletionResult]::new('sink', 'sink', [CompletionResultType]::ParameterValue, 'Manage event sinks')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'spt;event;list' {
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'JSON output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;event;test' {
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;event;replay' {
            [CompletionResult]::new('--since', '--since', [CompletionResultType]::ParameterName, 'Lookback window')
            [CompletionResult]::new('--binding', '--binding', [CompletionResultType]::ParameterName, 'Binding name')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;event;sink' {
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('test', 'test', [CompletionResultType]::ParameterValue, 'Test a sink')
            [CompletionResult]::new('list', 'list', [CompletionResultType]::ParameterValue, 'List configured sinks')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'spt;event;sink;test' {
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'JSON output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;event;sink;list' {
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'JSON output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;event;sink;help' {
            [CompletionResult]::new('test', 'test', [CompletionResultType]::ParameterValue, 'Test a sink')
            [CompletionResult]::new('list', 'list', [CompletionResultType]::ParameterValue, 'List configured sinks')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'spt;event;sink;help;test' {
            break
        }
        'spt;event;sink;help;list' {
            break
        }
        'spt;event;sink;help;help' {
            break
        }
        'spt;event;help' {
            [CompletionResult]::new('list', 'list', [CompletionResultType]::ParameterValue, 'List configured event bindings')
            [CompletionResult]::new('test', 'test', [CompletionResultType]::ParameterValue, 'Trigger a binding by name')
            [CompletionResult]::new('replay', 'replay', [CompletionResultType]::ParameterValue, 'Replay historical events through a binding')
            [CompletionResult]::new('sink', 'sink', [CompletionResultType]::ParameterValue, 'Manage event sinks')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'spt;event;help;list' {
            break
        }
        'spt;event;help;test' {
            break
        }
        'spt;event;help;replay' {
            break
        }
        'spt;event;help;sink' {
            [CompletionResult]::new('test', 'test', [CompletionResultType]::ParameterValue, 'Test a sink')
            [CompletionResult]::new('list', 'list', [CompletionResultType]::ParameterValue, 'List configured sinks')
            break
        }
        'spt;event;help;sink;test' {
            break
        }
        'spt;event;help;sink;list' {
            break
        }
        'spt;event;help;help' {
            break
        }
        'spt;stats' {
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('summary', 'summary', [CompletionResultType]::ParameterValue, 'Snapshot summary')
            [CompletionResult]::new('live', 'live', [CompletionResultType]::ParameterValue, 'Live updating view')
            [CompletionResult]::new('connections', 'connections', [CompletionResultType]::ParameterValue, 'Connection table')
            [CompletionResult]::new('throughput', 'throughput', [CompletionResultType]::ParameterValue, 'Throughput windows')
            [CompletionResult]::new('errors', 'errors', [CompletionResultType]::ParameterValue, 'Recent errors')
            [CompletionResult]::new('export', 'export', [CompletionResultType]::ParameterValue, 'Export stats to a file')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'spt;stats;summary' {
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Filter by profile')
            [CompletionResult]::new('--forward', '--forward', [CompletionResultType]::ParameterName, 'Filter by forward')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'JSON output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;stats;live' {
            [CompletionResult]::new('--interval', '--interval', [CompletionResultType]::ParameterName, 'Refresh interval')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Filter by profile')
            [CompletionResult]::new('--forward', '--forward', [CompletionResultType]::ParameterName, 'Filter by forward')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;stats;connections' {
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Filter by profile')
            [CompletionResult]::new('--forward', '--forward', [CompletionResultType]::ParameterName, 'Filter by forward')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'JSON output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;stats;throughput' {
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Filter by profile')
            [CompletionResult]::new('--forward', '--forward', [CompletionResultType]::ParameterName, 'Filter by forward')
            [CompletionResult]::new('--window', '--window', [CompletionResultType]::ParameterName, 'Window size')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'JSON output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;stats;errors' {
            [CompletionResult]::new('--since', '--since', [CompletionResultType]::ParameterName, 'Lookback window')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Filter by profile')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'JSON output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;stats;export' {
            [CompletionResult]::new('--format', '--format', [CompletionResultType]::ParameterName, 'Output format')
            [CompletionResult]::new('--since', '--since', [CompletionResultType]::ParameterName, 'Lookback window')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;stats;help' {
            [CompletionResult]::new('summary', 'summary', [CompletionResultType]::ParameterValue, 'Snapshot summary')
            [CompletionResult]::new('live', 'live', [CompletionResultType]::ParameterValue, 'Live updating view')
            [CompletionResult]::new('connections', 'connections', [CompletionResultType]::ParameterValue, 'Connection table')
            [CompletionResult]::new('throughput', 'throughput', [CompletionResultType]::ParameterValue, 'Throughput windows')
            [CompletionResult]::new('errors', 'errors', [CompletionResultType]::ParameterValue, 'Recent errors')
            [CompletionResult]::new('export', 'export', [CompletionResultType]::ParameterValue, 'Export stats to a file')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'spt;stats;help;summary' {
            break
        }
        'spt;stats;help;live' {
            break
        }
        'spt;stats;help;connections' {
            break
        }
        'spt;stats;help;throughput' {
            break
        }
        'spt;stats;help;errors' {
            break
        }
        'spt;stats;help;export' {
            break
        }
        'spt;stats;help;help' {
            break
        }
        'spt;session' {
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('list', 'list', [CompletionResultType]::ParameterValue, 'List sessions')
            [CompletionResult]::new('show', 'show', [CompletionResultType]::ParameterValue, 'Show a session')
            [CompletionResult]::new('close', 'close', [CompletionResultType]::ParameterValue, 'Close a session')
            [CompletionResult]::new('drain', 'drain', [CompletionResultType]::ParameterValue, 'Drain sessions for a profile')
            [CompletionResult]::new('top', 'top', [CompletionResultType]::ParameterValue, 'Top-style live view')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'spt;session;list' {
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Filter by profile')
            [CompletionResult]::new('--forward', '--forward', [CompletionResultType]::ParameterName, 'Filter by forward')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'JSON output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;session;show' {
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'JSON output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;session;close' {
            [CompletionResult]::new('--grace', '--grace', [CompletionResultType]::ParameterName, 'Grace period')
            [CompletionResult]::new('--reason', '--reason', [CompletionResultType]::ParameterName, 'Free-form reason for audit')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;session;drain' {
            [CompletionResult]::new('--forward', '--forward', [CompletionResultType]::ParameterName, 'Filter by forward')
            [CompletionResult]::new('--grace', '--grace', [CompletionResultType]::ParameterName, 'Drain timeout / grace period. Synonym: `--timeout`')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;session;top' {
            [CompletionResult]::new('--sort', '--sort', [CompletionResultType]::ParameterName, 'Sort key')
            [CompletionResult]::new('--limit', '--limit', [CompletionResultType]::ParameterName, 'Result limit')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;session;help' {
            [CompletionResult]::new('list', 'list', [CompletionResultType]::ParameterValue, 'List sessions')
            [CompletionResult]::new('show', 'show', [CompletionResultType]::ParameterValue, 'Show a session')
            [CompletionResult]::new('close', 'close', [CompletionResultType]::ParameterValue, 'Close a session')
            [CompletionResult]::new('drain', 'drain', [CompletionResultType]::ParameterValue, 'Drain sessions for a profile')
            [CompletionResult]::new('top', 'top', [CompletionResultType]::ParameterValue, 'Top-style live view')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'spt;session;help;list' {
            break
        }
        'spt;session;help;show' {
            break
        }
        'spt;session;help;close' {
            break
        }
        'spt;session;help;drain' {
            break
        }
        'spt;session;help;top' {
            break
        }
        'spt;session;help;help' {
            break
        }
        'spt;ftp' {
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('translator', 'translator', [CompletionResultType]::ParameterValue, 'Run / manage the FTP→SFTP translator service')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'spt;ftp;translator' {
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('serve', 'serve', [CompletionResultType]::ParameterValue, 'Start the FTP translator listening on `--bind`')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'spt;ftp;translator;serve' {
            [CompletionResult]::new('--bind', '--bind', [CompletionResultType]::ParameterName, 'Control-channel listen address (`host:port`)')
            [CompletionResult]::new('--pasv-range', '--pasv-range', [CompletionResultType]::ParameterName, 'Inclusive passive-port range, formatted `lo-hi`')
            [CompletionResult]::new('--external-ip', '--external-ip', [CompletionResultType]::ParameterName, 'Optional external IP to advertise in PASV replies (defaults to the control connection''s local address)')
            [CompletionResult]::new('--welcome-banner', '--welcome-banner', [CompletionResultType]::ParameterName, 'Welcome banner sent on connect')
            [CompletionResult]::new('--max-clients', '--max-clients', [CompletionResultType]::ParameterName, 'Maximum concurrent control sessions')
            [CompletionResult]::new('--idle-timeout', '--idle-timeout', [CompletionResultType]::ParameterName, 'Idle timeout for the control channel, e.g. `5m`, `300s`')
            [CompletionResult]::new('--tls-cert', '--tls-cert', [CompletionResultType]::ParameterName, 'PEM file with the TLS certificate chain')
            [CompletionResult]::new('--tls-key', '--tls-key', [CompletionResultType]::ParameterName, 'PEM file with the TLS private key')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Profile name used to open the SFTP backend')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--tls-required', '--tls-required', [CompletionResultType]::ParameterName, 'Require TLS before accepting USER/PASS')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'JSON output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;ftp;translator;help' {
            [CompletionResult]::new('serve', 'serve', [CompletionResultType]::ParameterValue, 'Start the FTP translator listening on `--bind`')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'spt;ftp;translator;help;serve' {
            break
        }
        'spt;ftp;translator;help;help' {
            break
        }
        'spt;ftp;help' {
            [CompletionResult]::new('translator', 'translator', [CompletionResultType]::ParameterValue, 'Run / manage the FTP→SFTP translator service')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'spt;ftp;help;translator' {
            [CompletionResult]::new('serve', 'serve', [CompletionResultType]::ParameterValue, 'Start the FTP translator listening on `--bind`')
            break
        }
        'spt;ftp;help;translator;serve' {
            break
        }
        'spt;ftp;help;help' {
            break
        }
        'spt;sftp' {
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('test', 'test', [CompletionResultType]::ParameterValue, 'Connect to the profile and open the SFTP subsystem')
            [CompletionResult]::new('list', 'list', [CompletionResultType]::ParameterValue, 'List a remote directory')
            [CompletionResult]::new('stat', 'stat', [CompletionResultType]::ParameterValue, 'Show metadata for a remote path')
            [CompletionResult]::new('get', 'get', [CompletionResultType]::ParameterValue, 'Download a remote file')
            [CompletionResult]::new('put', 'put', [CompletionResultType]::ParameterValue, 'Upload a local file')
            [CompletionResult]::new('mkdir', 'mkdir', [CompletionResultType]::ParameterValue, 'Create a remote directory')
            [CompletionResult]::new('rm', 'rm', [CompletionResultType]::ParameterValue, 'Remove a remote file')
            [CompletionResult]::new('rmdir', 'rmdir', [CompletionResultType]::ParameterValue, 'Remove a remote directory')
            [CompletionResult]::new('rename', 'rename', [CompletionResultType]::ParameterValue, 'Rename a remote file or directory')
            [CompletionResult]::new('cat', 'cat', [CompletionResultType]::ParameterValue, 'Print a remote file (with a size cap)')
            [CompletionResult]::new('tail', 'tail', [CompletionResultType]::ParameterValue, 'Print the trailing bytes of a remote file')
            [CompletionResult]::new('chmod', 'chmod', [CompletionResultType]::ParameterValue, 'Change POSIX permissions on a remote path')
            [CompletionResult]::new('symlink', 'symlink', [CompletionResultType]::ParameterValue, 'Create a remote symbolic link')
            [CompletionResult]::new('readlink', 'readlink', [CompletionResultType]::ParameterValue, 'Read the target of a remote symbolic link')
            [CompletionResult]::new('realpath', 'realpath', [CompletionResultType]::ParameterValue, 'Canonicalise a remote path')
            [CompletionResult]::new('put-recursive', 'put-recursive', [CompletionResultType]::ParameterValue, 'Mirror a local directory tree onto the server (recursive `put`)')
            [CompletionResult]::new('get-recursive', 'get-recursive', [CompletionResultType]::ParameterValue, 'Mirror a remote directory tree onto the local filesystem (recursive `get`)')
            [CompletionResult]::new('mount', 'mount', [CompletionResultType]::ParameterValue, 'Manage SFTP-backed filesystem mount entries')
            [CompletionResult]::new('drive', 'drive', [CompletionResultType]::ParameterValue, 'Manage SFTP-backed Windows drive entries')
            [CompletionResult]::new('umount', 'umount', [CompletionResultType]::ParameterValue, 'Tear down an SFTP-backed filesystem mount (shorthand for `spt sftp mount stop`)')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'spt;sftp;test' {
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Profile name')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'JSON output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;sftp;list' {
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Profile name')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'JSON output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;sftp;stat' {
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Profile name')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'JSON output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;sftp;get' {
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Profile name')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Local output path')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;sftp;put' {
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Profile name')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;sftp;mkdir' {
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Profile name')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'JSON output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;sftp;rm' {
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Profile name')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'JSON output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;sftp;rmdir' {
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Profile name')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'JSON output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;sftp;rename' {
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Profile name')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;sftp;cat' {
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Profile name')
            [CompletionResult]::new('--size-cap', '--size-cap', [CompletionResultType]::ParameterName, 'Maximum number of bytes to read; defaults to 4 MiB')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;sftp;tail' {
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Profile name')
            [CompletionResult]::new('--bytes', '--bytes', [CompletionResultType]::ParameterName, 'Number of trailing bytes to print; defaults to 4 KiB')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;sftp;chmod' {
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Profile name')
            [CompletionResult]::new('--mode', '--mode', [CompletionResultType]::ParameterName, 'Octal mode, for example `0640`')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;sftp;symlink' {
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Profile name')
            [CompletionResult]::new('--target', '--target', [CompletionResultType]::ParameterName, 'Target path the link should point to')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;sftp;readlink' {
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Profile name')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'JSON output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;sftp;realpath' {
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Profile name')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'JSON output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;sftp;put-recursive' {
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Profile name')
            [CompletionResult]::new('--bps', '--bps', [CompletionResultType]::ParameterName, 'Bandwidth cap, e.g. `5MiB` (parsed via `bytesize`); `0` disables')
            [CompletionResult]::new('--checksum', '--checksum', [CompletionResultType]::ParameterName, 'Post-transfer integrity check')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--resume', '--resume', [CompletionResultType]::ParameterName, 'Resume mode: seek into existing target files instead of truncating')
            [CompletionResult]::new('--follow-symlinks', '--follow-symlinks', [CompletionResultType]::ParameterName, 'Follow symbolic links during the walk (loops are still detected)')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;sftp;get-recursive' {
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Profile name')
            [CompletionResult]::new('--bps', '--bps', [CompletionResultType]::ParameterName, 'Bandwidth cap, e.g. `5MiB` (parsed via `bytesize`); `0` disables')
            [CompletionResult]::new('--checksum', '--checksum', [CompletionResultType]::ParameterName, 'Post-transfer integrity check')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--resume', '--resume', [CompletionResultType]::ParameterName, 'Resume mode: seek into existing target files instead of truncating')
            [CompletionResult]::new('--follow-symlinks', '--follow-symlinks', [CompletionResultType]::ParameterName, 'Follow symbolic links during the walk (loops are still detected)')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;sftp;mount' {
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('list', 'list', [CompletionResultType]::ParameterValue, 'List configured filesystem mounts')
            [CompletionResult]::new('add', 'add', [CompletionResultType]::ParameterValue, 'Add a filesystem mount entry to the config')
            [CompletionResult]::new('remove', 'remove', [CompletionResultType]::ParameterValue, 'Remove a filesystem mount entry from the config')
            [CompletionResult]::new('plan', 'plan', [CompletionResultType]::ParameterValue, 'Render the platform plan for a configured or proposed mount')
            [CompletionResult]::new('start', 'start', [CompletionResultType]::ParameterValue, 'Start an SFTP-backed filesystem mount')
            [CompletionResult]::new('stop', 'stop', [CompletionResultType]::ParameterValue, 'Tear down an SFTP-backed filesystem mount')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'spt;sftp;mount;list' {
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Profile name')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'JSON output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;sftp;mount;add' {
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Profile name')
            [CompletionResult]::new('--name', '--name', [CompletionResultType]::ParameterName, 'Mount name')
            [CompletionResult]::new('--remote', '--remote', [CompletionResultType]::ParameterName, 'Remote SFTP path')
            [CompletionResult]::new('--mount-point', '--mount-point', [CompletionResultType]::ParameterName, 'Local mount point')
            [CompletionResult]::new('--cache', '--cache', [CompletionResultType]::ParameterName, 'Cache mode')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--read-only', '--read-only', [CompletionResultType]::ParameterName, 'Mount read-only')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;sftp;mount;remove' {
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;sftp;mount;plan' {
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Profile name')
            [CompletionResult]::new('--name', '--name', [CompletionResultType]::ParameterName, 'Existing mount name. If omitted, `--remote` and `--mount-point` are used')
            [CompletionResult]::new('--remote', '--remote', [CompletionResultType]::ParameterName, 'Proposed remote path')
            [CompletionResult]::new('--mount-point', '--mount-point', [CompletionResultType]::ParameterName, 'Proposed mount point')
            [CompletionResult]::new('--cache', '--cache', [CompletionResultType]::ParameterName, 'Proposed cache mode')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--read-only', '--read-only', [CompletionResultType]::ParameterName, 'Proposed read-only mode')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'JSON output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;sftp;mount;start' {
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Profile name')
            [CompletionResult]::new('--local', '--local', [CompletionResultType]::ParameterName, 'Local mountpoint. Overrides any configured `mount_point`')
            [CompletionResult]::new('--remote', '--remote', [CompletionResultType]::ParameterName, 'Remote SFTP path to mount. Overrides any configured `remote_path`')
            [CompletionResult]::new('--volume', '--volume', [CompletionResultType]::ParameterName, 'Volume label (Windows)')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--read-only', '--read-only', [CompletionResultType]::ParameterName, 'Mount read-only')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'JSON output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;sftp;mount;stop' {
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'JSON output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;sftp;mount;help' {
            [CompletionResult]::new('list', 'list', [CompletionResultType]::ParameterValue, 'List configured filesystem mounts')
            [CompletionResult]::new('add', 'add', [CompletionResultType]::ParameterValue, 'Add a filesystem mount entry to the config')
            [CompletionResult]::new('remove', 'remove', [CompletionResultType]::ParameterValue, 'Remove a filesystem mount entry from the config')
            [CompletionResult]::new('plan', 'plan', [CompletionResultType]::ParameterValue, 'Render the platform plan for a configured or proposed mount')
            [CompletionResult]::new('start', 'start', [CompletionResultType]::ParameterValue, 'Start an SFTP-backed filesystem mount')
            [CompletionResult]::new('stop', 'stop', [CompletionResultType]::ParameterValue, 'Tear down an SFTP-backed filesystem mount')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'spt;sftp;mount;help;list' {
            break
        }
        'spt;sftp;mount;help;add' {
            break
        }
        'spt;sftp;mount;help;remove' {
            break
        }
        'spt;sftp;mount;help;plan' {
            break
        }
        'spt;sftp;mount;help;start' {
            break
        }
        'spt;sftp;mount;help;stop' {
            break
        }
        'spt;sftp;mount;help;help' {
            break
        }
        'spt;sftp;drive' {
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('list', 'list', [CompletionResultType]::ParameterValue, 'List configured Windows drive mounts')
            [CompletionResult]::new('add', 'add', [CompletionResultType]::ParameterValue, 'Add a Windows drive mount entry to the config')
            [CompletionResult]::new('remove', 'remove', [CompletionResultType]::ParameterValue, 'Remove a Windows drive mount entry from the config')
            [CompletionResult]::new('plan', 'plan', [CompletionResultType]::ParameterValue, 'Render the platform plan for a configured or proposed drive mount')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'spt;sftp;drive;list' {
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Profile name')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'JSON output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;sftp;drive;add' {
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Profile name')
            [CompletionResult]::new('--name', '--name', [CompletionResultType]::ParameterName, 'Mount name')
            [CompletionResult]::new('--remote', '--remote', [CompletionResultType]::ParameterName, 'Remote SFTP path')
            [CompletionResult]::new('--letter', '--letter', [CompletionResultType]::ParameterName, 'Windows drive letter, for example `S` or `S:`')
            [CompletionResult]::new('--cache', '--cache', [CompletionResultType]::ParameterName, 'Cache mode')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--read-only', '--read-only', [CompletionResultType]::ParameterName, 'Mount read-only')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;sftp;drive;remove' {
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;sftp;drive;plan' {
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Profile name')
            [CompletionResult]::new('--name', '--name', [CompletionResultType]::ParameterName, 'Existing mount name. If omitted, `--remote` and `--letter` are used')
            [CompletionResult]::new('--remote', '--remote', [CompletionResultType]::ParameterName, 'Proposed remote path')
            [CompletionResult]::new('--letter', '--letter', [CompletionResultType]::ParameterName, 'Proposed Windows drive letter')
            [CompletionResult]::new('--cache', '--cache', [CompletionResultType]::ParameterName, 'Proposed cache mode')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--read-only', '--read-only', [CompletionResultType]::ParameterName, 'Proposed read-only mode')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'JSON output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;sftp;drive;help' {
            [CompletionResult]::new('list', 'list', [CompletionResultType]::ParameterValue, 'List configured Windows drive mounts')
            [CompletionResult]::new('add', 'add', [CompletionResultType]::ParameterValue, 'Add a Windows drive mount entry to the config')
            [CompletionResult]::new('remove', 'remove', [CompletionResultType]::ParameterValue, 'Remove a Windows drive mount entry from the config')
            [CompletionResult]::new('plan', 'plan', [CompletionResultType]::ParameterValue, 'Render the platform plan for a configured or proposed drive mount')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'spt;sftp;drive;help;list' {
            break
        }
        'spt;sftp;drive;help;add' {
            break
        }
        'spt;sftp;drive;help;remove' {
            break
        }
        'spt;sftp;drive;help;plan' {
            break
        }
        'spt;sftp;drive;help;help' {
            break
        }
        'spt;sftp;umount' {
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'JSON output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;sftp;help' {
            [CompletionResult]::new('test', 'test', [CompletionResultType]::ParameterValue, 'Connect to the profile and open the SFTP subsystem')
            [CompletionResult]::new('list', 'list', [CompletionResultType]::ParameterValue, 'List a remote directory')
            [CompletionResult]::new('stat', 'stat', [CompletionResultType]::ParameterValue, 'Show metadata for a remote path')
            [CompletionResult]::new('get', 'get', [CompletionResultType]::ParameterValue, 'Download a remote file')
            [CompletionResult]::new('put', 'put', [CompletionResultType]::ParameterValue, 'Upload a local file')
            [CompletionResult]::new('mkdir', 'mkdir', [CompletionResultType]::ParameterValue, 'Create a remote directory')
            [CompletionResult]::new('rm', 'rm', [CompletionResultType]::ParameterValue, 'Remove a remote file')
            [CompletionResult]::new('rmdir', 'rmdir', [CompletionResultType]::ParameterValue, 'Remove a remote directory')
            [CompletionResult]::new('rename', 'rename', [CompletionResultType]::ParameterValue, 'Rename a remote file or directory')
            [CompletionResult]::new('cat', 'cat', [CompletionResultType]::ParameterValue, 'Print a remote file (with a size cap)')
            [CompletionResult]::new('tail', 'tail', [CompletionResultType]::ParameterValue, 'Print the trailing bytes of a remote file')
            [CompletionResult]::new('chmod', 'chmod', [CompletionResultType]::ParameterValue, 'Change POSIX permissions on a remote path')
            [CompletionResult]::new('symlink', 'symlink', [CompletionResultType]::ParameterValue, 'Create a remote symbolic link')
            [CompletionResult]::new('readlink', 'readlink', [CompletionResultType]::ParameterValue, 'Read the target of a remote symbolic link')
            [CompletionResult]::new('realpath', 'realpath', [CompletionResultType]::ParameterValue, 'Canonicalise a remote path')
            [CompletionResult]::new('put-recursive', 'put-recursive', [CompletionResultType]::ParameterValue, 'Mirror a local directory tree onto the server (recursive `put`)')
            [CompletionResult]::new('get-recursive', 'get-recursive', [CompletionResultType]::ParameterValue, 'Mirror a remote directory tree onto the local filesystem (recursive `get`)')
            [CompletionResult]::new('mount', 'mount', [CompletionResultType]::ParameterValue, 'Manage SFTP-backed filesystem mount entries')
            [CompletionResult]::new('drive', 'drive', [CompletionResultType]::ParameterValue, 'Manage SFTP-backed Windows drive entries')
            [CompletionResult]::new('umount', 'umount', [CompletionResultType]::ParameterValue, 'Tear down an SFTP-backed filesystem mount (shorthand for `spt sftp mount stop`)')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'spt;sftp;help;test' {
            break
        }
        'spt;sftp;help;list' {
            break
        }
        'spt;sftp;help;stat' {
            break
        }
        'spt;sftp;help;get' {
            break
        }
        'spt;sftp;help;put' {
            break
        }
        'spt;sftp;help;mkdir' {
            break
        }
        'spt;sftp;help;rm' {
            break
        }
        'spt;sftp;help;rmdir' {
            break
        }
        'spt;sftp;help;rename' {
            break
        }
        'spt;sftp;help;cat' {
            break
        }
        'spt;sftp;help;tail' {
            break
        }
        'spt;sftp;help;chmod' {
            break
        }
        'spt;sftp;help;symlink' {
            break
        }
        'spt;sftp;help;readlink' {
            break
        }
        'spt;sftp;help;realpath' {
            break
        }
        'spt;sftp;help;put-recursive' {
            break
        }
        'spt;sftp;help;get-recursive' {
            break
        }
        'spt;sftp;help;mount' {
            [CompletionResult]::new('list', 'list', [CompletionResultType]::ParameterValue, 'List configured filesystem mounts')
            [CompletionResult]::new('add', 'add', [CompletionResultType]::ParameterValue, 'Add a filesystem mount entry to the config')
            [CompletionResult]::new('remove', 'remove', [CompletionResultType]::ParameterValue, 'Remove a filesystem mount entry from the config')
            [CompletionResult]::new('plan', 'plan', [CompletionResultType]::ParameterValue, 'Render the platform plan for a configured or proposed mount')
            [CompletionResult]::new('start', 'start', [CompletionResultType]::ParameterValue, 'Start an SFTP-backed filesystem mount')
            [CompletionResult]::new('stop', 'stop', [CompletionResultType]::ParameterValue, 'Tear down an SFTP-backed filesystem mount')
            break
        }
        'spt;sftp;help;mount;list' {
            break
        }
        'spt;sftp;help;mount;add' {
            break
        }
        'spt;sftp;help;mount;remove' {
            break
        }
        'spt;sftp;help;mount;plan' {
            break
        }
        'spt;sftp;help;mount;start' {
            break
        }
        'spt;sftp;help;mount;stop' {
            break
        }
        'spt;sftp;help;drive' {
            [CompletionResult]::new('list', 'list', [CompletionResultType]::ParameterValue, 'List configured Windows drive mounts')
            [CompletionResult]::new('add', 'add', [CompletionResultType]::ParameterValue, 'Add a Windows drive mount entry to the config')
            [CompletionResult]::new('remove', 'remove', [CompletionResultType]::ParameterValue, 'Remove a Windows drive mount entry from the config')
            [CompletionResult]::new('plan', 'plan', [CompletionResultType]::ParameterValue, 'Render the platform plan for a configured or proposed drive mount')
            break
        }
        'spt;sftp;help;drive;list' {
            break
        }
        'spt;sftp;help;drive;add' {
            break
        }
        'spt;sftp;help;drive;remove' {
            break
        }
        'spt;sftp;help;drive;plan' {
            break
        }
        'spt;sftp;help;umount' {
            break
        }
        'spt;sftp;help;help' {
            break
        }
        'spt;diagnose' {
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('run', 'run', [CompletionResultType]::ParameterValue, 'Run a battery of diagnostic checks')
            [CompletionResult]::new('network', 'network', [CompletionResultType]::ParameterValue, 'Network checks')
            [CompletionResult]::new('auth', 'auth', [CompletionResultType]::ParameterValue, 'Authentication checks for a profile')
            [CompletionResult]::new('trust', 'trust', [CompletionResultType]::ParameterValue, 'Trust checks for a profile')
            [CompletionResult]::new('dns', 'dns', [CompletionResultType]::ParameterValue, 'DNS checks')
            [CompletionResult]::new('bind', 'bind', [CompletionResultType]::ParameterValue, 'Bind checks')
            [CompletionResult]::new('port', 'port', [CompletionResultType]::ParameterValue, 'Probe a host:port')
            [CompletionResult]::new('service', 'service', [CompletionResultType]::ParameterValue, 'Service-manager checks')
            [CompletionResult]::new('secrets', 'secrets', [CompletionResultType]::ParameterValue, 'Secret-backend checks')
            [CompletionResult]::new('observability', 'observability', [CompletionResultType]::ParameterValue, 'Observability sink checks')
            [CompletionResult]::new('mcp', 'mcp', [CompletionResultType]::ParameterValue, 'MCP server checks')
            [CompletionResult]::new('bundle', 'bundle', [CompletionResultType]::ParameterValue, 'Build a redacted support bundle')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'spt;diagnose;run' {
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Filter by profile')
            [CompletionResult]::new('--report', '--report', [CompletionResultType]::ParameterName, 'Write a structured report')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--all', '--all', [CompletionResultType]::ParameterName, 'Run every check')
            [CompletionResult]::new('--offline', '--offline', [CompletionResultType]::ParameterName, 'Restrict to offline-only checks')
            [CompletionResult]::new('--online', '--online', [CompletionResultType]::ParameterName, 'Restrict to online-only checks')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'JSON output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;diagnose;network' {
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Filter by profile')
            [CompletionResult]::new('--endpoint', '--endpoint', [CompletionResultType]::ParameterName, 'Filter by endpoint')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'JSON output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;diagnose;auth' {
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--probe', '--probe', [CompletionResultType]::ParameterName, 'Run a live connect probe (forward-compatible; structural-only today)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'JSON output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;diagnose;trust' {
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--probe', '--probe', [CompletionResultType]::ParameterName, 'Run a live connect probe (forward-compatible; structural-only today)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'JSON output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;diagnose;dns' {
            [CompletionResult]::new('--name', '--name', [CompletionResultType]::ParameterName, 'Name to test')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'JSON output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;diagnose;bind' {
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Filter by profile')
            [CompletionResult]::new('--forward', '--forward', [CompletionResultType]::ParameterName, 'Filter by forward')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'JSON output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;diagnose;port' {
            [CompletionResult]::new('--host', '--host', [CompletionResultType]::ParameterName, 'Target host')
            [CompletionResult]::new('--port', '--port', [CompletionResultType]::ParameterName, 'Target port')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--tcp', '--tcp', [CompletionResultType]::ParameterName, 'TCP probe')
            [CompletionResult]::new('--udp', '--udp', [CompletionResultType]::ParameterName, 'UDP probe')
            [CompletionResult]::new('--autodetect-service', '--autodetect-service', [CompletionResultType]::ParameterName, 'Try to identify the service')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'JSON output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;diagnose;service' {
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to the config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--user', '--user', [CompletionResultType]::ParameterName, 'User scope')
            [CompletionResult]::new('--system', '--system', [CompletionResultType]::ParameterName, 'System scope')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'JSON output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;diagnose;secrets' {
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'JSON output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;diagnose;observability' {
            [CompletionResult]::new('--sink', '--sink', [CompletionResultType]::ParameterName, 'Filter by sink name')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'JSON output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;diagnose;mcp' {
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'JSON output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;diagnose;bundle' {
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Output bundle path')
            [CompletionResult]::new('--since', '--since', [CompletionResultType]::ParameterName, 'Lookback window for events')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--redacted', '--redacted', [CompletionResultType]::ParameterName, 'Redact secrets and PII')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;diagnose;help' {
            [CompletionResult]::new('run', 'run', [CompletionResultType]::ParameterValue, 'Run a battery of diagnostic checks')
            [CompletionResult]::new('network', 'network', [CompletionResultType]::ParameterValue, 'Network checks')
            [CompletionResult]::new('auth', 'auth', [CompletionResultType]::ParameterValue, 'Authentication checks for a profile')
            [CompletionResult]::new('trust', 'trust', [CompletionResultType]::ParameterValue, 'Trust checks for a profile')
            [CompletionResult]::new('dns', 'dns', [CompletionResultType]::ParameterValue, 'DNS checks')
            [CompletionResult]::new('bind', 'bind', [CompletionResultType]::ParameterValue, 'Bind checks')
            [CompletionResult]::new('port', 'port', [CompletionResultType]::ParameterValue, 'Probe a host:port')
            [CompletionResult]::new('service', 'service', [CompletionResultType]::ParameterValue, 'Service-manager checks')
            [CompletionResult]::new('secrets', 'secrets', [CompletionResultType]::ParameterValue, 'Secret-backend checks')
            [CompletionResult]::new('observability', 'observability', [CompletionResultType]::ParameterValue, 'Observability sink checks')
            [CompletionResult]::new('mcp', 'mcp', [CompletionResultType]::ParameterValue, 'MCP server checks')
            [CompletionResult]::new('bundle', 'bundle', [CompletionResultType]::ParameterValue, 'Build a redacted support bundle')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'spt;diagnose;help;run' {
            break
        }
        'spt;diagnose;help;network' {
            break
        }
        'spt;diagnose;help;auth' {
            break
        }
        'spt;diagnose;help;trust' {
            break
        }
        'spt;diagnose;help;dns' {
            break
        }
        'spt;diagnose;help;bind' {
            break
        }
        'spt;diagnose;help;port' {
            break
        }
        'spt;diagnose;help;service' {
            break
        }
        'spt;diagnose;help;secrets' {
            break
        }
        'spt;diagnose;help;observability' {
            break
        }
        'spt;diagnose;help;mcp' {
            break
        }
        'spt;diagnose;help;bundle' {
            break
        }
        'spt;diagnose;help;help' {
            break
        }
        'spt;benchmark' {
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('run', 'run', [CompletionResultType]::ParameterValue, 'End-to-end mixed workload')
            [CompletionResult]::new('latency', 'latency', [CompletionResultType]::ParameterValue, 'Latency-focused benchmark')
            [CompletionResult]::new('throughput', 'throughput', [CompletionResultType]::ParameterValue, 'Throughput-focused benchmark')
            [CompletionResult]::new('udp', 'udp', [CompletionResultType]::ParameterValue, 'UDP benchmark (SSH3 only)')
            [CompletionResult]::new('reconnect', 'reconnect', [CompletionResultType]::ParameterValue, 'Reconnect benchmark')
            [CompletionResult]::new('dns', 'dns', [CompletionResultType]::ParameterValue, 'DNS benchmark')
            [CompletionResult]::new('limits', 'limits', [CompletionResultType]::ParameterValue, 'Limit/throttle introspection')
            [CompletionResult]::new('report', 'report', [CompletionResultType]::ParameterValue, 'Report tooling')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'spt;benchmark;run' {
            [CompletionResult]::new('--driver', '--driver', [CompletionResultType]::ParameterName, 'Driver to dispatch (one of `latency`, `throughput`, `udp`, `reconnect`, `dns`, `limits`)')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Profile name')
            [CompletionResult]::new('--forward', '--forward', [CompletionResultType]::ParameterName, 'Forward name')
            [CompletionResult]::new('--duration', '--duration', [CompletionResultType]::ParameterName, 'Duration')
            [CompletionResult]::new('--connections', '--connections', [CompletionResultType]::ParameterName, 'Concurrent connections')
            [CompletionResult]::new('--count', '--count', [CompletionResultType]::ParameterName, 'Iteration / sample count override')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--unsafe-allow-production-impact', '--unsafe-allow-production-impact', [CompletionResultType]::ParameterName, 'Allow drivers that may impact production. Combined with the `[benchmark.allow_production_impact]` config flag')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'JSON output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;benchmark;latency' {
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Profile name')
            [CompletionResult]::new('--forward', '--forward', [CompletionResultType]::ParameterName, 'Forward name')
            [CompletionResult]::new('--samples', '--samples', [CompletionResultType]::ParameterName, 'Sample count')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--unsafe-allow-production-impact', '--unsafe-allow-production-impact', [CompletionResultType]::ParameterName, 'Allow drivers that may impact production. Combined with the `[benchmark.allow_production_impact]` config flag')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'JSON output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;benchmark;throughput' {
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Profile name')
            [CompletionResult]::new('--forward', '--forward', [CompletionResultType]::ParameterName, 'Forward name')
            [CompletionResult]::new('--duration', '--duration', [CompletionResultType]::ParameterName, 'Duration')
            [CompletionResult]::new('--payload-size', '--payload-size', [CompletionResultType]::ParameterName, 'Payload size')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--unsafe-allow-production-impact', '--unsafe-allow-production-impact', [CompletionResultType]::ParameterName, 'Allow drivers that may impact production. Combined with the `[benchmark.allow_production_impact]` config flag')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'JSON output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;benchmark;udp' {
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Profile name')
            [CompletionResult]::new('--forward', '--forward', [CompletionResultType]::ParameterName, 'Forward name')
            [CompletionResult]::new('--duration', '--duration', [CompletionResultType]::ParameterName, 'Duration')
            [CompletionResult]::new('--packet-size', '--packet-size', [CompletionResultType]::ParameterName, 'Datagram size')
            [CompletionResult]::new('--pps', '--pps', [CompletionResultType]::ParameterName, 'Packets per second')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--unsafe-allow-production-impact', '--unsafe-allow-production-impact', [CompletionResultType]::ParameterName, 'Allow drivers that may impact production. Combined with the `[benchmark.allow_production_impact]` config flag')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'JSON output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;benchmark;reconnect' {
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Profile name')
            [CompletionResult]::new('--iterations', '--iterations', [CompletionResultType]::ParameterName, 'Iteration count')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--unsafe-allow-production-impact', '--unsafe-allow-production-impact', [CompletionResultType]::ParameterName, 'Allow drivers that may impact production. Combined with the `[benchmark.allow_production_impact]` config flag')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'JSON output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;benchmark;dns' {
            [CompletionResult]::new('--name', '--name', [CompletionResultType]::ParameterName, 'Name to resolve')
            [CompletionResult]::new('--samples', '--samples', [CompletionResultType]::ParameterName, 'Sample count')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'JSON output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;benchmark;limits' {
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Profile name')
            [CompletionResult]::new('--forward', '--forward', [CompletionResultType]::ParameterName, 'Forward name')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--unsafe-allow-production-impact', '--unsafe-allow-production-impact', [CompletionResultType]::ParameterName, 'Allow drivers that may impact production. Combined with the `[benchmark.allow_production_impact]` config flag')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'JSON output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;benchmark;report' {
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('compare', 'compare', [CompletionResultType]::ParameterValue, 'Compare two benchmark results')
            [CompletionResult]::new('export', 'export', [CompletionResultType]::ParameterValue, 'Export a benchmark result')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'spt;benchmark;report;compare' {
            [CompletionResult]::new('--baseline', '--baseline', [CompletionResultType]::ParameterName, 'Baseline result file')
            [CompletionResult]::new('--candidate', '--candidate', [CompletionResultType]::ParameterName, 'Candidate result file')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;benchmark;report;export' {
            [CompletionResult]::new('--format', '--format', [CompletionResultType]::ParameterName, 'Output format')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Output path')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;benchmark;report;help' {
            [CompletionResult]::new('compare', 'compare', [CompletionResultType]::ParameterValue, 'Compare two benchmark results')
            [CompletionResult]::new('export', 'export', [CompletionResultType]::ParameterValue, 'Export a benchmark result')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'spt;benchmark;report;help;compare' {
            break
        }
        'spt;benchmark;report;help;export' {
            break
        }
        'spt;benchmark;report;help;help' {
            break
        }
        'spt;benchmark;help' {
            [CompletionResult]::new('run', 'run', [CompletionResultType]::ParameterValue, 'End-to-end mixed workload')
            [CompletionResult]::new('latency', 'latency', [CompletionResultType]::ParameterValue, 'Latency-focused benchmark')
            [CompletionResult]::new('throughput', 'throughput', [CompletionResultType]::ParameterValue, 'Throughput-focused benchmark')
            [CompletionResult]::new('udp', 'udp', [CompletionResultType]::ParameterValue, 'UDP benchmark (SSH3 only)')
            [CompletionResult]::new('reconnect', 'reconnect', [CompletionResultType]::ParameterValue, 'Reconnect benchmark')
            [CompletionResult]::new('dns', 'dns', [CompletionResultType]::ParameterValue, 'DNS benchmark')
            [CompletionResult]::new('limits', 'limits', [CompletionResultType]::ParameterValue, 'Limit/throttle introspection')
            [CompletionResult]::new('report', 'report', [CompletionResultType]::ParameterValue, 'Report tooling')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'spt;benchmark;help;run' {
            break
        }
        'spt;benchmark;help;latency' {
            break
        }
        'spt;benchmark;help;throughput' {
            break
        }
        'spt;benchmark;help;udp' {
            break
        }
        'spt;benchmark;help;reconnect' {
            break
        }
        'spt;benchmark;help;dns' {
            break
        }
        'spt;benchmark;help;limits' {
            break
        }
        'spt;benchmark;help;report' {
            [CompletionResult]::new('compare', 'compare', [CompletionResultType]::ParameterValue, 'Compare two benchmark results')
            [CompletionResult]::new('export', 'export', [CompletionResultType]::ParameterValue, 'Export a benchmark result')
            break
        }
        'spt;benchmark;help;report;compare' {
            break
        }
        'spt;benchmark;help;report;export' {
            break
        }
        'spt;benchmark;help;help' {
            break
        }
        'spt;mcp' {
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('serve', 'serve', [CompletionResultType]::ParameterValue, 'Run the MCP server')
            [CompletionResult]::new('inspect', 'inspect', [CompletionResultType]::ParameterValue, 'Inspect MCP capabilities, resources, tools')
            [CompletionResult]::new('policy', 'policy', [CompletionResultType]::ParameterValue, 'Manage the MCP policy')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'spt;mcp;serve' {
            [CompletionResult]::new('--listen', '--listen', [CompletionResultType]::ParameterName, 'Listen on a loopback TCP address (`127.0.0.1:port`)')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Override config path')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--stdio', '--stdio', [CompletionResultType]::ParameterName, 'Speak MCP over stdio')
            [CompletionResult]::new('--read-only', '--read-only', [CompletionResultType]::ParameterName, 'Force read-only')
            [CompletionResult]::new('--enable', '--enable', [CompletionResultType]::ParameterName, 'Explicit `--enable` toggle (required unless `[mcp].enabled = true`)')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;mcp;inspect' {
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'JSON output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;mcp;policy' {
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('show', 'show', [CompletionResultType]::ParameterValue, 'Show the current policy')
            [CompletionResult]::new('set', 'set', [CompletionResultType]::ParameterValue, 'Update one or more policy keys')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'spt;mcp;policy;show' {
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;mcp;policy;set' {
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;mcp;policy;help' {
            [CompletionResult]::new('show', 'show', [CompletionResultType]::ParameterValue, 'Show the current policy')
            [CompletionResult]::new('set', 'set', [CompletionResultType]::ParameterValue, 'Update one or more policy keys')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'spt;mcp;policy;help;show' {
            break
        }
        'spt;mcp;policy;help;set' {
            break
        }
        'spt;mcp;policy;help;help' {
            break
        }
        'spt;mcp;help' {
            [CompletionResult]::new('serve', 'serve', [CompletionResultType]::ParameterValue, 'Run the MCP server')
            [CompletionResult]::new('inspect', 'inspect', [CompletionResultType]::ParameterValue, 'Inspect MCP capabilities, resources, tools')
            [CompletionResult]::new('policy', 'policy', [CompletionResultType]::ParameterValue, 'Manage the MCP policy')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'spt;mcp;help;serve' {
            break
        }
        'spt;mcp;help;inspect' {
            break
        }
        'spt;mcp;help;policy' {
            [CompletionResult]::new('show', 'show', [CompletionResultType]::ParameterValue, 'Show the current policy')
            [CompletionResult]::new('set', 'set', [CompletionResultType]::ParameterValue, 'Update one or more policy keys')
            break
        }
        'spt;mcp;help;policy;show' {
            break
        }
        'spt;mcp;help;policy;set' {
            break
        }
        'spt;mcp;help;help' {
            break
        }
        'spt;ssh3-serve' {
            [CompletionResult]::new('--listen', '--listen', [CompletionResultType]::ParameterName, 'Address and port to bind the QUIC/UDP listener on')
            [CompletionResult]::new('--cert', '--cert', [CompletionResultType]::ParameterName, 'Path to the server''s TLS certificate chain (PEM, leaf first). Required unless `--self-signed` is given')
            [CompletionResult]::new('--key', '--key', [CompletionResultType]::ParameterName, 'Path to the server''s TLS private key (PEM: PKCS#8, PKCS#1, or SEC1). Required unless `--self-signed` is given')
            [CompletionResult]::new('--self-signed-san', '--self-signed-san', [CompletionResultType]::ParameterName, 'DNS name(s) / IP literal(s) to embed as SANs in the self-signed cert. Only meaningful with `--self-signed`. Repeat for multiple SANs')
            [CompletionResult]::new('--protocol-token', '--protocol-token', [CompletionResultType]::ParameterName, 'The `:protocol` token the server requires on the HTTP/3 Extended-CONNECT (default `ssh3`). A mismatch is rejected with HTTP 421')
            [CompletionResult]::new('--allow-target', '--allow-target', [CompletionResultType]::ParameterName, 'Allow-list of `host:port` forward targets the server will dial. May be repeated. When empty, every requested `direct-tcp` open is accepted and dialed as requested (open relay — use with care)')
            [CompletionResult]::new('--fixed-target', '--fixed-target', [CompletionResultType]::ParameterName, 'Pin every accepted forward to this single `host:port` target regardless of what the peer requests (overrides `--allow-target`). Useful for a single-service bastion')
            [CompletionResult]::new('--require-authorization', '--require-authorization', [CompletionResultType]::ParameterName, 'Require this bearer/authorization value on the CONNECT request. When set, a CONNECT whose `Authorization` header does not match is rejected with HTTP 401')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--self-signed', '--self-signed', [CompletionResultType]::ParameterName, 'Dev-mode only: generate a self-signed certificate at startup instead of loading `--cert`/`--key`. Requires the binary to be built with the `server-selfsigned` feature; otherwise this flag errors. The SHA-256 SPKI pin of the generated cert is logged so a peer can pin it')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;status' {
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for the overview (overrides the global `--output`)')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json` (machine-readable overview)')
            [CompletionResult]::new('--detail', '--detail', [CompletionResultType]::ParameterName, 'Show verbose per-component state (resolved bind addresses, auth modes, last-error detail, per-forward counters) instead of the compact roll-up')
            [CompletionResult]::new('--watch', '--watch', [CompletionResultType]::ParameterName, 'Continuously refresh the overview in place instead of printing once')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;status-api' {
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('serve', 'serve', [CompletionResultType]::ParameterValue, 'Run the status API server in foreground (rare — supervisor normally hosts inline when `[status_api].enabled = true`)')
            [CompletionResult]::new('show', 'show', [CompletionResultType]::ParameterValue, 'Show whether the API is bound + how to reach it')
            [CompletionResult]::new('token', 'token', [CompletionResultType]::ParameterValue, 'Bearer-token management for the status API auth')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'spt;status-api;serve' {
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Override config path (otherwise inherits `--config`)')
            [CompletionResult]::new('--bind', '--bind', [CompletionResultType]::ParameterName, 'Override the bind address. Defaults to the value in `[status_api].bind`')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;status-api;show' {
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--detail', '--detail', [CompletionResultType]::ParameterName, 'Show the resolved auth mode and TLS state in addition to the bind')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;status-api;token' {
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('rotate', 'rotate', [CompletionResultType]::ParameterValue, 'Rotate the bearer token in the vault (only when `auth.mode = "bearer"` and the `token_from` SecretRef points at a writable backend)')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'spt;status-api;token;rotate' {
            [CompletionResult]::new('--bytes', '--bytes', [CompletionResultType]::ParameterName, 'Length in bytes of the random token before base64 encoding. Defaults to 32 (256-bit)')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--print-token', '--print-token', [CompletionResultType]::ParameterName, 'Print the new token to stdout (default: only print success + SecretRef). Useful for piping into other tooling')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;status-api;token;help' {
            [CompletionResult]::new('rotate', 'rotate', [CompletionResultType]::ParameterValue, 'Rotate the bearer token in the vault (only when `auth.mode = "bearer"` and the `token_from` SecretRef points at a writable backend)')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'spt;status-api;token;help;rotate' {
            break
        }
        'spt;status-api;token;help;help' {
            break
        }
        'spt;status-api;help' {
            [CompletionResult]::new('serve', 'serve', [CompletionResultType]::ParameterValue, 'Run the status API server in foreground (rare — supervisor normally hosts inline when `[status_api].enabled = true`)')
            [CompletionResult]::new('show', 'show', [CompletionResultType]::ParameterValue, 'Show whether the API is bound + how to reach it')
            [CompletionResult]::new('token', 'token', [CompletionResultType]::ParameterValue, 'Bearer-token management for the status API auth')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'spt;status-api;help;serve' {
            break
        }
        'spt;status-api;help;show' {
            break
        }
        'spt;status-api;help;token' {
            [CompletionResult]::new('rotate', 'rotate', [CompletionResultType]::ParameterValue, 'Rotate the bearer token in the vault (only when `auth.mode = "bearer"` and the `token_from` SecretRef points at a writable backend)')
            break
        }
        'spt;status-api;help;token;rotate' {
            break
        }
        'spt;status-api;help;help' {
            break
        }
        'spt;completion' {
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('generate', 'generate', [CompletionResultType]::ParameterValue, 'Print completions for a shell to stdout')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'spt;completion;generate' {
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;completion;help' {
            [CompletionResult]::new('generate', 'generate', [CompletionResultType]::ParameterValue, 'Print completions for a shell to stdout')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'spt;completion;help;generate' {
            break
        }
        'spt;completion;help;help' {
            break
        }
        'spt;about' {
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('list', 'list', [CompletionResultType]::ParameterValue, 'List every bundled library, one line per entry')
            [CompletionResult]::new('show', 'show', [CompletionResultType]::ParameterValue, 'Show detailed information for a single library')
            [CompletionResult]::new('licenses', 'licenses', [CompletionResultType]::ParameterValue, 'Group bundled libraries by SPDX license, with counts')
            [CompletionResult]::new('export', 'export', [CompletionResultType]::ParameterValue, 'Write attribution data to a file (format inferred from extension)')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'spt;about;list' {
            [CompletionResult]::new('--format', '--format', [CompletionResultType]::ParameterName, 'Output format')
            [CompletionResult]::new('--license', '--license', [CompletionResultType]::ParameterName, 'Filter by SPDX license substring (case-insensitive)')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--include-dev', '--include-dev', [CompletionResultType]::ParameterName, 'Include dev / test dependencies (default: runtime-only)')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;about;show' {
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;about;licenses' {
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;about;export' {
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;about;help' {
            [CompletionResult]::new('list', 'list', [CompletionResultType]::ParameterValue, 'List every bundled library, one line per entry')
            [CompletionResult]::new('show', 'show', [CompletionResultType]::ParameterValue, 'Show detailed information for a single library')
            [CompletionResult]::new('licenses', 'licenses', [CompletionResultType]::ParameterValue, 'Group bundled libraries by SPDX license, with counts')
            [CompletionResult]::new('export', 'export', [CompletionResultType]::ParameterValue, 'Write attribution data to a file (format inferred from extension)')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'spt;about;help;list' {
            break
        }
        'spt;about;help;show' {
            break
        }
        'spt;about;help;licenses' {
            break
        }
        'spt;about;help;export' {
            break
        }
        'spt;about;help;help' {
            break
        }
        'spt;kill' {
            [CompletionResult]::new('--name', '--name', [CompletionResultType]::ParameterName, 'Override the basename matched against running processes. Plain substring match; case-insensitive. Defaults to `spt` (Unix) / `spt.exe` (Windows)')
            [CompletionResult]::new('--timeout', '--timeout', [CompletionResultType]::ParameterName, 'Per-process grace window before the platform terminate returns. Defaults to 5 seconds. Honoured on Windows (`WaitForSingleObject`); informational on Unix where `SIGTERM` is asynchronous')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--force', '--force', [CompletionResultType]::ParameterName, 'Skip the graceful signal and go straight to a hard kill (`SIGKILL` / `TerminateProcess`). Default: send a graceful signal (`SIGTERM` / `TerminateProcess` with grace window) first')
            [CompletionResult]::new('--include-self', '--include-self', [CompletionResultType]::ParameterName, 'Include the current process in the kill list (the calling `spt` itself). Off by default — typical use is "kill all the other ones."')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Print what would be killed without actually signalling anything')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;update' {
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('check', 'check', [CompletionResultType]::ParameterValue, 'One-shot poll: print whether a newer release is available')
            [CompletionResult]::new('download', 'download', [CompletionResultType]::ParameterValue, 'Download the latest artifact to the staging directory without installing')
            [CompletionResult]::new('apply', 'apply', [CompletionResultType]::ParameterValue, 'Install the staged artifact (atomic swap, then optional restart)')
            [CompletionResult]::new('now', 'now', [CompletionResultType]::ParameterValue, 'Run `check` + `download` + `apply` in one go')
            [CompletionResult]::new('status', 'status', [CompletionResultType]::ParameterValue, 'Print current status: enabled flag, last check, latest version, next-scheduled tick, staged artifact')
            [CompletionResult]::new('history', 'history', [CompletionResultType]::ParameterValue, 'Past update events from the audit log')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'spt;update;check' {
            [CompletionResult]::new('--source', '--source', [CompletionResultType]::ParameterName, 'Bypass `[updater].source` and consult the named source kind. One of `github|url|static`. Optional override for one-off probes')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;update;download' {
            [CompletionResult]::new('--target', '--target', [CompletionResultType]::ParameterName, 'Target triple to fetch. Defaults to the running spt''s target')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;update;apply' {
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--no-restart', '--no-restart', [CompletionResultType]::ParameterName, 'Skip the post-install restart even when `[updater.action].restart_supervisor = true`')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;update;now' {
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--no-restart', '--no-restart', [CompletionResultType]::ParameterName, 'Skip the post-install restart')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;update;status' {
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Emit JSON instead of the human table')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;update;history' {
            [CompletionResult]::new('--limit', '--limit', [CompletionResultType]::ParameterName, 'How many past events to display. Default 10')
            [CompletionResult]::new('--config', '--config', [CompletionResultType]::ParameterName, 'Path to a single config file')
            [CompletionResult]::new('--config-dir', '--config-dir', [CompletionResultType]::ParameterName, 'Path to a directory of `*.toml` configs (loaded in lexical order)')
            [CompletionResult]::new('--config-url', '--config-url', [CompletionResultType]::ParameterName, 'HTTPS URL of a remote config to fetch')
            [CompletionResult]::new('--config-fingerprint', '--config-fingerprint', [CompletionResultType]::ParameterName, 'SHA-256 fingerprint pin for `--config-url`')
            [CompletionResult]::new('--state-dir', '--state-dir', [CompletionResultType]::ParameterName, 'Override the runtime state directory')
            [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Restrict operations to the named profile')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output format for command results')
            [CompletionResult]::new('--log-level', '--log-level', [CompletionResultType]::ParameterName, 'Tracing log level')
            [CompletionResult]::new('--color', '--color', [CompletionResultType]::ParameterName, 'Color policy for human output')
            [CompletionResult]::new('--portable', '--portable', [CompletionResultType]::ParameterName, 'Portable mode: keep all runtime state next to the executable instead of OS-standard locations (no OS install required)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Convenience alias for `--output json`')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('--quiet', '--quiet', [CompletionResultType]::ParameterName, 'Suppress non-essential output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity (repeat for more)')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'Disable color (legacy convenience flag; use `--color never`)')
            [CompletionResult]::new('--dry-run', '--dry-run', [CompletionResultType]::ParameterName, 'Show what would happen without making changes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'spt;update;help' {
            [CompletionResult]::new('check', 'check', [CompletionResultType]::ParameterValue, 'One-shot poll: print whether a newer release is available')
            [CompletionResult]::new('download', 'download', [CompletionResultType]::ParameterValue, 'Download the latest artifact to the staging directory without installing')
            [CompletionResult]::new('apply', 'apply', [CompletionResultType]::ParameterValue, 'Install the staged artifact (atomic swap, then optional restart)')
            [CompletionResult]::new('now', 'now', [CompletionResultType]::ParameterValue, 'Run `check` + `download` + `apply` in one go')
            [CompletionResult]::new('status', 'status', [CompletionResultType]::ParameterValue, 'Print current status: enabled flag, last check, latest version, next-scheduled tick, staged artifact')
            [CompletionResult]::new('history', 'history', [CompletionResultType]::ParameterValue, 'Past update events from the audit log')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'spt;update;help;check' {
            break
        }
        'spt;update;help;download' {
            break
        }
        'spt;update;help;apply' {
            break
        }
        'spt;update;help;now' {
            break
        }
        'spt;update;help;status' {
            break
        }
        'spt;update;help;history' {
            break
        }
        'spt;update;help;help' {
            break
        }
        'spt;help' {
            [CompletionResult]::new('config', 'config', [CompletionResultType]::ParameterValue, 'Manage configuration files (init, validate, diff, render, reload)')
            [CompletionResult]::new('profile', 'profile', [CompletionResultType]::ParameterValue, 'Manage SSH/SSH3 tunnel profiles')
            [CompletionResult]::new('forward', 'forward', [CompletionResultType]::ParameterValue, 'Manage forwards (local/remote TCP, UDP)')
            [CompletionResult]::new('tunnel', 'tunnel', [CompletionResultType]::ParameterValue, 'Run, inspect, and control tunnels')
            [CompletionResult]::new('service', 'service', [CompletionResultType]::ParameterValue, 'Install and control native services')
            [CompletionResult]::new('key', 'key', [CompletionResultType]::ParameterValue, 'Generate, inspect, and install SSH keys')
            [CompletionResult]::new('secret', 'secret', [CompletionResultType]::ParameterValue, 'Manage the secret vault and OS keychain references')
            [CompletionResult]::new('auth', 'auth', [CompletionResultType]::ParameterValue, 'Authentication helpers')
            [CompletionResult]::new('dns', 'dns', [CompletionResultType]::ParameterValue, 'Built-in DNS resolver and hosts-file management')
            [CompletionResult]::new('firewall', 'firewall', [CompletionResultType]::ParameterValue, 'Inspect and manage OS firewall / packet-filter rules')
            [CompletionResult]::new('log', 'log', [CompletionResultType]::ParameterValue, 'Log tailing, sink testing, and export')
            [CompletionResult]::new('observe', 'observe', [CompletionResultType]::ParameterValue, 'Metrics and Windows Event Log helpers')
            [CompletionResult]::new('event', 'event', [CompletionResultType]::ParameterValue, 'Event bindings and sinks')
            [CompletionResult]::new('stats', 'stats', [CompletionResultType]::ParameterValue, 'Statistics summaries and live counters')
            [CompletionResult]::new('session', 'session', [CompletionResultType]::ParameterValue, 'Inspect and manage active sessions')
            [CompletionResult]::new('ftp', 'ftp', [CompletionResultType]::ParameterValue, 'FTP→SFTP translator service')
            [CompletionResult]::new('sftp', 'sftp', [CompletionResultType]::ParameterValue, 'SFTP file operations and mount planning')
            [CompletionResult]::new('diagnose', 'diagnose', [CompletionResultType]::ParameterValue, 'Targeted diagnostics and support bundles')
            [CompletionResult]::new('benchmark', 'benchmark', [CompletionResultType]::ParameterValue, 'Controlled benchmarking against forwards')
            [CompletionResult]::new('mcp', 'mcp', [CompletionResultType]::ParameterValue, 'Built-in MCP server controls')
            [CompletionResult]::new('ssh3-serve', 'ssh3-serve', [CompletionResultType]::ParameterValue, 'Run the in-repo SSH3 (QUIC + HTTP/3) server end — the responder half of an spt↔spt SSH3 tunnel')
            [CompletionResult]::new('status', 'status', [CompletionResultType]::ParameterValue, 'Show overall app status — daemon, tunnels/profiles, forwards, and subsystems (status API, MCP, DNS, metrics, remote-config, events, services)')
            [CompletionResult]::new('status-api', 'status-api', [CompletionResultType]::ParameterValue, 'Controls for the read-only HTTP status API')
            [CompletionResult]::new('completion', 'completion', [CompletionResultType]::ParameterValue, 'Generate shell completions')
            [CompletionResult]::new('about', 'about', [CompletionResultType]::ParameterValue, 'List bundled libraries and their licenses')
            [CompletionResult]::new('kill', 'kill', [CompletionResultType]::ParameterValue, 'Terminate every running `spt` instance on this host')
            [CompletionResult]::new('update', 'update', [CompletionResultType]::ParameterValue, 'Embedded auto-updater (off by default). Manual commands work regardless of the `[updater].enabled` flag; the background polling thread is only spawned when explicitly enabled')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'spt;help;config' {
            [CompletionResult]::new('init', 'init', [CompletionResultType]::ParameterValue, 'Initialize a new config file from a template')
            [CompletionResult]::new('validate', 'validate', [CompletionResultType]::ParameterValue, 'Validate config syntax, schema, and obvious mistakes')
            [CompletionResult]::new('doctor', 'doctor', [CompletionResultType]::ParameterValue, 'Run environment checks against the loaded config')
            [CompletionResult]::new('render', 'render', [CompletionResultType]::ParameterValue, 'Render the canonical (optionally redacted) config')
            [CompletionResult]::new('diff', 'diff', [CompletionResultType]::ParameterValue, 'Diff two config files')
            [CompletionResult]::new('migrate', 'migrate', [CompletionResultType]::ParameterValue, 'Migrate a config between schema versions')
            [CompletionResult]::new('reload', 'reload', [CompletionResultType]::ParameterValue, 'Reload the running service''s config')
            [CompletionResult]::new('pull', 'pull', [CompletionResultType]::ParameterValue, 'Pull a remote config over HTTPS with pinning')
            [CompletionResult]::new('trust', 'trust', [CompletionResultType]::ParameterValue, 'Manage remote-config trust pins')
            [CompletionResult]::new('encrypt', 'encrypt', [CompletionResultType]::ParameterValue, 'Encrypt a plaintext config to a sealed `SPTENC1` envelope')
            [CompletionResult]::new('decrypt', 'decrypt', [CompletionResultType]::ParameterValue, 'Decrypt a sealed `SPTENC1` envelope back to plaintext TOML')
            [CompletionResult]::new('edit', 'edit', [CompletionResultType]::ParameterValue, 'Open a sealed config in `$EDITOR`; re-seal on save')
            [CompletionResult]::new('crypt', 'crypt', [CompletionResultType]::ParameterValue, 'Re-seal a sealed config under a new key (key rotation)')
            [CompletionResult]::new('gen-key', 'gen-key', [CompletionResultType]::ParameterValue, 'Generate a config-encryption key (X25519 keypair or raw PSK)')
            break
        }
        'spt;help;config;init' {
            break
        }
        'spt;help;config;validate' {
            break
        }
        'spt;help;config;doctor' {
            break
        }
        'spt;help;config;render' {
            break
        }
        'spt;help;config;diff' {
            break
        }
        'spt;help;config;migrate' {
            break
        }
        'spt;help;config;reload' {
            break
        }
        'spt;help;config;pull' {
            break
        }
        'spt;help;config;trust' {
            [CompletionResult]::new('add-url', 'add-url', [CompletionResultType]::ParameterValue, 'Add a pinned remote-config URL')
            break
        }
        'spt;help;config;trust;add-url' {
            break
        }
        'spt;help;config;encrypt' {
            break
        }
        'spt;help;config;decrypt' {
            break
        }
        'spt;help;config;edit' {
            break
        }
        'spt;help;config;crypt' {
            [CompletionResult]::new('rotate', 'rotate', [CompletionResultType]::ParameterValue, 'Re-seal a sealed config under a new key')
            break
        }
        'spt;help;config;crypt;rotate' {
            break
        }
        'spt;help;config;gen-key' {
            break
        }
        'spt;help;profile' {
            [CompletionResult]::new('list', 'list', [CompletionResultType]::ParameterValue, 'List configured profiles')
            [CompletionResult]::new('show', 'show', [CompletionResultType]::ParameterValue, 'Show the resolved profile (optionally redacted)')
            [CompletionResult]::new('add', 'add', [CompletionResultType]::ParameterValue, 'Add a new profile')
            [CompletionResult]::new('configure', 'configure', [CompletionResultType]::ParameterValue, 'Interactive TUI configurator')
            [CompletionResult]::new('set', 'set', [CompletionResultType]::ParameterValue, 'Set one or more `key=value` overrides')
            [CompletionResult]::new('enable', 'enable', [CompletionResultType]::ParameterValue, 'Enable a profile')
            [CompletionResult]::new('disable', 'disable', [CompletionResultType]::ParameterValue, 'Disable a profile')
            [CompletionResult]::new('remove', 'remove', [CompletionResultType]::ParameterValue, 'Remove a profile')
            [CompletionResult]::new('test', 'test', [CompletionResultType]::ParameterValue, 'Run targeted profile tests')
            break
        }
        'spt;help;profile;list' {
            break
        }
        'spt;help;profile;show' {
            break
        }
        'spt;help;profile;add' {
            break
        }
        'spt;help;profile;configure' {
            break
        }
        'spt;help;profile;set' {
            break
        }
        'spt;help;profile;enable' {
            break
        }
        'spt;help;profile;disable' {
            break
        }
        'spt;help;profile;remove' {
            break
        }
        'spt;help;profile;test' {
            break
        }
        'spt;help;forward' {
            [CompletionResult]::new('list', 'list', [CompletionResultType]::ParameterValue, 'List configured forwards')
            [CompletionResult]::new('show', 'show', [CompletionResultType]::ParameterValue, 'Show a forward')
            [CompletionResult]::new('add', 'add', [CompletionResultType]::ParameterValue, 'Add a forward')
            [CompletionResult]::new('explain', 'explain', [CompletionResultType]::ParameterValue, 'Explain how a forward is plumbed')
            [CompletionResult]::new('test', 'test', [CompletionResultType]::ParameterValue, 'Run targeted forward tests')
            [CompletionResult]::new('throttle', 'throttle', [CompletionResultType]::ParameterValue, 'Update throttle/limit knobs at runtime')
            [CompletionResult]::new('remove', 'remove', [CompletionResultType]::ParameterValue, 'Remove a forward')
            break
        }
        'spt;help;forward;list' {
            break
        }
        'spt;help;forward;show' {
            break
        }
        'spt;help;forward;add' {
            [CompletionResult]::new('local', 'local', [CompletionResultType]::ParameterValue, 'Local forward (`-L`)')
            [CompletionResult]::new('remote', 'remote', [CompletionResultType]::ParameterValue, 'Remote forward (`-R`)')
            [CompletionResult]::new('dynamic', 'dynamic', [CompletionResultType]::ParameterValue, 'Dynamic SOCKS4/SOCKS4A/SOCKS5/HTTP CONNECT proxy (`-D`)')
            break
        }
        'spt;help;forward;add;local' {
            break
        }
        'spt;help;forward;add;remote' {
            break
        }
        'spt;help;forward;add;dynamic' {
            break
        }
        'spt;help;forward;explain' {
            break
        }
        'spt;help;forward;test' {
            break
        }
        'spt;help;forward;throttle' {
            break
        }
        'spt;help;forward;remove' {
            break
        }
        'spt;help;tunnel' {
            [CompletionResult]::new('run', 'run', [CompletionResultType]::ParameterValue, 'Run configured tunnels')
            [CompletionResult]::new('status', 'status', [CompletionResultType]::ParameterValue, 'Show overall tunnel status')
            [CompletionResult]::new('stats', 'stats', [CompletionResultType]::ParameterValue, 'Live or one-shot stats')
            [CompletionResult]::new('sessions', 'sessions', [CompletionResultType]::ParameterValue, 'List active sessions')
            [CompletionResult]::new('stop', 'stop', [CompletionResultType]::ParameterValue, 'Stop tunnels')
            [CompletionResult]::new('reload', 'reload', [CompletionResultType]::ParameterValue, 'Reload running configuration')
            [CompletionResult]::new('health', 'health', [CompletionResultType]::ParameterValue, 'Health summary')
            [CompletionResult]::new('failover', 'failover', [CompletionResultType]::ParameterValue, 'Manually trigger failover for a profile')
            break
        }
        'spt;help;tunnel;run' {
            break
        }
        'spt;help;tunnel;status' {
            break
        }
        'spt;help;tunnel;stats' {
            break
        }
        'spt;help;tunnel;sessions' {
            break
        }
        'spt;help;tunnel;stop' {
            break
        }
        'spt;help;tunnel;reload' {
            break
        }
        'spt;help;tunnel;health' {
            break
        }
        'spt;help;tunnel;failover' {
            break
        }
        'spt;help;service' {
            [CompletionResult]::new('install', 'install', [CompletionResultType]::ParameterValue, 'Install a service for a config file')
            [CompletionResult]::new('uninstall', 'uninstall', [CompletionResultType]::ParameterValue, 'Uninstall a service')
            [CompletionResult]::new('start', 'start', [CompletionResultType]::ParameterValue, 'Start a service')
            [CompletionResult]::new('stop', 'stop', [CompletionResultType]::ParameterValue, 'Stop a service')
            [CompletionResult]::new('restart', 'restart', [CompletionResultType]::ParameterValue, 'Restart a service')
            [CompletionResult]::new('status', 'status', [CompletionResultType]::ParameterValue, 'Show service status')
            [CompletionResult]::new('render', 'render', [CompletionResultType]::ParameterValue, 'Render the would-be service unit')
            break
        }
        'spt;help;service;install' {
            break
        }
        'spt;help;service;uninstall' {
            break
        }
        'spt;help;service;start' {
            break
        }
        'spt;help;service;stop' {
            break
        }
        'spt;help;service;restart' {
            break
        }
        'spt;help;service;status' {
            break
        }
        'spt;help;service;render' {
            break
        }
        'spt;help;key' {
            [CompletionResult]::new('generate', 'generate', [CompletionResultType]::ParameterValue, 'Generate a new keypair')
            [CompletionResult]::new('inspect', 'inspect', [CompletionResultType]::ParameterValue, 'Inspect a key file')
            [CompletionResult]::new('public', 'public', [CompletionResultType]::ParameterValue, 'Print a public key (optionally to a file)')
            [CompletionResult]::new('change-passphrase', 'change-passphrase', [CompletionResultType]::ParameterValue, 'Change the passphrase on a private key')
            [CompletionResult]::new('sign-cert', 'sign-cert', [CompletionResultType]::ParameterValue, 'Sign an OpenSSH certificate')
            [CompletionResult]::new('verify-cert', 'verify-cert', [CompletionResultType]::ParameterValue, 'Verify an OpenSSH certificate')
            [CompletionResult]::new('install-public', 'install-public', [CompletionResultType]::ParameterValue, 'Install a public key on a remote host')
            break
        }
        'spt;help;key;generate' {
            break
        }
        'spt;help;key;inspect' {
            break
        }
        'spt;help;key;public' {
            break
        }
        'spt;help;key;change-passphrase' {
            break
        }
        'spt;help;key;sign-cert' {
            break
        }
        'spt;help;key;verify-cert' {
            break
        }
        'spt;help;key;install-public' {
            break
        }
        'spt;help;secret' {
            [CompletionResult]::new('store', 'store', [CompletionResultType]::ParameterValue, 'Initialize the secret store')
            [CompletionResult]::new('set', 'set', [CompletionResultType]::ParameterValue, 'Set a secret')
            [CompletionResult]::new('get', 'get', [CompletionResultType]::ParameterValue, 'Get a secret (redacted unless `--reveal`)')
            [CompletionResult]::new('list', 'list', [CompletionResultType]::ParameterValue, 'List known secret names')
            [CompletionResult]::new('rotate', 'rotate', [CompletionResultType]::ParameterValue, 'Rotate a secret')
            [CompletionResult]::new('remove', 'remove', [CompletionResultType]::ParameterValue, 'Remove a secret')
            [CompletionResult]::new('doctor', 'doctor', [CompletionResultType]::ParameterValue, 'Run secret backend health checks')
            break
        }
        'spt;help;secret;store' {
            [CompletionResult]::new('init', 'init', [CompletionResultType]::ParameterValue, 'Initialize a secret store')
            break
        }
        'spt;help;secret;store;init' {
            break
        }
        'spt;help;secret;set' {
            break
        }
        'spt;help;secret;get' {
            break
        }
        'spt;help;secret;list' {
            break
        }
        'spt;help;secret;rotate' {
            break
        }
        'spt;help;secret;remove' {
            break
        }
        'spt;help;secret;doctor' {
            break
        }
        'spt;help;auth' {
            [CompletionResult]::new('test', 'test', [CompletionResultType]::ParameterValue, 'Test authentication for a profile')
            [CompletionResult]::new('ssh3-login', 'ssh3-login', [CompletionResultType]::ParameterValue, 'Run an SSH3 OIDC device-flow login and optionally store the token')
            break
        }
        'spt;help;auth;test' {
            break
        }
        'spt;help;auth;ssh3-login' {
            break
        }
        'spt;help;dns' {
            [CompletionResult]::new('serve', 'serve', [CompletionResultType]::ParameterValue, 'Run the resolver')
            [CompletionResult]::new('status', 'status', [CompletionResultType]::ParameterValue, 'Resolver status')
            [CompletionResult]::new('query', 'query', [CompletionResultType]::ParameterValue, 'Issue a query against the configured resolver')
            [CompletionResult]::new('upstream', 'upstream', [CompletionResultType]::ParameterValue, 'Manage upstream resolvers')
            [CompletionResult]::new('record', 'record', [CompletionResultType]::ParameterValue, 'Manage managed records')
            [CompletionResult]::new('hosts', 'hosts', [CompletionResultType]::ParameterValue, 'Manage hosts-file rendering / apply / restore')
            break
        }
        'spt;help;dns;serve' {
            break
        }
        'spt;help;dns;status' {
            break
        }
        'spt;help;dns;query' {
            break
        }
        'spt;help;dns;upstream' {
            [CompletionResult]::new('set', 'set', [CompletionResultType]::ParameterValue, 'Replace the upstream list')
            break
        }
        'spt;help;dns;upstream;set' {
            break
        }
        'spt;help;dns;record' {
            [CompletionResult]::new('add', 'add', [CompletionResultType]::ParameterValue, 'Add a managed record')
            [CompletionResult]::new('remove', 'remove', [CompletionResultType]::ParameterValue, 'Remove a managed record')
            break
        }
        'spt;help;dns;record;add' {
            break
        }
        'spt;help;dns;record;remove' {
            break
        }
        'spt;help;dns;hosts' {
            [CompletionResult]::new('render', 'render', [CompletionResultType]::ParameterValue, 'Render the would-be hosts file')
            [CompletionResult]::new('apply', 'apply', [CompletionResultType]::ParameterValue, 'Apply the rendered hosts file')
            [CompletionResult]::new('restore', 'restore', [CompletionResultType]::ParameterValue, 'Restore a previous hosts backup')
            break
        }
        'spt;help;dns;hosts;render' {
            break
        }
        'spt;help;dns;hosts;apply' {
            break
        }
        'spt;help;dns;hosts;restore' {
            break
        }
        'spt;help;firewall' {
            [CompletionResult]::new('plan', 'plan', [CompletionResultType]::ParameterValue, 'Plan rules without applying')
            [CompletionResult]::new('apply', 'apply', [CompletionResultType]::ParameterValue, 'Apply rules (idempotent)')
            [CompletionResult]::new('remove', 'remove', [CompletionResultType]::ParameterValue, 'Remove rules')
            [CompletionResult]::new('status', 'status', [CompletionResultType]::ParameterValue, 'Show current applied state')
            [CompletionResult]::new('interfaces', 'interfaces', [CompletionResultType]::ParameterValue, 'List interfaces / bind targets')
            [CompletionResult]::new('bind-preview', 'bind-preview', [CompletionResultType]::ParameterValue, 'Preview the bind for a forward')
            [CompletionResult]::new('gateway', 'gateway', [CompletionResultType]::ParameterValue, 'Manage gateway/interface defaults in config')
            [CompletionResult]::new('policy', 'policy', [CompletionResultType]::ParameterValue, 'Inspect and manage GPO-style policy values')
            break
        }
        'spt;help;firewall;plan' {
            break
        }
        'spt;help;firewall;apply' {
            break
        }
        'spt;help;firewall;remove' {
            break
        }
        'spt;help;firewall;status' {
            break
        }
        'spt;help;firewall;interfaces' {
            break
        }
        'spt;help;firewall;bind-preview' {
            break
        }
        'spt;help;firewall;gateway' {
            [CompletionResult]::new('show', 'show', [CompletionResultType]::ParameterValue, 'Show configured interface/gateway policy')
            [CompletionResult]::new('set', 'set', [CompletionResultType]::ParameterValue, 'Update configured interface/gateway policy')
            break
        }
        'spt;help;firewall;gateway;show' {
            break
        }
        'spt;help;firewall;gateway;set' {
            break
        }
        'spt;help;firewall;policy' {
            [CompletionResult]::new('list', 'list', [CompletionResultType]::ParameterValue, 'List known policy bindings')
            [CompletionResult]::new('show', 'show', [CompletionResultType]::ParameterValue, 'Show live registry policy overlay and effective network/firewall fields')
            [CompletionResult]::new('set', 'set', [CompletionResultType]::ParameterValue, 'Set a policy value in HKCU/HKLM')
            [CompletionResult]::new('unset', 'unset', [CompletionResultType]::ParameterValue, 'Remove a policy value from HKCU/HKLM')
            break
        }
        'spt;help;firewall;policy;list' {
            break
        }
        'spt;help;firewall;policy;show' {
            break
        }
        'spt;help;firewall;policy;set' {
            break
        }
        'spt;help;firewall;policy;unset' {
            break
        }
        'spt;help;log' {
            [CompletionResult]::new('tail', 'tail', [CompletionResultType]::ParameterValue, 'Tail logs')
            [CompletionResult]::new('remote', 'remote', [CompletionResultType]::ParameterValue, 'Manage configured remote log sinks')
            [CompletionResult]::new('test', 'test', [CompletionResultType]::ParameterValue, 'Probe a configured sink')
            [CompletionResult]::new('export', 'export', [CompletionResultType]::ParameterValue, 'Export logs to a structured format')
            break
        }
        'spt;help;log;tail' {
            break
        }
        'spt;help;log;remote' {
            [CompletionResult]::new('list', 'list', [CompletionResultType]::ParameterValue, 'List configured remote log sinks')
            [CompletionResult]::new('test', 'test', [CompletionResultType]::ParameterValue, 'Probe a configured remote log sink')
            [CompletionResult]::new('status', 'status', [CompletionResultType]::ParameterValue, 'Show local delivery status for a remote log sink')
            [CompletionResult]::new('drain', 'drain', [CompletionResultType]::ParameterValue, 'Drain a remote log sink''s disk spool')
            break
        }
        'spt;help;log;remote;list' {
            break
        }
        'spt;help;log;remote;test' {
            break
        }
        'spt;help;log;remote;status' {
            break
        }
        'spt;help;log;remote;drain' {
            break
        }
        'spt;help;log;test' {
            break
        }
        'spt;help;log;export' {
            break
        }
        'spt;help;observe' {
            [CompletionResult]::new('metrics', 'metrics', [CompletionResultType]::ParameterValue, 'Print metrics')
            [CompletionResult]::new('windows-event', 'windows-event', [CompletionResultType]::ParameterValue, 'Windows Event Log integration')
            break
        }
        'spt;help;observe;metrics' {
            break
        }
        'spt;help;observe;windows-event' {
            [CompletionResult]::new('install-source', 'install-source', [CompletionResultType]::ParameterValue, 'Install a Windows Event Log source')
            [CompletionResult]::new('uninstall-source', 'uninstall-source', [CompletionResultType]::ParameterValue, 'Uninstall a Windows Event Log source')
            [CompletionResult]::new('test', 'test', [CompletionResultType]::ParameterValue, 'Emit a test event')
            break
        }
        'spt;help;observe;windows-event;install-source' {
            break
        }
        'spt;help;observe;windows-event;uninstall-source' {
            break
        }
        'spt;help;observe;windows-event;test' {
            break
        }
        'spt;help;event' {
            [CompletionResult]::new('list', 'list', [CompletionResultType]::ParameterValue, 'List configured event bindings')
            [CompletionResult]::new('test', 'test', [CompletionResultType]::ParameterValue, 'Trigger a binding by name')
            [CompletionResult]::new('replay', 'replay', [CompletionResultType]::ParameterValue, 'Replay historical events through a binding')
            [CompletionResult]::new('sink', 'sink', [CompletionResultType]::ParameterValue, 'Manage event sinks')
            break
        }
        'spt;help;event;list' {
            break
        }
        'spt;help;event;test' {
            break
        }
        'spt;help;event;replay' {
            break
        }
        'spt;help;event;sink' {
            [CompletionResult]::new('test', 'test', [CompletionResultType]::ParameterValue, 'Test a sink')
            [CompletionResult]::new('list', 'list', [CompletionResultType]::ParameterValue, 'List configured sinks')
            break
        }
        'spt;help;event;sink;test' {
            break
        }
        'spt;help;event;sink;list' {
            break
        }
        'spt;help;stats' {
            [CompletionResult]::new('summary', 'summary', [CompletionResultType]::ParameterValue, 'Snapshot summary')
            [CompletionResult]::new('live', 'live', [CompletionResultType]::ParameterValue, 'Live updating view')
            [CompletionResult]::new('connections', 'connections', [CompletionResultType]::ParameterValue, 'Connection table')
            [CompletionResult]::new('throughput', 'throughput', [CompletionResultType]::ParameterValue, 'Throughput windows')
            [CompletionResult]::new('errors', 'errors', [CompletionResultType]::ParameterValue, 'Recent errors')
            [CompletionResult]::new('export', 'export', [CompletionResultType]::ParameterValue, 'Export stats to a file')
            break
        }
        'spt;help;stats;summary' {
            break
        }
        'spt;help;stats;live' {
            break
        }
        'spt;help;stats;connections' {
            break
        }
        'spt;help;stats;throughput' {
            break
        }
        'spt;help;stats;errors' {
            break
        }
        'spt;help;stats;export' {
            break
        }
        'spt;help;session' {
            [CompletionResult]::new('list', 'list', [CompletionResultType]::ParameterValue, 'List sessions')
            [CompletionResult]::new('show', 'show', [CompletionResultType]::ParameterValue, 'Show a session')
            [CompletionResult]::new('close', 'close', [CompletionResultType]::ParameterValue, 'Close a session')
            [CompletionResult]::new('drain', 'drain', [CompletionResultType]::ParameterValue, 'Drain sessions for a profile')
            [CompletionResult]::new('top', 'top', [CompletionResultType]::ParameterValue, 'Top-style live view')
            break
        }
        'spt;help;session;list' {
            break
        }
        'spt;help;session;show' {
            break
        }
        'spt;help;session;close' {
            break
        }
        'spt;help;session;drain' {
            break
        }
        'spt;help;session;top' {
            break
        }
        'spt;help;ftp' {
            [CompletionResult]::new('translator', 'translator', [CompletionResultType]::ParameterValue, 'Run / manage the FTP→SFTP translator service')
            break
        }
        'spt;help;ftp;translator' {
            [CompletionResult]::new('serve', 'serve', [CompletionResultType]::ParameterValue, 'Start the FTP translator listening on `--bind`')
            break
        }
        'spt;help;ftp;translator;serve' {
            break
        }
        'spt;help;sftp' {
            [CompletionResult]::new('test', 'test', [CompletionResultType]::ParameterValue, 'Connect to the profile and open the SFTP subsystem')
            [CompletionResult]::new('list', 'list', [CompletionResultType]::ParameterValue, 'List a remote directory')
            [CompletionResult]::new('stat', 'stat', [CompletionResultType]::ParameterValue, 'Show metadata for a remote path')
            [CompletionResult]::new('get', 'get', [CompletionResultType]::ParameterValue, 'Download a remote file')
            [CompletionResult]::new('put', 'put', [CompletionResultType]::ParameterValue, 'Upload a local file')
            [CompletionResult]::new('mkdir', 'mkdir', [CompletionResultType]::ParameterValue, 'Create a remote directory')
            [CompletionResult]::new('rm', 'rm', [CompletionResultType]::ParameterValue, 'Remove a remote file')
            [CompletionResult]::new('rmdir', 'rmdir', [CompletionResultType]::ParameterValue, 'Remove a remote directory')
            [CompletionResult]::new('rename', 'rename', [CompletionResultType]::ParameterValue, 'Rename a remote file or directory')
            [CompletionResult]::new('cat', 'cat', [CompletionResultType]::ParameterValue, 'Print a remote file (with a size cap)')
            [CompletionResult]::new('tail', 'tail', [CompletionResultType]::ParameterValue, 'Print the trailing bytes of a remote file')
            [CompletionResult]::new('chmod', 'chmod', [CompletionResultType]::ParameterValue, 'Change POSIX permissions on a remote path')
            [CompletionResult]::new('symlink', 'symlink', [CompletionResultType]::ParameterValue, 'Create a remote symbolic link')
            [CompletionResult]::new('readlink', 'readlink', [CompletionResultType]::ParameterValue, 'Read the target of a remote symbolic link')
            [CompletionResult]::new('realpath', 'realpath', [CompletionResultType]::ParameterValue, 'Canonicalise a remote path')
            [CompletionResult]::new('put-recursive', 'put-recursive', [CompletionResultType]::ParameterValue, 'Mirror a local directory tree onto the server (recursive `put`)')
            [CompletionResult]::new('get-recursive', 'get-recursive', [CompletionResultType]::ParameterValue, 'Mirror a remote directory tree onto the local filesystem (recursive `get`)')
            [CompletionResult]::new('mount', 'mount', [CompletionResultType]::ParameterValue, 'Manage SFTP-backed filesystem mount entries')
            [CompletionResult]::new('drive', 'drive', [CompletionResultType]::ParameterValue, 'Manage SFTP-backed Windows drive entries')
            [CompletionResult]::new('umount', 'umount', [CompletionResultType]::ParameterValue, 'Tear down an SFTP-backed filesystem mount (shorthand for `spt sftp mount stop`)')
            break
        }
        'spt;help;sftp;test' {
            break
        }
        'spt;help;sftp;list' {
            break
        }
        'spt;help;sftp;stat' {
            break
        }
        'spt;help;sftp;get' {
            break
        }
        'spt;help;sftp;put' {
            break
        }
        'spt;help;sftp;mkdir' {
            break
        }
        'spt;help;sftp;rm' {
            break
        }
        'spt;help;sftp;rmdir' {
            break
        }
        'spt;help;sftp;rename' {
            break
        }
        'spt;help;sftp;cat' {
            break
        }
        'spt;help;sftp;tail' {
            break
        }
        'spt;help;sftp;chmod' {
            break
        }
        'spt;help;sftp;symlink' {
            break
        }
        'spt;help;sftp;readlink' {
            break
        }
        'spt;help;sftp;realpath' {
            break
        }
        'spt;help;sftp;put-recursive' {
            break
        }
        'spt;help;sftp;get-recursive' {
            break
        }
        'spt;help;sftp;mount' {
            [CompletionResult]::new('list', 'list', [CompletionResultType]::ParameterValue, 'List configured filesystem mounts')
            [CompletionResult]::new('add', 'add', [CompletionResultType]::ParameterValue, 'Add a filesystem mount entry to the config')
            [CompletionResult]::new('remove', 'remove', [CompletionResultType]::ParameterValue, 'Remove a filesystem mount entry from the config')
            [CompletionResult]::new('plan', 'plan', [CompletionResultType]::ParameterValue, 'Render the platform plan for a configured or proposed mount')
            [CompletionResult]::new('start', 'start', [CompletionResultType]::ParameterValue, 'Start an SFTP-backed filesystem mount')
            [CompletionResult]::new('stop', 'stop', [CompletionResultType]::ParameterValue, 'Tear down an SFTP-backed filesystem mount')
            break
        }
        'spt;help;sftp;mount;list' {
            break
        }
        'spt;help;sftp;mount;add' {
            break
        }
        'spt;help;sftp;mount;remove' {
            break
        }
        'spt;help;sftp;mount;plan' {
            break
        }
        'spt;help;sftp;mount;start' {
            break
        }
        'spt;help;sftp;mount;stop' {
            break
        }
        'spt;help;sftp;drive' {
            [CompletionResult]::new('list', 'list', [CompletionResultType]::ParameterValue, 'List configured Windows drive mounts')
            [CompletionResult]::new('add', 'add', [CompletionResultType]::ParameterValue, 'Add a Windows drive mount entry to the config')
            [CompletionResult]::new('remove', 'remove', [CompletionResultType]::ParameterValue, 'Remove a Windows drive mount entry from the config')
            [CompletionResult]::new('plan', 'plan', [CompletionResultType]::ParameterValue, 'Render the platform plan for a configured or proposed drive mount')
            break
        }
        'spt;help;sftp;drive;list' {
            break
        }
        'spt;help;sftp;drive;add' {
            break
        }
        'spt;help;sftp;drive;remove' {
            break
        }
        'spt;help;sftp;drive;plan' {
            break
        }
        'spt;help;sftp;umount' {
            break
        }
        'spt;help;diagnose' {
            [CompletionResult]::new('run', 'run', [CompletionResultType]::ParameterValue, 'Run a battery of diagnostic checks')
            [CompletionResult]::new('network', 'network', [CompletionResultType]::ParameterValue, 'Network checks')
            [CompletionResult]::new('auth', 'auth', [CompletionResultType]::ParameterValue, 'Authentication checks for a profile')
            [CompletionResult]::new('trust', 'trust', [CompletionResultType]::ParameterValue, 'Trust checks for a profile')
            [CompletionResult]::new('dns', 'dns', [CompletionResultType]::ParameterValue, 'DNS checks')
            [CompletionResult]::new('bind', 'bind', [CompletionResultType]::ParameterValue, 'Bind checks')
            [CompletionResult]::new('port', 'port', [CompletionResultType]::ParameterValue, 'Probe a host:port')
            [CompletionResult]::new('service', 'service', [CompletionResultType]::ParameterValue, 'Service-manager checks')
            [CompletionResult]::new('secrets', 'secrets', [CompletionResultType]::ParameterValue, 'Secret-backend checks')
            [CompletionResult]::new('observability', 'observability', [CompletionResultType]::ParameterValue, 'Observability sink checks')
            [CompletionResult]::new('mcp', 'mcp', [CompletionResultType]::ParameterValue, 'MCP server checks')
            [CompletionResult]::new('bundle', 'bundle', [CompletionResultType]::ParameterValue, 'Build a redacted support bundle')
            break
        }
        'spt;help;diagnose;run' {
            break
        }
        'spt;help;diagnose;network' {
            break
        }
        'spt;help;diagnose;auth' {
            break
        }
        'spt;help;diagnose;trust' {
            break
        }
        'spt;help;diagnose;dns' {
            break
        }
        'spt;help;diagnose;bind' {
            break
        }
        'spt;help;diagnose;port' {
            break
        }
        'spt;help;diagnose;service' {
            break
        }
        'spt;help;diagnose;secrets' {
            break
        }
        'spt;help;diagnose;observability' {
            break
        }
        'spt;help;diagnose;mcp' {
            break
        }
        'spt;help;diagnose;bundle' {
            break
        }
        'spt;help;benchmark' {
            [CompletionResult]::new('run', 'run', [CompletionResultType]::ParameterValue, 'End-to-end mixed workload')
            [CompletionResult]::new('latency', 'latency', [CompletionResultType]::ParameterValue, 'Latency-focused benchmark')
            [CompletionResult]::new('throughput', 'throughput', [CompletionResultType]::ParameterValue, 'Throughput-focused benchmark')
            [CompletionResult]::new('udp', 'udp', [CompletionResultType]::ParameterValue, 'UDP benchmark (SSH3 only)')
            [CompletionResult]::new('reconnect', 'reconnect', [CompletionResultType]::ParameterValue, 'Reconnect benchmark')
            [CompletionResult]::new('dns', 'dns', [CompletionResultType]::ParameterValue, 'DNS benchmark')
            [CompletionResult]::new('limits', 'limits', [CompletionResultType]::ParameterValue, 'Limit/throttle introspection')
            [CompletionResult]::new('report', 'report', [CompletionResultType]::ParameterValue, 'Report tooling')
            break
        }
        'spt;help;benchmark;run' {
            break
        }
        'spt;help;benchmark;latency' {
            break
        }
        'spt;help;benchmark;throughput' {
            break
        }
        'spt;help;benchmark;udp' {
            break
        }
        'spt;help;benchmark;reconnect' {
            break
        }
        'spt;help;benchmark;dns' {
            break
        }
        'spt;help;benchmark;limits' {
            break
        }
        'spt;help;benchmark;report' {
            [CompletionResult]::new('compare', 'compare', [CompletionResultType]::ParameterValue, 'Compare two benchmark results')
            [CompletionResult]::new('export', 'export', [CompletionResultType]::ParameterValue, 'Export a benchmark result')
            break
        }
        'spt;help;benchmark;report;compare' {
            break
        }
        'spt;help;benchmark;report;export' {
            break
        }
        'spt;help;mcp' {
            [CompletionResult]::new('serve', 'serve', [CompletionResultType]::ParameterValue, 'Run the MCP server')
            [CompletionResult]::new('inspect', 'inspect', [CompletionResultType]::ParameterValue, 'Inspect MCP capabilities, resources, tools')
            [CompletionResult]::new('policy', 'policy', [CompletionResultType]::ParameterValue, 'Manage the MCP policy')
            break
        }
        'spt;help;mcp;serve' {
            break
        }
        'spt;help;mcp;inspect' {
            break
        }
        'spt;help;mcp;policy' {
            [CompletionResult]::new('show', 'show', [CompletionResultType]::ParameterValue, 'Show the current policy')
            [CompletionResult]::new('set', 'set', [CompletionResultType]::ParameterValue, 'Update one or more policy keys')
            break
        }
        'spt;help;mcp;policy;show' {
            break
        }
        'spt;help;mcp;policy;set' {
            break
        }
        'spt;help;ssh3-serve' {
            break
        }
        'spt;help;status' {
            break
        }
        'spt;help;status-api' {
            [CompletionResult]::new('serve', 'serve', [CompletionResultType]::ParameterValue, 'Run the status API server in foreground (rare — supervisor normally hosts inline when `[status_api].enabled = true`)')
            [CompletionResult]::new('show', 'show', [CompletionResultType]::ParameterValue, 'Show whether the API is bound + how to reach it')
            [CompletionResult]::new('token', 'token', [CompletionResultType]::ParameterValue, 'Bearer-token management for the status API auth')
            break
        }
        'spt;help;status-api;serve' {
            break
        }
        'spt;help;status-api;show' {
            break
        }
        'spt;help;status-api;token' {
            [CompletionResult]::new('rotate', 'rotate', [CompletionResultType]::ParameterValue, 'Rotate the bearer token in the vault (only when `auth.mode = "bearer"` and the `token_from` SecretRef points at a writable backend)')
            break
        }
        'spt;help;status-api;token;rotate' {
            break
        }
        'spt;help;completion' {
            [CompletionResult]::new('generate', 'generate', [CompletionResultType]::ParameterValue, 'Print completions for a shell to stdout')
            break
        }
        'spt;help;completion;generate' {
            break
        }
        'spt;help;about' {
            [CompletionResult]::new('list', 'list', [CompletionResultType]::ParameterValue, 'List every bundled library, one line per entry')
            [CompletionResult]::new('show', 'show', [CompletionResultType]::ParameterValue, 'Show detailed information for a single library')
            [CompletionResult]::new('licenses', 'licenses', [CompletionResultType]::ParameterValue, 'Group bundled libraries by SPDX license, with counts')
            [CompletionResult]::new('export', 'export', [CompletionResultType]::ParameterValue, 'Write attribution data to a file (format inferred from extension)')
            break
        }
        'spt;help;about;list' {
            break
        }
        'spt;help;about;show' {
            break
        }
        'spt;help;about;licenses' {
            break
        }
        'spt;help;about;export' {
            break
        }
        'spt;help;kill' {
            break
        }
        'spt;help;update' {
            [CompletionResult]::new('check', 'check', [CompletionResultType]::ParameterValue, 'One-shot poll: print whether a newer release is available')
            [CompletionResult]::new('download', 'download', [CompletionResultType]::ParameterValue, 'Download the latest artifact to the staging directory without installing')
            [CompletionResult]::new('apply', 'apply', [CompletionResultType]::ParameterValue, 'Install the staged artifact (atomic swap, then optional restart)')
            [CompletionResult]::new('now', 'now', [CompletionResultType]::ParameterValue, 'Run `check` + `download` + `apply` in one go')
            [CompletionResult]::new('status', 'status', [CompletionResultType]::ParameterValue, 'Print current status: enabled flag, last check, latest version, next-scheduled tick, staged artifact')
            [CompletionResult]::new('history', 'history', [CompletionResultType]::ParameterValue, 'Past update events from the audit log')
            break
        }
        'spt;help;update;check' {
            break
        }
        'spt;help;update;download' {
            break
        }
        'spt;help;update;apply' {
            break
        }
        'spt;help;update;now' {
            break
        }
        'spt;help;update;status' {
            break
        }
        'spt;help;update;history' {
            break
        }
        'spt;help;help' {
            break
        }
    })

    $completions.Where{ $_.CompletionText -like "$wordToComplete*" } |
        Sort-Object -Property ListItemText
}
