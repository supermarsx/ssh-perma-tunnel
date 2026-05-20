
use builtin;
use str;

set edit:completion:arg-completer[spt] = {|@words|
    fn spaces {|n|
        builtin:repeat $n ' ' | str:join ''
    }
    fn cand {|text desc|
        edit:complex-candidate $text &display=$text' '(spaces (- 14 (wcswidth $text)))$desc
    }
    var command = 'spt'
    for word $words[1..-1] {
        if (str:has-prefix $word '-') {
            break
        }
        set command = $command';'$word
    }
    var completions = [
        &'spt'= {
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --json 'Convenience alias for `--output json`'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
            cand config 'Manage configuration files (init, validate, diff, render, reload)'
            cand profile 'Manage SSH/SSH3 tunnel profiles'
            cand forward 'Manage forwards (local/remote TCP, UDP)'
            cand tunnel 'Run, inspect, and control tunnels'
            cand service 'Install and control native services'
            cand key 'Generate, inspect, and install SSH keys'
            cand secret 'Manage the secret vault and OS keychain references'
            cand auth 'Authentication helpers'
            cand dns 'Built-in DNS resolver and hosts-file management'
            cand firewall 'Inspect and manage OS firewall / packet-filter rules'
            cand log 'Log tailing, sink testing, and export'
            cand observe 'Metrics and Windows Event Log helpers'
            cand event 'Event bindings and sinks'
            cand stats 'Statistics summaries and live counters'
            cand session 'Inspect and manage active sessions'
            cand diagnose 'Targeted diagnostics and support bundles'
            cand benchmark 'Controlled benchmarking against forwards'
            cand mcp 'Built-in MCP server controls'
            cand status 'Read-only status API controls (plan §t4-e5)'
            cand completion 'Generate shell completions'
            cand help 'Print this message or the help of the given subcommand(s)'
        }
        &'spt;config'= {
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --json 'Convenience alias for `--output json`'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
            cand init 'Initialize a new config file from a template'
            cand validate 'Validate config syntax, schema, and obvious mistakes'
            cand doctor 'Run environment checks against the loaded config'
            cand render 'Render the canonical (optionally redacted) config'
            cand diff 'Diff two config files'
            cand migrate 'Migrate a config between schema versions'
            cand reload 'Reload the running service''s config'
            cand pull 'Pull a remote config over HTTPS with pinning'
            cand trust 'Manage remote-config trust pins'
            cand encrypt 'Encrypt a plaintext config to a sealed `SPTENC1` envelope'
            cand decrypt 'Decrypt a sealed `SPTENC1` envelope back to plaintext TOML'
            cand edit 'Open a sealed config in `$EDITOR`; re-seal on save'
            cand crypt 'Re-seal a sealed config under a new key (key rotation)'
            cand help 'Print this message or the help of the given subcommand(s)'
        }
        &'spt;config;init'= {
            cand --path 'Output path for the generated config'
            cand --example 'Template to seed the config from'
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --json 'Convenience alias for `--output json`'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;config;validate'= {
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --strict 'Reject unknown fields and friendly aliases'
            cand --json 'Convenience alias for `--output json`'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;config;doctor'= {
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --network 'Run network checks'
            cand --service 'Run service-manager checks'
            cand --secrets 'Run secret backend checks'
            cand --dns 'Run DNS checks'
            cand --observability 'Run observability sink checks'
            cand --json 'Convenience alias for `--output json`'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;config;render'= {
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --redacted 'Redact secret values'
            cand --json 'Render as JSON instead of canonical TOML'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;config;diff'= {
            cand --from 'Base config'
            cand --to 'Candidate config'
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --json 'Convenience alias for `--output json`'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;config;migrate'= {
            cand --from-version 'Source schema version'
            cand --to-version 'Target schema version'
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --json 'Convenience alias for `--output json`'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;config;reload'= {
            cand --mode 'Reload mechanism to use'
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --wait 'Wait for reload to complete'
            cand --json 'Convenience alias for `--output json`'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;config;pull'= {
            cand --url 'HTTPS URL to fetch'
            cand --fingerprint 'SHA-256 fingerprint pin'
            cand --out 'Output path'
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --cache 'Update the local atomic cache'
            cand --json 'Convenience alias for `--output json`'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;config;trust'= {
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --json 'Convenience alias for `--output json`'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
            cand add-url 'Add a pinned remote-config URL'
            cand help 'Print this message or the help of the given subcommand(s)'
        }
        &'spt;config;trust;add-url'= {
            cand --url 'HTTPS URL to trust'
            cand --fingerprint 'SHA-256 fingerprint pin'
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --json 'Convenience alias for `--output json`'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;config;trust;help'= {
            cand add-url 'Add a pinned remote-config URL'
            cand help 'Print this message or the help of the given subcommand(s)'
        }
        &'spt;config;trust;help;add-url'= {
        }
        &'spt;config;trust;help;help'= {
        }
        &'spt;config;encrypt'= {
            cand --out 'Output path (default: `<IN>.sealed`)'
            cand --passphrase-from 'Read passphrase from a secret reference (e.g. `secret://env/SPT_PP`)'
            cand --recipient 'One or more X25519 recipient public keys (base64)'
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --use-vault-master 'Use the keychain-resident vault master key'
            cand --force 'Overwrite an existing output file'
            cand --json 'Convenience alias for `--output json`'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;config;decrypt'= {
            cand --out 'Output path. If unset, write the cleartext to stdout'
            cand --passphrase-from 'Read passphrase from a secret reference'
            cand --recipient-key 'Path to an X25519 private-key file (32 raw bytes or base64 line)'
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --json 'Convenience alias for `--output json`'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;config;edit'= {
            cand --passphrase-from 'Read passphrase from a secret reference'
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --json 'Convenience alias for `--output json`'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;config;crypt'= {
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --json 'Convenience alias for `--output json`'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
            cand rotate 'Re-seal a sealed config under a new key'
            cand help 'Print this message or the help of the given subcommand(s)'
        }
        &'spt;config;crypt;rotate'= {
            cand --new-passphrase-from 'New passphrase, read from a secret reference'
            cand --new-recipient 'New X25519 recipient public keys (base64)'
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --json 'Convenience alias for `--output json`'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;config;crypt;help'= {
            cand rotate 'Re-seal a sealed config under a new key'
            cand help 'Print this message or the help of the given subcommand(s)'
        }
        &'spt;config;crypt;help;rotate'= {
        }
        &'spt;config;crypt;help;help'= {
        }
        &'spt;config;help'= {
            cand init 'Initialize a new config file from a template'
            cand validate 'Validate config syntax, schema, and obvious mistakes'
            cand doctor 'Run environment checks against the loaded config'
            cand render 'Render the canonical (optionally redacted) config'
            cand diff 'Diff two config files'
            cand migrate 'Migrate a config between schema versions'
            cand reload 'Reload the running service''s config'
            cand pull 'Pull a remote config over HTTPS with pinning'
            cand trust 'Manage remote-config trust pins'
            cand encrypt 'Encrypt a plaintext config to a sealed `SPTENC1` envelope'
            cand decrypt 'Decrypt a sealed `SPTENC1` envelope back to plaintext TOML'
            cand edit 'Open a sealed config in `$EDITOR`; re-seal on save'
            cand crypt 'Re-seal a sealed config under a new key (key rotation)'
            cand help 'Print this message or the help of the given subcommand(s)'
        }
        &'spt;config;help;init'= {
        }
        &'spt;config;help;validate'= {
        }
        &'spt;config;help;doctor'= {
        }
        &'spt;config;help;render'= {
        }
        &'spt;config;help;diff'= {
        }
        &'spt;config;help;migrate'= {
        }
        &'spt;config;help;reload'= {
        }
        &'spt;config;help;pull'= {
        }
        &'spt;config;help;trust'= {
            cand add-url 'Add a pinned remote-config URL'
        }
        &'spt;config;help;trust;add-url'= {
        }
        &'spt;config;help;encrypt'= {
        }
        &'spt;config;help;decrypt'= {
        }
        &'spt;config;help;edit'= {
        }
        &'spt;config;help;crypt'= {
            cand rotate 'Re-seal a sealed config under a new key'
        }
        &'spt;config;help;crypt;rotate'= {
        }
        &'spt;config;help;help'= {
        }
        &'spt;profile'= {
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --json 'Convenience alias for `--output json`'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
            cand list 'List configured profiles'
            cand show 'Show the resolved profile (optionally redacted)'
            cand add 'Add a new profile'
            cand configure 'Interactive TUI configurator'
            cand set 'Set one or more `key=value` overrides'
            cand enable 'Enable a profile'
            cand disable 'Disable a profile'
            cand remove 'Remove a profile'
            cand test 'Run targeted profile tests'
            cand help 'Print this message or the help of the given subcommand(s)'
        }
        &'spt;profile;list'= {
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --json 'JSON output'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;profile;show'= {
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --redacted 'Redact secret fields'
            cand --json 'JSON output'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;profile;add'= {
            cand --protocol 'Protocol selector'
            cand --host 'Remote host'
            cand --user 'SSH user'
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --json 'Convenience alias for `--output json`'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;profile;configure'= {
            cand --name 'Profile name (created if missing)'
            cand --from-template 'Seed from a built-in template'
            cand --field 'One or more `KEY=VALUE` field overrides applied non-interactively. Implies `--no-tui` semantics for `--field` updates. Repeatable'
            cand --from 'Apply a TOML patch from `<file.toml>` to the profile (non-interactive). The file may contain a single `[profile]` table or a bare key/value document; both shapes are merged into the addressed `[[profiles]]` entry'
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --tui 'Force the TUI wizard'
            cand --no-tui 'Disable the TUI wizard (non-interactive)'
            cand --json 'Convenience alias for `--output json`'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;profile;set'= {
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --json 'Convenience alias for `--output json`'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;profile;enable'= {
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --json 'Convenience alias for `--output json`'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;profile;disable'= {
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --json 'Convenience alias for `--output json`'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;profile;remove'= {
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --json 'Convenience alias for `--output json`'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;profile;test'= {
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --connect-only 'Only test connect'
            cand --bind-only 'Only test bind'
            cand --auth-only 'Only test auth'
            cand --trust-only 'Only test trust (host-key/TLS pin)'
            cand --dns-only 'Only test DNS'
            cand --json 'Convenience alias for `--output json`'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;profile;help'= {
            cand list 'List configured profiles'
            cand show 'Show the resolved profile (optionally redacted)'
            cand add 'Add a new profile'
            cand configure 'Interactive TUI configurator'
            cand set 'Set one or more `key=value` overrides'
            cand enable 'Enable a profile'
            cand disable 'Disable a profile'
            cand remove 'Remove a profile'
            cand test 'Run targeted profile tests'
            cand help 'Print this message or the help of the given subcommand(s)'
        }
        &'spt;profile;help;list'= {
        }
        &'spt;profile;help;show'= {
        }
        &'spt;profile;help;add'= {
        }
        &'spt;profile;help;configure'= {
        }
        &'spt;profile;help;set'= {
        }
        &'spt;profile;help;enable'= {
        }
        &'spt;profile;help;disable'= {
        }
        &'spt;profile;help;remove'= {
        }
        &'spt;profile;help;test'= {
        }
        &'spt;profile;help;help'= {
        }
        &'spt;forward'= {
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --json 'Convenience alias for `--output json`'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
            cand list 'List configured forwards'
            cand show 'Show a forward'
            cand add 'Add a forward'
            cand explain 'Explain how a forward is plumbed'
            cand test 'Run targeted forward tests'
            cand throttle 'Update throttle/limit knobs at runtime'
            cand remove 'Remove a forward'
            cand help 'Print this message or the help of the given subcommand(s)'
        }
        &'spt;forward;list'= {
            cand --profile 'Filter by profile name'
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --json 'JSON output'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;forward;show'= {
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --friendly 'Friendly textual layout'
            cand --json 'JSON output'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;forward;add'= {
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --json 'Convenience alias for `--output json`'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
            cand local 'Local forward (`-L`)'
            cand remote 'Remote forward (`-R`)'
            cand help 'Print this message or the help of the given subcommand(s)'
        }
        &'spt;forward;add;local'= {
            cand --profile 'Owning profile name'
            cand --listen 'Listen address (`host:port` or `[::1]:port`)'
            cand --to 'Target address forwarded to'
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --tcp 'TCP forward (default)'
            cand --udp 'UDP forward (SSH3 only)'
            cand --json 'Convenience alias for `--output json`'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;forward;add;remote'= {
            cand --profile 'Owning profile name'
            cand --listen 'Listen address (`host:port` or `[::1]:port`)'
            cand --to 'Target address forwarded to'
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --tcp 'TCP forward (default)'
            cand --udp 'UDP forward (SSH3 only)'
            cand --json 'Convenience alias for `--output json`'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;forward;add;help'= {
            cand local 'Local forward (`-L`)'
            cand remote 'Remote forward (`-R`)'
            cand help 'Print this message or the help of the given subcommand(s)'
        }
        &'spt;forward;add;help;local'= {
        }
        &'spt;forward;add;help;remote'= {
        }
        &'spt;forward;add;help;help'= {
        }
        &'spt;forward;explain'= {
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --json 'Convenience alias for `--output json`'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;forward;test'= {
            cand --dns-name 'Probe with a DNS resolution'
            cand --timeout 'Timeout for the connect probe (e.g. `10s`)'
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --connect 'Probe with a TCP connect'
            cand --json 'Convenience alias for `--output json`'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;forward;throttle'= {
            cand --in 'Inbound rate (e.g. `10MiB/s`)'
            cand --out 'Outbound rate'
            cand --connections 'Per-forward connection limit'
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --json 'Convenience alias for `--output json`'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;forward;remove'= {
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --json 'Convenience alias for `--output json`'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;forward;help'= {
            cand list 'List configured forwards'
            cand show 'Show a forward'
            cand add 'Add a forward'
            cand explain 'Explain how a forward is plumbed'
            cand test 'Run targeted forward tests'
            cand throttle 'Update throttle/limit knobs at runtime'
            cand remove 'Remove a forward'
            cand help 'Print this message or the help of the given subcommand(s)'
        }
        &'spt;forward;help;list'= {
        }
        &'spt;forward;help;show'= {
        }
        &'spt;forward;help;add'= {
            cand local 'Local forward (`-L`)'
            cand remote 'Remote forward (`-R`)'
        }
        &'spt;forward;help;add;local'= {
        }
        &'spt;forward;help;add;remote'= {
        }
        &'spt;forward;help;explain'= {
        }
        &'spt;forward;help;test'= {
        }
        &'spt;forward;help;throttle'= {
        }
        &'spt;forward;help;remove'= {
        }
        &'spt;forward;help;help'= {
        }
        &'spt;tunnel'= {
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --json 'Convenience alias for `--output json`'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
            cand run 'Run configured tunnels'
            cand status 'Show overall tunnel status'
            cand stats 'Live or one-shot stats'
            cand sessions 'List active sessions'
            cand stop 'Stop tunnels'
            cand reload 'Reload running configuration'
            cand health 'Health summary'
            cand failover 'Manually trigger failover for a profile'
            cand help 'Print this message or the help of the given subcommand(s)'
        }
        &'spt;tunnel;run'= {
            cand --profiles 'Comma-separated profile filter'
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --foreground 'Run in the foreground'
            cand --once 'Start once and exit non-zero on startup failure'
            cand --json 'Convenience alias for `--output json`'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;tunnel;status'= {
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --watch 'Continuously refresh'
            cand --json 'JSON output'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;tunnel;stats'= {
            cand --profile 'Filter by profile'
            cand --forward 'Filter by forward'
            cand --interval 'Refresh interval'
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --json 'JSON output'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;tunnel;sessions'= {
            cand --profile 'Filter by profile'
            cand --forward 'Filter by forward'
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --json 'JSON output'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;tunnel;stop'= {
            cand --profile 'Stop a specific profile (or all if absent)'
            cand --grace 'Grace period for in-flight connections'
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --json 'Convenience alias for `--output json`'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;tunnel;reload'= {
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --wait 'Block until reload finishes'
            cand --json 'Convenience alias for `--output json`'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;tunnel;health'= {
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --json 'JSON output'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;tunnel;failover'= {
            cand --endpoint 'Override target endpoint as `host:port`. Synonym: `--to`'
            cand --reason 'Free-form reason for audit'
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --json 'Convenience alias for `--output json`'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;tunnel;help'= {
            cand run 'Run configured tunnels'
            cand status 'Show overall tunnel status'
            cand stats 'Live or one-shot stats'
            cand sessions 'List active sessions'
            cand stop 'Stop tunnels'
            cand reload 'Reload running configuration'
            cand health 'Health summary'
            cand failover 'Manually trigger failover for a profile'
            cand help 'Print this message or the help of the given subcommand(s)'
        }
        &'spt;tunnel;help;run'= {
        }
        &'spt;tunnel;help;status'= {
        }
        &'spt;tunnel;help;stats'= {
        }
        &'spt;tunnel;help;sessions'= {
        }
        &'spt;tunnel;help;stop'= {
        }
        &'spt;tunnel;help;reload'= {
        }
        &'spt;tunnel;help;health'= {
        }
        &'spt;tunnel;help;failover'= {
        }
        &'spt;tunnel;help;help'= {
        }
        &'spt;service'= {
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --json 'Convenience alias for `--output json`'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
            cand install 'Install a service for a config file'
            cand uninstall 'Uninstall a service'
            cand start 'Start a service'
            cand stop 'Stop a service'
            cand restart 'Restart a service'
            cand status 'Show service status'
            cand render 'Render the would-be service unit'
            cand help 'Print this message or the help of the given subcommand(s)'
        }
        &'spt;service;install'= {
            cand --config 'Path to the config file backing the service'
            cand --name 'Override the service unit name'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --user 'User-scoped service'
            cand --system 'System-scoped service'
            cand --json 'Convenience alias for `--output json`'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;service;uninstall'= {
            cand --config 'Path to the config file backing the service'
            cand --name 'Override the service unit name'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --user 'User-scoped service'
            cand --system 'System-scoped service'
            cand --json 'Convenience alias for `--output json`'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;service;start'= {
            cand --config 'Path to the config file backing the service'
            cand --name 'Override the service unit name'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --user 'User-scoped service'
            cand --system 'System-scoped service'
            cand --json 'Convenience alias for `--output json`'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;service;stop'= {
            cand --config 'Path to the config file backing the service'
            cand --name 'Override the service unit name'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --user 'User-scoped service'
            cand --system 'System-scoped service'
            cand --json 'Convenience alias for `--output json`'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;service;restart'= {
            cand --config 'Path to the config file backing the service'
            cand --name 'Override the service unit name'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --user 'User-scoped service'
            cand --system 'System-scoped service'
            cand --json 'Convenience alias for `--output json`'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;service;status'= {
            cand --config 'Path to the config file'
            cand --name 'Override the service unit name'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --user 'User-scoped service'
            cand --system 'System-scoped service'
            cand --json 'JSON output'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;service;render'= {
            cand --config 'Path to the config file'
            cand --name 'Override the service unit name'
            cand --format 'Output format'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --user 'User-scoped service'
            cand --system 'System-scoped service'
            cand --json 'Convenience alias for `--output json`'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;service;help'= {
            cand install 'Install a service for a config file'
            cand uninstall 'Uninstall a service'
            cand start 'Start a service'
            cand stop 'Stop a service'
            cand restart 'Restart a service'
            cand status 'Show service status'
            cand render 'Render the would-be service unit'
            cand help 'Print this message or the help of the given subcommand(s)'
        }
        &'spt;service;help;install'= {
        }
        &'spt;service;help;uninstall'= {
        }
        &'spt;service;help;start'= {
        }
        &'spt;service;help;stop'= {
        }
        &'spt;service;help;restart'= {
        }
        &'spt;service;help;status'= {
        }
        &'spt;service;help;render'= {
        }
        &'spt;service;help;help'= {
        }
        &'spt;key'= {
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --json 'Convenience alias for `--output json`'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
            cand generate 'Generate a new keypair'
            cand inspect 'Inspect a key file'
            cand public 'Print a public key (optionally to a file)'
            cand change-passphrase 'Change the passphrase on a private key'
            cand sign-cert 'Sign an OpenSSH certificate'
            cand verify-cert 'Verify an OpenSSH certificate'
            cand install-public 'Install a public key on a remote host'
            cand help 'Print this message or the help of the given subcommand(s)'
        }
        &'spt;key;generate'= {
            cand --type 'Algorithm'
            cand --out 'Output path (private key; public is `<path>.pub`)'
            cand --bits 'RSA bit length (only meaningful for `--type rsa`)'
            cand --comment 'Optional comment to embed'
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --encrypt 'Encrypt the private key at rest with a passphrase'
            cand --json 'Convenience alias for `--output json`'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;key;inspect'= {
            cand --fingerprint 'Fingerprint hash to print'
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --json 'JSON output'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;key;public'= {
            cand --out 'Output file (otherwise stdout)'
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --json 'Convenience alias for `--output json`'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;key;change-passphrase'= {
            cand --new-passphrase-from 'Read the new passphrase from a value source (`stdin`, `file:<path>`, or `env:<NAME>`)'
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --json 'Convenience alias for `--output json`'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;key;sign-cert'= {
            cand --ca-key 'Path to the signing CA private key'
            cand --public-key 'Public key to sign'
            cand --principal 'One or more principal names (repeat or comma-separated)'
            cand --validity 'Certificate validity duration (e.g. `1d`, `52w`)'
            cand --serial 'Serial number to embed'
            cand --cert-type 'Certificate type (user/host)'
            cand --key-id 'Free-form key id to embed in the certificate'
            cand --out 'Output certificate path'
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --json 'Convenience alias for `--output json`'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;key;verify-cert'= {
            cand --trusted-cas 'File containing trusted CA public keys (one per line)'
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --json 'Convenience alias for `--output json`'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;key;install-public'= {
            cand --profile 'Owning profile'
            cand --target 'Override target as `user@host[:port]`'
            cand --key 'Public key path'
            cand --remote-command 'Override the remote install command'
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --json 'Convenience alias for `--output json`'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;key;help'= {
            cand generate 'Generate a new keypair'
            cand inspect 'Inspect a key file'
            cand public 'Print a public key (optionally to a file)'
            cand change-passphrase 'Change the passphrase on a private key'
            cand sign-cert 'Sign an OpenSSH certificate'
            cand verify-cert 'Verify an OpenSSH certificate'
            cand install-public 'Install a public key on a remote host'
            cand help 'Print this message or the help of the given subcommand(s)'
        }
        &'spt;key;help;generate'= {
        }
        &'spt;key;help;inspect'= {
        }
        &'spt;key;help;public'= {
        }
        &'spt;key;help;change-passphrase'= {
        }
        &'spt;key;help;sign-cert'= {
        }
        &'spt;key;help;verify-cert'= {
        }
        &'spt;key;help;install-public'= {
        }
        &'spt;key;help;help'= {
        }
        &'spt;secret'= {
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --json 'Convenience alias for `--output json`'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
            cand store 'Initialize the secret store'
            cand set 'Set a secret'
            cand get 'Get a secret (redacted unless `--reveal`)'
            cand list 'List known secret names'
            cand rotate 'Rotate a secret'
            cand remove 'Remove a secret'
            cand doctor 'Run secret backend health checks'
            cand help 'Print this message or the help of the given subcommand(s)'
        }
        &'spt;secret;store'= {
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --json 'Convenience alias for `--output json`'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
            cand init 'Initialize a secret store'
            cand help 'Print this message or the help of the given subcommand(s)'
        }
        &'spt;secret;store;init'= {
            cand --backend 'Preferred backend'
            cand --vault-path 'Vault file location (overrides default `<state_dir>/vault.spt`)'
            cand --passphrase-from 'Read the vault passphrase from a value source (`stdin`, `file:<path>`, `env:<NAME>`)'
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --json 'Convenience alias for `--output json`'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;secret;store;help'= {
            cand init 'Initialize a secret store'
            cand help 'Print this message or the help of the given subcommand(s)'
        }
        &'spt;secret;store;help;init'= {
        }
        &'spt;secret;store;help;help'= {
        }
        &'spt;secret;set'= {
            cand --from-env 'Read from an environment variable'
            cand --from-file 'Read from a file (mode-checked)'
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --prompt 'Read from a TTY prompt'
            cand --json 'Convenience alias for `--output json`'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;secret;get'= {
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --reveal 'Print the plaintext value'
            cand --json 'Convenience alias for `--output json`'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;secret;list'= {
            cand --namespace 'Restrict to a single namespace'
            cand --vault-path 'Vault file location'
            cand --passphrase-from 'Read the vault passphrase from a value source'
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --json 'JSON output'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;secret;rotate'= {
            cand --new-value-from 'New value source for `rotate` (`stdin`, `file:<path>`, `env:<NAME>`)'
            cand --vault-path 'Vault file location'
            cand --passphrase-from 'Read the vault passphrase from a value source'
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --json 'Convenience alias for `--output json`'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;secret;remove'= {
            cand --new-value-from 'New value source for `rotate` (`stdin`, `file:<path>`, `env:<NAME>`)'
            cand --vault-path 'Vault file location'
            cand --passphrase-from 'Read the vault passphrase from a value source'
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --json 'Convenience alias for `--output json`'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;secret;doctor'= {
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --json 'Convenience alias for `--output json`'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;secret;help'= {
            cand store 'Initialize the secret store'
            cand set 'Set a secret'
            cand get 'Get a secret (redacted unless `--reveal`)'
            cand list 'List known secret names'
            cand rotate 'Rotate a secret'
            cand remove 'Remove a secret'
            cand doctor 'Run secret backend health checks'
            cand help 'Print this message or the help of the given subcommand(s)'
        }
        &'spt;secret;help;store'= {
            cand init 'Initialize a secret store'
        }
        &'spt;secret;help;store;init'= {
        }
        &'spt;secret;help;set'= {
        }
        &'spt;secret;help;get'= {
        }
        &'spt;secret;help;list'= {
        }
        &'spt;secret;help;rotate'= {
        }
        &'spt;secret;help;remove'= {
        }
        &'spt;secret;help;doctor'= {
        }
        &'spt;secret;help;help'= {
        }
        &'spt;auth'= {
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --json 'Convenience alias for `--output json`'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
            cand test 'Test authentication for a profile'
            cand ssh3-login 'Run an SSH3 OIDC device-flow login and optionally store the token'
            cand help 'Print this message or the help of the given subcommand(s)'
        }
        &'spt;auth;test'= {
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --json 'Convenience alias for `--output json`'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;auth;ssh3-login'= {
            cand --issuer 'OIDC issuer URL (the `.well-known/openid-configuration` parent)'
            cand --client-id 'OAuth client id registered with the issuer'
            cand --audience 'Optional OAuth audience'
            cand --scope 'Optional space-separated scope (defaults to `openid offline_access`)'
            cand --save-as 'If set, persist the resulting access (and refresh) token through the configured secret backend at this `secret://ns/name` ref'
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --json 'JSON output (machine-readable)'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;auth;help'= {
            cand test 'Test authentication for a profile'
            cand ssh3-login 'Run an SSH3 OIDC device-flow login and optionally store the token'
            cand help 'Print this message or the help of the given subcommand(s)'
        }
        &'spt;auth;help;test'= {
        }
        &'spt;auth;help;ssh3-login'= {
        }
        &'spt;auth;help;help'= {
        }
        &'spt;dns'= {
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --json 'Convenience alias for `--output json`'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
            cand serve 'Run the resolver'
            cand status 'Resolver status'
            cand query 'Issue a query against the configured resolver'
            cand upstream 'Manage upstream resolvers'
            cand record 'Manage managed records'
            cand hosts 'Manage hosts-file rendering / apply / restore'
            cand help 'Print this message or the help of the given subcommand(s)'
        }
        &'spt;dns;serve'= {
            cand --config 'Override config path'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --foreground 'Run in the foreground'
            cand --json 'Convenience alias for `--output json`'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;dns;status'= {
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --json 'JSON output'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;dns;query'= {
            cand --type 'Record type'
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --json 'Convenience alias for `--output json`'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;dns;upstream'= {
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --json 'Convenience alias for `--output json`'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
            cand set 'Replace the upstream list'
            cand help 'Print this message or the help of the given subcommand(s)'
        }
        &'spt;dns;upstream;set'= {
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --json 'Convenience alias for `--output json`'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;dns;upstream;help'= {
            cand set 'Replace the upstream list'
            cand help 'Print this message or the help of the given subcommand(s)'
        }
        &'spt;dns;upstream;help;set'= {
        }
        &'spt;dns;upstream;help;help'= {
        }
        &'spt;dns;record'= {
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --json 'Convenience alias for `--output json`'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
            cand add 'Add a managed record'
            cand remove 'Remove a managed record'
            cand help 'Print this message or the help of the given subcommand(s)'
        }
        &'spt;dns;record;add'= {
            cand --addr 'IP address'
            cand --ttl 'TTL (e.g. `5m`)'
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --json 'Convenience alias for `--output json`'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;dns;record;remove'= {
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --json 'Convenience alias for `--output json`'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;dns;record;help'= {
            cand add 'Add a managed record'
            cand remove 'Remove a managed record'
            cand help 'Print this message or the help of the given subcommand(s)'
        }
        &'spt;dns;record;help;add'= {
        }
        &'spt;dns;record;help;remove'= {
        }
        &'spt;dns;record;help;help'= {
        }
        &'spt;dns;hosts'= {
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --json 'Convenience alias for `--output json`'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
            cand render 'Render the would-be hosts file'
            cand apply 'Apply the rendered hosts file'
            cand restore 'Restore a previous hosts backup'
            cand help 'Print this message or the help of the given subcommand(s)'
        }
        &'spt;dns;hosts;render'= {
            cand --out 'Output path (otherwise stdout)'
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --json 'Convenience alias for `--output json`'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;dns;hosts;apply'= {
            cand --path 'Hosts file to write'
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --backup 'Take a timestamped backup first'
            cand --json 'Convenience alias for `--output json`'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;dns;hosts;restore'= {
            cand --backup 'Specific backup to restore'
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --json 'Convenience alias for `--output json`'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;dns;hosts;help'= {
            cand render 'Render the would-be hosts file'
            cand apply 'Apply the rendered hosts file'
            cand restore 'Restore a previous hosts backup'
            cand help 'Print this message or the help of the given subcommand(s)'
        }
        &'spt;dns;hosts;help;render'= {
        }
        &'spt;dns;hosts;help;apply'= {
        }
        &'spt;dns;hosts;help;restore'= {
        }
        &'spt;dns;hosts;help;help'= {
        }
        &'spt;dns;help'= {
            cand serve 'Run the resolver'
            cand status 'Resolver status'
            cand query 'Issue a query against the configured resolver'
            cand upstream 'Manage upstream resolvers'
            cand record 'Manage managed records'
            cand hosts 'Manage hosts-file rendering / apply / restore'
            cand help 'Print this message or the help of the given subcommand(s)'
        }
        &'spt;dns;help;serve'= {
        }
        &'spt;dns;help;status'= {
        }
        &'spt;dns;help;query'= {
        }
        &'spt;dns;help;upstream'= {
            cand set 'Replace the upstream list'
        }
        &'spt;dns;help;upstream;set'= {
        }
        &'spt;dns;help;record'= {
            cand add 'Add a managed record'
            cand remove 'Remove a managed record'
        }
        &'spt;dns;help;record;add'= {
        }
        &'spt;dns;help;record;remove'= {
        }
        &'spt;dns;help;hosts'= {
            cand render 'Render the would-be hosts file'
            cand apply 'Apply the rendered hosts file'
            cand restore 'Restore a previous hosts backup'
        }
        &'spt;dns;help;hosts;render'= {
        }
        &'spt;dns;help;hosts;apply'= {
        }
        &'spt;dns;help;hosts;restore'= {
        }
        &'spt;dns;help;help'= {
        }
        &'spt;firewall'= {
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --json 'Convenience alias for `--output json`'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
            cand plan 'Plan rules without applying'
            cand apply 'Apply rules (idempotent)'
            cand remove 'Remove rules'
            cand status 'Show current applied state'
            cand interfaces 'List interfaces / bind targets'
            cand bind-preview 'Preview the bind for a forward'
            cand gateway 'Manage gateway/interface defaults in config'
            cand policy 'Inspect and manage GPO-style policy values'
            cand help 'Print this message or the help of the given subcommand(s)'
        }
        &'spt;firewall;plan'= {
            cand --profile 'Filter by profile'
            cand --forward 'Filter by forward'
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --json 'JSON output'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;firewall;apply'= {
            cand --profile 'Filter by profile'
            cand --forward 'Filter by forward'
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --user 'User-scoped scope'
            cand --system 'System-scoped scope'
            cand --dry-run 'Print actions without changing system state'
            cand --json 'Convenience alias for `--output json`'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;firewall;remove'= {
            cand --profile 'Filter by profile'
            cand --forward 'Filter by forward'
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --user 'User-scoped scope'
            cand --system 'System-scoped scope'
            cand --dry-run 'Print actions without changing system state'
            cand --json 'Convenience alias for `--output json`'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;firewall;status'= {
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --json 'JSON output'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;firewall;interfaces'= {
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --json 'JSON output'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;firewall;bind-preview'= {
            cand --forward '`<profile>/<forward>`'
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --json 'JSON output'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;firewall;gateway'= {
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --json 'Convenience alias for `--output json`'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
            cand show 'Show configured interface/gateway policy'
            cand set 'Update configured interface/gateway policy'
            cand help 'Print this message or the help of the given subcommand(s)'
        }
        &'spt;firewall;gateway;show'= {
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --json 'JSON output'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;firewall;gateway;set'= {
            cand --default-interface 'Set `[network.interface].default_interface`'
            cand --default-gateway 'Set `[network.gateway].default_gateway`'
            cand --gateway-interface 'Set `[network.gateway].interface`'
            cand --route-check-target 'Set `[network.gateway].route_check_target`'
            cand --policy 'Set `[network.gateway].policy`'
            cand --require-gateway-match 'Set `[network.gateway].require_gateway_match`'
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --json 'JSON output'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;firewall;gateway;help'= {
            cand show 'Show configured interface/gateway policy'
            cand set 'Update configured interface/gateway policy'
            cand help 'Print this message or the help of the given subcommand(s)'
        }
        &'spt;firewall;gateway;help;show'= {
        }
        &'spt;firewall;gateway;help;set'= {
        }
        &'spt;firewall;gateway;help;help'= {
        }
        &'spt;firewall;policy'= {
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --json 'Convenience alias for `--output json`'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
            cand list 'List known policy bindings'
            cand show 'Show live registry policy overlay and effective network/firewall fields'
            cand set 'Set a policy value in HKCU/HKLM'
            cand unset 'Remove a policy value from HKCU/HKLM'
            cand help 'Print this message or the help of the given subcommand(s)'
        }
        &'spt;firewall;policy;list'= {
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --json 'JSON output'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;firewall;policy;show'= {
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --json 'JSON output'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;firewall;policy;set'= {
            cand --scope 'Target registry hive'
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --enforced 'Mark the containing machine-policy section enforced'
            cand --json 'JSON output'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;firewall;policy;unset'= {
            cand --scope 'Target registry hive'
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --clear-enforced 'Also clear the section-level `Enforced` sentinel'
            cand --json 'JSON output'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;firewall;policy;help'= {
            cand list 'List known policy bindings'
            cand show 'Show live registry policy overlay and effective network/firewall fields'
            cand set 'Set a policy value in HKCU/HKLM'
            cand unset 'Remove a policy value from HKCU/HKLM'
            cand help 'Print this message or the help of the given subcommand(s)'
        }
        &'spt;firewall;policy;help;list'= {
        }
        &'spt;firewall;policy;help;show'= {
        }
        &'spt;firewall;policy;help;set'= {
        }
        &'spt;firewall;policy;help;unset'= {
        }
        &'spt;firewall;policy;help;help'= {
        }
        &'spt;firewall;help'= {
            cand plan 'Plan rules without applying'
            cand apply 'Apply rules (idempotent)'
            cand remove 'Remove rules'
            cand status 'Show current applied state'
            cand interfaces 'List interfaces / bind targets'
            cand bind-preview 'Preview the bind for a forward'
            cand gateway 'Manage gateway/interface defaults in config'
            cand policy 'Inspect and manage GPO-style policy values'
            cand help 'Print this message or the help of the given subcommand(s)'
        }
        &'spt;firewall;help;plan'= {
        }
        &'spt;firewall;help;apply'= {
        }
        &'spt;firewall;help;remove'= {
        }
        &'spt;firewall;help;status'= {
        }
        &'spt;firewall;help;interfaces'= {
        }
        &'spt;firewall;help;bind-preview'= {
        }
        &'spt;firewall;help;gateway'= {
            cand show 'Show configured interface/gateway policy'
            cand set 'Update configured interface/gateway policy'
        }
        &'spt;firewall;help;gateway;show'= {
        }
        &'spt;firewall;help;gateway;set'= {
        }
        &'spt;firewall;help;policy'= {
            cand list 'List known policy bindings'
            cand show 'Show live registry policy overlay and effective network/firewall fields'
            cand set 'Set a policy value in HKCU/HKLM'
            cand unset 'Remove a policy value from HKCU/HKLM'
        }
        &'spt;firewall;help;policy;list'= {
        }
        &'spt;firewall;help;policy;show'= {
        }
        &'spt;firewall;help;policy;set'= {
        }
        &'spt;firewall;help;policy;unset'= {
        }
        &'spt;firewall;help;help'= {
        }
        &'spt;log'= {
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --json 'Convenience alias for `--output json`'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
            cand tail 'Tail logs'
            cand remote 'Manage configured remote log sinks'
            cand test 'Probe a configured sink'
            cand export 'Export logs to a structured format'
            cand help 'Print this message or the help of the given subcommand(s)'
        }
        &'spt;log;tail'= {
            cand --profile 'Filter by profile'
            cand --since 'Lookback window (e.g. `1h`)'
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --follow 'Follow mode'
            cand --json 'JSON output'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;log;remote'= {
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --json 'Convenience alias for `--output json`'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
            cand list 'List configured remote log sinks'
            cand test 'Probe a configured remote log sink'
            cand status 'Show local delivery status for a remote log sink'
            cand drain 'Drain a remote log sink''s disk spool'
            cand help 'Print this message or the help of the given subcommand(s)'
        }
        &'spt;log;remote;list'= {
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --json 'JSON output'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;log;remote;test'= {
            cand --sink 'Sink name'
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --send-test-record 'Send a real synthetic record instead of only probing reachability'
            cand --json 'JSON output'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;log;remote;status'= {
            cand --sink 'Sink name'
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --json 'JSON output'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;log;remote;drain'= {
            cand --sink 'Sink name'
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --json 'JSON output'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;log;remote;help'= {
            cand list 'List configured remote log sinks'
            cand test 'Probe a configured remote log sink'
            cand status 'Show local delivery status for a remote log sink'
            cand drain 'Drain a remote log sink''s disk spool'
            cand help 'Print this message or the help of the given subcommand(s)'
        }
        &'spt;log;remote;help;list'= {
        }
        &'spt;log;remote;help;test'= {
        }
        &'spt;log;remote;help;status'= {
        }
        &'spt;log;remote;help;drain'= {
        }
        &'spt;log;remote;help;help'= {
        }
        &'spt;log;test'= {
            cand --sink 'Sink name'
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --json 'Convenience alias for `--output json`'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;log;export'= {
            cand --format 'Output format'
            cand --since 'Lookback window'
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --json 'Convenience alias for `--output json`'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;log;help'= {
            cand tail 'Tail logs'
            cand remote 'Manage configured remote log sinks'
            cand test 'Probe a configured sink'
            cand export 'Export logs to a structured format'
            cand help 'Print this message or the help of the given subcommand(s)'
        }
        &'spt;log;help;tail'= {
        }
        &'spt;log;help;remote'= {
            cand list 'List configured remote log sinks'
            cand test 'Probe a configured remote log sink'
            cand status 'Show local delivery status for a remote log sink'
            cand drain 'Drain a remote log sink''s disk spool'
        }
        &'spt;log;help;remote;list'= {
        }
        &'spt;log;help;remote;test'= {
        }
        &'spt;log;help;remote;status'= {
        }
        &'spt;log;help;remote;drain'= {
        }
        &'spt;log;help;test'= {
        }
        &'spt;log;help;export'= {
        }
        &'spt;log;help;help'= {
        }
        &'spt;observe'= {
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --json 'Convenience alias for `--output json`'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
            cand metrics 'Print metrics'
            cand windows-event 'Windows Event Log integration'
            cand help 'Print this message or the help of the given subcommand(s)'
        }
        &'spt;observe;metrics'= {
            cand --format 'Output format'
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --json 'Convenience alias for `--output json`'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;observe;windows-event'= {
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --json 'Convenience alias for `--output json`'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
            cand install-source 'Install a Windows Event Log source'
            cand uninstall-source 'Uninstall a Windows Event Log source'
            cand test 'Emit a test event'
            cand help 'Print this message or the help of the given subcommand(s)'
        }
        &'spt;observe;windows-event;install-source'= {
            cand --source 'Source name'
            cand --channel 'Event Log channel. Defaults to `[observability.windows_event].channel` or `Application`'
            cand --message-dll 'Message table DLL or EXE for source registration'
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --json 'Convenience alias for `--output json`'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;observe;windows-event;uninstall-source'= {
            cand --source 'Source name'
            cand --channel 'Event Log channel. Defaults to `[observability.windows_event].channel` or `Application`'
            cand --message-dll 'Message table DLL or EXE for source registration'
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --json 'Convenience alias for `--output json`'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;observe;windows-event;test'= {
            cand --source 'Source name'
            cand --channel 'Event Log channel. Used for config/default resolution'
            cand --level 'Event severity (`info`, `warning`, `error`)'
            cand --event-id 'Event identifier'
            cand --message 'Event message'
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --json 'Convenience alias for `--output json`'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;observe;windows-event;help'= {
            cand install-source 'Install a Windows Event Log source'
            cand uninstall-source 'Uninstall a Windows Event Log source'
            cand test 'Emit a test event'
            cand help 'Print this message or the help of the given subcommand(s)'
        }
        &'spt;observe;windows-event;help;install-source'= {
        }
        &'spt;observe;windows-event;help;uninstall-source'= {
        }
        &'spt;observe;windows-event;help;test'= {
        }
        &'spt;observe;windows-event;help;help'= {
        }
        &'spt;observe;help'= {
            cand metrics 'Print metrics'
            cand windows-event 'Windows Event Log integration'
            cand help 'Print this message or the help of the given subcommand(s)'
        }
        &'spt;observe;help;metrics'= {
        }
        &'spt;observe;help;windows-event'= {
            cand install-source 'Install a Windows Event Log source'
            cand uninstall-source 'Uninstall a Windows Event Log source'
            cand test 'Emit a test event'
        }
        &'spt;observe;help;windows-event;install-source'= {
        }
        &'spt;observe;help;windows-event;uninstall-source'= {
        }
        &'spt;observe;help;windows-event;test'= {
        }
        &'spt;observe;help;help'= {
        }
        &'spt;event'= {
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --json 'Convenience alias for `--output json`'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
            cand list 'List configured event bindings'
            cand test 'Trigger a binding by name'
            cand replay 'Replay historical events through a binding'
            cand sink 'Manage event sinks'
            cand help 'Print this message or the help of the given subcommand(s)'
        }
        &'spt;event;list'= {
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --json 'JSON output'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;event;test'= {
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --json 'Convenience alias for `--output json`'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;event;replay'= {
            cand --since 'Lookback window'
            cand --binding 'Binding name'
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --json 'Convenience alias for `--output json`'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;event;sink'= {
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --json 'Convenience alias for `--output json`'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
            cand test 'Test a sink'
            cand list 'List configured sinks'
            cand help 'Print this message or the help of the given subcommand(s)'
        }
        &'spt;event;sink;test'= {
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --json 'JSON output'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;event;sink;list'= {
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --json 'JSON output'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;event;sink;help'= {
            cand test 'Test a sink'
            cand list 'List configured sinks'
            cand help 'Print this message or the help of the given subcommand(s)'
        }
        &'spt;event;sink;help;test'= {
        }
        &'spt;event;sink;help;list'= {
        }
        &'spt;event;sink;help;help'= {
        }
        &'spt;event;help'= {
            cand list 'List configured event bindings'
            cand test 'Trigger a binding by name'
            cand replay 'Replay historical events through a binding'
            cand sink 'Manage event sinks'
            cand help 'Print this message or the help of the given subcommand(s)'
        }
        &'spt;event;help;list'= {
        }
        &'spt;event;help;test'= {
        }
        &'spt;event;help;replay'= {
        }
        &'spt;event;help;sink'= {
            cand test 'Test a sink'
            cand list 'List configured sinks'
        }
        &'spt;event;help;sink;test'= {
        }
        &'spt;event;help;sink;list'= {
        }
        &'spt;event;help;help'= {
        }
        &'spt;stats'= {
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --json 'Convenience alias for `--output json`'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
            cand summary 'Snapshot summary'
            cand live 'Live updating view'
            cand connections 'Connection table'
            cand throughput 'Throughput windows'
            cand errors 'Recent errors'
            cand export 'Export stats to a file'
            cand help 'Print this message or the help of the given subcommand(s)'
        }
        &'spt;stats;summary'= {
            cand --profile 'Filter by profile'
            cand --forward 'Filter by forward'
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --json 'JSON output'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;stats;live'= {
            cand --interval 'Refresh interval'
            cand --profile 'Filter by profile'
            cand --forward 'Filter by forward'
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --json 'Convenience alias for `--output json`'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;stats;connections'= {
            cand --profile 'Filter by profile'
            cand --forward 'Filter by forward'
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --json 'JSON output'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;stats;throughput'= {
            cand --profile 'Filter by profile'
            cand --forward 'Filter by forward'
            cand --window 'Window size'
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --json 'JSON output'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;stats;errors'= {
            cand --since 'Lookback window'
            cand --profile 'Filter by profile'
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --json 'JSON output'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;stats;export'= {
            cand --format 'Output format'
            cand --since 'Lookback window'
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --json 'Convenience alias for `--output json`'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;stats;help'= {
            cand summary 'Snapshot summary'
            cand live 'Live updating view'
            cand connections 'Connection table'
            cand throughput 'Throughput windows'
            cand errors 'Recent errors'
            cand export 'Export stats to a file'
            cand help 'Print this message or the help of the given subcommand(s)'
        }
        &'spt;stats;help;summary'= {
        }
        &'spt;stats;help;live'= {
        }
        &'spt;stats;help;connections'= {
        }
        &'spt;stats;help;throughput'= {
        }
        &'spt;stats;help;errors'= {
        }
        &'spt;stats;help;export'= {
        }
        &'spt;stats;help;help'= {
        }
        &'spt;session'= {
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --json 'Convenience alias for `--output json`'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
            cand list 'List sessions'
            cand show 'Show a session'
            cand close 'Close a session'
            cand drain 'Drain sessions for a profile'
            cand top 'Top-style live view'
            cand help 'Print this message or the help of the given subcommand(s)'
        }
        &'spt;session;list'= {
            cand --profile 'Filter by profile'
            cand --forward 'Filter by forward'
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --json 'JSON output'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;session;show'= {
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --json 'JSON output'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;session;close'= {
            cand --grace 'Grace period'
            cand --reason 'Free-form reason for audit'
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --json 'Convenience alias for `--output json`'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;session;drain'= {
            cand --forward 'Filter by forward'
            cand --grace 'Drain timeout / grace period. Synonym: `--timeout`'
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --json 'Convenience alias for `--output json`'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;session;top'= {
            cand --sort 'Sort key'
            cand --limit 'Result limit'
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --json 'Convenience alias for `--output json`'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;session;help'= {
            cand list 'List sessions'
            cand show 'Show a session'
            cand close 'Close a session'
            cand drain 'Drain sessions for a profile'
            cand top 'Top-style live view'
            cand help 'Print this message or the help of the given subcommand(s)'
        }
        &'spt;session;help;list'= {
        }
        &'spt;session;help;show'= {
        }
        &'spt;session;help;close'= {
        }
        &'spt;session;help;drain'= {
        }
        &'spt;session;help;top'= {
        }
        &'spt;session;help;help'= {
        }
        &'spt;diagnose'= {
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --json 'Convenience alias for `--output json`'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
            cand run 'Run a battery of diagnostic checks'
            cand network 'Network checks'
            cand auth 'Authentication checks for a profile'
            cand trust 'Trust checks for a profile'
            cand dns 'DNS checks'
            cand bind 'Bind checks'
            cand port 'Probe a host:port'
            cand service 'Service-manager checks'
            cand secrets 'Secret-backend checks'
            cand observability 'Observability sink checks'
            cand mcp 'MCP server checks'
            cand bundle 'Build a redacted support bundle'
            cand help 'Print this message or the help of the given subcommand(s)'
        }
        &'spt;diagnose;run'= {
            cand --profile 'Filter by profile'
            cand --report 'Write a structured report'
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --all 'Run every check'
            cand --offline 'Restrict to offline-only checks'
            cand --online 'Restrict to online-only checks'
            cand --json 'JSON output'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;diagnose;network'= {
            cand --profile 'Filter by profile'
            cand --endpoint 'Filter by endpoint'
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --json 'JSON output'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;diagnose;auth'= {
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --probe 'Run a live connect probe (forward-compatible; structural-only today)'
            cand --json 'JSON output'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;diagnose;trust'= {
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --probe 'Run a live connect probe (forward-compatible; structural-only today)'
            cand --json 'JSON output'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;diagnose;dns'= {
            cand --name 'Name to test'
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --json 'JSON output'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;diagnose;bind'= {
            cand --profile 'Filter by profile'
            cand --forward 'Filter by forward'
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --json 'JSON output'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;diagnose;port'= {
            cand --host 'Target host'
            cand --port 'Target port'
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --tcp 'TCP probe'
            cand --udp 'UDP probe'
            cand --autodetect-service 'Try to identify the service'
            cand --json 'JSON output'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;diagnose;service'= {
            cand --config 'Path to the config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --user 'User scope'
            cand --system 'System scope'
            cand --json 'JSON output'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;diagnose;secrets'= {
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --json 'JSON output'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;diagnose;observability'= {
            cand --sink 'Filter by sink name'
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --json 'JSON output'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;diagnose;mcp'= {
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --json 'JSON output'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;diagnose;bundle'= {
            cand --out 'Output bundle path'
            cand --since 'Lookback window for events'
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --redacted 'Redact secrets and PII'
            cand --json 'Convenience alias for `--output json`'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;diagnose;help'= {
            cand run 'Run a battery of diagnostic checks'
            cand network 'Network checks'
            cand auth 'Authentication checks for a profile'
            cand trust 'Trust checks for a profile'
            cand dns 'DNS checks'
            cand bind 'Bind checks'
            cand port 'Probe a host:port'
            cand service 'Service-manager checks'
            cand secrets 'Secret-backend checks'
            cand observability 'Observability sink checks'
            cand mcp 'MCP server checks'
            cand bundle 'Build a redacted support bundle'
            cand help 'Print this message or the help of the given subcommand(s)'
        }
        &'spt;diagnose;help;run'= {
        }
        &'spt;diagnose;help;network'= {
        }
        &'spt;diagnose;help;auth'= {
        }
        &'spt;diagnose;help;trust'= {
        }
        &'spt;diagnose;help;dns'= {
        }
        &'spt;diagnose;help;bind'= {
        }
        &'spt;diagnose;help;port'= {
        }
        &'spt;diagnose;help;service'= {
        }
        &'spt;diagnose;help;secrets'= {
        }
        &'spt;diagnose;help;observability'= {
        }
        &'spt;diagnose;help;mcp'= {
        }
        &'spt;diagnose;help;bundle'= {
        }
        &'spt;diagnose;help;help'= {
        }
        &'spt;benchmark'= {
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --json 'Convenience alias for `--output json`'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
            cand run 'End-to-end mixed workload'
            cand latency 'Latency-focused benchmark'
            cand throughput 'Throughput-focused benchmark'
            cand udp 'UDP benchmark (SSH3 only)'
            cand reconnect 'Reconnect benchmark'
            cand dns 'DNS benchmark'
            cand limits 'Limit/throttle introspection'
            cand report 'Report tooling'
            cand help 'Print this message or the help of the given subcommand(s)'
        }
        &'spt;benchmark;run'= {
            cand --driver 'Driver to dispatch (one of `latency`, `throughput`, `udp`, `reconnect`, `dns`, `limits`)'
            cand --profile 'Profile name'
            cand --forward 'Forward name'
            cand --duration 'Duration'
            cand --connections 'Concurrent connections'
            cand --count 'Iteration / sample count override'
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --unsafe-allow-production-impact 'Allow drivers that may impact production. Combined with the `[benchmark.allow_production_impact]` config flag'
            cand --json 'JSON output'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;benchmark;latency'= {
            cand --profile 'Profile name'
            cand --forward 'Forward name'
            cand --samples 'Sample count'
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --json 'JSON output'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;benchmark;throughput'= {
            cand --profile 'Profile name'
            cand --forward 'Forward name'
            cand --duration 'Duration'
            cand --payload-size 'Payload size'
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --json 'JSON output'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;benchmark;udp'= {
            cand --profile 'Profile name'
            cand --forward 'Forward name'
            cand --duration 'Duration'
            cand --packet-size 'Datagram size'
            cand --pps 'Packets per second'
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --json 'JSON output'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;benchmark;reconnect'= {
            cand --profile 'Profile name'
            cand --iterations 'Iteration count'
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --json 'JSON output'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;benchmark;dns'= {
            cand --name 'Name to resolve'
            cand --samples 'Sample count'
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --json 'JSON output'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;benchmark;limits'= {
            cand --profile 'Profile name'
            cand --forward 'Forward name'
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --json 'JSON output'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;benchmark;report'= {
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --json 'Convenience alias for `--output json`'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
            cand compare 'Compare two benchmark results'
            cand export 'Export a benchmark result'
            cand help 'Print this message or the help of the given subcommand(s)'
        }
        &'spt;benchmark;report;compare'= {
            cand --baseline 'Baseline result file'
            cand --candidate 'Candidate result file'
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --json 'Convenience alias for `--output json`'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;benchmark;report;export'= {
            cand --format 'Output format'
            cand --out 'Output path'
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --json 'Convenience alias for `--output json`'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;benchmark;report;help'= {
            cand compare 'Compare two benchmark results'
            cand export 'Export a benchmark result'
            cand help 'Print this message or the help of the given subcommand(s)'
        }
        &'spt;benchmark;report;help;compare'= {
        }
        &'spt;benchmark;report;help;export'= {
        }
        &'spt;benchmark;report;help;help'= {
        }
        &'spt;benchmark;help'= {
            cand run 'End-to-end mixed workload'
            cand latency 'Latency-focused benchmark'
            cand throughput 'Throughput-focused benchmark'
            cand udp 'UDP benchmark (SSH3 only)'
            cand reconnect 'Reconnect benchmark'
            cand dns 'DNS benchmark'
            cand limits 'Limit/throttle introspection'
            cand report 'Report tooling'
            cand help 'Print this message or the help of the given subcommand(s)'
        }
        &'spt;benchmark;help;run'= {
        }
        &'spt;benchmark;help;latency'= {
        }
        &'spt;benchmark;help;throughput'= {
        }
        &'spt;benchmark;help;udp'= {
        }
        &'spt;benchmark;help;reconnect'= {
        }
        &'spt;benchmark;help;dns'= {
        }
        &'spt;benchmark;help;limits'= {
        }
        &'spt;benchmark;help;report'= {
            cand compare 'Compare two benchmark results'
            cand export 'Export a benchmark result'
        }
        &'spt;benchmark;help;report;compare'= {
        }
        &'spt;benchmark;help;report;export'= {
        }
        &'spt;benchmark;help;help'= {
        }
        &'spt;mcp'= {
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --json 'Convenience alias for `--output json`'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
            cand serve 'Run the MCP server'
            cand inspect 'Inspect MCP capabilities, resources, tools'
            cand policy 'Manage the MCP policy'
            cand help 'Print this message or the help of the given subcommand(s)'
        }
        &'spt;mcp;serve'= {
            cand --listen 'Listen on a loopback TCP address (`127.0.0.1:port`)'
            cand --config 'Override config path'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --stdio 'Speak MCP over stdio'
            cand --read-only 'Force read-only'
            cand --enable 'Explicit `--enable` toggle (required unless `[mcp].enabled = true`)'
            cand --json 'Convenience alias for `--output json`'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;mcp;inspect'= {
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --json 'JSON output'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;mcp;policy'= {
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --json 'Convenience alias for `--output json`'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
            cand show 'Show the current policy'
            cand set 'Update one or more policy keys'
            cand help 'Print this message or the help of the given subcommand(s)'
        }
        &'spt;mcp;policy;show'= {
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --json 'Convenience alias for `--output json`'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;mcp;policy;set'= {
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --json 'Convenience alias for `--output json`'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;mcp;policy;help'= {
            cand show 'Show the current policy'
            cand set 'Update one or more policy keys'
            cand help 'Print this message or the help of the given subcommand(s)'
        }
        &'spt;mcp;policy;help;show'= {
        }
        &'spt;mcp;policy;help;set'= {
        }
        &'spt;mcp;policy;help;help'= {
        }
        &'spt;mcp;help'= {
            cand serve 'Run the MCP server'
            cand inspect 'Inspect MCP capabilities, resources, tools'
            cand policy 'Manage the MCP policy'
            cand help 'Print this message or the help of the given subcommand(s)'
        }
        &'spt;mcp;help;serve'= {
        }
        &'spt;mcp;help;inspect'= {
        }
        &'spt;mcp;help;policy'= {
            cand show 'Show the current policy'
            cand set 'Update one or more policy keys'
        }
        &'spt;mcp;help;policy;show'= {
        }
        &'spt;mcp;help;policy;set'= {
        }
        &'spt;mcp;help;help'= {
        }
        &'spt;status'= {
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --json 'Convenience alias for `--output json`'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
            cand serve 'Run the status API server in foreground (rare — supervisor normally hosts inline when `[status_api].enabled = true`)'
            cand status 'Show whether the API is bound + how to reach it'
            cand token 'Bearer-token management for the status API auth'
            cand help 'Print this message or the help of the given subcommand(s)'
        }
        &'spt;status;serve'= {
            cand --config 'Override config path (otherwise inherits `--config`)'
            cand --bind 'Override the bind address. Defaults to the value in `[status_api].bind`'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --json 'Convenience alias for `--output json`'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;status;status'= {
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --detail 'Show the resolved auth mode and TLS state in addition to the bind'
            cand --json 'Convenience alias for `--output json`'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;status;token'= {
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --json 'Convenience alias for `--output json`'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
            cand rotate 'Rotate the bearer token in the vault (only when `auth.mode = "bearer"` and the `token_from` SecretRef points at a writable backend)'
            cand help 'Print this message or the help of the given subcommand(s)'
        }
        &'spt;status;token;rotate'= {
            cand --bytes 'Length in bytes of the random token before base64 encoding. Defaults to 32 (256-bit)'
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --print-token 'Print the new token to stdout (default: only print success + SecretRef). Useful for piping into other tooling'
            cand --json 'Convenience alias for `--output json`'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;status;token;help'= {
            cand rotate 'Rotate the bearer token in the vault (only when `auth.mode = "bearer"` and the `token_from` SecretRef points at a writable backend)'
            cand help 'Print this message or the help of the given subcommand(s)'
        }
        &'spt;status;token;help;rotate'= {
        }
        &'spt;status;token;help;help'= {
        }
        &'spt;status;help'= {
            cand serve 'Run the status API server in foreground (rare — supervisor normally hosts inline when `[status_api].enabled = true`)'
            cand status 'Show whether the API is bound + how to reach it'
            cand token 'Bearer-token management for the status API auth'
            cand help 'Print this message or the help of the given subcommand(s)'
        }
        &'spt;status;help;serve'= {
        }
        &'spt;status;help;status'= {
        }
        &'spt;status;help;token'= {
            cand rotate 'Rotate the bearer token in the vault (only when `auth.mode = "bearer"` and the `token_from` SecretRef points at a writable backend)'
        }
        &'spt;status;help;token;rotate'= {
        }
        &'spt;status;help;help'= {
        }
        &'spt;completion'= {
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --json 'Convenience alias for `--output json`'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
            cand generate 'Print completions for a shell to stdout'
            cand help 'Print this message or the help of the given subcommand(s)'
        }
        &'spt;completion;generate'= {
            cand --config 'Path to a single config file'
            cand --config-dir 'Path to a directory of `*.toml` configs (loaded in lexical order)'
            cand --config-url 'HTTPS URL of a remote config to fetch'
            cand --config-fingerprint 'SHA-256 fingerprint pin for `--config-url`'
            cand --state-dir 'Override the runtime state directory'
            cand --profile 'Restrict operations to the named profile'
            cand --output 'Output format for command results'
            cand --log-level 'Tracing log level'
            cand --color 'Color policy for human output'
            cand --json 'Convenience alias for `--output json`'
            cand -q 'Suppress non-essential output'
            cand --quiet 'Suppress non-essential output'
            cand -v 'Increase verbosity (repeat for more)'
            cand --verbose 'Increase verbosity (repeat for more)'
            cand --no-color 'Disable color (legacy convenience flag; use `--color never`)'
            cand --dry-run 'Show what would happen without making changes'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
        &'spt;completion;help'= {
            cand generate 'Print completions for a shell to stdout'
            cand help 'Print this message or the help of the given subcommand(s)'
        }
        &'spt;completion;help;generate'= {
        }
        &'spt;completion;help;help'= {
        }
        &'spt;help'= {
            cand config 'Manage configuration files (init, validate, diff, render, reload)'
            cand profile 'Manage SSH/SSH3 tunnel profiles'
            cand forward 'Manage forwards (local/remote TCP, UDP)'
            cand tunnel 'Run, inspect, and control tunnels'
            cand service 'Install and control native services'
            cand key 'Generate, inspect, and install SSH keys'
            cand secret 'Manage the secret vault and OS keychain references'
            cand auth 'Authentication helpers'
            cand dns 'Built-in DNS resolver and hosts-file management'
            cand firewall 'Inspect and manage OS firewall / packet-filter rules'
            cand log 'Log tailing, sink testing, and export'
            cand observe 'Metrics and Windows Event Log helpers'
            cand event 'Event bindings and sinks'
            cand stats 'Statistics summaries and live counters'
            cand session 'Inspect and manage active sessions'
            cand diagnose 'Targeted diagnostics and support bundles'
            cand benchmark 'Controlled benchmarking against forwards'
            cand mcp 'Built-in MCP server controls'
            cand status 'Read-only status API controls (plan §t4-e5)'
            cand completion 'Generate shell completions'
            cand help 'Print this message or the help of the given subcommand(s)'
        }
        &'spt;help;config'= {
            cand init 'Initialize a new config file from a template'
            cand validate 'Validate config syntax, schema, and obvious mistakes'
            cand doctor 'Run environment checks against the loaded config'
            cand render 'Render the canonical (optionally redacted) config'
            cand diff 'Diff two config files'
            cand migrate 'Migrate a config between schema versions'
            cand reload 'Reload the running service''s config'
            cand pull 'Pull a remote config over HTTPS with pinning'
            cand trust 'Manage remote-config trust pins'
            cand encrypt 'Encrypt a plaintext config to a sealed `SPTENC1` envelope'
            cand decrypt 'Decrypt a sealed `SPTENC1` envelope back to plaintext TOML'
            cand edit 'Open a sealed config in `$EDITOR`; re-seal on save'
            cand crypt 'Re-seal a sealed config under a new key (key rotation)'
        }
        &'spt;help;config;init'= {
        }
        &'spt;help;config;validate'= {
        }
        &'spt;help;config;doctor'= {
        }
        &'spt;help;config;render'= {
        }
        &'spt;help;config;diff'= {
        }
        &'spt;help;config;migrate'= {
        }
        &'spt;help;config;reload'= {
        }
        &'spt;help;config;pull'= {
        }
        &'spt;help;config;trust'= {
            cand add-url 'Add a pinned remote-config URL'
        }
        &'spt;help;config;trust;add-url'= {
        }
        &'spt;help;config;encrypt'= {
        }
        &'spt;help;config;decrypt'= {
        }
        &'spt;help;config;edit'= {
        }
        &'spt;help;config;crypt'= {
            cand rotate 'Re-seal a sealed config under a new key'
        }
        &'spt;help;config;crypt;rotate'= {
        }
        &'spt;help;profile'= {
            cand list 'List configured profiles'
            cand show 'Show the resolved profile (optionally redacted)'
            cand add 'Add a new profile'
            cand configure 'Interactive TUI configurator'
            cand set 'Set one or more `key=value` overrides'
            cand enable 'Enable a profile'
            cand disable 'Disable a profile'
            cand remove 'Remove a profile'
            cand test 'Run targeted profile tests'
        }
        &'spt;help;profile;list'= {
        }
        &'spt;help;profile;show'= {
        }
        &'spt;help;profile;add'= {
        }
        &'spt;help;profile;configure'= {
        }
        &'spt;help;profile;set'= {
        }
        &'spt;help;profile;enable'= {
        }
        &'spt;help;profile;disable'= {
        }
        &'spt;help;profile;remove'= {
        }
        &'spt;help;profile;test'= {
        }
        &'spt;help;forward'= {
            cand list 'List configured forwards'
            cand show 'Show a forward'
            cand add 'Add a forward'
            cand explain 'Explain how a forward is plumbed'
            cand test 'Run targeted forward tests'
            cand throttle 'Update throttle/limit knobs at runtime'
            cand remove 'Remove a forward'
        }
        &'spt;help;forward;list'= {
        }
        &'spt;help;forward;show'= {
        }
        &'spt;help;forward;add'= {
            cand local 'Local forward (`-L`)'
            cand remote 'Remote forward (`-R`)'
        }
        &'spt;help;forward;add;local'= {
        }
        &'spt;help;forward;add;remote'= {
        }
        &'spt;help;forward;explain'= {
        }
        &'spt;help;forward;test'= {
        }
        &'spt;help;forward;throttle'= {
        }
        &'spt;help;forward;remove'= {
        }
        &'spt;help;tunnel'= {
            cand run 'Run configured tunnels'
            cand status 'Show overall tunnel status'
            cand stats 'Live or one-shot stats'
            cand sessions 'List active sessions'
            cand stop 'Stop tunnels'
            cand reload 'Reload running configuration'
            cand health 'Health summary'
            cand failover 'Manually trigger failover for a profile'
        }
        &'spt;help;tunnel;run'= {
        }
        &'spt;help;tunnel;status'= {
        }
        &'spt;help;tunnel;stats'= {
        }
        &'spt;help;tunnel;sessions'= {
        }
        &'spt;help;tunnel;stop'= {
        }
        &'spt;help;tunnel;reload'= {
        }
        &'spt;help;tunnel;health'= {
        }
        &'spt;help;tunnel;failover'= {
        }
        &'spt;help;service'= {
            cand install 'Install a service for a config file'
            cand uninstall 'Uninstall a service'
            cand start 'Start a service'
            cand stop 'Stop a service'
            cand restart 'Restart a service'
            cand status 'Show service status'
            cand render 'Render the would-be service unit'
        }
        &'spt;help;service;install'= {
        }
        &'spt;help;service;uninstall'= {
        }
        &'spt;help;service;start'= {
        }
        &'spt;help;service;stop'= {
        }
        &'spt;help;service;restart'= {
        }
        &'spt;help;service;status'= {
        }
        &'spt;help;service;render'= {
        }
        &'spt;help;key'= {
            cand generate 'Generate a new keypair'
            cand inspect 'Inspect a key file'
            cand public 'Print a public key (optionally to a file)'
            cand change-passphrase 'Change the passphrase on a private key'
            cand sign-cert 'Sign an OpenSSH certificate'
            cand verify-cert 'Verify an OpenSSH certificate'
            cand install-public 'Install a public key on a remote host'
        }
        &'spt;help;key;generate'= {
        }
        &'spt;help;key;inspect'= {
        }
        &'spt;help;key;public'= {
        }
        &'spt;help;key;change-passphrase'= {
        }
        &'spt;help;key;sign-cert'= {
        }
        &'spt;help;key;verify-cert'= {
        }
        &'spt;help;key;install-public'= {
        }
        &'spt;help;secret'= {
            cand store 'Initialize the secret store'
            cand set 'Set a secret'
            cand get 'Get a secret (redacted unless `--reveal`)'
            cand list 'List known secret names'
            cand rotate 'Rotate a secret'
            cand remove 'Remove a secret'
            cand doctor 'Run secret backend health checks'
        }
        &'spt;help;secret;store'= {
            cand init 'Initialize a secret store'
        }
        &'spt;help;secret;store;init'= {
        }
        &'spt;help;secret;set'= {
        }
        &'spt;help;secret;get'= {
        }
        &'spt;help;secret;list'= {
        }
        &'spt;help;secret;rotate'= {
        }
        &'spt;help;secret;remove'= {
        }
        &'spt;help;secret;doctor'= {
        }
        &'spt;help;auth'= {
            cand test 'Test authentication for a profile'
            cand ssh3-login 'Run an SSH3 OIDC device-flow login and optionally store the token'
        }
        &'spt;help;auth;test'= {
        }
        &'spt;help;auth;ssh3-login'= {
        }
        &'spt;help;dns'= {
            cand serve 'Run the resolver'
            cand status 'Resolver status'
            cand query 'Issue a query against the configured resolver'
            cand upstream 'Manage upstream resolvers'
            cand record 'Manage managed records'
            cand hosts 'Manage hosts-file rendering / apply / restore'
        }
        &'spt;help;dns;serve'= {
        }
        &'spt;help;dns;status'= {
        }
        &'spt;help;dns;query'= {
        }
        &'spt;help;dns;upstream'= {
            cand set 'Replace the upstream list'
        }
        &'spt;help;dns;upstream;set'= {
        }
        &'spt;help;dns;record'= {
            cand add 'Add a managed record'
            cand remove 'Remove a managed record'
        }
        &'spt;help;dns;record;add'= {
        }
        &'spt;help;dns;record;remove'= {
        }
        &'spt;help;dns;hosts'= {
            cand render 'Render the would-be hosts file'
            cand apply 'Apply the rendered hosts file'
            cand restore 'Restore a previous hosts backup'
        }
        &'spt;help;dns;hosts;render'= {
        }
        &'spt;help;dns;hosts;apply'= {
        }
        &'spt;help;dns;hosts;restore'= {
        }
        &'spt;help;firewall'= {
            cand plan 'Plan rules without applying'
            cand apply 'Apply rules (idempotent)'
            cand remove 'Remove rules'
            cand status 'Show current applied state'
            cand interfaces 'List interfaces / bind targets'
            cand bind-preview 'Preview the bind for a forward'
            cand gateway 'Manage gateway/interface defaults in config'
            cand policy 'Inspect and manage GPO-style policy values'
        }
        &'spt;help;firewall;plan'= {
        }
        &'spt;help;firewall;apply'= {
        }
        &'spt;help;firewall;remove'= {
        }
        &'spt;help;firewall;status'= {
        }
        &'spt;help;firewall;interfaces'= {
        }
        &'spt;help;firewall;bind-preview'= {
        }
        &'spt;help;firewall;gateway'= {
            cand show 'Show configured interface/gateway policy'
            cand set 'Update configured interface/gateway policy'
        }
        &'spt;help;firewall;gateway;show'= {
        }
        &'spt;help;firewall;gateway;set'= {
        }
        &'spt;help;firewall;policy'= {
            cand list 'List known policy bindings'
            cand show 'Show live registry policy overlay and effective network/firewall fields'
            cand set 'Set a policy value in HKCU/HKLM'
            cand unset 'Remove a policy value from HKCU/HKLM'
        }
        &'spt;help;firewall;policy;list'= {
        }
        &'spt;help;firewall;policy;show'= {
        }
        &'spt;help;firewall;policy;set'= {
        }
        &'spt;help;firewall;policy;unset'= {
        }
        &'spt;help;log'= {
            cand tail 'Tail logs'
            cand remote 'Manage configured remote log sinks'
            cand test 'Probe a configured sink'
            cand export 'Export logs to a structured format'
        }
        &'spt;help;log;tail'= {
        }
        &'spt;help;log;remote'= {
            cand list 'List configured remote log sinks'
            cand test 'Probe a configured remote log sink'
            cand status 'Show local delivery status for a remote log sink'
            cand drain 'Drain a remote log sink''s disk spool'
        }
        &'spt;help;log;remote;list'= {
        }
        &'spt;help;log;remote;test'= {
        }
        &'spt;help;log;remote;status'= {
        }
        &'spt;help;log;remote;drain'= {
        }
        &'spt;help;log;test'= {
        }
        &'spt;help;log;export'= {
        }
        &'spt;help;observe'= {
            cand metrics 'Print metrics'
            cand windows-event 'Windows Event Log integration'
        }
        &'spt;help;observe;metrics'= {
        }
        &'spt;help;observe;windows-event'= {
            cand install-source 'Install a Windows Event Log source'
            cand uninstall-source 'Uninstall a Windows Event Log source'
            cand test 'Emit a test event'
        }
        &'spt;help;observe;windows-event;install-source'= {
        }
        &'spt;help;observe;windows-event;uninstall-source'= {
        }
        &'spt;help;observe;windows-event;test'= {
        }
        &'spt;help;event'= {
            cand list 'List configured event bindings'
            cand test 'Trigger a binding by name'
            cand replay 'Replay historical events through a binding'
            cand sink 'Manage event sinks'
        }
        &'spt;help;event;list'= {
        }
        &'spt;help;event;test'= {
        }
        &'spt;help;event;replay'= {
        }
        &'spt;help;event;sink'= {
            cand test 'Test a sink'
            cand list 'List configured sinks'
        }
        &'spt;help;event;sink;test'= {
        }
        &'spt;help;event;sink;list'= {
        }
        &'spt;help;stats'= {
            cand summary 'Snapshot summary'
            cand live 'Live updating view'
            cand connections 'Connection table'
            cand throughput 'Throughput windows'
            cand errors 'Recent errors'
            cand export 'Export stats to a file'
        }
        &'spt;help;stats;summary'= {
        }
        &'spt;help;stats;live'= {
        }
        &'spt;help;stats;connections'= {
        }
        &'spt;help;stats;throughput'= {
        }
        &'spt;help;stats;errors'= {
        }
        &'spt;help;stats;export'= {
        }
        &'spt;help;session'= {
            cand list 'List sessions'
            cand show 'Show a session'
            cand close 'Close a session'
            cand drain 'Drain sessions for a profile'
            cand top 'Top-style live view'
        }
        &'spt;help;session;list'= {
        }
        &'spt;help;session;show'= {
        }
        &'spt;help;session;close'= {
        }
        &'spt;help;session;drain'= {
        }
        &'spt;help;session;top'= {
        }
        &'spt;help;diagnose'= {
            cand run 'Run a battery of diagnostic checks'
            cand network 'Network checks'
            cand auth 'Authentication checks for a profile'
            cand trust 'Trust checks for a profile'
            cand dns 'DNS checks'
            cand bind 'Bind checks'
            cand port 'Probe a host:port'
            cand service 'Service-manager checks'
            cand secrets 'Secret-backend checks'
            cand observability 'Observability sink checks'
            cand mcp 'MCP server checks'
            cand bundle 'Build a redacted support bundle'
        }
        &'spt;help;diagnose;run'= {
        }
        &'spt;help;diagnose;network'= {
        }
        &'spt;help;diagnose;auth'= {
        }
        &'spt;help;diagnose;trust'= {
        }
        &'spt;help;diagnose;dns'= {
        }
        &'spt;help;diagnose;bind'= {
        }
        &'spt;help;diagnose;port'= {
        }
        &'spt;help;diagnose;service'= {
        }
        &'spt;help;diagnose;secrets'= {
        }
        &'spt;help;diagnose;observability'= {
        }
        &'spt;help;diagnose;mcp'= {
        }
        &'spt;help;diagnose;bundle'= {
        }
        &'spt;help;benchmark'= {
            cand run 'End-to-end mixed workload'
            cand latency 'Latency-focused benchmark'
            cand throughput 'Throughput-focused benchmark'
            cand udp 'UDP benchmark (SSH3 only)'
            cand reconnect 'Reconnect benchmark'
            cand dns 'DNS benchmark'
            cand limits 'Limit/throttle introspection'
            cand report 'Report tooling'
        }
        &'spt;help;benchmark;run'= {
        }
        &'spt;help;benchmark;latency'= {
        }
        &'spt;help;benchmark;throughput'= {
        }
        &'spt;help;benchmark;udp'= {
        }
        &'spt;help;benchmark;reconnect'= {
        }
        &'spt;help;benchmark;dns'= {
        }
        &'spt;help;benchmark;limits'= {
        }
        &'spt;help;benchmark;report'= {
            cand compare 'Compare two benchmark results'
            cand export 'Export a benchmark result'
        }
        &'spt;help;benchmark;report;compare'= {
        }
        &'spt;help;benchmark;report;export'= {
        }
        &'spt;help;mcp'= {
            cand serve 'Run the MCP server'
            cand inspect 'Inspect MCP capabilities, resources, tools'
            cand policy 'Manage the MCP policy'
        }
        &'spt;help;mcp;serve'= {
        }
        &'spt;help;mcp;inspect'= {
        }
        &'spt;help;mcp;policy'= {
            cand show 'Show the current policy'
            cand set 'Update one or more policy keys'
        }
        &'spt;help;mcp;policy;show'= {
        }
        &'spt;help;mcp;policy;set'= {
        }
        &'spt;help;status'= {
            cand serve 'Run the status API server in foreground (rare — supervisor normally hosts inline when `[status_api].enabled = true`)'
            cand status 'Show whether the API is bound + how to reach it'
            cand token 'Bearer-token management for the status API auth'
        }
        &'spt;help;status;serve'= {
        }
        &'spt;help;status;status'= {
        }
        &'spt;help;status;token'= {
            cand rotate 'Rotate the bearer token in the vault (only when `auth.mode = "bearer"` and the `token_from` SecretRef points at a writable backend)'
        }
        &'spt;help;status;token;rotate'= {
        }
        &'spt;help;completion'= {
            cand generate 'Print completions for a shell to stdout'
        }
        &'spt;help;completion;generate'= {
        }
        &'spt;help;help'= {
        }
    ]
    $completions[$command]
}
