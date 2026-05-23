# Print an optspec for argparse to handle cmd's options that are independent of any subcommand.
function __fish_spt_global_optspecs
	string join \n config= config-dir= config-url= config-fingerprint= state-dir= profile= output= json log-level= color= q/quiet v/verbose no-color dry-run h/help V/version
end

function __fish_spt_needs_command
	# Figure out if the current invocation already has a command.
	set -l cmd (commandline -opc)
	set -e cmd[1]
	argparse -s (__fish_spt_global_optspecs) -- $cmd 2>/dev/null
	or return
	if set -q argv[1]
		# Also print the command, so this can be used to figure out what it is.
		echo $argv[1]
		return 1
	end
	return 0
end

function __fish_spt_using_subcommand
	set -l cmd (__fish_spt_needs_command)
	test -z "$cmd"
	and return 1
	contains -- $cmd[1] $argv
end

complete -c spt -n "__fish_spt_needs_command" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_needs_command" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_needs_command" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_needs_command" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_needs_command" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_needs_command" -l profile -d 'Restrict operations to the named profile' -r
complete -c spt -n "__fish_spt_needs_command" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_needs_command" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_needs_command" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_needs_command" -l json -d 'Convenience alias for `--output json`'
complete -c spt -n "__fish_spt_needs_command" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_needs_command" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_needs_command" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_needs_command" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_needs_command" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_needs_command" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_needs_command" -f -a "config" -d 'Manage configuration files (init, validate, diff, render, reload)'
complete -c spt -n "__fish_spt_needs_command" -f -a "profile" -d 'Manage SSH/SSH3 tunnel profiles'
complete -c spt -n "__fish_spt_needs_command" -f -a "forward" -d 'Manage forwards (local/remote TCP, UDP)'
complete -c spt -n "__fish_spt_needs_command" -f -a "tunnel" -d 'Run, inspect, and control tunnels'
complete -c spt -n "__fish_spt_needs_command" -f -a "service" -d 'Install and control native services'
complete -c spt -n "__fish_spt_needs_command" -f -a "key" -d 'Generate, inspect, and install SSH keys'
complete -c spt -n "__fish_spt_needs_command" -f -a "secret" -d 'Manage the secret vault and OS keychain references'
complete -c spt -n "__fish_spt_needs_command" -f -a "auth" -d 'Authentication helpers'
complete -c spt -n "__fish_spt_needs_command" -f -a "dns" -d 'Built-in DNS resolver and hosts-file management'
complete -c spt -n "__fish_spt_needs_command" -f -a "firewall" -d 'Inspect and manage OS firewall / packet-filter rules'
complete -c spt -n "__fish_spt_needs_command" -f -a "log" -d 'Log tailing, sink testing, and export'
complete -c spt -n "__fish_spt_needs_command" -f -a "observe" -d 'Metrics and Windows Event Log helpers'
complete -c spt -n "__fish_spt_needs_command" -f -a "event" -d 'Event bindings and sinks'
complete -c spt -n "__fish_spt_needs_command" -f -a "stats" -d 'Statistics summaries and live counters'
complete -c spt -n "__fish_spt_needs_command" -f -a "session" -d 'Inspect and manage active sessions'
complete -c spt -n "__fish_spt_needs_command" -f -a "ftp" -d 'FTP→SFTP translator service'
complete -c spt -n "__fish_spt_needs_command" -f -a "sftp" -d 'SFTP file operations and mount planning'
complete -c spt -n "__fish_spt_needs_command" -f -a "diagnose" -d 'Targeted diagnostics and support bundles'
complete -c spt -n "__fish_spt_needs_command" -f -a "benchmark" -d 'Controlled benchmarking against forwards'
complete -c spt -n "__fish_spt_needs_command" -f -a "mcp" -d 'Built-in MCP server controls'
complete -c spt -n "__fish_spt_needs_command" -f -a "status" -d 'Read-only status API controls (plan §t4-e5)'
complete -c spt -n "__fish_spt_needs_command" -f -a "completion" -d 'Generate shell completions'
complete -c spt -n "__fish_spt_needs_command" -f -a "about" -d 'List bundled libraries and their licenses'
complete -c spt -n "__fish_spt_needs_command" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c spt -n "__fish_spt_using_subcommand config; and not __fish_seen_subcommand_from init validate doctor render diff migrate reload pull trust encrypt decrypt edit crypt help" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand config; and not __fish_seen_subcommand_from init validate doctor render diff migrate reload pull trust encrypt decrypt edit crypt help" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand config; and not __fish_seen_subcommand_from init validate doctor render diff migrate reload pull trust encrypt decrypt edit crypt help" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand config; and not __fish_seen_subcommand_from init validate doctor render diff migrate reload pull trust encrypt decrypt edit crypt help" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand config; and not __fish_seen_subcommand_from init validate doctor render diff migrate reload pull trust encrypt decrypt edit crypt help" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand config; and not __fish_seen_subcommand_from init validate doctor render diff migrate reload pull trust encrypt decrypt edit crypt help" -l profile -d 'Restrict operations to the named profile' -r
complete -c spt -n "__fish_spt_using_subcommand config; and not __fish_seen_subcommand_from init validate doctor render diff migrate reload pull trust encrypt decrypt edit crypt help" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand config; and not __fish_seen_subcommand_from init validate doctor render diff migrate reload pull trust encrypt decrypt edit crypt help" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand config; and not __fish_seen_subcommand_from init validate doctor render diff migrate reload pull trust encrypt decrypt edit crypt help" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand config; and not __fish_seen_subcommand_from init validate doctor render diff migrate reload pull trust encrypt decrypt edit crypt help" -l json -d 'Convenience alias for `--output json`'
complete -c spt -n "__fish_spt_using_subcommand config; and not __fish_seen_subcommand_from init validate doctor render diff migrate reload pull trust encrypt decrypt edit crypt help" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand config; and not __fish_seen_subcommand_from init validate doctor render diff migrate reload pull trust encrypt decrypt edit crypt help" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand config; and not __fish_seen_subcommand_from init validate doctor render diff migrate reload pull trust encrypt decrypt edit crypt help" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand config; and not __fish_seen_subcommand_from init validate doctor render diff migrate reload pull trust encrypt decrypt edit crypt help" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand config; and not __fish_seen_subcommand_from init validate doctor render diff migrate reload pull trust encrypt decrypt edit crypt help" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand config; and not __fish_seen_subcommand_from init validate doctor render diff migrate reload pull trust encrypt decrypt edit crypt help" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand config; and not __fish_seen_subcommand_from init validate doctor render diff migrate reload pull trust encrypt decrypt edit crypt help" -f -a "init" -d 'Initialize a new config file from a template'
complete -c spt -n "__fish_spt_using_subcommand config; and not __fish_seen_subcommand_from init validate doctor render diff migrate reload pull trust encrypt decrypt edit crypt help" -f -a "validate" -d 'Validate config syntax, schema, and obvious mistakes'
complete -c spt -n "__fish_spt_using_subcommand config; and not __fish_seen_subcommand_from init validate doctor render diff migrate reload pull trust encrypt decrypt edit crypt help" -f -a "doctor" -d 'Run environment checks against the loaded config'
complete -c spt -n "__fish_spt_using_subcommand config; and not __fish_seen_subcommand_from init validate doctor render diff migrate reload pull trust encrypt decrypt edit crypt help" -f -a "render" -d 'Render the canonical (optionally redacted) config'
complete -c spt -n "__fish_spt_using_subcommand config; and not __fish_seen_subcommand_from init validate doctor render diff migrate reload pull trust encrypt decrypt edit crypt help" -f -a "diff" -d 'Diff two config files'
complete -c spt -n "__fish_spt_using_subcommand config; and not __fish_seen_subcommand_from init validate doctor render diff migrate reload pull trust encrypt decrypt edit crypt help" -f -a "migrate" -d 'Migrate a config between schema versions'
complete -c spt -n "__fish_spt_using_subcommand config; and not __fish_seen_subcommand_from init validate doctor render diff migrate reload pull trust encrypt decrypt edit crypt help" -f -a "reload" -d 'Reload the running service\'s config'
complete -c spt -n "__fish_spt_using_subcommand config; and not __fish_seen_subcommand_from init validate doctor render diff migrate reload pull trust encrypt decrypt edit crypt help" -f -a "pull" -d 'Pull a remote config over HTTPS with pinning'
complete -c spt -n "__fish_spt_using_subcommand config; and not __fish_seen_subcommand_from init validate doctor render diff migrate reload pull trust encrypt decrypt edit crypt help" -f -a "trust" -d 'Manage remote-config trust pins'
complete -c spt -n "__fish_spt_using_subcommand config; and not __fish_seen_subcommand_from init validate doctor render diff migrate reload pull trust encrypt decrypt edit crypt help" -f -a "encrypt" -d 'Encrypt a plaintext config to a sealed `SPTENC1` envelope'
complete -c spt -n "__fish_spt_using_subcommand config; and not __fish_seen_subcommand_from init validate doctor render diff migrate reload pull trust encrypt decrypt edit crypt help" -f -a "decrypt" -d 'Decrypt a sealed `SPTENC1` envelope back to plaintext TOML'
complete -c spt -n "__fish_spt_using_subcommand config; and not __fish_seen_subcommand_from init validate doctor render diff migrate reload pull trust encrypt decrypt edit crypt help" -f -a "edit" -d 'Open a sealed config in `$EDITOR`; re-seal on save'
complete -c spt -n "__fish_spt_using_subcommand config; and not __fish_seen_subcommand_from init validate doctor render diff migrate reload pull trust encrypt decrypt edit crypt help" -f -a "crypt" -d 'Re-seal a sealed config under a new key (key rotation)'
complete -c spt -n "__fish_spt_using_subcommand config; and not __fish_seen_subcommand_from init validate doctor render diff migrate reload pull trust encrypt decrypt edit crypt help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from init" -l path -d 'Output path for the generated config' -r -F
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from init" -l example -d 'Template to seed the config from' -r -f -a "smtp\t''
jump\t''
reverse\t''
ssh3\t''
dns\t''
observability\t''
mcp\t''"
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from init" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from init" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from init" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from init" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from init" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from init" -l profile -d 'Restrict operations to the named profile' -r
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from init" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from init" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from init" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from init" -l json -d 'Convenience alias for `--output json`'
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from init" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from init" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from init" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from init" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from init" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from init" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from validate" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from validate" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from validate" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from validate" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from validate" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from validate" -l profile -d 'Restrict operations to the named profile' -r
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from validate" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from validate" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from validate" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from validate" -l strict -d 'Reject unknown fields and friendly aliases'
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from validate" -l json -d 'Convenience alias for `--output json`'
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from validate" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from validate" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from validate" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from validate" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from validate" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from validate" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from doctor" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from doctor" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from doctor" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from doctor" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from doctor" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from doctor" -l profile -d 'Restrict operations to the named profile' -r
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from doctor" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from doctor" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from doctor" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from doctor" -l network -d 'Run network checks'
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from doctor" -l service -d 'Run service-manager checks'
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from doctor" -l secrets -d 'Run secret backend checks'
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from doctor" -l dns -d 'Run DNS checks'
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from doctor" -l observability -d 'Run observability sink checks'
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from doctor" -l json -d 'Convenience alias for `--output json`'
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from doctor" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from doctor" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from doctor" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from doctor" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from doctor" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from doctor" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from render" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from render" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from render" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from render" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from render" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from render" -l profile -d 'Restrict operations to the named profile' -r
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from render" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from render" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from render" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from render" -l redacted -d 'Redact secret values'
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from render" -l json -d 'Render as JSON instead of canonical TOML'
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from render" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from render" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from render" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from render" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from render" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from render" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from diff" -l from -d 'Base config' -r -F
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from diff" -l to -d 'Candidate config' -r -F
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from diff" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from diff" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from diff" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from diff" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from diff" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from diff" -l profile -d 'Restrict operations to the named profile' -r
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from diff" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from diff" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from diff" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from diff" -l json -d 'Convenience alias for `--output json`'
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from diff" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from diff" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from diff" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from diff" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from diff" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from diff" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from migrate" -l from-version -d 'Source schema version' -r
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from migrate" -l to-version -d 'Target schema version' -r
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from migrate" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from migrate" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from migrate" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from migrate" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from migrate" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from migrate" -l profile -d 'Restrict operations to the named profile' -r
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from migrate" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from migrate" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from migrate" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from migrate" -l json -d 'Convenience alias for `--output json`'
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from migrate" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from migrate" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from migrate" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from migrate" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from migrate" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from migrate" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from reload" -l mode -d 'Reload mechanism to use' -r -f -a "signal\t''
watch\t''
service\t''
none\t''"
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from reload" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from reload" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from reload" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from reload" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from reload" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from reload" -l profile -d 'Restrict operations to the named profile' -r
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from reload" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from reload" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from reload" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from reload" -l wait -d 'Wait for reload to complete'
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from reload" -l json -d 'Convenience alias for `--output json`'
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from reload" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from reload" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from reload" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from reload" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from reload" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from reload" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from pull" -l url -d 'HTTPS URL to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from pull" -l fingerprint -d 'SHA-256 fingerprint pin' -r
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from pull" -l out -d 'Output path' -r -F
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from pull" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from pull" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from pull" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from pull" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from pull" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from pull" -l profile -d 'Restrict operations to the named profile' -r
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from pull" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from pull" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from pull" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from pull" -l cache -d 'Update the local atomic cache'
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from pull" -l json -d 'Convenience alias for `--output json`'
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from pull" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from pull" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from pull" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from pull" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from pull" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from pull" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from trust" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from trust" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from trust" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from trust" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from trust" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from trust" -l profile -d 'Restrict operations to the named profile' -r
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from trust" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from trust" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from trust" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from trust" -l json -d 'Convenience alias for `--output json`'
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from trust" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from trust" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from trust" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from trust" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from trust" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from trust" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from trust" -f -a "add-url" -d 'Add a pinned remote-config URL'
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from trust" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from encrypt" -l out -d 'Output path (default: `<IN>.sealed`)' -r -F
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from encrypt" -l passphrase-from -d 'Read passphrase from a secret reference (e.g. `secret://env/SPT_PP`)' -r
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from encrypt" -l recipient -d 'One or more X25519 recipient public keys (base64)' -r
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from encrypt" -l vault-path -d 'Vault directory or `vault.spt` file used for `secret://` passphrases and `--use-vault-master`' -r -F
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from encrypt" -l vault-passphrase-from -d 'Unlock the vault with a passphrase source instead of the keychain (`stdin`, `env:NAME`, `file:<path>`, or `file:///path`)' -r
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from encrypt" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from encrypt" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from encrypt" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from encrypt" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from encrypt" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from encrypt" -l profile -d 'Restrict operations to the named profile' -r
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from encrypt" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from encrypt" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from encrypt" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from encrypt" -l use-vault-master -d 'Use the keychain-resident vault master key'
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from encrypt" -l force -d 'Overwrite an existing output file'
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from encrypt" -l json -d 'Convenience alias for `--output json`'
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from encrypt" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from encrypt" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from encrypt" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from encrypt" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from encrypt" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from encrypt" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from decrypt" -l out -d 'Output path. If unset, write the cleartext to stdout' -r -F
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from decrypt" -l passphrase-from -d 'Read passphrase from a secret reference' -r
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from decrypt" -l recipient-key -d 'Path to an X25519 private-key file (32 raw bytes or base64 line)' -r -F
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from decrypt" -l vault-path -d 'Vault directory or `vault.spt` file used for `secret://` passphrases and vault-master envelopes' -r -F
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from decrypt" -l vault-passphrase-from -d 'Unlock the vault with a passphrase source instead of the keychain' -r
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from decrypt" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from decrypt" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from decrypt" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from decrypt" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from decrypt" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from decrypt" -l profile -d 'Restrict operations to the named profile' -r
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from decrypt" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from decrypt" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from decrypt" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from decrypt" -l json -d 'Convenience alias for `--output json`'
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from decrypt" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from decrypt" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from decrypt" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from decrypt" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from decrypt" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from decrypt" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from edit" -l passphrase-from -d 'Read passphrase from a secret reference' -r
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from edit" -l vault-path -d 'Vault directory or `vault.spt` file used for `secret://` passphrases and vault-master envelopes' -r -F
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from edit" -l vault-passphrase-from -d 'Unlock the vault with a passphrase source instead of the keychain' -r
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from edit" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from edit" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from edit" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from edit" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from edit" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from edit" -l profile -d 'Restrict operations to the named profile' -r
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from edit" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from edit" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from edit" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from edit" -l json -d 'Convenience alias for `--output json`'
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from edit" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from edit" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from edit" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from edit" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from edit" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from edit" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from crypt" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from crypt" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from crypt" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from crypt" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from crypt" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from crypt" -l profile -d 'Restrict operations to the named profile' -r
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from crypt" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from crypt" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from crypt" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from crypt" -l json -d 'Convenience alias for `--output json`'
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from crypt" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from crypt" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from crypt" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from crypt" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from crypt" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from crypt" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from crypt" -f -a "rotate" -d 'Re-seal a sealed config under a new key'
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from crypt" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from help" -f -a "init" -d 'Initialize a new config file from a template'
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from help" -f -a "validate" -d 'Validate config syntax, schema, and obvious mistakes'
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from help" -f -a "doctor" -d 'Run environment checks against the loaded config'
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from help" -f -a "render" -d 'Render the canonical (optionally redacted) config'
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from help" -f -a "diff" -d 'Diff two config files'
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from help" -f -a "migrate" -d 'Migrate a config between schema versions'
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from help" -f -a "reload" -d 'Reload the running service\'s config'
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from help" -f -a "pull" -d 'Pull a remote config over HTTPS with pinning'
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from help" -f -a "trust" -d 'Manage remote-config trust pins'
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from help" -f -a "encrypt" -d 'Encrypt a plaintext config to a sealed `SPTENC1` envelope'
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from help" -f -a "decrypt" -d 'Decrypt a sealed `SPTENC1` envelope back to plaintext TOML'
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from help" -f -a "edit" -d 'Open a sealed config in `$EDITOR`; re-seal on save'
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from help" -f -a "crypt" -d 'Re-seal a sealed config under a new key (key rotation)'
complete -c spt -n "__fish_spt_using_subcommand config; and __fish_seen_subcommand_from help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c spt -n "__fish_spt_using_subcommand profile; and not __fish_seen_subcommand_from list show add configure set enable disable remove test help" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand profile; and not __fish_seen_subcommand_from list show add configure set enable disable remove test help" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand profile; and not __fish_seen_subcommand_from list show add configure set enable disable remove test help" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand profile; and not __fish_seen_subcommand_from list show add configure set enable disable remove test help" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand profile; and not __fish_seen_subcommand_from list show add configure set enable disable remove test help" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand profile; and not __fish_seen_subcommand_from list show add configure set enable disable remove test help" -l profile -d 'Restrict operations to the named profile' -r
complete -c spt -n "__fish_spt_using_subcommand profile; and not __fish_seen_subcommand_from list show add configure set enable disable remove test help" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand profile; and not __fish_seen_subcommand_from list show add configure set enable disable remove test help" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand profile; and not __fish_seen_subcommand_from list show add configure set enable disable remove test help" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand profile; and not __fish_seen_subcommand_from list show add configure set enable disable remove test help" -l json -d 'Convenience alias for `--output json`'
complete -c spt -n "__fish_spt_using_subcommand profile; and not __fish_seen_subcommand_from list show add configure set enable disable remove test help" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand profile; and not __fish_seen_subcommand_from list show add configure set enable disable remove test help" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand profile; and not __fish_seen_subcommand_from list show add configure set enable disable remove test help" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand profile; and not __fish_seen_subcommand_from list show add configure set enable disable remove test help" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand profile; and not __fish_seen_subcommand_from list show add configure set enable disable remove test help" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand profile; and not __fish_seen_subcommand_from list show add configure set enable disable remove test help" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand profile; and not __fish_seen_subcommand_from list show add configure set enable disable remove test help" -f -a "list" -d 'List configured profiles'
complete -c spt -n "__fish_spt_using_subcommand profile; and not __fish_seen_subcommand_from list show add configure set enable disable remove test help" -f -a "show" -d 'Show the resolved profile (optionally redacted)'
complete -c spt -n "__fish_spt_using_subcommand profile; and not __fish_seen_subcommand_from list show add configure set enable disable remove test help" -f -a "add" -d 'Add a new profile'
complete -c spt -n "__fish_spt_using_subcommand profile; and not __fish_seen_subcommand_from list show add configure set enable disable remove test help" -f -a "configure" -d 'Interactive TUI configurator'
complete -c spt -n "__fish_spt_using_subcommand profile; and not __fish_seen_subcommand_from list show add configure set enable disable remove test help" -f -a "set" -d 'Set one or more `key=value` overrides'
complete -c spt -n "__fish_spt_using_subcommand profile; and not __fish_seen_subcommand_from list show add configure set enable disable remove test help" -f -a "enable" -d 'Enable a profile'
complete -c spt -n "__fish_spt_using_subcommand profile; and not __fish_seen_subcommand_from list show add configure set enable disable remove test help" -f -a "disable" -d 'Disable a profile'
complete -c spt -n "__fish_spt_using_subcommand profile; and not __fish_seen_subcommand_from list show add configure set enable disable remove test help" -f -a "remove" -d 'Remove a profile'
complete -c spt -n "__fish_spt_using_subcommand profile; and not __fish_seen_subcommand_from list show add configure set enable disable remove test help" -f -a "test" -d 'Run targeted profile tests'
complete -c spt -n "__fish_spt_using_subcommand profile; and not __fish_seen_subcommand_from list show add configure set enable disable remove test help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from list" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from list" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from list" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from list" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from list" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from list" -l profile -d 'Restrict operations to the named profile' -r
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from list" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from list" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from list" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from list" -l json -d 'JSON output'
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from list" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from list" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from list" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from list" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from list" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from list" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from show" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from show" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from show" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from show" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from show" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from show" -l profile -d 'Restrict operations to the named profile' -r
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from show" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from show" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from show" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from show" -l redacted -d 'Redact secret fields'
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from show" -l json -d 'JSON output'
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from show" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from show" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from show" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from show" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from show" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from show" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from add" -l protocol -d 'Protocol selector' -r -f -a "ssh2\t''
ssh3\t''"
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from add" -l host -d 'Remote host' -r
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from add" -l user -d 'SSH user' -r
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from add" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from add" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from add" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from add" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from add" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from add" -l profile -d 'Restrict operations to the named profile' -r
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from add" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from add" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from add" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from add" -l json -d 'Convenience alias for `--output json`'
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from add" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from add" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from add" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from add" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from add" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from add" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from configure" -l name -d 'Profile name (created if missing)' -r
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from configure" -l from-template -d 'Seed from a built-in template' -r
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from configure" -l field -d 'One or more `KEY=VALUE` field overrides applied non-interactively. Implies `--no-tui` semantics for `--field` updates. Repeatable' -r
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from configure" -l from -d 'Apply a TOML patch from `<file.toml>` to the profile (non-interactive). The file may contain a single `[profile]` table or a bare key/value document; both shapes are merged into the addressed `[[profiles]]` entry' -r -F
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from configure" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from configure" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from configure" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from configure" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from configure" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from configure" -l profile -d 'Restrict operations to the named profile' -r
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from configure" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from configure" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from configure" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from configure" -l tui -d 'Force the TUI wizard'
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from configure" -l no-tui -d 'Disable the TUI wizard (non-interactive)'
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from configure" -l json -d 'Convenience alias for `--output json`'
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from configure" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from configure" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from configure" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from configure" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from configure" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from configure" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from set" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from set" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from set" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from set" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from set" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from set" -l profile -d 'Restrict operations to the named profile' -r
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from set" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from set" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from set" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from set" -l json -d 'Convenience alias for `--output json`'
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from set" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from set" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from set" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from set" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from set" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from set" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from enable" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from enable" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from enable" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from enable" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from enable" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from enable" -l profile -d 'Restrict operations to the named profile' -r
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from enable" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from enable" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from enable" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from enable" -l json -d 'Convenience alias for `--output json`'
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from enable" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from enable" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from enable" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from enable" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from enable" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from enable" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from disable" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from disable" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from disable" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from disable" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from disable" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from disable" -l profile -d 'Restrict operations to the named profile' -r
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from disable" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from disable" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from disable" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from disable" -l json -d 'Convenience alias for `--output json`'
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from disable" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from disable" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from disable" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from disable" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from disable" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from disable" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from remove" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from remove" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from remove" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from remove" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from remove" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from remove" -l profile -d 'Restrict operations to the named profile' -r
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from remove" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from remove" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from remove" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from remove" -l json -d 'Convenience alias for `--output json`'
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from remove" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from remove" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from remove" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from remove" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from remove" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from remove" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from test" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from test" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from test" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from test" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from test" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from test" -l profile -d 'Restrict operations to the named profile' -r
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from test" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from test" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from test" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from test" -l connect-only -d 'Only test connect'
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from test" -l bind-only -d 'Only test bind'
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from test" -l auth-only -d 'Only test auth'
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from test" -l trust-only -d 'Only test trust (host-key/TLS pin)'
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from test" -l dns-only -d 'Only test DNS'
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from test" -l json -d 'Convenience alias for `--output json`'
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from test" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from test" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from test" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from test" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from test" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from test" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from help" -f -a "list" -d 'List configured profiles'
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from help" -f -a "show" -d 'Show the resolved profile (optionally redacted)'
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from help" -f -a "add" -d 'Add a new profile'
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from help" -f -a "configure" -d 'Interactive TUI configurator'
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from help" -f -a "set" -d 'Set one or more `key=value` overrides'
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from help" -f -a "enable" -d 'Enable a profile'
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from help" -f -a "disable" -d 'Disable a profile'
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from help" -f -a "remove" -d 'Remove a profile'
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from help" -f -a "test" -d 'Run targeted profile tests'
complete -c spt -n "__fish_spt_using_subcommand profile; and __fish_seen_subcommand_from help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c spt -n "__fish_spt_using_subcommand forward; and not __fish_seen_subcommand_from list show add explain test throttle remove help" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand forward; and not __fish_seen_subcommand_from list show add explain test throttle remove help" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand forward; and not __fish_seen_subcommand_from list show add explain test throttle remove help" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand forward; and not __fish_seen_subcommand_from list show add explain test throttle remove help" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand forward; and not __fish_seen_subcommand_from list show add explain test throttle remove help" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand forward; and not __fish_seen_subcommand_from list show add explain test throttle remove help" -l profile -d 'Restrict operations to the named profile' -r
complete -c spt -n "__fish_spt_using_subcommand forward; and not __fish_seen_subcommand_from list show add explain test throttle remove help" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand forward; and not __fish_seen_subcommand_from list show add explain test throttle remove help" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand forward; and not __fish_seen_subcommand_from list show add explain test throttle remove help" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand forward; and not __fish_seen_subcommand_from list show add explain test throttle remove help" -l json -d 'Convenience alias for `--output json`'
complete -c spt -n "__fish_spt_using_subcommand forward; and not __fish_seen_subcommand_from list show add explain test throttle remove help" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand forward; and not __fish_seen_subcommand_from list show add explain test throttle remove help" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand forward; and not __fish_seen_subcommand_from list show add explain test throttle remove help" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand forward; and not __fish_seen_subcommand_from list show add explain test throttle remove help" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand forward; and not __fish_seen_subcommand_from list show add explain test throttle remove help" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand forward; and not __fish_seen_subcommand_from list show add explain test throttle remove help" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand forward; and not __fish_seen_subcommand_from list show add explain test throttle remove help" -f -a "list" -d 'List configured forwards'
complete -c spt -n "__fish_spt_using_subcommand forward; and not __fish_seen_subcommand_from list show add explain test throttle remove help" -f -a "show" -d 'Show a forward'
complete -c spt -n "__fish_spt_using_subcommand forward; and not __fish_seen_subcommand_from list show add explain test throttle remove help" -f -a "add" -d 'Add a forward'
complete -c spt -n "__fish_spt_using_subcommand forward; and not __fish_seen_subcommand_from list show add explain test throttle remove help" -f -a "explain" -d 'Explain how a forward is plumbed'
complete -c spt -n "__fish_spt_using_subcommand forward; and not __fish_seen_subcommand_from list show add explain test throttle remove help" -f -a "test" -d 'Run targeted forward tests'
complete -c spt -n "__fish_spt_using_subcommand forward; and not __fish_seen_subcommand_from list show add explain test throttle remove help" -f -a "throttle" -d 'Update throttle/limit knobs at runtime'
complete -c spt -n "__fish_spt_using_subcommand forward; and not __fish_seen_subcommand_from list show add explain test throttle remove help" -f -a "remove" -d 'Remove a forward'
complete -c spt -n "__fish_spt_using_subcommand forward; and not __fish_seen_subcommand_from list show add explain test throttle remove help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c spt -n "__fish_spt_using_subcommand forward; and __fish_seen_subcommand_from list" -l profile -d 'Filter by profile name' -r
complete -c spt -n "__fish_spt_using_subcommand forward; and __fish_seen_subcommand_from list" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand forward; and __fish_seen_subcommand_from list" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand forward; and __fish_seen_subcommand_from list" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand forward; and __fish_seen_subcommand_from list" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand forward; and __fish_seen_subcommand_from list" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand forward; and __fish_seen_subcommand_from list" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand forward; and __fish_seen_subcommand_from list" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand forward; and __fish_seen_subcommand_from list" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand forward; and __fish_seen_subcommand_from list" -l json -d 'JSON output'
complete -c spt -n "__fish_spt_using_subcommand forward; and __fish_seen_subcommand_from list" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand forward; and __fish_seen_subcommand_from list" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand forward; and __fish_seen_subcommand_from list" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand forward; and __fish_seen_subcommand_from list" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand forward; and __fish_seen_subcommand_from list" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand forward; and __fish_seen_subcommand_from list" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand forward; and __fish_seen_subcommand_from show" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand forward; and __fish_seen_subcommand_from show" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand forward; and __fish_seen_subcommand_from show" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand forward; and __fish_seen_subcommand_from show" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand forward; and __fish_seen_subcommand_from show" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand forward; and __fish_seen_subcommand_from show" -l profile -d 'Restrict operations to the named profile' -r
complete -c spt -n "__fish_spt_using_subcommand forward; and __fish_seen_subcommand_from show" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand forward; and __fish_seen_subcommand_from show" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand forward; and __fish_seen_subcommand_from show" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand forward; and __fish_seen_subcommand_from show" -l friendly -d 'Friendly textual layout'
complete -c spt -n "__fish_spt_using_subcommand forward; and __fish_seen_subcommand_from show" -l json -d 'JSON output'
complete -c spt -n "__fish_spt_using_subcommand forward; and __fish_seen_subcommand_from show" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand forward; and __fish_seen_subcommand_from show" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand forward; and __fish_seen_subcommand_from show" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand forward; and __fish_seen_subcommand_from show" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand forward; and __fish_seen_subcommand_from show" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand forward; and __fish_seen_subcommand_from show" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand forward; and __fish_seen_subcommand_from add" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand forward; and __fish_seen_subcommand_from add" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand forward; and __fish_seen_subcommand_from add" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand forward; and __fish_seen_subcommand_from add" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand forward; and __fish_seen_subcommand_from add" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand forward; and __fish_seen_subcommand_from add" -l profile -d 'Restrict operations to the named profile' -r
complete -c spt -n "__fish_spt_using_subcommand forward; and __fish_seen_subcommand_from add" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand forward; and __fish_seen_subcommand_from add" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand forward; and __fish_seen_subcommand_from add" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand forward; and __fish_seen_subcommand_from add" -l json -d 'Convenience alias for `--output json`'
complete -c spt -n "__fish_spt_using_subcommand forward; and __fish_seen_subcommand_from add" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand forward; and __fish_seen_subcommand_from add" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand forward; and __fish_seen_subcommand_from add" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand forward; and __fish_seen_subcommand_from add" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand forward; and __fish_seen_subcommand_from add" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand forward; and __fish_seen_subcommand_from add" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand forward; and __fish_seen_subcommand_from add" -f -a "local" -d 'Local forward (`-L`)'
complete -c spt -n "__fish_spt_using_subcommand forward; and __fish_seen_subcommand_from add" -f -a "remote" -d 'Remote forward (`-R`)'
complete -c spt -n "__fish_spt_using_subcommand forward; and __fish_seen_subcommand_from add" -f -a "dynamic" -d 'Dynamic SOCKS4/SOCKS4A/SOCKS5/HTTP CONNECT proxy (`-D`)'
complete -c spt -n "__fish_spt_using_subcommand forward; and __fish_seen_subcommand_from add" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c spt -n "__fish_spt_using_subcommand forward; and __fish_seen_subcommand_from explain" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand forward; and __fish_seen_subcommand_from explain" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand forward; and __fish_seen_subcommand_from explain" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand forward; and __fish_seen_subcommand_from explain" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand forward; and __fish_seen_subcommand_from explain" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand forward; and __fish_seen_subcommand_from explain" -l profile -d 'Restrict operations to the named profile' -r
complete -c spt -n "__fish_spt_using_subcommand forward; and __fish_seen_subcommand_from explain" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand forward; and __fish_seen_subcommand_from explain" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand forward; and __fish_seen_subcommand_from explain" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand forward; and __fish_seen_subcommand_from explain" -l json -d 'Convenience alias for `--output json`'
complete -c spt -n "__fish_spt_using_subcommand forward; and __fish_seen_subcommand_from explain" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand forward; and __fish_seen_subcommand_from explain" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand forward; and __fish_seen_subcommand_from explain" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand forward; and __fish_seen_subcommand_from explain" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand forward; and __fish_seen_subcommand_from explain" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand forward; and __fish_seen_subcommand_from explain" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand forward; and __fish_seen_subcommand_from test" -l dns-name -d 'Probe with a DNS resolution' -r
complete -c spt -n "__fish_spt_using_subcommand forward; and __fish_seen_subcommand_from test" -l timeout -d 'Timeout for the connect probe (e.g. `10s`)' -r
complete -c spt -n "__fish_spt_using_subcommand forward; and __fish_seen_subcommand_from test" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand forward; and __fish_seen_subcommand_from test" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand forward; and __fish_seen_subcommand_from test" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand forward; and __fish_seen_subcommand_from test" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand forward; and __fish_seen_subcommand_from test" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand forward; and __fish_seen_subcommand_from test" -l profile -d 'Restrict operations to the named profile' -r
complete -c spt -n "__fish_spt_using_subcommand forward; and __fish_seen_subcommand_from test" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand forward; and __fish_seen_subcommand_from test" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand forward; and __fish_seen_subcommand_from test" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand forward; and __fish_seen_subcommand_from test" -l connect -d 'Probe with a TCP connect'
complete -c spt -n "__fish_spt_using_subcommand forward; and __fish_seen_subcommand_from test" -l json -d 'Convenience alias for `--output json`'
complete -c spt -n "__fish_spt_using_subcommand forward; and __fish_seen_subcommand_from test" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand forward; and __fish_seen_subcommand_from test" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand forward; and __fish_seen_subcommand_from test" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand forward; and __fish_seen_subcommand_from test" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand forward; and __fish_seen_subcommand_from test" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand forward; and __fish_seen_subcommand_from test" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand forward; and __fish_seen_subcommand_from throttle" -l in -d 'Inbound rate (e.g. `10MiB/s`)' -r
complete -c spt -n "__fish_spt_using_subcommand forward; and __fish_seen_subcommand_from throttle" -l out -d 'Outbound rate' -r
complete -c spt -n "__fish_spt_using_subcommand forward; and __fish_seen_subcommand_from throttle" -l connections -d 'Per-forward connection limit' -r
complete -c spt -n "__fish_spt_using_subcommand forward; and __fish_seen_subcommand_from throttle" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand forward; and __fish_seen_subcommand_from throttle" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand forward; and __fish_seen_subcommand_from throttle" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand forward; and __fish_seen_subcommand_from throttle" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand forward; and __fish_seen_subcommand_from throttle" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand forward; and __fish_seen_subcommand_from throttle" -l profile -d 'Restrict operations to the named profile' -r
complete -c spt -n "__fish_spt_using_subcommand forward; and __fish_seen_subcommand_from throttle" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand forward; and __fish_seen_subcommand_from throttle" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand forward; and __fish_seen_subcommand_from throttle" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand forward; and __fish_seen_subcommand_from throttle" -l json -d 'Convenience alias for `--output json`'
complete -c spt -n "__fish_spt_using_subcommand forward; and __fish_seen_subcommand_from throttle" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand forward; and __fish_seen_subcommand_from throttle" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand forward; and __fish_seen_subcommand_from throttle" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand forward; and __fish_seen_subcommand_from throttle" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand forward; and __fish_seen_subcommand_from throttle" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand forward; and __fish_seen_subcommand_from throttle" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand forward; and __fish_seen_subcommand_from remove" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand forward; and __fish_seen_subcommand_from remove" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand forward; and __fish_seen_subcommand_from remove" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand forward; and __fish_seen_subcommand_from remove" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand forward; and __fish_seen_subcommand_from remove" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand forward; and __fish_seen_subcommand_from remove" -l profile -d 'Restrict operations to the named profile' -r
complete -c spt -n "__fish_spt_using_subcommand forward; and __fish_seen_subcommand_from remove" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand forward; and __fish_seen_subcommand_from remove" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand forward; and __fish_seen_subcommand_from remove" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand forward; and __fish_seen_subcommand_from remove" -l json -d 'Convenience alias for `--output json`'
complete -c spt -n "__fish_spt_using_subcommand forward; and __fish_seen_subcommand_from remove" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand forward; and __fish_seen_subcommand_from remove" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand forward; and __fish_seen_subcommand_from remove" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand forward; and __fish_seen_subcommand_from remove" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand forward; and __fish_seen_subcommand_from remove" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand forward; and __fish_seen_subcommand_from remove" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand forward; and __fish_seen_subcommand_from help" -f -a "list" -d 'List configured forwards'
complete -c spt -n "__fish_spt_using_subcommand forward; and __fish_seen_subcommand_from help" -f -a "show" -d 'Show a forward'
complete -c spt -n "__fish_spt_using_subcommand forward; and __fish_seen_subcommand_from help" -f -a "add" -d 'Add a forward'
complete -c spt -n "__fish_spt_using_subcommand forward; and __fish_seen_subcommand_from help" -f -a "explain" -d 'Explain how a forward is plumbed'
complete -c spt -n "__fish_spt_using_subcommand forward; and __fish_seen_subcommand_from help" -f -a "test" -d 'Run targeted forward tests'
complete -c spt -n "__fish_spt_using_subcommand forward; and __fish_seen_subcommand_from help" -f -a "throttle" -d 'Update throttle/limit knobs at runtime'
complete -c spt -n "__fish_spt_using_subcommand forward; and __fish_seen_subcommand_from help" -f -a "remove" -d 'Remove a forward'
complete -c spt -n "__fish_spt_using_subcommand forward; and __fish_seen_subcommand_from help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c spt -n "__fish_spt_using_subcommand tunnel; and not __fish_seen_subcommand_from run status stats sessions stop reload health failover help" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand tunnel; and not __fish_seen_subcommand_from run status stats sessions stop reload health failover help" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand tunnel; and not __fish_seen_subcommand_from run status stats sessions stop reload health failover help" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand tunnel; and not __fish_seen_subcommand_from run status stats sessions stop reload health failover help" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand tunnel; and not __fish_seen_subcommand_from run status stats sessions stop reload health failover help" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand tunnel; and not __fish_seen_subcommand_from run status stats sessions stop reload health failover help" -l profile -d 'Restrict operations to the named profile' -r
complete -c spt -n "__fish_spt_using_subcommand tunnel; and not __fish_seen_subcommand_from run status stats sessions stop reload health failover help" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand tunnel; and not __fish_seen_subcommand_from run status stats sessions stop reload health failover help" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand tunnel; and not __fish_seen_subcommand_from run status stats sessions stop reload health failover help" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand tunnel; and not __fish_seen_subcommand_from run status stats sessions stop reload health failover help" -l json -d 'Convenience alias for `--output json`'
complete -c spt -n "__fish_spt_using_subcommand tunnel; and not __fish_seen_subcommand_from run status stats sessions stop reload health failover help" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand tunnel; and not __fish_seen_subcommand_from run status stats sessions stop reload health failover help" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand tunnel; and not __fish_seen_subcommand_from run status stats sessions stop reload health failover help" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand tunnel; and not __fish_seen_subcommand_from run status stats sessions stop reload health failover help" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand tunnel; and not __fish_seen_subcommand_from run status stats sessions stop reload health failover help" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand tunnel; and not __fish_seen_subcommand_from run status stats sessions stop reload health failover help" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand tunnel; and not __fish_seen_subcommand_from run status stats sessions stop reload health failover help" -f -a "run" -d 'Run configured tunnels'
complete -c spt -n "__fish_spt_using_subcommand tunnel; and not __fish_seen_subcommand_from run status stats sessions stop reload health failover help" -f -a "status" -d 'Show overall tunnel status'
complete -c spt -n "__fish_spt_using_subcommand tunnel; and not __fish_seen_subcommand_from run status stats sessions stop reload health failover help" -f -a "stats" -d 'Live or one-shot stats'
complete -c spt -n "__fish_spt_using_subcommand tunnel; and not __fish_seen_subcommand_from run status stats sessions stop reload health failover help" -f -a "sessions" -d 'List active sessions'
complete -c spt -n "__fish_spt_using_subcommand tunnel; and not __fish_seen_subcommand_from run status stats sessions stop reload health failover help" -f -a "stop" -d 'Stop tunnels'
complete -c spt -n "__fish_spt_using_subcommand tunnel; and not __fish_seen_subcommand_from run status stats sessions stop reload health failover help" -f -a "reload" -d 'Reload running configuration'
complete -c spt -n "__fish_spt_using_subcommand tunnel; and not __fish_seen_subcommand_from run status stats sessions stop reload health failover help" -f -a "health" -d 'Health summary'
complete -c spt -n "__fish_spt_using_subcommand tunnel; and not __fish_seen_subcommand_from run status stats sessions stop reload health failover help" -f -a "failover" -d 'Manually trigger failover for a profile'
complete -c spt -n "__fish_spt_using_subcommand tunnel; and not __fish_seen_subcommand_from run status stats sessions stop reload health failover help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from run" -l profiles -d 'Comma-separated profile filter' -r
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from run" -s J -l jump -d 'Proxy-jump chain `user@host[:port][,user@host…]`. When set, the chain is splatted into every selected profile\'s `hops` table at startup (CLI values take precedence over profile-file hops). Mirrors the OpenSSH `-J` flag (t6-e3)' -r
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from run" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from run" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from run" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from run" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from run" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from run" -l profile -d 'Restrict operations to the named profile' -r
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from run" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from run" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from run" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from run" -l foreground -d 'Run in the foreground'
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from run" -l once -d 'Start once and exit non-zero on startup failure'
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from run" -l json -d 'Convenience alias for `--output json`'
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from run" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from run" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from run" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from run" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from run" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from run" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from status" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from status" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from status" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from status" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from status" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from status" -l profile -d 'Restrict operations to the named profile' -r
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from status" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from status" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from status" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from status" -l watch -d 'Continuously refresh'
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from status" -l json -d 'JSON output'
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from status" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from status" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from status" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from status" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from status" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from status" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from stats" -l profile -d 'Filter by profile' -r
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from stats" -l forward -d 'Filter by forward' -r
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from stats" -l interval -d 'Refresh interval' -r
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from stats" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from stats" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from stats" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from stats" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from stats" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from stats" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from stats" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from stats" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from stats" -l json -d 'JSON output'
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from stats" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from stats" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from stats" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from stats" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from stats" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from stats" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from sessions" -l profile -d 'Filter by profile' -r
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from sessions" -l forward -d 'Filter by forward' -r
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from sessions" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from sessions" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from sessions" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from sessions" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from sessions" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from sessions" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from sessions" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from sessions" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from sessions" -l json -d 'JSON output'
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from sessions" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from sessions" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from sessions" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from sessions" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from sessions" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from sessions" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from stop" -l profile -d 'Stop a specific profile (or all if absent)' -r
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from stop" -l grace -d 'Grace period for in-flight connections' -r
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from stop" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from stop" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from stop" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from stop" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from stop" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from stop" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from stop" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from stop" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from stop" -l json -d 'Convenience alias for `--output json`'
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from stop" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from stop" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from stop" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from stop" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from stop" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from stop" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from reload" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from reload" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from reload" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from reload" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from reload" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from reload" -l profile -d 'Restrict operations to the named profile' -r
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from reload" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from reload" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from reload" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from reload" -l wait -d 'Block until reload finishes'
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from reload" -l json -d 'Convenience alias for `--output json`'
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from reload" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from reload" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from reload" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from reload" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from reload" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from reload" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from health" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from health" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from health" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from health" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from health" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from health" -l profile -d 'Restrict operations to the named profile' -r
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from health" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from health" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from health" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from health" -l json -d 'JSON output'
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from health" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from health" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from health" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from health" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from health" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from health" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from failover" -l endpoint -d 'Override target endpoint as `host:port`. Synonym: `--to`' -r
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from failover" -l reason -d 'Free-form reason for audit' -r
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from failover" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from failover" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from failover" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from failover" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from failover" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from failover" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from failover" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from failover" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from failover" -l json -d 'Convenience alias for `--output json`'
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from failover" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from failover" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from failover" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from failover" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from failover" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from failover" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from help" -f -a "run" -d 'Run configured tunnels'
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from help" -f -a "status" -d 'Show overall tunnel status'
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from help" -f -a "stats" -d 'Live or one-shot stats'
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from help" -f -a "sessions" -d 'List active sessions'
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from help" -f -a "stop" -d 'Stop tunnels'
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from help" -f -a "reload" -d 'Reload running configuration'
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from help" -f -a "health" -d 'Health summary'
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from help" -f -a "failover" -d 'Manually trigger failover for a profile'
complete -c spt -n "__fish_spt_using_subcommand tunnel; and __fish_seen_subcommand_from help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c spt -n "__fish_spt_using_subcommand service; and not __fish_seen_subcommand_from install uninstall start stop restart status render help" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand service; and not __fish_seen_subcommand_from install uninstall start stop restart status render help" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand service; and not __fish_seen_subcommand_from install uninstall start stop restart status render help" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand service; and not __fish_seen_subcommand_from install uninstall start stop restart status render help" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand service; and not __fish_seen_subcommand_from install uninstall start stop restart status render help" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand service; and not __fish_seen_subcommand_from install uninstall start stop restart status render help" -l profile -d 'Restrict operations to the named profile' -r
complete -c spt -n "__fish_spt_using_subcommand service; and not __fish_seen_subcommand_from install uninstall start stop restart status render help" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand service; and not __fish_seen_subcommand_from install uninstall start stop restart status render help" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand service; and not __fish_seen_subcommand_from install uninstall start stop restart status render help" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand service; and not __fish_seen_subcommand_from install uninstall start stop restart status render help" -l json -d 'Convenience alias for `--output json`'
complete -c spt -n "__fish_spt_using_subcommand service; and not __fish_seen_subcommand_from install uninstall start stop restart status render help" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand service; and not __fish_seen_subcommand_from install uninstall start stop restart status render help" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand service; and not __fish_seen_subcommand_from install uninstall start stop restart status render help" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand service; and not __fish_seen_subcommand_from install uninstall start stop restart status render help" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand service; and not __fish_seen_subcommand_from install uninstall start stop restart status render help" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand service; and not __fish_seen_subcommand_from install uninstall start stop restart status render help" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand service; and not __fish_seen_subcommand_from install uninstall start stop restart status render help" -f -a "install" -d 'Install a service for a config file'
complete -c spt -n "__fish_spt_using_subcommand service; and not __fish_seen_subcommand_from install uninstall start stop restart status render help" -f -a "uninstall" -d 'Uninstall a service'
complete -c spt -n "__fish_spt_using_subcommand service; and not __fish_seen_subcommand_from install uninstall start stop restart status render help" -f -a "start" -d 'Start a service'
complete -c spt -n "__fish_spt_using_subcommand service; and not __fish_seen_subcommand_from install uninstall start stop restart status render help" -f -a "stop" -d 'Stop a service'
complete -c spt -n "__fish_spt_using_subcommand service; and not __fish_seen_subcommand_from install uninstall start stop restart status render help" -f -a "restart" -d 'Restart a service'
complete -c spt -n "__fish_spt_using_subcommand service; and not __fish_seen_subcommand_from install uninstall start stop restart status render help" -f -a "status" -d 'Show service status'
complete -c spt -n "__fish_spt_using_subcommand service; and not __fish_seen_subcommand_from install uninstall start stop restart status render help" -f -a "render" -d 'Render the would-be service unit'
complete -c spt -n "__fish_spt_using_subcommand service; and not __fish_seen_subcommand_from install uninstall start stop restart status render help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from install" -l config -d 'Path to the config file backing the service' -r -F
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from install" -l name -d 'Override the service unit name' -r
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from install" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from install" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from install" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from install" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from install" -l profile -d 'Restrict operations to the named profile' -r
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from install" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from install" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from install" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from install" -l user -d 'User-scoped service'
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from install" -l system -d 'System-scoped service'
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from install" -l json -d 'Convenience alias for `--output json`'
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from install" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from install" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from install" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from install" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from install" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from install" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from uninstall" -l config -d 'Path to the config file backing the service' -r -F
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from uninstall" -l name -d 'Override the service unit name' -r
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from uninstall" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from uninstall" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from uninstall" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from uninstall" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from uninstall" -l profile -d 'Restrict operations to the named profile' -r
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from uninstall" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from uninstall" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from uninstall" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from uninstall" -l user -d 'User-scoped service'
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from uninstall" -l system -d 'System-scoped service'
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from uninstall" -l json -d 'Convenience alias for `--output json`'
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from uninstall" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from uninstall" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from uninstall" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from uninstall" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from uninstall" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from uninstall" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from start" -l config -d 'Path to the config file backing the service' -r -F
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from start" -l name -d 'Override the service unit name' -r
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from start" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from start" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from start" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from start" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from start" -l profile -d 'Restrict operations to the named profile' -r
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from start" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from start" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from start" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from start" -l user -d 'User-scoped service'
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from start" -l system -d 'System-scoped service'
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from start" -l json -d 'Convenience alias for `--output json`'
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from start" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from start" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from start" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from start" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from start" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from start" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from stop" -l config -d 'Path to the config file backing the service' -r -F
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from stop" -l name -d 'Override the service unit name' -r
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from stop" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from stop" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from stop" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from stop" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from stop" -l profile -d 'Restrict operations to the named profile' -r
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from stop" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from stop" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from stop" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from stop" -l user -d 'User-scoped service'
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from stop" -l system -d 'System-scoped service'
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from stop" -l json -d 'Convenience alias for `--output json`'
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from stop" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from stop" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from stop" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from stop" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from stop" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from stop" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from restart" -l config -d 'Path to the config file backing the service' -r -F
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from restart" -l name -d 'Override the service unit name' -r
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from restart" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from restart" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from restart" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from restart" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from restart" -l profile -d 'Restrict operations to the named profile' -r
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from restart" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from restart" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from restart" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from restart" -l user -d 'User-scoped service'
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from restart" -l system -d 'System-scoped service'
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from restart" -l json -d 'Convenience alias for `--output json`'
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from restart" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from restart" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from restart" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from restart" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from restart" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from restart" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from status" -l config -d 'Path to the config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from status" -l name -d 'Override the service unit name' -r
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from status" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from status" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from status" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from status" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from status" -l profile -d 'Restrict operations to the named profile' -r
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from status" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from status" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from status" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from status" -l user -d 'User-scoped service'
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from status" -l system -d 'System-scoped service'
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from status" -l json -d 'JSON output'
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from status" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from status" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from status" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from status" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from status" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from status" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from render" -l config -d 'Path to the config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from render" -l name -d 'Override the service unit name' -r
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from render" -l format -d 'Output format' -r -f -a "unit\t'systemd / OpenRC / SysV unit'
plist\t'macOS launchd plist'
windows\t'Windows service definition'"
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from render" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from render" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from render" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from render" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from render" -l profile -d 'Restrict operations to the named profile' -r
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from render" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from render" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from render" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from render" -l user -d 'User-scoped service'
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from render" -l system -d 'System-scoped service'
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from render" -l json -d 'Convenience alias for `--output json`'
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from render" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from render" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from render" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from render" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from render" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from render" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from help" -f -a "install" -d 'Install a service for a config file'
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from help" -f -a "uninstall" -d 'Uninstall a service'
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from help" -f -a "start" -d 'Start a service'
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from help" -f -a "stop" -d 'Stop a service'
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from help" -f -a "restart" -d 'Restart a service'
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from help" -f -a "status" -d 'Show service status'
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from help" -f -a "render" -d 'Render the would-be service unit'
complete -c spt -n "__fish_spt_using_subcommand service; and __fish_seen_subcommand_from help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c spt -n "__fish_spt_using_subcommand key; and not __fish_seen_subcommand_from generate inspect public change-passphrase sign-cert verify-cert install-public help" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand key; and not __fish_seen_subcommand_from generate inspect public change-passphrase sign-cert verify-cert install-public help" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand key; and not __fish_seen_subcommand_from generate inspect public change-passphrase sign-cert verify-cert install-public help" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand key; and not __fish_seen_subcommand_from generate inspect public change-passphrase sign-cert verify-cert install-public help" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand key; and not __fish_seen_subcommand_from generate inspect public change-passphrase sign-cert verify-cert install-public help" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand key; and not __fish_seen_subcommand_from generate inspect public change-passphrase sign-cert verify-cert install-public help" -l profile -d 'Restrict operations to the named profile' -r
complete -c spt -n "__fish_spt_using_subcommand key; and not __fish_seen_subcommand_from generate inspect public change-passphrase sign-cert verify-cert install-public help" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand key; and not __fish_seen_subcommand_from generate inspect public change-passphrase sign-cert verify-cert install-public help" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand key; and not __fish_seen_subcommand_from generate inspect public change-passphrase sign-cert verify-cert install-public help" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand key; and not __fish_seen_subcommand_from generate inspect public change-passphrase sign-cert verify-cert install-public help" -l json -d 'Convenience alias for `--output json`'
complete -c spt -n "__fish_spt_using_subcommand key; and not __fish_seen_subcommand_from generate inspect public change-passphrase sign-cert verify-cert install-public help" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand key; and not __fish_seen_subcommand_from generate inspect public change-passphrase sign-cert verify-cert install-public help" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand key; and not __fish_seen_subcommand_from generate inspect public change-passphrase sign-cert verify-cert install-public help" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand key; and not __fish_seen_subcommand_from generate inspect public change-passphrase sign-cert verify-cert install-public help" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand key; and not __fish_seen_subcommand_from generate inspect public change-passphrase sign-cert verify-cert install-public help" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand key; and not __fish_seen_subcommand_from generate inspect public change-passphrase sign-cert verify-cert install-public help" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand key; and not __fish_seen_subcommand_from generate inspect public change-passphrase sign-cert verify-cert install-public help" -f -a "generate" -d 'Generate a new keypair'
complete -c spt -n "__fish_spt_using_subcommand key; and not __fish_seen_subcommand_from generate inspect public change-passphrase sign-cert verify-cert install-public help" -f -a "inspect" -d 'Inspect a key file'
complete -c spt -n "__fish_spt_using_subcommand key; and not __fish_seen_subcommand_from generate inspect public change-passphrase sign-cert verify-cert install-public help" -f -a "public" -d 'Print a public key (optionally to a file)'
complete -c spt -n "__fish_spt_using_subcommand key; and not __fish_seen_subcommand_from generate inspect public change-passphrase sign-cert verify-cert install-public help" -f -a "change-passphrase" -d 'Change the passphrase on a private key'
complete -c spt -n "__fish_spt_using_subcommand key; and not __fish_seen_subcommand_from generate inspect public change-passphrase sign-cert verify-cert install-public help" -f -a "sign-cert" -d 'Sign an OpenSSH certificate'
complete -c spt -n "__fish_spt_using_subcommand key; and not __fish_seen_subcommand_from generate inspect public change-passphrase sign-cert verify-cert install-public help" -f -a "verify-cert" -d 'Verify an OpenSSH certificate'
complete -c spt -n "__fish_spt_using_subcommand key; and not __fish_seen_subcommand_from generate inspect public change-passphrase sign-cert verify-cert install-public help" -f -a "install-public" -d 'Install a public key on a remote host'
complete -c spt -n "__fish_spt_using_subcommand key; and not __fish_seen_subcommand_from generate inspect public change-passphrase sign-cert verify-cert install-public help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from generate" -l type -d 'Algorithm' -r -f -a "ed25519\t''
ecdsa-p256\t''
rsa\t''"
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from generate" -l out -d 'Output path (private key; public is `<path>.pub`)' -r -F
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from generate" -l bits -d 'RSA bit length (only meaningful for `--type rsa`)' -r
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from generate" -l comment -d 'Optional comment to embed' -r
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from generate" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from generate" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from generate" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from generate" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from generate" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from generate" -l profile -d 'Restrict operations to the named profile' -r
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from generate" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from generate" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from generate" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from generate" -l encrypt -d 'Encrypt the private key at rest with a passphrase'
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from generate" -l json -d 'Convenience alias for `--output json`'
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from generate" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from generate" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from generate" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from generate" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from generate" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from generate" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from inspect" -l fingerprint -d 'Fingerprint hash to print' -r -f -a "sha256\t''
md5\t''"
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from inspect" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from inspect" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from inspect" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from inspect" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from inspect" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from inspect" -l profile -d 'Restrict operations to the named profile' -r
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from inspect" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from inspect" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from inspect" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from inspect" -l json -d 'JSON output'
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from inspect" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from inspect" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from inspect" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from inspect" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from inspect" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from inspect" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from public" -l out -d 'Output file (otherwise stdout)' -r -F
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from public" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from public" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from public" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from public" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from public" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from public" -l profile -d 'Restrict operations to the named profile' -r
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from public" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from public" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from public" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from public" -l json -d 'Convenience alias for `--output json`'
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from public" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from public" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from public" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from public" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from public" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from public" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from change-passphrase" -l new-passphrase-from -d 'Read the new passphrase from a value source (`stdin`, `file:<path>`, or `env:<NAME>`)' -r
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from change-passphrase" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from change-passphrase" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from change-passphrase" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from change-passphrase" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from change-passphrase" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from change-passphrase" -l profile -d 'Restrict operations to the named profile' -r
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from change-passphrase" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from change-passphrase" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from change-passphrase" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from change-passphrase" -l json -d 'Convenience alias for `--output json`'
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from change-passphrase" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from change-passphrase" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from change-passphrase" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from change-passphrase" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from change-passphrase" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from change-passphrase" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from sign-cert" -l ca-key -d 'Path to the signing CA private key' -r -F
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from sign-cert" -l public-key -d 'Public key to sign' -r -F
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from sign-cert" -l principal -d 'One or more principal names (repeat or comma-separated)' -r
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from sign-cert" -l validity -d 'Certificate validity duration (e.g. `1d`, `52w`)' -r
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from sign-cert" -l serial -d 'Serial number to embed' -r
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from sign-cert" -l cert-type -d 'Certificate type (user/host)' -r -f -a "user\t'User certificate'
host\t'Host certificate'"
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from sign-cert" -l key-id -d 'Free-form key id to embed in the certificate' -r
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from sign-cert" -l out -d 'Output certificate path' -r -F
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from sign-cert" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from sign-cert" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from sign-cert" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from sign-cert" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from sign-cert" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from sign-cert" -l profile -d 'Restrict operations to the named profile' -r
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from sign-cert" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from sign-cert" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from sign-cert" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from sign-cert" -l json -d 'Convenience alias for `--output json`'
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from sign-cert" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from sign-cert" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from sign-cert" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from sign-cert" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from sign-cert" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from sign-cert" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from verify-cert" -l trusted-cas -d 'File containing trusted CA public keys (one per line)' -r -F
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from verify-cert" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from verify-cert" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from verify-cert" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from verify-cert" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from verify-cert" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from verify-cert" -l profile -d 'Restrict operations to the named profile' -r
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from verify-cert" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from verify-cert" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from verify-cert" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from verify-cert" -l json -d 'Convenience alias for `--output json`'
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from verify-cert" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from verify-cert" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from verify-cert" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from verify-cert" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from verify-cert" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from verify-cert" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from install-public" -l profile -d 'Owning profile' -r
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from install-public" -l target -d 'Override target as `user@host[:port]`' -r
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from install-public" -l key -d 'Public key path' -r -F
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from install-public" -l remote-command -d 'Override the remote install command' -r
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from install-public" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from install-public" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from install-public" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from install-public" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from install-public" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from install-public" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from install-public" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from install-public" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from install-public" -l json -d 'Convenience alias for `--output json`'
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from install-public" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from install-public" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from install-public" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from install-public" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from install-public" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from install-public" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from help" -f -a "generate" -d 'Generate a new keypair'
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from help" -f -a "inspect" -d 'Inspect a key file'
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from help" -f -a "public" -d 'Print a public key (optionally to a file)'
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from help" -f -a "change-passphrase" -d 'Change the passphrase on a private key'
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from help" -f -a "sign-cert" -d 'Sign an OpenSSH certificate'
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from help" -f -a "verify-cert" -d 'Verify an OpenSSH certificate'
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from help" -f -a "install-public" -d 'Install a public key on a remote host'
complete -c spt -n "__fish_spt_using_subcommand key; and __fish_seen_subcommand_from help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c spt -n "__fish_spt_using_subcommand secret; and not __fish_seen_subcommand_from store set get list rotate remove doctor help" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand secret; and not __fish_seen_subcommand_from store set get list rotate remove doctor help" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand secret; and not __fish_seen_subcommand_from store set get list rotate remove doctor help" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand secret; and not __fish_seen_subcommand_from store set get list rotate remove doctor help" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand secret; and not __fish_seen_subcommand_from store set get list rotate remove doctor help" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand secret; and not __fish_seen_subcommand_from store set get list rotate remove doctor help" -l profile -d 'Restrict operations to the named profile' -r
complete -c spt -n "__fish_spt_using_subcommand secret; and not __fish_seen_subcommand_from store set get list rotate remove doctor help" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand secret; and not __fish_seen_subcommand_from store set get list rotate remove doctor help" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand secret; and not __fish_seen_subcommand_from store set get list rotate remove doctor help" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand secret; and not __fish_seen_subcommand_from store set get list rotate remove doctor help" -l json -d 'Convenience alias for `--output json`'
complete -c spt -n "__fish_spt_using_subcommand secret; and not __fish_seen_subcommand_from store set get list rotate remove doctor help" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand secret; and not __fish_seen_subcommand_from store set get list rotate remove doctor help" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand secret; and not __fish_seen_subcommand_from store set get list rotate remove doctor help" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand secret; and not __fish_seen_subcommand_from store set get list rotate remove doctor help" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand secret; and not __fish_seen_subcommand_from store set get list rotate remove doctor help" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand secret; and not __fish_seen_subcommand_from store set get list rotate remove doctor help" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand secret; and not __fish_seen_subcommand_from store set get list rotate remove doctor help" -f -a "store" -d 'Initialize the secret store'
complete -c spt -n "__fish_spt_using_subcommand secret; and not __fish_seen_subcommand_from store set get list rotate remove doctor help" -f -a "set" -d 'Set a secret'
complete -c spt -n "__fish_spt_using_subcommand secret; and not __fish_seen_subcommand_from store set get list rotate remove doctor help" -f -a "get" -d 'Get a secret (redacted unless `--reveal`)'
complete -c spt -n "__fish_spt_using_subcommand secret; and not __fish_seen_subcommand_from store set get list rotate remove doctor help" -f -a "list" -d 'List known secret names'
complete -c spt -n "__fish_spt_using_subcommand secret; and not __fish_seen_subcommand_from store set get list rotate remove doctor help" -f -a "rotate" -d 'Rotate a secret'
complete -c spt -n "__fish_spt_using_subcommand secret; and not __fish_seen_subcommand_from store set get list rotate remove doctor help" -f -a "remove" -d 'Remove a secret'
complete -c spt -n "__fish_spt_using_subcommand secret; and not __fish_seen_subcommand_from store set get list rotate remove doctor help" -f -a "doctor" -d 'Run secret backend health checks'
complete -c spt -n "__fish_spt_using_subcommand secret; and not __fish_seen_subcommand_from store set get list rotate remove doctor help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from store" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from store" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from store" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from store" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from store" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from store" -l profile -d 'Restrict operations to the named profile' -r
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from store" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from store" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from store" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from store" -l json -d 'Convenience alias for `--output json`'
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from store" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from store" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from store" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from store" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from store" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from store" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from store" -f -a "init" -d 'Initialize a secret store'
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from store" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from set" -l from-env -d 'Read from an environment variable' -r
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from set" -l from-file -d 'Read from a file (mode-checked)' -r -F
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from set" -l vault-path -d 'Vault directory or `vault.spt` file when writing to the local vault' -r -F
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from set" -l passphrase-from -d 'Unlock the vault with a passphrase source (`stdin`, `env:NAME`, `file:<path>`, or `file:///path`)' -r
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from set" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from set" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from set" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from set" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from set" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from set" -l profile -d 'Restrict operations to the named profile' -r
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from set" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from set" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from set" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from set" -l prompt -d 'Read from a TTY prompt'
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from set" -l json -d 'Convenience alias for `--output json`'
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from set" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from set" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from set" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from set" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from set" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from set" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from get" -l vault-path -d 'Vault directory or `vault.spt` file when reading from the local vault' -r -F
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from get" -l passphrase-from -d 'Unlock the vault with a passphrase source' -r
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from get" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from get" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from get" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from get" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from get" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from get" -l profile -d 'Restrict operations to the named profile' -r
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from get" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from get" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from get" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from get" -l reveal -d 'Print the plaintext value'
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from get" -l json -d 'Convenience alias for `--output json`'
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from get" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from get" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from get" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from get" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from get" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from get" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from list" -l namespace -d 'Restrict to a single namespace' -r
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from list" -l vault-path -d 'Vault directory or `vault.spt` file location' -r -F
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from list" -l passphrase-from -d 'Read the vault passphrase from a value source' -r
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from list" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from list" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from list" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from list" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from list" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from list" -l profile -d 'Restrict operations to the named profile' -r
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from list" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from list" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from list" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from list" -l json -d 'JSON output'
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from list" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from list" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from list" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from list" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from list" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from list" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from rotate" -l new-value-from -d 'New value source for `rotate` (`stdin`, `file:<path>`, `env:<NAME>`)' -r
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from rotate" -l vault-path -d 'Vault directory or `vault.spt` file location' -r -F
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from rotate" -l passphrase-from -d 'Read the vault passphrase from a value source' -r
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from rotate" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from rotate" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from rotate" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from rotate" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from rotate" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from rotate" -l profile -d 'Restrict operations to the named profile' -r
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from rotate" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from rotate" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from rotate" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from rotate" -l json -d 'Convenience alias for `--output json`'
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from rotate" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from rotate" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from rotate" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from rotate" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from rotate" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from rotate" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from remove" -l new-value-from -d 'New value source for `rotate` (`stdin`, `file:<path>`, `env:<NAME>`)' -r
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from remove" -l vault-path -d 'Vault directory or `vault.spt` file location' -r -F
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from remove" -l passphrase-from -d 'Read the vault passphrase from a value source' -r
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from remove" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from remove" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from remove" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from remove" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from remove" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from remove" -l profile -d 'Restrict operations to the named profile' -r
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from remove" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from remove" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from remove" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from remove" -l json -d 'Convenience alias for `--output json`'
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from remove" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from remove" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from remove" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from remove" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from remove" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from remove" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from doctor" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from doctor" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from doctor" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from doctor" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from doctor" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from doctor" -l profile -d 'Restrict operations to the named profile' -r
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from doctor" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from doctor" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from doctor" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from doctor" -l json -d 'Convenience alias for `--output json`'
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from doctor" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from doctor" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from doctor" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from doctor" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from doctor" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from doctor" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from help" -f -a "store" -d 'Initialize the secret store'
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from help" -f -a "set" -d 'Set a secret'
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from help" -f -a "get" -d 'Get a secret (redacted unless `--reveal`)'
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from help" -f -a "list" -d 'List known secret names'
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from help" -f -a "rotate" -d 'Rotate a secret'
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from help" -f -a "remove" -d 'Remove a secret'
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from help" -f -a "doctor" -d 'Run secret backend health checks'
complete -c spt -n "__fish_spt_using_subcommand secret; and __fish_seen_subcommand_from help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c spt -n "__fish_spt_using_subcommand auth; and not __fish_seen_subcommand_from test ssh3-login help" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand auth; and not __fish_seen_subcommand_from test ssh3-login help" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand auth; and not __fish_seen_subcommand_from test ssh3-login help" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand auth; and not __fish_seen_subcommand_from test ssh3-login help" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand auth; and not __fish_seen_subcommand_from test ssh3-login help" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand auth; and not __fish_seen_subcommand_from test ssh3-login help" -l profile -d 'Restrict operations to the named profile' -r
complete -c spt -n "__fish_spt_using_subcommand auth; and not __fish_seen_subcommand_from test ssh3-login help" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand auth; and not __fish_seen_subcommand_from test ssh3-login help" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand auth; and not __fish_seen_subcommand_from test ssh3-login help" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand auth; and not __fish_seen_subcommand_from test ssh3-login help" -l json -d 'Convenience alias for `--output json`'
complete -c spt -n "__fish_spt_using_subcommand auth; and not __fish_seen_subcommand_from test ssh3-login help" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand auth; and not __fish_seen_subcommand_from test ssh3-login help" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand auth; and not __fish_seen_subcommand_from test ssh3-login help" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand auth; and not __fish_seen_subcommand_from test ssh3-login help" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand auth; and not __fish_seen_subcommand_from test ssh3-login help" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand auth; and not __fish_seen_subcommand_from test ssh3-login help" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand auth; and not __fish_seen_subcommand_from test ssh3-login help" -f -a "test" -d 'Test authentication for a profile'
complete -c spt -n "__fish_spt_using_subcommand auth; and not __fish_seen_subcommand_from test ssh3-login help" -f -a "ssh3-login" -d 'Run an SSH3 OIDC device-flow login and optionally store the token'
complete -c spt -n "__fish_spt_using_subcommand auth; and not __fish_seen_subcommand_from test ssh3-login help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c spt -n "__fish_spt_using_subcommand auth; and __fish_seen_subcommand_from test" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand auth; and __fish_seen_subcommand_from test" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand auth; and __fish_seen_subcommand_from test" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand auth; and __fish_seen_subcommand_from test" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand auth; and __fish_seen_subcommand_from test" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand auth; and __fish_seen_subcommand_from test" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand auth; and __fish_seen_subcommand_from test" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand auth; and __fish_seen_subcommand_from test" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand auth; and __fish_seen_subcommand_from test" -l json -d 'Convenience alias for `--output json`'
complete -c spt -n "__fish_spt_using_subcommand auth; and __fish_seen_subcommand_from test" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand auth; and __fish_seen_subcommand_from test" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand auth; and __fish_seen_subcommand_from test" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand auth; and __fish_seen_subcommand_from test" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand auth; and __fish_seen_subcommand_from test" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand auth; and __fish_seen_subcommand_from test" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand auth; and __fish_seen_subcommand_from ssh3-login" -l issuer -d 'OIDC issuer URL (the `.well-known/openid-configuration` parent)' -r
complete -c spt -n "__fish_spt_using_subcommand auth; and __fish_seen_subcommand_from ssh3-login" -l client-id -d 'OAuth client id registered with the issuer' -r
complete -c spt -n "__fish_spt_using_subcommand auth; and __fish_seen_subcommand_from ssh3-login" -l audience -d 'Optional OAuth audience' -r
complete -c spt -n "__fish_spt_using_subcommand auth; and __fish_seen_subcommand_from ssh3-login" -l scope -d 'Optional space-separated scope (defaults to `openid offline_access`)' -r
complete -c spt -n "__fish_spt_using_subcommand auth; and __fish_seen_subcommand_from ssh3-login" -l save-as -d 'If set, persist the resulting access (and refresh) token through the configured secret backend at this `secret://ns/name` ref' -r
complete -c spt -n "__fish_spt_using_subcommand auth; and __fish_seen_subcommand_from ssh3-login" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand auth; and __fish_seen_subcommand_from ssh3-login" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand auth; and __fish_seen_subcommand_from ssh3-login" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand auth; and __fish_seen_subcommand_from ssh3-login" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand auth; and __fish_seen_subcommand_from ssh3-login" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand auth; and __fish_seen_subcommand_from ssh3-login" -l profile -d 'Restrict operations to the named profile' -r
complete -c spt -n "__fish_spt_using_subcommand auth; and __fish_seen_subcommand_from ssh3-login" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand auth; and __fish_seen_subcommand_from ssh3-login" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand auth; and __fish_seen_subcommand_from ssh3-login" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand auth; and __fish_seen_subcommand_from ssh3-login" -l json -d 'JSON output (machine-readable)'
complete -c spt -n "__fish_spt_using_subcommand auth; and __fish_seen_subcommand_from ssh3-login" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand auth; and __fish_seen_subcommand_from ssh3-login" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand auth; and __fish_seen_subcommand_from ssh3-login" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand auth; and __fish_seen_subcommand_from ssh3-login" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand auth; and __fish_seen_subcommand_from ssh3-login" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand auth; and __fish_seen_subcommand_from ssh3-login" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand auth; and __fish_seen_subcommand_from help" -f -a "test" -d 'Test authentication for a profile'
complete -c spt -n "__fish_spt_using_subcommand auth; and __fish_seen_subcommand_from help" -f -a "ssh3-login" -d 'Run an SSH3 OIDC device-flow login and optionally store the token'
complete -c spt -n "__fish_spt_using_subcommand auth; and __fish_seen_subcommand_from help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c spt -n "__fish_spt_using_subcommand dns; and not __fish_seen_subcommand_from serve status query upstream record hosts help" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand dns; and not __fish_seen_subcommand_from serve status query upstream record hosts help" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand dns; and not __fish_seen_subcommand_from serve status query upstream record hosts help" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand dns; and not __fish_seen_subcommand_from serve status query upstream record hosts help" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand dns; and not __fish_seen_subcommand_from serve status query upstream record hosts help" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand dns; and not __fish_seen_subcommand_from serve status query upstream record hosts help" -l profile -d 'Restrict operations to the named profile' -r
complete -c spt -n "__fish_spt_using_subcommand dns; and not __fish_seen_subcommand_from serve status query upstream record hosts help" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand dns; and not __fish_seen_subcommand_from serve status query upstream record hosts help" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand dns; and not __fish_seen_subcommand_from serve status query upstream record hosts help" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand dns; and not __fish_seen_subcommand_from serve status query upstream record hosts help" -l json -d 'Convenience alias for `--output json`'
complete -c spt -n "__fish_spt_using_subcommand dns; and not __fish_seen_subcommand_from serve status query upstream record hosts help" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand dns; and not __fish_seen_subcommand_from serve status query upstream record hosts help" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand dns; and not __fish_seen_subcommand_from serve status query upstream record hosts help" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand dns; and not __fish_seen_subcommand_from serve status query upstream record hosts help" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand dns; and not __fish_seen_subcommand_from serve status query upstream record hosts help" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand dns; and not __fish_seen_subcommand_from serve status query upstream record hosts help" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand dns; and not __fish_seen_subcommand_from serve status query upstream record hosts help" -f -a "serve" -d 'Run the resolver'
complete -c spt -n "__fish_spt_using_subcommand dns; and not __fish_seen_subcommand_from serve status query upstream record hosts help" -f -a "status" -d 'Resolver status'
complete -c spt -n "__fish_spt_using_subcommand dns; and not __fish_seen_subcommand_from serve status query upstream record hosts help" -f -a "query" -d 'Issue a query against the configured resolver'
complete -c spt -n "__fish_spt_using_subcommand dns; and not __fish_seen_subcommand_from serve status query upstream record hosts help" -f -a "upstream" -d 'Manage upstream resolvers'
complete -c spt -n "__fish_spt_using_subcommand dns; and not __fish_seen_subcommand_from serve status query upstream record hosts help" -f -a "record" -d 'Manage managed records'
complete -c spt -n "__fish_spt_using_subcommand dns; and not __fish_seen_subcommand_from serve status query upstream record hosts help" -f -a "hosts" -d 'Manage hosts-file rendering / apply / restore'
complete -c spt -n "__fish_spt_using_subcommand dns; and not __fish_seen_subcommand_from serve status query upstream record hosts help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c spt -n "__fish_spt_using_subcommand dns; and __fish_seen_subcommand_from serve" -l config -d 'Override config path' -r -F
complete -c spt -n "__fish_spt_using_subcommand dns; and __fish_seen_subcommand_from serve" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand dns; and __fish_seen_subcommand_from serve" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand dns; and __fish_seen_subcommand_from serve" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand dns; and __fish_seen_subcommand_from serve" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand dns; and __fish_seen_subcommand_from serve" -l profile -d 'Restrict operations to the named profile' -r
complete -c spt -n "__fish_spt_using_subcommand dns; and __fish_seen_subcommand_from serve" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand dns; and __fish_seen_subcommand_from serve" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand dns; and __fish_seen_subcommand_from serve" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand dns; and __fish_seen_subcommand_from serve" -l foreground -d 'Run in the foreground'
complete -c spt -n "__fish_spt_using_subcommand dns; and __fish_seen_subcommand_from serve" -l json -d 'Convenience alias for `--output json`'
complete -c spt -n "__fish_spt_using_subcommand dns; and __fish_seen_subcommand_from serve" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand dns; and __fish_seen_subcommand_from serve" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand dns; and __fish_seen_subcommand_from serve" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand dns; and __fish_seen_subcommand_from serve" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand dns; and __fish_seen_subcommand_from serve" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand dns; and __fish_seen_subcommand_from serve" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand dns; and __fish_seen_subcommand_from status" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand dns; and __fish_seen_subcommand_from status" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand dns; and __fish_seen_subcommand_from status" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand dns; and __fish_seen_subcommand_from status" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand dns; and __fish_seen_subcommand_from status" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand dns; and __fish_seen_subcommand_from status" -l profile -d 'Restrict operations to the named profile' -r
complete -c spt -n "__fish_spt_using_subcommand dns; and __fish_seen_subcommand_from status" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand dns; and __fish_seen_subcommand_from status" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand dns; and __fish_seen_subcommand_from status" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand dns; and __fish_seen_subcommand_from status" -l json -d 'JSON output'
complete -c spt -n "__fish_spt_using_subcommand dns; and __fish_seen_subcommand_from status" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand dns; and __fish_seen_subcommand_from status" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand dns; and __fish_seen_subcommand_from status" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand dns; and __fish_seen_subcommand_from status" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand dns; and __fish_seen_subcommand_from status" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand dns; and __fish_seen_subcommand_from status" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand dns; and __fish_seen_subcommand_from query" -l type -d 'Record type' -r -f -a "a\t''
aaaa\t''
srv\t''
txt\t''"
complete -c spt -n "__fish_spt_using_subcommand dns; and __fish_seen_subcommand_from query" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand dns; and __fish_seen_subcommand_from query" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand dns; and __fish_seen_subcommand_from query" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand dns; and __fish_seen_subcommand_from query" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand dns; and __fish_seen_subcommand_from query" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand dns; and __fish_seen_subcommand_from query" -l profile -d 'Restrict operations to the named profile' -r
complete -c spt -n "__fish_spt_using_subcommand dns; and __fish_seen_subcommand_from query" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand dns; and __fish_seen_subcommand_from query" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand dns; and __fish_seen_subcommand_from query" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand dns; and __fish_seen_subcommand_from query" -l json -d 'Convenience alias for `--output json`'
complete -c spt -n "__fish_spt_using_subcommand dns; and __fish_seen_subcommand_from query" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand dns; and __fish_seen_subcommand_from query" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand dns; and __fish_seen_subcommand_from query" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand dns; and __fish_seen_subcommand_from query" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand dns; and __fish_seen_subcommand_from query" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand dns; and __fish_seen_subcommand_from query" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand dns; and __fish_seen_subcommand_from upstream" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand dns; and __fish_seen_subcommand_from upstream" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand dns; and __fish_seen_subcommand_from upstream" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand dns; and __fish_seen_subcommand_from upstream" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand dns; and __fish_seen_subcommand_from upstream" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand dns; and __fish_seen_subcommand_from upstream" -l profile -d 'Restrict operations to the named profile' -r
complete -c spt -n "__fish_spt_using_subcommand dns; and __fish_seen_subcommand_from upstream" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand dns; and __fish_seen_subcommand_from upstream" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand dns; and __fish_seen_subcommand_from upstream" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand dns; and __fish_seen_subcommand_from upstream" -l json -d 'Convenience alias for `--output json`'
complete -c spt -n "__fish_spt_using_subcommand dns; and __fish_seen_subcommand_from upstream" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand dns; and __fish_seen_subcommand_from upstream" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand dns; and __fish_seen_subcommand_from upstream" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand dns; and __fish_seen_subcommand_from upstream" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand dns; and __fish_seen_subcommand_from upstream" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand dns; and __fish_seen_subcommand_from upstream" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand dns; and __fish_seen_subcommand_from upstream" -f -a "set" -d 'Replace the upstream list'
complete -c spt -n "__fish_spt_using_subcommand dns; and __fish_seen_subcommand_from upstream" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c spt -n "__fish_spt_using_subcommand dns; and __fish_seen_subcommand_from record" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand dns; and __fish_seen_subcommand_from record" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand dns; and __fish_seen_subcommand_from record" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand dns; and __fish_seen_subcommand_from record" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand dns; and __fish_seen_subcommand_from record" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand dns; and __fish_seen_subcommand_from record" -l profile -d 'Restrict operations to the named profile' -r
complete -c spt -n "__fish_spt_using_subcommand dns; and __fish_seen_subcommand_from record" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand dns; and __fish_seen_subcommand_from record" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand dns; and __fish_seen_subcommand_from record" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand dns; and __fish_seen_subcommand_from record" -l json -d 'Convenience alias for `--output json`'
complete -c spt -n "__fish_spt_using_subcommand dns; and __fish_seen_subcommand_from record" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand dns; and __fish_seen_subcommand_from record" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand dns; and __fish_seen_subcommand_from record" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand dns; and __fish_seen_subcommand_from record" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand dns; and __fish_seen_subcommand_from record" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand dns; and __fish_seen_subcommand_from record" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand dns; and __fish_seen_subcommand_from record" -f -a "add" -d 'Add a managed record'
complete -c spt -n "__fish_spt_using_subcommand dns; and __fish_seen_subcommand_from record" -f -a "remove" -d 'Remove a managed record'
complete -c spt -n "__fish_spt_using_subcommand dns; and __fish_seen_subcommand_from record" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c spt -n "__fish_spt_using_subcommand dns; and __fish_seen_subcommand_from hosts" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand dns; and __fish_seen_subcommand_from hosts" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand dns; and __fish_seen_subcommand_from hosts" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand dns; and __fish_seen_subcommand_from hosts" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand dns; and __fish_seen_subcommand_from hosts" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand dns; and __fish_seen_subcommand_from hosts" -l profile -d 'Restrict operations to the named profile' -r
complete -c spt -n "__fish_spt_using_subcommand dns; and __fish_seen_subcommand_from hosts" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand dns; and __fish_seen_subcommand_from hosts" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand dns; and __fish_seen_subcommand_from hosts" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand dns; and __fish_seen_subcommand_from hosts" -l json -d 'Convenience alias for `--output json`'
complete -c spt -n "__fish_spt_using_subcommand dns; and __fish_seen_subcommand_from hosts" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand dns; and __fish_seen_subcommand_from hosts" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand dns; and __fish_seen_subcommand_from hosts" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand dns; and __fish_seen_subcommand_from hosts" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand dns; and __fish_seen_subcommand_from hosts" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand dns; and __fish_seen_subcommand_from hosts" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand dns; and __fish_seen_subcommand_from hosts" -f -a "render" -d 'Render the would-be hosts file'
complete -c spt -n "__fish_spt_using_subcommand dns; and __fish_seen_subcommand_from hosts" -f -a "apply" -d 'Apply the rendered hosts file'
complete -c spt -n "__fish_spt_using_subcommand dns; and __fish_seen_subcommand_from hosts" -f -a "restore" -d 'Restore a previous hosts backup'
complete -c spt -n "__fish_spt_using_subcommand dns; and __fish_seen_subcommand_from hosts" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c spt -n "__fish_spt_using_subcommand dns; and __fish_seen_subcommand_from help" -f -a "serve" -d 'Run the resolver'
complete -c spt -n "__fish_spt_using_subcommand dns; and __fish_seen_subcommand_from help" -f -a "status" -d 'Resolver status'
complete -c spt -n "__fish_spt_using_subcommand dns; and __fish_seen_subcommand_from help" -f -a "query" -d 'Issue a query against the configured resolver'
complete -c spt -n "__fish_spt_using_subcommand dns; and __fish_seen_subcommand_from help" -f -a "upstream" -d 'Manage upstream resolvers'
complete -c spt -n "__fish_spt_using_subcommand dns; and __fish_seen_subcommand_from help" -f -a "record" -d 'Manage managed records'
complete -c spt -n "__fish_spt_using_subcommand dns; and __fish_seen_subcommand_from help" -f -a "hosts" -d 'Manage hosts-file rendering / apply / restore'
complete -c spt -n "__fish_spt_using_subcommand dns; and __fish_seen_subcommand_from help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c spt -n "__fish_spt_using_subcommand firewall; and not __fish_seen_subcommand_from plan apply remove status interfaces bind-preview gateway policy help" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand firewall; and not __fish_seen_subcommand_from plan apply remove status interfaces bind-preview gateway policy help" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand firewall; and not __fish_seen_subcommand_from plan apply remove status interfaces bind-preview gateway policy help" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand firewall; and not __fish_seen_subcommand_from plan apply remove status interfaces bind-preview gateway policy help" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand firewall; and not __fish_seen_subcommand_from plan apply remove status interfaces bind-preview gateway policy help" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand firewall; and not __fish_seen_subcommand_from plan apply remove status interfaces bind-preview gateway policy help" -l profile -d 'Restrict operations to the named profile' -r
complete -c spt -n "__fish_spt_using_subcommand firewall; and not __fish_seen_subcommand_from plan apply remove status interfaces bind-preview gateway policy help" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand firewall; and not __fish_seen_subcommand_from plan apply remove status interfaces bind-preview gateway policy help" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand firewall; and not __fish_seen_subcommand_from plan apply remove status interfaces bind-preview gateway policy help" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand firewall; and not __fish_seen_subcommand_from plan apply remove status interfaces bind-preview gateway policy help" -l json -d 'Convenience alias for `--output json`'
complete -c spt -n "__fish_spt_using_subcommand firewall; and not __fish_seen_subcommand_from plan apply remove status interfaces bind-preview gateway policy help" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand firewall; and not __fish_seen_subcommand_from plan apply remove status interfaces bind-preview gateway policy help" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand firewall; and not __fish_seen_subcommand_from plan apply remove status interfaces bind-preview gateway policy help" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand firewall; and not __fish_seen_subcommand_from plan apply remove status interfaces bind-preview gateway policy help" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand firewall; and not __fish_seen_subcommand_from plan apply remove status interfaces bind-preview gateway policy help" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand firewall; and not __fish_seen_subcommand_from plan apply remove status interfaces bind-preview gateway policy help" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand firewall; and not __fish_seen_subcommand_from plan apply remove status interfaces bind-preview gateway policy help" -f -a "plan" -d 'Plan rules without applying'
complete -c spt -n "__fish_spt_using_subcommand firewall; and not __fish_seen_subcommand_from plan apply remove status interfaces bind-preview gateway policy help" -f -a "apply" -d 'Apply rules (idempotent)'
complete -c spt -n "__fish_spt_using_subcommand firewall; and not __fish_seen_subcommand_from plan apply remove status interfaces bind-preview gateway policy help" -f -a "remove" -d 'Remove rules'
complete -c spt -n "__fish_spt_using_subcommand firewall; and not __fish_seen_subcommand_from plan apply remove status interfaces bind-preview gateway policy help" -f -a "status" -d 'Show current applied state'
complete -c spt -n "__fish_spt_using_subcommand firewall; and not __fish_seen_subcommand_from plan apply remove status interfaces bind-preview gateway policy help" -f -a "interfaces" -d 'List interfaces / bind targets'
complete -c spt -n "__fish_spt_using_subcommand firewall; and not __fish_seen_subcommand_from plan apply remove status interfaces bind-preview gateway policy help" -f -a "bind-preview" -d 'Preview the bind for a forward'
complete -c spt -n "__fish_spt_using_subcommand firewall; and not __fish_seen_subcommand_from plan apply remove status interfaces bind-preview gateway policy help" -f -a "gateway" -d 'Manage gateway/interface defaults in config'
complete -c spt -n "__fish_spt_using_subcommand firewall; and not __fish_seen_subcommand_from plan apply remove status interfaces bind-preview gateway policy help" -f -a "policy" -d 'Inspect and manage GPO-style policy values'
complete -c spt -n "__fish_spt_using_subcommand firewall; and not __fish_seen_subcommand_from plan apply remove status interfaces bind-preview gateway policy help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from plan" -l profile -d 'Filter by profile' -r
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from plan" -l forward -d 'Filter by forward' -r
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from plan" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from plan" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from plan" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from plan" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from plan" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from plan" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from plan" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from plan" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from plan" -l json -d 'JSON output'
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from plan" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from plan" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from plan" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from plan" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from plan" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from plan" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from apply" -l profile -d 'Filter by profile' -r
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from apply" -l forward -d 'Filter by forward' -r
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from apply" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from apply" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from apply" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from apply" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from apply" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from apply" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from apply" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from apply" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from apply" -l user -d 'User-scoped scope'
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from apply" -l system -d 'System-scoped scope'
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from apply" -l dry-run -d 'Print actions without changing system state'
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from apply" -l json -d 'Convenience alias for `--output json`'
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from apply" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from apply" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from apply" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from apply" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from apply" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from remove" -l profile -d 'Filter by profile' -r
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from remove" -l forward -d 'Filter by forward' -r
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from remove" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from remove" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from remove" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from remove" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from remove" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from remove" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from remove" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from remove" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from remove" -l user -d 'User-scoped scope'
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from remove" -l system -d 'System-scoped scope'
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from remove" -l dry-run -d 'Print actions without changing system state'
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from remove" -l json -d 'Convenience alias for `--output json`'
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from remove" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from remove" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from remove" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from remove" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from remove" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from status" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from status" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from status" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from status" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from status" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from status" -l profile -d 'Restrict operations to the named profile' -r
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from status" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from status" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from status" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from status" -l json -d 'JSON output'
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from status" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from status" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from status" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from status" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from status" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from status" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from interfaces" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from interfaces" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from interfaces" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from interfaces" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from interfaces" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from interfaces" -l profile -d 'Restrict operations to the named profile' -r
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from interfaces" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from interfaces" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from interfaces" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from interfaces" -l json -d 'JSON output'
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from interfaces" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from interfaces" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from interfaces" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from interfaces" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from interfaces" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from interfaces" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from bind-preview" -l forward -d '`<profile>/<forward>`' -r
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from bind-preview" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from bind-preview" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from bind-preview" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from bind-preview" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from bind-preview" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from bind-preview" -l profile -d 'Restrict operations to the named profile' -r
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from bind-preview" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from bind-preview" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from bind-preview" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from bind-preview" -l json -d 'JSON output'
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from bind-preview" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from bind-preview" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from bind-preview" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from bind-preview" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from bind-preview" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from bind-preview" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from gateway" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from gateway" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from gateway" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from gateway" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from gateway" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from gateway" -l profile -d 'Restrict operations to the named profile' -r
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from gateway" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from gateway" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from gateway" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from gateway" -l json -d 'Convenience alias for `--output json`'
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from gateway" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from gateway" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from gateway" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from gateway" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from gateway" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from gateway" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from gateway" -f -a "show" -d 'Show configured interface/gateway policy'
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from gateway" -f -a "set" -d 'Update configured interface/gateway policy'
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from gateway" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from policy" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from policy" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from policy" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from policy" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from policy" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from policy" -l profile -d 'Restrict operations to the named profile' -r
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from policy" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from policy" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from policy" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from policy" -l json -d 'Convenience alias for `--output json`'
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from policy" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from policy" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from policy" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from policy" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from policy" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from policy" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from policy" -f -a "list" -d 'List known policy bindings'
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from policy" -f -a "show" -d 'Show live registry policy overlay and effective network/firewall fields'
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from policy" -f -a "set" -d 'Set a policy value in HKCU/HKLM'
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from policy" -f -a "unset" -d 'Remove a policy value from HKCU/HKLM'
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from policy" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from help" -f -a "plan" -d 'Plan rules without applying'
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from help" -f -a "apply" -d 'Apply rules (idempotent)'
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from help" -f -a "remove" -d 'Remove rules'
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from help" -f -a "status" -d 'Show current applied state'
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from help" -f -a "interfaces" -d 'List interfaces / bind targets'
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from help" -f -a "bind-preview" -d 'Preview the bind for a forward'
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from help" -f -a "gateway" -d 'Manage gateway/interface defaults in config'
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from help" -f -a "policy" -d 'Inspect and manage GPO-style policy values'
complete -c spt -n "__fish_spt_using_subcommand firewall; and __fish_seen_subcommand_from help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c spt -n "__fish_spt_using_subcommand log; and not __fish_seen_subcommand_from tail remote test export help" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand log; and not __fish_seen_subcommand_from tail remote test export help" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand log; and not __fish_seen_subcommand_from tail remote test export help" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand log; and not __fish_seen_subcommand_from tail remote test export help" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand log; and not __fish_seen_subcommand_from tail remote test export help" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand log; and not __fish_seen_subcommand_from tail remote test export help" -l profile -d 'Restrict operations to the named profile' -r
complete -c spt -n "__fish_spt_using_subcommand log; and not __fish_seen_subcommand_from tail remote test export help" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand log; and not __fish_seen_subcommand_from tail remote test export help" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand log; and not __fish_seen_subcommand_from tail remote test export help" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand log; and not __fish_seen_subcommand_from tail remote test export help" -l json -d 'Convenience alias for `--output json`'
complete -c spt -n "__fish_spt_using_subcommand log; and not __fish_seen_subcommand_from tail remote test export help" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand log; and not __fish_seen_subcommand_from tail remote test export help" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand log; and not __fish_seen_subcommand_from tail remote test export help" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand log; and not __fish_seen_subcommand_from tail remote test export help" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand log; and not __fish_seen_subcommand_from tail remote test export help" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand log; and not __fish_seen_subcommand_from tail remote test export help" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand log; and not __fish_seen_subcommand_from tail remote test export help" -f -a "tail" -d 'Tail logs'
complete -c spt -n "__fish_spt_using_subcommand log; and not __fish_seen_subcommand_from tail remote test export help" -f -a "remote" -d 'Manage configured remote log sinks'
complete -c spt -n "__fish_spt_using_subcommand log; and not __fish_seen_subcommand_from tail remote test export help" -f -a "test" -d 'Probe a configured sink'
complete -c spt -n "__fish_spt_using_subcommand log; and not __fish_seen_subcommand_from tail remote test export help" -f -a "export" -d 'Export logs to a structured format'
complete -c spt -n "__fish_spt_using_subcommand log; and not __fish_seen_subcommand_from tail remote test export help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c spt -n "__fish_spt_using_subcommand log; and __fish_seen_subcommand_from tail" -l profile -d 'Filter by profile' -r
complete -c spt -n "__fish_spt_using_subcommand log; and __fish_seen_subcommand_from tail" -l since -d 'Lookback window (e.g. `1h`)' -r
complete -c spt -n "__fish_spt_using_subcommand log; and __fish_seen_subcommand_from tail" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand log; and __fish_seen_subcommand_from tail" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand log; and __fish_seen_subcommand_from tail" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand log; and __fish_seen_subcommand_from tail" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand log; and __fish_seen_subcommand_from tail" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand log; and __fish_seen_subcommand_from tail" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand log; and __fish_seen_subcommand_from tail" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand log; and __fish_seen_subcommand_from tail" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand log; and __fish_seen_subcommand_from tail" -l follow -d 'Follow mode'
complete -c spt -n "__fish_spt_using_subcommand log; and __fish_seen_subcommand_from tail" -l json -d 'JSON output'
complete -c spt -n "__fish_spt_using_subcommand log; and __fish_seen_subcommand_from tail" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand log; and __fish_seen_subcommand_from tail" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand log; and __fish_seen_subcommand_from tail" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand log; and __fish_seen_subcommand_from tail" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand log; and __fish_seen_subcommand_from tail" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand log; and __fish_seen_subcommand_from tail" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand log; and __fish_seen_subcommand_from remote" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand log; and __fish_seen_subcommand_from remote" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand log; and __fish_seen_subcommand_from remote" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand log; and __fish_seen_subcommand_from remote" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand log; and __fish_seen_subcommand_from remote" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand log; and __fish_seen_subcommand_from remote" -l profile -d 'Restrict operations to the named profile' -r
complete -c spt -n "__fish_spt_using_subcommand log; and __fish_seen_subcommand_from remote" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand log; and __fish_seen_subcommand_from remote" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand log; and __fish_seen_subcommand_from remote" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand log; and __fish_seen_subcommand_from remote" -l json -d 'Convenience alias for `--output json`'
complete -c spt -n "__fish_spt_using_subcommand log; and __fish_seen_subcommand_from remote" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand log; and __fish_seen_subcommand_from remote" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand log; and __fish_seen_subcommand_from remote" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand log; and __fish_seen_subcommand_from remote" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand log; and __fish_seen_subcommand_from remote" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand log; and __fish_seen_subcommand_from remote" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand log; and __fish_seen_subcommand_from remote" -f -a "list" -d 'List configured remote log sinks'
complete -c spt -n "__fish_spt_using_subcommand log; and __fish_seen_subcommand_from remote" -f -a "test" -d 'Probe a configured remote log sink'
complete -c spt -n "__fish_spt_using_subcommand log; and __fish_seen_subcommand_from remote" -f -a "status" -d 'Show local delivery status for a remote log sink'
complete -c spt -n "__fish_spt_using_subcommand log; and __fish_seen_subcommand_from remote" -f -a "drain" -d 'Drain a remote log sink\'s disk spool'
complete -c spt -n "__fish_spt_using_subcommand log; and __fish_seen_subcommand_from remote" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c spt -n "__fish_spt_using_subcommand log; and __fish_seen_subcommand_from test" -l sink -d 'Sink name' -r
complete -c spt -n "__fish_spt_using_subcommand log; and __fish_seen_subcommand_from test" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand log; and __fish_seen_subcommand_from test" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand log; and __fish_seen_subcommand_from test" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand log; and __fish_seen_subcommand_from test" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand log; and __fish_seen_subcommand_from test" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand log; and __fish_seen_subcommand_from test" -l profile -d 'Restrict operations to the named profile' -r
complete -c spt -n "__fish_spt_using_subcommand log; and __fish_seen_subcommand_from test" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand log; and __fish_seen_subcommand_from test" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand log; and __fish_seen_subcommand_from test" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand log; and __fish_seen_subcommand_from test" -l json -d 'Convenience alias for `--output json`'
complete -c spt -n "__fish_spt_using_subcommand log; and __fish_seen_subcommand_from test" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand log; and __fish_seen_subcommand_from test" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand log; and __fish_seen_subcommand_from test" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand log; and __fish_seen_subcommand_from test" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand log; and __fish_seen_subcommand_from test" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand log; and __fish_seen_subcommand_from test" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand log; and __fish_seen_subcommand_from export" -l format -d 'Output format' -r -f -a "jsonl\t''
csv\t''"
complete -c spt -n "__fish_spt_using_subcommand log; and __fish_seen_subcommand_from export" -l since -d 'Lookback window' -r
complete -c spt -n "__fish_spt_using_subcommand log; and __fish_seen_subcommand_from export" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand log; and __fish_seen_subcommand_from export" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand log; and __fish_seen_subcommand_from export" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand log; and __fish_seen_subcommand_from export" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand log; and __fish_seen_subcommand_from export" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand log; and __fish_seen_subcommand_from export" -l profile -d 'Restrict operations to the named profile' -r
complete -c spt -n "__fish_spt_using_subcommand log; and __fish_seen_subcommand_from export" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand log; and __fish_seen_subcommand_from export" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand log; and __fish_seen_subcommand_from export" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand log; and __fish_seen_subcommand_from export" -l json -d 'Convenience alias for `--output json`'
complete -c spt -n "__fish_spt_using_subcommand log; and __fish_seen_subcommand_from export" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand log; and __fish_seen_subcommand_from export" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand log; and __fish_seen_subcommand_from export" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand log; and __fish_seen_subcommand_from export" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand log; and __fish_seen_subcommand_from export" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand log; and __fish_seen_subcommand_from export" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand log; and __fish_seen_subcommand_from help" -f -a "tail" -d 'Tail logs'
complete -c spt -n "__fish_spt_using_subcommand log; and __fish_seen_subcommand_from help" -f -a "remote" -d 'Manage configured remote log sinks'
complete -c spt -n "__fish_spt_using_subcommand log; and __fish_seen_subcommand_from help" -f -a "test" -d 'Probe a configured sink'
complete -c spt -n "__fish_spt_using_subcommand log; and __fish_seen_subcommand_from help" -f -a "export" -d 'Export logs to a structured format'
complete -c spt -n "__fish_spt_using_subcommand log; and __fish_seen_subcommand_from help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c spt -n "__fish_spt_using_subcommand observe; and not __fish_seen_subcommand_from metrics windows-event help" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand observe; and not __fish_seen_subcommand_from metrics windows-event help" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand observe; and not __fish_seen_subcommand_from metrics windows-event help" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand observe; and not __fish_seen_subcommand_from metrics windows-event help" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand observe; and not __fish_seen_subcommand_from metrics windows-event help" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand observe; and not __fish_seen_subcommand_from metrics windows-event help" -l profile -d 'Restrict operations to the named profile' -r
complete -c spt -n "__fish_spt_using_subcommand observe; and not __fish_seen_subcommand_from metrics windows-event help" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand observe; and not __fish_seen_subcommand_from metrics windows-event help" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand observe; and not __fish_seen_subcommand_from metrics windows-event help" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand observe; and not __fish_seen_subcommand_from metrics windows-event help" -l json -d 'Convenience alias for `--output json`'
complete -c spt -n "__fish_spt_using_subcommand observe; and not __fish_seen_subcommand_from metrics windows-event help" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand observe; and not __fish_seen_subcommand_from metrics windows-event help" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand observe; and not __fish_seen_subcommand_from metrics windows-event help" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand observe; and not __fish_seen_subcommand_from metrics windows-event help" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand observe; and not __fish_seen_subcommand_from metrics windows-event help" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand observe; and not __fish_seen_subcommand_from metrics windows-event help" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand observe; and not __fish_seen_subcommand_from metrics windows-event help" -f -a "metrics" -d 'Print metrics'
complete -c spt -n "__fish_spt_using_subcommand observe; and not __fish_seen_subcommand_from metrics windows-event help" -f -a "windows-event" -d 'Windows Event Log integration'
complete -c spt -n "__fish_spt_using_subcommand observe; and not __fish_seen_subcommand_from metrics windows-event help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c spt -n "__fish_spt_using_subcommand observe; and __fish_seen_subcommand_from metrics" -l format -d 'Output format' -r -f -a "prometheus\t''
json\t''"
complete -c spt -n "__fish_spt_using_subcommand observe; and __fish_seen_subcommand_from metrics" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand observe; and __fish_seen_subcommand_from metrics" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand observe; and __fish_seen_subcommand_from metrics" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand observe; and __fish_seen_subcommand_from metrics" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand observe; and __fish_seen_subcommand_from metrics" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand observe; and __fish_seen_subcommand_from metrics" -l profile -d 'Restrict operations to the named profile' -r
complete -c spt -n "__fish_spt_using_subcommand observe; and __fish_seen_subcommand_from metrics" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand observe; and __fish_seen_subcommand_from metrics" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand observe; and __fish_seen_subcommand_from metrics" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand observe; and __fish_seen_subcommand_from metrics" -l json -d 'Convenience alias for `--output json`'
complete -c spt -n "__fish_spt_using_subcommand observe; and __fish_seen_subcommand_from metrics" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand observe; and __fish_seen_subcommand_from metrics" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand observe; and __fish_seen_subcommand_from metrics" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand observe; and __fish_seen_subcommand_from metrics" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand observe; and __fish_seen_subcommand_from metrics" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand observe; and __fish_seen_subcommand_from metrics" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand observe; and __fish_seen_subcommand_from windows-event" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand observe; and __fish_seen_subcommand_from windows-event" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand observe; and __fish_seen_subcommand_from windows-event" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand observe; and __fish_seen_subcommand_from windows-event" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand observe; and __fish_seen_subcommand_from windows-event" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand observe; and __fish_seen_subcommand_from windows-event" -l profile -d 'Restrict operations to the named profile' -r
complete -c spt -n "__fish_spt_using_subcommand observe; and __fish_seen_subcommand_from windows-event" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand observe; and __fish_seen_subcommand_from windows-event" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand observe; and __fish_seen_subcommand_from windows-event" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand observe; and __fish_seen_subcommand_from windows-event" -l json -d 'Convenience alias for `--output json`'
complete -c spt -n "__fish_spt_using_subcommand observe; and __fish_seen_subcommand_from windows-event" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand observe; and __fish_seen_subcommand_from windows-event" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand observe; and __fish_seen_subcommand_from windows-event" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand observe; and __fish_seen_subcommand_from windows-event" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand observe; and __fish_seen_subcommand_from windows-event" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand observe; and __fish_seen_subcommand_from windows-event" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand observe; and __fish_seen_subcommand_from windows-event" -f -a "install-source" -d 'Install a Windows Event Log source'
complete -c spt -n "__fish_spt_using_subcommand observe; and __fish_seen_subcommand_from windows-event" -f -a "uninstall-source" -d 'Uninstall a Windows Event Log source'
complete -c spt -n "__fish_spt_using_subcommand observe; and __fish_seen_subcommand_from windows-event" -f -a "test" -d 'Emit a test event'
complete -c spt -n "__fish_spt_using_subcommand observe; and __fish_seen_subcommand_from windows-event" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c spt -n "__fish_spt_using_subcommand observe; and __fish_seen_subcommand_from help" -f -a "metrics" -d 'Print metrics'
complete -c spt -n "__fish_spt_using_subcommand observe; and __fish_seen_subcommand_from help" -f -a "windows-event" -d 'Windows Event Log integration'
complete -c spt -n "__fish_spt_using_subcommand observe; and __fish_seen_subcommand_from help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c spt -n "__fish_spt_using_subcommand event; and not __fish_seen_subcommand_from list test replay sink help" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand event; and not __fish_seen_subcommand_from list test replay sink help" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand event; and not __fish_seen_subcommand_from list test replay sink help" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand event; and not __fish_seen_subcommand_from list test replay sink help" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand event; and not __fish_seen_subcommand_from list test replay sink help" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand event; and not __fish_seen_subcommand_from list test replay sink help" -l profile -d 'Restrict operations to the named profile' -r
complete -c spt -n "__fish_spt_using_subcommand event; and not __fish_seen_subcommand_from list test replay sink help" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand event; and not __fish_seen_subcommand_from list test replay sink help" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand event; and not __fish_seen_subcommand_from list test replay sink help" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand event; and not __fish_seen_subcommand_from list test replay sink help" -l json -d 'Convenience alias for `--output json`'
complete -c spt -n "__fish_spt_using_subcommand event; and not __fish_seen_subcommand_from list test replay sink help" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand event; and not __fish_seen_subcommand_from list test replay sink help" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand event; and not __fish_seen_subcommand_from list test replay sink help" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand event; and not __fish_seen_subcommand_from list test replay sink help" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand event; and not __fish_seen_subcommand_from list test replay sink help" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand event; and not __fish_seen_subcommand_from list test replay sink help" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand event; and not __fish_seen_subcommand_from list test replay sink help" -f -a "list" -d 'List configured event bindings'
complete -c spt -n "__fish_spt_using_subcommand event; and not __fish_seen_subcommand_from list test replay sink help" -f -a "test" -d 'Trigger a binding by name'
complete -c spt -n "__fish_spt_using_subcommand event; and not __fish_seen_subcommand_from list test replay sink help" -f -a "replay" -d 'Replay historical events through a binding'
complete -c spt -n "__fish_spt_using_subcommand event; and not __fish_seen_subcommand_from list test replay sink help" -f -a "sink" -d 'Manage event sinks'
complete -c spt -n "__fish_spt_using_subcommand event; and not __fish_seen_subcommand_from list test replay sink help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c spt -n "__fish_spt_using_subcommand event; and __fish_seen_subcommand_from list" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand event; and __fish_seen_subcommand_from list" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand event; and __fish_seen_subcommand_from list" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand event; and __fish_seen_subcommand_from list" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand event; and __fish_seen_subcommand_from list" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand event; and __fish_seen_subcommand_from list" -l profile -d 'Restrict operations to the named profile' -r
complete -c spt -n "__fish_spt_using_subcommand event; and __fish_seen_subcommand_from list" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand event; and __fish_seen_subcommand_from list" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand event; and __fish_seen_subcommand_from list" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand event; and __fish_seen_subcommand_from list" -l json -d 'JSON output'
complete -c spt -n "__fish_spt_using_subcommand event; and __fish_seen_subcommand_from list" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand event; and __fish_seen_subcommand_from list" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand event; and __fish_seen_subcommand_from list" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand event; and __fish_seen_subcommand_from list" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand event; and __fish_seen_subcommand_from list" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand event; and __fish_seen_subcommand_from list" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand event; and __fish_seen_subcommand_from test" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand event; and __fish_seen_subcommand_from test" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand event; and __fish_seen_subcommand_from test" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand event; and __fish_seen_subcommand_from test" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand event; and __fish_seen_subcommand_from test" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand event; and __fish_seen_subcommand_from test" -l profile -d 'Restrict operations to the named profile' -r
complete -c spt -n "__fish_spt_using_subcommand event; and __fish_seen_subcommand_from test" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand event; and __fish_seen_subcommand_from test" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand event; and __fish_seen_subcommand_from test" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand event; and __fish_seen_subcommand_from test" -l json -d 'Convenience alias for `--output json`'
complete -c spt -n "__fish_spt_using_subcommand event; and __fish_seen_subcommand_from test" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand event; and __fish_seen_subcommand_from test" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand event; and __fish_seen_subcommand_from test" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand event; and __fish_seen_subcommand_from test" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand event; and __fish_seen_subcommand_from test" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand event; and __fish_seen_subcommand_from test" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand event; and __fish_seen_subcommand_from replay" -l since -d 'Lookback window' -r
complete -c spt -n "__fish_spt_using_subcommand event; and __fish_seen_subcommand_from replay" -l binding -d 'Binding name' -r
complete -c spt -n "__fish_spt_using_subcommand event; and __fish_seen_subcommand_from replay" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand event; and __fish_seen_subcommand_from replay" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand event; and __fish_seen_subcommand_from replay" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand event; and __fish_seen_subcommand_from replay" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand event; and __fish_seen_subcommand_from replay" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand event; and __fish_seen_subcommand_from replay" -l profile -d 'Restrict operations to the named profile' -r
complete -c spt -n "__fish_spt_using_subcommand event; and __fish_seen_subcommand_from replay" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand event; and __fish_seen_subcommand_from replay" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand event; and __fish_seen_subcommand_from replay" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand event; and __fish_seen_subcommand_from replay" -l json -d 'Convenience alias for `--output json`'
complete -c spt -n "__fish_spt_using_subcommand event; and __fish_seen_subcommand_from replay" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand event; and __fish_seen_subcommand_from replay" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand event; and __fish_seen_subcommand_from replay" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand event; and __fish_seen_subcommand_from replay" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand event; and __fish_seen_subcommand_from replay" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand event; and __fish_seen_subcommand_from replay" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand event; and __fish_seen_subcommand_from sink" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand event; and __fish_seen_subcommand_from sink" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand event; and __fish_seen_subcommand_from sink" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand event; and __fish_seen_subcommand_from sink" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand event; and __fish_seen_subcommand_from sink" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand event; and __fish_seen_subcommand_from sink" -l profile -d 'Restrict operations to the named profile' -r
complete -c spt -n "__fish_spt_using_subcommand event; and __fish_seen_subcommand_from sink" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand event; and __fish_seen_subcommand_from sink" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand event; and __fish_seen_subcommand_from sink" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand event; and __fish_seen_subcommand_from sink" -l json -d 'Convenience alias for `--output json`'
complete -c spt -n "__fish_spt_using_subcommand event; and __fish_seen_subcommand_from sink" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand event; and __fish_seen_subcommand_from sink" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand event; and __fish_seen_subcommand_from sink" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand event; and __fish_seen_subcommand_from sink" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand event; and __fish_seen_subcommand_from sink" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand event; and __fish_seen_subcommand_from sink" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand event; and __fish_seen_subcommand_from sink" -f -a "test" -d 'Test a sink'
complete -c spt -n "__fish_spt_using_subcommand event; and __fish_seen_subcommand_from sink" -f -a "list" -d 'List configured sinks'
complete -c spt -n "__fish_spt_using_subcommand event; and __fish_seen_subcommand_from sink" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c spt -n "__fish_spt_using_subcommand event; and __fish_seen_subcommand_from help" -f -a "list" -d 'List configured event bindings'
complete -c spt -n "__fish_spt_using_subcommand event; and __fish_seen_subcommand_from help" -f -a "test" -d 'Trigger a binding by name'
complete -c spt -n "__fish_spt_using_subcommand event; and __fish_seen_subcommand_from help" -f -a "replay" -d 'Replay historical events through a binding'
complete -c spt -n "__fish_spt_using_subcommand event; and __fish_seen_subcommand_from help" -f -a "sink" -d 'Manage event sinks'
complete -c spt -n "__fish_spt_using_subcommand event; and __fish_seen_subcommand_from help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c spt -n "__fish_spt_using_subcommand stats; and not __fish_seen_subcommand_from summary live connections throughput errors export help" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand stats; and not __fish_seen_subcommand_from summary live connections throughput errors export help" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand stats; and not __fish_seen_subcommand_from summary live connections throughput errors export help" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand stats; and not __fish_seen_subcommand_from summary live connections throughput errors export help" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand stats; and not __fish_seen_subcommand_from summary live connections throughput errors export help" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand stats; and not __fish_seen_subcommand_from summary live connections throughput errors export help" -l profile -d 'Restrict operations to the named profile' -r
complete -c spt -n "__fish_spt_using_subcommand stats; and not __fish_seen_subcommand_from summary live connections throughput errors export help" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand stats; and not __fish_seen_subcommand_from summary live connections throughput errors export help" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand stats; and not __fish_seen_subcommand_from summary live connections throughput errors export help" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand stats; and not __fish_seen_subcommand_from summary live connections throughput errors export help" -l json -d 'Convenience alias for `--output json`'
complete -c spt -n "__fish_spt_using_subcommand stats; and not __fish_seen_subcommand_from summary live connections throughput errors export help" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand stats; and not __fish_seen_subcommand_from summary live connections throughput errors export help" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand stats; and not __fish_seen_subcommand_from summary live connections throughput errors export help" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand stats; and not __fish_seen_subcommand_from summary live connections throughput errors export help" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand stats; and not __fish_seen_subcommand_from summary live connections throughput errors export help" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand stats; and not __fish_seen_subcommand_from summary live connections throughput errors export help" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand stats; and not __fish_seen_subcommand_from summary live connections throughput errors export help" -f -a "summary" -d 'Snapshot summary'
complete -c spt -n "__fish_spt_using_subcommand stats; and not __fish_seen_subcommand_from summary live connections throughput errors export help" -f -a "live" -d 'Live updating view'
complete -c spt -n "__fish_spt_using_subcommand stats; and not __fish_seen_subcommand_from summary live connections throughput errors export help" -f -a "connections" -d 'Connection table'
complete -c spt -n "__fish_spt_using_subcommand stats; and not __fish_seen_subcommand_from summary live connections throughput errors export help" -f -a "throughput" -d 'Throughput windows'
complete -c spt -n "__fish_spt_using_subcommand stats; and not __fish_seen_subcommand_from summary live connections throughput errors export help" -f -a "errors" -d 'Recent errors'
complete -c spt -n "__fish_spt_using_subcommand stats; and not __fish_seen_subcommand_from summary live connections throughput errors export help" -f -a "export" -d 'Export stats to a file'
complete -c spt -n "__fish_spt_using_subcommand stats; and not __fish_seen_subcommand_from summary live connections throughput errors export help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c spt -n "__fish_spt_using_subcommand stats; and __fish_seen_subcommand_from summary" -l profile -d 'Filter by profile' -r
complete -c spt -n "__fish_spt_using_subcommand stats; and __fish_seen_subcommand_from summary" -l forward -d 'Filter by forward' -r
complete -c spt -n "__fish_spt_using_subcommand stats; and __fish_seen_subcommand_from summary" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand stats; and __fish_seen_subcommand_from summary" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand stats; and __fish_seen_subcommand_from summary" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand stats; and __fish_seen_subcommand_from summary" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand stats; and __fish_seen_subcommand_from summary" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand stats; and __fish_seen_subcommand_from summary" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand stats; and __fish_seen_subcommand_from summary" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand stats; and __fish_seen_subcommand_from summary" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand stats; and __fish_seen_subcommand_from summary" -l json -d 'JSON output'
complete -c spt -n "__fish_spt_using_subcommand stats; and __fish_seen_subcommand_from summary" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand stats; and __fish_seen_subcommand_from summary" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand stats; and __fish_seen_subcommand_from summary" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand stats; and __fish_seen_subcommand_from summary" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand stats; and __fish_seen_subcommand_from summary" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand stats; and __fish_seen_subcommand_from summary" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand stats; and __fish_seen_subcommand_from live" -l interval -d 'Refresh interval' -r
complete -c spt -n "__fish_spt_using_subcommand stats; and __fish_seen_subcommand_from live" -l profile -d 'Filter by profile' -r
complete -c spt -n "__fish_spt_using_subcommand stats; and __fish_seen_subcommand_from live" -l forward -d 'Filter by forward' -r
complete -c spt -n "__fish_spt_using_subcommand stats; and __fish_seen_subcommand_from live" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand stats; and __fish_seen_subcommand_from live" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand stats; and __fish_seen_subcommand_from live" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand stats; and __fish_seen_subcommand_from live" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand stats; and __fish_seen_subcommand_from live" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand stats; and __fish_seen_subcommand_from live" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand stats; and __fish_seen_subcommand_from live" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand stats; and __fish_seen_subcommand_from live" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand stats; and __fish_seen_subcommand_from live" -l json -d 'Convenience alias for `--output json`'
complete -c spt -n "__fish_spt_using_subcommand stats; and __fish_seen_subcommand_from live" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand stats; and __fish_seen_subcommand_from live" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand stats; and __fish_seen_subcommand_from live" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand stats; and __fish_seen_subcommand_from live" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand stats; and __fish_seen_subcommand_from live" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand stats; and __fish_seen_subcommand_from live" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand stats; and __fish_seen_subcommand_from connections" -l profile -d 'Filter by profile' -r
complete -c spt -n "__fish_spt_using_subcommand stats; and __fish_seen_subcommand_from connections" -l forward -d 'Filter by forward' -r
complete -c spt -n "__fish_spt_using_subcommand stats; and __fish_seen_subcommand_from connections" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand stats; and __fish_seen_subcommand_from connections" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand stats; and __fish_seen_subcommand_from connections" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand stats; and __fish_seen_subcommand_from connections" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand stats; and __fish_seen_subcommand_from connections" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand stats; and __fish_seen_subcommand_from connections" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand stats; and __fish_seen_subcommand_from connections" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand stats; and __fish_seen_subcommand_from connections" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand stats; and __fish_seen_subcommand_from connections" -l json -d 'JSON output'
complete -c spt -n "__fish_spt_using_subcommand stats; and __fish_seen_subcommand_from connections" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand stats; and __fish_seen_subcommand_from connections" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand stats; and __fish_seen_subcommand_from connections" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand stats; and __fish_seen_subcommand_from connections" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand stats; and __fish_seen_subcommand_from connections" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand stats; and __fish_seen_subcommand_from connections" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand stats; and __fish_seen_subcommand_from throughput" -l profile -d 'Filter by profile' -r
complete -c spt -n "__fish_spt_using_subcommand stats; and __fish_seen_subcommand_from throughput" -l forward -d 'Filter by forward' -r
complete -c spt -n "__fish_spt_using_subcommand stats; and __fish_seen_subcommand_from throughput" -l window -d 'Window size' -r
complete -c spt -n "__fish_spt_using_subcommand stats; and __fish_seen_subcommand_from throughput" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand stats; and __fish_seen_subcommand_from throughput" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand stats; and __fish_seen_subcommand_from throughput" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand stats; and __fish_seen_subcommand_from throughput" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand stats; and __fish_seen_subcommand_from throughput" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand stats; and __fish_seen_subcommand_from throughput" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand stats; and __fish_seen_subcommand_from throughput" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand stats; and __fish_seen_subcommand_from throughput" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand stats; and __fish_seen_subcommand_from throughput" -l json -d 'JSON output'
complete -c spt -n "__fish_spt_using_subcommand stats; and __fish_seen_subcommand_from throughput" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand stats; and __fish_seen_subcommand_from throughput" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand stats; and __fish_seen_subcommand_from throughput" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand stats; and __fish_seen_subcommand_from throughput" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand stats; and __fish_seen_subcommand_from throughput" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand stats; and __fish_seen_subcommand_from throughput" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand stats; and __fish_seen_subcommand_from errors" -l since -d 'Lookback window' -r
complete -c spt -n "__fish_spt_using_subcommand stats; and __fish_seen_subcommand_from errors" -l profile -d 'Filter by profile' -r
complete -c spt -n "__fish_spt_using_subcommand stats; and __fish_seen_subcommand_from errors" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand stats; and __fish_seen_subcommand_from errors" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand stats; and __fish_seen_subcommand_from errors" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand stats; and __fish_seen_subcommand_from errors" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand stats; and __fish_seen_subcommand_from errors" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand stats; and __fish_seen_subcommand_from errors" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand stats; and __fish_seen_subcommand_from errors" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand stats; and __fish_seen_subcommand_from errors" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand stats; and __fish_seen_subcommand_from errors" -l json -d 'JSON output'
complete -c spt -n "__fish_spt_using_subcommand stats; and __fish_seen_subcommand_from errors" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand stats; and __fish_seen_subcommand_from errors" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand stats; and __fish_seen_subcommand_from errors" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand stats; and __fish_seen_subcommand_from errors" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand stats; and __fish_seen_subcommand_from errors" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand stats; and __fish_seen_subcommand_from errors" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand stats; and __fish_seen_subcommand_from export" -l format -d 'Output format' -r -f -a "json\t''
jsonl\t''
csv\t''
prometheus\t''"
complete -c spt -n "__fish_spt_using_subcommand stats; and __fish_seen_subcommand_from export" -l since -d 'Lookback window' -r
complete -c spt -n "__fish_spt_using_subcommand stats; and __fish_seen_subcommand_from export" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand stats; and __fish_seen_subcommand_from export" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand stats; and __fish_seen_subcommand_from export" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand stats; and __fish_seen_subcommand_from export" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand stats; and __fish_seen_subcommand_from export" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand stats; and __fish_seen_subcommand_from export" -l profile -d 'Restrict operations to the named profile' -r
complete -c spt -n "__fish_spt_using_subcommand stats; and __fish_seen_subcommand_from export" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand stats; and __fish_seen_subcommand_from export" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand stats; and __fish_seen_subcommand_from export" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand stats; and __fish_seen_subcommand_from export" -l json -d 'Convenience alias for `--output json`'
complete -c spt -n "__fish_spt_using_subcommand stats; and __fish_seen_subcommand_from export" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand stats; and __fish_seen_subcommand_from export" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand stats; and __fish_seen_subcommand_from export" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand stats; and __fish_seen_subcommand_from export" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand stats; and __fish_seen_subcommand_from export" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand stats; and __fish_seen_subcommand_from export" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand stats; and __fish_seen_subcommand_from help" -f -a "summary" -d 'Snapshot summary'
complete -c spt -n "__fish_spt_using_subcommand stats; and __fish_seen_subcommand_from help" -f -a "live" -d 'Live updating view'
complete -c spt -n "__fish_spt_using_subcommand stats; and __fish_seen_subcommand_from help" -f -a "connections" -d 'Connection table'
complete -c spt -n "__fish_spt_using_subcommand stats; and __fish_seen_subcommand_from help" -f -a "throughput" -d 'Throughput windows'
complete -c spt -n "__fish_spt_using_subcommand stats; and __fish_seen_subcommand_from help" -f -a "errors" -d 'Recent errors'
complete -c spt -n "__fish_spt_using_subcommand stats; and __fish_seen_subcommand_from help" -f -a "export" -d 'Export stats to a file'
complete -c spt -n "__fish_spt_using_subcommand stats; and __fish_seen_subcommand_from help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c spt -n "__fish_spt_using_subcommand session; and not __fish_seen_subcommand_from list show close drain top help" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand session; and not __fish_seen_subcommand_from list show close drain top help" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand session; and not __fish_seen_subcommand_from list show close drain top help" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand session; and not __fish_seen_subcommand_from list show close drain top help" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand session; and not __fish_seen_subcommand_from list show close drain top help" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand session; and not __fish_seen_subcommand_from list show close drain top help" -l profile -d 'Restrict operations to the named profile' -r
complete -c spt -n "__fish_spt_using_subcommand session; and not __fish_seen_subcommand_from list show close drain top help" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand session; and not __fish_seen_subcommand_from list show close drain top help" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand session; and not __fish_seen_subcommand_from list show close drain top help" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand session; and not __fish_seen_subcommand_from list show close drain top help" -l json -d 'Convenience alias for `--output json`'
complete -c spt -n "__fish_spt_using_subcommand session; and not __fish_seen_subcommand_from list show close drain top help" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand session; and not __fish_seen_subcommand_from list show close drain top help" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand session; and not __fish_seen_subcommand_from list show close drain top help" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand session; and not __fish_seen_subcommand_from list show close drain top help" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand session; and not __fish_seen_subcommand_from list show close drain top help" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand session; and not __fish_seen_subcommand_from list show close drain top help" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand session; and not __fish_seen_subcommand_from list show close drain top help" -f -a "list" -d 'List sessions'
complete -c spt -n "__fish_spt_using_subcommand session; and not __fish_seen_subcommand_from list show close drain top help" -f -a "show" -d 'Show a session'
complete -c spt -n "__fish_spt_using_subcommand session; and not __fish_seen_subcommand_from list show close drain top help" -f -a "close" -d 'Close a session'
complete -c spt -n "__fish_spt_using_subcommand session; and not __fish_seen_subcommand_from list show close drain top help" -f -a "drain" -d 'Drain sessions for a profile'
complete -c spt -n "__fish_spt_using_subcommand session; and not __fish_seen_subcommand_from list show close drain top help" -f -a "top" -d 'Top-style live view'
complete -c spt -n "__fish_spt_using_subcommand session; and not __fish_seen_subcommand_from list show close drain top help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c spt -n "__fish_spt_using_subcommand session; and __fish_seen_subcommand_from list" -l profile -d 'Filter by profile' -r
complete -c spt -n "__fish_spt_using_subcommand session; and __fish_seen_subcommand_from list" -l forward -d 'Filter by forward' -r
complete -c spt -n "__fish_spt_using_subcommand session; and __fish_seen_subcommand_from list" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand session; and __fish_seen_subcommand_from list" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand session; and __fish_seen_subcommand_from list" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand session; and __fish_seen_subcommand_from list" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand session; and __fish_seen_subcommand_from list" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand session; and __fish_seen_subcommand_from list" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand session; and __fish_seen_subcommand_from list" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand session; and __fish_seen_subcommand_from list" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand session; and __fish_seen_subcommand_from list" -l json -d 'JSON output'
complete -c spt -n "__fish_spt_using_subcommand session; and __fish_seen_subcommand_from list" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand session; and __fish_seen_subcommand_from list" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand session; and __fish_seen_subcommand_from list" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand session; and __fish_seen_subcommand_from list" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand session; and __fish_seen_subcommand_from list" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand session; and __fish_seen_subcommand_from list" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand session; and __fish_seen_subcommand_from show" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand session; and __fish_seen_subcommand_from show" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand session; and __fish_seen_subcommand_from show" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand session; and __fish_seen_subcommand_from show" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand session; and __fish_seen_subcommand_from show" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand session; and __fish_seen_subcommand_from show" -l profile -d 'Restrict operations to the named profile' -r
complete -c spt -n "__fish_spt_using_subcommand session; and __fish_seen_subcommand_from show" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand session; and __fish_seen_subcommand_from show" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand session; and __fish_seen_subcommand_from show" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand session; and __fish_seen_subcommand_from show" -l json -d 'JSON output'
complete -c spt -n "__fish_spt_using_subcommand session; and __fish_seen_subcommand_from show" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand session; and __fish_seen_subcommand_from show" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand session; and __fish_seen_subcommand_from show" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand session; and __fish_seen_subcommand_from show" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand session; and __fish_seen_subcommand_from show" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand session; and __fish_seen_subcommand_from show" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand session; and __fish_seen_subcommand_from close" -l grace -d 'Grace period' -r
complete -c spt -n "__fish_spt_using_subcommand session; and __fish_seen_subcommand_from close" -l reason -d 'Free-form reason for audit' -r
complete -c spt -n "__fish_spt_using_subcommand session; and __fish_seen_subcommand_from close" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand session; and __fish_seen_subcommand_from close" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand session; and __fish_seen_subcommand_from close" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand session; and __fish_seen_subcommand_from close" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand session; and __fish_seen_subcommand_from close" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand session; and __fish_seen_subcommand_from close" -l profile -d 'Restrict operations to the named profile' -r
complete -c spt -n "__fish_spt_using_subcommand session; and __fish_seen_subcommand_from close" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand session; and __fish_seen_subcommand_from close" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand session; and __fish_seen_subcommand_from close" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand session; and __fish_seen_subcommand_from close" -l json -d 'Convenience alias for `--output json`'
complete -c spt -n "__fish_spt_using_subcommand session; and __fish_seen_subcommand_from close" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand session; and __fish_seen_subcommand_from close" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand session; and __fish_seen_subcommand_from close" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand session; and __fish_seen_subcommand_from close" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand session; and __fish_seen_subcommand_from close" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand session; and __fish_seen_subcommand_from close" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand session; and __fish_seen_subcommand_from drain" -l forward -d 'Filter by forward' -r
complete -c spt -n "__fish_spt_using_subcommand session; and __fish_seen_subcommand_from drain" -l grace -d 'Drain timeout / grace period. Synonym: `--timeout`' -r
complete -c spt -n "__fish_spt_using_subcommand session; and __fish_seen_subcommand_from drain" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand session; and __fish_seen_subcommand_from drain" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand session; and __fish_seen_subcommand_from drain" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand session; and __fish_seen_subcommand_from drain" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand session; and __fish_seen_subcommand_from drain" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand session; and __fish_seen_subcommand_from drain" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand session; and __fish_seen_subcommand_from drain" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand session; and __fish_seen_subcommand_from drain" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand session; and __fish_seen_subcommand_from drain" -l json -d 'Convenience alias for `--output json`'
complete -c spt -n "__fish_spt_using_subcommand session; and __fish_seen_subcommand_from drain" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand session; and __fish_seen_subcommand_from drain" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand session; and __fish_seen_subcommand_from drain" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand session; and __fish_seen_subcommand_from drain" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand session; and __fish_seen_subcommand_from drain" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand session; and __fish_seen_subcommand_from drain" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand session; and __fish_seen_subcommand_from top" -l sort -d 'Sort key' -r -f -a "age\t''
bytes\t''
rate\t''
errors\t''"
complete -c spt -n "__fish_spt_using_subcommand session; and __fish_seen_subcommand_from top" -l limit -d 'Result limit' -r
complete -c spt -n "__fish_spt_using_subcommand session; and __fish_seen_subcommand_from top" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand session; and __fish_seen_subcommand_from top" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand session; and __fish_seen_subcommand_from top" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand session; and __fish_seen_subcommand_from top" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand session; and __fish_seen_subcommand_from top" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand session; and __fish_seen_subcommand_from top" -l profile -d 'Restrict operations to the named profile' -r
complete -c spt -n "__fish_spt_using_subcommand session; and __fish_seen_subcommand_from top" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand session; and __fish_seen_subcommand_from top" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand session; and __fish_seen_subcommand_from top" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand session; and __fish_seen_subcommand_from top" -l json -d 'Convenience alias for `--output json`'
complete -c spt -n "__fish_spt_using_subcommand session; and __fish_seen_subcommand_from top" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand session; and __fish_seen_subcommand_from top" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand session; and __fish_seen_subcommand_from top" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand session; and __fish_seen_subcommand_from top" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand session; and __fish_seen_subcommand_from top" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand session; and __fish_seen_subcommand_from top" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand session; and __fish_seen_subcommand_from help" -f -a "list" -d 'List sessions'
complete -c spt -n "__fish_spt_using_subcommand session; and __fish_seen_subcommand_from help" -f -a "show" -d 'Show a session'
complete -c spt -n "__fish_spt_using_subcommand session; and __fish_seen_subcommand_from help" -f -a "close" -d 'Close a session'
complete -c spt -n "__fish_spt_using_subcommand session; and __fish_seen_subcommand_from help" -f -a "drain" -d 'Drain sessions for a profile'
complete -c spt -n "__fish_spt_using_subcommand session; and __fish_seen_subcommand_from help" -f -a "top" -d 'Top-style live view'
complete -c spt -n "__fish_spt_using_subcommand session; and __fish_seen_subcommand_from help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c spt -n "__fish_spt_using_subcommand ftp; and not __fish_seen_subcommand_from translator help" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand ftp; and not __fish_seen_subcommand_from translator help" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand ftp; and not __fish_seen_subcommand_from translator help" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand ftp; and not __fish_seen_subcommand_from translator help" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand ftp; and not __fish_seen_subcommand_from translator help" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand ftp; and not __fish_seen_subcommand_from translator help" -l profile -d 'Restrict operations to the named profile' -r
complete -c spt -n "__fish_spt_using_subcommand ftp; and not __fish_seen_subcommand_from translator help" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand ftp; and not __fish_seen_subcommand_from translator help" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand ftp; and not __fish_seen_subcommand_from translator help" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand ftp; and not __fish_seen_subcommand_from translator help" -l json -d 'Convenience alias for `--output json`'
complete -c spt -n "__fish_spt_using_subcommand ftp; and not __fish_seen_subcommand_from translator help" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand ftp; and not __fish_seen_subcommand_from translator help" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand ftp; and not __fish_seen_subcommand_from translator help" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand ftp; and not __fish_seen_subcommand_from translator help" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand ftp; and not __fish_seen_subcommand_from translator help" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand ftp; and not __fish_seen_subcommand_from translator help" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand ftp; and not __fish_seen_subcommand_from translator help" -f -a "translator" -d 'Run / manage the FTP→SFTP translator service'
complete -c spt -n "__fish_spt_using_subcommand ftp; and not __fish_seen_subcommand_from translator help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c spt -n "__fish_spt_using_subcommand ftp; and __fish_seen_subcommand_from translator" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand ftp; and __fish_seen_subcommand_from translator" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand ftp; and __fish_seen_subcommand_from translator" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand ftp; and __fish_seen_subcommand_from translator" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand ftp; and __fish_seen_subcommand_from translator" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand ftp; and __fish_seen_subcommand_from translator" -l profile -d 'Restrict operations to the named profile' -r
complete -c spt -n "__fish_spt_using_subcommand ftp; and __fish_seen_subcommand_from translator" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand ftp; and __fish_seen_subcommand_from translator" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand ftp; and __fish_seen_subcommand_from translator" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand ftp; and __fish_seen_subcommand_from translator" -l json -d 'Convenience alias for `--output json`'
complete -c spt -n "__fish_spt_using_subcommand ftp; and __fish_seen_subcommand_from translator" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand ftp; and __fish_seen_subcommand_from translator" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand ftp; and __fish_seen_subcommand_from translator" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand ftp; and __fish_seen_subcommand_from translator" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand ftp; and __fish_seen_subcommand_from translator" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand ftp; and __fish_seen_subcommand_from translator" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand ftp; and __fish_seen_subcommand_from translator" -f -a "serve" -d 'Start the FTP translator listening on `--bind`'
complete -c spt -n "__fish_spt_using_subcommand ftp; and __fish_seen_subcommand_from translator" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c spt -n "__fish_spt_using_subcommand ftp; and __fish_seen_subcommand_from help" -f -a "translator" -d 'Run / manage the FTP→SFTP translator service'
complete -c spt -n "__fish_spt_using_subcommand ftp; and __fish_seen_subcommand_from help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c spt -n "__fish_spt_using_subcommand sftp; and not __fish_seen_subcommand_from test list stat get put mkdir rm rmdir rename cat tail chmod symlink readlink realpath put-recursive get-recursive mount drive umount help" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand sftp; and not __fish_seen_subcommand_from test list stat get put mkdir rm rmdir rename cat tail chmod symlink readlink realpath put-recursive get-recursive mount drive umount help" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand sftp; and not __fish_seen_subcommand_from test list stat get put mkdir rm rmdir rename cat tail chmod symlink readlink realpath put-recursive get-recursive mount drive umount help" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand sftp; and not __fish_seen_subcommand_from test list stat get put mkdir rm rmdir rename cat tail chmod symlink readlink realpath put-recursive get-recursive mount drive umount help" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand sftp; and not __fish_seen_subcommand_from test list stat get put mkdir rm rmdir rename cat tail chmod symlink readlink realpath put-recursive get-recursive mount drive umount help" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand sftp; and not __fish_seen_subcommand_from test list stat get put mkdir rm rmdir rename cat tail chmod symlink readlink realpath put-recursive get-recursive mount drive umount help" -l profile -d 'Restrict operations to the named profile' -r
complete -c spt -n "__fish_spt_using_subcommand sftp; and not __fish_seen_subcommand_from test list stat get put mkdir rm rmdir rename cat tail chmod symlink readlink realpath put-recursive get-recursive mount drive umount help" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand sftp; and not __fish_seen_subcommand_from test list stat get put mkdir rm rmdir rename cat tail chmod symlink readlink realpath put-recursive get-recursive mount drive umount help" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand sftp; and not __fish_seen_subcommand_from test list stat get put mkdir rm rmdir rename cat tail chmod symlink readlink realpath put-recursive get-recursive mount drive umount help" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand sftp; and not __fish_seen_subcommand_from test list stat get put mkdir rm rmdir rename cat tail chmod symlink readlink realpath put-recursive get-recursive mount drive umount help" -l json -d 'Convenience alias for `--output json`'
complete -c spt -n "__fish_spt_using_subcommand sftp; and not __fish_seen_subcommand_from test list stat get put mkdir rm rmdir rename cat tail chmod symlink readlink realpath put-recursive get-recursive mount drive umount help" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand sftp; and not __fish_seen_subcommand_from test list stat get put mkdir rm rmdir rename cat tail chmod symlink readlink realpath put-recursive get-recursive mount drive umount help" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand sftp; and not __fish_seen_subcommand_from test list stat get put mkdir rm rmdir rename cat tail chmod symlink readlink realpath put-recursive get-recursive mount drive umount help" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand sftp; and not __fish_seen_subcommand_from test list stat get put mkdir rm rmdir rename cat tail chmod symlink readlink realpath put-recursive get-recursive mount drive umount help" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand sftp; and not __fish_seen_subcommand_from test list stat get put mkdir rm rmdir rename cat tail chmod symlink readlink realpath put-recursive get-recursive mount drive umount help" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand sftp; and not __fish_seen_subcommand_from test list stat get put mkdir rm rmdir rename cat tail chmod symlink readlink realpath put-recursive get-recursive mount drive umount help" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand sftp; and not __fish_seen_subcommand_from test list stat get put mkdir rm rmdir rename cat tail chmod symlink readlink realpath put-recursive get-recursive mount drive umount help" -f -a "test" -d 'Connect to the profile and open the SFTP subsystem'
complete -c spt -n "__fish_spt_using_subcommand sftp; and not __fish_seen_subcommand_from test list stat get put mkdir rm rmdir rename cat tail chmod symlink readlink realpath put-recursive get-recursive mount drive umount help" -f -a "list" -d 'List a remote directory'
complete -c spt -n "__fish_spt_using_subcommand sftp; and not __fish_seen_subcommand_from test list stat get put mkdir rm rmdir rename cat tail chmod symlink readlink realpath put-recursive get-recursive mount drive umount help" -f -a "stat" -d 'Show metadata for a remote path'
complete -c spt -n "__fish_spt_using_subcommand sftp; and not __fish_seen_subcommand_from test list stat get put mkdir rm rmdir rename cat tail chmod symlink readlink realpath put-recursive get-recursive mount drive umount help" -f -a "get" -d 'Download a remote file'
complete -c spt -n "__fish_spt_using_subcommand sftp; and not __fish_seen_subcommand_from test list stat get put mkdir rm rmdir rename cat tail chmod symlink readlink realpath put-recursive get-recursive mount drive umount help" -f -a "put" -d 'Upload a local file'
complete -c spt -n "__fish_spt_using_subcommand sftp; and not __fish_seen_subcommand_from test list stat get put mkdir rm rmdir rename cat tail chmod symlink readlink realpath put-recursive get-recursive mount drive umount help" -f -a "mkdir" -d 'Create a remote directory'
complete -c spt -n "__fish_spt_using_subcommand sftp; and not __fish_seen_subcommand_from test list stat get put mkdir rm rmdir rename cat tail chmod symlink readlink realpath put-recursive get-recursive mount drive umount help" -f -a "rm" -d 'Remove a remote file'
complete -c spt -n "__fish_spt_using_subcommand sftp; and not __fish_seen_subcommand_from test list stat get put mkdir rm rmdir rename cat tail chmod symlink readlink realpath put-recursive get-recursive mount drive umount help" -f -a "rmdir" -d 'Remove a remote directory'
complete -c spt -n "__fish_spt_using_subcommand sftp; and not __fish_seen_subcommand_from test list stat get put mkdir rm rmdir rename cat tail chmod symlink readlink realpath put-recursive get-recursive mount drive umount help" -f -a "rename" -d 'Rename a remote file or directory'
complete -c spt -n "__fish_spt_using_subcommand sftp; and not __fish_seen_subcommand_from test list stat get put mkdir rm rmdir rename cat tail chmod symlink readlink realpath put-recursive get-recursive mount drive umount help" -f -a "cat" -d 'Print a remote file (with a size cap)'
complete -c spt -n "__fish_spt_using_subcommand sftp; and not __fish_seen_subcommand_from test list stat get put mkdir rm rmdir rename cat tail chmod symlink readlink realpath put-recursive get-recursive mount drive umount help" -f -a "tail" -d 'Print the trailing bytes of a remote file'
complete -c spt -n "__fish_spt_using_subcommand sftp; and not __fish_seen_subcommand_from test list stat get put mkdir rm rmdir rename cat tail chmod symlink readlink realpath put-recursive get-recursive mount drive umount help" -f -a "chmod" -d 'Change POSIX permissions on a remote path'
complete -c spt -n "__fish_spt_using_subcommand sftp; and not __fish_seen_subcommand_from test list stat get put mkdir rm rmdir rename cat tail chmod symlink readlink realpath put-recursive get-recursive mount drive umount help" -f -a "symlink" -d 'Create a remote symbolic link'
complete -c spt -n "__fish_spt_using_subcommand sftp; and not __fish_seen_subcommand_from test list stat get put mkdir rm rmdir rename cat tail chmod symlink readlink realpath put-recursive get-recursive mount drive umount help" -f -a "readlink" -d 'Read the target of a remote symbolic link'
complete -c spt -n "__fish_spt_using_subcommand sftp; and not __fish_seen_subcommand_from test list stat get put mkdir rm rmdir rename cat tail chmod symlink readlink realpath put-recursive get-recursive mount drive umount help" -f -a "realpath" -d 'Canonicalise a remote path'
complete -c spt -n "__fish_spt_using_subcommand sftp; and not __fish_seen_subcommand_from test list stat get put mkdir rm rmdir rename cat tail chmod symlink readlink realpath put-recursive get-recursive mount drive umount help" -f -a "put-recursive" -d 'Mirror a local directory tree onto the server (recursive `put`)'
complete -c spt -n "__fish_spt_using_subcommand sftp; and not __fish_seen_subcommand_from test list stat get put mkdir rm rmdir rename cat tail chmod symlink readlink realpath put-recursive get-recursive mount drive umount help" -f -a "get-recursive" -d 'Mirror a remote directory tree onto the local filesystem (recursive `get`)'
complete -c spt -n "__fish_spt_using_subcommand sftp; and not __fish_seen_subcommand_from test list stat get put mkdir rm rmdir rename cat tail chmod symlink readlink realpath put-recursive get-recursive mount drive umount help" -f -a "mount" -d 'Manage SFTP-backed filesystem mount entries'
complete -c spt -n "__fish_spt_using_subcommand sftp; and not __fish_seen_subcommand_from test list stat get put mkdir rm rmdir rename cat tail chmod symlink readlink realpath put-recursive get-recursive mount drive umount help" -f -a "drive" -d 'Manage SFTP-backed Windows drive entries'
complete -c spt -n "__fish_spt_using_subcommand sftp; and not __fish_seen_subcommand_from test list stat get put mkdir rm rmdir rename cat tail chmod symlink readlink realpath put-recursive get-recursive mount drive umount help" -f -a "umount" -d 'Tear down an SFTP-backed filesystem mount (shorthand for `spt sftp mount stop`)'
complete -c spt -n "__fish_spt_using_subcommand sftp; and not __fish_seen_subcommand_from test list stat get put mkdir rm rmdir rename cat tail chmod symlink readlink realpath put-recursive get-recursive mount drive umount help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from test" -l profile -d 'Profile name' -r
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from test" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from test" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from test" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from test" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from test" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from test" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from test" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from test" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from test" -l json -d 'JSON output'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from test" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from test" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from test" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from test" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from test" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from test" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from list" -l profile -d 'Profile name' -r
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from list" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from list" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from list" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from list" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from list" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from list" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from list" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from list" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from list" -l json -d 'JSON output'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from list" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from list" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from list" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from list" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from list" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from list" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from stat" -l profile -d 'Profile name' -r
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from stat" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from stat" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from stat" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from stat" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from stat" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from stat" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from stat" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from stat" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from stat" -l json -d 'JSON output'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from stat" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from stat" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from stat" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from stat" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from stat" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from stat" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from get" -l profile -d 'Profile name' -r
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from get" -l out -d 'Local output path' -r -F
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from get" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from get" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from get" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from get" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from get" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from get" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from get" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from get" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from get" -l json -d 'Convenience alias for `--output json`'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from get" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from get" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from get" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from get" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from get" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from get" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from put" -l profile -d 'Profile name' -r
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from put" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from put" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from put" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from put" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from put" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from put" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from put" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from put" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from put" -l json -d 'Convenience alias for `--output json`'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from put" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from put" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from put" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from put" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from put" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from put" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from mkdir" -l profile -d 'Profile name' -r
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from mkdir" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from mkdir" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from mkdir" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from mkdir" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from mkdir" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from mkdir" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from mkdir" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from mkdir" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from mkdir" -l json -d 'JSON output'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from mkdir" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from mkdir" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from mkdir" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from mkdir" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from mkdir" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from mkdir" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from rm" -l profile -d 'Profile name' -r
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from rm" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from rm" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from rm" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from rm" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from rm" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from rm" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from rm" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from rm" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from rm" -l json -d 'JSON output'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from rm" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from rm" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from rm" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from rm" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from rm" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from rm" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from rmdir" -l profile -d 'Profile name' -r
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from rmdir" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from rmdir" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from rmdir" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from rmdir" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from rmdir" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from rmdir" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from rmdir" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from rmdir" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from rmdir" -l json -d 'JSON output'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from rmdir" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from rmdir" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from rmdir" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from rmdir" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from rmdir" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from rmdir" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from rename" -l profile -d 'Profile name' -r
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from rename" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from rename" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from rename" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from rename" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from rename" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from rename" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from rename" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from rename" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from rename" -l json -d 'Convenience alias for `--output json`'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from rename" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from rename" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from rename" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from rename" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from rename" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from rename" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from cat" -l profile -d 'Profile name' -r
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from cat" -l size-cap -d 'Maximum number of bytes to read; defaults to 4 MiB' -r
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from cat" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from cat" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from cat" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from cat" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from cat" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from cat" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from cat" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from cat" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from cat" -l json -d 'Convenience alias for `--output json`'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from cat" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from cat" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from cat" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from cat" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from cat" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from cat" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from tail" -l profile -d 'Profile name' -r
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from tail" -l bytes -d 'Number of trailing bytes to print; defaults to 4 KiB' -r
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from tail" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from tail" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from tail" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from tail" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from tail" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from tail" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from tail" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from tail" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from tail" -l json -d 'Convenience alias for `--output json`'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from tail" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from tail" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from tail" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from tail" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from tail" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from tail" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from chmod" -l profile -d 'Profile name' -r
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from chmod" -l mode -d 'Octal mode, for example `0640`' -r
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from chmod" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from chmod" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from chmod" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from chmod" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from chmod" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from chmod" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from chmod" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from chmod" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from chmod" -l json -d 'Convenience alias for `--output json`'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from chmod" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from chmod" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from chmod" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from chmod" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from chmod" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from chmod" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from symlink" -l profile -d 'Profile name' -r
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from symlink" -l target -d 'Target path the link should point to' -r
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from symlink" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from symlink" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from symlink" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from symlink" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from symlink" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from symlink" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from symlink" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from symlink" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from symlink" -l json -d 'Convenience alias for `--output json`'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from symlink" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from symlink" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from symlink" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from symlink" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from symlink" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from symlink" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from readlink" -l profile -d 'Profile name' -r
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from readlink" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from readlink" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from readlink" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from readlink" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from readlink" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from readlink" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from readlink" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from readlink" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from readlink" -l json -d 'JSON output'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from readlink" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from readlink" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from readlink" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from readlink" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from readlink" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from readlink" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from realpath" -l profile -d 'Profile name' -r
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from realpath" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from realpath" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from realpath" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from realpath" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from realpath" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from realpath" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from realpath" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from realpath" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from realpath" -l json -d 'JSON output'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from realpath" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from realpath" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from realpath" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from realpath" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from realpath" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from realpath" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from put-recursive" -l profile -d 'Profile name' -r
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from put-recursive" -l bps -d 'Bandwidth cap, e.g. `5MiB` (parsed via `bytesize`); `0` disables' -r
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from put-recursive" -l checksum -d 'Post-transfer integrity check' -r -f -a "none\t'No post-transfer verification'
sha256\t'SHA-256 each file on both ends'"
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from put-recursive" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from put-recursive" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from put-recursive" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from put-recursive" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from put-recursive" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from put-recursive" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from put-recursive" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from put-recursive" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from put-recursive" -l resume -d 'Resume mode: seek into existing target files instead of truncating'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from put-recursive" -l follow-symlinks -d 'Follow symbolic links during the walk (loops are still detected)'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from put-recursive" -l json -d 'Convenience alias for `--output json`'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from put-recursive" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from put-recursive" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from put-recursive" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from put-recursive" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from put-recursive" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from put-recursive" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from get-recursive" -l profile -d 'Profile name' -r
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from get-recursive" -l bps -d 'Bandwidth cap, e.g. `5MiB` (parsed via `bytesize`); `0` disables' -r
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from get-recursive" -l checksum -d 'Post-transfer integrity check' -r -f -a "none\t'No post-transfer verification'
sha256\t'SHA-256 each file on both ends'"
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from get-recursive" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from get-recursive" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from get-recursive" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from get-recursive" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from get-recursive" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from get-recursive" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from get-recursive" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from get-recursive" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from get-recursive" -l resume -d 'Resume mode: seek into existing target files instead of truncating'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from get-recursive" -l follow-symlinks -d 'Follow symbolic links during the walk (loops are still detected)'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from get-recursive" -l json -d 'Convenience alias for `--output json`'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from get-recursive" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from get-recursive" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from get-recursive" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from get-recursive" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from get-recursive" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from get-recursive" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from mount" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from mount" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from mount" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from mount" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from mount" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from mount" -l profile -d 'Restrict operations to the named profile' -r
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from mount" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from mount" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from mount" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from mount" -l json -d 'Convenience alias for `--output json`'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from mount" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from mount" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from mount" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from mount" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from mount" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from mount" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from mount" -f -a "list" -d 'List configured filesystem mounts'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from mount" -f -a "add" -d 'Add a filesystem mount entry to the config'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from mount" -f -a "remove" -d 'Remove a filesystem mount entry from the config'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from mount" -f -a "plan" -d 'Render the platform plan for a configured or proposed mount'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from mount" -f -a "start" -d 'Start an SFTP-backed filesystem mount'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from mount" -f -a "stop" -d 'Tear down an SFTP-backed filesystem mount'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from mount" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from drive" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from drive" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from drive" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from drive" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from drive" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from drive" -l profile -d 'Restrict operations to the named profile' -r
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from drive" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from drive" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from drive" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from drive" -l json -d 'Convenience alias for `--output json`'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from drive" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from drive" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from drive" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from drive" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from drive" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from drive" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from drive" -f -a "list" -d 'List configured Windows drive mounts'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from drive" -f -a "add" -d 'Add a Windows drive mount entry to the config'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from drive" -f -a "remove" -d 'Remove a Windows drive mount entry from the config'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from drive" -f -a "plan" -d 'Render the platform plan for a configured or proposed drive mount'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from drive" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from umount" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from umount" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from umount" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from umount" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from umount" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from umount" -l profile -d 'Restrict operations to the named profile' -r
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from umount" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from umount" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from umount" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from umount" -l json -d 'JSON output'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from umount" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from umount" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from umount" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from umount" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from umount" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from umount" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from help" -f -a "test" -d 'Connect to the profile and open the SFTP subsystem'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from help" -f -a "list" -d 'List a remote directory'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from help" -f -a "stat" -d 'Show metadata for a remote path'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from help" -f -a "get" -d 'Download a remote file'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from help" -f -a "put" -d 'Upload a local file'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from help" -f -a "mkdir" -d 'Create a remote directory'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from help" -f -a "rm" -d 'Remove a remote file'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from help" -f -a "rmdir" -d 'Remove a remote directory'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from help" -f -a "rename" -d 'Rename a remote file or directory'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from help" -f -a "cat" -d 'Print a remote file (with a size cap)'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from help" -f -a "tail" -d 'Print the trailing bytes of a remote file'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from help" -f -a "chmod" -d 'Change POSIX permissions on a remote path'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from help" -f -a "symlink" -d 'Create a remote symbolic link'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from help" -f -a "readlink" -d 'Read the target of a remote symbolic link'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from help" -f -a "realpath" -d 'Canonicalise a remote path'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from help" -f -a "put-recursive" -d 'Mirror a local directory tree onto the server (recursive `put`)'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from help" -f -a "get-recursive" -d 'Mirror a remote directory tree onto the local filesystem (recursive `get`)'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from help" -f -a "mount" -d 'Manage SFTP-backed filesystem mount entries'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from help" -f -a "drive" -d 'Manage SFTP-backed Windows drive entries'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from help" -f -a "umount" -d 'Tear down an SFTP-backed filesystem mount (shorthand for `spt sftp mount stop`)'
complete -c spt -n "__fish_spt_using_subcommand sftp; and __fish_seen_subcommand_from help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c spt -n "__fish_spt_using_subcommand diagnose; and not __fish_seen_subcommand_from run network auth trust dns bind port service secrets observability mcp bundle help" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand diagnose; and not __fish_seen_subcommand_from run network auth trust dns bind port service secrets observability mcp bundle help" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand diagnose; and not __fish_seen_subcommand_from run network auth trust dns bind port service secrets observability mcp bundle help" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand diagnose; and not __fish_seen_subcommand_from run network auth trust dns bind port service secrets observability mcp bundle help" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand diagnose; and not __fish_seen_subcommand_from run network auth trust dns bind port service secrets observability mcp bundle help" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand diagnose; and not __fish_seen_subcommand_from run network auth trust dns bind port service secrets observability mcp bundle help" -l profile -d 'Restrict operations to the named profile' -r
complete -c spt -n "__fish_spt_using_subcommand diagnose; and not __fish_seen_subcommand_from run network auth trust dns bind port service secrets observability mcp bundle help" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand diagnose; and not __fish_seen_subcommand_from run network auth trust dns bind port service secrets observability mcp bundle help" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand diagnose; and not __fish_seen_subcommand_from run network auth trust dns bind port service secrets observability mcp bundle help" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand diagnose; and not __fish_seen_subcommand_from run network auth trust dns bind port service secrets observability mcp bundle help" -l json -d 'Convenience alias for `--output json`'
complete -c spt -n "__fish_spt_using_subcommand diagnose; and not __fish_seen_subcommand_from run network auth trust dns bind port service secrets observability mcp bundle help" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand diagnose; and not __fish_seen_subcommand_from run network auth trust dns bind port service secrets observability mcp bundle help" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand diagnose; and not __fish_seen_subcommand_from run network auth trust dns bind port service secrets observability mcp bundle help" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand diagnose; and not __fish_seen_subcommand_from run network auth trust dns bind port service secrets observability mcp bundle help" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand diagnose; and not __fish_seen_subcommand_from run network auth trust dns bind port service secrets observability mcp bundle help" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand diagnose; and not __fish_seen_subcommand_from run network auth trust dns bind port service secrets observability mcp bundle help" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand diagnose; and not __fish_seen_subcommand_from run network auth trust dns bind port service secrets observability mcp bundle help" -f -a "run" -d 'Run a battery of diagnostic checks'
complete -c spt -n "__fish_spt_using_subcommand diagnose; and not __fish_seen_subcommand_from run network auth trust dns bind port service secrets observability mcp bundle help" -f -a "network" -d 'Network checks'
complete -c spt -n "__fish_spt_using_subcommand diagnose; and not __fish_seen_subcommand_from run network auth trust dns bind port service secrets observability mcp bundle help" -f -a "auth" -d 'Authentication checks for a profile'
complete -c spt -n "__fish_spt_using_subcommand diagnose; and not __fish_seen_subcommand_from run network auth trust dns bind port service secrets observability mcp bundle help" -f -a "trust" -d 'Trust checks for a profile'
complete -c spt -n "__fish_spt_using_subcommand diagnose; and not __fish_seen_subcommand_from run network auth trust dns bind port service secrets observability mcp bundle help" -f -a "dns" -d 'DNS checks'
complete -c spt -n "__fish_spt_using_subcommand diagnose; and not __fish_seen_subcommand_from run network auth trust dns bind port service secrets observability mcp bundle help" -f -a "bind" -d 'Bind checks'
complete -c spt -n "__fish_spt_using_subcommand diagnose; and not __fish_seen_subcommand_from run network auth trust dns bind port service secrets observability mcp bundle help" -f -a "port" -d 'Probe a host:port'
complete -c spt -n "__fish_spt_using_subcommand diagnose; and not __fish_seen_subcommand_from run network auth trust dns bind port service secrets observability mcp bundle help" -f -a "service" -d 'Service-manager checks'
complete -c spt -n "__fish_spt_using_subcommand diagnose; and not __fish_seen_subcommand_from run network auth trust dns bind port service secrets observability mcp bundle help" -f -a "secrets" -d 'Secret-backend checks'
complete -c spt -n "__fish_spt_using_subcommand diagnose; and not __fish_seen_subcommand_from run network auth trust dns bind port service secrets observability mcp bundle help" -f -a "observability" -d 'Observability sink checks'
complete -c spt -n "__fish_spt_using_subcommand diagnose; and not __fish_seen_subcommand_from run network auth trust dns bind port service secrets observability mcp bundle help" -f -a "mcp" -d 'MCP server checks'
complete -c spt -n "__fish_spt_using_subcommand diagnose; and not __fish_seen_subcommand_from run network auth trust dns bind port service secrets observability mcp bundle help" -f -a "bundle" -d 'Build a redacted support bundle'
complete -c spt -n "__fish_spt_using_subcommand diagnose; and not __fish_seen_subcommand_from run network auth trust dns bind port service secrets observability mcp bundle help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from run" -l profile -d 'Filter by profile' -r
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from run" -l report -d 'Write a structured report' -r -F
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from run" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from run" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from run" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from run" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from run" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from run" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from run" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from run" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from run" -l all -d 'Run every check'
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from run" -l offline -d 'Restrict to offline-only checks'
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from run" -l online -d 'Restrict to online-only checks'
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from run" -l json -d 'JSON output'
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from run" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from run" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from run" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from run" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from run" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from run" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from network" -l profile -d 'Filter by profile' -r
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from network" -l endpoint -d 'Filter by endpoint' -r
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from network" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from network" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from network" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from network" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from network" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from network" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from network" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from network" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from network" -l json -d 'JSON output'
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from network" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from network" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from network" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from network" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from network" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from network" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from auth" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from auth" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from auth" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from auth" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from auth" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from auth" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from auth" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from auth" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from auth" -l probe -d 'Run a live connect probe (forward-compatible; structural-only today)'
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from auth" -l json -d 'JSON output'
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from auth" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from auth" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from auth" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from auth" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from auth" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from auth" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from trust" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from trust" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from trust" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from trust" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from trust" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from trust" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from trust" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from trust" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from trust" -l probe -d 'Run a live connect probe (forward-compatible; structural-only today)'
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from trust" -l json -d 'JSON output'
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from trust" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from trust" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from trust" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from trust" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from trust" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from trust" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from dns" -l name -d 'Name to test' -r
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from dns" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from dns" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from dns" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from dns" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from dns" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from dns" -l profile -d 'Restrict operations to the named profile' -r
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from dns" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from dns" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from dns" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from dns" -l json -d 'JSON output'
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from dns" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from dns" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from dns" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from dns" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from dns" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from dns" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from bind" -l profile -d 'Filter by profile' -r
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from bind" -l forward -d 'Filter by forward' -r
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from bind" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from bind" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from bind" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from bind" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from bind" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from bind" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from bind" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from bind" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from bind" -l json -d 'JSON output'
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from bind" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from bind" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from bind" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from bind" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from bind" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from bind" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from port" -l host -d 'Target host' -r
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from port" -l port -d 'Target port' -r
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from port" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from port" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from port" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from port" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from port" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from port" -l profile -d 'Restrict operations to the named profile' -r
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from port" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from port" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from port" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from port" -l tcp -d 'TCP probe'
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from port" -l udp -d 'UDP probe'
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from port" -l autodetect-service -d 'Try to identify the service'
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from port" -l json -d 'JSON output'
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from port" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from port" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from port" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from port" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from port" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from port" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from service" -l config -d 'Path to the config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from service" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from service" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from service" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from service" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from service" -l profile -d 'Restrict operations to the named profile' -r
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from service" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from service" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from service" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from service" -l user -d 'User scope'
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from service" -l system -d 'System scope'
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from service" -l json -d 'JSON output'
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from service" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from service" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from service" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from service" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from service" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from service" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from secrets" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from secrets" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from secrets" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from secrets" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from secrets" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from secrets" -l profile -d 'Restrict operations to the named profile' -r
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from secrets" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from secrets" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from secrets" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from secrets" -l json -d 'JSON output'
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from secrets" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from secrets" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from secrets" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from secrets" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from secrets" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from secrets" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from observability" -l sink -d 'Filter by sink name' -r
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from observability" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from observability" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from observability" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from observability" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from observability" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from observability" -l profile -d 'Restrict operations to the named profile' -r
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from observability" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from observability" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from observability" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from observability" -l json -d 'JSON output'
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from observability" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from observability" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from observability" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from observability" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from observability" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from observability" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from mcp" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from mcp" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from mcp" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from mcp" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from mcp" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from mcp" -l profile -d 'Restrict operations to the named profile' -r
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from mcp" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from mcp" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from mcp" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from mcp" -l json -d 'JSON output'
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from mcp" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from mcp" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from mcp" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from mcp" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from mcp" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from mcp" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from bundle" -l out -d 'Output bundle path' -r -F
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from bundle" -l since -d 'Lookback window for events' -r
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from bundle" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from bundle" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from bundle" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from bundle" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from bundle" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from bundle" -l profile -d 'Restrict operations to the named profile' -r
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from bundle" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from bundle" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from bundle" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from bundle" -l redacted -d 'Redact secrets and PII'
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from bundle" -l json -d 'Convenience alias for `--output json`'
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from bundle" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from bundle" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from bundle" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from bundle" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from bundle" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from bundle" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from help" -f -a "run" -d 'Run a battery of diagnostic checks'
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from help" -f -a "network" -d 'Network checks'
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from help" -f -a "auth" -d 'Authentication checks for a profile'
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from help" -f -a "trust" -d 'Trust checks for a profile'
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from help" -f -a "dns" -d 'DNS checks'
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from help" -f -a "bind" -d 'Bind checks'
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from help" -f -a "port" -d 'Probe a host:port'
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from help" -f -a "service" -d 'Service-manager checks'
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from help" -f -a "secrets" -d 'Secret-backend checks'
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from help" -f -a "observability" -d 'Observability sink checks'
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from help" -f -a "mcp" -d 'MCP server checks'
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from help" -f -a "bundle" -d 'Build a redacted support bundle'
complete -c spt -n "__fish_spt_using_subcommand diagnose; and __fish_seen_subcommand_from help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c spt -n "__fish_spt_using_subcommand benchmark; and not __fish_seen_subcommand_from run latency throughput udp reconnect dns limits report help" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand benchmark; and not __fish_seen_subcommand_from run latency throughput udp reconnect dns limits report help" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand benchmark; and not __fish_seen_subcommand_from run latency throughput udp reconnect dns limits report help" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand benchmark; and not __fish_seen_subcommand_from run latency throughput udp reconnect dns limits report help" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand benchmark; and not __fish_seen_subcommand_from run latency throughput udp reconnect dns limits report help" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand benchmark; and not __fish_seen_subcommand_from run latency throughput udp reconnect dns limits report help" -l profile -d 'Restrict operations to the named profile' -r
complete -c spt -n "__fish_spt_using_subcommand benchmark; and not __fish_seen_subcommand_from run latency throughput udp reconnect dns limits report help" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand benchmark; and not __fish_seen_subcommand_from run latency throughput udp reconnect dns limits report help" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand benchmark; and not __fish_seen_subcommand_from run latency throughput udp reconnect dns limits report help" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand benchmark; and not __fish_seen_subcommand_from run latency throughput udp reconnect dns limits report help" -l json -d 'Convenience alias for `--output json`'
complete -c spt -n "__fish_spt_using_subcommand benchmark; and not __fish_seen_subcommand_from run latency throughput udp reconnect dns limits report help" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand benchmark; and not __fish_seen_subcommand_from run latency throughput udp reconnect dns limits report help" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand benchmark; and not __fish_seen_subcommand_from run latency throughput udp reconnect dns limits report help" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand benchmark; and not __fish_seen_subcommand_from run latency throughput udp reconnect dns limits report help" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand benchmark; and not __fish_seen_subcommand_from run latency throughput udp reconnect dns limits report help" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand benchmark; and not __fish_seen_subcommand_from run latency throughput udp reconnect dns limits report help" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand benchmark; and not __fish_seen_subcommand_from run latency throughput udp reconnect dns limits report help" -f -a "run" -d 'End-to-end mixed workload'
complete -c spt -n "__fish_spt_using_subcommand benchmark; and not __fish_seen_subcommand_from run latency throughput udp reconnect dns limits report help" -f -a "latency" -d 'Latency-focused benchmark'
complete -c spt -n "__fish_spt_using_subcommand benchmark; and not __fish_seen_subcommand_from run latency throughput udp reconnect dns limits report help" -f -a "throughput" -d 'Throughput-focused benchmark'
complete -c spt -n "__fish_spt_using_subcommand benchmark; and not __fish_seen_subcommand_from run latency throughput udp reconnect dns limits report help" -f -a "udp" -d 'UDP benchmark (SSH3 only)'
complete -c spt -n "__fish_spt_using_subcommand benchmark; and not __fish_seen_subcommand_from run latency throughput udp reconnect dns limits report help" -f -a "reconnect" -d 'Reconnect benchmark'
complete -c spt -n "__fish_spt_using_subcommand benchmark; and not __fish_seen_subcommand_from run latency throughput udp reconnect dns limits report help" -f -a "dns" -d 'DNS benchmark'
complete -c spt -n "__fish_spt_using_subcommand benchmark; and not __fish_seen_subcommand_from run latency throughput udp reconnect dns limits report help" -f -a "limits" -d 'Limit/throttle introspection'
complete -c spt -n "__fish_spt_using_subcommand benchmark; and not __fish_seen_subcommand_from run latency throughput udp reconnect dns limits report help" -f -a "report" -d 'Report tooling'
complete -c spt -n "__fish_spt_using_subcommand benchmark; and not __fish_seen_subcommand_from run latency throughput udp reconnect dns limits report help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from run" -l driver -d 'Driver to dispatch (one of `latency`, `throughput`, `udp`, `reconnect`, `dns`, `limits`)' -r
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from run" -l profile -d 'Profile name' -r
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from run" -l forward -d 'Forward name' -r
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from run" -l duration -d 'Duration' -r
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from run" -l connections -d 'Concurrent connections' -r
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from run" -l count -d 'Iteration / sample count override' -r
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from run" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from run" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from run" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from run" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from run" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from run" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from run" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from run" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from run" -l unsafe-allow-production-impact -d 'Allow drivers that may impact production. Combined with the `[benchmark.allow_production_impact]` config flag'
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from run" -l json -d 'JSON output'
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from run" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from run" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from run" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from run" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from run" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from run" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from latency" -l profile -d 'Profile name' -r
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from latency" -l forward -d 'Forward name' -r
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from latency" -l samples -d 'Sample count' -r
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from latency" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from latency" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from latency" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from latency" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from latency" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from latency" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from latency" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from latency" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from latency" -l json -d 'JSON output'
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from latency" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from latency" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from latency" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from latency" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from latency" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from latency" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from throughput" -l profile -d 'Profile name' -r
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from throughput" -l forward -d 'Forward name' -r
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from throughput" -l duration -d 'Duration' -r
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from throughput" -l payload-size -d 'Payload size' -r
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from throughput" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from throughput" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from throughput" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from throughput" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from throughput" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from throughput" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from throughput" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from throughput" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from throughput" -l json -d 'JSON output'
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from throughput" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from throughput" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from throughput" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from throughput" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from throughput" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from throughput" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from udp" -l profile -d 'Profile name' -r
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from udp" -l forward -d 'Forward name' -r
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from udp" -l duration -d 'Duration' -r
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from udp" -l packet-size -d 'Datagram size' -r
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from udp" -l pps -d 'Packets per second' -r
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from udp" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from udp" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from udp" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from udp" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from udp" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from udp" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from udp" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from udp" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from udp" -l json -d 'JSON output'
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from udp" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from udp" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from udp" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from udp" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from udp" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from udp" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from reconnect" -l profile -d 'Profile name' -r
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from reconnect" -l iterations -d 'Iteration count' -r
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from reconnect" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from reconnect" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from reconnect" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from reconnect" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from reconnect" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from reconnect" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from reconnect" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from reconnect" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from reconnect" -l json -d 'JSON output'
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from reconnect" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from reconnect" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from reconnect" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from reconnect" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from reconnect" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from reconnect" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from dns" -l name -d 'Name to resolve' -r
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from dns" -l samples -d 'Sample count' -r
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from dns" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from dns" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from dns" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from dns" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from dns" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from dns" -l profile -d 'Restrict operations to the named profile' -r
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from dns" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from dns" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from dns" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from dns" -l json -d 'JSON output'
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from dns" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from dns" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from dns" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from dns" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from dns" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from dns" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from limits" -l profile -d 'Profile name' -r
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from limits" -l forward -d 'Forward name' -r
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from limits" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from limits" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from limits" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from limits" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from limits" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from limits" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from limits" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from limits" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from limits" -l json -d 'JSON output'
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from limits" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from limits" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from limits" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from limits" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from limits" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from limits" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from report" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from report" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from report" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from report" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from report" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from report" -l profile -d 'Restrict operations to the named profile' -r
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from report" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from report" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from report" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from report" -l json -d 'Convenience alias for `--output json`'
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from report" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from report" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from report" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from report" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from report" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from report" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from report" -f -a "compare" -d 'Compare two benchmark results'
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from report" -f -a "export" -d 'Export a benchmark result'
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from report" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from help" -f -a "run" -d 'End-to-end mixed workload'
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from help" -f -a "latency" -d 'Latency-focused benchmark'
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from help" -f -a "throughput" -d 'Throughput-focused benchmark'
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from help" -f -a "udp" -d 'UDP benchmark (SSH3 only)'
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from help" -f -a "reconnect" -d 'Reconnect benchmark'
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from help" -f -a "dns" -d 'DNS benchmark'
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from help" -f -a "limits" -d 'Limit/throttle introspection'
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from help" -f -a "report" -d 'Report tooling'
complete -c spt -n "__fish_spt_using_subcommand benchmark; and __fish_seen_subcommand_from help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c spt -n "__fish_spt_using_subcommand mcp; and not __fish_seen_subcommand_from serve inspect policy help" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand mcp; and not __fish_seen_subcommand_from serve inspect policy help" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand mcp; and not __fish_seen_subcommand_from serve inspect policy help" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand mcp; and not __fish_seen_subcommand_from serve inspect policy help" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand mcp; and not __fish_seen_subcommand_from serve inspect policy help" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand mcp; and not __fish_seen_subcommand_from serve inspect policy help" -l profile -d 'Restrict operations to the named profile' -r
complete -c spt -n "__fish_spt_using_subcommand mcp; and not __fish_seen_subcommand_from serve inspect policy help" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand mcp; and not __fish_seen_subcommand_from serve inspect policy help" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand mcp; and not __fish_seen_subcommand_from serve inspect policy help" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand mcp; and not __fish_seen_subcommand_from serve inspect policy help" -l json -d 'Convenience alias for `--output json`'
complete -c spt -n "__fish_spt_using_subcommand mcp; and not __fish_seen_subcommand_from serve inspect policy help" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand mcp; and not __fish_seen_subcommand_from serve inspect policy help" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand mcp; and not __fish_seen_subcommand_from serve inspect policy help" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand mcp; and not __fish_seen_subcommand_from serve inspect policy help" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand mcp; and not __fish_seen_subcommand_from serve inspect policy help" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand mcp; and not __fish_seen_subcommand_from serve inspect policy help" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand mcp; and not __fish_seen_subcommand_from serve inspect policy help" -f -a "serve" -d 'Run the MCP server'
complete -c spt -n "__fish_spt_using_subcommand mcp; and not __fish_seen_subcommand_from serve inspect policy help" -f -a "inspect" -d 'Inspect MCP capabilities, resources, tools'
complete -c spt -n "__fish_spt_using_subcommand mcp; and not __fish_seen_subcommand_from serve inspect policy help" -f -a "policy" -d 'Manage the MCP policy'
complete -c spt -n "__fish_spt_using_subcommand mcp; and not __fish_seen_subcommand_from serve inspect policy help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c spt -n "__fish_spt_using_subcommand mcp; and __fish_seen_subcommand_from serve" -l listen -d 'Listen on a loopback TCP address (`127.0.0.1:port`)' -r
complete -c spt -n "__fish_spt_using_subcommand mcp; and __fish_seen_subcommand_from serve" -l config -d 'Override config path' -r -F
complete -c spt -n "__fish_spt_using_subcommand mcp; and __fish_seen_subcommand_from serve" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand mcp; and __fish_seen_subcommand_from serve" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand mcp; and __fish_seen_subcommand_from serve" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand mcp; and __fish_seen_subcommand_from serve" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand mcp; and __fish_seen_subcommand_from serve" -l profile -d 'Restrict operations to the named profile' -r
complete -c spt -n "__fish_spt_using_subcommand mcp; and __fish_seen_subcommand_from serve" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand mcp; and __fish_seen_subcommand_from serve" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand mcp; and __fish_seen_subcommand_from serve" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand mcp; and __fish_seen_subcommand_from serve" -l stdio -d 'Speak MCP over stdio'
complete -c spt -n "__fish_spt_using_subcommand mcp; and __fish_seen_subcommand_from serve" -l read-only -d 'Force read-only'
complete -c spt -n "__fish_spt_using_subcommand mcp; and __fish_seen_subcommand_from serve" -l enable -d 'Explicit `--enable` toggle (required unless `[mcp].enabled = true`)'
complete -c spt -n "__fish_spt_using_subcommand mcp; and __fish_seen_subcommand_from serve" -l json -d 'Convenience alias for `--output json`'
complete -c spt -n "__fish_spt_using_subcommand mcp; and __fish_seen_subcommand_from serve" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand mcp; and __fish_seen_subcommand_from serve" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand mcp; and __fish_seen_subcommand_from serve" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand mcp; and __fish_seen_subcommand_from serve" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand mcp; and __fish_seen_subcommand_from serve" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand mcp; and __fish_seen_subcommand_from serve" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand mcp; and __fish_seen_subcommand_from inspect" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand mcp; and __fish_seen_subcommand_from inspect" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand mcp; and __fish_seen_subcommand_from inspect" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand mcp; and __fish_seen_subcommand_from inspect" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand mcp; and __fish_seen_subcommand_from inspect" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand mcp; and __fish_seen_subcommand_from inspect" -l profile -d 'Restrict operations to the named profile' -r
complete -c spt -n "__fish_spt_using_subcommand mcp; and __fish_seen_subcommand_from inspect" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand mcp; and __fish_seen_subcommand_from inspect" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand mcp; and __fish_seen_subcommand_from inspect" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand mcp; and __fish_seen_subcommand_from inspect" -l json -d 'JSON output'
complete -c spt -n "__fish_spt_using_subcommand mcp; and __fish_seen_subcommand_from inspect" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand mcp; and __fish_seen_subcommand_from inspect" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand mcp; and __fish_seen_subcommand_from inspect" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand mcp; and __fish_seen_subcommand_from inspect" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand mcp; and __fish_seen_subcommand_from inspect" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand mcp; and __fish_seen_subcommand_from inspect" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand mcp; and __fish_seen_subcommand_from policy" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand mcp; and __fish_seen_subcommand_from policy" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand mcp; and __fish_seen_subcommand_from policy" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand mcp; and __fish_seen_subcommand_from policy" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand mcp; and __fish_seen_subcommand_from policy" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand mcp; and __fish_seen_subcommand_from policy" -l profile -d 'Restrict operations to the named profile' -r
complete -c spt -n "__fish_spt_using_subcommand mcp; and __fish_seen_subcommand_from policy" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand mcp; and __fish_seen_subcommand_from policy" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand mcp; and __fish_seen_subcommand_from policy" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand mcp; and __fish_seen_subcommand_from policy" -l json -d 'Convenience alias for `--output json`'
complete -c spt -n "__fish_spt_using_subcommand mcp; and __fish_seen_subcommand_from policy" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand mcp; and __fish_seen_subcommand_from policy" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand mcp; and __fish_seen_subcommand_from policy" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand mcp; and __fish_seen_subcommand_from policy" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand mcp; and __fish_seen_subcommand_from policy" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand mcp; and __fish_seen_subcommand_from policy" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand mcp; and __fish_seen_subcommand_from policy" -f -a "show" -d 'Show the current policy'
complete -c spt -n "__fish_spt_using_subcommand mcp; and __fish_seen_subcommand_from policy" -f -a "set" -d 'Update one or more policy keys'
complete -c spt -n "__fish_spt_using_subcommand mcp; and __fish_seen_subcommand_from policy" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c spt -n "__fish_spt_using_subcommand mcp; and __fish_seen_subcommand_from help" -f -a "serve" -d 'Run the MCP server'
complete -c spt -n "__fish_spt_using_subcommand mcp; and __fish_seen_subcommand_from help" -f -a "inspect" -d 'Inspect MCP capabilities, resources, tools'
complete -c spt -n "__fish_spt_using_subcommand mcp; and __fish_seen_subcommand_from help" -f -a "policy" -d 'Manage the MCP policy'
complete -c spt -n "__fish_spt_using_subcommand mcp; and __fish_seen_subcommand_from help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c spt -n "__fish_spt_using_subcommand status; and not __fish_seen_subcommand_from serve status token help" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand status; and not __fish_seen_subcommand_from serve status token help" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand status; and not __fish_seen_subcommand_from serve status token help" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand status; and not __fish_seen_subcommand_from serve status token help" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand status; and not __fish_seen_subcommand_from serve status token help" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand status; and not __fish_seen_subcommand_from serve status token help" -l profile -d 'Restrict operations to the named profile' -r
complete -c spt -n "__fish_spt_using_subcommand status; and not __fish_seen_subcommand_from serve status token help" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand status; and not __fish_seen_subcommand_from serve status token help" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand status; and not __fish_seen_subcommand_from serve status token help" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand status; and not __fish_seen_subcommand_from serve status token help" -l json -d 'Convenience alias for `--output json`'
complete -c spt -n "__fish_spt_using_subcommand status; and not __fish_seen_subcommand_from serve status token help" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand status; and not __fish_seen_subcommand_from serve status token help" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand status; and not __fish_seen_subcommand_from serve status token help" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand status; and not __fish_seen_subcommand_from serve status token help" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand status; and not __fish_seen_subcommand_from serve status token help" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand status; and not __fish_seen_subcommand_from serve status token help" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand status; and not __fish_seen_subcommand_from serve status token help" -f -a "serve" -d 'Run the status API server in foreground (rare — supervisor normally hosts inline when `[status_api].enabled = true`)'
complete -c spt -n "__fish_spt_using_subcommand status; and not __fish_seen_subcommand_from serve status token help" -f -a "status" -d 'Show whether the API is bound + how to reach it'
complete -c spt -n "__fish_spt_using_subcommand status; and not __fish_seen_subcommand_from serve status token help" -f -a "token" -d 'Bearer-token management for the status API auth'
complete -c spt -n "__fish_spt_using_subcommand status; and not __fish_seen_subcommand_from serve status token help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c spt -n "__fish_spt_using_subcommand status; and __fish_seen_subcommand_from serve" -l config -d 'Override config path (otherwise inherits `--config`)' -r -F
complete -c spt -n "__fish_spt_using_subcommand status; and __fish_seen_subcommand_from serve" -l bind -d 'Override the bind address. Defaults to the value in `[status_api].bind`' -r
complete -c spt -n "__fish_spt_using_subcommand status; and __fish_seen_subcommand_from serve" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand status; and __fish_seen_subcommand_from serve" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand status; and __fish_seen_subcommand_from serve" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand status; and __fish_seen_subcommand_from serve" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand status; and __fish_seen_subcommand_from serve" -l profile -d 'Restrict operations to the named profile' -r
complete -c spt -n "__fish_spt_using_subcommand status; and __fish_seen_subcommand_from serve" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand status; and __fish_seen_subcommand_from serve" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand status; and __fish_seen_subcommand_from serve" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand status; and __fish_seen_subcommand_from serve" -l json -d 'Convenience alias for `--output json`'
complete -c spt -n "__fish_spt_using_subcommand status; and __fish_seen_subcommand_from serve" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand status; and __fish_seen_subcommand_from serve" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand status; and __fish_seen_subcommand_from serve" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand status; and __fish_seen_subcommand_from serve" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand status; and __fish_seen_subcommand_from serve" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand status; and __fish_seen_subcommand_from serve" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand status; and __fish_seen_subcommand_from status" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand status; and __fish_seen_subcommand_from status" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand status; and __fish_seen_subcommand_from status" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand status; and __fish_seen_subcommand_from status" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand status; and __fish_seen_subcommand_from status" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand status; and __fish_seen_subcommand_from status" -l profile -d 'Restrict operations to the named profile' -r
complete -c spt -n "__fish_spt_using_subcommand status; and __fish_seen_subcommand_from status" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand status; and __fish_seen_subcommand_from status" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand status; and __fish_seen_subcommand_from status" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand status; and __fish_seen_subcommand_from status" -l detail -d 'Show the resolved auth mode and TLS state in addition to the bind'
complete -c spt -n "__fish_spt_using_subcommand status; and __fish_seen_subcommand_from status" -l json -d 'Convenience alias for `--output json`'
complete -c spt -n "__fish_spt_using_subcommand status; and __fish_seen_subcommand_from status" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand status; and __fish_seen_subcommand_from status" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand status; and __fish_seen_subcommand_from status" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand status; and __fish_seen_subcommand_from status" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand status; and __fish_seen_subcommand_from status" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand status; and __fish_seen_subcommand_from status" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand status; and __fish_seen_subcommand_from token" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand status; and __fish_seen_subcommand_from token" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand status; and __fish_seen_subcommand_from token" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand status; and __fish_seen_subcommand_from token" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand status; and __fish_seen_subcommand_from token" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand status; and __fish_seen_subcommand_from token" -l profile -d 'Restrict operations to the named profile' -r
complete -c spt -n "__fish_spt_using_subcommand status; and __fish_seen_subcommand_from token" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand status; and __fish_seen_subcommand_from token" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand status; and __fish_seen_subcommand_from token" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand status; and __fish_seen_subcommand_from token" -l json -d 'Convenience alias for `--output json`'
complete -c spt -n "__fish_spt_using_subcommand status; and __fish_seen_subcommand_from token" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand status; and __fish_seen_subcommand_from token" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand status; and __fish_seen_subcommand_from token" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand status; and __fish_seen_subcommand_from token" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand status; and __fish_seen_subcommand_from token" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand status; and __fish_seen_subcommand_from token" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand status; and __fish_seen_subcommand_from token" -f -a "rotate" -d 'Rotate the bearer token in the vault (only when `auth.mode = "bearer"` and the `token_from` SecretRef points at a writable backend)'
complete -c spt -n "__fish_spt_using_subcommand status; and __fish_seen_subcommand_from token" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c spt -n "__fish_spt_using_subcommand status; and __fish_seen_subcommand_from help" -f -a "serve" -d 'Run the status API server in foreground (rare — supervisor normally hosts inline when `[status_api].enabled = true`)'
complete -c spt -n "__fish_spt_using_subcommand status; and __fish_seen_subcommand_from help" -f -a "status" -d 'Show whether the API is bound + how to reach it'
complete -c spt -n "__fish_spt_using_subcommand status; and __fish_seen_subcommand_from help" -f -a "token" -d 'Bearer-token management for the status API auth'
complete -c spt -n "__fish_spt_using_subcommand status; and __fish_seen_subcommand_from help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c spt -n "__fish_spt_using_subcommand completion; and not __fish_seen_subcommand_from generate help" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand completion; and not __fish_seen_subcommand_from generate help" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand completion; and not __fish_seen_subcommand_from generate help" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand completion; and not __fish_seen_subcommand_from generate help" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand completion; and not __fish_seen_subcommand_from generate help" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand completion; and not __fish_seen_subcommand_from generate help" -l profile -d 'Restrict operations to the named profile' -r
complete -c spt -n "__fish_spt_using_subcommand completion; and not __fish_seen_subcommand_from generate help" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand completion; and not __fish_seen_subcommand_from generate help" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand completion; and not __fish_seen_subcommand_from generate help" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand completion; and not __fish_seen_subcommand_from generate help" -l json -d 'Convenience alias for `--output json`'
complete -c spt -n "__fish_spt_using_subcommand completion; and not __fish_seen_subcommand_from generate help" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand completion; and not __fish_seen_subcommand_from generate help" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand completion; and not __fish_seen_subcommand_from generate help" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand completion; and not __fish_seen_subcommand_from generate help" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand completion; and not __fish_seen_subcommand_from generate help" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand completion; and not __fish_seen_subcommand_from generate help" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand completion; and not __fish_seen_subcommand_from generate help" -f -a "generate" -d 'Print completions for a shell to stdout'
complete -c spt -n "__fish_spt_using_subcommand completion; and not __fish_seen_subcommand_from generate help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c spt -n "__fish_spt_using_subcommand completion; and __fish_seen_subcommand_from generate" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand completion; and __fish_seen_subcommand_from generate" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand completion; and __fish_seen_subcommand_from generate" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand completion; and __fish_seen_subcommand_from generate" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand completion; and __fish_seen_subcommand_from generate" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand completion; and __fish_seen_subcommand_from generate" -l profile -d 'Restrict operations to the named profile' -r
complete -c spt -n "__fish_spt_using_subcommand completion; and __fish_seen_subcommand_from generate" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand completion; and __fish_seen_subcommand_from generate" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand completion; and __fish_seen_subcommand_from generate" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand completion; and __fish_seen_subcommand_from generate" -l json -d 'Convenience alias for `--output json`'
complete -c spt -n "__fish_spt_using_subcommand completion; and __fish_seen_subcommand_from generate" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand completion; and __fish_seen_subcommand_from generate" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand completion; and __fish_seen_subcommand_from generate" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand completion; and __fish_seen_subcommand_from generate" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand completion; and __fish_seen_subcommand_from generate" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand completion; and __fish_seen_subcommand_from generate" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand completion; and __fish_seen_subcommand_from help" -f -a "generate" -d 'Print completions for a shell to stdout'
complete -c spt -n "__fish_spt_using_subcommand completion; and __fish_seen_subcommand_from help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c spt -n "__fish_spt_using_subcommand about; and not __fish_seen_subcommand_from list show licenses export help" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand about; and not __fish_seen_subcommand_from list show licenses export help" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand about; and not __fish_seen_subcommand_from list show licenses export help" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand about; and not __fish_seen_subcommand_from list show licenses export help" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand about; and not __fish_seen_subcommand_from list show licenses export help" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand about; and not __fish_seen_subcommand_from list show licenses export help" -l profile -d 'Restrict operations to the named profile' -r
complete -c spt -n "__fish_spt_using_subcommand about; and not __fish_seen_subcommand_from list show licenses export help" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand about; and not __fish_seen_subcommand_from list show licenses export help" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand about; and not __fish_seen_subcommand_from list show licenses export help" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand about; and not __fish_seen_subcommand_from list show licenses export help" -l json -d 'Convenience alias for `--output json`'
complete -c spt -n "__fish_spt_using_subcommand about; and not __fish_seen_subcommand_from list show licenses export help" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand about; and not __fish_seen_subcommand_from list show licenses export help" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand about; and not __fish_seen_subcommand_from list show licenses export help" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand about; and not __fish_seen_subcommand_from list show licenses export help" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand about; and not __fish_seen_subcommand_from list show licenses export help" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand about; and not __fish_seen_subcommand_from list show licenses export help" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand about; and not __fish_seen_subcommand_from list show licenses export help" -f -a "list" -d 'List every bundled library, one line per entry'
complete -c spt -n "__fish_spt_using_subcommand about; and not __fish_seen_subcommand_from list show licenses export help" -f -a "show" -d 'Show detailed information for a single library'
complete -c spt -n "__fish_spt_using_subcommand about; and not __fish_seen_subcommand_from list show licenses export help" -f -a "licenses" -d 'Group bundled libraries by SPDX license, with counts'
complete -c spt -n "__fish_spt_using_subcommand about; and not __fish_seen_subcommand_from list show licenses export help" -f -a "export" -d 'Write attribution data to a file (format inferred from extension)'
complete -c spt -n "__fish_spt_using_subcommand about; and not __fish_seen_subcommand_from list show licenses export help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c spt -n "__fish_spt_using_subcommand about; and __fish_seen_subcommand_from list" -l format -d 'Output format' -r -f -a "text\t'Human-readable text (default)'
json\t'Structured JSON array'
markdown\t'Distribution-friendly Markdown attribution block'"
complete -c spt -n "__fish_spt_using_subcommand about; and __fish_seen_subcommand_from list" -l license -d 'Filter by SPDX license substring (case-insensitive)' -r
complete -c spt -n "__fish_spt_using_subcommand about; and __fish_seen_subcommand_from list" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand about; and __fish_seen_subcommand_from list" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand about; and __fish_seen_subcommand_from list" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand about; and __fish_seen_subcommand_from list" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand about; and __fish_seen_subcommand_from list" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand about; and __fish_seen_subcommand_from list" -l profile -d 'Restrict operations to the named profile' -r
complete -c spt -n "__fish_spt_using_subcommand about; and __fish_seen_subcommand_from list" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand about; and __fish_seen_subcommand_from list" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand about; and __fish_seen_subcommand_from list" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand about; and __fish_seen_subcommand_from list" -l include-dev -d 'Include dev / test dependencies (default: runtime-only)'
complete -c spt -n "__fish_spt_using_subcommand about; and __fish_seen_subcommand_from list" -l json -d 'Convenience alias for `--output json`'
complete -c spt -n "__fish_spt_using_subcommand about; and __fish_seen_subcommand_from list" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand about; and __fish_seen_subcommand_from list" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand about; and __fish_seen_subcommand_from list" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand about; and __fish_seen_subcommand_from list" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand about; and __fish_seen_subcommand_from list" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand about; and __fish_seen_subcommand_from list" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand about; and __fish_seen_subcommand_from show" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand about; and __fish_seen_subcommand_from show" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand about; and __fish_seen_subcommand_from show" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand about; and __fish_seen_subcommand_from show" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand about; and __fish_seen_subcommand_from show" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand about; and __fish_seen_subcommand_from show" -l profile -d 'Restrict operations to the named profile' -r
complete -c spt -n "__fish_spt_using_subcommand about; and __fish_seen_subcommand_from show" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand about; and __fish_seen_subcommand_from show" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand about; and __fish_seen_subcommand_from show" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand about; and __fish_seen_subcommand_from show" -l json -d 'Convenience alias for `--output json`'
complete -c spt -n "__fish_spt_using_subcommand about; and __fish_seen_subcommand_from show" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand about; and __fish_seen_subcommand_from show" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand about; and __fish_seen_subcommand_from show" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand about; and __fish_seen_subcommand_from show" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand about; and __fish_seen_subcommand_from show" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand about; and __fish_seen_subcommand_from show" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand about; and __fish_seen_subcommand_from licenses" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand about; and __fish_seen_subcommand_from licenses" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand about; and __fish_seen_subcommand_from licenses" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand about; and __fish_seen_subcommand_from licenses" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand about; and __fish_seen_subcommand_from licenses" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand about; and __fish_seen_subcommand_from licenses" -l profile -d 'Restrict operations to the named profile' -r
complete -c spt -n "__fish_spt_using_subcommand about; and __fish_seen_subcommand_from licenses" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand about; and __fish_seen_subcommand_from licenses" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand about; and __fish_seen_subcommand_from licenses" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand about; and __fish_seen_subcommand_from licenses" -l json -d 'Convenience alias for `--output json`'
complete -c spt -n "__fish_spt_using_subcommand about; and __fish_seen_subcommand_from licenses" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand about; and __fish_seen_subcommand_from licenses" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand about; and __fish_seen_subcommand_from licenses" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand about; and __fish_seen_subcommand_from licenses" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand about; and __fish_seen_subcommand_from licenses" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand about; and __fish_seen_subcommand_from licenses" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand about; and __fish_seen_subcommand_from export" -l config -d 'Path to a single config file' -r -F
complete -c spt -n "__fish_spt_using_subcommand about; and __fish_seen_subcommand_from export" -l config-dir -d 'Path to a directory of `*.toml` configs (loaded in lexical order)' -r -F
complete -c spt -n "__fish_spt_using_subcommand about; and __fish_seen_subcommand_from export" -l config-url -d 'HTTPS URL of a remote config to fetch' -r
complete -c spt -n "__fish_spt_using_subcommand about; and __fish_seen_subcommand_from export" -l config-fingerprint -d 'SHA-256 fingerprint pin for `--config-url`' -r
complete -c spt -n "__fish_spt_using_subcommand about; and __fish_seen_subcommand_from export" -l state-dir -d 'Override the runtime state directory' -r -F
complete -c spt -n "__fish_spt_using_subcommand about; and __fish_seen_subcommand_from export" -l profile -d 'Restrict operations to the named profile' -r
complete -c spt -n "__fish_spt_using_subcommand about; and __fish_seen_subcommand_from export" -l output -d 'Output format for command results' -r -f -a "human\t'Human-readable text (default)'
json\t'Structured JSON'
jsonl\t'JSON Lines (one record per line)'
yaml\t'YAML'"
complete -c spt -n "__fish_spt_using_subcommand about; and __fish_seen_subcommand_from export" -l log-level -d 'Tracing log level' -r -f -a "error\t'Only errors'
warn\t'Warnings and above'
info\t'Informational and above (default)'
debug\t'Debug and above'
trace\t'Trace and above (very verbose)'"
complete -c spt -n "__fish_spt_using_subcommand about; and __fish_seen_subcommand_from export" -l color -d 'Color policy for human output' -r -f -a "auto\t'Auto-detect based on tty'
always\t'Always emit color escapes'
never\t'Never emit color escapes'"
complete -c spt -n "__fish_spt_using_subcommand about; and __fish_seen_subcommand_from export" -l json -d 'Convenience alias for `--output json`'
complete -c spt -n "__fish_spt_using_subcommand about; and __fish_seen_subcommand_from export" -s q -l quiet -d 'Suppress non-essential output'
complete -c spt -n "__fish_spt_using_subcommand about; and __fish_seen_subcommand_from export" -s v -l verbose -d 'Increase verbosity (repeat for more)'
complete -c spt -n "__fish_spt_using_subcommand about; and __fish_seen_subcommand_from export" -l no-color -d 'Disable color (legacy convenience flag; use `--color never`)'
complete -c spt -n "__fish_spt_using_subcommand about; and __fish_seen_subcommand_from export" -l dry-run -d 'Show what would happen without making changes'
complete -c spt -n "__fish_spt_using_subcommand about; and __fish_seen_subcommand_from export" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c spt -n "__fish_spt_using_subcommand about; and __fish_seen_subcommand_from export" -s V -l version -d 'Print version'
complete -c spt -n "__fish_spt_using_subcommand about; and __fish_seen_subcommand_from help" -f -a "list" -d 'List every bundled library, one line per entry'
complete -c spt -n "__fish_spt_using_subcommand about; and __fish_seen_subcommand_from help" -f -a "show" -d 'Show detailed information for a single library'
complete -c spt -n "__fish_spt_using_subcommand about; and __fish_seen_subcommand_from help" -f -a "licenses" -d 'Group bundled libraries by SPDX license, with counts'
complete -c spt -n "__fish_spt_using_subcommand about; and __fish_seen_subcommand_from help" -f -a "export" -d 'Write attribution data to a file (format inferred from extension)'
complete -c spt -n "__fish_spt_using_subcommand about; and __fish_seen_subcommand_from help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c spt -n "__fish_spt_using_subcommand help; and not __fish_seen_subcommand_from config profile forward tunnel service key secret auth dns firewall log observe event stats session ftp sftp diagnose benchmark mcp status completion about help" -f -a "config" -d 'Manage configuration files (init, validate, diff, render, reload)'
complete -c spt -n "__fish_spt_using_subcommand help; and not __fish_seen_subcommand_from config profile forward tunnel service key secret auth dns firewall log observe event stats session ftp sftp diagnose benchmark mcp status completion about help" -f -a "profile" -d 'Manage SSH/SSH3 tunnel profiles'
complete -c spt -n "__fish_spt_using_subcommand help; and not __fish_seen_subcommand_from config profile forward tunnel service key secret auth dns firewall log observe event stats session ftp sftp diagnose benchmark mcp status completion about help" -f -a "forward" -d 'Manage forwards (local/remote TCP, UDP)'
complete -c spt -n "__fish_spt_using_subcommand help; and not __fish_seen_subcommand_from config profile forward tunnel service key secret auth dns firewall log observe event stats session ftp sftp diagnose benchmark mcp status completion about help" -f -a "tunnel" -d 'Run, inspect, and control tunnels'
complete -c spt -n "__fish_spt_using_subcommand help; and not __fish_seen_subcommand_from config profile forward tunnel service key secret auth dns firewall log observe event stats session ftp sftp diagnose benchmark mcp status completion about help" -f -a "service" -d 'Install and control native services'
complete -c spt -n "__fish_spt_using_subcommand help; and not __fish_seen_subcommand_from config profile forward tunnel service key secret auth dns firewall log observe event stats session ftp sftp diagnose benchmark mcp status completion about help" -f -a "key" -d 'Generate, inspect, and install SSH keys'
complete -c spt -n "__fish_spt_using_subcommand help; and not __fish_seen_subcommand_from config profile forward tunnel service key secret auth dns firewall log observe event stats session ftp sftp diagnose benchmark mcp status completion about help" -f -a "secret" -d 'Manage the secret vault and OS keychain references'
complete -c spt -n "__fish_spt_using_subcommand help; and not __fish_seen_subcommand_from config profile forward tunnel service key secret auth dns firewall log observe event stats session ftp sftp diagnose benchmark mcp status completion about help" -f -a "auth" -d 'Authentication helpers'
complete -c spt -n "__fish_spt_using_subcommand help; and not __fish_seen_subcommand_from config profile forward tunnel service key secret auth dns firewall log observe event stats session ftp sftp diagnose benchmark mcp status completion about help" -f -a "dns" -d 'Built-in DNS resolver and hosts-file management'
complete -c spt -n "__fish_spt_using_subcommand help; and not __fish_seen_subcommand_from config profile forward tunnel service key secret auth dns firewall log observe event stats session ftp sftp diagnose benchmark mcp status completion about help" -f -a "firewall" -d 'Inspect and manage OS firewall / packet-filter rules'
complete -c spt -n "__fish_spt_using_subcommand help; and not __fish_seen_subcommand_from config profile forward tunnel service key secret auth dns firewall log observe event stats session ftp sftp diagnose benchmark mcp status completion about help" -f -a "log" -d 'Log tailing, sink testing, and export'
complete -c spt -n "__fish_spt_using_subcommand help; and not __fish_seen_subcommand_from config profile forward tunnel service key secret auth dns firewall log observe event stats session ftp sftp diagnose benchmark mcp status completion about help" -f -a "observe" -d 'Metrics and Windows Event Log helpers'
complete -c spt -n "__fish_spt_using_subcommand help; and not __fish_seen_subcommand_from config profile forward tunnel service key secret auth dns firewall log observe event stats session ftp sftp diagnose benchmark mcp status completion about help" -f -a "event" -d 'Event bindings and sinks'
complete -c spt -n "__fish_spt_using_subcommand help; and not __fish_seen_subcommand_from config profile forward tunnel service key secret auth dns firewall log observe event stats session ftp sftp diagnose benchmark mcp status completion about help" -f -a "stats" -d 'Statistics summaries and live counters'
complete -c spt -n "__fish_spt_using_subcommand help; and not __fish_seen_subcommand_from config profile forward tunnel service key secret auth dns firewall log observe event stats session ftp sftp diagnose benchmark mcp status completion about help" -f -a "session" -d 'Inspect and manage active sessions'
complete -c spt -n "__fish_spt_using_subcommand help; and not __fish_seen_subcommand_from config profile forward tunnel service key secret auth dns firewall log observe event stats session ftp sftp diagnose benchmark mcp status completion about help" -f -a "ftp" -d 'FTP→SFTP translator service'
complete -c spt -n "__fish_spt_using_subcommand help; and not __fish_seen_subcommand_from config profile forward tunnel service key secret auth dns firewall log observe event stats session ftp sftp diagnose benchmark mcp status completion about help" -f -a "sftp" -d 'SFTP file operations and mount planning'
complete -c spt -n "__fish_spt_using_subcommand help; and not __fish_seen_subcommand_from config profile forward tunnel service key secret auth dns firewall log observe event stats session ftp sftp diagnose benchmark mcp status completion about help" -f -a "diagnose" -d 'Targeted diagnostics and support bundles'
complete -c spt -n "__fish_spt_using_subcommand help; and not __fish_seen_subcommand_from config profile forward tunnel service key secret auth dns firewall log observe event stats session ftp sftp diagnose benchmark mcp status completion about help" -f -a "benchmark" -d 'Controlled benchmarking against forwards'
complete -c spt -n "__fish_spt_using_subcommand help; and not __fish_seen_subcommand_from config profile forward tunnel service key secret auth dns firewall log observe event stats session ftp sftp diagnose benchmark mcp status completion about help" -f -a "mcp" -d 'Built-in MCP server controls'
complete -c spt -n "__fish_spt_using_subcommand help; and not __fish_seen_subcommand_from config profile forward tunnel service key secret auth dns firewall log observe event stats session ftp sftp diagnose benchmark mcp status completion about help" -f -a "status" -d 'Read-only status API controls (plan §t4-e5)'
complete -c spt -n "__fish_spt_using_subcommand help; and not __fish_seen_subcommand_from config profile forward tunnel service key secret auth dns firewall log observe event stats session ftp sftp diagnose benchmark mcp status completion about help" -f -a "completion" -d 'Generate shell completions'
complete -c spt -n "__fish_spt_using_subcommand help; and not __fish_seen_subcommand_from config profile forward tunnel service key secret auth dns firewall log observe event stats session ftp sftp diagnose benchmark mcp status completion about help" -f -a "about" -d 'List bundled libraries and their licenses'
complete -c spt -n "__fish_spt_using_subcommand help; and not __fish_seen_subcommand_from config profile forward tunnel service key secret auth dns firewall log observe event stats session ftp sftp diagnose benchmark mcp status completion about help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from config" -f -a "init" -d 'Initialize a new config file from a template'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from config" -f -a "validate" -d 'Validate config syntax, schema, and obvious mistakes'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from config" -f -a "doctor" -d 'Run environment checks against the loaded config'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from config" -f -a "render" -d 'Render the canonical (optionally redacted) config'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from config" -f -a "diff" -d 'Diff two config files'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from config" -f -a "migrate" -d 'Migrate a config between schema versions'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from config" -f -a "reload" -d 'Reload the running service\'s config'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from config" -f -a "pull" -d 'Pull a remote config over HTTPS with pinning'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from config" -f -a "trust" -d 'Manage remote-config trust pins'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from config" -f -a "encrypt" -d 'Encrypt a plaintext config to a sealed `SPTENC1` envelope'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from config" -f -a "decrypt" -d 'Decrypt a sealed `SPTENC1` envelope back to plaintext TOML'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from config" -f -a "edit" -d 'Open a sealed config in `$EDITOR`; re-seal on save'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from config" -f -a "crypt" -d 'Re-seal a sealed config under a new key (key rotation)'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from profile" -f -a "list" -d 'List configured profiles'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from profile" -f -a "show" -d 'Show the resolved profile (optionally redacted)'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from profile" -f -a "add" -d 'Add a new profile'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from profile" -f -a "configure" -d 'Interactive TUI configurator'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from profile" -f -a "set" -d 'Set one or more `key=value` overrides'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from profile" -f -a "enable" -d 'Enable a profile'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from profile" -f -a "disable" -d 'Disable a profile'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from profile" -f -a "remove" -d 'Remove a profile'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from profile" -f -a "test" -d 'Run targeted profile tests'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from forward" -f -a "list" -d 'List configured forwards'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from forward" -f -a "show" -d 'Show a forward'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from forward" -f -a "add" -d 'Add a forward'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from forward" -f -a "explain" -d 'Explain how a forward is plumbed'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from forward" -f -a "test" -d 'Run targeted forward tests'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from forward" -f -a "throttle" -d 'Update throttle/limit knobs at runtime'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from forward" -f -a "remove" -d 'Remove a forward'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from tunnel" -f -a "run" -d 'Run configured tunnels'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from tunnel" -f -a "status" -d 'Show overall tunnel status'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from tunnel" -f -a "stats" -d 'Live or one-shot stats'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from tunnel" -f -a "sessions" -d 'List active sessions'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from tunnel" -f -a "stop" -d 'Stop tunnels'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from tunnel" -f -a "reload" -d 'Reload running configuration'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from tunnel" -f -a "health" -d 'Health summary'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from tunnel" -f -a "failover" -d 'Manually trigger failover for a profile'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from service" -f -a "install" -d 'Install a service for a config file'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from service" -f -a "uninstall" -d 'Uninstall a service'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from service" -f -a "start" -d 'Start a service'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from service" -f -a "stop" -d 'Stop a service'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from service" -f -a "restart" -d 'Restart a service'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from service" -f -a "status" -d 'Show service status'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from service" -f -a "render" -d 'Render the would-be service unit'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from key" -f -a "generate" -d 'Generate a new keypair'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from key" -f -a "inspect" -d 'Inspect a key file'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from key" -f -a "public" -d 'Print a public key (optionally to a file)'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from key" -f -a "change-passphrase" -d 'Change the passphrase on a private key'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from key" -f -a "sign-cert" -d 'Sign an OpenSSH certificate'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from key" -f -a "verify-cert" -d 'Verify an OpenSSH certificate'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from key" -f -a "install-public" -d 'Install a public key on a remote host'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from secret" -f -a "store" -d 'Initialize the secret store'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from secret" -f -a "set" -d 'Set a secret'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from secret" -f -a "get" -d 'Get a secret (redacted unless `--reveal`)'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from secret" -f -a "list" -d 'List known secret names'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from secret" -f -a "rotate" -d 'Rotate a secret'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from secret" -f -a "remove" -d 'Remove a secret'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from secret" -f -a "doctor" -d 'Run secret backend health checks'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from auth" -f -a "test" -d 'Test authentication for a profile'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from auth" -f -a "ssh3-login" -d 'Run an SSH3 OIDC device-flow login and optionally store the token'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from dns" -f -a "serve" -d 'Run the resolver'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from dns" -f -a "status" -d 'Resolver status'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from dns" -f -a "query" -d 'Issue a query against the configured resolver'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from dns" -f -a "upstream" -d 'Manage upstream resolvers'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from dns" -f -a "record" -d 'Manage managed records'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from dns" -f -a "hosts" -d 'Manage hosts-file rendering / apply / restore'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from firewall" -f -a "plan" -d 'Plan rules without applying'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from firewall" -f -a "apply" -d 'Apply rules (idempotent)'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from firewall" -f -a "remove" -d 'Remove rules'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from firewall" -f -a "status" -d 'Show current applied state'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from firewall" -f -a "interfaces" -d 'List interfaces / bind targets'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from firewall" -f -a "bind-preview" -d 'Preview the bind for a forward'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from firewall" -f -a "gateway" -d 'Manage gateway/interface defaults in config'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from firewall" -f -a "policy" -d 'Inspect and manage GPO-style policy values'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from log" -f -a "tail" -d 'Tail logs'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from log" -f -a "remote" -d 'Manage configured remote log sinks'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from log" -f -a "test" -d 'Probe a configured sink'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from log" -f -a "export" -d 'Export logs to a structured format'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from observe" -f -a "metrics" -d 'Print metrics'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from observe" -f -a "windows-event" -d 'Windows Event Log integration'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from event" -f -a "list" -d 'List configured event bindings'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from event" -f -a "test" -d 'Trigger a binding by name'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from event" -f -a "replay" -d 'Replay historical events through a binding'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from event" -f -a "sink" -d 'Manage event sinks'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from stats" -f -a "summary" -d 'Snapshot summary'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from stats" -f -a "live" -d 'Live updating view'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from stats" -f -a "connections" -d 'Connection table'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from stats" -f -a "throughput" -d 'Throughput windows'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from stats" -f -a "errors" -d 'Recent errors'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from stats" -f -a "export" -d 'Export stats to a file'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from session" -f -a "list" -d 'List sessions'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from session" -f -a "show" -d 'Show a session'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from session" -f -a "close" -d 'Close a session'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from session" -f -a "drain" -d 'Drain sessions for a profile'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from session" -f -a "top" -d 'Top-style live view'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from ftp" -f -a "translator" -d 'Run / manage the FTP→SFTP translator service'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from sftp" -f -a "test" -d 'Connect to the profile and open the SFTP subsystem'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from sftp" -f -a "list" -d 'List a remote directory'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from sftp" -f -a "stat" -d 'Show metadata for a remote path'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from sftp" -f -a "get" -d 'Download a remote file'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from sftp" -f -a "put" -d 'Upload a local file'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from sftp" -f -a "mkdir" -d 'Create a remote directory'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from sftp" -f -a "rm" -d 'Remove a remote file'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from sftp" -f -a "rmdir" -d 'Remove a remote directory'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from sftp" -f -a "rename" -d 'Rename a remote file or directory'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from sftp" -f -a "cat" -d 'Print a remote file (with a size cap)'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from sftp" -f -a "tail" -d 'Print the trailing bytes of a remote file'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from sftp" -f -a "chmod" -d 'Change POSIX permissions on a remote path'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from sftp" -f -a "symlink" -d 'Create a remote symbolic link'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from sftp" -f -a "readlink" -d 'Read the target of a remote symbolic link'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from sftp" -f -a "realpath" -d 'Canonicalise a remote path'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from sftp" -f -a "put-recursive" -d 'Mirror a local directory tree onto the server (recursive `put`)'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from sftp" -f -a "get-recursive" -d 'Mirror a remote directory tree onto the local filesystem (recursive `get`)'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from sftp" -f -a "mount" -d 'Manage SFTP-backed filesystem mount entries'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from sftp" -f -a "drive" -d 'Manage SFTP-backed Windows drive entries'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from sftp" -f -a "umount" -d 'Tear down an SFTP-backed filesystem mount (shorthand for `spt sftp mount stop`)'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from diagnose" -f -a "run" -d 'Run a battery of diagnostic checks'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from diagnose" -f -a "network" -d 'Network checks'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from diagnose" -f -a "auth" -d 'Authentication checks for a profile'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from diagnose" -f -a "trust" -d 'Trust checks for a profile'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from diagnose" -f -a "dns" -d 'DNS checks'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from diagnose" -f -a "bind" -d 'Bind checks'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from diagnose" -f -a "port" -d 'Probe a host:port'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from diagnose" -f -a "service" -d 'Service-manager checks'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from diagnose" -f -a "secrets" -d 'Secret-backend checks'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from diagnose" -f -a "observability" -d 'Observability sink checks'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from diagnose" -f -a "mcp" -d 'MCP server checks'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from diagnose" -f -a "bundle" -d 'Build a redacted support bundle'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from benchmark" -f -a "run" -d 'End-to-end mixed workload'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from benchmark" -f -a "latency" -d 'Latency-focused benchmark'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from benchmark" -f -a "throughput" -d 'Throughput-focused benchmark'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from benchmark" -f -a "udp" -d 'UDP benchmark (SSH3 only)'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from benchmark" -f -a "reconnect" -d 'Reconnect benchmark'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from benchmark" -f -a "dns" -d 'DNS benchmark'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from benchmark" -f -a "limits" -d 'Limit/throttle introspection'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from benchmark" -f -a "report" -d 'Report tooling'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from mcp" -f -a "serve" -d 'Run the MCP server'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from mcp" -f -a "inspect" -d 'Inspect MCP capabilities, resources, tools'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from mcp" -f -a "policy" -d 'Manage the MCP policy'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from status" -f -a "serve" -d 'Run the status API server in foreground (rare — supervisor normally hosts inline when `[status_api].enabled = true`)'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from status" -f -a "status" -d 'Show whether the API is bound + how to reach it'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from status" -f -a "token" -d 'Bearer-token management for the status API auth'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from completion" -f -a "generate" -d 'Print completions for a shell to stdout'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from about" -f -a "list" -d 'List every bundled library, one line per entry'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from about" -f -a "show" -d 'Show detailed information for a single library'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from about" -f -a "licenses" -d 'Group bundled libraries by SPDX license, with counts'
complete -c spt -n "__fish_spt_using_subcommand help; and __fish_seen_subcommand_from about" -f -a "export" -d 'Write attribution data to a file (format inferred from extension)'
