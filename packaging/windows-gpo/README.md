# spt Windows Group Policy templates

This directory ships an ADMX/ADML administrative template for the
`ssh-perma-tunnel` (`spt`) agent, plus a PowerShell installer that copies the
files into the local PolicyDefinitions store (or a domain Central Store).

## Files

| File | Purpose |
|------|---------|
| `spt.admx` | Policy schema: categories, policies, registry value mappings. |
| `en-US/spt.adml` | English display strings + presentation. |
| `es-ES/spt.adml` | Spanish display strings + presentation. |
| `pt-PT/spt.adml` | Portuguese (Portugal) display strings + presentation. |
| `de-DE/spt.adml` | German display strings + presentation. |
| `fr-FR/spt.adml` | French display strings + presentation. |
| `it-IT/spt.adml` | Italian display strings + presentation. |
| `ja-JP/spt.adml` | Japanese display strings + presentation. |
| `zh-CN/spt.adml` | Chinese (Simplified) display strings + presentation. |
| `install-policy.ps1` | Idempotent installer (`-DryRun` and `-CentralStore` supported). |

### Locale coverage

| Locale | File | Status |
|--------|------|--------|
| en-US | `en-US/spt.adml` | Source of truth |
| es-ES | `es-ES/spt.adml` | Translated |
| pt-PT | `pt-PT/spt.adml` | Translated |
| de-DE | `de-DE/spt.adml` | Translated |
| fr-FR | `fr-FR/spt.adml` | Translated |
| it-IT | `it-IT/spt.adml` | Translated |
| ja-JP | `ja-JP/spt.adml` | Translated |
| zh-CN | `zh-CN/spt.adml` | Translated |

Translations are best-effort. The technical accuracy of policy semantics is
guaranteed only by the en-US source — translated strings describe the same
behaviour but are not normative. PRs that improve phrasing for any locale (more
idiomatic Windows terminology, regionally preferred wording, typo fixes) are
welcome; please keep `<string id="...">` and `<presentation id="...">` keys
in 1:1 correspondence with `en-US/spt.adml`.

## Installation

### Local machine (single host, requires Administrator)

```powershell
# From an elevated PowerShell prompt:
cd <path-to>\packaging\windows-gpo
.\install-policy.ps1            # actually install
.\install-policy.ps1 -DryRun    # preview only
```

This copies:

- `spt.admx` -> `%SystemRoot%\PolicyDefinitions\spt.admx`
- `en-US\spt.adml` -> `%SystemRoot%\PolicyDefinitions\en-US\spt.adml`
- `es-ES\spt.adml` -> `%SystemRoot%\PolicyDefinitions\es-ES\spt.adml`
- `pt-PT\spt.adml` -> `%SystemRoot%\PolicyDefinitions\pt-PT\spt.adml`
- `de-DE\spt.adml` -> `%SystemRoot%\PolicyDefinitions\de-DE\spt.adml`
- `fr-FR\spt.adml` -> `%SystemRoot%\PolicyDefinitions\fr-FR\spt.adml`
- `it-IT\spt.adml` -> `%SystemRoot%\PolicyDefinitions\it-IT\spt.adml`
- `ja-JP\spt.adml` -> `%SystemRoot%\PolicyDefinitions\ja-JP\spt.adml`
- `zh-CN\spt.adml` -> `%SystemRoot%\PolicyDefinitions\zh-CN\spt.adml`

### Domain Central Store (recommended for AD-joined fleets)

```powershell
.\install-policy.ps1 -CentralStore '\\corp.example.com\SYSVOL\corp.example.com\Policies\PolicyDefinitions'
```

After deployment, refresh policy on a target host with `gpupdate /force`.

### CLI management

The same registry-backed policy surface can be inspected and managed from
`spt`:

```powershell
spt firewall policy list --json
spt firewall policy show --config C:\ProgramData\spt\spt.toml --json
spt firewall policy set Network.DefaultInterface Ethernet --scope user
spt firewall policy set Network.AllowedInterfaces Ethernet,Wintun --scope machine --enforced
spt firewall policy unset Network.DefaultInterface --scope user
```

`--scope machine` writes `HKLM` and requires elevation. `--enforced` sets the
section-level `Enforced` sentinel used by the runtime overlay.

### Editing policies

After install, open `gpedit.msc` (local) or the Group Policy Management Editor
(domain) and navigate to:

- **Computer Configuration -> Administrative Templates -> spt — SSH Permanent Tunnel**
- **User Configuration -> Administrative Templates -> spt — SSH Permanent Tunnel**

Sections: General, Network, Crypto, Observability, Security.

## Policy precedence

The agent merges configuration from multiple sources. Highest precedence wins:

1. **HKLM (machine policy)** — `HKEY_LOCAL_MACHINE\Software\Policies\spt\<Section>\<Name>`
2. **HKCU (user policy)** — `HKEY_CURRENT_USER\Software\Policies\spt\<Section>\<Name>`
3. **Configuration file** — values loaded from the active TOML config.
4. **Built-in defaults** — compiled into the agent.

For policies set under `Software\Policies\spt`:

- If a sibling DWORD `Enforced` is set to `1` under the same `<Section>` key,
  the policy value is **mandatory** — the agent rejects any config-file value
  that conflicts and refuses to start with a non-zero exit. This matches
  Windows' standard "managed" semantics for the `Software\Policies\...` hive.
- Otherwise the policy is **advisory**: it overrides defaults but yields to
  the configuration file when present. This mirrors the Group Policy
  preferences model.

The `Software\Policies` hive (as opposed to `Software\<Vendor>`) is used
intentionally: it is the standard location for ADMX-managed values, is
cleared automatically when a policy is removed from a GPO, and is
ACL-protected so non-administrators cannot tamper with machine policy.

## Registry layout

Every policy maps to a value under one of the following keys:

```
HKLM\Software\Policies\spt\General
HKLM\Software\Policies\spt\Network
HKLM\Software\Policies\spt\Crypto
HKLM\Software\Policies\spt\Observability
HKLM\Software\Policies\spt\Security

HKCU\Software\Policies\spt\General        (where a User-class policy exists)
HKCU\Software\Policies\spt\Observability
HKCU\Software\Policies\spt\Security
```

| Section       | Value name                       | Type              | Notes |
|---------------|----------------------------------|-------------------|-------|
| General       | `StateDir`                       | REG_SZ            | Absolute path |
| General       | `DefaultConfigPath`              | REG_SZ            | Absolute path |
| General       | `ServiceAutoStart`               | REG_DWORD (0/1)   | Machine only |
| Network       | `RemoteConfigUrlPin`             | REG_SZ            | Machine only |
| Network       | `RemoteConfigFingerprintSha256`  | REG_SZ            | lowercase hex |
| Network       | `McpEnabled`                     | REG_DWORD (0/1)   | |
| Network       | `McpListen`                      | REG_SZ            | e.g. `127.0.0.1:7843` |
| Network       | `BindRestrictions`               | REG_MULTI_SZ      | one CIDR per line |
| Network       | `DefaultInterface`               | REG_SZ            | default bind interface |
| Network       | `AllowedInterfaces`              | REG_MULTI_SZ      | interface allow-list |
| Network       | `DeniedInterfaces`               | REG_MULTI_SZ      | interface deny-list |
| Network       | `RequireExplicitInterface`       | REG_DWORD (0/1)   | require per-forward interface |
| Network       | `AllowAllInterfaces`             | REG_DWORD (0/1)   | permit wildcard binds |
| Network       | `BindIpv6`                       | REG_SZ            | auto/prefer/disable |
| Network       | `DefaultGateway`                 | REG_SZ            | default gateway address/alias |
| Network       | `GatewayInterface`               | REG_SZ            | expected gateway interface |
| Network       | `RouteCheckTarget`               | REG_SZ            | route probe target |
| Network       | `RequireGatewayMatch`            | REG_DWORD (0/1)   | enforce gateway/interface match |
| Network       | `GatewayPolicy`                  | REG_SZ            | disabled/default_route/interface_only/route_to_target |
| Network       | `OffloadTcpNoDelay`              | REG_DWORD (0/1)   | TCP_NODELAY policy |
| Network       | `OffloadSocketKeepalive`         | REG_DWORD (0/1)   | socket keepalive policy |
| Network       | `OffloadTcpFastOpen`             | REG_DWORD (0/1)   | TCP Fast Open policy |
| Network       | `OffloadReusePort`               | REG_DWORD (0/1)   | listener port reuse policy |
| Network       | `OffloadZeroCopy`                | REG_DWORD (0/1)   | zero-copy policy |
| Network       | `OffloadIoUring`                 | REG_DWORD (0/1)   | Linux io_uring policy |
| Network       | `OffloadSendfile`                | REG_DWORD (0/1)   | sendfile-style transfer policy |
| Network       | `OffloadChecksumOffload`         | REG_DWORD (0/1)   | NIC checksum offload policy |
| Network       | `OffloadLargeSendOffload`        | REG_DWORD (0/1)   | TSO/large-send offload policy |
| Network       | `LoadBalanceStrategy`            | REG_SZ            | priority/weighted/round_robin/least_connections/manual |
| Network       | `LoadBalanceStickySessions`      | REG_DWORD (0/1)   | endpoint stickiness |
| Network       | `LoadBalanceHealthCheck`         | REG_SZ            | tcp_connect/ssh_handshake/ssh_auth_preflight/ssh3_endpoint |
| Network       | `LoadBalanceFailAfter`           | REG_DWORD         | consecutive failures |
| Network       | `LoadBalanceRestoreAfter`        | REG_SZ            | duration, e.g. 30s |
| Network       | `LoadBalanceRebalanceInterval`   | REG_SZ            | duration, e.g. 5m |
| Crypto        | `AllowSsh2`                      | REG_DWORD (0/1)   | |
| Crypto        | `AllowSsh3`                      | REG_DWORD (0/1)   | |
| Crypto        | `AllowedKexAlgorithms`           | REG_MULTI_SZ      | |
| Crypto        | `AllowedCiphers`                 | REG_MULTI_SZ      | |
| Crypto        | `AllowedMacs`                    | REG_MULTI_SZ      | |
| Crypto        | `AllowedHostKeyTypes`            | REG_MULTI_SZ      | |
| Observability | `LogLevel`                       | REG_SZ (enum)     | trace/debug/info/warn/error |
| Observability | `LogDestinations`                | REG_MULTI_SZ      | |
| Observability | `TelemetryOptOut`                | REG_DWORD (0/1)   | |
| Security      | `AllowedFirewallActions`         | REG_MULTI_SZ      | |
| Security      | `SecretBackend`                  | REG_SZ (enum)     | `keyring` or `file` |

## ADMX schema versioning

- `revision` and `schemaVersion` in `spt.admx` are both `1.0`. Bump
  `revision` whenever any policy name, key, or value changes shape (rename,
  retype, or removal). Additive changes (new policies under existing
  categories) keep the existing `revision` but should be released alongside
  a CHANGELOG note. Never recycle a removed `name` for a different policy —
  Windows caches policy-name-to-value mappings per machine.
- `schemaVersion="1.0"` matches the Microsoft-published
  `PolicyDefinitions.xsd` shipped with Windows. Higher schema versions
  (1.1, 1.2) are unnecessary for this template and would reduce
  compatibility with Server 2012 R2 GPMC.
- The `policyNamespaces/target` namespace
  (`SshPermaTunnel.Policies.Spt`) is the public identity of this template.
  Do not change it; downstream GPOs reference policies by `namespace:name`.

## Validating the ADMX

Microsoft does not publish a stable XSD URL, but a copy of the schema ships
with every Windows installation. Operators can validate locally:

```powershell
# Requires PowerShell 5.1+ on a Windows host with the Group Policy schema.
$xsd = Join-Path $env:SystemRoot 'schemas\GroupPolicy\PolicyDefinitions.xsd'
if (Test-Path $xsd) {
    [xml]$doc = Get-Content .\spt.admx
    $doc.Schemas.Add('http://schemas.microsoft.com/GroupPolicy/2006/07/PolicyDefinitions', $xsd) | Out-Null
    $doc.Validate({ param($s, $e) Write-Error $e.Message })
    Write-Host 'spt.admx validates against the local PolicyDefinitions schema.'
} else {
    Write-Warning "Schema not present at $xsd; install RSAT or run on a host with GPMC."
}
```

A second sanity check: after running `install-policy.ps1`, open `gpedit.msc`.
If the **spt — SSH Permanent Tunnel** node renders, all referenced strings
and presentations resolved correctly. Any malformed reference produces an
"Encountered an error" dialog with the offending policy name.

## Lint / static analysis (install-policy.ps1)

The installer was authored to be `Invoke-ScriptAnalyzer` clean against the
default ruleset:

```powershell
Install-Module -Name PSScriptAnalyzer -Scope CurrentUser
Invoke-ScriptAnalyzer -Path .\install-policy.ps1 -Severity Warning,Error
```

If you modify the script, re-run that command and resolve any new findings.

## Removing the template

```powershell
Remove-Item "$env:SystemRoot\PolicyDefinitions\spt.admx" -Force
foreach ($loc in 'en-US','es-ES','pt-PT','de-DE','fr-FR','it-IT','ja-JP','zh-CN') {
    $path = "$env:SystemRoot\PolicyDefinitions\$loc\spt.adml"
    if (Test-Path $path) { Remove-Item $path -Force }
}
```

This removes the editor surface only; previously written registry values
under `Software\Policies\spt` remain until the corresponding GPO is
unlinked or deleted, or the keys are removed manually.
