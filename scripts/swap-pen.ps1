<#
.SYNOPSIS
    Replace the placeholder IANA Private Enterprise Number with the production
    PEN returned by IANA.

.DESCRIPTION
    Rewrites the single `{ enterprises 32473 }` line in mibs/SPT-MIB.txt and
    the single SPT enterprise OID constant SPT_ENTERPRISE_OID_ARCS in
    crates/spt-snmp/src/lib.rs. Leaves .bak copies. PowerShell equivalent of
    scripts/swap-pen.sh.

    See docs/pen-registration.md for the registration packet.

.PARAMETER NewPen
    The IANA-assigned Private Enterprise Number (positive integer).

.EXAMPLE
    PS> .\scripts\swap-pen.ps1 60123
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$NewPen
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($NewPen -notmatch '^[0-9]+$') {
    Write-Error "PEN must be a positive integer, got: $NewPen"
    exit 2
}

# Resolve repo root from the script location so relative paths are stable.
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot  = Resolve-Path (Join-Path $ScriptDir '..')

$Mib = Join-Path $RepoRoot 'mibs/SPT-MIB.txt'
$Lib = Join-Path $RepoRoot 'crates/spt-snmp/src/lib.rs'

if (-not (Test-Path $Mib)) { Write-Error "cannot find $Mib"; exit 1 }
if (-not (Test-Path $Lib)) { Write-Error "cannot find $Lib"; exit 1 }

$MibContent = Get-Content -Raw -Encoding UTF8 -Path $Mib
$LibContent = Get-Content -Raw -Encoding UTF8 -Path $Lib

if ($MibContent -notmatch 'enterprises 32473') {
    Write-Error "no placeholder '{ enterprises 32473 }' found in $Mib (already swapped? edited by hand?)"
    exit 1
}
if ($LibContent -notmatch 'SPT_ENTERPRISE_OID_ARCS') {
    Write-Error "SPT_ENTERPRISE_OID_ARCS not found in $Lib"
    exit 1
}

# Write .bak alongside the originals (mirrors `sed -i.bak`).
Copy-Item -Path $Mib -Destination "$Mib.bak" -Force
Copy-Item -Path $Lib -Destination "$Lib.bak" -Force

$NewMibContent = $MibContent -replace 'enterprises 32473', "enterprises $NewPen"
$NewLibContent = $LibContent -replace '&\[1, 3, 6, 1, 4, 1, 32_473\]', "&[1, 3, 6, 1, 4, 1, $NewPen]"

# Preserve UTF-8 without BOM (PowerShell 7+ default for Set-Content).
Set-Content -Path $Mib -Value $NewMibContent -NoNewline -Encoding utf8NoBOM
Set-Content -Path $Lib -Value $NewLibContent -NoNewline -Encoding utf8NoBOM

Write-Host "swapped MIB enterprise OID 32473 -> $NewPen"
Write-Host "  - $Mib"
Write-Host "  - $Lib"
Write-Host ""
Write-Host "Next steps:"
Write-Host "  1) Bump the MIB REVISION line in $Mib (LAST-UPDATED + new REVISION entry)."
Write-Host "  2) Review docs/pen-registration.md and mark it as 'assigned PEN: $NewPen'."
Write-Host "  3) Run: cargo build --workspace --locked && cargo test -p spt-snmp --locked"
Write-Host "  4) Commit the change and the .bak files' deletion."
