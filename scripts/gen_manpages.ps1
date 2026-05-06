# Regenerate the committed roff man pages under packaging/man/ from the live
# clap::Command tree exposed by spt-cli. Idempotent — output is deterministic.
#
# Usage:
#   scripts/gen_manpages.ps1 [-OutDir <path>]
[CmdletBinding()]
param(
    [string]$OutDir
)
$ErrorActionPreference = 'Stop'
$root = Resolve-Path (Join-Path $PSScriptRoot '..')
if (-not $OutDir) { $OutDir = Join-Path $root 'packaging/man' }
Push-Location $root
try {
    cargo run --quiet --bin spt-mangen -- --out $OutDir
    Write-Host "spt-mangen: regenerated man pages in $OutDir"
} finally {
    Pop-Location
}
