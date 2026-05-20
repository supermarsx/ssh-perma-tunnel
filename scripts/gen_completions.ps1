# Regenerate committed shell completions under packaging/completions/ from the
# live Clap command tree.
#
# Usage:
#   scripts/gen_completions.ps1 [-OutDir <path>]

[CmdletBinding()]
param(
    [string]$OutDir = (Join-Path (Split-Path -Parent $PSScriptRoot) 'packaging/completions')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

cargo run -p spt-bin --bin spt-completions -- --out $OutDir
Write-Host "spt-completions: regenerated shell completions in $OutDir"
