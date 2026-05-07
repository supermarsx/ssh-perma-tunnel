#!/usr/bin/env pwsh
# pack-msi-windows.ps1 — wrap `cargo wix` against packaging/msi/main.wxs.

[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [string]$Target,
    [switch]$DryRun,
    [switch]$Help
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. "$PSScriptRoot/../build/_common.ps1"

function Show-Usage {
    @"
Usage: scripts/package/pack-msi-windows.ps1 -Target <triple> [-DryRun]

Wraps \`cargo wix\` to build an MSI for one of the Windows MSVC targets.
The binary must already be built. The script passes --no-build.

Output: dist/<version>/spt-<version>-<target>.msi
"@
}

if ($Help -or -not $Target) {
    Show-Usage
    if (-not $Help) { exit 1 } else { exit 0 }
}

if (-not (Test-TargetEligible $Target)) { Stop-Die "unknown target: $Target" }
if (-not (Test-WindowsTarget $Target))  { Stop-Die "pack-msi-windows.ps1 is for Windows MSVC targets only." }

if (-not (Test-CommandAvailable 'cargo')) { Stop-Die "cargo not on PATH" }

# Probe for cargo-wix; warn-and-skip if missing rather than failing.
$wixHelp = & cargo wix --help 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-Warn "cargo-wix not installed; skipping. Install with: cargo install cargo-wix --locked"
    exit 0
}

$root    = Get-RepoRoot
$version = Get-VersionFromCargo
$bin     = Get-BinaryForTarget $Target
if (-not (Test-Path -LiteralPath $bin)) {
    Stop-Die "binary missing: $bin (run build-target.ps1 $Target first)"
}

$dist = New-DistDir
$out  = Join-Path $dist "spt-$version-$Target.msi"

$cmd = @('wix', '-p', 'spt-bin',
         '--target', $Target,
         '--no-build', '--nocapture',
         '--output', $out)

Write-Info ("command: cargo " + ($cmd -join ' '))
if ($DryRun) { exit 0 }

Push-Location $root
try {
    & cargo @cmd
    if ($LASTEXITCODE -ne 0) { Stop-Die "cargo wix failed (exit $LASTEXITCODE)" }
}
finally { Pop-Location }

Write-Info "produced: $out"
Write-Output $out
