#!/usr/bin/env pwsh
# build-target.ps1 — build the spt binary for one target on Windows hosts.
#
# Only the two windows-msvc targets are buildable natively here.
# For Linux/macOS targets, use scripts/build/build-target.sh on the
# corresponding host (or via WSL with cross-rs + Docker).

[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [string]$Target,

    [string]$Profile = 'release',

    [switch]$DryRun,

    [switch]$Help
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. "$PSScriptRoot/_common.ps1"

function Show-Usage {
    @"
Usage: scripts/build/build-target.ps1 -Target <triple> [-Profile release] [-DryRun]

Builds the spt binary for one of the two Windows MSVC targets:
  x86_64-pc-windows-msvc
  aarch64-pc-windows-msvc

Cross-targets (Linux/macOS) must be built from a Linux/macOS host using
scripts/build/build-target.sh. cross-rs requires Docker and is not viable
on a typical Windows developer machine for those targets.
"@
}

if ($Help -or -not $Target) {
    Show-Usage
    if (-not $Help) { exit 1 } else { exit 0 }
}

if (-not (Test-TargetEligible $Target)) {
    Stop-Die "target not in allow-list: $Target"
}
if (-not (Test-WindowsTarget $Target)) {
    Stop-Die "target $Target is not a Windows MSVC target. Use build-target.sh on a Linux/macOS host."
}

$env:SOURCE_DATE_EPOCH = if ($env:SOURCE_DATE_EPOCH) { $env:SOURCE_DATE_EPOCH } else { Get-SourceDateEpoch }
if (-not $env:CARGO_INCREMENTAL) { $env:CARGO_INCREMENTAL = '0' }

$cargoBin = if ($env:CARGO) { $env:CARGO } else { 'cargo' }
$cmd = @($cargoBin, 'build', "--profile=$Profile", '--locked', '--target', $Target, '-p', 'spt-bin')

Write-Info "building spt for $Target (host=$(Get-HostTriple))"
Write-Info ("SOURCE_DATE_EPOCH=$($env:SOURCE_DATE_EPOCH)")
Write-Info ("command: " + ($cmd -join ' '))

if ($DryRun) { exit 0 }

Push-Location (Get-RepoRoot)
try {
    & $cmd[0] $cmd[1..($cmd.Length - 1)]
    if ($LASTEXITCODE -ne 0) { Stop-Die "cargo build failed (exit $LASTEXITCODE)" }
}
finally {
    Pop-Location
}

$bin = Get-BinaryForTarget $Target
if (-not (Test-Path -LiteralPath $bin)) {
    Stop-Die "expected binary not found at $bin"
}

Write-Info "built: $bin"
Write-Output $bin
