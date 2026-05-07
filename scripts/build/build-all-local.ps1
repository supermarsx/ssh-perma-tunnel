#!/usr/bin/env pwsh
# build-all-local.ps1 — build every Windows-MSVC target on this host.
#
# Linux/macOS cross-targets aren't viable from a Windows shell (cross-rs +
# Docker is non-trivial to drive from PowerShell, and macOS targets need
# an Apple SDK). Use scripts/build/build-all-local.sh on a Linux/macOS host
# for those.

[CmdletBinding()]
param(
    [switch]$DryRun,
    [switch]$FailFast,
    [switch]$Help
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. "$PSScriptRoot/_common.ps1"

if ($Help) {
    @"
Usage: scripts/build/build-all-local.ps1 [-DryRun] [-FailFast]

Builds the two Windows MSVC targets reachable from a Windows host.
Use the .sh sibling on Linux/macOS for the other six targets.
"@
    exit 0
}

$winTargets = $AllowedTargets | Where-Object { Test-WindowsTarget $_ }
$results = @()
$attempted = 0
$succeeded = 0

foreach ($t in $winTargets) {
    $attempted++
    if ($DryRun) {
        $results += "PLAN $t (native)"
        continue
    }
    Write-Info "==> $t"
    try {
        & "$PSScriptRoot/build-target.ps1" -Target $t
        $results += "OK   $t"
        $succeeded++
    }
    catch {
        $results += "FAIL $t ($($_.Exception.Message))"
        if ($FailFast) { break }
    }
}

Write-Host ""
Write-Host "===== build-all-local summary ====="
$results | ForEach-Object { Write-Host $_ }
Write-Host "==================================="

if ($DryRun) { exit 0 }
if ($attempted -eq 0) {
    Write-Warn "no Windows targets attempted (unexpected)"
    exit 0
}
if ($succeeded -eq 0) { Stop-Die 'every attempted target failed' }
