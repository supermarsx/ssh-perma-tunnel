#!/usr/bin/env pwsh
# scripts/build/_common.ps1 — shared helpers for spt PowerShell scripts.
#
# Dot-source from every other .ps1 script:
#     . "$PSScriptRoot/_common.ps1"
#     . (Join-Path (Get-RepoRoot) 'scripts/build/_common.ps1')

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-Info { param([string]$Message) Write-Host "info: $Message" -ForegroundColor Cyan }
function Write-Warn { param([string]$Message) Write-Host "warn: $Message" -ForegroundColor Yellow }
function Stop-Die   { param([string]$Message) Write-Host "error: $Message" -ForegroundColor Red; exit 1 }

function Get-RepoRoot {
    (& git rev-parse --show-toplevel).Trim()
}

function Get-VersionFromCargo {
    $cargoToml = Join-Path (Get-RepoRoot) 'Cargo.toml'
    $inSection = $false
    foreach ($line in Get-Content -LiteralPath $cargoToml) {
        if ($line -match '^\[workspace\.package\]') { $inSection = $true; continue }
        if ($inSection -and $line -match '^\[') { $inSection = $false }
        if ($inSection -and $line -match '^\s*version\s*=\s*"([^"]+)"') {
            return $Matches[1]
        }
    }
    Stop-Die 'Could not parse [workspace.package] version from Cargo.toml'
}

function Get-GitShortSha { (& git rev-parse --short=12 HEAD).Trim() }

function Get-SourceDateEpoch { (& git log -1 --format=%ct).Trim() }

function Get-HostTriple {
    $line = (& rustc -vV) | Select-String -Pattern '^host:\s*(.+)$'
    if (-not $line) { Stop-Die 'rustc -vV did not produce a host: line' }
    return $line.Matches[0].Groups[1].Value.Trim()
}

$AllowedTargets = @(
    'x86_64-unknown-linux-gnu',
    'x86_64-unknown-linux-musl',
    'aarch64-unknown-linux-gnu',
    'aarch64-unknown-linux-musl',
    'x86_64-apple-darwin',
    'aarch64-apple-darwin',
    'x86_64-pc-windows-msvc',
    'aarch64-pc-windows-msvc'
)

function Test-TargetEligible {
    param([string]$Target)
    return $AllowedTargets -contains $Target
}

function Test-WindowsTarget {
    param([string]$Target)
    return $Target -like '*-pc-windows-msvc'
}

function Get-DistDir {
    $v = Get-VersionFromCargo
    return (Join-Path (Get-RepoRoot) "dist/$v")
}

function New-DistDir {
    $d = Get-DistDir
    if (-not (Test-Path -LiteralPath $d)) {
        New-Item -ItemType Directory -Path $d -Force | Out-Null
    }
    return $d
}

function Get-BinaryForTarget {
    param([string]$Target)
    $root = Get-RepoRoot
    if (Test-WindowsTarget $Target) {
        return Join-Path $root "target/$Target/release/spt.exe"
    }
    return Join-Path $root "target/$Target/release/spt"
}

function Test-CommandAvailable {
    param([string]$Name)
    $null -ne (Get-Command $Name -ErrorAction SilentlyContinue)
}
