# Smoke test for the Chocolatey nuspec.
#
# Local mode: parse the nuspec as XML, verify required metadata, and verify
# the tools\ scripts referenced exist. We deliberately do not invoke
# `choco pack`/`choco install` here because the install scripts download
# tagged release artefacts.
#
# Release mode (SPT_PKG_RELEASE_MODE=1): runs `choco pack` against a
# release-substituted nuspec.

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$nuspec = Join-Path $root 'packaging\choco\spt.nuspec'

if (-not (Test-Path $nuspec)) {
    Write-Error "missing $nuspec"
}

# 1. XML parse.
[xml]$doc = Get-Content -Raw $nuspec

# 2. Required metadata children.
$meta = $doc.package.metadata
foreach ($child in @('id', 'version', 'authors', 'description', 'licenseUrl')) {
    if (-not $meta.$child) {
        Write-Error "nuspec missing metadata/$child"
    }
}

# 3. Required tool scripts.
$tools = Join-Path $root 'packaging\choco\tools'
foreach ($script in @('chocolateyinstall.ps1', 'chocolateyuninstall.ps1')) {
    if (-not (Test-Path (Join-Path $tools $script))) {
        Write-Warning "tools/$script missing (not strictly required, but recommended)"
    }
}

if ($env:SPT_PKG_RELEASE_MODE -eq '1') {
    if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
        Write-Error 'choco not installed in release mode'
    }
    Push-Location (Split-Path $nuspec)
    try {
        choco pack
        # choco install --source . spt -y     # requires admin; skip in CI
    } finally {
        Pop-Location
    }
}

Write-Output "OK: choco smoke (mode=$($env:SPT_PKG_RELEASE_MODE))"
