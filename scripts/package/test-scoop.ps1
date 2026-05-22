# Smoke test for the Scoop manifest.
#
# Local mode: validates that the JSON parses and required keys are present.
# Release mode (SPT_PKG_RELEASE_MODE=1): performs a real `scoop install` from
# a local bucket — only viable when the release artifacts are reachable.

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$manifest = Join-Path $root 'packaging\scoop\spt.json'

if (-not (Test-Path $manifest)) {
    Write-Error "missing $manifest"
}

# 1. Parse JSON.
$obj = Get-Content -Raw $manifest | ConvertFrom-Json

# 2. Required keys.
foreach ($key in @('version', 'description', 'homepage', 'license', 'architecture')) {
    if (-not $obj.PSObject.Properties.Name.Contains($key)) {
        Write-Error "manifest missing required key: $key"
    }
}

# 3. Architecture entries (64bit at minimum).
if (-not $obj.architecture.'64bit') {
    Write-Error 'manifest missing architecture.64bit entry'
}

# 4. Release-mode install.
if ($env:SPT_PKG_RELEASE_MODE -eq '1') {
    if (-not (Get-Command scoop -ErrorAction SilentlyContinue)) {
        Write-Error 'scoop not installed in release mode'
    }
    $bucket = Join-Path $env:USERPROFILE 'scoop\buckets\local-spt\bucket'
    New-Item -ItemType Directory -Force -Path $bucket | Out-Null
    Copy-Item $manifest (Join-Path $bucket 'spt.json') -Force
    scoop install local-spt/spt
    spt --version
}

Write-Output "OK: scoop smoke (mode=$($env:SPT_PKG_RELEASE_MODE))"
