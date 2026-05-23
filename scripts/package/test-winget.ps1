# Smoke test for the winget manifest set.
#
# Local mode: parse each of the three YAML manifest files (version, installer,
# locale) and verify the PackageIdentifier matches across them. A full
# `winget validate` requires the published Microsoft Store binary and is
# release-gated.

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$dir = Join-Path $root 'packaging\winget\manifests\m\Mariana\spt\26.1'

if (-not (Test-Path $dir)) {
    Write-Error "missing manifest directory $dir"
}

$files = @(
    'Mariana.spt.yaml',
    'Mariana.spt.installer.yaml',
    'Mariana.spt.locale.en-US.yaml'
)

# Lightweight YAML parser: scan for `PackageIdentifier:` line. Avoids needing
# powershell-yaml on every runner.
$ids = @()
foreach ($f in $files) {
    $path = Join-Path $dir $f
    if (-not (Test-Path $path)) { Write-Error "missing $path" }
    # NB: regex anchor (no -SimpleMatch). `^PackageIdentifier:` interpreted
    # as a literal substring never matches — every PackageIdentifier line in
    # the generated manifests begins at column 0 but contains no `^` char.
    # The earlier `-SimpleMatch` form silently matched nothing on every CI
    # run and tripped the `no PackageIdentifier` error path.
    $line = Select-String -Path $path -Pattern '^PackageIdentifier:' | Select-Object -First 1
    if (-not $line) { Write-Error "$f has no PackageIdentifier" }
    $ids += $line.Line.Trim()
}
$unique = $ids | Select-Object -Unique
if ($unique.Count -ne 1) {
    Write-Error "PackageIdentifier mismatch across manifests: $($ids -join '; ')"
}

if ($env:SPT_PKG_RELEASE_MODE -eq '1') {
    if (Get-Command winget -ErrorAction SilentlyContinue) {
        winget validate --manifest $dir
    } else {
        Write-Warning 'winget not available in release mode runner; skipping validate'
    }
}

Write-Output "OK: winget smoke (mode=$($env:SPT_PKG_RELEASE_MODE))"
