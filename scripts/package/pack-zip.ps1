#!/usr/bin/env pwsh
# pack-zip.ps1 — produce a Windows .zip for one MSVC target.
#
# Layout inside the archive:
#   spt-<version>-<target>\
#     spt.exe
#     LICENSE
#     README.md
#     docs\...
#     share\man\man1\spt*.1
#
# Output: dist\<version>\spt-<version>-<target>.zip

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
Usage: scripts/package/pack-zip.ps1 -Target <triple> [-DryRun]

Packs the already-built target/<target>/release/spt.exe into
dist/<version>/spt-<version>-<target>.zip together with LICENSE, README.md,
docs/, and the man pages.

Only Windows-MSVC targets are supported by this script.
"@
}

if ($Help -or -not $Target) {
    Show-Usage
    if (-not $Help) { exit 1 } else { exit 0 }
}

if (-not (Test-TargetEligible $Target)) { Stop-Die "unknown target: $Target" }
if (-not (Test-WindowsTarget $Target))  { Stop-Die "pack-zip is for Windows targets only; use pack-tarball.sh otherwise." }

$root    = Get-RepoRoot
$version = Get-VersionFromCargo
$bin     = Get-BinaryForTarget $Target
if (-not (Test-Path -LiteralPath $bin)) {
    Stop-Die "binary missing: $bin (run build-target.ps1 $Target first)"
}

$dist = New-DistDir
$name = "spt-$version-$Target"
$stage = Join-Path ([System.IO.Path]::GetTempPath()) "spt-zip-$([guid]::NewGuid().ToString('N'))"
$staged = Join-Path $stage $name
New-Item -ItemType Directory -Path $staged -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $staged 'docs') -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $staged 'share/man/man1') -Force | Out-Null

try {
    Copy-Item $bin (Join-Path $staged 'spt.exe')

    $license = Join-Path $root 'license.md'
    if (Test-Path -LiteralPath $license) { Copy-Item $license (Join-Path $staged 'LICENSE') }
    $readme = Join-Path $root 'readme.md'
    if (Test-Path -LiteralPath $readme)  { Copy-Item $readme  (Join-Path $staged 'README.md') }

    $docsDir = Join-Path $root 'docs'
    if (Test-Path -LiteralPath $docsDir) {
        Get-ChildItem -LiteralPath $docsDir -File -Recurse -Include *.md,*.txt | ForEach-Object {
            $rel = $_.FullName.Substring($root.Length + 1)
            $target = Join-Path $staged $rel
            New-Item -ItemType Directory -Path (Split-Path $target) -Force | Out-Null
            Copy-Item $_.FullName $target
        }
    }

    $manDir = Join-Path $root 'packaging/man'
    if (Test-Path -LiteralPath $manDir) {
        Get-ChildItem -LiteralPath $manDir -File -Filter 'spt*.1' | ForEach-Object {
            Copy-Item $_.FullName (Join-Path $staged 'share/man/man1') -Force
        }
    }

    $archive = Join-Path $dist "$name.zip"

    if ($DryRun) {
        Write-Info "would pack -> $archive"
        Get-ChildItem -LiteralPath $staged -Recurse -File | ForEach-Object { Write-Host $_.FullName }
        return
    }

    if (Test-Path -LiteralPath $archive) { Remove-Item -LiteralPath $archive -Force }
    Compress-Archive -Path (Join-Path $stage "$name") -DestinationPath $archive -CompressionLevel Optimal
    Write-Info "packed: $archive"
    Write-Output $archive
}
finally {
    if (Test-Path -LiteralPath $stage) { Remove-Item -LiteralPath $stage -Recurse -Force }
}
