#!/usr/bin/env pwsh
# sign-windows.ps1 — Authenticode-sign every Windows artifact under dist/<version>/.
#
# Optional. If WINDOWS_SIGNING_CERT_BASE64 is unset, logs a warning and exits 0.

[CmdletBinding()]
param(
    [string]$Path,
    [switch]$Help
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. "$PSScriptRoot/../build/_common.ps1"

function Show-Usage {
    @"
Usage: scripts/sign/sign-windows.ps1 [-Path <file-or-dir>]

Signs every spt-*.exe / spt-*.msi under dist/<version>/ (or a single file
if -Path is supplied) using signtool.

Required env (all together):
  WINDOWS_SIGNING_CERT_BASE64   PFX bundle, base64-encoded
  WINDOWS_SIGNING_PASSWORD      PFX password

Optional env:
  WINDOWS_TIMESTAMP_URL         RFC 3161 TSA (default: http://timestamp.digicert.com)

Without env vars: warn and exit 0 (artifacts ship unsigned).
"@
}

if ($Help) { Show-Usage; exit 0 }

$cb = [Environment]::GetEnvironmentVariable('WINDOWS_SIGNING_CERT_BASE64')
$pw = [Environment]::GetEnvironmentVariable('WINDOWS_SIGNING_PASSWORD')
if (-not $cb -or -not $pw) {
    Write-Warn 'WINDOWS_SIGNING_CERT_BASE64 / WINDOWS_SIGNING_PASSWORD unset; skipping Authenticode signing'
    exit 0
}

# Locate signtool.
$signtool = Get-Command signtool -ErrorAction SilentlyContinue
if (-not $signtool) {
    # Best-effort search of the Windows SDK.
    $candidates = @(
        "$env:ProgramFiles(x86)/Windows Kits/10/bin/x64/signtool.exe",
        "$env:ProgramFiles(x86)/Windows Kits/10/bin/10.0.22621.0/x64/signtool.exe",
        "$env:ProgramFiles(x86)/Windows Kits/10/bin/10.0.20348.0/x64/signtool.exe"
    )
    foreach ($c in $candidates) {
        if (Test-Path -LiteralPath $c) { $signtool = (Get-Command $c); break }
    }
}
if (-not $signtool) { Write-Warn 'signtool.exe not found on PATH or under Windows SDK; skipping'; exit 0 }

$tsa = if ($env:WINDOWS_TIMESTAMP_URL) { $env:WINDOWS_TIMESTAMP_URL } else { 'http://timestamp.digicert.com' }

$pfx = Join-Path ([System.IO.Path]::GetTempPath()) "spt-signing-$([guid]::NewGuid().ToString('N')).pfx"
[IO.File]::WriteAllBytes($pfx, [Convert]::FromBase64String($cb))

try {
    if (-not $Path) {
        $dist = Get-DistDir
        if (-not (Test-Path -LiteralPath $dist)) { Write-Warn "dist dir missing: $dist"; exit 0 }
        $files = Get-ChildItem -LiteralPath $dist -File -Include 'spt*.exe','spt*.msi' -ErrorAction SilentlyContinue
    }
    elseif (Test-Path -LiteralPath $Path -PathType Container) {
        $files = Get-ChildItem -LiteralPath $Path -File -Include 'spt*.exe','spt*.msi'
    }
    else {
        $files = @(Get-Item -LiteralPath $Path)
    }

    if (-not $files -or $files.Count -eq 0) {
        Write-Warn 'no .exe/.msi to sign'
        exit 0
    }

    foreach ($f in $files) {
        Write-Info "signing $($f.FullName)"
        & $signtool.Source sign /fd SHA256 /tr $tsa /td SHA256 /f $pfx /p $pw $f.FullName
        if ($LASTEXITCODE -ne 0) { Stop-Die "signtool failed on $($f.FullName)" }
    }
}
finally {
    if (Test-Path -LiteralPath $pfx) { Remove-Item -LiteralPath $pfx -Force }
}
