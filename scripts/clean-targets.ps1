<#
.SYNOPSIS
    Remove generated Rust target directories from this repository.

.DESCRIPTION
    Finds every directory named "target" under the repo root, prunes traversal
    inside those directories, verifies each path is inside this checkout, and
    removes it. Use -DryRun or -WhatIf to inspect the cleanup first.

.PARAMETER DryRun
    Print the target directories that would be removed without deleting them.

.EXAMPLE
    PS> .\scripts\clean-targets.ps1 -DryRun

.EXAMPLE
    PS> .\scripts\clean-targets.ps1
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [switch]$DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = (Resolve-Path (Join-Path $ScriptDir '..')).Path
$PrunedDirectoryNames = @('.git', '.docker-tmp')

function Test-UnderRepoRoot {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Root
    )

    $full = [System.IO.Path]::GetFullPath($Path)
    $rootFull = [System.IO.Path]::GetFullPath($Root)
    if (-not $rootFull.EndsWith([System.IO.Path]::DirectorySeparatorChar)) {
        $rootFull += [System.IO.Path]::DirectorySeparatorChar
    }

    return $full.StartsWith($rootFull, [System.StringComparison]::OrdinalIgnoreCase)
}

function Find-TargetDirs {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Root
    )

    $stack = [System.Collections.Generic.Stack[string]]::new()
    $stack.Push($Root)
    $targets = [System.Collections.Generic.List[string]]::new()

    while ($stack.Count -gt 0) {
        $dir = $stack.Pop()
        foreach ($child in Get-ChildItem -LiteralPath $dir -Directory -Force -ErrorAction SilentlyContinue) {
            if ($PrunedDirectoryNames -contains $child.Name) {
                continue
            }
            if ($child.Name -eq 'target') {
                $targets.Add($child.FullName)
                continue
            }

            $stack.Push($child.FullName)
        }
    }

    return $targets | Sort-Object -Property Length -Descending
}

function ConvertTo-ExtendedWindowsPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if ([System.IO.Path]::DirectorySeparatorChar -ne '\') {
        return $Path
    }
    if ($Path.StartsWith('\\?\', [System.StringComparison]::Ordinal)) {
        return $Path
    }
    if ($Path.StartsWith('\\', [System.StringComparison]::Ordinal)) {
        return "\\?\UNC\$($Path.TrimStart('\'))"
    }

    return "\\?\$Path"
}

function Remove-TargetDir {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if ([System.IO.Path]::DirectorySeparatorChar -eq '\') {
        $extendedPath = ConvertTo-ExtendedWindowsPath -Path $Path
        try {
            [System.IO.Directory]::Delete($extendedPath, $true)
            return
        } catch {
            Write-Host "extended Windows delete failed; retrying with Remove-Item: $($_.Exception.Message)"
            Remove-Item -LiteralPath $extendedPath -Recurse -Force
            return
        }
    }

    Remove-Item -LiteralPath $Path -Recurse -Force
}

$targets = @(Find-TargetDirs -Root $RepoRoot)
if ($targets.Count -eq 0) {
    Write-Host "clean-targets: no target directories found under $RepoRoot"
    exit 0
}

Write-Host "clean-targets: found $($targets.Count) target directories under $RepoRoot"

$removed = 0
foreach ($target in $targets) {
    $resolved = (Resolve-Path -LiteralPath $target).Path
    $item = Get-Item -LiteralPath $resolved -Force

    if ((Split-Path -Leaf $resolved) -ne 'target') {
        throw "refusing to remove non-target path: $resolved"
    }
    if (-not (Test-UnderRepoRoot -Path $resolved -Root $RepoRoot)) {
        throw "refusing to remove path outside repo root: $resolved"
    }
    if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "refusing to remove reparse point target directory: $resolved"
    }

    if ($DryRun) {
        Write-Host "would remove $resolved"
        continue
    }

    if ($PSCmdlet.ShouldProcess($resolved, 'Remove target directory')) {
        Write-Host "removing $resolved"
        Remove-TargetDir -Path $resolved
        $removed += 1
    }
}

if ($DryRun) {
    Write-Host "clean-targets: dry run complete; removed 0 directories"
} else {
    Write-Host "clean-targets: removed $removed target directories"
}
