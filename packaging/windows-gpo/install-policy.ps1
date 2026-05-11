#Requires -Version 5.1
<#
.SYNOPSIS
    Install the spt (ssh-perma-tunnel) ADMX/ADML policy template into the
    local PolicyDefinitions store.

.DESCRIPTION
    Copies spt.admx into %SystemRoot%\PolicyDefinitions and each <locale>\spt.adml
    into the matching %SystemRoot%\PolicyDefinitions\<locale>\ directory.

    Idempotent: re-running with the same source files is a no-op (file
    contents are compared; copies skipped when identical).

    Use -DryRun to preview the actions without modifying the system.

    Use -CentralStore <path> to install into a domain Central Store
    (typically \\<domain>\SYSVOL\<domain>\Policies\PolicyDefinitions) instead
    of the local store. Requires write access to that share.

.PARAMETER SourceDir
    Directory containing spt.admx and the per-locale ADML subdirectories.
    Defaults to the directory containing this script.

.PARAMETER CentralStore
    Optional UNC path to a domain Central Store. When supplied, files are
    written there instead of the local %SystemRoot%\PolicyDefinitions store.

.PARAMETER DryRun
    Print actions without performing them.

.EXAMPLE
    .\install-policy.ps1
    Install into the local PolicyDefinitions store.

.EXAMPLE
    .\install-policy.ps1 -DryRun
    Preview changes only.

.EXAMPLE
    .\install-policy.ps1 -CentralStore '\\corp.example.com\SYSVOL\corp.example.com\Policies\PolicyDefinitions'
    Install into the domain Central Store.

.NOTES
    Requires Administrator rights when targeting %SystemRoot%\PolicyDefinitions.
    The script intentionally avoids cmdlets outside the default Windows
    PowerShell 5.1 surface so it works on stock servers without extra modules.

    Write-Information is used for human-readable progress because this script
    is intended to be run interactively; callers can suppress output with
    -InformationAction SilentlyContinue.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute(
    'PSReviewUnusedParameter', '',
    Justification = 'Parameters are consumed by helper functions via script scope.')]
param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string] $SourceDir = $PSScriptRoot,

    [Parameter()]
    [string] $CentralStore,

    [Parameter()]
    [switch] $DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$InformationPreference = 'Continue'

# Locales shipped alongside spt.admx. Auto-discovery (below) installs every
# subdirectory matching ^[a-z]{2}(-[A-Z]{2})?$ that contains spt.adml, so this
# list is documentation rather than a gate; it is also used to warn the
# operator if any expected locale ADML is missing from the source tree.
$script:ExpectedLocales = @(
    'en-US',  # Source of truth (English)
    'es-ES',  # Spanish (Spain)
    'pt-PT',  # Portuguese (Portugal)
    'de-DE',  # German (Germany)
    'fr-FR',  # French (France)
    'it-IT',  # Italian (Italy)
    'ja-JP',  # Japanese (Japan)
    'zh-CN'   # Chinese (Simplified)
)

function Write-Action {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Message
    )
    if ($script:DryRun) {
        Write-Information -MessageData "[DRY-RUN] $Message"
    } else {
        Write-Information -MessageData $Message
    }
}

function Test-FilesIdentical {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)] [string] $Left,
        [Parameter(Mandatory)] [string] $Right
    )
    if (-not (Test-Path -LiteralPath $Right -PathType Leaf)) {
        return $false
    }
    $leftHash  = (Get-FileHash -LiteralPath $Left  -Algorithm SHA256).Hash
    $rightHash = (Get-FileHash -LiteralPath $Right -Algorithm SHA256).Hash
    return $leftHash -eq $rightHash
}

function Copy-PolicyFile {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory)] [string] $Source,
        [Parameter(Mandatory)] [string] $Destination
    )

    $destDir = Split-Path -Path $Destination -Parent
    if (-not (Test-Path -LiteralPath $destDir -PathType Container)) {
        Write-Action -Message "Create directory: $destDir"
        if (-not $script:DryRun) {
            $null = New-Item -ItemType Directory -Path $destDir -Force
        }
    }

    if (Test-FilesIdentical -Left $Source -Right $Destination) {
        Write-Information -MessageData "Unchanged: $Destination"
        return
    }

    Write-Action -Message "Copy: $Source -> $Destination"
    if (-not $script:DryRun) {
        if ($PSCmdlet.ShouldProcess($Destination, 'Copy policy file')) {
            Copy-Item -LiteralPath $Source -Destination $Destination -Force
        }
    }
}

function Get-PolicyRoot {
    [CmdletBinding()]
    [OutputType([string])]
    param()
    if ($script:CentralStore) {
        return $script:CentralStore
    }
    if (-not $env:SystemRoot) {
        throw 'SystemRoot environment variable is not set; cannot determine policy root.'
    }
    return (Join-Path -Path $env:SystemRoot -ChildPath 'PolicyDefinitions')
}

function Invoke-Install {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()

    if (-not (Test-Path -LiteralPath $script:SourceDir -PathType Container)) {
        throw "Source directory not found: $script:SourceDir"
    }

    $admxSource = Join-Path -Path $script:SourceDir -ChildPath 'spt.admx'
    if (-not (Test-Path -LiteralPath $admxSource -PathType Leaf)) {
        throw "spt.admx not found at: $admxSource"
    }

    $policyRoot = Get-PolicyRoot
    Write-Information -MessageData "Target policy root: $policyRoot"

    Copy-PolicyFile -Source $admxSource -Destination (Join-Path -Path $policyRoot -ChildPath 'spt.admx')

    $localeDirs = Get-ChildItem -LiteralPath $script:SourceDir -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match '^[a-z]{2}(-[A-Z]{2})?$' }

    if (-not $localeDirs) {
        Write-Warning 'No locale subdirectories found; ADML files will not be installed.'
        return
    }

    $foundLocales = @()
    foreach ($localeDir in $localeDirs) {
        $admlSource = Join-Path -Path $localeDir.FullName -ChildPath 'spt.adml'
        if (-not (Test-Path -LiteralPath $admlSource -PathType Leaf)) {
            Write-Warning "Skipping locale '$($localeDir.Name)': spt.adml missing."
            continue
        }
        $admlDest = Join-Path -Path (Join-Path -Path $policyRoot -ChildPath $localeDir.Name) -ChildPath 'spt.adml'
        Copy-PolicyFile -Source $admlSource -Destination $admlDest
        $foundLocales += $localeDir.Name
    }

    foreach ($expected in $script:ExpectedLocales) {
        if ($foundLocales -notcontains $expected) {
            Write-Warning "Expected locale '$expected' not present in $script:SourceDir; ADML for it was not installed."
        }
    }
}

try {
    Invoke-Install
    if ($DryRun) {
        Write-Information -MessageData 'Dry run complete. No changes were made.'
    } else {
        Write-Information -MessageData 'spt policy template installation complete.'
    }
}
catch {
    Write-Error -Message ("install-policy.ps1 failed: {0}" -f $_.Exception.Message)
    exit 1
}
