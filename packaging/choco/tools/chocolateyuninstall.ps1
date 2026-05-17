$ErrorActionPreference = 'Stop'

$packageName  = 'spt'
$softwareName = 'spt*'
$fileType     = 'msi'
$silentArgs   = '/qn /norestart'
$validExitCodes = @(0, 3010, 1605, 1614, 1641)

# Auto-detect the MSI ProductCode written by the Windows installer.
# Get-UninstallRegistryKey ships with the Chocolatey helper module.
[array]$keys = Get-UninstallRegistryKey -SoftwareName $softwareName

if ($keys.Count -eq 0) {
    Write-Warning "spt is not installed via MSI; nothing to uninstall."
    return
}

if ($keys.Count -gt 1) {
    Write-Warning "Found $($keys.Count) registry keys matching '$softwareName'; uninstalling all."
}

foreach ($key in $keys) {
    $productCode = $key.PSChildName
    if (-not $productCode) {
        Write-Warning "Skipping key with empty PSChildName: $($key.DisplayName)"
        continue
    }

    $uninstallArgs = @{
        packageName    = $packageName
        fileType       = $fileType
        silentArgs     = "$productCode $silentArgs"
        validExitCodes = $validExitCodes
        file           = ''
    }

    Uninstall-ChocolateyPackage @uninstallArgs
}
