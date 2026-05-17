$ErrorActionPreference = 'Stop'
$toolsDir = "$(Split-Path -parent $MyInvocation.MyCommand.Definition)"

# spt ships separate MSI installers per architecture from GitHub Releases.
# The checksums below MUST be regenerated for every release. The Chocolatey
# community moderators will reject the submission if checksums are missing
# or do not match the upstream SHA256SUMS file.
$packageArgs = @{
    packageName    = 'spt'
    fileType       = 'msi'
    url64bit       = 'https://github.com/Mariana/ssh-perma-tunnel/releases/download/v0.1.0/spt-0.1.0-x86_64-pc-windows-msvc.msi'
    urlArm64       = 'https://github.com/Mariana/ssh-perma-tunnel/releases/download/v0.1.0/spt-0.1.0-aarch64-pc-windows-msvc.msi'
    checksum64     = 'PLACEHOLDER_X64_SHA256'
    checksumArm64  = 'PLACEHOLDER_ARM64_SHA256'
    checksumType64 = 'sha256'
    checksumType   = 'sha256'
    silentArgs     = '/qn /norestart'
    validExitCodes = @(0, 3010, 1641)
}

Install-ChocolateyPackage @packageArgs
