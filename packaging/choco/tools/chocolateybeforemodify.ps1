$ErrorActionPreference = 'Stop'

# chocolateybeforemodify.ps1 runs before upgrade and before uninstall, while
# the OLD version is still present. We use it to gracefully stop the spt
# Windows service so the MSI can replace spt.exe without a reboot prompt
# (MSI exit code 3010) and without leaving orphaned worker processes.

$serviceName = 'spt'

$service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($null -eq $service) {
    Write-Host "spt service is not installed; skipping pre-modify stop."
    return
}

if ($service.Status -eq 'Stopped') {
    Write-Host "spt service is already stopped."
    return
}

Write-Host "Stopping spt service before upgrade/uninstall..."
try {
    Stop-Service -Name $serviceName -Force -ErrorAction Stop
    # Give the SCM a moment to mark the service as stopped before the MSI runs.
    $service.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
    Write-Host "spt service stopped."
} catch {
    Write-Warning "Failed to stop spt service cleanly: $($_.Exception.Message)"
    Write-Warning "The MSI may request a reboot (exit code 3010) to replace in-use files."
}
