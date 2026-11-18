<#
.SYNOPSIS
    Safely deactivates the virtual monitor, removes all Root\LumaBridgeIddDriver PnP
    device nodes, deletes Driver Store OEM packages, and optionally cleans up test signing
    certificates created for validation.
#>
[CmdletBinding()]
param(
    [switch]$RemoveTestCertificate,

    [string]$CertificateSubject = 'CN=LumaBridge Test Driver Signing',

    [switch]$DryRun,

    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path -Path $PSScriptRoot -ChildPath 'LumaBridgeDriverCommon.psm1') -Force

$constants = Get-LumaBridgeDriverConstants
$null = Assert-LumaBridgeAdministrator -OperationName 'Uninstall and Rollback LumaBridgeIddDriver' -DryRun:$DryRun

$instances = @(Get-LumaBridgePnpInstances)
$packages = @(Get-LumaBridgeDriverStorePackages)

$summaryMsg = "Remove {0} PnP instance(s) and {1} Driver Store package(s){2}" -f `
    $instances.Count, `
    $packages.Count, `
    $(if ($RemoveTestCertificate) { (" plus matching '{0}' test certificates" -f $CertificateSubject) } else { '' })

if (-not (Confirm-LumaBridgeAction -PromptMessage $summaryMsg -DryRun:$DryRun -Force:$Force)) {
    if ($DryRun) {
        foreach ($inst in $instances) {
            Write-Host ("[DRY-RUN] Would set EnableVirtualMonitor=0 at '{0}'" -f $inst.DeviceParametersPath) -ForegroundColor Cyan
            $null = Invoke-LumaBridgeExternalCommand -FilePath 'pnputil.exe' -Arguments @('/remove-device', $inst.InstanceId) -DryRun
        }
        if ($instances.Count -eq 0) {
            Write-Host ("[DRY-RUN] No '{0}' PnP device instances currently present to remove." -f $constants.HardwareId) -ForegroundColor Cyan
        }
        foreach ($pkg in $packages) {
            $null = Invoke-LumaBridgeExternalCommand -FilePath 'pnputil.exe' -Arguments @('/delete-driver', $pkg.PublishedName, '/uninstall', '/force') -DryRun
        }
        if ($packages.Count -eq 0) {
            Write-Host ("[DRY-RUN] No '{0}' OEM packages currently registered in Driver Store." -f $constants.InfFileName) -ForegroundColor Cyan
        }
        if ($RemoveTestCertificate) {
            Write-Host ("[DRY-RUN] Would remove certificates with Subject '{0}' from CurrentUser\My, LocalMachine\Root, and LocalMachine\TrustedPublisher." -f $CertificateSubject) -ForegroundColor Cyan
        }
    }
    return
}

$removedDevices = New-Object System.Collections.Generic.List[string]
foreach ($inst in $instances) {
    if (Test-Path -LiteralPath $inst.DeviceParametersPath) {
        New-ItemProperty -LiteralPath $inst.DeviceParametersPath -Name $constants.RegistryValueEnableMon -PropertyType DWord -Value 0 -Force -ErrorAction SilentlyContinue | Out-Null
    }
    $null = Invoke-LumaBridgeExternalCommand -FilePath 'pnputil.exe' -Arguments @('/remove-device', $inst.InstanceId)
    $removedDevices.Add($inst.InstanceId)
}

$removedPackages = New-Object System.Collections.Generic.List[string]
foreach ($pkg in $packages) {
    $null = Invoke-LumaBridgeExternalCommand -FilePath 'pnputil.exe' -Arguments @('/delete-driver', $pkg.PublishedName, '/uninstall', '/force')
    $removedPackages.Add($pkg.PublishedName)
}

$removedCertificates = New-Object System.Collections.Generic.List[string]
if ($RemoveTestCertificate) {
    foreach ($storePath in @('Cert:\CurrentUser\My', 'Cert:\LocalMachine\Root', 'Cert:\LocalMachine\TrustedPublisher')) {
        if (Test-Path -LiteralPath $storePath) {
            $matchingCerts = Get-ChildItem -Path $storePath -ErrorAction SilentlyContinue |
                Where-Object { $_.Subject -eq $CertificateSubject }
            foreach ($cert in $matchingCerts) {
                Remove-Item -LiteralPath (Join-Path -Path $storePath -ChildPath $cert.Thumbprint) -Force -ErrorAction Stop
                $removedCertificates.Add(("{0}\{1}" -f $storePath, $cert.Thumbprint))
            }
        }
    }
}

$remainingInstances = @(Get-LumaBridgePnpInstances)
$remainingPackages = @(Get-LumaBridgeDriverStorePackages)

[pscustomobject]@{
    RemovedPnpInstances   = @($removedDevices.ToArray())
    RemovedOemPackages    = @($removedPackages.ToArray())
    RemovedCertificates   = @($removedCertificates.ToArray())
    RemainingPnpCount     = $remainingInstances.Count
    RemainingPackageCount = $remainingPackages.Count
    RollbackClean         = ($remainingInstances.Count -eq 0 -and $remainingPackages.Count -eq 0)
}
