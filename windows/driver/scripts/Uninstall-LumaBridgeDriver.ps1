<#
.SYNOPSIS
    Safely deactivates the virtual monitor, removes all Root\LumaBridgeIddDriver PnP
    device nodes, deletes Driver Store OEM packages (without /force by default), and
    optionally removes a specific test signing certificate by SHA-1 thumbprint upon
    explicit confirmation.
#>
[CmdletBinding()]
param(
    [switch]$RemoveTestCertificate,

    [string]$CertificateThumbprint,

    [switch]$ConfirmCertificateRemoval,

    [switch]$ForceDriverStoreDelete,

    [switch]$DryRun,

    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$commonModulePath = (Resolve-Path -LiteralPath (Join-Path -Path $PSScriptRoot -ChildPath 'LumaBridgeDriverCommon.psm1')).Path
$loadedCommon = Get-Module -Name 'LumaBridgeDriverCommon'
if ($null -eq $loadedCommon -or $loadedCommon.Path -ine $commonModulePath) {
    Import-Module $commonModulePath -Force
}

$constants = Get-LumaBridgeDriverConstants
$null = Assert-LumaBridgeAdministrator -OperationName 'Uninstall and Rollback LumaBridgeIddDriver' -DryRun:$DryRun

$normalizedThumbprint = $null
if ($RemoveTestCertificate) {
    if ([string]::IsNullOrWhiteSpace($CertificateThumbprint)) {
        throw 'Certificate removal requires -CertificateThumbprint (40 hexadecimal characters). Subject-based wildcard removal is disallowed.'
    }
    $normalizedThumbprint = ($CertificateThumbprint -replace '\s', '').ToUpperInvariant()
    if ($normalizedThumbprint -notmatch '^[0-9A-F]{40}$') {
        throw ("Invalid -CertificateThumbprint '{0}'. Expected a 40-character hexadecimal SHA-1 thumbprint." -f $CertificateThumbprint)
    }
}

$instances = @(Get-LumaBridgePnpInstances)
$packages = @(Get-LumaBridgeDriverStorePackages)

$summaryMsg = "Remove {0} PnP instance(s) and {1} Driver Store package(s){2}" -f `
    $instances.Count, `
    $packages.Count, `
    $(if ($RemoveTestCertificate) { (" (plus explicit confirmation for certificate thumbprint '{0}')" -f $normalizedThumbprint) } else { '' })

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
            $delArgs = @('/delete-driver', $pkg.PublishedName, '/uninstall')
            if ($ForceDriverStoreDelete) {
                $delArgs += '/force'
            }
            $null = Invoke-LumaBridgeExternalCommand -FilePath 'pnputil.exe' -Arguments $delArgs -DryRun
        }
        if ($packages.Count -eq 0) {
            Write-Host ("[DRY-RUN] No '{0}' OEM packages currently registered in Driver Store." -f $constants.InfFileName) -ForegroundColor Cyan
        }
        if ($RemoveTestCertificate) {
            Write-Host ("[DRY-RUN] Would prompt explicit confirmation to remove certificate thumbprint '{0}' from CurrentUser\My, LocalMachine\Root, and LocalMachine\TrustedPublisher." -f $normalizedThumbprint) -ForegroundColor Cyan
        }
    }
    return
}

$removedDevices = New-Object System.Collections.Generic.List[string]
foreach ($inst in $instances) {
    try {
        Set-LumaBridgeDeviceEnableVirtualMonitor -DeviceParametersPath $inst.DeviceParametersPath -Value 0
    }
    catch {
    }
    $null = Invoke-LumaBridgeExternalCommand -FilePath 'pnputil.exe' -Arguments @('/remove-device', $inst.InstanceId)
    $removedDevices.Add($inst.InstanceId)
}

$removedPackages = New-Object System.Collections.Generic.List[string]
foreach ($pkg in $packages) {
    $delArgs = @('/delete-driver', $pkg.PublishedName, '/uninstall')
    if ($ForceDriverStoreDelete) {
        $delArgs += '/force'
    }
    $null = Invoke-LumaBridgeExternalCommand -FilePath 'pnputil.exe' -Arguments $delArgs
    $removedPackages.Add($pkg.PublishedName)
}

$removedCertificates = New-Object System.Collections.Generic.List[string]
if ($RemoveTestCertificate) {
    $certPrompt = "Remove certificate with thumbprint '{0}' from CurrentUser\My, LocalMachine\Root, and LocalMachine\TrustedPublisher" -f $normalizedThumbprint
    if (Confirm-LumaBridgeAction -PromptMessage $certPrompt -DryRun:$DryRun -Force:$ConfirmCertificateRemoval) {
        foreach ($removedPath in @(Remove-LumaBridgeCertificateFromStores -Thumbprint $normalizedThumbprint)) {
            $removedCertificates.Add($removedPath)
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
