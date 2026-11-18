<#
.SYNOPSIS
    Dynamically locates the active Root\LumaBridgeIddDriver PnP instance and safely
    enables or disables the MVP virtual monitor (EnableVirtualMonitor = 1 or 0).
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Enable', 'Disable')]
    [string]$Action,

    [string]$InstanceId,

    [switch]$NoRestart,

    [switch]$DryRun,

    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path -Path $PSScriptRoot -ChildPath 'LumaBridgeDriverCommon.psm1') -Force

$constants = Get-LumaBridgeDriverConstants
$null = Assert-LumaBridgeAdministrator -OperationName ("{0} LumaBridge Virtual Monitor" -f $Action) -DryRun:$DryRun

$instances = @(Get-LumaBridgePnpInstances)
$target = $null

if (-not [string]::IsNullOrWhiteSpace($InstanceId)) {
    $target = $instances | Where-Object { $_.InstanceId -ieq $InstanceId } | Select-Object -First 1
    if ($null -eq $target -and -not $DryRun) {
        throw ("PnP instance '{0}' was not found among '{1}' devices." -f $InstanceId, $constants.HardwareId)
    }
}
else {
    if ($instances.Count -eq 0 -and -not $DryRun) {
        throw ("No '{0}' PnP device instance found. Run Install-LumaBridgeDriver.ps1 first." -f $constants.HardwareId)
    }
    if ($instances.Count -gt 1) {
        $ids = ($instances | ForEach-Object { $_.InstanceId }) -join ', '
        throw ("Multiple '{0}' PnP instances found ({1}). Pass -InstanceId explicitly or remove duplicates." -f $constants.HardwareId, $ids)
    }
    if ($instances.Count -eq 1) {
        $target = $instances[0]
    }
}

$desiredValue = if ($Action -eq 'Enable') { 1 } else { 0 }
$targetInstanceId = if ($null -ne $target) {
    $target.InstanceId
}
elseif (-not [string]::IsNullOrWhiteSpace($InstanceId)) {
    $InstanceId
}
else {
    '<dynamic Root\LumaBridgeIddDriver instance>'
}

$targetRegPath = if ($null -ne $target) {
    $target.DeviceParametersPath
}
else {
    "HKLM:\SYSTEM\CurrentControlSet\Enum\$targetInstanceId\Device Parameters"
}

$confirmMsg = "Set {0}={1} at '{2}'{3}" -f `
    $constants.RegistryValueEnableMon, `
    $desiredValue, `
    $targetRegPath, `
    $(if ($NoRestart) { '' } else { (" and restart PnP device '{0}'" -f $targetInstanceId) })

if (-not (Confirm-LumaBridgeAction -PromptMessage $confirmMsg -DryRun:$DryRun -Force:$Force)) {
    if ($DryRun) {
        Write-Host ("[DRY-RUN] Would write REG_DWORD {0}={1} in '{2}'" -f $constants.RegistryValueEnableMon, $desiredValue, $targetRegPath) -ForegroundColor Cyan
        if (-not $NoRestart) {
            $null = Invoke-LumaBridgeExternalCommand -FilePath 'pnputil.exe' -Arguments @('/restart-device', $targetInstanceId) -DryRun
        }
    }
    return
}

if (-not (Test-Path -LiteralPath $targetRegPath)) {
    New-Item -Path $targetRegPath -Force | Out-Null
}

New-ItemProperty -LiteralPath $targetRegPath -Name $constants.RegistryValueEnableMon -PropertyType DWord -Value $desiredValue -Force | Out-Null

if (-not $NoRestart) {
    $null = Invoke-LumaBridgeExternalCommand -FilePath 'pnputil.exe' -Arguments @('/restart-device', $targetInstanceId)
}

$updated = @(Get-LumaBridgePnpInstances) | Where-Object { $_.InstanceId -ieq $targetInstanceId } | Select-Object -First 1
[pscustomobject]@{
    Action               = $Action
    InstanceId           = $targetInstanceId
    EnableVirtualMonitor = $desiredValue
    DeviceRestarted      = (-not $NoRestart)
    CurrentDeviceState   = $updated
}
