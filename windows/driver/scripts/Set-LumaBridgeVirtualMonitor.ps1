<#
.SYNOPSIS
    Dynamically locates the active Root\LumaBridgeIddDriver PnP instance via
    DEVPKEY_Device_HardwareIds and safely enables or disables the MVP virtual monitor
    (EnableVirtualMonitor = 1 or 0) with rollback on partial activation failure.
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

$commonModulePath = (Resolve-Path -LiteralPath (Join-Path -Path $PSScriptRoot -ChildPath 'LumaBridgeDriverCommon.psm1')).Path
$loadedCommon = Get-Module -Name 'LumaBridgeDriverCommon'
if ($null -eq $loadedCommon -or $loadedCommon.Path -ine $commonModulePath) {
    Import-Module $commonModulePath -Force
}

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
    Get-LumaBridgeDeviceParametersRegistryPath -InstanceId $targetInstanceId
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

try {
    Set-LumaBridgeDeviceEnableVirtualMonitor -DeviceParametersPath $targetRegPath -Value $desiredValue

    if (-not $NoRestart) {
        $null = Invoke-LumaBridgeExternalCommand -FilePath 'pnputil.exe' -Arguments @('/restart-device', $targetInstanceId)
    }

    $updated = @(Get-LumaBridgePnpInstances) | Where-Object { $_.InstanceId -ieq $targetInstanceId } | Select-Object -First 1
    if ($null -eq $updated) {
        throw ("PnP instance '{0}' could not be found after setting {1}={2}." -f $targetInstanceId, $constants.RegistryValueEnableMon, $desiredValue)
    }

    if ([int]$updated.EnableVirtualMonitor -ne $desiredValue) {
        throw ("Expected {0}={1} on '{2}', observed '{3}'." -f $constants.RegistryValueEnableMon, $desiredValue, $targetInstanceId, $updated.EnableVirtualMonitor)
    }

    if (-not $NoRestart) {
        $hasProblem = ($null -ne $updated.ProblemCode -and [int]$updated.ProblemCode -ne 0)
        if ($updated.Status -ine 'OK' -or $hasProblem) {
            throw ("Device '{0}' entered unhealthy state after restart (Status='{1}', ProblemCode={2})." -f $targetInstanceId, $updated.Status, $updated.ProblemCode)
        }
    }

    [pscustomobject]@{
        Action               = $Action
        InstanceId           = $targetInstanceId
        EnableVirtualMonitor = $desiredValue
        DeviceRestarted      = (-not $NoRestart)
        CurrentDeviceState   = $updated
    }
}
catch {
    $primaryError = $_.Exception.Message
    if ($Action -eq 'Enable') {
        $rollbackNotes = New-Object System.Collections.Generic.List[string]
        try {
            Set-LumaBridgeDeviceEnableVirtualMonitor -DeviceParametersPath $targetRegPath -Value 0
            $rollbackNotes.Add('Reverted EnableVirtualMonitor=0')
        }
        catch {
            $rollbackNotes.Add(("Failed reverting EnableVirtualMonitor=0: {0}" -f $_.Exception.Message))
        }

        if (-not $NoRestart) {
            try {
                $null = Invoke-LumaBridgeExternalCommand -FilePath 'pnputil.exe' -Arguments @('/restart-device', $targetInstanceId)
                $rollbackNotes.Add(("Restarted device '{0}'" -f $targetInstanceId))
            }
            catch {
                $rollbackNotes.Add(("Failed restarting device '{0}': {1}" -f $targetInstanceId, $_.Exception.Message))
            }
        }

        throw ("Virtual monitor activation failed: {0}. Rollback: {1}." -f $primaryError, ($rollbackNotes -join '; '))
    }

    throw
}
