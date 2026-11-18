<#
.SYNOPSIS
    Idempotently installs or updates LumaBridgeIddDriver from a verified isolated staged
    package, creating at most one Root\LumaBridgeIddDriver device node with
    EnableVirtualMonitor=0, verifying driver binding, and rolling back partial failures.
#>
[CmdletBinding()]
param(
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Release',

    [string]$StagingDir,

    [switch]$AllowUntrustedChain,

    [switch]$SkipTestSigningCheck,

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
$null = Assert-LumaBridgeAdministrator -OperationName 'Install LumaBridgeIddDriver' -DryRun:$DryRun

if ([string]::IsNullOrWhiteSpace($StagingDir)) {
    $StagingDir = Get-LumaBridgeDefaultStagingDirectory -Configuration $Configuration
}

$sourcePackageDir = Get-LumaBridgePackageDirectory -Configuration $Configuration
$StagingDir = Assert-LumaBridgeIsolatedStagingDirectory -StagingDir $StagingDir -SourcePackageDir $sourcePackageDir

$prereqScript = Join-Path -Path $PSScriptRoot -ChildPath 'Test-LumaBridgePrerequisites.ps1'
$prereq = & $prereqScript -Configuration $Configuration -StagingDir $StagingDir

if (-not $prereq.HostOs.IsSupportedWindows11) {
    throw ("Unsupported OS build {0}. Windows 11 x64 (build >= {1}) is required." -f $prereq.HostOs.CurrentBuildNumber, $constants.MinimumWindows11Build)
}

$devconPath = $prereq.WdkTools.DevconPath
if ([string]::IsNullOrWhiteSpace($devconPath)) {
    throw 'devcon.exe could not be located under Windows Kits\10.'
}

$stagedInf = Join-Path -Path $StagingDir -ChildPath $constants.InfFileName
$existingInstances = @(Get-LumaBridgePnpInstances)

if ($existingInstances.Count -gt 1) {
    $ids = ($existingInstances | ForEach-Object { $_.InstanceId }) -join ', '
    throw ("Multiple instances of '{0}' already exist ({1}). Run Uninstall-LumaBridgeDriver.ps1 before reinstalling." -f $constants.HardwareId, $ids)
}

if (-not $DryRun) {
    if ($null -eq $prereq.StagingPackage) {
        throw ("Staging directory does not exist: {0}. Run Invoke-LumaBridgePackageSigning.ps1 first." -f $StagingDir)
    }

    $null = Test-LumaBridgePackageArtifacts `
        -PackageDirectory $StagingDir `
        -RequireValidSignature `
        -AllowUntrustedChain:$AllowUntrustedChain

    if (-not $SkipTestSigningCheck -and $prereq.SecurityState.TestSigning -ne 'Enabled') {
        throw ("Windows Test Signing state is '{0}'. Enable it manually in an elevated prompt with 'bcdedit /set testsigning on' and reboot, or pass -SkipTestSigningCheck for trusted CA packages." -f $prereq.SecurityState.TestSigning)
    }
}

$isUpdate = ($existingInstances.Count -eq 1)
$actionSummary = if ($isUpdate) {
    "Disable virtual monitor (EnableVirtualMonitor=0), update existing device '{0}' using staged INF '{1}', and verify driver binding" -f $existingInstances[0].InstanceId, $stagedInf
}
else {
    "Stage driver '{0}', create 1 root-enumerated '{1}' device with EnableVirtualMonitor=0, and verify driver binding" -f $stagedInf, $constants.HardwareId
}

if (-not (Confirm-LumaBridgeAction -PromptMessage $actionSummary -DryRun:$DryRun -Force:$Force)) {
    if ($DryRun) {
        if ($isUpdate) {
            Write-Host ("[DRY-RUN] Would enforce REG_DWORD {0}=0 at '{1}' before updating" -f $constants.RegistryValueEnableMon, $existingInstances[0].DeviceParametersPath) -ForegroundColor Cyan
            if ($null -ne $existingInstances[0].EnableVirtualMonitor -and [int]$existingInstances[0].EnableVirtualMonitor -ne 0) {
                $null = Invoke-LumaBridgeExternalCommand -FilePath 'pnputil.exe' -Arguments @('/restart-device', $existingInstances[0].InstanceId) -DryRun
            }
            $null = Invoke-LumaBridgeExternalCommand -FilePath 'pnputil.exe' -Arguments @('/add-driver', $stagedInf, '/install') -DryRun
            Write-Host ("[DRY-RUN] Would confirm post-update driver binding (Provider='{0}', ProblemCode=0, matching DriverVer)" -f $constants.DriverProviderName) -ForegroundColor Cyan
        }
        else {
            $null = Invoke-LumaBridgeExternalCommand -FilePath 'pnputil.exe' -Arguments @('/add-driver', $stagedInf) -DryRun
            $null = Invoke-LumaBridgeExternalCommand -FilePath $devconPath -Arguments @('install', $stagedInf, $constants.HardwareId) -DryRun
            Write-Host ("[DRY-RUN] Would query created '{0}' PnP instance, set REG_DWORD {1}=0, and confirm bound driver" -f $constants.HardwareId, $constants.RegistryValueEnableMon) -ForegroundColor Cyan
        }
    }
    return
}

$prePackages = @(Get-LumaBridgeDriverStorePackages)
$prePublishedNames = @($prePackages | ForEach-Object { $_.PublishedName })

try {
    if ($isUpdate) {
        $existingInstance = $existingInstances[0]
        Set-LumaBridgeDeviceEnableVirtualMonitor -DeviceParametersPath $existingInstance.DeviceParametersPath -Value 0
        if ($null -ne $existingInstance.EnableVirtualMonitor -and [int]$existingInstance.EnableVirtualMonitor -ne 0) {
            $null = Invoke-LumaBridgeExternalCommand -FilePath 'pnputil.exe' -Arguments @('/restart-device', $existingInstance.InstanceId)
        }
        $null = Invoke-LumaBridgeExternalCommand -FilePath 'pnputil.exe' -Arguments @('/add-driver', $stagedInf, '/install')
    }
    else {
        $null = Invoke-LumaBridgeExternalCommand -FilePath 'pnputil.exe' -Arguments @('/add-driver', $stagedInf)
        $null = Invoke-LumaBridgeExternalCommand -FilePath $devconPath -Arguments @('install', $stagedInf, $constants.HardwareId)
    }

    $postInstances = @(Get-LumaBridgePnpInstances)
    if ($postInstances.Count -ne 1) {
        throw ("Expected exactly 1 '{0}' PnP instance after install, found {1}." -f $constants.HardwareId, $postInstances.Count)
    }

    $instance = $postInstances[0]
    Set-LumaBridgeDeviceEnableVirtualMonitor -DeviceParametersPath $instance.DeviceParametersPath -Value 0

    $finalInstances = @(Get-LumaBridgePnpInstances)
    if ($finalInstances.Count -ne 1) {
        throw ("Expected exactly 1 '{0}' PnP instance during final verification, found {1}." -f $constants.HardwareId, $finalInstances.Count)
    }

    $postPackages = @(Get-LumaBridgeDriverStorePackages)
    $bindingResult = Test-LumaBridgeDeviceDriverBinding `
        -Instance $finalInstances[0] `
        -DriverStorePackages $postPackages `
        -ExpectedInfPath $stagedInf

    if (-not $bindingResult.IsBound) {
        throw ("Driver binding verification failed for '{0}': {1}" -f $finalInstances[0].InstanceId, ($bindingResult.Reasons -join '; '))
    }

    [pscustomobject]@{
        InstalledInf         = $stagedInf
        Instance             = $finalInstances[0]
        DriverBinding        = $bindingResult
        VirtualMonitorPolicy = 'DisabledByDefault (EnableVirtualMonitor=0)'
    }
}
catch {
    $primaryError = $_.Exception.Message
    $rollbackActions = New-Object System.Collections.Generic.List[string]

    if (-not $isUpdate) {
        try {
            $createdInstances = @(Get-LumaBridgePnpInstances)
            foreach ($inst in $createdInstances) {
                try {
                    Set-LumaBridgeDeviceEnableVirtualMonitor -DeviceParametersPath $inst.DeviceParametersPath -Value 0
                }
                catch {
                }
                try {
                    $null = Invoke-LumaBridgeExternalCommand -FilePath 'pnputil.exe' -Arguments @('/remove-device', $inst.InstanceId)
                    $rollbackActions.Add(("Removed partial PnP instance '{0}'" -f $inst.InstanceId))
                }
                catch {
                    $rollbackActions.Add(("Failed removing PnP instance '{0}': {1}" -f $inst.InstanceId, $_.Exception.Message))
                }
            }
        }
        catch {
            $rollbackActions.Add(("Failed enumerating PnP instances during rollback: {0}" -f $_.Exception.Message))
        }

        try {
            $addedPackages = @(Get-LumaBridgeDriverStorePackages | Where-Object { $prePublishedNames -notcontains $_.PublishedName })
            foreach ($pkg in $addedPackages) {
                try {
                    $null = Invoke-LumaBridgeExternalCommand -FilePath 'pnputil.exe' -Arguments @('/delete-driver', $pkg.PublishedName, '/uninstall')
                    $rollbackActions.Add(("Deleted newly staged package '{0}'" -f $pkg.PublishedName))
                }
                catch {
                    $rollbackActions.Add(("Failed deleting package '{0}': {1}" -f $pkg.PublishedName, $_.Exception.Message))
                }
            }
        }
        catch {
            $rollbackActions.Add(("Failed enumerating Driver Store packages during rollback: {0}" -f $_.Exception.Message))
        }
    }
    else {
        $existingInstance = $existingInstances[0]
        try {
            Set-LumaBridgeDeviceEnableVirtualMonitor -DeviceParametersPath $existingInstance.DeviceParametersPath -Value 0
            $rollbackActions.Add(("Enforced EnableVirtualMonitor=0 on '{0}'" -f $existingInstance.InstanceId))
        }
        catch {
            $rollbackActions.Add(("Failed setting EnableVirtualMonitor=0 on '{0}': {1}" -f $existingInstance.InstanceId, $_.Exception.Message))
        }

        try {
            $addedPackages = @(Get-LumaBridgeDriverStorePackages | Where-Object { $prePublishedNames -notcontains $_.PublishedName })
            foreach ($pkg in $addedPackages) {
                try {
                    $null = Invoke-LumaBridgeExternalCommand -FilePath 'pnputil.exe' -Arguments @('/delete-driver', $pkg.PublishedName, '/uninstall')
                    $rollbackActions.Add(("Deleted failed update package '{0}'" -f $pkg.PublishedName))
                }
                catch {
                    $rollbackActions.Add(("Failed deleting update package '{0}': {1}" -f $pkg.PublishedName, $_.Exception.Message))
                }
            }
        }
        catch {
            $rollbackActions.Add(("Failed enumerating Driver Store packages during update rollback: {0}" -f $_.Exception.Message))
        }

        try {
            $null = Invoke-LumaBridgeExternalCommand -FilePath 'pnputil.exe' -Arguments @('/restart-device', $existingInstance.InstanceId)
            $rollbackActions.Add(("Restarted device '{0}' to restore previous driver state" -f $existingInstance.InstanceId))
        }
        catch {
            $rollbackActions.Add(("Failed restarting device '{0}': {1}" -f $existingInstance.InstanceId, $_.Exception.Message))
        }
    }

    $rollbackSummary = if ($rollbackActions.Count -gt 0) { $rollbackActions -join '; ' } else { 'No rollback actions required' }
    throw ("Driver installation/update failed: {0}. Rollback: {1}." -f $primaryError, $rollbackSummary)
}
