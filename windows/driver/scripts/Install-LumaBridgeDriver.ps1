<#
.SYNOPSIS
    Idempotently installs or updates LumaBridgeIddDriver from a verified staged package,
    creating at most one Root\LumaBridgeIddDriver device node with EnableVirtualMonitor=0.
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

Import-Module (Join-Path -Path $PSScriptRoot -ChildPath 'LumaBridgeDriverCommon.psm1') -Force

$constants = Get-LumaBridgeDriverConstants
$null = Assert-LumaBridgeAdministrator -OperationName 'Install LumaBridgeIddDriver' -DryRun:$DryRun

if ([string]::IsNullOrWhiteSpace($StagingDir)) {
    $StagingDir = Get-LumaBridgeDefaultStagingDirectory -Configuration $Configuration
}

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

    if ($AllowUntrustedChain) {
        if (-not $prereq.StagingPackage.AllFilesPresent -or
            $prereq.StagingPackage.DllSignatureStatus -eq 'NotSigned' -or
            $prereq.StagingPackage.CatSignatureStatus -eq 'NotSigned') {
            throw ("Staged package in '{0}' is missing artifacts or embedded signatures." -f $StagingDir)
        }
    }
    else {
        $null = Test-LumaBridgePackageArtifacts -PackageDirectory $StagingDir -RequireValidSignature
    }

    if (-not $SkipTestSigningCheck -and $prereq.SecurityState.TestSigning -ne 'Enabled') {
        throw ("Windows Test Signing state is '{0}'. Enable it manually in an elevated prompt with 'bcdedit /set testsigning on' and reboot, or pass -SkipTestSigningCheck for trusted CA packages." -f $prereq.SecurityState.TestSigning)
    }
}

$actionSummary = if ($existingInstances.Count -eq 1) {
    "Update existing device '{0}' using staged INF '{1}' (keeping EnableVirtualMonitor=0)" -f $existingInstances[0].InstanceId, $stagedInf
}
else {
    "Stage driver '{0}', create 1 root-enumerated '{1}' device, and keep EnableVirtualMonitor=0" -f $stagedInf, $constants.HardwareId
}

if (-not (Confirm-LumaBridgeAction -PromptMessage $actionSummary -DryRun:$DryRun -Force:$Force)) {
    if ($DryRun) {
        if ($existingInstances.Count -eq 1) {
            $null = Invoke-LumaBridgeExternalCommand -FilePath 'pnputil.exe' -Arguments @('/add-driver', $stagedInf, '/install') -DryRun
            Write-Host ("[DRY-RUN] Would enforce REG_DWORD {0}=0 at '{1}'" -f $constants.RegistryValueEnableMon, $existingInstances[0].DeviceParametersPath) -ForegroundColor Cyan
        }
        else {
            $null = Invoke-LumaBridgeExternalCommand -FilePath 'pnputil.exe' -Arguments @('/add-driver', $stagedInf) -DryRun
            $null = Invoke-LumaBridgeExternalCommand -FilePath $devconPath -Arguments @('install', $stagedInf, $constants.HardwareId) -DryRun
            Write-Host ("[DRY-RUN] Would query created '{0}' PnP instance and set REG_DWORD {1}=0 in Device Parameters" -f $constants.HardwareId, $constants.RegistryValueEnableMon) -ForegroundColor Cyan
        }
    }
    return
}

if ($existingInstances.Count -eq 1) {
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
if (-not (Test-Path -LiteralPath $instance.DeviceParametersPath)) {
    New-Item -Path $instance.DeviceParametersPath -Force | Out-Null
}
New-ItemProperty -LiteralPath $instance.DeviceParametersPath -Name $constants.RegistryValueEnableMon -PropertyType DWord -Value 0 -Force | Out-Null

$finalInstances = @(Get-LumaBridgePnpInstances)
[pscustomobject]@{
    InstalledInf         = $stagedInf
    Instance             = $finalInstances[0]
    VirtualMonitorPolicy = 'DisabledByDefault (EnableVirtualMonitor=0)'
}
