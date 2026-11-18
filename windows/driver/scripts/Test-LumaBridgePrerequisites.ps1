<#
.SYNOPSIS
    Performs non-destructive read-only diagnostics of Windows 11 host prerequisites
    required before functional testing of LumaBridgeIddDriver.
#>
[CmdletBinding()]
param(
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Release',

    [string]$StagingDir,

    [switch]$AsJson
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$commonModulePath = (Resolve-Path -LiteralPath (Join-Path -Path $PSScriptRoot -ChildPath 'LumaBridgeDriverCommon.psm1')).Path
$loadedCommon = Get-Module -Name 'LumaBridgeDriverCommon'
if ($null -eq $loadedCommon -or $loadedCommon.Path -ine $commonModulePath) {
    Import-Module $commonModulePath -Force
}

$constants = Get-LumaBridgeDriverConstants
$isAdmin = Test-LumaBridgeIsAdministrator
$is64BitOs = [Environment]::Is64BitOperatingSystem

$osRegPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$osReg = Get-ItemProperty -LiteralPath $osRegPath -ErrorAction Stop
$buildNumber = [int]$osReg.CurrentBuildNumber
$ubr = if ($null -ne $osReg.UBR) { [int]$osReg.UBR } else { 0 }
$displayVersion = if (-not [string]::IsNullOrWhiteSpace($osReg.DisplayVersion)) { $osReg.DisplayVersion } else { $osReg.ReleaseId }
$isSupportedWindows11 = ($is64BitOs -and $buildNumber -ge $constants.MinimumWindows11Build)

$securityState = Get-LumaBridgeHostSecurityState
$secureBootState = $securityState.SecureBoot
$testSigningState = $securityState.TestSigning

$wudfCandidates = @(
    (Join-Path -Path $env:SystemRoot -ChildPath 'System32\Drivers\UMDF\WUDFx02000.dll'),
    (Join-Path -Path $env:SystemRoot -ChildPath 'System32\WUDFx02000.dll')
)
$wudfPath = $wudfCandidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
$wudfVersion = if ($null -ne $wudfPath) { (Get-Item -LiteralPath $wudfPath).VersionInfo.FileVersion } else { $null }

$iddCxPath = Join-Path -Path $env:SystemRoot -ChildPath 'System32\IddCx.dll'
if (-not (Test-Path -LiteralPath $iddCxPath)) {
    $iddCxAlt = Join-Path -Path $env:SystemRoot -ChildPath 'System32\Drivers\UMDF\IddCx.dll'
    if (Test-Path -LiteralPath $iddCxAlt) {
        $iddCxPath = $iddCxAlt
    }
    else {
        $iddCxPath = $null
    }
}
$iddCxVersion = if ($null -ne $iddCxPath) { (Get-Item -LiteralPath $iddCxPath).VersionInfo.FileVersion } else { $null }

$buildPackageDir = Get-LumaBridgePackageDirectory -Configuration $Configuration
$buildArtifacts = Test-LumaBridgePackageArtifacts -PackageDirectory $buildPackageDir

$effectiveStagingDir = if (-not [string]::IsNullOrWhiteSpace($StagingDir)) {
    $StagingDir
}
else {
    Get-LumaBridgeDefaultStagingDirectory -Configuration $Configuration
}
$stagingArtifacts = if (Test-Path -LiteralPath $effectiveStagingDir) {
    Test-LumaBridgePackageArtifacts -PackageDirectory $effectiveStagingDir
}
else {
    $null
}

$signtoolPath = Get-LumaBridgeWdkToolPath -ToolName 'signtool.exe'
$devconPath = Get-LumaBridgeWdkToolPath -ToolName 'devcon.exe'
$inf2catPath = Get-LumaBridgeWdkToolPath -ToolName 'Inf2Cat.exe'

$pnpInstances = @(Get-LumaBridgePnpInstances)
$driverStoreEntries = @(Get-LumaBridgeDriverStorePackages)

$report = [pscustomobject]@{
    TimestampUtc              = (Get-Date).ToUniversalTime().ToString('o')
    Configuration             = $Configuration
    IsAdministrator           = $isAdmin
    HostOs                    = [pscustomobject]@{
        ProductName          = $osReg.ProductName
        DisplayVersion       = $displayVersion
        CurrentBuildNumber   = $buildNumber
        UBR                  = $ubr
        Is64BitOs            = $is64BitOs
        IsSupportedWindows11 = $isSupportedWindows11
    }
    SecurityState             = [pscustomobject]@{
        SecureBoot  = $secureBootState
        TestSigning = $testSigningState
    }
    RuntimeComponents         = [pscustomobject]@{
        WUDFx02000Path    = $wudfPath
        WUDFx02000Version = $wudfVersion
        IddCxPath         = $iddCxPath
        IddCxVersion      = $iddCxVersion
    }
    WdkTools                  = [pscustomobject]@{
        SignToolPath = $signtoolPath
        DevconPath   = $devconPath
        Inf2CatPath  = $inf2catPath
    }
    BuildPackage              = $buildArtifacts
    StagingPackage            = $stagingArtifacts
    PnpInstances              = $pnpInstances
    DriverStorePackages       = $driverStoreEntries
    ReadyForTestSignStaging   = ($isSupportedWindows11 -and $buildArtifacts.AllFilesPresent -and ($null -ne $signtoolPath) -and ($null -ne $inf2catPath))
    ReadyForControlledInstall = ($isSupportedWindows11 -and ($null -ne $stagingArtifacts) -and $stagingArtifacts.IsCryptographicallyValid -and ($testSigningState -eq 'Enabled') -and ($null -ne $devconPath))
}

if ($AsJson) {
    $report | ConvertTo-Json -Depth 6
    return
}

$report
