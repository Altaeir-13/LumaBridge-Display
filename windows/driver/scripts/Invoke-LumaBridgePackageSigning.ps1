<#
.SYNOPSIS
    Prepares a clean isolated staging copy of LumaBridgeIddDriver, signs the DLL and
    regenerated Windows 11 x64 catalog with a development/test certificate, and verifies
    cryptographic integrity without modifying .vcxproj signing settings or repository sources.
#>
[CmdletBinding()]
param(
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Release',

    [string]$StagingDir,

    [string]$CertificateThumbprint,

    [string]$CertificateSubject = 'CN=LumaBridge Test Driver Signing',

    [switch]$CreateTestCertificateIfMissing,

    [string]$TimestampUrl,

    [switch]$TrustCertificate,

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
$sourcePackageDir = Get-LumaBridgePackageDirectory -Configuration $Configuration
if ([string]::IsNullOrWhiteSpace($StagingDir)) {
    $StagingDir = Get-LumaBridgeDefaultStagingDirectory -Configuration $Configuration
}

$StagingDir = Assert-LumaBridgeIsolatedStagingDirectory -StagingDir $StagingDir -SourcePackageDir $sourcePackageDir

$signtoolPath = Get-LumaBridgeWdkToolPath -ToolName 'signtool.exe'
$inf2catPath = Get-LumaBridgeWdkToolPath -ToolName 'Inf2Cat.exe'

if ($null -eq $signtoolPath) {
    throw 'signtool.exe could not be located under Windows Kits\10.'
}
if ($null -eq $inf2catPath) {
    throw 'Inf2Cat.exe could not be located under Windows Kits\10.'
}

$sourceInf = Join-Path -Path $sourcePackageDir -ChildPath $constants.InfFileName
$sourceDll = Join-Path -Path $sourcePackageDir -ChildPath $constants.DllFileName
$sourceCat = Join-Path -Path $sourcePackageDir -ChildPath $constants.CatFileName
foreach ($requiredFile in @($sourceInf, $sourceDll)) {
    if (-not (Test-Path -LiteralPath $requiredFile -PathType Leaf)) {
        throw ("Required build artifact not found: {0}. Rebuild {1}|x64 first." -f $requiredFile, $Configuration)
    }
}

if ($TrustCertificate) {
    $null = Assert-LumaBridgeAdministrator -OperationName 'Trust Test Signing Certificate in LocalMachine Stores' -DryRun:$DryRun
}

$signingCert = Find-LumaBridgeSigningCertificate -CertificateThumbprint $CertificateThumbprint -CertificateSubject $CertificateSubject
if (-not [string]::IsNullOrWhiteSpace($CertificateThumbprint) -and $null -eq $signingCert -and -not $DryRun) {
    throw ("Code signing certificate with thumbprint '{0}' was not found in Cert:\CurrentUser\My." -f $CertificateThumbprint)
}

if ($null -eq $signingCert -and -not $CreateTestCertificateIfMissing -and -not $DryRun) {
    throw ("No active code signing certificate matching '{0}' found in Cert:\CurrentUser\My. Pass -CertificateThumbprint or -CreateTestCertificateIfMissing." -f $CertificateSubject)
}

$stagedInf = Join-Path -Path $StagingDir -ChildPath $constants.InfFileName
$stagedDll = Join-Path -Path $StagingDir -ChildPath $constants.DllFileName
$stagedCat = Join-Path -Path $StagingDir -ChildPath $constants.CatFileName
$cerExportPath = Join-Path -Path $StagingDir -ChildPath 'LumaBridgeTest.cer'

$planMessage = "Clean and stage package to isolated '{0}', sign '{1}', regenerate/sign '{2}', and verify catalog membership for DLL + INF" -f `
    $StagingDir, $constants.DllFileName, $constants.CatFileName
if (-not (Confirm-LumaBridgeAction -PromptMessage $planMessage -DryRun:$DryRun -Force:$Force)) {
    if ($DryRun) {
        $thumbPreview = if ($null -ne $signingCert) { $signingCert.Thumbprint } else { '<to-be-created-self-signed>' }
        Write-Host ("[DRY-RUN] Source package: {0}" -f $sourcePackageDir) -ForegroundColor Cyan
        Write-Host ("[DRY-RUN] Isolated staging target (cleaned before copy): {0}" -f $StagingDir) -ForegroundColor Cyan
        Write-Host ("[DRY-RUN] Certificate thumbprint: {0} (Subject='{1}')" -f $thumbPreview, $CertificateSubject) -ForegroundColor Cyan
        $null = Invoke-LumaBridgeExternalCommand -FilePath $signtoolPath -Arguments @('sign', '/fd', 'SHA256', '/sha1', $thumbPreview, $stagedDll) -DryRun
        $null = Invoke-LumaBridgeExternalCommand -FilePath $inf2catPath -Arguments @(("/driver:{0}" -f $StagingDir), ("/os:{0}" -f $constants.SupportedInf2CatOsList), '/uselocaltime') -DryRun
        $null = Invoke-LumaBridgeExternalCommand -FilePath $signtoolPath -Arguments @('sign', '/fd', 'SHA256', '/sha1', $thumbPreview, $stagedCat) -DryRun
        $null = Invoke-LumaBridgeExternalCommand -FilePath $signtoolPath -Arguments @('verify', '/pa', '/c', $stagedCat, $stagedDll) -DryRun
        $null = Invoke-LumaBridgeExternalCommand -FilePath $signtoolPath -Arguments @('verify', '/pa', '/c', $stagedCat, $stagedInf) -DryRun
        if ($TrustCertificate) {
            $null = Invoke-LumaBridgeExternalCommand -FilePath 'certutil.exe' -Arguments @('-addstore', 'Root', $cerExportPath) -DryRun
            $null = Invoke-LumaBridgeExternalCommand -FilePath 'certutil.exe' -Arguments @('-addstore', 'TrustedPublisher', $cerExportPath) -DryRun
        }
    }
    return
}

$sourceHashesBefore = @{
    Inf = (Get-FileHash -LiteralPath $sourceInf -Algorithm SHA256).Hash
    Dll = (Get-FileHash -LiteralPath $sourceDll -Algorithm SHA256).Hash
    Cat = if (Test-Path -LiteralPath $sourceCat -PathType Leaf) { (Get-FileHash -LiteralPath $sourceCat -Algorithm SHA256).Hash } else { $null }
}

if (Test-Path -LiteralPath $StagingDir) {
    Get-ChildItem -LiteralPath $StagingDir -Force | Remove-Item -Recurse -Force
}
else {
    New-Item -Path $StagingDir -ItemType Directory -Force | Out-Null
}

Copy-Item -LiteralPath $sourceInf -Destination $stagedInf -Force
Copy-Item -LiteralPath $sourceDll -Destination $stagedDll -Force

if ($null -eq $signingCert) {
    $signingCert = New-LumaBridgeSigningCertificate -CertificateSubject $CertificateSubject -ValidMonths 6
}

$signDllArgs = @('sign', '/fd', 'SHA256', '/sha1', $signingCert.Thumbprint)
if (-not [string]::IsNullOrWhiteSpace($TimestampUrl)) {
    $signDllArgs += @('/tr', $TimestampUrl, '/td', 'SHA256')
}
$signDllArgs += $stagedDll
$null = Invoke-LumaBridgeExternalCommand -FilePath $signtoolPath -Arguments $signDllArgs

$null = Invoke-LumaBridgeExternalCommand -FilePath $inf2catPath -Arguments @(
    ("/driver:{0}" -f $StagingDir),
    ("/os:{0}" -f $constants.SupportedInf2CatOsList),
    '/uselocaltime'
)

if (-not (Test-Path -LiteralPath $stagedCat -PathType Leaf)) {
    throw ("Catalog generation did not produce expected file: {0}" -f $stagedCat)
}

$signCatArgs = @('sign', '/fd', 'SHA256', '/sha1', $signingCert.Thumbprint)
if (-not [string]::IsNullOrWhiteSpace($TimestampUrl)) {
    $signCatArgs += @('/tr', $TimestampUrl, '/td', 'SHA256')
}
$signCatArgs += $stagedCat
$null = Invoke-LumaBridgeExternalCommand -FilePath $signtoolPath -Arguments $signCatArgs

# Export public certificate only after Inf2Cat finishes so the directory hashed by Inf2Cat stays clean.
Export-LumaBridgeCertificateFile -Certificate $signingCert -FilePath $cerExportPath

if ($TrustCertificate) {
    $null = Invoke-LumaBridgeExternalCommand -FilePath 'certutil.exe' -Arguments @('-addstore', 'Root', $cerExportPath)
    $null = Invoke-LumaBridgeExternalCommand -FilePath 'certutil.exe' -Arguments @('-addstore', 'TrustedPublisher', $cerExportPath)
}

$verification = Test-LumaBridgePackageArtifacts `
    -PackageDirectory $StagingDir `
    -ExpectedSignerThumbprint $signingCert.Thumbprint `
    -RequireValidSignature `
    -AllowUntrustedChain:(-not $TrustCertificate)

$sourceHashesAfter = @{
    Inf = (Get-FileHash -LiteralPath $sourceInf -Algorithm SHA256).Hash
    Dll = (Get-FileHash -LiteralPath $sourceDll -Algorithm SHA256).Hash
    Cat = if (Test-Path -LiteralPath $sourceCat -PathType Leaf) { (Get-FileHash -LiteralPath $sourceCat -Algorithm SHA256).Hash } else { $null }
}

if ($sourceHashesBefore.Inf -ne $sourceHashesAfter.Inf -or
    $sourceHashesBefore.Dll -ne $sourceHashesAfter.Dll -or
    $sourceHashesBefore.Cat -ne $sourceHashesAfter.Cat) {
    throw ("Source build artifacts in '{0}' were unexpectedly modified during staging." -f $sourcePackageDir)
}

[pscustomobject]@{
    StagingDir               = $StagingDir
    CertificatePath          = $cerExportPath
    CertificateThumbprint    = $signingCert.Thumbprint
    CertificateTrusted       = $TrustCertificate.IsPresent
    SourceArtifactsPreserved = $true
    Verification             = $verification
}
