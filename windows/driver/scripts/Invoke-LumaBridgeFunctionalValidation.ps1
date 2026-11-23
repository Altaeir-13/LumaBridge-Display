<#
.SYNOPSIS
    Executes the end-to-end Windows 11 functional validation workflow for LumaBridgeIddDriver
    (M4.1 real D3D11 frame extraction + hardened Named Pipe IPC + lumabridge-host.exe)
    with non-destructive pre-checks, cryptographic/hash verification, ETW provider checks,
    authorized installation, time-bounded host execution, diagnostics collection, and
    guaranteed automatic rollback in a finally block.
#>
[CmdletBinding()]
param(
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Release',

    [string]$StagingDir,

    [string]$OutputDir,

    [string]$HostExecutablePath,

    [string]$CertificateThumbprint,

    [string]$CertificateSubject = 'CN=LumaBridge Test Driver Signing',

    [switch]$CreateTestCertificateIfMissing,

    [switch]$TrustCertificate,

    [switch]$AllowUntrustedChain,

    [switch]$SkipTestSigningCheck,

    [string]$AuthorizedHostUserSid,

    [ValidateRange(1, 10000)]
    [int]$MaxFrames = 30,

    [ValidateRange(500, 120000)]
    [int]$HostDurationMs = 15000,

    [ValidateRange(500, 30000)]
    [int]$ConnectTimeoutMs = 5000,

    [ValidateRange(50, 5000)]
    [int]$IoTimeoutMs = 500,

    [ValidateRange(1000, 300000)]
    [int]$HostHardTimeoutMs = 30000,

    [string]$ExpectedBranch = 'feature/windows-frame-extraction-ipc',

    [switch]$AllowAnyBranch,

    [switch]$SkipDriverInstall,

    [switch]$IncludeDxgKrnl,

    [switch]$FullUninstallOnExit,

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

function Get-LumaBridgeValidationOptionalProp {
    param(
        $InputObject,
        [Parameter(Mandatory = $true)]
        [string]$PropertyName,
        $DefaultValue = $null
    )

    if ($null -eq $InputObject) {
        return $DefaultValue
    }
    if ($InputObject -is [System.Collections.IDictionary]) {
        if ($InputObject.Contains($PropertyName)) {
            return $InputObject[$PropertyName]
        }
        return $DefaultValue
    }
    if ($InputObject.PSObject.Properties.Name -contains $PropertyName) {
        return $InputObject.$PropertyName
    }
    return $DefaultValue
}

$constants = Get-LumaBridgeDriverConstants
$repoRoot = Get-LumaBridgeRepoRoot
$sourcePackageDir = Get-LumaBridgePackageDirectory -Configuration $Configuration

if ([string]::IsNullOrWhiteSpace($StagingDir)) {
    $StagingDir = Get-LumaBridgeDefaultStagingDirectory -Configuration $Configuration
}
$StagingDir = Assert-LumaBridgeIsolatedStagingDirectory -StagingDir $StagingDir -SourcePackageDir $sourcePackageDir

if ([string]::IsNullOrWhiteSpace($OutputDir)) {
    $localAppData = if (-not [string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) {
        $env:LOCALAPPDATA
    }
    else {
        [Environment]::GetFolderPath('LocalApplicationData')
    }
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $OutputDir = Join-Path -Path $localAppData -ChildPath ("LumaBridgeDisplay\Validation\{0}" -f $stamp)
}

if ([string]::IsNullOrWhiteSpace($HostExecutablePath)) {
    $HostExecutablePath = Join-Path -Path $repoRoot -ChildPath ("windows\driver\x64\{0}\lumabridge-host.exe" -f $Configuration)
}

$effectiveAuthorizedUserSid = if (-not [string]::IsNullOrWhiteSpace($AuthorizedHostUserSid)) {
    $AuthorizedHostUserSid.Trim()
}
else {
    [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
}
if ($effectiveAuthorizedUserSid -notmatch '^S-1-[0-9-]+$') {
    throw ("Invalid AuthorizedHostUserSid '{0}'." -f $effectiveAuthorizedUserSid)
}

$effectiveAllowUntrusted = ($AllowUntrustedChain -or (-not $TrustCertificate))
$prereqScript = Join-Path -Path $PSScriptRoot -ChildPath 'Test-LumaBridgePrerequisites.ps1'
$signingScript = Join-Path -Path $PSScriptRoot -ChildPath 'Invoke-LumaBridgePackageSigning.ps1'
$etwScript = Join-Path -Path $PSScriptRoot -ChildPath 'Invoke-LumaBridgeEtwTrace.ps1'
$installScript = Join-Path -Path $PSScriptRoot -ChildPath 'Install-LumaBridgeDriver.ps1'
$virtMonScript = Join-Path -Path $PSScriptRoot -ChildPath 'Set-LumaBridgeVirtualMonitor.ps1'
$diagScript = Join-Path -Path $PSScriptRoot -ChildPath 'Collect-LumaBridgeDiagnostics.ps1'
$uninstallScript = Join-Path -Path $PSScriptRoot -ChildPath 'Uninstall-LumaBridgeDriver.ps1'

$etwDir = Join-Path -Path $OutputDir -ChildPath 'etw'
$diagDir = Join-Path -Path $OutputDir -ChildPath 'diagnostics'
$installFailDiagDir = Join-Path -Path $OutputDir -ChildPath 'install-failure-diag'
$hostJsonPath = Join-Path -Path $OutputDir -ChildPath 'lumabridge-host-summary.json'
$reportJsonPath = Join-Path -Path $OutputDir -ChildPath 'functional-validation-report.json'
$reportMdPath = Join-Path -Path $OutputDir -ChildPath 'functional-validation-report.md'

# -------------------------------------------------------------------------
# Stage 1: Pre-checks non-destrutivas
# -------------------------------------------------------------------------
$null = Assert-LumaBridgeAdministrator -OperationName 'Run LumaBridge M4.1 Functional Validation' -DryRun:$DryRun
$prereq = & $prereqScript -Configuration $Configuration -StagingDir $StagingDir

if (-not $prereq.HostOs.IsSupportedWindows11) {
    throw ("Unsupported Windows build {0}; Windows 11 x64 >= {1} is required." -f $prereq.HostOs.CurrentBuildNumber, $constants.MinimumWindows11Build)
}
if (-not $prereq.BuildPackage.AllFilesPresent) {
    throw ("Missing built package files in '{0}'. Rebuild {1}|x64 first." -f $sourcePackageDir, $Configuration)
}
if (-not $DryRun) {
    if ([string]::IsNullOrWhiteSpace($prereq.WdkTools.SignToolPath) -or
        [string]::IsNullOrWhiteSpace($prereq.WdkTools.Inf2CatPath) -or
        [string]::IsNullOrWhiteSpace($prereq.WdkTools.DevconPath)) {
        throw 'Required WDK tools (signtool.exe, Inf2Cat.exe, devcon.exe) were not all found.'
    }
}

$initialInstances = @($prereq.PnpInstances)
if ($initialInstances.Count -gt 1) {
    $ids = ($initialInstances | ForEach-Object { $_.InstanceId }) -join ', '
    throw ("Multiple '{0}' PnP instances exist ({1}); clean up duplicates before validation." -f $constants.HardwareId, $ids)
}

$preExistingInstance = if ($initialInstances.Count -eq 1) { $initialInstances[0] } else { $null }
$initialWudfProcs = @(Get-LumaBridgeWudfHostProcesses -PnpInstances $initialInstances)
$initialDumpInventory = Get-LumaBridgeCrashDumpInventory -LookbackMinutes 60
$initialDumpCount = [int](Get-LumaBridgeValidationOptionalProp -InputObject $initialDumpInventory -PropertyName 'TotalFoundCount' -DefaultValue 0)

# -------------------------------------------------------------------------
# Stage 2: Branch & build artifact validation
# -------------------------------------------------------------------------
$gitBranchResult = Invoke-LumaBridgeExternalCommand -FilePath 'git.exe' -Arguments @('-C', $repoRoot, 'rev-parse', '--abbrev-ref', 'HEAD')
$currentBranch = if (@($gitBranchResult.Output).Count -gt 0) { ([string]$gitBranchResult.Output[0]).Trim() } else { '' }
if (-not $AllowAnyBranch -and $currentBranch -ne $ExpectedBranch) {
    throw ("Active Git branch is '{0}', expected '{1}'. Switch branch or pass -AllowAnyBranch." -f $currentBranch, $ExpectedBranch)
}

$sourceInf = Join-Path -Path $sourcePackageDir -ChildPath $constants.InfFileName
$sourceDll = Join-Path -Path $sourcePackageDir -ChildPath $constants.DllFileName
$sourceCat = Join-Path -Path $sourcePackageDir -ChildPath $constants.CatFileName
foreach ($reqFile in @($sourceInf, $sourceDll, $HostExecutablePath)) {
    if (-not (Test-Path -LiteralPath $reqFile -PathType Leaf)) {
        throw ("Required functional validation artifact not found: {0}" -f $reqFile)
    }
}

$preBuildHashes = [ordered]@{
    InfSha256  = (Get-FileHash -LiteralPath $sourceInf -Algorithm SHA256).Hash
    DllSha256  = (Get-FileHash -LiteralPath $sourceDll -Algorithm SHA256).Hash
    CatSha256  = if (Test-Path -LiteralPath $sourceCat -PathType Leaf) { (Get-FileHash -LiteralPath $sourceCat -Algorithm SHA256).Hash } else { $null }
    HostSha256 = (Get-FileHash -LiteralPath $HostExecutablePath -Algorithm SHA256).Hash
}

if ($DryRun) {
    $signingDry = & $signingScript `
        -Configuration $Configuration `
        -StagingDir $StagingDir `
        -CertificateThumbprint $CertificateThumbprint `
        -CertificateSubject $CertificateSubject `
        -CreateTestCertificateIfMissing:$CreateTestCertificateIfMissing `
        -TrustCertificate:$TrustCertificate `
        -DryRun

    $etwStartDry = & $etwScript -Action Start -OutputDir $etwDir -IncludeDxgKrnl:$IncludeDxgKrnl -DryRun
    if (-not $SkipDriverInstall) {
        $null = & $installScript -Configuration $Configuration -StagingDir $StagingDir -AllowUntrustedChain:$effectiveAllowUntrusted -SkipTestSigningCheck:$SkipTestSigningCheck -DryRun
    }
    $dryInstId = if ($null -ne $preExistingInstance) { $preExistingInstance.InstanceId } else { 'ROOT\DISPLAY\<instance>' }
    $null = & $virtMonScript -Action Enable -InstanceId $dryInstId -DryRun
    Write-Host ("[DRY-RUN] Stage 8: Would set REG_SZ AuthorizedHostUserSid='{0}' and REG_DWORD EnableFrameExtraction=1 on '{1}' then restart PnP device" -f $effectiveAuthorizedUserSid, $dryInstId) -ForegroundColor Cyan
    $hostArgsDry = @(
        '--pipe', '\\.\pipe\LumaBridgeFrameIpc_v1',
        '--max-frames', "$MaxFrames",
        '--duration-ms', "$HostDurationMs",
        '--connect-timeout-ms', "$ConnectTimeoutMs",
        '--io-timeout-ms', "$IoTimeoutMs",
        '--reconnect',
        '--json-summary', $hostJsonPath
    )
    $hostDry = Invoke-LumaBridgeHostProcess -ExecutablePath $HostExecutablePath -Arguments $hostArgsDry -HardTimeoutMs $HostHardTimeoutMs -DryRun
    $etwStopDry = & $etwScript -Action Stop -OutputDir $etwDir -IncludeDxgKrnl:$IncludeDxgKrnl -DryRun
    $diagDry = & $diagScript -Configuration $Configuration -StagingDir $StagingDir -OutputDir $diagDir -DryRun
    Write-Host ("[DRY-RUN] Stage 11 (finally rollback): Would stop active ETW, revert EnableFrameExtraction=0, clear AuthorizedHostUserSid, restore EnableVirtualMonitor, restart device{0}, and write report '{1}'" -f $(if ($FullUninstallOnExit) { ' and run Uninstall-LumaBridgeDriver.ps1' } else { '' }), $reportJsonPath) -ForegroundColor Cyan

    return [pscustomobject]@{
        DryRun                = $true
        Configuration         = $Configuration
        Branch                = $currentBranch
        PlannedStagingDir     = $StagingDir
        PlannedOutputDir      = $OutputDir
        HostExecutablePath    = $HostExecutablePath
        AuthorizedHostUserSid = $effectiveAuthorizedUserSid
        PreBuildHashes        = $preBuildHashes
        SigningPreview        = $signingDry
        EtwStartPreview       = $etwStartDry
        HostPreview           = $hostDry
        EtwStopPreview        = $etwStopDry
        DiagnosticsPreview    = $diagDry
        PlannedReportJsonPath = $reportJsonPath
        PlannedReportMdPath   = $reportMdPath
    }
}

# Explicit operator authorization check prior to Stage 3/5/6 system or store mutations.
$authPrompt = "Execute controlled Windows M4.1 functional validation (Staging='{0}', Install={1}, EnableVirtualMonitor=1, EnableFrameExtraction=1, HostMaxFrames={2}, DurationMs={3}, AutoRollback=finally)" -f `
    $StagingDir, (-not $SkipDriverInstall), $MaxFrames, $HostDurationMs
if (-not (Confirm-LumaBridgeAction -PromptMessage $authPrompt -Force:$Force)) {
    throw 'Functional validation cancelled because explicit authorization was not granted.'
}

# -------------------------------------------------------------------------
# Stage 3 & Stage 4: Prepare isolated signed staging ($signResult.StagingDir) & verify
# -------------------------------------------------------------------------
$signResult = & $signingScript `
    -Configuration $Configuration `
    -StagingDir $StagingDir `
    -CertificateThumbprint $CertificateThumbprint `
    -CertificateSubject $CertificateSubject `
    -CreateTestCertificateIfMissing:$CreateTestCertificateIfMissing `
    -TrustCertificate:$TrustCertificate `
    -Force

if ($null -eq $signResult -or [string]::IsNullOrWhiteSpace($signResult.StagingDir)) {
    throw 'Invoke-LumaBridgePackageSigning.ps1 did not return StagingDir.'
}
$signedStagingDir = $signResult.StagingDir
$signedThumbprint = $signResult.CertificateThumbprint
$didTrustCert = [bool]$signResult.CertificateTrusted

$packageVerify = Test-LumaBridgePackageArtifacts `
    -PackageDirectory $signedStagingDir `
    -ExpectedSignerThumbprint $signedThumbprint `
    -RequireValidSignature `
    -AllowUntrustedChain:$effectiveAllowUntrusted

$postSignBuildHashes = [ordered]@{
    InfSha256  = (Get-FileHash -LiteralPath $sourceInf -Algorithm SHA256).Hash
    DllSha256  = (Get-FileHash -LiteralPath $sourceDll -Algorithm SHA256).Hash
    CatSha256  = if (Test-Path -LiteralPath $sourceCat -PathType Leaf) { (Get-FileHash -LiteralPath $sourceCat -Algorithm SHA256).Hash } else { $null }
    HostSha256 = (Get-FileHash -LiteralPath $HostExecutablePath -Algorithm SHA256).Hash
}
if ($preBuildHashes.InfSha256 -ne $postSignBuildHashes.InfSha256 -or
    $preBuildHashes.DllSha256 -ne $postSignBuildHashes.DllSha256 -or
    $preBuildHashes.HostSha256 -ne $postSignBuildHashes.HostSha256) {
    throw 'Repository build artifacts were modified unexpectedly during signed staging.'
}

if (-not (Test-Path -LiteralPath $OutputDir)) {
    New-Item -Path $OutputDir -ItemType Directory -Force | Out-Null
}

# Tracking variables for deterministic finally rollback
$etwStarted = $false
$etwStopped = $false
$targetInstance = $preExistingInstance
$didFreshDriverInstall = $false
$driverInstallCompleted = $false
$hadPreExistingVirtMon = ($null -ne $preExistingInstance -and $null -ne $preExistingInstance.EnableVirtualMonitor -and [int]$preExistingInstance.EnableVirtualMonitor -eq 1)
$hadPreExistingAuthSid = if ($null -ne $preExistingInstance) { Get-LumaBridgeValidationOptionalProp -InputObject $preExistingInstance -PropertyName 'AuthorizedHostUserSid' -DefaultValue $null } else { $null }
$modifiedVirtMon = $false
$modifiedExtraction = $false
$modifiedAuthSid = $false

$etwStartResult = $null
$etwVerifyResult = $null
$etwStopResult = $null
$installResult = $null
$virtMonEnableResult = $null
$hostProcResult = $null
$hostSummary = $null
$diagResult = $null
$postRunWudfProcs = @()
$postRunDumpInventory = $null
$acceptanceCriteria = $null
$validationError = $null
$rollbackActions = New-Object System.Collections.Generic.List[string]
$rollbackClean = $false
$postRollbackInstances = @()

try {
    # ---------------------------------------------------------------------
    # Stage 5: Controlled ETW capture + VerifyProviders
    # ---------------------------------------------------------------------
    $etwStartResult = & $etwScript -Action Start -OutputDir $etwDir -IncludeDxgKrnl:$IncludeDxgKrnl -Force
    $etwStarted = $true

    $etwVerifyResult = & $etwScript -Action VerifyProviders -OutputDir $etwDir
    if (-not [bool](Get-LumaBridgeValidationOptionalProp -InputObject $etwVerifyResult -PropertyName 'AllProvidersVerified' -DefaultValue $false)) {
        $missingGuids = @($etwVerifyResult.MissingProviderGuids) -join ', '
        throw ("ETW VerifyProviders failed; missing provider GUID(s): {0}" -f $missingGuids)
    }

    # ---------------------------------------------------------------------
    # Stage 6: Authorized driver installation / binding confirmation
    # ---------------------------------------------------------------------
    if (-not $SkipDriverInstall) {
        if ($null -eq $preExistingInstance) {
            $didFreshDriverInstall = $true
        }
        $installResult = & $installScript `
            -Configuration $Configuration `
            -StagingDir $signedStagingDir `
            -AllowUntrustedChain:$effectiveAllowUntrusted `
            -SkipTestSigningCheck:$SkipTestSigningCheck `
            -DiagnosticsOutputDir $installFailDiagDir `
            -Force
        $driverInstallCompleted = $true
    }

    $currentInstances = @(Get-LumaBridgePnpInstances)
    if ($currentInstances.Count -ne 1) {
        throw ("Expected exactly 1 '{0}' PnP instance in Stage 6, found {1}." -f $constants.HardwareId, $currentInstances.Count)
    }
    $targetInstance = $currentInstances[0]
    if ($targetInstance.Status -ine 'OK' -or ($null -ne $targetInstance.ProblemCode -and [int]$targetInstance.ProblemCode -ne 0)) {
        throw ("Adapter '{0}' unhealthy after Stage 6 (Status='{1}', ProblemCode={2}, ProblemStatus={3})." -f $targetInstance.InstanceId, $targetInstance.Status, $targetInstance.ProblemCode, $targetInstance.ProblemStatusHex)
    }

    # ---------------------------------------------------------------------
    # Stage 7: Virtual monitor activation
    # ---------------------------------------------------------------------
    $virtMonEnableResult = & $virtMonScript -Action Enable -InstanceId $targetInstance.InstanceId -Force
    $modifiedVirtMon = $true

    $postMonInstances = @(Get-LumaBridgePnpInstances | Where-Object { $_.InstanceId -ieq $targetInstance.InstanceId })
    if ($postMonInstances.Count -ne 1) {
        throw ("PnP instance '{0}' missing after enabling virtual monitor." -f $targetInstance.InstanceId)
    }
    $targetInstance = $postMonInstances[0]
    if ($targetInstance.Status -ine 'OK' -or
        ($null -ne $targetInstance.ProblemCode -and [int]$targetInstance.ProblemCode -ne 0) -or
        [int]$targetInstance.EnableVirtualMonitor -ne 1) {
        throw ("Virtual monitor activation check failed on '{0}' (Status='{1}', ProblemCode={2}, EnableVirtualMonitor={3})." -f $targetInstance.InstanceId, $targetInstance.Status, $targetInstance.ProblemCode, $targetInstance.EnableVirtualMonitor)
    }

    # ---------------------------------------------------------------------
    # Stage 8: Temporary EnableFrameExtraction=1 & brokered AuthorizedHostUserSid
    # ---------------------------------------------------------------------
    Set-LumaBridgeDeviceAuthorizedHostUserSid -DeviceParametersPath $targetInstance.DeviceParametersPath -SidString $effectiveAuthorizedUserSid
    $modifiedAuthSid = $true
    Set-LumaBridgeDeviceEnableFrameExtraction -DeviceParametersPath $targetInstance.DeviceParametersPath -Value 1
    $modifiedExtraction = $true

    $null = Invoke-LumaBridgeExternalCommand -FilePath 'pnputil.exe' -Arguments @('/restart-device', $targetInstance.InstanceId)

    $postExtInstances = @(Get-LumaBridgePnpInstances | Where-Object { $_.InstanceId -ieq $targetInstance.InstanceId })
    if ($postExtInstances.Count -ne 1) {
        throw ("PnP instance '{0}' missing after enabling EnableFrameExtraction=1." -f $targetInstance.InstanceId)
    }
    $targetInstance = $postExtInstances[0]
    if ($targetInstance.Status -ine 'OK' -or
        ($null -ne $targetInstance.ProblemCode -and [int]$targetInstance.ProblemCode -ne 0)) {
        throw ("Adapter '{0}' unhealthy after EnableFrameExtraction=1 restart (Status='{1}', ProblemCode={2})." -f $targetInstance.InstanceId, $targetInstance.Status, $targetInstance.ProblemCode)
    }

    # ---------------------------------------------------------------------
    # Stage 9: Time-bounded lumabridge-host.exe execution
    # ---------------------------------------------------------------------
    $effectiveHardTimeoutMs = [Math]::Max($HostHardTimeoutMs, ($HostDurationMs + $ConnectTimeoutMs + 5000))
    $hostArgs = @(
        '--pipe', '\\.\pipe\LumaBridgeFrameIpc_v1',
        '--max-frames', "$MaxFrames",
        '--duration-ms', "$HostDurationMs",
        '--connect-timeout-ms', "$ConnectTimeoutMs",
        '--io-timeout-ms', "$IoTimeoutMs",
        '--reconnect',
        '--json-summary', $hostJsonPath
    )
    $hostProcResult = Invoke-LumaBridgeHostProcess -ExecutablePath $HostExecutablePath -Arguments $hostArgs -HardTimeoutMs $effectiveHardTimeoutMs

    if (Test-Path -LiteralPath $hostJsonPath -PathType Leaf) {
        $hostSummary = Get-Content -LiteralPath $hostJsonPath -Raw | ConvertFrom-Json
    }

    # ---------------------------------------------------------------------
    # Stage 10: Metrics & log collection (ETW Stop + Diagnostics + Acceptance check)
    # ---------------------------------------------------------------------
    $etwStopResult = & $etwScript -Action Stop -OutputDir $etwDir -IncludeDxgKrnl:$IncludeDxgKrnl -Force
    $etwStopped = $true

    $capturedEtlPath = Get-LumaBridgeValidationOptionalProp -InputObject $etwStopResult -PropertyName 'EtlPath' -DefaultValue $null
    $diagParams = @{
        Configuration = $Configuration
        StagingDir    = $signedStagingDir
        OutputDir     = $diagDir
    }
    if (-not [string]::IsNullOrWhiteSpace($capturedEtlPath)) {
        $diagParams['EtlPath'] = $capturedEtlPath
    }
    $diagResult = & $diagScript @diagParams

    $postRunInstances = @(Get-LumaBridgePnpInstances | Where-Object { $_.InstanceId -ieq $targetInstance.InstanceId })
    if ($postRunInstances.Count -eq 1) {
        $targetInstance = $postRunInstances[0]
    }
    $postRunWudfProcs = @(Get-LumaBridgeWudfHostProcesses -PnpInstances $postRunInstances)
    $postRunDumpInventory = Get-LumaBridgeCrashDumpInventory -LookbackMinutes 60
    $postDumpCount = [int](Get-LumaBridgeValidationOptionalProp -InputObject $postRunDumpInventory -PropertyName 'TotalFoundCount' -DefaultValue 0)

    # Evaluate acceptance criteria strictly from collected evidence
    $cmProbNone = ($null -ne $targetInstance -and $targetInstance.Status -ieq 'OK' -and [int]$targetInstance.ProblemCode -eq 0)

    $stageSummary = if ($null -ne $diagResult -and $null -ne $diagResult.Summary) {
        Get-LumaBridgeValidationOptionalProp -InputObject $diagResult.Summary -PropertyName 'StageExecutionSummary' -DefaultValue $null
    }
    else { $null }
    $startupDiag = if ($null -ne $targetInstance) {
        Get-LumaBridgeValidationOptionalProp -InputObject $targetInstance -PropertyName 'StartupDiagnostics' -DefaultValue $null
    }
    else { $null }

    $adapterInitFinishedOk = $false
    if ($null -ne $startupDiag -and
        ([string]$startupDiag.LastSuccessfulStage -eq 'AdapterInitFinished' -or [string]$startupDiag.LastStage -eq 'AdapterInitFinished') -and
        ([string]$startupDiag.LastStatusHex -eq '0x00000000' -or [string]$startupDiag.LastErrorStatusHex -eq '0x00000000')) {
        $adapterInitFinishedOk = $true
    }
    elseif ($null -ne $stageSummary -and $stageSummary.StageRecords) {
        $initHits = @($stageSummary.StageRecords | Where-Object { $_.Stage -eq 'AdapterInitFinished' -and $_.StatusHex -eq '0x00000000' })
        if ($initHits.Count -gt 0) {
            $adapterInitFinishedOk = $true
        }
    }

    $virtualMonitorActive = ($null -ne $targetInstance -and [int]$targetInstance.EnableVirtualMonitor -eq 1)

    $framesReceived = if ($null -ne $hostSummary) { [uint64](Get-LumaBridgeValidationOptionalProp -InputObject $hostSummary -PropertyName 'FramesReceived' -DefaultValue 0) } else { [uint64]0 }
    $checksumMismatches = if ($null -ne $hostSummary) { [uint64](Get-LumaBridgeValidationOptionalProp -InputObject $hostSummary -PropertyName 'ChecksumMismatches' -DefaultValue 1) } else { [uint64]1 }
    $protocolErrors = if ($null -ne $hostSummary) { [uint64](Get-LumaBridgeValidationOptionalProp -InputObject $hostSummary -PropertyName 'ProtocolErrors' -DefaultValue 1) } else { [uint64]1 }
    $lastFrameSeq = if ($null -ne $hostSummary) { [uint64](Get-LumaBridgeValidationOptionalProp -InputObject $hostSummary -PropertyName 'LastFrameSequence' -DefaultValue 0) } else { [uint64]0 }
    $lastProtocolStatus = if ($null -ne $hostSummary) { [string](Get-LumaBridgeValidationOptionalProp -InputObject $hostSummary -PropertyName 'LastProtocolStatus' -DefaultValue 'Unknown') } else { 'Missing' }
    $avgLatUs = if ($null -ne $hostSummary) { [uint64](Get-LumaBridgeValidationOptionalProp -InputObject $hostSummary -PropertyName 'AvgEndToEndLatencyUs' -DefaultValue 0) } else { [uint64]0 }

    $hostSucceeded = ($null -ne $hostProcResult -and (-not $hostProcResult.TimedOut) -and ($hostProcResult.ExitCode -eq 0))
    $hostReceivedFrames = ($hostSucceeded -and ($framesReceived -gt 0))
    $crc32Valid = ($null -ne $hostSummary -and $framesReceived -gt 0 -and $checksumMismatches -eq 0)
    $sequenceAndTimestampsOk = ($null -ne $hostSummary -and $lastFrameSeq -ge 1 -and $protocolErrors -eq 0 -and $avgLatUs -ge 0)
    $noUnauthorizedIpcClients = ($lastProtocolStatus -ne 'UnauthorizedClient')
    $noNewCrashDumps = ($postDumpCount -le $initialDumpCount)
    $wudfProcessHealthy = ($postRunWudfProcs.Count -ge 1 -or $null -eq $preExistingInstance)

    $acceptanceCriteria = [pscustomobject]@{
        CmProbNone                      = $cmProbNone
        AdapterInitFinishedOk           = $adapterInitFinishedOk
        VirtualMonitorActive            = $virtualMonitorActive
        HostProcessSucceeded            = $hostSucceeded
        HostReceivedFrames              = $hostReceivedFrames
        Crc32Valid                      = $crc32Valid
        SequenceAndTimestampsConsistent = $sequenceAndTimestampsOk
        NoUnauthorizedIpcClients        = $noUnauthorizedIpcClients
        NoNewCrashDumps                 = $noNewCrashDumps
        WudfProcessHealthy              = $wudfProcessHealthy
        AllPassed                       = (
            $cmProbNone -and
            $adapterInitFinishedOk -and
            $virtualMonitorActive -and
            $hostReceivedFrames -and
            $crc32Valid -and
            $sequenceAndTimestampsOk -and
            $noUnauthorizedIpcClients -and
            $noNewCrashDumps -and
            $wudfProcessHealthy
        )
    }

    if (-not $acceptanceCriteria.AllPassed) {
        $failedFlags = @($acceptanceCriteria.PSObject.Properties | Where-Object { $_.Name -ne 'AllPassed' -and -not [bool]$_.Value } | ForEach-Object { $_.Name }) -join ', '
        throw ("Functional validation acceptance criteria not satisfied: {0}" -f $failedFlags)
    }
}
catch {
    $validationError = $_.Exception.Message
}
finally {
    # ---------------------------------------------------------------------
    # Stage 11: Guaranteed Rollback (runs even after partial/host failure)
    # ---------------------------------------------------------------------
    if ($etwStarted -and -not $etwStopped) {
        try {
            $null = & $etwScript -Action Stop -OutputDir $etwDir -IncludeDxgKrnl:$IncludeDxgKrnl -Force
            $etwStopped = $true
            $rollbackActions.Add('Stopped active ETW trace session during finally rollback')
        }
        catch {
            $rollbackActions.Add(("Failed stopping ETW session in finally: {0}" -f $_.Exception.Message))
        }
    }

    if ($null -ne $targetInstance) {
        if ($modifiedExtraction) {
            try {
                Set-LumaBridgeDeviceEnableFrameExtraction -DeviceParametersPath $targetInstance.DeviceParametersPath -Value 0
                $rollbackActions.Add(("Reverted EnableFrameExtraction=0 on '{0}'" -f $targetInstance.InstanceId))
            }
            catch {
                $rollbackActions.Add(("Failed reverting EnableFrameExtraction=0 on '{0}': {1}" -f $targetInstance.InstanceId, $_.Exception.Message))
            }
        }

        if ($modifiedAuthSid) {
            try {
                if ([string]::IsNullOrWhiteSpace($hadPreExistingAuthSid)) {
                    Set-LumaBridgeDeviceAuthorizedHostUserSid -DeviceParametersPath $targetInstance.DeviceParametersPath -Clear
                    $rollbackActions.Add(("Cleared temporary AuthorizedHostUserSid on '{0}'" -f $targetInstance.InstanceId))
                }
                else {
                    Set-LumaBridgeDeviceAuthorizedHostUserSid -DeviceParametersPath $targetInstance.DeviceParametersPath -SidString $hadPreExistingAuthSid
                    $rollbackActions.Add(("Restored prior AuthorizedHostUserSid on '{0}'" -f $targetInstance.InstanceId))
                }
            }
            catch {
                $rollbackActions.Add(("Failed reverting AuthorizedHostUserSid on '{0}': {1}" -f $targetInstance.InstanceId, $_.Exception.Message))
            }
        }

        $shouldFullUninstall = ($FullUninstallOnExit -or ($didFreshDriverInstall -and -not $driverInstallCompleted))
        if ($shouldFullUninstall) {
            try {
                $uninstallParams = @{ Force = $true }
                if ($didTrustCert -and -not [string]::IsNullOrWhiteSpace($signedThumbprint)) {
                    $uninstallParams['RemoveTestCertificate'] = $true
                    $uninstallParams['CertificateThumbprint'] = $signedThumbprint
                    $uninstallParams['ConfirmCertificateRemoval'] = $true
                }
                $null = & $uninstallScript @uninstallParams
                $rollbackActions.Add('Executed Uninstall-LumaBridgeDriver.ps1 during finally rollback')
            }
            catch {
                $rollbackActions.Add(("Uninstall-LumaBridgeDriver.ps1 failed in finally: {0}" -f $_.Exception.Message))
            }
        }
        else {
            if ($modifiedVirtMon -and -not $hadPreExistingVirtMon) {
                try {
                    Set-LumaBridgeDeviceEnableVirtualMonitor -DeviceParametersPath $targetInstance.DeviceParametersPath -Value 0
                    $rollbackActions.Add(("Reverted EnableVirtualMonitor=0 on '{0}'" -f $targetInstance.InstanceId))
                }
                catch {
                    $rollbackActions.Add(("Failed reverting EnableVirtualMonitor=0 on '{0}': {1}" -f $targetInstance.InstanceId, $_.Exception.Message))
                }
            }

            if ($modifiedExtraction -or $modifiedAuthSid -or ($modifiedVirtMon -and -not $hadPreExistingVirtMon)) {
                try {
                    $null = Invoke-LumaBridgeExternalCommand -FilePath 'pnputil.exe' -Arguments @('/restart-device', $targetInstance.InstanceId)
                    $rollbackActions.Add(("Restarted device '{0}' to apply rolled-back parameters" -f $targetInstance.InstanceId))
                }
                catch {
                    $rollbackActions.Add(("Failed restarting device '{0}' in finally: {1}" -f $targetInstance.InstanceId, $_.Exception.Message))
                }
            }
        }
    }
    elseif ($didFreshDriverInstall -or $FullUninstallOnExit) {
        try {
            $null = & $uninstallScript -Force
            $rollbackActions.Add('Executed fallback Uninstall-LumaBridgeDriver.ps1 during finally rollback')
        }
        catch {
            $rollbackActions.Add(("Fallback Uninstall-LumaBridgeDriver.ps1 failed in finally: {0}" -f $_.Exception.Message))
        }
    }

    try {
        $postRollbackInstances = @(Get-LumaBridgePnpInstances)
        if ($FullUninstallOnExit -or ($didFreshDriverInstall -and -not $driverInstallCompleted)) {
            $rollbackClean = ($postRollbackInstances.Count -eq 0)
        }
        elseif ($postRollbackInstances.Count -eq 1) {
            $rbInst = $postRollbackInstances[0]
            $extReset = ($null -eq $rbInst.EnableFrameExtraction -or [int]$rbInst.EnableFrameExtraction -eq 0)
            $monReset = ($hadPreExistingVirtMon -or $null -eq $rbInst.EnableVirtualMonitor -or [int]$rbInst.EnableVirtualMonitor -eq 0)
            $devHealthy = ($rbInst.Status -ieq 'OK' -and ($null -eq $rbInst.ProblemCode -or [int]$rbInst.ProblemCode -eq 0))
            $rollbackClean = ($extReset -and $monReset -and $devHealthy)
        }
        else {
            $rollbackClean = ($null -eq $preExistingInstance)
        }
    }
    catch {
        $rollbackClean = $false
        $rollbackActions.Add(("Post-rollback verification failed: {0}" -f $_.Exception.Message))
    }

    $reportPayload = [pscustomobject]@{
        CompletedAtUtc        = (Get-Date).ToUniversalTime().ToString('o')
        Configuration         = $Configuration
        Branch                = $currentBranch
        SignedStagingDir      = $signedStagingDir
        CertificateThumbprint = $signedThumbprint
        AuthorizedHostUserSid = $effectiveAuthorizedUserSid
        PreBuildHashes        = $preBuildHashes
        PostSignBuildHashes   = $postSignBuildHashes
        PackageVerified       = [bool]$packageVerify.SignerCertificatesMatch
        EtwVerifyResult       = $etwVerifyResult
        HostProcessResult     = $hostProcResult
        HostSummary           = $hostSummary
        AcceptanceCriteria    = $acceptanceCriteria
        ValidationSucceeded   = ([string]::IsNullOrWhiteSpace($validationError))
        ValidationError       = $validationError
        RollbackActions       = @($rollbackActions.ToArray())
        RollbackClean         = $rollbackClean
        PostRollbackInstances = $postRollbackInstances
        OutputDir             = $OutputDir
    }

    try {
        if (-not (Test-Path -LiteralPath $OutputDir)) {
            $null = New-Item -Path $OutputDir -ItemType Directory -Force
        }
        $reportPayload | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $reportJsonPath -Encoding UTF8

        $mdLines = New-Object System.Collections.Generic.List[string]
        $mdLines.Add('# LumaBridge M4.1 Functional Validation Report')
        $mdLines.Add('')
        $mdLines.Add(("- Completed UTC: ``{0}``" -f $reportPayload.CompletedAtUtc))
        $mdLines.Add(("- Branch: ``{0}`` | Configuration: ``{1}``" -f $currentBranch, $Configuration))
        $mdLines.Add(("- Staged Package (``StagingDir``): ``{0}``" -f $signedStagingDir))
        $mdLines.Add(("- Validation Succeeded: ``{0}`` | Rollback Clean: ``{1}``" -f $reportPayload.ValidationSucceeded, $rollbackClean))
        if (-not [string]::IsNullOrWhiteSpace($validationError)) {
            $mdLines.Add(("- Error: ``{0}``" -f $validationError))
        }
        if ($null -ne $hostSummary) {
            $mdLines.Add(("- Host Consumer: Frames=``{0}``, ChecksumMismatches=``{1}``, ProtocolErrors=``{2}``, ReceiveFps=``{3}``, AvgE2EUs=``{4}``" -f `
                $hostSummary.FramesReceived, $hostSummary.ChecksumMismatches, $hostSummary.ProtocolErrors, $hostSummary.ReceiveFps, $hostSummary.AvgEndToEndLatencyUs))
        }
        $mdLines.Add('')
        $mdLines.Add('## Rollback Actions')
        foreach ($act in $rollbackActions) {
            $mdLines.Add(("- {0}" -f $act))
        }
        $mdLines | Set-Content -LiteralPath $reportMdPath -Encoding UTF8
    }
    catch {
    }
}

if (-not [string]::IsNullOrWhiteSpace($validationError)) {
    throw ("LumaBridge M4.1 functional validation failed: {0}. RollbackClean={1}. Report='{2}'." -f $validationError, $rollbackClean, $reportJsonPath)
}

return [pscustomobject]@{
    ValidationSucceeded   = $true
    RollbackClean         = $rollbackClean
    Configuration         = $Configuration
    Branch                = $currentBranch
    StagingDir            = $signedStagingDir
    OutputDir             = $OutputDir
    ReportJsonPath        = $reportJsonPath
    ReportMdPath          = $reportMdPath
    HostSummaryPath       = $hostJsonPath
    HostSummary           = $hostSummary
    AcceptanceCriteria    = $acceptanceCriteria
    DiagnosticsResult     = $diagResult
    RollbackActions       = @($rollbackActions.ToArray())
    PostRollbackInstances = $postRollbackInstances
}
