<#
.SYNOPSIS
    Executes the end-to-end Windows 11 functional validation workflow for LumaBridgeIddDriver
    (M4.1/M4.1.1 real D3D11 frame extraction + M4.2/M4.2.1 GPU Shared Textures + NVENC H.264)
    with explicit separation between Smoke, Performance, 30s 1080p60 Benchmark, and
    Prolonged Stability profiles, causal timestamp telemetry checks, and guaranteed finally rollback.
#>
[CmdletBinding()]
param(
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Release',

    [ValidateSet('Smoke', 'Performance', 'Both', 'Benchmark30s', 'ProlongedStability', 'Full')]
    [string]$TestProfile = 'Smoke',

    [string]$StagingDir,

    [string]$OutputDir,

    [string]$HostExecutablePath,

    [string]$SyntheticFidelityExecutablePath,

    [string]$CertificateThumbprint,

    [string]$CertificateSubject = 'CN=LumaBridge Test Driver Signing',

    [switch]$CreateTestCertificateIfMissing,

    [switch]$TrustCertificate,

    [switch]$AllowUntrustedChain,

    [switch]$SkipTestSigningCheck,

    [string]$AuthorizedHostUserSid,

    [ValidateRange(1, 1000)]
    [int]$SmokeMinFrames = 1,

    [ValidateRange(1, 10000)]
    [int]$MaxFrames = 60,

    [ValidateRange(500, 120000)]
    [int]$HostDurationMs = 5000,

    [ValidateRange(1, 10000)]
    [int]$PerformanceTargetFrames = 60,

    [ValidateRange(500, 120000)]
    [int]$PerformanceDurationMs = 10000,

    [ValidateRange(30, 600)]
    [int]$BenchmarkDurationSec = 30,

    [ValidateRange(30, 3600)]
    [int]$StabilityDurationSec = 120,

    [ValidateRange(1, 120)]
    [int]$StimulusFps = 60,

    [string]$StimulusDisplayName,

    [ValidateRange(500, 30000)]
    [int]$ConnectTimeoutMs = 5000,

    [ValidateRange(50, 5000)]
    [int]$IoTimeoutMs = 500,

    [ValidateRange(1000, 300000)]
    [int]$HostHardTimeoutMs = 30000,

    [ValidateSet('Auto', 'Gpu', 'Cpu')]
    [string]$TransportMode = 'Auto',

    [switch]$RequireGpuShared,

    [switch]$EnableNvenc,

    [switch]$RequireNvenc,

    [ValidateRange(100000, 200000000)]
    [int]$NvencBitrateBps = 15000000,

    [switch]$VerifyH264Decode,

    [string]$ExpectedBranch = 'feature/windows-gpu-shared-textures-nvenc',

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

function Get-LumaBridgeGpuEngineUtilizationSample {
    [CmdletBinding()]
    param()

    try {
        $counter = Get-Counter '\GPU Engine(*)\Utilization Percentage' -ErrorAction Stop
        $samples = @($counter.CounterSamples)
        if ($samples.Count -eq 0) {
            return [pscustomobject]@{
                Available               = $false
                TotalUtilizationPercent = $null
                PeakEnginePercent       = $null
                SampleCount             = 0
                Error                   = 'No GPU Engine counter samples returned.'
            }
        }
        $sum = 0.0
        $peak = 0.0
        foreach ($s in $samples) {
            $val = [double]$s.CookedValue
            $sum += $val
            if ($val -gt $peak) {
                $peak = $val
            }
        }
        return [pscustomobject]@{
            Available               = $true
            TotalUtilizationPercent = [Math]::Round($sum, 2)
            PeakEnginePercent       = [Math]::Round($peak, 2)
            SampleCount             = $samples.Count
            Error                   = $null
        }
    }
    catch {
        return [pscustomobject]@{
            Available               = $false
            TotalUtilizationPercent = $null
            PeakEnginePercent       = $null
            SampleCount             = 0
            Error                   = $_.Exception.Message
        }
    }
}

function Test-LumaBridgeTemporalTelemetry {
    [CmdletBinding()]
    param($Summary)

    if ($null -eq $Summary) {
        return [pscustomobject]@{
            Evaluated                       = $false
            SequenceMonotonicityOk          = $false
            TimestampsMonotonicOk           = $false
            TimestampsValidOk               = $false
            MeasurableLatenciesOk           = $false
            TemporalCoverageSufficient      = $false
            SequenceAndTimestampsConsistent = $false
            TimestampMeasurementErrors      = [uint64]0
            CoreTimestampCoveragePercent    = 0.0
            LiveTimestampCoveragePercent    = 0.0
            PresentTimestampCoveragePercent = 0.0
            NvencExtractToBsCoveragePercent = 0.0
            ValidCoreTimestampSamples       = [uint64]0
            ValidLiveTimestampSamples       = [uint64]0
            ValidPresentTimestampSamples    = [uint64]0
        }
    }

    $lastSeq = [uint64](Get-LumaBridgeValidationOptionalProp $Summary 'LastFrameSequence' 0)
    $protoErr = [uint64](Get-LumaBridgeValidationOptionalProp $Summary 'ProtocolErrors' 0)
    $outOfOrderSeq = [uint64](Get-LumaBridgeValidationOptionalProp $Summary 'OutOfOrderSequenceCount' 0)
    $nonMonotonicTs = [uint64](Get-LumaBridgeValidationOptionalProp $Summary 'NonMonotonicTimestampCount' 0)
    $tsErrors = [uint64](Get-LumaBridgeValidationOptionalProp $Summary 'TimestampMeasurementErrors' 0)
    $missingCore = [uint64](Get-LumaBridgeValidationOptionalProp $Summary 'MissingCoreTimestampCount' 0)
    $futureErr = [uint64](Get-LumaBridgeValidationOptionalProp $Summary 'FutureTimestampErrorCount' 0)
    $incompatUnits = [uint64](Get-LumaBridgeValidationOptionalProp $Summary 'IncompatibleTimestampUnitsCount' 0)
    $qpcMismatch = [uint64](Get-LumaBridgeValidationOptionalProp $Summary 'QpcFrequencyMismatchCount' 0)
    $liveFrames = [uint64](Get-LumaBridgeValidationOptionalProp $Summary 'LiveFramesReceived' 0)

    $validCoreSamples = [uint64](Get-LumaBridgeValidationOptionalProp $Summary 'ValidCoreTimestampSamples' 0)
    $validLiveSamples = [uint64](Get-LumaBridgeValidationOptionalProp $Summary 'ValidLiveTimestampSamples' 0)
    $validPresSamples = [uint64](Get-LumaBridgeValidationOptionalProp $Summary 'ValidPresentTimestampSamples' 0)
    $coreCov = [double](Get-LumaBridgeValidationOptionalProp $Summary 'CoreTimestampCoveragePercent' 0.0)
    $liveCov = [double](Get-LumaBridgeValidationOptionalProp $Summary 'LiveTimestampCoveragePercent' 0.0)
    $presCov = [double](Get-LumaBridgeValidationOptionalProp $Summary 'PresentTimestampCoveragePercent' 0.0)

    $e2e = Get-LumaBridgeValidationOptionalProp $Summary 'EndToEndLatency' $null
    $liveE2E = Get-LumaBridgeValidationOptionalProp $Summary 'LiveEndToEndLatency' $null
    $e2eSampleCount = if ($null -ne $e2e) { [uint64](Get-LumaBridgeValidationOptionalProp $e2e 'SampleCount' 0) } else { [uint64]0 }
    $e2eAvailable = if ($null -ne $e2e) { [bool](Get-LumaBridgeValidationOptionalProp $e2e 'Available' ($e2eSampleCount -ge 1)) } else { $false }
    $liveE2ESampleCount = if ($null -ne $liveE2E) { [uint64](Get-LumaBridgeValidationOptionalProp $liveE2E 'SampleCount' 0) } else { [uint64]0 }
    $liveE2EAvailable = if ($null -ne $liveE2E) { [bool](Get-LumaBridgeValidationOptionalProp $liveE2E 'Available' ($liveE2ESampleCount -ge 1)) } else { $false }

    $nvenc = Get-LumaBridgeValidationOptionalProp $Summary 'Nvenc' $null
    $nvEncoded = if ($null -ne $nvenc) { [uint64](Get-LumaBridgeValidationOptionalProp $nvenc 'NvencFramesEncoded' 0) } else { [uint64]0 }
    $nvInvalidTs = if ($null -ne $nvenc) { [uint64](Get-LumaBridgeValidationOptionalProp $nvenc 'InvalidTimestampCount' 0) } else { [uint64]0 }
    $nvBsCov = if ($null -ne $nvenc) { [double](Get-LumaBridgeValidationOptionalProp $nvenc 'ExtractToBitstreamCoveragePercent' 0.0) } else { 0.0 }

    $seqMonotonicOk = ($lastSeq -ge 1) -and ($outOfOrderSeq -eq 0) -and ($protoErr -eq 0)
    $tsMonotonicOk = ($nonMonotonicTs -eq 0)
    $tsValidOk = ($tsErrors -eq 0) -and ($missingCore -eq 0) -and ($futureErr -eq 0) -and ($incompatUnits -eq 0) -and ($qpcMismatch -eq 0)
    $measurableOk = if ($liveFrames -gt 0) {
        $liveE2EAvailable -and ($liveE2ESampleCount -ge 1)
    }
    else {
        $e2eAvailable -and ($e2eSampleCount -ge 1)
    }
    $nvCovOk = ($nvEncoded -eq 0) -or (($nvInvalidTs -eq 0) -and ($nvBsCov -ge 95.0))
    $coverageOk = ($coreCov -ge 95.0) -and (($liveFrames -eq 0) -or ($liveCov -ge 95.0)) -and $nvCovOk

    $consistent = $seqMonotonicOk -and $tsMonotonicOk -and $tsValidOk -and $measurableOk -and $coverageOk
    return [pscustomobject]@{
        Evaluated                       = $true
        SequenceMonotonicityOk          = $seqMonotonicOk
        TimestampsMonotonicOk           = $tsMonotonicOk
        TimestampsValidOk               = $tsValidOk
        MeasurableLatenciesOk           = $measurableOk
        TemporalCoverageSufficient      = $coverageOk
        SequenceAndTimestampsConsistent = $consistent
        TimestampMeasurementErrors      = $tsErrors
        CoreTimestampCoveragePercent    = $coreCov
        LiveTimestampCoveragePercent    = $liveCov
        PresentTimestampCoveragePercent = $presCov
        NvencExtractToBsCoveragePercent = $nvBsCov
        ValidCoreTimestampSamples       = $validCoreSamples
        ValidLiveTimestampSamples       = $validLiveSamples
        ValidPresentTimestampSamples    = $validPresSamples
    }
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
$runSmokeProfile = ($TestProfile -in @('Smoke', 'Both', 'Full'))
$runPerfProfile = ($TestProfile -in @('Performance', 'Both'))
$runBenchmark30sProfile = ($TestProfile -in @('Benchmark30s', 'Full'))
$runStabilityProfile = ($TestProfile -in @('ProlongedStability', 'Full'))

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
$hostSmokeJsonPath = Join-Path -Path $OutputDir -ChildPath 'lumabridge-host-smoke-summary.json'
$hostPerfJsonPath = Join-Path -Path $OutputDir -ChildPath 'lumabridge-host-performance-summary.json'
$hostBench30sJsonPath = Join-Path -Path $OutputDir -ChildPath 'lumabridge-host-benchmark30s-summary.json'
$hostStabilityJsonPath = Join-Path -Path $OutputDir -ChildPath 'lumabridge-host-stability-summary.json'
$hostJsonPath = Join-Path -Path $OutputDir -ChildPath 'lumabridge-host-summary.json'
$reportJsonPath = Join-Path -Path $OutputDir -ChildPath 'functional-validation-report.json'
$reportMdPath = Join-Path -Path $OutputDir -ChildPath 'functional-validation-report.md'

# -------------------------------------------------------------------------
# Stage 1: Non-destructive pre-checks & prior state preservation
# -------------------------------------------------------------------------
$null = Assert-LumaBridgeAdministrator -OperationName 'Run LumaBridge M4.1.1 Functional Validation' -DryRun:$DryRun
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
$preValidationState = if ($null -ne $preExistingInstance) {
    [pscustomobject]@{
        ExistedBeforeRun      = $true
        InstanceId            = $preExistingInstance.InstanceId
        Status                = $preExistingInstance.Status
        ProblemCode           = $preExistingInstance.ProblemCode
        DriverInfPath         = Get-LumaBridgeValidationOptionalProp -InputObject $preExistingInstance -PropertyName 'DriverInfPath'
        DriverVersion         = Get-LumaBridgeValidationOptionalProp -InputObject $preExistingInstance -PropertyName 'DriverVersion'
        EnableVirtualMonitor     = Get-LumaBridgeValidationOptionalProp -InputObject $preExistingInstance -PropertyName 'EnableVirtualMonitor'
        EnableFrameExtraction    = Get-LumaBridgeValidationOptionalProp -InputObject $preExistingInstance -PropertyName 'EnableFrameExtraction'
        EnableGpuSharedTransport = Get-LumaBridgeValidationOptionalProp -InputObject $preExistingInstance -PropertyName 'EnableGpuSharedTransport'
        AuthorizedHostUserSid    = Get-LumaBridgeValidationOptionalProp -InputObject $preExistingInstance -PropertyName 'AuthorizedHostUserSid'
    }
}
else {
    [pscustomobject]@{
        ExistedBeforeRun         = $false
        InstanceId               = $null
        Status                   = $null
        ProblemCode              = $null
        DriverInfPath            = $null
        DriverVersion            = $null
        EnableVirtualMonitor     = $null
        EnableFrameExtraction    = $null
        EnableGpuSharedTransport = $null
        AuthorizedHostUserSid    = $null
    }
}

$initialWudfProcs = @(Get-LumaBridgeWudfHostProcesses -PnpInstances $initialInstances)
$initialDumpInventory = Get-LumaBridgeCrashDumpInventory -LookbackMinutes 60
$initialDumpCount = [int](Get-LumaBridgeValidationOptionalProp -InputObject $initialDumpInventory -PropertyName 'TotalFoundCount' -DefaultValue 0)

# -------------------------------------------------------------------------
# Stage 2: Branch & build artifact validation
# -------------------------------------------------------------------------
$gitBranchResult = Invoke-LumaBridgeExternalCommand -FilePath 'git.exe' -Arguments @('-C', $repoRoot, 'rev-parse', '--abbrev-ref', 'HEAD')
$currentBranch = if (@($gitBranchResult.Output).Count -gt 0) { ([string]$gitBranchResult.Output[0]).Trim() } else { '' }
$branchAllowed = if ($AllowAnyBranch) {
    $true
}
elseif ($PSBoundParameters.ContainsKey('ExpectedBranch')) {
    $currentBranch -eq $ExpectedBranch
}
else {
    $currentBranch -in @('feature/windows-gpu-shared-textures-nvenc', 'feature/windows-frame-extraction-ipc')
}
if (-not $branchAllowed) {
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

function Add-LumaBridgeM42HostArgs {
    param([System.Collections.Generic.List[string]]$ArgList)
    if ($RequireGpuShared) {
        $ArgList.Add('--transport')
        $ArgList.Add('gpu')
        $ArgList.Add('--require-gpu-shared')
    }
    elseif ($TransportMode -eq 'Gpu') {
        $ArgList.Add('--transport')
        $ArgList.Add('gpu')
    }
    elseif ($TransportMode -eq 'Cpu') {
        $ArgList.Add('--transport')
        $ArgList.Add('cpu')
    }

    if ($EnableNvenc -or $RequireNvenc) {
        $ArgList.Add('--nvenc')
        if ($RequireNvenc) {
            $ArgList.Add('--require-nvenc')
        }
        $ArgList.Add('--nvenc-bitrate-bps')
        $ArgList.Add("$NvencBitrateBps")
        $ArgList.Add('--prewarm-width')
        $ArgList.Add('1920')
        $ArgList.Add('--prewarm-height')
        $ArgList.Add('1080')
    }

    if ($VerifyH264Decode) {
        $ArgList.Add('--verify-h264-decode')
    }
}

function Build-SmokeHostArgs {
    param([string]$JsonOut)
    $list = New-Object System.Collections.Generic.List[string]
    foreach ($item in @(
        '--pipe', '\\.\pipe\LumaBridgeFrameIpc_v1',
        '--min-frames', "$SmokeMinFrames",
        '--max-frames', "$MaxFrames",
        '--duration-ms', "$HostDurationMs",
        '--connect-timeout-ms', "$ConnectTimeoutMs",
        '--io-timeout-ms', "$IoTimeoutMs",
        '--reconnect',
        '--json-summary', $JsonOut
    )) {
        $list.Add($item)
    }
    Add-LumaBridgeM42HostArgs -ArgList $list
    return @($list.ToArray())
}

function Build-PerfHostArgs {
    param([string]$JsonOut)
    $list = New-Object System.Collections.Generic.List[string]
    foreach ($item in @(
        '--pipe', '\\.\pipe\LumaBridgeFrameIpc_v1',
        '--max-frames', "$PerformanceTargetFrames",
        '--require-max-frames',
        '--duration-ms', "$PerformanceDurationMs",
        '--connect-timeout-ms', "$ConnectTimeoutMs",
        '--io-timeout-ms', "$IoTimeoutMs",
        '--reconnect',
        '--visual-stimulus',
        '--require-virtual-stimulus',
        '--stimulus-fps', "$StimulusFps",
        '--json-summary', $JsonOut
    )) {
        $list.Add($item)
    }
    if (-not [string]::IsNullOrWhiteSpace($StimulusDisplayName)) {
        $list.Add('--stimulus-display')
        $list.Add($StimulusDisplayName)
    }
    Add-LumaBridgeM42HostArgs -ArgList $list
    return @($list.ToArray())
}

function Build-ProlongedHostArgs {
    param(
        [string]$JsonOut,
        [int]$DurationSec
    )

    $durationMs = $DurationSec * 1000
    $minTargetFrames = [int][Math]::Max(1, [Math]::Floor($DurationSec * $StimulusFps * 0.75))
    $list = New-Object System.Collections.Generic.List[string]
    foreach ($item in @(
        '--pipe', '\\.\pipe\LumaBridgeFrameIpc_v1',
        '--min-frames', "$minTargetFrames",
        '--duration-ms', "$durationMs",
        '--connect-timeout-ms', "$ConnectTimeoutMs",
        '--io-timeout-ms', "$IoTimeoutMs",
        '--reconnect',
        '--visual-stimulus',
        '--require-virtual-stimulus',
        '--stimulus-fps', "$StimulusFps",
        '--json-summary', $JsonOut
    )) {
        $list.Add($item)
    }
    if (-not [string]::IsNullOrWhiteSpace($StimulusDisplayName)) {
        $list.Add('--stimulus-display')
        $list.Add($StimulusDisplayName)
    }
    Add-LumaBridgeM42HostArgs -ArgList $list
    return @($list.ToArray())
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
    $dryGpuMsg = if ($TransportMode -eq 'Cpu') { ' and REG_DWORD EnableGpuSharedTransport=0' } elseif ($TransportMode -eq 'Gpu' -or $RequireGpuShared) { ' and REG_DWORD EnableGpuSharedTransport=1' } else { '' }
    Write-Host ("[DRY-RUN] Stage 8: Would set REG_SZ AuthorizedHostUserSid='{0}', REG_DWORD EnableFrameExtraction=1{1} on '{2}' then restart PnP device" -f $effectiveAuthorizedUserSid, $dryGpuMsg, $dryInstId) -ForegroundColor Cyan

    $smokeDry = $null
    if ($runSmokeProfile) {
        $smokeHardMs = [Math]::Max($HostHardTimeoutMs, ($HostDurationMs + $ConnectTimeoutMs + 5000))
        $smokeDry = Invoke-LumaBridgeHostProcess -ExecutablePath $HostExecutablePath -Arguments (Build-SmokeHostArgs -JsonOut $hostSmokeJsonPath) -HardTimeoutMs $smokeHardMs -DryRun
    }
    $perfDry = $null
    if ($runPerfProfile) {
        $perfHardMs = [Math]::Max($HostHardTimeoutMs, ($PerformanceDurationMs + $ConnectTimeoutMs + 5000))
        $perfDry = Invoke-LumaBridgeHostProcess -ExecutablePath $HostExecutablePath -Arguments (Build-PerfHostArgs -JsonOut $hostPerfJsonPath) -HardTimeoutMs $perfHardMs -DryRun
    }
    $bench30sDry = $null
    if ($runBenchmark30sProfile) {
        $bench30sHardMs = [Math]::Max($HostHardTimeoutMs, (($BenchmarkDurationSec * 1000) + $ConnectTimeoutMs + 15000))
        $bench30sDry = Invoke-LumaBridgeHostProcess -ExecutablePath $HostExecutablePath -Arguments (Build-ProlongedHostArgs -JsonOut $hostBench30sJsonPath -DurationSec $BenchmarkDurationSec) -HardTimeoutMs $bench30sHardMs -DryRun
    }
    $stabilityDry = $null
    if ($runStabilityProfile) {
        $stabilityHardMs = [Math]::Max($HostHardTimeoutMs, (($StabilityDurationSec * 1000) + $ConnectTimeoutMs + 15000))
        $stabilityDry = Invoke-LumaBridgeHostProcess -ExecutablePath $HostExecutablePath -Arguments (Build-ProlongedHostArgs -JsonOut $hostStabilityJsonPath -DurationSec $StabilityDurationSec) -HardTimeoutMs $stabilityHardMs -DryRun
    }

    $etwStopDry = & $etwScript -Action Stop -OutputDir $etwDir -IncludeDxgKrnl:$IncludeDxgKrnl -DryRun
    $diagDry = & $diagScript -Configuration $Configuration -StagingDir $StagingDir -OutputDir $diagDir -DryRun
    Write-Host ("[DRY-RUN] Stage 11 (finally rollback): Would stop active ETW, revert EnableFrameExtraction=0, clear AuthorizedHostUserSid, restore EnableVirtualMonitor, restart device{0}, and write report '{1}'" -f $(if ($FullUninstallOnExit) { ' and run Uninstall-LumaBridgeDriver.ps1' } else { '' }), $reportJsonPath) -ForegroundColor Cyan

    $dryHostPreview = if ($null -ne $stabilityDry) { $stabilityDry } elseif ($null -ne $bench30sDry) { $bench30sDry } elseif ($null -ne $perfDry) { $perfDry } else { $smokeDry }
    return [pscustomobject]@{
        DryRun                  = $true
        Configuration           = $Configuration
        TestProfile             = $TestProfile
        Branch                  = $currentBranch
        PreValidationState      = $preValidationState
        PlannedStagingDir       = $StagingDir
        PlannedOutputDir        = $OutputDir
        HostExecutablePath      = $HostExecutablePath
        AuthorizedHostUserSid   = $effectiveAuthorizedUserSid
        PreBuildHashes          = $preBuildHashes
        SigningPreview          = $signingDry
        EtwStartPreview         = $etwStartDry
        SmokeHostPreview        = $smokeDry
        PerfHostPreview         = $perfDry
        Benchmark30sHostPreview = $bench30sDry
        StabilityHostPreview    = $stabilityDry
        HostPreview             = $dryHostPreview
        EtwStopPreview          = $etwStopDry
        DiagnosticsPreview      = $diagDry
        PlannedReportJsonPath   = $reportJsonPath
        PlannedReportMdPath     = $reportMdPath
    }
}

# Explicit operator authorization check prior to Stage 3/5/6 system or store mutations.
$authPrompt = "Execute controlled Windows M4.1.1 validation (Profile='{0}', Staging='{1}', InstallOrUpdateDriver={2}, EnableVirtualMonitor=1, EnableFrameExtraction=1, Rollback='Registry/ETW parameters reverted in finally; driver package downgrade NOT implemented')" -f `
    $TestProfile, $StagingDir, (-not $SkipDriverInstall)
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
$hadPreExistingGpuTrans = if ($null -ne $preExistingInstance) { Get-LumaBridgeValidationOptionalProp -InputObject $preExistingInstance -PropertyName 'EnableGpuSharedTransport' -DefaultValue $null } else { $null }
$hadPreExistingAuthSid = if ($null -ne $preExistingInstance) { Get-LumaBridgeValidationOptionalProp -InputObject $preExistingInstance -PropertyName 'AuthorizedHostUserSid' -DefaultValue $null } else { $null }
$modifiedVirtMon = $false
$modifiedExtraction = $false
$modifiedGpuTrans = $false
$modifiedAuthSid = $false

$etwStartResult = $null
$etwVerifyResult = $null
$etwStopResult = $null
$installResult = $null
$installedBindingCheck = $null
$virtMonEnableResult = $null
$smokeHostResult = $null
$smokeSummary = $null
$perfHostResult = $null
$perfSummary = $null
$bench30sHostResult = $null
$bench30sSummary = $null
$stabilityHostResult = $null
$stabilitySummary = $null
$syntheticFidelityResult = $null
$preStage9WudfProcs = @()
$gpuUtilSample = $null
$processResourceSummary = $null
$hostProcResult = $null
$hostSummary = $null
$diagResult = $null
$postRunWudfProcs = @()
$postRunDumpInventory = $null
$acceptanceCriteria = $null
$validationError = $null
$rollbackActions = New-Object System.Collections.Generic.List[string]
$rollbackIncompleteReasons = New-Object System.Collections.Generic.List[string]
$rollbackClean = $false
$postRollbackInstances = @()

$rollbackScopeNote = if ($FullUninstallOnExit) {
    'Rolls back ETW, temporary registry parameters (EnableFrameExtraction=0, AuthorizedHostUserSid, EnableVirtualMonitor), and removes device/driver package via Uninstall-LumaBridgeDriver.ps1.'
}
elseif ($SkipDriverInstall) {
    'Rolls back ETW and temporary registry parameters (EnableFrameExtraction=0, AuthorizedHostUserSid, EnableVirtualMonitor) on the existing installed driver.'
}
else {
    'Rolls back ETW and temporary registry parameters (EnableFrameExtraction=0, AuthorizedHostUserSid, EnableVirtualMonitor). Does NOT downgrade/restore an older pre-existing driver binary unless -FullUninstallOnExit uninstalls on exit.'
}

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

    if (Get-Command -Name 'Test-LumaBridgeDeviceDriverBinding' -ErrorAction SilentlyContinue) {
        $stagedInfPath = Join-Path -Path $signedStagingDir -ChildPath $constants.InfFileName
        $installedBindingCheck = Test-LumaBridgeDeviceDriverBinding -Instance $targetInstance -ExpectedInfPath $stagedInfPath
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
    # Stage 8: Temporary EnableFrameExtraction=1, EnableGpuSharedTransport & AuthorizedHostUserSid
    # ---------------------------------------------------------------------
    Set-LumaBridgeDeviceAuthorizedHostUserSid -DeviceParametersPath $targetInstance.DeviceParametersPath -SidString $effectiveAuthorizedUserSid
    $modifiedAuthSid = $true
    if ($TransportMode -eq 'Cpu') {
        Set-LumaBridgeDeviceEnableGpuSharedTransport -DeviceParametersPath $targetInstance.DeviceParametersPath -Value 0
        $modifiedGpuTrans = $true
    }
    elseif ($TransportMode -eq 'Gpu' -or $RequireGpuShared) {
        Set-LumaBridgeDeviceEnableGpuSharedTransport -DeviceParametersPath $targetInstance.DeviceParametersPath -Value 1
        $modifiedGpuTrans = $true
    }
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
    # Stage 9: Time-bounded lumabridge-host.exe execution (Smoke / Perf / 30s Benchmark / Prolonged Stability)
    # ---------------------------------------------------------------------
    $preStage9WudfProcs = @(Get-LumaBridgeWudfHostProcesses -PnpInstances @($targetInstance))
    $gpuUtilSample = Get-LumaBridgeGpuEngineUtilizationSample

    if ($runSmokeProfile) {
        $smokeHardTimeoutMs = [Math]::Max($HostHardTimeoutMs, ($HostDurationMs + $ConnectTimeoutMs + 5000))
        $smokeHostResult = Invoke-LumaBridgeHostProcess `
            -ExecutablePath $HostExecutablePath `
            -Arguments (Build-SmokeHostArgs -JsonOut $hostSmokeJsonPath) `
            -HardTimeoutMs $smokeHardTimeoutMs
        if (Test-Path -LiteralPath $hostSmokeJsonPath -PathType Leaf) {
            $smokeSummary = Get-Content -LiteralPath $hostSmokeJsonPath -Raw | ConvertFrom-Json
            Copy-Item -LiteralPath $hostSmokeJsonPath -Destination $hostJsonPath -Force
        }
        $hostProcResult = $smokeHostResult
        $hostSummary = $smokeSummary
    }

    $smokeFramesValidCount = if ($null -ne $smokeSummary) {
        [uint64](Get-LumaBridgeValidationOptionalProp -InputObject $smokeSummary -PropertyName 'FramesValid' -DefaultValue (Get-LumaBridgeValidationOptionalProp -InputObject $smokeSummary -PropertyName 'FramesReceived' -DefaultValue 0))
    }
    else { [uint64]0 }

    $smokeGateForNext = ((-not $runSmokeProfile) -or ($smokeFramesValidCount -ge [uint64]$SmokeMinFrames))

    if ($runPerfProfile -and $smokeGateForNext) {
        $perfHardTimeoutMs = [Math]::Max($HostHardTimeoutMs, ($PerformanceDurationMs + $ConnectTimeoutMs + 5000))
        $perfHostResult = Invoke-LumaBridgeHostProcess `
            -ExecutablePath $HostExecutablePath `
            -Arguments (Build-PerfHostArgs -JsonOut $hostPerfJsonPath) `
            -HardTimeoutMs $perfHardTimeoutMs
        if (Test-Path -LiteralPath $hostPerfJsonPath -PathType Leaf) {
            $perfSummary = Get-Content -LiteralPath $hostPerfJsonPath -Raw | ConvertFrom-Json
            Copy-Item -LiteralPath $hostPerfJsonPath -Destination $hostJsonPath -Force
            $hostProcResult = $perfHostResult
            $hostSummary = $perfSummary
        }
    }

    if ($runBenchmark30sProfile -and $smokeGateForNext) {
        $bench30sHardTimeoutMs = [Math]::Max($HostHardTimeoutMs, (($BenchmarkDurationSec * 1000) + $ConnectTimeoutMs + 15000))
        $bench30sHostResult = Invoke-LumaBridgeHostProcess `
            -ExecutablePath $HostExecutablePath `
            -Arguments (Build-ProlongedHostArgs -JsonOut $hostBench30sJsonPath -DurationSec $BenchmarkDurationSec) `
            -HardTimeoutMs $bench30sHardTimeoutMs
        if (Test-Path -LiteralPath $hostBench30sJsonPath -PathType Leaf) {
            $bench30sSummary = Get-Content -LiteralPath $hostBench30sJsonPath -Raw | ConvertFrom-Json
            Copy-Item -LiteralPath $hostBench30sJsonPath -Destination $hostJsonPath -Force
            $hostProcResult = $bench30sHostResult
            $hostSummary = $bench30sSummary
        }
    }

    if ($runStabilityProfile -and $smokeGateForNext) {
        $stabilityHardTimeoutMs = [Math]::Max($HostHardTimeoutMs, (($StabilityDurationSec * 1000) + $ConnectTimeoutMs + 15000))
        $stabilityHostResult = Invoke-LumaBridgeHostProcess `
            -ExecutablePath $HostExecutablePath `
            -Arguments (Build-ProlongedHostArgs -JsonOut $hostStabilityJsonPath -DurationSec $StabilityDurationSec) `
            -HardTimeoutMs $stabilityHardTimeoutMs
        if (Test-Path -LiteralPath $hostStabilityJsonPath -PathType Leaf) {
            $stabilitySummary = Get-Content -LiteralPath $hostStabilityJsonPath -Raw | ConvertFrom-Json
            Copy-Item -LiteralPath $hostStabilityJsonPath -Destination $hostJsonPath -Force
            $hostProcResult = $stabilityHostResult
            $hostSummary = $stabilitySummary
        }
    }

    $gpuUtilDuringRun = Get-LumaBridgeGpuEngineUtilizationSample
    if ($null -ne $gpuUtilDuringRun -and $gpuUtilDuringRun.Available) {
        $gpuUtilSample = $gpuUtilDuringRun
    }

    if (-not [string]::IsNullOrWhiteSpace($SyntheticFidelityExecutablePath) -and (Test-Path -LiteralPath $SyntheticFidelityExecutablePath -PathType Leaf)) {
        $synRes = Invoke-LumaBridgeExternalCommand -FilePath $SyntheticFidelityExecutablePath -Arguments @()
        $syntheticFidelityResult = [pscustomobject]@{
            ExecutablePath = $SyntheticFidelityExecutablePath
            ExitCode       = $synRes.ExitCode
            Passed         = ($synRes.ExitCode -eq 0)
            Output         = @($synRes.Output)
        }
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

    $primaryEvalSummary = if ($null -ne $stabilitySummary) {
        $stabilitySummary
    }
    elseif ($null -ne $bench30sSummary) {
        $bench30sSummary
    }
    elseif ($null -ne $perfSummary) {
        $perfSummary
    }
    else {
        $smokeSummary
    }
    $primaryEvalProc = if ($null -ne $stabilitySummary) {
        $stabilityHostResult
    }
    elseif ($null -ne $bench30sSummary) {
        $bench30sHostResult
    }
    elseif ($null -ne $perfSummary) {
        $perfHostResult
    }
    else {
        $smokeHostResult
    }

    $smokeEvalSummary = if ($null -ne $smokeSummary) { $smokeSummary } else { $primaryEvalSummary }
    $smokeEvalProc = if ($null -ne $smokeHostResult) { $smokeHostResult } else { $primaryEvalProc }

    $framesReceived = if ($null -ne $primaryEvalSummary) { [uint64](Get-LumaBridgeValidationOptionalProp -InputObject $primaryEvalSummary -PropertyName 'FramesReceived' -DefaultValue 0) } else { [uint64]0 }
    $framesValid = if ($null -ne $primaryEvalSummary) { [uint64](Get-LumaBridgeValidationOptionalProp -InputObject $primaryEvalSummary -PropertyName 'FramesValid' -DefaultValue $framesReceived) } else { [uint64]0 }
    $checksumMismatches = if ($null -ne $primaryEvalSummary) { [uint64](Get-LumaBridgeValidationOptionalProp -InputObject $primaryEvalSummary -PropertyName 'ChecksumMismatches' -DefaultValue 1) } else { [uint64]1 }
    $protocolErrors = if ($null -ne $primaryEvalSummary) { [uint64](Get-LumaBridgeValidationOptionalProp -InputObject $primaryEvalSummary -PropertyName 'ProtocolErrors' -DefaultValue 1) } else { [uint64]1 }
    $fatalIoTimeouts = if ($null -ne $primaryEvalSummary) { [uint64](Get-LumaBridgeValidationOptionalProp -InputObject $primaryEvalSummary -PropertyName 'FatalIoTimeouts' -DefaultValue 0) } else { [uint64]0 }
    $fatalIpcErrors = if ($null -ne $primaryEvalSummary) { [uint64](Get-LumaBridgeValidationOptionalProp -InputObject $primaryEvalSummary -PropertyName 'FatalIpcErrors' -DefaultValue 0) } else { [uint64]0 }
    $lastFrameSeq = if ($null -ne $primaryEvalSummary) { [uint64](Get-LumaBridgeValidationOptionalProp -InputObject $primaryEvalSummary -PropertyName 'LastFrameSequence' -DefaultValue 0) } else { [uint64]0 }
    $lastProtocolStatus = if ($null -ne $primaryEvalSummary) { [string](Get-LumaBridgeValidationOptionalProp -InputObject $primaryEvalSummary -PropertyName 'LastProtocolStatus' -DefaultValue 'Unknown') } else { 'Missing' }
    $connectCount = if ($null -ne $primaryEvalSummary) { [uint64](Get-LumaBridgeValidationOptionalProp -InputObject $primaryEvalSummary -PropertyName 'ConnectCount' -DefaultValue 0) } else { [uint64]0 }
    $hostTransportHealthy = if ($null -ne $primaryEvalSummary) { [bool](Get-LumaBridgeValidationOptionalProp -InputObject $primaryEvalSummary -PropertyName 'TransportHealthy' -DefaultValue $false) } else { $false }
    $frameTargetReached = if ($null -ne $primaryEvalSummary) { [bool](Get-LumaBridgeValidationOptionalProp -InputObject $primaryEvalSummary -PropertyName 'FrameTargetReached' -DefaultValue $false) } else { $false }

    $smokeFramesValid = if ($null -ne $smokeEvalSummary) { [uint64](Get-LumaBridgeValidationOptionalProp -InputObject $smokeEvalSummary -PropertyName 'FramesValid' -DefaultValue 0) } else { [uint64]0 }
    $smokeChecksumMismatches = if ($null -ne $smokeEvalSummary) { [uint64](Get-LumaBridgeValidationOptionalProp -InputObject $smokeEvalSummary -PropertyName 'ChecksumMismatches' -DefaultValue 1) } else { [uint64]1 }
    $smokeProtocolErrors = if ($null -ne $smokeEvalSummary) { [uint64](Get-LumaBridgeValidationOptionalProp -InputObject $smokeEvalSummary -PropertyName 'ProtocolErrors' -DefaultValue 1) } else { [uint64]1 }
    $smokeFatalIoTimeouts = if ($null -ne $smokeEvalSummary) { [uint64](Get-LumaBridgeValidationOptionalProp -InputObject $smokeEvalSummary -PropertyName 'FatalIoTimeouts' -DefaultValue 0) } else { [uint64]0 }
    $smokeFatalIpcErrors = if ($null -ne $smokeEvalSummary) { [uint64](Get-LumaBridgeValidationOptionalProp -InputObject $smokeEvalSummary -PropertyName 'FatalIpcErrors' -DefaultValue 0) } else { [uint64]0 }
    $smokeConnectCount = if ($null -ne $smokeEvalSummary) { [uint64](Get-LumaBridgeValidationOptionalProp -InputObject $smokeEvalSummary -PropertyName 'ConnectCount' -DefaultValue 0) } else { [uint64]0 }
    $smokeHostTransportHealthy = if ($null -ne $smokeEvalSummary) { [bool](Get-LumaBridgeValidationOptionalProp -InputObject $smokeEvalSummary -PropertyName 'TransportHealthy' -DefaultValue $false) } else { $false }
    $smokeHostExitedNormally = ($null -ne $smokeEvalProc -and (-not $smokeEvalProc.TimedOut) -and ($smokeEvalProc.ExitCode -eq 0))
    $smokeTemporalEval = Test-LumaBridgeTemporalTelemetry -Summary $smokeEvalSummary

    $executedSummaries = @(@($smokeSummary, $perfSummary, $bench30sSummary, $stabilitySummary) | Where-Object { $null -ne $_ })
    $primaryTemporal = Test-LumaBridgeTemporalTelemetry -Summary $primaryEvalSummary
    $seqMonotonicityOk = ($executedSummaries.Count -ge 1)
    $timestampsMonotonicOk = ($executedSummaries.Count -ge 1)
    $timestampsValidOk = ($executedSummaries.Count -ge 1)
    $measurableLatenciesOk = ($executedSummaries.Count -ge 1)
    $temporalCoverageSufficient = ($executedSummaries.Count -ge 1)
    $totalTimestampMeasurementErrors = [uint64]0
    foreach ($execSum in $executedSummaries) {
        $tEval = Test-LumaBridgeTemporalTelemetry -Summary $execSum
        $seqMonotonicityOk = $seqMonotonicityOk -and $tEval.SequenceMonotonicityOk
        $timestampsMonotonicOk = $timestampsMonotonicOk -and $tEval.TimestampsMonotonicOk
        $timestampsValidOk = $timestampsValidOk -and $tEval.TimestampsValidOk
        $measurableLatenciesOk = $measurableLatenciesOk -and $tEval.MeasurableLatenciesOk
        $temporalCoverageSufficient = $temporalCoverageSufficient -and $tEval.TemporalCoverageSufficient
        $totalTimestampMeasurementErrors += $tEval.TimestampMeasurementErrors
    }
    $sequenceAndTimestampsOk = ($seqMonotonicityOk -and $timestampsMonotonicOk -and $timestampsValidOk -and $measurableLatenciesOk -and $temporalCoverageSufficient)

    $hostExitedNormally = ($null -ne $primaryEvalProc -and (-not $primaryEvalProc.TimedOut) -and ($primaryEvalProc.ExitCode -eq 0))
    $ipcConnected = ($connectCount -ge 1)
    $transportHealthy = ($hostTransportHealthy -and $protocolErrors -eq 0 -and $checksumMismatches -eq 0 -and $fatalIoTimeouts -eq 0 -and $fatalIpcErrors -eq 0)
    $crc32Valid = ($framesValid -ge 1 -and $checksumMismatches -eq 0)
    $noUnauthorizedIpcClients = ($lastProtocolStatus -ne 'UnauthorizedClient')
    $noNewCrashDumps = ($postDumpCount -le $initialDumpCount)
    $wudfProcessHealthy = ($postRunWudfProcs.Count -ge 1 -or $null -eq $preExistingInstance)

    $functionalSmokePassed = (
        $runSmokeProfile -and
        $cmProbNone -and
        $adapterInitFinishedOk -and
        $virtualMonitorActive -and
        ($smokeConnectCount -ge 1) -and
        $smokeHostExitedNormally -and
        ($smokeFramesValid -ge [uint64]$SmokeMinFrames) -and
        ($smokeChecksumMismatches -eq 0) -and
        $smokeTemporalEval.SequenceAndTimestampsConsistent -and
        ($smokeHostTransportHealthy -and $smokeProtocolErrors -eq 0 -and $smokeFatalIoTimeouts -eq 0 -and $smokeFatalIpcErrors -eq 0) -and
        $noUnauthorizedIpcClients -and
        $noNewCrashDumps -and
        $wudfProcessHealthy
    )

    $perfExecuted = ($null -ne $perfHostResult)
    $perfFramesValid = if ($null -ne $perfSummary) { [uint64](Get-LumaBridgeValidationOptionalProp -InputObject $perfSummary -PropertyName 'FramesValid' -DefaultValue 0) } else { [uint64]0 }
    $perfTransportHealthy = if ($null -ne $perfSummary) { [bool](Get-LumaBridgeValidationOptionalProp -InputObject $perfSummary -PropertyName 'TransportHealthy' -DefaultValue $false) } else { $false }
    $perfTargetReachedFlag = if ($null -ne $perfSummary) { [bool](Get-LumaBridgeValidationOptionalProp -InputObject $perfSummary -PropertyName 'FrameTargetReached' -DefaultValue $false) } else { $false }
    $perfStim = if ($null -ne $perfSummary) { Get-LumaBridgeValidationOptionalProp -InputObject $perfSummary -PropertyName 'VisualStimulus' -DefaultValue $null } else { $null }
    $perfStimStarted = ($null -ne $perfStim -and [bool](Get-LumaBridgeValidationOptionalProp -InputObject $perfStim -PropertyName 'VirtualDisplayIdentified' -DefaultValue $false) -and [bool](Get-LumaBridgeValidationOptionalProp -InputObject $perfStim -PropertyName 'Started' -DefaultValue $false))
    $perfTemporalEval = Test-LumaBridgeTemporalTelemetry -Summary $perfSummary
    $perfTargetReached = (
        $perfExecuted -and
        (-not $perfHostResult.TimedOut) -and
        ($perfHostResult.ExitCode -eq 0) -and
        $perfTransportHealthy -and
        $perfTargetReachedFlag -and
        ($perfFramesValid -ge [uint64]$PerformanceTargetFrames) -and
        $perfStimStarted -and
        $perfTemporalEval.SequenceAndTimestampsConsistent
    )

    $bench30sExecuted = ($null -ne $bench30sHostResult)
    $bench30sValidFrames = if ($null -ne $bench30sSummary) { [uint64](Get-LumaBridgeValidationOptionalProp -InputObject $bench30sSummary -PropertyName 'FramesValid' -DefaultValue 0) } else { [uint64]0 }
    $bench30sDurationUs = if ($null -ne $bench30sSummary) { [uint64](Get-LumaBridgeValidationOptionalProp -InputObject $bench30sSummary -PropertyName 'TotalConnectedDurationUs' -DefaultValue (Get-LumaBridgeValidationOptionalProp -InputObject $bench30sSummary -PropertyName 'TotalExecutionDurationUs' 0)) } else { [uint64]0 }
    $bench30sMinFramesExpected = [uint64][Math]::Max(1, [int][Math]::Floor($BenchmarkDurationSec * $StimulusFps * 0.75))
    $bench30sStim = if ($null -ne $bench30sSummary) { Get-LumaBridgeValidationOptionalProp -InputObject $bench30sSummary -PropertyName 'VisualStimulus' -DefaultValue $null } else { $null }
    $bench30sStimStarted = ($null -ne $bench30sStim -and [bool](Get-LumaBridgeValidationOptionalProp -InputObject $bench30sStim -PropertyName 'VirtualDisplayIdentified' -DefaultValue $false) -and [bool](Get-LumaBridgeValidationOptionalProp -InputObject $bench30sStim -PropertyName 'Started' -DefaultValue $false))
    $bench30sTemporal = Test-LumaBridgeTemporalTelemetry -Summary $bench30sSummary
    $bench30sPassed = (
        $bench30sExecuted -and
        (-not $bench30sHostResult.TimedOut) -and
        ($bench30sHostResult.ExitCode -eq 0) -and
        ($null -ne $bench30sSummary) -and
        [bool](Get-LumaBridgeValidationOptionalProp -InputObject $bench30sSummary -PropertyName 'TransportHealthy' -DefaultValue $false) -and
        $bench30sStimStarted -and
        ($bench30sValidFrames -ge $bench30sMinFramesExpected) -and
        ($bench30sDurationUs -ge [uint64]($BenchmarkDurationSec * 900000)) -and
        $bench30sTemporal.SequenceAndTimestampsConsistent
    )

    $stabilityExecuted = ($null -ne $stabilityHostResult)
    $stabilityValidFrames = if ($null -ne $stabilitySummary) { [uint64](Get-LumaBridgeValidationOptionalProp -InputObject $stabilitySummary -PropertyName 'FramesValid' -DefaultValue 0) } else { [uint64]0 }
    $stabilityDurationUs = if ($null -ne $stabilitySummary) { [uint64](Get-LumaBridgeValidationOptionalProp -InputObject $stabilitySummary -PropertyName 'TotalConnectedDurationUs' -DefaultValue (Get-LumaBridgeValidationOptionalProp -InputObject $stabilitySummary -PropertyName 'TotalExecutionDurationUs' 0)) } else { [uint64]0 }
    $stabilityMinFramesExpected = [uint64][Math]::Max(1, [int][Math]::Floor($StabilityDurationSec * $StimulusFps * 0.75))
    $stabilityStim = if ($null -ne $stabilitySummary) { Get-LumaBridgeValidationOptionalProp -InputObject $stabilitySummary -PropertyName 'VisualStimulus' -DefaultValue $null } else { $null }
    $stabilityStimStarted = ($null -ne $stabilityStim -and [bool](Get-LumaBridgeValidationOptionalProp -InputObject $stabilityStim -PropertyName 'VirtualDisplayIdentified' -DefaultValue $false) -and [bool](Get-LumaBridgeValidationOptionalProp -InputObject $stabilityStim -PropertyName 'Started' -DefaultValue $false))
    $stabilityTemporal = Test-LumaBridgeTemporalTelemetry -Summary $stabilitySummary
    $stabilityPassed = (
        $stabilityExecuted -and
        (-not $stabilityHostResult.TimedOut) -and
        ($stabilityHostResult.ExitCode -eq 0) -and
        ($null -ne $stabilitySummary) -and
        [bool](Get-LumaBridgeValidationOptionalProp -InputObject $stabilitySummary -PropertyName 'TransportHealthy' -DefaultValue $false) -and
        $stabilityStimStarted -and
        ($stabilityValidFrames -ge $stabilityMinFramesExpected) -and
        ($stabilityDurationUs -ge [uint64]($StabilityDurationSec * 900000)) -and
        $stabilityTemporal.SequenceAndTimestampsConsistent
    )

    $prolongedStabilityProven = (
        ($bench30sPassed -and $bench30sValidFrames -ge 1500 -and $bench30sDurationUs -ge 28000000) -or
        ($stabilityPassed -and $stabilityValidFrames -ge 1500 -and $stabilityDurationUs -ge 28000000)
    )

    $smokeGateOk = (-not $runSmokeProfile) -or $functionalSmokePassed
    $perfGateOk = (-not $runPerfProfile) -or $perfTargetReached
    $bench30sGateOk = (-not $runBenchmark30sProfile) -or $bench30sPassed
    $stabilityGateOk = (-not $runStabilityProfile) -or $stabilityPassed

    $evalGpuMode = if ($null -ne $primaryEvalSummary) { [string](Get-LumaBridgeValidationOptionalProp -InputObject $primaryEvalSummary -PropertyName 'NegotiatedTransportMode' -DefaultValue 'CpuStagingPipe') } else { 'CpuStagingPipe' }
    $evalFallback = if ($null -ne $primaryEvalSummary) { [bool](Get-LumaBridgeValidationOptionalProp -InputObject $primaryEvalSummary -PropertyName 'FallbackToCpuActivated' -DefaultValue $false) } else { $false }
    $evalGpuOpened = if ($null -ne $primaryEvalSummary) { [uint64](Get-LumaBridgeValidationOptionalProp -InputObject $primaryEvalSummary -PropertyName 'GpuFramesOpened' -DefaultValue 0) } else { [uint64]0 }
    $evalCpuReads = if ($null -ne $primaryEvalSummary) { [uint64](Get-LumaBridgeValidationOptionalProp -InputObject $primaryEvalSummary -PropertyName 'CpuStagingReadsPerformed' -DefaultValue 0) } else { [uint64]0 }
    $evalOpenFailures = if ($null -ne $primaryEvalSummary) { [uint64](Get-LumaBridgeValidationOptionalProp -InputObject $primaryEvalSummary -PropertyName 'GpuSharedOpenFailures' -DefaultValue 0) } else { [uint64]0 }
    $evalSyncTimeouts = if ($null -ne $primaryEvalSummary) { [uint64](Get-LumaBridgeValidationOptionalProp -InputObject $primaryEvalSummary -PropertyName 'GpuSyncTimeouts' -DefaultValue 0) } else { [uint64]0 }
    $evalLuidErrors = if ($null -ne $primaryEvalSummary) { [uint64](Get-LumaBridgeValidationOptionalProp -InputObject $primaryEvalSummary -PropertyName 'AdapterMismatchErrors' -DefaultValue 0) } else { [uint64]0 }
    $evalNvenc = if ($null -ne $primaryEvalSummary) { Get-LumaBridgeValidationOptionalProp -InputObject $primaryEvalSummary -PropertyName 'Nvenc' -DefaultValue $null } else { $null }
    $evalNvencEncoded = if ($null -ne $evalNvenc) { [uint64](Get-LumaBridgeValidationOptionalProp -InputObject $evalNvenc -PropertyName 'NvencFramesEncoded' -DefaultValue 0) } else { [uint64]0 }
    $evalNvencBytes = if ($null -ne $evalNvenc) { [uint64](Get-LumaBridgeValidationOptionalProp -InputObject $evalNvenc -PropertyName 'TotalBitstreamBytes' -DefaultValue 0) } else { [uint64]0 }
    $evalH264 = if ($null -ne $primaryEvalSummary) { Get-LumaBridgeValidationOptionalProp -InputObject $primaryEvalSummary -PropertyName 'H264DecodeValidation' -DefaultValue $null } else { $null }
    $evalH264Passed = if ($null -ne $evalH264) { [bool](Get-LumaBridgeValidationOptionalProp -InputObject $evalH264 -PropertyName 'Passed' -DefaultValue $false) } else { $false }
    $structuralDecodeValidated = if ($null -ne $evalH264) {
        [bool](Get-LumaBridgeValidationOptionalProp -InputObject $evalH264 -PropertyName 'StructuralDecodeValidated' -DefaultValue $evalH264Passed) -and $evalH264Passed
    }
    else { $false }
    $fidelityPsnrValidated = (
        ($null -ne $evalH264 -and [bool](Get-LumaBridgeValidationOptionalProp -InputObject $evalH264 -PropertyName 'FidelityPsnrValidated' -DefaultValue $false)) -or
        ($null -ne $syntheticFidelityResult -and [bool]$syntheticFidelityResult.Passed)
    )

    $realGpuSyncHealthy = (-not $RequireGpuShared) -or ($evalGpuMode -eq 'GpuSharedNtHandle' -and (-not $evalFallback) -and $evalGpuOpened -ge 1 -and $evalOpenFailures -eq 0 -and $evalSyncTimeouts -eq 0 -and $evalLuidErrors -eq 0)
    $gpuSharedPassed = ($evalGpuMode -eq 'GpuSharedNtHandle' -and (-not $evalFallback) -and $evalGpuOpened -ge 1 -and $evalOpenFailures -eq 0 -and $evalSyncTimeouts -eq 0 -and $evalLuidErrors -eq 0 -and $evalCpuReads -eq 0)
    $nvencPassed = ($evalNvencEncoded -ge 1 -and $evalNvencBytes -ge 1)
    $h264DecodePassed = $evalH264Passed

    $gpuGateOk = (-not $RequireGpuShared) -or $gpuSharedPassed
    $nvencGateOk = (-not $RequireNvenc) -or $nvencPassed
    $h264GateOk = (-not $VerifyH264Decode) -or $h264DecodePassed

    $allPassed = (
        $cmProbNone -and
        $adapterInitFinishedOk -and
        $virtualMonitorActive -and
        $noUnauthorizedIpcClients -and
        $noNewCrashDumps -and
        $wudfProcessHealthy -and
        $sequenceAndTimestampsOk -and
        $realGpuSyncHealthy -and
        $smokeGateOk -and
        $perfGateOk -and
        $bench30sGateOk -and
        $stabilityGateOk -and
        $gpuGateOk -and
        $nvencGateOk -and
        $h264GateOk
    )

    $preWudfWsMb = if ($preStage9WudfProcs.Count -gt 0) { [double](Get-LumaBridgeValidationOptionalProp $preStage9WudfProcs[0] 'WorkingSetMB' 0.0) } else { $null }
    $postWudfWsMb = if ($postRunWudfProcs.Count -gt 0) { [double](Get-LumaBridgeValidationOptionalProp $postRunWudfProcs[0] 'WorkingSetMB' 0.0) } else { $null }
    $preWudfPrivMb = if ($preStage9WudfProcs.Count -gt 0) { [double](Get-LumaBridgeValidationOptionalProp $preStage9WudfProcs[0] 'PrivateMemoryMB' 0.0) } else { $null }
    $postWudfPrivMb = if ($postRunWudfProcs.Count -gt 0) { [double](Get-LumaBridgeValidationOptionalProp $postRunWudfProcs[0] 'PrivateMemoryMB' 0.0) } else { $null }

    $processResourceSummary = [pscustomobject]@{
        PreWudfWorkingSetMB     = $preWudfWsMb
        PostWudfWorkingSetMB    = $postWudfWsMb
        WudfWorkingSetDeltaMB   = if ($null -ne $preWudfWsMb -and $null -ne $postWudfWsMb) { [Math]::Round(($postWudfWsMb - $preWudfWsMb), 2) } else { $null }
        PreWudfPrivateMemoryMB  = $preWudfPrivMb
        PostWudfPrivateMemoryMB = $postWudfPrivMb
        WudfPrivateDeltaMB      = if ($null -ne $preWudfPrivMb -and $null -ne $postWudfPrivMb) { [Math]::Round(($postWudfPrivMb - $preWudfPrivMb), 2) } else { $null }
        HostResourceUsage       = if ($null -ne $primaryEvalSummary) { Get-LumaBridgeValidationOptionalProp $primaryEvalSummary 'ResourceUsage' $null } else { $null }
        GpuUtilization          = $gpuUtilSample
    }

    $acceptanceCriteria = [pscustomobject]@{
        CmProbNone                      = $cmProbNone
        AdapterInitFinishedOk           = $adapterInitFinishedOk
        VirtualMonitorActive            = $virtualMonitorActive
        IpcConnected                    = $ipcConnected
        HostProcessExitedNormally       = $hostExitedNormally
        HostProcessSucceeded            = $hostExitedNormally
        FramesReceived                  = $framesReceived
        FramesValid                     = $framesValid
        HostReceivedFrames              = ($framesValid -ge 1)
        FrameTargetReached              = $(if ($null -ne $perfSummary) { $perfTargetReachedFlag } else { $frameTargetReached })
        FunctionalSmokePassed           = $functionalSmokePassed
        PerformanceTestExecuted         = $perfExecuted
        PerformanceTargetReached        = $perfTargetReached
        Benchmark30sExecuted            = $bench30sExecuted
        Benchmark30sPassed              = $bench30sPassed
        ProlongedStabilityExecuted      = $stabilityExecuted
        ProlongedStabilityPassed        = $stabilityPassed
        ProlongedStabilityProven        = $prolongedStabilityProven
        TransportHealthy                = $transportHealthy
        RealGpuSyncHealthy              = $realGpuSyncHealthy
        GpuSharedPassed                 = $gpuSharedPassed
        NvencPassed                     = $nvencPassed
        H264DecodePassed                = $h264DecodePassed
        StructuralDecodeValidated       = $structuralDecodeValidated
        FidelityPsnrValidated           = $fidelityPsnrValidated
        Crc32Valid                      = $crc32Valid
        SequenceMonotonicityOk          = $seqMonotonicityOk
        TimestampsMonotonicOk           = $timestampsMonotonicOk
        TimestampsValidOk               = $timestampsValidOk
        MeasurableLatenciesOk           = $measurableLatenciesOk
        TemporalCoverageSufficient      = $temporalCoverageSufficient
        SequenceAndTimestampsConsistent = $sequenceAndTimestampsOk
        TimestampMeasurementErrors      = $totalTimestampMeasurementErrors
        CoreTimestampCoveragePercent    = $primaryTemporal.CoreTimestampCoveragePercent
        LiveTimestampCoveragePercent    = $primaryTemporal.LiveTimestampCoveragePercent
        PresentTimestampCoveragePercent = $primaryTemporal.PresentTimestampCoveragePercent
        NvencExtractToBsCoveragePercent = $primaryTemporal.NvencExtractToBsCoveragePercent
        NoUnauthorizedIpcClients        = $noUnauthorizedIpcClients
        NoNewCrashDumps                 = $noNewCrashDumps
        WudfProcessHealthy              = $wudfProcessHealthy
        RollbackClean                   = $false
        AllPassed                       = $allPassed
    }

    if (-not $allPassed) {
        $skipEvalNames = @(
            'AllPassed', 'RollbackClean', 'FramesReceived', 'FramesValid', 'FrameTargetReached',
            'PerformanceTestExecuted', 'PerformanceTargetReached',
            'Benchmark30sExecuted', 'Benchmark30sPassed',
            'ProlongedStabilityExecuted', 'ProlongedStabilityPassed', 'ProlongedStabilityProven',
            'GpuSharedPassed', 'NvencPassed', 'H264DecodePassed',
            'StructuralDecodeValidated', 'FidelityPsnrValidated',
            'TimestampMeasurementErrors', 'CoreTimestampCoveragePercent',
            'LiveTimestampCoveragePercent', 'PresentTimestampCoveragePercent', 'NvencExtractToBsCoveragePercent'
        )
        $failedFlags = @($acceptanceCriteria.PSObject.Properties | Where-Object { $_.Name -notin $skipEvalNames -and -not [bool]$_.Value } | ForEach-Object { $_.Name })
        if ($runPerfProfile -and -not $perfTargetReached) {
            $failedFlags += 'PerformanceTargetReached'
        }
        if ($runBenchmark30sProfile -and -not $bench30sPassed) {
            $failedFlags += 'Benchmark30sPassed'
        }
        if ($runStabilityProfile -and -not $stabilityPassed) {
            $failedFlags += 'ProlongedStabilityPassed'
        }
        if ($RequireGpuShared -and -not $gpuSharedPassed) {
            $failedFlags += 'GpuSharedPassed'
        }
        if ($RequireNvenc -and -not $nvencPassed) {
            $failedFlags += 'NvencPassed'
        }
        if ($VerifyH264Decode -and -not $h264DecodePassed) {
            $failedFlags += 'H264DecodePassed'
        }
        throw ("Functional validation acceptance criteria not satisfied: {0}" -f (($failedFlags | Select-Object -Unique) -join ', '))
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
            $msg = ("Failed stopping ETW session in finally: {0}" -f $_.Exception.Message)
            $rollbackActions.Add($msg)
            $rollbackIncompleteReasons.Add($msg)
        }
    }

    if ($null -ne $targetInstance) {
        if ($modifiedExtraction) {
            try {
                Set-LumaBridgeDeviceEnableFrameExtraction -DeviceParametersPath $targetInstance.DeviceParametersPath -Value 0
                $rollbackActions.Add(("Reverted EnableFrameExtraction=0 on '{0}'" -f $targetInstance.InstanceId))
            }
            catch {
                $msg = ("Failed reverting EnableFrameExtraction=0 on '{0}': {1}" -f $targetInstance.InstanceId, $_.Exception.Message)
                $rollbackActions.Add($msg)
                $rollbackIncompleteReasons.Add($msg)
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
                $msg = ("Failed reverting AuthorizedHostUserSid on '{0}': {1}" -f $targetInstance.InstanceId, $_.Exception.Message)
                $rollbackActions.Add($msg)
                $rollbackIncompleteReasons.Add($msg)
            }
        }

        if ($modifiedGpuTrans) {
            try {
                if ($null -eq $hadPreExistingGpuTrans) {
                    Set-LumaBridgeDeviceEnableGpuSharedTransport -DeviceParametersPath $targetInstance.DeviceParametersPath -Clear
                    $rollbackActions.Add(("Cleared temporary EnableGpuSharedTransport on '{0}'" -f $targetInstance.InstanceId))
                }
                else {
                    Set-LumaBridgeDeviceEnableGpuSharedTransport -DeviceParametersPath $targetInstance.DeviceParametersPath -Value ([int]$hadPreExistingGpuTrans)
                    $rollbackActions.Add(("Restored prior EnableGpuSharedTransport={0} on '{1}'" -f [int]$hadPreExistingGpuTrans, $targetInstance.InstanceId))
                }
            }
            catch {
                $msg = ("Failed reverting EnableGpuSharedTransport on '{0}': {1}" -f $targetInstance.InstanceId, $_.Exception.Message)
                $rollbackActions.Add($msg)
                $rollbackIncompleteReasons.Add($msg)
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
                $msg = ("Uninstall-LumaBridgeDriver.ps1 failed in finally: {0}" -f $_.Exception.Message)
                $rollbackActions.Add($msg)
                $rollbackIncompleteReasons.Add($msg)
            }
        }
        else {
            if ($modifiedVirtMon -and -not $hadPreExistingVirtMon) {
                try {
                    Set-LumaBridgeDeviceEnableVirtualMonitor -DeviceParametersPath $targetInstance.DeviceParametersPath -Value 0
                    $rollbackActions.Add(("Reverted EnableVirtualMonitor=0 on '{0}'" -f $targetInstance.InstanceId))
                }
                catch {
                    $msg = ("Failed reverting EnableVirtualMonitor=0 on '{0}': {1}" -f $targetInstance.InstanceId, $_.Exception.Message)
                    $rollbackActions.Add($msg)
                    $rollbackIncompleteReasons.Add($msg)
                }
            }

            if ($modifiedExtraction -or $modifiedAuthSid -or $modifiedGpuTrans -or ($modifiedVirtMon -and -not $hadPreExistingVirtMon)) {
                try {
                    $null = Invoke-LumaBridgeExternalCommand -FilePath 'pnputil.exe' -Arguments @('/restart-device', $targetInstance.InstanceId)
                    $rollbackActions.Add(("Restarted device '{0}' to apply rolled-back parameters" -f $targetInstance.InstanceId))
                }
                catch {
                    $msg = ("Failed restarting device '{0}' in finally: {1}" -f $targetInstance.InstanceId, $_.Exception.Message)
                    $rollbackActions.Add($msg)
                    $rollbackIncompleteReasons.Add($msg)
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
            $msg = ("Fallback Uninstall-LumaBridgeDriver.ps1 failed in finally: {0}" -f $_.Exception.Message)
            $rollbackActions.Add($msg)
            $rollbackIncompleteReasons.Add($msg)
        }
    }

    try {
        $postRollbackInstances = @(Get-LumaBridgePnpInstances)
        if ($FullUninstallOnExit -or ($didFreshDriverInstall -and -not $driverInstallCompleted)) {
            $rollbackClean = ($postRollbackInstances.Count -eq 0) -and ($rollbackIncompleteReasons.Count -eq 0)
            if ($postRollbackInstances.Count -ne 0) {
                $rollbackIncompleteReasons.Add(("Expected 0 PnP instances after full uninstall, found {0}" -f $postRollbackInstances.Count))
            }
        }
        elseif ($postRollbackInstances.Count -eq 1) {
            $rbInst = $postRollbackInstances[0]
            $extReset = ($null -eq $rbInst.EnableFrameExtraction -or [int]$rbInst.EnableFrameExtraction -eq 0)
            $monReset = ($hadPreExistingVirtMon -or $null -eq $rbInst.EnableVirtualMonitor -or [int]$rbInst.EnableVirtualMonitor -eq 0)
            $sidReset = if ([string]::IsNullOrWhiteSpace($hadPreExistingAuthSid)) {
                [string]::IsNullOrWhiteSpace((Get-LumaBridgeValidationOptionalProp -InputObject $rbInst -PropertyName 'AuthorizedHostUserSid' -DefaultValue ''))
            }
            else {
                (Get-LumaBridgeValidationOptionalProp -InputObject $rbInst -PropertyName 'AuthorizedHostUserSid' -DefaultValue '') -eq $hadPreExistingAuthSid
            }
            $rbGpuTrans = Get-LumaBridgeValidationOptionalProp -InputObject $rbInst -PropertyName 'EnableGpuSharedTransport' -DefaultValue $null
            $gpuTransReset = if (-not $modifiedGpuTrans) {
                $true
            }
            elseif ($null -eq $hadPreExistingGpuTrans) {
                ($null -eq $rbGpuTrans)
            }
            else {
                ($null -ne $rbGpuTrans -and [int]$rbGpuTrans -eq [int]$hadPreExistingGpuTrans)
            }
            $devHealthy = ($rbInst.Status -ieq 'OK' -and ($null -eq $rbInst.ProblemCode -or [int]$rbInst.ProblemCode -eq 0))
            if (-not $extReset) { $rollbackIncompleteReasons.Add(("EnableFrameExtraction remained {0} after rollback" -f $rbInst.EnableFrameExtraction)) }
            if (-not $monReset) { $rollbackIncompleteReasons.Add(("EnableVirtualMonitor remained {0} after rollback" -f $rbInst.EnableVirtualMonitor)) }
            if (-not $sidReset) { $rollbackIncompleteReasons.Add('AuthorizedHostUserSid did not match pre-validation value after rollback') }
            if (-not $gpuTransReset) { $rollbackIncompleteReasons.Add('EnableGpuSharedTransport did not match pre-validation value after rollback') }
            if (-not $devHealthy) { $rollbackIncompleteReasons.Add(("Post-rollback device unhealthy (Status='{0}', ProblemCode={1})" -f $rbInst.Status, $rbInst.ProblemCode)) }
            $rollbackClean = ($extReset -and $monReset -and $sidReset -and $gpuTransReset -and $devHealthy -and ($rollbackIncompleteReasons.Count -eq 0))
        }
        else {
            $rollbackClean = ($null -eq $preExistingInstance) -and ($rollbackIncompleteReasons.Count -eq 0)
            if ($null -ne $preExistingInstance) {
                $rollbackIncompleteReasons.Add(("Pre-existing PnP instance '{0}' missing after rollback" -f $preExistingInstance.InstanceId))
            }
        }
    }
    catch {
        $rollbackClean = $false
        $rollbackIncompleteReasons.Add(("Post-rollback verification failed: {0}" -f $_.Exception.Message))
    }

    if ($null -ne $acceptanceCriteria) {
        $acceptanceCriteria.RollbackClean = $rollbackClean
    }

    $reportPayload = [pscustomobject]@{
        CompletedAtUtc            = (Get-Date).ToUniversalTime().ToString('o')
        Configuration             = $Configuration
        TestProfile               = $TestProfile
        Branch                    = $currentBranch
        PreValidationState        = $preValidationState
        SignedStagingDir          = $signedStagingDir
        CertificateThumbprint     = $signedThumbprint
        AuthorizedHostUserSid     = $effectiveAuthorizedUserSid
        PreBuildHashes            = $preBuildHashes
        PostSignBuildHashes       = $postSignBuildHashes
        PackageVerified           = [bool]$packageVerify.SignerCertificatesMatch
        InstalledBindingCheck     = $installedBindingCheck
        EtwVerifyResult           = $etwVerifyResult
        SmokeHostProcessResult    = $smokeHostResult
        SmokeHostSummary          = $smokeSummary
        PerfHostProcessResult     = $perfHostResult
        PerfHostSummary           = $perfSummary
        Benchmark30sProcessResult = $bench30sHostResult
        Benchmark30sHostSummary   = $bench30sSummary
        StabilityProcessResult    = $stabilityHostResult
        StabilityHostSummary      = $stabilitySummary
        SyntheticFidelityResult   = $syntheticFidelityResult
        ProcessResourceSummary    = $processResourceSummary
        HostProcessResult         = $hostProcResult
        HostSummary               = $hostSummary
        AcceptanceCriteria        = $acceptanceCriteria
        ValidationSucceeded       = ([string]::IsNullOrWhiteSpace($validationError))
        ValidationError           = $validationError
        RollbackScopeNote         = $rollbackScopeNote
        RollbackActions           = @($rollbackActions.ToArray())
        RollbackIncompleteReasons = @($rollbackIncompleteReasons.ToArray())
        RollbackClean             = $rollbackClean
        PostRollbackInstances     = $postRollbackInstances
        OutputDir                 = $OutputDir
    }

    try {
        if (-not (Test-Path -LiteralPath $OutputDir)) {
            $null = New-Item -Path $OutputDir -ItemType Directory -Force
        }
        $reportPayload | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $reportJsonPath -Encoding UTF8

        $mdLines = New-Object System.Collections.Generic.List[string]
        $mdLines.Add('# LumaBridge M4.2.1 Functional Validation Report')
        $mdLines.Add('')
        $mdLines.Add(("- Completed UTC: ``{0}``" -f $reportPayload.CompletedAtUtc))
        $mdLines.Add(("- Branch: ``{0}`` | Configuration: ``{1}`` | Profile: ``{2}``" -f $currentBranch, $Configuration, $TestProfile))
        $mdLines.Add(("- Staged Package (``StagingDir``): ``{0}``" -f $signedStagingDir))
        $mdLines.Add(("- Validation Succeeded: ``{0}`` | Rollback Clean: ``{1}``" -f $reportPayload.ValidationSucceeded, $rollbackClean))
        $mdLines.Add(("- Rollback Scope: {0}" -f $rollbackScopeNote))
        if (-not [string]::IsNullOrWhiteSpace($validationError)) {
            $mdLines.Add(("- Error: ``{0}``" -f $validationError))
        }
        if ($null -ne $smokeSummary) {
            $mdLines.Add(("- Smoke Host: ExitReason=``{0}``, Frames=``{1}``, Valid=``{2}``, Live=``{3}``, PreConn=``{4}``, ExecFps=``{5}``, TransportHealthy=``{6}``, TsErrors=``{7}``" -f `
                (Get-LumaBridgeValidationOptionalProp $smokeSummary 'ExitReason' 'Unknown'), `
                $smokeSummary.FramesReceived, `
                (Get-LumaBridgeValidationOptionalProp $smokeSummary 'FramesValid' $smokeSummary.FramesReceived), `
                (Get-LumaBridgeValidationOptionalProp $smokeSummary 'LiveFramesReceived' 0), `
                (Get-LumaBridgeValidationOptionalProp $smokeSummary 'PreConnectFramesReceived' 0), `
                (Get-LumaBridgeValidationOptionalProp $smokeSummary 'AverageExecutionFps' $smokeSummary.ReceiveFps), `
                (Get-LumaBridgeValidationOptionalProp $smokeSummary 'TransportHealthy' $false), `
                (Get-LumaBridgeValidationOptionalProp $smokeSummary 'TimestampMeasurementErrors' 0)))
        }
        if ($null -ne $perfSummary) {
            $mdLines.Add(("- Performance Host: ExitReason=``{0}``, Frames=``{1}``, TargetReached=``{2}``, ActiveFps=``{3}``, LiveFps=``{4}``, LiveE2EAvgUs=``{5}``, TsErrors=``{6}``" -f `
                (Get-LumaBridgeValidationOptionalProp $perfSummary 'ExitReason' 'Unknown'), `
                $perfSummary.FramesReceived, `
                (Get-LumaBridgeValidationOptionalProp $perfSummary 'FrameTargetReached' $false), `
                (Get-LumaBridgeValidationOptionalProp $perfSummary 'ObservedActiveFps' $perfSummary.ReceiveFps), `
                (Get-LumaBridgeValidationOptionalProp $perfSummary 'SustainedLiveFps' 0), `
                $perfSummary.AvgEndToEndLatencyUs, `
                (Get-LumaBridgeValidationOptionalProp $perfSummary 'TimestampMeasurementErrors' 0)))
        }
        if ($null -ne $bench30sSummary) {
            $mdLines.Add(("- Benchmark 30s Host: FramesValid=``{0}``, LiveFps=``{1}``, CoreCov=``{2}%``, LiveCov=``{3}%``, TsErrors=``{4}``" -f `
                (Get-LumaBridgeValidationOptionalProp $bench30sSummary 'FramesValid' 0), `
                (Get-LumaBridgeValidationOptionalProp $bench30sSummary 'SustainedLiveFps' 0), `
                (Get-LumaBridgeValidationOptionalProp $bench30sSummary 'CoreTimestampCoveragePercent' 0), `
                (Get-LumaBridgeValidationOptionalProp $bench30sSummary 'LiveTimestampCoveragePercent' 0), `
                (Get-LumaBridgeValidationOptionalProp $bench30sSummary 'TimestampMeasurementErrors' 0)))
        }
        if ($null -ne $stabilitySummary) {
            $mdLines.Add(("- Prolonged Stability Host: FramesValid=``{0}``, LiveFps=``{1}``, CoreCov=``{2}%``, LiveCov=``{3}%``, TsErrors=``{4}``" -f `
                (Get-LumaBridgeValidationOptionalProp $stabilitySummary 'FramesValid' 0), `
                (Get-LumaBridgeValidationOptionalProp $stabilitySummary 'SustainedLiveFps' 0), `
                (Get-LumaBridgeValidationOptionalProp $stabilitySummary 'CoreTimestampCoveragePercent' 0), `
                (Get-LumaBridgeValidationOptionalProp $stabilitySummary 'LiveTimestampCoveragePercent' 0), `
                (Get-LumaBridgeValidationOptionalProp $stabilitySummary 'TimestampMeasurementErrors' 0)))
        }
        if ($null -ne $acceptanceCriteria) {
            $mdLines.Add(("- Acceptance: StructuralDecode=``{0}``, FidelityPSNR=``{1}``, ProlongedStabilityProven=``{2}``" -f `
                $acceptanceCriteria.StructuralDecodeValidated, $acceptanceCriteria.FidelityPsnrValidated, $acceptanceCriteria.ProlongedStabilityProven))
        }
        $mdLines.Add('')
        $mdLines.Add('## Rollback Actions')
        foreach ($act in $rollbackActions) {
            $mdLines.Add(("- {0}" -f $act))
        }
        if ($rollbackIncompleteReasons.Count -gt 0) {
            $mdLines.Add('')
            $mdLines.Add('## Rollback Incomplete Reasons')
            foreach ($inc in $rollbackIncompleteReasons) {
                $mdLines.Add(("- {0}" -f $inc))
            }
        }
        $mdLines | Set-Content -LiteralPath $reportMdPath -Encoding UTF8
    }
    catch {
    }
}

if (-not [string]::IsNullOrWhiteSpace($validationError)) {
    throw ("LumaBridge M4.1.1 functional validation failed: {0}. RollbackClean={1}. Report='{2}'." -f $validationError, $rollbackClean, $reportJsonPath)
}

return [pscustomobject]@{
    ValidationSucceeded       = $true
    RollbackClean             = $rollbackClean
    RollbackIncompleteReasons = @($rollbackIncompleteReasons.ToArray())
    RollbackScopeNote         = $rollbackScopeNote
    Configuration             = $Configuration
    TestProfile               = $TestProfile
    Branch                    = $currentBranch
    StagingDir                = $signedStagingDir
    OutputDir                 = $OutputDir
    ReportJsonPath            = $reportJsonPath
    ReportMdPath              = $reportMdPath
    HostSummaryPath           = $hostJsonPath
    SmokeSummaryPath          = $hostSmokeJsonPath
    PerfSummaryPath           = $hostPerfJsonPath
    Benchmark30sSummaryPath   = $hostBench30sJsonPath
    StabilitySummaryPath      = $hostStabilityJsonPath
    SmokeSummary              = $smokeSummary
    PerfSummary               = $perfSummary
    Benchmark30sSummary       = $bench30sSummary
    StabilitySummary          = $stabilitySummary
    ProcessResourceSummary    = $processResourceSummary
    HostSummary               = $hostSummary
    AcceptanceCriteria        = $acceptanceCriteria
    DiagnosticsResult         = $diagResult
    RollbackActions           = @($rollbackActions.ToArray())
    PostRollbackInstances     = $postRollbackInstances
}
