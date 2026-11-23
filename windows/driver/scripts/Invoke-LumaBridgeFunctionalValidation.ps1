<#
.SYNOPSIS
    Executes the end-to-end Windows 11 functional validation workflow for LumaBridgeIddDriver
    (M4.1/M4.1.1 real D3D11 frame extraction + M4.2/M4.2.1 GPU Shared Textures + NVENC H.264)
    with explicit separation between Smoke, Performance, 30s 1080p60 Benchmark, and
    Prolonged Stability profiles, independent per-subprofile acceptance gates, strict
    WUDFHost.exe correlation, continuous resource telemetry, RunId/stale-JSON guards,
    causal timestamp telemetry checks, and guaranteed non-masking finally rollback.
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
    [int]$StabilityDurationSec = 180,

    [ValidateRange(1, 120)]
    [int]$StimulusFps = 60,

    [string]$StimulusDisplayName,

    [ValidateRange(500, 300000)]
    [int]$ConnectTimeoutMs = 5000,

    [ValidateRange(50, 5000)]
    [int]$IoTimeoutMs = 500,

    [ValidateRange(1000, 4200000)]
    [int]$HostHardTimeoutMs = 30000,

    [ValidateRange(0.5, 1.0)]
    [double]$MinBenchmarkFrameRatio = 0.98,

    [ValidateRange(0.5, 1.0)]
    [double]$MinSustainedFpsRatio = 0.95,

    [ValidateRange(0.5, 1.0)]
    [double]$MinNvencEncodeRatio = 0.98,

    [ValidateRange(0.0, 0.5)]
    [double]$MaxDropRatio = 0.02,

    [ValidateRange(30, 3600)]
    [int]$MinProlongedStabilitySec = 180,

    [ValidateRange(0, 7680)]
    [int]$ExpectedBenchmarkWidth = 1920,

    [ValidateRange(0, 4320)]
    [int]$ExpectedBenchmarkHeight = 1080,

    [ValidateRange(1, 120)]
    [int]$ExpectedBenchmarkStimulusFps = 60,

    [ValidateRange(1, 60)]
    [int]$ResourceSampleIntervalSec = 5,

    [ValidateRange(0, 4096)]
    [int]$CoreEtwMaxFileSizeMb = 0,

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
            TruncatedLatencyMetrics         = @()
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

    $truncatedList = New-Object System.Collections.Generic.List[object]
    foreach ($metricName in @('EndToEndLatency', 'LiveEndToEndLatency', 'IpcTransitLatency', 'InterFrameInterval', 'InterFrameJitter')) {
        $mObj = Get-LumaBridgeValidationOptionalProp $Summary $metricName $null
        if ($null -ne $mObj) {
            $isTrunc = [bool](Get-LumaBridgeValidationOptionalProp $mObj 'SamplesTruncated' $false)
            if ($isTrunc) {
                $truncatedList.Add([pscustomobject]@{
                    MetricName        = $metricName
                    SampleCount       = [uint64](Get-LumaBridgeValidationOptionalProp $mObj 'SampleCount' 0)
                    StoredSampleCount = [uint64](Get-LumaBridgeValidationOptionalProp $mObj 'StoredSampleCount' 0)
                    ReservoirSampled  = [bool](Get-LumaBridgeValidationOptionalProp $mObj 'ReservoirSampled' $false)
                })
            }
        }
    }

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
        TruncatedLatencyMetrics         = @($truncatedList.ToArray())
    }
}

function Read-LumaBridgeValidatedHostSummary {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$JsonPath,

        [Parameter(Mandatory = $true)]
        [string]$ExpectedRunId,

        [Parameter(Mandatory = $true)]
        [DateTime]$LaunchStartUtc
    )

    if (-not (Test-Path -LiteralPath $JsonPath -PathType Leaf)) {
        return [pscustomobject]@{
            IsValid = $false
            Status  = 'MISSING'
            Summary = $null
            Reason  = ("Expected host JSON summary file was not created: '{0}'." -f $JsonPath)
        }
    }

    try {
        $fileItem = Get-Item -LiteralPath $JsonPath -ErrorAction Stop
        if ($fileItem.LastWriteTimeUtc -lt $LaunchStartUtc.AddSeconds(-2)) {
            return [pscustomobject]@{
                IsValid = $false
                Status  = 'STALE_TIMESTAMP'
                Summary = $null
                Reason  = ("Host JSON summary '{0}' LastWriteTimeUtc ({1}) predates subprofile launch ({2})." -f $JsonPath, $fileItem.LastWriteTimeUtc.ToString('o'), $LaunchStartUtc.ToString('o'))
            }
        }
    }
    catch {
        return [pscustomobject]@{
            IsValid = $false
            Status  = 'STAT_FAILED'
            Summary = $null
            Reason  = ("Failed inspecting host JSON summary timestamp '{0}': {1}" -f $JsonPath, $_.Exception.Message)
        }
    }

    $rawText = $null
    $parsed = $null
    try {
        $rawText = Get-Content -LiteralPath $JsonPath -Raw -ErrorAction Stop
        if ([string]::IsNullOrWhiteSpace($rawText)) {
            throw 'Summary file is empty.'
        }
        $parsed = $rawText | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        return [pscustomobject]@{
            IsValid = $false
            Status  = 'INVALID_JSON'
            Summary = $null
            Reason  = ("Failed parsing host JSON summary '{0}': {1}" -f $JsonPath, $_.Exception.Message)
        }
    }

    if ($null -eq $parsed) {
        return [pscustomobject]@{
            IsValid = $false
            Status  = 'INCOMPLETE_SUMMARY'
            Summary = $null
            Reason  = ("Host JSON summary '{0}' parsed to null." -f $JsonPath)
        }
    }

    $observedRunId = [string](Get-LumaBridgeValidationOptionalProp $parsed 'RunId' '')
    if ([string]::IsNullOrWhiteSpace($observedRunId)) {
        return [pscustomobject]@{
            IsValid = $false
            Status  = 'MISSING_RUN_ID'
            Summary = $null
            Reason  = ("Host JSON summary '{0}' is missing required RunId (expected '{1}')." -f $JsonPath, $ExpectedRunId)
        }
    }
    if ($observedRunId -cne $ExpectedRunId) {
        return [pscustomobject]@{
            IsValid = $false
            Status  = 'RUN_ID_MISMATCH'
            Summary = $null
            Reason  = ("Host JSON summary '{0}' belongs to foreign RunId '{1}' (expected '{2}')." -f $JsonPath, $observedRunId, $ExpectedRunId)
        }
    }

    if ($parsed.PSObject.Properties.Name -contains 'SummaryComplete' -and (-not [bool]$parsed.SummaryComplete)) {
        return [pscustomobject]@{
            IsValid = $false
            Status  = 'INCOMPLETE_SUMMARY'
            Summary = $null
            Reason  = ("Host JSON summary '{0}' marked SummaryComplete=false." -f $JsonPath)
        }
    }

    foreach ($reqProp in @('HostProcessExitedNormally', 'TransportHealthy', 'FramesReceived', 'TimestampMeasurementErrors')) {
        if (-not ($parsed.PSObject.Properties.Name -contains $reqProp)) {
            return [pscustomobject]@{
                IsValid = $false
                Status  = 'INCOMPLETE_SUMMARY'
                Summary = $null
                Reason  = ("Host JSON summary '{0}' is missing mandatory field '{1}'." -f $JsonPath, $reqProp)
            }
        }
    }

    return [pscustomobject]@{
        IsValid = $true
        Status  = 'VALID'
        Summary = $parsed
        Reason  = 'Validated RunId, timestamp freshness, JSON schema, and completeness.'
    }
}

function Test-LumaBridgeSubprofileGates {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('Smoke', 'Performance', 'Benchmark30s', 'ProlongedStability')]
        [string]$SubprofileName,

        $ValidationResult,

        $ProcessResult,

        [switch]$RequireGpuShared,

        [switch]$RequireNvenc,

        [switch]$VerifyH264Decode,

        [uint64]$SmokeMinFrames = 1,

        [uint64]$PerformanceTargetFrames = 60,

        [int]$ExpectedDurationSec = 0,

        [int]$StimulusFps = 60,

        [int]$ExpectedStimulusFps = 60,

        [int]$ExpectedWidth = 1920,

        [int]$ExpectedHeight = 1080,

        [double]$MinFrameRatio = 0.98,

        [double]$MinSustainedFpsRatio = 0.95,

        [double]$MinNvencEncodeRatio = 0.98,

        [double]$MaxDropRatio = 0.02
    )

    $reasons = New-Object System.Collections.Generic.List[string]
    $summary = if ($null -ne $ValidationResult -and $ValidationResult.IsValid) { $ValidationResult.Summary } else { $null }
    $summaryValid = ($null -ne $ValidationResult -and $ValidationResult.IsValid -and $null -ne $summary)
    if (-not $summaryValid) {
        $reasons.Add($(if ($null -ne $ValidationResult) { $ValidationResult.Reason } else { 'Subprofile summary missing.' }))
    }

    $procExitedOk = ($null -ne $ProcessResult -and (-not [bool]$ProcessResult.TimedOut) -and ([int]$ProcessResult.ExitCode -eq 0))
    if (-not $procExitedOk) {
        $reasons.Add(("Process did not exit cleanly (TimedOut={0}, ExitCode={1})." -f $(if ($null -ne $ProcessResult) { $ProcessResult.TimedOut } else { $null }), $(if ($null -ne $ProcessResult) { $ProcessResult.ExitCode } else { $null })))
    }

    $hostExitedNormally = if ($summaryValid) { [bool](Get-LumaBridgeValidationOptionalProp $summary 'HostProcessExitedNormally' $false) } else { $false }
    $hostTransportHealthy = if ($summaryValid) { [bool](Get-LumaBridgeValidationOptionalProp $summary 'TransportHealthy' $false) } else { $false }
    $connectCount = if ($summaryValid) { [uint64](Get-LumaBridgeValidationOptionalProp $summary 'ConnectCount' 0) } else { [uint64]0 }
    $framesReceived = if ($summaryValid) { [uint64](Get-LumaBridgeValidationOptionalProp $summary 'FramesReceived' 0) } else { [uint64]0 }
    $framesValid = if ($summaryValid) { [uint64](Get-LumaBridgeValidationOptionalProp $summary 'FramesValid' 0) } else { [uint64]0 }
    $checksumMismatches = if ($summaryValid) { [uint64](Get-LumaBridgeValidationOptionalProp $summary 'ChecksumMismatches' 1) } else { [uint64]1 }
    $syntheticMismatches = if ($summaryValid) { [uint64](Get-LumaBridgeValidationOptionalProp $summary 'SyntheticPatternMismatches' 0) } else { [uint64]0 }
    $protocolErrors = if ($summaryValid) { [uint64](Get-LumaBridgeValidationOptionalProp $summary 'ProtocolErrors' 1) } else { [uint64]1 }
    $fatalIoTimeouts = if ($summaryValid) { [uint64](Get-LumaBridgeValidationOptionalProp $summary 'FatalIoTimeouts' 0) } else { [uint64]0 }
    $fatalIpcErrors = if ($summaryValid) { [uint64](Get-LumaBridgeValidationOptionalProp $summary 'FatalIpcErrors' 0) } else { [uint64]0 }
    $lastProtocolStatus = if ($summaryValid) { [string](Get-LumaBridgeValidationOptionalProp $summary 'LastProtocolStatus' 'Unknown') } else { 'Missing' }
    $frameTargetReached = if ($summaryValid) { [bool](Get-LumaBridgeValidationOptionalProp $summary 'FrameTargetReached' $false) } else { $false }

    $ipcOk = ($connectCount -ge 1) -and $hostExitedNormally -and $hostTransportHealthy -and
        ($checksumMismatches -eq 0) -and ($syntheticMismatches -eq 0) -and
        ($protocolErrors -eq 0) -and ($fatalIoTimeouts -eq 0) -and ($fatalIpcErrors -eq 0) -and
        ($lastProtocolStatus -ne 'UnauthorizedClient')
    if ($summaryValid -and -not $ipcOk) {
        $reasons.Add(("IPC/Integrity failure (Connects={0}, Healthy={1}, CRC={2}, ProtoErr={3}, Status={4})." -f $connectCount, $hostTransportHealthy, $checksumMismatches, $protocolErrors, $lastProtocolStatus))
    }

    $temporalEval = Test-LumaBridgeTemporalTelemetry -Summary $summary
    if ($summaryValid -and -not $temporalEval.SequenceAndTimestampsConsistent) {
        $reasons.Add(("Temporal telemetry gate failed (TsErr={0}, CoreCov={1}%, LiveCov={2}%, MonoSeq={3}, MonoTs={4})." -f $temporalEval.TimestampMeasurementErrors, $temporalEval.CoreTimestampCoveragePercent, $temporalEval.LiveTimestampCoveragePercent, $temporalEval.SequenceMonotonicityOk, $temporalEval.TimestampsMonotonicOk))
    }

    $gpuMode = if ($summaryValid) { [string](Get-LumaBridgeValidationOptionalProp $summary 'NegotiatedTransportMode' 'CpuStagingPipe') } else { 'CpuStagingPipe' }
    $gpuFallback = if ($summaryValid) { [bool](Get-LumaBridgeValidationOptionalProp $summary 'FallbackToCpuActivated' $false) } else { $false }
    $gpuOpened = if ($summaryValid) { [uint64](Get-LumaBridgeValidationOptionalProp $summary 'GpuFramesOpened' 0) } else { [uint64]0 }
    $gpuDropped = if ($summaryValid) { [uint64](Get-LumaBridgeValidationOptionalProp $summary 'GpuFramesDropped' 0) } else { [uint64]0 }
    $gpuOpenFail = if ($summaryValid) { [uint64](Get-LumaBridgeValidationOptionalProp $summary 'GpuSharedOpenFailures' 0) } else { [uint64]0 }
    $gpuSyncTo = if ($summaryValid) { [uint64](Get-LumaBridgeValidationOptionalProp $summary 'GpuSyncTimeouts' 0) } else { [uint64]0 }
    $gpuLuidErr = if ($summaryValid) { [uint64](Get-LumaBridgeValidationOptionalProp $summary 'AdapterMismatchErrors' 0) } else { [uint64]0 }
    $cpuReads = if ($summaryValid) { [uint64](Get-LumaBridgeValidationOptionalProp $summary 'CpuStagingReadsPerformed' 0) } else { [uint64]0 }

    $gpuTotalAttempts = $gpuOpened + $gpuDropped
    $gpuDropRatio = if ($gpuTotalAttempts -gt 0) { [double]$gpuDropped / [double]$gpuTotalAttempts } else { 0.0 }
    $gpuSharedPassed = (
        $summaryValid -and
        ($gpuMode -eq 'GpuSharedNtHandle') -and
        (-not $gpuFallback) -and
        ($gpuOpened -ge 1) -and
        ($gpuOpenFail -eq 0) -and
        ($gpuSyncTo -eq 0) -and
        ($gpuLuidErr -eq 0) -and
        ($cpuReads -eq 0) -and
        ($gpuDropRatio -le $MaxDropRatio)
    )
    if ($RequireGpuShared -and $summaryValid -and -not $gpuSharedPassed) {
        $reasons.Add(("GpuShared gate failed (Mode={0}, Fallback={1}, Opened={2}, GpuDrop={3}, OpenFail={4}, SyncTo={5}, LuidErr={6}, CpuReads={7})." -f $gpuMode, $gpuFallback, $gpuOpened, $gpuDropped, $gpuOpenFail, $gpuSyncTo, $gpuLuidErr, $cpuReads))
    }

    $durationUs = if ($summaryValid) {
        $connUs = [uint64](Get-LumaBridgeValidationOptionalProp $summary 'TotalConnectedDurationUs' 0)
        if ($connUs -gt 0) { $connUs } else { [uint64](Get-LumaBridgeValidationOptionalProp $summary 'TotalExecutionDurationUs' 0) }
    }
    else { [uint64]0 }
    $measuredSec = [double]$durationUs / 1000000.0

    $nvencObj = if ($summaryValid) { Get-LumaBridgeValidationOptionalProp $summary 'Nvenc' $null } else { $null }
    $nvSubmitted = if ($null -ne $nvencObj) { [uint64](Get-LumaBridgeValidationOptionalProp $nvencObj 'NvencFramesSubmitted' 0) } else { [uint64]0 }
    $nvEncoded = if ($null -ne $nvencObj) { [uint64](Get-LumaBridgeValidationOptionalProp $nvencObj 'NvencFramesEncoded' 0) } else { [uint64]0 }
    $nvDropped = if ($null -ne $nvencObj) { [uint64](Get-LumaBridgeValidationOptionalProp $nvencObj 'NvencDroppedFrames' 0) } else { [uint64]0 }
    $nvQueueDrops = if ($null -ne $nvencObj) { [uint64](Get-LumaBridgeValidationOptionalProp $nvencObj 'EncodedQueueDrops' 0) } else { [uint64]0 }
    $nvBytes = if ($null -ne $nvencObj) { [uint64](Get-LumaBridgeValidationOptionalProp $nvencObj 'TotalBitstreamBytes' 0) } else { [uint64]0 }
    $nvOutFpsRaw = if ($null -ne $nvencObj) { Get-LumaBridgeValidationOptionalProp $nvencObj 'EncoderOutputFps' $null } else { $null }
    $nvOutFps = if ($null -ne $nvOutFpsRaw) { [double]$nvOutFpsRaw } elseif ($measuredSec -gt 0.0) { [double]$nvEncoded / $measuredSec } else { 0.0 }
    $nvWidth = if ($null -ne $nvencObj) { [uint32](Get-LumaBridgeValidationOptionalProp $nvencObj 'Width' 0) } else { [uint32]0 }
    $nvHeight = if ($null -ne $nvencObj) { [uint32](Get-LumaBridgeValidationOptionalProp $nvencObj 'Height' 0) } else { [uint32]0 }
    $nvInitialized = if ($null -ne $nvencObj) { [bool](Get-LumaBridgeValidationOptionalProp $nvencObj 'Initialized' $true) } else { $false }

    $nvEncodeRatio = if ($framesValid -gt 0) { [double]$nvEncoded / [double]$framesValid } else { 0.0 }
    $totalNvDrops = $nvDropped + $nvQueueDrops
    $nvDropDenom = if ($nvSubmitted -gt 0) { $nvSubmitted } else { $framesValid }
    $nvDropRatio = if ($nvDropDenom -gt 0) { [double]$totalNvDrops / [double]$nvDropDenom } else { 1.0 }
    $minEncodedExpected = if ($SubprofileName -eq 'Smoke' -and $framesValid -le 1) {
        [uint64]1
    }
    else {
        [uint64][Math]::Max(1, [int64][Math]::Floor([double]$framesValid * $MinNvencEncodeRatio))
    }
    $nvOutFpsOk = ($SubprofileName -notin @('Benchmark30s', 'ProlongedStability')) -or ($nvOutFps -ge ([double]$StimulusFps * $MinSustainedFpsRatio))

    $nvencPassed = (
        $summaryValid -and
        ($nvEncoded -ge $minEncodedExpected) -and
        ($nvBytes -ge 1) -and
        (($SubprofileName -eq 'Smoke' -and $framesValid -le 1) -or ($nvEncodeRatio -ge $MinNvencEncodeRatio)) -and
        ($nvDropRatio -le $MaxDropRatio) -and
        $nvOutFpsOk
    )
    if ($RequireNvenc -and $summaryValid -and -not $nvencPassed) {
        $reasons.Add(("NVENC gate failed (Encoded={0}/{1}, Ratio={2:P1}, Drops={3}/{4}, Bytes={5}, OutputFps={6:F2})." -f $nvEncoded, $framesValid, $nvEncodeRatio, $totalNvDrops, $nvDropDenom, $nvBytes, $nvOutFps))
    }

    $h264Obj = if ($summaryValid) { Get-LumaBridgeValidationOptionalProp $summary 'H264DecodeValidation' $null } else { $null }
    $h264Flag = if ($null -ne $h264Obj) { [bool](Get-LumaBridgeValidationOptionalProp $h264Obj 'Passed' $false) } else { $false }
    $h264Struct = if ($null -ne $h264Obj) { [bool](Get-LumaBridgeValidationOptionalProp $h264Obj 'StructuralDecodeValidated' $h264Flag) } else { $false }
    $h264Packets = if ($null -ne $h264Obj) { [uint64](Get-LumaBridgeValidationOptionalProp $h264Obj 'PacketsInspected' $nvEncoded) } else { [uint64]0 }
    $h264Decoded = if ($null -ne $h264Obj) { [uint64](Get-LumaBridgeValidationOptionalProp $h264Obj 'FramesDecoded' $nvEncoded) } else { [uint64]0 }
    $h264NalErr = if ($null -ne $h264Obj) { [uint64](Get-LumaBridgeValidationOptionalProp $h264Obj 'NalParseFailures' 0) } else { [uint64]0 }
    $h264DecErr = if ($null -ne $h264Obj) { [uint64](Get-LumaBridgeValidationOptionalProp $h264Obj 'DecodeFailures' 0) } else { [uint64]0 }
    $h264DecodeRatioOk = ($SubprofileName -notin @('Benchmark30s', 'ProlongedStability')) -or ($h264Packets -eq 0 -and $nvEncoded -eq 0) -or (([double]$h264Decoded / [double][Math]::Max(1, $nvEncoded)) -ge $MinNvencEncodeRatio)
    $h264Passed = ($summaryValid -and $h264Flag -and $h264Struct -and ($h264NalErr -eq 0) -and ($h264DecErr -eq 0) -and ($h264Decoded -ge 1) -and $h264DecodeRatioOk)
    if ($VerifyH264Decode -and $summaryValid -and -not $h264Passed) {
        $reasons.Add(("H264Decode gate failed (Passed={0}, Struct={1}, Decoded={2}/{3}, NalErr={4}, DecErr={5})." -f $h264Flag, $h264Struct, $h264Decoded, $nvEncoded, $h264NalErr, $h264DecErr))
    }

    $frameWidth = if ($summaryValid) { [uint32](Get-LumaBridgeValidationOptionalProp $summary 'LastFrameWidth' 0) } else { [uint32]0 }
    $frameHeight = if ($summaryValid) { [uint32](Get-LumaBridgeValidationOptionalProp $summary 'LastFrameHeight' 0) } else { [uint32]0 }
    $resolutionOk = $true
    if ($SubprofileName -in @('Benchmark30s', 'ProlongedStability')) {
        $dimMatch = ($frameWidth -eq $ExpectedWidth) -and ($frameHeight -eq $ExpectedHeight)
        $nvDimMatch = (-not $RequireNvenc) -or (-not $nvInitialized) -or ($nvWidth -eq 0 -and $nvHeight -eq 0) -or ($nvWidth -eq $ExpectedWidth -and $nvHeight -eq $ExpectedHeight)
        $resolutionOk = ($dimMatch -and $nvDimMatch)
        if ($summaryValid -and -not $resolutionOk) {
            $reasons.Add(("Effective resolution mismatch (Frame={0}x{1}, Nvenc={2}x{3}, Expected={4}x{5})." -f $frameWidth, $frameHeight, $nvWidth, $nvHeight, $ExpectedWidth, $ExpectedHeight))
        }
    }

    $stimObj = if ($summaryValid) { Get-LumaBridgeValidationOptionalProp $summary 'VisualStimulus' $null } else { $null }
    $stimStarted = ($null -ne $stimObj -and [bool](Get-LumaBridgeValidationOptionalProp $stimObj 'VirtualDisplayIdentified' $false) -and [bool](Get-LumaBridgeValidationOptionalProp $stimObj 'Started' $false))
    $stimTargetFpsProp = if ($null -ne $stimObj -and ($stimObj.PSObject.Properties.Name -contains 'TargetFps')) { [int]$stimObj.TargetFps } else { $StimulusFps }
    $sustainedLiveFps = if ($summaryValid) { [double](Get-LumaBridgeValidationOptionalProp $summary 'SustainedLiveFps' 0.0) } else { 0.0 }
    $observedActiveFps = if ($summaryValid) { [double](Get-LumaBridgeValidationOptionalProp $summary 'ObservedActiveFps' 0.0) } else { 0.0 }
    $receiveFps = if ($summaryValid) { [double](Get-LumaBridgeValidationOptionalProp $summary 'ReceiveFps' 0.0) } else { 0.0 }
    $measuredFps = if ($sustainedLiveFps -gt 0.0) { $sustainedLiveFps } elseif ($observedActiveFps -gt 0.0) { $observedActiveFps } else { $receiveFps }

    $profileSpecificOk = $true
    $expectedMinFrames = [uint64]1
    switch ($SubprofileName) {
        'Smoke' {
            $expectedMinFrames = [uint64]$SmokeMinFrames
            $profileSpecificOk = ($framesValid -ge $expectedMinFrames)
            if ($summaryValid -and -not $profileSpecificOk) {
                $reasons.Add(("Smoke valid frames {0} < SmokeMinFrames {1}." -f $framesValid, $expectedMinFrames))
            }
        }
        'Performance' {
            $expectedMinFrames = [uint64]$PerformanceTargetFrames
            $profileSpecificOk = ($stimStarted -and $frameTargetReached -and ($framesValid -ge $expectedMinFrames))
            if ($summaryValid -and -not $profileSpecificOk) {
                $reasons.Add(("Performance gate failed (StimStarted={0}, FrameTargetReached={1}, FramesValid={2}/{3})." -f $stimStarted, $frameTargetReached, $framesValid, $expectedMinFrames))
            }
        }
        default {
            # Benchmark30s and ProlongedStability strict continuous gates
            $minDurationUs = [uint64]([double]$ExpectedDurationSec * 950000.0)
            $durationOk = ($ExpectedDurationSec -gt 0) -and ($durationUs -ge $minDurationUs)
            $frameBasisSec = [Math]::Max($measuredSec, [double]$ExpectedDurationSec * 0.95)
            $expectedMinFrames = [uint64][Math]::Max(1, [int64][Math]::Floor($frameBasisSec * [double]$StimulusFps * $MinFrameRatio))
            $framesCountOk = ($framesValid -ge $expectedMinFrames)
            $minRequiredFps = [double]$StimulusFps * $MinSustainedFpsRatio
            $sustainedFpsOk = ($measuredFps -ge $minRequiredFps)
            $stimFpsOk = ($StimulusFps -eq $ExpectedStimulusFps) -and ($stimTargetFpsProp -eq $ExpectedStimulusFps)
            $profileSpecificOk = ($stimStarted -and $stimFpsOk -and $durationOk -and $framesCountOk -and $sustainedFpsOk -and $resolutionOk)

            if ($summaryValid -and -not $stimStarted) { $reasons.Add('Visual stimulus failed to identify/start on virtual display.') }
            if ($summaryValid -and -not $stimFpsOk) { $reasons.Add(("Stimulus FPS config/target ({0} / {1}) != expected {2}." -f $StimulusFps, $stimTargetFpsProp, $ExpectedStimulusFps)) }
            if ($summaryValid -and -not $durationOk) { $reasons.Add(("Measured benchmark duration {0:F2}s < required 95% of {1}s." -f $measuredSec, $ExpectedDurationSec)) }
            if ($summaryValid -and -not $framesCountOk) { $reasons.Add(("Valid frames {0} < minimum {1} ({2:P1} at {3} FPS)." -f $framesValid, $expectedMinFrames, $MinFrameRatio, $StimulusFps)) }
            if ($summaryValid -and -not $sustainedFpsOk) { $reasons.Add(("Sustained FPS {0:F2} < minimum {1:F2} FPS." -f $measuredFps, $minRequiredFps)) }
        }
    }

    $passed = (
        $summaryValid -and
        $procExitedOk -and
        $ipcOk -and
        $temporalEval.SequenceAndTimestampsConsistent -and
        ((-not $RequireGpuShared) -or $gpuSharedPassed) -and
        ((-not $RequireNvenc) -or $nvencPassed) -and
        ((-not $VerifyH264Decode) -or $h264Passed) -and
        $resolutionOk -and
        $profileSpecificOk
    )

    return [pscustomobject]@{
        SubprofileName       = $SubprofileName
        SummaryValid         = $summaryValid
        SummaryStatus        = if ($null -ne $ValidationResult) { $ValidationResult.Status } else { 'MISSING' }
        ProcessExitedOk      = $procExitedOk
        IpcOk                = $ipcOk
        TemporalEval         = $temporalEval
        GpuSharedPassed      = $gpuSharedPassed
        NvencPassed          = $nvencPassed
        H264DecodePassed     = $h264Passed
        ResolutionOk         = $resolutionOk
        ProfileSpecificOk    = $profileSpecificOk
        Passed               = $passed
        ExpectedDurationSec  = $ExpectedDurationSec
        MeasuredDurationSec  = [Math]::Round($measuredSec, 3)
        ExpectedMinFrames    = $expectedMinFrames
        FramesReceived       = $framesReceived
        FramesValid          = $framesValid
        FramesEncoded        = $nvEncoded
        FramesDecoded        = $h264Decoded
        FramesDropped        = [pscustomobject]@{
            GpuFramesDropped   = $gpuDropped
            NvencDroppedFrames = $nvDropped
            EncodedQueueDrops  = $nvQueueDrops
            TotalNvencDrops    = $totalNvDrops
        }
        FramesPresented      = 'NOT_MEASURED_NO_REMOTE_RECEIVER'
        MeasuredResolution   = ("{0}x{1}" -f $frameWidth, $frameHeight)
        MeasuredSustainedFps = [Math]::Round($measuredFps, 2)
        NvencEncodeRatio     = [Math]::Round($nvEncodeRatio, 4)
        NvencDropRatio       = [Math]::Round($nvDropRatio, 4)
        EncoderOutputFps     = [Math]::Round($nvOutFps, 2)
        FailureReasons       = @($reasons.ToArray())
    }
}

$constants = Get-LumaBridgeDriverConstants
$repoRoot = Get-LumaBridgeRepoRoot
$sourcePackageDir = Get-LumaBridgePackageDirectory -Configuration $Configuration
$runId = "{0}-{1}" -f (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ'), ([Guid]::NewGuid().ToString('N').Substring(0, 12))

if ([string]::IsNullOrWhiteSpace($StagingDir)) {
    $StagingDir = "{0}_{1}" -f (Get-LumaBridgeDefaultStagingDirectory -Configuration $Configuration), $runId
}
$StagingDir = Assert-LumaBridgeIsolatedStagingDirectory -StagingDir $StagingDir -SourcePackageDir $sourcePackageDir

if ([string]::IsNullOrWhiteSpace($OutputDir)) {
    $localAppData = if (-not [string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) {
        $env:LOCALAPPDATA
    }
    else {
        [Environment]::GetFolderPath('LocalApplicationData')
    }
    $OutputDir = Join-Path -Path $localAppData -ChildPath ("LumaBridgeDisplay\Validation\{0}" -f $runId)
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

$maxSubprofileSec = 0
if ($runSmokeProfile) { $maxSubprofileSec = [Math]::Max($maxSubprofileSec, [int][Math]::Ceiling($HostDurationMs / 1000.0)) }
if ($runPerfProfile) { $maxSubprofileSec = [Math]::Max($maxSubprofileSec, [int][Math]::Ceiling($PerformanceDurationMs / 1000.0)) }
if ($runBenchmark30sProfile) { $maxSubprofileSec = [Math]::Max($maxSubprofileSec, $BenchmarkDurationSec) }
if ($runStabilityProfile) { $maxSubprofileSec = [Math]::Max($maxSubprofileSec, $StabilityDurationSec) }

$effectiveCoreEtwMaxMb = if ($CoreEtwMaxFileSizeMb -gt 0) {
    $CoreEtwMaxFileSizeMb
}
elseif ($maxSubprofileSec -ge 600) {
    1024
}
elseif ($maxSubprofileSec -ge 180) {
    512
}
else {
    256
}

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
# Stage 1: Non-destructive pre-checks & full initial system state snapshot
# -------------------------------------------------------------------------
$null = Assert-LumaBridgeAdministrator -OperationName 'Run LumaBridge M4.2.1 Functional Validation' -DryRun:$DryRun
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
$initialDriverStorePackages = @(Get-LumaBridgeValidationOptionalProp -InputObject $prereq -PropertyName 'DriverStorePackages' -DefaultValue @())
$initialSnapshot = Get-LumaBridgeInitialSystemSnapshot `
    -PnpInstances $initialInstances `
    -DriverStorePackages $initialDriverStorePackages `
    -CertificateThumbprint $CertificateThumbprint `
    -CertificateSubject $CertificateSubject `
    -EtwSessionName $constants.EtwSessionName `
    -DxgSessionName $constants.EtwDxgSessionName

$preValidationState = if ($null -ne $preExistingInstance) {
    [pscustomobject]@{
        ExistedBeforeRun         = $true
        InstanceId               = $preExistingInstance.InstanceId
        Status                   = $preExistingInstance.Status
        ProblemCode              = $preExistingInstance.ProblemCode
        DriverInfPath            = Get-LumaBridgeValidationOptionalProp -InputObject $preExistingInstance -PropertyName 'DriverInfPath'
        DriverVersion            = Get-LumaBridgeValidationOptionalProp -InputObject $preExistingInstance -PropertyName 'DriverVersion'
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
    $currentBranch -in @('feature/windows-gpu-shared-textures-nvenc', 'fix/m0-validation-gates-hardening', 'feature/windows-frame-extraction-ipc')
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
    param(
        [System.Collections.Generic.List[string]]$ArgList,
        [switch]$StrictBenchmarkGates
    )
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
            if ($StrictBenchmarkGates) {
                $ArgList.Add('--min-nvenc-encode-ratio')
                $ArgList.Add("$MinNvencEncodeRatio")
                $ArgList.Add('--max-nvenc-drop-ratio')
                $ArgList.Add("$MaxDropRatio")
            }
        }
        $ArgList.Add('--nvenc-bitrate-bps')
        $ArgList.Add("$NvencBitrateBps")
        $ArgList.Add('--prewarm-width')
        $ArgList.Add("$ExpectedBenchmarkWidth")
        $ArgList.Add('--prewarm-height')
        $ArgList.Add("$ExpectedBenchmarkHeight")
    }

    if ($VerifyH264Decode) {
        $ArgList.Add('--verify-h264-decode')
    }

    if ($StrictBenchmarkGates -and $ExpectedBenchmarkWidth -gt 0 -and $ExpectedBenchmarkHeight -gt 0) {
        $ArgList.Add('--require-width')
        $ArgList.Add("$ExpectedBenchmarkWidth")
        $ArgList.Add('--require-height')
        $ArgList.Add("$ExpectedBenchmarkHeight")
    }

    $ArgList.Add('--require-valid-timestamps')
    $ArgList.Add('--run-id')
    $ArgList.Add($runId)
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

    $durationMs = [int64]$DurationSec * 1000
    $minTargetFrames = [int][Math]::Max(1, [int64][Math]::Floor([double]$DurationSec * [double]$StimulusFps * $MinBenchmarkFrameRatio))
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
    Add-LumaBridgeM42HostArgs -ArgList $list -StrictBenchmarkGates
    return @($list.ToArray())
}

$timeoutPlan = [ordered]@{}
if ($runSmokeProfile) {
    $timeoutPlan['Smoke'] = Get-LumaBridgeValidationHostTimeoutMs -RequestedDurationMs $HostDurationMs -ConnectTimeoutMs $ConnectTimeoutMs -PrewarmMarginMs 5000 -ShutdownMarginMs 15000 -MinimumHardTimeoutMs $HostHardTimeoutMs
}
if ($runPerfProfile) {
    $timeoutPlan['Performance'] = Get-LumaBridgeValidationHostTimeoutMs -RequestedDurationMs $PerformanceDurationMs -ConnectTimeoutMs $ConnectTimeoutMs -PrewarmMarginMs 5000 -ShutdownMarginMs 15000 -MinimumHardTimeoutMs $HostHardTimeoutMs
}
if ($runBenchmark30sProfile) {
    $timeoutPlan['Benchmark30s'] = Get-LumaBridgeValidationHostTimeoutMs -RequestedDurationMs ([int64]$BenchmarkDurationSec * 1000) -ConnectTimeoutMs $ConnectTimeoutMs -PrewarmMarginMs 15000 -ShutdownMarginMs 30000 -MinimumHardTimeoutMs $HostHardTimeoutMs
}
if ($runStabilityProfile) {
    $timeoutPlan['ProlongedStability'] = Get-LumaBridgeValidationHostTimeoutMs -RequestedDurationMs ([int64]$StabilityDurationSec * 1000) -ConnectTimeoutMs $ConnectTimeoutMs -PrewarmMarginMs 15000 -ShutdownMarginMs 30000 -MinimumHardTimeoutMs $HostHardTimeoutMs
}

$benchmarkGateCriteria = [pscustomobject]@{
    ExpectedResolution        = ("{0}x{1}" -f $ExpectedBenchmarkWidth, $ExpectedBenchmarkHeight)
    ExpectedStimulusFps       = $StimulusFps
    MinBenchmarkFrameRatio    = $MinBenchmarkFrameRatio
    MinSustainedFpsRatio      = $MinSustainedFpsRatio
    MinNvencEncodeRatio       = $MinNvencEncodeRatio
    MaxDropRatio              = $MaxDropRatio
    MinProlongedStabilitySec  = $MinProlongedStabilitySec
    MinTemporalCoveragePct    = 95.0
    MaxTimestampErrors        = 0
    ResourceSampleIntervalSec = $ResourceSampleIntervalSec
    CoreEtwMaxFileSizeMb      = $effectiveCoreEtwMaxMb
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

    $etwStartDry = & $etwScript -Action Start -OutputDir $etwDir -CoreMaxFileSizeMb $effectiveCoreEtwMaxMb -IncludeDxgKrnl:$IncludeDxgKrnl -DryRun
    if (-not $SkipDriverInstall) {
        $null = & $installScript -Configuration $Configuration -StagingDir $StagingDir -AllowUntrustedChain:$effectiveAllowUntrusted -SkipTestSigningCheck:$SkipTestSigningCheck -DryRun
    }
    $dryInstId = if ($null -ne $preExistingInstance) { $preExistingInstance.InstanceId } else { 'ROOT\DISPLAY\<instance>' }
    $null = & $virtMonScript -Action Enable -InstanceId $dryInstId -DryRun
    $dryGpuMsg = if ($TransportMode -eq 'Cpu') { ' and REG_DWORD EnableGpuSharedTransport=0' } elseif ($TransportMode -eq 'Gpu' -or $RequireGpuShared) { ' and REG_DWORD EnableGpuSharedTransport=1' } else { '' }
    Write-Host ("[DRY-RUN] Stage 8 (RunId={0}): Would set REG_SZ AuthorizedHostUserSid='{1}', REG_DWORD EnableFrameExtraction=1{2} on '{3}' then restart PnP device" -f $runId, $effectiveAuthorizedUserSid, $dryGpuMsg, $dryInstId) -ForegroundColor Cyan

    $smokeDry = $null
    if ($runSmokeProfile) {
        $smokeDry = Invoke-LumaBridgeHostProcess -ExecutablePath $HostExecutablePath -Arguments (Build-SmokeHostArgs -JsonOut $hostSmokeJsonPath) -HardTimeoutMs $timeoutPlan['Smoke'].HardTimeoutMs -ResourceSampleIntervalSec $ResourceSampleIntervalSec -DryRun
    }
    $perfDry = $null
    if ($runPerfProfile) {
        $perfDry = Invoke-LumaBridgeHostProcess -ExecutablePath $HostExecutablePath -Arguments (Build-PerfHostArgs -JsonOut $hostPerfJsonPath) -HardTimeoutMs $timeoutPlan['Performance'].HardTimeoutMs -ResourceSampleIntervalSec $ResourceSampleIntervalSec -DryRun
    }
    $bench30sDry = $null
    if ($runBenchmark30sProfile) {
        $bench30sDry = Invoke-LumaBridgeHostProcess -ExecutablePath $HostExecutablePath -Arguments (Build-ProlongedHostArgs -JsonOut $hostBench30sJsonPath -DurationSec $BenchmarkDurationSec) -HardTimeoutMs $timeoutPlan['Benchmark30s'].HardTimeoutMs -ResourceSampleIntervalSec $ResourceSampleIntervalSec -DryRun
    }
    $stabilityDry = $null
    if ($runStabilityProfile) {
        $stabilityDry = Invoke-LumaBridgeHostProcess -ExecutablePath $HostExecutablePath -Arguments (Build-ProlongedHostArgs -JsonOut $hostStabilityJsonPath -DurationSec $StabilityDurationSec) -HardTimeoutMs $timeoutPlan['ProlongedStability'].HardTimeoutMs -ResourceSampleIntervalSec $ResourceSampleIntervalSec -DryRun
    }

    $etwStopDry = & $etwScript -Action Stop -OutputDir $etwDir -IncludeDxgKrnl:$IncludeDxgKrnl -DryRun
    $diagDry = & $diagScript -Configuration $Configuration -StagingDir $StagingDir -OutputDir $diagDir -DryRun
    Write-Host ("[DRY-RUN] Stage 11 (finally rollback): Would stop active ETW, restore initial registry snapshot (EnableVirtualMonitor/EnableFrameExtraction/EnableGpuSharedTransport/AuthorizedHostUserSid), preserve pre-existing certs, restart device{0}, and write report '{1}'" -f $(if ($FullUninstallOnExit) { ' and run Uninstall-LumaBridgeDriver.ps1' } else { '' }), $reportJsonPath) -ForegroundColor Cyan

    $dryHostPreview = if ($null -ne $stabilityDry) { $stabilityDry } elseif ($null -ne $bench30sDry) { $bench30sDry } elseif ($null -ne $perfDry) { $perfDry } else { $smokeDry }
    return [pscustomobject]@{
        DryRun                     = $true
        RunId                      = $runId
        Configuration              = $Configuration
        TestProfile                = $TestProfile
        Branch                     = $currentBranch
        PreValidationState         = $preValidationState
        InitialSystemSnapshot      = $initialSnapshot
        SecurityState              = $prereq.SecurityState
        TimeoutPlan                = [pscustomobject]$timeoutPlan
        BenchmarkGateCriteria      = $benchmarkGateCriteria
        PlannedCoreEtwMaxFileSizeMb = $effectiveCoreEtwMaxMb
        PlannedStagingDir          = $StagingDir
        PlannedOutputDir           = $OutputDir
        HostExecutablePath         = $HostExecutablePath
        AuthorizedHostUserSid      = $effectiveAuthorizedUserSid
        PreBuildHashes             = $preBuildHashes
        SigningPreview             = $signingDry
        EtwStartPreview            = $etwStartDry
        SmokeHostPreview           = $smokeDry
        PerfHostPreview            = $perfDry
        Benchmark30sHostPreview    = $bench30sDry
        StabilityHostPreview       = $stabilityDry
        HostPreview                = $dryHostPreview
        EtwStopPreview             = $etwStopDry
        DiagnosticsPreview         = $diagDry
        PlannedReportJsonPath      = $reportJsonPath
        PlannedReportMdPath        = $reportMdPath
    }
}

# Explicit operator authorization check prior to Stage 3/5/6 system or store mutations.
$authPrompt = "Execute controlled Windows M4.2.1 validation (RunId='{0}', Profile='{1}', Staging='{2}', InstallOrUpdateDriver={3}, EnableVirtualMonitor=1, EnableFrameExtraction=1, Rollback='Registry/ETW/Monitor restored to initial snapshot in finally; driver package downgrade NOT implemented')" -f `
    $runId, $TestProfile, $StagingDir, (-not $SkipDriverInstall)
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
$certCreatedInRun = [bool](Get-LumaBridgeValidationOptionalProp -InputObject $signResult -PropertyName 'CertificateCreatedInRun' -DefaultValue $false)
$certTrustedInRun = [bool](Get-LumaBridgeValidationOptionalProp -InputObject $signResult -PropertyName 'CertificateTrustedInRun' -DefaultValue $false)
$certWasPreExistingInSnapshot = $false
if (-not [string]::IsNullOrWhiteSpace($signedThumbprint) -and $null -ne $initialSnapshot -and $null -ne $initialSnapshot.CertificateSnapshot) {
    $certWasPreExistingInSnapshot = (@($initialSnapshot.CertificateSnapshot.MatchingThumbprints | Where-Object { $_ -ieq $signedThumbprint }).Count -gt 0)
}

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

# Tracking variables for deterministic non-masking finally rollback
$etwStarted = $false
$etwStopped = $false
$targetInstance = $preExistingInstance
$didFreshDriverInstall = $false
$driverInstallAttempted = (-not $SkipDriverInstall)
$driverInstallCompleted = $false
$priorRegSnapshot = $initialSnapshot.RegistryValues
$modifiedVirtMon = $false
$modifiedExtraction = $false
$modifiedGpuTrans = $false
$modifiedAuthSid = $false
$stage8RestartAnchorUtc = $null

$etwStartResult = $null
$etwVerifyResult = $null
$etwStopResult = $null
$installResult = $null
$installedBindingCheck = $null
$virtMonEnableResult = $null
$smokeHostResult = $null
$smokeSummaryValidation = $null
$smokeSummary = $null
$perfHostResult = $null
$perfSummaryValidation = $null
$perfSummary = $null
$bench30sHostResult = $null
$bench30sSummaryValidation = $null
$bench30sSummary = $null
$stabilityHostResult = $null
$stabilitySummaryValidation = $null
$stabilitySummary = $null
$subprofileEvaluations = [ordered]@{}
$syntheticFidelityResult = $null
$preStage9WudfProcs = @()
$preStage9WudfResolution = $null
$continuousTelemetryList = New-Object System.Collections.Generic.List[object]
$processResourceSummary = $null
$hostProcResult = $null
$hostSummary = $null
$diagResult = $null
$diagCollectionError = $null
$stage9Error = $null
$postRunWudfProcs = @()
$postRunWudfResolution = $null
$postRunDumpInventory = $null
$acceptanceCriteria = $null
$validationError = $null
$driverBindingVerified = $false
$latencySamplingAudit = @()
$rollbackActions = New-Object System.Collections.Generic.List[string]
$rollbackIncompleteReasons = New-Object System.Collections.Generic.List[string]
$unrestoredStateDetails = New-Object System.Collections.Generic.List[string]
$runtimeCleanupSucceeded = $false
$driverBindingPersisted = $false
$systemStateRestored = $false
$rollbackClean = $false
$functionalValidationSucceeded = $false
$overallSucceeded = $false
$postRollbackInstances = @()

$rollbackScopeNote = if ($FullUninstallOnExit) {
    'Rolls back ETW, restores/removes temporary registry parameters per initial snapshot, and removes device/driver package via Uninstall-LumaBridgeDriver.ps1 while preserving pre-existing certificates.'
}
elseif ($SkipDriverInstall) {
    'Rolls back ETW and restores temporary registry parameters (EnableFrameExtraction, EnableGpuSharedTransport, AuthorizedHostUserSid, EnableVirtualMonitor) to exact initial snapshot values while preserving pre-existing certificates and driver binding.'
}
else {
    'Rolls back ETW and restores temporary registry parameters to exact initial snapshot values. Authorized driver update persists across exit (SystemStateRestored=false when binding changed; DriverBindingPersisted=true) unless -FullUninstallOnExit uninstalls on exit; never removes pre-existing certificates or historical Driver Store packages.'
}

function Invoke-LumaBridgeStage10DiagnosticsCapture {
    param([string]$FailureContextMessage)
    $localCapturedEtl = $null
    if ($etwStarted -and -not $etwStopped) {
        try {
            $script:etwStopResult = & $etwScript -Action Stop -OutputDir $etwDir -IncludeDxgKrnl:$IncludeDxgKrnl -Force
            $script:etwStopped = $true
            $localCapturedEtl = Get-LumaBridgeValidationOptionalProp -InputObject $script:etwStopResult -PropertyName 'EtlPath' -DefaultValue $null
        }
        catch {
            $script:diagCollectionError = ("ETW Stop in Stage 10 failed: {0}" -f $_.Exception.Message)
        }
    }
    elseif ($null -ne $script:etwStopResult) {
        $localCapturedEtl = Get-LumaBridgeValidationOptionalProp -InputObject $script:etwStopResult -PropertyName 'EtlPath' -DefaultValue $null
    }

    if ($null -eq $script:diagResult) {
        $diagParams = @{
            Configuration = $Configuration
            StagingDir    = $signedStagingDir
            OutputDir     = $diagDir
        }
        if (-not [string]::IsNullOrWhiteSpace($localCapturedEtl)) {
            $diagParams['EtlPath'] = $localCapturedEtl
        }
        if (-not [string]::IsNullOrWhiteSpace($FailureContextMessage)) {
            $diagParams['FailureContext'] = $FailureContextMessage
        }
        try {
            $script:diagResult = & $diagScript @diagParams
        }
        catch {
            $msg = ("Collect-LumaBridgeDiagnostics.ps1 failed: {0}" -f $_.Exception.Message)
            $script:diagCollectionError = if ([string]::IsNullOrWhiteSpace($script:diagCollectionError)) { $msg } else { "$($script:diagCollectionError); $msg" }
        }
    }
}

try {
    # ---------------------------------------------------------------------
    # Stage 5: Controlled ETW capture + VerifyProviders
    # ---------------------------------------------------------------------
    $etwStartResult = & $etwScript -Action Start -OutputDir $etwDir -CoreMaxFileSizeMb $effectiveCoreEtwMaxMb -IncludeDxgKrnl:$IncludeDxgKrnl -Force
    $etwStarted = $true

    $etwVerifyResult = & $etwScript -Action VerifyProviders -OutputDir $etwDir
    if (-not [bool](Get-LumaBridgeValidationOptionalProp -InputObject $etwVerifyResult -PropertyName 'AllProvidersVerified' -DefaultValue $false)) {
        $missingGuids = @($etwVerifyResult.MissingProviderGuids) -join ', '
        throw ("ETW VerifyProviders failed; missing provider GUID(s): {0}" -f $missingGuids)
    }

    # ---------------------------------------------------------------------
    # Stage 6: Authorized driver installation & strict binding/identity confirmation
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

    $stagedInfPath = Join-Path -Path $signedStagingDir -ChildPath $constants.InfFileName
    $stagedDllPath = Join-Path -Path $signedStagingDir -ChildPath $constants.DllFileName
    $postStage6Packages = @(Get-LumaBridgeDriverStorePackages)
    $preStage6WudfProcs = @(Get-LumaBridgeWudfHostProcesses -PnpInstances @($targetInstance))
    $loadedModulePathForBinding = $null
    foreach ($wp in $preStage6WudfProcs) {
        $lmp = Get-LumaBridgeValidationOptionalProp -InputObject $wp -PropertyName 'LoadedDriverModulePath' -DefaultValue $null
        if ($wp.IsLumaBridgeHost -and -not [string]::IsNullOrWhiteSpace([string]$lmp)) {
            $loadedModulePathForBinding = [string]$lmp
            break
        }
    }

    $installedBindingCheck = Test-LumaBridgeDeviceDriverBinding `
        -Instance $targetInstance `
        -DriverStorePackages $postStage6Packages `
        -ExpectedInfPath $stagedInfPath `
        -ExpectedDllPath $stagedDllPath `
        -LoadedModulePath $loadedModulePathForBinding

    if ($null -eq $installedBindingCheck -or (-not [bool]$installedBindingCheck.IsBound)) {
        $bindReasons = if ($null -ne $installedBindingCheck) { @($installedBindingCheck.Reasons) -join '; ' } else { 'Binding check returned null.' }
        throw ("Installed driver binding/identity check failed on '{0}' (SkipDriverInstall={1}, BoundVersion={2}, ExpectedVersion={3}, BinaryIdentity={4}): {5}" -f `
            $targetInstance.InstanceId, $SkipDriverInstall.IsPresent, `
            (Get-LumaBridgeValidationOptionalProp $installedBindingCheck 'BoundDriverVersion'), `
            (Get-LumaBridgeValidationOptionalProp $installedBindingCheck 'ExpectedDriverVersion'), `
            (Get-LumaBridgeValidationOptionalProp $installedBindingCheck 'BinaryIdentityStatus' 'NOT_MEASURED'), `
            $bindReasons)
    }
    $driverBindingVerified = $true

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

    $stage8RestartAnchorUtc = (Get-Date).ToUniversalTime()
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
    # Stage 9: Time-bounded lumabridge-host.exe execution (guarded so Stage 10 diagnostics always run)
    # ---------------------------------------------------------------------
    $preStage9WudfProcs = @(Get-LumaBridgeWudfHostProcesses -PnpInstances @($targetInstance) -NotBeforeUtc $stage8RestartAnchorUtc)
    $preStage9WudfResolution = Resolve-LumaBridgeVerifiedWudfHostProcess -WudfProcesses $preStage9WudfProcs -RequireStartedAfterAnchor
    $verifiedPreWudfPid = if ($null -ne $preStage9WudfResolution.Process) { [int]$preStage9WudfResolution.Process.Id } else { $null }

    $invokeSubprofile = {
        param(
            [string]$SubName,
            [string[]]$HostArgs,
            [string]$JsonOutPath,
            [int]$HardTimeoutMs
        )
        if (Test-Path -LiteralPath $JsonOutPath -PathType Leaf) {
            Remove-Item -LiteralPath $JsonOutPath -Force -ErrorAction SilentlyContinue
        }
        $launchUtc = (Get-Date).ToUniversalTime()
        $procRes = Invoke-LumaBridgeHostProcess `
            -ExecutablePath $HostExecutablePath `
            -Arguments $HostArgs `
            -HardTimeoutMs $HardTimeoutMs `
            -ResourceSampleIntervalSec $ResourceSampleIntervalSec `
            -WudfProcessId $verifiedPreWudfPid

        $resTel = Get-LumaBridgeValidationOptionalProp -InputObject $procRes -PropertyName 'ResourceTelemetry' -DefaultValue $null
        if ($null -ne $resTel) {
            $continuousTelemetryList.Add([pscustomobject]@{
                Subprofile = $SubName
                Telemetry  = $resTel
            })
        }

        $jsonVal = Read-LumaBridgeValidatedHostSummary -JsonPath $JsonOutPath -ExpectedRunId $runId -LaunchStartUtc $launchUtc
        if ($jsonVal.IsValid) {
            Copy-Item -LiteralPath $JsonOutPath -Destination $hostJsonPath -Force
        }

        return [pscustomobject]@{
            ProcResult     = $procRes
            JsonValidation = $jsonVal
            Summary        = $jsonVal.Summary
        }
    }

    try {
        if ($runSmokeProfile) {
            $smokeOut = & $invokeSubprofile 'Smoke' (Build-SmokeHostArgs -JsonOut $hostSmokeJsonPath) $hostSmokeJsonPath $timeoutPlan['Smoke'].HardTimeoutMs
            $smokeHostResult = $smokeOut.ProcResult
            $smokeSummaryValidation = $smokeOut.JsonValidation
            $smokeSummary = $smokeOut.Summary
            $hostProcResult = $smokeHostResult
            $hostSummary = $smokeSummary
            $subprofileEvaluations['Smoke'] = Test-LumaBridgeSubprofileGates `
                -SubprofileName 'Smoke' `
                -ValidationResult $smokeSummaryValidation `
                -ProcessResult $smokeHostResult `
                -RequireGpuShared:$RequireGpuShared `
                -RequireNvenc:$RequireNvenc `
                -VerifyH264Decode:$VerifyH264Decode `
                -SmokeMinFrames ([uint64]$SmokeMinFrames) `
                -StimulusFps $StimulusFps `
                -MinNvencEncodeRatio $MinNvencEncodeRatio `
                -MaxDropRatio $MaxDropRatio
        }

        $smokeFramesValidCount = if ($null -ne $smokeSummary) {
            [uint64](Get-LumaBridgeValidationOptionalProp -InputObject $smokeSummary -PropertyName 'FramesValid' -DefaultValue (Get-LumaBridgeValidationOptionalProp -InputObject $smokeSummary -PropertyName 'FramesReceived' -DefaultValue 0))
        }
        else { [uint64]0 }
        $smokeGateForNext = ((-not $runSmokeProfile) -or ($null -ne $subprofileEvaluations['Smoke'] -and $subprofileEvaluations['Smoke'].Passed) -or ($smokeFramesValidCount -ge [uint64]$SmokeMinFrames))

        if ($runPerfProfile -and $smokeGateForNext) {
            $perfOut = & $invokeSubprofile 'Performance' (Build-PerfHostArgs -JsonOut $hostPerfJsonPath) $hostPerfJsonPath $timeoutPlan['Performance'].HardTimeoutMs
            $perfHostResult = $perfOut.ProcResult
            $perfSummaryValidation = $perfOut.JsonValidation
            $perfSummary = $perfOut.Summary
            $hostProcResult = $perfHostResult
            $hostSummary = $perfSummary
            $subprofileEvaluations['Performance'] = Test-LumaBridgeSubprofileGates `
                -SubprofileName 'Performance' `
                -ValidationResult $perfSummaryValidation `
                -ProcessResult $perfHostResult `
                -RequireGpuShared:$RequireGpuShared `
                -RequireNvenc:$RequireNvenc `
                -VerifyH264Decode:$VerifyH264Decode `
                -PerformanceTargetFrames ([uint64]$PerformanceTargetFrames) `
                -StimulusFps $StimulusFps `
                -MinNvencEncodeRatio $MinNvencEncodeRatio `
                -MaxDropRatio $MaxDropRatio
        }

        if ($runBenchmark30sProfile -and $smokeGateForNext) {
            $b30Out = & $invokeSubprofile 'Benchmark30s' (Build-ProlongedHostArgs -JsonOut $hostBench30sJsonPath -DurationSec $BenchmarkDurationSec) $hostBench30sJsonPath $timeoutPlan['Benchmark30s'].HardTimeoutMs
            $bench30sHostResult = $b30Out.ProcResult
            $bench30sSummaryValidation = $b30Out.JsonValidation
            $bench30sSummary = $b30Out.Summary
            $hostProcResult = $bench30sHostResult
            $hostSummary = $bench30sSummary
            $subprofileEvaluations['Benchmark30s'] = Test-LumaBridgeSubprofileGates `
                -SubprofileName 'Benchmark30s' `
                -ValidationResult $bench30sSummaryValidation `
                -ProcessResult $bench30sHostResult `
                -RequireGpuShared:$RequireGpuShared `
                -RequireNvenc:$RequireNvenc `
                -VerifyH264Decode:$VerifyH264Decode `
                -ExpectedDurationSec $BenchmarkDurationSec `
                -StimulusFps $StimulusFps `
                -ExpectedStimulusFps $ExpectedBenchmarkStimulusFps `
                -ExpectedWidth $ExpectedBenchmarkWidth `
                -ExpectedHeight $ExpectedBenchmarkHeight `
                -MinFrameRatio $MinBenchmarkFrameRatio `
                -MinSustainedFpsRatio $MinSustainedFpsRatio `
                -MinNvencEncodeRatio $MinNvencEncodeRatio `
                -MaxDropRatio $MaxDropRatio
        }

        if ($runStabilityProfile -and $smokeGateForNext) {
            $stabOut = & $invokeSubprofile 'ProlongedStability' (Build-ProlongedHostArgs -JsonOut $hostStabilityJsonPath -DurationSec $StabilityDurationSec) $hostStabilityJsonPath $timeoutPlan['ProlongedStability'].HardTimeoutMs
            $stabilityHostResult = $stabOut.ProcResult
            $stabilitySummaryValidation = $stabOut.JsonValidation
            $stabilitySummary = $stabOut.Summary
            $hostProcResult = $stabilityHostResult
            $hostSummary = $stabilitySummary
            $subprofileEvaluations['ProlongedStability'] = Test-LumaBridgeSubprofileGates `
                -SubprofileName 'ProlongedStability' `
                -ValidationResult $stabilitySummaryValidation `
                -ProcessResult $stabilityHostResult `
                -RequireGpuShared:$RequireGpuShared `
                -RequireNvenc:$RequireNvenc `
                -VerifyH264Decode:$VerifyH264Decode `
                -ExpectedDurationSec $StabilityDurationSec `
                -StimulusFps $StimulusFps `
                -ExpectedStimulusFps $ExpectedBenchmarkStimulusFps `
                -ExpectedWidth $ExpectedBenchmarkWidth `
                -ExpectedHeight $ExpectedBenchmarkHeight `
                -MinFrameRatio $MinBenchmarkFrameRatio `
                -MinSustainedFpsRatio $MinSustainedFpsRatio `
                -MinNvencEncodeRatio $MinNvencEncodeRatio `
                -MaxDropRatio $MaxDropRatio
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
    }
    catch {
        $stage9Error = $_.Exception.Message
    }

    # ---------------------------------------------------------------------
    # Stage 10: Metrics & log collection (ALWAYS runs even if Stage 9 threw)
    # ---------------------------------------------------------------------
    Invoke-LumaBridgeStage10DiagnosticsCapture -FailureContextMessage $stage9Error

    $postRunInstances = @(Get-LumaBridgePnpInstances | Where-Object { $_.InstanceId -ieq $targetInstance.InstanceId })
    if ($postRunInstances.Count -eq 1) {
        $targetInstance = $postRunInstances[0]
    }
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

    $ipcReportedServerPid = if ($null -ne $primaryEvalSummary) {
        [int](Get-LumaBridgeValidationOptionalProp -InputObject $primaryEvalSummary -PropertyName 'ServerProcessId' -DefaultValue 0)
    }
    else { 0 }
    $postRunWudfProcs = @(Get-LumaBridgeWudfHostProcesses -PnpInstances $postRunInstances -NotBeforeUtc $stage8RestartAnchorUtc -ExpectedHostPid $(if ($ipcReportedServerPid -gt 0) { $ipcReportedServerPid } else { $null }))
    $postRunWudfResolution = Resolve-LumaBridgeVerifiedWudfHostProcess `
        -WudfProcesses $postRunWudfProcs `
        -ExpectedPid $(if ($ipcReportedServerPid -gt 0) { $ipcReportedServerPid } else { $null }) `
        -RequireStartedAfterAnchor

    $wudfExitedMidRun = (@($continuousTelemetryList | Where-Object { $_.Telemetry.WudfProcessExitedDuringRun }).Count -gt 0)
    $wudfIdentityStatus = if ($preStage9WudfResolution.Status -ne 'VERIFIED') {
        $preStage9WudfResolution.Status
    }
    elseif ($postRunWudfResolution.Status -ne 'VERIFIED') {
        $postRunWudfResolution.Status
    }
    elseif ($wudfExitedMidRun) {
        'FAIL'
    }
    else {
        'VERIFIED'
    }
    $wudfProcessHealthy = ($wudfIdentityStatus -eq 'VERIFIED')

    $evalSubList = @($subprofileEvaluations.Values)
    $allSubprofilesPassed = ($evalSubList.Count -ge 1)
    $seqMonotonicityOk = ($evalSubList.Count -ge 1)
    $timestampsMonotonicOk = ($evalSubList.Count -ge 1)
    $timestampsValidOk = ($evalSubList.Count -ge 1)
    $measurableLatenciesOk = ($evalSubList.Count -ge 1)
    $temporalCoverageSufficient = ($evalSubList.Count -ge 1)
    $totalTimestampMeasurementErrors = [uint64]0
    $gpuSharedPassed = ($evalSubList.Count -ge 1)
    $nvencPassed = ($evalSubList.Count -ge 1)
    $h264DecodePassed = ($evalSubList.Count -ge 1)
    $truncatedMetricsList = New-Object System.Collections.Generic.List[object]

    foreach ($se in $evalSubList) {
        $allSubprofilesPassed = $allSubprofilesPassed -and [bool]$se.Passed
        $te = $se.TemporalEval
        $seqMonotonicityOk = $seqMonotonicityOk -and $te.SequenceMonotonicityOk
        $timestampsMonotonicOk = $timestampsMonotonicOk -and $te.TimestampsMonotonicOk
        $timestampsValidOk = $timestampsValidOk -and $te.TimestampsValidOk
        $measurableLatenciesOk = $measurableLatenciesOk -and $te.MeasurableLatenciesOk
        $temporalCoverageSufficient = $temporalCoverageSufficient -and $te.TemporalCoverageSufficient
        $totalTimestampMeasurementErrors += $te.TimestampMeasurementErrors
        $gpuSharedPassed = $gpuSharedPassed -and [bool]$se.GpuSharedPassed
        $nvencPassed = $nvencPassed -and [bool]$se.NvencPassed
        $h264DecodePassed = $h264DecodePassed -and [bool]$se.H264DecodePassed
        foreach ($tm in @($te.TruncatedLatencyMetrics)) {
            $truncatedMetricsList.Add([pscustomobject]@{
                Subprofile        = $se.SubprofileName
                MetricName        = $tm.MetricName
                SampleCount       = $tm.SampleCount
                StoredSampleCount = $tm.StoredSampleCount
                ReservoirSampled  = $tm.ReservoirSampled
            })
        }
    }
    $latencySamplingAudit = @($truncatedMetricsList.ToArray())
    $sequenceAndTimestampsOk = ($seqMonotonicityOk -and $timestampsMonotonicOk -and $timestampsValidOk -and $measurableLatenciesOk -and $temporalCoverageSufficient)

    $smokeEvalObj = if ($subprofileEvaluations.Contains('Smoke')) { $subprofileEvaluations['Smoke'] } else { $null }
    $perfEvalObj = if ($subprofileEvaluations.Contains('Performance')) { $subprofileEvaluations['Performance'] } else { $null }
    $bench30sEvalObj = if ($subprofileEvaluations.Contains('Benchmark30s')) { $subprofileEvaluations['Benchmark30s'] } else { $null }
    $stabEvalObj = if ($subprofileEvaluations.Contains('ProlongedStability')) { $subprofileEvaluations['ProlongedStability'] } else { $null }

    $functionalSmokePassed = ($null -ne $smokeEvalObj -and $smokeEvalObj.Passed -and $cmProbNone -and $adapterInitFinishedOk -and $virtualMonitorActive -and ($postDumpCount -le $initialDumpCount) -and $wudfProcessHealthy)
    $perfExecuted = ($null -ne $perfHostResult)
    $perfTargetReached = ($null -ne $perfEvalObj -and $perfEvalObj.Passed)
    $bench30sExecuted = ($null -ne $bench30sHostResult)
    $bench30sPassed = ($null -ne $bench30sEvalObj -and $bench30sEvalObj.Passed)
    $stabilityExecuted = ($null -ne $stabilityHostResult)
    $stabilityPassed = ($null -ne $stabEvalObj -and $stabEvalObj.Passed)

    $prolongedStabilityProven = (
        $stabilityExecuted -and
        $stabilityPassed -and
        ($StabilityDurationSec -ge $MinProlongedStabilitySec) -and
        ($null -ne $stabEvalObj -and $stabEvalObj.MeasuredDurationSec -ge ([double]$MinProlongedStabilitySec * 0.95)) -and
        $driverBindingVerified -and
        $wudfProcessHealthy
    )

    $primaryTemporal = Test-LumaBridgeTemporalTelemetry -Summary $primaryEvalSummary
    $framesReceived = if ($null -ne $primaryEvalSummary) { [uint64](Get-LumaBridgeValidationOptionalProp $primaryEvalSummary 'FramesReceived' 0) } else { [uint64]0 }
    $framesValid = if ($null -ne $primaryEvalSummary) { [uint64](Get-LumaBridgeValidationOptionalProp $primaryEvalSummary 'FramesValid' $framesReceived) } else { [uint64]0 }
    $checksumMismatches = if ($null -ne $primaryEvalSummary) { [uint64](Get-LumaBridgeValidationOptionalProp $primaryEvalSummary 'ChecksumMismatches' 1) } else { [uint64]1 }
    $protocolErrors = if ($null -ne $primaryEvalSummary) { [uint64](Get-LumaBridgeValidationOptionalProp $primaryEvalSummary 'ProtocolErrors' 1) } else { [uint64]1 }
    $fatalIoTimeouts = if ($null -ne $primaryEvalSummary) { [uint64](Get-LumaBridgeValidationOptionalProp $primaryEvalSummary 'FatalIoTimeouts' 0) } else { [uint64]0 }
    $fatalIpcErrors = if ($null -ne $primaryEvalSummary) { [uint64](Get-LumaBridgeValidationOptionalProp $primaryEvalSummary 'FatalIpcErrors' 0) } else { [uint64]0 }
    $lastProtocolStatus = if ($null -ne $primaryEvalSummary) { [string](Get-LumaBridgeValidationOptionalProp $primaryEvalSummary 'LastProtocolStatus' 'Unknown') } else { 'Missing' }
    $connectCount = if ($null -ne $primaryEvalSummary) { [uint64](Get-LumaBridgeValidationOptionalProp $primaryEvalSummary 'ConnectCount' 0) } else { [uint64]0 }
    $hostTransportHealthy = if ($null -ne $primaryEvalSummary) { [bool](Get-LumaBridgeValidationOptionalProp $primaryEvalSummary 'TransportHealthy' $false) } else { $false }
    $frameTargetReached = if ($null -ne $primaryEvalSummary) { [bool](Get-LumaBridgeValidationOptionalProp $primaryEvalSummary 'FrameTargetReached' $false) } else { $false }

    $evalH264 = if ($null -ne $primaryEvalSummary) { Get-LumaBridgeValidationOptionalProp $primaryEvalSummary 'H264DecodeValidation' $null } else { $null }
    $structuralDecodeValidated = ($h264DecodePassed -and $null -ne $evalH264 -and [bool](Get-LumaBridgeValidationOptionalProp $evalH264 'StructuralDecodeValidated' $false))
    $fidelityPsnrValidated = (
        ($null -ne $evalH264 -and [bool](Get-LumaBridgeValidationOptionalProp $evalH264 'FidelityPsnrValidated' $false)) -or
        ($null -ne $syntheticFidelityResult -and [bool]$syntheticFidelityResult.Passed)
    )

    $hostExitedNormally = ($null -ne $primaryEvalProc -and (-not $primaryEvalProc.TimedOut) -and ($primaryEvalProc.ExitCode -eq 0))
    $ipcConnected = ($connectCount -ge 1)
    $transportHealthy = ($hostTransportHealthy -and $protocolErrors -eq 0 -and $checksumMismatches -eq 0 -and $fatalIoTimeouts -eq 0 -and $fatalIpcErrors -eq 0)
    $crc32Valid = ($framesValid -ge 1 -and $checksumMismatches -eq 0)
    $noUnauthorizedIpcClients = ($lastProtocolStatus -ne 'UnauthorizedClient')
    $noNewCrashDumps = ($postDumpCount -le $initialDumpCount)
    $realGpuSyncHealthy = (-not $RequireGpuShared) -or $gpuSharedPassed

    $smokeGateOk = (-not $runSmokeProfile) -or $functionalSmokePassed
    $perfGateOk = (-not $runPerfProfile) -or $perfTargetReached
    $bench30sGateOk = (-not $runBenchmark30sProfile) -or $bench30sPassed
    $stabilityGateOk = (-not $runStabilityProfile) -or $stabilityPassed
    $gpuGateOk = (-not $RequireGpuShared) -or $gpuSharedPassed
    $nvencGateOk = (-not $RequireNvenc) -or $nvencPassed
    $h264GateOk = (-not $VerifyH264Decode) -or $h264DecodePassed

    $allPassed = (
        [string]::IsNullOrWhiteSpace($stage9Error) -and
        $driverBindingVerified -and
        $cmProbNone -and
        $adapterInitFinishedOk -and
        $virtualMonitorActive -and
        $noUnauthorizedIpcClients -and
        $noNewCrashDumps -and
        $wudfProcessHealthy -and
        $allSubprofilesPassed -and
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

    $primaryContinuousTelemetry = if ($continuousTelemetryList.Count -gt 0) { $continuousTelemetryList[$continuousTelemetryList.Count - 1].Telemetry } else { $null }
    $wudfProcessSelected = if ($null -ne $postRunWudfResolution.Process) { $postRunWudfResolution.Process } else { $preStage9WudfResolution.Process }

    $processResourceSummary = [pscustomobject]@{
        WudfIdentityStatus         = $wudfIdentityStatus
        VerifiedWudfPid            = if ($null -ne $wudfProcessSelected) { [int]$wudfProcessSelected.Id } else { $null }
        WudfAssociationMethod      = if ($null -ne $wudfProcessSelected) { $wudfProcessSelected.AssociationMethod } else { $null }
        ContinuousSampleIntervalSec = $ResourceSampleIntervalSec
        ContinuousSubprofiles      = @($continuousTelemetryList.ToArray())
        PrimaryContinuousTelemetry = $primaryContinuousTelemetry
        HostProcessResourceUsage   = if ($null -ne $primaryEvalSummary) { Get-LumaBridgeValidationOptionalProp $primaryEvalSummary 'ResourceUsage' $null } else { $null }
    }

    $acceptanceCriteria = [pscustomobject]@{
        RunId                           = $runId
        DriverBindingVerified           = $driverBindingVerified
        CmProbNone                      = $cmProbNone
        AdapterInitFinishedOk           = $adapterInitFinishedOk
        VirtualMonitorActive            = $virtualMonitorActive
        IpcConnected                    = $ipcConnected
        HostProcessExitedNormally       = $hostExitedNormally
        HostProcessSucceeded            = $hostExitedNormally
        FramesReceived                  = $framesReceived
        FramesValid                     = $framesValid
        HostReceivedFrames              = ($framesValid -ge 1)
        FrameTargetReached              = $(if ($null -ne $perfSummary) { [bool](Get-LumaBridgeValidationOptionalProp $perfSummary 'FrameTargetReached' $false) } else { $frameTargetReached })
        FunctionalSmokePassed           = $functionalSmokePassed
        PerformanceTestExecuted         = $perfExecuted
        PerformanceTargetReached        = $perfTargetReached
        Benchmark30sExecuted            = $bench30sExecuted
        Benchmark30sPassed              = $bench30sPassed
        ProlongedStabilityExecuted      = $stabilityExecuted
        ProlongedStabilityPassed        = $stabilityPassed
        ProlongedStabilityProven        = $prolongedStabilityProven
        AllSubprofilesPassed            = $allSubprofilesPassed
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
        WudfIdentityStatus              = $wudfIdentityStatus
        WudfProcessHealthy              = $wudfProcessHealthy
        RollbackClean                   = $false
        RuntimeCleanupSucceeded         = $false
        SystemStateRestored             = $false
        DriverBindingPersisted          = $false
        OverallSucceeded                = $false
        AllPassed                       = $allPassed
    }

    if (-not $allPassed) {
        if (-not [string]::IsNullOrWhiteSpace($stage9Error)) {
            throw $stage9Error
        }
        $subprofileReasons = @($evalSubList | Where-Object { -not $_.Passed } | ForEach-Object { ("{0}: [{1}]" -f $_.SubprofileName, ($_.FailureReasons -join ' | ')) })
        $skipEvalNames = @(
            'RunId', 'AllPassed', 'RollbackClean', 'RuntimeCleanupSucceeded', 'SystemStateRestored', 'DriverBindingPersisted', 'OverallSucceeded',
            'FramesReceived', 'FramesValid', 'FrameTargetReached', 'WudfIdentityStatus',
            'PerformanceTestExecuted', 'PerformanceTargetReached',
            'Benchmark30sExecuted', 'Benchmark30sPassed',
            'ProlongedStabilityExecuted', 'ProlongedStabilityPassed', 'ProlongedStabilityProven',
            'GpuSharedPassed', 'NvencPassed', 'H264DecodePassed',
            'StructuralDecodeValidated', 'FidelityPsnrValidated',
            'TimestampMeasurementErrors', 'CoreTimestampCoveragePercent',
            'LiveTimestampCoveragePercent', 'PresentTimestampCoveragePercent', 'NvencExtractToBsCoveragePercent'
        )
        $failedFlags = @($acceptanceCriteria.PSObject.Properties | Where-Object { $_.Name -notin $skipEvalNames -and -not [bool]$_.Value } | ForEach-Object { $_.Name })
        if ($runPerfProfile -and -not $perfTargetReached) { $failedFlags += 'PerformanceTargetReached' }
        if ($runBenchmark30sProfile -and -not $bench30sPassed) { $failedFlags += 'Benchmark30sPassed' }
        if ($runStabilityProfile -and -not $stabilityPassed) { $failedFlags += 'ProlongedStabilityPassed' }
        if ($RequireGpuShared -and -not $gpuSharedPassed) { $failedFlags += 'GpuSharedPassed' }
        if ($RequireNvenc -and -not $nvencPassed) { $failedFlags += 'NvencPassed' }
        if ($VerifyH264Decode -and -not $h264DecodePassed) { $failedFlags += 'H264DecodePassed' }
        $detailSuffix = if ($subprofileReasons.Count -gt 0) { " SubprofileDetails: " + ($subprofileReasons -join '; ') } else { '' }
        throw ("Functional validation acceptance criteria not satisfied: {0}{1}" -f (($failedFlags | Select-Object -Unique) -join ', '), $detailSuffix)
    }
}
catch {
    $validationError = $_.Exception.Message
    if ($null -eq $diagResult) {
        Invoke-LumaBridgeStage10DiagnosticsCapture -FailureContextMessage $validationError
    }
}
finally {
    # ---------------------------------------------------------------------
    # Stage 11: Guaranteed Non-Masking Rollback to Initial Snapshot
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

    $shouldFullUninstall = ($FullUninstallOnExit -or ($didFreshDriverInstall -and -not $driverInstallCompleted))

    if ($null -ne $targetInstance) {
        if ($shouldFullUninstall) {
            try {
                $uninstallParams = @{ Force = $true }
                # Never remove a pre-existing certificate; only remove ephemeral cert created/trusted in this run.
                if (-not [string]::IsNullOrWhiteSpace($signedThumbprint) -and ($certCreatedInRun -or ($certTrustedInRun -and -not $certWasPreExistingInSnapshot))) {
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
            $needDeviceRestart = $false

            if ($modifiedExtraction -and $null -ne $priorRegSnapshot) {
                try {
                    if ($priorRegSnapshot.EnableFrameExtraction.ValueExists) {
                        Set-LumaBridgeDeviceEnableFrameExtraction -DeviceParametersPath $targetInstance.DeviceParametersPath -Value ([int]$priorRegSnapshot.EnableFrameExtraction.Value)
                        $rollbackActions.Add(("Restored EnableFrameExtraction={0} on '{1}'" -f [int]$priorRegSnapshot.EnableFrameExtraction.Value, $targetInstance.InstanceId))
                    }
                    else {
                        Set-LumaBridgeDeviceEnableFrameExtraction -DeviceParametersPath $targetInstance.DeviceParametersPath -Clear
                        $rollbackActions.Add(("Cleared temporary EnableFrameExtraction on '{0}' (absent before run)" -f $targetInstance.InstanceId))
                    }
                    $needDeviceRestart = $true
                }
                catch {
                    $msg = ("Failed restoring EnableFrameExtraction on '{0}': {1}" -f $targetInstance.InstanceId, $_.Exception.Message)
                    $rollbackActions.Add($msg)
                    $rollbackIncompleteReasons.Add($msg)
                }
            }

            if ($modifiedAuthSid -and $null -ne $priorRegSnapshot) {
                try {
                    if ($priorRegSnapshot.AuthorizedHostUserSid.ValueExists -and -not [string]::IsNullOrWhiteSpace([string]$priorRegSnapshot.AuthorizedHostUserSid.Value)) {
                        Set-LumaBridgeDeviceAuthorizedHostUserSid -DeviceParametersPath $targetInstance.DeviceParametersPath -SidString ([string]$priorRegSnapshot.AuthorizedHostUserSid.Value)
                        $rollbackActions.Add(("Restored prior AuthorizedHostUserSid on '{0}'" -f $targetInstance.InstanceId))
                    }
                    else {
                        Set-LumaBridgeDeviceAuthorizedHostUserSid -DeviceParametersPath $targetInstance.DeviceParametersPath -Clear
                        $rollbackActions.Add(("Cleared temporary AuthorizedHostUserSid on '{0}'" -f $targetInstance.InstanceId))
                    }
                    $needDeviceRestart = $true
                }
                catch {
                    $msg = ("Failed restoring AuthorizedHostUserSid on '{0}': {1}" -f $targetInstance.InstanceId, $_.Exception.Message)
                    $rollbackActions.Add($msg)
                    $rollbackIncompleteReasons.Add($msg)
                }
            }

            if ($modifiedGpuTrans -and $null -ne $priorRegSnapshot) {
                try {
                    if ($priorRegSnapshot.EnableGpuSharedTransport.ValueExists) {
                        Set-LumaBridgeDeviceEnableGpuSharedTransport -DeviceParametersPath $targetInstance.DeviceParametersPath -Value ([int]$priorRegSnapshot.EnableGpuSharedTransport.Value)
                        $rollbackActions.Add(("Restored prior EnableGpuSharedTransport={0} on '{1}'" -f [int]$priorRegSnapshot.EnableGpuSharedTransport.Value, $targetInstance.InstanceId))
                    }
                    else {
                        Set-LumaBridgeDeviceEnableGpuSharedTransport -DeviceParametersPath $targetInstance.DeviceParametersPath -Clear
                        $rollbackActions.Add(("Cleared temporary EnableGpuSharedTransport on '{0}'" -f $targetInstance.InstanceId))
                    }
                    $needDeviceRestart = $true
                }
                catch {
                    $msg = ("Failed restoring EnableGpuSharedTransport on '{0}': {1}" -f $targetInstance.InstanceId, $_.Exception.Message)
                    $rollbackActions.Add($msg)
                    $rollbackIncompleteReasons.Add($msg)
                }
            }

            # Restore EnableVirtualMonitor if Stage 7 ran OR if Stage 6 update altered it (e.g., disabled 1->0 before failing).
            if ($null -ne $priorRegSnapshot -and ($modifiedVirtMon -or ($driverInstallAttempted -and $initialSnapshot.ExistedBeforeRun))) {
                try {
                    if ($priorRegSnapshot.EnableVirtualMonitor.ValueExists) {
                        $curMonVal = Get-LumaBridgeDeviceEnableVirtualMonitor -DeviceParametersPath $targetInstance.DeviceParametersPath
                        if ($null -eq $curMonVal -or [int]$curMonVal -ne [int]$priorRegSnapshot.EnableVirtualMonitor.Value) {
                            Set-LumaBridgeDeviceEnableVirtualMonitor -DeviceParametersPath $targetInstance.DeviceParametersPath -Value ([int]$priorRegSnapshot.EnableVirtualMonitor.Value)
                            $rollbackActions.Add(("Restored prior EnableVirtualMonitor={0} on '{1}'" -f [int]$priorRegSnapshot.EnableVirtualMonitor.Value, $targetInstance.InstanceId))
                            $needDeviceRestart = $true
                        }
                    }
                    elseif ($modifiedVirtMon) {
                        Set-LumaBridgeDeviceEnableVirtualMonitor -DeviceParametersPath $targetInstance.DeviceParametersPath -Clear
                        $rollbackActions.Add(("Cleared temporary EnableVirtualMonitor on '{0}' (absent before run)" -f $targetInstance.InstanceId))
                        $needDeviceRestart = $true
                    }
                }
                catch {
                    $msg = ("Failed restoring EnableVirtualMonitor on '{0}': {1}" -f $targetInstance.InstanceId, $_.Exception.Message)
                    $rollbackActions.Add($msg)
                    $rollbackIncompleteReasons.Add($msg)
                }
            }

            if ($needDeviceRestart) {
                try {
                    $null = Invoke-LumaBridgeExternalCommand -FilePath 'pnputil.exe' -Arguments @('/restart-device', $targetInstance.InstanceId)
                    $rollbackActions.Add(("Restarted device '{0}' to apply restored parameters" -f $targetInstance.InstanceId))
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
        if ($shouldFullUninstall) {
            if ($postRollbackInstances.Count -ne 0) {
                $msg = ("Expected 0 PnP instances after full uninstall, found {0}" -f $postRollbackInstances.Count)
                $rollbackIncompleteReasons.Add($msg)
                $unrestoredStateDetails.Add($msg)
            }
            $runtimeCleanupSucceeded = ($postRollbackInstances.Count -eq 0) -and ($rollbackIncompleteReasons.Count -eq 0)
            $driverBindingPersisted = $false
            $systemStateRestored = $runtimeCleanupSucceeded -and (-not $initialSnapshot.ExistedBeforeRun)
        }
        elseif ($postRollbackInstances.Count -eq 1) {
            $rbInst = $postRollbackInstances[0]
            $extReset = if ($null -ne $priorRegSnapshot -and $priorRegSnapshot.EnableFrameExtraction.ValueExists) {
                ($null -ne $rbInst.EnableFrameExtraction -and [int]$rbInst.EnableFrameExtraction -eq [int]$priorRegSnapshot.EnableFrameExtraction.Value)
            }
            else {
                ($null -eq $rbInst.EnableFrameExtraction)
            }
            $monReset = if ($null -ne $priorRegSnapshot -and $priorRegSnapshot.EnableVirtualMonitor.ValueExists) {
                ($null -ne $rbInst.EnableVirtualMonitor -and [int]$rbInst.EnableVirtualMonitor -eq [int]$priorRegSnapshot.EnableVirtualMonitor.Value)
            }
            else {
                ($null -eq $rbInst.EnableVirtualMonitor)
            }
            $rbSidVal = [string](Get-LumaBridgeValidationOptionalProp -InputObject $rbInst -PropertyName 'AuthorizedHostUserSid' -DefaultValue '')
            $sidReset = if ($null -ne $priorRegSnapshot -and $priorRegSnapshot.AuthorizedHostUserSid.ValueExists) {
                ($rbSidVal -eq [string]$priorRegSnapshot.AuthorizedHostUserSid.Value)
            }
            else {
                [string]::IsNullOrWhiteSpace($rbSidVal)
            }
            $rbGpuTrans = Get-LumaBridgeValidationOptionalProp -InputObject $rbInst -PropertyName 'EnableGpuSharedTransport' -DefaultValue $null
            $gpuTransReset = if ($null -ne $priorRegSnapshot -and $priorRegSnapshot.EnableGpuSharedTransport.ValueExists) {
                ($null -ne $rbGpuTrans -and [int]$rbGpuTrans -eq [int]$priorRegSnapshot.EnableGpuSharedTransport.Value)
            }
            else {
                ($null -eq $rbGpuTrans)
            }
            $devHealthy = ($rbInst.Status -ieq 'OK' -and ($null -eq $rbInst.ProblemCode -or [int]$rbInst.ProblemCode -eq 0))

            if (-not $extReset) {
                $m = ("EnableFrameExtraction is '{0}' after rollback (expected '{1}')" -f $rbInst.EnableFrameExtraction, $(if ($null -ne $priorRegSnapshot -and $priorRegSnapshot.EnableFrameExtraction.ValueExists) { $priorRegSnapshot.EnableFrameExtraction.Value } else { '<absent>' }))
                $rollbackIncompleteReasons.Add($m); $unrestoredStateDetails.Add($m)
            }
            if (-not $monReset) {
                $m = ("EnableVirtualMonitor is '{0}' after rollback (expected '{1}')" -f $rbInst.EnableVirtualMonitor, $(if ($null -ne $priorRegSnapshot -and $priorRegSnapshot.EnableVirtualMonitor.ValueExists) { $priorRegSnapshot.EnableVirtualMonitor.Value } else { '<absent>' }))
                $rollbackIncompleteReasons.Add($m); $unrestoredStateDetails.Add($m)
            }
            if (-not $sidReset) {
                $m = 'AuthorizedHostUserSid did not match initial snapshot after rollback'
                $rollbackIncompleteReasons.Add($m); $unrestoredStateDetails.Add($m)
            }
            if (-not $gpuTransReset) {
                $m = ("EnableGpuSharedTransport is '{0}' after rollback (expected '{1}')" -f $rbGpuTrans, $(if ($null -ne $priorRegSnapshot -and $priorRegSnapshot.EnableGpuSharedTransport.ValueExists) { $priorRegSnapshot.EnableGpuSharedTransport.Value } else { '<absent>' }))
                $rollbackIncompleteReasons.Add($m); $unrestoredStateDetails.Add($m)
            }
            if (-not $devHealthy) {
                $m = ("Post-rollback device unhealthy (Status='{0}', ProblemCode={1})" -f $rbInst.Status, $rbInst.ProblemCode)
                $rollbackIncompleteReasons.Add($m); $unrestoredStateDetails.Add($m)
            }

            $runtimeCleanupSucceeded = ($extReset -and $monReset -and $sidReset -and $gpuTransReset -and $devHealthy -and ($rollbackIncompleteReasons.Count -eq 0))
            $driverBindingPersisted = ($driverInstallCompleted -and (-not $shouldFullUninstall))
            $driverVersionOrInfChanged = $false
            if ($initialSnapshot.ExistedBeforeRun -and $null -ne $initialSnapshot.PnpInstance) {
                $driverVersionOrInfChanged = (
                    ($rbInst.DriverVersion -ne $initialSnapshot.PnpInstance.DriverVersion) -or
                    ($rbInst.DriverInfPath -ne $initialSnapshot.PnpInstance.DriverInfPath)
                )
            }
            elseif (-not $initialSnapshot.ExistedBeforeRun) {
                $driverVersionOrInfChanged = $true
            }
            if ($driverBindingPersisted -and $driverVersionOrInfChanged) {
                $unrestoredStateDetails.Add(("Authorized driver binding persisted: '{0}' INF='{1}' Version='{2}' (no automatic binary downgrade)." -f $rbInst.InstanceId, $rbInst.DriverInfPath, $rbInst.DriverVersion))
            }
            $systemStateRestored = ($runtimeCleanupSucceeded -and (-not $driverBindingPersisted) -and (-not $driverVersionOrInfChanged))
        }
        else {
            if ($null -ne $preExistingInstance) {
                $m = ("Pre-existing PnP instance '{0}' missing after rollback" -f $preExistingInstance.InstanceId)
                $rollbackIncompleteReasons.Add($m); $unrestoredStateDetails.Add($m)
            }
            $runtimeCleanupSucceeded = ($null -eq $preExistingInstance) -and ($rollbackIncompleteReasons.Count -eq 0)
            $driverBindingPersisted = $false
            $systemStateRestored = $runtimeCleanupSucceeded
        }

        if ($etwStarted -and -not $etwStopped) {
            $m = 'ETW session remained active after rollback.'
            $rollbackIncompleteReasons.Add($m); $unrestoredStateDetails.Add($m)
            $runtimeCleanupSucceeded = $false
            $systemStateRestored = $false
        }
        $preExistingCertsPreserved = $true
        $missingPreExistingCerts = New-Object System.Collections.Generic.List[string]
        if ($null -ne $initialSnapshot -and $null -ne $initialSnapshot.CertificateSnapshot -and $null -ne $initialSnapshot.CertificateSnapshot.Stores) {
            $postRollbackCertSnap = Get-LumaBridgeCertificateStoreSnapshot -Thumbprint $CertificateThumbprint -Subject $CertificateSubject
            foreach ($storeProp in $initialSnapshot.CertificateSnapshot.Stores.PSObject.Properties) {
                $sName = $storeProp.Name
                $beforeStore = $storeProp.Value
                if (-not [bool]$beforeStore.Accessible) { continue }
                $afterStore = if ($null -ne $postRollbackCertSnap -and $null -ne $postRollbackCertSnap.Stores -and ($postRollbackCertSnap.Stores.PSObject.Properties.Name -contains $sName)) {
                    $postRollbackCertSnap.Stores.$sName
                } else { $null }
                $afterThumbs = @()
                if ($null -ne $afterStore -and $null -ne $afterStore.Certs) {
                    $afterThumbs = @($afterStore.Certs | ForEach-Object { $_.Thumbprint })
                }
                foreach ($bc in @($beforeStore.Certs)) {
                    if ($afterThumbs -notcontains $bc.Thumbprint) {
                        $preExistingCertsPreserved = $false
                        $missingPreExistingCerts.Add(("{0}\{1}" -f $sName, $bc.Thumbprint))
                    }
                }
            }
            if (-not $preExistingCertsPreserved) {
                $m = ("Pre-existing certificate(s) missing after rollback: {0}" -f ($missingPreExistingCerts -join ', '))
                $rollbackIncompleteReasons.Add($m); $unrestoredStateDetails.Add($m)
                $runtimeCleanupSucceeded = $false
                $systemStateRestored = $false
            }
        }
    }
    catch {
        $preExistingCertsPreserved = $false
        $runtimeCleanupSucceeded = $false
        $systemStateRestored = $false
        $m = ("Post-rollback verification failed: {0}" -f $_.Exception.Message)
        $rollbackIncompleteReasons.Add($m)
        $unrestoredStateDetails.Add($m)
    }

    $rollbackClean = ($runtimeCleanupSucceeded -and ($rollbackIncompleteReasons.Count -eq 0))
    $functionalValidationSucceeded = ([string]::IsNullOrWhiteSpace($validationError) -and $null -ne $acceptanceCriteria -and [bool]$acceptanceCriteria.AllPassed)
    $overallSucceeded = ($functionalValidationSucceeded -and $rollbackClean)

    if ($null -ne $acceptanceCriteria) {
        $acceptanceCriteria.RollbackClean = $rollbackClean
        $acceptanceCriteria.RuntimeCleanupSucceeded = $runtimeCleanupSucceeded
        $acceptanceCriteria.SystemStateRestored = $systemStateRestored
        $acceptanceCriteria.DriverBindingPersisted = $driverBindingPersisted
        $acceptanceCriteria.OverallSucceeded = $overallSucceeded
    }

    $manualRecoverySteps = @(
        'Identify the specific LumaBridge host process PID via Get-CimInstance Win32_Process -Filter "Name=''lumabridge-host.exe''" before stopping anything (never run Stop-Process -Name blindly across unrelated sessions).',
        'Identify the LumaBridge PnP instance dynamically via DEVPKEY_Device_HardwareIds = Root\LumaBridgeIddDriver (never touch third-party displays).',
        'Restore EnableFrameExtraction, EnableGpuSharedTransport, AuthorizedHostUserSid, and EnableVirtualMonitor to InitialSystemSnapshot.RegistryValues (e.g., keep EnableVirtualMonitor=1 if it existed before the run), then run pnputil /restart-device <InstanceId>.',
        'Preserve pre-existing certificates (e.g., 1EEFC55BD7EEB2A9115432607B97978736B9DFE0) and historical Driver Store packages unless explicitly authorized.'
    )

    $reportPayload = [pscustomobject]@{
        RunId                         = $runId
        CompletedAtUtc                = (Get-Date).ToUniversalTime().ToString('o')
        Configuration                 = $Configuration
        TestProfile                   = $TestProfile
        Branch                        = $currentBranch
        PreValidationState            = $preValidationState
        InitialSystemSnapshot         = $initialSnapshot
        SecurityState                 = $prereq.SecurityState
        TimeoutPlan                   = [pscustomobject]$timeoutPlan
        BenchmarkGateCriteria         = $benchmarkGateCriteria
        EtwFileSizePolicy             = [pscustomobject]@{ CoreMaxFileSizeMb = $effectiveCoreEtwMaxMb; Note = $(if ($maxSubprofileSec -ge 600) { 'Expanded ETW limit for prolonged run; monitor for log wrap' } else { 'Standard sequential ETW size' }) }
        LatencySamplingAudit          = $latencySamplingAudit
        SignedStagingDir              = $signedStagingDir
        CertificateThumbprint         = $signedThumbprint
        CertificateWasPreExisting     = $certWasPreExistingInSnapshot
        PreExistingCertsPreserved     = $preExistingCertsPreserved
        AuthorizedHostUserSid         = $effectiveAuthorizedUserSid
        PreBuildHashes                = $preBuildHashes
        PostSignBuildHashes           = $postSignBuildHashes
        PackageVerified               = [bool]$packageVerify.SignerCertificatesMatch
        InstalledBindingCheck         = $installedBindingCheck
        EtwVerifyResult               = $etwVerifyResult
        PreStage9WudfResolution       = $preStage9WudfResolution
        PostRunWudfResolution         = $postRunWudfResolution
        SmokeHostProcessResult        = $smokeHostResult
        SmokeSummaryValidation        = $smokeSummaryValidation
        SmokeHostSummary              = $smokeSummary
        PerfHostProcessResult         = $perfHostResult
        PerfSummaryValidation         = $perfSummaryValidation
        PerfHostSummary               = $perfSummary
        Benchmark30sProcessResult     = $bench30sHostResult
        Benchmark30sSummaryValidation = $bench30sSummaryValidation
        Benchmark30sHostSummary       = $bench30sSummary
        StabilityProcessResult        = $stabilityHostResult
        StabilitySummaryValidation    = $stabilitySummaryValidation
        StabilityHostSummary          = $stabilitySummary
        SubprofileEvaluations         = [pscustomobject]$subprofileEvaluations
        SyntheticFidelityResult       = $syntheticFidelityResult
        ProcessResourceSummary        = $processResourceSummary
        HostProcessResult             = $hostProcResult
        HostSummary                   = $hostSummary
        DiagnosticsResult             = $diagResult
        DiagnosticsCollectionError    = $diagCollectionError
        AcceptanceCriteria            = $acceptanceCriteria
        FunctionalValidationSucceeded = $functionalValidationSucceeded
        RuntimeCleanupSucceeded       = $runtimeCleanupSucceeded
        SystemStateRestored           = $systemStateRestored
        DriverBindingPersisted        = $driverBindingPersisted
        RollbackClean                 = $rollbackClean
        OverallSucceeded              = $overallSucceeded
        ValidationSucceeded           = $overallSucceeded
        ValidationError               = $validationError
        RollbackScopeNote             = $rollbackScopeNote
        RollbackActions               = @($rollbackActions.ToArray())
        RollbackIncompleteReasons     = @($rollbackIncompleteReasons.ToArray())
        UnrestoredStateDetails        = @($unrestoredStateDetails.ToArray())
        ManualRecoverySteps           = $manualRecoverySteps
        PostRollbackInstances         = $postRollbackInstances
        OutputDir                     = $OutputDir
    }

    try {
        if (-not (Test-Path -LiteralPath $OutputDir)) {
            $null = New-Item -Path $OutputDir -ItemType Directory -Force
        }
        $reportPayload | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $reportJsonPath -Encoding UTF8

        $mdLines = New-Object System.Collections.Generic.List[string]
        $mdLines.Add('# LumaBridge M4.2.1 Functional Validation Report')
        $mdLines.Add('')
        $mdLines.Add(("- RunId: ``{0}`` | Completed UTC: ``{1}``" -f $runId, $reportPayload.CompletedAtUtc))
        $mdLines.Add(("- Branch: ``{0}`` | Configuration: ``{1}`` | Profile: ``{2}``" -f $currentBranch, $Configuration, $TestProfile))
        $mdLines.Add(("- Staged Package (``StagingDir``): ``{0}``" -f $signedStagingDir))
        $mdLines.Add(("- FunctionalValidationSucceeded: ``{0}`` | RuntimeCleanupSucceeded: ``{1}`` | SystemStateRestored: ``{2}`` | DriverBindingPersisted: ``{3}`` | RollbackClean: ``{4}`` | OverallSucceeded: ``{5}``" -f `
            $functionalValidationSucceeded, $runtimeCleanupSucceeded, $systemStateRestored, $driverBindingPersisted, $rollbackClean, $overallSucceeded))
        $mdLines.Add(("- Rollback Scope: {0}" -f $rollbackScopeNote))
        if (-not [string]::IsNullOrWhiteSpace($validationError)) {
            $mdLines.Add(("- Error: ``{0}``" -f $validationError))
        }
        foreach ($seKey in $subprofileEvaluations.Keys) {
            $seVal = $subprofileEvaluations[$seKey]
            $mdLines.Add(("- Subprofile ``{0}``: Passed=``{1}``, SummaryStatus=``{2}``, Res=``{3}``, Dur=``{4}s``, Valid=``{5}``/``{6}``, Enc=``{7}``, Dec=``{8}``, DropGpu=``{9}``, DropNv=``{10}``, Fps=``{11}``, TsErr=``{12}``" -f `
                $seKey, $seVal.Passed, $seVal.SummaryStatus, $seVal.MeasuredResolution, $seVal.MeasuredDurationSec, `
                $seVal.FramesValid, $seVal.ExpectedMinFrames, $seVal.FramesEncoded, $seVal.FramesDecoded, `
                $seVal.FramesDropped.GpuFramesDropped, $seVal.FramesDropped.TotalNvencDrops, $seVal.MeasuredSustainedFps, `
                $seVal.TemporalEval.TimestampMeasurementErrors))
        }
        if ($null -ne $acceptanceCriteria) {
            $mdLines.Add(("- Acceptance: StructuralDecode=``{0}``, FidelityPSNR=``{1}``, ProlongedStabilityProven=``{2}``, WudfIdentity=``{3}``" -f `
                $acceptanceCriteria.StructuralDecodeValidated, $acceptanceCriteria.FidelityPsnrValidated, $acceptanceCriteria.ProlongedStabilityProven, $wudfIdentityStatus))
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
        if ($unrestoredStateDetails.Count -gt 0) {
            $mdLines.Add('')
            $mdLines.Add('## Non-Restored or Persisted State Details')
            foreach ($unr in $unrestoredStateDetails) {
                $mdLines.Add(("- {0}" -f $unr))
            }
        }
        $mdLines | Set-Content -LiteralPath $reportMdPath -Encoding UTF8
    }
    catch {
    }
}

if (-not $overallSucceeded) {
    $errParts = New-Object System.Collections.Generic.List[string]
    if (-not [string]::IsNullOrWhiteSpace($validationError)) {
        $errParts.Add($validationError)
    }
    if (-not $rollbackClean) {
        $rbDetail = if ($rollbackIncompleteReasons.Count -gt 0) { ($rollbackIncompleteReasons -join '; ') } else { 'Post-rollback state verification did not pass.' }
        $errParts.Add(("Rollback incomplete: {0}" -f $rbDetail))
    }
    $combinedErr = ($errParts -join ' | ')
    throw ("LumaBridge M4.2.1 functional validation failed: {0}. OverallSucceeded={1}. FunctionalValidationSucceeded={2}. RollbackClean={3}. RuntimeCleanupSucceeded={4}. SystemStateRestored={5}. DriverBindingPersisted={6}. Report='{7}'." -f `
        $combinedErr, $overallSucceeded, $functionalValidationSucceeded, $rollbackClean, $runtimeCleanupSucceeded, $systemStateRestored, $driverBindingPersisted, $reportJsonPath)
}

return [pscustomobject]@{
    RunId                         = $runId
    ValidationSucceeded           = $overallSucceeded
    OverallSucceeded              = $overallSucceeded
    FunctionalValidationSucceeded = $functionalValidationSucceeded
    RuntimeCleanupSucceeded       = $runtimeCleanupSucceeded
    SystemStateRestored           = $systemStateRestored
    DriverBindingPersisted        = $driverBindingPersisted
    RollbackClean                 = $rollbackClean
    RollbackIncompleteReasons     = @($rollbackIncompleteReasons.ToArray())
    UnrestoredStateDetails        = @($unrestoredStateDetails.ToArray())
    RollbackScopeNote             = $rollbackScopeNote
    Configuration                 = $Configuration
    TestProfile                   = $TestProfile
    Branch                        = $currentBranch
    StagingDir                    = $signedStagingDir
    OutputDir                     = $OutputDir
    ReportJsonPath                = $reportJsonPath
    ReportMdPath                  = $reportMdPath
    HostSummaryPath               = $hostJsonPath
    SmokeSummaryPath              = $hostSmokeJsonPath
    PerfSummaryPath               = $hostPerfJsonPath
    Benchmark30sSummaryPath       = $hostBench30sJsonPath
    StabilitySummaryPath          = $hostStabilityJsonPath
    SubprofileEvaluations         = [pscustomobject]$subprofileEvaluations
    SmokeSummary                  = $smokeSummary
    PerfSummary                   = $perfSummary
    Benchmark30sSummary           = $bench30sSummary
    StabilitySummary              = $stabilitySummary
    ProcessResourceSummary        = $processResourceSummary
    HostSummary                   = $hostSummary
    AcceptanceCriteria            = $acceptanceCriteria
    DiagnosticsResult             = $diagResult
    RollbackActions               = @($rollbackActions.ToArray())
    PostRollbackInstances         = $postRollbackInstances
}
