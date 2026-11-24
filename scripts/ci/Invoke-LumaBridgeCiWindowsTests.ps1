<#
.SYNOPSIS
    Non-administrative CI runner for LumaBridge Display Windows C++ and PowerShell checks.

.DESCRIPTION
    Validates PowerShell syntax across tracked scripts, initializes the MSVC x64 toolchain
    without mutating the repository or OS state, compiles and runs the explicitly allowlisted
    non-WDK/non-GPU C++ unit/component test suites, verifies lumabridge-host.exe compilation,
    validates exact bijection over all 71 tests in LumaBridgeFunctionalToolingTests.ps1, and
    executes the explicitly allowlisted 21 non-WDK PowerShell tests with strict exit propagation.
#>
[CmdletBinding()]
param(
    [string]$RepoRoot,
    [string]$BuildRoot,
    [string]$SummaryPath,
    [string]$JsonReportPath,
    [string]$LogDir,
    [switch]$SkipCpp,
    [switch]$SkipPowerShell,
    [switch]$ValidateInventoryOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Resolve-NormalizedRepoRoot {
    param([string]$ExplicitRoot)
    if (-not [string]::IsNullOrWhiteSpace($ExplicitRoot)) {
        return (Resolve-Path -LiteralPath $ExplicitRoot).Path
    }
    return (Resolve-Path -LiteralPath (Join-Path -Path $PSScriptRoot -ChildPath '..\..')).Path
}

function Scrub-SensitivePaths {
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) {
        return $Text
    }
    $result = $Text
    foreach ($candidate in @($env:USERPROFILE, $env:HOME)) {
        if (-not [string]::IsNullOrWhiteSpace($candidate)) {
            $result = [regex]::Replace($result, [regex]::Escape($candidate), '<USER_HOME>', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
        }
    }
    if (-not [string]::IsNullOrWhiteSpace($env:USERNAME)) {
        $result = [regex]::Replace(
            $result,
            '(?i)([A-Za-z]:\\Users\\)' + [regex]::Escape($env:USERNAME) + '(?=[\\/"''\s]|$)',
            '$1<USER>'
        )
    }
    return $result
}

function Resolve-VsDevCmdPath {
    $vswhereCandidates = @(
        (Join-Path -Path ${env:ProgramFiles(x86)} -ChildPath 'Microsoft Visual Studio\Installer\vswhere.exe'),
        (Join-Path -Path $env:ProgramFiles -ChildPath 'Microsoft Visual Studio\Installer\vswhere.exe')
    ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) -and (Test-Path -LiteralPath $_ -PathType Leaf) }

    foreach ($vswhere in $vswhereCandidates) {
        $installPaths = @(& $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath 2>$null)
        foreach ($installPath in $installPaths) {
            if (-not [string]::IsNullOrWhiteSpace($installPath)) {
                $devCmd = Join-Path -Path $installPath.Trim() -ChildPath 'Common7\Tools\VsDevCmd.bat'
                if (Test-Path -LiteralPath $devCmd -PathType Leaf) {
                    return $devCmd
                }
            }
        }
        $allPaths = @(& $vswhere -all -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath 2>$null)
        foreach ($installPath in $allPaths) {
            if (-not [string]::IsNullOrWhiteSpace($installPath)) {
                $devCmd = Join-Path -Path $installPath.Trim() -ChildPath 'Common7\Tools\VsDevCmd.bat'
                if (Test-Path -LiteralPath $devCmd -PathType Leaf) {
                    return $devCmd
                }
            }
        }
    }

    foreach ($root in @(${env:ProgramFiles(x86)}, $env:ProgramFiles)) {
        if ([string]::IsNullOrWhiteSpace($root)) { continue }
        foreach ($rel in @(
            'Microsoft Visual Studio\2022\Enterprise\Common7\Tools\VsDevCmd.bat',
            'Microsoft Visual Studio\2022\Professional\Common7\Tools\VsDevCmd.bat',
            'Microsoft Visual Studio\2022\Community\Common7\Tools\VsDevCmd.bat',
            'Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat',
            'Microsoft Visual Studio\18\Enterprise\Common7\Tools\VsDevCmd.bat',
            'Microsoft Visual Studio\18\Community\Common7\Tools\VsDevCmd.bat',
            'Microsoft Visual Studio\18\BuildTools\Common7\Tools\VsDevCmd.bat'
        )) {
            $candidate = Join-Path -Path $root -ChildPath $rel
            if (Test-Path -LiteralPath $candidate -PathType Leaf) {
                return $candidate
            }
        }
    }

    return $null
}

function Initialize-MsvcX64Environment {
    $existingCl = Get-Command -Name 'cl.exe' -ErrorAction SilentlyContinue
    if ($null -ne $existingCl) {
        return "Preconfigured: $($existingCl.Source)"
    }

    $vsDevCmd = Resolve-VsDevCmdPath
    if ([string]::IsNullOrWhiteSpace($vsDevCmd)) {
        throw 'Could not locate VsDevCmd.bat with MSVC x64 tools (Microsoft.VisualStudio.Component.VC.Tools.x86.x64).'
    }

    $tempBat = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath ("lb_vsenv_{0}.cmd" -f ([guid]::NewGuid().ToString('N')))
    try {
        $batLines = @(
            '@echo off',
            ('call "{0}" -arch=amd64 -host_arch=amd64 >nul' -f $vsDevCmd),
            'if errorlevel 1 exit /b %errorlevel%',
            'set'
        )
        [System.IO.File]::WriteAllLines($tempBat, $batLines, [System.Text.Encoding]::ASCII)
        $prevEap = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        try {
            $envLines = @(& cmd.exe /d /c ('"{0}"' -f $tempBat) 2>&1)
            $cmdExit = $LASTEXITCODE
        }
        finally {
            $ErrorActionPreference = $prevEap
        }
        if ($cmdExit -ne 0) {
            throw ("VsDevCmd.bat failed with exit code {0}." -f $cmdExit)
        }
        foreach ($line in $envLines) {
            $text = [string]$line
            $eqIdx = $text.IndexOf('=')
            if ($eqIdx -gt 0) {
                $varName = $text.Substring(0, $eqIdx)
                $varVal = $text.Substring($eqIdx + 1)
                if (-not [string]::IsNullOrWhiteSpace($varName)) {
                    [System.Environment]::SetEnvironmentVariable($varName, $varVal, 'Process')
                }
            }
        }
    }
    finally {
        Remove-Item -LiteralPath $tempBat -Force -ErrorAction SilentlyContinue
    }

    $resolvedCl = Get-Command -Name 'cl.exe' -ErrorAction SilentlyContinue
    if ($null -eq $resolvedCl) {
        throw 'cl.exe is still unavailable after importing VsDevCmd.bat x64 environment.'
    }
    return $resolvedCl.Source
}

function Invoke-NativeTool {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Executable,
        [Parameter(Mandatory = $false)]
        [AllowEmptyCollection()]
        [string[]]$Arguments = @(),
        [Parameter(Mandatory = $true)]
        [string]$WorkingDirectory
    )

    Push-Location -LiteralPath $WorkingDirectory
    try {
        $prevEap = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        try {
            if ($null -ne $Arguments -and $Arguments.Count -gt 0) {
                $output = @(& $Executable @Arguments 2>&1 | ForEach-Object { [string]$_ })
            }
            else {
                $output = @(& $Executable 2>&1 | ForEach-Object { [string]$_ })
            }
            $exitCode = $LASTEXITCODE
        }
        finally {
            $ErrorActionPreference = $prevEap
        }
        return [pscustomobject]@{
            ExitCode = $exitCode
            Output   = $output
        }
    }
    finally {
        Pop-Location
    }
}

$resolvedRepoRoot = Resolve-NormalizedRepoRoot -ExplicitRoot $RepoRoot
$runId = [guid]::NewGuid().ToString('N').Substring(0, 12)
$ownsBuildRoot = $false
if ([string]::IsNullOrWhiteSpace($BuildRoot)) {
    $BuildRoot = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath ("LumaBridgeCiBuild_{0}" -f $runId)
    $ownsBuildRoot = $true
}
if ([string]::IsNullOrWhiteSpace($LogDir)) {
    $LogDir = Join-Path -Path $BuildRoot -ChildPath 'logs'
}

New-Item -Path $BuildRoot -ItemType Directory -Force | Out-Null
New-Item -Path $LogDir -ItemType Directory -Force | Out-Null

$overallPassed = $true
$failures = New-Object System.Collections.Generic.List[string]
$psSyntaxResults = New-Object System.Collections.Generic.List[object]
$cppSuiteResults = New-Object System.Collections.Generic.List[object]
$cppHostBuildResult = $null
$psTestSummary = $null
$toolchainPath = $null

# ---------------------------------------------------------------------------
# Explicit C++ Test & Build Inventory (all 10 unit/component suites + E2E + Host)
# ---------------------------------------------------------------------------
$cppInventory = @(
    [ordered]@{
        Name          = 'AdapterLifecycleTests'
        SourcePath    = 'windows/driver/tests/AdapterLifecycleTests.cpp'
        Selected      = $true
        ExpectedCount = 21
        Categories    = @('DETERMINISTIC_CPU_ONLY', 'WINDOWS_TOOLCHAIN_REQUIRED')
        Reason        = 'Deterministic state machine & diagnostic stage checks.'
        CompileInputs = @('windows\driver\tests\AdapterLifecycleTests.cpp')
        StdFlag       = '/std:c++17'
        ExtraFlags    = @()
        LinkLibs      = @()
    },
    [ordered]@{
        Name          = 'MonitorModesTests'
        SourcePath    = 'windows/driver/tests/MonitorModesTests.cpp'
        Selected      = $true
        ExpectedCount = 12
        Categories    = @('DETERMINISTIC_CPU_ONLY', 'WINDOWS_TOOLCHAIN_REQUIRED')
        Reason        = 'Deterministic CTA-861 mode & bandwidth validation.'
        CompileInputs = @('windows\driver\tests\MonitorModesTests.cpp', 'windows\driver\LumaBridgeIddDriver\MonitorModes.cpp')
        StdFlag       = '/std:c++17'
        ExtraFlags    = @()
        LinkLibs      = @()
    },
    [ordered]@{
        Name          = 'SwapChainLifecycleTests'
        SourcePath    = 'windows/driver/tests/SwapChainLifecycleTests.cpp'
        Selected      = $true
        ExpectedCount = 15
        Categories    = @('DETERMINISTIC_CPU_ONLY', 'WINDOWS_TOOLCHAIN_REQUIRED')
        Reason        = 'Deterministic SwapChainProcessor lifecycle via mock ISwapChainBackend.'
        CompileInputs = @('windows\driver\tests\SwapChainLifecycleTests.cpp', 'windows\driver\LumaBridgeIddDriver\SwapChainProcessor.cpp')
        StdFlag       = '/std:c++17'
        ExtraFlags    = @()
        LinkLibs      = @()
    },
    [ordered]@{
        Name          = 'VirtualMonitorLifecycleTests'
        SourcePath    = 'windows/driver/tests/VirtualMonitorLifecycleTests.cpp'
        Selected      = $true
        ExpectedCount = 15
        Categories    = @('DETERMINISTIC_CPU_ONLY', 'WINDOWS_TOOLCHAIN_REQUIRED')
        Reason        = 'Deterministic VirtualMonitorManager lifecycle via mock IVirtualMonitorBackend.'
        CompileInputs = @('windows\driver\tests\VirtualMonitorLifecycleTests.cpp', 'windows\driver\LumaBridgeIddDriver\VirtualMonitor.cpp')
        StdFlag       = '/std:c++17'
        ExtraFlags    = @()
        LinkLibs      = @()
    },
    [ordered]@{
        Name          = 'FrameExtractionTests'
        SourcePath    = 'windows/driver/tests/FrameExtractionTests.cpp'
        Selected      = $true
        ExpectedCount = 12
        Categories    = @('WINDOWS_TOOLCHAIN_REQUIRED')
        Reason        = 'D3D11 frame extraction with automatic D3D_DRIVER_TYPE_WARP fallback.'
        CompileInputs = @(
            'windows\driver\tests\FrameExtractionTests.cpp',
            'windows\driver\LumaBridgeIddDriver\FrameExtractor.cpp',
            'windows\driver\LumaBridgeIddDriver\FrameTransport.cpp',
            'windows\driver\LumaBridgeIddDriver\SharedTexturePool.cpp',
            'windows\driver\LumaBridgeIddDriver\SwapChainProcessor.cpp'
        )
        StdFlag       = '/std:c++17'
        ExtraFlags    = @()
        LinkLibs      = @('d3d11.lib', 'dxgi.lib', 'advapi32.lib')
    },
    [ordered]@{
        Name          = 'GpuSharedTextureTests'
        SourcePath    = 'windows/driver/tests/GpuSharedTextureTests.cpp'
        Selected      = $true
        ExpectedCount = 9
        Categories    = @('WINDOWS_TOOLCHAIN_REQUIRED')
        Reason        = 'SharedTexturePool & KeyedMutex contract tests with automatic D3D_DRIVER_TYPE_WARP fallback.'
        CompileInputs = @(
            'windows\driver\tests\GpuSharedTextureTests.cpp',
            'windows\driver\LumaBridgeIddDriver\SharedTexturePool.cpp',
            'windows\driver\LumaBridgeIddDriver\FrameTransport.cpp',
            'windows\driver\LumaBridgeIddDriver\SwapChainProcessor.cpp',
            'windows\host\FrameConsumer.cpp'
        )
        StdFlag       = '/std:c++17'
        ExtraFlags    = @('/DUNICODE', '/D_UNICODE', '/Iwindows\driver\LumaBridgeIddDriver')
        LinkLibs      = @('d3d11.lib', 'dxgi.lib', 'advapi32.lib', 'user32.lib', 'gdi32.lib')
    },
    [ordered]@{
        Name          = 'FrameIpcTests'
        SourcePath    = 'windows/driver/tests/FrameIpcTests.cpp'
        Selected      = $true
        ExpectedCount = 31
        Categories    = @('WINDOWS_TOOLCHAIN_REQUIRED')
        Reason        = 'Named Pipe LBIF v1.0/v1.1 security, backpressure, WARP fallback, and Auto stimulus surface.'
        CompileInputs = @(
            'windows\driver\tests\FrameIpcTests.cpp',
            'windows\driver\LumaBridgeIddDriver\SharedTexturePool.cpp',
            'windows\driver\LumaBridgeIddDriver\FrameTransport.cpp',
            'windows\host\FrameConsumer.cpp'
        )
        StdFlag       = '/std:c++17'
        ExtraFlags    = @('/DUNICODE', '/D_UNICODE')
        LinkLibs      = @('d3d11.lib', 'dxgi.lib', 'advapi32.lib', 'user32.lib', 'gdi32.lib')
    },
    [ordered]@{
        Name          = 'HostValidationWorkerAndStimulusTests'
        SourcePath    = 'windows/driver/tests/HostValidationWorkerAndStimulusTests.cpp'
        Selected      = $true
        ExpectedCount = 28
        Categories    = @('WINDOWS_TOOLCHAIN_REQUIRED')
        Reason        = 'Async H264 worker, HostGateEvaluator, VirtualDisplayStimulus mocks, and COM/MF thread balance.'
        CompileInputs = @(
            'windows\driver\tests\HostValidationWorkerAndStimulusTests.cpp',
            'windows\host\FrameConsumer.cpp',
            'windows\host\NvencH264Encoder.cpp',
            'windows\host\H264BitstreamValidator.cpp'
        )
        StdFlag       = '/std:c++20'
        ExtraFlags    = @('/Od', '/Zi', '/MDd', '/DUNICODE', '/D_UNICODE', '/Iwindows\host', '/Iwindows\driver\LumaBridgeIddDriver')
        LinkLibs      = @('d3d11.lib', 'dxgi.lib', 'advapi32.lib', 'user32.lib', 'gdi32.lib', 'mfplat.lib', 'mfuuid.lib', 'wmcodecdspuuid.lib', 'ole32.lib')
    },
    [ordered]@{
        Name          = 'DriverPackageValidationTests'
        SourcePath    = 'windows/driver/tests/DriverPackageValidationTests.cpp'
        Selected      = $false
        ExpectedCount = 6
        Categories    = @('WINDOWS_TOOLCHAIN_REQUIRED', 'WDK_REQUIRED')
        Reason        = 'Requires WDK MSBuild/StampInf/Inf2Cat build artifacts under windows/driver/x64/{Debug,Release}/LumaBridgeIddDriver.'
        CompileInputs = @()
        StdFlag       = '/std:c++17'
        ExtraFlags    = @()
        LinkLibs      = @('crypt32.lib', 'wintrust.lib')
    },
    [ordered]@{
        Name          = 'NvencEncoderTests'
        SourcePath    = 'windows/driver/tests/NvencEncoderTests.cpp'
        Selected      = $false
        ExpectedCount = 8
        Categories    = @('WINDOWS_TOOLCHAIN_REQUIRED', 'GPU_REQUIRED', 'NVENC_REQUIRED')
        Reason        = 'Requires physical NVIDIA GPU and installed nvEncodeAPI64.dll runtime.'
        CompileInputs = @()
        StdFlag       = '/std:c++17'
        ExtraFlags    = @()
        LinkLibs      = @()
    }
)

# ---------------------------------------------------------------------------
# Explicit PowerShell Bijection Inventory (all 71 cases in LumaBridgeFunctionalToolingTests.ps1)
# ---------------------------------------------------------------------------
$selectedPowerShellTests = @(
    'PnpIdentificationUsesEffectiveDevpkeyHardwareIdsOnly',
    'DriverStoreXmlParsingIsLocaleIndependent',
    'VirtualMonitorEnablePartialFailureTriggersRollback',
    'UninstallOmitsForceByDefaultAndSupportsOptInForce',
    'UninstallCertificateRemovalRequiresThumbprintAndConfirmation',
    'DiagnosticsIdentifiesLumaBridgeWudfHostProcess',
    'PnpProblemStatusAndStartupBreadcrumbsCollected',
    'SetupApiExcerptAndEventChannelCollection',
    'DriverStageSummaryIdentifiesLastSuccessfulAndFailingStage',
    'CrashDumpInventoryAndEtwTraceDryRun',
    'EtwTraceUsesProviderFileAndSeparatesDxgKrnlSession',
    'StreamingEtlQueryAppliesNativeXPathWithoutPreFilterCap',
    'PrepareIddSampleReferenceDryRunEnforcesIsolation',
    'DiagnosticStageBuildManifestAndSubkeyBreadcrumbs',
    'ObservabilityVerifyProvidersAndUnclampedEtlTraceLoggingRecovery',
    'M01_S04_TimeoutCalculation30To3600SecAndOverflowValidation',
    'M01_S05_ContinuousTelemetrySamplingAndNotMeasuredContract',
    'M01_S08_HostSecurityVbsHvciAndServicesReadOnlyDiagnostics',
    'M022_RuntimeInformationResolvesFrameworkUnambiguouslyAndHandlesCollisions',
    'M022_IsolatedProcessWithPsReadLineLoadedPassesPrerequisitesUnderStrictMode',
    'M024_DecoupledLightweightAndGpuTelemetrySkipsEndGpuCounterAndReportsIntervalsAndLeakAssessment'
)

$excludedPowerShellTests = [ordered]@{
    'PackageSigningAndCryptographicVerificationPositive' = 'WDK_REQUIRED (signtool.exe, Inf2Cat.exe, Release driver package)'
    'InfTamperingRejectedEvenWithAllowUntrustedChain' = 'WDK_REQUIRED (signtool.exe, Inf2Cat.exe, devcon.exe, Release driver package)'
    'DllTamperingRejectedEvenWithAllowUntrustedChain' = 'WDK_REQUIRED (signtool.exe, Inf2Cat.exe, Release driver package)'
    'UnsignedTamperedCatAndExpiredCertRejected' = 'WDK_REQUIRED (signtool.exe, Inf2Cat.exe, Release driver package)'
    'SignerCertificateMismatchRejected' = 'WDK_REQUIRED (signtool.exe, Inf2Cat.exe, Release driver package)'
    'IsolatedCleanStagingRejectsRepoPathsAndCleansResiduals' = 'WDK_REQUIRED (signtool.exe, Inf2Cat.exe, Release driver package)'
    'DuplicateDevicesBlockedByInstallAndMonitorScripts' = 'WDK_REQUIRED (Install-LumaBridgeDriver.ps1 requires devcon.exe)'
    'FreshInstallSucceedsAndConfirmsDriverBinding' = 'WDK_REQUIRED (signtool.exe, Inf2Cat.exe, devcon.exe, Release driver package)'
    'RepeatedInstallDisablesMonitorBeforeUpdate' = 'WDK_REQUIRED (signtool.exe, Inf2Cat.exe, devcon.exe, Release driver package)'
    'PartialFreshInstallFailureTriggersRollback' = 'WDK_REQUIRED (signtool.exe, Inf2Cat.exe, devcon.exe, Release driver package)'
    'PartialUpdateFailureTriggersRollback' = 'WDK_REQUIRED (signtool.exe, Inf2Cat.exe, devcon.exe, Release driver package)'
    'AllScriptsDryRunDoNotMutateSystemState' = 'WDK_REQUIRED (asserts BuildPackage.AllFilesPresent and WDK tools)'
    'InstallFailurePreservesPreRollbackDiagnosticsBeforeCleanup' = 'WDK_REQUIRED (signtool.exe, Inf2Cat.exe, devcon.exe, Release driver package)'
    'WppTmfCacheAndDecodeDryRunAndStreamFilter' = 'WDK_REQUIRED (asserts tracepdb.exe under Windows Kits)'
    'FunctionalValidationScriptDryRunAndFinallyRollbackOnFailure' = 'WDK_REQUIRED (Invoke-LumaBridgeFunctionalValidation requires signtool/Inf2Cat/devcon/Release package)'
    'HostProcessOutputCaptureGlobalTimeoutAndTwoProfileRunner' = 'WDK_REQUIRED (Invoke-LumaBridgeFunctionalValidation + New-M01ValidationMockHarness)'
    'M42GpuTransportNvencGatesAndRollback' = 'WDK_REQUIRED (Invoke-LumaBridgeFunctionalValidation + Release package + WDK tools)'
    'M421TimestampErrorsMaskingRejectedAndProlongedProfilesDryRun' = 'WDK_REQUIRED (New-M01ValidationMockHarness + Release package + WDK tools)'
    'M01_S01_WudfHostMultiCandidateAndAntiStaleCorrelation' = 'WDK_REQUIRED (New-M01ValidationMockHarness)'
    'M01_S01_WudfHostMissingReusedPidAndMidRunExitRejected' = 'WDK_REQUIRED (New-M01ValidationMockHarness)'
    'M01_S02_PartialRollbackAlwaysFailsOverallWithNonZeroThrow' = 'WDK_REQUIRED (New-M01ValidationMockHarness)'
    'M01_S03_BenchmarkRejectsWrongResolution' = 'WDK_REQUIRED (New-M01ValidationMockHarness)'
    'M01_S03_BenchmarkRejectsLowFramesOrLowSustainedFps' = 'WDK_REQUIRED (New-M01ValidationMockHarness)'
    'M01_S03_NvencSingleFrameEncodedRejected' = 'WDK_REQUIRED (New-M01ValidationMockHarness)'
    'M01_S03_ExcessiveFrameDropsRejected' = 'WDK_REQUIRED (New-M01ValidationMockHarness)'
    'M01_S03_Benchmark30sNeverProves180sProlongedStability' = 'WDK_REQUIRED (New-M01ValidationMockHarness)'
    'M01_S06_InitialSnapshotPreservesPreExistingCertsAndRegistrySemantics' = 'WDK_REQUIRED (New-M01ValidationMockHarness)'
    'M01_S07_StaleWrongRunIdAndIncompleteJsonRejected' = 'WDK_REQUIRED (New-M01ValidationMockHarness)'
    'M01_S07_WrongDriverVersionMissingBindingAndBinaryHashMismatchRejected' = 'WDK_REQUIRED (New-M01ValidationMockHarness)'
    'M01_S07_CompositeProfilesBothAndFullEvaluateEachSubprofileIndependently' = 'WDK_REQUIRED (New-M01ValidationMockHarness)'
    'M01_S06_S07_IntermediateStage6_7_8_9FailuresWithRecoveryAndDiagnostics' = 'WDK_REQUIRED (New-M01ValidationMockHarness)'
    'M021_Benchmark30sRejects28500MsAnd29999MsAndAccepts30000Ms' = 'WDK_REQUIRED (New-M01ValidationMockHarness)'
    'M021_ProlongedStability180sRejects171sAnd179999MsAndAccepts180000Ms' = 'WDK_REQUIRED (New-M01ValidationMockHarness)'
    'M021_InvalidQpcClockIdleConnectedPipeAndSafetyTimeoutRejected' = 'WDK_REQUIRED (New-M01ValidationMockHarness)'
    'M021_PercentileMethodologyAuditsHostAndNvencExactEstimatedAndNullUnavailable' = 'WDK_REQUIRED (New-M01ValidationMockHarness)'
    'M021_ProlongedDryRunForwardsConnectedDurationAndSafetyExecutionFlags' = 'WDK_REQUIRED (New-M01ValidationMockHarness)'
    'M022_PreflightFailureEmitsStructuredDiagnosticAndPreservesOriginalException' = 'WDK_REQUIRED (New-M01ValidationMockHarness)'
    'M024_Benchmark30sWithoutSmokePassesAndReportsFunctionalSmokeNotTested' = 'WDK_REQUIRED (New-M01ValidationMockHarness)'
    'M024_SmokeFailurePropagatesToAcceptanceCriteriaAndReport' = 'WDK_REQUIRED (New-M01ValidationMockHarness)'
    'M024_CpuFramesInGpuOnlySessionFailsSubprofileAndExitCode1ClassifiedAsControlledExitGateFailure' = 'WDK_REQUIRED (New-M01ValidationMockHarness)'
    'M024_ReuseSignedStagingPreservesArtifactsByteForByteAndRejectsTamperingAndInvalidSig' = 'WDK_REQUIRED (New-SignedTestPackage)'
    'M024_ReuseSignedStagingRejectsMismatchedBindingOverlappingPathsAndHistoricalReportDir' = 'WDK_REQUIRED (New-SignedTestPackage)'
    'M024_ReuseSignedStagingDryRunMutatesZeroFiles' = 'WDK_REQUIRED (New-SignedTestPackage + New-M01ValidationMockHarness)'
    'M024_RuntimeInformationWithPsReadLineAndStrictModePassesForValidationScripts' = 'WDK_REQUIRED (Invoke-LumaBridgeFunctionalValidation -DryRun checks WDK tools)'
    'M025_1_StimulusBackendDryRunForwardingAndRetrocompat' = 'WDK_REQUIRED (New-M01ValidationMockHarness)'
    'M025_1_ExplicitDxgiGatePositivePass' = 'WDK_REQUIRED (New-M01ValidationMockHarness)'
    'M025_1_ExplicitDxgiGateRejectsFallbackZeroPresentIncompleteTerminalAndMissingFields' = 'WDK_REQUIRED (New-M01ValidationMockHarness)'
    'M025_1_H264WorkerFailureAndMissingFieldsFailGate' = 'WDK_REQUIRED (New-M01ValidationMockHarness)'
    'M025_1_AutoModeBackwardCompatAndGdiSelection' = 'WDK_REQUIRED (New-M01ValidationMockHarness)'
    'M025_1_PsReadLineStrictModeDxgiDryRun' = 'WDK_REQUIRED (Invoke-LumaBridgeFunctionalValidation -DryRun checks WDK tools)'
}

try {
    # -----------------------------------------------------------------------
    # Phase 1: PowerShell syntax check on all tracked/CI .ps1 and .psm1 files
    # -----------------------------------------------------------------------
    $psFiles = @(
        Get-ChildItem -LiteralPath (Join-Path $resolvedRepoRoot 'windows\driver\scripts') -File -Recurse
        Get-ChildItem -LiteralPath (Join-Path $resolvedRepoRoot 'windows\driver\tests') -File -Recurse
        Get-ChildItem -LiteralPath (Join-Path $resolvedRepoRoot 'scripts\ci') -File -Recurse
    ) | Where-Object { $_.Extension -in @('.ps1', '.psm1') } | Sort-Object -Property FullName -Unique

    if ($psFiles.Count -lt 13) {
        throw ("Expected at least 13 PowerShell files under repo, found {0}." -f $psFiles.Count)
    }

    foreach ($psFile in $psFiles) {
        $tokens = $null
        $parseErrors = $null
        $null = [System.Management.Automation.Language.Parser]::ParseFile($psFile.FullName, [ref]$tokens, [ref]$parseErrors)
        $rel = $psFile.FullName.Substring($resolvedRepoRoot.Length).TrimStart('\', '/') -replace '\\', '/'
        $ok = ($null -eq $parseErrors -or $parseErrors.Count -eq 0)
        $psSyntaxResults.Add([pscustomobject]@{
            File       = $rel
            Valid      = $ok
            ErrorCount = if ($null -eq $parseErrors) { 0 } else { $parseErrors.Count }
        })
        if (-not $ok) {
            $overallPassed = $false
            $msg = "PowerShell syntax error in ${rel}: $($parseErrors[0].Message) (line $($parseErrors[0].Extent.StartLineNumber))"
            $failures.Add($msg)
            Write-Host ("[FAIL] {0}" -f $msg) -ForegroundColor Red
        }
        else {
            Write-Host ("[PASS] Syntax OK: {0}" -f $rel) -ForegroundColor Green
        }
    }

    # -----------------------------------------------------------------------
    # Phase 2: PowerShell 71-test AST bijection validation
    # -----------------------------------------------------------------------
    $psSuitePath = Join-Path -Path $resolvedRepoRoot -ChildPath 'windows\driver\tests\LumaBridgeFunctionalToolingTests.ps1'
    $psSuiteText = [System.IO.File]::ReadAllText($psSuitePath)
    $suiteTokens = $null
    $suiteParseErrors = $null
    $suiteAst = [System.Management.Automation.Language.Parser]::ParseFile($psSuitePath, [ref]$suiteTokens, [ref]$suiteParseErrors)
    if ($null -ne $suiteParseErrors -and $suiteParseErrors.Count -gt 0) {
        throw ("Failed to parse LumaBridgeFunctionalToolingTests.ps1: {0}" -f $suiteParseErrors[0].Message)
    }

    $discoveredTests = New-Object System.Collections.Generic.List[object]
    $firstUnitTestStart = -1
    $footerStart = -1
    foreach ($stmt in $suiteAst.EndBlock.Statements) {
        if ($stmt -is [System.Management.Automation.Language.TryStatementAst]) {
            $footerStart = $stmt.Extent.StartOffset
            continue
        }
        if ($stmt -is [System.Management.Automation.Language.PipelineAst] -and $stmt.PipelineElements.Count -eq 1) {
            $cmd = $stmt.PipelineElements[0]
            if ($cmd -is [System.Management.Automation.Language.CommandAst] -and $cmd.GetCommandName() -eq 'Invoke-UnitTest') {
                $testName = $null
                for ($e = 0; $e -lt $cmd.CommandElements.Count; $e++) {
                    $el = $cmd.CommandElements[$e]
                    if ($el -is [System.Management.Automation.Language.CommandParameterAst] -and $el.ParameterName -eq 'Name') {
                        if ($null -ne $el.Argument) {
                            $testName = $el.Argument.SafeGetValue()
                        }
                        elseif (($e + 1) -lt $cmd.CommandElements.Count) {
                            $testName = $cmd.CommandElements[$e + 1].SafeGetValue()
                        }
                        break
                    }
                }
                if ([string]::IsNullOrWhiteSpace($testName)) {
                    throw ("Could not extract -Name from Invoke-UnitTest at line {0}." -f $stmt.Extent.StartLineNumber)
                }
                if ($firstUnitTestStart -lt 0) {
                    $firstUnitTestStart = $stmt.Extent.StartOffset
                }
                $discoveredTests.Add([pscustomobject]@{
                    Name = [string]$testName
                    Text = $stmt.Extent.Text
                })
            }
        }
    }

    if ($discoveredTests.Count -ne 71) {
        throw ("Expected 71 tests in LumaBridgeFunctionalToolingTests.ps1, discovered {0}." -f $discoveredTests.Count)
    }
    if ($firstUnitTestStart -le 0 -or $footerStart -le $firstUnitTestStart) {
        throw 'Unexpected AST structure in LumaBridgeFunctionalToolingTests.ps1 while locating prelude/footer.'
    }

    $discoveredSet = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)
    foreach ($dt in $discoveredTests) {
        if (-not $discoveredSet.Add($dt.Name)) {
            throw ("Duplicate PowerShell test name discovered: {0}" -f $dt.Name)
        }
    }
    $selectedSet = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)
    foreach ($sName in $selectedPowerShellTests) {
        if (-not $selectedSet.Add($sName)) {
            throw ("Duplicate selected PowerShell test name in manifest: {0}" -f $sName)
        }
        if (-not $discoveredSet.Contains($sName)) {
            throw ("Selected PowerShell test '{0}' does not exist in LumaBridgeFunctionalToolingTests.ps1." -f $sName)
        }
        if ($excludedPowerShellTests.Contains($sName)) {
            throw ("Overlap between selected and excluded PowerShell lists: {0}" -f $sName)
        }
    }
    foreach ($eName in $excludedPowerShellTests.Keys) {
        if (-not $discoveredSet.Contains($eName)) {
            throw ("Excluded PowerShell test '{0}' does not exist in LumaBridgeFunctionalToolingTests.ps1." -f $eName)
        }
    }
    if (($selectedPowerShellTests.Count + $excludedPowerShellTests.Count) -ne $discoveredTests.Count) {
        throw ("PowerShell inventory mismatch: selected({0}) + excluded({1}) != discovered({2})." -f `
            $selectedPowerShellTests.Count, $excludedPowerShellTests.Count, $discoveredTests.Count)
    }
    Write-Host ("[PASS] PowerShell AST inventory bijection verified: {0} selected + {1} excluded = {2} total." -f `
        $selectedPowerShellTests.Count, $excludedPowerShellTests.Count, $discoveredTests.Count) -ForegroundColor Green

    if (-not $ValidateInventoryOnly) {
        # -------------------------------------------------------------------
        # Phase 3: C++ MSVC build & execution
        # -------------------------------------------------------------------
        if (-not $SkipCpp) {
            $toolchainPath = Scrub-SensitivePaths (Initialize-MsvcX64Environment)
            Write-Host ("[INFO] MSVC x64 toolchain ready: {0}" -f $toolchainPath)

            # 3A. Build lumabridge-host.exe (compile-only verification)
            $hostOutDir = Join-Path -Path $BuildRoot -ChildPath 'lumabridge-host'
            New-Item -Path $hostOutDir -ItemType Directory -Force | Out-Null
            $hostExe = Join-Path -Path $hostOutDir -ChildPath 'lumabridge-host.exe'
            $hostCompileArgs = @(
                '/nologo', '/std:c++20', '/W4', '/WX', '/EHsc', '/O2', '/MD', '/DNDEBUG',
                '/DUNICODE', '/D_UNICODE',
                '/Iwindows\driver\LumaBridgeIddDriver', '/Iwindows\host',
                'windows\host\main.cpp',
                'windows\host\FrameConsumer.cpp',
                'windows\host\NvencH264Encoder.cpp',
                'windows\host\H264BitstreamValidator.cpp',
                ("/Fo{0}\" -f $hostOutDir),
                ("/Fd{0}\" -f $hostOutDir),
                ("/Fe:{0}" -f $hostExe),
                '/link',
                'd3d11.lib', 'dxgi.lib', 'advapi32.lib', 'user32.lib', 'gdi32.lib',
                'mfplat.lib', 'mfuuid.lib', 'wmcodecdspuuid.lib', 'ole32.lib', 'psapi.lib'
            )
            $hostRes = Invoke-NativeTool -Executable 'cl.exe' -Arguments $hostCompileArgs -WorkingDirectory $resolvedRepoRoot
            $hostLogPath = Join-Path -Path $LogDir -ChildPath 'build-lumabridge-host.log'
            [System.IO.File]::WriteAllLines($hostLogPath, @($hostRes.Output | ForEach-Object { Scrub-SensitivePaths $_ }), [System.Text.Encoding]::UTF8)
            $hostOk = ($hostRes.ExitCode -eq 0) -and (Test-Path -LiteralPath $hostExe -PathType Leaf)
            $cppHostBuildResult = [pscustomobject]@{
                Name     = 'lumabridge-host.exe'
                Mode     = 'CompileOnly'
                ExitCode = $hostRes.ExitCode
                Passed   = $hostOk
            }
            if (-not $hostOk) {
                $overallPassed = $false
                $failures.Add(("Compile-only build failed for lumabridge-host.exe (exit={0})." -f $hostRes.ExitCode))
                Write-Host ("[FAIL] lumabridge-host.exe build failed (exit={0})" -f $hostRes.ExitCode) -ForegroundColor Red
            }
            else {
                Write-Host "[PASS] Built lumabridge-host.exe (compile-only verification)" -ForegroundColor Green
            }

            # 3B. Compile and execute all selected C++ suites
            foreach ($suite in $cppInventory) {
                if (-not $suite.Selected) {
                    $cppSuiteResults.Add([pscustomobject]@{
                        Name          = $suite.Name
                        Selected      = $false
                        ExpectedCount = $suite.ExpectedCount
                        ExecutedCount = 0
                        FailureCount  = 0
                        ExitCode      = $null
                        Passed        = $null
                        Categories    = $suite.Categories
                        Reason        = $suite.Reason
                    })
                    continue
                }

                $suiteDir = Join-Path -Path $BuildRoot -ChildPath $suite.Name
                New-Item -Path $suiteDir -ItemType Directory -Force | Out-Null
                $suiteExe = Join-Path -Path $suiteDir -ChildPath ("{0}.exe" -f $suite.Name)

                $clArgs = New-Object System.Collections.Generic.List[string]
                $clArgs.Add('/nologo')
                $clArgs.Add($suite.StdFlag)
                $clArgs.Add('/W4')
                $clArgs.Add('/WX')
                $clArgs.Add('/EHsc')
                foreach ($ef in $suite.ExtraFlags) { $clArgs.Add($ef) }
                foreach ($inp in $suite.CompileInputs) { $clArgs.Add($inp) }
                $clArgs.Add(("/Fo{0}\" -f $suiteDir))
                $clArgs.Add(("/Fd{0}\" -f $suiteDir))
                $clArgs.Add(("/Fe:{0}" -f $suiteExe))
                if ($suite.LinkLibs.Count -gt 0) {
                    $clArgs.Add('/link')
                    foreach ($lib in $suite.LinkLibs) { $clArgs.Add($lib) }
                }

                $buildRes = Invoke-NativeTool -Executable 'cl.exe' -Arguments $clArgs.ToArray() -WorkingDirectory $resolvedRepoRoot
                $buildLogPath = Join-Path -Path $LogDir -ChildPath ("build-{0}.log" -f $suite.Name)
                [System.IO.File]::WriteAllLines($buildLogPath, @($buildRes.Output | ForEach-Object { Scrub-SensitivePaths $_ }), [System.Text.Encoding]::UTF8)

                if ($buildRes.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $suiteExe -PathType Leaf)) {
                    $overallPassed = $false
                    $failures.Add(("C++ build failed for {0} (exit={1})." -f $suite.Name, $buildRes.ExitCode))
                    Write-Host ("[FAIL] {0} compile failed (exit={1})" -f $suite.Name, $buildRes.ExitCode) -ForegroundColor Red
                    $cppSuiteResults.Add([pscustomobject]@{
                        Name          = $suite.Name
                        Selected      = $true
                        ExpectedCount = $suite.ExpectedCount
                        ExecutedCount = 0
                        FailureCount  = 0
                        ExitCode      = $buildRes.ExitCode
                        Passed        = $false
                        Categories    = $suite.Categories
                        Reason        = 'Compilation failed'
                    })
                    continue
                }

                $runRes = Invoke-NativeTool -Executable $suiteExe -Arguments @() -WorkingDirectory $resolvedRepoRoot
                $runLogPath = Join-Path -Path $LogDir -ChildPath ("run-{0}.log" -f $suite.Name)
                $scrubbedOut = @($runRes.Output | ForEach-Object { Scrub-SensitivePaths $_ })
                [System.IO.File]::WriteAllLines($runLogPath, $scrubbedOut, [System.Text.Encoding]::UTF8)

                $joinedOut = $scrubbedOut -join "`n"
                $summaryMatch = [regex]::Match($joinedOut, 'Summary:\s*(\d+)\s+tests run,\s*(\d+)\s+assertion failures\.')
                $failLines = @($scrubbedOut | Where-Object { $_ -match '^\[FAIL\]' })
                $executedCount = if ($summaryMatch.Success) { [int]$summaryMatch.Groups[1].Value } else { -1 }
                $failCount = if ($summaryMatch.Success) { [int]$summaryMatch.Groups[2].Value } else { -1 }
                $suiteOk = ($runRes.ExitCode -eq 0) -and $summaryMatch.Success -and ($executedCount -eq $suite.ExpectedCount) -and ($failCount -eq 0) -and ($failLines.Count -eq 0)

                if (-not $suiteOk) {
                    $overallPassed = $false
                    $failures.Add(("C++ suite {0} failed validation (exit={1}, executed={2}/{3}, failures={4}, failLines={5})." -f `
                        $suite.Name, $runRes.ExitCode, $executedCount, $suite.ExpectedCount, $failCount, $failLines.Count))
                    Write-Host ("[FAIL] {0}: exit={1}, executed={2}/{3}, failures={4}" -f `
                        $suite.Name, $runRes.ExitCode, $executedCount, $suite.ExpectedCount, $failCount) -ForegroundColor Red
                    foreach ($line in $scrubbedOut) { Write-Host ("  {0}" -f $line) }
                }
                else {
                    Write-Host ("[PASS] {0}: {1}/{2} tests passed (0 failures)" -f $suite.Name, $executedCount, $suite.ExpectedCount) -ForegroundColor Green
                }

                $cppSuiteResults.Add([pscustomobject]@{
                    Name          = $suite.Name
                    Selected      = $true
                    ExpectedCount = $suite.ExpectedCount
                    ExecutedCount = [Math]::Max(0, $executedCount)
                    FailureCount  = [Math]::Max(0, $failCount)
                    ExitCode      = $runRes.ExitCode
                    Passed        = $suiteOk
                    Categories    = $suite.Categories
                    Reason        = $suite.Reason
                })
            }
        }

        # -------------------------------------------------------------------
        # Phase 4: Execute explicitly allowlisted 21 PowerShell tests
        # -------------------------------------------------------------------
        if (-not $SkipPowerShell) {
            $preludeText = $psSuiteText.Substring(0, $firstUnitTestStart)
            $testsDirActual = Join-Path -Path $resolvedRepoRoot -ChildPath 'windows\driver\tests'
            $escapedTestsDir = $testsDirActual.Replace("'", "''")
            if ($preludeText -notmatch '(?m)^\$testsDir\s*=\s*\$PSScriptRoot\r?$') {
                throw 'Could not anchor $testsDir in LumaBridgeFunctionalToolingTests.ps1 prelude.'
            }
            $anchoredPrelude = [regex]::Replace(
                $preludeText,
                '(?m)^\$testsDir\s*=\s*\$PSScriptRoot\r?$',
                ('$testsDir = ''{0}''' -f $escapedTestsDir),
                1
            )
            if ($anchoredPrelude -eq $preludeText) {
                throw 'Failed to replace $testsDir anchor in LumaBridgeFunctionalToolingTests.ps1 prelude.'
            }
            $footerText = $psSuiteText.Substring($footerStart)

            $selectedBodies = New-Object System.Collections.Generic.List[string]
            foreach ($dt in $discoveredTests) {
                if ($selectedSet.Contains($dt.Name)) {
                    $selectedBodies.Add($dt.Text)
                }
            }
            if ($selectedBodies.Count -ne $selectedPowerShellTests.Count) {
                throw 'Internal error slicing selected PowerShell tests.'
            }

            $ephemeralPsPath = Join-Path -Path $BuildRoot -ChildPath 'RunSelectedFunctionalToolingTests.ps1'
            $ephemeralContent = $anchoredPrelude + "`r`n" + ($selectedBodies -join "`r`n`r`n") + "`r`n`r`n" + $footerText
            [System.IO.File]::WriteAllText($ephemeralPsPath, $ephemeralContent, [System.Text.Encoding]::UTF8)

            try {
                $psExe = Join-Path -Path $env:SystemRoot -ChildPath 'System32\WindowsPowerShell\v1.0\powershell.exe'
                if (-not (Test-Path -LiteralPath $psExe -PathType Leaf)) {
                    $psExe = 'powershell.exe'
                }
                $psRunRes = Invoke-NativeTool -Executable $psExe -Arguments @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $ephemeralPsPath) -WorkingDirectory $resolvedRepoRoot
                $psLogPath = Join-Path -Path $LogDir -ChildPath 'run-LumaBridgeFunctionalToolingTests-ci-subset.log'
                $scrubbedPsOut = @($psRunRes.Output | ForEach-Object { Scrub-SensitivePaths $_ })
                [System.IO.File]::WriteAllLines($psLogPath, $scrubbedPsOut, [System.Text.Encoding]::UTF8)

                $joinedPsOut = $scrubbedPsOut -join "`n"
                $psSumMatch = [regex]::Match($joinedPsOut, 'Summary:\s*(\d+)\s+tests run,\s*(\d+)\s+assertion failures\.')
                $psExecuted = if ($psSumMatch.Success) { [int]$psSumMatch.Groups[1].Value } else { -1 }
                $psFailCount = if ($psSumMatch.Success) { [int]$psSumMatch.Groups[2].Value } else { -1 }

                $missingPassNames = New-Object System.Collections.Generic.List[string]
                foreach ($sName in $selectedPowerShellTests) {
                    $passPattern = '(?m)^\[PASS\]\s+' + [regex]::Escape($sName) + '\s*$'
                    if ($joinedPsOut -notmatch $passPattern) {
                        $missingPassNames.Add($sName)
                    }
                }

                $psOk = ($psRunRes.ExitCode -eq 0) -and $psSumMatch.Success -and ($psExecuted -eq $selectedPowerShellTests.Count) -and ($psFailCount -eq 0) -and ($missingPassNames.Count -eq 0)
                if (-not $psOk) {
                    $overallPassed = $false
                    $failures.Add(("PowerShell CI subset failed (exit={0}, executed={1}/{2}, failures={3}, missingPass={4})." -f `
                        $psRunRes.ExitCode, $psExecuted, $selectedPowerShellTests.Count, $psFailCount, ($missingPassNames -join ',')))
                    Write-Host ("[FAIL] PowerShell CI subset: exit={0}, executed={1}/{2}, failures={3}" -f `
                        $psRunRes.ExitCode, $psExecuted, $selectedPowerShellTests.Count, $psFailCount) -ForegroundColor Red
                    foreach ($line in $scrubbedPsOut) { Write-Host ("  {0}" -f $line) }
                }
                else {
                    Write-Host ("[PASS] PowerShell CI subset: {0}/{1} selected tests passed (0 failures; {2} WDK-dependent tests explicitly excluded)" -f `
                        $psExecuted, $selectedPowerShellTests.Count, $excludedPowerShellTests.Count) -ForegroundColor Green
                }

                $psTestSummary = [pscustomobject]@{
                    TotalInSuite  = $discoveredTests.Count
                    ExpectedCount = $selectedPowerShellTests.Count
                    ExecutedCount = [Math]::Max(0, $psExecuted)
                    ExcludedCount = $excludedPowerShellTests.Count
                    FailureCount  = [Math]::Max(0, $psFailCount)
                    ExitCode      = $psRunRes.ExitCode
                    Passed        = $psOk
                    SelectedNames = $selectedPowerShellTests
                    ExcludedTests = $excludedPowerShellTests
                }
            }
            finally {
                Remove-Item -LiteralPath $ephemeralPsPath -Force -ErrorAction SilentlyContinue
            }
        }
    }

    # -----------------------------------------------------------------------
    # Phase 5: Structured JSON & Markdown Summaries
    # -----------------------------------------------------------------------
    $selectedCppList = @($cppSuiteResults | Where-Object { $_.Selected })
    $excludedCppList = @($cppSuiteResults | Where-Object { -not $_.Selected })
    $cppExpectedTotal = 0
    $cppExecutedTotal = 0
    foreach ($cppItem in $selectedCppList) {
        $cppExpectedTotal += [int]$cppItem.ExpectedCount
        $cppExecutedTotal += [int]$cppItem.ExecutedCount
    }

    $reportObj = [ordered]@{
        GeneratedAtUtc        = (Get-Date).ToUniversalTime().ToString('o')
        OverallPassed         = $overallPassed
        ValidateInventoryOnly = [bool]$ValidateInventoryOnly
        MsvcCompiler          = $toolchainPath
        PowerShellSyntax      = $psSyntaxResults.ToArray()
        CppHostBuild          = $cppHostBuildResult
        CppSuites             = $cppSuiteResults.ToArray()
        CppExpectedExecuted   = $cppExpectedTotal
        CppActualExecuted     = $cppExecutedTotal
        PowerShellSummary     = $psTestSummary
        Failures              = $failures.ToArray()
        Disclaimer            = 'Hosted non-admin Windows CI does NOT validate IddCx driver load, WUDFHost.exe runtime, PnP install, physical GPU transport, physical NVENC, DXGI desktop capture, Benchmark30s, ProlongedStability, or production driver signing.'
    }

    if (-not [string]::IsNullOrWhiteSpace($JsonReportPath)) {
        $jsonDir = Split-Path -Parent $JsonReportPath
        if (-not [string]::IsNullOrWhiteSpace($jsonDir)) {
            New-Item -Path $jsonDir -ItemType Directory -Force | Out-Null
        }
        $reportObj | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $JsonReportPath -Encoding UTF8
    }

    $mdLines = New-Object System.Collections.Generic.List[string]
    $mdLines.Add('## Windows Non-Admin CI Summary')
    $mdLines.Add('')
    $mdLines.Add(('- Overall Result: **{0}**' -f $(if ($overallPassed) { 'PASS' } else { 'FAIL' })))
    $syntaxValidCount = 0
    foreach ($synItem in $psSyntaxResults) {
        if ($synItem.Valid) { $syntaxValidCount++ }
    }
    $mdLines.Add(('- PowerShell Syntax Checks: **{0}/{1}** valid' -f @($syntaxValidCount, $psSyntaxResults.Count)))
    if ($null -ne $cppHostBuildResult) {
        $mdLines.Add(('- `lumabridge-host.exe` (Compile-Only): **{0}**' -f $(if ($cppHostBuildResult.Passed) { 'PASS' } else { 'FAIL' })))
    }
    if ($selectedCppList.Count -gt 0) {
        $mdLines.Add(('- C++ Unit/Component Suites (Selected): **{0}/{1}** cases executed across **{2}** suites (**{3}** suites / **14** cases excluded: WDK/GPU/NVENC; plus **9** E2E tests excluded)' -f @(
            $reportObj.CppActualExecuted, $reportObj.CppExpectedExecuted, $selectedCppList.Count, $excludedCppList.Count)))
        $mdLines.Add('')
        $mdLines.Add('| C++ Suite | Status | Executed / Expected | Categories | Notes |')
        $mdLines.Add('|---|---|---:|---|---|')
        foreach ($row in $cppSuiteResults) {
            $statusLabel = if (-not $row.Selected) { 'EXCLUDED' } elseif ($row.Passed) { 'PASS' } else { 'FAIL' }
            $mdLines.Add(('| `{0}` | `{1}` | {2} / {3} | `{4}` | {5} |' -f @(
                $row.Name, $statusLabel, $row.ExecutedCount, $row.ExpectedCount, ($row.Categories -join ', '), $row.Reason)))
        }
    }
    if ($null -ne $psTestSummary) {
        $mdLines.Add('')
        $mdLines.Add(('- PowerShell Tooling Subset (`LumaBridgeFunctionalToolingTests.ps1`): **{0}/{1}** executed & passed (**{2}** `WDK_REQUIRED` tests explicitly excluded; inventory total **{3}/71**)' -f @(
            $psTestSummary.ExecutedCount, $psTestSummary.ExpectedCount, $psTestSummary.ExcludedCount, $psTestSummary.TotalInSuite)))
    }
    if ($failures.Count -gt 0) {
        $mdLines.Add('')
        $mdLines.Add('### Failures')
        foreach ($f in $failures) {
            $mdLines.Add(('- {0}' -f $f))
        }
    }
    $mdLines.Add('')
    $mdLines.Add('> **Qualification Boundary:** Conventional hosted Windows CI does **not** prove IddCx driver initialization, `WUDFHost.exe` runtime, PnP installation, physical GPU shared transport, physical NVENC encoding, live desktop capture, `Benchmark30s`, `ProlongedStability`, or production driver distribution.')

    $summaryText = ($mdLines -join "`n") + "`n"
    if (-not [string]::IsNullOrWhiteSpace($SummaryPath)) {
        $sumDir = Split-Path -Parent $SummaryPath
        if (-not [string]::IsNullOrWhiteSpace($sumDir)) {
            New-Item -Path $sumDir -ItemType Directory -Force | Out-Null
        }
        [System.IO.File]::AppendAllText($SummaryPath, $summaryText, [System.Text.Encoding]::UTF8)
    }

    if (-not $overallPassed) {
        exit 1
    }
    exit 0
}
finally {
    if ($ownsBuildRoot -and (Test-Path -LiteralPath $BuildRoot)) {
        Remove-Item -LiteralPath $BuildRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}
