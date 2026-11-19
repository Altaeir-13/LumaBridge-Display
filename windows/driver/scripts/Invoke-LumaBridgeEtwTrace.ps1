[CmdletBinding()]
param(
    [ValidateSet('Start', 'Stop', 'Status', 'ExportSummary', 'DecodeWpp', 'VerifyProviders')]
    [string]$Action = 'Status',

    [string]$SessionName,

    [string]$DxgSessionName,

    [string]$OutputDir,

    [string]$EtlPath,

    [string]$DxgEtlPath,

    [switch]$IncludeDxgKrnl,

    [Nullable[DateTime]]$StartTimeUtc = $null,

    [Nullable[DateTime]]$EndTimeUtc = $null,

    [Nullable[int]]$ProcessId = $null,

    [ValidateRange(1, 50000)]
    [int]$MaxMatchedEvents = 500,

    [switch]$DecodeWpp,

    [string]$SymbolCacheDir,

    [string]$TmfCacheDir,

    [switch]$SkipSymbolDownload,

    [switch]$DryRun,

    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$commonModulePath = Join-Path -Path $PSScriptRoot -ChildPath 'LumaBridgeDriverCommon.psm1'
$loadedCommon = Get-Module -Name 'LumaBridgeDriverCommon' -ErrorAction SilentlyContinue
if ($null -eq $loadedCommon -or $loadedCommon.Path -ine $commonModulePath) {
    Import-Module -Name $commonModulePath -Force
}

$constants = Get-LumaBridgeDriverConstants
if ([string]::IsNullOrWhiteSpace($SessionName)) {
    $SessionName = $constants.EtwSessionName
}
if ([string]::IsNullOrWhiteSpace($DxgSessionName)) {
    $DxgSessionName = $constants.EtwDxgSessionName
}

if ([string]::IsNullOrWhiteSpace($OutputDir)) {
    $localAppData = if ([string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) {
        Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath 'LumaBridgeDisplay'
    }
    else {
        Join-Path -Path $env:LOCALAPPDATA -ChildPath 'LumaBridgeDisplay'
    }
    $OutputDir = Join-Path -Path $localAppData -ChildPath 'Diagnostics\Etw'
}

if ([string]::IsNullOrWhiteSpace($EtlPath)) {
    $EtlPath = Join-Path -Path $OutputDir -ChildPath ("{0}.etl" -f $SessionName)
}
if ([string]::IsNullOrWhiteSpace($DxgEtlPath)) {
    $DxgEtlPath = Join-Path -Path $OutputDir -ChildPath ("{0}.etl" -f $DxgSessionName)
}

$coreProviders = @(
    [pscustomobject]@{ Name = 'LumaBridgeIddDriver (TraceLogging)'; Guid = $constants.LumaBridgeTraceProviderGuid; Flags = '0xFFFFFFFFFFFFFFFF'; Level = '5' },
    [pscustomobject]@{ Name = 'Microsoft-Windows-IndirectDisplays-ClassExtension-Events'; Guid = $constants.IddCxManifestProviderGuid; Flags = '0xFFFFFFFFFFFFFFFF'; Level = '5' },
    [pscustomobject]@{ Name = 'IddCx WPP (Class Extension)'; Guid = $constants.IddCxWppProviderGuid; Flags = $constants.IddCxWppAllFlags; Level = '5' },
    [pscustomobject]@{ Name = 'Microsoft-Windows-DriverFrameworks-UserMode'; Guid = $constants.UmdfOperationalProviderGuid; Flags = '0xFFFFFFFFFFFFFFFF'; Level = '5' },
    [pscustomobject]@{ Name = 'WDF/UMDF Core WPP'; Guid = $constants.WdfCoreWppProviderGuid; Flags = '0xFFFFFFFFFFFFFFFF'; Level = '5' },
    [pscustomobject]@{ Name = 'Microsoft-Windows-WerKernel'; Guid = $constants.WerKernelProviderGuid; Flags = '0xFFFFFFFFFFFFFFFF'; Level = '5' }
)

$dxgProviders = @(
    [pscustomobject]@{ Name = 'Microsoft-Windows-DxgKrnl'; Guid = $constants.DxgKrnlProviderGuid; Flags = '0xFFFFFFFFFFFFFFFF'; Level = '4' },
    [pscustomobject]@{ Name = 'Microsoft-Windows-Watchdog-Events'; Guid = $constants.WatchdogEventsProviderGuid; Flags = '0xFFFFFFFFFFFFFFFF'; Level = '5' }
)

$coreExpectedGuids = @($coreProviders | ForEach-Object { $_.Guid })
$coreProvidersFile = Join-Path -Path $OutputDir -ChildPath ("{0}.providers.txt" -f $SessionName)
$dxgProvidersFile = Join-Path -Path $OutputDir -ChildPath ("{0}.providers.txt" -f $DxgSessionName)
$decodedSummaryPath = Join-Path -Path $OutputDir -ChildPath 'etw-decoded-events.json'
$wppDecodedPath = Join-Path -Path $OutputDir -ChildPath 'wpp-decoded-events.json'

$rdpIddAutoLoggerSource = if ([string]::IsNullOrWhiteSpace($env:DriverData)) {
    $null
}
else {
    Join-Path -Path $env:DriverData -ChildPath 'LogFiles\WMI\Microsoft-Windows-Rdp-Graphics-RdpIdd-Trace.etl'
}

switch ($Action) {
    'Status' {
        $channels = @(Get-LumaBridgeEventChannelStatus)
        $sessionRunning = $false
        $dxgSessionRunning = $false
        $queryOutput = @()
        $queryError = $null
        $providerVerification = $null

        try {
            $queryResult = Invoke-LumaBridgeExternalCommand -FilePath 'logman.exe' -Arguments @('query', $SessionName, '-ets') -DryRun:$DryRun
            $queryOutput = @($queryResult.Output)
            $sessionRunning = (-not $DryRun)
            if ($sessionRunning) {
                $providerVerification = Test-LumaBridgeEtwSessionProviders -QueryOutputLines $queryOutput -ExpectedProviderGuids $coreExpectedGuids
            }
        }
        catch {
            $queryError = $_.Exception.Message
        }

        if (-not $DryRun) {
            try {
                $null = Invoke-LumaBridgeExternalCommand -FilePath 'logman.exe' -Arguments @('query', $DxgSessionName, '-ets')
                $dxgSessionRunning = $true
            }
            catch {
                $dxgSessionRunning = $false
            }
        }

        $rdpAutoLoggerExists = $false
        $rdpAutoLoggerAccessDenied = $false
        if (-not [string]::IsNullOrWhiteSpace($rdpIddAutoLoggerSource)) {
            try {
                $rdpAutoLoggerExists = Test-Path -LiteralPath $rdpIddAutoLoggerSource -ErrorAction Stop
            }
            catch [System.UnauthorizedAccessException] {
                $rdpAutoLoggerAccessDenied = $true
            }
            catch {
                $rdpAutoLoggerExists = $false
            }
        }

        return [pscustomobject]@{
            Action                       = 'Status'
            DryRun                       = [bool]$DryRun
            SessionName                  = $SessionName
            DxgSessionName               = $DxgSessionName
            SessionRunning               = $sessionRunning
            DxgSessionRunning            = $dxgSessionRunning
            ExpectedEtlPath              = $EtlPath
            EtlExists                    = (Test-Path -LiteralPath $EtlPath)
            DxgEtlPath                   = $DxgEtlPath
            DxgEtlExists                 = (Test-Path -LiteralPath $DxgEtlPath)
            RdpIddAutoLoggerPath         = $rdpIddAutoLoggerSource
            RdpIddAutoLoggerExists       = $rdpAutoLoggerExists
            RdpIddAutoLoggerAccessDenied = $rdpAutoLoggerAccessDenied
            QueryOutput                  = $queryOutput
            QueryError                   = $queryError
            ProviderVerification         = $providerVerification
            EventChannels                = $channels
            CoreProviders                = $coreProviders
            DxgProviders                 = $dxgProviders
            ConfiguredProviders          = $coreProviders
        }
    }

    'VerifyProviders' {
        $queryOutput = @()
        $queryError = $null
        $verification = $null
        $sessionRunning = $false

        try {
            $queryResult = Invoke-LumaBridgeExternalCommand -FilePath 'logman.exe' -Arguments @('query', $SessionName, '-ets') -DryRun:$DryRun
            $queryOutput = @($queryResult.Output)
            $sessionRunning = (-not $DryRun)
            if ($sessionRunning) {
                $verification = Test-LumaBridgeEtwSessionProviders -QueryOutputLines $queryOutput -ExpectedProviderGuids $coreExpectedGuids
            }
        }
        catch {
            $queryError = $_.Exception.Message
        }

        return [pscustomobject]@{
            Action               = 'VerifyProviders'
            DryRun               = [bool]$DryRun
            SessionName          = $SessionName
            SessionRunning       = $sessionRunning
            QueryOutput          = $queryOutput
            QueryError           = $queryError
            ProviderVerification = $verification
        }
    }

    'Start' {
        $null = Assert-LumaBridgeAdministrator -OperationName 'Start LumaBridge ETW trace session' -DryRun:$DryRun

        $proceed = $true
        if (-not $DryRun) {
            $proceed = Confirm-LumaBridgeAction -PromptMessage ("Start sequential Core ETW capture session '{0}' (using provider file '{1}') writing to '{2}'?" -f $SessionName, $coreProvidersFile, $EtlPath) -DryRun:$DryRun -Force:$Force
        }

        if (-not $proceed) {
            return [pscustomobject]@{
                Action         = 'Start'
                Cancelled      = $true
                DryRun         = $false
                SessionName    = $SessionName
                DxgSessionName = $DxgSessionName
                EtlPath        = $EtlPath
                DxgEtlPath     = $DxgEtlPath
                OutputDir      = $OutputDir
                CoreProviders  = $coreProviders
                DxgProviders   = $dxgProviders
                Providers      = $coreProviders
            }
        }

        $corePfLines = @(New-LumaBridgeEtwProviderFileContent -SessionKind 'Core')
        $dxgPfLines = if ($IncludeDxgKrnl) { @(New-LumaBridgeEtwProviderFileContent -SessionKind 'Dxg') } else { @() }

        if (-not $DryRun) {
            foreach ($dirToEnsure in @($OutputDir, (Split-Path -Path $EtlPath -Parent), $(if ($IncludeDxgKrnl) { Split-Path -Path $DxgEtlPath -Parent } else { $null }))) {
                if (-not [string]::IsNullOrWhiteSpace($dirToEnsure) -and -not (Test-Path -LiteralPath $dirToEnsure)) {
                    $null = New-Item -Path $dirToEnsure -ItemType Directory -Force
                }
            }
            $corePfLines | Set-Content -LiteralPath $coreProvidersFile -Encoding ASCII
            if ($IncludeDxgKrnl) {
                $dxgPfLines | Set-Content -LiteralPath $dxgProvidersFile -Encoding ASCII
            }
        }

        $executedCommands = New-Object System.Collections.Generic.List[string]
        $coreCreateArgs = @(
            'create', 'trace', $SessionName,
            '-pf', $coreProvidersFile,
            '-o', $EtlPath,
            '-bs', '1024',
            '-nb', '16', '64',
            '-ct', 'perf',
            '-f', 'bin',
            '-max', '256',
            '-ets'
        )
        $null = Invoke-LumaBridgeExternalCommand -FilePath 'logman.exe' -Arguments $coreCreateArgs -DryRun:$DryRun
        $executedCommands.Add(("logman.exe {0}" -f ($coreCreateArgs -join ' ')))

        $verifyArgs = @('query', $SessionName, '-ets')
        $verifyResult = Invoke-LumaBridgeExternalCommand -FilePath 'logman.exe' -Arguments $verifyArgs -DryRun:$DryRun
        $executedCommands.Add(("logman.exe {0}" -f ($verifyArgs -join ' ')))

        $providerVerification = $null
        if (-not $DryRun) {
            $providerVerification = Test-LumaBridgeEtwSessionProviders -QueryOutputLines @($verifyResult.Output) -ExpectedProviderGuids $coreExpectedGuids
        }

        if ($IncludeDxgKrnl) {
            $dxgCreateArgs = @(
                'create', 'trace', $DxgSessionName,
                '-pf', $dxgProvidersFile,
                '-o', $DxgEtlPath,
                '-bs', '1024',
                '-nb', '16', '64',
                '-ct', 'perf',
                '-f', 'bincirc',
                '-max', '128',
                '-ets'
            )
            $null = Invoke-LumaBridgeExternalCommand -FilePath 'logman.exe' -Arguments $dxgCreateArgs -DryRun:$DryRun
            $executedCommands.Add(("logman.exe {0}" -f ($dxgCreateArgs -join ' ')))
        }

        return [pscustomobject]@{
            Action               = 'Start'
            Cancelled            = $false
            DryRun               = [bool]$DryRun
            SessionName          = $SessionName
            DxgSessionName       = $DxgSessionName
            OutputDir            = $OutputDir
            EtlPath              = $EtlPath
            DxgEtlPath           = if ($IncludeDxgKrnl) { $DxgEtlPath } else { $null }
            CoreProvidersFile    = $coreProvidersFile
            DxgProvidersFile     = if ($IncludeDxgKrnl) { $dxgProvidersFile } else { $null }
            CoreProvidersContent = $corePfLines
            DxgProvidersContent  = $dxgPfLines
            IncludeDxgKrnl       = [bool]$IncludeDxgKrnl
            CoreProviders        = $coreProviders
            DxgProviders         = if ($IncludeDxgKrnl) { $dxgProviders } else { @() }
            Providers            = $coreProviders
            ProviderVerification = $providerVerification
            ExecutedCommands     = @($executedCommands.ToArray())
        }
    }

    'Stop' {
        $null = Assert-LumaBridgeAdministrator -OperationName 'Stop LumaBridge ETW trace session' -DryRun:$DryRun

        $proceed = $true
        if (-not $DryRun) {
            $proceed = Confirm-LumaBridgeAction -PromptMessage ("Stop ETW capture session '{0}' and export summary to '{1}'?" -f $SessionName, $OutputDir) -DryRun:$DryRun -Force:$Force
        }

        if (-not $proceed) {
            return [pscustomobject]@{
                Action         = 'Stop'
                Cancelled      = $true
                DryRun         = $false
                SessionName    = $SessionName
                DxgSessionName = $DxgSessionName
                EtlPath        = $EtlPath
                DxgEtlPath     = $DxgEtlPath
                OutputDir      = $OutputDir
            }
        }

        $stopArgs = @('stop', $SessionName, '-ets')
        $null = Invoke-LumaBridgeExternalCommand -FilePath 'logman.exe' -Arguments $stopArgs -DryRun:$DryRun

        $dxgStopped = $false
        if ($IncludeDxgKrnl) {
            $dxgStopArgs = @('stop', $DxgSessionName, '-ets')
            try {
                $null = Invoke-LumaBridgeExternalCommand -FilePath 'logman.exe' -Arguments $dxgStopArgs -DryRun:$DryRun
                $dxgStopped = $true
            }
            catch {
                $dxgStopped = $false
            }
        }
        elseif (-not $DryRun) {
            try {
                $null = Invoke-LumaBridgeExternalCommand -FilePath 'logman.exe' -Arguments @('query', $DxgSessionName, '-ets')
                $null = Invoke-LumaBridgeExternalCommand -FilePath 'logman.exe' -Arguments @('stop', $DxgSessionName, '-ets')
                $dxgStopped = $true
            }
            catch {
                $dxgStopped = $false
            }
        }

        if ($DryRun) {
            return [pscustomobject]@{
                Action               = 'Stop'
                Cancelled            = $false
                DryRun               = $true
                SessionName          = $SessionName
                DxgSessionName       = $DxgSessionName
                IncludeDxgKrnl       = [bool]$IncludeDxgKrnl
                EtlPath              = $EtlPath
                DxgEtlPath           = $DxgEtlPath
                OutputDir            = $OutputDir
                DecodedSummaryPath   = $decodedSummaryPath
                RdpIddAutoLoggerPath = $rdpIddAutoLoggerSource
            }
        }

        if (-not (Test-Path -LiteralPath $OutputDir)) {
            $null = New-Item -Path $OutputDir -ItemType Directory -Force
        }

        $copiedAutoLoggerPath = $null
        if (-not [string]::IsNullOrWhiteSpace($rdpIddAutoLoggerSource) -and (Test-Path -LiteralPath $rdpIddAutoLoggerSource)) {
            $targetAutoLoggerPath = Join-Path -Path $OutputDir -ChildPath 'Microsoft-Windows-Rdp-Graphics-RdpIdd-Trace.etl'
            try {
                Copy-Item -LiteralPath $rdpIddAutoLoggerSource -Destination $targetAutoLoggerPath -Force -ErrorAction Stop
                $copiedAutoLoggerPath = $targetAutoLoggerPath
            }
            catch {
                $copiedAutoLoggerPath = $null
            }
        }

        $etlSummary = Get-LumaBridgeEtlEventSummary `
            -EtlPath $EtlPath `
            -StartTimeUtc $StartTimeUtc `
            -EndTimeUtc $EndTimeUtc `
            -ProcessId $ProcessId `
            -MaxMatchedEvents $MaxMatchedEvents
        $stageSummary = Get-LumaBridgeDriverTraceStageSummary -EtlEvents @($etlSummary.LumaBridgeEvents)

        $wppResult = $null
        if ($DecodeWpp) {
            $null = Initialize-LumaBridgeWppTmfCache -SymbolCacheDir $SymbolCacheDir -TmfCacheDir $TmfCacheDir -SkipSymbolDownload:$SkipSymbolDownload
            $wppResult = Invoke-LumaBridgeWppEtlDecode -EtlPath $EtlPath -TmfCacheDir $TmfCacheDir -SymbolCacheDir $SymbolCacheDir -OutputPath $wppDecodedPath -ProcessId $ProcessId -SkipSymbolServer:$SkipSymbolDownload
        }

        $exportPayload = [pscustomobject]@{
            ExportedAtUtc       = (Get-Date).ToUniversalTime().ToString('o')
            SessionName         = $SessionName
            DxgSessionName      = $DxgSessionName
            DxgSessionStopped   = $dxgStopped
            EtlPath             = $EtlPath
            DxgEtlPath          = $DxgEtlPath
            CopiedRdpIddEtlPath = $copiedAutoLoggerPath
            EtlSummary          = $etlSummary
            WppDecodeSummary    = $wppResult
            StageSummary        = $stageSummary
        }
        $exportPayload | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $decodedSummaryPath -Encoding UTF8

        return [pscustomobject]@{
            Action              = 'Stop'
            Cancelled           = $false
            DryRun              = $false
            SessionName         = $SessionName
            DxgSessionName      = $DxgSessionName
            DxgSessionStopped   = $dxgStopped
            EtlPath             = $EtlPath
            DxgEtlPath          = $DxgEtlPath
            OutputDir           = $OutputDir
            DecodedSummaryPath  = $decodedSummaryPath
            WppDecodedPath      = if ($DecodeWpp) { $wppDecodedPath } else { $null }
            CopiedRdpIddEtlPath = $copiedAutoLoggerPath
            EtlSummary          = $etlSummary
            WppDecodeSummary    = $wppResult
            StageSummary        = $stageSummary
        }
    }

    'ExportSummary' {
        $etlSummary = Get-LumaBridgeEtlEventSummary `
            -EtlPath $EtlPath `
            -StartTimeUtc $StartTimeUtc `
            -EndTimeUtc $EndTimeUtc `
            -ProcessId $ProcessId `
            -MaxMatchedEvents $MaxMatchedEvents
        $stageSummary = Get-LumaBridgeDriverTraceStageSummary -EtlEvents @($etlSummary.LumaBridgeEvents)

        $wppResult = $null
        if ($DecodeWpp -and -not $DryRun) {
            $null = Initialize-LumaBridgeWppTmfCache -SymbolCacheDir $SymbolCacheDir -TmfCacheDir $TmfCacheDir -SkipSymbolDownload:$SkipSymbolDownload
            $wppResult = Invoke-LumaBridgeWppEtlDecode -EtlPath $EtlPath -TmfCacheDir $TmfCacheDir -SymbolCacheDir $SymbolCacheDir -OutputPath $wppDecodedPath -ProcessId $ProcessId -SkipSymbolServer:$SkipSymbolDownload
        }

        if (-not $DryRun) {
            if (-not (Test-Path -LiteralPath $OutputDir)) {
                $null = New-Item -Path $OutputDir -ItemType Directory -Force
            }

            $exportPayload = [pscustomobject]@{
                ExportedAtUtc    = (Get-Date).ToUniversalTime().ToString('o')
                SessionName      = $SessionName
                EtlPath          = $EtlPath
                EtlSummary       = $etlSummary
                WppDecodeSummary = $wppResult
                StageSummary     = $stageSummary
            }
            $exportPayload | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $decodedSummaryPath -Encoding UTF8
        }

        return [pscustomobject]@{
            Action             = 'ExportSummary'
            DryRun             = [bool]$DryRun
            EtlPath            = $EtlPath
            OutputDir          = $OutputDir
            DecodedSummaryPath = if ($DryRun) { $null } else { $decodedSummaryPath }
            WppDecodedPath     = if ($DecodeWpp -and -not $DryRun) { $wppDecodedPath } else { $null }
            EtlSummary         = $etlSummary
            WppDecodeSummary   = $wppResult
            StageSummary       = $stageSummary
        }
    }

    'DecodeWpp' {
        $tmfInit = Initialize-LumaBridgeWppTmfCache `
            -SymbolCacheDir $SymbolCacheDir `
            -TmfCacheDir $TmfCacheDir `
            -SkipSymbolDownload:$SkipSymbolDownload `
            -DryRun:$DryRun

        $effectiveOutputPath = if ($DryRun) { $wppDecodedPath } else {
            if (-not (Test-Path -LiteralPath $OutputDir)) {
                $null = New-Item -Path $OutputDir -ItemType Directory -Force
            }
            $wppDecodedPath
        }

        $wppDecode = Invoke-LumaBridgeWppEtlDecode `
            -EtlPath $EtlPath `
            -TmfCacheDir $tmfInit.TmfCacheDir `
            -SymbolCacheDir $tmfInit.SymbolCacheDir `
            -OutputPath $effectiveOutputPath `
            -ProcessId $ProcessId `
            -MaxMatchedLines $MaxMatchedEvents `
            -SkipSymbolServer:$SkipSymbolDownload `
            -DryRun:$DryRun

        return [pscustomobject]@{
            Action           = 'DecodeWpp'
            DryRun           = [bool]$DryRun
            EtlPath          = $EtlPath
            OutputDir        = $OutputDir
            TmfInit          = $tmfInit
            WppDecodeSummary = $wppDecode
            OutputPath       = if ($DryRun) { $null } else { $effectiveOutputPath }
        }
    }
}
