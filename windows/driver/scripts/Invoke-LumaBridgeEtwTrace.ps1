[CmdletBinding()]
param(
    [ValidateSet('Start', 'Stop', 'Status', 'ExportSummary')]
    [string]$Action = 'Status',

    [string]$SessionName,

    [string]$OutputDir,

    [string]$EtlPath,

    [switch]$IncludeDxgKrnl,

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

$providers = @(
    [pscustomobject]@{ Name = 'LumaBridgeIddDriver (TraceLogging)'; Guid = $constants.LumaBridgeTraceProviderGuid; Flags = '0xFFFFFFFFFFFFFFFF'; Level = '5' },
    [pscustomobject]@{ Name = 'Microsoft-Windows-IndirectDisplays-ClassExtension-Events'; Guid = $constants.IddCxManifestProviderGuid; Flags = '0xFFFFFFFFFFFFFFFF'; Level = '5' },
    [pscustomobject]@{ Name = 'IddCx WPP (Class Extension)'; Guid = $constants.IddCxWppProviderGuid; Flags = $constants.IddCxWppMatchAnyKeyword; Level = '4' },
    [pscustomobject]@{ Name = 'Microsoft-Windows-DriverFrameworks-UserMode'; Guid = $constants.UmdfOperationalProviderGuid; Flags = '0xFFFFFFFFFFFFFFFF'; Level = '5' },
    [pscustomobject]@{ Name = 'WDF/UMDF Core WPP'; Guid = $constants.WdfCoreWppProviderGuid; Flags = '0xFFFFFFFFFFFFFFFF'; Level = '5' },
    [pscustomobject]@{ Name = 'Microsoft-Windows-Watchdog-Events'; Guid = $constants.WatchdogEventsProviderGuid; Flags = '0xFFFFFFFFFFFFFFFF'; Level = '5' },
    [pscustomobject]@{ Name = 'Microsoft-Windows-WerKernel'; Guid = $constants.WerKernelProviderGuid; Flags = '0xFFFFFFFFFFFFFFFF'; Level = '5' }
)

if ($IncludeDxgKrnl) {
    $providers += [pscustomobject]@{
        Name  = 'Microsoft-Windows-DxgKrnl'
        Guid  = $constants.DxgKrnlProviderGuid
        Flags = '0xFFFFFFFFFFFFFFFF'
        Level = '4'
    }
}

$decodedSummaryPath = Join-Path -Path $OutputDir -ChildPath 'etw-decoded-events.json'
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
        $queryOutput = @()
        $queryError = $null

        try {
            $queryResult = Invoke-LumaBridgeExternalCommand -FilePath 'logman.exe' -Arguments @('query', $SessionName, '-ets') -DryRun:$DryRun
            $queryOutput = @($queryResult.Output)
            $sessionRunning = (-not $DryRun)
        }
        catch {
            $queryError = $_.Exception.Message
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
            SessionRunning               = $sessionRunning
            ExpectedEtlPath              = $EtlPath
            EtlExists                    = (Test-Path -LiteralPath $EtlPath)
            RdpIddAutoLoggerPath         = $rdpIddAutoLoggerSource
            RdpIddAutoLoggerExists       = $rdpAutoLoggerExists
            RdpIddAutoLoggerAccessDenied = $rdpAutoLoggerAccessDenied
            QueryOutput                  = $queryOutput
            QueryError                   = $queryError
            EventChannels                = $channels
            ConfiguredProviders          = $providers
        }
    }

    'Start' {
        $null = Assert-LumaBridgeAdministrator -OperationName 'Start LumaBridge ETW trace session' -DryRun:$DryRun

        $proceed = $true
        if (-not $DryRun) {
            $proceed = Confirm-LumaBridgeAction -PromptMessage ("Start ETW capture session '{0}' writing to '{1}'?" -f $SessionName, $EtlPath) -DryRun:$DryRun -Force:$Force
        }

        if (-not $proceed) {
            return [pscustomobject]@{
                Action      = 'Start'
                Cancelled   = $true
                DryRun      = $false
                SessionName = $SessionName
                EtlPath     = $EtlPath
                OutputDir   = $OutputDir
                Providers   = $providers
            }
        }

        if (-not $DryRun) {
            if (-not (Test-Path -LiteralPath $OutputDir)) {
                $null = New-Item -Path $OutputDir -ItemType Directory -Force
            }
            $etlParent = Split-Path -Path $EtlPath -Parent
            if (-not [string]::IsNullOrWhiteSpace($etlParent) -and -not (Test-Path -LiteralPath $etlParent)) {
                $null = New-Item -Path $etlParent -ItemType Directory -Force
            }
        }

        $executedCommands = New-Object System.Collections.Generic.List[string]
        $primaryProvider = $providers[0]
        $createArgs = @(
            'create', 'trace', $SessionName,
            '-p', $primaryProvider.Guid, $primaryProvider.Flags, $primaryProvider.Level,
            '-o', $EtlPath,
            '-bs', '1024',
            '-nb', '16', '64',
            '-ct', 'perf',
            '-f', 'bincirc',
            '-max', '128',
            '-ets'
        )
        $null = Invoke-LumaBridgeExternalCommand -FilePath 'logman.exe' -Arguments $createArgs -DryRun:$DryRun
        $executedCommands.Add(("logman.exe {0}" -f ($createArgs -join ' ')))

        for ($i = 1; $i -lt $providers.Count; $i++) {
            $provider = $providers[$i]
            $updateArgs = @(
                'update', 'trace', $SessionName,
                '-p', $provider.Guid, $provider.Flags, $provider.Level,
                '-ets'
            )
            $null = Invoke-LumaBridgeExternalCommand -FilePath 'logman.exe' -Arguments $updateArgs -DryRun:$DryRun
            $executedCommands.Add(("logman.exe {0}" -f ($updateArgs -join ' ')))
        }

        return [pscustomobject]@{
            Action           = 'Start'
            Cancelled        = $false
            DryRun           = [bool]$DryRun
            SessionName      = $SessionName
            OutputDir        = $OutputDir
            EtlPath          = $EtlPath
            IncludeDxgKrnl   = [bool]$IncludeDxgKrnl
            Providers        = $providers
            ExecutedCommands = @($executedCommands.ToArray())
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
                Action      = 'Stop'
                Cancelled   = $true
                DryRun      = $false
                SessionName = $SessionName
                EtlPath     = $EtlPath
                OutputDir   = $OutputDir
            }
        }

        $stopArgs = @('stop', $SessionName, '-ets')
        $null = Invoke-LumaBridgeExternalCommand -FilePath 'logman.exe' -Arguments $stopArgs -DryRun:$DryRun

        if ($DryRun) {
            return [pscustomobject]@{
                Action               = 'Stop'
                Cancelled            = $false
                DryRun               = $true
                SessionName          = $SessionName
                EtlPath              = $EtlPath
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

        $etlSummary = Get-LumaBridgeEtlEventSummary -EtlPath $EtlPath
        $stageSummary = Get-LumaBridgeDriverTraceStageSummary -EtlEvents @($etlSummary.LumaBridgeEvents)

        $exportPayload = [pscustomobject]@{
            ExportedAtUtc       = (Get-Date).ToUniversalTime().ToString('o')
            SessionName         = $SessionName
            EtlPath             = $EtlPath
            CopiedRdpIddEtlPath = $copiedAutoLoggerPath
            EtlSummary          = $etlSummary
            StageSummary        = $stageSummary
        }
        $exportPayload | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $decodedSummaryPath -Encoding UTF8

        return [pscustomobject]@{
            Action               = 'Stop'
            Cancelled            = $false
            DryRun               = $false
            SessionName          = $SessionName
            EtlPath              = $EtlPath
            OutputDir            = $OutputDir
            DecodedSummaryPath   = $decodedSummaryPath
            CopiedRdpIddEtlPath  = $copiedAutoLoggerPath
            EtlSummary           = $etlSummary
            StageSummary         = $stageSummary
        }
    }

    'ExportSummary' {
        $etlSummary = Get-LumaBridgeEtlEventSummary -EtlPath $EtlPath
        $stageSummary = Get-LumaBridgeDriverTraceStageSummary -EtlEvents @($etlSummary.LumaBridgeEvents)

        if (-not $DryRun) {
            if (-not (Test-Path -LiteralPath $OutputDir)) {
                $null = New-Item -Path $OutputDir -ItemType Directory -Force
            }

            $exportPayload = [pscustomobject]@{
                ExportedAtUtc = (Get-Date).ToUniversalTime().ToString('o')
                SessionName   = $SessionName
                EtlPath       = $EtlPath
                EtlSummary    = $etlSummary
                StageSummary  = $stageSummary
            }
            $exportPayload | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $decodedSummaryPath -Encoding UTF8
        }

        return [pscustomobject]@{
            Action             = 'ExportSummary'
            DryRun             = [bool]$DryRun
            EtlPath            = $EtlPath
            OutputDir          = $OutputDir
            DecodedSummaryPath = if ($DryRun) { $null } else { $decodedSummaryPath }
            EtlSummary         = $etlSummary
            StageSummary       = $stageSummary
        }
    }
}
