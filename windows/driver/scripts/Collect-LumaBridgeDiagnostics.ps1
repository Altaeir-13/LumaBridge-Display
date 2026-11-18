<#
.SYNOPSIS
    Collects read-only host/driver diagnostics, PnP state, LumaBridge-associated WUDFHost.exe
    resource usage, Windows Event Logs, and optional [LB-DRIVER] / [LB-DRIVER] [METRICS]
    trace summaries without capturing or storing desktop pixel content.
#>
[CmdletBinding()]
param(
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Release',

    [string]$OutputDir,

    [string]$DebugLogPath,

    [ValidateRange(1, 10080)]
    [int]$EventLookbackMinutes = 60,

    [switch]$DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$commonModulePath = (Resolve-Path -LiteralPath (Join-Path -Path $PSScriptRoot -ChildPath 'LumaBridgeDriverCommon.psm1')).Path
$loadedCommon = Get-Module -Name 'LumaBridgeDriverCommon'
if ($null -eq $loadedCommon -or $loadedCommon.Path -ine $commonModulePath) {
    Import-Module $commonModulePath -Force
}

$prereqScript = Join-Path -Path $PSScriptRoot -ChildPath 'Test-LumaBridgePrerequisites.ps1'

if ([string]::IsNullOrWhiteSpace($OutputDir)) {
    $localAppData = if (-not [string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) {
        $env:LOCALAPPDATA
    }
    else {
        [Environment]::GetFolderPath('LocalApplicationData')
    }
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $OutputDir = Join-Path -Path $localAppData -ChildPath ("LumaBridgeDisplay\Diagnostics\{0}" -f $stamp)
}

if ($DryRun) {
    $prereqPreview = & $prereqScript -Configuration $Configuration
    Write-Host ("[DRY-RUN] Would collect PnP instances, Driver Store state, LumaBridge-associated WUDFHost.exe memory/handle stats, Event Logs ({0}m window){1}" -f `
        $EventLookbackMinutes, `
        $(if ([string]::IsNullOrWhiteSpace($DebugLogPath)) { '' } else { (", and parse trace log '{0}'" -f $DebugLogPath) })) -ForegroundColor Cyan
    Write-Host ("[DRY-RUN] Would write JSON/Markdown reports under '{0}'" -f $OutputDir) -ForegroundColor Cyan
    return [pscustomobject]@{
        DryRun                = $true
        PlannedOutputDir      = $OutputDir
        PrerequisitesSnapshot = $prereqPreview
    }
}

$prereq = & $prereqScript -Configuration $Configuration
$cutoffTime = (Get-Date).AddMinutes(-1 * $EventLookbackMinutes)

$collectedEvents = New-Object System.Collections.Generic.List[object]
$logSpecs = @(
    @{ LogName = 'Microsoft-Windows-DriverFrameworks-UserMode/Operational'; Pattern = 'LumaBridge|WUDF|UserMode|UmPass|Indirect|Idd' },
    @{ LogName = 'System'; Pattern = 'LumaBridge|WUDF|IndirectKmd|IddCx|Display' }
)

foreach ($spec in $logSpecs) {
    try {
        $events = Get-WinEvent -FilterHashtable @{
            LogName   = $spec.LogName
            StartTime = $cutoffTime
        } -MaxEvents 200 -ErrorAction Stop | Where-Object {
            $_.Message -match $spec.Pattern -or $_.ProviderName -match 'DriverFrameworks|WUDF|LumaBridge|Display'
        } | Select-Object -First 40

        foreach ($ev in $events) {
            $evPid = if ($ev.PSObject.Properties.Name -contains 'ProcessId') { $ev.ProcessId } else { $null }
            $collectedEvents.Add([pscustomobject]@{
                LogName      = $spec.LogName
                TimeCreated  = $ev.TimeCreated.ToUniversalTime().ToString('o')
                LevelDisplay = $ev.LevelDisplayName
                Id           = $ev.Id
                ProcessId    = $evPid
                ProviderName = $ev.ProviderName
                Message      = if ($null -ne $ev.Message) { ($ev.Message -replace '\r?\n', ' ').Trim() } else { '' }
            })
        }
    }
    catch {
        $collectedEvents.Add([pscustomobject]@{
            LogName      = $spec.LogName
            TimeCreated  = (Get-Date).ToUniversalTime().ToString('o')
            LevelDisplay = 'Info'
            Id           = 0
            ProcessId    = $null
            ProviderName = 'LumaBridgeDiagnostics'
            Message      = ("Log query skipped or returned no events: {0}" -f $_.Exception.Message)
        })
    }
}

$parsedDriverEvents = New-Object System.Collections.Generic.List[string]
$parsedMetrics = New-Object System.Collections.Generic.List[object]

if (-not [string]::IsNullOrWhiteSpace($DebugLogPath)) {
    if (-not (Test-Path -LiteralPath $DebugLogPath -PathType Leaf)) {
        throw ("Specified DebugLogPath was not found: {0}" -f $DebugLogPath)
    }

    foreach ($line in Get-Content -LiteralPath $DebugLogPath) {
        if ($line -match '\[LB-DRIVER\]\s+\[METRICS\]\s+(?<Fields>.+)$') {
            $kvMap = [ordered]@{}
            foreach ($token in ($matches['Fields'] -split '\s+')) {
                if ($token -match '^(?<K>[^=]+)=(?<V>.+)$') {
                    $kvMap[$matches['K']] = $matches['V']
                }
            }
            $parsedMetrics.Add([pscustomobject]$kvMap)
        }
        elseif ($line -match '\[LB-DRIVER\]') {
            $parsedDriverEvents.Add($line.Trim())
        }
    }
}

$wudfProcesses = @(Get-LumaBridgeWudfHostProcesses `
    -PnpInstances @($prereq.PnpInstances) `
    -RecentEvents @($collectedEvents.ToArray()) `
    -DebugTraceLines @($parsedDriverEvents.ToArray()))

$lumaBridgeWudfProcesses = @($wudfProcesses | Where-Object { $_.IsLumaBridgeHost })
$primaryLumaBridgeWudf = if ($lumaBridgeWudfProcesses.Count -gt 0) { $lumaBridgeWudfProcesses[0] } else { $null }

$summary = [pscustomobject]@{
    GeneratedAtUtc           = (Get-Date).ToUniversalTime().ToString('o')
    Configuration            = $Configuration
    CaptureScope             = 'Metadata, states, FPS/timing counters, resource usage, and logs only (no desktop pixel content)'
    Prerequisites            = $prereq
    LumaBridgeWudfHostProcess = $primaryLumaBridgeWudf
    LumaBridgeWudfHostProcesses = $lumaBridgeWudfProcesses
    WudfHostProcesses        = $wudfProcesses
    RecentEvents             = @($collectedEvents.ToArray())
    DriverTraceLineCount     = $parsedDriverEvents.Count
    DriverMetricsSamples     = @($parsedMetrics.ToArray())
    LatestMetricsSample      = if ($parsedMetrics.Count -gt 0) { $parsedMetrics[$parsedMetrics.Count - 1] } else { $null }
}

if (-not (Test-Path -LiteralPath $OutputDir)) {
    New-Item -Path $OutputDir -ItemType Directory -Force | Out-Null
}

$jsonPath = Join-Path -Path $OutputDir -ChildPath 'diagnostics-summary.json'
$mdPath = Join-Path -Path $OutputDir -ChildPath 'diagnostics-summary.md'

$summary | ConvertTo-Json -Depth 8 | Out-File -LiteralPath $jsonPath -Encoding utf8

$wudfLine = if ($null -ne $primaryLumaBridgeWudf) {
    "- LumaBridge WUDFHost.exe: PID ``{0}`` (Method=``{1}``, WorkingSet=``{2} MB``, Private=``{3} MB``, Handles=``{4}``)" -f `
        $primaryLumaBridgeWudf.Id, $primaryLumaBridgeWudf.AssociationMethod, $primaryLumaBridgeWudf.WorkingSetMB, $primaryLumaBridgeWudf.PrivateMemoryMB, $primaryLumaBridgeWudf.HandleCount
}
else {
    "- LumaBridge WUDFHost.exe: ``Not identified / Not loaded`` (Total system WUDFHost processes: ``{0}``)" -f $wudfProcesses.Count
}

$mdLines = @(
    '# LumaBridge IDD Driver Diagnostics Report',
    '',
    ("- Generated UTC: ``{0}``" -f $summary.GeneratedAtUtc),
    ("- Configuration: ``{0}``" -f $Configuration),
    ("- Windows Build: ``{0}.{1}`` (Supported Win11: ``{2}``)" -f $prereq.HostOs.CurrentBuildNumber, $prereq.HostOs.UBR, $prereq.HostOs.IsSupportedWindows11),
    ("- TestSigning: ``{0}`` | SecureBoot: ``{1}``" -f $prereq.SecurityState.TestSigning, $prereq.SecurityState.SecureBoot),
    ("- PnP Instances: ``{0}`` | DriverStore Packages: ``{1}`` | LumaBridge WUDFHost Matches: ``{2}`` / Total ``{3}``" -f $prereq.PnpInstances.Count, $prereq.DriverStorePackages.Count, $lumaBridgeWudfProcesses.Count, $wudfProcesses.Count),
    $wudfLine,
    ("- Parsed Driver Trace Lines: ``{0}`` | Metrics Snapshots: ``{1}``" -f $parsedDriverEvents.Count, $parsedMetrics.Count),
    '',
    'See ``diagnostics-summary.json`` in this folder for full structured output.'
)
$mdLines | Out-File -LiteralPath $mdPath -Encoding utf8

[pscustomobject]@{
    OutputDir          = $OutputDir
    JsonReportPath     = $jsonPath
    MarkdownReportPath = $mdPath
    Summary            = $summary
}
