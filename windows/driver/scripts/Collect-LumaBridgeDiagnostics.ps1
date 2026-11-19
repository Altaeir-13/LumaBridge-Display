<#
.SYNOPSIS
    Collects read-only host/driver diagnostics, PnP status/problem codes, SetupAPI excerpts,
    Kernel-PnP/CodeIntegrity/UMDF/WerKernel/IddCx event channels, crash-dump inventories,
    ETW traces, LumaBridge-associated WUDFHost.exe resource usage, and startup stage
    breadcrumbs without capturing or storing desktop pixel content.
#>
[CmdletBinding()]
param(
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Release',

    [string]$OutputDir,

    [string]$DebugLogPath,

    [ValidateRange(1, 10080)]
    [int]$EventLookbackMinutes = 60,

    [string]$StagingDir,

    [string]$EtlPath,

    [string]$DxgEtlPath,

    [Nullable[DateTime]]$EtlStartTimeUtc = $null,

    [Nullable[DateTime]]$EtlEndTimeUtc = $null,

    [Nullable[int]]$EtlProcessId = $null,

    [switch]$DecodeWpp,

    [string]$TmfCacheDir,

    [string]$SetupApiLogPath,

    [string]$FailureContext,

    [switch]$DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$commonModulePath = (Resolve-Path -LiteralPath (Join-Path -Path $PSScriptRoot -ChildPath 'LumaBridgeDriverCommon.psm1')).Path
$loadedCommon = Get-Module -Name 'LumaBridgeDriverCommon' -ErrorAction SilentlyContinue
if ($null -eq $loadedCommon -or $loadedCommon.Path -ine $commonModulePath) {
    Import-Module $commonModulePath -Force
}

function Get-LumaBridgeOptionalPropertyValue {
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

function ConvertTo-LumaBridgePackageMetadata {
    param($PackageResult)

    if ($null -eq $PackageResult) {
        return $null
    }

    return [pscustomobject]@{
        PackageDirectory         = Get-LumaBridgeOptionalPropertyValue -InputObject $PackageResult -PropertyName 'PackageDirectory'
        AllFilesPresent          = [bool](Get-LumaBridgeOptionalPropertyValue -InputObject $PackageResult -PropertyName 'AllFilesPresent' -DefaultValue $false)
        InfDriverVersion         = Get-LumaBridgeOptionalPropertyValue -InputObject $PackageResult -PropertyName 'InfDriverVersion'
        InfDriverVerRaw          = Get-LumaBridgeOptionalPropertyValue -InputObject $PackageResult -PropertyName 'InfDriverVerRaw'
        InfSha256                = Get-LumaBridgeOptionalPropertyValue -InputObject $PackageResult -PropertyName 'InfSha256'
        DllSha256                = Get-LumaBridgeOptionalPropertyValue -InputObject $PackageResult -PropertyName 'DllSha256'
        CatSha256                = Get-LumaBridgeOptionalPropertyValue -InputObject $PackageResult -PropertyName 'CatSha256'
        IsCryptographicallyValid = [bool](Get-LumaBridgeOptionalPropertyValue -InputObject $PackageResult -PropertyName 'IsCryptographicallyValid' -DefaultValue $false)
        IsValidWithUntrustedRoot = [bool](Get-LumaBridgeOptionalPropertyValue -InputObject $PackageResult -PropertyName 'IsValidWithUntrustedRoot' -DefaultValue $false)
        Valid                    = [bool](Get-LumaBridgeOptionalPropertyValue -InputObject $PackageResult -PropertyName 'IsCryptographicallyValid' -DefaultValue $false)
        DllSignerThumbprint      = Get-LumaBridgeOptionalPropertyValue -InputObject $PackageResult -PropertyName 'DllSignerThumbprint'
        CatSignerThumbprint      = Get-LumaBridgeOptionalPropertyValue -InputObject $PackageResult -PropertyName 'CatSignerThumbprint'
    }
}

$constants = Get-LumaBridgeDriverConstants
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

$invokePrereq = {
    if ([string]::IsNullOrWhiteSpace($StagingDir)) {
        & $prereqScript -Configuration $Configuration
    }
    else {
        & $prereqScript -Configuration $Configuration -StagingDir $StagingDir
    }
}

$plannedJsonPath = Join-Path -Path $OutputDir -ChildPath 'diagnostics-summary.json'
$plannedMdPath = Join-Path -Path $OutputDir -ChildPath 'diagnostics-summary.md'
$plannedSetupApiPath = Join-Path -Path $OutputDir -ChildPath 'setupapi-excerpt.log'

if ($DryRun) {
    $prereqPreview = & $invokePrereq
    Write-Host ("[DRY-RUN] Would collect PnP instances (including DEVPKEY_Device_ProblemStatus and startup breadcrumbs), Driver Store state, SetupAPI log excerpt, Event Log channel states & events ({0}m window), crash-dump inventory, package hashes, and LumaBridge-associated WUDFHost.exe stats{1}{2}" -f `
        $EventLookbackMinutes, `
        $(if ([string]::IsNullOrWhiteSpace($DebugLogPath)) { '' } else { (", debug trace '{0}'" -f $DebugLogPath) }), `
        $(if ([string]::IsNullOrWhiteSpace($EtlPath)) { '' } else { (", ETW log '{0}'" -f $EtlPath) })) -ForegroundColor Cyan
    Write-Host ("[DRY-RUN] Would write JSON/Markdown/SetupAPI reports under '{0}'" -f $OutputDir) -ForegroundColor Cyan
    return [pscustomobject]@{
        DryRun                = $true
        PlannedOutputDir      = $OutputDir
        PlannedArtifacts      = @($plannedJsonPath, $plannedMdPath, $plannedSetupApiPath)
        PrerequisitesSnapshot = $prereqPreview
    }
}

$prereq = & $invokePrereq

$instanceIdsList = New-Object System.Collections.Generic.List[string]
$publishedInfList = New-Object System.Collections.Generic.List[string]
$primaryStartupDiagnostics = $null

foreach ($inst in @($prereq.PnpInstances)) {
    $instId = [string](Get-LumaBridgeOptionalPropertyValue -InputObject $inst -PropertyName 'InstanceId' -DefaultValue '')
    if (-not [string]::IsNullOrWhiteSpace($instId) -and ($instanceIdsList -notcontains $instId)) {
        $instanceIdsList.Add($instId)
    }

    $driverInf = [string](Get-LumaBridgeOptionalPropertyValue -InputObject $inst -PropertyName 'DriverInfPath' -DefaultValue '')
    if (-not [string]::IsNullOrWhiteSpace($driverInf)) {
        $infLeaf = [System.IO.Path]::GetFileName($driverInf)
        if (-not [string]::IsNullOrWhiteSpace($infLeaf) -and ($publishedInfList -notcontains $infLeaf)) {
            $publishedInfList.Add($infLeaf)
        }
    }

    if ($null -eq $primaryStartupDiagnostics) {
        $candDiag = Get-LumaBridgeOptionalPropertyValue -InputObject $inst -PropertyName 'StartupDiagnostics'
        if ($null -ne $candDiag) {
            $primaryStartupDiagnostics = $candDiag
        }
    }
}

foreach ($pkg in @($prereq.DriverStorePackages)) {
    $pubName = [string](Get-LumaBridgeOptionalPropertyValue -InputObject $pkg -PropertyName 'PublishedName' -DefaultValue '')
    if (-not [string]::IsNullOrWhiteSpace($pubName) -and ($publishedInfList -notcontains $pubName)) {
        $publishedInfList.Add($pubName)
    }
}

$instanceIds = @($instanceIdsList.ToArray())
$publishedInfNames = @($publishedInfList.ToArray())

$eventChannelStatus = @(Get-LumaBridgeEventChannelStatus)
$recentEvents = @(Get-LumaBridgeDiagnosticEvents `
    -LookbackMinutes $EventLookbackMinutes `
    -InstanceIds $instanceIds `
    -PublishedInfNames $publishedInfNames `
    -ChannelStatus $eventChannelStatus)

$effectiveSetupApiPath = if ([string]::IsNullOrWhiteSpace($SetupApiLogPath)) {
    $constants.DefaultSetupApiLogPath
}
else {
    $SetupApiLogPath
}

$setupApiExcerpt = Get-LumaBridgeSetupApiLogExcerpt `
    -SetupApiLogPath $effectiveSetupApiPath `
    -InstanceIds $instanceIds `
    -PublishedInfNames $publishedInfNames

$crashDumpInventory = Get-LumaBridgeCrashDumpInventory -LookbackMinutes $EventLookbackMinutes

$etlEventSummary = $null
$wppDecodeSummary = $null
$dxgEtlStats = $null

if (-not [string]::IsNullOrWhiteSpace($DxgEtlPath)) {
    $dxgEtlStats = Get-LumaBridgeEtlTraceStats -EtlPath $DxgEtlPath
}

if (-not [string]::IsNullOrWhiteSpace($EtlPath)) {
    $effectiveEtlStart = $EtlStartTimeUtc
    $effectiveEtlEnd = $EtlEndTimeUtc

    if ($null -eq $effectiveEtlStart -and $null -eq $effectiveEtlEnd) {
        $anchorTimes = New-Object System.Collections.Generic.List[DateTime]
        foreach ($ev in $recentEvents) {
            if ($null -eq $ev) { continue }
            $ln = [string](Get-LumaBridgeOptionalPropertyValue -InputObject $ev -PropertyName 'LogName' -DefaultValue '')
            $evId = Get-LumaBridgeOptionalPropertyValue -InputObject $ev -PropertyName 'Id' -DefaultValue 0
            $tsStr = [string](Get-LumaBridgeOptionalPropertyValue -InputObject $ev -PropertyName 'TimeCreated' -DefaultValue '')
            if (($ln -match 'Kernel-PnP|DriverFrameworks-UserMode' -or $evId -in @(400, 411, 2006, 2103)) -and
                -not [string]::IsNullOrWhiteSpace($tsStr) -and $evId -ne 0) {
                $dt = [DateTime]::MinValue
                if ([DateTime]::TryParse($tsStr, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AdjustToUniversal, [ref]$dt)) {
                    $anchorTimes.Add($dt.ToUniversalTime())
                }
            }
        }
        if ($anchorTimes.Count -gt 0) {
            $sortedAnchors = @($anchorTimes.ToArray() | Sort-Object)
            $effectiveEtlStart = $sortedAnchors[0].AddSeconds(-30)
            $effectiveEtlEnd = $sortedAnchors[$sortedAnchors.Count - 1].AddSeconds(30)
        }
    }

    $etlEventSummary = Get-LumaBridgeEtlEventSummary `
        -EtlPath $EtlPath `
        -StartTimeUtc $effectiveEtlStart `
        -EndTimeUtc $effectiveEtlEnd `
        -ProcessId $EtlProcessId

    if ($DecodeWpp -and (Test-Path -LiteralPath $EtlPath -PathType Leaf)) {
        $tmfInit = Initialize-LumaBridgeWppTmfCache -TmfCacheDir $TmfCacheDir -SkipSymbolDownload
        $wppDecodeSummary = Invoke-LumaBridgeWppEtlDecode -EtlPath $EtlPath -TmfCacheDir $tmfInit.TmfCacheDir -ProcessId $EtlProcessId -SkipSymbolServer
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

$etlLumaBridgeEvents = if ($null -ne $etlEventSummary -and $null -ne $etlEventSummary.LumaBridgeEvents) {
    @($etlEventSummary.LumaBridgeEvents)
}
else {
    @()
}

$stageExecutionSummary = Get-LumaBridgeDriverTraceStageSummary `
    -TraceLines @($parsedDriverEvents.ToArray()) `
    -StartupDiagnostics $primaryStartupDiagnostics `
    -EtlEvents $etlLumaBridgeEvents

$wudfProcesses = @(Get-LumaBridgeWudfHostProcesses `
    -PnpInstances @($prereq.PnpInstances) `
    -RecentEvents $recentEvents `
    -DebugTraceLines @($parsedDriverEvents.ToArray()))

$lumaBridgeWudfProcesses = @($wudfProcesses | Where-Object { $_.IsLumaBridgeHost })
$primaryLumaBridgeWudf = if ($lumaBridgeWudfProcesses.Count -gt 0) { $lumaBridgeWudfProcesses[0] } else { $null }

$testedPackages = [pscustomobject]@{
    BuildPackage   = ConvertTo-LumaBridgePackageMetadata -PackageResult (Get-LumaBridgeOptionalPropertyValue -InputObject $prereq -PropertyName 'BuildPackage')
    StagingPackage = ConvertTo-LumaBridgePackageMetadata -PackageResult (Get-LumaBridgeOptionalPropertyValue -InputObject $prereq -PropertyName 'StagingPackage')
}

$summary = [pscustomobject]@{
    GeneratedAtUtc            = (Get-Date).ToUniversalTime().ToString('o')
    Configuration             = $Configuration
    FailureContext            = if ([string]::IsNullOrWhiteSpace($FailureContext)) { $null } else { $FailureContext }
    CaptureScope              = 'Metadata, states, FPS/timing counters, resource usage, and logs only (no desktop pixel content)'
    Prerequisites             = $prereq
    TestedPackages            = $testedPackages
    StageExecutionSummary     = $stageExecutionSummary
    EventChannelStatus        = $eventChannelStatus
    SetupApiExcerpt           = $setupApiExcerpt
    CrashDumpInventory        = $crashDumpInventory
    EtlEventSummary           = $etlEventSummary
    WppDecodeSummary          = $wppDecodeSummary
    DxgEtlStats               = $dxgEtlStats
    LumaBridgeWudfHostProcess = $primaryLumaBridgeWudf
    LumaBridgeWudfHostProcesses = $lumaBridgeWudfProcesses
    WudfHostProcesses         = $wudfProcesses
    RecentEvents              = $recentEvents
    DriverTraceLineCount      = $parsedDriverEvents.Count
    DriverMetricsSamples      = @($parsedMetrics.ToArray())
    LatestMetricsSample       = if ($parsedMetrics.Count -gt 0) { $parsedMetrics[$parsedMetrics.Count - 1] } else { $null }
}

if (-not (Test-Path -LiteralPath $OutputDir)) {
    New-Item -Path $OutputDir -ItemType Directory -Force | Out-Null
}

$jsonPath = $plannedJsonPath
$mdPath = $plannedMdPath
$setupApiExcerptPath = $null

$summary | ConvertTo-Json -Depth 8 | Out-File -LiteralPath $jsonPath -Encoding utf8

$rawExcerptText = [string](Get-LumaBridgeOptionalPropertyValue -InputObject $setupApiExcerpt -PropertyName 'RawExcerptText' -DefaultValue '')
if (-not [string]::IsNullOrWhiteSpace($rawExcerptText)) {
    $rawExcerptText | Out-File -LiteralPath $plannedSetupApiPath -Encoding utf8
    $setupApiExcerptPath = $plannedSetupApiPath
}

$wudfLine = if ($null -ne $primaryLumaBridgeWudf) {
    "- LumaBridge WUDFHost.exe: PID ``{0}`` (Method=``{1}``, WorkingSet=``{2} MB``, Private=``{3} MB``, Handles=``{4}``)" -f `
        $primaryLumaBridgeWudf.Id, $primaryLumaBridgeWudf.AssociationMethod, $primaryLumaBridgeWudf.WorkingSetMB, $primaryLumaBridgeWudf.PrivateMemoryMB, $primaryLumaBridgeWudf.HandleCount
}
else {
    "- LumaBridge WUDFHost.exe: ``Not identified / Not loaded`` (Total system WUDFHost processes: ``{0}``)" -f $wudfProcesses.Count
}

$mdLines = New-Object System.Collections.Generic.List[string]
$mdLines.Add('# LumaBridge IDD Driver Diagnostics Report')
$mdLines.Add('')
$mdLines.Add(("- Generated UTC: ``{0}``" -f $summary.GeneratedAtUtc))
$mdLines.Add(("- Configuration: ``{0}``" -f $Configuration))
if (-not [string]::IsNullOrWhiteSpace($FailureContext)) {
    $mdLines.Add(("- Failure Context: ``{0}``" -f $FailureContext))
}
$mdLines.Add(("- Windows Build: ``{0}.{1}`` (Supported Win11: ``{2}``)" -f $prereq.HostOs.CurrentBuildNumber, $prereq.HostOs.UBR, $prereq.HostOs.IsSupportedWindows11))
$mdLines.Add(("- TestSigning: ``{0}`` | SecureBoot: ``{1}``" -f $prereq.SecurityState.TestSigning, $prereq.SecurityState.SecureBoot))
$mdLines.Add(("- PnP Instances: ``{0}`` | DriverStore Packages: ``{1}`` | LumaBridge WUDFHost Matches: ``{2}`` / Total ``{3}``" -f @($prereq.PnpInstances).Count, @($prereq.DriverStorePackages).Count, $lumaBridgeWudfProcesses.Count, $wudfProcesses.Count))
$mdLines.Add($wudfLine)
$mdLines.Add(("- Parsed Driver Trace Lines: ``{0}`` | Metrics Snapshots: ``{1}``" -f $parsedDriverEvents.Count, $parsedMetrics.Count))

$mdLines.Add('')
$mdLines.Add('## Tested Packages')
if ($null -ne $testedPackages.BuildPackage) {
    $bp = $testedPackages.BuildPackage
    $mdLines.Add(("- Build Package: ``{0}`` | DriverVer=``{1}`` (``{2}``) | INF SHA256=``{3}`` | DLL SHA256=``{4}`` | CAT SHA256=``{5}`` | Valid=``{6}``" -f `
        $bp.PackageDirectory, $bp.InfDriverVersion, $bp.InfDriverVerRaw, $bp.InfSha256, $bp.DllSha256, $bp.CatSha256, $bp.Valid))
}
if ($null -ne $testedPackages.StagingPackage) {
    $sp = $testedPackages.StagingPackage
    $mdLines.Add(("- Staging Package: ``{0}`` | DriverVer=``{1}`` (``{2}``) | INF SHA256=``{3}`` | DLL SHA256=``{4}`` | CAT SHA256=``{5}`` | Valid=``{6}``" -f `
        $sp.PackageDirectory, $sp.InfDriverVersion, $sp.InfDriverVerRaw, $sp.InfSha256, $sp.DllSha256, $sp.CatSha256, $sp.Valid))
}

$mdLines.Add('')
$mdLines.Add('## PnP Instances')
if (@($prereq.PnpInstances).Count -eq 0) {
    $mdLines.Add('- None found.')
}
else {
    foreach ($inst in @($prereq.PnpInstances)) {
        $iId = Get-LumaBridgeOptionalPropertyValue -InputObject $inst -PropertyName 'InstanceId'
        $iProb = Get-LumaBridgeOptionalPropertyValue -InputObject $inst -PropertyName 'ProblemCode'
        $iProbHex = Get-LumaBridgeOptionalPropertyValue -InputObject $inst -PropertyName 'ProblemStatusHex'
        $iInf = Get-LumaBridgeOptionalPropertyValue -InputObject $inst -PropertyName 'DriverInfPath'
        $iSvc = Get-LumaBridgeOptionalPropertyValue -InputObject $inst -PropertyName 'DriverService'
        $iEnMon = Get-LumaBridgeOptionalPropertyValue -InputObject $inst -PropertyName 'EnableVirtualMonitor'
        $iUpper = @(Get-LumaBridgeOptionalPropertyValue -InputObject $inst -PropertyName 'UpperFilters' -DefaultValue @()) -join ','
        $mdLines.Add(("- Instance=``{0}`` | Status=``{1}`` | ProblemCode=``{2}`` | ProblemStatus=``{3}`` | INF=``{4}`` | Service=``{5}`` | UpperFilters=``{6}`` | EnableVirtualMonitor=``{7}``" -f `
            $iId, (Get-LumaBridgeOptionalPropertyValue -InputObject $inst -PropertyName 'Status'), $iProb, $iProbHex, $iInf, $iSvc, $iUpper, $iEnMon))

        $sDiag = Get-LumaBridgeOptionalPropertyValue -InputObject $inst -PropertyName 'StartupDiagnostics'
        if ($null -ne $sDiag) {
            $mdLines.Add(("  - StartupBreadcrumbs: LastStage=``{0}``, LastSuccessfulStage=``{1}``, LastStatus=``{2}``, LastErrorStage=``{3}``, LastErrorStatus=``{4}``, IddCxVersion=``{5}``, HostPID=``{6}``, DllAttachCount=``{7}``" -f `
                (Get-LumaBridgeOptionalPropertyValue -InputObject $sDiag -PropertyName 'LastStage'), `
                (Get-LumaBridgeOptionalPropertyValue -InputObject $sDiag -PropertyName 'LastSuccessfulStage'), `
                (Get-LumaBridgeOptionalPropertyValue -InputObject $sDiag -PropertyName 'LastStatusHex'), `
                (Get-LumaBridgeOptionalPropertyValue -InputObject $sDiag -PropertyName 'LastErrorStage'), `
                (Get-LumaBridgeOptionalPropertyValue -InputObject $sDiag -PropertyName 'LastErrorStatusHex'), `
                (Get-LumaBridgeOptionalPropertyValue -InputObject $sDiag -PropertyName 'IddCxRuntimeVerHex'), `
                (Get-LumaBridgeOptionalPropertyValue -InputObject $sDiag -PropertyName 'HostProcessId'), `
                (Get-LumaBridgeOptionalPropertyValue -InputObject $sDiag -PropertyName 'DllAttachCount')))
        }
    }
}

$mdLines.Add('')
$mdLines.Add('## Driver Startup Stage Summary')
$mdLines.Add(("- DriverEntryReached: ``{0}`` | LastStage: ``{1}`` | LastSuccessfulStage: ``{2}`` | LastStatus: ``{3}``" -f `
    $stageExecutionSummary.DriverEntryReached, $stageExecutionSummary.LastStage, $stageExecutionSummary.LastSuccessfulStage, $stageExecutionSummary.LastStatusHex))
$mdLines.Add(("- FirstFailureStage: ``{0}`` | FirstFailureStatus: ``{1}`` | StageRecords: ``{2}`` | Sources: ``{3}``" -f `
    $stageExecutionSummary.FirstFailureStage, $stageExecutionSummary.FirstFailureStatusHex, $stageExecutionSummary.StageRecordCount, ($stageExecutionSummary.SourcesUsed -join ', ')))

$mdLines.Add('')
$mdLines.Add('## Event Channel Status & Recent Events')
foreach ($ch in $eventChannelStatus) {
    $mdLines.Add(("- Channel ``{0}``: Enabled=``{1}``, Records=``{2}``, Error=``{3}``" -f `
        $ch.LogName, $ch.IsEnabled, $ch.RecordCount, $ch.QueryError))
}
$mdLines.Add(("- Collected Events (``{0}`` within last {1}m):" -f $recentEvents.Count, $EventLookbackMinutes))
foreach ($ev in ($recentEvents | Select-Object -First 25)) {
    $mdLines.Add(("  - [``{0}``] [``{1}`` Id=``{2}`` Provider=``{3}``] {4}" -f `
        $ev.TimeCreated, $ev.LogName, $ev.Id, $ev.ProviderName, $ev.Message))
}

$mdLines.Add('')
$mdLines.Add('## SetupAPI Excerpt & Crash Dump Inventory')
$wdfWarnCount = @(Get-LumaBridgeOptionalPropertyValue -InputObject $setupApiExcerpt -PropertyName 'WdfSchemaWarnings' -DefaultValue @()).Count
$startProbCount = @(Get-LumaBridgeOptionalPropertyValue -InputObject $setupApiExcerpt -PropertyName 'DeviceStartProblemLines' -DefaultValue @()).Count
$mdLines.Add(("- SetupAPI (``{0}``): Exists=``{1}``, MatchedSections=``{2}``, WdfSchemaWarnings=``{3}``, DeviceStartProblemLines=``{4}``, ExcerptFile=``{5}``" -f `
    $setupApiExcerpt.LogPath, $setupApiExcerpt.Exists, $setupApiExcerpt.MatchedSectionCount, $wdfWarnCount, $startProbCount, $setupApiExcerptPath))
$mdLines.Add(("- Crash Dumps / WER / AutoLogger hits: ``{0}`` across ``{1}`` probed locations" -f `
    $crashDumpInventory.TotalFoundCount, @($crashDumpInventory.Locations).Count))
foreach ($dumpFile in @($crashDumpInventory.Files | Select-Object -First 15)) {
    $mdLines.Add(("  - [``{0}``] ``{1}`` ({2} bytes, UTC=``{3}``)" -f `
        $dumpFile.Category, $dumpFile.FullName, $dumpFile.LengthBytes, $dumpFile.LastWriteTimeUtc))
}

if ($null -ne $etlEventSummary) {
    $mdLines.Add('')
    $mdLines.Add('## ETW Trace Summary')
    $xpathUsed = Get-LumaBridgeOptionalPropertyValue -InputObject $etlEventSummary -PropertyName 'XPathUsed' -DefaultValue ''
    $filteredOut = Get-LumaBridgeOptionalPropertyValue -InputObject $etlEventSummary -PropertyName 'FilteredOutHighVolume' -DefaultValue $false
    $wrapWarn = Get-LumaBridgeOptionalPropertyValue -InputObject $etlEventSummary -PropertyName 'CircularWrapWarning' -DefaultValue ''
    $mdLines.Add(("- ETL: ``{0}`` | Exists=``{1}`` | EventCount=``{2}`` | LumaBridgeEvents=``{3}`` | ExcludedHighVolume=``{4}`` | Error=``{5}``" -f `
        $etlEventSummary.EtlPath, $etlEventSummary.Exists, $etlEventSummary.EventCount, @($etlEventSummary.LumaBridgeEvents).Count, $filteredOut, $etlEventSummary.Error))
    if (-not [string]::IsNullOrWhiteSpace([string]$xpathUsed)) {
        $mdLines.Add(("- XPath Filter: ``{0}``" -f $xpathUsed))
    }
    if (-not [string]::IsNullOrWhiteSpace([string]$wrapWarn)) {
        $mdLines.Add(("- WARNING: {0}" -f $wrapWarn))
    }
}

if ($null -ne $wppDecodeSummary) {
    $mdLines.Add('')
    $mdLines.Add('## WPP Trace Decode Summary')
    $mdLines.Add(("- TotalScannedLines=``{0}`` | MatchedLines=``{1}`` | IddCxWppLines=``{2}`` | Error=``{3}``" -f `
        $wppDecodeSummary.TotalScannedLines, $wppDecodeSummary.MatchedLineCount, @($wppDecodeSummary.IddCxWppLines).Count, $wppDecodeSummary.Error))
}

if ($null -ne $dxgEtlStats) {
    $mdLines.Add('')
    $mdLines.Add('## Separated DxgKrnl / Watchdog ETL Metadata')
    $mdLines.Add(("- DxgETL: ``{0}`` | Available=``{1}`` | Mode=``{2}`` | Start=``{3}`` | End=``{4}``" -f `
        $dxgEtlStats.EtlPath, $dxgEtlStats.Available, $dxgEtlStats.LogFileMode, $dxgEtlStats.StartTimeUtc, $dxgEtlStats.EndTimeUtc))
}

$mdLines.Add('')
$mdLines.Add('See ``diagnostics-summary.json`` in this folder for full structured output.')
$mdLines | Out-File -LiteralPath $mdPath -Encoding utf8

[pscustomobject]@{
    OutputDir           = $OutputDir
    JsonReportPath      = $jsonPath
    MarkdownReportPath  = $mdPath
    SummaryJsonPath     = $jsonPath
    SummaryMarkdownPath = $mdPath
    SetupApiExcerptPath = $setupApiExcerptPath
    Summary             = $summary
}
