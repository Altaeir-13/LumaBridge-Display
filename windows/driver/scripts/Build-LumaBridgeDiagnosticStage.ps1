[CmdletBinding()]
param(
    [ValidateRange(1, 6)]
    [int]$DiagnosticStage = 6,

    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Release',

    [string]$OutputRoot = (Join-Path -Path $env:LOCALAPPDATA -ChildPath 'LumaBridgeDisplay\DiagnosticStages'),

    [string]$SourcePackageDir = '',

    [switch]$SkipBuild,

    [switch]$RestoreDefaultStageAfterBuild,

    [switch]$DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$commonModulePath = Join-Path -Path $PSScriptRoot -ChildPath 'LumaBridgeDriverCommon.psm1'
$loadedCommon = Get-Module -Name 'LumaBridgeDriverCommon' -ErrorAction SilentlyContinue
if ($null -eq $loadedCommon -or $loadedCommon.Path -ine $commonModulePath) {
    Import-Module -Name $commonModulePath -Force
}

function Resolve-LumaBridgeStageVsDevCmdPath {
    [CmdletBinding()]
    param()

    $candidates = New-Object System.Collections.Generic.List[string]
    $vswhereCandidates = @(
        (Join-Path -Path ${env:ProgramFiles(x86)} -ChildPath 'Microsoft Visual Studio\Installer\vswhere.exe'),
        (Join-Path -Path $env:ProgramFiles -ChildPath 'Microsoft Visual Studio\Installer\vswhere.exe')
    ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) -and (Test-Path -LiteralPath $_) }

    foreach ($vswhere in $vswhereCandidates) {
        try {
            $installPaths = & $vswhere -all -products * -requires Microsoft.Component.MSBuild -property installationPath 2>$null
            foreach ($installPath in @($installPaths)) {
                if (-not [string]::IsNullOrWhiteSpace($installPath)) {
                    $candidates.Add((Join-Path -Path $installPath.Trim() -ChildPath 'Common7\Tools\VsDevCmd.bat'))
                }
            }
        }
        catch {
            # Fallback to well-known Visual Studio installation paths below.
        }
    }

    foreach ($root in @(${env:ProgramFiles(x86)}, $env:ProgramFiles)) {
        if ([string]::IsNullOrWhiteSpace($root)) {
            continue
        }
        foreach ($rel in @(
            'Microsoft Visual Studio\18\BuildTools\Common7\Tools\VsDevCmd.bat',
            'Microsoft Visual Studio\18\Community\Common7\Tools\VsDevCmd.bat',
            'Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat',
            'Microsoft Visual Studio\2022\Community\Common7\Tools\VsDevCmd.bat',
            'Microsoft Visual Studio\2022\Professional\Common7\Tools\VsDevCmd.bat',
            'Microsoft Visual Studio\2022\Enterprise\Common7\Tools\VsDevCmd.bat'
        )) {
            $candidates.Add((Join-Path -Path $root -ChildPath $rel))
        }
    }

    foreach ($candidate in $candidates) {
        if (-not [string]::IsNullOrWhiteSpace($candidate) -and (Test-Path -LiteralPath $candidate)) {
            return $candidate
        }
    }

    return $null
}

function Invoke-LumaBridgeStageMsBuild {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SolutionPath,

        [Parameter(Mandatory = $true)]
        [string]$Configuration,

        [Parameter(Mandatory = $true)]
        [int]$Stage,

        [string]$VsDevCmdPath
    )

    $msbuildArgs = @(
        $SolutionPath,
        '/t:Rebuild',
        ("/p:Configuration={0};Platform=x64;LumaBridgeDiagnosticStage={1}" -f $Configuration, $Stage),
        '/m',
        '/v:m'
    )
    $msbuildQuotedArgs = ($msbuildArgs | ForEach-Object {
        if ($_ -match '\s') { '"{0}"' -f $_ } else { $_ }
    }) -join ' '

    $batchLines = New-Object System.Collections.Generic.List[string]
    $batchLines.Add('@echo off')
    if (-not [string]::IsNullOrWhiteSpace($VsDevCmdPath)) {
        $batchLines.Add(('call "{0}" -arch=amd64 -host_arch=amd64' -f $VsDevCmdPath))
        $batchLines.Add('if errorlevel 1 exit /b %errorlevel%')
    }
    $batchLines.Add(('msbuild.exe {0}' -f $msbuildQuotedArgs))
    $batchLines.Add('exit /b %errorlevel%')

    $tempCmdPath = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath ("LumaBridgeBuildStage_{0}.cmd" -f ([Guid]::NewGuid().ToString('N')))
    try {
        [System.IO.File]::WriteAllLines($tempCmdPath, $batchLines.ToArray(), [System.Text.Encoding]::ASCII)
        $prevEap = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        try {
            $output = @(& cmd.exe /d /c ('"{0}"' -f $tempCmdPath) 2>&1 | ForEach-Object { $_.ToString() })
            $exitCode = $LASTEXITCODE
        }
        finally {
            $ErrorActionPreference = $prevEap
        }
    }
    finally {
        Remove-Item -LiteralPath $tempCmdPath -Force -ErrorAction SilentlyContinue
    }

    if ($exitCode -ne 0) {
        $tail = ($output | Select-Object -Last 25) -join "`n"
        throw ("MSBuild failed for Stage {0} ({1}|x64) with exit code {2}:`n{3}" -f $Stage, $Configuration, $exitCode, $tail)
    }

    return @($output)
}

$repoRoot = Get-LumaBridgeRepoRoot
$solutionPath = Join-Path -Path $repoRoot -ChildPath 'windows\driver\LumaBridgeIddDriver.sln'
$defaultPkgDir = Get-LumaBridgePackageDirectory -Configuration $Configuration
$resolvedSourcePkgDir = if ([string]::IsNullOrWhiteSpace($SourcePackageDir)) {
    $defaultPkgDir
}
else {
    $SourcePackageDir
}

$isolatedRoot = Assert-LumaBridgeIsolatedStagingDirectory -StagingDir $OutputRoot -SourcePackageDir $resolvedSourcePkgDir
$stagePackageDir = Join-Path -Path $isolatedRoot -ChildPath ("Stage{0}\{1}" -f $DiagnosticStage, $Configuration)
$manifestPath = Join-Path -Path $stagePackageDir -ChildPath 'stage-build-manifest.json'
$vsDevCmdPath = Resolve-LumaBridgeStageVsDevCmdPath

$plannedCommands = New-Object System.Collections.Generic.List[string]
if (-not $SkipBuild) {
    $plannedCommands.Add(('msbuild.exe "{0}" /t:Rebuild /p:Configuration={1};Platform=x64;LumaBridgeDiagnosticStage={2} /m' -f `
        $solutionPath, $Configuration, $DiagnosticStage))
}
$plannedCommands.Add(('Stage files to "{0}" and write "{1}"' -f $stagePackageDir, $manifestPath))
if ($RestoreDefaultStageAfterBuild -and ($DiagnosticStage -ne 6) -and (-not $SkipBuild)) {
    $plannedCommands.Add(('msbuild.exe "{0}" /t:Rebuild /p:Configuration={1};Platform=x64;LumaBridgeDiagnosticStage=6 /m' -f `
        $solutionPath, $Configuration))
}

if ($DryRun) {
    return [pscustomobject]@{
        TimestampUtc              = (Get-Date).ToUniversalTime().ToString('o')
        DryRun                    = $true
        DiagnosticStage           = $DiagnosticStage
        Configuration             = $Configuration
        Platform                  = 'x64'
        SourcePackageDir          = $resolvedSourcePkgDir
        StagePackageDir           = $stagePackageDir
        ManifestPath              = $manifestPath
        SkipBuild                 = [bool]$SkipBuild
        RestoreDefaultStageAfterBuild = [bool]$RestoreDefaultStageAfterBuild
        PlannedCommands           = @($plannedCommands.ToArray())
        DllSha256                 = $null
        InfSha256                 = $null
        CatSha256                 = $null
        PdbSha256                 = $null
    }
}

$buildOutput = @()
if (-not $SkipBuild) {
    $hasMsBuildInEnv = ($null -ne (Get-Command -Name 'msbuild.exe' -ErrorAction SilentlyContinue))
    if (-not $hasMsBuildInEnv -and [string]::IsNullOrWhiteSpace($vsDevCmdPath)) {
        throw 'Could not locate VsDevCmd.bat or msbuild.exe for MSBuild execution.'
    }
    $buildOutput = @(Invoke-LumaBridgeStageMsBuild `
        -SolutionPath $solutionPath `
        -Configuration $Configuration `
        -Stage $DiagnosticStage `
        -VsDevCmdPath $(if ($hasMsBuildInEnv) { '' } else { $vsDevCmdPath }))
}

$srcDll = Join-Path -Path $resolvedSourcePkgDir -ChildPath 'LumaBridgeIddDriver.dll'
$srcInf = Join-Path -Path $resolvedSourcePkgDir -ChildPath 'LumaBridgeIddDriver.inf'
$srcCat = Join-Path -Path $resolvedSourcePkgDir -ChildPath 'LumaBridgeIddDriver.cat'
$srcOutDir = Split-Path -Path $resolvedSourcePkgDir -Parent
$srcPdb = Join-Path -Path $srcOutDir -ChildPath 'LumaBridgeIddDriver.pdb'
if (-not (Test-Path -LiteralPath $srcPdb -PathType Leaf)) {
    $fallbackPdb = Join-Path -Path $resolvedSourcePkgDir -ChildPath 'LumaBridgeIddDriver.pdb'
    if (Test-Path -LiteralPath $fallbackPdb -PathType Leaf) {
        $srcPdb = $fallbackPdb
    }
}

foreach ($requiredArtifact in @($srcDll, $srcInf, $srcCat)) {
    if (-not (Test-Path -LiteralPath $requiredArtifact -PathType Leaf)) {
        throw ("Expected driver package artifact not found: {0}" -f $requiredArtifact)
    }
}

if (Test-Path -LiteralPath $stagePackageDir) {
    Remove-Item -LiteralPath $stagePackageDir -Recurse -Force
}
$null = New-Item -Path $stagePackageDir -ItemType Directory -Force

$dstDll = Join-Path -Path $stagePackageDir -ChildPath 'LumaBridgeIddDriver.dll'
$dstInf = Join-Path -Path $stagePackageDir -ChildPath 'LumaBridgeIddDriver.inf'
$dstCat = Join-Path -Path $stagePackageDir -ChildPath 'LumaBridgeIddDriver.cat'
$dstPdb = Join-Path -Path $stagePackageDir -ChildPath 'LumaBridgeIddDriver.pdb'

Copy-Item -LiteralPath $srcDll -Destination $dstDll -Force
Copy-Item -LiteralPath $srcInf -Destination $dstInf -Force
Copy-Item -LiteralPath $srcCat -Destination $dstCat -Force
$pdbHash = $null
if (Test-Path -LiteralPath $srcPdb -PathType Leaf) {
    Copy-Item -LiteralPath $srcPdb -Destination $dstPdb -Force
    $pdbHash = (Get-FileHash -LiteralPath $dstPdb -Algorithm SHA256).Hash
}
else {
    $dstPdb = $null
}

$dllHash = (Get-FileHash -LiteralPath $dstDll -Algorithm SHA256).Hash
$infHash = (Get-FileHash -LiteralPath $dstInf -Algorithm SHA256).Hash
$catHash = (Get-FileHash -LiteralPath $dstCat -Algorithm SHA256).Hash

$restoredDefault = $false
if ($RestoreDefaultStageAfterBuild -and ($DiagnosticStage -ne 6) -and (-not $SkipBuild)) {
    $hasMsBuildInEnv = ($null -ne (Get-Command -Name 'msbuild.exe' -ErrorAction SilentlyContinue))
    $null = Invoke-LumaBridgeStageMsBuild `
        -SolutionPath $solutionPath `
        -Configuration $Configuration `
        -Stage 6 `
        -VsDevCmdPath $(if ($hasMsBuildInEnv) { '' } else { $vsDevCmdPath })
    $restoredDefault = $true
}

$manifest = [pscustomobject]@{
    TimestampUtc              = (Get-Date).ToUniversalTime().ToString('o')
    DryRun                    = $false
    DiagnosticStage           = $DiagnosticStage
    Configuration             = $Configuration
    Platform                  = 'x64'
    SourcePackageDir          = $resolvedSourcePkgDir
    StagePackageDir           = $stagePackageDir
    ManifestPath              = $manifestPath
    SkipBuild                 = [bool]$SkipBuild
    RestoredDefaultStageAfterBuild = $restoredDefault
    DllPath                   = $dstDll
    InfPath                   = $dstInf
    CatPath                   = $dstCat
    PdbPath                   = $dstPdb
    DllSha256                 = $dllHash
    InfSha256                 = $infHash
    CatSha256                 = $catHash
    PdbSha256                 = $pdbHash
    PlannedCommands           = @($plannedCommands.ToArray())
    BuildLineCount            = $buildOutput.Count
}

$manifest | ConvertTo-Json -Depth 6 | Out-File -LiteralPath $manifestPath -Encoding utf8
return $manifest
