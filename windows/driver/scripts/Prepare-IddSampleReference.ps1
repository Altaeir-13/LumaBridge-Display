[CmdletBinding()]
param(
    [string]$WorkDir = 'C:\Temp\LumaBridgeReference\IndirectDisplay',

    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Release',

    [ValidateSet('x64')]
    [string]$Platform = 'x64',

    [string]$WindowsTargetPlatformVersion = '10.0.28000.0',

    [string]$Repository = 'microsoft/Windows-driver-samples',

    [string]$Branch = 'main',

    [string]$SampleSubPath = 'video/IndirectDisplay',

    [switch]$SkipFetch,

    [switch]$SkipBuild,

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

$repoRoot = Get-LumaBridgeRepoRoot
$repoDriverRoot = Join-Path -Path $repoRoot -ChildPath 'windows\driver'
$isolatedWorkDir = Assert-LumaBridgeIsolatedStagingDirectory -StagingDir $WorkDir -SourcePackageDir $repoDriverRoot

function Resolve-LumaBridgeVsDevCmdPath {
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

function Invoke-LumaBridgeGitHubDirectoryDownload {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Repository,

        [Parameter(Mandatory = $true)]
        [string]$Branch,

        [Parameter(Mandatory = $true)]
        [string]$RepoSubPath,

        [Parameter(Mandatory = $true)]
        [string]$TargetRoot,

        [string]$CurrentRepoPath = $RepoSubPath
    )

    $ghCommand = Get-Command -Name 'gh.exe' -ErrorAction SilentlyContinue
    if ($null -eq $ghCommand) {
        $ghCommand = Get-Command -Name 'gh' -ErrorAction SilentlyContinue
    }
    if ($null -eq $ghCommand) {
        throw 'GitHub CLI (gh) was not found on PATH. Install/authenticate gh or pass -SkipFetch.'
    }

    $escapedBranch = [Uri]::EscapeDataString($Branch)
    $apiPath = "repos/$Repository/contents/${CurrentRepoPath}?ref=$escapedBranch"
    $rawJson = & $ghCommand.Source api $apiPath 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw ("Failed to list '{0}' from {1}: {2}" -f $CurrentRepoPath, $Repository, ($rawJson -join [Environment]::NewLine))
    }

    $parsed = (($rawJson | ForEach-Object { $_.ToString() }) -join [Environment]::NewLine) | ConvertFrom-Json
    $entries = if ($parsed -is [System.Array]) { $parsed } elseif ($null -ne $parsed) { @($parsed) } else { @() }
    $downloaded = New-Object System.Collections.Generic.List[string]

    $prefix = $RepoSubPath.TrimEnd('/') + '/'
    foreach ($entry in $entries) {
        $entryPath = [string]$entry.path
        $entryName = [string]$entry.name
        $entryType = [string]$entry.type
        $relativePath = if ($entryPath.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
            $entryPath.Substring($prefix.Length)
        }
        else {
            $entryName
        }
        $localPath = Join-Path -Path $TargetRoot -ChildPath ($relativePath -replace '/', '\')

        if ($entryType -eq 'dir') {
            $null = New-Item -Path $localPath -ItemType Directory -Force
            $nested = Invoke-LumaBridgeGitHubDirectoryDownload `
                -Repository $Repository `
                -Branch $Branch `
                -RepoSubPath $RepoSubPath `
                -TargetRoot $TargetRoot `
                -CurrentRepoPath $entryPath
            foreach ($nestedFile in @($nested)) {
                $downloaded.Add($nestedFile)
            }
            continue
        }

        if ($entryType -eq 'file') {
            $parentDir = Split-Path -Path $localPath -Parent
            if (-not (Test-Path -LiteralPath $parentDir)) {
                $null = New-Item -Path $parentDir -ItemType Directory -Force
            }

            $fileApiPath = "repos/$Repository/contents/${entryPath}?ref=$escapedBranch"
            $fileJsonText = & $ghCommand.Source api $fileApiPath 2>&1
            if ($LASTEXITCODE -ne 0) {
                throw ("Failed to fetch file '{0}' from {1}: {2}" -f $entryPath, $Repository, ($fileJsonText -join [Environment]::NewLine))
            }

            $fileMeta = (($fileJsonText | ForEach-Object { $_.ToString() }) -join [Environment]::NewLine) | ConvertFrom-Json
            if ($null -ne $fileMeta.content -and -not [string]::IsNullOrWhiteSpace([string]$fileMeta.content) -and $fileMeta.encoding -eq 'base64') {
                $bytes = [Convert]::FromBase64String(([string]$fileMeta.content -replace '\s', ''))
                [System.IO.File]::WriteAllBytes($localPath, $bytes)
            }
            elseif (-not [string]::IsNullOrWhiteSpace([string]$fileMeta.download_url)) {
                Invoke-WebRequest -Uri ([string]$fileMeta.download_url) -OutFile $localPath -UseBasicParsing
            }
            else {
                throw ("GitHub API did not return base64 content or download_url for '{0}'." -f $entryPath)
            }

            $downloaded.Add($localPath)
        }
    }

    return @($downloaded)
}

$solutionPath = Join-Path -Path $isolatedWorkDir -ChildPath 'IddSampleDriver.sln'
$driverProjectPath = Join-Path -Path $isolatedWorkDir -ChildPath 'IddSampleDriver\IddSampleDriver.vcxproj'
$appProjectPath = Join-Path -Path $isolatedWorkDir -ChildPath 'IddSampleApp\IddSampleApp.vcxproj'
$vsDevCmdPath = Resolve-LumaBridgeVsDevCmdPath
$infVerifPath = Get-LumaBridgeWdkToolPath -ToolName 'InfVerif.exe'

$msbuildArgs = @(
    $solutionPath,
    '/m',
    '/t:Build',
    ('/p:Configuration={0}' -f $Configuration),
    ('/p:Platform={0}' -f $Platform),
    ('/p:WindowsTargetPlatformVersion={0}' -f $WindowsTargetPlatformVersion),
    '/p:SignMode=Off',
    '/p:RunCodeAnalysis=false',
    '/p:EnablePREfast=false',
    '/p:EnableInf2Cat=true',
    '/p:Inf2CatUseLocalTime=true'
)

$plannedCommands = New-Object System.Collections.Generic.List[string]
if (-not $SkipFetch) {
    $plannedCommands.Add(("gh api repos/{0}/contents/{1}?ref={2} -> {3} (recursive byte-exact download, zero repo edits)" -f $Repository, $SampleSubPath, $Branch, $isolatedWorkDir))
}
if (-not $SkipBuild) {
    $vsCmdDisplay = if ([string]::IsNullOrWhiteSpace($vsDevCmdPath)) { '<VsDevCmd.bat>' } else { $vsDevCmdPath }
    $plannedCommands.Add(('cmd.exe /d /c ""{0}" -arch=amd64 -host_arch=amd64 && set _CL_=/analyze- && msbuild {1}"' -f $vsCmdDisplay, ($msbuildArgs -join ' ')))
    $infVerifDisplay = if ([string]::IsNullOrWhiteSpace($infVerifPath)) { 'InfVerif.exe' } else { $infVerifPath }
    $plannedCommands.Add(('"{0}" /v /u "<built>\\IddSampleDriver.inf"' -f $infVerifDisplay))
}

if ($DryRun) {
    foreach ($cmdText in $plannedCommands) {
        Write-Host ("[DRY-RUN] {0}" -f $cmdText) -ForegroundColor Cyan
    }

    return [pscustomobject]@{
        TimestampUtc                 = (Get-Date).ToUniversalTime().ToString('o')
        DryRun                       = $true
        InstallAttempted             = $false
        IsolatedWorkDir              = $isolatedWorkDir
        Repository                   = $Repository
        Branch                       = $Branch
        SampleSubPath                = $SampleSubPath
        Configuration                = $Configuration
        Platform                     = $Platform
        WindowsTargetPlatformVersion = $WindowsTargetPlatformVersion
        VsDevCmdPath                 = $vsDevCmdPath
        InfVerifPath                 = $infVerifPath
        SolutionPath                 = $solutionPath
        DriverProjectPath            = $driverProjectPath
        AppProjectPath               = $appProjectPath
        SkipFetch                    = [bool]$SkipFetch
        SkipBuild                    = [bool]$SkipBuild
        PlannedCommands              = @($plannedCommands)
        DownloadedFiles              = @()
        BuiltArtifacts               = $null
        InfVerifPassed               = $null
        InfVerifOutput               = @()
    }
}

$downloadedFiles = @()
if (-not $SkipFetch) {
    if ((Test-Path -LiteralPath $isolatedWorkDir) -and @((Get-ChildItem -LiteralPath $isolatedWorkDir -Force -ErrorAction SilentlyContinue)).Count -gt 0) {
        if (-not $Force) {
            throw ("Reference working directory '{0}' already exists and is not empty. Pass -Force to overwrite or -SkipFetch to reuse existing sources." -f $isolatedWorkDir)
        }
        Remove-Item -LiteralPath $isolatedWorkDir -Recurse -Force
    }

    $null = New-Item -Path $isolatedWorkDir -ItemType Directory -Force
    $downloadedFiles = @(Invoke-LumaBridgeGitHubDirectoryDownload `
        -Repository $Repository `
        -Branch $Branch `
        -RepoSubPath $SampleSubPath `
        -TargetRoot $isolatedWorkDir)

    if (-not (Test-Path -LiteralPath $solutionPath)) {
        throw ("Expected solution '{0}' was not downloaded from {1}/{2}." -f $solutionPath, $Repository, $SampleSubPath)
    }
}
elseif (-not (Test-Path -LiteralPath $solutionPath)) {
    throw ("Reference solution '{0}' does not exist and -SkipFetch was specified." -f $solutionPath)
}

$buildExitCode = $null
$buildOutput = @()
$builtArtifacts = $null
$infVerifPassed = $null
$infVerifOutput = @()

if (-not $SkipBuild) {
    if ([string]::IsNullOrWhiteSpace($vsDevCmdPath) -or -not (Test-Path -LiteralPath $vsDevCmdPath)) {
        throw 'Could not locate VsDevCmd.bat for Visual Studio BuildTools/IDE.'
    }

    $msbuildQuotedArgs = ($msbuildArgs | ForEach-Object {
        if ($_ -match '\s') { '"{0}"' -f $_ } else { $_ }
    }) -join ' '

    $batchLines = @(
        '@echo off',
        ('call "{0}" -arch=amd64 -host_arch=amd64' -f $vsDevCmdPath),
        'if errorlevel 1 exit /b %errorlevel%',
        'set _CL_=/analyze-',
        ('msbuild.exe {0}' -f $msbuildQuotedArgs),
        'exit /b %errorlevel%'
    )
    $tempCmdPath = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath ("LumaBridgeBuildRef_{0}.cmd" -f ([Guid]::NewGuid().ToString('N')))
    try {
        [System.IO.File]::WriteAllLines($tempCmdPath, $batchLines, [System.Text.Encoding]::ASCII)
        $prevEap = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        try {
            $buildOutput = @(& cmd.exe /d /c ('"{0}"' -f $tempCmdPath) 2>&1 | ForEach-Object { $_.ToString() })
            $buildExitCode = $LASTEXITCODE
        }
        finally {
            $ErrorActionPreference = $prevEap
        }
    }
    finally {
        Remove-Item -LiteralPath $tempCmdPath -Force -ErrorAction SilentlyContinue
    }

    if ($buildExitCode -ne 0) {
        $tailLines = @($buildOutput | Select-Object -Last 60) -join [Environment]::NewLine
        throw ("Isolated build of IddSampleDriver reference failed with exit code {0}. Tail output:{1}{2}" -f $buildExitCode, [Environment]::NewLine, $tailLines)
    }

    $driverDll = Get-ChildItem -Path $isolatedWorkDir -Recurse -Filter 'IddSampleDriver.dll' -File -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -like "*\$Platform\$Configuration\IddSampleDriver\IddSampleDriver.dll" } |
        Select-Object -First 1
    if ($null -eq $driverDll) {
        $driverDll = Get-ChildItem -Path $isolatedWorkDir -Recurse -Filter 'IddSampleDriver.dll' -File -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -like "*\$Platform\$Configuration\*" } |
            Select-Object -First 1
    }
    if ($null -eq $driverDll) {
        $driverDll = Get-ChildItem -Path $isolatedWorkDir -Recurse -Filter 'IddSampleDriver.dll' -File -ErrorAction SilentlyContinue |
            Select-Object -First 1
    }
    if ($null -eq $driverDll) {
        throw ("Build succeeded but IddSampleDriver.dll was not found under '{0}'." -f $isolatedWorkDir)
    }

    $driverOutDir = $driverDll.Directory.FullName
    $driverInf = Get-ChildItem -Path $driverOutDir -Filter '*.inf' -File -ErrorAction SilentlyContinue | Select-Object -First 1
    $driverPdb = Get-ChildItem -Path $driverOutDir -Filter 'IddSampleDriver.pdb' -File -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -eq $driverPdb) {
        $driverPdb = Get-ChildItem -Path $isolatedWorkDir -Recurse -Filter 'IddSampleDriver.pdb' -File -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -like "*\$Platform\$Configuration\*" } |
            Select-Object -First 1
    }
    $driverCat = Get-ChildItem -Path $driverOutDir -Filter '*.cat' -File -ErrorAction SilentlyContinue | Select-Object -First 1
    $appExe = Get-ChildItem -Path $isolatedWorkDir -Recurse -Filter 'IddSampleApp.exe' -File -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -like "*\$Platform\$Configuration\*" } |
        Select-Object -First 1
    if ($null -eq $appExe) {
        $appExe = Get-ChildItem -Path $isolatedWorkDir -Recurse -Filter 'IddSampleApp.exe' -File -ErrorAction SilentlyContinue |
            Select-Object -First 1
    }

    if ($null -ne $driverInf -and -not [string]::IsNullOrWhiteSpace($infVerifPath) -and (Test-Path -LiteralPath $infVerifPath)) {
        $prevEap = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        try {
            $infVerifOutput = @(& $infVerifPath '/v' '/u' $driverInf.FullName 2>&1 | ForEach-Object { $_.ToString() })
            $infVerifPassed = ($LASTEXITCODE -eq 0)
        }
        finally {
            $ErrorActionPreference = $prevEap
        }
    }

    $builtArtifacts = [pscustomobject]@{
        DriverOutputDir   = $driverOutDir
        DriverDllPath     = $driverDll.FullName
        DriverPdbPath     = if ($null -ne $driverPdb) { $driverPdb.FullName } else { $null }
        DriverInfPath     = if ($null -ne $driverInf) { $driverInf.FullName } else { $null }
        DriverCatalogPath = if ($null -ne $driverCat) { $driverCat.FullName } else { $null }
        SampleAppExePath  = if ($null -ne $appExe) { $appExe.FullName } else { $null }
    }
}

return [pscustomobject]@{
    TimestampUtc                 = (Get-Date).ToUniversalTime().ToString('o')
    DryRun                       = $false
    InstallAttempted             = $false
    IsolatedWorkDir              = $isolatedWorkDir
    Repository                   = $Repository
    Branch                       = $Branch
    SampleSubPath                = $SampleSubPath
    Configuration                = $Configuration
    Platform                     = $Platform
    WindowsTargetPlatformVersion = $WindowsTargetPlatformVersion
    VsDevCmdPath                 = $vsDevCmdPath
    InfVerifPath                 = $infVerifPath
    DownloadedCount              = $downloadedFiles.Count
    DownloadedFiles              = @($downloadedFiles)
    BuildExitCode                = $buildExitCode
    BuiltArtifacts               = $builtArtifacts
    InfVerifPassed               = $infVerifPassed
    InfVerifOutput               = @($infVerifOutput)
}
