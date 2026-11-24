# SPDX-License-Identifier: Apache-2.0
<#
.SYNOPSIS
    Non-administrative CI qualification script for LumaBridge Display M1.1 (Rust <-> C++ MSVC FFI PoC).
.DESCRIPTION
    Verifies Rust formatting, cbindgen header synchronization, clippy (-D warnings),
    Rust unit tests across feature configurations, MSVC x64 Debug (/MDd) and Release (/MD)
    C11/C++20 native harnesses, isolated opt-in linkage into lumabridge-host.exe,
    standard host build isolation, dumpbin export/import hygiene, and an informative
    release FFI boundary benchmark run.
#>
[CmdletBinding()]
param(
    [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path,
    [string]$SummaryPath = '',
    [string]$JsonReportPath = '',
    [string]$BuildRoot = '',
    [switch]$SkipBenchmark,
    [switch]$InstallMissingTools,
    [switch]$RequireCargoDeny
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Scrub-SensitivePaths {
    param([AllowEmptyString()][string]$Text)
    if ([string]::IsNullOrEmpty($Text)) {
        return ''
    }
    $scrubbed = $Text -replace '(?i)[A-Za-z]:\\Users\\[^\\\s"'']+', '<USERPROFILE>'
    return $scrubbed
}

function Invoke-NativeChecked {
    param(
        [Parameter(Mandatory = $true)][string]$Label,
        [Parameter(Mandatory = $true)][string]$Executable,
        [string[]]$Arguments = @(),
        [string]$WorkingDirectory = $PWD.Path
    )
    Write-Host ("=== {0} ===" -f $Label)
    Push-Location -LiteralPath $WorkingDirectory
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $output = & $Executable @Arguments 2>&1
        $rc = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $prev
        Pop-Location
    }
    foreach ($line in @($output)) {
        Write-Host (Scrub-SensitivePaths ([string]$line))
    }
    if ($rc -ne 0) {
        throw ("Step '{0}' failed with exit code {1}." -f $Label, $rc)
    }
    return ,$output
}

function Initialize-MsvcX64Environment {
    if ((Get-Command 'cl.exe' -ErrorAction SilentlyContinue) -and
        (-not [string]::IsNullOrWhiteSpace($env:VCToolsVersion))) {
        return ("VCTools={0}" -f $env:VCToolsVersion)
    }

    $vswhereCandidates = @(
        @(
            (Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'),
            (Join-Path $env:ProgramFiles 'Microsoft Visual Studio\Installer\vswhere.exe')
        ) | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf }
    )

    if ($vswhereCandidates.Count -eq 0) {
        throw 'vswhere.exe not found; MSVC x64 Build Tools are required.'
    }

    $installPath = & $vswhereCandidates[0] -latest -products * `
        -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
        -property installationPath | Select-Object -First 1

    if ([string]::IsNullOrWhiteSpace($installPath)) {
        throw 'No Visual Studio installation with VC x64 tools was found.'
    }

    $vsDevCmd = Join-Path $installPath 'Common7\Tools\VsDevCmd.bat'
    if (-not (Test-Path -LiteralPath $vsDevCmd -PathType Leaf)) {
        throw ("VsDevCmd.bat not found under '{0}'." -f $installPath)
    }

    $envLines = cmd.exe /c "`"$vsDevCmd`" -arch=amd64 -host_arch=amd64 >nul && set"
    if ($LASTEXITCODE -ne 0) {
        throw ("VsDevCmd.bat failed with exit code {0}." -f $LASTEXITCODE)
    }
    foreach ($line in $envLines) {
        if ($line -match '^([^=]+)=(.*)$') {
            [System.Environment]::SetEnvironmentVariable($matches[1], $matches[2], 'Process')
        }
    }
    return ("VCTools={0}" -f $env:VCToolsVersion)
}

function Ensure-CargoTools {
    $cargoBin = Join-Path $env:USERPROFILE '.cargo\bin'
    if (Test-Path -LiteralPath $cargoBin -PathType Container) {
        if (-not ($env:PATH.Split(';') -contains $cargoBin)) {
            $env:PATH = "$cargoBin;$env:PATH"
        }
    }
    if (-not (Get-Command 'cargo.exe' -ErrorAction SilentlyContinue)) {
        throw 'cargo.exe not found on PATH or in user cargo bin.'
    }
}

$resolvedRoot = (Resolve-Path -LiteralPath $RepoRoot).Path
$coreDir = Join-Path $resolvedRoot 'core'
if ([string]::IsNullOrWhiteSpace($BuildRoot)) {
    $BuildRoot = Join-Path $env:TEMP ('lumabridge-ffi-poc-ci-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
}
$ownBuildRoot = -not (Test-Path -LiteralPath $BuildRoot)
New-Item -Path $BuildRoot -ItemType Directory -Force | Out-Null

$report = [ordered]@{
    msvc_toolchain       = ''
    windows_sdk_version  = ''
    rustc_version        = ''
    cbindgen_checked     = $false
    cargo_deny_checked   = $false
    rust_checks_passed   = $false
    debug_harness_passed = $false
    release_harness_passed = $false
    host_poc_debug_passed  = $false
    host_poc_release_passed = $false
    std_host_isolated    = $false
    benchmark_executed   = $false
    benchmark_mode       = ''
    benchmark_p99_us     = $null
}

try {
    Ensure-CargoTools
    $report.msvc_toolchain = Initialize-MsvcX64Environment
    $report.windows_sdk_version = ($env:WindowsSDKVersion -replace '\\$', '')

    $rustcVer = (& rustc --version)
    $report.rustc_version = [string]$rustcVer
    Write-Host ("[INFO] Rustc: {0} | {1} | WindowsSDK={2}" -f $report.rustc_version, $report.msvc_toolchain, $report.windows_sdk_version)

    if ($InstallMissingTools) {
        if (-not (Get-Command 'cbindgen.exe' -ErrorAction SilentlyContinue)) {
            Invoke-NativeChecked -Label 'INSTALL CBINDGEN' -Executable 'cargo' -Arguments @('install', 'cbindgen', '--version', '0.29.4', '--locked') -WorkingDirectory $coreDir | Out-Null
        }
        if (-not (Get-Command 'cargo-deny.exe' -ErrorAction SilentlyContinue)) {
            Invoke-NativeChecked -Label 'INSTALL CARGO-DENY' -Executable 'cargo' -Arguments @('install', 'cargo-deny', '--version', '0.22.1', '--locked') -WorkingDirectory $coreDir | Out-Null
        }
    }

    Invoke-NativeChecked -Label 'RUSTFMT CHECK' -Executable 'cargo' -Arguments @('fmt', '--all', '--check') -WorkingDirectory $coreDir | Out-Null

    if (Get-Command 'cbindgen.exe' -ErrorAction SilentlyContinue) {
        $genHeader = Join-Path $BuildRoot 'lumabridge_ffi.generated.h'
        Invoke-NativeChecked -Label 'CBINDGEN DRIFT CHECK' -Executable 'cbindgen' -Arguments @(
            '--config', 'crates/lumabridge-ffi/cbindgen.toml',
            '--crate', 'lumabridge-ffi',
            '--output', $genHeader
        ) -WorkingDirectory $coreDir | Out-Null
        $committedHeader = Join-Path $coreDir 'crates\lumabridge-ffi\include\lumabridge_ffi.h'
        $expectedNorm = ([System.IO.File]::ReadAllText($committedHeader) -replace "`r`n", "`n").TrimEnd()
        $actualNorm = ([System.IO.File]::ReadAllText($genHeader) -replace "`r`n", "`n").TrimEnd()
        if ($expectedNorm -ne $actualNorm) {
            throw 'Generated cbindgen header drifted from committed core/crates/lumabridge-ffi/include/lumabridge_ffi.h.'
        }
        $report.cbindgen_checked = $true
        Write-Host '[PASS] cbindgen C ABI header matches committed header exactly.' -ForegroundColor Green
    }

    Invoke-NativeChecked -Label 'CLIPPY DEFAULT' -Executable 'cargo' -Arguments @('clippy', '--workspace', '--all-targets', '--', '-D', 'warnings') -WorkingDirectory $coreDir | Out-Null
    Invoke-NativeChecked -Label 'CLIPPY FAULT-INJECTION' -Executable 'cargo' -Arguments @('clippy', '--workspace', '--all-targets', '--features', 'poc-fault-injection', '--', '-D', 'warnings') -WorkingDirectory $coreDir | Out-Null
    Invoke-NativeChecked -Label 'CLIPPY UNIFFI' -Executable 'cargo' -Arguments @('clippy', '--workspace', '--all-targets', '--features', 'uniffi', '--', '-D', 'warnings') -WorkingDirectory $coreDir | Out-Null

    Invoke-NativeChecked -Label 'RUST TEST DEFAULT' -Executable 'cargo' -Arguments @('test', '--workspace') -WorkingDirectory $coreDir | Out-Null
    Invoke-NativeChecked -Label 'RUST TEST FAULT-INJECTION' -Executable 'cargo' -Arguments @('test', '--workspace', '--features', 'poc-fault-injection') -WorkingDirectory $coreDir | Out-Null
    Invoke-NativeChecked -Label 'RUST TEST UNIFFI' -Executable 'cargo' -Arguments @('test', '--workspace', '--features', 'uniffi') -WorkingDirectory $coreDir | Out-Null
    $report.rust_checks_passed = $true

    if (Get-Command 'cargo-deny.exe' -ErrorAction SilentlyContinue) {
        Invoke-NativeChecked -Label 'CARGO DENY CHECK' -Executable 'cargo' -Arguments @('deny', 'check', 'licenses', 'bans', 'sources') -WorkingDirectory $coreDir | Out-Null
        $report.cargo_deny_checked = $true
    }
    elseif ($RequireCargoDeny) {
        throw 'cargo-deny was requested via -RequireCargoDeny but was not found on PATH.'
    }

    $dbgDir = Join-Path $BuildRoot 'debug'
    $relDir = Join-Path $BuildRoot 'release'
    $stdDir = Join-Path $BuildRoot 'std-host'
    New-Item -Path $dbgDir, $relDir, $stdDir -ItemType Directory -Force | Out-Null

    # Build fault-injection DLLs first into dedicated filenames
    Invoke-NativeChecked -Label 'CARGO BUILD FAULT DEBUG' -Executable 'cargo' -Arguments @('build', '-p', 'lumabridge-ffi', '--features', 'poc-fault-injection') -WorkingDirectory $coreDir | Out-Null
    Copy-Item -LiteralPath (Join-Path $coreDir 'target\debug\lumabridge_ffi.dll') -Destination (Join-Path $dbgDir 'lumabridge_ffi_poc_fault.dll') -Force

    Invoke-NativeChecked -Label 'CARGO BUILD FAULT RELEASE' -Executable 'cargo' -Arguments @('build', '-p', 'lumabridge-ffi', '--features', 'poc-fault-injection', '--release') -WorkingDirectory $coreDir | Out-Null
    Copy-Item -LiteralPath (Join-Path $coreDir 'target\release\lumabridge_ffi.dll') -Destination (Join-Path $relDir 'lumabridge_ffi_poc_fault.dll') -Force

    # Build clean default production DLLs
    Invoke-NativeChecked -Label 'CARGO BUILD PROD DEBUG' -Executable 'cargo' -Arguments @('build', '-p', 'lumabridge-ffi') -WorkingDirectory $coreDir | Out-Null
    Copy-Item -LiteralPath (Join-Path $coreDir 'target\debug\lumabridge_ffi.dll') -Destination (Join-Path $dbgDir 'lumabridge_ffi.dll') -Force
    Copy-Item -LiteralPath (Join-Path $coreDir 'target\debug\lumabridge_ffi.dll.lib') -Destination (Join-Path $dbgDir 'lumabridge_ffi.dll.lib') -Force

    Invoke-NativeChecked -Label 'CARGO BUILD PROD RELEASE' -Executable 'cargo' -Arguments @('build', '-p', 'lumabridge-ffi', '--release') -WorkingDirectory $coreDir | Out-Null
    Copy-Item -LiteralPath (Join-Path $coreDir 'target\release\lumabridge_ffi.dll') -Destination (Join-Path $relDir 'lumabridge_ffi.dll') -Force
    Copy-Item -LiteralPath (Join-Path $coreDir 'target\release\lumabridge_ffi.dll.lib') -Destination (Join-Path $relDir 'lumabridge_ffi.dll.lib') -Force

    $incFfi = 'core\crates\lumabridge-ffi\include'
    $cCompat = 'core\tests\native_cpp\LumaBridgeFfiCCompat.c'
    $cppHarness = 'core\tests\native_cpp\LumaBridgeFfiHarness.cpp'

    foreach ($mode in @('debug', 'release')) {
        $outDir = if ($mode -eq 'debug') { $dbgDir } else { $relDir }
        $crtFlag = if ($mode -eq 'debug') { '/MDd' } else { '/MD' }
        $optFlags = if ($mode -eq 'debug') { @('/Od', '/D_DEBUG', '/Zi') } else { @('/O2', '/DNDEBUG') }
        $dllLib = Join-Path $outDir 'lumabridge_ffi.dll.lib'
        $faultDll = Join-Path $outDir 'lumabridge_ffi_poc_fault.dll'
        $prodDll = Join-Path $outDir 'lumabridge_ffi.dll'

        $cObj = Join-Path $outDir 'LumaBridgeFfiCCompat.obj'
        Invoke-NativeChecked -Label ("CL C11 ({0})" -f $mode) -Executable 'cl.exe' -Arguments (@(
            '/nologo', '/std:c11', '/W4', '/WX', $crtFlag) + $optFlags + @(
            ("/I{0}" -f $incFfi), '/c', $cCompat, ("/Fo{0}" -f $cObj), ("/Fd{0}\" -f $outDir)
        )) -WorkingDirectory $resolvedRoot | Out-Null

        $harnessExe = Join-Path $outDir 'LumaBridgeFfiHarness.exe'
        Invoke-NativeChecked -Label ("CL C++20 HARNESS ({0})" -f $mode) -Executable 'cl.exe' -Arguments (@(
            '/nologo', '/std:c++20', '/W4', '/WX', '/EHsc', $crtFlag) + $optFlags + @(
            ("/I{0}" -f $incFfi), $cppHarness, $cObj,
            ("/Fo{0}\" -f $outDir), ("/Fd{0}\" -f $outDir), ("/Fe:{0}" -f $harnessExe),
            '/link', $dllLib, 'psapi.lib'
        )) -WorkingDirectory $resolvedRoot | Out-Null

        Invoke-NativeChecked -Label ("RUN HARNESS ({0})" -f $mode) -Executable $harnessExe -Arguments @('--fault-dll', $faultDll) -WorkingDirectory $outDir | Out-Null

        $hostPocExe = Join-Path $outDir 'lumabridge-host-ffi-poc.exe'
        Invoke-NativeChecked -Label ("CL HOST FFI POC ({0})" -f $mode) -Executable 'cl.exe' -Arguments (@(
            '/nologo', '/std:c++20', '/W4', '/WX', '/EHsc', $crtFlag) + $optFlags + @(
            '/DUNICODE', '/D_UNICODE', '/DLUMABRIDGE_ENABLE_FFI_POC',
            '/Iwindows\driver\LumaBridgeIddDriver', '/Iwindows\host', ("/I{0}" -f $incFfi),
            'windows\host\main.cpp', 'windows\host\FrameConsumer.cpp',
            'windows\host\NvencH264Encoder.cpp', 'windows\host\H264BitstreamValidator.cpp',
            'windows\host\FfiPocAdapter.cpp',
            ("/Fo{0}\" -f $outDir), ("/Fd{0}\" -f $outDir), ("/Fe:{0}" -f $hostPocExe),
            '/link', $dllLib, 'd3d11.lib', 'dxgi.lib', 'advapi32.lib', 'user32.lib', 'gdi32.lib',
            'mfplat.lib', 'mfuuid.lib', 'wmcodecdspuuid.lib', 'ole32.lib', 'psapi.lib'
        )) -WorkingDirectory $resolvedRoot | Out-Null

        Invoke-NativeChecked -Label ("RUN HOST SELFTEST ({0})" -f $mode) -Executable $hostPocExe -Arguments @('--ffi-poc-selftest') -WorkingDirectory $outDir | Out-Null

        $prodExports = Invoke-NativeChecked -Label ("DUMPBIN PROD EXPORTS ({0})" -f $mode) -Executable 'dumpbin.exe' -Arguments @('/NOLOGO', '/EXPORTS', $prodDll) -WorkingDirectory $outDir
        if (@($prodExports | Select-String -SimpleMatch 'lb_core_poc_trigger_panic').Count -ne 0) {
            throw ("Production DLL '{0}' unexpectedly exported lb_core_poc_trigger_panic." -f $mode)
        }

        $hostDeps = Invoke-NativeChecked -Label ("DUMPBIN HOST DEPENDENTS ({0})" -f $mode) -Executable 'dumpbin.exe' -Arguments @('/NOLOGO', '/DEPENDENTS', $hostPocExe) -WorkingDirectory $outDir
        if (@($hostDeps | Select-String -SimpleMatch 'lumabridge_ffi.dll').Count -eq 0) {
            throw ("Host FFI PoC binary ({0}) did not declare dependency on lumabridge_ffi.dll." -f $mode)
        }

        if ($mode -eq 'debug') {
            $report.debug_harness_passed = $true
            $report.host_poc_debug_passed = $true
        }
        else {
            $report.release_harness_passed = $true
            $report.host_poc_release_passed = $true
        }
    }

    # Standard host build WITHOUT LUMABRIDGE_ENABLE_FFI_POC must remain isolated from lumabridge_ffi.dll
    $stdHostExe = Join-Path $stdDir 'lumabridge-host.exe'
    Invoke-NativeChecked -Label 'CL STANDARD HOST (ISOLATED)' -Executable 'cl.exe' -Arguments @(
        '/nologo', '/std:c++20', '/W4', '/WX', '/EHsc', '/O2', '/MD', '/DNDEBUG',
        '/DUNICODE', '/D_UNICODE', '/Iwindows\driver\LumaBridgeIddDriver', '/Iwindows\host',
        'windows\host\main.cpp', 'windows\host\FrameConsumer.cpp',
        'windows\host\NvencH264Encoder.cpp', 'windows\host\H264BitstreamValidator.cpp',
        ("/Fo{0}\" -f $stdDir), ("/Fd{0}\" -f $stdDir), ("/Fe:{0}" -f $stdHostExe),
        '/link', 'd3d11.lib', 'dxgi.lib', 'advapi32.lib', 'user32.lib', 'gdi32.lib',
        'mfplat.lib', 'mfuuid.lib', 'wmcodecdspuuid.lib', 'ole32.lib', 'psapi.lib'
    ) -WorkingDirectory $resolvedRoot | Out-Null

    $stdDeps = Invoke-NativeChecked -Label 'DUMPBIN STANDARD HOST DEPENDENTS' -Executable 'dumpbin.exe' -Arguments @('/NOLOGO', '/DEPENDENTS', $stdHostExe) -WorkingDirectory $stdDir
    if (@($stdDeps | Select-String -SimpleMatch 'lumabridge_ffi.dll').Count -ne 0) {
        throw 'Standard lumabridge-host.exe unexpectedly depends on lumabridge_ffi.dll.'
    }
    $report.std_host_isolated = $true

    if (-not $SkipBenchmark) {
        $benchExe = Join-Path $relDir 'LumaBridgeFfiBenchmark.exe'
        $benchJson = Join-Path $relDir 'ci-bench-informative.json'
        Invoke-NativeChecked -Label 'CL FFI BENCHMARK RELEASE' -Executable 'cl.exe' -Arguments @(
            '/nologo', '/std:c++20', '/W4', '/WX', '/EHsc', '/O2', '/MD', '/DNDEBUG',
            ("/I{0}" -f $incFfi), 'core\tests\native_cpp\LumaBridgeFfiBenchmark.cpp',
            ("/Fo{0}\" -f $relDir), ("/Fd{0}\" -f $relDir), ("/Fe:{0}" -f $benchExe),
            '/link', (Join-Path $relDir 'lumabridge_ffi.dll.lib')
        ) -WorkingDirectory $resolvedRoot | Out-Null

        Invoke-NativeChecked -Label 'RUN FFI BENCHMARK (CI INFORMATIVE)' -Executable $benchExe -Arguments @('--ci-informative', '--json', $benchJson) -WorkingDirectory $relDir | Out-Null
        if (Test-Path -LiteralPath $benchJson -PathType Leaf) {
            $bData = Get-Content -LiteralPath $benchJson -Raw | ConvertFrom-Json
            $report.benchmark_executed = $true
            $report.benchmark_mode = [string]$bData.mode
            $report.benchmark_p99_us = [double]$bData.stats.ffi_borrowed_submit.p99_us
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($JsonReportPath)) {
        $jsonDir = Split-Path -Parent $JsonReportPath
        if ($jsonDir) { New-Item -Path $jsonDir -ItemType Directory -Force | Out-Null }
        ($report | ConvertTo-Json -Depth 4) | Set-Content -LiteralPath $JsonReportPath -Encoding UTF8
    }

    if (-not [string]::IsNullOrWhiteSpace($SummaryPath)) {
        $lines = @(
            '## M1.1 FFI & MSVC Interoperability CI Summary',
            '',
            "- Toolchain: ``$($report.rustc_version)`` + ``$($report.msvc_toolchain)`` (SDK ``$($report.windows_sdk_version)``)",
            "- Rust checks (fmt/clippy/test default+fault+uniffi): ``$($report.rust_checks_passed)`` (cbindgen drift check: ``$($report.cbindgen_checked)``, cargo-deny: ``$($report.cargo_deny_checked)``)",
            "- Debug (/MDd) & Release (/MD) C11/C++20 Harness (120 cycles + panic containment): ``Debug=$($report.debug_harness_passed)``, ``Release=$($report.release_harness_passed)``",
            "- Host ``lumabridge-host.exe --ffi-poc-selftest``: ``Debug=$($report.host_poc_debug_passed)``, ``Release=$($report.host_poc_release_passed)`` | Standard host isolated: ``$($report.std_host_isolated)``",
            "- Benchmark (CI informative non-gating): ``executed=$($report.benchmark_executed)`` (``mode=$($report.benchmark_mode)``, ``ffi_borrowed_p99_us=$($report.benchmark_p99_us)``)"
        )
        Add-Content -LiteralPath $SummaryPath -Value ($lines -join "`n") -Encoding UTF8
    }

    Write-Host '[PASS] Invoke-LumaBridgeFfiPocCi completed cleanly.' -ForegroundColor Green
}
finally {
    if ($ownBuildRoot -and (Test-Path -LiteralPath $BuildRoot)) {
        Remove-Item -LiteralPath $BuildRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}
