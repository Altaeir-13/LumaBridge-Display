Set-StrictMode -Version Latest

$script:LumaBridgeDriverConstants = [pscustomobject]@{
    HardwareId               = 'Root\LumaBridgeIddDriver'
    DeviceDisplayName        = 'LumaBridge Indirect Display Adapter'
    DriverServiceName        = 'LumaBridgeIddDriver'
    InfFileName              = 'LumaBridgeIddDriver.inf'
    DllFileName              = 'LumaBridgeIddDriver.dll'
    CatFileName              = 'lumabridgeidddriver.cat'
    DefaultCertificateSubject = 'CN=LumaBridge Test Driver Signing'
    DefaultConfiguration     = 'Release'
    SupportedInf2CatOsList   = '10_CO_X64,10_NI_X64,10_GE_X64'
    MinimumWindows11Build    = 22000
    RegistryValueEnableMon   = 'EnableVirtualMonitor'
}

function Get-LumaBridgeDriverConstants {
    [CmdletBinding()]
    param()
    return $script:LumaBridgeDriverConstants
}

function Get-LumaBridgeRepoRoot {
    [CmdletBinding()]
    param()

    $scriptsDir = $PSScriptRoot
    $driverDir = Split-Path -Parent $scriptsDir
    $windowsDir = Split-Path -Parent $driverDir
    $repoRoot = Split-Path -Parent $windowsDir
    return (Resolve-Path -LiteralPath $repoRoot).Path
}

function Get-LumaBridgePackageDirectory {
    [CmdletBinding()]
    param(
        [ValidateSet('Debug', 'Release')]
        [string]$Configuration = 'Release'
    )

    $repoRoot = Get-LumaBridgeRepoRoot
    return Join-Path -Path $repoRoot -ChildPath ("windows\driver\x64\{0}\LumaBridgeIddDriver" -f $Configuration)
}

function Get-LumaBridgeDefaultStagingDirectory {
    [CmdletBinding()]
    param(
        [ValidateSet('Debug', 'Release')]
        [string]$Configuration = 'Release'
    )

    $localAppData = if (-not [string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) {
        $env:LOCALAPPDATA
    }
    else {
        [Environment]::GetFolderPath('LocalApplicationData')
    }

    return Join-Path -Path $localAppData -ChildPath ("LumaBridgeDisplay\Staging\{0}" -f $Configuration)
}

function Get-LumaBridgeWdkToolPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('signtool.exe', 'devcon.exe', 'Inf2Cat.exe')]
        [string]$ToolName
    )

    $kitsRoot = Join-Path -Path ${env:ProgramFiles(x86)} -ChildPath 'Windows Kits\10'
    if (-not (Test-Path -LiteralPath $kitsRoot)) {
        return $null
    }

    $preferredPaths = switch ($ToolName) {
        'signtool.exe' {
            @(
                (Join-Path -Path $kitsRoot -ChildPath 'bin\10.0.28000.0\x64\signtool.exe'),
                (Join-Path -Path $kitsRoot -ChildPath 'App Certification Kit\signtool.exe')
            )
        }
        'devcon.exe' {
            @(
                (Join-Path -Path $kitsRoot -ChildPath 'Tools\10.0.28000.0\x64\devcon.exe')
            )
        }
        'Inf2Cat.exe' {
            @(
                (Join-Path -Path $kitsRoot -ChildPath 'bin\10.0.28000.0\x86\Inf2Cat.exe'),
                (Join-Path -Path $kitsRoot -ChildPath 'bin\10.0.28000.0\x64\Inf2Cat.exe')
            )
        }
    }

    foreach ($candidate in $preferredPaths) {
        if (Test-Path -LiteralPath $candidate) {
            return $candidate
        }
    }

    $searchRoot = if ($ToolName -eq 'devcon.exe') {
        Join-Path -Path $kitsRoot -ChildPath 'Tools'
    }
    else {
        Join-Path -Path $kitsRoot -ChildPath 'bin'
    }

    if (-not (Test-Path -LiteralPath $searchRoot)) {
        return $null
    }

    $archPattern = if ($ToolName -eq 'Inf2Cat.exe') { '\\(x64|x86)\\' } else { '\\x64\\' }
    $discovered = Get-ChildItem -Path $searchRoot -Recurse -Filter $ToolName -File -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -match $archPattern } |
        Sort-Object -Property FullName -Descending |
        Select-Object -First 1

    if ($null -ne $discovered) {
        return $discovered.FullName
    }

    return $null
}

function Test-LumaBridgeIsAdministrator {
    [CmdletBinding()]
    param()

    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Assert-LumaBridgeAdministrator {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$OperationName,

        [switch]$DryRun
    )

    $isAdmin = Test-LumaBridgeIsAdministrator
    if ($isAdmin) {
        return $true
    }

    if ($DryRun) {
        Write-Warning ("[DRY-RUN] Current session is not elevated. Live execution of '{0}' requires an Administrator PowerShell session." -f $OperationName)
        return $false
    }

    throw ("Operation '{0}' requires Administrator privileges. Re-run in an elevated PowerShell session." -f $OperationName)
}

function Confirm-LumaBridgeAction {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$PromptMessage,

        [switch]$DryRun,
        [switch]$Force
    )

    if ($DryRun) {
        Write-Host ("[DRY-RUN] {0}" -f $PromptMessage) -ForegroundColor Cyan
        return $false
    }

    if ($Force) {
        return $true
    }

    if (-not [Environment]::UserInteractive) {
        throw "Interactive confirmation is unavailable in non-interactive mode. Pass -Force to confirm or -DryRun to preview."
    }

    $answer = Read-Host -Prompt ("{0} [y/N]" -f $PromptMessage)
    if ($answer -match '^(y|yes|s|sim)$') {
        return $true
    }

    Write-Host 'Operation cancelled by user.' -ForegroundColor Yellow
    return $false
}

function Invoke-LumaBridgeExternalCommand {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,

        [string[]]$Arguments = @(),

        [switch]$DryRun
    )

    $formattedArgs = ($Arguments | ForEach-Object {
        if ($_ -match '\s') { '"{0}"' -f $_ } else { $_ }
    }) -join ' '

    if ($DryRun) {
        Write-Host ("[DRY-RUN] Would execute: {0} {1}" -f $FilePath, $formattedArgs) -ForegroundColor Cyan
        return [pscustomobject]@{
            ExitCode = 0
            Output   = @()
            DryRun   = $true
        }
    }

    $outputLines = & $FilePath @Arguments 2>&1
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0) {
        $detail = ($outputLines | ForEach-Object { $_.ToString() }) -join [Environment]::NewLine
        throw ("Command '{0} {1}' failed with exit code {2}. Output:{3}{4}" -f $FilePath, $formattedArgs, $exitCode, [Environment]::NewLine, $detail)
    }

    return [pscustomobject]@{
        ExitCode = $exitCode
        Output   = @($outputLines | ForEach-Object { $_.ToString() })
        DryRun   = $false
    }
}

function Get-LumaBridgePnpInstances {
    [CmdletBinding()]
    param(
        [string]$HardwareId = $script:LumaBridgeDriverConstants.HardwareId
    )

    $results = New-Object System.Collections.Generic.List[object]
    $seenIds = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)

    if (Get-Command -Name 'Get-PnpDevice' -ErrorAction SilentlyContinue) {
        $devices = Get-PnpDevice -ErrorAction SilentlyContinue | Where-Object {
            ($_.HardwareID -contains $HardwareId) -or
            ($_.InstanceId -like 'ROOT\DISPLAY\*' -and $_.FriendlyName -like '*LumaBridge*') -or
            ($_.FriendlyName -eq $script:LumaBridgeDriverConstants.DeviceDisplayName)
        }

        foreach ($dev in $devices) {
            if ($seenIds.Add($dev.InstanceId)) {
                $probCode = $null
                $prop = Get-PnpDeviceProperty -InstanceId $dev.InstanceId -KeyName 'DEVPKEY_Device_ProblemCode' -ErrorAction SilentlyContinue
                if ($null -ne $prop) {
                    $probCode = $prop.Data
                }

                $regParamsPath = "HKLM:\SYSTEM\CurrentControlSet\Enum\{0}\Device Parameters" -f $dev.InstanceId
                $enableVal = $null
                if (Test-Path -LiteralPath $regParamsPath) {
                    $regProps = Get-ItemProperty -LiteralPath $regParamsPath -Name $script:LumaBridgeDriverConstants.RegistryValueEnableMon -ErrorAction SilentlyContinue
                    if ($null -ne $regProps) {
                        $enableVal = $regProps.($script:LumaBridgeDriverConstants.RegistryValueEnableMon)
                    }
                }

                $results.Add([pscustomobject]@{
                    InstanceId           = $dev.InstanceId
                    FriendlyName         = $dev.FriendlyName
                    Status               = $dev.Status
                    ProblemCode          = $probCode
                    Present              = [bool]$dev.Present
                    HardwareIds          = @($dev.HardwareID)
                    DeviceParametersPath = $regParamsPath
                    EnableVirtualMonitor = $enableVal
                })
            }
        }
    }
    elseif (Get-Command -Name 'Get-CimInstance' -ErrorAction SilentlyContinue) {
        $entities = Get-CimInstance -ClassName Win32_PnPEntity -ErrorAction SilentlyContinue | Where-Object {
            ($_.HardwareID -contains $HardwareId) -or
            ($_.Name -eq $script:LumaBridgeDriverConstants.DeviceDisplayName)
        }

        foreach ($ent in $entities) {
            if ($seenIds.Add($ent.PNPDeviceID)) {
                $regParamsPath = "HKLM:\SYSTEM\CurrentControlSet\Enum\{0}\Device Parameters" -f $ent.PNPDeviceID
                $enableVal = $null
                if (Test-Path -LiteralPath $regParamsPath) {
                    $regProps = Get-ItemProperty -LiteralPath $regParamsPath -Name $script:LumaBridgeDriverConstants.RegistryValueEnableMon -ErrorAction SilentlyContinue
                    if ($null -ne $regProps) {
                        $enableVal = $regProps.($script:LumaBridgeDriverConstants.RegistryValueEnableMon)
                    }
                }

                $results.Add([pscustomobject]@{
                    InstanceId           = $ent.PNPDeviceID
                    FriendlyName         = $ent.Name
                    Status               = $ent.Status
                    ProblemCode          = $ent.ConfigManagerErrorCode
                    Present              = ($ent.ConfigManagerErrorCode -eq 0)
                    HardwareIds          = @($ent.HardwareID)
                    DeviceParametersPath = $regParamsPath
                    EnableVirtualMonitor = $enableVal
                })
            }
        }
    }

    return @($results.ToArray())
}

function Get-LumaBridgeDriverStorePackages {
    [CmdletBinding()]
    param(
        [string]$InfFilter = $script:LumaBridgeDriverConstants.InfFileName
    )

    $pnputilLines = & pnputil.exe /enum-drivers 2>&1
    if ($LASTEXITCODE -ne 0) {
        return @()
    }

    $entries = New-Object System.Collections.Generic.List[object]
    $current = $null

    foreach ($rawLine in $pnputilLines) {
        $line = $rawLine.ToString().Trim()
        if ([string]::IsNullOrWhiteSpace($line)) {
            if ($null -ne $current) {
                $entries.Add([pscustomobject]$current)
                $current = $null
            }
            continue
        }

        if ($line -match '^(?<Key>[^:]+):\s*(?<Value>.*)$') {
            $key = $matches['Key'].Trim()
            $value = $matches['Value'].Trim()
            if ($key -match 'Published Name|Nome Publicado') {
                if ($null -ne $current) {
                    $entries.Add([pscustomobject]$current)
                }
                $current = [ordered]@{
                    PublishedName = $value
                    OriginalName  = ''
                    ProviderName  = ''
                    ClassName     = ''
                    DriverVersion = ''
                    SignerName    = ''
                }
            }
            elseif ($null -ne $current) {
                if ($key -match 'Original Name|Nome Original') {
                    $current['OriginalName'] = $value
                }
                elseif ($key -match 'Provider Name|Nome do Provedor') {
                    $current['ProviderName'] = $value
                }
                elseif ($key -match 'Class Name|Nome da Classe') {
                    $current['ClassName'] = $value
                }
                elseif ($key -match 'Driver Version|Vers.*Driver') {
                    $current['DriverVersion'] = $value
                }
                elseif ($key -match 'Signer Name|Nome do Signat') {
                    $current['SignerName'] = $value
                }
            }
        }
    }

    if ($null -ne $current) {
        $entries.Add([pscustomobject]$current)
    }

    return @($entries | Where-Object {
        $_.OriginalName -ieq $InfFilter -or $_.ProviderName -eq 'LumaBridge'
    })
}

function Test-LumaBridgePackageArtifacts {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$PackageDirectory,

        [switch]$RequireValidSignature
    )

    $constants = $script:LumaBridgeDriverConstants
    $infPath = Join-Path -Path $PackageDirectory -ChildPath $constants.InfFileName
    $dllPath = Join-Path -Path $PackageDirectory -ChildPath $constants.DllFileName
    $catPath = Join-Path -Path $PackageDirectory -ChildPath $constants.CatFileName

    $infExists = Test-Path -LiteralPath $infPath -PathType Leaf
    $dllExists = Test-Path -LiteralPath $dllPath -PathType Leaf
    $catExists = Test-Path -LiteralPath $catPath -PathType Leaf

    $dllSig = if ($dllExists) { Get-AuthenticodeSignature -LiteralPath $dllPath } else { $null }
    $catSig = if ($catExists) { Get-AuthenticodeSignature -LiteralPath $catPath } else { $null }

    $dllSignedValid = ($null -ne $dllSig -and $dllSig.Status -eq 'Valid')
    $catSignedValid = ($null -ne $catSig -and $catSig.Status -eq 'Valid')

    $signtool = Get-LumaBridgeWdkToolPath -ToolName 'signtool.exe'
    $catalogMemberVerified = $false
    $catalogVerifyOutput = ''

    if ($dllExists -and $catExists -and ($null -ne $signtool) -and ($null -ne $catSig) -and ($catSig.Status -ne 'NotSigned')) {
        $verifyOut = & $signtool verify /pa /c $catPath $dllPath 2>&1
        $catalogVerifyOutput = ($verifyOut | ForEach-Object { $_.ToString() }) -join [Environment]::NewLine
        $catalogMemberVerified = ($LASTEXITCODE -eq 0)
    }

    $result = [pscustomobject]@{
        PackageDirectory       = $PackageDirectory
        AllFilesPresent        = ($infExists -and $dllExists -and $catExists)
        InfPath                = $infPath
        InfPresent             = $infExists
        InfSha256              = if ($infExists) { (Get-FileHash -LiteralPath $infPath -Algorithm SHA256).Hash } else { $null }
        DllPath                = $dllPath
        DllPresent             = $dllExists
        DllSha256              = if ($dllExists) { (Get-FileHash -LiteralPath $dllPath -Algorithm SHA256).Hash } else { $null }
        DllSignatureStatus     = if ($null -ne $dllSig) { $dllSig.Status.ToString() } else { 'Missing' }
        DllSignerThumbprint    = if ($null -ne $dllSig -and $null -ne $dllSig.SignerCertificate) { $dllSig.SignerCertificate.Thumbprint } else { $null }
        CatPath                = $catPath
        CatPresent             = $catExists
        CatSha256              = if ($catExists) { (Get-FileHash -LiteralPath $catPath -Algorithm SHA256).Hash } else { $null }
        CatSignatureStatus     = if ($null -ne $catSig) { $catSig.Status.ToString() } else { 'Missing' }
        CatSignerThumbprint    = if ($null -ne $catSig -and $null -ne $catSig.SignerCertificate) { $catSig.SignerCertificate.Thumbprint } else { $null }
        CatalogMemberVerified  = $catalogMemberVerified
        CatalogVerifyDetail    = $catalogVerifyOutput
        IsCryptographicallyValid = ($infExists -and $dllExists -and $catExists -and $dllSignedValid -and $catSignedValid -and $catalogMemberVerified)
    }

    if ($RequireValidSignature -and -not $result.IsCryptographicallyValid) {
        throw ("Cryptographic verification failed for '{0}'. AllFilesPresent={1}, DllSig={2}, CatSig={3}, CatalogMemberVerified={4}. Run Invoke-LumaBridgePackageSigning.ps1 first and ensure the signing certificate is trusted." -f `
            $PackageDirectory, $result.AllFilesPresent, $result.DllSignatureStatus, $result.CatSignatureStatus, $result.CatalogMemberVerified)
    }

    return $result
}

Export-ModuleMember -Function @(
    'Get-LumaBridgeDriverConstants',
    'Get-LumaBridgeRepoRoot',
    'Get-LumaBridgePackageDirectory',
    'Get-LumaBridgeDefaultStagingDirectory',
    'Get-LumaBridgeWdkToolPath',
    'Test-LumaBridgeIsAdministrator',
    'Assert-LumaBridgeAdministrator',
    'Confirm-LumaBridgeAction',
    'Invoke-LumaBridgeExternalCommand',
    'Get-LumaBridgePnpInstances',
    'Get-LumaBridgeDriverStorePackages',
    'Test-LumaBridgePackageArtifacts'
)
