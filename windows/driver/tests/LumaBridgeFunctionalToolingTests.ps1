Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$testsDir = $PSScriptRoot
$driverDir = Split-Path -Parent $testsDir
$scriptsDir = Join-Path -Path $driverDir -ChildPath 'scripts'
$commonModulePath = (Resolve-Path -LiteralPath (Join-Path -Path $scriptsDir -ChildPath 'LumaBridgeDriverCommon.psm1')).Path

Import-Module $commonModulePath -Force

$script:TestsRun = 0
$script:TestsFailed = 0
$script:TestTempRoot = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath ("LumaBridgeToolingTests_{0}" -f ([guid]::NewGuid().ToString('N')))
New-Item -Path $script:TestTempRoot -ItemType Directory -Force | Out-Null

$global:LbTestState = @{}

function Assert-True {
    param(
        [Parameter(Mandatory = $true)]
        [bool]$Condition,

        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    if (-not $Condition) {
        throw ("Assertion failed: {0}" -f $Message)
    }
}

function Assert-Equal {
    param(
        $Actual,
        $Expected,
        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    if ($Actual -ne $Expected) {
        throw ("Assertion failed ({0}): expected '{1}', got '{2}'." -f $Message, $Expected, $Actual)
    }
}

function Assert-Throws {
    param(
        [Parameter(Mandatory = $true)]
        [scriptblock]$Action,

        [string]$ExpectedPattern,

        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    $didThrow = $false
    $errMsg = ''
    try {
        & $Action | Out-Null
    }
    catch {
        $didThrow = $true
        $errMsg = $_.Exception.Message
    }

    if (-not $didThrow) {
        throw ("Expected exception was not thrown ({0})." -f $Message)
    }

    if (-not [string]::IsNullOrWhiteSpace($ExpectedPattern) -and ($errMsg -notmatch $ExpectedPattern)) {
        throw ("Exception message mismatch ({0}): pattern '{1}' did not match '{2}'." -f $Message, $ExpectedPattern, $errMsg)
    }
}

function New-EphemeralTestCertificate {
    param(
        [string]$Subject = 'CN=LumaBridge Ephemeral Test Signing',
        [datetimeoffset]$NotBefore = ([datetimeoffset]::UtcNow.AddDays(-1)),
        [datetimeoffset]$NotAfter = ([datetimeoffset]::UtcNow.AddDays(30)),
        [Parameter(Mandatory = $true)]
        [string]$OutDirectory,
        [string]$NamePrefix = 'cert'
    )

    if (-not (Test-Path -LiteralPath $OutDirectory)) {
        New-Item -Path $OutDirectory -ItemType Directory -Force | Out-Null
    }

    $rsa = [System.Security.Cryptography.RSA]::Create(2048)
    $req = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
        $Subject,
        $rsa,
        [System.Security.Cryptography.HashAlgorithmName]::SHA256,
        [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
    )

    $ekuOids = [System.Security.Cryptography.OidCollection]::new()
    $null = $ekuOids.Add([System.Security.Cryptography.Oid]::new('1.3.6.1.5.5.7.3.3'))
    $req.CertificateExtensions.Add([System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new($ekuOids, $false))
    $req.CertificateExtensions.Add([System.Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new([System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature, $false))

    $cert = $req.CreateSelfSigned($NotBefore, $NotAfter)
    $password = 'LumaBridgeTest!123'
    $pfxPath = Join-Path -Path $OutDirectory -ChildPath ("{0}.pfx" -f $NamePrefix)
    $cerPath = Join-Path -Path $OutDirectory -ChildPath ("{0}.cer" -f $NamePrefix)

    [System.IO.File]::WriteAllBytes($pfxPath, $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx, $password))
    [System.IO.File]::WriteAllBytes($cerPath, $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert))

    return [pscustomobject]@{
        Certificate = $cert
        Thumbprint  = $cert.Thumbprint
        Subject     = $cert.Subject
        NotBefore   = $cert.NotBefore
        NotAfter    = $cert.NotAfter
        PfxPath     = $pfxPath
        CerPath     = $cerPath
        Password    = $password
    }
}

function New-SignedTestPackage {
    param(
        [Parameter(Mandatory = $true)]
        [string]$TargetDir,

        [Parameter(Mandatory = $true)]
        [psobject]$CertInfo,

        [switch]$ExportCerAsPackageFile
    )

    $releaseDir = Get-LumaBridgePackageDirectory -Configuration Release
    $signtool = Get-LumaBridgeWdkToolPath -ToolName 'signtool.exe'
    $inf2cat = Get-LumaBridgeWdkToolPath -ToolName 'Inf2Cat.exe'
    $constants = Get-LumaBridgeDriverConstants

    if (Test-Path -LiteralPath $TargetDir) {
        Remove-Item -LiteralPath $TargetDir -Recurse -Force
    }
    New-Item -Path $TargetDir -ItemType Directory -Force | Out-Null

    Copy-Item -LiteralPath (Join-Path -Path $releaseDir -ChildPath $constants.InfFileName) -Destination $TargetDir -Force
    Copy-Item -LiteralPath (Join-Path -Path $releaseDir -ChildPath $constants.DllFileName) -Destination $TargetDir -Force

    $dllPath = Join-Path -Path $TargetDir -ChildPath $constants.DllFileName
    $catPath = Join-Path -Path $TargetDir -ChildPath $constants.CatFileName

    $prevEap = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $out1 = & $signtool sign /fd SHA256 /f $CertInfo.PfxPath /p $CertInfo.Password $dllPath 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw ("signtool DLL failed: {0}" -f ($out1 -join ' '))
        }

        $out2 = & $inf2cat ("/driver:{0}" -f $TargetDir) ("/os:{0}" -f $constants.SupportedInf2CatOsList) /uselocaltime 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw ("Inf2Cat failed: {0}" -f ($out2 -join ' '))
        }

        $out3 = & $signtool sign /fd SHA256 /f $CertInfo.PfxPath /p $CertInfo.Password $catPath 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw ("signtool CAT failed: {0}" -f ($out3 -join ' '))
        }
    }
    finally {
        $ErrorActionPreference = $prevEap
    }

    if ($ExportCerAsPackageFile) {
        Copy-Item -LiteralPath $CertInfo.CerPath -Destination (Join-Path -Path $TargetDir -ChildPath 'LumaBridgeTest.cer') -Force
    }
}

$script:CommonModulePathForReload = $commonModulePath

function Invoke-WithModuleMocks {
    param(
        [hashtable]$GlobalMocks = @{},
        [hashtable]$ModuleMocks = @{},
        [Parameter(Mandatory = $true)]
        [scriptblock]$Body
    )

    $commonMod = Get-Module -Name 'LumaBridgeDriverCommon'
    $savedGlobal = @{}

    try {
        foreach ($name in $GlobalMocks.Keys) {
            $existing = Microsoft.PowerShell.Management\Get-Item -Path ("Function:\global:{0}" -f $name) -ErrorAction SilentlyContinue
            if ($null -ne $existing) {
                $savedGlobal[$name] = $existing.ScriptBlock
            }
            else {
                $savedGlobal[$name] = $null
            }
            Microsoft.PowerShell.Management\Set-Item -Path ("Function:\global:{0}" -f $name) -Value $GlobalMocks[$name]
        }

        foreach ($name in $ModuleMocks.Keys) {
            $fnDef = $ModuleMocks[$name]
            & $commonMod {
                param($FnName, $FnBody)
                Microsoft.PowerShell.Management\Set-Item -Path ("Function:\script:{0}" -f $FnName) -Value $FnBody
            } $name $fnDef
        }

        & $Body
    }
    finally {
        foreach ($name in $savedGlobal.Keys) {
            if ($null -ne $savedGlobal[$name]) {
                Microsoft.PowerShell.Management\Set-Item -Path ("Function:\global:{0}" -f $name) -Value $savedGlobal[$name]
            }
            else {
                Microsoft.PowerShell.Management\Remove-Item -Path ("Function:\global:{0}" -f $name) -ErrorAction SilentlyContinue
            }
        }

        Import-Module $script:CommonModulePathForReload -Force
    }
}

function Invoke-UnitTest {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [scriptblock]$TestBody
    )

    $script:TestsRun++
    $global:LbTestState = @{}
    $caseDir = Join-Path -Path $script:TestTempRoot -ChildPath ("case_{0}_{1}" -f $script:TestsRun, $Name)
    New-Item -Path $caseDir -ItemType Directory -Force | Out-Null

    try {
        & $TestBody $caseDir
        Write-Host ("[PASS] {0}" -f $Name) -ForegroundColor Green
    }
    catch {
        $script:TestsFailed++
        Write-Host ("[FAIL] {0}: {1}" -f $Name, $_.Exception.Message) -ForegroundColor Red
    }
}

# 1. Positive cryptographic verification + staging signing flow without altering source artifacts
Invoke-UnitTest -Name 'PackageSigningAndCryptographicVerificationPositive' -TestBody {
    param($caseDir)
    $certDir = Join-Path $caseDir 'certs'
    $stagingDir = Join-Path $caseDir 'staging'
    $certInfo = New-EphemeralTestCertificate -OutDirectory $certDir -NamePrefix 'valid'

    $releaseDir = Get-LumaBridgePackageDirectory -Configuration Release
    $origInfHash = (Get-FileHash (Join-Path $releaseDir 'LumaBridgeIddDriver.inf') -Algorithm SHA256).Hash
    $origDllHash = (Get-FileHash (Join-Path $releaseDir 'LumaBridgeIddDriver.dll') -Algorithm SHA256).Hash
    $origCatHash = (Get-FileHash (Join-Path $releaseDir 'lumabridgeidddriver.cat') -Algorithm SHA256).Hash

    $global:LbTestState['CertInfo'] = $certInfo
    $global:LbTestState['Signtool'] = Get-LumaBridgeWdkToolPath -ToolName 'signtool.exe'

    Invoke-WithModuleMocks -GlobalMocks @{
        'Find-LumaBridgeSigningCertificate' = {
            [CmdletBinding()]
            param([string]$CertificateThumbprint, [string]$CertificateSubject)
            return $global:LbTestState['CertInfo'].Certificate
        }
        'Export-LumaBridgeCertificateFile' = {
            [CmdletBinding()]
            param($Certificate, [string]$FilePath)
            [System.IO.File]::WriteAllBytes($FilePath, $Certificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert))
        }
        'Invoke-LumaBridgeExternalCommand' = {
            [CmdletBinding()]
            param([string]$FilePath, [string[]]$Arguments = @(), [switch]$DryRun)
            $prevEap = $ErrorActionPreference
            $ErrorActionPreference = 'Continue'
            try {
                if ($FilePath -ieq $global:LbTestState['Signtool'] -and $Arguments.Count -ge 1 -and $Arguments[0] -eq 'sign') {
                    $targetFile = $Arguments[$Arguments.Count - 1]
                    $ci = $global:LbTestState['CertInfo']
                    $out = & $FilePath sign /fd SHA256 /f $ci.PfxPath /p $ci.Password $targetFile 2>&1
                    if ($LASTEXITCODE -ne 0) { throw ("Mocked signtool failed: {0}" -f ($out -join ' ')) }
                    return [pscustomobject]@{ ExitCode = 0; Output = @($out); DryRun = $false }
                }
                $out = & $FilePath @Arguments 2>&1
                if ($LASTEXITCODE -ne 0) { throw ("Command failed: {0}" -f ($out -join ' ')) }
                return [pscustomobject]@{ ExitCode = 0; Output = @($out); DryRun = $false }
            }
            finally {
                $ErrorActionPreference = $prevEap
            }
        }
    } -Body {
        $signingScript = Join-Path $scriptsDir 'Invoke-LumaBridgePackageSigning.ps1'
        $res = & $signingScript -Configuration Release -StagingDir $stagingDir -CertificateThumbprint $certInfo.Thumbprint -Force

        Assert-True ($res.SourceArtifactsPreserved -eq $true) 'SourceArtifactsPreserved should be true'
        Assert-True ($res.Verification.DllCatalogHashVerified -eq $true) 'DLL hash should be verified in catalog'
        Assert-True ($res.Verification.InfCatalogHashVerified -eq $true) 'INF hash should be verified in catalog'
        Assert-True ($res.Verification.SignerCertificatesMatch -eq $true) 'Signer certs must match across DLL, CAT, CER'
        Assert-True ($res.Verification.CatCmsSignatureIntact -eq $true) 'CAT PKCS#7 signature must be intact'
        Assert-True ($res.Verification.IsValidWithUntrustedRoot -eq $true) 'Untrusted test root package should pass IsValidWithUntrustedRoot'
        Assert-True ($res.Verification.IsCryptographicallyValid -eq $false) 'Untrusted test root must not pass strict trusted chain check'
    }

    Assert-Equal ((Get-FileHash (Join-Path $releaseDir 'LumaBridgeIddDriver.inf') -Algorithm SHA256).Hash) $origInfHash 'Original INF unchanged'
    Assert-Equal ((Get-FileHash (Join-Path $releaseDir 'LumaBridgeIddDriver.dll') -Algorithm SHA256).Hash) $origDllHash 'Original DLL unchanged'
    Assert-Equal ((Get-FileHash (Join-Path $releaseDir 'lumabridgeidddriver.cat') -Algorithm SHA256).Hash) $origCatHash 'Original CAT unchanged'

    Assert-Throws {
        Test-LumaBridgePackageArtifacts -PackageDirectory $stagingDir -RequireValidSignature
    } -ExpectedPattern 'Cryptographic verification failed' -Message 'Strict mode must reject untrusted test chain'
}

# 2. Tampered INF must be rejected both strictly and under -AllowUntrustedChain
Invoke-UnitTest -Name 'InfTamperingRejectedEvenWithAllowUntrustedChain' -TestBody {
    param($caseDir)
    $certInfo = New-EphemeralTestCertificate -OutDirectory (Join-Path $caseDir 'certs') -NamePrefix 'inf'
    $pkgDir = Join-Path $caseDir 'pkg'
    New-SignedTestPackage -TargetDir $pkgDir -CertInfo $certInfo -ExportCerAsPackageFile

    $infPath = Join-Path $pkgDir 'LumaBridgeIddDriver.inf'
    Add-Content -LiteralPath $infPath -Value "`r\n; tampered comment" -Encoding ASCII

    $check = Test-LumaBridgePackageArtifacts -PackageDirectory $pkgDir
    Assert-Equal $check.InfCatalogHashVerified $false 'InfCatalogHashVerified must become false after INF tamper'
    Assert-Equal $check.DllCatalogHashVerified $true 'DllCatalogHashVerified remains true'
    Assert-Equal $check.IsValidWithUntrustedRoot $false 'IsValidWithUntrustedRoot must be false when INF tampered'

    Assert-Throws {
        Test-LumaBridgePackageArtifacts -PackageDirectory $pkgDir -RequireValidSignature -AllowUntrustedChain
    } -ExpectedPattern 'InfCatHash=False' -Message 'AllowUntrustedChain must reject tampered INF'

    Invoke-WithModuleMocks -GlobalMocks @{
        'Assert-LumaBridgeAdministrator' = { [CmdletBinding()] param([string]$OperationName, [switch]$DryRun) return $true }
        'Get-LumaBridgePnpInstances' = { [CmdletBinding()] param([string]$HardwareId) return @() }
    } -ModuleMocks @{
        'Get-LumaBridgePnpInstances' = { [CmdletBinding()] param([string]$HardwareId) return @() }
    } -Body {
        Assert-Throws {
            & (Join-Path $scriptsDir 'Install-LumaBridgeDriver.ps1') -Configuration Release -StagingDir $pkgDir -AllowUntrustedChain -SkipTestSigningCheck -Force
        } -ExpectedPattern 'InfCatHash=False' -Message 'Install must block tampered INF even with -AllowUntrustedChain'
    }
}

# 3. Tampered DLL must be rejected both strictly and under -AllowUntrustedChain
Invoke-UnitTest -Name 'DllTamperingRejectedEvenWithAllowUntrustedChain' -TestBody {
    param($caseDir)
    $certInfo = New-EphemeralTestCertificate -OutDirectory (Join-Path $caseDir 'certs') -NamePrefix 'dll'
    $pkgDir = Join-Path $caseDir 'pkg'
    New-SignedTestPackage -TargetDir $pkgDir -CertInfo $certInfo -ExportCerAsPackageFile

    $dllPath = Join-Path $pkgDir 'LumaBridgeIddDriver.dll'
    $bytes = [System.IO.File]::ReadAllBytes($dllPath)
    $bytes[1024] = $bytes[1024] -bxor 0xFF
    [System.IO.File]::WriteAllBytes($dllPath, $bytes)

    $check = Test-LumaBridgePackageArtifacts -PackageDirectory $pkgDir
    Assert-Equal $check.DllSignatureStatus 'HashMismatch' 'Tampered DLL must report HashMismatch'
    Assert-Equal $check.DllCatalogHashVerified $false 'Tampered DLL catalog hash must fail'
    Assert-Equal $check.IsValidWithUntrustedRoot $false 'AllowUntrustedChain flag cannot pass tampered DLL'

    Assert-Throws {
        Test-LumaBridgePackageArtifacts -PackageDirectory $pkgDir -RequireValidSignature -AllowUntrustedChain
    } -ExpectedPattern 'HashMismatch' -Message 'AllowUntrustedChain must reject tampered DLL'
}

# 4. Unsigned package, tampered CAT, and expired cert must be rejected even with -AllowUntrustedChain
Invoke-UnitTest -Name 'UnsignedTamperedCatAndExpiredCertRejected' -TestBody {
    param($caseDir)
    # 4a: Unsigned package
    $releaseDir = Get-LumaBridgePackageDirectory -Configuration Release
    Assert-Throws {
        Test-LumaBridgePackageArtifacts -PackageDirectory $releaseDir -RequireValidSignature -AllowUntrustedChain
    } -ExpectedPattern 'NotSigned' -Message 'Unsigned package rejected under AllowUntrustedChain'

    # 4b: Tampered CAT
    $certInfo = New-EphemeralTestCertificate -OutDirectory (Join-Path $caseDir 'certs') -NamePrefix 'cat'
    $pkgDir = Join-Path $caseDir 'pkg_tampered_cat'
    New-SignedTestPackage -TargetDir $pkgDir -CertInfo $certInfo -ExportCerAsPackageFile
    $catPath = Join-Path $pkgDir 'lumabridgeidddriver.cat'
    $catBytes = [System.IO.File]::ReadAllBytes($catPath)
    $catBytes[$catBytes.Length - 180] = $catBytes[$catBytes.Length - 180] -bxor 0xFF
    [System.IO.File]::WriteAllBytes($catPath, $catBytes)

    $catCheck = Test-LumaBridgePackageArtifacts -PackageDirectory $pkgDir
    Assert-Equal $catCheck.CatCmsSignatureIntact $false 'Tampered CAT CMS signature must fail'
    Assert-Equal $catCheck.IsValidWithUntrustedRoot $false 'Tampered CAT must fail IsValidWithUntrustedRoot'
    Assert-Throws {
        Test-LumaBridgePackageArtifacts -PackageDirectory $pkgDir -RequireValidSignature -AllowUntrustedChain
    } -ExpectedPattern 'Cryptographic verification failed' -Message 'AllowUntrustedChain must reject tampered CAT'

    # 4c: Short-lived cert signed while valid, then allowed to expire
    $shortLivedCert = New-EphemeralTestCertificate `
        -OutDirectory (Join-Path $caseDir 'expired_certs') `
        -NamePrefix 'expired' `
        -NotBefore ([datetimeoffset]::UtcNow.AddMinutes(-5)) `
        -NotAfter ([datetimeoffset]::UtcNow.AddSeconds(3))
    $pkgExpired = Join-Path $caseDir 'pkg_expired'
    New-SignedTestPackage -TargetDir $pkgExpired -CertInfo $shortLivedCert -ExportCerAsPackageFile
    Start-Sleep -Seconds 4
    $expCheck = Test-LumaBridgePackageArtifacts -PackageDirectory $pkgExpired
    Assert-Equal $expCheck.SignerCertificatesMatch $false 'Expired signing cert must invalidate SignerCertificatesMatch'
    Assert-Equal $expCheck.IsValidWithUntrustedRoot $false 'Expired cert must fail IsValidWithUntrustedRoot'
}

# 5. Mismatched certificates between DLL, CAT, and exported CER must be rejected
Invoke-UnitTest -Name 'SignerCertificateMismatchRejected' -TestBody {
    param($caseDir)
    $certA = New-EphemeralTestCertificate -Subject 'CN=LumaBridge Cert A' -OutDirectory (Join-Path $caseDir 'certsA') -NamePrefix 'a'
    $certB = New-EphemeralTestCertificate -Subject 'CN=LumaBridge Cert B' -OutDirectory (Join-Path $caseDir 'certsB') -NamePrefix 'b'
    $pkgDir = Join-Path $caseDir 'pkg'
    New-SignedTestPackage -TargetDir $pkgDir -CertInfo $certA -ExportCerAsPackageFile

    $signtool = Get-LumaBridgeWdkToolPath -ToolName 'signtool.exe'
    $catPath = Join-Path $pkgDir 'lumabridgeidddriver.cat'
    $prevEap = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $out = & $signtool sign /fd SHA256 /f $certB.PfxPath /p $certB.Password $catPath 2>&1
        if ($LASTEXITCODE -ne 0) { throw ("signtool CertB failed: {0}" -f ($out -join ' ')) }
    }
    finally {
        $ErrorActionPreference = $prevEap
    }

    $mismatchCheck = Test-LumaBridgePackageArtifacts -PackageDirectory $pkgDir
    Assert-Equal $mismatchCheck.SignerCertificatesMatch $false 'DLL (Cert A) vs CAT (Cert B) must fail SignerCertificatesMatch'
    Assert-Throws {
        Test-LumaBridgePackageArtifacts -PackageDirectory $pkgDir -RequireValidSignature -AllowUntrustedChain
    } -ExpectedPattern 'SignerCertsMatch=False' -Message 'Mismatched DLL/CAT certs must be rejected'

    $pkgCerMismatch = Join-Path $caseDir 'pkg_cer'
    New-SignedTestPackage -TargetDir $pkgCerMismatch -CertInfo $certA
    Copy-Item -LiteralPath $certB.CerPath -Destination (Join-Path $pkgCerMismatch 'LumaBridgeTest.cer') -Force
    $cerMismatchCheck = Test-LumaBridgePackageArtifacts -PackageDirectory $pkgCerMismatch
    Assert-Equal $cerMismatchCheck.SignerCertificatesMatch $false 'Mismatched LumaBridgeTest.cer must fail SignerCertificatesMatch'
}

# 6. Isolated staging rejects repo/build paths and removes stale files before Inf2Cat
Invoke-UnitTest -Name 'IsolatedCleanStagingRejectsRepoPathsAndCleansResiduals' -TestBody {
    param($caseDir)
    $repoRoot = Get-LumaBridgeRepoRoot
    $releaseDir = Get-LumaBridgePackageDirectory -Configuration Release

    Assert-Throws {
        Assert-LumaBridgeIsolatedStagingDirectory -StagingDir $releaseDir -SourcePackageDir $releaseDir
    } -ExpectedPattern 'strictly isolated' -Message 'Build directory must be rejected as staging'

    Assert-Throws {
        Assert-LumaBridgeIsolatedStagingDirectory -StagingDir (Join-Path $repoRoot 'windows\driver\staging') -SourcePackageDir $releaseDir
    } -ExpectedPattern 'strictly isolated' -Message 'In-repo directory must be rejected as staging'

    Assert-Throws {
        Assert-LumaBridgeIsolatedStagingDirectory -StagingDir (Split-Path -Parent $repoRoot) -SourcePackageDir $releaseDir
    } -ExpectedPattern 'strictly isolated' -Message 'Parent directory containing repo must be rejected as staging'

    $dirtyStaging = Join-Path $caseDir 'dirty_staging'
    New-Item -Path $dirtyStaging -ItemType Directory -Force | Out-Null
    Set-Content -LiteralPath (Join-Path $dirtyStaging 'stale_extra.dll') -Value 'junk' -Encoding ASCII
    Set-Content -LiteralPath (Join-Path $dirtyStaging 'LumaBridgeTest.cer') -Value 'junk' -Encoding ASCII

    $certInfo = New-EphemeralTestCertificate -OutDirectory (Join-Path $caseDir 'certs') -NamePrefix 'clean'
    $global:LbTestState['CertInfo'] = $certInfo
    $global:LbTestState['Signtool'] = Get-LumaBridgeWdkToolPath -ToolName 'signtool.exe'

    Invoke-WithModuleMocks -GlobalMocks @{
        'Find-LumaBridgeSigningCertificate' = {
            [CmdletBinding()]
            param([string]$CertificateThumbprint, [string]$CertificateSubject)
            return $global:LbTestState['CertInfo'].Certificate
        }
        'Export-LumaBridgeCertificateFile' = {
            [CmdletBinding()]
            param($Certificate, [string]$FilePath)
            [System.IO.File]::WriteAllBytes($FilePath, $Certificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert))
        }
        'Invoke-LumaBridgeExternalCommand' = {
            [CmdletBinding()]
            param([string]$FilePath, [string[]]$Arguments = @(), [switch]$DryRun)
            $prevEap = $ErrorActionPreference
            $ErrorActionPreference = 'Continue'
            try {
                if ($FilePath -ieq $global:LbTestState['Signtool'] -and $Arguments.Count -ge 1 -and $Arguments[0] -eq 'sign') {
                    $targetFile = $Arguments[$Arguments.Count - 1]
                    $ci = $global:LbTestState['CertInfo']
                    $out = & $FilePath sign /fd SHA256 /f $ci.PfxPath /p $ci.Password $targetFile 2>&1
                    if ($LASTEXITCODE -ne 0) { throw ($out -join ' ') }
                    return [pscustomobject]@{ ExitCode = 0; Output = @($out); DryRun = $false }
                }
                $out = & $FilePath @Arguments 2>&1
                if ($LASTEXITCODE -ne 0) { throw ($out -join ' ') }
                return [pscustomobject]@{ ExitCode = 0; Output = @($out); DryRun = $false }
            }
            finally {
                $ErrorActionPreference = $prevEap
            }
        }
    } -Body {
        $res = & (Join-Path $scriptsDir 'Invoke-LumaBridgePackageSigning.ps1') -Configuration Release -StagingDir $dirtyStaging -CertificateThumbprint $certInfo.Thumbprint -Force
        Assert-Equal (Test-Path -LiteralPath (Join-Path $dirtyStaging 'stale_extra.dll')) $false 'Stale residual files must be cleaned from staging'
        Assert-True ($res.Verification.AllFilesPresent) 'Staged files must be present'
        Assert-True ($res.Verification.CatalogHashesVerified) 'Catalog hashes must succeed cleanly'
    }
}

# 7. PnP identification strictly uses DEVPKEY_Device_HardwareIds (no FriendlyName spoofing)
Invoke-UnitTest -Name 'PnpIdentificationUsesEffectiveDevpkeyHardwareIdsOnly' -TestBody {
    param($caseDir)
    Invoke-WithModuleMocks -ModuleMocks @{
        'Get-PnpDevice' = {
            [CmdletBinding()]
            param()
            return @(
                [pscustomobject]@{
                    InstanceId   = 'ROOT\DISPLAY\SPOOFED'
                    FriendlyName = 'LumaBridge Indirect Display Adapter'
                    Status       = 'OK'
                    Present      = $true
                    Class        = 'Display'
                    HardwareID   = @('Root\LumaBridgeIddDriver')
                },
                [pscustomobject]@{
                    InstanceId   = 'ROOT\DISPLAY\REAL0001'
                    FriendlyName = 'Generic Display Label'
                    Status       = 'OK'
                    Present      = $true
                    Class        = 'Display'
                    HardwareID   = @()
                }
            )
        }
        'Get-PnpDeviceProperty' = {
            [CmdletBinding()]
            param([string]$InstanceId, [string]$KeyName)
            if ($InstanceId -eq 'ROOT\DISPLAY\SPOOFED' -and $KeyName -eq 'DEVPKEY_Device_HardwareIds') {
                return [pscustomobject]@{ Data = @('PCI\VEN_0000&DEV_0000') }
            }
            if ($InstanceId -eq 'ROOT\DISPLAY\REAL0001') {
                $val = switch ($KeyName) {
                    'DEVPKEY_Device_HardwareIds'     { @('Root\LumaBridgeIddDriver') }
                    'DEVPKEY_Device_ProblemCode'     { 0 }
                    'DEVPKEY_Device_DriverInfPath'   { 'oem42.inf' }
                    'DEVPKEY_Device_DriverProvider'  { 'LumaBridge' }
                    'DEVPKEY_Device_DriverVersion'   { '1.2.3.4' }
                    'DEVPKEY_Device_Service'         { 'WUDFRd' }
                    'DEVPKEY_Device_ConfigurationId' { 'oem42.inf:Root\LumaBridgeIddDriver' }
                    default { $null }
                }
                return [pscustomobject]@{ Data = $val }
            }
            return $null
        }
        'Get-LumaBridgeDeviceEnableVirtualMonitor' = { [CmdletBinding()] param([string]$DeviceParametersPath) return 0 }
    } -Body {
        $instances = @(Get-LumaBridgePnpInstances)
        Assert-Equal $instances.Count 1 'Only the device matching DEVPKEY_Device_HardwareIds should be returned'
        Assert-Equal $instances[0].InstanceId 'ROOT\DISPLAY\REAL0001' 'Real device should be returned'
        Assert-Equal $instances[0].DriverInfPath 'oem42.inf' 'DriverInfPath populated'
        Assert-Equal $instances[0].DriverProvider 'LumaBridge' 'DriverProvider populated'
        Assert-Equal $instances[0].DriverVersion '1.2.3.4' 'DriverVersion populated'
    }
}

# 8. Locale-independent structured XML parsing of pnputil /enum-drivers /format xml
Invoke-UnitTest -Name 'DriverStoreXmlParsingIsLocaleIndependent' -TestBody {
    param($caseDir)
    $sampleXml = @'
<?xml version="1.0" encoding="utf-8"?>
<PnpUtil Version="10.0.26300" Command="/enum-drivers /format xml">
    <Driver DriverName="oem71.inf">
        <OriginalName>nv_dispi.inf</OriginalName>
        <ProviderName>NVIDIA</ProviderName>
        <ClassName>Adaptadores de vídeo</ClassName>
        <ClassGuid>{4d36e968-e325-11ce-bfc1-08002be10318}</ClassGuid>
        <DriverVersion>10/19/2026 32.0.16.2101</DriverVersion>
        <SignerName>Microsoft Windows Hardware Compatibility Publisher</SignerName>
    </Driver>
    <Driver DriverName="oem42.inf">
        <OriginalName>lumabridgeidddriver.inf</OriginalName>
        <ProviderName>LumaBridge</ProviderName>
        <ClassName>Adaptadores de vídeo</ClassName>
        <ClassGuid>{4d36e968-e325-11ce-bfc1-08002be10318}</ClassGuid>
        <DriverVersion>11/18/2026 0.1.0.1</DriverVersion>
        <SignerName>LumaBridge Test Driver Signing</SignerName>
    </Driver>
</PnpUtil>
'@

    $global:LbTestState['XmlLines'] = $sampleXml -split "`r?`n"
    Invoke-WithModuleMocks -ModuleMocks @{
        'Invoke-LumaBridgePnpUtilEnumDriversXml' = {
            [CmdletBinding()] param()
            return [pscustomobject]@{ ExitCode = 0; Output = $global:LbTestState['XmlLines'] }
        }
    } -Body {
        $pkgs = @(Get-LumaBridgeDriverStorePackages)
        Assert-Equal $pkgs.Count 1 'Exactly one LumaBridge Driver Store package should be parsed from XML'
        Assert-Equal $pkgs[0].PublishedName 'oem42.inf' 'PublishedName extracted'
        Assert-Equal $pkgs[0].OriginalName 'lumabridgeidddriver.inf' 'OriginalName extracted'
        Assert-Equal $pkgs[0].ProviderName 'LumaBridge' 'ProviderName extracted'
        Assert-Equal $pkgs[0].ClassGuid '{4d36e968-e325-11ce-bfc1-08002be10318}' 'ClassGuid extracted'
    }
}

# 9. Duplicate PnP devices blocked cleanly
Invoke-UnitTest -Name 'DuplicateDevicesBlockedByInstallAndMonitorScripts' -TestBody {
    param($caseDir)
    $global:LbTestState['DupList'] = @(
        [pscustomobject]@{ InstanceId = 'ROOT\DISPLAY\0000'; DeviceParametersPath = 'MOCK\0'; EnableVirtualMonitor = 0 },
        [pscustomobject]@{ InstanceId = 'ROOT\DISPLAY\0001'; DeviceParametersPath = 'MOCK\1'; EnableVirtualMonitor = 0 }
    )

    Invoke-WithModuleMocks -GlobalMocks @{
        'Assert-LumaBridgeAdministrator' = { [CmdletBinding()] param([string]$OperationName, [switch]$DryRun) return $true }
        'Get-LumaBridgePnpInstances' = { [CmdletBinding()] param([string]$HardwareId) return $global:LbTestState['DupList'] }
        'Get-LumaBridgeDriverStorePackages' = { [CmdletBinding()] param([string]$InfFilter) return @() }
    } -ModuleMocks @{
        'Get-LumaBridgePnpInstances' = { [CmdletBinding()] param([string]$HardwareId) return $global:LbTestState['DupList'] }
        'Get-LumaBridgeDriverStorePackages' = { [CmdletBinding()] param([string]$InfFilter) return @() }
    } -Body {
        Assert-Throws {
            & (Join-Path $scriptsDir 'Install-LumaBridgeDriver.ps1') -Configuration Release -StagingDir (Join-Path $caseDir 'stg') -DryRun
        } -ExpectedPattern 'Multiple instances' -Message 'Install must block duplicate devices'

        Assert-Throws {
            & (Join-Path $scriptsDir 'Set-LumaBridgeVirtualMonitor.ps1') -Action Enable -DryRun
        } -ExpectedPattern 'Multiple .* instances' -Message 'Set-LumaBridgeVirtualMonitor must block duplicate devices'
    }
}

# 10. Fresh install succeeds, sets EnableVirtualMonitor=0, and confirms bound driver
Invoke-UnitTest -Name 'FreshInstallSucceedsAndConfirmsDriverBinding' -TestBody {
    param($caseDir)
    $certInfo = New-EphemeralTestCertificate -OutDirectory (Join-Path $caseDir 'certs') -NamePrefix 'fresh'
    $pkgDir = Join-Path $caseDir 'pkg'
    New-SignedTestPackage -TargetDir $pkgDir -CertInfo $certInfo -ExportCerAsPackageFile
    $expectedVer = Get-LumaBridgeInfDriverVersion -InfPath (Join-Path $pkgDir 'LumaBridgeIddDriver.inf')

    $global:LbTestState['Fresh'] = [ordered]@{
        Installed   = $false
        EnableVal   = $null
        Calls       = New-Object System.Collections.Generic.List[string]
        ExpectedVer = $expectedVer
    }

    $getInstancesMock = {
        [CmdletBinding()] param([string]$HardwareId)
        $st = $global:LbTestState['Fresh']
        if (-not $st.Installed) { return @() }
        return @([pscustomobject]@{
            InstanceId           = 'ROOT\DISPLAY\0000'
            FriendlyName         = 'LumaBridge Indirect Display Adapter'
            Status               = 'OK'
            ProblemCode          = 0
            Present              = $true
            HardwareIds          = @('Root\LumaBridgeIddDriver')
            DriverInfPath        = 'oem42.inf'
            DriverProvider       = 'LumaBridge'
            DriverVersion        = $st.ExpectedVer
            DriverService        = 'WUDFRd'
            ConfigurationId      = 'oem42.inf:Root\LumaBridgeIddDriver'
            DeviceParametersPath = 'MOCK:\ROOT\DISPLAY\0000\Device Parameters'
            EnableVirtualMonitor = $st.EnableVal
        })
    }

    $getPackagesMock = {
        [CmdletBinding()] param([string]$InfFilter)
        if (-not $global:LbTestState['Fresh'].Installed) { return @() }
        return @([pscustomobject]@{
            PublishedName = 'oem42.inf'
            OriginalName  = 'lumabridgeidddriver.inf'
            ProviderName  = 'LumaBridge'
            ClassGuid     = '{4d36e968-e325-11ce-bfc1-08002be10318}'
        })
    }

    Invoke-WithModuleMocks -GlobalMocks @{
        'Assert-LumaBridgeAdministrator' = { [CmdletBinding()] param([string]$OperationName, [switch]$DryRun) return $true }
        'Get-LumaBridgeHostSecurityState' = { [CmdletBinding()] param() return [pscustomobject]@{ SecureBoot = 'Disabled'; TestSigning = 'Enabled' } }
        'Get-LumaBridgePnpInstances' = $getInstancesMock
        'Get-LumaBridgeDriverStorePackages' = $getPackagesMock
        'Set-LumaBridgeDeviceEnableVirtualMonitor' = {
            [CmdletBinding()] param([string]$DeviceParametersPath, [int]$Value)
            $global:LbTestState['Fresh'].EnableVal = $Value
            $global:LbTestState['Fresh'].Calls.Add(("SetEnable:{0}" -f $Value))
        }
        'Invoke-LumaBridgeExternalCommand' = {
            [CmdletBinding()] param([string]$FilePath, [string[]]$Arguments = @(), [switch]$DryRun)
            $cmdLine = "{0} {1}" -f (Split-Path -Leaf $FilePath), ($Arguments -join ' ')
            $global:LbTestState['Fresh'].Calls.Add($cmdLine)
            if ($FilePath -like '*devcon.exe' -and $Arguments[0] -eq 'install') {
                $global:LbTestState['Fresh'].Installed = $true
            }
            return [pscustomobject]@{ ExitCode = 0; Output = @('OK'); DryRun = $false }
        }
    } -ModuleMocks @{
        'Get-LumaBridgeHostSecurityState' = { [CmdletBinding()] param() return [pscustomobject]@{ SecureBoot = 'Disabled'; TestSigning = 'Enabled' } }
        'Get-LumaBridgePnpInstances' = $getInstancesMock
        'Get-LumaBridgeDriverStorePackages' = $getPackagesMock
    } -Body {
        $res = & (Join-Path $scriptsDir 'Install-LumaBridgeDriver.ps1') -Configuration Release -StagingDir $pkgDir -AllowUntrustedChain -Force
        Assert-Equal $res.Instance.InstanceId 'ROOT\DISPLAY\0000' 'Instance created'
        Assert-Equal $res.Instance.EnableVirtualMonitor 0 'EnableVirtualMonitor initialized to 0'
        Assert-True ($res.DriverBinding.IsBound) 'Driver binding verified after install'
        Assert-Equal $global:LbTestState['Fresh'].Calls.Count 3 'Expected add-driver, devcon install, SetEnable:0'
    }
}

# 11. Repeated install disables active monitor and restarts device BEFORE updating driver
Invoke-UnitTest -Name 'RepeatedInstallDisablesMonitorBeforeUpdate' -TestBody {
    param($caseDir)
    $certInfo = New-EphemeralTestCertificate -OutDirectory (Join-Path $caseDir 'certs') -NamePrefix 'repeat'
    $pkgDir = Join-Path $caseDir 'pkg'
    New-SignedTestPackage -TargetDir $pkgDir -CertInfo $certInfo -ExportCerAsPackageFile
    $expectedVer = Get-LumaBridgeInfDriverVersion -InfPath (Join-Path $pkgDir 'LumaBridgeIddDriver.inf')

    $global:LbTestState['Repeat'] = [ordered]@{
        EnableVal   = 1
        ExpectedVer = $expectedVer
        Calls       = New-Object System.Collections.Generic.List[string]
    }

    $getInstancesMock = {
        [CmdletBinding()] param([string]$HardwareId)
        $st = $global:LbTestState['Repeat']
        return @([pscustomobject]@{
            InstanceId           = 'ROOT\DISPLAY\0000'
            FriendlyName         = 'LumaBridge Indirect Display Adapter'
            Status               = 'OK'
            ProblemCode          = 0
            Present              = $true
            HardwareIds          = @('Root\LumaBridgeIddDriver')
            DriverInfPath        = 'oem42.inf'
            DriverProvider       = 'LumaBridge'
            DriverVersion        = $st.ExpectedVer
            DriverService        = 'WUDFRd'
            ConfigurationId      = 'oem42.inf:Root\LumaBridgeIddDriver'
            DeviceParametersPath = 'MOCK:\ROOT\DISPLAY\0000\Device Parameters'
            EnableVirtualMonitor = $st.EnableVal
        })
    }

    $getPackagesMock = {
        [CmdletBinding()] param([string]$InfFilter)
        return @([pscustomobject]@{
            PublishedName = 'oem42.inf'
            OriginalName  = 'lumabridgeidddriver.inf'
            ProviderName  = 'LumaBridge'
            ClassGuid     = '{4d36e968-e325-11ce-bfc1-08002be10318}'
        })
    }

    Invoke-WithModuleMocks -GlobalMocks @{
        'Assert-LumaBridgeAdministrator' = { [CmdletBinding()] param([string]$OperationName, [switch]$DryRun) return $true }
        'Get-LumaBridgeHostSecurityState' = { [CmdletBinding()] param() return [pscustomobject]@{ SecureBoot = 'Disabled'; TestSigning = 'Enabled' } }
        'Get-LumaBridgePnpInstances' = $getInstancesMock
        'Get-LumaBridgeDriverStorePackages' = $getPackagesMock
        'Set-LumaBridgeDeviceEnableVirtualMonitor' = {
            [CmdletBinding()] param([string]$DeviceParametersPath, [int]$Value)
            $global:LbTestState['Repeat'].EnableVal = $Value
            $global:LbTestState['Repeat'].Calls.Add(("SetEnable:{0}" -f $Value))
        }
        'Invoke-LumaBridgeExternalCommand' = {
            [CmdletBinding()] param([string]$FilePath, [string[]]$Arguments = @(), [switch]$DryRun)
            $global:LbTestState['Repeat'].Calls.Add(("{0} {1}" -f (Split-Path -Leaf $FilePath), ($Arguments -join ' ')))
            return [pscustomobject]@{ ExitCode = 0; Output = @('OK'); DryRun = $false }
        }
    } -ModuleMocks @{
        'Get-LumaBridgeHostSecurityState' = { [CmdletBinding()] param() return [pscustomobject]@{ SecureBoot = 'Disabled'; TestSigning = 'Enabled' } }
        'Get-LumaBridgePnpInstances' = $getInstancesMock
        'Get-LumaBridgeDriverStorePackages' = $getPackagesMock
    } -Body {
        $res = & (Join-Path $scriptsDir 'Install-LumaBridgeDriver.ps1') -Configuration Release -StagingDir $pkgDir -AllowUntrustedChain -Force
        Assert-Equal $res.Instance.EnableVirtualMonitor 0 'EnableVirtualMonitor stays 0 after repeated install'
        Assert-True ($res.DriverBinding.IsBound) 'Driver binding verified after update'
        Assert-Equal $global:LbTestState['Repeat'].Calls[0] 'SetEnable:0' 'First action must disable monitor before update'
        Assert-True ($global:LbTestState['Repeat'].Calls[1] -like 'pnputil.exe /restart-device ROOT\DISPLAY\0000') 'Device must restart to depart active monitor before update'
        Assert-True ($global:LbTestState['Repeat'].Calls[2] -like 'pnputil.exe /add-driver * /install') 'Update runs after monitor disabled and restarted'
    }
}

# 12. Partial fresh install failure triggers full rollback
Invoke-UnitTest -Name 'PartialFreshInstallFailureTriggersRollback' -TestBody {
    param($caseDir)
    $certInfo = New-EphemeralTestCertificate -OutDirectory (Join-Path $caseDir 'certs') -NamePrefix 'rb_fresh'
    $pkgDir = Join-Path $caseDir 'pkg'
    New-SignedTestPackage -TargetDir $pkgDir -CertInfo $certInfo -ExportCerAsPackageFile

    $global:LbTestState['RbFresh'] = [ordered]@{
        HasDevice  = $false
        HasPackage = $false
        ForceUsed  = $false
    }

    $getInstancesMock = {
        [CmdletBinding()] param([string]$HardwareId)
        if (-not $global:LbTestState['RbFresh'].HasDevice) { return @() }
        return @([pscustomobject]@{
            InstanceId           = 'ROOT\DISPLAY\0099'
            FriendlyName         = 'Broken Device'
            Status               = 'Error'
            ProblemCode          = 28
            Present              = $true
            HardwareIds          = @('Root\LumaBridgeIddDriver')
            DriverInfPath        = $null
            DriverProvider       = $null
            DriverVersion        = $null
            DriverService        = $null
            ConfigurationId      = $null
            DeviceParametersPath = 'MOCK:\ROOT\DISPLAY\0099\Device Parameters'
            EnableVirtualMonitor = 0
        })
    }

    $getPackagesMock = {
        [CmdletBinding()] param([string]$InfFilter)
        if (-not $global:LbTestState['RbFresh'].HasPackage) { return @() }
        return @([pscustomobject]@{
            PublishedName = 'oem99.inf'
            OriginalName  = 'lumabridgeidddriver.inf'
            ProviderName  = 'LumaBridge'
            ClassGuid     = '{4d36e968-e325-11ce-bfc1-08002be10318}'
        })
    }

    Invoke-WithModuleMocks -GlobalMocks @{
        'Assert-LumaBridgeAdministrator' = { [CmdletBinding()] param([string]$OperationName, [switch]$DryRun) return $true }
        'Get-LumaBridgeHostSecurityState' = { [CmdletBinding()] param() return [pscustomobject]@{ SecureBoot = 'Disabled'; TestSigning = 'Enabled' } }
        'Get-LumaBridgePnpInstances' = $getInstancesMock
        'Get-LumaBridgeDriverStorePackages' = $getPackagesMock
        'Set-LumaBridgeDeviceEnableVirtualMonitor' = { [CmdletBinding()] param([string]$DeviceParametersPath, [int]$Value) }
        'Invoke-LumaBridgeExternalCommand' = {
            [CmdletBinding()] param([string]$FilePath, [string[]]$Arguments = @(), [switch]$DryRun)
            if ($Arguments -contains '/force') { $global:LbTestState['RbFresh'].ForceUsed = $true }
            if ($FilePath -like '*pnputil*' -and $Arguments[0] -eq '/add-driver') {
                $global:LbTestState['RbFresh'].HasPackage = $true
            }
            elseif ($FilePath -like '*devcon*' -and $Arguments[0] -eq 'install') {
                $global:LbTestState['RbFresh'].HasDevice = $true
                throw 'devcon simulated failure after partial node creation'
            }
            elseif ($FilePath -like '*pnputil*' -and $Arguments[0] -eq '/remove-device') {
                $global:LbTestState['RbFresh'].HasDevice = $false
            }
            elseif ($FilePath -like '*pnputil*' -and $Arguments[0] -eq '/delete-driver') {
                $global:LbTestState['RbFresh'].HasPackage = $false
            }
            return [pscustomobject]@{ ExitCode = 0; Output = @('OK'); DryRun = $false }
        }
    } -ModuleMocks @{
        'Get-LumaBridgeHostSecurityState' = { [CmdletBinding()] param() return [pscustomobject]@{ SecureBoot = 'Disabled'; TestSigning = 'Enabled' } }
        'Get-LumaBridgePnpInstances' = $getInstancesMock
        'Get-LumaBridgeDriverStorePackages' = $getPackagesMock
    } -Body {
        Assert-Throws {
            & (Join-Path $scriptsDir 'Install-LumaBridgeDriver.ps1') -Configuration Release -StagingDir $pkgDir -AllowUntrustedChain -Force
        } -ExpectedPattern 'Rollback:.*Removed partial PnP instance.*Deleted newly staged package' -Message 'Fresh install failure must trigger full rollback'

        Assert-Equal $global:LbTestState['RbFresh'].HasDevice $false 'Partial PnP device must be removed by rollback'
        Assert-Equal $global:LbTestState['RbFresh'].HasPackage $false 'Newly added OEM package must be deleted by rollback'
        Assert-Equal $global:LbTestState['RbFresh'].ForceUsed $false 'Rollback must not use /force'
    }
}

# 13. Partial update failure rolls back newly staged OEM package without wiping pre-existing package
Invoke-UnitTest -Name 'PartialUpdateFailureTriggersRollback' -TestBody {
    param($caseDir)
    $certInfo = New-EphemeralTestCertificate -OutDirectory (Join-Path $caseDir 'certs') -NamePrefix 'rb_upd'
    $pkgDir = Join-Path $caseDir 'pkg'
    New-SignedTestPackage -TargetDir $pkgDir -CertInfo $certInfo -ExportCerAsPackageFile

    $global:LbTestState['RbUpd'] = [ordered]@{
        HasNewPkg = $false
        Restarted = $false
    }

    $getInstancesMock = {
        [CmdletBinding()] param([string]$HardwareId)
        return @([pscustomobject]@{
            InstanceId           = 'ROOT\DISPLAY\0000'
            FriendlyName         = 'LumaBridge Indirect Display Adapter'
            Status               = 'OK'
            ProblemCode          = 0
            Present              = $true
            HardwareIds          = @('Root\LumaBridgeIddDriver')
            DriverInfPath        = 'oem10.inf'
            DriverProvider       = 'LumaBridge'
            DriverVersion        = '0.0.0.1'
            DriverService        = 'WUDFRd'
            ConfigurationId      = 'oem10.inf:Root\LumaBridgeIddDriver'
            DeviceParametersPath = 'MOCK:\ROOT\DISPLAY\0000\Device Parameters'
            EnableVirtualMonitor = 0
        })
    }

    $getPackagesMock = {
        [CmdletBinding()] param([string]$InfFilter)
        $list = @([pscustomobject]@{
            PublishedName = 'oem10.inf'
            OriginalName  = 'lumabridgeidddriver.inf'
            ProviderName  = 'LumaBridge'
            ClassGuid     = '{4d36e968-e325-11ce-bfc1-08002be10318}'
        })
        if ($global:LbTestState['RbUpd'].HasNewPkg) {
            $list += [pscustomobject]@{
                PublishedName = 'oem99.inf'
                OriginalName  = 'lumabridgeidddriver.inf'
                ProviderName  = 'LumaBridge'
                ClassGuid     = '{4d36e968-e325-11ce-bfc1-08002be10318}'
            }
        }
        return $list
    }

    Invoke-WithModuleMocks -GlobalMocks @{
        'Assert-LumaBridgeAdministrator' = { [CmdletBinding()] param([string]$OperationName, [switch]$DryRun) return $true }
        'Get-LumaBridgeHostSecurityState' = { [CmdletBinding()] param() return [pscustomobject]@{ SecureBoot = 'Disabled'; TestSigning = 'Enabled' } }
        'Get-LumaBridgePnpInstances' = $getInstancesMock
        'Get-LumaBridgeDriverStorePackages' = $getPackagesMock
        'Set-LumaBridgeDeviceEnableVirtualMonitor' = { [CmdletBinding()] param([string]$DeviceParametersPath, [int]$Value) }
        'Invoke-LumaBridgeExternalCommand' = {
            [CmdletBinding()] param([string]$FilePath, [string[]]$Arguments = @(), [switch]$DryRun)
            if ($Arguments[0] -eq '/add-driver') {
                $global:LbTestState['RbUpd'].HasNewPkg = $true
            }
            elseif ($Arguments[0] -eq '/delete-driver' -and $Arguments[1] -eq 'oem99.inf') {
                $global:LbTestState['RbUpd'].HasNewPkg = $false
            }
            elseif ($Arguments[0] -eq '/restart-device') {
                $global:LbTestState['RbUpd'].Restarted = $true
            }
            return [pscustomobject]@{ ExitCode = 0; Output = @('OK'); DryRun = $false }
        }
    } -ModuleMocks @{
        'Get-LumaBridgeHostSecurityState' = { [CmdletBinding()] param() return [pscustomobject]@{ SecureBoot = 'Disabled'; TestSigning = 'Enabled' } }
        'Get-LumaBridgePnpInstances' = $getInstancesMock
        'Get-LumaBridgeDriverStorePackages' = $getPackagesMock
    } -Body {
        Assert-Throws {
            & (Join-Path $scriptsDir 'Install-LumaBridgeDriver.ps1') -Configuration Release -StagingDir $pkgDir -AllowUntrustedChain -Force
        } -ExpectedPattern "Driver binding verification failed.*Deleted failed update package 'oem99\.inf'.*Restarted device" -Message 'Update binding failure must roll back new OEM package and restart device'

        Assert-Equal $global:LbTestState['RbUpd'].HasNewPkg $false 'Failed update package oem99.inf must be deleted'
        Assert-Equal $global:LbTestState['RbUpd'].Restarted $true 'Device must be restarted to restore previous driver'
    }
}

# 14. Virtual monitor Enable failure rolls back EnableVirtualMonitor=0 and restarts device
Invoke-UnitTest -Name 'VirtualMonitorEnablePartialFailureTriggersRollback' -TestBody {
    param($caseDir)
    $global:LbTestState['VmState'] = [ordered]@{
        EnableVal    = 0
        ProblemCode  = 0
        RestartCount = 0
        FailEnable   = $true
    }

    $getInstancesMock = {
        [CmdletBinding()] param([string]$HardwareId)
        $st = $global:LbTestState['VmState']
        return @([pscustomobject]@{
            InstanceId           = 'ROOT\DISPLAY\0000'
            FriendlyName         = 'LumaBridge Indirect Display Adapter'
            Status               = if ($st.ProblemCode -eq 0) { 'OK' } else { 'Error' }
            ProblemCode          = $st.ProblemCode
            Present              = $true
            HardwareIds          = @('Root\LumaBridgeIddDriver')
            DeviceParametersPath = 'MOCK:\ROOT\DISPLAY\0000\Device Parameters'
            EnableVirtualMonitor = $st.EnableVal
        })
    }

    Invoke-WithModuleMocks -GlobalMocks @{
        'Assert-LumaBridgeAdministrator' = { [CmdletBinding()] param([string]$OperationName, [switch]$DryRun) return $true }
        'Get-LumaBridgePnpInstances' = $getInstancesMock
        'Set-LumaBridgeDeviceEnableVirtualMonitor' = {
            [CmdletBinding()] param([string]$DeviceParametersPath, [int]$Value)
            $st = $global:LbTestState['VmState']
            $st.EnableVal = $Value
            if ($Value -eq 1 -and $st.FailEnable) {
                $st.ProblemCode = 43
            }
            else {
                $st.ProblemCode = 0
            }
        }
        'Invoke-LumaBridgeExternalCommand' = {
            [CmdletBinding()] param([string]$FilePath, [string[]]$Arguments = @(), [switch]$DryRun)
            if ($Arguments[0] -eq '/restart-device') {
                $global:LbTestState['VmState'].RestartCount++
            }
            return [pscustomobject]@{ ExitCode = 0; Output = @('OK'); DryRun = $false }
        }
    } -ModuleMocks @{
        'Get-LumaBridgePnpInstances' = $getInstancesMock
    } -Body {
        Assert-Throws {
            & (Join-Path $scriptsDir 'Set-LumaBridgeVirtualMonitor.ps1') -Action Enable -Force
        } -ExpectedPattern 'ProblemCode=43.*Rollback: Reverted EnableVirtualMonitor=0; Restarted device' -Message 'Activation failure must roll back EnableVirtualMonitor to 0'

        Assert-Equal $global:LbTestState['VmState'].EnableVal 0 'EnableVirtualMonitor rolled back to 0'
        Assert-Equal $global:LbTestState['VmState'].RestartCount 2 'Device restarted for activation attempt and rollback recovery'
    }
}

# 15. Uninstall omits /force by default and supports opt-in -ForceDriverStoreDelete
Invoke-UnitTest -Name 'UninstallOmitsForceByDefaultAndSupportsOptInForce' -TestBody {
    param($caseDir)
    $global:LbTestState['Uninst'] = [ordered]@{
        Calls   = New-Object System.Collections.Generic.List[string]
        Removed = $false
    }

    $getInstancesMock = {
        [CmdletBinding()] param([string]$HardwareId)
        if ($global:LbTestState['Uninst'].Removed) { return @() }
        return @([pscustomobject]@{
            InstanceId           = 'ROOT\DISPLAY\0000'
            DeviceParametersPath = 'MOCK:\ROOT\DISPLAY\0000\Device Parameters'
            EnableVirtualMonitor = 1
        })
    }
    $getPackagesMock = {
        [CmdletBinding()] param([string]$InfFilter)
        if ($global:LbTestState['Uninst'].Removed) { return @() }
        return @([pscustomobject]@{ PublishedName = 'oem42.inf'; OriginalName = 'lumabridgeidddriver.inf' })
    }

    Invoke-WithModuleMocks -GlobalMocks @{
        'Assert-LumaBridgeAdministrator' = { [CmdletBinding()] param([string]$OperationName, [switch]$DryRun) return $true }
        'Get-LumaBridgePnpInstances' = $getInstancesMock
        'Get-LumaBridgeDriverStorePackages' = $getPackagesMock
        'Set-LumaBridgeDeviceEnableVirtualMonitor' = { [CmdletBinding()] param([string]$DeviceParametersPath, [int]$Value) }
        'Invoke-LumaBridgeExternalCommand' = {
            [CmdletBinding()] param([string]$FilePath, [string[]]$Arguments = @(), [switch]$DryRun)
            $global:LbTestState['Uninst'].Calls.Add(($Arguments -join ' '))
            if ($Arguments[0] -eq '/delete-driver') { $global:LbTestState['Uninst'].Removed = $true }
            return [pscustomobject]@{ ExitCode = 0; Output = @('OK'); DryRun = $false }
        }
    } -Body {
        $res1 = & (Join-Path $scriptsDir 'Uninstall-LumaBridgeDriver.ps1') -Force
        Assert-True ($res1.RollbackClean) 'Default uninstall succeeds cleanly'
        Assert-Equal $global:LbTestState['Uninst'].Calls[1] '/delete-driver oem42.inf /uninstall' 'Default uninstall must NOT pass /force'
    }

    $global:LbTestState['Uninst'].Calls.Clear()
    $global:LbTestState['Uninst'].Removed = $false
    Invoke-WithModuleMocks -GlobalMocks @{
        'Assert-LumaBridgeAdministrator' = { [CmdletBinding()] param([string]$OperationName, [switch]$DryRun) return $true }
        'Get-LumaBridgePnpInstances' = $getInstancesMock
        'Get-LumaBridgeDriverStorePackages' = $getPackagesMock
        'Set-LumaBridgeDeviceEnableVirtualMonitor' = { [CmdletBinding()] param([string]$DeviceParametersPath, [int]$Value) }
        'Invoke-LumaBridgeExternalCommand' = {
            [CmdletBinding()] param([string]$FilePath, [string[]]$Arguments = @(), [switch]$DryRun)
            $global:LbTestState['Uninst'].Calls.Add(($Arguments -join ' '))
            if ($Arguments[0] -eq '/delete-driver') { $global:LbTestState['Uninst'].Removed = $true }
            return [pscustomobject]@{ ExitCode = 0; Output = @('OK'); DryRun = $false }
        }
    } -Body {
        $res2 = & (Join-Path $scriptsDir 'Uninstall-LumaBridgeDriver.ps1') -ForceDriverStoreDelete -Force
        Assert-True ($res2.RollbackClean) 'Opt-in force uninstall succeeds cleanly'
        Assert-Equal $global:LbTestState['Uninst'].Calls[1] '/delete-driver oem42.inf /uninstall /force' 'Opt-in -ForceDriverStoreDelete must pass /force'
    }
}

# 16. Uninstall certificate removal requires valid SHA-1 thumbprint and explicit confirmation
Invoke-UnitTest -Name 'UninstallCertificateRemovalRequiresThumbprintAndConfirmation' -TestBody {
    param($caseDir)
    $targetThumb = 'AABBCCDDEEFF00112233445566778899AABBCCDD'
    $otherThumb = '1111222233334444555566667777888899990000'
    $global:LbTestState['TargetThumb'] = $targetThumb
    $global:LbTestState['OtherThumb'] = $otherThumb
    $global:LbTestState['RemovedCertPaths'] = New-Object System.Collections.Generic.List[string]

    Invoke-WithModuleMocks -GlobalMocks @{
        'Assert-LumaBridgeAdministrator' = { [CmdletBinding()] param([string]$OperationName, [switch]$DryRun) return $true }
        'Get-LumaBridgePnpInstances' = { [CmdletBinding()] param([string]$HardwareId) return @() }
        'Get-LumaBridgeDriverStorePackages' = { [CmdletBinding()] param([string]$InfFilter) return @() }
    } -Body {
        Assert-Throws {
            & (Join-Path $scriptsDir 'Uninstall-LumaBridgeDriver.ps1') -RemoveTestCertificate -Force
        } -ExpectedPattern 'requires -CertificateThumbprint' -Message 'Must reject missing thumbprint'

        Assert-Throws {
            & (Join-Path $scriptsDir 'Uninstall-LumaBridgeDriver.ps1') -RemoveTestCertificate -CertificateThumbprint 'INVALID' -Force
        } -ExpectedPattern '40-character hexadecimal' -Message 'Must reject invalid thumbprint format'
    }

    Invoke-WithModuleMocks -GlobalMocks @{
        'Assert-LumaBridgeAdministrator' = { [CmdletBinding()] param([string]$OperationName, [switch]$DryRun) return $true }
        'Get-LumaBridgePnpInstances' = { [CmdletBinding()] param([string]$HardwareId) return @() }
        'Get-LumaBridgeDriverStorePackages' = { [CmdletBinding()] param([string]$InfFilter) return @() }
        'Confirm-LumaBridgeAction' = {
            [CmdletBinding()] param([string]$PromptMessage, [switch]$DryRun, [switch]$Force)
            return [bool]$Force
        }
    } -ModuleMocks @{
        'Test-Path' = {
            [CmdletBinding()] param([string]$LiteralPath, [string]$Path, [Microsoft.PowerShell.Commands.TestPathType]$PathType)
            if ($LiteralPath -like 'Cert:\*') { return $true }
            return Microsoft.PowerShell.Management\Test-Path @PSBoundParameters
        }
        'Get-ChildItem' = {
            [CmdletBinding()] param([string]$Path, [string]$LiteralPath, [switch]$Force)
            if ($Path -like 'Cert:\*') {
                return @(
                    [pscustomobject]@{ Thumbprint = $global:LbTestState['TargetThumb']; Subject = 'CN=LumaBridge Test Driver Signing' },
                    [pscustomobject]@{ Thumbprint = $global:LbTestState['OtherThumb']; Subject = 'CN=LumaBridge Test Driver Signing' }
                )
            }
            return Microsoft.PowerShell.Management\Get-ChildItem @PSBoundParameters
        }
        'Remove-Item' = {
            [CmdletBinding()] param([string]$LiteralPath, [switch]$Force)
            if ($LiteralPath -like 'Cert:\*') {
                $global:LbTestState['RemovedCertPaths'].Add($LiteralPath)
                return
            }
            Microsoft.PowerShell.Management\Remove-Item @PSBoundParameters
        }
    } -Body {
        $resNoCertConfirm = & (Join-Path $scriptsDir 'Uninstall-LumaBridgeDriver.ps1') -RemoveTestCertificate -CertificateThumbprint $targetThumb -Force
        Assert-Equal $resNoCertConfirm.RemovedCertificates.Count 0 'Certs must NOT be removed without explicit cert confirmation'

        $resConfirmed = & (Join-Path $scriptsDir 'Uninstall-LumaBridgeDriver.ps1') -RemoveTestCertificate -CertificateThumbprint $targetThumb -ConfirmCertificateRemoval -Force
        Assert-Equal $resConfirmed.RemovedCertificates.Count 3 'Matching thumbprint removed from all 3 stores'
        Assert-Equal (@($resConfirmed.RemovedCertificates | Where-Object { $_ -like "*$otherThumb*" }).Count) 0 'Unrelated cert with same Subject must NOT be removed'
    }
}

# 17. Diagnostics specifically identifies the LumaBridge WUDFHost.exe process
Invoke-UnitTest -Name 'DiagnosticsIdentifiesLumaBridgeWudfHostProcess' -TestBody {
    param($caseDir)
    $diagOutDir = Join-Path $caseDir 'diag_out'
    $traceLog = Join-Path $caseDir 'debugview.log'
    @(
        '[14:00:01] [3003] [LB-DRIVER] [INFO] stage=MonitorArrival status=0x00000000 state=AdapterReady msg="ok"',
        '[14:00:02] [3003] [LB-DRIVER] [METRICS] stage=MonitorAssignSwapChain adapterState=AdapterReady monitorState=Arrived monCreate=1 monArrive=1 monDepart=0 monDepartFail=0 scState=Active scActive=1 scAssigned=1 scDeleted=0 framesAcq=60 framesProc=60 framesDrop=0 acqFps=60.00 procFps=60.00 lastUs=120 avgUs=130 maxUs=200 dxgiDevRem=0 transientErr=0 fatalErr=0 wsKB=24000 privKB=12000 handles=350'
    ) | Out-File -LiteralPath $traceLog -Encoding ascii

    $global:LbTestState['DiagPnp'] = @([pscustomobject]@{
        InstanceId           = 'ROOT\DISPLAY\0000'
        FriendlyName         = 'LumaBridge Indirect Display Adapter'
        Status               = 'OK'
        ProblemCode          = 0
        Present              = $true
        HardwareIds          = @('Root\LumaBridgeIddDriver')
        DeviceParametersPath = 'MOCK:\ROOT\DISPLAY\0000\Device Parameters'
        EnableVirtualMonitor = 1
    })

    $global:LbTestState['DiagRawProcs'] = @(
        [pscustomobject]@{
            Id = 1001; StartTimeUtc = '2026-11-18T10:00:00Z'; WorkingSetMB = 12.0; PrivateMemoryMB = 2.5
            HandleCount = 250; ThreadCount = 5; TotalProcessorSec = 0.2; CommandLine = $null
            LoadedModules = @([pscustomobject]@{ ModuleName = 'HidCfu.dll'; FileName = 'C:\Windows\System32\Drivers\UMDF\HidCfu.dll' })
        },
        [pscustomobject]@{
            Id = 2002; StartTimeUtc = '2026-11-18T10:05:00Z'; WorkingSetMB = 34.5; PrivateMemoryMB = 18.2
            HandleCount = 410; ThreadCount = 9; TotalProcessorSec = 1.4; CommandLine = $null
            LoadedModules = @([pscustomobject]@{ ModuleName = 'LumaBridgeIddDriver.dll'; FileName = 'C:\Windows\System32\DriverStore\FileRepository\lumabridge.inf_amd64_123\LumaBridgeIddDriver.dll' })
        },
        [pscustomobject]@{
            Id = 3003; StartTimeUtc = '2026-11-18T10:06:00Z'; WorkingSetMB = 22.0; PrivateMemoryMB = 8.0
            HandleCount = 300; ThreadCount = 6; TotalProcessorSec = 0.5; CommandLine = $null
            LoadedModules = @()
        }
    )

    Invoke-WithModuleMocks -GlobalMocks @{
        'Get-LumaBridgePnpInstances' = { [CmdletBinding()] param([string]$HardwareId) return $global:LbTestState['DiagPnp'] }
        'Get-LumaBridgeDriverStorePackages' = { [CmdletBinding()] param([string]$InfFilter) return @() }
        'Get-WinEvent' = { [CmdletBinding()] param([hashtable]$FilterHashtable, [int]$MaxEvents) return @() }
    } -ModuleMocks @{
        'Get-LumaBridgePnpInstances' = { [CmdletBinding()] param([string]$HardwareId) return $global:LbTestState['DiagPnp'] }
        'Get-LumaBridgeDriverStorePackages' = { [CmdletBinding()] param([string]$InfFilter) return @() }
        'Get-LumaBridgeRawWudfProcesses' = { [CmdletBinding()] param() return $global:LbTestState['DiagRawProcs'] }
    } -Body {
        $diag = & (Join-Path $scriptsDir 'Collect-LumaBridgeDiagnostics.ps1') -Configuration Release -OutputDir $diagOutDir -DebugLogPath $traceLog
        Assert-True ($null -ne $diag.Summary.LumaBridgeWudfHostProcess) 'Primary LumaBridge WUDFHost process must be identified'
        Assert-Equal $diag.Summary.LumaBridgeWudfHostProcess.Id 2002 'LoadedModule WUDFHost PID 2002 identified'
        Assert-Equal $diag.Summary.LumaBridgeWudfHostProcess.AssociationMethod 'LoadedModule' 'Association method recorded'
        Assert-Equal $diag.Summary.LumaBridgeWudfHostProcesses.Count 2 'PID 2002 (LoadedModule) and PID 3003 (DebugTracePid) correlated; unrelated PID 1001 excluded'
        Assert-Equal (@($diag.Summary.WudfHostProcesses | Where-Object { $_.Id -eq 1001 })[0].IsLumaBridgeHost) $false 'Unrelated WUDFHost PID 1001 must not be flagged'
        Assert-True (Test-Path -LiteralPath $diag.JsonReportPath) 'JSON diagnostics file created'
        Assert-True (Test-Path -LiteralPath $diag.MarkdownReportPath) 'Markdown diagnostics file created'
    }
}

# 18. DryRun across all scripts executes without mutating state
Invoke-UnitTest -Name 'AllScriptsDryRunDoNotMutateSystemState' -TestBody {
    param($caseDir)
    $stg = Join-Path $caseDir 'dry_stg'

    $prereqOut = & (Join-Path $scriptsDir 'Test-LumaBridgePrerequisites.ps1') -Configuration Release
    Assert-True ($prereqOut.BuildPackage.AllFilesPresent) 'Release build artifacts must be present'

    & (Join-Path $scriptsDir 'Invoke-LumaBridgePackageSigning.ps1') -Configuration Release -StagingDir $stg -CreateTestCertificateIfMissing -DryRun | Out-Null
    Assert-Equal (Test-Path -LiteralPath $stg) $false 'Signing DryRun must not create staging dir'

    & (Join-Path $scriptsDir 'Install-LumaBridgeDriver.ps1') -Configuration Release -StagingDir $stg -DryRun | Out-Null

    Invoke-WithModuleMocks -GlobalMocks @{
        'Get-LumaBridgePnpInstances' = {
            [CmdletBinding()] param([string]$HardwareId)
            return @([pscustomobject]@{
                InstanceId           = 'ROOT\DISPLAY\DRY0'
                DeviceParametersPath = 'MOCK:\ROOT\DISPLAY\DRY0\Device Parameters'
                EnableVirtualMonitor = 0
            })
        }
    } -Body {
        & (Join-Path $scriptsDir 'Set-LumaBridgeVirtualMonitor.ps1') -Action Enable -DryRun | Out-Null
    }

    $diagDry = & (Join-Path $scriptsDir 'Collect-LumaBridgeDiagnostics.ps1') -Configuration Release -OutputDir (Join-Path $caseDir 'dry_diag') -DryRun
    Assert-True ($diagDry.DryRun -eq $true) 'Collect diagnostics DryRun returns DryRun=true'
    Assert-Equal (Test-Path -LiteralPath (Join-Path $caseDir 'dry_diag')) $false 'Diagnostics DryRun must not create OutputDir'

    & (Join-Path $scriptsDir 'Uninstall-LumaBridgeDriver.ps1') -RemoveTestCertificate -CertificateThumbprint '00112233445566778899AABBCCDDEEFF00112233' -DryRun | Out-Null
}

try {
    Write-Host ("Summary: {0} tests run, {1} assertion failures." -f $script:TestsRun, $script:TestsFailed)
}
finally {
    Remove-Variable -Name 'LbTestState' -Scope Global -ErrorAction SilentlyContinue
    if (Test-Path -LiteralPath $script:TestTempRoot) {
        Microsoft.PowerShell.Management\Remove-Item -LiteralPath $script:TestTempRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

if ($script:TestsFailed -ne 0) {
    exit 1
}
exit 0
