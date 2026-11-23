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
        'Get-WinEvent' = { [CmdletBinding()] param([hashtable]$FilterHashtable, [int]$MaxEvents) return @() }
        'Get-LumaBridgeEventChannelStatus' = { [CmdletBinding()] param([string[]]$ChannelNames) return @() }
        'Get-LumaBridgeDiagnosticEvents' = { [CmdletBinding()] param([int]$LookbackMinutes, [string[]]$InstanceIds, [string[]]$PublishedInfNames, [object[]]$ChannelStatus) return @() }
        'Get-LumaBridgeSetupApiLogExcerpt' = { [CmdletBinding()] param([string]$SetupApiLogPath, [string[]]$InstanceIds, [string[]]$PublishedInfNames, [int]$MaxMatchedSections) return [pscustomobject]@{ LogPath = $SetupApiLogPath; Exists = $false; AccessDenied = $false; Error = ''; MatchedSectionCount = 0; WdfSchemaWarnings = @(); DeviceStartProblemLines = @(); Sections = @(); RawExcerptText = '' } }
        'Get-LumaBridgeCrashDumpInventory' = { [CmdletBinding()] param([int]$LookbackMinutes) return [pscustomobject]@{ LookbackMinutes = $LookbackMinutes; Locations = @(); Files = @(); TotalFoundCount = 0 } }
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
        $diagDir = Join-Path $caseDir 'rb_fresh_diag'
        Assert-Throws {
            & (Join-Path $scriptsDir 'Install-LumaBridgeDriver.ps1') -Configuration Release -StagingDir $pkgDir -AllowUntrustedChain -DiagnosticsOutputDir $diagDir -Force
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
        'Get-WinEvent' = { [CmdletBinding()] param([hashtable]$FilterHashtable, [int]$MaxEvents) return @() }
        'Get-LumaBridgeEventChannelStatus' = { [CmdletBinding()] param([string[]]$ChannelNames) return @() }
        'Get-LumaBridgeDiagnosticEvents' = { [CmdletBinding()] param([int]$LookbackMinutes, [string[]]$InstanceIds, [string[]]$PublishedInfNames, [object[]]$ChannelStatus) return @() }
        'Get-LumaBridgeSetupApiLogExcerpt' = { [CmdletBinding()] param([string]$SetupApiLogPath, [string[]]$InstanceIds, [string[]]$PublishedInfNames, [int]$MaxMatchedSections) return [pscustomobject]@{ LogPath = $SetupApiLogPath; Exists = $false; AccessDenied = $false; Error = ''; MatchedSectionCount = 0; WdfSchemaWarnings = @(); DeviceStartProblemLines = @(); Sections = @(); RawExcerptText = '' } }
        'Get-LumaBridgeCrashDumpInventory' = { [CmdletBinding()] param([int]$LookbackMinutes) return [pscustomobject]@{ LookbackMinutes = $LookbackMinutes; Locations = @(); Files = @(); TotalFoundCount = 0 } }
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
        $diagDir = Join-Path $caseDir 'rb_upd_diag'
        Assert-Throws {
            & (Join-Path $scriptsDir 'Install-LumaBridgeDriver.ps1') -Configuration Release -StagingDir $pkgDir -AllowUntrustedChain -DiagnosticsOutputDir $diagDir -Force
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
        'Get-LumaBridgeEventChannelStatus' = { [CmdletBinding()] param([string[]]$ChannelNames) return @() }
        'Get-LumaBridgeDiagnosticEvents' = { [CmdletBinding()] param([int]$LookbackMinutes, [string[]]$InstanceIds, [string[]]$PublishedInfNames, [object[]]$ChannelStatus) return @() }
        'Get-LumaBridgeSetupApiLogExcerpt' = { [CmdletBinding()] param([string]$SetupApiLogPath, [string[]]$InstanceIds, [string[]]$PublishedInfNames, [int]$MaxMatchedSections) return [pscustomobject]@{ LogPath = $SetupApiLogPath; Exists = $false; AccessDenied = $false; Error = ''; MatchedSectionCount = 0; WdfSchemaWarnings = @(); DeviceStartProblemLines = @(); Sections = @(); RawExcerptText = '' } }
        'Get-LumaBridgeCrashDumpInventory' = { [CmdletBinding()] param([int]$LookbackMinutes) return [pscustomobject]@{ LookbackMinutes = $LookbackMinutes; Locations = @(); Files = @(); TotalFoundCount = 0 } }
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

    $etwDryDir = Join-Path $caseDir 'dry_etw'
    $etwStartDry = & (Join-Path $scriptsDir 'Invoke-LumaBridgeEtwTrace.ps1') -Action Start -OutputDir $etwDryDir -DryRun
    Assert-True ($etwStartDry.DryRun -eq $true) 'ETW Start DryRun returns DryRun=true'
    Assert-Equal (Test-Path -LiteralPath $etwDryDir) $false 'ETW Start DryRun must not create OutputDir'
    $etwStopDry = & (Join-Path $scriptsDir 'Invoke-LumaBridgeEtwTrace.ps1') -Action Stop -OutputDir $etwDryDir -DryRun
    Assert-True ($etwStopDry.DryRun -eq $true) 'ETW Stop DryRun returns DryRun=true'
    $etwStatusDry = & (Join-Path $scriptsDir 'Invoke-LumaBridgeEtwTrace.ps1') -Action Status -OutputDir $etwDryDir -DryRun
    Assert-True ($etwStatusDry.DryRun -eq $true) 'ETW Status DryRun returns DryRun=true'
    Assert-True (@($etwStatusDry.EventChannels).Count -ge 1) 'ETW Status queries channel status metadata'

    & (Join-Path $scriptsDir 'Uninstall-LumaBridgeDriver.ps1') -RemoveTestCertificate -CertificateThumbprint '00112233445566778899AABBCCDDEEFF00112233' -DryRun | Out-Null
}

# 19. PnP ProblemStatus (0xC000009E), UpperFilters, and Diag* startup breadcrumbs are collected and surfaced
Invoke-UnitTest -Name 'PnpProblemStatusAndStartupBreadcrumbsCollected' -TestBody {
    param($caseDir)
    Assert-Equal (Format-LumaBridgeNtStatusHex -StatusValue -1073741666) '0xC000009E' 'Signed INT32 NTSTATUS formats as 0xC000009E'
    Assert-Equal (Format-LumaBridgeNtStatusHex -StatusValue ([uint32]3221225630)) '0xC000009E' 'Unsigned UINT32 NTSTATUS formats as 0xC000009E'
    Assert-Equal (Format-LumaBridgeNtStatusHex -StatusValue 0) '0x00000000' 'Zero status formats cleanly'

    $mockRegPath = 'MOCK:\SYSTEM\CurrentControlSet\Enum\ROOT\DISPLAY\0000\Device Parameters'
    $global:LbTestState['MockRegPath'] = $mockRegPath

    $mockPnpDevice = [pscustomobject]@{
        InstanceId   = 'ROOT\DISPLAY\0000'
        FriendlyName = 'LumaBridge Indirect Display Adapter'
        Status       = 'Error'
        Present      = $true
        HardwareID   = @('Root\LumaBridgeIddDriver')
        Class        = 'Display'
    }

    $propMock = {
        param([string]$InstanceId, [string]$KeyName)
        switch ($KeyName) {
            'DEVPKEY_Device_HardwareIds'    { return @('Root\LumaBridgeIddDriver') }
            'DEVPKEY_Device_ProblemCode'    { return 10 }
            'DEVPKEY_Device_ProblemStatus'  { return -1073741666 }
            'DEVPKEY_Device_DriverInfPath'  { return 'oem68.inf' }
            'DEVPKEY_Device_DriverProvider' { return 'LumaBridge' }
            'DEVPKEY_Device_DriverVersion'  { return '21.24.54.993' }
            'DEVPKEY_Device_Service'        { return 'WUDFRd' }
            'DEVPKEY_Device_UpperFilters'   { return @('IndirectKmd') }
            'DEVPKEY_Device_LowerFilters'   { return @() }
            default                         { return $null }
        }
    }

    $diagRegProps = [pscustomobject]@{
        DiagLastStage           = 'AdapterInitAsync'
        DiagLastSuccessfulStage = 'IddCxDeviceInitialize'
        DiagLastStatus          = -1073741666
        DiagLastErrorStage      = 'AdapterInitAsync'
        DiagLastErrorStatus     = -1073741666
        DiagIddCxVersion        = 0x00010400
        DiagHostProcessId       = 7420
        DiagDllAttachCount      = 1
    }

    $global:LbTestState['PropMockObj'] = $mockPnpDevice
    $global:LbTestState['DiagRegProps'] = $diagRegProps

    Invoke-WithModuleMocks -GlobalMocks @{
        'Get-PnpDevice' = { [CmdletBinding()] param() return @($global:LbTestState['PropMockObj']) }
    } -ModuleMocks @{
        'Get-PnpDevice' = { [CmdletBinding()] param() return @($global:LbTestState['PropMockObj']) }
        'Get-LumaBridgeDevicePropertyData' = $propMock
        'Get-LumaBridgeDeviceParametersRegistryPath' = { param([string]$InstanceId) return $global:LbTestState['MockRegPath'] }
        'Get-LumaBridgeDeviceEnableVirtualMonitor' = { param([string]$DeviceParametersPath) return 0 }
        'Test-Path' = {
            param([string]$LiteralPath, [string]$PathType)
            if ($LiteralPath -eq $global:LbTestState['MockRegPath']) { return $true }
            if ($PathType) { return (Microsoft.PowerShell.Management\Test-Path -LiteralPath $LiteralPath -PathType $PathType) }
            return (Microsoft.PowerShell.Management\Test-Path -LiteralPath $LiteralPath)
        }
        'Get-ItemProperty' = {
            param([string]$LiteralPath)
            if ($LiteralPath -eq $global:LbTestState['MockRegPath']) { return $global:LbTestState['DiagRegProps'] }
            return (Microsoft.PowerShell.Management\Get-ItemProperty -LiteralPath $LiteralPath)
        }
    } -Body {
        $instances = @(Get-LumaBridgePnpInstances)
        Assert-Equal $instances.Count 1 'Exactly one PnP instance parsed'
        Assert-Equal $instances[0].ProblemCode 10 'ProblemCode=10 preserved'
        Assert-Equal $instances[0].ProblemStatusHex '0xC000009E' 'DEVPKEY_Device_ProblemStatus formatted as 0xC000009E'
        Assert-True (@($instances[0].UpperFilters) -contains 'IndirectKmd') 'UpperFilters contains IndirectKmd'
        Assert-True ($null -ne $instances[0].StartupDiagnostics) 'Diag* startup breadcrumbs collected'
        Assert-Equal $instances[0].StartupDiagnostics.LastSuccessfulStage 'IddCxDeviceInitialize' 'LastSuccessfulStage decoded'
        Assert-Equal $instances[0].StartupDiagnostics.LastErrorStatusHex '0xC000009E' 'LastErrorStatusHex decoded'
        Assert-Equal $instances[0].StartupDiagnostics.IddCxRuntimeVerHex '0x00010400' 'IddCx runtime version decoded'

        $binding = Test-LumaBridgeDeviceDriverBinding -Instance $instances[0]
        Assert-Equal $binding.IsBound $false 'Failed start must fail binding check'
        Assert-Equal $binding.ProblemStatusHex '0xC000009E' 'Binding output exposes ProblemStatusHex'
        Assert-True (($binding.Reasons -join '; ') -match 'ProblemStatus is 0xC000009E') 'Binding reason explains ProblemStatus'
    }
}

# 20. Install failure captures SetupAPI, ProblemStatus, and stage diagnostics BEFORE rollback removes device & OEM INF
Invoke-UnitTest -Name 'InstallFailurePreservesPreRollbackDiagnosticsBeforeCleanup' -TestBody {
    param($caseDir)
    $certInfo = New-EphemeralTestCertificate -OutDirectory (Join-Path $caseDir 'certs') -NamePrefix 'prerollback'
    $pkgDir = Join-Path $caseDir 'pkg'
    New-SignedTestPackage -TargetDir $pkgDir -CertInfo $certInfo -ExportCerAsPackageFile

    $setupApiLog = Join-Path $caseDir 'setupapi.dev.log'
    @(
        '>>>  [Device Install (Hardware initiated) - ROOT\DISPLAY\0000]',
        '>>>  Section start 2026/11/18 20:52:06.472',
        '     dvi: {Plug and Play Service: Device Install for ROOT\DISPLAY\0000}',
        '     inf: {SetupCopyOEMInf: oem68.inf}',
        '     ndv: Using WDF schema version 2.23 when section requires version 2.31. Section = [LumaBridge_Install.NT.Wdf]',
        '!!!  dvi: Device not started: Device has problem: 0x0a (CM_PROB_FAILED_START), problem status: 0xc000009e.',
        '<<<  Section end 2026/11/18 20:52:07.120',
        '<<<  [Exit status: SUCCESS]'
    ) | Set-Content -LiteralPath $setupApiLog -Encoding UTF8

    $traceLog = Join-Path $caseDir 'driver_trace.log'
    @(
        '[1] [LB-DRIVER] [INFO] pid=7420 tid=100 stage=DriverEntry status=0x00000000 state=Uninitialized lastOk=DllProcessAttach msg="DriverEntry entered"',
        '[2] [LB-DRIVER] [INFO] pid=7420 tid=100 stage=DeviceD0Entry status=0x00000000 state=DeviceInitialized lastOk=IddCxDeviceInitialize msg="EvtDeviceD0Entry entered"',
        '[3] [LB-DRIVER] [ERROR] pid=7420 tid=100 stage=AdapterInitAsync status=0xC000009E state=AdapterFailed lastOk=DeviceD0Entry msg="IddCxAdapterInitAsync failed"'
    ) | Set-Content -LiteralPath $traceLog -Encoding UTF8

    $diagOutDir = Join-Path $caseDir 'preserved_diag'
    $global:LbTestState['PreRb'] = [ordered]@{
        HasPkg        = $false
        HasDevice     = $false
        SetupApiPath  = $setupApiLog
        RealSetupParser = (Get-Command Get-LumaBridgeSetupApiLogExcerpt).ScriptBlock
    }

    $getInstancesPreRb = {
        [CmdletBinding()] param([string]$HardwareId)
        if (-not $global:LbTestState['PreRb'].HasDevice) { return @() }
        return @([pscustomobject]@{
            InstanceId           = 'ROOT\DISPLAY\0000'
            FriendlyName         = 'LumaBridge Indirect Display Adapter'
            Status               = 'Error'
            ProblemCode          = 10
            ProblemStatus        = -1073741666
            ProblemStatusHex     = '0xC000009E'
            Present              = $true
            HardwareIds          = @('Root\LumaBridgeIddDriver')
            DriverInfPath        = 'oem68.inf'
            DriverProvider       = 'LumaBridge'
            DriverVersion        = '21.24.54.993'
            DriverService        = 'WUDFRd'
            UpperFilters         = @('IndirectKmd')
            LowerFilters         = @()
            ConfigurationId      = 'oem68.inf:Root\LumaBridgeIddDriver'
            DeviceParametersPath = 'MOCK:\ROOT\DISPLAY\0000\Device Parameters'
            EnableVirtualMonitor = 0
            StartupDiagnostics   = [pscustomobject]@{
                LastStage           = 'AdapterInitAsync'
                LastSuccessfulStage = 'DeviceD0Entry'
                LastStatus          = -1073741666
                LastStatusHex       = '0xC000009E'
                LastErrorStage      = 'AdapterInitAsync'
                LastErrorStatus     = -1073741666
                LastErrorStatusHex  = '0xC000009E'
                IddCxRuntimeVersion = 0x00010400
                IddCxRuntimeVerHex  = '0x00010400'
                HostProcessId       = 7420
                DllAttachCount      = 1
            }
        })
    }

    $getPackagesPreRb = {
        [CmdletBinding()] param([string]$InfFilter)
        if (-not $global:LbTestState['PreRb'].HasPkg) { return @() }
        return @([pscustomobject]@{
            PublishedName = 'oem68.inf'
            OriginalName  = 'lumabridgeidddriver.inf'
            ProviderName  = 'LumaBridge'
            ClassGuid     = '{4d36e968-e325-11ce-bfc1-08002be10318}'
        })
    }

    Invoke-WithModuleMocks -GlobalMocks @{
        'Assert-LumaBridgeAdministrator' = { [CmdletBinding()] param([string]$OperationName, [switch]$DryRun) return $true }
        'Get-LumaBridgeHostSecurityState' = { [CmdletBinding()] param() return [pscustomobject]@{ SecureBoot = 'Disabled'; TestSigning = 'Enabled' } }
        'Get-LumaBridgePnpInstances' = $getInstancesPreRb
        'Get-LumaBridgeDriverStorePackages' = $getPackagesPreRb
        'Get-WinEvent' = { [CmdletBinding()] param([hashtable]$FilterHashtable, [int]$MaxEvents) return @() }
        'Get-LumaBridgeEventChannelStatus' = { [CmdletBinding()] param([string[]]$ChannelNames) return @() }
        'Get-LumaBridgeDiagnosticEvents' = { [CmdletBinding()] param([int]$LookbackMinutes, [string[]]$InstanceIds, [string[]]$PublishedInfNames, [object[]]$ChannelStatus) return @() }
        'Get-LumaBridgeCrashDumpInventory' = { [CmdletBinding()] param([int]$LookbackMinutes) return [pscustomobject]@{ LookbackMinutes = $LookbackMinutes; Locations = @(); Files = @(); TotalFoundCount = 0 } }
        'Get-LumaBridgeSetupApiLogExcerpt' = {
            [CmdletBinding()]
            param([string]$SetupApiLogPath, [string[]]$InstanceIds, [string[]]$PublishedInfNames, [int]$MaxMatchedSections = 10)
            & $global:LbTestState['PreRb'].RealSetupParser -SetupApiLogPath $global:LbTestState['PreRb'].SetupApiPath -InstanceIds $InstanceIds -PublishedInfNames $PublishedInfNames -MaxMatchedSections $MaxMatchedSections
        }
        'Set-LumaBridgeDeviceEnableVirtualMonitor' = { [CmdletBinding()] param([string]$DeviceParametersPath, [int]$Value) }
        'Invoke-LumaBridgeExternalCommand' = {
            [CmdletBinding()] param([string]$FilePath, [string[]]$Arguments = @(), [switch]$DryRun)
            if ($FilePath -like '*pnputil*' -and $Arguments[0] -eq '/add-driver') {
                $global:LbTestState['PreRb'].HasPkg = $true
            }
            elseif ($FilePath -like '*devcon*' -and $Arguments[0] -eq 'install') {
                $global:LbTestState['PreRb'].HasDevice = $true
            }
            elseif ($FilePath -like '*pnputil*' -and $Arguments[0] -eq '/remove-device') {
                $global:LbTestState['PreRb'].HasDevice = $false
            }
            elseif ($FilePath -like '*pnputil*' -and $Arguments[0] -eq '/delete-driver') {
                $global:LbTestState['PreRb'].HasPkg = $false
            }
            return [pscustomobject]@{ ExitCode = 0; Output = @('OK'); DryRun = $false }
        }
    } -ModuleMocks @{
        'Get-LumaBridgeHostSecurityState' = { [CmdletBinding()] param() return [pscustomobject]@{ SecureBoot = 'Disabled'; TestSigning = 'Enabled' } }
        'Get-LumaBridgePnpInstances' = $getInstancesPreRb
        'Get-LumaBridgeDriverStorePackages' = $getPackagesPreRb
    } -Body {
        Assert-Throws {
            & (Join-Path $scriptsDir 'Install-LumaBridgeDriver.ps1') `
                -Configuration Release `
                -StagingDir $pkgDir `
                -AllowUntrustedChain `
                -DiagnosticsOutputDir $diagOutDir `
                -DebugLogPath $traceLog `
                -Force
        } -ExpectedPattern 'Diagnostics preserved at.*ProblemStatus=0xC000009E.*LastSuccessfulStage=DeviceD0Entry' -Message 'Install failure message must include preserved diagnostics path and ProblemStatus'

        # Verify rollback actually removed both device and oem68.inf
        Assert-Equal $global:LbTestState['PreRb'].HasDevice $false 'Rollback must remove ROOT\DISPLAY\0000'
        Assert-Equal $global:LbTestState['PreRb'].HasPkg $false 'Rollback must delete oem68.inf'

        # Verify pre-rollback evidence persisted across rollback!
        $summaryJsonPath = Join-Path $diagOutDir 'diagnostics-summary.json'
        $summaryMdPath = Join-Path $diagOutDir 'diagnostics-summary.md'
        $setupExcerptPath = Join-Path $diagOutDir 'setupapi-excerpt.log'
        $postRollbackPath = Join-Path $diagOutDir 'post-rollback-status.json'

        Assert-True (Test-Path -LiteralPath $summaryJsonPath) 'Pre-rollback diagnostics-summary.json preserved'
        Assert-True (Test-Path -LiteralPath $summaryMdPath) 'Pre-rollback diagnostics-summary.md preserved'
        Assert-True (Test-Path -LiteralPath $setupExcerptPath) 'Pre-rollback setupapi-excerpt.log preserved'
        Assert-True (Test-Path -LiteralPath $postRollbackPath) 'post-rollback-status.json preserved'

        $summaryJson = Get-Content -LiteralPath $summaryJsonPath -Raw | ConvertFrom-Json
        Assert-Equal $summaryJson.Prerequisites.PnpInstances.Count 1 'Pre-rollback snapshot captured PnP instance before removal'
        Assert-Equal $summaryJson.Prerequisites.PnpInstances[0].ProblemCode 10 'Pre-rollback snapshot captured ProblemCode=10'
        Assert-Equal $summaryJson.Prerequisites.PnpInstances[0].ProblemStatusHex '0xC000009E' 'Pre-rollback snapshot captured ProblemStatusHex=0xC000009E'
        Assert-Equal $summaryJson.Prerequisites.PnpInstances[0].DriverInfPath 'oem68.inf' 'Pre-rollback snapshot captured oem68.inf'
        Assert-Equal $summaryJson.StageExecutionSummary.LastSuccessfulStage 'DeviceD0Entry' 'Pre-rollback snapshot captured LastSuccessfulStage'
        Assert-Equal $summaryJson.StageExecutionSummary.FirstFailureStage 'AdapterInitAsync' 'Pre-rollback snapshot captured FirstFailureStage'
        Assert-Equal $summaryJson.StageExecutionSummary.FirstFailureStatusHex '0xC000009E' 'Pre-rollback snapshot captured FirstFailureStatusHex'
        Assert-True ($summaryJson.SetupApiExcerpt.MatchedSectionCount -ge 1) 'Pre-rollback SetupAPI excerpt matched section'

        $postRbJson = Get-Content -LiteralPath $postRollbackPath -Raw | ConvertFrom-Json
        Assert-Equal $postRbJson.PreRollbackDiagCaptured $true 'post-rollback confirms pre-rollback capture succeeded'
        Assert-Equal @($postRbJson.RemainingInstances).Count 0 'post-rollback confirms 0 remaining instances'
        Assert-Equal @($postRbJson.RemainingDriverStorePackages).Count 0 'post-rollback confirms 0 remaining OEM packages'
    }
}

# 21. SetupAPI excerpt parser and multi-channel event collector filter relevant records accurately
Invoke-UnitTest -Name 'SetupApiExcerptAndEventChannelCollection' -TestBody {
    param($caseDir)
    $syntheticLog = Join-Path $caseDir 'setupapi.dev.log'
    @(
        '>>>  [Device Install (Hardware initiated) - USB\VID_0000&PID_0001\123]',
        '>>>  Section start 2026/11/18 19:00:00.000',
        '     dvi: unrelated usb device install',
        '<<<  Section end 2026/11/18 19:00:01.000',
        '<<<  [Exit status: SUCCESS]',
        '',
        '>>>  [Device Install (Hardware initiated) - ROOT\DISPLAY\0000]',
        '>>>  Section start 2026/11/18 20:52:06.472',
        '     inf: {SetupCopyOEMInf: oem68.inf}',
        '     ndv: Using WDF schema version 2.23 when section requires version 2.31. Section = [LumaBridge_Install.NT.Wdf]',
        '!!!  dvi: Device not started: Device has problem: 0x0a (CM_PROB_FAILED_START), problem status: 0xc000009e.',
        '<<<  Section end 2026/11/18 20:52:07.010',
        '<<<  [Exit status: SUCCESS]'
    ) | Set-Content -LiteralPath $syntheticLog -Encoding UTF8

    $excerpt = Get-LumaBridgeSetupApiLogExcerpt -SetupApiLogPath $syntheticLog -InstanceIds @('ROOT\DISPLAY\0000') -PublishedInfNames @('oem68.inf')
    Assert-Equal $excerpt.Exists $true 'Synthetic setupapi.dev.log exists'
    Assert-Equal $excerpt.MatchedSectionCount 1 'Only ROOT\DISPLAY\0000 section matches; unrelated USB section excluded'
    Assert-Equal $excerpt.WdfSchemaWarnings.Count 1 'WDF schema 2.23 vs 2.31 warning extracted'
    Assert-Equal $excerpt.DeviceStartProblemLines.Count 1 'CM_PROB_FAILED_START / 0xc000009e line extracted'
    Assert-True ($excerpt.RawExcerptText -notmatch 'USB\\VID_0000') 'Unrelated USB section must not appear in excerpt'

    $nowUtc = (Get-Date)
    $mockEventsByLog = @{
        'Microsoft-Windows-Kernel-PnP/Configuration' = @(
            [pscustomobject]@{
                TimeCreated = $nowUtc; LevelDisplayName = 'Error'; Level = 2; Id = 411; RecordId = 101; ProcessId = 4
                ProviderName = 'Microsoft-Windows-Kernel-PnP'
                Message = 'Device ROOT\DISPLAY\0000 had a problem starting. Status: 0xC000009E'
            }
        )
        'Microsoft-Windows-WerKernel/Operational' = @(
            [pscustomobject]@{
                TimeCreated = $nowUtc; LevelDisplayName = 'Information'; Level = 4; Id = 1001; RecordId = 202; ProcessId = 4
                ProviderName = 'Microsoft-Windows-WerKernel'
                Message = 'Component WATCHDOG has requested to create a Live Kernel Dump and the request has been completed.'
            }
        )
        'Microsoft-Windows-CodeIntegrity/Operational' = @(
            [pscustomobject]@{
                TimeCreated = $nowUtc; LevelDisplayName = 'Warning'; Level = 3; Id = 3033; RecordId = 303; ProcessId = 4
                ProviderName = 'Microsoft-Windows-CodeIntegrity'
                Message = 'Code Integrity warning check.'
            }
        )
    }
    $global:LbTestState['MockEventsByLog'] = $mockEventsByLog

    $channelStatus = @(
        [pscustomobject]@{ LogName = 'Microsoft-Windows-Kernel-PnP/Configuration'; IsEnabled = $true },
        [pscustomobject]@{ LogName = 'Microsoft-Windows-WerKernel/Operational'; IsEnabled = $true },
        [pscustomobject]@{ LogName = 'Microsoft-Windows-CodeIntegrity/Operational'; IsEnabled = $true },
        [pscustomobject]@{ LogName = 'Microsoft-Windows-IndirectDisplays-ClassExtension-Events/Diagnostic'; IsEnabled = $false }
    )

    Invoke-WithModuleMocks -GlobalMocks @{
        'Get-WinEvent' = {
            param([hashtable]$FilterHashtable, [int]$MaxEvents)
            $ln = $FilterHashtable.LogName
            if ($global:LbTestState['MockEventsByLog'].ContainsKey($ln)) {
                return $global:LbTestState['MockEventsByLog'][$ln]
            }
            return @()
        }
    } -ModuleMocks @{
        'Get-WinEvent' = {
            param([hashtable]$FilterHashtable, [int]$MaxEvents)
            $ln = $FilterHashtable.LogName
            if ($global:LbTestState['MockEventsByLog'].ContainsKey($ln)) {
                return $global:LbTestState['MockEventsByLog'][$ln]
            }
            return @()
        }
    } -Body {
        $events = @(Get-LumaBridgeDiagnosticEvents -LookbackMinutes 60 -InstanceIds @('ROOT\DISPLAY\0000') -PublishedInfNames @('oem68.inf') -ChannelStatus $channelStatus)
        Assert-True ((@($events | Where-Object { $_.Id -eq 411 -and $_.LogName -eq 'Microsoft-Windows-Kernel-PnP/Configuration' })).Count -eq 1) 'Kernel-PnP 411 captured'
        Assert-True ((@($events | Where-Object { $_.Id -eq 1001 -and $_.LogName -eq 'Microsoft-Windows-WerKernel/Operational' })).Count -eq 1) 'WerKernel 1001 WATCHDOG captured'
        Assert-True ((@($events | Where-Object { $_.Id -eq 3033 -and $_.LogName -eq 'Microsoft-Windows-CodeIntegrity/Operational' })).Count -eq 1) 'CodeIntegrity warning captured'
        Assert-True ((@($events | Where-Object { $_.LogName -eq 'Microsoft-Windows-IndirectDisplays-ClassExtension-Events/Diagnostic' })).Count -eq 0) 'Disabled channel skipped cleanly'
    }
}

# 22. Driver trace stage summary combines DebugView, TraceLogging ETL properties, and registry breadcrumbs
Invoke-UnitTest -Name 'DriverStageSummaryIdentifiesLastSuccessfulAndFailingStage' -TestBody {
    $traceLines = @(
        '[10] [LB-DRIVER] [INFO] pid=7420 tid=201 stage=DriverEntry status=0x00000000 state=Uninitialized lastOk=DllProcessAttach msg="DriverEntry entered"',
        '[11] [LB-DRIVER] [INFO] pid=7420 tid=201 stage=DeviceD0Entry status=0x00000000 state=DeviceInitialized lastOk=IddCxDeviceInitialize msg="EvtDeviceD0Entry entered"',
        '[12] [LB-DRIVER] [ERROR] pid=7420 tid=201 stage=AdapterInitAsync status=0xC000009E state=AdapterFailed lastOk=DeviceD0Entry msg="IddCxAdapterInitAsync failed"'
    )

    $etlEvents = @(
        [pscustomobject]@{
            ProviderName = 'LumaBridgeIddDriver'
            Properties   = @('INFO', 7420, 201, 'IddCxGetVersion', 0, 'AdapterInitPending', 'DeviceD0Entry', 'IddCxGetVersion succeeded')
        }
    )

    $regDiag = [pscustomobject]@{
        LastStage           = 'AdapterInitAsync'
        LastSuccessfulStage = 'DeviceD0Entry'
        LastStatusHex       = '0xC000009E'
        LastErrorStage      = 'AdapterInitAsync'
        LastErrorStatusHex  = '0xC000009E'
    }

    $summary = Get-LumaBridgeDriverTraceStageSummary -TraceLines $traceLines -StartupDiagnostics $regDiag -EtlEvents $etlEvents
    Assert-Equal $summary.DriverEntryReached $true 'DriverEntryReached detected'
    Assert-Equal $summary.LastSuccessfulStage 'DeviceD0Entry' 'LastSuccessfulStage identifies DeviceD0Entry'
    Assert-Equal $summary.FirstFailureStage 'AdapterInitAsync' 'FirstFailureStage identifies AdapterInitAsync'
    Assert-Equal $summary.FirstFailureStatusHex '0xC000009E' 'FirstFailureStatusHex is 0xC000009E'
    Assert-Equal $summary.StageRecordCount 4 'Combined DebugView + TraceLogging ETL record count'
    Assert-True ($summary.SourcesUsed -contains 'DebugView') 'SourcesUsed contains DebugView'
    Assert-True ($summary.SourcesUsed -contains 'TraceLoggingEtl') 'SourcesUsed contains TraceLoggingEtl'
    Assert-True ($summary.SourcesUsed -contains 'RegistryBreadcrumb') 'SourcesUsed contains RegistryBreadcrumb'
}

# 23. Crash dump inventory & ETW trace helper script work cleanly in isolation and DryRun
Invoke-UnitTest -Name 'CrashDumpInventoryAndEtwTraceDryRun' -TestBody {
    param($caseDir)
    $crashDir = Join-Path $caseDir 'CrashDumps'
    New-Item -Path $crashDir -ItemType Directory -Force | Out-Null
    [System.IO.File]::WriteAllBytes((Join-Path $crashDir 'WUDFHost.1234.dmp'), [byte[]]@(1, 2, 3, 4))

    $autoLoggerPath = Join-Path $caseDir 'Microsoft-Windows-Rdp-Graphics-RdpIdd-Trace.etl'
    [System.IO.File]::WriteAllBytes($autoLoggerPath, [byte[]]@(5, 6, 7, 8))

    $inv = Get-LumaBridgeCrashDumpInventory -LookbackMinutes 60 -LocalCrashDumpsDir $crashDir -DriverDataAutoLoggerPath $autoLoggerPath
    Assert-Equal (@($inv.Files | Where-Object { $_.Category -eq 'UserCrashDump' -and $_.Name -eq 'WUDFHost.1234.dmp' })).Count 1 'UserCrashDump WUDFHost.1234.dmp discovered'
    Assert-Equal (@($inv.Files | Where-Object { $_.Category -eq 'RdpIddAutoLoggerEtl' })).Count 1 'RdpIdd AutoLogger ETL discovered'

    $etwDir = Join-Path $caseDir 'etw_dry'
    $startDry = & (Join-Path $scriptsDir 'Invoke-LumaBridgeEtwTrace.ps1') -Action Start -IncludeDxgKrnl -OutputDir $etwDir -DryRun
    Assert-Equal $startDry.DryRun $true 'ETW Start DryRun works'
    Assert-Equal @($startDry.CoreProviders).Count 6 'ETW Start Core session has 6 providers'
    Assert-Equal @($startDry.DxgProviders).Count 2 'ETW Start with -IncludeDxgKrnl adds 2 Dxg providers in separate session'
    Assert-Equal @($startDry.Providers).Count 6 'ETW Start compatibility Providers equals 6 Core providers'
    Assert-Equal @($startDry.ExecutedCommands).Count 3 'Core logman create (-pf) + Core logman query + Dxg logman create planned'
    Assert-Equal (Test-Path -LiteralPath $etwDir) $false 'ETW Start DryRun must not create output directory'

    $exportDir = Join-Path $caseDir 'etw_export'
    $fakeEtl = Join-Path $exportDir 'LumaBridgeIddCore.etl'
    $global:LbTestState['MockEtlPath'] = $fakeEtl

    Invoke-WithModuleMocks -GlobalMocks @{
        'Get-LumaBridgeEtlEventSummary' = {
            param(
                [string]$EtlPath,
                [string[]]$ProviderGuids = @(),
                [string[]]$ProviderNames = @(),
                [Nullable[DateTime]]$StartTimeUtc = $null,
                [Nullable[DateTime]]$EndTimeUtc = $null,
                [Nullable[int]]$ProcessId = $null,
                [int]$MaxMatchedEvents = 500,
                [switch]$ExcludeHighVolumeGraphics
            )
            return [pscustomobject]@{
                EtlPath               = $EtlPath
                Exists                = $true
                EventCount            = 1
                MatchedEventCount     = 1
                MatchedLimitReached   = $false
                FilteredOutHighVolume = $true
                XPathUsed             = '*'
                TraceStats            = $null
                CircularWrapWarning   = $null
                LumaBridgeEvents      = @(
                    [pscustomobject]@{
                        ProviderName = 'LumaBridgeIddDriver'
                        Properties   = @('INFO', 100, 200, 'DriverEntry', 0, 'Uninitialized', 'DllProcessAttach', 'DriverEntry entered')
                    }
                )
                Providers             = @([pscustomobject]@{ ProviderName = 'LumaBridgeIddDriver'; Count = 1 })
                Events                = @()
                Error                 = ''
            }
        }
    } -Body {
        $exported = & (Join-Path $scriptsDir 'Invoke-LumaBridgeEtwTrace.ps1') -Action ExportSummary -OutputDir $exportDir -EtlPath $fakeEtl
        Assert-True (Test-Path -LiteralPath $exported.DecodedSummaryPath) 'ExportSummary writes etw-decoded-events.json'
        Assert-Equal $exported.StageSummary.DriverEntryReached $true 'ExportSummary computes StageSummary from ETL events'
    }
}

# 24. ETW trace uses clean -pf provider files, verifies providers, and separates DxgKrnl session
Invoke-UnitTest -Name 'EtwTraceUsesProviderFileAndSeparatesDxgKrnlSession' -TestBody {
    param($caseDir)

    $corePf = @(New-LumaBridgeEtwProviderFileContent -SessionKind 'Core')
    Assert-Equal $corePf.Count 6 'Core -pf content emits 6 provider lines'
    Assert-Equal (@($corePf | Where-Object { $_ -match '^#' })).Count 0 'Core -pf lines must not contain comment headers'
    Assert-Equal (@($corePf | Where-Object { $_ -match 'A7E4C910-5B32-4F8E-9D21-7C3A1B8E4F01' })).Count 1 'Core -pf includes LumaBridge TraceLogging provider'
    Assert-Equal (@($corePf | Where-Object { $_ -match 'D92BCB52-FA78-406F-A9A5-2037509FADEA' })).Count 1 'Core -pf includes IddCx WPP provider'
    Assert-Equal (@($corePf | Where-Object { $_ -match '802EC45A-1E99-4B83-9920-87C98277BA9D|70E74DD8-39DB-5F6F-6FD1-F5581B29E834' })).Count 0 'Core -pf excludes DxgKrnl and Watchdog-Events'

    $dxgPf = @(New-LumaBridgeEtwProviderFileContent -SessionKind 'Dxg')
    Assert-Equal $dxgPf.Count 2 'Dxg -pf content emits 2 high-volume provider lines'
    Assert-Equal (@($dxgPf | Where-Object { $_ -match '802EC45A-1E99-4B83-9920-87C98277BA9D' })).Count 1 'Dxg -pf includes DxgKrnl'
    Assert-Equal (@($dxgPf | Where-Object { $_ -match '70E74DD8-39DB-5F6F-6FD1-F5581B29E834' })).Count 1 'Dxg -pf includes Watchdog-Events'

    $c = Get-LumaBridgeDriverConstants
    $expectedCoreGuids = @(
        $c.LumaBridgeTraceProviderGuid,
        $c.IddCxManifestProviderGuid,
        $c.IddCxWppProviderGuid,
        $c.UmdfOperationalProviderGuid,
        $c.WdfCoreWppProviderGuid,
        $c.WerKernelProviderGuid
    )
    $mockQueryComplete = @(
        'Name:                 LumaBridgeIddCore',
        ('Provider:             {0}' -f $c.LumaBridgeTraceProviderGuid),
        ('Provider:             {0}' -f $c.IddCxManifestProviderGuid),
        ('Provider:             {0}' -f $c.IddCxWppProviderGuid),
        ('Provider:             {0}' -f $c.UmdfOperationalProviderGuid),
        ('Provider:             {0}' -f $c.WdfCoreWppProviderGuid),
        ('Provider:             {0}' -f $c.WerKernelProviderGuid)
    )
    $okVerify = Test-LumaBridgeEtwSessionProviders -QueryOutputLines $mockQueryComplete -ExpectedProviderGuids $expectedCoreGuids
    Assert-Equal $okVerify.AllProvidersVerified $true 'Test-LumaBridgeEtwSessionProviders verifies all 6 Core GUIDs'
    Assert-Equal @($okVerify.MissingProviderGuids).Count 0 'Zero missing GUIDs when complete'

    $incompleteVerify = Test-LumaBridgeEtwSessionProviders -QueryOutputLines @($mockQueryComplete | Select-Object -SkipLast 1) -ExpectedProviderGuids $expectedCoreGuids
    Assert-Equal $incompleteVerify.AllProvidersVerified $false 'Test-LumaBridgeEtwSessionProviders detects missing provider GUID'
    Assert-Equal @($incompleteVerify.MissingProviderGuids).Count 1 'Exactly 1 missing GUID reported'

    $etwCoreOnlyDir = Join-Path $caseDir 'etw_core_only'
    $coreOnlyDry = & (Join-Path $scriptsDir 'Invoke-LumaBridgeEtwTrace.ps1') -Action Start -OutputDir $etwCoreOnlyDir -DryRun
    Assert-Equal $coreOnlyDry.SessionName 'LumaBridgeIddCore' 'Default ETW Start uses LumaBridgeIddCore sequential session'
    Assert-Equal $coreOnlyDry.IncludeDxgKrnl $false 'DxgKrnl disabled by default'
    Assert-Equal @($coreOnlyDry.ExecutedCommands).Count 2 'Core-only Start schedules create (-pf) + query verification only'
    Assert-True ($coreOnlyDry.ExecutedCommands[0] -match '-pf\s') 'logman create trace uses -pf provider file'
    Assert-True ($coreOnlyDry.ExecutedCommands[0] -match '-f bin\s') 'Core session uses sequential -f bin mode'
    Assert-True ($coreOnlyDry.ExecutedCommands[1] -match 'query LumaBridgeIddCore -ets') 'Immediate provider query verification planned'
}

# 25. Streaming ETL XPath removes 500-event pre-filter cap and SetupAPI excludes unrelated VBoxSup sections
Invoke-UnitTest -Name 'StreamingEtlQueryAppliesNativeXPathWithoutPreFilterCap' -TestBody {
    param($caseDir)

    $defaultXPath = Get-LumaBridgeEtlXPathQuery -ExcludeHighVolumeGraphics
    Assert-True ($defaultXPath -match '802ec45a-1e99-4b83-9920-87c98277ba9d') 'Default XPath excludes DxgKrnl GUID'
    Assert-True ($defaultXPath -match '70e74dd8-39db-5f6f-6fd1-f5581b29e834') 'Default XPath excludes Watchdog-Events GUID'

    $startUtc = [DateTime]::SpecifyKind([DateTime]'2026-11-19T00:57:18', [DateTimeKind]::Utc)
    $endUtc = [DateTime]::SpecifyKind([DateTime]'2026-11-19T00:58:18', [DateTimeKind]::Utc)
    $targetedXPath = Get-LumaBridgeEtlXPathQuery `
        -ProviderGuids @('{A7E4C910-5B32-4F8E-9D21-7C3A1B8E4F01}') `
        -ProviderNames @('Microsoft-Windows-DriverFrameworks-UserMode') `
        -StartTimeUtc $startUtc `
        -EndTimeUtc $endUtc `
        -ProcessId 23812
    Assert-True ($targetedXPath -match 'a7e4c910-5b32-4f8e-9d21-7c3a1b8e4f01') 'Targeted XPath includes normalized Provider GUID'
    Assert-True ($targetedXPath -match "Microsoft-Windows-DriverFrameworks-UserMode") 'Targeted XPath includes Provider Name'
    Assert-True ($targetedXPath -match '@SystemTime>=') 'Targeted XPath includes StartTimeUtc lower bound'
    Assert-True ($targetedXPath -match '@SystemTime<=') 'Targeted XPath includes EndTimeUtc upper bound'
    Assert-True ($targetedXPath -match 'Execution\[@ProcessID=23812\]') 'Targeted XPath includes ProcessId filter'

    $dummyEtl = Join-Path $caseDir 'dummy.etl'
    [System.IO.File]::WriteAllBytes($dummyEtl, [byte[]]@(1, 2, 3, 4))
    $global:LbTestState['CapturedXPath'] = $null
    $global:LbTestState['CapturedMax'] = 0

    Invoke-WithModuleMocks -ModuleMocks @{
        'Get-LumaBridgeEtlTraceStats' = {
            param([string]$EtlPath)
            return [pscustomobject]@{
                Available           = $true
                CircularWrapWarning = 'Circular wrap evicted window before 00:58:04Z'
                Error               = ''
            }
        }
        'Invoke-LumaBridgeEtlXPathReader' = {
            param([string]$EtlPath, [string]$XPath, [int]$MaxMatchedEvents)
            $global:LbTestState['CapturedXPath'] = $XPath
            $global:LbTestState['CapturedMax'] = $MaxMatchedEvents
            return [pscustomobject]@{
                LimitReached = $false
                Events       = @(
                    [pscustomobject]@{
                        TimeCreated  = '2026-11-19T00:57:48.030Z'
                        ProviderName = 'LumaBridgeIddDriver'
                        ProviderId   = '{a7e4c910-5b32-4f8e-9d21-7c3a1b8e4f01}'
                        Id           = 1
                        LevelDisplay = 'Information'
                        ProcessId    = 23812
                        ThreadId     = 100
                        Message      = '[LB-DRIVER] DriverEntry entered'
                        Properties   = @()
                    },
                    [pscustomobject]@{
                        TimeCreated  = '2026-11-19T00:57:48.031Z'
                        ProviderName = 'Microsoft-Windows-DriverFrameworks-UserMode'
                        ProviderId   = '{2e35aaeb-857f-4beb-a418-2e6c0e54d988}'
                        Id           = 2103
                        LevelDisplay = 'Error'
                        ProcessId    = 23812
                        ThreadId     = 101
                        Message      = 'PnP fail 0xC000009E'
                        Properties   = @()
                    }
                )
            }
        }
    } -Body {
        $etlOut = Get-LumaBridgeEtlEventSummary -EtlPath $dummyEtl -MaxMatchedEvents 1200
        Assert-True ($global:LbTestState['CapturedXPath'] -match '802ec45a-1e99-4b83-9920-87c98277ba9d') 'Native XPath passed directly to streaming reader'
        Assert-Equal $global:LbTestState['CapturedMax'] 1200 'MaxMatchedEvents cap (1200) forwarded after native filtering instead of fixed 500 pre-filter'
        Assert-Equal $etlOut.MatchedEventCount 2 'Both matching events returned'
        Assert-Equal $etlOut.FilteredOutHighVolume $true 'High-volume graphics exclusion active by default'
        Assert-Equal @($etlOut.LumaBridgeEvents).Count 1 'LumaBridge TraceLogging event isolated'
        Assert-True ($etlOut.CircularWrapWarning -match 'Circular wrap') 'CircularWrapWarning surfaced in summary'
    }

    $setupLogPath = Join-Path $caseDir 'setupapi_test.log'
    @(
        '>>>  [Device Install (UpdateDriverForPlugAndPlayDevices) - Root\VBoxSup]',
        '     Inf name: oem68.inf',
        '<<<  Section end 2026/11/18 20:50:00.000: [Exit status: SUCCESS]',
        '>>>  [Device Install (Hardware initiated) - ROOT\DISPLAY\0000]',
        '     Installing LumaBridgeIddDriver.inf (oem68.inf)',
        '     ! dvi: Device failed start CM_PROB_FAILED_START ProblemStatus 0xC000009E',
        '<<<  Section end 2026/11/18 20:57:48.100: [Exit status: SUCCESS]'
    ) | Set-Content -LiteralPath $setupLogPath -Encoding UTF8

    $setupExcerpt = Get-LumaBridgeSetupApiLogExcerpt -SetupApiLogPath $setupLogPath -InstanceIds @('ROOT\DISPLAY\0000') -PublishedInfNames @('oem68.inf')
    Assert-Equal $setupExcerpt.MatchedSectionCount 1 'Only LumaBridge/Display section matched despite shared oem68.inf token in VBoxSup section'
    Assert-Equal ($setupExcerpt.RawExcerptText -match 'VBoxSup') $false 'Unrelated VBoxSup.inf section excluded'
    Assert-True ($setupExcerpt.RawExcerptText -match 'CM_PROB_FAILED_START') 'Relevant LumaBridge start failure preserved'
}

# 26. WPP TMF cache DryRun & line-streaming WPP decode filtering
Invoke-UnitTest -Name 'WppTmfCacheAndDecodeDryRunAndStreamFilter' -TestBody {
    param($caseDir)

    $symDir = Join-Path $caseDir 'sym_dry'
    $tmfDir = Join-Path $caseDir 'tmf_dry'
    $tmfDry = Initialize-LumaBridgeWppTmfCache -SymbolCacheDir $symDir -TmfCacheDir $tmfDir -DryRun
    Assert-Equal $tmfDry.DryRun $true 'Initialize-LumaBridgeWppTmfCache -DryRun succeeds'
    Assert-Equal (Test-Path -LiteralPath $symDir) $false 'DryRun must not create SymbolCacheDir'
    Assert-Equal (Test-Path -LiteralPath $tmfDir) $false 'DryRun must not create TmfCacheDir'
    Assert-True (@($tmfDry.ExecutedCommands | Where-Object { $_ -match 'tracepdb' }).Count -ge 1) 'DryRun plans tracepdb execution'

    $sampleFmt = Join-Path $caseDir 'tracefmt_sample.txt'
    @(
        '[0]0004.1168::11/18/2026-21:57:48.010 [Microsoft-Windows-DxgKrnl]noisy dxg event',
        '[0]0004.1168::11/18/2026-21:57:48.011 [Microsoft-Windows-Watchdog-Events]noisy watchdog event',
        '[9]5D04.1F7C::11/18/2026-21:57:48.021 [cx][IddCx]DriverEntry: Exit, status=STATUS_SUCCESS',
        '[3]1234.0ABC::11/18/2026-21:57:48.022 [cx][IddCx]OtherPid: Exit, status=STATUS_SUCCESS'
    ) | Set-Content -LiteralPath $sampleFmt -Encoding UTF8

    $decodedOut = Join-Path $caseDir 'wpp_decoded.txt'
    $wpp = Invoke-LumaBridgeWppEtlDecode -ExistingTraceFmtTextPath $sampleFmt -ProcessId 23812 -OutputPath $decodedOut
    Assert-Equal $wpp.TotalScannedLines 4 'Streamed all 4 lines from tracefmt output'
    Assert-Equal $wpp.MatchedLineCount 1 'Matched exactly 1 line for PID 23812 (5D04) excluding high-volume noise'
    Assert-Equal @($wpp.IddCxWppLines).Count 1 'IddCx WPP line isolated cleanly'
    Assert-True ($wpp.IddCxWppLines[0] -match 'IddCx.*DriverEntry') 'Decoded IddCx WPP text preserved'
    Assert-True (Test-Path -LiteralPath $decodedOut) 'WPP filtered text written to OutputPath'
}

# 27. Prepare-IddSampleReference.ps1 enforces repository isolation and clean DryRun
Invoke-UnitTest -Name 'PrepareIddSampleReferenceDryRunEnforcesIsolation' -TestBody {
    param($caseDir)

    $insideRepoDir = Join-Path (Split-Path $scriptsDir -Parent) 'ref_inside_repo_invalid'
    $threwIsolation = $false
    try {
        $null = & (Join-Path $scriptsDir 'Prepare-IddSampleReference.ps1') -WorkDir $insideRepoDir -DryRun
    }
    catch {
        if ($_.Exception.Message -match 'strictly isolated') {
            $threwIsolation = $true
        }
    }
    Assert-True $threwIsolation 'Prepare-IddSampleReference rejects WorkDir inside repo'

    $isolatedWorkDir = Join-Path $caseDir 'ref_isolated'
    $refDry = & (Join-Path $scriptsDir 'Prepare-IddSampleReference.ps1') -WorkDir $isolatedWorkDir -DryRun
    Assert-Equal $refDry.DryRun $true 'Prepare-IddSampleReference -DryRun returns structured result'
    Assert-Equal $refDry.InstallAttempted $false 'Prepare-IddSampleReference never attempts driver install'
    Assert-Equal (Test-Path -LiteralPath $isolatedWorkDir) $false 'DryRun must not create WorkDir'
    Assert-True (@($refDry.PlannedCommands | Where-Object { $_ -match 'gh api' }).Count -eq 1) 'Plans GitHub Contents API download for IndirectDisplay'
    Assert-True (@($refDry.PlannedCommands | Where-Object { $_ -match 'msbuild' }).Count -eq 1) 'Plans isolated MSBuild compile'
    Assert-True (@($refDry.PlannedCommands | Where-Object { $_ -match 'infverif' }).Count -eq 1) 'Plans InfVerif /v /u verification'
}

# 28. DiagnosticStage build helper stages manifest/SHA-256 and reads subkey DiagBuildStage breadcrumbs
Invoke-UnitTest -Name 'DiagnosticStageBuildManifestAndSubkeyBreadcrumbs' -TestBody {
    param($caseDir)

    $subkeyPath = Join-Path $caseDir 'DeviceParameters\LumaBridgeIddDriver'
    $baseParamsPath = Join-Path $caseDir 'DeviceParameters'
    $diagRegProps = [pscustomobject]@{
        DiagLastStage           = 'AdapterInitAsync'
        DiagLastSuccessfulStage = 'DeviceD0Entry'
        DiagLastStatus          = 0
        DiagLastErrorStage      = 'None'
        DiagLastErrorStatus     = 0
        DiagIddCxVersion        = 0x00010400
        DiagHostProcessId       = 4120
        DiagDllAttachCount      = 1
        DiagBuildStage          = 1
    }

    $global:LbTestState['SubkeyPath'] = $subkeyPath
    $global:LbTestState['BaseParamsPath'] = $baseParamsPath
    $global:LbTestState['SubkeyDiagProps'] = $diagRegProps

    Invoke-WithModuleMocks -ModuleMocks @{
        'Test-Path' = {
            param([string]$LiteralPath, [string]$PathType)
            if ($LiteralPath -eq $global:LbTestState['BaseParamsPath']) { return $true }
            if ($LiteralPath -eq $global:LbTestState['SubkeyPath']) { return $true }
            if ($PathType) { return (Microsoft.PowerShell.Management\Test-Path -LiteralPath $LiteralPath -PathType $PathType) }
            return (Microsoft.PowerShell.Management\Test-Path -LiteralPath $LiteralPath)
        }
        'Get-ItemProperty' = {
            param([string]$LiteralPath)
            if ($LiteralPath -eq $global:LbTestState['BaseParamsPath']) {
                return [pscustomobject]@{ EnableVirtualMonitor = 0 }
            }
            if ($LiteralPath -eq $global:LbTestState['SubkeyPath']) {
                return $global:LbTestState['SubkeyDiagProps']
            }
            return (Microsoft.PowerShell.Management\Get-ItemProperty -LiteralPath $LiteralPath)
        }
    } -Body {
        $diag = Get-LumaBridgeDeviceStartupDiagnostics -DeviceParametersPath $baseParamsPath
        Assert-True ($null -ne $diag) 'Subkey Diag* breadcrumbs resolved automatically'
        Assert-Equal $diag.LastStage 'AdapterInitAsync' 'Subkey LastStage decoded'
        Assert-Equal $diag.BuildStage 1 'DiagBuildStage decoded from subkey'
        Assert-Equal $diag.RegistryPath $subkeyPath 'Resolved RegistryPath points to driver subkey'
    }

    $stageOutRoot = Join-Path $caseDir 'stage_out'
    $dryStage = & (Join-Path $scriptsDir 'Build-LumaBridgeDiagnosticStage.ps1') -DiagnosticStage 1 -OutputRoot $stageOutRoot -DryRun
    Assert-Equal $dryStage.DryRun $true 'Build-LumaBridgeDiagnosticStage -DryRun returns structured result'
    Assert-Equal $dryStage.DiagnosticStage 1 'DiagnosticStage recorded in DryRun output'
    Assert-Equal (Test-Path -LiteralPath $stageOutRoot) $false 'DryRun must not create OutputRoot'

    $dummySrcOut = Join-Path $caseDir 'dummy_out'
    $dummySrcPkg = Join-Path $dummySrcOut 'LumaBridgeIddDriver'
    $null = New-Item -Path $dummySrcPkg -ItemType Directory -Force
    [System.IO.File]::WriteAllBytes((Join-Path $dummySrcPkg 'LumaBridgeIddDriver.dll'), [byte[]]@(1..64))
    [System.IO.File]::WriteAllText((Join-Path $dummySrcPkg 'LumaBridgeIddDriver.inf'), '; test inf')
    [System.IO.File]::WriteAllBytes((Join-Path $dummySrcPkg 'LumaBridgeIddDriver.cat'), [byte[]]@(65..96))
    [System.IO.File]::WriteAllBytes((Join-Path $dummySrcOut 'LumaBridgeIddDriver.pdb'), [byte[]]@(97..128))

    $stageResult = & (Join-Path $scriptsDir 'Build-LumaBridgeDiagnosticStage.ps1') `
        -DiagnosticStage 1 `
        -Configuration Release `
        -OutputRoot $stageOutRoot `
        -SourcePackageDir $dummySrcPkg `
        -SkipBuild

    Assert-Equal $stageResult.DryRun $false 'SkipBuild staging ran cleanly'
    Assert-Equal $stageResult.DiagnosticStage 1 'Stage manifest DiagnosticStage=1'
    Assert-True (Test-Path -LiteralPath $stageResult.ManifestPath -PathType Leaf) 'stage-build-manifest.json written'
    Assert-True (-not [string]::IsNullOrWhiteSpace($stageResult.DllSha256)) 'DllSha256 recorded'
    Assert-True (-not [string]::IsNullOrWhiteSpace($stageResult.InfSha256)) 'InfSha256 recorded'
    Assert-True (-not [string]::IsNullOrWhiteSpace($stageResult.CatSha256)) 'CatSha256 recorded'
    Assert-True (-not [string]::IsNullOrWhiteSpace($stageResult.PdbSha256)) 'PdbSha256 recorded'

    $parsedManifest = Get-Content -LiteralPath $stageResult.ManifestPath -Raw | ConvertFrom-Json
    Assert-Equal $parsedManifest.DiagnosticStage 1 'JSON manifest DiagnosticStage equals 1'
    Assert-Equal $parsedManifest.DllSha256 $stageResult.DllSha256 'JSON manifest DllSha256 matches result'
}

# 29. Observability fixes: VerifyProviders top-level flag, unclamped ETL query despite old PnP events, and TraceLogging recovery
Invoke-UnitTest -Name 'ObservabilityVerifyProvidersAndUnclampedEtlTraceLoggingRecovery' -TestBody {
    param($caseDir)

    $c = Get-LumaBridgeDriverConstants
    $mockLogmanLines = @(
        'Name:                 LumaBridgeIddCore',
        ('Provider:             {0}' -f $c.LumaBridgeTraceProviderGuid),
        ('Provider:             {0}' -f $c.IddCxManifestProviderGuid),
        ('Provider:             {0}' -f $c.IddCxWppProviderGuid),
        ('Provider:             {0}' -f $c.UmdfOperationalProviderGuid),
        ('Provider:             {0}' -f $c.WdfCoreWppProviderGuid),
        ('Provider:             {0}' -f $c.WerKernelProviderGuid)
    )
    $global:LbTestState['MockLogmanLines'] = $mockLogmanLines

    Invoke-WithModuleMocks -GlobalMocks @{
        'Invoke-LumaBridgeExternalCommand' = {
            param([string]$FilePath, [string[]]$Arguments, [switch]$DryRun)
            return [pscustomobject]@{
                ExitCode = 0
                Output   = $global:LbTestState['MockLogmanLines']
                DryRun   = $false
            }
        }
    } -Body {
        $verifyOut = & (Join-Path $scriptsDir 'Invoke-LumaBridgeEtwTrace.ps1') -Action VerifyProviders
        Assert-Equal $verifyOut.AllProvidersVerified $true 'VerifyProviders exposes top-level AllProvidersVerified=$true'
        Assert-Equal $verifyOut.ProviderVerification.AllProvidersVerified $true 'VerifyProviders preserves nested ProviderVerification.AllProvidersVerified=$true'
        Assert-Equal @($verifyOut.MissingProviderGuids).Count 0 'VerifyProviders exposes empty MissingProviderGuids at top level'
    }

    # Test targeted TraceLogging recovery when Pass 1 hits MaxMatchedEvents cap with GUID-only event
    $dummyEtl = Join-Path $caseDir 'obs_test.etl'
    [System.IO.File]::WriteAllBytes($dummyEtl, [byte[]]@(1, 2, 3, 4))
    $global:LbTestState['ReaderCalls'] = 0

    Invoke-WithModuleMocks -ModuleMocks @{
        'Get-LumaBridgeEtlTraceStats' = {
            param([string]$EtlPath)
            return [pscustomobject]@{ Available = $true; CircularWrapWarning = $null; Error = '' }
        }
        'Invoke-LumaBridgeEtlXPathReader' = {
            param([string]$EtlPath, [string]$XPath, [int]$MaxMatchedEvents)
            $global:LbTestState['ReaderCalls'] = [int]$global:LbTestState['ReaderCalls'] + 1
            if ($global:LbTestState['ReaderCalls'] -eq 1) {
                return [pscustomobject]@{
                    LimitReached = $true
                    Events       = @(
                        [pscustomobject]@{
                            TimeCreated  = '2026-11-22T12:00:00.000Z'
                            ProviderName = ''
                            ProviderId   = '{d92bcb52-fa78-406f-a9a5-2037509fadea}'
                            Id           = 10
                            LevelDisplay = 'Information'
                            ProcessId    = 8768
                            ThreadId     = 100
                            Message      = ''
                            Properties   = @()
                        }
                    )
                }
            }
            return [pscustomobject]@{
                LimitReached = $false
                Events       = @(
                    [pscustomobject]@{
                        TimeCreated  = '2026-11-22T12:00:05.000Z'
                        ProviderName = ''
                        ProviderId   = '{a7e4c910-5b32-4f8e-9d21-7c3a1b8e4f01}'
                        Id           = 0
                        LevelDisplay = 'Information'
                        ProcessId    = 8768
                        ThreadId     = 200
                        Message      = '[LB-DRIVER] [INFO] pid=8768 tid=200 stage=AdapterInitFinished status=0x00000000 state=AdapterReady lastOk=AdapterInitAsync msg="ok"'
                        Properties   = @('INFO', '8768', '200', 'AdapterInitFinished', '0', 'AdapterReady', 'AdapterInitAsync', 'ok')
                    },
                    [pscustomobject]@{
                        TimeCreated  = '2026-11-22T12:00:06.000Z'
                        ProviderName = ''
                        ProviderId   = '{a7e4c910-5b32-4f8e-9d21-7c3a1b8e4f01}'
                        Id           = 1
                        LevelDisplay = 'Information'
                        ProcessId    = 8768
                        ThreadId     = 200
                        Message      = '[LB-DRIVER] [METRICS/ETL] stage=MonitorAssignSwapChain fields=29'
                        Properties   = @('MonitorAssignSwapChain', 'AdapterReady', 'Arrived', 'Active', 'True', '19', '19', '0', '60', '60', 'True', '19', '19', '19', '0', '0', '0', '0', '1', '19', '120', '450', '0', '0', '0', '0', '1024', '2048', '100')
                    }
                )
            }
        }
    } -Body {
        $etlSummary = Get-LumaBridgeEtlEventSummary -EtlPath $dummyEtl -MaxMatchedEvents 500
        Assert-Equal $global:LbTestState['ReaderCalls'] 2 'Targeted second pass executes when LimitReached=true and LumaBridgeEvents=0'
        Assert-Equal $etlSummary.TargetedLumaBridgeQueryUsed $true 'TargetedLumaBridgeQueryUsed flag set'
        Assert-Equal @($etlSummary.LumaBridgeEvents).Count 2 'Both GUID-only TraceLogging events recovered'

        $stageSum = Get-LumaBridgeDriverTraceStageSummary -EtlEvents @($etlSummary.LumaBridgeEvents)
        Assert-Equal $stageSum.DriverEntryReached $true 'DriverEntryReached detected from GUID-only TraceLogging event'
        Assert-Equal $stageSum.StageRecordCount 1 '29-field DriverMetrics event not misparsed as 8-field DriverStage record'
        Assert-Equal $stageSum.LastStage 'AdapterInitFinished' 'LastStage extracted from GUID-only DriverStage record'
    }

    # Verify Collect-LumaBridgeDiagnostics does not clamp ETL StartTimeUtc/EndTimeUtc to older PnP events
    $diagOutDir = Join-Path $caseDir 'diag_out'
    $fakeSetupLog = Join-Path $caseDir 'setupapi_obs.log'
    [System.IO.File]::WriteAllText($fakeSetupLog, '')
    $global:LbTestState['CapturedEtlStart'] = 'NOT_SET'
    $global:LbTestState['CapturedEtlEnd'] = 'NOT_SET'

    Invoke-WithModuleMocks -GlobalMocks @{
        'Get-LumaBridgeEventChannelStatus' = {
            return @([pscustomobject]@{ LogName = 'Microsoft-Windows-Kernel-PnP/Configuration'; IsEnabled = $true; LogType = 'Operational'; RecordCount = 1; QueryError = '' })
        }
        'Get-LumaBridgeDiagnosticEvents' = {
            param([int]$LookbackMinutes, [string[]]$InstanceIds, [string[]]$PublishedInfNames, [object[]]$ChannelStatus)
            return @(
                [pscustomobject]@{
                    LogName       = 'Microsoft-Windows-Kernel-PnP/Configuration'
                    TimeCreated   = '2026-11-22T11:00:00.000Z'
                    LevelDisplay  = 'Information'
                    Id            = 400
                    EventRecordId = 1
                    ProcessId     = 4
                    ProviderName  = 'Microsoft-Windows-Kernel-PnP'
                    Message       = 'Old PnP configure event'
                }
            )
        }
        'Get-LumaBridgeCrashDumpInventory' = {
            return [pscustomobject]@{ LookbackMinutes = 60; Locations = @(); Files = @(); TotalFoundCount = 0 }
        }
        'Get-LumaBridgeEtlEventSummary' = {
            param([string]$EtlPath, [string[]]$ProviderGuids = @(), [string[]]$ProviderNames = @(), [Nullable[DateTime]]$StartTimeUtc = $null, [Nullable[DateTime]]$EndTimeUtc = $null, [Nullable[int]]$ProcessId = $null, [int]$MaxMatchedEvents = 500, [switch]$ExcludeHighVolumeGraphics)
            $global:LbTestState['CapturedEtlStart'] = $StartTimeUtc
            $global:LbTestState['CapturedEtlEnd'] = $EndTimeUtc
            return [pscustomobject]@{
                EtlPath               = $EtlPath
                Exists                = $true
                EventCount            = 1
                MatchedEventCount     = 1
                MatchedLimitReached   = $false
                FilteredOutHighVolume = $true
                XPathUsed             = '*'
                TraceStats            = $null
                CircularWrapWarning   = $null
                LumaBridgeEvents      = @()
                Providers             = @()
                Events                = @()
                Error                 = ''
            }
        }
    } -Body {
        $diagRes = & (Join-Path $scriptsDir 'Collect-LumaBridgeDiagnostics.ps1') -OutputDir $diagOutDir -EtlPath $dummyEtl -SetupApiLogPath $fakeSetupLog
        Assert-Equal $global:LbTestState['CapturedEtlStart'] $null 'Collect-LumaBridgeDiagnostics does not clamp StartTimeUtc to old PnP events'
        Assert-Equal $global:LbTestState['CapturedEtlEnd'] $null 'Collect-LumaBridgeDiagnostics does not clamp EndTimeUtc to old PnP events'
        Assert-True (-not [string]::IsNullOrWhiteSpace($diagRes.Summary.InferredPnpAnchorStartUtc)) 'Inferred PnP anchor window recorded informatively'
    }
}

# 30. Functional validation orchestrator DryRun, StagingDir handling, and guaranteed finally rollback on failure
Invoke-UnitTest -Name 'FunctionalValidationScriptDryRunAndFinallyRollbackOnFailure' -TestBody {
    param($caseDir)

    $valScript = Join-Path $scriptsDir 'Invoke-LumaBridgeFunctionalValidation.ps1'
    $scriptText = Get-Content -LiteralPath $valScript -Raw
    Assert-True ($scriptText -match '\$signResult\.StagingDir\b') 'Validation script references StagingDir property'
    Assert-True ($scriptText -notmatch '\$signResult\.StagingDirectory\b') 'Validation script must not reference non-existent StagingDirectory property'

    $docsValPath = Join-Path (Get-LumaBridgeRepoRoot) 'docs\setup\windows-idd-functional-validation.md'
    $docsText = Get-Content -LiteralPath $docsValPath -Raw
    Assert-True ($docsText -match '\$signResult\.StagingDir\b') 'Validation documentation references StagingDir property'
    Assert-True ($docsText -notmatch '-StagingDir\s+\$signResult\.StagingDirectory\b') 'Validation documentation must not pass StagingDirectory'

    $dryStg = Join-Path $caseDir 'dry_stg'
    $dryOut = Join-Path $caseDir 'dry_out'
    $dryRes = & $valScript -Configuration Release -StagingDir $dryStg -OutputDir $dryOut -AllowAnyBranch -DryRun
    Assert-Equal $dryRes.DryRun $true 'Invoke-LumaBridgeFunctionalValidation -DryRun returns DryRun=true'
    Assert-Equal (Test-Path -LiteralPath $dryStg) $false 'DryRun must not create StagingDir'
    Assert-Equal (Test-Path -LiteralPath $dryOut) $false 'DryRun must not create OutputDir'

    # Live failure simulation: host consumer fails in Stage 9 -> finally must revert flags, stop ETW, restart device, and persist report
    $certInfo = New-EphemeralTestCertificate -OutDirectory (Join-Path $caseDir 'certs') -NamePrefix 'valrb'
    $liveStg = Join-Path $caseDir 'live_stg'
    $liveOut = Join-Path $caseDir 'live_out'
    $fakeHostExe = Join-Path $caseDir 'lumabridge-host.exe'
    [System.IO.File]::WriteAllBytes($fakeHostExe, [byte[]]@(0x4D, 0x5A, 0x90, 0x00))

    $c = Get-LumaBridgeDriverConstants
    $mockLogmanLines = @(
        'Name:                 LumaBridgeIddCore',
        ('Provider:             {0}' -f $c.LumaBridgeTraceProviderGuid),
        ('Provider:             {0}' -f $c.IddCxManifestProviderGuid),
        ('Provider:             {0}' -f $c.IddCxWppProviderGuid),
        ('Provider:             {0}' -f $c.UmdfOperationalProviderGuid),
        ('Provider:             {0}' -f $c.WdfCoreWppProviderGuid),
        ('Provider:             {0}' -f $c.WerKernelProviderGuid)
    )

    $global:LbTestState['ValMock'] = [ordered]@{
        CertInfo         = $certInfo
        Signtool         = Get-LumaBridgeWdkToolPath -ToolName 'signtool.exe'
        LogmanLines      = $mockLogmanLines
        EnableMon        = 0
        EnableExt        = 0
        AuthSid          = $null
        EtwRunning       = $false
        EtwStopCalls     = 0
        RestartCount     = 0
        InjectStage8Fail = $false
    }

    $mockGetInstances = {
        [CmdletBinding()] param([string]$HardwareId)
        $st = $global:LbTestState['ValMock']
        return @([pscustomobject]@{
            InstanceId            = 'ROOT\DISPLAY\0000'
            FriendlyName          = 'LumaBridge Indirect Display Adapter'
            Status                = 'OK'
            ProblemCode           = 0
            ProblemStatus         = 0
            ProblemStatusHex      = '0x00000000'
            Present               = $true
            HardwareIds           = @('Root\LumaBridgeIddDriver')
            DriverInfPath         = 'oem99.inf'
            DriverProvider        = 'LumaBridge'
            DriverVersion         = (Get-LumaBridgeInfDriverVersion -InfPath (Join-Path (Get-LumaBridgePackageDirectory -Configuration Release) 'LumaBridgeIddDriver.inf'))
            DriverService         = 'WUDFRd'
            UpperFilters          = @('IndirectKmd')
            LowerFilters          = @()
            ConfigurationId       = 'oem99.inf:Root\LumaBridgeIddDriver'
            DeviceParametersPath  = 'MOCK:\ROOT\DISPLAY\0000\Device Parameters'
            EnableVirtualMonitor  = $st.EnableMon
            EnableFrameExtraction = $st.EnableExt
            AuthorizedHostUserSid = $st.AuthSid
            StartupDiagnostics    = [pscustomobject]@{
                LastStage           = 'AdapterInitFinished'
                LastSuccessfulStage = 'AdapterInitFinished'
                LastStatusHex       = '0x00000000'
                LastErrorStatusHex  = '0x00000000'
            }
        })
    }

    $mockExternalCmd = {
        [CmdletBinding()] param([string]$FilePath, [string[]]$Arguments = @(), [switch]$DryRun)
        $st = $global:LbTestState['ValMock']
        if ($FilePath -like '*git*') {
            return [pscustomobject]@{ ExitCode = 0; Output = @('feature/windows-frame-extraction-ipc'); DryRun = $false }
        }
        if ($FilePath -ieq $st.Signtool -and $Arguments.Count -ge 1 -and $Arguments[0] -eq 'sign') {
            $targetFile = $Arguments[$Arguments.Count - 1]
            $ci = $st.CertInfo
            $out = & $FilePath sign /fd SHA256 /f $ci.PfxPath /p $ci.Password $targetFile 2>&1
            if ($LASTEXITCODE -ne 0) { throw ("Mock signtool failed: {0}" -f ($out -join ' ')) }
            return [pscustomobject]@{ ExitCode = 0; Output = @($out); DryRun = $false }
        }
        if ($FilePath -like '*Inf2Cat*' -or ($FilePath -ieq $st.Signtool -and $Arguments[0] -eq 'verify')) {
            $out = & $FilePath @Arguments 2>&1
            if ($LASTEXITCODE -ne 0) { throw ("Tool failed: {0}" -f ($out -join ' ')) }
            return [pscustomobject]@{ ExitCode = 0; Output = @($out); DryRun = $false }
        }
        if ($FilePath -like '*logman*') {
            if ($Arguments[0] -eq 'create') {
                if ($Arguments.Count -ge 3 -and $Arguments[2] -eq 'LumaBridgeIddCore') {
                    $st.EtwRunning = $true
                }
                return [pscustomobject]@{ ExitCode = 0; Output = @('The command completed successfully.'); DryRun = $false }
            }
            if ($Arguments[0] -eq 'query') {
                if ($Arguments.Count -ge 2 -and $Arguments[1] -eq 'LumaBridgeIddDxg') {
                    throw 'Data Collector Set was not found.'
                }
                return [pscustomobject]@{ ExitCode = 0; Output = $st.LogmanLines; DryRun = $false }
            }
            if ($Arguments[0] -eq 'stop') {
                if ($Arguments.Count -ge 2 -and $Arguments[1] -eq 'LumaBridgeIddCore') {
                    $st.EtwRunning = $false
                    $st.EtwStopCalls++
                }
                return [pscustomobject]@{ ExitCode = 0; Output = @('The command completed successfully.'); DryRun = $false }
            }
        }
        if ($FilePath -like '*pnputil*' -and $Arguments[0] -eq '/restart-device') {
            $st.RestartCount++
            if ($st.InjectStage8Fail -and $st.EnableExt -eq 1 -and $st.RestartCount -eq 2) {
                throw 'Simulated Stage 8 pnputil restart failure'
            }
            return [pscustomobject]@{ ExitCode = 0; Output = @('Device restarted.'); DryRun = $false }
        }
        return [pscustomobject]@{ ExitCode = 0; Output = @('OK'); DryRun = $false }
    }

    $sharedMocks = @{
        'Assert-LumaBridgeAdministrator'              = { [CmdletBinding()] param([string]$OperationName, [switch]$DryRun) return $true }
        'Get-LumaBridgeHostSecurityState'             = { [CmdletBinding()] param() return [pscustomobject]@{ SecureBoot = 'Disabled'; TestSigning = 'Enabled' } }
        'Find-LumaBridgeSigningCertificate'           = { [CmdletBinding()] param([string]$CertificateThumbprint, [string]$CertificateSubject) return $global:LbTestState['ValMock'].CertInfo.Certificate }
        'Export-LumaBridgeCertificateFile'            = { [CmdletBinding()] param($Certificate, [string]$FilePath) [System.IO.File]::WriteAllBytes($FilePath, $Certificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)) }
        'Get-LumaBridgePnpInstances'                  = $mockGetInstances
        'Set-LumaBridgeDeviceEnableVirtualMonitor'    = { [CmdletBinding()] param([string]$DeviceParametersPath, [int]$Value = 0, [switch]$Clear) if ($Clear) { $global:LbTestState['ValMock'].EnableMon = $null } else { $global:LbTestState['ValMock'].EnableMon = $Value } }
        'Get-LumaBridgeDeviceEnableVirtualMonitor'    = { [CmdletBinding()] param([string]$DeviceParametersPath) return $global:LbTestState['ValMock'].EnableMon }
        'Set-LumaBridgeDeviceEnableFrameExtraction'   = { [CmdletBinding()] param([string]$DeviceParametersPath, [int]$Value = 0, [switch]$Clear) if ($Clear) { $global:LbTestState['ValMock'].EnableExt = $null } else { $global:LbTestState['ValMock'].EnableExt = $Value } }
        'Get-LumaBridgeDeviceEnableFrameExtraction'   = { [CmdletBinding()] param([string]$DeviceParametersPath) return $global:LbTestState['ValMock'].EnableExt }
        'Set-LumaBridgeDeviceAuthorizedHostUserSid'   = { [CmdletBinding()] param([string]$DeviceParametersPath, [string]$SidString, [switch]$Clear) if ($Clear -or [string]::IsNullOrWhiteSpace($SidString)) { $global:LbTestState['ValMock'].AuthSid = $null } else { $global:LbTestState['ValMock'].AuthSid = $SidString } }
        'Get-LumaBridgeDeviceAuthorizedHostUserSid'   = { [CmdletBinding()] param([string]$DeviceParametersPath) return $global:LbTestState['ValMock'].AuthSid }
        'Invoke-LumaBridgeExternalCommand'            = $mockExternalCmd
        'Get-LumaBridgeWudfHostProcesses'             = { [CmdletBinding()] param([object[]]$PnpInstances, [object[]]$RecentEvents, [string[]]$DebugTraceLines, [Nullable[DateTime]]$NotBeforeUtc = $null, [Nullable[int]]$ExpectedHostPid = $null) return @([pscustomobject]@{ Id = 8768; IsLumaBridgeHost = $true; AssociationMethod = 'LoadedModule'; WorkingSetMB = 30.0; PrivateMemoryMB = 15.0; HandleCount = 400; StartedAfterAnchor = $true }) }
        'Get-LumaBridgeCrashDumpInventory'            = { [CmdletBinding()] param([int]$LookbackMinutes) return [pscustomobject]@{ LookbackMinutes = $LookbackMinutes; Locations = @(); Files = @(); TotalFoundCount = 0 } }
        'Get-LumaBridgeEventChannelStatus'            = { [CmdletBinding()] param([string[]]$ChannelNames) return @() }
        'Get-LumaBridgeDiagnosticEvents'              = { [CmdletBinding()] param([int]$LookbackMinutes, [string[]]$InstanceIds, [string[]]$PublishedInfNames, [object[]]$ChannelStatus) return @() }
        'Get-LumaBridgeSetupApiLogExcerpt'            = { [CmdletBinding()] param([string]$SetupApiLogPath, [string[]]$InstanceIds, [string[]]$PublishedInfNames, [int]$MaxMatchedSections) return [pscustomobject]@{ LogPath = $SetupApiLogPath; Exists = $false; AccessDenied = $false; Error = ''; MatchedSectionCount = 0; WdfSchemaWarnings = @(); DeviceStartProblemLines = @(); Sections = @(); RawExcerptText = '' } }
        'Get-LumaBridgeDriverStorePackages'           = { [CmdletBinding()] param([string]$InfFilter) return @() }
        'Get-LumaBridgeEtlEventSummary'               = { [CmdletBinding()] param([string]$EtlPath, $StartTimeUtc, $EndTimeUtc, $ProcessId, [int]$MaxMatchedEvents = 500, [switch]$ExcludeHighVolumeGraphics) return [pscustomobject]@{ EtlPath = $EtlPath; Exists = $true; EventCount = 1; MatchedEventCount = 1; MatchedLimitReached = $false; FilteredOutHighVolume = $true; XPathUsed = '*'; TraceStats = $null; CircularWrapWarning = $null; LumaBridgeEvents = @(); Providers = @(); Events = @(); Error = '' } }
        'Invoke-LumaBridgeHostProcess'                = {
            [CmdletBinding()] param([string]$ExecutablePath, [string[]]$Arguments = @(), [int]$HardTimeoutMs = 30000, [int]$ResourceSampleIntervalSec = 0, [Nullable[int]]$WudfProcessId = $null, [switch]$DryRun)
            return [pscustomobject]@{ ExitCode = 1; TimedOut = $false; ProcessId = 4401; Output = @('Simulated host connect timeout'); StdErr = @(); DryRun = $false }
        }
    }

    Invoke-WithModuleMocks -GlobalMocks $sharedMocks -ModuleMocks $sharedMocks -Body {
        Assert-Throws {
            & $valScript `
                -Configuration Release `
                -StagingDir $liveStg `
                -OutputDir $liveOut `
                -HostExecutablePath $fakeHostExe `
                -CertificateThumbprint $certInfo.Thumbprint `
                -AllowUntrustedChain `
                -SkipDriverInstall `
                -Force
        } -ExpectedPattern 'RollbackClean=True' -Message 'Simulated host failure must trigger clean finally rollback'
    }

    $stAfterHostFail = $global:LbTestState['ValMock']
    Assert-Equal $stAfterHostFail.EnableExt 0 'finally reverted EnableFrameExtraction to 0 after host failure'
    Assert-Equal $stAfterHostFail.AuthSid $null 'finally cleared AuthorizedHostUserSid after host failure'
    Assert-Equal $stAfterHostFail.EnableMon 0 'finally restored EnableVirtualMonitor to 0 after host failure'
    Assert-Equal $stAfterHostFail.EtwRunning $false 'ETW stopped cleanly after host failure'
    Assert-True ($stAfterHostFail.RestartCount -ge 3) 'Device restarted on enable + finally rollback'
    Assert-True (Test-Path -LiteralPath (Join-Path $liveOut 'functional-validation-report.json') -PathType Leaf) 'Validation report JSON persisted on failure'
    $failReport = Get-Content -LiteralPath (Join-Path $liveOut 'functional-validation-report.json') -Raw | ConvertFrom-Json
    Assert-Equal $failReport.RollbackClean $true 'Report records RollbackClean=true'
    Assert-Equal $failReport.SignedStagingDir $liveStg 'Report records StagingDir'

    # Case B: Mid-flight Stage 8 exception (before Stage 10 stops ETW) -> finally must stop active ETW and revert state
    $liveOut2 = Join-Path $caseDir 'live_out2'
    $st2 = $global:LbTestState['ValMock']
    $st2.EnableMon = 0
    $st2.EnableExt = 0
    $st2.AuthSid = $null
    $st2.EtwRunning = $false
    $st2.EtwStopCalls = 0
    $st2.RestartCount = 0
    $st2.InjectStage8Fail = $true

    Invoke-WithModuleMocks -GlobalMocks $sharedMocks -ModuleMocks $sharedMocks -Body {
        Assert-Throws {
            & $valScript `
                -Configuration Release `
                -StagingDir $liveStg `
                -OutputDir $liveOut2 `
                -HostExecutablePath $fakeHostExe `
                -CertificateThumbprint $certInfo.Thumbprint `
                -AllowUntrustedChain `
                -SkipDriverInstall `
                -Force
        } -ExpectedPattern 'Simulated Stage 8 pnputil restart failure.*RollbackClean=True' -Message 'Mid-flight Stage 8 crash triggers finally ETW stop and registry rollback'
    }

    Assert-Equal $st2.EtwRunning $false 'finally stopped ETW after Stage 8 exception'
    Assert-Equal $st2.EtwStopCalls 1 'finally invoked ETW Stop exactly once on mid-flight exception'
    Assert-Equal $st2.EnableExt 0 'finally reverted EnableFrameExtraction=0 after Stage 8 exception'
    Assert-Equal $st2.AuthSid $null 'finally cleared AuthorizedHostUserSid after Stage 8 exception'
    Assert-Equal $st2.EnableMon 0 'finally reverted EnableVirtualMonitor=0 after Stage 8 exception'
}

# 31. Host stdout/stderr capture, hard timeout handling, and two-profile Smoke vs Performance validation
Invoke-UnitTest -Name 'HostProcessOutputCaptureGlobalTimeoutAndTwoProfileRunner' -TestBody {
    param($caseDir)

    # 1. Verify Invoke-LumaBridgeHostProcess captures stdout + stderr cleanly via ReadToEndAsync
    $psExe = (Get-Command powershell.exe).Source
    $capRes = Invoke-LumaBridgeHostProcess -ExecutablePath $psExe -Arguments @('-NoProfile', '-Command', '[Console]::Out.WriteLine("LB_STDOUT_OK"); [Console]::Error.WriteLine("LB_STDERR_OK"); exit 0') -HardTimeoutMs 10000
    Assert-Equal $capRes.ExitCode 0 'Capture helper exits 0'
    Assert-Equal $capRes.TimedOut $false 'Capture helper did not time out'
    Assert-True ($capRes.Output -contains 'LB_STDOUT_OK') 'Invoke-LumaBridgeHostProcess captures stdout lines non-empty'
    Assert-True ($capRes.StdErr -contains 'LB_STDERR_OK') 'Invoke-LumaBridgeHostProcess captures stderr lines non-empty'

    # 2. Verify global hard timeout kills hung child process and marks TimedOut=true
    $timeoutRes = Invoke-LumaBridgeHostProcess -ExecutablePath $psExe -Arguments @('-NoProfile', '-Command', '[Console]::Out.WriteLine("BEFORE_HANG"); [Console]::Out.Flush(); Start-Sleep -Seconds 30') -HardTimeoutMs 600
    Assert-Equal $timeoutRes.TimedOut $true 'Global hard timeout terminates hung process cleanly'
    Assert-Equal $timeoutRes.ExitCode -1 'Global hard timeout returns ExitCode=-1'

    # 3. Verify two-profile runner separates FunctionalSmokePassed from PerformanceTestExecuted/Reached
    $valScript = Join-Path $scriptsDir 'Invoke-LumaBridgeFunctionalValidation.ps1'
    $certInfo = New-EphemeralTestCertificate -OutDirectory (Join-Path $caseDir 'certs') -NamePrefix 'val2prof'
    $stgDir = Join-Path $caseDir 'stg_prof'
    $outSmokeOnly = Join-Path $caseDir 'out_smoke_only'
    $outBothFailPerf = Join-Path $caseDir 'out_both_fail_perf'
    $fakeHostExe = Join-Path $caseDir 'lumabridge-host.exe'
    [System.IO.File]::WriteAllBytes($fakeHostExe, [byte[]]@(0x4D, 0x5A, 0x90, 0x00))

    $c = Get-LumaBridgeDriverConstants
    $mockLogmanLines = @(
        'Name:                 LumaBridgeIddCore',
        ('Provider:             {0}' -f $c.LumaBridgeTraceProviderGuid),
        ('Provider:             {0}' -f $c.IddCxManifestProviderGuid),
        ('Provider:             {0}' -f $c.IddCxWppProviderGuid),
        ('Provider:             {0}' -f $c.UmdfOperationalProviderGuid),
        ('Provider:             {0}' -f $c.WdfCoreWppProviderGuid),
        ('Provider:             {0}' -f $c.WerKernelProviderGuid)
    )

    $global:LbTestState['ProfMock'] = [ordered]@{
        CertInfo    = $certInfo
        Signtool    = Get-LumaBridgeWdkToolPath -ToolName 'signtool.exe'
        LogmanLines = $mockLogmanLines
        EnableMon   = 0
        EnableExt   = 0
        AuthSid     = $null
        EtwRunning  = $false
        PerfFails   = $false
    }

    $profMocks = @{
        'Assert-LumaBridgeAdministrator'            = { [CmdletBinding()] param([string]$OperationName, [switch]$DryRun) return $true }
        'Get-LumaBridgeHostSecurityState'           = { [CmdletBinding()] param() return [pscustomobject]@{ SecureBoot = 'Disabled'; TestSigning = 'Enabled' } }
        'Find-LumaBridgeSigningCertificate'         = { [CmdletBinding()] param([string]$CertificateThumbprint, [string]$CertificateSubject) return $global:LbTestState['ProfMock'].CertInfo.Certificate }
        'Export-LumaBridgeCertificateFile'          = { [CmdletBinding()] param($Certificate, [string]$FilePath) [System.IO.File]::WriteAllBytes($FilePath, $Certificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)) }
        'Get-LumaBridgePnpInstances'                = {
            [CmdletBinding()] param([string]$HardwareId)
            $st = $global:LbTestState['ProfMock']
            return @([pscustomobject]@{
                InstanceId            = 'ROOT\DISPLAY\0000'
                FriendlyName          = 'LumaBridge Indirect Display Adapter'
                Status                = 'OK'
                ProblemCode           = 0
                ProblemStatus         = 0
                ProblemStatusHex      = '0x00000000'
                Present               = $true
                HardwareIds           = @('Root\LumaBridgeIddDriver')
                DriverInfPath         = 'oem99.inf'
                DriverProvider        = 'LumaBridge'
                DriverVersion         = (Get-LumaBridgeInfDriverVersion -InfPath (Join-Path (Get-LumaBridgePackageDirectory -Configuration Release) 'LumaBridgeIddDriver.inf'))
                DriverService         = 'WUDFRd'
                UpperFilters          = @('IndirectKmd')
                LowerFilters          = @()
                ConfigurationId       = 'oem99.inf:Root\LumaBridgeIddDriver'
                DeviceParametersPath  = 'MOCK:\ROOT\DISPLAY\0000\Device Parameters'
                EnableVirtualMonitor  = $st.EnableMon
                EnableFrameExtraction = $st.EnableExt
                AuthorizedHostUserSid = $st.AuthSid
                StartupDiagnostics    = [pscustomobject]@{ LastStage = 'AdapterInitFinished'; LastSuccessfulStage = 'AdapterInitFinished'; LastStatusHex = '0x00000000'; LastErrorStatusHex = '0x00000000' }
            })
        }
        'Set-LumaBridgeDeviceEnableVirtualMonitor'  = { [CmdletBinding()] param([string]$DeviceParametersPath, [int]$Value = 0, [switch]$Clear) if ($Clear) { $global:LbTestState['ProfMock'].EnableMon = $null } else { $global:LbTestState['ProfMock'].EnableMon = $Value } }
        'Get-LumaBridgeDeviceEnableVirtualMonitor'  = { [CmdletBinding()] param([string]$DeviceParametersPath) return $global:LbTestState['ProfMock'].EnableMon }
        'Set-LumaBridgeDeviceEnableFrameExtraction' = { [CmdletBinding()] param([string]$DeviceParametersPath, [int]$Value = 0, [switch]$Clear) if ($Clear) { $global:LbTestState['ProfMock'].EnableExt = $null } else { $global:LbTestState['ProfMock'].EnableExt = $Value } }
        'Get-LumaBridgeDeviceEnableFrameExtraction' = { [CmdletBinding()] param([string]$DeviceParametersPath) return $global:LbTestState['ProfMock'].EnableExt }
        'Set-LumaBridgeDeviceAuthorizedHostUserSid' = { [CmdletBinding()] param([string]$DeviceParametersPath, [string]$SidString, [switch]$Clear) if ($Clear -or [string]::IsNullOrWhiteSpace($SidString)) { $global:LbTestState['ProfMock'].AuthSid = $null } else { $global:LbTestState['ProfMock'].AuthSid = $SidString } }
        'Get-LumaBridgeDeviceAuthorizedHostUserSid' = { [CmdletBinding()] param([string]$DeviceParametersPath) return $global:LbTestState['ProfMock'].AuthSid }
        'Get-LumaBridgeWudfHostProcesses'           = { [CmdletBinding()] param($PnpInstances, $RecentEvents, $DebugTraceLines, [Nullable[DateTime]]$NotBeforeUtc = $null, [Nullable[int]]$ExpectedHostPid = $null) return @([pscustomobject]@{ Id = 8768; IsLumaBridgeHost = $true; AssociationMethod = 'LoadedModule'; WorkingSetMB = 30.0; PrivateMemoryMB = 15.0; HandleCount = 400; StartedAfterAnchor = $true }) }
        'Get-LumaBridgeCrashDumpInventory'          = { [CmdletBinding()] param([int]$LookbackMinutes) return [pscustomobject]@{ LookbackMinutes = $LookbackMinutes; Locations = @(); Files = @(); TotalFoundCount = 0 } }
        'Get-LumaBridgeEventChannelStatus'            = { [CmdletBinding()] param($ChannelNames) return @() }
        'Get-LumaBridgeDiagnosticEvents'            = { [CmdletBinding()] param($LookbackMinutes, $InstanceIds, $PublishedInfNames, $ChannelStatus) return @() }
        'Get-LumaBridgeSetupApiLogExcerpt'          = { [CmdletBinding()] param($SetupApiLogPath, $InstanceIds, $PublishedInfNames, $MaxMatchedSections) return [pscustomobject]@{ LogPath = $SetupApiLogPath; Exists = $false; AccessDenied = $false; Error = ''; MatchedSectionCount = 0; WdfSchemaWarnings = @(); DeviceStartProblemLines = @(); Sections = @(); RawExcerptText = '' } }
        'Get-LumaBridgeDriverStorePackages'         = { [CmdletBinding()] param($InfFilter) return @() }
        'Get-LumaBridgeEtlEventSummary'             = { [CmdletBinding()] param($EtlPath, $StartTimeUtc, $EndTimeUtc, $ProcessId, [int]$MaxMatchedEvents = 500, [switch]$ExcludeHighVolumeGraphics) return [pscustomobject]@{ EtlPath = $EtlPath; Exists = $true; EventCount = 1; MatchedEventCount = 1; MatchedLimitReached = $false; FilteredOutHighVolume = $true; XPathUsed = '*'; TraceStats = $null; CircularWrapWarning = $null; LumaBridgeEvents = @(); Providers = @(); Events = @(); Error = '' } }
        'Invoke-LumaBridgeExternalCommand'          = {
            [CmdletBinding()] param([string]$FilePath, [string[]]$Arguments = @(), [switch]$DryRun)
            $st = $global:LbTestState['ProfMock']
            if ($FilePath -like '*git*') { return [pscustomobject]@{ ExitCode = 0; Output = @('feature/windows-frame-extraction-ipc'); DryRun = $false } }
            if ($FilePath -ieq $st.Signtool -and $Arguments[0] -eq 'sign') {
                $out = & $FilePath sign /fd SHA256 /f $st.CertInfo.PfxPath /p $st.CertInfo.Password $Arguments[-1] 2>&1
                if ($LASTEXITCODE -ne 0) { throw 'mock signtool sign error' }
                return [pscustomobject]@{ ExitCode = 0; Output = @($out); DryRun = $false }
            }
            if ($FilePath -like '*Inf2Cat*' -or ($FilePath -ieq $st.Signtool -and $Arguments[0] -eq 'verify')) {
                $out = & $FilePath @Arguments 2>&1
                if ($LASTEXITCODE -ne 0) { throw 'mock verify error' }
                return [pscustomobject]@{ ExitCode = 0; Output = @($out); DryRun = $false }
            }
            if ($FilePath -like '*logman*') {
                if ($Arguments[0] -eq 'query' -and $Arguments[1] -eq 'LumaBridgeIddDxg') { throw 'not found' }
                if ($Arguments[0] -eq 'query') { return [pscustomobject]@{ ExitCode = 0; Output = $st.LogmanLines; DryRun = $false } }
            }
            return [pscustomobject]@{ ExitCode = 0; Output = @('OK'); DryRun = $false }
        }
        'Invoke-LumaBridgeHostProcess'              = {
            [CmdletBinding()] param([string]$ExecutablePath, [string[]]$Arguments = @(), [int]$HardTimeoutMs = 30000, [int]$ResourceSampleIntervalSec = 0, [Nullable[int]]$WudfProcessId = $null, [switch]$DryRun)
            $jsonIdx = [Array]::IndexOf($Arguments, '--json-summary')
            $jsonPath = $Arguments[$jsonIdx + 1]
            $runIdIdx = [Array]::IndexOf($Arguments, '--run-id')
            $runIdVal = if ($runIdIdx -ge 0 -and ($runIdIdx + 1) -lt $Arguments.Count) { [string]$Arguments[$runIdIdx + 1] } else { '' }
            $isPerf = ($Arguments -contains '--require-max-frames')
            $st = $global:LbTestState['ProfMock']
            if (-not $isPerf) {
                $payload = [pscustomobject]@{
                    RunId = $runIdVal; SummaryComplete = $true;
                    ExitReason = 'DurationElapsed'; HostProcessExitedNormally = $true; TransportHealthy = $true;
                    ConnectCount = 1; FramesReceived = 3; FramesValid = 3; LiveFramesReceived = 0; PreConnectFramesReceived = 3;
                    FrameTargetReached = $false; MinFramesReached = $true; ChecksumMismatches = 0; ProtocolErrors = 0; FatalIoTimeouts = 0; FatalIpcErrors = 0;
                    LastFrameSequence = 33; LastFrameWidth = 1920; LastFrameHeight = 1080; LastProtocolStatus = 'Ok'; AvgEndToEndLatencyUs = 1200; ReceiveFps = 0.6;
                    TimestampMeasurementErrors = 0; OutOfOrderSequenceCount = 0; NonMonotonicTimestampCount = 0; MissingCoreTimestampCount = 0;
                    FutureTimestampErrorCount = 0; IncompatibleTimestampUnitsCount = 0; QpcFrequencyMismatchCount = 0;
                    ValidCoreTimestampSamples = 3; ValidLiveTimestampSamples = 0; ValidPresentTimestampSamples = 0;
                    CoreTimestampCoveragePercent = 100.0; LiveTimestampCoveragePercent = 0.0; PresentTimestampCoveragePercent = 0.0;
                    EndToEndLatency = [pscustomobject]@{ Available = $true; SampleCount = 3; AvgUs = 1200; P95Us = 1400; P99Us = 1450 };
                    LiveEndToEndLatency = [pscustomobject]@{ Available = $false; SampleCount = 0; AvgUs = 0; P95Us = 0; P99Us = 0 }
                }
                $payload | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $jsonPath -Encoding UTF8
                return [pscustomobject]@{ ExitCode = 0; TimedOut = $false; ProcessId = 4401; Output = @('[LB-HOST] Summary: frames=3'); StdErr = @(); DryRun = $false }
            }
            else {
                $failPerf = $st.PerfFails
                $fc = $(if ($failPerf) { 12 } else { 60 })
                $payload = [pscustomobject]@{
                    RunId = $runIdVal; SummaryComplete = $true;
                    ExitReason = 'DurationElapsed'; HostProcessExitedNormally = $true; TransportHealthy = $true;
                    ConnectCount = 1; FramesReceived = $fc; FramesValid = $fc; LiveFramesReceived = $fc; PreConnectFramesReceived = 0;
                    FrameTargetReached = (-not $failPerf); ChecksumMismatches = 0; ProtocolErrors = 0; FatalIoTimeouts = 0; FatalIpcErrors = 0;
                    LastFrameSequence = 93; LastFrameWidth = 1920; LastFrameHeight = 1080; LastProtocolStatus = 'Ok'; AvgEndToEndLatencyUs = 2400; ReceiveFps = 58.5;
                    TimestampMeasurementErrors = 0; OutOfOrderSequenceCount = 0; NonMonotonicTimestampCount = 0; MissingCoreTimestampCount = 0;
                    FutureTimestampErrorCount = 0; IncompatibleTimestampUnitsCount = 0; QpcFrequencyMismatchCount = 0;
                    ValidCoreTimestampSamples = $fc; ValidLiveTimestampSamples = $fc; ValidPresentTimestampSamples = $fc;
                    CoreTimestampCoveragePercent = 100.0; LiveTimestampCoveragePercent = 100.0; PresentTimestampCoveragePercent = 100.0;
                    EndToEndLatency = [pscustomobject]@{ Available = $true; SampleCount = $fc; AvgUs = 2400; P95Us = 3200; P99Us = 3800 };
                    LiveEndToEndLatency = [pscustomobject]@{ Available = $true; SampleCount = $fc; AvgUs = 2400; P95Us = 3200; P99Us = 3800 };
                    VisualStimulus = [pscustomobject]@{ VirtualDisplayIdentified = $true; Started = $true }
                }
                $payload | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $jsonPath -Encoding UTF8
                return [pscustomobject]@{ ExitCode = $(if ($failPerf) { 1 } else { 0 }); TimedOut = $false; ProcessId = 4401; Output = @('[LB-HOST] Summary: perf'); StdErr = @(); DryRun = $false }
            }
        }
    }

    Invoke-WithModuleMocks -GlobalMocks $profMocks -ModuleMocks $profMocks -Body {
        $smokeRes = & $valScript -Configuration Release -TestProfile Smoke -StagingDir $stgDir -OutputDir $outSmokeOnly -HostExecutablePath $fakeHostExe -CertificateThumbprint $certInfo.Thumbprint -AllowUntrustedChain -SkipDriverInstall -Force
        Assert-Equal $smokeRes.ValidationSucceeded $true 'Smoke profile passes on 3 valid frames (<60) when host exits 0 cleanly'
        Assert-Equal $smokeRes.AcceptanceCriteria.FunctionalSmokePassed $true 'FunctionalSmokePassed is true'
        Assert-Equal $smokeRes.AcceptanceCriteria.FrameTargetReached $false 'Smoke faithfully records FrameTargetReached=false for 3/60'
        Assert-Equal $smokeRes.AcceptanceCriteria.PerformanceTestExecuted $false 'Smoke profile does not mark PerformanceTestExecuted=true'
        Assert-Equal $smokeRes.AcceptanceCriteria.PerformanceTargetReached $false 'Smoke profile does not mark unexecuted PerformanceTest as passed'
        Assert-Equal $smokeRes.RollbackClean $true 'RollbackClean is true after Smoke'
    }

    $global:LbTestState['ProfMock'].PerfFails = $true
    Invoke-WithModuleMocks -GlobalMocks $profMocks -ModuleMocks $profMocks -Body {
        Assert-Throws {
            & $valScript -Configuration Release -TestProfile Both -StagingDir $stgDir -OutputDir $outBothFailPerf -HostExecutablePath $fakeHostExe -CertificateThumbprint $certInfo.Thumbprint -AllowUntrustedChain -SkipDriverInstall -Force
        } -ExpectedPattern 'PerformanceTargetReached.*RollbackClean=True' -Message 'Profile Both rejects missed perf target while keeping clean rollback'
    }
    $failBothReport = Get-Content -LiteralPath (Join-Path $outBothFailPerf 'functional-validation-report.json') -Raw | ConvertFrom-Json
    Assert-Equal $failBothReport.AcceptanceCriteria.FunctionalSmokePassed $true 'Smoke remained passed even when Perf target failed'
    Assert-Equal $failBothReport.AcceptanceCriteria.PerformanceTestExecuted $true 'PerformanceTestExecuted recorded true'
    Assert-Equal $failBothReport.AcceptanceCriteria.PerformanceTargetReached $false 'PerformanceTargetReached recorded false'
    Assert-Equal $failBothReport.RollbackClean $true 'RollbackClean=true after Perf failure'
}

Invoke-UnitTest -Name 'M42GpuTransportNvencGatesAndRollback' -TestBody {
    param($caseDir)
    $valScript = Join-Path $scriptsDir 'Invoke-LumaBridgeFunctionalValidation.ps1'
    $certInfo = New-EphemeralTestCertificate -OutDirectory (Join-Path $caseDir 'certs') -NamePrefix 'm42'
    $stgDir = Join-Path $caseDir 'stg_m42'
    $outCpuRollback = Join-Path $caseDir 'out_cpu_rollback'
    $outGpuNvencPass = Join-Path $caseDir 'out_gpu_nvenc_pass'
    $outGpuCpuReadFail = Join-Path $caseDir 'out_gpu_cpuread_fail'
    $fakeHostExe = Join-Path $caseDir 'lumabridge-host.exe'
    [System.IO.File]::WriteAllBytes($fakeHostExe, [byte[]]@(0x4D, 0x5A, 0x90, 0x00))

    $c = Get-LumaBridgeDriverConstants
    Assert-Equal $c.RegistryValueEnableGpuTrans 'EnableGpuSharedTransport' 'Constant RegistryValueEnableGpuTrans matches driver REG_DWORD name'

    $mockLogmanLines = @(
        'Name:                 LumaBridgeIddCore',
        ('Provider:             {0}' -f $c.LumaBridgeTraceProviderGuid),
        ('Provider:             {0}' -f $c.IddCxManifestProviderGuid),
        ('Provider:             {0}' -f $c.IddCxWppProviderGuid),
        ('Provider:             {0}' -f $c.UmdfOperationalProviderGuid),
        ('Provider:             {0}' -f $c.WdfCoreWppProviderGuid),
        ('Provider:             {0}' -f $c.WerKernelProviderGuid)
    )

    $global:LbTestState['M42Mock'] = [ordered]@{
        CertInfo       = $certInfo
        Signtool       = Get-LumaBridgeWdkToolPath -ToolName 'signtool.exe'
        LogmanLines    = $mockLogmanLines
        EnableMon      = 0
        EnableExt      = 0
        EnableGpuTrans = $null
        ObservedGpuDuringStage8 = $null
        AuthSid        = $null
        EtwRunning     = $false
        SimulateCpuReadViolation = $false
    }

    $m42Mocks = @{
        'Assert-LumaBridgeAdministrator'               = { [CmdletBinding()] param([string]$OperationName, [switch]$DryRun) return $true }
        'Get-LumaBridgeHostSecurityState'              = { [CmdletBinding()] param() return [pscustomobject]@{ SecureBoot = 'Disabled'; TestSigning = 'Enabled' } }
        'Find-LumaBridgeSigningCertificate'            = { [CmdletBinding()] param([string]$CertificateThumbprint, [string]$CertificateSubject) return $global:LbTestState['M42Mock'].CertInfo.Certificate }
        'Export-LumaBridgeCertificateFile'             = { [CmdletBinding()] param($Certificate, [string]$FilePath) [System.IO.File]::WriteAllBytes($FilePath, $Certificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)) }
        'Get-LumaBridgePnpInstances'                   = {
            [CmdletBinding()] param([string]$HardwareId)
            $st = $global:LbTestState['M42Mock']
            return @([pscustomobject]@{
                InstanceId = 'ROOT\DISPLAY\0000'; FriendlyName = 'LumaBridge Indirect Display Adapter'; Status = 'OK';
                ProblemCode = 0; ProblemStatus = 0; ProblemStatusHex = '0x00000000'; Present = $true;
                HardwareIds = @('Root\LumaBridgeIddDriver'); DriverInfPath = 'oem99.inf'; DriverProvider = 'LumaBridge';
                DriverVersion = (Get-LumaBridgeInfDriverVersion -InfPath (Join-Path (Get-LumaBridgePackageDirectory -Configuration Release) 'LumaBridgeIddDriver.inf')); DriverService = 'WUDFRd'; UpperFilters = @('IndirectKmd'); LowerFilters = @();
                ConfigurationId = 'oem99.inf:Root\LumaBridgeIddDriver'; DeviceParametersPath = 'MOCK:\ROOT\DISPLAY\0000\Device Parameters';
                EnableVirtualMonitor = $st.EnableMon; EnableFrameExtraction = $st.EnableExt;
                EnableGpuSharedTransport = $st.EnableGpuTrans; AuthorizedHostUserSid = $st.AuthSid;
                StartupDiagnostics = [pscustomobject]@{ LastStage = 'AdapterInitFinished'; LastSuccessfulStage = 'AdapterInitFinished'; LastStatusHex = '0x00000000'; LastErrorStatusHex = '0x00000000' }
            })
        }
        'Set-LumaBridgeDeviceEnableVirtualMonitor'     = { [CmdletBinding()] param([string]$DeviceParametersPath, [int]$Value = 0, [switch]$Clear) if ($Clear) { $global:LbTestState['M42Mock'].EnableMon = $null } else { $global:LbTestState['M42Mock'].EnableMon = $Value } }
        'Get-LumaBridgeDeviceEnableVirtualMonitor'     = { [CmdletBinding()] param([string]$DeviceParametersPath) return $global:LbTestState['M42Mock'].EnableMon }
        'Set-LumaBridgeDeviceEnableFrameExtraction'    = { [CmdletBinding()] param([string]$DeviceParametersPath, [int]$Value = 0, [switch]$Clear) if ($Clear) { $global:LbTestState['M42Mock'].EnableExt = $null } else { $global:LbTestState['M42Mock'].EnableExt = $Value } }
        'Get-LumaBridgeDeviceEnableFrameExtraction'    = { [CmdletBinding()] param([string]$DeviceParametersPath) return $global:LbTestState['M42Mock'].EnableExt }
        'Set-LumaBridgeDeviceEnableGpuSharedTransport' = {
            [CmdletBinding()] param([string]$DeviceParametersPath, [int]$Value = 1, [switch]$Clear)
            $st = $global:LbTestState['M42Mock']
            if ($Clear) { $st.EnableGpuTrans = $null } else { $st.EnableGpuTrans = $Value; $st.ObservedGpuDuringStage8 = $Value }
        }
        'Get-LumaBridgeDeviceEnableGpuSharedTransport' = { [CmdletBinding()] param([string]$DeviceParametersPath) return $global:LbTestState['M42Mock'].EnableGpuTrans }
        'Set-LumaBridgeDeviceAuthorizedHostUserSid'    = { [CmdletBinding()] param([string]$DeviceParametersPath, [string]$SidString, [switch]$Clear) if ($Clear -or [string]::IsNullOrWhiteSpace($SidString)) { $global:LbTestState['M42Mock'].AuthSid = $null } else { $global:LbTestState['M42Mock'].AuthSid = $SidString } }
        'Get-LumaBridgeDeviceAuthorizedHostUserSid'    = { [CmdletBinding()] param([string]$DeviceParametersPath) return $global:LbTestState['M42Mock'].AuthSid }
        'Get-LumaBridgeWudfHostProcesses'              = { [CmdletBinding()] param($PnpInstances, $RecentEvents, $DebugTraceLines, [Nullable[DateTime]]$NotBeforeUtc = $null, [Nullable[int]]$ExpectedHostPid = $null) return @([pscustomobject]@{ Id = 8768; IsLumaBridgeHost = $true; AssociationMethod = 'LoadedModule'; WorkingSetMB = 30.0; PrivateMemoryMB = 15.0; HandleCount = 400; StartedAfterAnchor = $true }) }
        'Get-LumaBridgeCrashDumpInventory'             = { [CmdletBinding()] param([int]$LookbackMinutes) return [pscustomobject]@{ LookbackMinutes = $LookbackMinutes; Locations = @(); Files = @(); TotalFoundCount = 0 } }
        'Get-LumaBridgeEventChannelStatus'             = { [CmdletBinding()] param($ChannelNames) return @() }
        'Get-LumaBridgeDiagnosticEvents'               = { [CmdletBinding()] param($LookbackMinutes, $InstanceIds, $PublishedInfNames, $ChannelStatus) return @() }
        'Get-LumaBridgeSetupApiLogExcerpt'             = { [CmdletBinding()] param($SetupApiLogPath, $InstanceIds, $PublishedInfNames, $MaxMatchedSections) return [pscustomobject]@{ LogPath = $SetupApiLogPath; Exists = $false; AccessDenied = $false; Error = ''; MatchedSectionCount = 0; WdfSchemaWarnings = @(); DeviceStartProblemLines = @(); Sections = @(); RawExcerptText = '' } }
        'Get-LumaBridgeDriverStorePackages'            = { [CmdletBinding()] param($InfFilter) return @() }
        'Get-LumaBridgeEtlEventSummary'                = { [CmdletBinding()] param($EtlPath, $StartTimeUtc, $EndTimeUtc, $ProcessId, [int]$MaxMatchedEvents = 500, [switch]$ExcludeHighVolumeGraphics) return [pscustomobject]@{ EtlPath = $EtlPath; Exists = $true; EventCount = 1; MatchedEventCount = 1; MatchedLimitReached = $false; FilteredOutHighVolume = $true; XPathUsed = '*'; TraceStats = $null; CircularWrapWarning = $null; LumaBridgeEvents = @(); Providers = @(); Events = @(); Error = '' } }
        'Invoke-LumaBridgeExternalCommand'             = {
            [CmdletBinding()] param([string]$FilePath, [string[]]$Arguments = @(), [switch]$DryRun)
            $st = $global:LbTestState['M42Mock']
            if ($FilePath -like '*git*') { return [pscustomobject]@{ ExitCode = 0; Output = @('feature/windows-gpu-shared-textures-nvenc'); DryRun = $false } }
            if ($DryRun) { return [pscustomobject]@{ ExitCode = 0; Output = @('[DRY-RUN]'); DryRun = $true } }
            if ($FilePath -ieq $st.Signtool -and $Arguments[0] -eq 'sign') {
                $out = & $FilePath sign /fd SHA256 /f $st.CertInfo.PfxPath /p $st.CertInfo.Password $Arguments[-1] 2>&1
                if ($LASTEXITCODE -ne 0) { throw 'mock signtool sign error' }
                return [pscustomobject]@{ ExitCode = 0; Output = @($out); DryRun = $false }
            }
            if ($FilePath -like '*Inf2Cat*' -or ($FilePath -ieq $st.Signtool -and $Arguments[0] -eq 'verify')) {
                $out = & $FilePath @Arguments 2>&1
                if ($LASTEXITCODE -ne 0) { throw 'mock verify error' }
                return [pscustomobject]@{ ExitCode = 0; Output = @($out); DryRun = $false }
            }
            if ($FilePath -like '*logman*') {
                if ($Arguments[0] -eq 'query' -and $Arguments[1] -eq 'LumaBridgeIddDxg') { throw 'not found' }
                if ($Arguments[0] -eq 'query') { return [pscustomobject]@{ ExitCode = 0; Output = $st.LogmanLines; DryRun = $false } }
            }
            return [pscustomobject]@{ ExitCode = 0; Output = @('OK'); DryRun = $false }
        }
        'Invoke-LumaBridgeHostProcess'                 = {
            [CmdletBinding()] param([string]$ExecutablePath, [string[]]$Arguments = @(), [int]$HardTimeoutMs = 30000, [int]$ResourceSampleIntervalSec = 0, [Nullable[int]]$WudfProcessId = $null, [switch]$DryRun)
            if ($DryRun) {
                $stDry = $global:LbTestState['M42Mock']
                $stDry.LastDryRunArgs = @($Arguments)
                return [pscustomobject]@{ ExitCode = 0; TimedOut = $false; ProcessId = 0; Output = @('[DRY-RUN] host'); StdErr = @(); DryRun = $true }
            }
            $jsonIdx = [Array]::IndexOf($Arguments, '--json-summary')
            $jsonPath = $Arguments[$jsonIdx + 1]
            $runIdIdx = [Array]::IndexOf($Arguments, '--run-id')
            $runIdVal = if ($runIdIdx -ge 0 -and ($runIdIdx + 1) -lt $Arguments.Count) { [string]$Arguments[$runIdIdx + 1] } else { '' }
            $st = $global:LbTestState['M42Mock']
            $isGpu = ($Arguments -contains '--require-gpu-shared')
            $cpuReads = if ($st.SimulateCpuReadViolation) { 5 } else { 0 }
            $payload = [pscustomobject]@{
                RunId = $runIdVal; SummaryComplete = $true;
                ExitReason = 'FrameTargetReached'; HostProcessExitedNormally = $true; TransportHealthy = $true;
                NegotiatedTransportMode = $(if ($isGpu) { 'GpuSharedNtHandle' } else { 'CpuStagingPipe' });
                FallbackToCpuActivated = $false; GpuFramesOpened = $(if ($isGpu) { 3 } else { 0 });
                GpuSharedOpenFailures = 0; GpuSyncTimeouts = 0; AdapterMismatchErrors = 0; CpuStagingReadsPerformed = $cpuReads;
                ConnectCount = 1; FramesReceived = 60; FramesValid = 60; LiveFramesReceived = 60; PreConnectFramesReceived = 0;
                FrameTargetReached = $true; MinFramesReached = $true; TotalConnectedDurationUs = 1000000; SustainedLiveFps = 60.0;
                ChecksumMismatches = 0; ProtocolErrors = 0; FatalIoTimeouts = 0; FatalIpcErrors = 0;
                LastFrameSequence = 60; LastFrameWidth = 1920; LastFrameHeight = 1080; LastProtocolStatus = 'Ok'; AvgEndToEndLatencyUs = 450; ReceiveFps = 60.0;
                TimestampMeasurementErrors = 0; OutOfOrderSequenceCount = 0; NonMonotonicTimestampCount = 0; MissingCoreTimestampCount = 0;
                FutureTimestampErrorCount = 0; IncompatibleTimestampUnitsCount = 0; QpcFrequencyMismatchCount = 0;
                ValidCoreTimestampSamples = 60; ValidLiveTimestampSamples = 60; ValidPresentTimestampSamples = 60;
                CoreTimestampCoveragePercent = 100.0; LiveTimestampCoveragePercent = 100.0; PresentTimestampCoveragePercent = 100.0;
                EndToEndLatency = [pscustomobject]@{ Available = $true; SampleCount = 60; AvgUs = 450; P95Us = 800; P99Us = 950 };
                LiveEndToEndLatency = [pscustomobject]@{ Available = $true; SampleCount = 60; AvgUs = 450; P95Us = 800; P99Us = 950 };
                Nvenc = [pscustomobject]@{ NvencFramesSubmitted = 60; NvencFramesEncoded = 60; NvencDroppedFrames = 0; EncodedQueueDrops = 0; TotalBitstreamBytes = 2500000; InvalidTimestampCount = 0; ExtractToBitstreamCoveragePercent = 100.0; EncoderOutputFps = 60.0; Width = 1920; Height = 1080; Initialized = $true };
                H264DecodeValidation = [pscustomobject]@{ Passed = $true; StructuralDecodeValidated = $true; FidelityPsnrValidated = $false; PacketsInspected = 60; FramesDecoded = 60; NalParseFailures = 0; DecodeFailures = 0 };
                VisualStimulus = [pscustomobject]@{ VirtualDisplayIdentified = $true; Started = $true }
            }
            $payload | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $jsonPath -Encoding UTF8
            return [pscustomobject]@{ ExitCode = 0; TimedOut = $false; ProcessId = 4401; Output = @('[LB-HOST] Summary'); StdErr = @(); DryRun = $false }
        }
    }

    Invoke-WithModuleMocks -GlobalMocks $m42Mocks -ModuleMocks $m42Mocks -Body {
        $dryRes = & $valScript -Configuration Release -TestProfile Both -TransportMode Gpu -RequireGpuShared -EnableNvenc -RequireNvenc -NvencBitrateBps 20000000 -VerifyH264Decode -StagingDir $stgDir -OutputDir $outGpuNvencPass -HostExecutablePath $fakeHostExe -CertificateThumbprint $certInfo.Thumbprint -SkipDriverInstall -DryRun
        Assert-Equal $dryRes.DryRun $true 'M4.2 DryRun succeeded on feature/windows-gpu-shared-textures-nvenc branch'
        Assert-True ($global:LbTestState['M42Mock']['LastDryRunArgs'] -contains '--require-gpu-shared') 'DryRun forwards --require-gpu-shared'
        Assert-True ($global:LbTestState['M42Mock']['LastDryRunArgs'] -contains '--require-nvenc') 'DryRun forwards --require-nvenc'
        Assert-True ($global:LbTestState['M42Mock']['LastDryRunArgs'] -contains '--verify-h264-decode') 'DryRun forwards --verify-h264-decode'

        $cpuModeRes = & $valScript -Configuration Release -TestProfile Smoke -TransportMode Cpu -StagingDir $stgDir -OutputDir $outCpuRollback -HostExecutablePath $fakeHostExe -CertificateThumbprint $certInfo.Thumbprint -AllowUntrustedChain -SkipDriverInstall -Force
        Assert-Equal $cpuModeRes.ValidationSucceeded $true 'M4.2 -TransportMode Cpu validation succeeded'
        Assert-Equal $global:LbTestState['M42Mock'].ObservedGpuDuringStage8 0 'EnableGpuSharedTransport temporarily forced to 0 for -TransportMode Cpu'
        Assert-Equal $global:LbTestState['M42Mock'].EnableGpuTrans $null 'EnableGpuSharedTransport restored back to absent ($null) on rollback'
        Assert-Equal $cpuModeRes.RollbackClean $true 'RollbackClean after -TransportMode Cpu'

        $gpuNvencRes = & $valScript -Configuration Release -TestProfile Both -TransportMode Gpu -RequireGpuShared -EnableNvenc -RequireNvenc -VerifyH264Decode -StagingDir $stgDir -OutputDir $outGpuNvencPass -HostExecutablePath $fakeHostExe -CertificateThumbprint $certInfo.Thumbprint -AllowUntrustedChain -SkipDriverInstall -Force
        Assert-Equal $gpuNvencRes.ValidationSucceeded $true 'M4.2 GPU+NVENC+H264 validation passed'
        Assert-Equal $gpuNvencRes.AcceptanceCriteria.GpuSharedPassed $true 'GpuSharedPassed gate true'
        Assert-Equal $gpuNvencRes.AcceptanceCriteria.NvencPassed $true 'NvencPassed gate true'
        Assert-Equal $gpuNvencRes.AcceptanceCriteria.H264DecodePassed $true 'H264DecodePassed gate true'
        Assert-Equal $gpuNvencRes.RollbackClean $true 'RollbackClean after GPU+NVENC'

        $global:LbTestState['M42Mock'].SimulateCpuReadViolation = $true
        Assert-Throws {
            & $valScript -Configuration Release -TestProfile Smoke -TransportMode Gpu -RequireGpuShared -StagingDir $stgDir -OutputDir $outGpuCpuReadFail -HostExecutablePath $fakeHostExe -CertificateThumbprint $certInfo.Thumbprint -AllowUntrustedChain -SkipDriverInstall -Force
        } -ExpectedPattern 'GpuSharedPassed.*RollbackClean=True' -Message 'CpuStagingReadsPerformed > 0 violates RequireGpuShared GpuSharedPassed gate'
    }
}

Invoke-UnitTest -Name 'M421TimestampErrorsMaskingRejectedAndProlongedProfilesDryRun' -TestBody {
    param($caseDir)
    $valScript = Join-Path $scriptsDir 'Invoke-LumaBridgeFunctionalValidation.ps1'
    $certInfo = New-EphemeralTestCertificate -OutDirectory (Join-Path $caseDir 'certs') -NamePrefix 'm421'
    $stgDir = Join-Path $caseDir 'stg_m421'
    $outTsFail = Join-Path $caseDir 'out_ts_fail'
    $out120Pass = Join-Path $caseDir 'out_120_pass'
    $out30sPass = Join-Path $caseDir 'out_30s_pass'
    $fakeHostExe = Join-Path $caseDir 'lumabridge-host.exe'
    [System.IO.File]::WriteAllBytes($fakeHostExe, [byte[]]@(0x4D, 0x5A, 0x90, 0x00))

    $c = Get-LumaBridgeDriverConstants
    $mockLogmanLines = @(
        'Name:                 LumaBridgeIddCore',
        ('Provider:             {0}' -f $c.LumaBridgeTraceProviderGuid),
        ('Provider:             {0}' -f $c.IddCxManifestProviderGuid),
        ('Provider:             {0}' -f $c.IddCxWppProviderGuid),
        ('Provider:             {0}' -f $c.UmdfOperationalProviderGuid),
        ('Provider:             {0}' -f $c.WdfCoreWppProviderGuid),
        ('Provider:             {0}' -f $c.WerKernelProviderGuid)
    )

    $global:LbTestState['M421Mock'] = [ordered]@{
        CertInfo    = $certInfo
        Signtool    = Get-LumaBridgeWdkToolPath -ToolName 'signtool.exe'
        LogmanLines = $mockLogmanLines
        EnableMon   = 0
        EnableExt   = 0
        EnableGpuTrans = $null
        AuthSid     = $null
        Mode        = 'MaskingBug'
        DryArgsLog  = @{}
    }

    $m421Mocks = @{
        'Assert-LumaBridgeAdministrator'               = { [CmdletBinding()] param([string]$OperationName, [switch]$DryRun) return $true }
        'Get-LumaBridgeHostSecurityState'              = { [CmdletBinding()] param() return [pscustomobject]@{ SecureBoot = 'Disabled'; TestSigning = 'Enabled' } }
        'Find-LumaBridgeSigningCertificate'            = { [CmdletBinding()] param([string]$CertificateThumbprint, [string]$CertificateSubject) return $global:LbTestState['M421Mock'].CertInfo.Certificate }
        'Export-LumaBridgeCertificateFile'             = { [CmdletBinding()] param($Certificate, [string]$FilePath) [System.IO.File]::WriteAllBytes($FilePath, $Certificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)) }
        'Get-LumaBridgePnpInstances'                   = {
            [CmdletBinding()] param([string]$HardwareId)
            $st = $global:LbTestState['M421Mock']
            return @([pscustomobject]@{
                InstanceId = 'ROOT\DISPLAY\0000'; FriendlyName = 'LumaBridge Indirect Display Adapter'; Status = 'OK';
                ProblemCode = 0; ProblemStatus = 0; ProblemStatusHex = '0x00000000'; Present = $true;
                HardwareIds = @('Root\LumaBridgeIddDriver'); DriverInfPath = 'oem99.inf'; DriverProvider = 'LumaBridge';
                DriverVersion = (Get-LumaBridgeInfDriverVersion -InfPath (Join-Path (Get-LumaBridgePackageDirectory -Configuration Release) 'LumaBridgeIddDriver.inf')); DriverService = 'WUDFRd'; UpperFilters = @('IndirectKmd'); LowerFilters = @();
                ConfigurationId = 'oem99.inf:Root\LumaBridgeIddDriver'; DeviceParametersPath = 'MOCK:\ROOT\DISPLAY\0000\Device Parameters';
                EnableVirtualMonitor = $st.EnableMon; EnableFrameExtraction = $st.EnableExt;
                EnableGpuSharedTransport = $st.EnableGpuTrans; AuthorizedHostUserSid = $st.AuthSid;
                StartupDiagnostics = [pscustomobject]@{ LastStage = 'AdapterInitFinished'; LastSuccessfulStage = 'AdapterInitFinished'; LastStatusHex = '0x00000000'; LastErrorStatusHex = '0x00000000' }
            })
        }
        'Set-LumaBridgeDeviceEnableVirtualMonitor'     = { [CmdletBinding()] param([string]$DeviceParametersPath, [int]$Value = 0, [switch]$Clear) if ($Clear) { $global:LbTestState['M421Mock'].EnableMon = $null } else { $global:LbTestState['M421Mock'].EnableMon = $Value } }
        'Get-LumaBridgeDeviceEnableVirtualMonitor'     = { [CmdletBinding()] param([string]$DeviceParametersPath) return $global:LbTestState['M421Mock'].EnableMon }
        'Set-LumaBridgeDeviceEnableFrameExtraction'    = { [CmdletBinding()] param([string]$DeviceParametersPath, [int]$Value = 0, [switch]$Clear) if ($Clear) { $global:LbTestState['M421Mock'].EnableExt = $null } else { $global:LbTestState['M421Mock'].EnableExt = $Value } }
        'Get-LumaBridgeDeviceEnableFrameExtraction'    = { [CmdletBinding()] param([string]$DeviceParametersPath) return $global:LbTestState['M421Mock'].EnableExt }
        'Set-LumaBridgeDeviceEnableGpuSharedTransport' = {
            [CmdletBinding()] param([string]$DeviceParametersPath, [int]$Value = 1, [switch]$Clear)
            if ($Clear) { $global:LbTestState['M421Mock'].EnableGpuTrans = $null } else { $global:LbTestState['M421Mock'].EnableGpuTrans = $Value }
        }
        'Get-LumaBridgeDeviceEnableGpuSharedTransport' = { [CmdletBinding()] param([string]$DeviceParametersPath) return $global:LbTestState['M421Mock'].EnableGpuTrans }
        'Set-LumaBridgeDeviceAuthorizedHostUserSid'    = { [CmdletBinding()] param([string]$DeviceParametersPath, [string]$SidString, [switch]$Clear) if ($Clear -or [string]::IsNullOrWhiteSpace($SidString)) { $global:LbTestState['M421Mock'].AuthSid = $null } else { $global:LbTestState['M421Mock'].AuthSid = $SidString } }
        'Get-LumaBridgeDeviceAuthorizedHostUserSid'    = { [CmdletBinding()] param([string]$DeviceParametersPath) return $global:LbTestState['M421Mock'].AuthSid }
        'Get-LumaBridgeWudfHostProcesses'              = { [CmdletBinding()] param($PnpInstances, $RecentEvents, $DebugTraceLines, [Nullable[DateTime]]$NotBeforeUtc = $null, [Nullable[int]]$ExpectedHostPid = $null) return @([pscustomobject]@{ Id = 8768; IsLumaBridgeHost = $true; AssociationMethod = 'LoadedModule'; WorkingSetMB = 30.0; PrivateMemoryMB = 15.0; HandleCount = 400; StartedAfterAnchor = $true }) }
        'Get-LumaBridgeCrashDumpInventory'             = { [CmdletBinding()] param([int]$LookbackMinutes) return [pscustomobject]@{ LookbackMinutes = $LookbackMinutes; Locations = @(); Files = @(); TotalFoundCount = 0 } }
        'Get-LumaBridgeEventChannelStatus'             = { [CmdletBinding()] param($ChannelNames) return @() }
        'Get-LumaBridgeDiagnosticEvents'               = { [CmdletBinding()] param($LookbackMinutes, $InstanceIds, $PublishedInfNames, $ChannelStatus) return @() }
        'Get-LumaBridgeSetupApiLogExcerpt'             = { [CmdletBinding()] param($SetupApiLogPath, $InstanceIds, $PublishedInfNames, $MaxMatchedSections) return [pscustomobject]@{ LogPath = $SetupApiLogPath; Exists = $false; AccessDenied = $false; Error = ''; MatchedSectionCount = 0; WdfSchemaWarnings = @(); DeviceStartProblemLines = @(); Sections = @(); RawExcerptText = '' } }
        'Get-LumaBridgeDriverStorePackages'            = { [CmdletBinding()] param($InfFilter) return @() }
        'Get-LumaBridgeEtlEventSummary'                = { [CmdletBinding()] param($EtlPath, $StartTimeUtc, $EndTimeUtc, $ProcessId, [int]$MaxMatchedEvents = 500, [switch]$ExcludeHighVolumeGraphics) return [pscustomobject]@{ EtlPath = $EtlPath; Exists = $true; EventCount = 1; MatchedEventCount = 1; MatchedLimitReached = $false; FilteredOutHighVolume = $true; XPathUsed = '*'; TraceStats = $null; CircularWrapWarning = $null; LumaBridgeEvents = @(); Providers = @(); Events = @(); Error = '' } }
        'Invoke-LumaBridgeExternalCommand'             = {
            [CmdletBinding()] param([string]$FilePath, [string[]]$Arguments = @(), [switch]$DryRun)
            $st = $global:LbTestState['M421Mock']
            if ($FilePath -like '*git*') { return [pscustomobject]@{ ExitCode = 0; Output = @('feature/windows-gpu-shared-textures-nvenc'); DryRun = $false } }
            if ($DryRun) { return [pscustomobject]@{ ExitCode = 0; Output = @('[DRY-RUN]'); DryRun = $true } }
            if ($FilePath -ieq $st.Signtool -and $Arguments[0] -eq 'sign') {
                $out = & $FilePath sign /fd SHA256 /f $st.CertInfo.PfxPath /p $st.CertInfo.Password $Arguments[-1] 2>&1
                if ($LASTEXITCODE -ne 0) { throw 'mock signtool sign error' }
                return [pscustomobject]@{ ExitCode = 0; Output = @($out); DryRun = $false }
            }
            if ($FilePath -like '*Inf2Cat*' -or ($FilePath -ieq $st.Signtool -and $Arguments[0] -eq 'verify')) {
                $out = & $FilePath @Arguments 2>&1
                if ($LASTEXITCODE -ne 0) { throw 'mock verify error' }
                return [pscustomobject]@{ ExitCode = 0; Output = @($out); DryRun = $false }
            }
            if ($FilePath -like '*logman*') {
                if ($Arguments[0] -eq 'query' -and $Arguments[1] -eq 'LumaBridgeIddDxg') { throw 'not found' }
                if ($Arguments[0] -eq 'query') { return [pscustomobject]@{ ExitCode = 0; Output = $st.LogmanLines; DryRun = $false } }
            }
            return [pscustomobject]@{ ExitCode = 0; Output = @('OK'); DryRun = $false }
        }
        'Invoke-LumaBridgeHostProcess'                 = {
            [CmdletBinding()] param([string]$ExecutablePath, [string[]]$Arguments = @(), [int]$HardTimeoutMs = 30000, [int]$ResourceSampleIntervalSec = 0, [Nullable[int]]$WudfProcessId = $null, [switch]$DryRun)
            $st = $global:LbTestState['M421Mock']
            if ($DryRun) {
                $st.DryArgsLog[$st.Mode] = @($Arguments)
                return [pscustomobject]@{ ExitCode = 0; TimedOut = $false; ProcessId = 0; Output = @('[DRY-RUN]'); StdErr = @(); DryRun = $true }
            }
            $jsonIdx = [Array]::IndexOf($Arguments, '--json-summary')
            $jsonPath = $Arguments[$jsonIdx + 1]
            $runIdIdx = [Array]::IndexOf($Arguments, '--run-id')
            $runIdVal = if ($runIdIdx -ge 0 -and ($runIdIdx + 1) -lt $Arguments.Count) { [string]$Arguments[$runIdIdx + 1] } else { '' }
            if ($st.Mode -eq 'MaskingBug') {
                # Simulates M4.2 regression: 120 frames ok in seq/CRC, but 120 TimestampMeasurementErrors and 0 LiveEndToEnd samples
                $payload = [pscustomobject]@{
                    RunId = $runIdVal; SummaryComplete = $true;
                    ExitReason = 'FrameTargetReached'; HostProcessExitedNormally = $true; TransportHealthy = $true;
                    NegotiatedTransportMode = 'GpuSharedNtHandle'; FallbackToCpuActivated = $false; GpuFramesOpened = 3;
                    GpuSharedOpenFailures = 0; GpuSyncTimeouts = 0; AdapterMismatchErrors = 0; CpuStagingReadsPerformed = 0;
                    ConnectCount = 1; FramesReceived = 120; FramesValid = 120; LiveFramesReceived = 120; PreConnectFramesReceived = 0;
                    FrameTargetReached = $true; MinFramesReached = $true; TotalConnectedDurationUs = 2000000; SustainedLiveFps = 59.6;
                    ChecksumMismatches = 0; ProtocolErrors = 0; FatalIoTimeouts = 0; FatalIpcErrors = 0;
                    LastFrameSequence = 120; LastFrameWidth = 1920; LastFrameHeight = 1080; LastProtocolStatus = 'Ok'; AvgEndToEndLatencyUs = 0; ReceiveFps = 59.6;
                    TimestampMeasurementErrors = 120; OutOfOrderSequenceCount = 0; NonMonotonicTimestampCount = 0;
                    MissingCoreTimestampCount = 0; FutureTimestampErrorCount = 120; IncompatibleTimestampUnitsCount = 0; QpcFrequencyMismatchCount = 0;
                    ValidCoreTimestampSamples = 0; ValidLiveTimestampSamples = 0; ValidPresentTimestampSamples = 6;
                    CoreTimestampCoveragePercent = 0.0; LiveTimestampCoveragePercent = 0.0; PresentTimestampCoveragePercent = 5.0;
                    EndToEndLatency = [pscustomobject]@{ Available = $false; SampleCount = 0; AvgUs = 0 };
                    LiveEndToEndLatency = [pscustomobject]@{ Available = $false; SampleCount = 0; AvgUs = 0 };
                    Nvenc = [pscustomobject]@{ NvencFramesSubmitted = 120; NvencFramesEncoded = 120; NvencDroppedFrames = 0; EncodedQueueDrops = 0; TotalBitstreamBytes = 4000000; InvalidTimestampCount = 0; ExtractToBitstreamCoveragePercent = 100.0; EncoderOutputFps = 59.6; Width = 1920; Height = 1080; Initialized = $true };
                    H264DecodeValidation = [pscustomobject]@{ Passed = $true; StructuralDecodeValidated = $true; FidelityPsnrValidated = $false; PacketsInspected = 120; FramesDecoded = 120; NalParseFailures = 0; DecodeFailures = 0 };
                    VisualStimulus = [pscustomobject]@{ VirtualDisplayIdentified = $true; Started = $true }
                }
            }
            elseif ($st.Mode -eq 'Short120Ok') {
                $payload = [pscustomobject]@{
                    RunId = $runIdVal; SummaryComplete = $true;
                    ExitReason = 'FrameTargetReached'; HostProcessExitedNormally = $true; TransportHealthy = $true;
                    NegotiatedTransportMode = 'GpuSharedNtHandle'; FallbackToCpuActivated = $false; GpuFramesOpened = 3;
                    GpuSharedOpenFailures = 0; GpuSyncTimeouts = 0; AdapterMismatchErrors = 0; CpuStagingReadsPerformed = 0;
                    ConnectCount = 1; FramesReceived = 120; FramesValid = 120; LiveFramesReceived = 120; PreConnectFramesReceived = 0;
                    FrameTargetReached = $true; MinFramesReached = $true; TotalConnectedDurationUs = 2000000; SustainedLiveFps = 60.0;
                    ChecksumMismatches = 0; ProtocolErrors = 0; FatalIoTimeouts = 0; FatalIpcErrors = 0;
                    LastFrameSequence = 120; LastFrameWidth = 1920; LastFrameHeight = 1080; LastProtocolStatus = 'Ok'; AvgEndToEndLatencyUs = 900; ReceiveFps = 60.0;
                    TimestampMeasurementErrors = 0; OutOfOrderSequenceCount = 0; NonMonotonicTimestampCount = 0;
                    MissingCoreTimestampCount = 0; FutureTimestampErrorCount = 0; IncompatibleTimestampUnitsCount = 0; QpcFrequencyMismatchCount = 0;
                    ValidCoreTimestampSamples = 120; ValidLiveTimestampSamples = 120; ValidPresentTimestampSamples = 120;
                    CoreTimestampCoveragePercent = 100.0; LiveTimestampCoveragePercent = 100.0; PresentTimestampCoveragePercent = 100.0;
                    EndToEndLatency = [pscustomobject]@{ Available = $true; SampleCount = 120; AvgUs = 900 };
                    LiveEndToEndLatency = [pscustomobject]@{ Available = $true; SampleCount = 120; AvgUs = 900 };
                    Nvenc = [pscustomobject]@{ NvencFramesSubmitted = 120; NvencFramesEncoded = 120; NvencDroppedFrames = 0; EncodedQueueDrops = 0; TotalBitstreamBytes = 4000000; InvalidTimestampCount = 0; ExtractToBitstreamCoveragePercent = 100.0; EncoderOutputFps = 60.0; Width = 1920; Height = 1080; Initialized = $true };
                    H264DecodeValidation = [pscustomobject]@{ Passed = $true; StructuralDecodeValidated = $true; FidelityPsnrValidated = $false; PacketsInspected = 120; FramesDecoded = 120; NalParseFailures = 0; DecodeFailures = 0 };
                    VisualStimulus = [pscustomobject]@{ VirtualDisplayIdentified = $true; Started = $true }
                }
            }
            else {
                # Valid 30s 1800-frame benchmark run
                $payload = [pscustomobject]@{
                    RunId = $runIdVal; SummaryComplete = $true;
                    ExitReason = 'DurationElapsed'; HostProcessExitedNormally = $true; TransportHealthy = $true;
                    NegotiatedTransportMode = 'GpuSharedNtHandle'; FallbackToCpuActivated = $false; GpuFramesOpened = 3;
                    GpuSharedOpenFailures = 0; GpuSyncTimeouts = 0; AdapterMismatchErrors = 0; CpuStagingReadsPerformed = 0;
                    ConnectCount = 1; FramesReceived = 1800; FramesValid = 1800; LiveFramesReceived = 1800; PreConnectFramesReceived = 0;
                    FrameTargetReached = $false; MinFramesReached = $true; TotalConnectedDurationUs = 30000000; SustainedLiveFps = 60.0;
                    ChecksumMismatches = 0; ProtocolErrors = 0; FatalIoTimeouts = 0; FatalIpcErrors = 0;
                    LastFrameSequence = 1800; LastFrameWidth = 1920; LastFrameHeight = 1080; LastProtocolStatus = 'Ok'; AvgEndToEndLatencyUs = 950; ReceiveFps = 60.0;
                    TimestampMeasurementErrors = 0; OutOfOrderSequenceCount = 0; NonMonotonicTimestampCount = 0;
                    MissingCoreTimestampCount = 0; FutureTimestampErrorCount = 0; IncompatibleTimestampUnitsCount = 0; QpcFrequencyMismatchCount = 0;
                    ValidCoreTimestampSamples = 1800; ValidLiveTimestampSamples = 1800; ValidPresentTimestampSamples = 1800;
                    CoreTimestampCoveragePercent = 100.0; LiveTimestampCoveragePercent = 100.0; PresentTimestampCoveragePercent = 100.0;
                    EndToEndLatency = [pscustomobject]@{ Available = $true; SampleCount = 1800; AvgUs = 950; P95Us = 1500; P99Us = 1900 };
                    LiveEndToEndLatency = [pscustomobject]@{ Available = $true; SampleCount = 1800; AvgUs = 950; P95Us = 1500; P99Us = 1900 };
                    Nvenc = [pscustomobject]@{ NvencFramesSubmitted = 1800; NvencFramesEncoded = 1800; NvencDroppedFrames = 0; EncodedQueueDrops = 0; TotalBitstreamBytes = 60000000; InvalidTimestampCount = 0; ExtractToBitstreamCoveragePercent = 100.0; EncoderOutputFps = 60.0; Width = 1920; Height = 1080; Initialized = $true };
                    H264DecodeValidation = [pscustomobject]@{ Passed = $true; StructuralDecodeValidated = $true; FidelityPsnrValidated = $false; PacketsInspected = 1800; FramesDecoded = 1800; NalParseFailures = 0; DecodeFailures = 0 };
                    VisualStimulus = [pscustomobject]@{ VirtualDisplayIdentified = $true; Started = $true }
                }
            }
            $payload | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $jsonPath -Encoding UTF8
            return [pscustomobject]@{ ExitCode = 0; TimedOut = $false; ProcessId = 4401; Output = @('[LB-HOST] Summary'); StdErr = @(); DryRun = $false }
        }
    }

    Invoke-WithModuleMocks -GlobalMocks $m421Mocks -ModuleMocks $m421Mocks -Body {
        # 1. Regression check: 120 TimestampMeasurementErrors + 0 LiveEndToEnd samples MUST FAIL even when LastFrameSequence=120 & ProtocolErrors=0
        $global:LbTestState['M421Mock'].Mode = 'MaskingBug'
        Assert-Throws {
            & $valScript -Configuration Release -TestProfile Performance -PerformanceTargetFrames 120 -TransportMode Gpu -RequireGpuShared -EnableNvenc -RequireNvenc -VerifyH264Decode -StagingDir $stgDir -OutputDir $outTsFail -HostExecutablePath $fakeHostExe -CertificateThumbprint $certInfo.Thumbprint -AllowUntrustedChain -SkipDriverInstall -Force
        } -ExpectedPattern 'SequenceAndTimestampsConsistent.*RollbackClean=True' -Message '120 timestamp measurement errors + 0 live samples must reject SequenceAndTimestampsConsistent and AllPassed while keeping clean rollback'

        $tsFailReport = Get-Content -LiteralPath (Join-Path $outTsFail 'functional-validation-report.json') -Raw | ConvertFrom-Json
        Assert-Equal $tsFailReport.AcceptanceCriteria.AllPassed $false 'AllPassed is false when timestamp errors occur'
        Assert-Equal $tsFailReport.AcceptanceCriteria.SequenceAndTimestampsConsistent $false 'SequenceAndTimestampsConsistent is false when timestamp errors occur'
        Assert-Equal $tsFailReport.AcceptanceCriteria.TimestampsValidOk $false 'TimestampsValidOk is false on 120 timestamp errors'
        Assert-Equal $tsFailReport.AcceptanceCriteria.MeasurableLatenciesOk $false 'MeasurableLatenciesOk is false when LiveEndToEnd SampleCount == 0'
        Assert-Equal $tsFailReport.AcceptanceCriteria.TemporalCoverageSufficient $false 'TemporalCoverageSufficient is false when coverage == 0%'
        Assert-Equal $tsFailReport.AcceptanceCriteria.TimestampMeasurementErrors 120 'Report preserves exact TimestampMeasurementErrors count'
        Assert-Equal $tsFailReport.RollbackClean $true 'RollbackClean remains true'

        # 2. 120-frame clean run validates structural decode + timestamps, but NEVER sets ProlongedStabilityProven=true or FidelityPsnrValidated=true
        $global:LbTestState['M421Mock'].Mode = 'Short120Ok'
        $shortRes = & $valScript -Configuration Release -TestProfile Performance -PerformanceTargetFrames 120 -TransportMode Gpu -RequireGpuShared -EnableNvenc -RequireNvenc -VerifyH264Decode -StagingDir $stgDir -OutputDir $out120Pass -HostExecutablePath $fakeHostExe -CertificateThumbprint $certInfo.Thumbprint -AllowUntrustedChain -SkipDriverInstall -Force
        Assert-Equal $shortRes.ValidationSucceeded $true 'Clean 120-frame run passes Performance profile'
        Assert-Equal $shortRes.AcceptanceCriteria.StructuralDecodeValidated $true 'StructuralDecodeValidated is true on live decode'
        Assert-Equal $shortRes.AcceptanceCriteria.FidelityPsnrValidated $false 'FidelityPsnrValidated remains false without synthetic reference'
        Assert-Equal $shortRes.AcceptanceCriteria.ProlongedStabilityProven $false '120-frame run never claims ProlongedStabilityProven=true'

        # 3. DryRun for Benchmark30s and ProlongedStability (120s)
        $global:LbTestState['M421Mock'].Mode = 'Dry30s'
        $dry30s = & $valScript -Configuration Release -TestProfile Benchmark30s -BenchmarkDurationSec 30 -TransportMode Gpu -RequireGpuShared -EnableNvenc -RequireNvenc -VerifyH264Decode -StagingDir $stgDir -OutputDir $out30sPass -HostExecutablePath $fakeHostExe -CertificateThumbprint $certInfo.Thumbprint -SkipDriverInstall -DryRun
        Assert-Equal $dry30s.DryRun $true 'Benchmark30s DryRun succeeded'
        Assert-True ($global:LbTestState['M421Mock'].DryArgsLog['Dry30s'] -contains '30000') 'Benchmark30s DryRun passes 30000 ms duration'
        Assert-True ($global:LbTestState['M421Mock'].DryArgsLog['Dry30s'] -contains '--prewarm-width') 'Benchmark30s DryRun forwards --prewarm-width'

        $global:LbTestState['M421Mock'].Mode = 'DryStab'
        $dryStab = & $valScript -Configuration Release -TestProfile ProlongedStability -StabilityDurationSec 120 -TransportMode Gpu -RequireGpuShared -EnableNvenc -RequireNvenc -VerifyH264Decode -StagingDir $stgDir -OutputDir $out30sPass -HostExecutablePath $fakeHostExe -CertificateThumbprint $certInfo.Thumbprint -SkipDriverInstall -DryRun
        Assert-Equal $dryStab.DryRun $true 'ProlongedStability DryRun succeeded'
        Assert-True ($global:LbTestState['M421Mock'].DryArgsLog['DryStab'] -contains '120000') 'ProlongedStability DryRun passes 120000 ms duration'

        # 4. Valid 30s 1800-frame benchmark run passes Benchmark30s WITHOUT falsely proving >=180s ProlongedStabilityProven
        $global:LbTestState['M421Mock'].Mode = 'Bench30s'
        $benchRes = & $valScript -Configuration Release -TestProfile Benchmark30s -BenchmarkDurationSec 30 -TransportMode Gpu -RequireGpuShared -EnableNvenc -RequireNvenc -VerifyH264Decode -StagingDir $stgDir -OutputDir $out30sPass -HostExecutablePath $fakeHostExe -CertificateThumbprint $certInfo.Thumbprint -AllowUntrustedChain -SkipDriverInstall -Force
        Assert-Equal $benchRes.ValidationSucceeded $true 'Benchmark30s profile passes with 1800 frames / 30s'
        Assert-Equal $benchRes.AcceptanceCriteria.Benchmark30sExecuted $true 'Benchmark30sExecuted=true'
        Assert-Equal $benchRes.AcceptanceCriteria.Benchmark30sPassed $true 'Benchmark30sPassed=true'
        Assert-Equal $benchRes.AcceptanceCriteria.ProlongedStabilityProven $false 'ProlongedStabilityProven remains false after Benchmark30s (30s cannot prove >=180s prolonged stability)'
        Assert-Equal $benchRes.RollbackClean $true 'RollbackClean=true after Benchmark30s'
    }
}

function New-M01MockHostPayload {
    param(
        [string]$RunId = '',
        [uint64]$Frames = 60,
        [uint32]$Width = 1920,
        [uint32]$Height = 1080,
        [int]$DurationSec = 1,
        [double]$SustainedFps = 60.0,
        [int]$TargetFps = 60,
        [uint64]$NvencSubmitted = 60,
        [uint64]$NvencEncoded = 60,
        [uint64]$NvencDropped = 0,
        [uint64]$EncodedQueueDrops = 0,
        [double]$EncoderOutputFps = 60.0,
        [uint64]$H264Decoded = 60,
        [int]$ServerProcessId = 8768,
        [bool]$SummaryComplete = $true,
        [bool]$FrameTargetReached = $true,
        [bool]$StimulusStarted = $true
    )

    $durUs = [uint64]([Math]::Max(1, $DurationSec) * 1000000)
    $sampleCount = [uint64]([Math]::Max(1, $Frames))
    return [pscustomobject]@{
        RunId                        = $RunId
        HostProcessId                = 4401
        ServerProcessId              = $ServerProcessId
        SummaryComplete              = $SummaryComplete
        ExitReason                   = $(if ($DurationSec -ge 30) { 'DurationElapsed' } else { 'FrameTargetReached' })
        HostProcessExitedNormally    = $true
        TransportHealthy             = $true
        NegotiatedTransportMode      = 'GpuSharedNtHandle'
        FallbackToCpuActivated       = $false
        GpuFramesOpened              = 3
        GpuFramesDropped             = 0
        GpuSharedOpenFailures        = 0
        GpuSyncTimeouts              = 0
        AdapterMismatchErrors        = 0
        CpuStagingReadsPerformed     = 0
        ConnectCount                 = 1
        FramesReceived               = $Frames
        FramesValid                  = $Frames
        LiveFramesReceived           = $Frames
        PreConnectFramesReceived     = 0
        FrameTargetReached           = $FrameTargetReached
        MinFramesReached             = ($Frames -ge 1)
        TotalConnectedDurationUs     = $durUs
        SustainedLiveFps             = $SustainedFps
        ObservedActiveFps            = $SustainedFps
        ReceiveFps                   = $SustainedFps
        ChecksumMismatches           = 0
        ProtocolErrors               = 0
        FatalIoTimeouts              = 0
        FatalIpcErrors               = 0
        LastFrameSequence            = $Frames
        LastFrameWidth               = $Width
        LastFrameHeight              = $Height
        LastProtocolStatus           = 'Ok'
        AvgEndToEndLatencyUs         = 850
        TimestampMeasurementErrors   = 0
        OutOfOrderSequenceCount      = 0
        NonMonotonicTimestampCount   = 0
        MissingCoreTimestampCount    = 0
        FutureTimestampErrorCount    = 0
        IncompatibleTimestampUnitsCount = 0
        QpcFrequencyMismatchCount    = 0
        ValidCoreTimestampSamples    = $Frames
        ValidLiveTimestampSamples    = $Frames
        ValidPresentTimestampSamples = $Frames
        CoreTimestampCoveragePercent = 100.0
        LiveTimestampCoveragePercent = 100.0
        PresentTimestampCoveragePercent = 100.0
        EndToEndLatency              = [pscustomobject]@{ Available = ($Frames -gt 0); SampleCount = $sampleCount; StoredSampleCount = $sampleCount; SamplesTruncated = $false; ReservoirSampled = $false; AvgUs = 850; P95Us = 1200; P99Us = 1400 }
        LiveEndToEndLatency          = [pscustomobject]@{ Available = ($Frames -gt 0); SampleCount = $sampleCount; StoredSampleCount = $sampleCount; SamplesTruncated = $false; ReservoirSampled = $false; AvgUs = 850; P95Us = 1200; P99Us = 1400 }
        Nvenc                        = [pscustomobject]@{
            Initialized                       = $true
            Width                             = $Width
            Height                            = $Height
            NvencFramesSubmitted              = $NvencSubmitted
            NvencFramesEncoded                = $NvencEncoded
            NvencDroppedFrames                = $NvencDropped
            EncodedQueueDrops                 = $EncodedQueueDrops
            TotalBitstreamBytes               = ([uint64]([Math]::Max(1, $NvencEncoded)) * 30000)
            InvalidTimestampCount             = 0
            ExtractToBitstreamCoveragePercent = 100.0
            EncoderOutputFps                  = $EncoderOutputFps
        }
        H264DecodeValidation         = [pscustomobject]@{
            Passed                    = $true
            StructuralDecodeValidated = $true
            FidelityPsnrValidated     = $false
            PacketsInspected          = $NvencEncoded
            FramesDecoded             = $H264Decoded
            NalParseFailures          = 0
            DecodeFailures            = 0
        }
        VisualStimulus               = [pscustomobject]@{
            VirtualDisplayIdentified = $StimulusStarted
            Started                  = $StimulusStarted
            TargetFps                = $TargetFps
        }
    }
}

function New-M01ValidationMockHarness {
    param(
        [Parameter(Mandatory = $true)]
        [string]$CaseDir,
        [Parameter(Mandatory = $true)]
        [string]$StateKey,
        [string]$InitialDriverInfPath = 'oem99.inf',
        [string]$InitialDriverVersion = '',
        [int]$InitialEnableMon = 0,
        [int]$InitialEnableExt = 0,
        [object]$InitialEnableGpuTrans = $null,
        [string]$InitialAuthSid = $null,
        [string]$PreExistingCertThumbprint = ''
    )

    $certInfo = New-EphemeralTestCertificate -OutDirectory (Join-Path $CaseDir 'certs') -NamePrefix $StateKey
    $releaseInfPath = Join-Path (Get-LumaBridgePackageDirectory -Configuration Release) 'LumaBridgeIddDriver.inf'
    $releaseDriverVer = Get-LumaBridgeInfDriverVersion -InfPath $releaseInfPath
    if ([string]::IsNullOrWhiteSpace($InitialDriverVersion)) {
        $InitialDriverVersion = $releaseDriverVer
    }

    $c = Get-LumaBridgeDriverConstants
    $mockLogmanLines = @(
        'Name:                 LumaBridgeIddCore',
        ('Provider:             {0}' -f $c.LumaBridgeTraceProviderGuid),
        ('Provider:             {0}' -f $c.IddCxManifestProviderGuid),
        ('Provider:             {0}' -f $c.IddCxWppProviderGuid),
        ('Provider:             {0}' -f $c.UmdfOperationalProviderGuid),
        ('Provider:             {0}' -f $c.WdfCoreWppProviderGuid),
        ('Provider:             {0}' -f $c.WerKernelProviderGuid)
    )

    $fakeHostExe = Join-Path $CaseDir 'lumabridge-host.exe'
    if (-not (Test-Path -LiteralPath $fakeHostExe -PathType Leaf)) {
        [System.IO.File]::WriteAllBytes($fakeHostExe, [byte[]]@(0x4D, 0x5A, 0x90, 0x00))
    }

    $global:LbTestState[$StateKey] = [ordered]@{
        StateKey                  = $StateKey
        CertInfo                  = $certInfo
        Signtool                  = Get-LumaBridgeWdkToolPath -ToolName 'signtool.exe'
        LogmanLines               = $mockLogmanLines
        ReleaseDriverVersion      = $releaseDriverVer
        FakeHostExe               = $fakeHostExe
        StagingDir                = Join-Path $CaseDir ("stg_{0}" -f $StateKey)
        InstanceId                = 'ROOT\DISPLAY\0000'
        Status                    = 'OK'
        ProblemCode               = 0
        DriverInfPath             = $InitialDriverInfPath
        DriverVersion             = $InitialDriverVersion
        EnableMon                 = $InitialEnableMon
        EnableExt                 = $InitialEnableExt
        EnableGpuTrans            = $InitialEnableGpuTrans
        AuthSid                   = $InitialAuthSid
        PreExistingCertThumbprint = $PreExistingCertThumbprint
        DropCertInPostRollback    = $false
        LockEnableExtOnRollback   = $false
        Stage9Reached             = $false
        InjectStage7Fail          = $false
        EtwRunning                = $false
        EtwStopCalls              = 0
        CertutilAddCalls          = 0
        WudfProcsFactory          = $null
        HostHandler               = $null
        InRollback                = $false
    }

    $stateKeyCapture = $StateKey
    $makeCertSnap = {
        param([string]$Thumb, [bool]$IncludePreExisting)
        $entries = [ordered]@{}
        foreach ($sn in @('Cert:\CurrentUser\My', 'Cert:\LocalMachine\Root', 'Cert:\LocalMachine\TrustedPublisher')) {
            if ($IncludePreExisting -and -not [string]::IsNullOrWhiteSpace($Thumb)) {
                $entries[$sn] = [pscustomobject]@{
                    Accessible = $true
                    Error      = $null
                    Count      = 1
                    Certs      = @([pscustomobject]@{ Thumbprint = $Thumb.ToUpperInvariant(); Subject = 'CN=LumaBridge Test Driver Signing' })
                }
            }
            else {
                $entries[$sn] = [pscustomobject]@{ Accessible = $true; Error = $null; Count = 0; Certs = @() }
            }
        }
        return [pscustomobject]@{
            CapturedAtUtc       = (Get-Date).ToUniversalTime().ToString('o')
            QueryThumbprint     = $Thumb
            MatchingThumbprints = $(if ($IncludePreExisting -and -not [string]::IsNullOrWhiteSpace($Thumb)) { @($Thumb.ToUpperInvariant()) } else { @() })
            Stores              = [pscustomobject]$entries
        }
    }.GetNewClosure()

    $mocks = @{
        'Assert-LumaBridgeAdministrator' = { [CmdletBinding()] param([string]$OperationName, [switch]$DryRun) return $true }.GetNewClosure()
        'Get-LumaBridgeHostSecurityState' = {
            [CmdletBinding()] param()
            return [pscustomobject]@{
                SecureBoot = 'Disabled'; TestSigning = 'Enabled'; VbsStatus = 'Running'; HvciStatus = 'Running';
                OsArchitecture = 'X64'; OsBuild = 26200; OsUbr = 8037;
                BlockingConditions = @(); InformationalWarnings = @(); UnavailableChecks = @()
            }
        }.GetNewClosure()
        'Find-LumaBridgeSigningCertificate' = {
            [CmdletBinding()] param([string]$CertificateThumbprint, [string]$CertificateSubject)
            return $global:LbTestState[$stateKeyCapture].CertInfo.Certificate
        }.GetNewClosure()
        'Export-LumaBridgeCertificateFile' = {
            [CmdletBinding()] param($Certificate, [string]$FilePath)
            [System.IO.File]::WriteAllBytes($FilePath, $Certificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert))
        }.GetNewClosure()
        'Get-LumaBridgeCertificateStoreSnapshot' = {
            [CmdletBinding()] param([string]$Thumbprint, [string]$Subject)
            $st = $global:LbTestState[$stateKeyCapture]
            $hasPre = (-not [string]::IsNullOrWhiteSpace($st.PreExistingCertThumbprint)) -and (-not ($st.InRollback -and $st.DropCertInPostRollback))
            return (& $makeCertSnap $st.PreExistingCertThumbprint $hasPre)
        }.GetNewClosure()
        'Get-LumaBridgePnpInstances' = {
            [CmdletBinding()] param([string]$HardwareId)
            $st = $global:LbTestState[$stateKeyCapture]
            return @([pscustomobject]@{
                InstanceId               = $st.InstanceId
                FriendlyName             = 'LumaBridge Indirect Display Adapter'
                Status                   = $st.Status
                ProblemCode              = $st.ProblemCode
                ProblemStatus            = $(if ($st.ProblemCode -eq 0) { 0 } else { -1073741666 })
                ProblemStatusHex         = $(if ($st.ProblemCode -eq 0) { '0x00000000' } else { '0xC000009E' })
                Present                  = $true
                HardwareIds              = @('Root\LumaBridgeIddDriver')
                DriverInfPath            = $st.DriverInfPath
                DriverProvider           = 'LumaBridge'
                DriverVersion            = $st.DriverVersion
                DriverService            = 'WUDFRd'
                UpperFilters             = @('IndirectKmd')
                LowerFilters             = @()
                ConfigurationId          = ("{0}:Root\LumaBridgeIddDriver" -f $st.DriverInfPath)
                DeviceParametersPath     = 'MOCK:\ROOT\DISPLAY\0000\Device Parameters'
                EnableVirtualMonitor     = $st.EnableMon
                EnableFrameExtraction    = $st.EnableExt
                EnableGpuSharedTransport = $st.EnableGpuTrans
                AuthorizedHostUserSid    = $st.AuthSid
                StartupDiagnostics       = [pscustomobject]@{ LastStage = 'AdapterInitFinished'; LastSuccessfulStage = 'AdapterInitFinished'; LastStatusHex = '0x00000000'; LastErrorStatusHex = '0x00000000' }
            })
        }.GetNewClosure()
        'Set-LumaBridgeDeviceEnableVirtualMonitor' = {
            [CmdletBinding()] param([string]$DeviceParametersPath, [int]$Value = 0, [switch]$Clear)
            $st = $global:LbTestState[$stateKeyCapture]
            if ($Clear) { $st.EnableMon = $null } else { $st.EnableMon = $Value }
            if ($st.InjectStage7Fail -and $Value -eq 1) {
                throw 'Simulated Stage 7 virtual monitor failure'
            }
        }.GetNewClosure()
        'Get-LumaBridgeDeviceEnableVirtualMonitor' = {
            [CmdletBinding()] param([string]$DeviceParametersPath)
            return $global:LbTestState[$stateKeyCapture].EnableMon
        }.GetNewClosure()
        'Set-LumaBridgeDeviceEnableFrameExtraction' = {
            [CmdletBinding()] param([string]$DeviceParametersPath, [int]$Value = 0, [switch]$Clear)
            $st = $global:LbTestState[$stateKeyCapture]
            if ($st.LockEnableExtOnRollback -and $st.Stage9Reached) {
                $st.EnableExt = 1
                return
            }
            if ($Clear) { $st.EnableExt = $null } else { $st.EnableExt = $Value }
        }.GetNewClosure()
        'Get-LumaBridgeDeviceEnableFrameExtraction' = {
            [CmdletBinding()] param([string]$DeviceParametersPath)
            return $global:LbTestState[$stateKeyCapture].EnableExt
        }.GetNewClosure()
        'Set-LumaBridgeDeviceEnableGpuSharedTransport' = {
            [CmdletBinding()] param([string]$DeviceParametersPath, [int]$Value = 1, [switch]$Clear)
            $st = $global:LbTestState[$stateKeyCapture]
            if ($Clear) { $st.EnableGpuTrans = $null } else { $st.EnableGpuTrans = $Value }
        }.GetNewClosure()
        'Get-LumaBridgeDeviceEnableGpuSharedTransport' = {
            [CmdletBinding()] param([string]$DeviceParametersPath)
            return $global:LbTestState[$stateKeyCapture].EnableGpuTrans
        }.GetNewClosure()
        'Set-LumaBridgeDeviceAuthorizedHostUserSid' = {
            [CmdletBinding()] param([string]$DeviceParametersPath, [string]$SidString, [switch]$Clear)
            $st = $global:LbTestState[$stateKeyCapture]
            if ($Clear -or [string]::IsNullOrWhiteSpace($SidString)) { $st.AuthSid = $null } else { $st.AuthSid = $SidString }
        }.GetNewClosure()
        'Get-LumaBridgeDeviceAuthorizedHostUserSid' = {
            [CmdletBinding()] param([string]$DeviceParametersPath)
            return $global:LbTestState[$stateKeyCapture].AuthSid
        }.GetNewClosure()
        'Get-LumaBridgeWudfHostProcesses' = {
            [CmdletBinding()] param([object[]]$PnpInstances, [object[]]$RecentEvents, [string[]]$DebugTraceLines, [Nullable[DateTime]]$NotBeforeUtc = $null, [Nullable[int]]$ExpectedHostPid = $null)
            $st = $global:LbTestState[$stateKeyCapture]
            if ($null -ne $st.WudfProcsFactory) {
                return (& $st.WudfProcsFactory $PnpInstances $NotBeforeUtc $ExpectedHostPid)
            }
            return @([pscustomobject]@{ Id = 8768; IsLumaBridgeHost = $true; AssociationMethod = 'LoadedModule'; IdentityStatus = 'VERIFIED'; HasExited = $false; WorkingSetMB = 30.0; PrivateMemoryMB = 15.0; HandleCount = 400; StartedAfterAnchor = $true })
        }.GetNewClosure()
        'Get-LumaBridgeCrashDumpInventory' = { [CmdletBinding()] param([int]$LookbackMinutes) return [pscustomobject]@{ LookbackMinutes = $LookbackMinutes; Locations = @(); Files = @(); TotalFoundCount = 0 } }.GetNewClosure()
        'Get-LumaBridgeEventChannelStatus' = { [CmdletBinding()] param([string[]]$ChannelNames) return @() }.GetNewClosure()
        'Get-LumaBridgeDiagnosticEvents' = { [CmdletBinding()] param([int]$LookbackMinutes, [string[]]$InstanceIds, [string[]]$PublishedInfNames, [object[]]$ChannelStatus) return @() }.GetNewClosure()
        'Get-LumaBridgeSetupApiLogExcerpt' = { [CmdletBinding()] param([string]$SetupApiLogPath, [string[]]$InstanceIds, [string[]]$PublishedInfNames, [int]$MaxMatchedSections) return [pscustomobject]@{ LogPath = $SetupApiLogPath; Exists = $false; AccessDenied = $false; Error = ''; MatchedSectionCount = 0; WdfSchemaWarnings = @(); DeviceStartProblemLines = @(); Sections = @(); RawExcerptText = '' } }.GetNewClosure()
        'Get-LumaBridgeDriverStorePackages' = { [CmdletBinding()] param([string]$InfFilter) return @() }.GetNewClosure()
        'Get-LumaBridgeEtlEventSummary' = { [CmdletBinding()] param($EtlPath, $StartTimeUtc, $EndTimeUtc, $ProcessId, [int]$MaxMatchedEvents = 500, [switch]$ExcludeHighVolumeGraphics) return [pscustomobject]@{ EtlPath = $EtlPath; Exists = $true; EventCount = 1; MatchedEventCount = 1; MatchedLimitReached = $false; FilteredOutHighVolume = $true; XPathUsed = '*'; TraceStats = $null; CircularWrapWarning = $null; LumaBridgeEvents = @(); Providers = @(); Events = @(); Error = '' } }.GetNewClosure()
        'Invoke-LumaBridgeExternalCommand' = {
            [CmdletBinding()] param([string]$FilePath, [string[]]$Arguments = @(), [switch]$DryRun)
            $st = $global:LbTestState[$stateKeyCapture]
            if ($FilePath -like '*git*') { return [pscustomobject]@{ ExitCode = 0; Output = @('feature/windows-gpu-shared-textures-nvenc'); DryRun = $false } }
            if ($DryRun) { return [pscustomobject]@{ ExitCode = 0; Output = @('[DRY-RUN]'); DryRun = $true } }
            if ($FilePath -like '*certutil*' -and ($Arguments -contains '-addstore')) {
                $st.CertutilAddCalls++
                return [pscustomobject]@{ ExitCode = 0; Output = @('Cert added'); DryRun = $false }
            }
            if ($FilePath -ieq $st.Signtool -and $Arguments.Count -ge 1 -and $Arguments[0] -eq 'sign') {
                $out = & $FilePath sign /fd SHA256 /f $st.CertInfo.PfxPath /p $st.CertInfo.Password $Arguments[-1] 2>&1
                if ($LASTEXITCODE -ne 0) { throw 'mock signtool sign error' }
                return [pscustomobject]@{ ExitCode = 0; Output = @($out); DryRun = $false }
            }
            if ($FilePath -like '*Inf2Cat*' -or ($FilePath -ieq $st.Signtool -and $Arguments.Count -ge 1 -and $Arguments[0] -eq 'verify')) {
                $out = & $FilePath @Arguments 2>&1
                if ($LASTEXITCODE -ne 0) { throw 'mock verify error' }
                return [pscustomobject]@{ ExitCode = 0; Output = @($out); DryRun = $false }
            }
            if ($FilePath -like '*logman*') {
                if ($Arguments.Count -ge 1 -and $Arguments[0] -eq 'create' -and ($Arguments -contains 'LumaBridgeIddCore')) {
                    $st.EtwRunning = $true
                    return [pscustomobject]@{ ExitCode = 0; Output = @('The command completed successfully.'); DryRun = $false }
                }
                if ($Arguments.Count -ge 1 -and $Arguments[0] -eq 'stop' -and ($Arguments -contains 'LumaBridgeIddCore')) {
                    $st.EtwRunning = $false
                    $st.InRollback = $true
                    $st.EtwStopCalls++
                    return [pscustomobject]@{ ExitCode = 0; Output = @('The command completed successfully.'); DryRun = $false }
                }
                if ($Arguments[0] -eq 'query' -and ($Arguments -contains 'LumaBridgeIddDxg')) { throw 'not found' }
                if ($Arguments[0] -eq 'query' -and -not $st.EtwRunning) { throw 'Session not running' }
                if ($Arguments[0] -eq 'query') { return [pscustomobject]@{ ExitCode = 0; Output = $st.LogmanLines; DryRun = $false } }
            }
            return [pscustomobject]@{ ExitCode = 0; Output = @('OK'); DryRun = $false }
        }.GetNewClosure()
        'Invoke-LumaBridgeHostProcess' = {
            [CmdletBinding()] param([string]$ExecutablePath, [string[]]$Arguments = @(), [int]$HardTimeoutMs = 30000, [int]$ResourceSampleIntervalSec = 0, [Nullable[int]]$WudfProcessId = $null, [switch]$DryRun)
            $st = $global:LbTestState[$stateKeyCapture]
            $st.Stage9Reached = $true
            $st.InRollback = $true
            if ($DryRun) {
                return [pscustomobject]@{ ExitCode = 0; TimedOut = $false; ProcessId = 0; Output = @('[DRY-RUN]'); StdErr = @(); DryRun = $true }
            }
            $jsonIdx = [Array]::IndexOf($Arguments, '--json-summary')
            $jsonPath = $Arguments[$jsonIdx + 1]
            $runIdIdx = [Array]::IndexOf($Arguments, '--run-id')
            $runIdVal = if ($runIdIdx -ge 0 -and ($runIdIdx + 1) -lt $Arguments.Count) { [string]$Arguments[$runIdIdx + 1] } else { '' }
            $durIdx = [Array]::IndexOf($Arguments, '--duration-ms')
            $durMs = if ($durIdx -ge 0 -and ($durIdx + 1) -lt $Arguments.Count) { [int]$Arguments[$durIdx + 1] } else { 5000 }
            $maxFIdx = [Array]::IndexOf($Arguments, '--max-frames')
            $maxF = if ($maxFIdx -ge 0 -and ($maxFIdx + 1) -lt $Arguments.Count) { [int]$Arguments[$maxFIdx + 1] } else { 0 }

            if ($null -ne $st.HostHandler) {
                return (& $st.HostHandler $Arguments $jsonPath $runIdVal $durMs $maxF $WudfProcessId)
            }
            $sec = [Math]::Max(1, [int][Math]::Round($durMs / 1000.0))
            $fc = if ($maxF -gt 0) { [uint64]$maxF } else { [uint64]($sec * 60) }
            $payload = New-M01MockHostPayload -RunId $runIdVal -Frames $fc -DurationSec $sec -NvencSubmitted $fc -NvencEncoded $fc -H264Decoded $fc
            $payload | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $jsonPath -Encoding UTF8
            return [pscustomobject]@{ ExitCode = 0; TimedOut = $false; ProcessId = 4401; Output = @('[LB-HOST] Summary'); StdErr = @(); DryRun = $false }
        }.GetNewClosure()
    }

    return [pscustomobject]@{
        State = $global:LbTestState[$StateKey]
        Mocks = $mocks
    }
}

# 34. M0.1 S-01 (#1): Multi-candidate WUDFHost correlation, anti-stale pre-restart PID rejection & conflict detection
Invoke-UnitTest -Name 'M01_S01_WudfHostMultiCandidateAndAntiStaleCorrelation' -TestBody {
    param($caseDir)
    $anchorUtc = [DateTime]::UtcNow.AddSeconds(-5)
    $pnp = @([pscustomobject]@{
        InstanceId           = 'ROOT\DISPLAY\0000'
        DeviceParametersPath = ''
        WudfDiagnosticInfo   = [pscustomobject]@{ HostPid = 4102; HostProcessGUID = '{aaaaaaaa-1111-2222-3333-444444444444}'; DeviceGroupId = 'LumaBridgeGroupA'; LifetimeID = '{11111111-1111-1111-1111-111111111111}' }
        StartupDiagnostics   = [pscustomobject]@{ HostProcessId = 4102 }
    })

    # Case A: 3 candidates: unrelated PID 4101, stale pre-restart PID 4102, verified LoadedModule PID 4105
    $global:LbTestState['S01RawA'] = @(
        [pscustomobject]@{ Id = 4101; ProcessName = 'WUDFHost'; HasExited = $false; StartTimeUtc = [DateTime]::UtcNow.ToString('o'); CommandLine = 'WUDFHost.exe -HostGuid:{other}'; LoadedModules = @([pscustomobject]@{ ModuleName = 'HidCfu.dll'; FileName = 'C:\Windows\System32\Drivers\UMDF\HidCfu.dll' }); LoadedModulesReadable = $true; WorkingSetMB = 10.0; PrivateMemoryMB = 3.0; HandleCount = 200; ThreadCount = 4; TotalProcessorSec = 0.1 },
        [pscustomobject]@{ Id = 4102; ProcessName = 'WUDFHost'; HasExited = $false; StartTimeUtc = $anchorUtc.AddMinutes(-10).ToString('o'); CommandLine = ''; LoadedModules = @(); LoadedModulesReadable = $false; WorkingSetMB = 12.0; PrivateMemoryMB = 4.0; HandleCount = 220; ThreadCount = 5; TotalProcessorSec = 0.2 },
        [pscustomobject]@{ Id = 4105; ProcessName = 'WUDFHost'; HasExited = $false; StartTimeUtc = [DateTime]::UtcNow.ToString('o'); CommandLine = 'WUDFHost.exe'; LoadedModules = @([pscustomobject]@{ ModuleName = 'LumaBridgeIddDriver.dll'; FileName = 'C:\Windows\System32\DriverStore\FileRepository\lb\LumaBridgeIddDriver.dll' }); LoadedModulesReadable = $true; WorkingSetMB = 32.0; PrivateMemoryMB = 16.0; HandleCount = 420; ThreadCount = 10; TotalProcessorSec = 1.5 }
    )
    Invoke-WithModuleMocks -ModuleMocks @{ 'Get-LumaBridgeRawWudfProcesses' = { return $global:LbTestState['S01RawA'] } } -Body {
        $procs = @(Get-LumaBridgeWudfHostProcesses -PnpInstances $pnp -NotBeforeUtc $anchorUtc)
        $stale = @($procs | Where-Object { $_.Id -eq 4102 })[0]
        Assert-Equal $stale.IsLumaBridgeHost $false 'Pre-restart stale PID 4102 rejected'
        Assert-Equal $stale.AssociationMethod 'StalePreRestartPid' 'Pre-restart stale PID tagged StalePreRestartPid'
        Assert-Equal $stale.IdentityStatus 'STALE_OR_CONFLICT' 'Pre-restart stale PID tagged STALE_OR_CONFLICT'
        $res = Resolve-LumaBridgeVerifiedWudfHostProcess -WudfProcesses $procs -RequireStartedAfterAnchor
        Assert-Equal $res.Status 'VERIFIED' 'LoadedModule candidate 4105 resolved as VERIFIED'
        Assert-Equal $res.Process.Id 4105 'Verified candidate 4105 selected over unrelated 4101 and stale 4102'
    }

    # Case B: Conflicting WUDFDiagnosticInfo HostPid (4103) vs StartupDiagnostics HostProcessId (4104) without loaded DLL -> FAIL
    $pnpConflict = @([pscustomobject]@{
        InstanceId           = 'ROOT\DISPLAY\0000'
        DeviceParametersPath = ''
        WudfDiagnosticInfo   = [pscustomobject]@{ HostPid = 4103 }
        StartupDiagnostics   = [pscustomobject]@{ HostProcessId = 4104 }
    })
    $global:LbTestState['S01RawB'] = @(
        [pscustomobject]@{ Id = 4103; ProcessName = 'WUDFHost'; HasExited = $false; StartTimeUtc = [DateTime]::UtcNow.ToString('o'); CommandLine = ''; LoadedModules = @(); LoadedModulesReadable = $false; WorkingSetMB = 12.0; PrivateMemoryMB = 4.0; HandleCount = 220; ThreadCount = 5; TotalProcessorSec = 0.2 },
        [pscustomobject]@{ Id = 4104; ProcessName = 'WUDFHost'; HasExited = $false; StartTimeUtc = [DateTime]::UtcNow.ToString('o'); CommandLine = ''; LoadedModules = @(); LoadedModulesReadable = $false; WorkingSetMB = 12.0; PrivateMemoryMB = 4.0; HandleCount = 220; ThreadCount = 5; TotalProcessorSec = 0.2 }
    )
    Invoke-WithModuleMocks -ModuleMocks @{ 'Get-LumaBridgeRawWudfProcesses' = { return $global:LbTestState['S01RawB'] } } -Body {
        $procsB = @(Get-LumaBridgeWudfHostProcesses -PnpInstances $pnpConflict -NotBeforeUtc $anchorUtc)
        $resB = Resolve-LumaBridgeVerifiedWudfHostProcess -WudfProcesses $procsB -RequireStartedAfterAnchor
        Assert-Equal $resB.Status 'FAIL' 'Conflicting HostPid metadata without DLL verification produces FAIL (never VERIFIED)'
    }

    # Case C: End-to-end runner picks verified PID 4105 from multiple WUDFHost processes and matches ServerProcessId=4105
    $valScript = Join-Path $scriptsDir 'Invoke-LumaBridgeFunctionalValidation.ps1'
    $h = New-M01ValidationMockHarness -CaseDir $caseDir -StateKey 'S01Runner'
    $h.State.WudfProcsFactory = {
        param($p, $nb, $exp)
        return @(
            [pscustomobject]@{ Id = 4101; IsLumaBridgeHost = $false; AssociationMethod = 'Unverified'; IdentityStatus = 'UNVERIFIED'; HasExited = $false; WorkingSetMB = 10.0; PrivateMemoryMB = 3.0; HandleCount = 200; StartedAfterAnchor = $true },
            [pscustomobject]@{ Id = 4105; IsLumaBridgeHost = $true; AssociationMethod = 'LoadedModule'; IdentityStatus = 'VERIFIED'; HasExited = $false; WorkingSetMB = 32.0; PrivateMemoryMB = 16.0; HandleCount = 420; StartedAfterAnchor = $true }
        )
    }
    $h.State.HostHandler = {
        param($Arguments, $jsonPath, $runIdVal, $durMs, $maxF, $wudfPid)
        Assert-Equal $wudfPid 4105 'Runner passes verified WUDFHost PID 4105 (not unrelated 4101) to Invoke-LumaBridgeHostProcess'
        $payload = New-M01MockHostPayload -RunId $runIdVal -Frames 10 -ServerProcessId 4105 -NvencSubmitted 10 -NvencEncoded 10 -H264Decoded 10
        $payload | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $jsonPath -Encoding UTF8
        return [pscustomobject]@{ ExitCode = 0; TimedOut = $false; ProcessId = 4401; Output = @('[LB-HOST] ok'); StdErr = @(); DryRun = $false }
    }
    $outDir = Join-Path $caseDir 'out_s01_ok'
    Invoke-WithModuleMocks -GlobalMocks $h.Mocks -ModuleMocks $h.Mocks -Body {
        $res = & $valScript -Configuration Release -TestProfile Smoke -StagingDir $h.State.StagingDir -OutputDir $outDir -HostExecutablePath $h.State.FakeHostExe -CertificateThumbprint $h.State.CertInfo.Thumbprint -AllowUntrustedChain -SkipDriverInstall -Force
        Assert-Equal $res.OverallSucceeded $true 'Runner succeeds when verified WUDFHost 4105 matches ServerProcessId'
        Assert-Equal $res.AcceptanceCriteria.WudfIdentityStatus 'VERIFIED' 'AcceptanceCriteria records WudfIdentityStatus=VERIFIED'
    }
}

# 35. M0.1 S-01 (#2): Missing WUDFHost, unrelated-only WUDFHost, reused PID without DLL & mid-run WUDF exit rejected
Invoke-UnitTest -Name 'M01_S01_WudfHostMissingReusedPidAndMidRunExitRejected' -TestBody {
    param($caseDir)
    $anchorUtc = [DateTime]::UtcNow.AddSeconds(-5)
    $pnp = @([pscustomobject]@{
        InstanceId           = 'ROOT\DISPLAY\0000'
        DeviceParametersPath = ''
        WudfDiagnosticInfo   = [pscustomobject]@{ HostPid = 4106 }
        StartupDiagnostics   = [pscustomobject]@{ HostProcessId = 4106 }
    })

    # 0 processes -> FAIL
    $resEmpty = Resolve-LumaBridgeVerifiedWudfHostProcess -WudfProcesses @()
    Assert-Equal $resEmpty.Status 'FAIL' 'Zero WUDFHost processes returns FAIL'

    # Unrelated only -> UNKNOWN
    $global:LbTestState['S01OnlyUnrel'] = @(
        [pscustomobject]@{ Id = 4101; ProcessName = 'WUDFHost'; HasExited = $false; StartTimeUtc = [DateTime]::UtcNow.ToString('o'); CommandLine = ''; LoadedModules = @([pscustomobject]@{ ModuleName = 'Other.dll'; FileName = 'C:\Other.dll' }); LoadedModulesReadable = $true; WorkingSetMB = 10.0; PrivateMemoryMB = 3.0; HandleCount = 150; ThreadCount = 3; TotalProcessorSec = 0.1 }
    )
    Invoke-WithModuleMocks -ModuleMocks @{ 'Get-LumaBridgeRawWudfProcesses' = { return $global:LbTestState['S01OnlyUnrel'] } } -Body {
        $procsUnrel = @(Get-LumaBridgeWudfHostProcesses -PnpInstances @([pscustomobject]@{ InstanceId = 'ROOT\DISPLAY\0000'; DeviceParametersPath = '' }))
        $resUnrel = Resolve-LumaBridgeVerifiedWudfHostProcess -WudfProcesses $procsUnrel
        Assert-Equal $resUnrel.Status 'UNKNOWN' 'Only unrelated WUDFHost returns UNKNOWN (never PASS/VERIFIED)'
    }

    # Reused PID 4106 with readable modules lacking LumaBridgeIddDriver.dll -> STALE_OR_CONFLICT / FAIL
    $global:LbTestState['S01Reused'] = @(
        [pscustomobject]@{ Id = 4106; ProcessName = 'WUDFHost'; HasExited = $false; StartTimeUtc = [DateTime]::UtcNow.ToString('o'); CommandLine = ''; LoadedModules = @([pscustomobject]@{ ModuleName = 'UnrelatedUmdf.dll'; FileName = 'C:\UnrelatedUmdf.dll' }); LoadedModulesReadable = $true; WorkingSetMB = 10.0; PrivateMemoryMB = 3.0; HandleCount = 150; ThreadCount = 3; TotalProcessorSec = 0.1 }
    )
    Invoke-WithModuleMocks -ModuleMocks @{ 'Get-LumaBridgeRawWudfProcesses' = { return $global:LbTestState['S01Reused'] } } -Body {
        $procsReused = @(Get-LumaBridgeWudfHostProcesses -PnpInstances $pnp -NotBeforeUtc $anchorUtc)
        Assert-Equal $procsReused[0].IdentityStatus 'STALE_OR_CONFLICT' 'Reused PID without LumaBridge DLL marked STALE_OR_CONFLICT'
        Assert-Equal $procsReused[0].AssociationMethod 'ReusedOrMismatchedPidModules' 'AssociationMethod indicates module mismatch'
        $resReused = Resolve-LumaBridgeVerifiedWudfHostProcess -WudfProcesses $procsReused
        Assert-Equal $resReused.Status 'FAIL' 'Reused PID triggers FAIL status'
    }

    # Mid-run WUDFHost exit during active host execution -> runner fails with WudfProcessHealthy=false
    $valScript = Join-Path $scriptsDir 'Invoke-LumaBridgeFunctionalValidation.ps1'
    $h = New-M01ValidationMockHarness -CaseDir $caseDir -StateKey 'S01MidExit'
    $h.State.HostHandler = {
        param($Arguments, $jsonPath, $runIdVal, $durMs, $maxF, $wudfPid)
        $payload = New-M01MockHostPayload -RunId $runIdVal -Frames 60 -ServerProcessId 8768
        $payload | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $jsonPath -Encoding UTF8
        return [pscustomobject]@{
            ExitCode = 0; TimedOut = $false; ProcessId = 4401; Output = @('[LB-HOST] ok'); StdErr = @(); DryRun = $false;
            ResourceTelemetry = [pscustomobject]@{ WudfProcessExitedDuringRun = $true; Samples = @() }
        }
    }
    $outDir = Join-Path $caseDir 'out_mid_exit'
    Invoke-WithModuleMocks -GlobalMocks $h.Mocks -ModuleMocks $h.Mocks -Body {
        Assert-Throws {
            & $valScript -Configuration Release -TestProfile Smoke -StagingDir $h.State.StagingDir -OutputDir $outDir -HostExecutablePath $h.State.FakeHostExe -CertificateThumbprint $h.State.CertInfo.Thumbprint -AllowUntrustedChain -SkipDriverInstall -Force
        } -ExpectedPattern 'WudfProcessHealthy.*RollbackClean=True' -Message 'Mid-run WUDFHost exit must reject validation while preserving clean rollback'
    }
    $rep = Get-Content -LiteralPath (Join-Path $outDir 'functional-validation-report.json') -Raw | ConvertFrom-Json
    Assert-Equal $rep.AcceptanceCriteria.WudfIdentityStatus 'FAIL' 'Report records WudfIdentityStatus=FAIL after mid-run WUDF exit'
    Assert-Equal $rep.AcceptanceCriteria.WudfProcessHealthy $false 'Report records WudfProcessHealthy=false'
    Assert-Equal $rep.FunctionalValidationSucceeded $false 'FunctionalValidationSucceeded=false after mid-run WUDF exit'
    Assert-Equal $rep.RollbackClean $true 'RollbackClean=true'
}

# 36. M0.1 S-02 (#3): Partial rollback failure always forces OverallSucceeded=false & throws non-zero even when Stage 9 passed
Invoke-UnitTest -Name 'M01_S02_PartialRollbackAlwaysFailsOverallWithNonZeroThrow' -TestBody {
    param($caseDir)
    $valScript = Join-Path $scriptsDir 'Invoke-LumaBridgeFunctionalValidation.ps1'
    $h = New-M01ValidationMockHarness -CaseDir $caseDir -StateKey 'S02PartialRb'
    $h.State.LockEnableExtOnRollback = $true
    $outDir = Join-Path $caseDir 'out_partial_rb'

    Invoke-WithModuleMocks -GlobalMocks $h.Mocks -ModuleMocks $h.Mocks -Body {
        Assert-Throws {
            & $valScript -Configuration Release -TestProfile Smoke -StagingDir $h.State.StagingDir -OutputDir $outDir -HostExecutablePath $h.State.FakeHostExe -CertificateThumbprint $h.State.CertInfo.Thumbprint -AllowUntrustedChain -SkipDriverInstall -Force
        } -ExpectedPattern 'OverallSucceeded=False.*FunctionalValidationSucceeded=True.*RollbackClean=False.*RuntimeCleanupSucceeded=False' -Message 'Partial rollback leaving EnableFrameExtraction=1 forces throw with OverallSucceeded=False'
    }

    $rep = Get-Content -LiteralPath (Join-Path $outDir 'functional-validation-report.json') -Raw | ConvertFrom-Json
    Assert-Equal $rep.FunctionalValidationSucceeded $true 'Stage 9 FunctionalValidationSucceeded faithfully stays true'
    Assert-Equal $rep.RuntimeCleanupSucceeded $false 'RuntimeCleanupSucceeded=false when EnableFrameExtraction stays 1'
    Assert-Equal $rep.RollbackClean $false 'RollbackClean=false on partial rollback'
    Assert-Equal $rep.OverallSucceeded $false 'OverallSucceeded=false on partial rollback'
    Assert-Equal $rep.ValidationSucceeded $false 'ValidationSucceeded=false on partial rollback'
    Assert-Equal $h.State.EtwRunning $false 'ETW was stopped even though EnableFrameExtraction rollback failed'
}

# 37. M0.1 S-03 (#4): Benchmark rejects wrong resolution (1280x720 != 1920x1080)
Invoke-UnitTest -Name 'M01_S03_BenchmarkRejectsWrongResolution' -TestBody {
    param($caseDir)
    $valScript = Join-Path $scriptsDir 'Invoke-LumaBridgeFunctionalValidation.ps1'
    $h = New-M01ValidationMockHarness -CaseDir $caseDir -StateKey 'S03WrongRes'
    $h.State.HostHandler = {
        param($Arguments, $jsonPath, $runIdVal, $durMs, $maxF, $wudfPid)
        $payload = New-M01MockHostPayload -RunId $runIdVal -Frames 1800 -Width 1280 -Height 720 -DurationSec 30 -NvencSubmitted 1800 -NvencEncoded 1800 -H264Decoded 1800
        $payload | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $jsonPath -Encoding UTF8
        return [pscustomobject]@{ ExitCode = 0; TimedOut = $false; ProcessId = 4401; Output = @('[LB-HOST] ok'); StdErr = @(); DryRun = $false }
    }
    $outDir = Join-Path $caseDir 'out_wrong_res'
    Invoke-WithModuleMocks -GlobalMocks $h.Mocks -ModuleMocks $h.Mocks -Body {
        Assert-Throws {
            & $valScript -Configuration Release -TestProfile Benchmark30s -BenchmarkDurationSec 30 -TransportMode Gpu -RequireGpuShared -EnableNvenc -RequireNvenc -VerifyH264Decode -StagingDir $h.State.StagingDir -OutputDir $outDir -HostExecutablePath $h.State.FakeHostExe -CertificateThumbprint $h.State.CertInfo.Thumbprint -AllowUntrustedChain -SkipDriverInstall -Force
        } -ExpectedPattern 'Benchmark30sPassed.*RollbackClean=True' -Message 'Benchmark30s must reject 1280x720 when 1920x1080 is required'
    }
    $rep = Get-Content -LiteralPath (Join-Path $outDir 'functional-validation-report.json') -Raw | ConvertFrom-Json
    Assert-Equal $rep.AcceptanceCriteria.Benchmark30sPassed $false 'Benchmark30sPassed=false on 1280x720'
    Assert-Equal $rep.SubprofileEvaluations.Benchmark30s.ResolutionOk $false 'ResolutionOk=false recorded on 1280x720'
    Assert-Equal $rep.OverallSucceeded $false 'OverallSucceeded=false'
    Assert-Equal $rep.RollbackClean $true 'RollbackClean=true'
}

# 38. M0.1 S-03 (#5): Benchmark rejects low frames (<98%) and low sustained FPS (<95%)
Invoke-UnitTest -Name 'M01_S03_BenchmarkRejectsLowFramesOrLowSustainedFps' -TestBody {
    param($caseDir)
    $valScript = Join-Path $scriptsDir 'Invoke-LumaBridgeFunctionalValidation.ps1'

    # Case A: 1500/1800 frames (< 98% = 1764) even with FPS=60
    $hA = New-M01ValidationMockHarness -CaseDir $caseDir -StateKey 'S03LowFrames'
    $hA.State.HostHandler = {
        param($Arguments, $jsonPath, $runIdVal, $durMs, $maxF, $wudfPid)
        $payload = New-M01MockHostPayload -RunId $runIdVal -Frames 1500 -DurationSec 30 -SustainedFps 60.0 -NvencSubmitted 1500 -NvencEncoded 1500 -H264Decoded 1500
        $payload | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $jsonPath -Encoding UTF8
        return [pscustomobject]@{ ExitCode = 0; TimedOut = $false; ProcessId = 4401; Output = @('[LB-HOST] ok'); StdErr = @(); DryRun = $false }
    }
    $outLowF = Join-Path $caseDir 'out_low_frames'
    Invoke-WithModuleMocks -GlobalMocks $hA.Mocks -ModuleMocks $hA.Mocks -Body {
        Assert-Throws {
            & $valScript -Configuration Release -TestProfile Benchmark30s -BenchmarkDurationSec 30 -TransportMode Gpu -RequireGpuShared -EnableNvenc -RequireNvenc -VerifyH264Decode -StagingDir $hA.State.StagingDir -OutputDir $outLowF -HostExecutablePath $hA.State.FakeHostExe -CertificateThumbprint $hA.State.CertInfo.Thumbprint -AllowUntrustedChain -SkipDriverInstall -Force
        } -ExpectedPattern 'Benchmark30sPassed' -Message '1500/1800 frames must fail Benchmark30s'
    }

    # Case B: 1800 frames but SustainedLiveFps=45.0 (< 57.0) -> fail
    $hB = New-M01ValidationMockHarness -CaseDir $caseDir -StateKey 'S03LowFps'
    $hB.State.HostHandler = {
        param($Arguments, $jsonPath, $runIdVal, $durMs, $maxF, $wudfPid)
        $payload = New-M01MockHostPayload -RunId $runIdVal -Frames 1800 -DurationSec 30 -SustainedFps 45.0 -NvencSubmitted 1800 -NvencEncoded 1800 -EncoderOutputFps 45.0 -H264Decoded 1800
        $payload | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $jsonPath -Encoding UTF8
        return [pscustomobject]@{ ExitCode = 0; TimedOut = $false; ProcessId = 4401; Output = @('[LB-HOST] ok'); StdErr = @(); DryRun = $false }
    }
    $outLowFps = Join-Path $caseDir 'out_low_fps'
    Invoke-WithModuleMocks -GlobalMocks $hB.Mocks -ModuleMocks $hB.Mocks -Body {
        Assert-Throws {
            & $valScript -Configuration Release -TestProfile Benchmark30s -BenchmarkDurationSec 30 -TransportMode Gpu -RequireGpuShared -EnableNvenc -RequireNvenc -VerifyH264Decode -StagingDir $hB.State.StagingDir -OutputDir $outLowFps -HostExecutablePath $hB.State.FakeHostExe -CertificateThumbprint $hB.State.CertInfo.Thumbprint -AllowUntrustedChain -SkipDriverInstall -Force
        } -ExpectedPattern 'Benchmark30sPassed' -Message 'SustainedLiveFps=45.0 (<57.0) must fail Benchmark30s'
    }
}

# 39. M0.1 S-03 (#6): NVENC with only 1 encoded frame out of 120 valid frames rejected
Invoke-UnitTest -Name 'M01_S03_NvencSingleFrameEncodedRejected' -TestBody {
    param($caseDir)
    $valScript = Join-Path $scriptsDir 'Invoke-LumaBridgeFunctionalValidation.ps1'
    $h = New-M01ValidationMockHarness -CaseDir $caseDir -StateKey 'S03SingleNvenc'
    $h.State.HostHandler = {
        param($Arguments, $jsonPath, $runIdVal, $durMs, $maxF, $wudfPid)
        $payload = New-M01MockHostPayload -RunId $runIdVal -Frames 120 -DurationSec 2 -NvencSubmitted 120 -NvencEncoded 1 -H264Decoded 1
        $payload | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $jsonPath -Encoding UTF8
        return [pscustomobject]@{ ExitCode = 0; TimedOut = $false; ProcessId = 4401; Output = @('[LB-HOST] ok'); StdErr = @(); DryRun = $false }
    }
    $outDir = Join-Path $caseDir 'out_single_nvenc'
    Invoke-WithModuleMocks -GlobalMocks $h.Mocks -ModuleMocks $h.Mocks -Body {
        Assert-Throws {
            & $valScript -Configuration Release -TestProfile Performance -PerformanceTargetFrames 120 -TransportMode Gpu -RequireGpuShared -EnableNvenc -RequireNvenc -VerifyH264Decode -StagingDir $h.State.StagingDir -OutputDir $outDir -HostExecutablePath $h.State.FakeHostExe -CertificateThumbprint $h.State.CertInfo.Thumbprint -AllowUntrustedChain -SkipDriverInstall -Force
        } -ExpectedPattern 'NvencPassed.*RollbackClean=True' -Message 'Single NVENC encoded frame (1/120) must be rejected when RequireNvenc is set'
    }
    $rep = Get-Content -LiteralPath (Join-Path $outDir 'functional-validation-report.json') -Raw | ConvertFrom-Json
    Assert-Equal $rep.AcceptanceCriteria.NvencPassed $false 'NvencPassed=false for 1/120 encoded'
}

# 40. M0.1 S-03 (#7): Excessive NVENC/queue drops above MaxDropRatio rejected
Invoke-UnitTest -Name 'M01_S03_ExcessiveFrameDropsRejected' -TestBody {
    param($caseDir)
    $valScript = Join-Path $scriptsDir 'Invoke-LumaBridgeFunctionalValidation.ps1'
    $h = New-M01ValidationMockHarness -CaseDir $caseDir -StateKey 'S03Drops'
    $h.State.HostHandler = {
        param($Arguments, $jsonPath, $runIdVal, $durMs, $maxF, $wudfPid)
        $payload = New-M01MockHostPayload -RunId $runIdVal -Frames 120 -DurationSec 2 -NvencSubmitted 200 -NvencEncoded 120 -NvencDropped 50 -EncodedQueueDrops 30 -H264Decoded 120
        $payload | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $jsonPath -Encoding UTF8
        return [pscustomobject]@{ ExitCode = 0; TimedOut = $false; ProcessId = 4401; Output = @('[LB-HOST] ok'); StdErr = @(); DryRun = $false }
    }
    $outDir = Join-Path $caseDir 'out_drops'
    Invoke-WithModuleMocks -GlobalMocks $h.Mocks -ModuleMocks $h.Mocks -Body {
        Assert-Throws {
            & $valScript -Configuration Release -TestProfile Performance -PerformanceTargetFrames 120 -TransportMode Gpu -RequireGpuShared -EnableNvenc -RequireNvenc -VerifyH264Decode -MaxDropRatio 0.02 -StagingDir $h.State.StagingDir -OutputDir $outDir -HostExecutablePath $h.State.FakeHostExe -CertificateThumbprint $h.State.CertInfo.Thumbprint -AllowUntrustedChain -SkipDriverInstall -Force
        } -ExpectedPattern 'NvencPassed.*RollbackClean=True' -Message '40% NVENC/queue drop rate (>2%) must reject NvencPassed'
    }
    $rep = Get-Content -LiteralPath (Join-Path $outDir 'functional-validation-report.json') -Raw | ConvertFrom-Json
    Assert-Equal $rep.AcceptanceCriteria.NvencPassed $false 'NvencPassed=false on excessive drops'
}

# 41. M0.1 S-03 (#8): 30s benchmark never proves >=180s ProlongedStability; 180s does
Invoke-UnitTest -Name 'M01_S03_Benchmark30sNeverProves180sProlongedStability' -TestBody {
    param($caseDir)
    $valScript = Join-Path $scriptsDir 'Invoke-LumaBridgeFunctionalValidation.ps1'
    $h = New-M01ValidationMockHarness -CaseDir $caseDir -StateKey 'S03StabProof'

    Invoke-WithModuleMocks -GlobalMocks $h.Mocks -ModuleMocks $h.Mocks -Body {
        $res30 = & $valScript -Configuration Release -TestProfile Benchmark30s -BenchmarkDurationSec 30 -TransportMode Gpu -RequireGpuShared -EnableNvenc -RequireNvenc -VerifyH264Decode -StagingDir $h.State.StagingDir -OutputDir (Join-Path $caseDir 'out_30s') -HostExecutablePath $h.State.FakeHostExe -CertificateThumbprint $h.State.CertInfo.Thumbprint -AllowUntrustedChain -SkipDriverInstall -Force
        Assert-Equal $res30.OverallSucceeded $true '30s benchmark passes'
        Assert-Equal $res30.AcceptanceCriteria.Benchmark30sPassed $true 'Benchmark30sPassed=true'
        Assert-Equal $res30.AcceptanceCriteria.ProlongedStabilityProven $false '30s benchmark NEVER claims ProlongedStabilityProven=true'

        $res60 = & $valScript -Configuration Release -TestProfile ProlongedStability -StabilityDurationSec 60 -MinProlongedStabilitySec 180 -TransportMode Gpu -RequireGpuShared -EnableNvenc -RequireNvenc -VerifyH264Decode -StagingDir $h.State.StagingDir -OutputDir (Join-Path $caseDir 'out_60s') -HostExecutablePath $h.State.FakeHostExe -CertificateThumbprint $h.State.CertInfo.Thumbprint -AllowUntrustedChain -SkipDriverInstall -Force
        Assert-Equal $res60.OverallSucceeded $true '60s subprofile passes its 60s gate'
        Assert-Equal $res60.AcceptanceCriteria.ProlongedStabilityPassed $true 'ProlongedStabilityPassed=true for 60s run'
        Assert-Equal $res60.AcceptanceCriteria.ProlongedStabilityProven $false '60s run keeps ProlongedStabilityProven=false when MinProlongedStabilitySec=180'

        $res180 = & $valScript -Configuration Release -TestProfile ProlongedStability -StabilityDurationSec 180 -MinProlongedStabilitySec 180 -TransportMode Gpu -RequireGpuShared -EnableNvenc -RequireNvenc -VerifyH264Decode -StagingDir $h.State.StagingDir -OutputDir (Join-Path $caseDir 'out_180s') -HostExecutablePath $h.State.FakeHostExe -CertificateThumbprint $h.State.CertInfo.Thumbprint -AllowUntrustedChain -SkipDriverInstall -Force
        Assert-Equal $res180.OverallSucceeded $true '180s prolonged run passes'
        Assert-Equal $res180.AcceptanceCriteria.ProlongedStabilityProven $true '180s prolonged run sets ProlongedStabilityProven=true'
    }
}

# 42. M0.1 S-04 (#9): Timeout calculation across 30, 180, 600, 1800, 3600s + overflow guard + ETW >256MB support
Invoke-UnitTest -Name 'M01_S04_TimeoutCalculation30To3600SecAndOverflowValidation' -TestBody {
    param($caseDir)
    $expected = @(
        @{ Sec = 30;   Hard = 80000 },
        @{ Sec = 180;  Hard = 230000 },
        @{ Sec = 600;  Hard = 650000 },
        @{ Sec = 1800; Hard = 1850000 },
        @{ Sec = 3600; Hard = 3650000 }
    )
    foreach ($item in $expected) {
        $calc = Get-LumaBridgeValidationHostTimeoutMs -RequestedDurationMs ([int64]$item.Sec * 1000) -ConnectTimeoutMs 5000 -PrewarmMarginMs 15000 -ShutdownMarginMs 30000 -MinimumHardTimeoutMs 30000
        Assert-Equal $calc.HardTimeoutMs $item.Hard ("HardTimeoutMs matches expected margin math for {0}s" -f $item.Sec)
    }

    Assert-Throws {
        $null = Get-LumaBridgeValidationHostTimeoutMs -RequestedDurationMs 4000000
    } -ExpectedPattern 'out of valid range \[500\.\.3600000\]' -Message 'Durations > 3600000ms must fail explicitly instead of silently overflowing or truncating'

    & (Join-Path $scriptsDir 'Invoke-LumaBridgeEtwTrace.ps1') -Action Start -OutputDir (Join-Path $caseDir 'etw_1024') -CoreMaxFileSizeMb 1024 -DryRun | Out-Null
}

# 43. M0.1 S-05 (#10): Continuous resource telemetry PID isolation and NOT_MEASURED contract (never substituting 0)
Invoke-UnitTest -Name 'M01_S05_ContinuousTelemetrySamplingAndNotMeasuredContract' -TestBody {
    param($caseDir)
    $snapMocks = @{
        'Get-LumaBridgeProcessMetricsByPid' = {
            param([int]$ProcessId)
            if ($ProcessId -eq 4200) {
                return [pscustomobject]@{ Available = $true; CpuTimeSec = 1.25; WorkingSetMB = 84.5; PrivateMemoryMB = 62.0; HandleCount = 510; ThreadCount = 14; Reason = $null }
            }
            return [pscustomobject]@{ Available = $false; CpuTimeSec = $null; WorkingSetMB = $null; PrivateMemoryMB = $null; HandleCount = $null; ThreadCount = $null; Reason = ("Process PID {0} not running" -f $ProcessId) }
        }
        'Get-LumaBridgeGpuPerfCounterSamples' = {
            param([string]$CounterPath)
            if ($CounterPath -like '*Dedicated Usage*') {
                return [pscustomobject]@{
                    Available = $true; Reason = $null;
                    Samples   = @(
                        [pscustomobject]@{ InstanceName = 'pid_4200_luid_0x00000000_0x0001_phys_0'; Path = '\GPU Process Memory(pid_4200)\Dedicated Usage'; CookedValue = (128MB) },
                        [pscustomobject]@{ InstanceName = 'pid_42001_luid_0x00000000_0x0001_phys_0'; Path = '\GPU Process Memory(pid_42001)\Dedicated Usage'; CookedValue = (512MB) }
                    )
                }
            }
            return [pscustomobject]@{
                Available = $true; Reason = $null;
                Samples   = @(
                    [pscustomobject]@{ InstanceName = 'pid_4200_luid_0x00000000_0x0001_phys_0_eng_0_engtype_3D'; Path = '\GPU Engine(pid_4200_..._engtype_3D)\Utilization Percentage'; CookedValue = 14.5 },
                    [pscustomobject]@{ InstanceName = 'pid_42001_luid_0x00000000_0x0001_phys_0_eng_2_engtype_VideoEncode'; Path = '\GPU Engine(pid_42001_..._engtype_VideoEncode)\Utilization Percentage'; CookedValue = 88.0 }
                )
            }
        }
    }

    Invoke-WithModuleMocks -ModuleMocks $snapMocks -Body {
        $s1 = Get-LumaBridgeProcessResourceSnapshot -HostPid 4200 -WudfPid 4209 -Phase 'Start'
        $s2 = Get-LumaBridgeProcessResourceSnapshot -HostPid 4200 -WudfPid 4209 -Phase 'End'

        Assert-Equal $s1.Host.Status 'MEASURED' 'Host process metrics measured cleanly'
        Assert-Equal $s1.Host.DedicatedVramMB 128.0 'Host VRAM matches pid_4200 only (excludes pid_42001 512MB)'
        Assert-Equal $s1.Host.GpuEngineTotalPercent 14.5 'Host GPU Engine matches pid_4200 only (excludes pid_42001 88.0%)'

        Assert-Equal $s1.WudfHost.Status 'NOT_MEASURED' 'Unavailable WUDFHost reports NOT_MEASURED (never 0)'
        Assert-Equal $s1.WudfHost.WorkingSetMB $null 'Unavailable WorkingSetMB is $null (never 0)'
        Assert-Equal $s1.WudfHost.DedicatedVramStatus 'NOT_MEASURED' 'Unavailable VRAM reports NOT_MEASURED'
        Assert-Equal $s1.WudfHost.DedicatedVramMB $null 'Unavailable VRAM is $null (never 0)'
        Assert-True (-not [string]::IsNullOrWhiteSpace($s1.WudfHost.Reason)) 'Unmeasured telemetry includes explicit Reason'

        $hostSum = Measure-LumaBridgeResourceSeriesSummary -Samples @($s1, $s2) -Role Host
        $wudfSum = Measure-LumaBridgeResourceSeriesSummary -Samples @($s1, $s2) -Role WudfHost
        Assert-Equal $hostSum.Status 'MEASURED' 'Host series status MEASURED'
        Assert-Equal $hostSum.DedicatedVramMB.Peak 128.0 'Host VRAM Peak=128MB'
        Assert-Equal $wudfSum.Status 'NOT_MEASURED' 'WudfHost series status NOT_MEASURED'
        Assert-Equal $wudfSum.WorkingSetMB.Peak $null 'WudfHost WorkingSetMB.Peak is $null'
    }
}

# 44. M0.1 S-06 (#11): Initial snapshot restores pre-existing EnableVirtualMonitor=1 and preserves pre-existing certs
Invoke-UnitTest -Name 'M01_S06_InitialSnapshotPreservesPreExistingCertsAndRegistrySemantics' -TestBody {
    param($caseDir)
    $valScript = Join-Path $scriptsDir 'Invoke-LumaBridgeFunctionalValidation.ps1'

    # Case A: Pre-existing EnableVirtualMonitor=1, absent EnableGpuSharedTransport/AuthSid, pre-existing cert -> exact restore
    $h = New-M01ValidationMockHarness -CaseDir $caseDir -StateKey 'S06Preserve' -InitialEnableMon 1 -InitialEnableExt 0 -InitialEnableGpuTrans $null -InitialAuthSid $null
    $h.State.PreExistingCertThumbprint = $h.State.CertInfo.Thumbprint

    Invoke-WithModuleMocks -GlobalMocks $h.Mocks -ModuleMocks $h.Mocks -Body {
        $res = & $valScript -Configuration Release -TestProfile Smoke -TransportMode Gpu -StagingDir $h.State.StagingDir -OutputDir (Join-Path $caseDir 'out_preserve') -HostExecutablePath $h.State.FakeHostExe -CertificateThumbprint $h.State.CertInfo.Thumbprint -SkipDriverInstall -Force
        Assert-Equal $res.OverallSucceeded $true 'Run succeeds with pre-existing EnableVirtualMonitor=1 and trusted cert'
        Assert-Equal $res.SystemStateRestored $true 'SystemStateRestored=true when exact initial snapshot restored'
        Assert-Equal $res.RollbackClean $true 'RollbackClean=true'
        Assert-Equal $h.State.EnableMon 1 'Pre-existing EnableVirtualMonitor=1 preserved on rollback (NOT cleared to 0)'
        Assert-Equal $h.State.EnableExt 0 'Pre-existing EnableFrameExtraction=0 restored'
        Assert-Equal $h.State.EnableGpuTrans $null 'Previously absent EnableGpuSharedTransport restored to $null'
        Assert-Equal $h.State.AuthSid $null 'Previously absent AuthorizedHostUserSid cleared back to $null'
    }
    $rep = Get-Content -LiteralPath (Join-Path (Join-Path $caseDir 'out_preserve') 'functional-validation-report.json') -Raw | ConvertFrom-Json
    Assert-Equal $rep.CertificateWasPreExisting $true 'Report records CertificateWasPreExisting=true'
    Assert-Equal $rep.PreExistingCertsPreserved $true 'Report records PreExistingCertsPreserved=true'

    # Case B: Invoke-LumaBridgePackageSigning -TrustCertificate skips certutil -addstore when cert is already trusted in Root & TrustedPublisher
    $h.State.CertutilAddCalls = 0
    $signSkipMocks = @{}
    foreach ($k in $h.Mocks.Keys) { $signSkipMocks[$k] = $h.Mocks[$k] }
    $signSkipMocks['Test-LumaBridgePackageArtifacts'] = {
        [CmdletBinding()]
        param([string]$PackageDirectory, [string]$ExpectedSignerThumbprint, [switch]$RequireValidSignature, [switch]$AllowUntrustedChain)
        return [pscustomobject]@{
            SignerCertificatesMatch  = $true
            IsCryptographicallyValid = $true
            IsValidWithUntrustedRoot = $true
        }
    }
    Invoke-WithModuleMocks -GlobalMocks $signSkipMocks -ModuleMocks $signSkipMocks -Body {
        $signOut = & (Join-Path $scriptsDir 'Invoke-LumaBridgePackageSigning.ps1') -Configuration Release -StagingDir (Join-Path $caseDir 'stg_sign_skip') -CertificateThumbprint $h.State.CertInfo.Thumbprint -TrustCertificate -Force
        Assert-Equal $h.State.CertutilAddCalls 0 'PackageSigning -TrustCertificate avoids redundant certutil -addstore when already trusted'
        Assert-Equal $signOut.CertificateAlreadyTrustedRoot $true 'CertificateAlreadyTrustedRoot=true'
        Assert-Equal $signOut.CertificateAlreadyTrustedPub $true 'CertificateAlreadyTrustedPub=true'
        Assert-Equal $signOut.CertificateTrustedInRun $false 'CertificateTrustedInRun=false'
    }

    # Case C: Missing pre-existing cert post-rollback forces RollbackClean=false & throw
    $hC = New-M01ValidationMockHarness -CaseDir $caseDir -StateKey 'S06DropCert' -InitialEnableMon 1
    $hC.State.PreExistingCertThumbprint = $hC.State.CertInfo.Thumbprint
    $hC.State.DropCertInPostRollback = $true
    $outDrop = Join-Path $caseDir 'out_drop_cert'
    Invoke-WithModuleMocks -GlobalMocks $hC.Mocks -ModuleMocks $hC.Mocks -Body {
        Assert-Throws {
            & $valScript -Configuration Release -TestProfile Smoke -StagingDir $hC.State.StagingDir -OutputDir $outDrop -HostExecutablePath $hC.State.FakeHostExe -CertificateThumbprint $hC.State.CertInfo.Thumbprint -SkipDriverInstall -Force
        } -ExpectedPattern 'RollbackClean=False' -Message 'Disappearance of pre-existing cert post-rollback must fail RollbackClean'
    }
    $repDrop = Get-Content -LiteralPath (Join-Path $outDrop 'functional-validation-report.json') -Raw | ConvertFrom-Json
    Assert-Equal $repDrop.PreExistingCertsPreserved $false 'Report records PreExistingCertsPreserved=false'
}

# 45. M0.1 S-07 (#12): Stale timestamps, mismatched RunId, incomplete summary & truncated JSON rejected
Invoke-UnitTest -Name 'M01_S07_StaleWrongRunIdAndIncompleteJsonRejected' -TestBody {
    param($caseDir)
    $valScript = Join-Path $scriptsDir 'Invoke-LumaBridgeFunctionalValidation.ps1'

    $modes = @(
        @{ Key = 'RunIdMismatch'; ExpectedStatus = 'RUN_ID_MISMATCH' },
        @{ Key = 'Incomplete';    ExpectedStatus = 'INCOMPLETE_SUMMARY' },
        @{ Key = 'Truncated';     ExpectedStatus = 'INVALID_JSON' },
        @{ Key = 'StaleTime';     ExpectedStatus = 'STALE_TIMESTAMP' }
    )

    foreach ($m in $modes) {
        $sk = "S07_" + $m.Key
        $h = New-M01ValidationMockHarness -CaseDir $caseDir -StateKey $sk
        $modeName = $m.Key
        $h.State.HostHandler = {
            param($Arguments, $jsonPath, $runIdVal, $durMs, $maxF, $wudfPid)
            switch ($modeName) {
                'RunIdMismatch' {
                    $p = New-M01MockHostPayload -RunId '20200101T000000Z-foreign0000' -Frames 60
                    $p | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $jsonPath -Encoding UTF8
                }
                'Incomplete' {
                    $p = New-M01MockHostPayload -RunId $runIdVal -Frames 60 -SummaryComplete $false
                    $p | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $jsonPath -Encoding UTF8
                }
                'Truncated' {
                    '{"RunId":"' + $runIdVal + '","FramesReceived":' | Set-Content -LiteralPath $jsonPath -Encoding UTF8
                }
                'StaleTime' {
                    $p = New-M01MockHostPayload -RunId $runIdVal -Frames 60
                    $p | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $jsonPath -Encoding UTF8
                    [System.IO.File]::SetLastWriteTimeUtc($jsonPath, [DateTime]::UtcNow.AddMinutes(-15))
                }
            }
            return [pscustomobject]@{ ExitCode = 0; TimedOut = $false; ProcessId = 4401; Output = @('[LB-HOST] ok'); StdErr = @(); DryRun = $false }
        }.GetNewClosure()

        $outDir = Join-Path $caseDir ("out_{0}" -f $m.Key)
        Invoke-WithModuleMocks -GlobalMocks $h.Mocks -ModuleMocks $h.Mocks -Body {
            Assert-Throws {
                & $valScript -Configuration Release -TestProfile Smoke -StagingDir $h.State.StagingDir -OutputDir $outDir -HostExecutablePath $h.State.FakeHostExe -CertificateThumbprint $h.State.CertInfo.Thumbprint -AllowUntrustedChain -SkipDriverInstall -Force
            } -ExpectedPattern 'RollbackClean=True' -Message ("Runner rejects {0} JSON summary" -f $m.Key)
        }
        $rep = Get-Content -LiteralPath (Join-Path $outDir 'functional-validation-report.json') -Raw | ConvertFrom-Json
        Assert-Equal $rep.SmokeSummaryValidation.Status $m.ExpectedStatus ("Report records SummaryValidation.Status={0}" -f $m.ExpectedStatus)
        Assert-Equal $rep.FunctionalValidationSucceeded $false ("FunctionalValidationSucceeded=false for {0}" -f $m.Key)
    }
}

# 46. M0.1 S-07 (#13): Wrong driver version, missing binding & DLL SHA-256 mismatch rejected
Invoke-UnitTest -Name 'M01_S07_WrongDriverVersionMissingBindingAndBinaryHashMismatchRejected' -TestBody {
    param($caseDir)
    $valScript = Join-Path $scriptsDir 'Invoke-LumaBridgeFunctionalValidation.ps1'

    # Case A: -SkipDriverInstall when bound driver is old 1.50.4.765 -> Stage 6 fails & preserves EnableVirtualMonitor=1
    $h = New-M01ValidationMockHarness -CaseDir $caseDir -StateKey 'S07OldDriver' -InitialDriverVersion '1.50.4.765' -InitialEnableMon 1
    $outOld = Join-Path $caseDir 'out_old_drv'
    Invoke-WithModuleMocks -GlobalMocks $h.Mocks -ModuleMocks $h.Mocks -Body {
        Assert-Throws {
            & $valScript -Configuration Release -TestProfile Smoke -StagingDir $h.State.StagingDir -OutputDir $outOld -HostExecutablePath $h.State.FakeHostExe -CertificateThumbprint $h.State.CertInfo.Thumbprint -AllowUntrustedChain -SkipDriverInstall -Force
        } -ExpectedPattern 'Installed driver binding/identity check failed.*RollbackClean=True' -Message 'Old driver version under -SkipDriverInstall fails Stage 6'
    }
    Assert-Equal $h.State.EnableMon 1 'EnableVirtualMonitor=1 preserved after Stage 6 failure'

    # Case B: Direct Test-LumaBridgeDeviceDriverBinding binary identity tests
    $relDir = Get-LumaBridgePackageDirectory -Configuration Release
    $relInf = Join-Path $relDir 'LumaBridgeIddDriver.inf'
    $relDll = Join-Path $relDir 'LumaBridgeIddDriver.dll'
    $relVer = Get-LumaBridgeInfDriverVersion -InfPath $relInf
    $tamperedDll = Join-Path $caseDir 'Tampered.dll'
    [System.IO.File]::WriteAllBytes($tamperedDll, [byte[]]@(1, 2, 3, 4, 5))

    $instOk = [pscustomobject]@{ InstanceId = 'ROOT\DISPLAY\0000'; Present = $true; Status = 'OK'; ProblemCode = 0; HardwareIds = @('Root\LumaBridgeIddDriver'); DriverInfPath = 'oem99.inf'; DriverProvider = 'LumaBridge'; DriverVersion = $relVer }
    $bindOk = Test-LumaBridgeDeviceDriverBinding -Instance $instOk -ExpectedInfPath $relInf -ExpectedDllPath $relDll -LoadedModulePath $relDll -RequireBinaryHashMatch
    Assert-Equal $bindOk.IsBound $true 'Matching DLL SHA-256 binds cleanly'
    Assert-Equal $bindOk.BinaryIdentityStatus 'VERIFIED' 'BinaryIdentityStatus=VERIFIED'

    $bindMismatch = Test-LumaBridgeDeviceDriverBinding -Instance $instOk -ExpectedInfPath $relInf -ExpectedDllPath $relDll -LoadedModulePath $tamperedDll -RequireBinaryHashMatch
    Assert-Equal $bindMismatch.IsBound $false 'Mismatched DLL SHA-256 fails binding'
    Assert-Equal $bindMismatch.BinaryIdentityStatus 'MISMATCH' 'BinaryIdentityStatus=MISMATCH'

    $instNoInf = [pscustomobject]@{ InstanceId = 'ROOT\DISPLAY\0000'; Present = $true; Status = 'OK'; ProblemCode = 0; HardwareIds = @('Root\LumaBridgeIddDriver'); DriverInfPath = ''; DriverProvider = 'LumaBridge'; DriverVersion = $relVer }
    $bindNoInf = Test-LumaBridgeDeviceDriverBinding -Instance $instNoInf -ExpectedInfPath $relInf
    Assert-Equal $bindNoInf.IsBound $false 'Empty DriverInfPath fails binding'

    $bindUnmeasured = Test-LumaBridgeDeviceDriverBinding -Instance $instOk -ExpectedInfPath $relInf -ExpectedDllPath $relDll -LoadedModulePath (Join-Path $caseDir 'Missing.dll') -RequireBinaryHashMatch
    Assert-Equal $bindUnmeasured.IsBound $false 'RequireBinaryHashMatch fails when binary identity is NOT_MEASURED'
    Assert-Equal $bindUnmeasured.BinaryIdentityStatus 'NOT_MEASURED' 'BinaryIdentityStatus=NOT_MEASURED'
}

# 47. M0.1 S-07 (#14): Composite profiles Both and Full evaluate each subprofile independently
Invoke-UnitTest -Name 'M01_S07_CompositeProfilesBothAndFullEvaluateEachSubprofileIndependently' -TestBody {
    param($caseDir)
    $valScript = Join-Path $scriptsDir 'Invoke-LumaBridgeFunctionalValidation.ps1'

    # Case A: Both where Smoke returns >=1 frames so Performance still runs and PASSES (60 frames),
    # while Smoke FAILS (ChecksumMismatches=1 / ExitCode=1) -> Overall MUST FAIL
    $hBoth = New-M01ValidationMockHarness -CaseDir $caseDir -StateKey 'S07BothFailSmoke'
    $hBoth.State.HostHandler = {
        param($Arguments, $jsonPath, $runIdVal, $durMs, $maxF, $wudfPid)
        $isPerf = ($Arguments -contains '--require-max-frames')
        $fc = if ($isPerf) { 60 } else { 3 }
        $payload = New-M01MockHostPayload -RunId $runIdVal -Frames $fc -FrameTargetReached $isPerf -NvencSubmitted $fc -NvencEncoded $fc -H264Decoded $fc
        if (-not $isPerf) {
            $payload.ChecksumMismatches = 1
        }
        $payload | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $jsonPath -Encoding UTF8
        return [pscustomobject]@{ ExitCode = $(if ($isPerf) { 0 } else { 1 }); TimedOut = $false; ProcessId = 4401; Output = @('[LB-HOST] ok'); StdErr = @(); DryRun = $false }
    }
    $outBoth = Join-Path $caseDir 'out_both_indep'
    Invoke-WithModuleMocks -GlobalMocks $hBoth.Mocks -ModuleMocks $hBoth.Mocks -Body {
        Assert-Throws {
            & $valScript -Configuration Release -TestProfile Both -StagingDir $hBoth.State.StagingDir -OutputDir $outBoth -HostExecutablePath $hBoth.State.FakeHostExe -CertificateThumbprint $hBoth.State.CertInfo.Thumbprint -AllowUntrustedChain -SkipDriverInstall -Force
        } -ExpectedPattern 'AllSubprofilesPassed.*RollbackClean=True' -Message 'Both fails overall when Smoke fails even if Performance passes'
    }
    $repBoth = Get-Content -LiteralPath (Join-Path $outBoth 'functional-validation-report.json') -Raw | ConvertFrom-Json
    Assert-Equal $repBoth.AcceptanceCriteria.FunctionalSmokePassed $false 'FunctionalSmokePassed=false'
    Assert-Equal $repBoth.AcceptanceCriteria.PerformanceTargetReached $true 'PerformanceTargetReached=true'
    Assert-Equal $repBoth.AcceptanceCriteria.AllSubprofilesPassed $false 'AllSubprofilesPassed=false'

    # Case B: Full where Smoke, Performance, ProlongedStability PASS, ONLY Benchmark30s fails (1280x720) -> Overall MUST FAIL
    $hFull = New-M01ValidationMockHarness -CaseDir $caseDir -StateKey 'S07FullFailBench'
    $hFull.State.HostHandler = {
        param($Arguments, $jsonPath, $runIdVal, $durMs, $maxF, $wudfPid)
        $is30s = ($durMs -eq 30000)
        $sec = [Math]::Max(1, [int][Math]::Round($durMs / 1000.0))
        $fc = if ($Arguments -contains '--require-max-frames') { [uint64]$maxF } else { [uint64]($sec * 60) }
        $w = if ($is30s) { [uint32]1280 } else { [uint32]1920 }
        $ht = if ($is30s) { [uint32]720 } else { [uint32]1080 }
        $payload = New-M01MockHostPayload -RunId $runIdVal -Frames $fc -Width $w -Height $ht -DurationSec $sec -NvencSubmitted $fc -NvencEncoded $fc -H264Decoded $fc
        $payload | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $jsonPath -Encoding UTF8
        return [pscustomobject]@{ ExitCode = 0; TimedOut = $false; ProcessId = 4401; Output = @('[LB-HOST] ok'); StdErr = @(); DryRun = $false }
    }
    $outFull = Join-Path $caseDir 'out_full_indep'
    Invoke-WithModuleMocks -GlobalMocks $hFull.Mocks -ModuleMocks $hFull.Mocks -Body {
        Assert-Throws {
            & $valScript -Configuration Release -TestProfile Full -BenchmarkDurationSec 30 -StabilityDurationSec 180 -TransportMode Gpu -RequireGpuShared -EnableNvenc -RequireNvenc -VerifyH264Decode -StagingDir $hFull.State.StagingDir -OutputDir $outFull -HostExecutablePath $hFull.State.FakeHostExe -CertificateThumbprint $hFull.State.CertInfo.Thumbprint -AllowUntrustedChain -SkipDriverInstall -Force
        } -ExpectedPattern 'Benchmark30sPassed.*RollbackClean=True' -Message 'Full fails overall when Benchmark30s fails even if ProlongedStability passes'
    }
    $repFull = Get-Content -LiteralPath (Join-Path $outFull 'functional-validation-report.json') -Raw | ConvertFrom-Json
    Assert-Equal $repFull.AcceptanceCriteria.FunctionalSmokePassed $true 'Full Smoke passed'
    Assert-Equal $repFull.AcceptanceCriteria.PerformanceTestExecuted $false 'Full profile does not run standalone Performance subprofile'
    Assert-Equal $repFull.AcceptanceCriteria.Benchmark30sExecuted $true 'Full Benchmark30s executed'
    Assert-Equal $repFull.AcceptanceCriteria.Benchmark30sPassed $false 'Full Benchmark30s failed'
    Assert-Equal $repFull.AcceptanceCriteria.ProlongedStabilityExecuted $true 'Full ProlongedStability executed'
    Assert-Equal $repFull.AcceptanceCriteria.ProlongedStabilityPassed $true 'Full ProlongedStability passed'
    Assert-Equal $repFull.AcceptanceCriteria.ProlongedStabilityProven $true 'Full ProlongedStabilityProven=true (180s)'
    Assert-Equal $repFull.AcceptanceCriteria.AllSubprofilesPassed $false 'AllSubprofilesPassed=false'
}

# 48. M0.1 S-06/S-07 (#15): Intermediate Stage 6, Stage 7, and Stage 9 failures recover cleanly & capture Stage 10 diagnostics
Invoke-UnitTest -Name 'M01_S06_S07_IntermediateStage6_7_8_9FailuresWithRecoveryAndDiagnostics' -TestBody {
    param($caseDir)
    $valScript = Join-Path $scriptsDir 'Invoke-LumaBridgeFunctionalValidation.ps1'

    # Case A: Stage 6 unhealthy PnP instance stops ETW, preserves EnableVirtualMonitor=1 & honestly reports persistent ProblemCode on rollback;
    # and healthy PnP instance with missing binding fails Stage 6 with RollbackClean=True
    $h6 = New-M01ValidationMockHarness -CaseDir $caseDir -StateKey 'S07Stage6' -InitialEnableMon 1
    $h6.State.Status = 'Error'
    $h6.State.ProblemCode = 31
    Invoke-WithModuleMocks -GlobalMocks $h6.Mocks -ModuleMocks $h6.Mocks -Body {
        Assert-Throws {
            & $valScript -Configuration Release -TestProfile Smoke -StagingDir $h6.State.StagingDir -OutputDir (Join-Path $caseDir 'out_st6') -HostExecutablePath $h6.State.FakeHostExe -CertificateThumbprint $h6.State.CertInfo.Thumbprint -AllowUntrustedChain -SkipDriverInstall -Force
        } -ExpectedPattern 'unhealthy after Stage 6.*Post-rollback device unhealthy' -Message 'Stage 6 unhealthy device halts validation and surfaces persistent ProblemCode post-rollback'
    }
    Assert-Equal $h6.State.EtwRunning $false 'ETW stopped after Stage 6 failure'
    Assert-Equal $h6.State.EnableMon 1 'EnableVirtualMonitor=1 preserved after Stage 6 failure'

    $h6Bind = New-M01ValidationMockHarness -CaseDir $caseDir -StateKey 'S07Stage6Bind' -InitialDriverInfPath '' -InitialEnableMon 1
    Invoke-WithModuleMocks -GlobalMocks $h6Bind.Mocks -ModuleMocks $h6Bind.Mocks -Body {
        Assert-Throws {
            & $valScript -Configuration Release -TestProfile Smoke -StagingDir $h6Bind.State.StagingDir -OutputDir (Join-Path $caseDir 'out_st6_bind') -HostExecutablePath $h6Bind.State.FakeHostExe -CertificateThumbprint $h6Bind.State.CertInfo.Thumbprint -AllowUntrustedChain -SkipDriverInstall -Force
        } -ExpectedPattern 'Installed driver binding/identity check failed.*RollbackClean=True' -Message 'Stage 6 missing INF binding triggers clean rollback'
    }
    Assert-Equal $h6Bind.State.EtwRunning $false 'ETW stopped after Stage 6 missing binding failure'
    Assert-Equal $h6Bind.State.EnableMon 1 'EnableVirtualMonitor=1 preserved after Stage 6 missing binding failure'

    # Case B: Stage 7 monitor activation failure
    $h7 = New-M01ValidationMockHarness -CaseDir $caseDir -StateKey 'S07Stage7' -InitialEnableMon 0
    $h7.State.InjectStage7Fail = $true
    Invoke-WithModuleMocks -GlobalMocks $h7.Mocks -ModuleMocks $h7.Mocks -Body {
        Assert-Throws {
            & $valScript -Configuration Release -TestProfile Smoke -StagingDir $h7.State.StagingDir -OutputDir (Join-Path $caseDir 'out_st7') -HostExecutablePath $h7.State.FakeHostExe -CertificateThumbprint $h7.State.CertInfo.Thumbprint -AllowUntrustedChain -SkipDriverInstall -Force
        } -ExpectedPattern 'Simulated Stage 7 virtual monitor failure.*RollbackClean=True' -Message 'Stage 7 failure triggers clean rollback'
    }
    Assert-Equal $h7.State.EtwRunning $false 'ETW stopped after Stage 7 failure'
    Assert-Equal $h7.State.EnableMon 0 'EnableVirtualMonitor restored to 0 after Stage 7 failure'

    # Case C: Stage 9 host crash still executes Stage 10 diagnostics capture
    $h9 = New-M01ValidationMockHarness -CaseDir $caseDir -StateKey 'S07Stage9' -InitialEnableMon 1
    $h9.State.HostHandler = {
        param($Arguments, $jsonPath, $runIdVal, $durMs, $maxF, $wudfPid)
        return [pscustomobject]@{ ExitCode = 1; TimedOut = $false; ProcessId = 4401; Output = @('[LB-HOST] simulated crash'); StdErr = @('fatal'); DryRun = $false }
    }
    $out9 = Join-Path $caseDir 'out_st9'
    Invoke-WithModuleMocks -GlobalMocks $h9.Mocks -ModuleMocks $h9.Mocks -Body {
        Assert-Throws {
            & $valScript -Configuration Release -TestProfile Smoke -StagingDir $h9.State.StagingDir -OutputDir $out9 -HostExecutablePath $h9.State.FakeHostExe -CertificateThumbprint $h9.State.CertInfo.Thumbprint -AllowUntrustedChain -SkipDriverInstall -Force
        } -ExpectedPattern 'RollbackClean=True' -Message 'Stage 9 failure rolls back cleanly'
    }
    $rep9 = Get-Content -LiteralPath (Join-Path $out9 'functional-validation-report.json') -Raw | ConvertFrom-Json
    Assert-True ($null -ne $rep9.DiagnosticsResult) 'Stage 10 DiagnosticsResult captured even when Stage 9 host failed'
    Assert-True (Test-Path -LiteralPath $rep9.DiagnosticsResult.JsonReportPath -PathType Leaf) 'Stage 10 diagnostics JSON written on Stage 9 failure'
    Assert-Equal $rep9.RollbackClean $true 'RollbackClean=true after Stage 9 failure'
}

# 49. M0.1 S-08: Read-only VBS/HVCI, OS build/arch, required services & API availability diagnostics
Invoke-UnitTest -Name 'M01_S08_HostSecurityVbsHvciAndServicesReadOnlyDiagnostics' -TestBody {
    param($caseDir)

    # Case A: Mocked Running VBS + HVCI -> populates InformationalWarnings without inventing blocking error
    Invoke-WithModuleMocks -ModuleMocks @{
        'Confirm-SecureBootUEFI' = { return $false }
        'Get-CimInstance' = {
            param($Namespace, $ClassName)
            return [pscustomobject]@{ VirtualizationBasedSecurityStatus = 2; SecurityServicesRunning = @(1, 2); SecurityServicesConfigured = @(1, 2) }
        }
        'Get-Service' = {
            param([string]$Name)
            return [pscustomobject]@{ Status = 'Running'; StartType = 'Manual' }
        }
    } -Body {
        $sec = Get-LumaBridgeHostSecurityState
        Assert-Equal $sec.VbsStatus 'Running' 'VbsStatus=Running reported'
        Assert-Equal $sec.HvciStatus 'Running' 'HvciStatus=Running reported'
        Assert-True (@($sec.InformationalWarnings).Count -ge 2) 'HVCI and VBS produce informational warnings'
        Assert-Equal $sec.RequiredServices.WUDFRd.Status 'Running' 'RequiredServices.WUDFRd reported'
    }

    # Case B: Inaccessible DeviceGuard + missing registry/service -> records UnavailableChecks (never invents Disabled)
    Invoke-WithModuleMocks -ModuleMocks @{
        'Confirm-SecureBootUEFI' = { throw ([System.UnauthorizedAccessException]::new('Access denied')) }
        'Get-CimInstance' = { throw 'WMI blocked' }
        'Get-LumaBridgeRegistryValueState' = { param([string]$LiteralPath, [string]$Name) return [pscustomobject]@{ KeyExists = $false; ValueExists = $false; Value = $null } }
        'Get-Service' = { param([string]$Name) throw 'Service inaccessible' }
    } -Body {
        $secUnavail = Get-LumaBridgeHostSecurityState
        Assert-Equal $secUnavail.HvciStatus 'Unavailable' 'HvciStatus marked Unavailable when CIM & registry are inaccessible'
        Assert-True (@($secUnavail.UnavailableChecks) -contains 'HvciStatus') 'UnavailableChecks includes HvciStatus'
        Assert-True (@($secUnavail.UnavailableChecks) -contains 'Service:WUDFRd') 'UnavailableChecks includes Service:WUDFRd'
    }

    # Case C: Live read-only prerequisites script returns VBS/HVCI/Build/Architecture/Services/ApiAvailability schema
    $prereqOut = & (Join-Path $scriptsDir 'Test-LumaBridgePrerequisites.ps1') -Configuration Release
    Assert-True ($null -ne $prereqOut.SecurityState.VbsStatus) 'Live SecurityState exposes VbsStatus'
    Assert-True ($null -ne $prereqOut.SecurityState.HvciStatus) 'Live SecurityState exposes HvciStatus'
    Assert-True ($null -ne $prereqOut.RequiredServices.WUDFRd) 'Live Prerequisites exposes RequiredServices.WUDFRd'
    Assert-True ($null -ne $prereqOut.ApiAvailability) 'Live Prerequisites exposes ApiAvailability'
    Assert-True (-not [string]::IsNullOrWhiteSpace($prereqOut.HostOs.Architecture)) 'Live HostOs exposes Architecture'
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
