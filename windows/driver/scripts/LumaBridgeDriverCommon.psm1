Set-StrictMode -Version Latest

Add-Type -AssemblyName System.Security

$script:LumaBridgeDriverConstants = [pscustomobject]@{
    HardwareId                  = 'Root\LumaBridgeIddDriver'
    DeviceDisplayName           = 'LumaBridge Indirect Display Adapter'
    DriverServiceName           = 'LumaBridgeIddDriver'
    DisplayClassGuid            = '{4d36e968-e325-11ce-bfc1-08002be10318}'
    DriverProviderName          = 'LumaBridge'
    InfFileName                 = 'LumaBridgeIddDriver.inf'
    DllFileName                 = 'LumaBridgeIddDriver.dll'
    CatFileName                 = 'lumabridgeidddriver.cat'
    DefaultCertificateSubject   = 'CN=LumaBridge Test Driver Signing'
    DefaultConfiguration        = 'Release'
    SupportedInf2CatOsList      = '10_CO_X64,10_NI_X64,10_GE_X64'
    MinimumWindows11Build       = 22000
    RegistryValueEnableMon      = 'EnableVirtualMonitor'
    RegistryValueEnableExt      = 'EnableFrameExtraction'
    RegistryValueEnableGpuTrans = 'EnableGpuSharedTransport'
    RegistryValueAuthorizedSid  = 'AuthorizedHostUserSid'
    EtwSessionName              = 'LumaBridgeIddCore'
    EtwDxgSessionName           = 'LumaBridgeIddDxg'
    EtwLegacySessionName        = 'LumaBridgeIddTrace'
    LumaBridgeTraceProviderGuid = '{A7E4C910-5B32-4F8E-9D21-7C3A1B8E4F01}'
    IddCxManifestProviderGuid   = '{966CD1C0-3F69-42AD-9877-517DCE8462B4}'
    IddCxWppProviderGuid        = '{D92BCB52-FA78-406F-A9A5-2037509FADEA}'
    IddCxWppMatchAnyKeyword     = '0x4000000004f4'
    IddCxWppAllFlags            = '0xFFFFFFFFFFFFFFFF'
    UmdfOperationalProviderGuid = '{2E35AAEB-857F-4BEB-A418-2E6C0E54D988}'
    WdfCoreWppProviderGuid      = '{485E7DE9-0A80-11D8-AD15-505054503030}'
    WatchdogEventsProviderGuid  = '{70E74DD8-39DB-5F6F-6FD1-F5581B29E834}'
    WerKernelProviderGuid       = '{87A623F0-8DB5-5C11-7C80-A2EBBCBE5189}'
    DxgKrnlProviderGuid         = '{802EC45A-1E99-4B83-9920-87C98277BA9D}'
    DefaultSetupApiLogPath      = 'C:\Windows\INF\setupapi.dev.log'
}

if (-not ([System.Management.Automation.PSTypeName]'LumaBridgeNativeCatalogVerifier').Type) {
    Add-Type -Language CSharp -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;

public sealed class LumaBridgeCatalogVerificationResult
{
    public bool DllCatalogHashVerified { get; set; }
    public bool InfCatalogHashVerified { get; set; }
    public bool AllMembersVerified { get; set; }
    public int MemberCount { get; set; }
    public string Detail { get; set; }
}

public static class LumaBridgeNativeCatalogVerifier
{
    private const uint CRYPTCAT_OPEN_EXISTING = 0x00000002;
    private const uint GENERIC_READ = 0x80000000;
    private const uint FILE_SHARE_READ = 0x00000001;
    private const uint FILE_SHARE_WRITE = 0x00000002;
    private const uint FILE_SHARE_DELETE = 0x00000004;
    private const uint OPEN_EXISTING = 3;
    private const uint FILE_ATTRIBUTE_NORMAL = 0x00000080;

    private const uint WTD_UI_NONE = 2;
    private const uint WTD_REVOKE_NONE = 0;
    private const uint WTD_CHOICE_FILE = 1;
    private const uint WTD_STATEACTION_VERIFY = 1;
    private const uint WTD_STATEACTION_CLOSE = 2;
    private const uint WTD_SAFER_FLAG = 0x00000100;

    private const string OID_NIST_SHA256 = "2.16.840.1.101.3.4.2.1";
    private const string OID_OIWSEC_SHA1 = "1.3.14.3.2.26";

    private static readonly Guid WINTRUST_ACTION_GENERIC_VERIFY_V2 =
        new Guid("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

    [StructLayout(LayoutKind.Sequential, Pack = 8)]
    private struct CRYPTOAPI_BLOB
    {
        public uint cbData;
        public IntPtr pbData;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 8)]
    private struct CRYPT_ATTRIBUTE_TYPE_VALUE
    {
        public IntPtr pszObjId;
        public CRYPTOAPI_BLOB Value;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 8)]
    private struct CRYPT_ALGORITHM_IDENTIFIER
    {
        public IntPtr pszObjId;
        public CRYPTOAPI_BLOB Parameters;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 8)]
    private struct SIP_INDIRECT_DATA
    {
        public CRYPT_ATTRIBUTE_TYPE_VALUE Data;
        public CRYPT_ALGORITHM_IDENTIFIER DigestAlgorithm;
        public CRYPTOAPI_BLOB Digest;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 8)]
    private struct CRYPTCATMEMBER
    {
        public uint cbStruct;
        public IntPtr pwszReferenceTag;
        public IntPtr pwszFileName;
        public Guid gSubjectType;
        public uint fdwMemberFlags;
        public IntPtr pIndirectData;
        public uint dwCertVersion;
        public uint dwReserved;
        public IntPtr hReserved;
        public CRYPTOAPI_BLOB sEncodedIndirectData;
        public CRYPTOAPI_BLOB sEncodedMemberInfo;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 8)]
    private struct CRYPTCATATTRIBUTE
    {
        public uint cbStruct;
        public IntPtr pwszReferenceTag;
        public uint dwAttrTypeAndAction;
        public uint cbValue;
        public IntPtr pbValue;
        public uint dwReserved;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 8)]
    private struct WINTRUST_FILE_INFO
    {
        public uint cbStruct;
        public IntPtr pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 8)]
    private struct WINTRUST_DATA
    {
        public uint cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public IntPtr pFile;
        public uint dwStateAction;
        public IntPtr hWVTStateData;
        public IntPtr pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
        public IntPtr pSignatureSettings;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateFileW(
        string lpFileName,
        uint dwDesiredAccess,
        uint dwShareMode,
        IntPtr lpSecurityAttributes,
        uint dwCreationDisposition,
        uint dwFlagsAndAttributes,
        IntPtr hTemplateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    [DllImport("wintrust.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CryptCATOpen(
        string pwszFileName,
        uint fdwOpenFlags,
        IntPtr hProv,
        uint dwPublicVersion,
        uint dwEncodingType);

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern bool CryptCATClose(IntPtr hCatalog);

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern IntPtr CryptCATEnumerateMember(IntPtr hCatalog, IntPtr pPrevMember);

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern IntPtr CryptCATEnumerateAttr(IntPtr hCatalog, IntPtr pCatMember, IntPtr pPrevAttr);

    [DllImport("wintrust.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CryptCATAdminAcquireContext2(
        out IntPtr phCatAdmin,
        IntPtr pgSubsystem,
        string pwszHashAlgorithm,
        IntPtr pStrongHashPolicy,
        uint dwFlags);

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern bool CryptCATAdminReleaseContext(IntPtr hCatAdmin, uint dwFlags);

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern bool CryptCATAdminCalcHashFromFileHandle2(
        IntPtr hCatAdmin,
        IntPtr hFile,
        ref uint pcbHash,
        byte[] pbHash,
        uint dwFlags);

    [DllImport("wintrust.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern int WinVerifyTrust(
        IntPtr hwnd,
        ref Guid pgActionID,
        ref WINTRUST_DATA pWVTData);

    public static uint GetFileVerifyTrustStatus(string filePath)
    {
        if (string.IsNullOrEmpty(filePath) || !File.Exists(filePath))
        {
            return 0x800B0100; // TRUST_E_NOSIGNATURE
        }

        IntPtr widePathPtr = IntPtr.Zero;
        IntPtr fileInfoPtr = IntPtr.Zero;
        WINTRUST_DATA trustData = new WINTRUST_DATA();
        Guid actionGuid = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        bool needClose = false;

        try
        {
            widePathPtr = Marshal.StringToHGlobalUni(filePath);
            WINTRUST_FILE_INFO fileInfo = new WINTRUST_FILE_INFO
            {
                cbStruct = (uint)Marshal.SizeOf(typeof(WINTRUST_FILE_INFO)),
                pcwszFilePath = widePathPtr,
                hFile = IntPtr.Zero,
                pgKnownSubject = IntPtr.Zero
            };
            fileInfoPtr = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(WINTRUST_FILE_INFO)));
            Marshal.StructureToPtr(fileInfo, fileInfoPtr, false);

            trustData.cbStruct = (uint)Marshal.SizeOf(typeof(WINTRUST_DATA));
            trustData.dwUIChoice = WTD_UI_NONE;
            trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
            trustData.dwUnionChoice = WTD_CHOICE_FILE;
            trustData.pFile = fileInfoPtr;
            trustData.dwStateAction = WTD_STATEACTION_VERIFY;
            trustData.dwProvFlags = WTD_SAFER_FLAG;

            int status = WinVerifyTrust(IntPtr.Zero, ref actionGuid, ref trustData);
            needClose = true;
            return unchecked((uint)status);
        }
        finally
        {
            if (needClose)
            {
                trustData.dwStateAction = WTD_STATEACTION_CLOSE;
                WinVerifyTrust(IntPtr.Zero, ref actionGuid, ref trustData);
            }
            if (fileInfoPtr != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(fileInfoPtr);
            }
            if (widePathPtr != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(widePathPtr);
            }
        }
    }

    private static byte[] ComputeSipHash(IntPtr hCatAdmin, string filePath)
    {
        IntPtr hFile = CreateFileW(
            filePath,
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            IntPtr.Zero,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            IntPtr.Zero);

        if (hFile == new IntPtr(-1) || hFile == IntPtr.Zero)
        {
            return null;
        }

        try
        {
            uint hashSize = 0;
            CryptCATAdminCalcHashFromFileHandle2(hCatAdmin, hFile, ref hashSize, null, 0);
            if (hashSize == 0)
            {
                return null;
            }

            byte[] hash = new byte[hashSize];
            if (!CryptCATAdminCalcHashFromFileHandle2(hCatAdmin, hFile, ref hashSize, hash, 0))
            {
                return null;
            }

            if (hashSize != hash.Length)
            {
                Array.Resize(ref hash, (int)hashSize);
            }
            return hash;
        }
        finally
        {
            CloseHandle(hFile);
        }
    }

    private static bool BytesEqual(byte[] a, byte[] b)
    {
        if (a == null || b == null || a.Length != b.Length)
        {
            return false;
        }
        for (int i = 0; i < a.Length; ++i)
        {
            if (a[i] != b[i])
            {
                return false;
            }
        }
        return true;
    }

    public static LumaBridgeCatalogVerificationResult VerifyCatalogMembers(
        string catPath,
        string dllPath,
        string infPath,
        string expectedDllFileName,
        string expectedInfFileName)
    {
        var result = new LumaBridgeCatalogVerificationResult
        {
            DllCatalogHashVerified = false,
            InfCatalogHashVerified = false,
            AllMembersVerified = false,
            MemberCount = 0,
            Detail = string.Empty
        };

        if (!File.Exists(catPath) || !File.Exists(dllPath) || !File.Exists(infPath))
        {
            result.Detail = "Missing catalog, DLL, or INF file.";
            return result;
        }

        IntPtr hCatAdminSha256 = IntPtr.Zero;
        IntPtr hCatAdminSha1 = IntPtr.Zero;
        IntPtr hCat = new IntPtr(-1);

        try
        {
            if (!CryptCATAdminAcquireContext2(out hCatAdminSha256, IntPtr.Zero, "SHA256", IntPtr.Zero, 0) ||
                !CryptCATAdminAcquireContext2(out hCatAdminSha1, IntPtr.Zero, "SHA1", IntPtr.Zero, 0))
            {
                result.Detail = "CryptCATAdminAcquireContext2 failed.";
                return result;
            }

            byte[] expectedDllSha256 = ComputeSipHash(hCatAdminSha256, dllPath);
            byte[] expectedInfSha256 = ComputeSipHash(hCatAdminSha256, infPath);
            byte[] expectedDllSha1 = ComputeSipHash(hCatAdminSha1, dllPath);
            byte[] expectedInfSha1 = ComputeSipHash(hCatAdminSha1, infPath);

            if (expectedDllSha256 == null || expectedInfSha256 == null ||
                expectedDllSha1 == null || expectedInfSha1 == null)
            {
                result.Detail = "Failed to compute Authenticode SIP hashes for DLL or INF.";
                return result;
            }

            hCat = CryptCATOpen(catPath, CRYPTCAT_OPEN_EXISTING, IntPtr.Zero, 0, 0);
            if (hCat == new IntPtr(-1) || hCat == IntPtr.Zero)
            {
                result.Detail = "CryptCATOpen failed for catalog file.";
                return result;
            }

            string targetDllLower = expectedDllFileName.ToLowerInvariant();
            string targetInfLower = expectedInfFileName.ToLowerInvariant();
            bool foundDllSha256 = false;
            bool foundInfSha256 = false;
            bool dllDigestMismatch = false;
            bool infDigestMismatch = false;
            bool unexpectedMember = false;
            string firstFailureDetail = string.Empty;
            int memberCount = 0;

            IntPtr memberPtr = IntPtr.Zero;
            while ((memberPtr = CryptCATEnumerateMember(hCat, memberPtr)) != IntPtr.Zero)
            {
                ++memberCount;
                CRYPTCATMEMBER member = (CRYPTCATMEMBER)Marshal.PtrToStructure(memberPtr, typeof(CRYPTCATMEMBER));
                if (member.pIndirectData == IntPtr.Zero)
                {
                    result.Detail = "Catalog member has null pIndirectData.";
                    result.MemberCount = memberCount;
                    return result;
                }

                SIP_INDIRECT_DATA indirect = (SIP_INDIRECT_DATA)Marshal.PtrToStructure(
                    member.pIndirectData, typeof(SIP_INDIRECT_DATA));
                if (indirect.Digest.pbData == IntPtr.Zero ||
                    indirect.Digest.cbData == 0 ||
                    indirect.DigestAlgorithm.pszObjId == IntPtr.Zero)
                {
                    result.Detail = "Catalog member has invalid digest or algorithm OID.";
                    result.MemberCount = memberCount;
                    return result;
                }

                string oid = Marshal.PtrToStringAnsi(indirect.DigestAlgorithm.pszObjId);
                bool isSha256 = string.Equals(oid, OID_NIST_SHA256, StringComparison.Ordinal);
                bool isSha1 = string.Equals(oid, OID_OIWSEC_SHA1, StringComparison.Ordinal);
                if (!isSha256 && !isSha1)
                {
                    result.Detail = "Catalog member uses unsupported digest OID: " + oid;
                    result.MemberCount = memberCount;
                    return result;
                }

                byte[] memberDigest = new byte[indirect.Digest.cbData];
                Marshal.Copy(indirect.Digest.pbData, memberDigest, 0, (int)indirect.Digest.cbData);

                string memberFileName = string.Empty;
                IntPtr attrPtr = IntPtr.Zero;
                while ((attrPtr = CryptCATEnumerateAttr(hCat, memberPtr, attrPtr)) != IntPtr.Zero)
                {
                    CRYPTCATATTRIBUTE attr = (CRYPTCATATTRIBUTE)Marshal.PtrToStructure(attrPtr, typeof(CRYPTCATATTRIBUTE));
                    string attrTag = attr.pwszReferenceTag != IntPtr.Zero
                        ? Marshal.PtrToStringUni(attr.pwszReferenceTag)
                        : string.Empty;
                    if (string.Equals(attrTag, "File", StringComparison.OrdinalIgnoreCase) &&
                        attr.pbValue != IntPtr.Zero &&
                        attr.cbValue >= 2)
                    {
                        memberFileName = Marshal.PtrToStringUni(attr.pbValue, (int)(attr.cbValue / 2))
                            .TrimEnd('\0')
                            .ToLowerInvariant();
                        break;
                    }
                }

                string refTagLower = member.pwszReferenceTag != IntPtr.Zero
                    ? Marshal.PtrToStringUni(member.pwszReferenceTag).ToLowerInvariant()
                    : string.Empty;

                if (memberFileName == targetDllLower || refTagLower == targetDllLower)
                {
                    byte[] expected = isSha256 ? expectedDllSha256 : expectedDllSha1;
                    if (!BytesEqual(memberDigest, expected))
                    {
                        dllDigestMismatch = true;
                        if (string.IsNullOrEmpty(firstFailureDetail))
                        {
                            firstFailureDetail = "Catalog digest mismatch for DLL (" + oid + ").";
                        }
                    }
                    else if (isSha256)
                    {
                        foundDllSha256 = true;
                    }
                }
                else if (memberFileName == targetInfLower || refTagLower == targetInfLower)
                {
                    byte[] expected = isSha256 ? expectedInfSha256 : expectedInfSha1;
                    if (!BytesEqual(memberDigest, expected))
                    {
                        infDigestMismatch = true;
                        if (string.IsNullOrEmpty(firstFailureDetail))
                        {
                            firstFailureDetail = "Catalog digest mismatch for INF (" + oid + ").";
                        }
                    }
                    else if (isSha256)
                    {
                        foundInfSha256 = true;
                    }
                }
                else
                {
                    unexpectedMember = true;
                    if (string.IsNullOrEmpty(firstFailureDetail))
                    {
                        firstFailureDetail = "Unexpected catalog member: " +
                            (string.IsNullOrEmpty(memberFileName) ? refTagLower : memberFileName);
                    }
                }
            }

            result.MemberCount = memberCount;
            result.DllCatalogHashVerified = (foundDllSha256 && !dllDigestMismatch);
            result.InfCatalogHashVerified = (foundInfSha256 && !infDigestMismatch);
            result.AllMembersVerified = (memberCount >= 2 && result.DllCatalogHashVerified && result.InfCatalogHashVerified && !unexpectedMember);
            result.Detail = result.AllMembersVerified
                ? "Verified SHA-256 catalog SIP digests for DLL and INF."
                : (!string.IsNullOrEmpty(firstFailureDetail)
                    ? firstFailureDetail
                    : "Missing required SHA-256 catalog member for DLL or INF.");
            return result;
        }
        finally
        {
            if (hCat != new IntPtr(-1) && hCat != IntPtr.Zero)
            {
                CryptCATClose(hCat);
            }
            if (hCatAdminSha256 != IntPtr.Zero)
            {
                CryptCATAdminReleaseContext(hCatAdminSha256, 0);
            }
            if (hCatAdminSha1 != IntPtr.Zero)
            {
                CryptCATAdminReleaseContext(hCatAdminSha1, 0);
            }
        }
    }
}
'@
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

function Assert-LumaBridgeIsolatedStagingDirectory {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$StagingDir,

        [Parameter(Mandatory = $true)]
        [string]$SourcePackageDir
    )

    if ([string]::IsNullOrWhiteSpace($StagingDir)) {
        throw 'StagingDir cannot be empty.'
    }

    $normalizePath = {
        param([string]$InputPath)
        $full = [System.IO.Path]::GetFullPath($InputPath)
        return $full.TrimEnd('\', '/')
    }

    $normStaging = & $normalizePath $StagingDir
    $normSource = & $normalizePath $SourcePackageDir
    $normRepoRoot = & $normalizePath (Get-LumaBridgeRepoRoot)

    foreach ($forbiddenBase in @($normSource, $normRepoRoot)) {
        $stagingPrefix = if ($normStaging.EndsWith(':')) { $normStaging + '\' } else { $normStaging + '\' }
        $forbiddenPrefix = if ($forbiddenBase.EndsWith(':')) { $forbiddenBase + '\' } else { $forbiddenBase + '\' }

        if ($normStaging -ieq $forbiddenBase -or
            $normStaging.StartsWith($forbiddenPrefix, [StringComparison]::OrdinalIgnoreCase) -or
            $forbiddenBase.StartsWith($stagingPrefix, [StringComparison]::OrdinalIgnoreCase)) {
            throw ("Staging directory '{0}' must be strictly isolated outside repository/build path '{1}' to prevent overwriting build artifacts." -f $normStaging, $forbiddenBase)
        }
    }

    return $normStaging
}

function Get-LumaBridgeWdkToolPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet(
            'signtool.exe',
            'devcon.exe',
            'Inf2Cat.exe',
            'InfVerif.exe',
            'tracefmt.exe',
            'tracepdb.exe',
            'tracelog.exe',
            'symchk.exe',
            'windbg.exe',
            'cdb.exe',
            'kd.exe',
            'wdfverifier.exe',
            'xperf.exe')]
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
        'wdfverifier.exe' {
            @(
                (Join-Path -Path $kitsRoot -ChildPath 'Tools\10.0.28000.0\x64\wdfverifier.exe')
            )
        }
        'InfVerif.exe' {
            @(
                (Join-Path -Path $kitsRoot -ChildPath 'Tools\10.0.28000.0\x64\infverif.exe')
            )
        }
        'Inf2Cat.exe' {
            @(
                (Join-Path -Path $kitsRoot -ChildPath 'bin\10.0.28000.0\x86\Inf2Cat.exe'),
                (Join-Path -Path $kitsRoot -ChildPath 'bin\10.0.28000.0\x64\Inf2Cat.exe')
            )
        }
        { $_ -in @('tracefmt.exe', 'tracepdb.exe', 'tracelog.exe') } {
            @(
                (Join-Path -Path $kitsRoot -ChildPath ("bin\10.0.28000.0\x64\{0}" -f $ToolName)),
                (Join-Path -Path $kitsRoot -ChildPath ("bin\10.0.26100.0\x64\{0}" -f $ToolName))
            )
        }
        { $_ -in @('symchk.exe', 'windbg.exe', 'cdb.exe', 'kd.exe') } {
            @(
                (Join-Path -Path $kitsRoot -ChildPath ("Debuggers\x64\{0}" -f $ToolName))
            )
        }
        'xperf.exe' {
            @(
                (Join-Path -Path $kitsRoot -ChildPath 'Windows Performance Toolkit\xperf.exe')
            )
        }
    }

    foreach ($candidate in $preferredPaths) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            return $candidate
        }
    }

    $searchRoot = switch ($ToolName) {
        { $_ -in @('devcon.exe', 'wdfverifier.exe', 'InfVerif.exe') } { Join-Path -Path $kitsRoot -ChildPath 'Tools'; break }
        { $_ -in @('symchk.exe', 'windbg.exe', 'cdb.exe', 'kd.exe') } { Join-Path -Path $kitsRoot -ChildPath 'Debuggers'; break }
        'xperf.exe' { Join-Path -Path $kitsRoot -ChildPath 'Windows Performance Toolkit'; break }
        default { Join-Path -Path $kitsRoot -ChildPath 'bin'; break }
    }

    if (-not (Test-Path -LiteralPath $searchRoot)) {
        return $null
    }

    $archPattern = switch ($ToolName) {
        'Inf2Cat.exe' { '\\(x64|x86)\\'; break }
        'xperf.exe' { '.*'; break }
        default { '\\x64\\'; break }
    }

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

    $prevEap = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $outputLines = & $FilePath @Arguments 2>&1
        $exitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $prevEap
    }
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

function Invoke-LumaBridgeHostProcess {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ExecutablePath,

        [string[]]$Arguments = @(),

        [ValidateRange(500, 600000)]
        [int]$HardTimeoutMs = 30000,

        [switch]$DryRun
    )

    $escapedArgs = ($Arguments | ForEach-Object {
        if ($_ -match '[\s"]') {
            '"' + ($_ -replace '"', '\"') + '"'
        }
        else {
            $_
        }
    }) -join ' '

    if ($DryRun) {
        Write-Host ("[DRY-RUN] Would run host process (timeout={0}ms): `"{1}`" {2}" -f $HardTimeoutMs, $ExecutablePath, $escapedArgs) -ForegroundColor Cyan
        return [pscustomobject]@{
            ExitCode   = 0
            TimedOut   = $false
            Output     = @()
            StdErr     = @()
            DryRun     = $true
        }
    }

    if (-not (Test-Path -LiteralPath $ExecutablePath -PathType Leaf)) {
        throw ("Host consumer executable not found: {0}" -f $ExecutablePath)
    }

    $psi = [System.Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = $ExecutablePath
    $psi.Arguments = $escapedArgs
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true

    $proc = [System.Diagnostics.Process]::new()
    $proc.StartInfo = $psi
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

    try {
        if (-not $proc.Start()) {
            throw ("Failed to start host consumer executable: {0}" -f $ExecutablePath)
        }

        $stdoutTask = $proc.StandardOutput.ReadToEndAsync()
        $stderrTask = $proc.StandardError.ReadToEndAsync()

        $exited = $proc.WaitForExit($HardTimeoutMs)
        $timedOut = $false
        if (-not $exited) {
            $timedOut = $true
            try { $proc.Kill() } catch { }
            try { $null = $proc.WaitForExit(3000) } catch { }
        }
        else {
            # Ensure native process handle and stdio handles are completely drained.
            $proc.WaitForExit()
        }
        $stopwatch.Stop()

        $rawStdout = ''
        $rawStderr = ''
        try {
            if ($stdoutTask.Wait(3000)) {
                $rawStdout = $stdoutTask.Result
            }
        }
        catch { }
        try {
            if ($stderrTask.Wait(3000)) {
                $rawStderr = $stderrTask.Result
            }
        }
        catch { }

        $stdoutLines = if ([string]::IsNullOrEmpty($rawStdout)) {
            @()
        }
        else {
            @($rawStdout -split "\r?\n" | Where-Object { $_ -ne '' })
        }
        $stderrLines = if ([string]::IsNullOrEmpty($rawStderr)) {
            @()
        }
        else {
            @($rawStderr -split "\r?\n" | Where-Object { $_ -ne '' })
        }

        $exitCode = if ($timedOut) { -1 } else { [int]$proc.ExitCode }
        return [pscustomobject]@{
            ExitCode   = $exitCode
            TimedOut   = $timedOut
            DurationMs = [Math]::Round($stopwatch.Elapsed.TotalMilliseconds, 2)
            Output     = $stdoutLines
            StdErr     = $stderrLines
            RawStdOut  = $rawStdout
            RawStdErr  = $rawStderr
            DryRun     = $false
        }
    }
    finally {
        if ($null -ne $proc) {
            try {
                if (-not $proc.HasExited) {
                    $proc.Kill()
                }
            }
            catch { }
            $proc.Dispose()
        }
    }
}

function Get-LumaBridgeDeviceParametersRegistryPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$InstanceId
    )

    return ("HKLM:\SYSTEM\CurrentControlSet\Enum\{0}\Device Parameters" -f $InstanceId)
}

function Get-LumaBridgeDeviceEnableVirtualMonitor {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$DeviceParametersPath
    )

    if (-not (Test-Path -LiteralPath $DeviceParametersPath)) {
        return $null
    }

    $regProps = Get-ItemProperty -LiteralPath $DeviceParametersPath -Name $script:LumaBridgeDriverConstants.RegistryValueEnableMon -ErrorAction SilentlyContinue
    if ($null -ne $regProps) {
        return $regProps.($script:LumaBridgeDriverConstants.RegistryValueEnableMon)
    }

    return $null
}

function Set-LumaBridgeDeviceEnableVirtualMonitor {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$DeviceParametersPath,

        [Parameter(Mandatory = $true)]
        [ValidateSet(0, 1)]
        [int]$Value
    )

    if (-not (Test-Path -LiteralPath $DeviceParametersPath)) {
        New-Item -Path $DeviceParametersPath -Force | Out-Null
    }

    New-ItemProperty -LiteralPath $DeviceParametersPath -Name $script:LumaBridgeDriverConstants.RegistryValueEnableMon -PropertyType DWord -Value $Value -Force | Out-Null
}

function Get-LumaBridgeDeviceEnableFrameExtraction {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$DeviceParametersPath
    )

    if (-not (Test-Path -LiteralPath $DeviceParametersPath)) {
        return $null
    }

    $propName = $script:LumaBridgeDriverConstants.RegistryValueEnableExt
    $regProps = Get-ItemProperty -LiteralPath $DeviceParametersPath -Name $propName -ErrorAction SilentlyContinue
    if ($null -ne $regProps -and ($regProps.PSObject.Properties.Name -contains $propName)) {
        return $regProps.$propName
    }

    return $null
}

function Set-LumaBridgeDeviceEnableFrameExtraction {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$DeviceParametersPath,

        [Parameter(Mandatory = $true)]
        [ValidateSet(0, 1)]
        [int]$Value
    )

    if (-not (Test-Path -LiteralPath $DeviceParametersPath)) {
        New-Item -Path $DeviceParametersPath -Force | Out-Null
    }

    New-ItemProperty -LiteralPath $DeviceParametersPath -Name $script:LumaBridgeDriverConstants.RegistryValueEnableExt -PropertyType DWord -Value $Value -Force | Out-Null
}

function Get-LumaBridgeDeviceEnableGpuSharedTransport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$DeviceParametersPath
    )

    if (-not (Test-Path -LiteralPath $DeviceParametersPath)) {
        return $null
    }

    $propName = $script:LumaBridgeDriverConstants.RegistryValueEnableGpuTrans
    $regProps = Get-ItemProperty -LiteralPath $DeviceParametersPath -Name $propName -ErrorAction SilentlyContinue
    if ($null -ne $regProps -and ($regProps.PSObject.Properties.Name -contains $propName)) {
        return $regProps.$propName
    }

    return $null
}

function Set-LumaBridgeDeviceEnableGpuSharedTransport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$DeviceParametersPath,

        [ValidateSet(0, 1)]
        [int]$Value = 1,

        [switch]$Clear
    )

    $propName = $script:LumaBridgeDriverConstants.RegistryValueEnableGpuTrans
    if ($Clear) {
        if (Test-Path -LiteralPath $DeviceParametersPath) {
            Remove-ItemProperty -LiteralPath $DeviceParametersPath -Name $propName -ErrorAction SilentlyContinue
        }
        return
    }

    if (-not (Test-Path -LiteralPath $DeviceParametersPath)) {
        New-Item -Path $DeviceParametersPath -Force | Out-Null
    }

    New-ItemProperty -LiteralPath $DeviceParametersPath -Name $propName -PropertyType DWord -Value $Value -Force | Out-Null
}

function Get-LumaBridgeDeviceAuthorizedHostUserSid {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$DeviceParametersPath
    )

    if (-not (Test-Path -LiteralPath $DeviceParametersPath)) {
        return $null
    }

    $propName = $script:LumaBridgeDriverConstants.RegistryValueAuthorizedSid
    $regProps = Get-ItemProperty -LiteralPath $DeviceParametersPath -Name $propName -ErrorAction SilentlyContinue
    if ($null -ne $regProps -and ($regProps.PSObject.Properties.Name -contains $propName)) {
        $raw = [string]$regProps.$propName
        if (-not [string]::IsNullOrWhiteSpace($raw)) {
            return $raw.Trim()
        }
    }

    return $null
}

function Set-LumaBridgeDeviceAuthorizedHostUserSid {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$DeviceParametersPath,

        [string]$SidString,

        [switch]$Clear
    )

    $propName = $script:LumaBridgeDriverConstants.RegistryValueAuthorizedSid
    if ($Clear -or [string]::IsNullOrWhiteSpace($SidString)) {
        if (Test-Path -LiteralPath $DeviceParametersPath) {
            Remove-ItemProperty -LiteralPath $DeviceParametersPath -Name $propName -ErrorAction SilentlyContinue
        }
        return
    }

    $trimmedSid = $SidString.Trim()
    if ($trimmedSid -notmatch '^S-1-[0-9-]+$') {
        throw ("Invalid Windows SID format '{0}' for AuthorizedHostUserSid." -f $SidString)
    }

    if (-not (Test-Path -LiteralPath $DeviceParametersPath)) {
        New-Item -Path $DeviceParametersPath -Force | Out-Null
    }

    New-ItemProperty -LiteralPath $DeviceParametersPath -Name $propName -PropertyType String -Value $trimmedSid -Force | Out-Null
}

function Get-LumaBridgeDevicePropertyData {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$InstanceId,

        [Parameter(Mandatory = $true)]
        [string]$KeyName
    )

    $prop = Get-PnpDeviceProperty -InstanceId $InstanceId -KeyName $KeyName -ErrorAction SilentlyContinue
    if ($null -eq $prop -or -not ($prop.PSObject.Properties.Name -contains 'Data')) {
        return $null
    }

    return $prop.Data
}

function Format-LumaBridgeNtStatusHex {
    [CmdletBinding()]
    param(
        $StatusValue
    )

    if ($null -eq $StatusValue) {
        return $null
    }

    try {
        if ($StatusValue -is [string]) {
            if ([string]::IsNullOrWhiteSpace($StatusValue)) {
                return $null
            }
            if ($StatusValue -match '^\s*0[xX]([0-9A-Fa-f]{1,8})\s*$') {
                $parsed = [Convert]::ToUInt32($matches[1], 16)
                return ('0x{0:X8}' -f $parsed)
            }
        }

        $numeric64 = [int64]$StatusValue
        $u32 = [uint32]($numeric64 -band 0xFFFFFFFFL)
        return ('0x{0:X8}' -f $u32)
    }
    catch {
        return $null
    }
}

function Get-LumaBridgeDeviceStartupDiagnostics {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$DeviceParametersPath
    )

    if ([string]::IsNullOrWhiteSpace($DeviceParametersPath)) {
        return $null
    }

    $diagNames = @(
        'DiagLastStage',
        'DiagLastSuccessfulStage',
        'DiagLastStatus',
        'DiagLastErrorStage',
        'DiagLastErrorStatus',
        'DiagIddCxVersion',
        'DiagHostProcessId',
        'DiagDllAttachCount',
        'DiagBuildStage',
        'DiagTraceLoggingRegistered',
        'DiagTraceLoggingStatus'
    )

    $candidatePaths = @(
        $DeviceParametersPath,
        ("{0}\LumaBridgeIddDriver" -f $DeviceParametersPath.TrimEnd('\'))
    )

    $props = $null
    $resolvedPath = $null
    foreach ($candidatePath in $candidatePaths) {
        $exists = $false
        try {
            $exists = Test-Path -LiteralPath $candidatePath -ErrorAction SilentlyContinue
        }
        catch {
            $exists = $false
        }

        if (-not $exists) {
            continue
        }

        $candidateProps = $null
        try {
            $candidateProps = Get-ItemProperty -LiteralPath $candidatePath -ErrorAction Stop
        }
        catch {
            $candidateProps = $null
        }

        if ($null -eq $candidateProps) {
            continue
        }

        $hasAny = $false
        foreach ($name in $diagNames) {
            if ($candidateProps.PSObject.Properties.Name -contains $name) {
                $hasAny = $true
                break
            }
        }
        if ($hasAny) {
            $props = $candidateProps
            $resolvedPath = $candidatePath
            break
        }
    }

    if ($null -eq $props) {
        return $null
    }

    $getProp = {
        param([string]$PropName)
        if ($props.PSObject.Properties.Name -contains $PropName) {
            return $props.$PropName
        }
        return $null
    }

    $lastStatusRaw = & $getProp 'DiagLastStatus'
    $lastErrorStatusRaw = & $getProp 'DiagLastErrorStatus'
    $iddCxVersionRaw = & $getProp 'DiagIddCxVersion'
    $tlStatusRaw = & $getProp 'DiagTraceLoggingStatus'

    return [pscustomobject]@{
        RegistryPath           = $resolvedPath
        LastStage              = & $getProp 'DiagLastStage'
        LastSuccessfulStage    = & $getProp 'DiagLastSuccessfulStage'
        LastStatus             = $lastStatusRaw
        LastStatusHex          = Format-LumaBridgeNtStatusHex -StatusValue $lastStatusRaw
        LastErrorStage         = & $getProp 'DiagLastErrorStage'
        LastErrorStatus        = $lastErrorStatusRaw
        LastErrorStatusHex     = Format-LumaBridgeNtStatusHex -StatusValue $lastErrorStatusRaw
        IddCxRuntimeVersion    = $iddCxVersionRaw
        IddCxRuntimeVerHex     = Format-LumaBridgeNtStatusHex -StatusValue $iddCxVersionRaw
        HostProcessId          = & $getProp 'DiagHostProcessId'
        DllAttachCount         = & $getProp 'DiagDllAttachCount'
        BuildStage             = & $getProp 'DiagBuildStage'
        TraceLoggingRegistered = & $getProp 'DiagTraceLoggingRegistered'
        TraceLoggingStatus     = $tlStatusRaw
        TraceLoggingStatusHex  = Format-LumaBridgeNtStatusHex -StatusValue $tlStatusRaw
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
        $allDevices = @(Get-PnpDevice -ErrorAction SilentlyContinue)
        $candidates = if ($allDevices.Count -le 50) {
            $allDevices
        }
        else {
            @($allDevices | Where-Object {
                (@($_.HardwareID) -contains $HardwareId) -or
                ($_.InstanceId -like 'ROOT\DISPLAY\*') -or
                ($_.Class -eq 'Display') -or
                (($null -eq $_.HardwareID -or @($_.HardwareID).Count -eq 0) -and ($_.InstanceId -like 'ROOT\*'))
            })
        }

        foreach ($dev in $candidates) {
            if ([string]::IsNullOrWhiteSpace($dev.InstanceId)) {
                continue
            }

            $hwIdData = Get-LumaBridgeDevicePropertyData -InstanceId $dev.InstanceId -KeyName 'DEVPKEY_Device_HardwareIds'
            $effectiveHardwareIds = if ($null -ne $hwIdData) {
                @($hwIdData | ForEach-Object { $_.ToString() } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
            }
            else {
                @()
            }

            if (@($effectiveHardwareIds | Where-Object { $_ -ieq $HardwareId }).Count -eq 0) {
                continue
            }

            if ($seenIds.Add($dev.InstanceId)) {
                $probCode = Get-LumaBridgeDevicePropertyData -InstanceId $dev.InstanceId -KeyName 'DEVPKEY_Device_ProblemCode'
                $probStatus = Get-LumaBridgeDevicePropertyData -InstanceId $dev.InstanceId -KeyName 'DEVPKEY_Device_ProblemStatus'
                $probStatusHex = Format-LumaBridgeNtStatusHex -StatusValue $probStatus
                $driverInfPath = Get-LumaBridgeDevicePropertyData -InstanceId $dev.InstanceId -KeyName 'DEVPKEY_Device_DriverInfPath'
                $driverProvider = Get-LumaBridgeDevicePropertyData -InstanceId $dev.InstanceId -KeyName 'DEVPKEY_Device_DriverProvider'
                $driverVersion = Get-LumaBridgeDevicePropertyData -InstanceId $dev.InstanceId -KeyName 'DEVPKEY_Device_DriverVersion'
                $driverService = Get-LumaBridgeDevicePropertyData -InstanceId $dev.InstanceId -KeyName 'DEVPKEY_Device_Service'
                $configurationId = Get-LumaBridgeDevicePropertyData -InstanceId $dev.InstanceId -KeyName 'DEVPKEY_Device_ConfigurationId'
                $upperFiltersData = Get-LumaBridgeDevicePropertyData -InstanceId $dev.InstanceId -KeyName 'DEVPKEY_Device_UpperFilters'
                $lowerFiltersData = Get-LumaBridgeDevicePropertyData -InstanceId $dev.InstanceId -KeyName 'DEVPKEY_Device_LowerFilters'

                $upperFilters = if ($null -ne $upperFiltersData) {
                    @($upperFiltersData | ForEach-Object { $_.ToString() } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
                }
                else {
                    @()
                }
                $lowerFilters = if ($null -ne $lowerFiltersData) {
                    @($lowerFiltersData | ForEach-Object { $_.ToString() } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
                }
                else {
                    @()
                }

                $regParamsPath = Get-LumaBridgeDeviceParametersRegistryPath -InstanceId $dev.InstanceId
                $enableVal = Get-LumaBridgeDeviceEnableVirtualMonitor -DeviceParametersPath $regParamsPath
                $enableExtractionVal = Get-LumaBridgeDeviceEnableFrameExtraction -DeviceParametersPath $regParamsPath
                $enableGpuTransportVal = Get-LumaBridgeDeviceEnableGpuSharedTransport -DeviceParametersPath $regParamsPath
                $authorizedSidVal = Get-LumaBridgeDeviceAuthorizedHostUserSid -DeviceParametersPath $regParamsPath
                $startupDiag = Get-LumaBridgeDeviceStartupDiagnostics -DeviceParametersPath $regParamsPath

                $results.Add([pscustomobject]@{
                    InstanceId               = $dev.InstanceId
                    FriendlyName             = $dev.FriendlyName
                    Status                   = $dev.Status
                    ProblemCode              = $probCode
                    ProblemStatus            = $probStatus
                    ProblemStatusHex         = $probStatusHex
                    Present                  = [bool]$dev.Present
                    HardwareIds              = @($effectiveHardwareIds)
                    DriverInfPath            = $driverInfPath
                    DriverProvider           = $driverProvider
                    DriverVersion            = $driverVersion
                    DriverService            = $driverService
                    UpperFilters             = @($upperFilters)
                    LowerFilters             = @($lowerFilters)
                    ConfigurationId          = $configurationId
                    DeviceParametersPath     = $regParamsPath
                    EnableVirtualMonitor     = $enableVal
                    EnableFrameExtraction    = $enableExtractionVal
                    EnableGpuSharedTransport = $enableGpuTransportVal
                    AuthorizedHostUserSid    = $authorizedSidVal
                    StartupDiagnostics       = $startupDiag
                })
            }
        }
    }
    elseif (Get-Command -Name 'Get-CimInstance' -ErrorAction SilentlyContinue) {
        $entities = Get-CimInstance -ClassName Win32_PnPEntity -ErrorAction SilentlyContinue | Where-Object {
            @($_.HardwareID | Where-Object { $_ -ieq $HardwareId }).Count -gt 0
        }

        foreach ($ent in $entities) {
            if ($seenIds.Add($ent.PNPDeviceID)) {
                $regParamsPath = Get-LumaBridgeDeviceParametersRegistryPath -InstanceId $ent.PNPDeviceID
                $enableVal = Get-LumaBridgeDeviceEnableVirtualMonitor -DeviceParametersPath $regParamsPath
                $enableExtractionVal = Get-LumaBridgeDeviceEnableFrameExtraction -DeviceParametersPath $regParamsPath
                $enableGpuTransportVal = Get-LumaBridgeDeviceEnableGpuSharedTransport -DeviceParametersPath $regParamsPath
                $authorizedSidVal = Get-LumaBridgeDeviceAuthorizedHostUserSid -DeviceParametersPath $regParamsPath
                $startupDiag = Get-LumaBridgeDeviceStartupDiagnostics -DeviceParametersPath $regParamsPath

                $results.Add([pscustomobject]@{
                    InstanceId               = $ent.PNPDeviceID
                    FriendlyName             = $ent.Name
                    Status                   = $ent.Status
                    ProblemCode              = $ent.ConfigManagerErrorCode
                    ProblemStatus            = $null
                    ProblemStatusHex         = $null
                    Present                  = ($ent.ConfigManagerErrorCode -eq 0)
                    HardwareIds              = @($ent.HardwareID)
                    DriverInfPath            = $null
                    DriverProvider           = $null
                    DriverVersion            = $null
                    DriverService            = $ent.Service
                    UpperFilters             = @()
                    LowerFilters             = @()
                    ConfigurationId          = $null
                    DeviceParametersPath     = $regParamsPath
                    EnableVirtualMonitor     = $enableVal
                    EnableFrameExtraction    = $enableExtractionVal
                    EnableGpuSharedTransport = $enableGpuTransportVal
                    AuthorizedHostUserSid    = $authorizedSidVal
                    StartupDiagnostics       = $startupDiag
                })
            }
        }
    }

    return @($results.ToArray())
}

function Get-LumaBridgeInfDriverVerMetadata {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$InfPath
    )

    if (-not (Test-Path -LiteralPath $InfPath -PathType Leaf)) {
        return $null
    }

    $inVersionSection = $false
    foreach ($rawLine in Get-Content -LiteralPath $InfPath) {
        $line = ($rawLine -replace ';.*$', '').Trim()
        if ([string]::IsNullOrWhiteSpace($line)) {
            continue
        }

        if ($line -match '^\[(?<Section>[^\]]+)\]$') {
            $inVersionSection = ($matches['Section'].Trim() -ieq 'Version')
            continue
        }

        if ($inVersionSection -and $line -match '^(?i)DriverVer\s*=\s*(?<Raw>(?<Date>[^,]+),\s*(?<Version>[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+))\s*$') {
            return [pscustomobject]@{
                Raw     = $matches['Raw'].Trim()
                Date    = $matches['Date'].Trim()
                Version = $matches['Version'].Trim()
            }
        }
    }

    return $null
}

function Get-LumaBridgeInfDriverVersion {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$InfPath
    )

    $meta = Get-LumaBridgeInfDriverVerMetadata -InfPath $InfPath
    if ($null -ne $meta) {
        return $meta.Version
    }

    return $null
}

function Test-LumaBridgeDeviceDriverBinding {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [psobject]$Instance,

        [object[]]$DriverStorePackages = @(),

        [string]$ExpectedInfPath,

        [string]$HardwareId = $script:LumaBridgeDriverConstants.HardwareId
    )

    $reasons = New-Object System.Collections.Generic.List[string]
    $expectedVersion = $null
    $constants = $script:LumaBridgeDriverConstants
    $problemCode = $null
    $problemStatusHex = $null

    if ($null -eq $Instance) {
        $reasons.Add('Device instance is null.')
    }
    else {
        $problemCode = if ($Instance.PSObject.Properties.Name -contains 'ProblemCode') { $Instance.ProblemCode } else { $null }
        $rawProbStatusHex = if ($Instance.PSObject.Properties.Name -contains 'ProblemStatusHex') { $Instance.ProblemStatusHex } else { $null }
        $rawProbStatus = if ($Instance.PSObject.Properties.Name -contains 'ProblemStatus') { $Instance.ProblemStatus } else { $null }
        $problemStatusHex = if (-not [string]::IsNullOrWhiteSpace([string]$rawProbStatusHex)) {
            [string]$rawProbStatusHex
        }
        else {
            Format-LumaBridgeNtStatusHex -StatusValue $rawProbStatus
        }

        if (-not $Instance.Present) {
            $reasons.Add("Device is not marked Present.")
        }
        if ($Instance.Status -ine 'OK') {
            $reasons.Add(("Device status is '{0}' instead of 'OK'." -f $Instance.Status))
        }
        if ($null -ne $problemCode -and [int]$problemCode -ne 0) {
            $probMsg = "Device ProblemCode is {0} (expected 0)" -f $problemCode
            if (-not [string]::IsNullOrWhiteSpace($problemStatusHex)) {
                $probMsg += ("; ProblemStatus is {0}" -f $problemStatusHex)
            }
            $reasons.Add(($probMsg + '.'))
        }
        if (@($Instance.HardwareIds | Where-Object { $_ -ieq $HardwareId }).Count -eq 0) {
            $reasons.Add(("Device DEVPKEY_Device_HardwareIds does not contain '{0}'." -f $HardwareId))
        }
        if ([string]::IsNullOrWhiteSpace($Instance.DriverInfPath)) {
            $reasons.Add('DEVPKEY_Device_DriverInfPath is empty.')
        }
        if ($Instance.DriverProvider -ne $constants.DriverProviderName) {
            $reasons.Add(("Bound driver provider is '{0}' instead of '{1}'." -f $Instance.DriverProvider, $constants.DriverProviderName))
        }
        if (-not [string]::IsNullOrWhiteSpace($Instance.DriverInfPath) -and $DriverStorePackages.Count -gt 0) {
            $matchingPkg = @($DriverStorePackages | Where-Object { $_.PublishedName -ieq $Instance.DriverInfPath })
            if ($matchingPkg.Count -eq 0) {
                $reasons.Add(("Bound INF '{0}' does not match any LumaBridge package in Driver Store." -f $Instance.DriverInfPath))
            }
        }
        if (-not [string]::IsNullOrWhiteSpace($ExpectedInfPath) -and (Test-Path -LiteralPath $ExpectedInfPath -PathType Leaf)) {
            $expectedVersion = Get-LumaBridgeInfDriverVersion -InfPath $ExpectedInfPath
            if (-not [string]::IsNullOrWhiteSpace($expectedVersion) -and ($Instance.DriverVersion -ne $expectedVersion)) {
                $reasons.Add(("Bound driver version '{0}' does not match expected INF DriverVer '{1}'." -f $Instance.DriverVersion, $expectedVersion))
            }
        }
    }

    return [pscustomobject]@{
        IsBound               = ($reasons.Count -eq 0)
        Reasons               = @($reasons.ToArray())
        ExpectedDriverVersion = $expectedVersion
        BoundDriverInfPath    = if ($null -ne $Instance) { $Instance.DriverInfPath } else { $null }
        BoundDriverProvider   = if ($null -ne $Instance) { $Instance.DriverProvider } else { $null }
        BoundDriverVersion    = if ($null -ne $Instance) { $Instance.DriverVersion } else { $null }
        ProblemCode           = $problemCode
        ProblemStatusHex      = $problemStatusHex
    }
}

function Invoke-LumaBridgePnpUtilEnumDriversXml {
    [CmdletBinding()]
    param()

    $prevEap = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $lines = & pnputil.exe /enum-drivers /format xml 2>&1
        $exitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $prevEap
    }

    return [pscustomobject]@{
        ExitCode = $exitCode
        Output   = @($lines | ForEach-Object { $_.ToString() })
    }
}

function Get-LumaBridgeDriverStorePackages {
    [CmdletBinding()]
    param(
        [string]$InfFilter = $script:LumaBridgeDriverConstants.InfFileName
    )

    $enumResult = Invoke-LumaBridgePnpUtilEnumDriversXml
    if ($null -eq $enumResult -or $enumResult.ExitCode -ne 0) {
        return @()
    }

    $rawText = ($enumResult.Output -join [Environment]::NewLine).Trim()
    if ([string]::IsNullOrWhiteSpace($rawText)) {
        return @()
    }

    $xmlStartIdx = $rawText.IndexOf('<')
    if ($xmlStartIdx -gt 0) {
        $rawText = $rawText.Substring($xmlStartIdx)
    }

    try {
        [xml]$xmlDoc = $rawText
    }
    catch {
        throw ("Failed to parse structured XML output from pnputil /enum-drivers /format xml: {0}" -f $_.Exception.Message)
    }

    $constants = $script:LumaBridgeDriverConstants
    $entries = New-Object System.Collections.Generic.List[object]
    $driverNodes = @($xmlDoc.SelectNodes('//Driver'))

    foreach ($node in $driverNodes) {
        if ($null -eq $node) {
            continue
        }

        $publishedName = $node.GetAttribute('DriverName')
        if ([string]::IsNullOrWhiteSpace($publishedName)) {
            continue
        }

        $originalName = if ($null -ne $node.SelectSingleNode('OriginalName')) { $node.SelectSingleNode('OriginalName').InnerText.Trim() } else { '' }
        $providerName = if ($null -ne $node.SelectSingleNode('ProviderName')) { $node.SelectSingleNode('ProviderName').InnerText.Trim() } else { '' }
        $className = if ($null -ne $node.SelectSingleNode('ClassName')) { $node.SelectSingleNode('ClassName').InnerText.Trim() } else { '' }
        $classGuid = if ($null -ne $node.SelectSingleNode('ClassGuid')) { $node.SelectSingleNode('ClassGuid').InnerText.Trim() } else { '' }
        $driverVersion = if ($null -ne $node.SelectSingleNode('DriverVersion')) { $node.SelectSingleNode('DriverVersion').InnerText.Trim() } else { '' }
        $signerName = if ($null -ne $node.SelectSingleNode('SignerName')) { $node.SelectSingleNode('SignerName').InnerText.Trim() } else { '' }

        $matchesInf = ($originalName -ieq $InfFilter)
        $matchesProviderAndClass = ($providerName -eq $constants.DriverProviderName) -and (
            ($classGuid -ieq $constants.DisplayClassGuid) -or
            [string]::IsNullOrWhiteSpace($classGuid)
        )

        if ($matchesInf -or $matchesProviderAndClass) {
            $entries.Add([pscustomobject]@{
                PublishedName = $publishedName
                OriginalName  = $originalName
                ProviderName  = $providerName
                ClassName     = $className
                ClassGuid     = $classGuid
                DriverVersion = $driverVersion
                SignerName    = $signerName
            })
        }
    }

    return @($entries.ToArray())
}

function Test-LumaBridgeCatalogFileHashes {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$CatPath,

        [Parameter(Mandatory = $true)]
        [string]$DllPath,

        [Parameter(Mandatory = $true)]
        [string]$InfPath
    )

    $constants = $script:LumaBridgeDriverConstants
    if (-not (Test-Path -LiteralPath $CatPath -PathType Leaf) -or
        -not (Test-Path -LiteralPath $DllPath -PathType Leaf) -or
        -not (Test-Path -LiteralPath $InfPath -PathType Leaf)) {
        return [pscustomobject]@{
            DllCatalogHashVerified = $false
            InfCatalogHashVerified = $false
            AllMembersVerified     = $false
            MemberCount            = 0
            Detail                 = 'Missing catalog, DLL, or INF file.'
        }
    }

    $nativeResult = [LumaBridgeNativeCatalogVerifier]::VerifyCatalogMembers(
        $CatPath,
        $DllPath,
        $InfPath,
        $constants.DllFileName,
        $constants.InfFileName
    )

    return [pscustomobject]@{
        DllCatalogHashVerified = [bool]$nativeResult.DllCatalogHashVerified
        InfCatalogHashVerified = [bool]$nativeResult.InfCatalogHashVerified
        AllMembersVerified     = [bool]$nativeResult.AllMembersVerified
        MemberCount            = [int]$nativeResult.MemberCount
        Detail                 = [string]$nativeResult.Detail
    }
}

function Get-LumaBridgeWinVerifyTrustStatus {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath
    )

    return [uint32]([LumaBridgeNativeCatalogVerifier]::GetFileVerifyTrustStatus($FilePath))
}

function Test-LumaBridgeCatalogCmsSignature {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$CatPath
    )

    if (-not (Test-Path -LiteralPath $CatPath -PathType Leaf)) {
        return [pscustomobject]@{
            HasSignature              = $false
            IsCryptographicallyIntact = $false
            SignerThumbprints         = @()
            Error                     = 'Catalog file missing.'
        }
    }

    try {
        $bytes = [System.IO.File]::ReadAllBytes($CatPath)
        $cms = New-Object System.Security.Cryptography.Pkcs.SignedCms
        $cms.Decode($bytes)

        $signerCount = $cms.SignerInfos.Count
        if ($signerCount -eq 0) {
            return [pscustomobject]@{
                HasSignature              = $false
                IsCryptographicallyIntact = $false
                SignerThumbprints         = @()
                Error                     = 'Catalog has no PKCS#7 signers.'
            }
        }

        $cms.CheckSignature($true)
        $thumbprints = @(foreach ($si in $cms.SignerInfos) {
            if ($null -ne $si.Certificate) {
                $si.Certificate.Thumbprint
            }
        })

        return [pscustomobject]@{
            HasSignature              = $true
            IsCryptographicallyIntact = ($thumbprints.Count -ge 1)
            SignerThumbprints         = @($thumbprints)
            Error                     = ''
        }
    }
    catch {
        return [pscustomobject]@{
            HasSignature              = $false
            IsCryptographicallyIntact = $false
            SignerThumbprints         = @()
            Error                     = $_.Exception.Message
        }
    }
}

function Invoke-LumaBridgeSigntoolCatalogVerify {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SigntoolPath,

        [Parameter(Mandatory = $true)]
        [string]$CatPath,

        [Parameter(Mandatory = $true)]
        [string]$TargetFilePath
    )

    $prevEap = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $outputLines = & $SigntoolPath verify /pa /c $CatPath $TargetFilePath 2>&1
        $exitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $prevEap
    }
    $outputText = ($outputLines | ForEach-Object { $_.ToString() }) -join [Environment]::NewLine

    return [pscustomobject]@{
        ExitCode = $exitCode
        Verified = ($exitCode -eq 0)
        Output   = $outputText
    }
}

function Test-LumaBridgePackageArtifacts {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$PackageDirectory,

        [switch]$RequireValidSignature,

        [switch]$AllowUntrustedChain,

        [string]$ExpectedSignerThumbprint
    )

    $constants = $script:LumaBridgeDriverConstants
    $infPath = Join-Path -Path $PackageDirectory -ChildPath $constants.InfFileName
    $dllPath = Join-Path -Path $PackageDirectory -ChildPath $constants.DllFileName
    $catPath = Join-Path -Path $PackageDirectory -ChildPath $constants.CatFileName
    $cerPath = Join-Path -Path $PackageDirectory -ChildPath 'LumaBridgeTest.cer'

    $infExists = Test-Path -LiteralPath $infPath -PathType Leaf
    $dllExists = Test-Path -LiteralPath $dllPath -PathType Leaf
    $catExists = Test-Path -LiteralPath $catPath -PathType Leaf
    $cerExists = Test-Path -LiteralPath $cerPath -PathType Leaf
    $allFilesPresent = ($infExists -and $dllExists -and $catExists)

    $dllSig = if ($dllExists) { Get-AuthenticodeSignature -LiteralPath $dllPath } else { $null }
    $catSig = if ($catExists) { Get-AuthenticodeSignature -LiteralPath $catPath } else { $null }

    $dllWvtStatus = if ($dllExists) { Get-LumaBridgeWinVerifyTrustStatus -FilePath $dllPath } else { [uint32]0x800B0100L }
    $catWvtStatus = if ($catExists) { Get-LumaBridgeWinVerifyTrustStatus -FilePath $catPath } else { [uint32]0x800B0100L }
    $catCms = if ($catExists) {
        Test-LumaBridgeCatalogCmsSignature -CatPath $catPath
    }
    else {
        [pscustomobject]@{ HasSignature = $false; IsCryptographicallyIntact = $false; SignerThumbprints = @(); Error = 'Catalog file missing.' }
    }

    $catHashes = if ($allFilesPresent) {
        Test-LumaBridgeCatalogFileHashes -CatPath $catPath -DllPath $dllPath -InfPath $infPath
    }
    else {
        [pscustomobject]@{ DllCatalogHashVerified = $false; InfCatalogHashVerified = $false; AllMembersVerified = $false; MemberCount = 0; Detail = 'Missing required package artifact.' }
    }

    $signtool = Get-LumaBridgeWdkToolPath -ToolName 'signtool.exe'
    $dllSigntoolVerified = $false
    $infSigntoolVerified = $false
    $catalogVerifyDetails = New-Object System.Collections.Generic.List[string]

    if ($allFilesPresent -and ($null -ne $signtool) -and ($null -ne $catSig) -and ($catSig.Status -ne 'NotSigned')) {
        $dllVerify = Invoke-LumaBridgeSigntoolCatalogVerify -SigntoolPath $signtool -CatPath $catPath -TargetFilePath $dllPath
        $infVerify = Invoke-LumaBridgeSigntoolCatalogVerify -SigntoolPath $signtool -CatPath $catPath -TargetFilePath $infPath
        $dllSigntoolVerified = $dllVerify.Verified
        $infSigntoolVerified = $infVerify.Verified
        if (-not [string]::IsNullOrWhiteSpace($dllVerify.Output)) {
            $catalogVerifyDetails.Add(("[DLL] {0}" -f $dllVerify.Output.Trim()))
        }
        if (-not [string]::IsNullOrWhiteSpace($infVerify.Output)) {
            $catalogVerifyDetails.Add(("[INF] {0}" -f $infVerify.Output.Trim()))
        }
    }

    $now = Get-Date
    $dllCert = if ($null -ne $dllSig) { $dllSig.SignerCertificate } else { $null }
    $catCert = if ($null -ne $catSig) { $catSig.SignerCertificate } else { $null }
    $dllThumbprint = if ($null -ne $dllCert) { $dllCert.Thumbprint } else { $null }
    $catThumbprint = if ($null -ne $catCert) { $catCert.Thumbprint } else { $null }

    $dllCertTimeValid = ($null -ne $dllCert -and $dllCert.NotBefore -le $now -and $dllCert.NotAfter -ge $now)
    $catCertTimeValid = ($null -ne $catCert -and $catCert.NotBefore -le $now -and $catCert.NotAfter -ge $now)

    $cerThumbprint = $null
    $cerCertTimeValid = $true
    if ($cerExists) {
        try {
            $cerCert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($cerPath)
            $cerThumbprint = $cerCert.Thumbprint
            $cerCertTimeValid = ($cerCert.NotBefore -le $now -and $cerCert.NotAfter -ge $now)
        }
        catch {
            $cerThumbprint = 'INVALID_CER'
            $cerCertTimeValid = $false
        }
    }

    $normalizedExpectedThumb = if (-not [string]::IsNullOrWhiteSpace($ExpectedSignerThumbprint)) {
        ($ExpectedSignerThumbprint -replace '\s', '').ToUpperInvariant()
    }
    else {
        $null
    }

    $catCmsThumbMatches = $true
    if ($catCms.HasSignature) {
        $catCmsThumbMatches = (@($catCms.SignerThumbprints | Where-Object { $_ -ieq $catThumbprint }).Count -gt 0)
    }

    $signerCertificatesMatch =
        (-not [string]::IsNullOrWhiteSpace($dllThumbprint)) -and
        (-not [string]::IsNullOrWhiteSpace($catThumbprint)) -and
        $dllCertTimeValid -and
        $catCertTimeValid -and
        $cerCertTimeValid -and
        ($dllThumbprint -ieq $catThumbprint) -and
        $catCmsThumbMatches -and
        ([string]::IsNullOrWhiteSpace($cerThumbprint) -or ($cerThumbprint -ieq $dllThumbprint)) -and
        ([string]::IsNullOrWhiteSpace($normalizedExpectedThumb) -or ($normalizedExpectedThumb -ieq $dllThumbprint))

    [uint32]$certE_UntrustedRoot = [uint32]0x800B0109L
    $dllStatusStr = if ($null -ne $dllSig) { $dllSig.Status.ToString() } else { 'Missing' }
    $catStatusStr = if ($null -ne $catSig) { $catSig.Status.ToString() } else { 'Missing' }

    $testUntrustedChainAcceptable = {
        param([System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert)
        if ($null -eq $Cert) { return $false }
        $chain = [System.Security.Cryptography.X509Certificates.X509Chain]::new()
        $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
        $chain.ChainPolicy.VerificationFlags = [System.Security.Cryptography.X509Certificates.X509VerificationFlags]::NoFlag
        [void]$chain.Build($Cert)
        $allowedFlags = [System.Security.Cryptography.X509Certificates.X509ChainStatusFlags](
            [int][System.Security.Cryptography.X509Certificates.X509ChainStatusFlags]::NoError -bor
            [int][System.Security.Cryptography.X509Certificates.X509ChainStatusFlags]::UntrustedRoot -bor
            [int][System.Security.Cryptography.X509Certificates.X509ChainStatusFlags]::PartialChain -bor
            [int][System.Security.Cryptography.X509Certificates.X509ChainStatusFlags]::RevocationStatusUnknown -bor
            [int][System.Security.Cryptography.X509Certificates.X509ChainStatusFlags]::OfflineRevocation
        )
        foreach ($cs in $chain.ChainStatus) {
            if (([int]$cs.Status -band (-bnot [int]$allowedFlags)) -ne 0) {
                return $false
            }
        }
        return $true
    }

    $dllChainUntrustedOk = (& $testUntrustedChainAcceptable $dllCert)
    $catChainUntrustedOk = (& $testUntrustedChainAcceptable $catCert)

    $dllSignedValid = ($null -ne $dllSig -and $dllSig.Status -eq 'Valid' -and $dllWvtStatus -eq 0)
    $catSignedValid = ($null -ne $catSig -and $catSig.Status -eq 'Valid' -and $catCms.IsCryptographicallyIntact)

    $dllIntactUntrusted = ($null -ne $dllSig) -and
        ($dllSig.Status -in @('Valid', 'UnknownError')) -and
        ($dllWvtStatus -in @([uint32]0, $certE_UntrustedRoot)) -and
        $dllChainUntrustedOk

    $catIntactUntrusted = ($null -ne $catSig) -and
        ($catSig.Status -in @('Valid', 'UnknownError')) -and
        $catCms.IsCryptographicallyIntact -and
        $catChainUntrustedOk

    $catalogMemberVerified = ($catHashes.AllMembersVerified -and $dllSigntoolVerified -and $infSigntoolVerified)
    $isCryptographicallyValid = (
        $allFilesPresent -and
        $dllSignedValid -and
        $catSignedValid -and
        $signerCertificatesMatch -and
        $catalogMemberVerified
    )
    $isValidWithUntrustedRoot = (
        $allFilesPresent -and
        $dllIntactUntrusted -and
        $catIntactUntrusted -and
        $signerCertificatesMatch -and
        $catHashes.AllMembersVerified
    )

    $infDriverVerMeta = if ($infExists) { Get-LumaBridgeInfDriverVerMetadata -InfPath $infPath } else { $null }

    $result = [pscustomobject]@{
        PackageDirectory           = $PackageDirectory
        AllFilesPresent            = $allFilesPresent
        InfPath                    = $infPath
        InfPresent                 = $infExists
        InfDriverVersion           = if ($null -ne $infDriverVerMeta) { $infDriverVerMeta.Version } else { $null }
        InfDriverVerRaw            = if ($null -ne $infDriverVerMeta) { $infDriverVerMeta.Raw } else { $null }
        InfSha256                  = if ($infExists) { (Get-FileHash -LiteralPath $infPath -Algorithm SHA256).Hash } else { $null }
        DllPath                    = $dllPath
        DllPresent                 = $dllExists
        DllSha256                  = if ($dllExists) { (Get-FileHash -LiteralPath $dllPath -Algorithm SHA256).Hash } else { $null }
        DllSignatureStatus         = $dllStatusStr
        DllWinVerifyTrustStatus    = ('0x{0:X8}' -f $dllWvtStatus)
        DllSignerThumbprint        = $dllThumbprint
        CatPath                    = $catPath
        CatPresent                 = $catExists
        CatSha256                  = if ($catExists) { (Get-FileHash -LiteralPath $catPath -Algorithm SHA256).Hash } else { $null }
        CatSignatureStatus         = $catStatusStr
        CatWinVerifyTrustStatus    = ('0x{0:X8}' -f $catWvtStatus)
        CatCmsSignatureIntact      = $catCms.IsCryptographicallyIntact
        CatSignerThumbprint        = $catThumbprint
        ExportedCerThumbprint      = $cerThumbprint
        SignerCertificatesMatch    = $signerCertificatesMatch
        DllCatalogHashVerified     = $catHashes.DllCatalogHashVerified
        InfCatalogHashVerified     = $catHashes.InfCatalogHashVerified
        CatalogHashesVerified      = $catHashes.AllMembersVerified
        CatalogHashVerifyDetail    = $catHashes.Detail
        DllCatalogSigntoolVerified = $dllSigntoolVerified
        InfCatalogSigntoolVerified = $infSigntoolVerified
        CatalogMemberVerified      = $catalogMemberVerified
        CatalogVerifyDetail        = ($catalogVerifyDetails -join [Environment]::NewLine)
        IsCryptographicallyValid   = $isCryptographicallyValid
        IsValidWithUntrustedRoot   = $isValidWithUntrustedRoot
    }

    if ($RequireValidSignature) {
        $passed = if ($AllowUntrustedChain) { $result.IsValidWithUntrustedRoot } else { $result.IsCryptographicallyValid }
        if (-not $passed) {
            throw ("Cryptographic verification failed for '{0}' (AllowUntrustedChain={1}). AllFilesPresent={2}, DllSig={3} ({4}), CatSig={5} ({6}), CatCmsIntact={7}, SignerCertsMatch={8}, DllCatHash={9}, InfCatHash={10}, DllSigntool={11}, InfSigntool={12}. Detail: {13}" -f `
                $PackageDirectory,
                $AllowUntrustedChain.IsPresent,
                $result.AllFilesPresent,
                $result.DllSignatureStatus,
                $result.DllWinVerifyTrustStatus,
                $result.CatSignatureStatus,
                $result.CatWinVerifyTrustStatus,
                $result.CatCmsSignatureIntact,
                $result.SignerCertificatesMatch,
                $result.DllCatalogHashVerified,
                $result.InfCatalogHashVerified,
                $result.DllCatalogSigntoolVerified,
                $result.InfCatalogSigntoolVerified,
                $result.CatalogHashVerifyDetail)
        }
    }

    return $result
}

function Get-LumaBridgeRawWudfProcesses {
    [CmdletBinding()]
    param()

    $cimByPid = @{}
    if (Get-Command -Name 'Get-CimInstance' -ErrorAction SilentlyContinue) {
        $cimProcs = Get-CimInstance -ClassName Win32_Process -Filter "Name = 'WUDFHost.exe'" -ErrorAction SilentlyContinue
        foreach ($cp in @($cimProcs)) {
            $cimByPid[[int]$cp.ProcessId] = $cp.CommandLine
        }
    }

    $procs = @(Get-Process -Name 'WUDFHost' -ErrorAction SilentlyContinue)
    $rawList = New-Object System.Collections.Generic.List[object]

    foreach ($p in $procs) {
        $startUtc = $null
        try { $startUtc = $p.StartTime.ToUniversalTime().ToString('o') } catch { $startUtc = $null }
        $cpuSec = $null
        try { $cpuSec = [Math]::Round($p.TotalProcessorTime.TotalSeconds, 3) } catch { $cpuSec = $null }

        $loadedModules = @()
        try {
            $loadedModules = @($p.Modules | ForEach-Object {
                [pscustomobject]@{
                    ModuleName = $_.ModuleName
                    FileName   = $_.FileName
                }
            })
        }
        catch {
            $loadedModules = @()
        }

        $cmdLine = if ($cimByPid.ContainsKey([int]$p.Id)) { $cimByPid[[int]$p.Id] } else { $null }

        $rawList.Add([pscustomobject]@{
            Id                = [int]$p.Id
            StartTimeUtc      = $startUtc
            WorkingSetMB      = [Math]::Round($p.WorkingSet64 / 1MB, 2)
            PrivateMemoryMB   = [Math]::Round($p.PrivateMemorySize64 / 1MB, 2)
            HandleCount       = [int]$p.HandleCount
            ThreadCount       = [int]$p.Threads.Count
            TotalProcessorSec = $cpuSec
            CommandLine       = $cmdLine
            LoadedModules     = $loadedModules
        })
    }

    return @($rawList.ToArray())
}

function Get-LumaBridgeWudfHostProcesses {
    [CmdletBinding()]
    param(
        [object[]]$PnpInstances = @(),

        [object[]]$RecentEvents = @(),

        [string[]]$DebugTraceLines = @()
    )

    $constants = $script:LumaBridgeDriverConstants
    $rawProcesses = @(Get-LumaBridgeRawWudfProcesses)

    $hostGuids = New-Object System.Collections.Generic.HashSet[string] ([StringComparer]::OrdinalIgnoreCase)
    $instanceIds = New-Object System.Collections.Generic.HashSet[string] ([StringComparer]::OrdinalIgnoreCase)

    foreach ($inst in @($PnpInstances)) {
        if ($null -eq $inst -or [string]::IsNullOrWhiteSpace($inst.InstanceId)) {
            continue
        }
        $null = $instanceIds.Add($inst.InstanceId)

        if (-not [string]::IsNullOrWhiteSpace($inst.DeviceParametersPath)) {
            $hasWudfSubKey = $false
            $wudfSubKey = $null
            try {
                $wudfSubKey = Join-Path -Path $inst.DeviceParametersPath -ChildPath 'WUDF'
                $hasWudfSubKey = Test-Path -LiteralPath $wudfSubKey -ErrorAction SilentlyContinue
            }
            catch {
                $hasWudfSubKey = $false
            }
            if ($hasWudfSubKey -and -not [string]::IsNullOrWhiteSpace($wudfSubKey)) {
                $wudfProps = Get-ItemProperty -LiteralPath $wudfSubKey -ErrorAction SilentlyContinue
                if ($null -ne $wudfProps -and ($wudfProps.PSObject.Properties.Name -contains 'HostProcessGUID')) {
                    $guidVal = [string]$wudfProps.HostProcessGUID
                    if (-not [string]::IsNullOrWhiteSpace($guidVal)) {
                        $null = $hostGuids.Add($guidVal.Trim())
                    }
                }
            }
        }
    }

    $eventMatchedPids = New-Object System.Collections.Generic.HashSet[int]
    foreach ($ev in @($RecentEvents)) {
        if ($null -eq $ev) {
            continue
        }

        $msg = if ($null -ne $ev.Message) { [string]$ev.Message } else { '' }
        $mentionsLumaBridge = ($msg -match '(?i)LumaBridge')
        if (-not $mentionsLumaBridge) {
            foreach ($iid in $instanceIds) {
                if ($msg.IndexOf($iid, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
                    $mentionsLumaBridge = $true
                    break
                }
            }
        }

        if ($mentionsLumaBridge) {
            if (($ev.PSObject.Properties.Name -contains 'ProcessId') -and $null -ne $ev.ProcessId -and [int]$ev.ProcessId -gt 0) {
                $null = $eventMatchedPids.Add([int]$ev.ProcessId)
            }
            if ($msg -match '(?i)\b(?:Host\s+process(?:\s+ID)?|PID)\s*[:=#]?\s*(?<Pid>\d+)\b') {
                $null = $eventMatchedPids.Add([int]$matches['Pid'])
            }
        }
    }

    $traceMatchedPids = New-Object System.Collections.Generic.HashSet[int]
    foreach ($line in @($DebugTraceLines)) {
        if ([string]::IsNullOrWhiteSpace($line) -or ($line -notmatch '\[LB-DRIVER\]')) {
            continue
        }
        if ($line -match '(?:\[(?<Pid>\d+)\]|PID\s*=\s*(?<Pid>\d+)|^\d+\s+[^\t]+\s+\[(?<Pid>\d+)\])') {
            $null = $traceMatchedPids.Add([int]$matches['Pid'])
        }
    }

    $annotated = New-Object System.Collections.Generic.List[object]
    $hasActiveLumaBridgeDevice = ($PnpInstances.Count -gt 0)

    foreach ($proc in $rawProcesses) {
        $isLumaBridge = $false
        $method = if ($hasActiveLumaBridgeDevice) { 'Unverified' } else { 'None' }
        $loadedDriverModulePath = $null

        if ($hasActiveLumaBridgeDevice) {
            foreach ($mod in @($proc.LoadedModules)) {
                if ($null -eq $mod) {
                    continue
                }
                if (($mod.ModuleName -ieq $constants.DllFileName) -or
                    ($mod.FileName -like ("*\{0}" -f $constants.DllFileName))) {
                    $isLumaBridge = $true
                    $method = 'LoadedModule'
                    $loadedDriverModulePath = $mod.FileName
                    break
                }
            }

            if (-not $isLumaBridge -and -not [string]::IsNullOrWhiteSpace($proc.CommandLine)) {
                if (($proc.CommandLine -match '(?i)LumaBridge') -or
                    ($proc.CommandLine -match '(?i)LumaBridgeIddGroup')) {
                    $isLumaBridge = $true
                    $method = 'CommandLineLumaBridge'
                }
                else {
                    foreach ($hg in $hostGuids) {
                        if ($proc.CommandLine.IndexOf($hg, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
                            $isLumaBridge = $true
                            $method = 'CommandLineHostGuid'
                            break
                        }
                    }
                }
            }

            if (-not $isLumaBridge -and $eventMatchedPids.Contains([int]$proc.Id)) {
                $isLumaBridge = $true
                $method = 'EventLogCorrelation'
            }

            if (-not $isLumaBridge -and $traceMatchedPids.Contains([int]$proc.Id)) {
                $isLumaBridge = $true
                $method = 'DebugTracePid'
            }
        }

        $annotated.Add([pscustomobject]@{
            Id                     = [int]$proc.Id
            IsLumaBridgeHost       = $isLumaBridge
            AssociationMethod      = $method
            LoadedDriverModulePath = $loadedDriverModulePath
            StartTimeUtc           = $proc.StartTimeUtc
            WorkingSetMB           = $proc.WorkingSetMB
            PrivateMemoryMB        = $proc.PrivateMemoryMB
            HandleCount            = $proc.HandleCount
            ThreadCount            = $proc.ThreadCount
            TotalProcessorSec      = $proc.TotalProcessorSec
        })
    }

    return @($annotated.ToArray())
}

function Get-LumaBridgeHostSecurityState {
    [CmdletBinding()]
    param()

    $secureBootState = 'Unknown'
    if (Get-Command -Name 'Confirm-SecureBootUEFI' -ErrorAction SilentlyContinue) {
        try {
            $sb = Confirm-SecureBootUEFI -ErrorAction Stop
            $secureBootState = if ($sb) { 'Enabled' } else { 'Disabled' }
        }
        catch [System.UnauthorizedAccessException] {
            $secureBootState = 'RequiresAdministrator'
        }
        catch {
            $secureBootState = 'UnsupportedOrLegacyBios'
        }
    }
    if ($secureBootState -in @('Unknown', 'RequiresAdministrator')) {
        $sbReg = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State' -Name 'UEFISecureBootEnabled' -ErrorAction SilentlyContinue
        if ($null -ne $sbReg -and ($sbReg.PSObject.Properties.Name -contains 'UEFISecureBootEnabled')) {
            $secureBootState = if ([int]$sbReg.UEFISecureBootEnabled -eq 1) { 'Enabled' } else { 'Disabled' }
        }
    }

    $testSigningState = 'Unknown'
    try {
        $prevEap = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        try {
            $bcdLines = & bcdedit.exe /enum '{current}' 2>&1
            $bcdExitCode = $LASTEXITCODE
        }
        finally {
            $ErrorActionPreference = $prevEap
        }
        if ($bcdExitCode -eq 0) {
            $tsLine = $bcdLines | Where-Object { $_ -match '^\s*testsigning\s+' } | Select-Object -First 1
            if ($null -ne $tsLine) {
                if ($tsLine -match '\s+(Yes|Sim|On)\s*$') {
                    $testSigningState = 'Enabled'
                }
                else {
                    $testSigningState = 'Disabled'
                }
            }
            else {
                $testSigningState = 'Disabled'
            }
        }
        else {
            $testSigningState = 'RequiresAdministrator'
        }
    }
    catch {
        $testSigningState = 'RequiresAdministrator'
    }
    if ($testSigningState -in @('Unknown', 'RequiresAdministrator')) {
        $ctrlReg = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control' -Name 'SystemStartOptions' -ErrorAction SilentlyContinue
        if ($null -ne $ctrlReg -and ($ctrlReg.PSObject.Properties.Name -contains 'SystemStartOptions') -and -not [string]::IsNullOrWhiteSpace($ctrlReg.SystemStartOptions)) {
            if ($ctrlReg.SystemStartOptions -match '(?i)(?:^|\s)TESTSIGNING(?:$|\s)') {
                $testSigningState = 'Enabled'
            }
            else {
                $testSigningState = 'Disabled'
            }
        }
    }

    return [pscustomobject]@{
        SecureBoot  = $secureBootState
        TestSigning = $testSigningState
    }
}

function Find-LumaBridgeSigningCertificate {
    [CmdletBinding()]
    param(
        [string]$CertificateThumbprint,

        [string]$CertificateSubject = $script:LumaBridgeDriverConstants.DefaultCertificateSubject
    )

    if (-not [string]::IsNullOrWhiteSpace($CertificateThumbprint)) {
        $normalizedThumb = ($CertificateThumbprint -replace '\s', '').ToUpperInvariant()
        return (Get-ChildItem -Path 'Cert:\CurrentUser\My' -CodeSigningCert -ErrorAction SilentlyContinue |
            Where-Object { $_.Thumbprint -ieq $normalizedThumb } |
            Select-Object -First 1)
    }

    $now = Get-Date
    return (Get-ChildItem -Path 'Cert:\CurrentUser\My' -CodeSigningCert -ErrorAction SilentlyContinue |
        Where-Object { $_.Subject -eq $CertificateSubject -and $_.NotBefore -le $now -and $_.NotAfter -gt $now } |
        Sort-Object -Property NotAfter -Descending |
        Select-Object -First 1)
}

function New-LumaBridgeSigningCertificate {
    [CmdletBinding()]
    param(
        [string]$CertificateSubject = $script:LumaBridgeDriverConstants.DefaultCertificateSubject,

        [int]$ValidMonths = 6
    )

    return (New-SelfSignedCertificate `
        -Type CodeSigningCert `
        -Subject $CertificateSubject `
        -CertStoreLocation 'Cert:\CurrentUser\My' `
        -NotAfter (Get-Date).AddMonths($ValidMonths))
}

function Export-LumaBridgeCertificateFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $Certificate,

        [Parameter(Mandatory = $true)]
        [string]$FilePath
    )

    Export-Certificate -Cert $Certificate -FilePath $FilePath -Force | Out-Null
}

function Remove-LumaBridgeCertificateFromStores {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Thumbprint,

        [string[]]$Stores = @('Cert:\CurrentUser\My', 'Cert:\LocalMachine\Root', 'Cert:\LocalMachine\TrustedPublisher')
    )

    $normalizedThumb = ($Thumbprint -replace '\s', '').ToUpperInvariant()
    $removed = New-Object System.Collections.Generic.List[string]

    foreach ($storePath in $Stores) {
        if (Test-Path -LiteralPath $storePath) {
            $matchingCerts = @(Get-ChildItem -Path $storePath -ErrorAction SilentlyContinue |
                Where-Object { $_.Thumbprint -ieq $normalizedThumb })
            foreach ($cert in $matchingCerts) {
                Remove-Item -LiteralPath (Join-Path -Path $storePath -ChildPath $cert.Thumbprint) -Force -ErrorAction Stop
                $removed.Add(("{0}\{1}" -f $storePath, $cert.Thumbprint))
            }
        }
    }

    return @($removed.ToArray())
}

function Get-LumaBridgeSetupApiLogExcerpt {
    [CmdletBinding()]
    param(
        [string]$SetupApiLogPath = $script:LumaBridgeDriverConstants.DefaultSetupApiLogPath,

        [string[]]$InstanceIds = @(),

        [string[]]$PublishedInfNames = @(),

        [ValidateRange(1, 100)]
        [int]$MaxMatchedSections = 20
    )

    if ([string]::IsNullOrWhiteSpace($SetupApiLogPath) -or -not (Test-Path -LiteralPath $SetupApiLogPath -PathType Leaf)) {
        return [pscustomobject]@{
            LogPath                  = $SetupApiLogPath
            Exists                   = $false
            AccessDenied             = $false
            Error                    = 'SetupAPI log file not found.'
            MatchedSectionCount      = 0
            WdfSchemaWarnings        = @()
            DeviceStartProblemLines  = @()
            Sections                 = @()
            RawExcerptText           = ''
        }
    }

    $lines = New-Object System.Collections.Generic.List[string]
    $fs = $null
    $reader = $null
    try {
        $fs = [System.IO.File]::Open(
            $SetupApiLogPath,
            [System.IO.FileMode]::Open,
            [System.IO.FileAccess]::Read,
            [System.IO.FileShare]::ReadWrite)
        $reader = New-Object System.IO.StreamReader($fs)
        while (-not $reader.EndOfStream) {
            $lines.Add($reader.ReadLine())
        }
    }
    catch [System.UnauthorizedAccessException] {
        return [pscustomobject]@{
            LogPath                  = $SetupApiLogPath
            Exists                   = $true
            AccessDenied             = $true
            Error                    = $_.Exception.Message
            MatchedSectionCount      = 0
            WdfSchemaWarnings        = @()
            DeviceStartProblemLines  = @()
            Sections                 = @()
            RawExcerptText           = ''
        }
    }
    catch {
        return [pscustomobject]@{
            LogPath                  = $SetupApiLogPath
            Exists                   = $true
            AccessDenied             = $false
            Error                    = $_.Exception.Message
            MatchedSectionCount      = 0
            WdfSchemaWarnings        = @()
            DeviceStartProblemLines  = @()
            Sections                 = @()
            RawExcerptText           = ''
        }
    }
    finally {
        if ($null -ne $reader) { $reader.Dispose() }
        elseif ($null -ne $fs) { $fs.Dispose() }
    }

    $primaryPatterns = New-Object System.Collections.Generic.List[string]
    $primaryPatterns.Add('LumaBridge')
    $primaryPatterns.Add([regex]::Escape($script:LumaBridgeDriverConstants.HardwareId))
    $primaryPatterns.Add([regex]::Escape($script:LumaBridgeDriverConstants.InfFileName))
    foreach ($id in @($InstanceIds)) {
        if (-not [string]::IsNullOrWhiteSpace($id)) {
            $primaryPatterns.Add([regex]::Escape($id.Trim()))
        }
    }
    $primaryPattern = '(?i)(' + (($primaryPatterns | Select-Object -Unique) -join '|') + ')'

    $publishedPatterns = New-Object System.Collections.Generic.List[string]
    foreach ($inf in @($PublishedInfNames)) {
        if (-not [string]::IsNullOrWhiteSpace($inf)) {
            $publishedPatterns.Add([regex]::Escape($inf.Trim()))
        }
    }
    $publishedPattern = if ($publishedPatterns.Count -gt 0) {
        '(?i)(' + (($publishedPatterns | Select-Object -Unique) -join '|') + ')'
    }
    else {
        $null
    }
    $publishedContextGuard = '(?i)(LumaBridge|4d36e968-e325-11ce-bfc1-08002be10318|WUDFRd|IndirectKmd|ROOT\\DISPLAY)'

    $allMatchedSections = New-Object System.Collections.Generic.List[object]
    $currentLines = $null
    $currentTitle = ''
    $currentStart = ''

    $flushSection = {
        param($SecLines, [string]$Title, [string]$StartTime)
        if ($null -eq $SecLines -or $SecLines.Count -eq 0) {
            return
        }
        $joined = ($SecLines.ToArray() -join [Environment]::NewLine)
        $isPrimaryMatch = ($joined -match $primaryPattern)
        $isPublishedMatch = ($null -ne $publishedPattern) -and ($joined -match $publishedPattern) -and ($joined -match $publishedContextGuard)
        if ($isPrimaryMatch -or $isPublishedMatch) {
            $exitStatus = $null
            for ($i = $SecLines.Count - 1; $i -ge 0; --$i) {
                if ($SecLines[$i] -match '<<<\s+\[Exit status:\s*(?<Status>[^\]]+)\]') {
                    $exitStatus = $matches['Status'].Trim()
                    break
                }
            }
            $wdfWarns = @($SecLines.ToArray() | Where-Object { $_ -match '(?i)Using WDF schema version' })
            $probLines = @($SecLines.ToArray() | Where-Object { $_ -match '(?i)(Device not started|CM_PROB_|problem status:|FAILED)' })
            $allMatchedSections.Add([pscustomobject]@{
                Title                   = $Title
                StartTime               = $StartTime
                ExitStatus              = $exitStatus
                LineCount               = $SecLines.Count
                WdfSchemaWarnings       = @($wdfWarns | ForEach-Object { $_.Trim() })
                DeviceStartProblemLines = @($probLines | ForEach-Object { $_.Trim() })
                Text                    = $joined
            })
        }
    }

    foreach ($line in $lines) {
        if ($line -match '^>>>\s+\[(?<Title>[^\]]+)\]\s*$') {
            & $flushSection $currentLines $currentTitle $currentStart
            $currentLines = New-Object System.Collections.Generic.List[string]
            $currentTitle = $matches['Title'].Trim()
            $currentStart = ''
            $currentLines.Add($line)
            continue
        }

        if ($null -eq $currentLines) {
            continue
        }

        $currentLines.Add($line)
        if ([string]::IsNullOrWhiteSpace($currentStart) -and $line -match '^>>>\s+Section start\s+(?<Ts>.+)$') {
            $currentStart = $matches['Ts'].Trim()
        }

        if ($line -match '^<<<\s+\[Exit status:') {
            & $flushSection $currentLines $currentTitle $currentStart
            $currentLines = $null
            $currentTitle = ''
            $currentStart = ''
        }
    }

    & $flushSection $currentLines $currentTitle $currentStart

    $selectedSections = if ($allMatchedSections.Count -gt $MaxMatchedSections) {
        @($allMatchedSections.ToArray() | Select-Object -Last $MaxMatchedSections)
    }
    else {
        @($allMatchedSections.ToArray())
    }
    $selectedSections = @($selectedSections)

    $allWdfWarns = New-Object System.Collections.Generic.List[string]
    $allProbLines = New-Object System.Collections.Generic.List[string]
    foreach ($sec in $selectedSections) {
        foreach ($w in @($sec.WdfSchemaWarnings)) { $allWdfWarns.Add($w) }
        foreach ($p in @($sec.DeviceStartProblemLines)) { $allProbLines.Add($p) }
    }

    $excerptText = ($selectedSections | ForEach-Object { $_.Text }) -join ([Environment]::NewLine + [Environment]::NewLine)

    return [pscustomobject]@{
        LogPath                 = $SetupApiLogPath
        Exists                  = $true
        AccessDenied            = $false
        Error                   = ''
        MatchedSectionCount     = $selectedSections.Count
        WdfSchemaWarnings       = @($allWdfWarns.ToArray())
        DeviceStartProblemLines = @($allProbLines.ToArray())
        Sections                = @($selectedSections | ForEach-Object {
            [pscustomobject]@{
                Title                   = $_.Title
                StartTime               = $_.StartTime
                ExitStatus              = $_.ExitStatus
                LineCount               = $_.LineCount
                WdfSchemaWarnings       = $_.WdfSchemaWarnings
                DeviceStartProblemLines = $_.DeviceStartProblemLines
            }
        })
        RawExcerptText          = $excerptText
    }
}

function Get-LumaBridgeEventChannelStatus {
    [CmdletBinding()]
    param(
        [string[]]$ChannelNames = @(
            'Microsoft-Windows-Kernel-PnP/Configuration',
            'Microsoft-Windows-Kernel-PnP/Device Management',
            'Microsoft-Windows-Kernel-PnP/Driver Watchdog',
            'Microsoft-Windows-CodeIntegrity/Operational',
            'Microsoft-Windows-DriverFrameworks-UserMode/Operational',
            'Microsoft-Windows-WerKernel/Operational',
            'Microsoft-Windows-DxgKrnl-Admin',
            'Microsoft-Windows-DxgKrnl-Operational',
            'Microsoft-Windows-IndirectDisplays-ClassExtension-Events/Diagnostic',
            'System'
        )
    )

    $winEventCmd = Get-Command -Name 'Get-WinEvent' -ErrorAction SilentlyContinue
    $supportsListLog = ($null -ne $winEventCmd -and $winEventCmd.Parameters.ContainsKey('ListLog'))
    $statuses = New-Object System.Collections.Generic.List[object]

    foreach ($ch in $ChannelNames) {
        if (-not $supportsListLog) {
            $statuses.Add([pscustomobject]@{
                LogName     = $ch
                IsEnabled   = $true
                LogType     = 'MockedOrUnavailable'
                RecordCount = $null
                QueryError  = ''
            })
            continue
        }

        try {
            $logInfo = Get-WinEvent -ListLog $ch -ErrorAction Stop | Select-Object -First 1
            $statuses.Add([pscustomobject]@{
                LogName     = $logInfo.LogName
                IsEnabled   = [bool]$logInfo.IsEnabled
                LogType     = $logInfo.LogType.ToString()
                RecordCount = $logInfo.RecordCount
                QueryError  = ''
            })
        }
        catch {
            $statuses.Add([pscustomobject]@{
                LogName     = $ch
                IsEnabled   = $false
                LogType     = 'Unavailable'
                RecordCount = $null
                QueryError  = $_.Exception.Message
            })
        }
    }

    return @($statuses.ToArray())
}

function Get-LumaBridgeDiagnosticEvents {
    [CmdletBinding()]
    param(
        [ValidateRange(1, 10080)]
        [int]$LookbackMinutes = 60,

        [string[]]$InstanceIds = @(),

        [string[]]$PublishedInfNames = @(),

        [object[]]$ChannelStatus = @()
    )

    $cutoffTime = (Get-Date).AddMinutes(-1 * $LookbackMinutes)
    $extraTokens = New-Object System.Collections.Generic.List[string]
    foreach ($id in @($InstanceIds)) {
        if (-not [string]::IsNullOrWhiteSpace($id)) { $extraTokens.Add([regex]::Escape($id.Trim())) }
    }
    foreach ($inf in @($PublishedInfNames)) {
        if (-not [string]::IsNullOrWhiteSpace($inf)) { $extraTokens.Add([regex]::Escape($inf.Trim())) }
    }
    $dynamicSuffix = if ($extraTokens.Count -gt 0) { '|' + (($extraTokens | Select-Object -Unique) -join '|') } else { '' }

    $channelSpecs = @(
        @{
            LogName    = 'Microsoft-Windows-Kernel-PnP/Configuration'
            Pattern    = ('LumaBridge|ROOT\\DISPLAY|IndirectKmd|WUDFRd' + $dynamicSuffix)
            IncludeIds = @(400, 410, 411, 420, 430)
            AllLevels  = $false
        },
        @{
            LogName    = 'Microsoft-Windows-Kernel-PnP/Device Management'
            Pattern    = ('LumaBridge|ROOT\\DISPLAY|IndirectKmd|WUDFRd' + $dynamicSuffix)
            IncludeIds = @()
            AllLevels  = $false
        },
        @{
            LogName    = 'Microsoft-Windows-Kernel-PnP/Driver Watchdog'
            Pattern    = ('LumaBridge|ROOT\\DISPLAY|IndirectKmd|WUDFRd|WATCHDOG' + $dynamicSuffix)
            IncludeIds = @()
            AllLevels  = $true
        },
        @{
            LogName    = 'Microsoft-Windows-CodeIntegrity/Operational'
            Pattern    = ('LumaBridge|WUDF|Indirect' + $dynamicSuffix)
            IncludeIds = @()
            IncludeWarnOrError = $true
            AllLevels  = $false
        },
        @{
            LogName    = 'Microsoft-Windows-DriverFrameworks-UserMode/Operational'
            Pattern    = ('LumaBridge|WUDF|UserMode|UmPass|Indirect|Idd|ROOT\\DISPLAY' + $dynamicSuffix)
            IncludeIds = @()
            AllLevels  = $true
        },
        @{
            LogName    = 'Microsoft-Windows-WerKernel/Operational'
            Pattern    = 'WATCHDOG|LumaBridge|WUDF|Indirect|Display|Dxg'
            IncludeIds = @(1001)
            AllLevels  = $true
        },
        @{
            LogName    = 'Microsoft-Windows-DxgKrnl-Admin'
            Pattern    = 'LumaBridge|Indirect|Display|Watchdog'
            IncludeIds = @()
            AllLevels  = $true
        },
        @{
            LogName    = 'Microsoft-Windows-DxgKrnl-Operational'
            Pattern    = 'LumaBridge|Indirect|Display|Watchdog'
            IncludeIds = @()
            AllLevels  = $true
        },
        @{
            LogName    = 'Microsoft-Windows-IndirectDisplays-ClassExtension-Events/Diagnostic'
            Pattern    = '.*'
            IncludeIds = @()
            AllLevels  = $true
        },
        @{
            LogName    = 'System'
            Pattern    = ('LumaBridge|WUDF|IndirectKmd|IddCx|Display|WATCHDOG|0xc000009e' + $dynamicSuffix)
            IncludeIds = @()
            AllLevels  = $false
        }
    )

    $enabledMap = @{}
    foreach ($cs in @($ChannelStatus)) {
        if ($null -ne $cs -and ($cs.PSObject.Properties.Name -contains 'LogName')) {
            $enabledMap[$cs.LogName] = [bool]$cs.IsEnabled
        }
    }

    $collected = New-Object System.Collections.Generic.List[object]

    foreach ($spec in $channelSpecs) {
        $logName = $spec.LogName
        if ($enabledMap.ContainsKey($logName) -and -not $enabledMap[$logName]) {
            continue
        }

        try {
            $events = @(Get-WinEvent -FilterHashtable @{
                LogName   = $logName
                StartTime = $cutoffTime
            } -MaxEvents 200 -ErrorAction Stop)

            $matched = New-Object System.Collections.Generic.List[object]
            foreach ($ev in $events) {
                $msg = if ($null -ne $ev.Message) { [string]$ev.Message } else { '' }
                $prov = if ($ev.PSObject.Properties.Name -contains 'ProviderName') { [string]$ev.ProviderName } else { '' }
                $evId = if ($ev.PSObject.Properties.Name -contains 'Id') { [int]$ev.Id } else { 0 }
                $evLevel = if ($ev.PSObject.Properties.Name -contains 'Level') { $ev.Level } else { $null }

                $isMatch = ($spec.AllLevels) -or
                    ($msg -match $spec.Pattern) -or
                    ($prov -match 'DriverFrameworks|WUDF|LumaBridge|Indirect|WerKernel|DxgKrnl') -or
                    (@($spec.IncludeIds) -contains $evId)

                if (-not $isMatch -and $spec.ContainsKey('IncludeWarnOrError') -and $spec.IncludeWarnOrError -and $null -ne $evLevel -and [int]$evLevel -le 3) {
                    $isMatch = $true
                }

                if ($isMatch) {
                    $evPid = if ($ev.PSObject.Properties.Name -contains 'ProcessId') { $ev.ProcessId } else { $null }
                    $evRecId = if ($ev.PSObject.Properties.Name -contains 'RecordId') { $ev.RecordId } else { $null }
                    $evLevelDisp = if ($ev.PSObject.Properties.Name -contains 'LevelDisplayName') { $ev.LevelDisplayName } else { '' }
                    $evTime = if ($ev.PSObject.Properties.Name -contains 'TimeCreated' -and $null -ne $ev.TimeCreated) {
                        $ev.TimeCreated.ToUniversalTime().ToString('o')
                    }
                    else {
                        (Get-Date).ToUniversalTime().ToString('o')
                    }

                    $matched.Add([pscustomobject]@{
                        LogName       = $logName
                        TimeCreated   = $evTime
                        LevelDisplay  = $evLevelDisp
                        Id            = $evId
                        EventRecordId = $evRecId
                        ProcessId     = $evPid
                        ProviderName  = $prov
                        Message       = ($msg -replace '\r?\n', ' ').Trim()
                    })
                    if ($matched.Count -ge 40) {
                        break
                    }
                }
            }

            foreach ($m in $matched) {
                $collected.Add($m)
            }
        }
        catch {
            $collected.Add([pscustomobject]@{
                LogName       = $logName
                TimeCreated   = (Get-Date).ToUniversalTime().ToString('o')
                LevelDisplay  = 'Info'
                Id            = 0
                EventRecordId = $null
                ProcessId     = $null
                ProviderName  = 'LumaBridgeDiagnostics'
                Message       = ("Log query skipped or returned no events: {0}" -f $_.Exception.Message)
            })
        }
    }

    return @($collected.ToArray())
}

function Get-LumaBridgeCrashDumpInventory {
    [CmdletBinding()]
    param(
        [ValidateRange(1, 10080)]
        [int]$LookbackMinutes = 120,

        [string]$LocalCrashDumpsDir,

        [string]$DriverDataAutoLoggerPath
    )

    $cutoff = (Get-Date).AddMinutes(-1 * $LookbackMinutes)
    if ([string]::IsNullOrWhiteSpace($LocalCrashDumpsDir)) {
        $localAppData = if (-not [string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) {
            $env:LOCALAPPDATA
        }
        else {
            [Environment]::GetFolderPath('LocalApplicationData')
        }
        $LocalCrashDumpsDir = Join-Path -Path $localAppData -ChildPath 'CrashDumps'
    }

    if ([string]::IsNullOrWhiteSpace($DriverDataAutoLoggerPath)) {
        $driverDataRoot = if (-not [string]::IsNullOrWhiteSpace($env:DriverData)) {
            $env:DriverData
        }
        else {
            Join-Path -Path $env:SystemRoot -ChildPath 'System32\Drivers\DriverData'
        }
        $DriverDataAutoLoggerPath = Join-Path -Path $driverDataRoot -ChildPath 'LogFiles\WMI\Microsoft-Windows-Rdp-Graphics-RdpIdd-Trace.etl'
    }

    $probeSpecs = @(
        @{ Category = 'UmdfDump'; Path = 'C:\ProgramData\Microsoft\WDF'; Pattern = '*'; FilterRegex = '.*'; Recurse = $true },
        @{ Category = 'LiveKernelDump'; Path = 'C:\Windows\LiveKernelReports'; Pattern = '*.dmp'; FilterRegex = '.*'; Recurse = $false },
        @{ Category = 'LiveKernelWatchdog'; Path = 'C:\Windows\LiveKernelReports\WATCHDOG'; Pattern = '*.dmp'; FilterRegex = '.*'; Recurse = $true },
        @{ Category = 'KernelMinidump'; Path = 'C:\Windows\Minidump'; Pattern = '*.dmp'; FilterRegex = '.*'; Recurse = $false },
        @{ Category = 'UserCrashDump'; Path = $LocalCrashDumpsDir; Pattern = '*.dmp'; FilterRegex = 'WUDF|LumaBridge'; Recurse = $false },
        @{ Category = 'WerReportQueue'; Path = 'C:\ProgramData\Microsoft\Windows\WER\ReportQueue'; Pattern = '*'; FilterRegex = 'WUDF|WATCHDOG|LiveKernel|LumaBridge|Idd|Display|DWM'; Recurse = $false },
        @{ Category = 'WerReportArchive'; Path = 'C:\ProgramData\Microsoft\Windows\WER\ReportArchive'; Pattern = '*'; FilterRegex = 'WUDF|WATCHDOG|LiveKernel|LumaBridge|Idd|Display|DWM'; Recurse = $false },
        @{ Category = 'RdpIddAutoLoggerEtl'; Path = $DriverDataAutoLoggerPath; Pattern = '*'; FilterRegex = '.*'; Recurse = $false; SingleFile = $true }
    )

    $locations = New-Object System.Collections.Generic.List[object]
    $foundFiles = New-Object System.Collections.Generic.List[object]

    foreach ($spec in $probeSpecs) {
        $targetPath = $spec.Path
        $exists = $false
        $accessDenied = $false
        $errMsg = ''
        $locMatches = New-Object System.Collections.Generic.List[object]

        try {
            $exists = Test-Path -LiteralPath $targetPath -ErrorAction Stop
        }
        catch [System.UnauthorizedAccessException] {
            $accessDenied = $true
            $errMsg = $_.Exception.Message
        }
        catch {
            $errMsg = $_.Exception.Message
        }

        if ($exists -and -not $accessDenied) {
            try {
                if ($spec.ContainsKey('SingleFile') -and $spec.SingleFile) {
                    $item = Get-Item -LiteralPath $targetPath -Force -ErrorAction Stop
                    $entry = [pscustomobject]@{
                        Category         = $spec.Category
                        FullName         = $item.FullName
                        Name             = $item.Name
                        LengthBytes      = [int64]$item.Length
                        LastWriteTimeUtc = $item.LastWriteTimeUtc.ToString('o')
                    }
                    $locMatches.Add($entry)
                    $foundFiles.Add($entry)
                }
                else {
                    $items = Get-ChildItem -LiteralPath $targetPath -Filter $spec.Pattern -Force -Recurse:([bool]$spec.Recurse) -ErrorAction Stop |
                        Where-Object {
                            ($_.LastWriteTime -ge $cutoff -or $spec.Category -eq 'UmdfDump') -and
                            ($_.Name -match $spec.FilterRegex)
                        } |
                        Sort-Object -Property LastWriteTimeUtc -Descending |
                        Select-Object -First 25

                    foreach ($item in @($items)) {
                        $lengthBytes = if ($item.PSObject.Properties.Name -contains 'Length') { [int64]$item.Length } else { 0L }
                        $entry = [pscustomobject]@{
                            Category         = $spec.Category
                            FullName         = $item.FullName
                            Name             = $item.Name
                            LengthBytes      = $lengthBytes
                            LastWriteTimeUtc = $item.LastWriteTimeUtc.ToString('o')
                        }
                        $locMatches.Add($entry)
                        $foundFiles.Add($entry)
                    }
                }
            }
            catch [System.UnauthorizedAccessException] {
                $accessDenied = $true
                $errMsg = $_.Exception.Message
            }
            catch {
                $errMsg = $_.Exception.Message
            }
        }

        $locations.Add([pscustomobject]@{
            Category          = $spec.Category
            Path              = $targetPath
            Exists            = $exists
            AccessDenied      = $accessDenied
            MatchingFileCount = $locMatches.Count
            Error             = $errMsg
        })
    }

    return [pscustomobject]@{
        LookbackMinutes = $LookbackMinutes
        Locations       = @($locations.ToArray())
        Files           = @($foundFiles.ToArray())
        TotalFoundCount = $foundFiles.Count
    }
}

function New-LumaBridgeEtwProviderFileContent {
    [CmdletBinding()]
    param(
        [ValidateSet('Core', 'Dxg')]
        [string]$SessionKind = 'Core',

        [switch]$RestrictIddCxWppKeywords
    )

    $c = $script:LumaBridgeDriverConstants
    $lines = New-Object System.Collections.Generic.List[string]

    if ($SessionKind -eq 'Core') {
        $iddWppFlags = if ($RestrictIddCxWppKeywords) { $c.IddCxWppMatchAnyKeyword } else { $c.IddCxWppAllFlags }
        $specs = @(
            @{ Guid = $c.LumaBridgeTraceProviderGuid; Flags = '0xFFFFFFFFFFFFFFFF'; Level = '5' },
            @{ Guid = $c.IddCxManifestProviderGuid;   Flags = '0xFFFFFFFFFFFFFFFF'; Level = '5' },
            @{ Guid = $c.IddCxWppProviderGuid;        Flags = $iddWppFlags;         Level = '5' },
            @{ Guid = $c.UmdfOperationalProviderGuid; Flags = '0xFFFFFFFFFFFFFFFF'; Level = '5' },
            @{ Guid = $c.WdfCoreWppProviderGuid;      Flags = '0xFFFFFFFFFFFFFFFF'; Level = '5' },
            @{ Guid = $c.WerKernelProviderGuid;       Flags = '0xFFFFFFFFFFFFFFFF'; Level = '5' }
        )
    }
    else {
        $specs = @(
            @{ Guid = $c.DxgKrnlProviderGuid;        Flags = '0xFFFFFFFFFFFFFFFF'; Level = '4' },
            @{ Guid = $c.WatchdogEventsProviderGuid; Flags = '0xFFFFFFFFFFFFFFFF'; Level = '5' }
        )
    }

    foreach ($s in $specs) {
        $lines.Add(("{0} {1} {2}" -f $s.Guid, $s.Flags, $s.Level))
    }

    return @($lines.ToArray())
}

function Test-LumaBridgeEtwSessionProviders {
    [CmdletBinding()]
    param(
        [string[]]$QueryOutputLines = @(),

        [string[]]$ExpectedProviderGuids = @()
    )

    $foundSet = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $guidRegex = [regex]'\{?[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}?'

    foreach ($line in @($QueryOutputLines)) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        foreach ($m in $guidRegex.Matches($line)) {
            $bare = ($m.Value -replace '[{}]', '').ToUpperInvariant()
            $null = $foundSet.Add(('{' + $bare + '}'))
        }
    }

    $normalizedExpected = New-Object System.Collections.Generic.List[string]
    $missing = New-Object System.Collections.Generic.List[string]

    foreach ($exp in @($ExpectedProviderGuids)) {
        if ([string]::IsNullOrWhiteSpace($exp)) { continue }
        $bare = ($exp.Trim() -replace '[{}]', '').ToUpperInvariant()
        $norm = '{' + $bare + '}'
        if ($normalizedExpected -notcontains $norm) {
            $normalizedExpected.Add($norm)
            if (-not $foundSet.Contains($norm)) {
                $missing.Add($norm)
            }
        }
    }

    return [pscustomobject]@{
        Checked              = $true
        ExpectedCount        = $normalizedExpected.Count
        ExpectedProviderGuids = @($normalizedExpected.ToArray())
        FoundProviderGuids   = @($foundSet | Sort-Object)
        MissingProviderGuids = @($missing.ToArray())
        AllProvidersVerified = ($normalizedExpected.Count -gt 0 -and $missing.Count -eq 0)
    }
}

function Get-LumaBridgeEtlTraceStats {
    [CmdletBinding()]
    param(
        [string]$EtlPath
    )

    $result = [pscustomobject]@{
        Available           = $false
        EtlPath             = $EtlPath
        StartTimeUtc        = $null
        EndTimeUtc          = $null
        LogFileMode         = $null
        CircularBufferMode  = $false
        LostBuffers         = $null
        LostEvents          = $null
        CircularWrapWarning = $null
        Error               = ''
    }

    if ([string]::IsNullOrWhiteSpace($EtlPath) -or -not (Test-Path -LiteralPath $EtlPath -PathType Leaf)) {
        $result.Error = 'ETL file not found.'
        return $result
    }

    $xperfPath = Get-LumaBridgeWdkToolPath -ToolName 'xperf.exe'
    if ([string]::IsNullOrWhiteSpace($xperfPath)) {
        $result.Error = 'xperf.exe not found under Windows Kits\10.'
        return $result
    }

    $prevEap = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $lines = & $xperfPath -i $EtlPath -a tracestats 2>&1
        if ($LASTEXITCODE -ne 0) {
            $result.Error = ("xperf tracestats exited with code {0}" -f $LASTEXITCODE)
            return $result
        }

        $result.Available = $true
        foreach ($rawLine in @($lines)) {
            $line = [string]$rawLine
            if ($line -match '^\s*Start time \(UTC\)\s*:\s*(?<Ts>\d{4}/\d{2}/\d{2}:\d{2}:\d{2}:\d{2}\.\d+)' -and $null -eq $result.StartTimeUtc) {
                $dt = [DateTime]::MinValue
                if ([DateTime]::TryParseExact($matches['Ts'], 'yyyy/MM/dd:HH:mm:ss.fffffff', [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal, [ref]$dt)) {
                    $result.StartTimeUtc = $dt.ToUniversalTime().ToString('o')
                }
            }
            elseif ($line -match '^\s*End time \(UTC\)\s*:\s*(?<Ts>\d{4}/\d{2}/\d{2}:\d{2}:\d{2}:\d{2}\.\d+)' -and $null -eq $result.EndTimeUtc) {
                $dt = [DateTime]::MinValue
                if ([DateTime]::TryParseExact($matches['Ts'], 'yyyy/MM/dd:HH:mm:ss.fffffff', [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal, [ref]$dt)) {
                    $result.EndTimeUtc = $dt.ToUniversalTime().ToString('o')
                }
            }
            elseif ($line -match '^\s*Log file mode\s*:\s*(?<Mode>.+)$') {
                $mode = $matches['Mode'].Trim()
                $result.LogFileMode = $mode
                $result.CircularBufferMode = ($mode -match '(?i)Circular')
            }
            elseif ($line -match '^\s*#\s*Lost Buffers\s*:\s*(?<Val>\d+)') {
                $result.LostBuffers = [int]$matches['Val']
            }
            elseif ($line -match '^\s*#\s*Lost Events\s*:\s*(?<Val>\d+)') {
                $result.LostEvents = [int]$matches['Val']
            }
        }

        if ($result.CircularBufferMode) {
            $result.CircularWrapWarning = 'ETL uses circular buffer mode; older events from high-volume providers (e.g. DxgKrnl) may overwrite earlier startup windows unless separated.'
        }
    }
    catch {
        $result.Error = $_.Exception.Message
    }
    finally {
        $ErrorActionPreference = $prevEap
    }

    return $result
}

function Get-LumaBridgeEtlXPathQuery {
    [CmdletBinding()]
    param(
        [string[]]$ProviderGuids = @(),

        [string[]]$ProviderNames = @(),

        [Nullable[DateTime]]$StartTimeUtc = $null,

        [Nullable[DateTime]]$EndTimeUtc = $null,

        [Nullable[int]]$ProcessId = $null,

        [switch]$ExcludeHighVolumeGraphics
    )

    $c = $script:LumaBridgeDriverConstants
    $systemClauses = New-Object System.Collections.Generic.List[string]
    $providerTerms = New-Object System.Collections.Generic.List[string]

    foreach ($g in @($ProviderGuids)) {
        if ([string]::IsNullOrWhiteSpace($g)) { continue }
        $norm = '{' + (($g.Trim() -replace '[{}]', '').ToLowerInvariant()) + '}'
        $providerTerms.Add(("@Guid='{0}'" -f $norm))
    }

    foreach ($n in @($ProviderNames)) {
        if ([string]::IsNullOrWhiteSpace($n)) { continue }
        $safeName = $n.Trim().Replace("'", '')
        $providerTerms.Add(("@Name='{0}'" -f $safeName))
    }

    if ($providerTerms.Count -gt 0) {
        $systemClauses.Add(('Provider[' + ($providerTerms.ToArray() -join ' or ') + ']'))
    }
    elseif ($ExcludeHighVolumeGraphics) {
        $dxg = '{' + (($c.DxgKrnlProviderGuid -replace '[{}]', '').ToLowerInvariant()) + '}'
        $wdg = '{' + (($c.WatchdogEventsProviderGuid -replace '[{}]', '').ToLowerInvariant()) + '}'
        $systemClauses.Add(("Provider[@Guid!='{0}' and @Guid!='{1}']" -f $dxg, $wdg))
    }

    $timeTerms = New-Object System.Collections.Generic.List[string]
    if ($null -ne $StartTimeUtc) {
        $timeTerms.Add(("@SystemTime>='{0}'" -f ([DateTime]$StartTimeUtc).ToUniversalTime().ToString('o')))
    }
    if ($null -ne $EndTimeUtc) {
        $timeTerms.Add(("@SystemTime<='{0}'" -f ([DateTime]$EndTimeUtc).ToUniversalTime().ToString('o')))
    }
    if ($timeTerms.Count -gt 0) {
        $systemClauses.Add(('TimeCreated[' + ($timeTerms.ToArray() -join ' and ') + ']'))
    }

    if ($null -ne $ProcessId) {
        $systemClauses.Add(("Execution[@ProcessID={0}]" -f ([int]$ProcessId)))
    }

    if ($systemClauses.Count -eq 0) {
        return '*'
    }

    return ("*[System[{0}]]" -f ($systemClauses.ToArray() -join ' and '))
}

function Invoke-LumaBridgeEtlXPathReader {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$EtlPath,

        [Parameter(Mandatory = $true)]
        [string]$XPath,

        [ValidateRange(1, 50000)]
        [int]$MaxMatchedEvents = 500
    )

    $matched = New-Object System.Collections.Generic.List[object]
    $limitReached = $false
    $reader = $null

    try {
        $query = [System.Diagnostics.Eventing.Reader.EventLogQuery]::new(
            $EtlPath,
            [System.Diagnostics.Eventing.Reader.PathType]::FilePath,
            $XPath)
        $reader = [System.Diagnostics.Eventing.Reader.EventLogReader]::new($query)

        while ($null -ne ($ev = $reader.ReadEvent())) {
            try {
                if ($matched.Count -ge $MaxMatchedEvents) {
                    $limitReached = $true
                    break
                }

                $prov = if ($null -ne $ev.ProviderName) { [string]$ev.ProviderName } else { '' }
                $provId = if ($null -ne $ev.ProviderId) { ('{' + $ev.ProviderId.ToString().ToLowerInvariant() + '}') } else { '' }
                $lbGuidLowerReader = '{' + (($script:LumaBridgeDriverConstants.LumaBridgeTraceProviderGuid -replace '[{}]', '').ToLowerInvariant()) + '}'
                if ([string]::IsNullOrWhiteSpace($prov) -and ($provId -ieq $lbGuidLowerReader)) {
                    $prov = 'LumaBridgeIddDriver'
                }

                $evMsg = ''
                try {
                    $desc = $ev.FormatDescription()
                    if (-not [string]::IsNullOrWhiteSpace($desc)) {
                        $evMsg = ($desc -replace '\r?\n', ' ').Trim()
                    }
                }
                catch {
                    $evMsg = ''
                }

                $evTime = if ($null -ne $ev.TimeCreated) { $ev.TimeCreated.ToUniversalTime().ToString('o') } else { $null }
                $evLevel = if ($null -ne $ev.LevelDisplayName) { [string]$ev.LevelDisplayName } else { [string]$ev.Level }

                $propValues = New-Object System.Collections.Generic.List[string]
                if ($null -ne $ev.Properties) {
                    foreach ($p in $ev.Properties) {
                        if ($null -ne $p -and $null -ne $p.Value) {
                            $propValues.Add([string]$p.Value)
                        }
                        else {
                            $propValues.Add('')
                        }
                    }
                }

                if ([string]::IsNullOrWhiteSpace($evMsg) -and ($prov -ieq 'LumaBridgeIddDriver')) {
                    if ($propValues.Count -eq 8 -and ($propValues[0] -in @('INFO', 'WARN', 'ERROR'))) {
                        $statusFmt = Format-LumaBridgeNtStatusHex -StatusValue $propValues[4]
                        if ([string]::IsNullOrWhiteSpace($statusFmt)) { $statusFmt = [string]$propValues[4] }
                        $evMsg = ('[LB-DRIVER] [{0}] pid={1} tid={2} stage={3} status={4} state={5} lastOk={6} msg="{7}"' -f `
                            $propValues[0], $propValues[1], $propValues[2], $propValues[3], $statusFmt, $propValues[5], $propValues[6], $propValues[7])
                    }
                    elseif ($propValues.Count -gt 0) {
                        $evMsg = ('[LB-DRIVER] [METRICS/ETL] stage={0} fields={1}' -f $propValues[0], $propValues.Count)
                    }
                }

                $matched.Add([pscustomobject]@{
                    TimeCreated  = $evTime
                    ProviderName = $prov
                    ProviderId   = $provId
                    Id           = [int]$ev.Id
                    LevelDisplay = $evLevel
                    ProcessId    = $ev.ProcessId
                    ThreadId     = $ev.ThreadId
                    Message      = $evMsg
                    Properties   = @($propValues.ToArray())
                })
            }
            finally {
                $ev.Dispose()
            }
        }
    }
    finally {
        if ($null -ne $reader) {
            $reader.Dispose()
        }
    }

    return [pscustomobject]@{
        Events       = @($matched.ToArray())
        LimitReached = $limitReached
    }
}

function Get-LumaBridgeEtlEventSummary {
    [CmdletBinding()]
    param(
        [string]$EtlPath,

        [string[]]$ProviderGuids = @(),

        [string[]]$ProviderNames = @(),

        [Nullable[DateTime]]$StartTimeUtc = $null,

        [Nullable[DateTime]]$EndTimeUtc = $null,

        [Nullable[int]]$ProcessId = $null,

        [Alias('MaxEvents')]
        [ValidateRange(1, 50000)]
        [int]$MaxMatchedEvents = 500,

        [switch]$ExcludeHighVolumeGraphics
    )

    $excludeHighVol = if ($PSBoundParameters.ContainsKey('ExcludeHighVolumeGraphics')) {
        [bool]$ExcludeHighVolumeGraphics
    }
    else {
        (@($ProviderGuids).Count -eq 0 -and @($ProviderNames).Count -eq 0)
    }

    if ([string]::IsNullOrWhiteSpace($EtlPath) -or -not (Test-Path -LiteralPath $EtlPath -PathType Leaf)) {
        return [pscustomobject]@{
            EtlPath               = $EtlPath
            Exists                = $false
            EventCount            = 0
            MatchedEventCount     = 0
            MatchedLimitReached   = $false
            FilteredOutHighVolume = $excludeHighVol
            XPathUsed             = ''
            TraceStats            = $null
            CircularWrapWarning   = $null
            LumaBridgeEvents      = @()
            Providers             = @()
            Events                = @()
            Error                 = 'ETL file not found.'
        }
    }

    $xpath = Get-LumaBridgeEtlXPathQuery `
        -ProviderGuids $ProviderGuids `
        -ProviderNames $ProviderNames `
        -StartTimeUtc $StartTimeUtc `
        -EndTimeUtc $EndTimeUtc `
        -ProcessId $ProcessId `
        -ExcludeHighVolumeGraphics:$excludeHighVol

    $traceStats = Get-LumaBridgeEtlTraceStats -EtlPath $EtlPath
    $events = @()
    $limitReached = $false
    $err = ''

    try {
        $readOut = Invoke-LumaBridgeEtlXPathReader -EtlPath $EtlPath -XPath $xpath -MaxMatchedEvents $MaxMatchedEvents
        $events = @($readOut.Events)
        $limitReached = [bool]$readOut.LimitReached
    }
    catch {
        $err = $_.Exception.Message
    }

    $lbGuidLower = '{' + (($script:LumaBridgeDriverConstants.LumaBridgeTraceProviderGuid -replace '[{}]', '').ToLowerInvariant()) + '}'
    $lbEvents = @($events | Where-Object {
        $_.ProviderName -ieq 'LumaBridgeIddDriver' -or
        (($_.PSObject.Properties.Name -contains 'ProviderId') -and ($_.ProviderId -ieq $lbGuidLower)) -or
        $_.Message -match '\[LB-DRIVER\]'
    })

    $targetedLumaBridgeQueryUsed = $false
    if ($limitReached -and (@($lbEvents).Count -eq 0) -and (@($ProviderGuids).Count -eq 0) -and (@($ProviderNames).Count -eq 0) -and [string]::IsNullOrEmpty($err)) {
        $targetedLumaBridgeQueryUsed = $true
        $lbTargetedXPath = Get-LumaBridgeEtlXPathQuery `
            -ProviderGuids @($script:LumaBridgeDriverConstants.LumaBridgeTraceProviderGuid) `
            -StartTimeUtc $StartTimeUtc `
            -EndTimeUtc $EndTimeUtc `
            -ProcessId $ProcessId
        try {
            $targetedOut = Invoke-LumaBridgeEtlXPathReader -EtlPath $EtlPath -XPath $lbTargetedXPath -MaxMatchedEvents $MaxMatchedEvents
            $recovered = @($targetedOut.Events)
            if ($recovered.Count -gt 0) {
                $merged = New-Object System.Collections.Generic.List[object]
                $seenKeys = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
                foreach ($existingEv in @($events)) {
                    $merged.Add($existingEv)
                    $t = if ($existingEv.PSObject.Properties.Name -contains 'TimeCreated') { [string]$existingEv.TimeCreated } else { '' }
                    $p = if ($existingEv.PSObject.Properties.Name -contains 'ProviderId') { [string]$existingEv.ProviderId } else { '' }
                    $i = if ($existingEv.PSObject.Properties.Name -contains 'Id') { [string]$existingEv.Id } else { '' }
                    $th = if ($existingEv.PSObject.Properties.Name -contains 'ThreadId') { [string]$existingEv.ThreadId } else { '' }
                    $null = $seenKeys.Add(("{0}|{1}|{2}|{3}" -f $t, $p, $i, $th))
                }
                foreach ($recEv in $recovered) {
                    $t = if ($recEv.PSObject.Properties.Name -contains 'TimeCreated') { [string]$recEv.TimeCreated } else { '' }
                    $p = if ($recEv.PSObject.Properties.Name -contains 'ProviderId') { [string]$recEv.ProviderId } else { '' }
                    $i = if ($recEv.PSObject.Properties.Name -contains 'Id') { [string]$recEv.Id } else { '' }
                    $th = if ($recEv.PSObject.Properties.Name -contains 'ThreadId') { [string]$recEv.ThreadId } else { '' }
                    $key = "{0}|{1}|{2}|{3}" -f $t, $p, $i, $th
                    if (-not $seenKeys.Contains($key)) {
                        $null = $seenKeys.Add($key)
                        $merged.Add($recEv)
                    }
                }
                $events = @($merged.ToArray())
                $lbEvents = @($events | Where-Object {
                    $_.ProviderName -ieq 'LumaBridgeIddDriver' -or
                    (($_.PSObject.Properties.Name -contains 'ProviderId') -and ($_.ProviderId -ieq $lbGuidLower)) -or
                    $_.Message -match '\[LB-DRIVER\]'
                })
            }
        }
        catch {
            if ([string]::IsNullOrEmpty($err)) {
                $err = $_.Exception.Message
            }
        }
    }

    $providerCounts = @($events | Group-Object -Property {
        if (-not [string]::IsNullOrWhiteSpace($_.ProviderName)) { $_.ProviderName }
        elseif (($_.PSObject.Properties.Name -contains 'ProviderId') -and ($_.ProviderId -ieq $lbGuidLower)) { 'LumaBridgeIddDriver' }
        elseif (($_.PSObject.Properties.Name -contains 'ProviderId') -and -not [string]::IsNullOrWhiteSpace($_.ProviderId)) { $_.ProviderId }
        else { 'ClassicOrWpp' }
    } | ForEach-Object {
        [pscustomobject]@{
            ProviderName = $_.Name
            Count        = $_.Count
        }
    })

    $wrapWarning = if ($null -ne $traceStats) { $traceStats.CircularWrapWarning } else { $null }

    return [pscustomobject]@{
        EtlPath                     = $EtlPath
        Exists                      = $true
        EventCount                  = $events.Count
        MatchedEventCount           = $events.Count
        MatchedLimitReached         = $limitReached
        TargetedLumaBridgeQueryUsed = $targetedLumaBridgeQueryUsed
        FilteredOutHighVolume       = $excludeHighVol
        XPathUsed                   = $xpath
        TraceStats                  = $traceStats
        CircularWrapWarning         = $wrapWarning
        LumaBridgeEvents            = $lbEvents
        Providers                   = $providerCounts
        Events                      = $events
        Error                       = $err
    }
}

function Initialize-LumaBridgeWppTmfCache {
    [CmdletBinding()]
    param(
        [string]$SymbolCacheDir,

        [string]$TmfCacheDir,

        [string[]]$Binaries = @(
            (Join-Path -Path $env:SystemRoot -ChildPath 'System32\drivers\UMDF\IddCx.dll'),
            (Join-Path -Path $env:SystemRoot -ChildPath 'System32\WUDFx02000.dll')
        ),

        [string]$SymbolServerUrl = 'https://msdl.microsoft.com/download/symbols',

        [switch]$SkipSymbolDownload,

        [switch]$DryRun
    )

    if ([string]::IsNullOrWhiteSpace($SymbolCacheDir)) {
        $baseTmp = [System.IO.Path]::GetTempPath()
        $SymbolCacheDir = Join-Path -Path $baseTmp -ChildPath 'LumaBridgeSymCache'
    }
    if ([string]::IsNullOrWhiteSpace($TmfCacheDir)) {
        $baseTmp = [System.IO.Path]::GetTempPath()
        $TmfCacheDir = Join-Path -Path $baseTmp -ChildPath 'LumaBridgeTmfCache'
    }

    $symchkPath = Get-LumaBridgeWdkToolPath -ToolName 'symchk.exe'
    $tracepdbPath = Get-LumaBridgeWdkToolPath -ToolName 'tracepdb.exe'
    $errors = New-Object System.Collections.Generic.List[string]
    $executedCommands = New-Object System.Collections.Generic.List[string]

    if (-not $DryRun) {
        if (-not (Test-Path -LiteralPath $SymbolCacheDir)) { $null = New-Item -Path $SymbolCacheDir -ItemType Directory -Force }
        if (-not (Test-Path -LiteralPath $TmfCacheDir)) { $null = New-Item -Path $TmfCacheDir -ItemType Directory -Force }
    }

    if (-not $SkipSymbolDownload) {
        if ([string]::IsNullOrWhiteSpace($symchkPath)) {
            $errors.Add('symchk.exe not found under Windows Kits\10\Debuggers\x64.')
        }
        else {
            foreach ($bin in @($Binaries)) {
                if ([string]::IsNullOrWhiteSpace($bin)) { continue }
                if (-not $DryRun -and -not (Test-Path -LiteralPath $bin -PathType Leaf)) {
                    $errors.Add(("Binary not found for symbol check: {0}" -f $bin))
                    continue
                }
                $symSpec = "srv*{0}*{1}" -f $SymbolCacheDir, $SymbolServerUrl
                $symArgs = @('/if', $bin, '/s', $symSpec, '/op', '/os')
                try {
                    $null = Invoke-LumaBridgeExternalCommand -FilePath $symchkPath -Arguments $symArgs -DryRun:$DryRun
                    $executedCommands.Add(("{0} {1}" -f $symchkPath, ($symArgs -join ' ')))
                }
                catch {
                    $errors.Add($_.Exception.Message)
                }
            }
        }
    }

    $pdbFiles = @(if (Test-Path -LiteralPath $SymbolCacheDir) {
        Get-ChildItem -LiteralPath $SymbolCacheDir -Recurse -File -Filter '*.pdb' -ErrorAction SilentlyContinue
    })

    if ([string]::IsNullOrWhiteSpace($tracepdbPath)) {
        $errors.Add('tracepdb.exe not found under Windows Kits\10\bin.')
    }
    elseif ($DryRun) {
        $executedCommands.Add(("{0} -f <cached_pdb_file> -p {1}" -f $tracepdbPath, $TmfCacheDir))
    }
    else {
        foreach ($pdb in $pdbFiles) {
            $tpArgs = @('-f', $pdb.FullName, '-p', $TmfCacheDir)
            try {
                $null = Invoke-LumaBridgeExternalCommand -FilePath $tracepdbPath -Arguments $tpArgs
                $executedCommands.Add(("{0} {1}" -f $tracepdbPath, ($tpArgs -join ' ')))
            }
            catch {
                $errors.Add($_.Exception.Message)
            }
        }
    }

    $tmfFiles = @(if (Test-Path -LiteralPath $TmfCacheDir) {
        Get-ChildItem -LiteralPath $TmfCacheDir -File -Filter '*.tmf' -ErrorAction SilentlyContinue
    })

    return [pscustomobject]@{
        DryRun           = [bool]$DryRun
        SymbolCacheDir   = $SymbolCacheDir
        TmfCacheDir      = $TmfCacheDir
        PdbCount         = @($pdbFiles).Count
        TmfCount         = @($tmfFiles).Count
        ExecutedCommands = @($executedCommands.ToArray())
        Errors           = @($errors.ToArray())
    }
}

function Invoke-LumaBridgeWppEtlDecode {
    [CmdletBinding()]
    param(
        [string]$EtlPath,

        [string]$TmfCacheDir,

        [string]$SymbolCacheDir,

        [string]$SymbolServerUrl = 'https://msdl.microsoft.com/download/symbols',

        [string]$OutputPath,

        [string]$ExistingTraceFmtTextPath,

        [Nullable[int]]$ProcessId = $null,

        [string[]]$ExcludeProviders = @('Microsoft-Windows-DxgKrnl', 'Microsoft-Windows-Watchdog-Events'),

        [ValidateRange(1, 50000)]
        [int]$MaxMatchedLines = 500,

        [switch]$SkipSymbolServer,

        [switch]$DryRun
    )

    if ([string]::IsNullOrWhiteSpace($TmfCacheDir)) {
        $TmfCacheDir = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath 'LumaBridgeTmfCache'
    }
    if ([string]::IsNullOrWhiteSpace($SymbolCacheDir)) {
        $SymbolCacheDir = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath 'LumaBridgeSymCache'
    }

    $tracefmtPath = Get-LumaBridgeWdkToolPath -ToolName 'tracefmt.exe'
    if ($DryRun) {
        $cmdPreview = if ([string]::IsNullOrWhiteSpace($tracefmtPath)) { 'tracefmt.exe' } else { $tracefmtPath }
        return [pscustomobject]@{
            DryRun            = $true
            EtlPath           = $EtlPath
            TmfCacheDir       = $TmfCacheDir
            PlannedCommand    = ("{0} {1} -p {2} -o <temp_stream_txt> -nosummary" -f $cmdPreview, $EtlPath, $TmfCacheDir)
            OutputPath        = $OutputPath
            MatchedLineCount  = 0
            MatchedLines      = @()
            IddCxWppLines     = @()
            ProviderCounts    = @()
            TotalScannedLines = 0
            Error             = ''
        }
    }

    $sourceTextPath = $null
    $cleanupTemp = $false
    $traceStats = $null

    if (-not [string]::IsNullOrWhiteSpace($ExistingTraceFmtTextPath)) {
        if (-not (Test-Path -LiteralPath $ExistingTraceFmtTextPath -PathType Leaf)) {
            return [pscustomobject]@{
                DryRun            = $false
                EtlPath           = $EtlPath
                Exists            = $false
                TotalScannedLines = 0
                ProviderCounts    = @()
                MatchedLineCount  = 0
                MatchedLines      = @()
                IddCxWppLines     = @()
                OutputPath        = $OutputPath
                Error             = ("ExistingTraceFmtTextPath not found: {0}" -f $ExistingTraceFmtTextPath)
            }
        }
        $sourceTextPath = $ExistingTraceFmtTextPath
    }
    else {
        if ([string]::IsNullOrWhiteSpace($EtlPath) -or -not (Test-Path -LiteralPath $EtlPath -PathType Leaf)) {
            return [pscustomobject]@{
                DryRun            = $false
                EtlPath           = $EtlPath
                Exists            = $false
                TotalScannedLines = 0
                ProviderCounts    = @()
                MatchedLineCount  = 0
                MatchedLines      = @()
                IddCxWppLines     = @()
                OutputPath        = $OutputPath
                Error             = 'ETL file not found.'
            }
        }

        $traceStats = Get-LumaBridgeEtlTraceStats -EtlPath $EtlPath
        if ([string]::IsNullOrWhiteSpace($tracefmtPath)) {
            return [pscustomobject]@{
                DryRun            = $false
                EtlPath           = $EtlPath
                Exists            = $true
                TotalScannedLines = 0
                ProviderCounts    = @()
                MatchedLineCount  = 0
                MatchedLines      = @()
                IddCxWppLines     = @()
                OutputPath        = $OutputPath
                Error             = 'tracefmt.exe not found under Windows Kits\10\bin.'
            }
        }

        $sourceTextPath = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath ("lb_tracefmt_{0}.txt" -f ([guid]::NewGuid().ToString('N')))
        $cleanupTemp = $true
        $tfArgs = @($EtlPath, '-p', $TmfCacheDir)
        if (-not $SkipSymbolServer) {
            $tfArgs += @('-r', ("srv*{0}*{1}" -f $SymbolCacheDir, $SymbolServerUrl))
        }
        $tfArgs += @('-o', $sourceTextPath, '-nosummary')

        $prevEap = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        try {
            $null = & $tracefmtPath @tfArgs 2>&1
            if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $sourceTextPath -PathType Leaf)) {
                return [pscustomobject]@{
                    DryRun            = $false
                    EtlPath           = $EtlPath
                    Exists            = $true
                    TotalScannedLines = 0
                    ProviderCounts    = @()
                    MatchedLineCount  = 0
                    MatchedLines      = @()
                    IddCxWppLines     = @()
                    OutputPath        = $OutputPath
                    Error             = ("tracefmt.exe exited with code {0}." -f $LASTEXITCODE)
                }
            }
        }
        finally {
            $ErrorActionPreference = $prevEap
        }
    }

    $totalLines = 0
    $providerMap = @{}
    $matchedLines = New-Object System.Collections.Generic.List[string]
    $iddCxLines = New-Object System.Collections.Generic.List[string]
    $excludedSet = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($ex in @($ExcludeProviders)) {
        if (-not [string]::IsNullOrWhiteSpace($ex)) { $null = $excludedSet.Add($ex.Trim()) }
    }

    try {
        foreach ($line in [System.IO.File]::ReadLines($sourceTextPath)) {
            if ([string]::IsNullOrWhiteSpace($line)) { continue }
            ++$totalLines

            $prov = ''
            $linePid = $null
            if ($line -match '^\[[^\]]+\](?<PidHex>[0-9A-Fa-f]+)\.[0-9A-Fa-f]+::[0-9/:-]+\.[0-9]+\s+\[(?<Prov>[^\]]+)\]') {
                $linePid = [Convert]::ToInt32($matches['PidHex'], 16)
                $prov = $matches['Prov'].Trim()
            }
            elseif ($line -match '^\s*(?:Unknown|Invalid)\(') {
                continue
            }

            $provKey = if (-not [string]::IsNullOrWhiteSpace($prov)) { $prov } else { 'Other' }
            if (-not $providerMap.ContainsKey($provKey)) { $providerMap[$provKey] = 0 }
            $providerMap[$provKey] = $providerMap[$provKey] + 1

            if ($excludedSet.Contains($provKey)) {
                continue
            }

            if ($null -ne $ProcessId -and $null -ne $linePid -and $linePid -ne ([int]$ProcessId)) {
                continue
            }

            if ($matchedLines.Count -lt $MaxMatchedLines) {
                $matchedLines.Add($line)
            }
            if ($line -match '(\[cx\]|\[IddCx\]|LumaBridge|0xc000009e)') {
                $iddCxLines.Add($line)
            }
        }
    }
    finally {
        if ($cleanupTemp -and -not [string]::IsNullOrWhiteSpace($sourceTextPath)) {
            Remove-Item -LiteralPath $sourceTextPath -Force -ErrorAction SilentlyContinue
        }
    }

    $providerCounts = @($providerMap.GetEnumerator() | Sort-Object -Property Value -Descending | ForEach-Object {
        [pscustomobject]@{
            ProviderName = $_.Key
            Count        = $_.Value
        }
    })

    $payload = [pscustomobject]@{
        DryRun              = $false
        EtlPath             = $EtlPath
        Exists              = $true
        TmfCacheDir         = $TmfCacheDir
        TotalScannedLines   = $totalLines
        ProviderCounts      = $providerCounts
        MatchedLineCount    = $matchedLines.Count
        MatchedLines        = @($matchedLines.ToArray())
        IddCxWppLines       = @($iddCxLines.ToArray())
        TraceStats          = $traceStats
        CircularWrapWarning = if ($null -ne $traceStats) { $traceStats.CircularWrapWarning } else { $null }
        OutputPath          = $OutputPath
        Error               = ''
    }

    if (-not [string]::IsNullOrWhiteSpace($OutputPath)) {
        $parent = Split-Path -Path $OutputPath -Parent
        if (-not [string]::IsNullOrWhiteSpace($parent) -and -not (Test-Path -LiteralPath $parent)) {
            $null = New-Item -Path $parent -ItemType Directory -Force
        }
        $payload | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $OutputPath -Encoding UTF8
    }

    return $payload
}

function Get-LumaBridgeDriverTraceStageSummary {
    [CmdletBinding()]
    param(
        [string[]]$TraceLines = @(),

        $StartupDiagnostics = $null,

        [object[]]$EtlEvents = @()
    )

    $records = New-Object System.Collections.Generic.List[object]
    $sourcesUsed = New-Object System.Collections.Generic.List[string]

    foreach ($line in @($TraceLines)) {
        if ([string]::IsNullOrWhiteSpace($line) -or ($line -notmatch '\[LB-DRIVER\]') -or ($line -match '\[LB-DRIVER\]\s+\[METRICS\]')) {
            continue
        }

        if ($line -match '\[LB-DRIVER\]\s+\[(?<Level>[^\]]+)\].*?stage=(?<Stage>\S+)\s+status=(?<Status>0x[0-9A-Fa-f]+)\s+state=(?<State>\S+)(?:\s+lastOk=(?<LastOk>\S+))?(?:\s+msg="(?<Msg>[^"]*)")?') {
            $pidVal = if ($line -match '\bpid=(?<Pid>\d+)\b') { [int]$matches['Pid'] } else { $null }
            $tidVal = if ($line -match '\btid=(?<Tid>\d+)\b') { [int]$matches['Tid'] } else { $null }
            $records.Add([pscustomobject]@{
                Source              = 'DebugView'
                Level               = $matches['Level']
                ProcessId           = $pidVal
                ThreadId            = $tidVal
                Stage               = $matches['Stage']
                StatusHex           = Format-LumaBridgeNtStatusHex -StatusValue $matches['Status']
                LifecycleState      = $matches['State']
                LastSuccessfulStage = if ($matches.ContainsKey('LastOk') -and -not [string]::IsNullOrWhiteSpace($matches['LastOk'])) { $matches['LastOk'] } else { $null }
                Message             = if ($matches.ContainsKey('Msg')) { $matches['Msg'] } else { '' }
            })
        }
    }

    if ($records.Count -gt 0) {
        $sourcesUsed.Add('DebugView')
    }

    $lbGuidLowerStage = '{' + (($script:LumaBridgeDriverConstants.LumaBridgeTraceProviderGuid -replace '[{}]', '').ToLowerInvariant()) + '}'
    $etwAdded = 0
    foreach ($ev in @($EtlEvents)) {
        if ($null -eq $ev) { continue }
        $prov = if ($ev.PSObject.Properties.Name -contains 'ProviderName') { [string]$ev.ProviderName } else { '' }
        $evProvId = if ($ev.PSObject.Properties.Name -contains 'ProviderId') { [string]$ev.ProviderId } else { '' }
        if (($prov -ine 'LumaBridgeIddDriver') -and ($evProvId -ine $lbGuidLowerStage)) { continue }

        $props = if ($ev.PSObject.Properties.Name -contains 'Properties') { @($ev.Properties) } else { @() }
        $props = @($props)
        if ($props.Count -eq 8 -and ([string]$props[0] -in @('INFO', 'WARN', 'ERROR'))) {
            ++$etwAdded
            $records.Add([pscustomobject]@{
                Source              = 'TraceLoggingEtl'
                Level               = [string]$props[0]
                ProcessId           = $props[1]
                ThreadId            = $props[2]
                Stage               = [string]$props[3]
                StatusHex           = Format-LumaBridgeNtStatusHex -StatusValue $props[4]
                LifecycleState      = [string]$props[5]
                LastSuccessfulStage = [string]$props[6]
                Message             = [string]$props[7]
            })
        }
    }

    if ($etwAdded -gt 0) {
        $sourcesUsed.Add('TraceLoggingEtl')
    }

    $driverEntryReached = $false
    $lastStage = $null
    $lastSuccessfulStage = $null
    $lastStatusHex = $null
    $firstFailureStage = $null
    $firstFailureStatusHex = $null

    foreach ($rec in $records) {
        if ($rec.Stage -in @('DriverEntry', 'DeviceAdd', 'DeviceInitConfig', 'WdfDeviceCreate', 'IddCxDeviceInitialize', 'DeviceD0Entry', 'AdapterInitAsync', 'AdapterInitFinished')) {
            $driverEntryReached = $true
        }

        $lastStage = $rec.Stage
        $lastStatusHex = $rec.StatusHex

        $isFailureStatus = $false
        if (-not [string]::IsNullOrWhiteSpace($rec.StatusHex) -and $rec.StatusHex -match '^0x([0-9A-Fa-f]{8})$') {
            $u32 = [Convert]::ToUInt32($matches[1], 16)
            $isFailureStatus = ($u32 -ge 0x80000000L)
        }

        if ($rec.Level -eq 'ERROR' -or $isFailureStatus) {
            if ($null -eq $firstFailureStage) {
                $firstFailureStage = $rec.Stage
                $firstFailureStatusHex = $rec.StatusHex
            }
            if (-not [string]::IsNullOrWhiteSpace($rec.LastSuccessfulStage) -and $rec.LastSuccessfulStage -ne 'None') {
                $lastSuccessfulStage = $rec.LastSuccessfulStage
            }
        }
        else {
            if (-not [string]::IsNullOrWhiteSpace($rec.LastSuccessfulStage) -and $rec.LastSuccessfulStage -ne 'None') {
                $lastSuccessfulStage = $rec.LastSuccessfulStage
            }
            elseif ($rec.Stage -ne 'None') {
                $lastSuccessfulStage = $rec.Stage
            }
        }
    }

    if ($null -ne $StartupDiagnostics) {
        $sourcesUsed.Add('RegistryBreadcrumb')
        $regLastStage = if ($StartupDiagnostics.PSObject.Properties.Name -contains 'LastStage') { $StartupDiagnostics.LastStage } else { $null }
        $regLastOk = if ($StartupDiagnostics.PSObject.Properties.Name -contains 'LastSuccessfulStage') { $StartupDiagnostics.LastSuccessfulStage } else { $null }
        $regLastStatusHex = if ($StartupDiagnostics.PSObject.Properties.Name -contains 'LastStatusHex') { $StartupDiagnostics.LastStatusHex } else { $null }
        $regErrStage = if ($StartupDiagnostics.PSObject.Properties.Name -contains 'LastErrorStage') { $StartupDiagnostics.LastErrorStage } else { $null }
        $regErrStatusHex = if ($StartupDiagnostics.PSObject.Properties.Name -contains 'LastErrorStatusHex') { $StartupDiagnostics.LastErrorStatusHex } else { $null }

        if (-not [string]::IsNullOrWhiteSpace($regLastOk) -and $regLastOk -ne 'None') {
            $driverEntryReached = $true
        }
        if ([string]::IsNullOrWhiteSpace($lastStage)) { $lastStage = $regLastStage }
        if ([string]::IsNullOrWhiteSpace($lastSuccessfulStage) -or $lastSuccessfulStage -eq 'None') { $lastSuccessfulStage = $regLastOk }
        if ([string]::IsNullOrWhiteSpace($lastStatusHex)) { $lastStatusHex = $regLastStatusHex }
        if ([string]::IsNullOrWhiteSpace($firstFailureStage) -and -not [string]::IsNullOrWhiteSpace($regErrStage) -and $regErrStage -ne 'None') {
            $firstFailureStage = $regErrStage
            $firstFailureStatusHex = $regErrStatusHex
        }
    }

    return [pscustomobject]@{
        DriverEntryReached    = $driverEntryReached
        LastStage             = $lastStage
        LastSuccessfulStage   = $lastSuccessfulStage
        LastStatusHex         = $lastStatusHex
        FirstFailureStage     = $firstFailureStage
        FirstFailureStatusHex = $firstFailureStatusHex
        StageRecordCount      = $records.Count
        StageRecords          = @($records.ToArray())
        SourcesUsed           = @($sourcesUsed.ToArray() | Select-Object -Unique)
    }
}

Export-ModuleMember -Function @(
    'Get-LumaBridgeDriverConstants',
    'Get-LumaBridgeRepoRoot',
    'Get-LumaBridgePackageDirectory',
    'Get-LumaBridgeDefaultStagingDirectory',
    'Assert-LumaBridgeIsolatedStagingDirectory',
    'Get-LumaBridgeWdkToolPath',
    'Get-LumaBridgeHostSecurityState',
    'Find-LumaBridgeSigningCertificate',
    'New-LumaBridgeSigningCertificate',
    'Export-LumaBridgeCertificateFile',
    'Remove-LumaBridgeCertificateFromStores',
    'Test-LumaBridgeIsAdministrator',
    'Assert-LumaBridgeAdministrator',
    'Confirm-LumaBridgeAction',
    'Invoke-LumaBridgeExternalCommand',
    'Invoke-LumaBridgeHostProcess',
    'Format-LumaBridgeNtStatusHex',
    'Get-LumaBridgeDeviceParametersRegistryPath',
    'Get-LumaBridgeDeviceEnableVirtualMonitor',
    'Set-LumaBridgeDeviceEnableVirtualMonitor',
    'Get-LumaBridgeDeviceEnableFrameExtraction',
    'Set-LumaBridgeDeviceEnableFrameExtraction',
    'Get-LumaBridgeDeviceEnableGpuSharedTransport',
    'Set-LumaBridgeDeviceEnableGpuSharedTransport',
    'Get-LumaBridgeDeviceAuthorizedHostUserSid',
    'Set-LumaBridgeDeviceAuthorizedHostUserSid',
    'Get-LumaBridgeDeviceStartupDiagnostics',
    'Get-LumaBridgeDevicePropertyData',
    'Get-LumaBridgePnpInstances',
    'Get-LumaBridgeInfDriverVerMetadata',
    'Get-LumaBridgeInfDriverVersion',
    'Test-LumaBridgeDeviceDriverBinding',
    'Invoke-LumaBridgePnpUtilEnumDriversXml',
    'Get-LumaBridgeDriverStorePackages',
    'Test-LumaBridgeCatalogFileHashes',
    'Get-LumaBridgeWinVerifyTrustStatus',
    'Test-LumaBridgeCatalogCmsSignature',
    'Invoke-LumaBridgeSigntoolCatalogVerify',
    'Test-LumaBridgePackageArtifacts',
    'Get-LumaBridgeRawWudfProcesses',
    'Get-LumaBridgeWudfHostProcesses',
    'Get-LumaBridgeSetupApiLogExcerpt',
    'Get-LumaBridgeEventChannelStatus',
    'Get-LumaBridgeDiagnosticEvents',
    'Get-LumaBridgeCrashDumpInventory',
    'New-LumaBridgeEtwProviderFileContent',
    'Test-LumaBridgeEtwSessionProviders',
    'Get-LumaBridgeEtlTraceStats',
    'Get-LumaBridgeEtlXPathQuery',
    'Invoke-LumaBridgeEtlXPathReader',
    'Get-LumaBridgeEtlEventSummary',
    'Initialize-LumaBridgeWppTmfCache',
    'Invoke-LumaBridgeWppEtlDecode',
    'Get-LumaBridgeDriverTraceStageSummary'
)
