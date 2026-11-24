#ifndef WIN32_NO_STATUS
#define WIN32_NO_STATUS
#endif
#include <Windows.h>
#undef WIN32_NO_STATUS

#include <bcrypt.h>
#include <mscat.h>
#include <softpub.h>
#include <wincrypt.h>
#include <wintrust.h>

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "wintrust.lib")

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <map>
#include <string>
#include <vector>

namespace {

int g_TestsRun = 0;
int g_TestsFailed = 0;

void
CheckCondition(
    bool condition,
    const char* expression,
    int line
    ) noexcept
{
    if (!condition)
    {
        ++g_TestsFailed;
        std::printf("[FAIL] line %d: %s\n", line, expression);
    }
}

#define EXPECT_TRUE(expr) CheckCondition((expr), #expr, __LINE__)
#define EXPECT_EQ(actual, expected) CheckCondition(((actual) == (expected)), #actual " == " #expected, __LINE__)

struct InfDocument
{
    std::map<std::string, std::vector<std::string>> Sections;
    std::string RawText;
};

std::string
ToLowerAscii(
    std::string value
    )
{
    std::transform(
        value.begin(),
        value.end(),
        value.begin(),
        [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
    return value;
}

std::string
TrimAscii(
    const std::string& value
    )
{
    const char* whitespace = " \t\r\n";
    const size_t start = value.find_first_not_of(whitespace);
    if (start == std::string::npos)
    {
        return {};
    }
    const size_t end = value.find_last_not_of(whitespace);
    return value.substr(start, end - start + 1);
}

/// Strips inline INF comments outside double-quoted strings.
std::string
StripInfComment(
    const std::string& line
    )
{
    bool inQuotes = false;
    for (size_t i = 0; i < line.size(); ++i)
    {
        const char ch = line[i];
        if (ch == '"')
        {
            inQuotes = !inQuotes;
        }
        else if (ch == ';' && !inQuotes)
        {
            return line.substr(0, i);
        }
    }
    return line;
}

std::string
CollapseCommaWhitespace(
    const std::string& input
    )
{
    std::string out;
    out.reserve(input.size());
    bool inQuotes = false;
    for (size_t i = 0; i < input.size(); ++i)
    {
        const char ch = input[i];
        if (ch == '"')
        {
            inQuotes = !inQuotes;
            out.push_back(ch);
            continue;
        }

        if (!inQuotes && ch == ',')
        {
            while (!out.empty() && (out.back() == ' ' || out.back() == '\t'))
            {
                out.pop_back();
            }
            out.push_back(',');
            while (i + 1 < input.size() && (input[i + 1] == ' ' || input[i + 1] == '\t'))
            {
                ++i;
            }
            continue;
        }

        out.push_back(ch);
    }
    return out;
}

std::string
NormalizeInfAssignment(
    const std::string& raw
    )
{
    const size_t eqPos = raw.find('=');
    if (eqPos == std::string::npos)
    {
        return ToLowerAscii(CollapseCommaWhitespace(TrimAscii(raw)));
    }

    const std::string lhs = TrimAscii(raw.substr(0, eqPos));
    const std::string rhs = CollapseCommaWhitespace(TrimAscii(raw.substr(eqPos + 1)));
    return ToLowerAscii(lhs + "=" + rhs);
}

InfDocument
ParseInfText(
    const std::string& text
    )
{
    InfDocument doc{};
    doc.RawText = text;

    std::string currentSection;
    size_t pos = 0;
    while (pos <= text.size())
    {
        size_t lineEnd = text.find('\n', pos);
        if (lineEnd == std::string::npos)
        {
            lineEnd = text.size();
        }

        const std::string line = TrimAscii(StripInfComment(text.substr(pos, lineEnd - pos)));
        if (!line.empty())
        {
            if (line.front() == '[' && line.back() == ']' && line.size() > 2)
            {
                currentSection = ToLowerAscii(TrimAscii(line.substr(1, line.size() - 2)));
                (void)doc.Sections[currentSection];
            }
            else if (!currentSection.empty())
            {
                doc.Sections[currentSection].push_back(line);
            }
        }

        if (lineEnd == text.size())
        {
            break;
        }
        pos = lineEnd + 1;
    }

    return doc;
}

bool
ReadBinaryFile(
    const std::filesystem::path& path,
    std::vector<uint8_t>& outBytes
    )
{
    std::ifstream stream(path, std::ios::binary | std::ios::ate);
    if (!stream.is_open())
    {
        return false;
    }

    const std::streamsize size = stream.tellg();
    if (size < 0)
    {
        return false;
    }

    outBytes.resize(static_cast<size_t>(size));
    stream.seekg(0, std::ios::beg);
    if (size > 0 && !stream.read(reinterpret_cast<char*>(outBytes.data()), size))
    {
        return false;
    }
    return true;
}

bool
SectionHasNormalizedEntry(
    const InfDocument& doc,
    const std::string& sectionName,
    const std::string& expectedNormalized
    )
{
    const auto it = doc.Sections.find(ToLowerAscii(sectionName));
    if (it == doc.Sections.end())
    {
        return false;
    }

    const std::string target = NormalizeInfAssignment(expectedNormalized);
    for (const auto& entry : it->second)
    {
        if (NormalizeInfAssignment(entry) == target)
        {
            return true;
        }
    }
    return false;
}

std::string
FindSectionDirectiveValue(
    const InfDocument& doc,
    const std::string& sectionName,
    const std::string& keyName
    )
{
    const auto it = doc.Sections.find(ToLowerAscii(sectionName));
    if (it == doc.Sections.end())
    {
        return {};
    }

    const std::string targetKey = ToLowerAscii(keyName);
    for (const auto& entry : it->second)
    {
        const size_t eqPos = entry.find('=');
        if (eqPos == std::string::npos)
        {
            continue;
        }
        if (ToLowerAscii(TrimAscii(entry.substr(0, eqPos))) == targetKey)
        {
            return TrimAscii(entry.substr(eqPos + 1));
        }
    }
    return {};
}

std::vector<std::string>
ExtractReferencedPackageFiles(
    const InfDocument& doc
    )
{
    std::vector<std::string> files;

    const auto srcIt = doc.Sections.find("sourcedisksfiles");
    if (srcIt != doc.Sections.end())
    {
        for (const auto& line : srcIt->second)
        {
            const size_t eqPos = line.find('=');
            if (eqPos != std::string::npos)
            {
                const std::string fileName = TrimAscii(line.substr(0, eqPos));
                if (!fileName.empty())
                {
                    files.push_back(fileName);
                }
            }
        }
    }

    const auto copyIt = doc.Sections.find("umdrivercopy");
    if (copyIt != doc.Sections.end())
    {
        for (const auto& line : copyIt->second)
        {
            const size_t commaPos = line.find(',');
            const std::string fileName = TrimAscii((commaPos == std::string::npos) ? line : line.substr(0, commaPos));
            if (!fileName.empty())
            {
                files.push_back(fileName);
            }
        }
    }

    return files;
}

bool
IsValidUnsignedX64DriverDll(
    const std::vector<uint8_t>& bytes
    )
{
    if (bytes.size() < sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS64))
    {
        return false;
    }

    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(bytes.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0)
    {
        return false;
    }

    const size_t ntOffset = static_cast<size_t>(dos->e_lfanew);
    if (ntOffset > bytes.size() - sizeof(IMAGE_NT_HEADERS64))
    {
        return false;
    }

    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(bytes.data() + ntOffset);
    if (nt->Signature != IMAGE_NT_SIGNATURE ||
        nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 ||
        (nt->FileHeader.Characteristics & IMAGE_FILE_DLL) == 0 ||
        nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    {
        return false;
    }

    const auto& securityDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];
    return securityDir.VirtualAddress == 0 && securityDir.Size == 0;
}

std::string
WideToLowerAscii(
    const wchar_t* wide
    )
{
    if (wide == nullptr)
    {
        return {};
    }

    std::string out;
    for (const wchar_t* p = wide; *p != L'\0'; ++p)
    {
        if (*p > 0x7F)
        {
            out.push_back('?');
        }
        else
        {
            out.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(*p))));
        }
    }
    return out;
}

bool
IsFileUnsignedViaWinTrust(
    const std::filesystem::path& filePath
    )
{
    WINTRUST_FILE_INFO fileInfo{};
    fileInfo.cbStruct = sizeof(fileInfo);
    const std::wstring widePath = filePath.wstring();
    fileInfo.pcwszFilePath = widePath.c_str();

    WINTRUST_DATA trustData{};
    trustData.cbStruct = sizeof(trustData);
    trustData.dwUIChoice = WTD_UI_NONE;
    trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    trustData.dwUnionChoice = WTD_CHOICE_FILE;
    trustData.pFile = &fileInfo;
    trustData.dwStateAction = WTD_STATEACTION_VERIFY;
    trustData.dwProvFlags = WTD_SAFER_FLAG;

    GUID policyGuid = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    const LONG status = WinVerifyTrust(nullptr, &policyGuid, &trustData);

    trustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(nullptr, &policyGuid, &trustData);

    return status == TRUST_E_NOSIGNATURE || status == CRYPT_E_NO_SIGNER;
}

bool
IsUnsignedCatalogCtl(
    const std::filesystem::path& catPath
    )
{
    const std::wstring widePath = catPath.wstring();
    DWORD encoding = 0;
    DWORD contentType = 0;
    DWORD formatType = 0;
    HCRYPTMSG hMsg = nullptr;

    if (!CryptQueryObject(
            CERT_QUERY_OBJECT_FILE,
            widePath.c_str(),
            CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED | CERT_QUERY_CONTENT_FLAG_CTL,
            CERT_QUERY_FORMAT_FLAG_BINARY,
            0,
            &encoding,
            &contentType,
            &formatType,
            nullptr,
            &hMsg,
            nullptr))
    {
        return false;
    }

    DWORD signerCount = 0;
    if (hMsg != nullptr)
    {
        DWORD signerCountSize = sizeof(signerCount);
        const BOOL gotSigners = CryptMsgGetParam(
            hMsg,
            CMSG_SIGNER_COUNT_PARAM,
            0,
            &signerCount,
            &signerCountSize);
        CryptMsgClose(hMsg);
        if (!gotSigners || signerCount != 0)
        {
            return false;
        }
    }

    return IsFileUnsignedViaWinTrust(catPath);
}

bool
ComputeAuthenticodeSipHashSha256(
    HCATADMIN hCatAdmin,
    const std::filesystem::path& filePath,
    std::vector<uint8_t>& outDigest
    )
{
    const std::wstring widePath = filePath.wstring();
    HANDLE hFile = CreateFileW(
        widePath.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        return false;
    }

    DWORD hashSize = 0;
    (void)CryptCATAdminCalcHashFromFileHandle2(hCatAdmin, hFile, &hashSize, nullptr, 0);
    if (hashSize == 0 || GetLastError() != ERROR_INSUFFICIENT_BUFFER)
    {
        CloseHandle(hFile);
        return false;
    }

    outDigest.resize(hashSize);
    const BOOL ok = CryptCATAdminCalcHashFromFileHandle2(
        hCatAdmin,
        hFile,
        &hashSize,
        outDigest.data(),
        0);
    CloseHandle(hFile);
    if (!ok)
    {
        outDigest.clear();
        return false;
    }
    outDigest.resize(hashSize);
    return true;
}

bool
ValidateUnsignedCatalogForDirectory(
    const std::filesystem::path& catPath,
    const std::filesystem::path& packageRootDir
    )
{
    if (!std::filesystem::is_regular_file(catPath))
    {
        return false;
    }

    if (!IsUnsignedCatalogCtl(catPath))
    {
        return false;
    }

    std::wstring wideCatPath = catPath.wstring();
    HANDLE hCat = CryptCATOpen(wideCatPath.data(), CRYPTCAT_OPEN_EXISTING, 0, 0, 0);
    if (hCat == INVALID_HANDLE_VALUE)
    {
        return false;
    }

    bool hasWin11OsAttr = false;
    {
        CRYPTCATATTRIBUTE* attr = nullptr;
        while ((attr = CryptCATEnumerateCatAttr(hCat, attr)) != nullptr)
        {
            const std::string tagLower = WideToLowerAscii(attr->pwszReferenceTag);
            if ((tagLower == "os" || tagLower == "osattr") &&
                attr->pbValue != nullptr &&
                attr->cbValue >= sizeof(wchar_t))
            {
                const auto* wideVal = reinterpret_cast<const wchar_t*>(attr->pbValue);
                std::wstring osAttrWide(wideVal, attr->cbValue / sizeof(wchar_t));
                while (!osAttrWide.empty() && osAttrWide.back() == L'\0')
                {
                    osAttrWide.pop_back();
                }
                const std::string osAttr = WideToLowerAscii(osAttrWide.c_str());
                // Inf2Cat encodes catalog-level OS attribute for Windows 11 21H2/22H2/24H2+ x64.
                if (osAttr.find("_v100_x64_21h2") != std::string::npos &&
                    osAttr.find("_v100_x64_22h2") != std::string::npos &&
                    osAttr.find("_v100_x64_24h2") != std::string::npos &&
                    osAttr.find("19h1") == std::string::npos)
                {
                    hasWin11OsAttr = true;
                }
            }
        }
    }

    HCATADMIN hCatAdminSha256 = nullptr;
    HCATADMIN hCatAdminSha1 = nullptr;
    if (!CryptCATAdminAcquireContext2(
            &hCatAdminSha256,
            nullptr,
            BCRYPT_SHA256_ALGORITHM,
            nullptr,
            0) ||
        !CryptCATAdminAcquireContext2(
            &hCatAdminSha1,
            nullptr,
            BCRYPT_SHA1_ALGORITHM,
            nullptr,
            0))
    {
        if (hCatAdminSha256 != nullptr)
        {
            CryptCATAdminReleaseContext(hCatAdminSha256, 0);
        }
        if (hCatAdminSha1 != nullptr)
        {
            CryptCATAdminReleaseContext(hCatAdminSha1, 0);
        }
        CryptCATClose(hCat);
        return false;
    }

    std::vector<uint8_t> expectedDllSha256;
    std::vector<uint8_t> expectedInfSha256;
    std::vector<uint8_t> expectedDllSha1;
    std::vector<uint8_t> expectedInfSha1;
    const bool hashedAll =
        ComputeAuthenticodeSipHashSha256(
            hCatAdminSha256,
            packageRootDir / "LumaBridgeIddDriver.dll",
            expectedDllSha256) &&
        ComputeAuthenticodeSipHashSha256(
            hCatAdminSha256,
            packageRootDir / "LumaBridgeIddDriver.inf",
            expectedInfSha256) &&
        ComputeAuthenticodeSipHashSha256(
            hCatAdminSha1,
            packageRootDir / "LumaBridgeIddDriver.dll",
            expectedDllSha1) &&
        ComputeAuthenticodeSipHashSha256(
            hCatAdminSha1,
            packageRootDir / "LumaBridgeIddDriver.inf",
            expectedInfSha1);

    CryptCATAdminReleaseContext(hCatAdminSha256, 0);
    CryptCATAdminReleaseContext(hCatAdminSha1, 0);

    if (!hashedAll)
    {
        CryptCATClose(hCat);
        return false;
    }

    bool foundDllSha256 = false;
    bool foundInfSha256 = false;
    size_t memberCount = 0;

    CRYPTCATMEMBER* member = nullptr;
    while ((member = CryptCATEnumerateMember(hCat, member)) != nullptr)
    {
        ++memberCount;
        if (member->pIndirectData == nullptr ||
            member->pIndirectData->Digest.pbData == nullptr ||
            member->pIndirectData->Digest.cbData == 0 ||
            member->pIndirectData->DigestAlgorithm.pszObjId == nullptr)
        {
            CryptCATClose(hCat);
            return false;
        }

        const std::string algOid(member->pIndirectData->DigestAlgorithm.pszObjId);
        const bool isSha256 = (algOid == szOID_NIST_sha256);
        const bool isSha1 = (algOid == szOID_OIWSEC_sha1);
        if (!isSha256 && !isSha1)
        {
            CryptCATClose(hCat);
            return false;
        }

        const std::vector<uint8_t> memberDigest(
            member->pIndirectData->Digest.pbData,
            member->pIndirectData->Digest.pbData + member->pIndirectData->Digest.cbData);

        std::string memberFileName;
        CRYPTCATATTRIBUTE* memberAttr = nullptr;
        while ((memberAttr = CryptCATEnumerateAttr(hCat, member, memberAttr)) != nullptr)
        {
            if (WideToLowerAscii(memberAttr->pwszReferenceTag) == "file" &&
                memberAttr->pbValue != nullptr &&
                memberAttr->cbValue >= sizeof(wchar_t))
            {
                const auto* wideName = reinterpret_cast<const wchar_t*>(memberAttr->pbValue);
                std::wstring nameWide(wideName, memberAttr->cbValue / sizeof(wchar_t));
                while (!nameWide.empty() && nameWide.back() == L'\0')
                {
                    nameWide.pop_back();
                }
                memberFileName = WideToLowerAscii(nameWide.c_str());
                break;
            }
        }

        const std::string refTagLower = WideToLowerAscii(member->pwszReferenceTag);
        if (memberFileName == "lumabridgeidddriver.dll" ||
            refTagLower == "lumabridgeidddriver.dll")
        {
            const auto& expected = isSha256 ? expectedDllSha256 : expectedDllSha1;
            if (memberDigest != expected)
            {
                CryptCATClose(hCat);
                return false;
            }
            if (isSha256)
            {
                foundDllSha256 = true;
            }
        }
        else if (memberFileName == "lumabridgeidddriver.inf" ||
                 refTagLower == "lumabridgeidddriver.inf")
        {
            const auto& expected = isSha256 ? expectedInfSha256 : expectedInfSha1;
            if (memberDigest != expected)
            {
                CryptCATClose(hCat);
                return false;
            }
            if (isSha256)
            {
                foundInfSha256 = true;
            }
        }
        else
        {
            // Unexpected catalog member indicates stale or contaminated package directory.
            CryptCATClose(hCat);
            return false;
        }
    }

    CryptCATClose(hCat);
    return hasWin11OsAttr && memberCount >= 2 && foundDllSha256 && foundInfSha256;
}

bool
IsValidStampedDriverVer(
    const std::string& driverVer
    )
{
    // Expect stamped format: MM/DD/YYYY,H.M.S.MS (different from source placeholder).
    if (driverVer.empty() || driverVer == "07/01/2026,0.1.0.0")
    {
        return false;
    }

    const size_t commaPos = driverVer.find(',');
    if (commaPos == std::string::npos || commaPos < 8 || commaPos > 10)
    {
        return false;
    }

    const std::string datePart = driverVer.substr(0, commaPos);
    const std::string verPart = driverVer.substr(commaPos + 1);
    return std::count(datePart.begin(), datePart.end(), '/') == 2 &&
           std::count(verPart.begin(), verPart.end(), '.') == 3;
}

void
ValidateStampedInfDocument(
    const InfDocument& doc
    )
{
    const std::string lowerRaw = ToLowerAscii(doc.RawText);
    EXPECT_TRUE(lowerRaw.find("$arch$") == std::string::npos);
    EXPECT_TRUE(lowerRaw.find("$umdfversion$") == std::string::npos);
    EXPECT_TRUE(lowerRaw.find("$kmdfversion$") == std::string::npos);
    EXPECT_TRUE(lowerRaw.find("wudfupdate_") == std::string::npos);

    EXPECT_TRUE(SectionHasNormalizedEntry(doc, "Version", "Signature = \"$WINDOWS NT$\""));
    EXPECT_TRUE(SectionHasNormalizedEntry(doc, "Version", "Class = Display"));
    EXPECT_TRUE(SectionHasNormalizedEntry(doc, "Version", "ClassGuid = {4d36e968-e325-11ce-bfc1-08002be10318}"));
    EXPECT_TRUE(SectionHasNormalizedEntry(doc, "Version", "ClassVer = 2.0"));
    EXPECT_TRUE(SectionHasNormalizedEntry(doc, "Version", "Provider = %ManufacturerName%"));
    EXPECT_TRUE(SectionHasNormalizedEntry(doc, "Version", "CatalogFile = LumaBridgeIddDriver.cat"));
    EXPECT_TRUE(SectionHasNormalizedEntry(doc, "Version", "PnpLockdown = 1"));
    EXPECT_TRUE(IsValidStampedDriverVer(FindSectionDirectiveValue(doc, "Version", "DriverVer")));

    EXPECT_TRUE(SectionHasNormalizedEntry(doc, "Manufacturer", "%ManufacturerName% = Standard,NTamd64.10.0...22000"));
    EXPECT_TRUE(SectionHasNormalizedEntry(
        doc,
        "Standard.NTamd64.10.0...22000",
        "%LumaBridgeDeviceName% = LumaBridge_Install, Root\\LumaBridgeIddDriver"));

    EXPECT_TRUE(SectionHasNormalizedEntry(doc, "LumaBridge_Install.NT", "CopyFiles = UMDriverCopy"));
    EXPECT_TRUE(SectionHasNormalizedEntry(doc, "LumaBridge_Install.NT", "Include = wudfrd.inf"));
    EXPECT_TRUE(SectionHasNormalizedEntry(doc, "LumaBridge_Install.NT", "Needs = WUDFRD.NT"));

    EXPECT_TRUE(SectionHasNormalizedEntry(doc, "LumaBridge_Install.NT.hw", "AddReg = LumaBridge_HardwareDeviceSettings"));
    EXPECT_TRUE(SectionHasNormalizedEntry(doc, "LumaBridge_Install.NT.hw", "Include = wudfrd.inf"));
    EXPECT_TRUE(SectionHasNormalizedEntry(doc, "LumaBridge_Install.NT.hw", "Needs = WUDFRD.NT.HW"));

    EXPECT_TRUE(SectionHasNormalizedEntry(doc, "LumaBridge_Install.NT.Services", "Include = wudfrd.inf"));
    EXPECT_TRUE(SectionHasNormalizedEntry(doc, "LumaBridge_Install.NT.Services", "Needs = WUDFRD.NT.Services"));

    EXPECT_TRUE(SectionHasNormalizedEntry(
        doc,
        "LumaBridge_Install.NT.Wdf",
        "UmdfService = LumaBridgeIddDriver,LumaBridge_UMDF_Service"));
    EXPECT_TRUE(SectionHasNormalizedEntry(doc, "LumaBridge_Install.NT.Wdf", "UmdfServiceOrder = LumaBridgeIddDriver"));
    EXPECT_TRUE(SectionHasNormalizedEntry(
        doc,
        "LumaBridge_Install.NT.Wdf",
        "UmdfKernelModeClientPolicy = AllowKernelModeClients"));
    EXPECT_TRUE(SectionHasNormalizedEntry(
        doc,
        "LumaBridge_Install.NT.Wdf",
        "UmdfHostProcessSharing = ProcessSharingDisabled"));

    EXPECT_TRUE(SectionHasNormalizedEntry(doc, "LumaBridge_UMDF_Service", "UmdfLibraryVersion = 2.31.0"));
    EXPECT_TRUE(SectionHasNormalizedEntry(
        doc,
        "LumaBridge_UMDF_Service",
        "ServiceBinary = %13%\\LumaBridgeIddDriver.dll"));
    EXPECT_TRUE(SectionHasNormalizedEntry(doc, "LumaBridge_UMDF_Service", "UmdfExtensions = IddCx0102"));

    EXPECT_TRUE(SectionHasNormalizedEntry(
        doc,
        "LumaBridge_HardwareDeviceSettings",
        "HKR,,\"UpperFilters\",%REG_MULTI_SZ%,\"IndirectKmd\""));
    EXPECT_TRUE(SectionHasNormalizedEntry(
        doc,
        "LumaBridge_HardwareDeviceSettings",
        "HKR,\"WUDF\",\"DeviceGroupId\",%REG_SZ%,\"LumaBridgeIddGroup\""));
}

bool
ValidatePackageAndOutDirConsistency(
    const std::filesystem::path& configOutDir
    )
{
    const std::filesystem::path packageDir = configOutDir / "LumaBridgeIddDriver";
    if (!std::filesystem::is_directory(configOutDir) ||
        !std::filesystem::is_directory(packageDir))
    {
        return false;
    }

    const std::filesystem::path pkgDll = packageDir / "LumaBridgeIddDriver.dll";
    const std::filesystem::path pkgInf = packageDir / "LumaBridgeIddDriver.inf";
    const std::filesystem::path pkgCat = packageDir / "LumaBridgeIddDriver.cat";

    const std::filesystem::path outDll = configOutDir / "LumaBridgeIddDriver.dll";
    const std::filesystem::path outInf = configOutDir / "LumaBridgeIddDriver.inf";
    const std::filesystem::path outCat = configOutDir / "LumaBridgeIddDriver.cat";

    std::vector<uint8_t> pkgDllBytes;
    std::vector<uint8_t> outDllBytes;
    std::vector<uint8_t> pkgInfBytes;
    std::vector<uint8_t> outInfBytes;
    std::vector<uint8_t> pkgCatBytes;
    std::vector<uint8_t> outCatBytes;

    if (!ReadBinaryFile(pkgDll, pkgDllBytes) ||
        !ReadBinaryFile(outDll, outDllBytes) ||
        !ReadBinaryFile(pkgInf, pkgInfBytes) ||
        !ReadBinaryFile(outInf, outInfBytes) ||
        !ReadBinaryFile(pkgCat, pkgCatBytes) ||
        !ReadBinaryFile(outCat, outCatBytes))
    {
        return false;
    }

    if (pkgDllBytes != outDllBytes ||
        pkgInfBytes != outInfBytes ||
        pkgCatBytes != outCatBytes)
    {
        return false;
    }

    if (!IsValidUnsignedX64DriverDll(pkgDllBytes) ||
        !IsFileUnsignedViaWinTrust(pkgDll))
    {
        return false;
    }

    if (!ValidateUnsignedCatalogForDirectory(pkgCat, packageDir) ||
        !ValidateUnsignedCatalogForDirectory(outCat, configOutDir))
    {
        return false;
    }

    return true;
}

void
ValidateBuiltConfigurationPackage(
    const std::filesystem::path& configOutDir
    )
{
    EXPECT_TRUE(ValidatePackageAndOutDirConsistency(configOutDir));

    const std::filesystem::path packageDir = configOutDir / "LumaBridgeIddDriver";
    std::vector<uint8_t> pkgInfBytes;
    EXPECT_TRUE(ReadBinaryFile(packageDir / "LumaBridgeIddDriver.inf", pkgInfBytes));

    const std::string infText(pkgInfBytes.begin(), pkgInfBytes.end());
    const InfDocument doc = ParseInfText(infText);
    ValidateStampedInfDocument(doc);

    const std::vector<std::string> referencedFiles = ExtractReferencedPackageFiles(doc);
    EXPECT_EQ(referencedFiles.size(), static_cast<size_t>(2));
    for (const auto& fileName : referencedFiles)
    {
        EXPECT_TRUE(std::filesystem::exists(packageDir / fileName));
        EXPECT_TRUE(std::filesystem::exists(configOutDir / fileName));
    }
}

struct TempDirGuard
{
    std::filesystem::path Path;

    explicit TempDirGuard(const wchar_t* prefix)
    {
        const DWORD pid = GetCurrentProcessId();
        const ULONGLONG tick = GetTickCount64();
        Path = std::filesystem::temp_directory_path() /
               (std::wstring(prefix) + L"_" + std::to_wstring(pid) + L"_" + std::to_wstring(tick));
        std::error_code ec;
        std::filesystem::remove_all(Path, ec);
        std::filesystem::create_directories(Path / "LumaBridgeIddDriver", ec);
    }

    ~TempDirGuard()
    {
        std::error_code ec;
        std::filesystem::remove_all(Path, ec);
    }
};

void
CopyValidPackageToTemp(
    const std::filesystem::path& sourceOutDir,
    const std::filesystem::path& destOutDir
    )
{
    const std::filesystem::path srcPkg = sourceOutDir / "LumaBridgeIddDriver";
    const std::filesystem::path dstPkg = destOutDir / "LumaBridgeIddDriver";
    for (const char* name : {"LumaBridgeIddDriver.dll", "LumaBridgeIddDriver.inf", "LumaBridgeIddDriver.cat"})
    {
        std::filesystem::copy_file(srcPkg / name, dstPkg / name, std::filesystem::copy_options::overwrite_existing);
        std::filesystem::copy_file(sourceOutDir / name, destOutDir / name, std::filesystem::copy_options::overwrite_existing);
    }
}

void
TestParserAndHelperRejectInvalidInputs()
{
    const InfDocument parsed = ParseInfText(
        "[SourceDisksFiles]\n"
        "LumaBridgeIddDriver.dll = 1 ; primary driver\n"
        "[UMDriverCopy]\n"
        "LumaBridgeIddDriver.dll,,,0x00000100 ; COPYFLG_NOPRUNE\n");
    const std::vector<std::string> files = ExtractReferencedPackageFiles(parsed);
    EXPECT_EQ(files.size(), static_cast<size_t>(2));
    EXPECT_EQ(files[0], std::string("LumaBridgeIddDriver.dll"));
    EXPECT_EQ(files[1], std::string("LumaBridgeIddDriver.dll"));

    EXPECT_TRUE(!IsValidStampedDriverVer("07/01/2026,0.1.0.0"));
    EXPECT_TRUE(IsValidStampedDriverVer("11/18/2026,14.33.28.45"));

    const std::vector<uint8_t> bogusBytes{'M', 'Z', 0x00, 0x01};
    EXPECT_TRUE(!IsValidUnsignedX64DriverDll(bogusBytes));
}

void
TestSourceInfContainsStampInfPlaceholders()
{
    const std::filesystem::path sourceInf = "windows/driver/LumaBridgeIddDriver/LumaBridgeIddDriver.inf";
    std::vector<uint8_t> rawBytes;
    EXPECT_TRUE(ReadBinaryFile(sourceInf, rawBytes));

    const std::string text(rawBytes.begin(), rawBytes.end());
    const InfDocument doc = ParseInfText(text);
    EXPECT_TRUE(SectionHasNormalizedEntry(doc, "Manufacturer", "%ManufacturerName% = Standard,NT$ARCH$.10.0...22000"));
    EXPECT_TRUE(SectionHasNormalizedEntry(doc, "LumaBridge_UMDF_Service", "UmdfLibraryVersion = $UMDFVERSION$"));
    EXPECT_TRUE(SectionHasNormalizedEntry(doc, "Version", "CatalogFile = LumaBridgeIddDriver.cat"));
}

void
TestDebugPackageArtifactsValidAndConsistent()
{
    ValidateBuiltConfigurationPackage("windows/driver/x64/Debug");
}

void
TestReleasePackageArtifactsValidAndConsistent()
{
    ValidateBuiltConfigurationPackage("windows/driver/x64/Release");
}

void
TestNegativeTamperedAndInconsistentPackagesRejected()
{
    const std::filesystem::path debugOut = "windows/driver/x64/Debug";
    const std::filesystem::path releaseOut = "windows/driver/x64/Release";

    // 1. Tampered DLL must fail Authenticode catalog hash verification.
    {
        TempDirGuard tmp(L"lb_tamper_dll");
        CopyValidPackageToTemp(debugOut, tmp.Path);

        std::vector<uint8_t> dllBytes;
        EXPECT_TRUE(ReadBinaryFile(tmp.Path / "LumaBridgeIddDriver" / "LumaBridgeIddDriver.dll", dllBytes));
        EXPECT_TRUE(dllBytes.size() > 512);
        dllBytes.back() ^= 0xFF;
        {
            std::ofstream out(tmp.Path / "LumaBridgeIddDriver" / "LumaBridgeIddDriver.dll", std::ios::binary | std::ios::trunc);
            out.write(reinterpret_cast<const char*>(dllBytes.data()), static_cast<std::streamsize>(dllBytes.size()));
        }
        {
            std::ofstream out(tmp.Path / "LumaBridgeIddDriver.dll", std::ios::binary | std::ios::trunc);
            out.write(reinterpret_cast<const char*>(dllBytes.data()), static_cast<std::streamsize>(dllBytes.size()));
        }
        EXPECT_TRUE(!ValidatePackageAndOutDirConsistency(tmp.Path));
    }

    // 2. Tampered INF must fail catalog member hash verification.
    {
        TempDirGuard tmp(L"lb_tamper_inf");
        CopyValidPackageToTemp(debugOut, tmp.Path);

        {
            std::ofstream out(tmp.Path / "LumaBridgeIddDriver" / "LumaBridgeIddDriver.inf", std::ios::binary | std::ios::app);
            out << "\n; tampered\n";
        }
        {
            std::ofstream out(tmp.Path / "LumaBridgeIddDriver.inf", std::ios::binary | std::ios::app);
            out << "\n; tampered\n";
        }
        EXPECT_TRUE(!ValidatePackageAndOutDirConsistency(tmp.Path));
    }

    // 3. Corrupted catalog must fail CryptCATOpen / CryptQueryObject.
    {
        TempDirGuard tmp(L"lb_corrupt_cat");
        CopyValidPackageToTemp(debugOut, tmp.Path);

        const std::vector<uint8_t> bogusCat{0x30, 0x82, 0x00, 0x10, 0x01, 0x02, 0x03, 0x04};
        for (const auto& catPath : {
                 tmp.Path / "LumaBridgeIddDriver" / "LumaBridgeIddDriver.cat",
                 tmp.Path / "LumaBridgeIddDriver.cat"})
        {
            std::ofstream out(catPath, std::ios::binary | std::ios::trunc);
            out.write(reinterpret_cast<const char*>(bogusCat.data()), static_cast<std::streamsize>(bogusCat.size()));
        }
        EXPECT_TRUE(!ValidatePackageAndOutDirConsistency(tmp.Path));
    }

    // 4. Cross-configuration inconsistent catalog (Debug catalog paired with Release binaries) must fail.
    {
        TempDirGuard tmp(L"lb_inconsistent_cat");
        CopyValidPackageToTemp(releaseOut, tmp.Path);
        std::filesystem::copy_file(
            debugOut / "LumaBridgeIddDriver" / "LumaBridgeIddDriver.cat",
            tmp.Path / "LumaBridgeIddDriver" / "LumaBridgeIddDriver.cat",
            std::filesystem::copy_options::overwrite_existing);
        std::filesystem::copy_file(
            debugOut / "LumaBridgeIddDriver.cat",
            tmp.Path / "LumaBridgeIddDriver.cat",
            std::filesystem::copy_options::overwrite_existing);
        EXPECT_TRUE(!ValidatePackageAndOutDirConsistency(tmp.Path));
    }

    // 5. Missing artifact in OutDir or PackageDir must fail.
    {
        TempDirGuard tmp(L"lb_missing_artifact");
        CopyValidPackageToTemp(debugOut, tmp.Path);
        std::filesystem::remove(tmp.Path / "LumaBridgeIddDriver.cat");
        EXPECT_TRUE(!ValidatePackageAndOutDirConsistency(tmp.Path));
    }
}

std::string
ReadTextFile(
    const std::filesystem::path& path
    )
{
    std::vector<uint8_t> rawBytes;
    if (!ReadBinaryFile(path, rawBytes))
    {
        return {};
    }
    return std::string(rawBytes.begin(), rawBytes.end());
}

void
TestAdapterSourceEnforcesSupportedIddCxTransmissionTypeAndStageConfig()
{
    const std::string adapterHeader = ReadTextFile("windows/driver/LumaBridgeIddDriver/Adapter.h");
    const std::string adapterSource = ReadTextFile("windows/driver/LumaBridgeIddDriver/Adapter.cpp");
    const std::string driverSource = ReadTextFile("windows/driver/LumaBridgeIddDriver/Driver.cpp");
    const std::string stageConfigHeader = ReadTextFile("windows/driver/LumaBridgeIddDriver/DiagnosticStageConfig.h");

    EXPECT_TRUE(!adapterHeader.empty());
    EXPECT_TRUE(!adapterSource.empty());
    EXPECT_TRUE(!driverSource.empty());
    EXPECT_TRUE(!stageConfigHeader.empty());

    EXPECT_TRUE(adapterHeader.find("kEndpointMajorVersion = 1") != std::string::npos);
    EXPECT_TRUE(
        adapterHeader.find("kAdapterTransmissionType = IDDCX_TRANSMISSION_TYPE_WIRED_OTHER") !=
        std::string::npos);
    EXPECT_TRUE(
        adapterHeader.find("IsSupportedIddCxRuntimeTransmissionType(static_cast<uint32_t>(kAdapterTransmissionType))") !=
        std::string::npos);

    EXPECT_TRUE(
        adapterSource.find("adapterCaps.EndPointDiagnostics.TransmissionType = lumabridge::driver::kAdapterTransmissionType;") !=
        std::string::npos);
    EXPECT_TRUE(adapterSource.find("IDDCX_TRANSMISSION_TYPE_NETWORK_OTHER") == std::string::npos);
    EXPECT_TRUE(adapterSource.find("PLUGPLAY_REGKEY_DEVICE | WDF_REGKEY_DEVICE_SUBKEY") != std::string::npos);
    EXPECT_TRUE(adapterSource.find("DiagBuildStage") != std::string::npos);

    // Ensure EvtDeviceD0Entry never masks LumaBridgeStartAdapter failure as STATUS_SUCCESS.
    const size_t d0StartPos = driverSource.find("LumaBridgeStartAdapter(Device);");
    EXPECT_TRUE(d0StartPos != std::string::npos);
    EXPECT_TRUE(driverSource.find("return status;", d0StartPos) != std::string::npos);

    EXPECT_TRUE(stageConfigHeader.find("#define LUMABRIDGE_DIAGNOSTIC_STAGE 6") != std::string::npos);
}

template <typename Fn>
void
RunTest(
    const char* name,
    Fn fn
    )
{
    ++g_TestsRun;
    const int failuresBefore = g_TestsFailed;
    fn();
    if (g_TestsFailed == failuresBefore)
    {
        std::printf("[PASS] %s\n", name);
    }
    else
    {
        std::printf("[FAIL] %s\n", name);
    }
}

} // namespace

int
main()
{
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    RunTest("ParserAndHelperRejectInvalidInputs", TestParserAndHelperRejectInvalidInputs);
    RunTest("SourceInfContainsStampInfPlaceholders", TestSourceInfContainsStampInfPlaceholders);
    RunTest("DebugPackageArtifactsValidAndConsistent", TestDebugPackageArtifactsValidAndConsistent);
    RunTest("ReleasePackageArtifactsValidAndConsistent", TestReleasePackageArtifactsValidAndConsistent);
    RunTest("NegativeTamperedAndInconsistentPackagesRejected", TestNegativeTamperedAndInconsistentPackagesRejected);
    RunTest(
        "AdapterSourceEnforcesSupportedIddCxTransmissionTypeAndStageConfig",
        TestAdapterSourceEnforcesSupportedIddCxTransmissionTypeAndStageConfig);

    std::printf("Summary: %d tests run, %d assertion failures.\n", g_TestsRun, g_TestsFailed);
    return (g_TestsFailed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
