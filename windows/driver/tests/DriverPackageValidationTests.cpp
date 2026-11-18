#ifndef WIN32_NO_STATUS
#define WIN32_NO_STATUS
#endif
#include <Windows.h>
#undef WIN32_NO_STATUS

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

bool
ContainsUtf16LeCaseInsensitive(
    const std::vector<uint8_t>& bytes,
    const std::string& asciiNeedle
    )
{
    if (asciiNeedle.empty() || bytes.size() < asciiNeedle.size() * 2)
    {
        return false;
    }

    const std::string lowerNeedle = ToLowerAscii(asciiNeedle);
    const size_t needleByteCount = lowerNeedle.size() * 2;
    for (size_t i = 0; i + needleByteCount <= bytes.size(); ++i)
    {
        bool matched = true;
        for (size_t j = 0; j < lowerNeedle.size(); ++j)
        {
            const uint8_t lo = bytes[i + j * 2];
            const uint8_t hi = bytes[i + j * 2 + 1];
            const char folded = static_cast<char>(std::tolower(lo));
            if (hi != 0 || folded != lowerNeedle[j])
            {
                matched = false;
                break;
            }
        }
        if (matched)
        {
            return true;
        }
    }
    return false;
}

bool
IsValidUnsignedCatalog(
    const std::vector<uint8_t>& bytes
    )
{
    // Microsoft security catalogs are DER-encoded PKCS#7 SignedData CTLs starting with SEQUENCE (0x30).
    if (bytes.size() < 64 || bytes[0] != 0x30)
    {
        return false;
    }

    return ContainsUtf16LeCaseInsensitive(bytes, "lumabridgeidddriver.dll") &&
           ContainsUtf16LeCaseInsensitive(bytes, "lumabridgeidddriver.inf") &&
           ContainsUtf16LeCaseInsensitive(bytes, "root\\lumabridgeidddriver") &&
           ContainsUtf16LeCaseInsensitive(bytes, "_v100_x64_19h1");
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

    EXPECT_TRUE(SectionHasNormalizedEntry(doc, "Manufacturer", "%ManufacturerName% = Standard,NTamd64.10.0...18362"));
    EXPECT_TRUE(SectionHasNormalizedEntry(
        doc,
        "Standard.NTamd64.10.0...18362",
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

void
ValidateBuiltConfigurationPackage(
    const std::filesystem::path& configOutDir
    )
{
    const std::filesystem::path packageDir = configOutDir / "LumaBridgeIddDriver";
    EXPECT_TRUE(std::filesystem::is_directory(configOutDir));
    EXPECT_TRUE(std::filesystem::is_directory(packageDir));

    const std::filesystem::path pkgDll = packageDir / "LumaBridgeIddDriver.dll";
    const std::filesystem::path pkgInf = packageDir / "LumaBridgeIddDriver.inf";
    const std::filesystem::path pkgCat = packageDir / "LumaBridgeIddDriver.cat";

    const std::filesystem::path outDll = configOutDir / "LumaBridgeIddDriver.dll";
    const std::filesystem::path outInf = configOutDir / "LumaBridgeIddDriver.inf";
    const std::filesystem::path outCat = configOutDir / "LumaBridgeIddDriver.cat";

    EXPECT_TRUE(std::filesystem::exists(pkgDll));
    EXPECT_TRUE(std::filesystem::exists(pkgInf));
    EXPECT_TRUE(std::filesystem::exists(pkgCat));
    EXPECT_TRUE(std::filesystem::exists(outDll));
    EXPECT_TRUE(std::filesystem::exists(outInf));
    EXPECT_TRUE(std::filesystem::exists(outCat));

    std::vector<uint8_t> pkgDllBytes;
    std::vector<uint8_t> outDllBytes;
    std::vector<uint8_t> pkgInfBytes;
    std::vector<uint8_t> outInfBytes;
    std::vector<uint8_t> pkgCatBytes;
    std::vector<uint8_t> outCatBytes;

    EXPECT_TRUE(ReadBinaryFile(pkgDll, pkgDllBytes));
    EXPECT_TRUE(ReadBinaryFile(outDll, outDllBytes));
    EXPECT_TRUE(ReadBinaryFile(pkgInf, pkgInfBytes));
    EXPECT_TRUE(ReadBinaryFile(outInf, outInfBytes));
    EXPECT_TRUE(ReadBinaryFile(pkgCat, pkgCatBytes));
    EXPECT_TRUE(ReadBinaryFile(outCat, outCatBytes));

    EXPECT_TRUE(pkgDllBytes == outDllBytes);
    EXPECT_TRUE(pkgInfBytes == outInfBytes);
    EXPECT_TRUE(pkgCatBytes == outCatBytes);

    EXPECT_TRUE(IsValidUnsignedX64DriverDll(pkgDllBytes));
    EXPECT_TRUE(IsValidUnsignedCatalog(pkgCatBytes));

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
    EXPECT_TRUE(!IsValidUnsignedCatalog(bogusBytes));
}

void
TestSourceInfContainsStampInfPlaceholders()
{
    const std::filesystem::path sourceInf = "windows/driver/LumaBridgeIddDriver/LumaBridgeIddDriver.inf";
    std::vector<uint8_t> rawBytes;
    EXPECT_TRUE(ReadBinaryFile(sourceInf, rawBytes));

    const std::string text(rawBytes.begin(), rawBytes.end());
    const InfDocument doc = ParseInfText(text);
    EXPECT_TRUE(SectionHasNormalizedEntry(doc, "Manufacturer", "%ManufacturerName% = Standard,NT$ARCH$.10.0...18362"));
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
    RunTest("ParserAndHelperRejectInvalidInputs", TestParserAndHelperRejectInvalidInputs);
    RunTest("SourceInfContainsStampInfPlaceholders", TestSourceInfContainsStampInfPlaceholders);
    RunTest("DebugPackageArtifactsValidAndConsistent", TestDebugPackageArtifactsValidAndConsistent);
    RunTest("ReleasePackageArtifactsValidAndConsistent", TestReleasePackageArtifactsValidAndConsistent);

    std::printf("Summary: %d tests run, %d assertion failures.\n", g_TestsRun, g_TestsFailed);
    return (g_TestsFailed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
