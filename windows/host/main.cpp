#include "FrameConsumer.h"

#include <cstdio>
#include <cstdlib>
#include <cwchar>
#include <fstream>
#include <string>

namespace {

HANDLE g_ConsoleStopEvent = nullptr;

BOOL WINAPI
ConsoleCtrlHandler(
    DWORD ctrlType
    ) noexcept
{
    if (ctrlType == CTRL_C_EVENT ||
        ctrlType == CTRL_BREAK_EVENT ||
        ctrlType == CTRL_CLOSE_EVENT)
    {
        if (g_ConsoleStopEvent != nullptr)
        {
            (void)SetEvent(g_ConsoleStopEvent);
        }
        return TRUE;
    }
    return FALSE;
}

std::string
NarrowAsciiFromWide(
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
        const wchar_t ch = *p;
        out.push_back((ch >= 0x20 && ch <= 0x7E) ? static_cast<char>(ch) : '?');
    }
    return out;
}

std::string
EscapeJsonString(
    const std::string& input
    )
{
    std::string out;
    out.reserve(input.size() + 8U);
    for (char ch : input)
    {
        switch (ch)
        {
        case '\\':
            out += "\\\\";
            break;
        case '"':
            out += "\\\"";
            break;
        case '\n':
            out += "\\n";
            break;
        case '\r':
            out += "\\r";
            break;
        case '\t':
            out += "\\t";
            break;
        default:
            out.push_back(ch);
            break;
        }
    }
    return out;
}

bool
ParseUnsigned64(
    const wchar_t* text,
    uint64_t& outValue
    ) noexcept
{
    if (text == nullptr || text[0] == L'\0')
    {
        return false;
    }
    wchar_t* endPtr = nullptr;
    const unsigned long long parsed = std::wcstoull(text, &endPtr, 0);
    if (endPtr == text || *endPtr != L'\0')
    {
        return false;
    }
    outValue = static_cast<uint64_t>(parsed);
    return true;
}

void
PrintUsage()
{
    std::printf(
        "lumabridge-host.exe - Local IPC Frame Consumer (M4.1)\n"
        "Usage:\n"
        "  lumabridge-host.exe [options]\n\n"
        "Options:\n"
        "  --pipe <name>                 Named pipe path (default: \\\\.\\pipe\\LumaBridgeFrameIpc_v1)\n"
        "  --max-frames <n>              Stop after receiving N frames (default: 0 = unlimited)\n"
        "  --duration-ms <ms>            Stop after MS milliseconds (default: 0 = unlimited)\n"
        "  --connect-timeout-ms <ms>     Pipe connect timeout in ms (default: 3000)\n"
        "  --io-timeout-ms <ms>          Pipe I/O timeout in ms (default: 500)\n"
        "  --auth-token <value>          32-bit auth token in dec/hex (default: 0x4148424C)\n"
        "  --verify-synthetic-pattern    Verify BGRA8 synthetic test pattern pixels\n"
        "  --reconnect                   Automatically reconnect on disconnect/idle loss\n"
        "  --json-summary <path>         Write non-visual telemetry summary JSON to file\n"
        "  --quiet                       Suppress per-frame console output\n"
        "  --help                        Show this help message\n");
}

bool
WriteJsonSummary(
    const std::wstring& jsonPath,
    const lumabridge::host::HostConsumerConfig& config,
    const lumabridge::host::HostConsumerMetricsSnapshot& metrics,
    HRESULT runResult
    )
{
    if (jsonPath.empty())
    {
        return true;
    }

    std::ofstream out(jsonPath, std::ios::binary | std::ios::trunc);
    if (!out.is_open())
    {
        return false;
    }

    char hrBuf[16]{};
    _snprintf_s(hrBuf, sizeof(hrBuf), _TRUNCATE, "0x%08lX", static_cast<unsigned long>(runResult));

    char errBuf[16]{};
    _snprintf_s(errBuf, sizeof(errBuf), _TRUNCATE, "0x%08lX", static_cast<unsigned long>(metrics.LastErrorHResult));

    char crcBuf[16]{};
    _snprintf_s(crcBuf, sizeof(crcBuf), _TRUNCATE, "0x%08X", metrics.LastFrameChecksumCrc32);

    out << "{\n"
        << "  \"PipeName\": \"" << EscapeJsonString(NarrowAsciiFromWide(config.PipeName.c_str())) << "\",\n"
        << "  \"RunHResult\": \"" << hrBuf << "\",\n"
        << "  \"LastErrorHResult\": \"" << errBuf << "\",\n"
        << "  \"LastProtocolStatus\": \"" << lumabridge::ipc::FrameIpcStatusToString(metrics.LastProtocolStatus) << "\",\n"
        << "  \"SessionId\": " << metrics.SessionId << ",\n"
        << "  \"ServerProcessId\": " << metrics.ServerProcessId << ",\n"
        << "  \"AdapterLuidLow\": " << metrics.AdapterLuidLow << ",\n"
        << "  \"AdapterLuidHigh\": " << metrics.AdapterLuidHigh << ",\n"
        << "  \"ServerMaxQueueDepth\": " << metrics.ServerMaxQueueDepth << ",\n"
        << "  \"ConnectCount\": " << metrics.ConnectCount << ",\n"
        << "  \"ReconnectCount\": " << metrics.ReconnectCount << ",\n"
        << "  \"FramesReceived\": " << metrics.FramesReceived << ",\n"
        << "  \"BytesReceived\": " << metrics.BytesReceived << ",\n"
        << "  \"SequenceGapsDetected\": " << metrics.SequenceGapsDetected << ",\n"
        << "  \"ChecksumMismatches\": " << metrics.ChecksumMismatches << ",\n"
        << "  \"SyntheticPatternMismatches\": " << metrics.SyntheticPatternMismatches << ",\n"
        << "  \"ProtocolErrors\": " << metrics.ProtocolErrors << ",\n"
        << "  \"LastFrameSequence\": " << metrics.LastFrameSequence << ",\n"
        << "  \"LastPresentationFrameNumber\": " << metrics.LastPresentationFrameNumber << ",\n"
        << "  \"LastFrameWidth\": " << metrics.LastFrameWidth << ",\n"
        << "  \"LastFrameHeight\": " << metrics.LastFrameHeight << ",\n"
        << "  \"LastPixelFormat\": " << metrics.LastPixelFormat << ",\n"
        << "  \"LastFrameChecksumCrc32\": \"" << crcBuf << "\",\n"
        << "  \"LastEndToEndLatencyUs\": " << metrics.LastEndToEndLatencyUs << ",\n"
        << "  \"AvgEndToEndLatencyUs\": " << metrics.AvgEndToEndLatencyUs << ",\n"
        << "  \"MaxEndToEndLatencyUs\": " << metrics.MaxEndToEndLatencyUs << ",\n"
        << "  \"LastIpcTransitLatencyUs\": " << metrics.LastIpcTransitLatencyUs << ",\n"
        << "  \"ReceiveFps\": " << metrics.ReceiveFps << "\n"
        << "}\n";

    return out.good();
}

} // namespace

int
wmain(
    int argc,
    wchar_t* argv[]
    )
{
    lumabridge::host::HostConsumerConfig config{};
    std::wstring jsonSummaryPath;
    bool quiet = false;

    for (int i = 1; i < argc; ++i)
    {
        const std::wstring arg = argv[i];
        if (arg == L"--help" || arg == L"-h")
        {
            PrintUsage();
            return EXIT_SUCCESS;
        }
        else if (arg == L"--pipe" && (i + 1) < argc)
        {
            config.PipeName = argv[++i];
        }
        else if (arg == L"--max-frames" && (i + 1) < argc)
        {
            uint64_t val = 0ULL;
            if (!ParseUnsigned64(argv[++i], val))
            {
                std::fprintf(stderr, "Invalid --max-frames value.\n");
                return EXIT_FAILURE;
            }
            config.MaxFrames = val;
        }
        else if (arg == L"--duration-ms" && (i + 1) < argc)
        {
            uint64_t val = 0ULL;
            if (!ParseUnsigned64(argv[++i], val) || val > 0xFFFFFFFFULL)
            {
                std::fprintf(stderr, "Invalid --duration-ms value.\n");
                return EXIT_FAILURE;
            }
            config.MaxDurationMs = static_cast<uint32_t>(val);
        }
        else if (arg == L"--connect-timeout-ms" && (i + 1) < argc)
        {
            uint64_t val = 0ULL;
            if (!ParseUnsigned64(argv[++i], val) || val > 0xFFFFFFFFULL)
            {
                std::fprintf(stderr, "Invalid --connect-timeout-ms value.\n");
                return EXIT_FAILURE;
            }
            config.ConnectTimeoutMs = static_cast<DWORD>(val);
        }
        else if (arg == L"--io-timeout-ms" && (i + 1) < argc)
        {
            uint64_t val = 0ULL;
            if (!ParseUnsigned64(argv[++i], val) || val == 0ULL || val > 0xFFFFFFFFULL)
            {
                std::fprintf(stderr, "Invalid --io-timeout-ms value.\n");
                return EXIT_FAILURE;
            }
            config.IoTimeoutMs = static_cast<DWORD>(val);
        }
        else if (arg == L"--auth-token" && (i + 1) < argc)
        {
            uint64_t val = 0ULL;
            if (!ParseUnsigned64(argv[++i], val) || val > 0xFFFFFFFFULL)
            {
                std::fprintf(stderr, "Invalid --auth-token value.\n");
                return EXIT_FAILURE;
            }
            config.AuthToken = static_cast<uint32_t>(val);
        }
        else if (arg == L"--verify-synthetic-pattern")
        {
            config.VerifySyntheticPattern = true;
        }
        else if (arg == L"--reconnect")
        {
            config.AutoReconnect = true;
        }
        else if (arg == L"--json-summary" && (i + 1) < argc)
        {
            jsonSummaryPath = argv[++i];
        }
        else if (arg == L"--quiet")
        {
            quiet = true;
        }
        else
        {
            std::fprintf(stderr, "Unknown or incomplete argument: %s\n", NarrowAsciiFromWide(arg.c_str()).c_str());
            PrintUsage();
            return EXIT_FAILURE;
        }
    }

    HANDLE stopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (stopEvent == nullptr)
    {
        std::fprintf(stderr, "CreateEventW failed (%lu).\n", GetLastError());
        return EXIT_FAILURE;
    }
    g_ConsoleStopEvent = stopEvent;
    (void)SetConsoleCtrlHandler(ConsoleCtrlHandler, TRUE);

    lumabridge::host::FrameConsumer consumer(config);
    const HRESULT runHr = consumer.RunLoop(
        stopEvent,
        [quiet](const lumabridge::ipc::FrameIpcFrameHeader& header, const std::vector<uint8_t>&) {
            if (!quiet)
            {
                std::printf(
                    "[LB-HOST] frame seq=%llu pres=%u %ux%u fmt=%u bytes=%u crc=0x%08X\n",
                    static_cast<unsigned long long>(header.FrameSequence),
                    header.PresentationFrameNumber,
                    header.Width,
                    header.Height,
                    header.PixelFormat,
                    header.PayloadSizeBytes,
                    header.PayloadCrc32);
            }
        });

    (void)SetConsoleCtrlHandler(ConsoleCtrlHandler, FALSE);
    g_ConsoleStopEvent = nullptr;
    CloseHandle(stopEvent);

    const lumabridge::host::HostConsumerMetricsSnapshot metrics = consumer.GetMetricsSnapshot();
    const bool jsonOk = WriteJsonSummary(jsonSummaryPath, config, metrics, runHr);

    std::printf(
        "[LB-HOST] Summary: hr=0x%08lX session=%llu serverPid=%u connects=%llu frames=%llu bytes=%llu "
        "gaps=%llu crcErr=%llu patternErr=%llu protoErr=%llu fps=%.2f avgLatUs=%llu maxLatUs=%llu\n",
        static_cast<unsigned long>(runHr),
        static_cast<unsigned long long>(metrics.SessionId),
        metrics.ServerProcessId,
        static_cast<unsigned long long>(metrics.ConnectCount),
        static_cast<unsigned long long>(metrics.FramesReceived),
        static_cast<unsigned long long>(metrics.BytesReceived),
        static_cast<unsigned long long>(metrics.SequenceGapsDetected),
        static_cast<unsigned long long>(metrics.ChecksumMismatches),
        static_cast<unsigned long long>(metrics.SyntheticPatternMismatches),
        static_cast<unsigned long long>(metrics.ProtocolErrors),
        metrics.ReceiveFps,
        static_cast<unsigned long long>(metrics.AvgEndToEndLatencyUs),
        static_cast<unsigned long long>(metrics.MaxEndToEndLatencyUs));

    if (!jsonOk)
    {
        std::fprintf(stderr, "Failed to write JSON summary.\n");
        return EXIT_FAILURE;
    }

    const bool expectedFramesMet = (config.MaxFrames == 0ULL) || (metrics.FramesReceived >= config.MaxFrames);
    const bool integrityOk =
        (metrics.ChecksumMismatches == 0ULL) &&
        (metrics.SyntheticPatternMismatches == 0ULL) &&
        (metrics.ProtocolErrors == 0ULL);

    return (SUCCEEDED(runHr) && expectedFramesMet && integrityOk) ? EXIT_SUCCESS : EXIT_FAILURE;
}
