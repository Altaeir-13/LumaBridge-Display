#include "FrameConsumer.h"
#include "VirtualDisplayStimulus.h"

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
        "lumabridge-host.exe - Local IPC Frame Consumer (M4.1.1)\n"
        "Usage:\n"
        "  lumabridge-host.exe [options]\n\n"
        "Options:\n"
        "  --pipe <name>                 Named pipe path (default: \\\\.\\pipe\\LumaBridgeFrameIpc_v1)\n"
        "  --max-frames <n>              Stop early after receiving N valid frames (default: 0 = unlimited)\n"
        "  --min-frames <n>              Minimum valid frames required for success exit code\n"
        "  --require-max-frames          Require full --max-frames target for success exit code\n"
        "  --duration-ms <ms>            Stop after MS milliseconds (default: 0 = unlimited)\n"
        "  --connect-timeout-ms <ms>     Pipe connect timeout in ms (default: 3000)\n"
        "  --io-timeout-ms <ms>          Pipe I/O timeout in ms (default: 500)\n"
        "  --verify-synthetic-pattern    Verify BGRA8 synthetic test pattern pixels\n"
        "  --reconnect                   Automatically reconnect on disconnect/idle loss\n"
        "  --visual-stimulus             Render controlled motion window on active LumaBridge virtual display\n"
        "  --require-virtual-stimulus    Fail if --visual-stimulus cannot identify the virtual display\n"
        "  --stimulus-fps <fps>          Stimulus refresh frequency in Hz (default: 60, range 1..120)\n"
        "  --stimulus-display <gdiName>  Optional explicit GDI display device (e.g. \\\\.\\DISPLAY2)\n"
        "  --json-summary <path>         Write non-visual telemetry summary JSON to file\n"
        "  --quiet                       Suppress per-frame console output\n"
        "  --help                        Show this help message\n");
}

void
WriteLatencyStatsJson(
    std::ofstream& out,
    const char* name,
    const lumabridge::host::LatencySummaryStats& stats,
    bool trailingComma
    )
{
    out << "  \"" << name << "\": {\n"
        << "    \"SampleCount\": " << stats.SampleCount << ",\n"
        << "    \"MinUs\": " << stats.MinUs << ",\n"
        << "    \"AvgUs\": " << stats.AvgUs << ",\n"
        << "    \"MaxUs\": " << stats.MaxUs << ",\n"
        << "    \"P50Us\": " << stats.P50Us << ",\n"
        << "    \"P95Us\": " << stats.P95Us << ",\n"
        << "    \"P99Us\": " << stats.P99Us << ",\n"
        << "    \"LastUs\": " << stats.LastUs << "\n"
        << "  }" << (trailingComma ? "," : "") << "\n";
}

bool
WriteJsonSummary(
    const std::wstring& jsonPath,
    const lumabridge::host::HostConsumerConfig& config,
    const lumabridge::host::HostConsumerMetricsSnapshot& metrics,
    const lumabridge::host::StimulusMetricsSnapshot& stimulus,
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

    char recTimeoutBuf[16]{};
    _snprintf_s(
        recTimeoutBuf,
        sizeof(recTimeoutBuf),
        _TRUNCATE,
        "0x%08lX",
        static_cast<unsigned long>(metrics.LastRecoverableTimeoutHResult));

    char crcBuf[16]{};
    _snprintf_s(crcBuf, sizeof(crcBuf), _TRUNCATE, "0x%08X", metrics.LastFrameChecksumCrc32);

    out << "{\n"
        << "  \"PipeName\": \"" << EscapeJsonString(NarrowAsciiFromWide(config.PipeName.c_str())) << "\",\n"
        << "  \"RunHResult\": \"" << hrBuf << "\",\n"
        << "  \"LastErrorHResult\": \"" << errBuf << "\",\n"
        << "  \"LastRecoverableTimeoutHResult\": \"" << recTimeoutBuf << "\",\n"
        << "  \"LastProtocolStatus\": \"" << lumabridge::ipc::FrameIpcStatusToString(metrics.LastProtocolStatus) << "\",\n"
        << "  \"ExitReason\": \"" << lumabridge::host::HostExitReasonToString(metrics.ExitReason) << "\",\n"
        << "  \"HostProcessExitedNormally\": " << (metrics.HostProcessExitedNormally ? "true" : "false") << ",\n"
        << "  \"TransportHealthy\": " << (metrics.TransportHealthy ? "true" : "false") << ",\n"
        << "  \"FrameTargetReached\": " << (metrics.FrameTargetReached ? "true" : "false") << ",\n"
        << "  \"MinFramesReached\": " << (metrics.MinFramesReached ? "true" : "false") << ",\n"
        << "  \"SessionId\": " << metrics.SessionId << ",\n"
        << "  \"ServerProcessId\": " << metrics.ServerProcessId << ",\n"
        << "  \"AdapterLuidLow\": " << metrics.AdapterLuidLow << ",\n"
        << "  \"AdapterLuidHigh\": " << metrics.AdapterLuidHigh << ",\n"
        << "  \"ServerMaxQueueDepth\": " << metrics.ServerMaxQueueDepth << ",\n"
        << "  \"ConnectCount\": " << metrics.ConnectCount << ",\n"
        << "  \"ReconnectCount\": " << metrics.ReconnectCount << ",\n"
        << "  \"DisconnectCount\": " << metrics.DisconnectCount << ",\n"
        << "  \"SessionsCompleted\": " << metrics.SessionsCompleted << ",\n"
        << "  \"FramesReceived\": " << metrics.FramesReceived << ",\n"
        << "  \"FramesValid\": " << metrics.FramesValid << ",\n"
        << "  \"LiveFramesReceived\": " << metrics.LiveFramesReceived << ",\n"
        << "  \"PreConnectFramesReceived\": " << metrics.PreConnectFramesReceived << ",\n"
        << "  \"MaxFramesPerSession\": " << metrics.MaxFramesPerSession << ",\n"
        << "  \"MinFramesPerSession\": " << metrics.MinFramesPerSession << ",\n"
        << "  \"BytesReceived\": " << metrics.BytesReceived << ",\n"
        << "  \"SequenceGapsDetected\": " << metrics.SequenceGapsDetected << ",\n"
        << "  \"ChecksumMismatches\": " << metrics.ChecksumMismatches << ",\n"
        << "  \"SyntheticPatternMismatches\": " << metrics.SyntheticPatternMismatches << ",\n"
        << "  \"ProtocolErrors\": " << metrics.ProtocolErrors << ",\n"
        << "  \"RecoverableIoTimeouts\": " << metrics.RecoverableIoTimeouts << ",\n"
        << "  \"FatalIoTimeouts\": " << metrics.FatalIoTimeouts << ",\n"
        << "  \"PartialMessageTimeouts\": " << metrics.PartialMessageTimeouts << ",\n"
        << "  \"FatalIpcErrors\": " << metrics.FatalIpcErrors << ",\n"
        << "  \"TimestampMeasurementErrors\": " << metrics.TimestampMeasurementErrors << ",\n"
        << "  \"LastFrameSequence\": " << metrics.LastFrameSequence << ",\n"
        << "  \"LastPresentationFrameNumber\": " << metrics.LastPresentationFrameNumber << ",\n"
        << "  \"LastFrameWidth\": " << metrics.LastFrameWidth << ",\n"
        << "  \"LastFrameHeight\": " << metrics.LastFrameHeight << ",\n"
        << "  \"LastPixelFormat\": " << metrics.LastPixelFormat << ",\n"
        << "  \"LastFrameChecksumCrc32\": \"" << crcBuf << "\",\n"
        << "  \"QpcFrequency\": " << metrics.QpcFrequency << ",\n"
        << "  \"TotalExecutionDurationUs\": " << metrics.TotalExecutionDurationUs << ",\n"
        << "  \"TotalConnectedDurationUs\": " << metrics.TotalConnectedDurationUs << ",\n"
        << "  \"TotalIdleWaitDurationUs\": " << metrics.TotalIdleWaitDurationUs << ",\n"
        << "  \"LastEndToEndLatencyUs\": " << metrics.LastEndToEndLatencyUs << ",\n"
        << "  \"AvgEndToEndLatencyUs\": " << metrics.AvgEndToEndLatencyUs << ",\n"
        << "  \"MaxEndToEndLatencyUs\": " << metrics.MaxEndToEndLatencyUs << ",\n"
        << "  \"LastIpcTransitLatencyUs\": " << metrics.LastIpcTransitLatencyUs << ",\n"
        << "  \"ReceiveFps\": " << metrics.ReceiveFps << ",\n"
        << "  \"AverageExecutionFps\": " << metrics.AverageExecutionFps << ",\n"
        << "  \"ConnectedFps\": " << metrics.ConnectedFps << ",\n"
        << "  \"ObservedActiveFps\": " << metrics.ObservedActiveFps << ",\n"
        << "  \"SustainedLiveFps\": " << metrics.SustainedLiveFps << ",\n"
        << "  \"FpsSampleSufficient\": " << (metrics.FpsSampleSufficient ? "true" : "false") << ",\n";

    WriteLatencyStatsJson(out, "CopyLatency", metrics.CopyLatency, true);
    WriteLatencyStatsJson(out, "PresentToExtractLatency", metrics.PresentToExtractLatency, true);
    WriteLatencyStatsJson(out, "QueueWaitLatency", metrics.QueueWaitLatency, true);
    WriteLatencyStatsJson(out, "LiveQueueWaitLatency", metrics.LiveQueueWaitLatency, true);
    WriteLatencyStatsJson(out, "IpcTransitLatency", metrics.IpcTransitLatency, true);
    WriteLatencyStatsJson(out, "HostVerifyAckLatency", metrics.HostVerifyAckLatency, true);
    WriteLatencyStatsJson(out, "EndToEndLatency", metrics.EndToEndLatency, true);
    WriteLatencyStatsJson(out, "LiveEndToEndLatency", metrics.LiveEndToEndLatency, true);
    WriteLatencyStatsJson(out, "InterFrameInterval", metrics.InterFrameInterval, true);

    out << "  \"VisualStimulus\": {\n"
        << "    \"Requested\": " << (stimulus.Requested ? "true" : "false") << ",\n"
        << "    \"VirtualDisplayIdentified\": " << (stimulus.VirtualDisplayIdentified ? "true" : "false") << ",\n"
        << "    \"Started\": " << (stimulus.Started ? "true" : "false") << ",\n"
        << "    \"CompletedCleanly\": " << (stimulus.CompletedCleanly ? "true" : "false") << ",\n"
        << "    \"TargetFps\": " << stimulus.TargetFps << ",\n"
        << "    \"TicksPresented\": " << stimulus.TicksPresented << ",\n"
        << "    \"PaintCount\": " << stimulus.PaintCount << ",\n"
        << "    \"DurationUs\": " << stimulus.DurationUs << ",\n"
        << "    \"AchievedFps\": " << stimulus.AchievedFps << ",\n"
        << "    \"DisplayDeviceName\": \"" << EscapeJsonString(NarrowAsciiFromWide(stimulus.DisplayDeviceName.c_str())) << "\",\n"
        << "    \"BoundsLeft\": " << stimulus.BoundsLeft << ",\n"
        << "    \"BoundsTop\": " << stimulus.BoundsTop << ",\n"
        << "    \"BoundsWidth\": " << stimulus.BoundsWidth << ",\n"
        << "    \"BoundsHeight\": " << stimulus.BoundsHeight << ",\n"
        << "    \"IdentificationSource\": \"" << EscapeJsonString(stimulus.IdentificationSource) << "\",\n"
        << "    \"ErrorMessage\": \"" << EscapeJsonString(stimulus.ErrorMessage) << "\"\n"
        << "  }\n"
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
    std::wstring stimulusDisplayName;
    bool hasExplicitMinFrames = false;
    bool enableVisualStimulus = false;
    bool requireVirtualStimulus = false;
    uint32_t stimulusFps = 60U;
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
        else if (arg == L"--min-frames" && (i + 1) < argc)
        {
            uint64_t val = 0ULL;
            if (!ParseUnsigned64(argv[++i], val))
            {
                std::fprintf(stderr, "Invalid --min-frames value.\n");
                return EXIT_FAILURE;
            }
            config.MinFrames = val;
            hasExplicitMinFrames = true;
        }
        else if (arg == L"--require-max-frames")
        {
            config.RequireFrameTarget = true;
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
        else if (arg == L"--verify-synthetic-pattern")
        {
            config.VerifySyntheticPattern = true;
        }
        else if (arg == L"--reconnect")
        {
            config.AutoReconnect = true;
        }
        else if (arg == L"--visual-stimulus")
        {
            enableVisualStimulus = true;
        }
        else if (arg == L"--require-virtual-stimulus")
        {
            enableVisualStimulus = true;
            requireVirtualStimulus = true;
        }
        else if (arg == L"--stimulus-fps" && (i + 1) < argc)
        {
            uint64_t val = 0ULL;
            if (!ParseUnsigned64(argv[++i], val) || val == 0ULL || val > 120ULL)
            {
                std::fprintf(stderr, "Invalid --stimulus-fps value (must be 1..120).\n");
                return EXIT_FAILURE;
            }
            stimulusFps = static_cast<uint32_t>(val);
        }
        else if (arg == L"--stimulus-display" && (i + 1) < argc)
        {
            stimulusDisplayName = argv[++i];
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

    if (!hasExplicitMinFrames && config.MaxFrames > 0ULL && config.MaxDurationMs == 0U)
    {
        config.RequireFrameTarget = true;
    }
    if (config.RequireFrameTarget && config.MaxFrames > config.MinFrames)
    {
        config.MinFrames = config.MaxFrames;
    }

    lumabridge::host::VirtualDisplayStimulus stimulus;
    if (enableVisualStimulus)
    {
        const bool stimStarted = stimulus.Start(stimulusFps, stimulusDisplayName);
        const auto stimPreSnap = stimulus.GetMetricsSnapshot();
        if (!stimStarted && requireVirtualStimulus)
        {
            std::fprintf(
                stderr,
                "[LB-HOST] Virtual stimulus required but unavailable: %s\n",
                stimPreSnap.ErrorMessage.c_str());
            const lumabridge::host::HostConsumerMetricsSnapshot emptyMetrics{};
            (void)WriteJsonSummary(jsonSummaryPath, config, emptyMetrics, stimPreSnap, E_FAIL);
            std::fflush(stdout);
            std::fflush(stderr);
            return EXIT_FAILURE;
        }
        if (!stimStarted && !quiet)
        {
            std::fprintf(
                stderr,
                "[LB-HOST] Visual stimulus skipped: %s\n",
                stimPreSnap.ErrorMessage.c_str());
        }
    }

    HANDLE stopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (stopEvent == nullptr)
    {
        std::fprintf(stderr, "CreateEventW failed (%lu).\n", GetLastError());
        stimulus.Stop();
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
                const bool isPreConnect =
                    ((header.Flags & static_cast<uint32_t>(lumabridge::ipc::FrameIpcFlags::PreConnectQueuedFrame)) != 0U);
                std::printf(
                    "[LB-HOST] frame seq=%llu pres=%u %ux%u fmt=%u bytes=%u crc=0x%08X preConn=%u\n",
                    static_cast<unsigned long long>(header.FrameSequence),
                    header.PresentationFrameNumber,
                    header.Width,
                    header.Height,
                    header.PixelFormat,
                    header.PayloadSizeBytes,
                    header.PayloadCrc32,
                    isPreConnect ? 1U : 0U);
            }
        });

    (void)SetConsoleCtrlHandler(ConsoleCtrlHandler, FALSE);
    g_ConsoleStopEvent = nullptr;
    CloseHandle(stopEvent);

    stimulus.Stop();
    const lumabridge::host::StimulusMetricsSnapshot stimSnap = stimulus.GetMetricsSnapshot();
    const lumabridge::host::HostConsumerMetricsSnapshot metrics = consumer.GetMetricsSnapshot();
    const bool jsonOk = WriteJsonSummary(jsonSummaryPath, config, metrics, stimSnap, runHr);

    std::printf(
        "[LB-HOST] Summary: hr=0x%08lX exit=%s normal=%u healthy=%u session=%llu serverPid=%u connects=%llu reconnects=%llu "
        "frames=%llu valid=%llu live=%llu preConn=%llu bytes=%llu gaps=%llu crcErr=%llu patternErr=%llu protoErr=%llu "
        "recTimeout=%llu fatalTimeout=%llu partialTimeout=%llu tsErr=%llu execMs=%llu connMs=%llu idleMs=%llu "
        "execFps=%.2f activeFps=%.2f liveFps=%.2f sampleOk=%u avgE2EUs=%llu liveAvgE2EUs=%llu liveP95Us=%llu ipcAvgUs=%llu\n",
        static_cast<unsigned long>(runHr),
        lumabridge::host::HostExitReasonToString(metrics.ExitReason),
        metrics.HostProcessExitedNormally ? 1U : 0U,
        metrics.TransportHealthy ? 1U : 0U,
        static_cast<unsigned long long>(metrics.SessionId),
        metrics.ServerProcessId,
        static_cast<unsigned long long>(metrics.ConnectCount),
        static_cast<unsigned long long>(metrics.ReconnectCount),
        static_cast<unsigned long long>(metrics.FramesReceived),
        static_cast<unsigned long long>(metrics.FramesValid),
        static_cast<unsigned long long>(metrics.LiveFramesReceived),
        static_cast<unsigned long long>(metrics.PreConnectFramesReceived),
        static_cast<unsigned long long>(metrics.BytesReceived),
        static_cast<unsigned long long>(metrics.SequenceGapsDetected),
        static_cast<unsigned long long>(metrics.ChecksumMismatches),
        static_cast<unsigned long long>(metrics.SyntheticPatternMismatches),
        static_cast<unsigned long long>(metrics.ProtocolErrors),
        static_cast<unsigned long long>(metrics.RecoverableIoTimeouts),
        static_cast<unsigned long long>(metrics.FatalIoTimeouts),
        static_cast<unsigned long long>(metrics.PartialMessageTimeouts),
        static_cast<unsigned long long>(metrics.TimestampMeasurementErrors),
        static_cast<unsigned long long>(metrics.TotalExecutionDurationUs / 1000ULL),
        static_cast<unsigned long long>(metrics.TotalConnectedDurationUs / 1000ULL),
        static_cast<unsigned long long>(metrics.TotalIdleWaitDurationUs / 1000ULL),
        metrics.AverageExecutionFps,
        metrics.ObservedActiveFps,
        metrics.SustainedLiveFps,
        metrics.FpsSampleSufficient ? 1U : 0U,
        static_cast<unsigned long long>(metrics.AvgEndToEndLatencyUs),
        static_cast<unsigned long long>(metrics.LiveEndToEndLatency.AvgUs),
        static_cast<unsigned long long>(metrics.LiveEndToEndLatency.P95Us),
        static_cast<unsigned long long>(metrics.IpcTransitLatency.AvgUs));

    if (stimSnap.Requested)
    {
        std::printf(
            "[LB-HOST] Stimulus: identified=%u started=%u src=%s ticks=%llu paints=%llu achievedFps=%.2f\n",
            stimSnap.VirtualDisplayIdentified ? 1U : 0U,
            stimSnap.Started ? 1U : 0U,
            stimSnap.IdentificationSource.c_str(),
            static_cast<unsigned long long>(stimSnap.TicksPresented),
            static_cast<unsigned long long>(stimSnap.PaintCount),
            stimSnap.AchievedFps);
    }

    std::fflush(stdout);
    std::fflush(stderr);

    if (!jsonOk)
    {
        std::fprintf(stderr, "Failed to write JSON summary.\n");
        std::fflush(stderr);
        return EXIT_FAILURE;
    }

    const bool integrityOk =
        (metrics.ChecksumMismatches == 0ULL) &&
        (metrics.SyntheticPatternMismatches == 0ULL) &&
        (metrics.ProtocolErrors == 0ULL);
    const bool minFramesOk = (metrics.FramesValid >= config.MinFrames);
    const bool maxTargetOk = (!config.RequireFrameTarget) || metrics.FrameTargetReached;
    const bool stimulusOk = (!requireVirtualStimulus) || (stimSnap.VirtualDisplayIdentified && stimSnap.Started);

    return (SUCCEEDED(runHr) &&
            metrics.HostProcessExitedNormally &&
            metrics.TransportHealthy &&
            integrityOk &&
            minFramesOk &&
            maxTargetOk &&
            stimulusOk)
        ? EXIT_SUCCESS
        : EXIT_FAILURE;
}
