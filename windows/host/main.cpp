#include "FrameConsumer.h"
#include "H264BitstreamValidator.h"
#include "NvencH264Encoder.h"
#include "VirtualDisplayStimulus.h"

#include <algorithm>
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

const char*
TransportModeToString(
    lumabridge::ipc::FrameIpcTransportMode mode
    ) noexcept
{
    switch (mode)
    {
    case lumabridge::ipc::FrameIpcTransportMode::GpuSharedNtHandle:
        return "GpuSharedNtHandle";
    case lumabridge::ipc::FrameIpcTransportMode::CpuStagingPipe:
    default:
        return "CpuStagingPipe";
    }
}

void
PrintUsage()
{
    std::printf(
        "lumabridge-host.exe - Local IPC Frame Consumer & NVENC H.264 Host (M4.2)\n"
        "Usage:\n"
        "  lumabridge-host.exe [options]\n\n"
        "Options:\n"
        "  --pipe <name>                    Named pipe path (default: \\\\.\\pipe\\LumaBridgeFrameIpc_v1)\n"
        "  --max-frames <n>                 Stop early after receiving N valid frames (default: 0 = unlimited)\n"
        "  --min-frames <n>                 Minimum valid frames required for success exit code\n"
        "  --require-max-frames             Require full --max-frames target for success exit code\n"
        "  --duration-ms <ms>               Stop after MS milliseconds (default: 0 = unlimited)\n"
        "  --connect-timeout-ms <ms>        Pipe connect timeout in ms (default: 3000)\n"
        "  --io-timeout-ms <ms>             Pipe I/O timeout in ms (default: 500)\n"
        "  --verify-synthetic-pattern       Verify BGRA8 synthetic test pattern pixels\n"
        "  --reconnect                      Automatically reconnect on disconnect/idle loss\n"
        "  --transport <gpu|cpu|auto>       Transport preference (default: auto)\n"
        "  --require-gpu-shared             Require GPU shared texture transport without CPU fallback\n"
        "  --nvenc                          Encode incoming GPU frames to H.264 via NVENC\n"
        "  --require-nvenc                  Require active NVENC H.264 output for success exit code\n"
        "  --nvenc-bitrate-bps <bps>        NVENC CBR bitrate in bps (default: 15000000)\n"
        "  --nvenc-gop <frames>             NVENC GOP / IDR interval in frames (default: 120)\n"
        "  --nvenc-force-idr-every <n>      Explicitly request IDR every N encoded frames (default: 0)\n"
        "  --nvenc-color-format <mode>      NVENC input format: auto|argb|nv12 (default: auto)\n"
        "  --verify-h264-decode             Decode produced H.264 bitstream via independent MF MFT\n"
        "  --visual-stimulus                Render controlled motion window on active LumaBridge virtual display\n"
        "  --require-virtual-stimulus       Fail if --visual-stimulus cannot identify the virtual display\n"
        "  --stimulus-fps <fps>             Stimulus refresh frequency in Hz (default: 60, range 1..120)\n"
        "  --stimulus-display <gdiName>     Optional explicit GDI display device (e.g. \\\\.\\DISPLAY2)\n"
        "  --json-summary <path>            Write non-visual telemetry summary JSON to file\n"
        "  --quiet                          Suppress per-frame console output\n"
        "  --help                           Show this help message\n");
}

void
WriteLatencyStatsJsonWithIndent(
    std::ofstream& out,
    const char* indent,
    const char* name,
    const lumabridge::host::LatencySummaryStats& stats,
    bool trailingComma
    )
{
    out << indent << "\"" << name << "\": {\n"
        << indent << "  \"SampleCount\": " << stats.SampleCount << ",\n"
        << indent << "  \"MinUs\": " << stats.MinUs << ",\n"
        << indent << "  \"AvgUs\": " << stats.AvgUs << ",\n"
        << indent << "  \"MaxUs\": " << stats.MaxUs << ",\n"
        << indent << "  \"P50Us\": " << stats.P50Us << ",\n"
        << indent << "  \"P95Us\": " << stats.P95Us << ",\n"
        << indent << "  \"P99Us\": " << stats.P99Us << ",\n"
        << indent << "  \"LastUs\": " << stats.LastUs << "\n"
        << indent << "}" << (trailingComma ? "," : "") << "\n";
}

void
WriteLatencyStatsJson(
    std::ofstream& out,
    const char* name,
    const lumabridge::host::LatencySummaryStats& stats,
    bool trailingComma
    )
{
    WriteLatencyStatsJsonWithIndent(out, "  ", name, stats, trailingComma);
}

bool
WriteJsonSummary(
    const std::wstring& jsonPath,
    const lumabridge::host::HostConsumerConfig& config,
    const lumabridge::host::HostConsumerMetricsSnapshot& metrics,
    const lumabridge::host::StimulusMetricsSnapshot& stimulus,
    const lumabridge::host::NvencMetricsSnapshot& nvenc,
    const lumabridge::host::H264ValidationSummary& h264Validation,
    bool nvencRequested,
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

    char nvencHrBuf[16]{};
    _snprintf_s(nvencHrBuf, sizeof(nvencHrBuf), _TRUNCATE, "0x%08lX", static_cast<unsigned long>(nvenc.LastHResult));

    char h264HrBuf[16]{};
    _snprintf_s(h264HrBuf, sizeof(h264HrBuf), _TRUNCATE, "0x%08lX", static_cast<unsigned long>(h264Validation.LastHResult));

    out << "{\n"
        << "  \"PipeName\": \"" << EscapeJsonString(NarrowAsciiFromWide(config.PipeName.c_str())) << "\",\n"
        << "  \"RunHResult\": \"" << hrBuf << "\",\n"
        << "  \"LastErrorHResult\": \"" << errBuf << "\",\n"
        << "  \"LastRecoverableTimeoutHResult\": \"" << recTimeoutBuf << "\",\n"
        << "  \"LastProtocolStatus\": \"" << lumabridge::ipc::FrameIpcStatusToString(metrics.LastProtocolStatus) << "\",\n"
        << "  \"ExitReason\": \"" << lumabridge::host::HostExitReasonToString(metrics.ExitReason) << "\",\n"
        << "  \"HostProcessExitedNormally\": " << (metrics.HostProcessExitedNormally ? "true" : "false") << ",\n"
        << "  \"TransportHealthy\": " << (metrics.TransportHealthy ? "true" : "false") << ",\n"
        << "  \"NegotiatedTransportMode\": \"" << TransportModeToString(metrics.NegotiatedTransportMode) << "\",\n"
        << "  \"FallbackToCpuActivated\": " << (metrics.FallbackToCpuActivated ? "true" : "false") << ",\n"
        << "  \"SharedTexturePoolSize\": " << metrics.SharedTexturePoolSize << ",\n"
        << "  \"SharedTexturePoolPeakUsage\": " << metrics.SharedTexturePoolPeakUsage << ",\n"
        << "  \"GpuFramesOpened\": " << metrics.GpuFramesOpened << ",\n"
        << "  \"GpuFramesDropped\": " << metrics.GpuFramesDropped << ",\n"
        << "  \"GpuSharedOpenFailures\": " << metrics.GpuSharedOpenFailures << ",\n"
        << "  \"GpuSyncTimeouts\": " << metrics.GpuSyncTimeouts << ",\n"
        << "  \"AdapterMismatchErrors\": " << metrics.AdapterMismatchErrors << ",\n"
        << "  \"CpuStagingReadsPerformed\": " << metrics.CpuStagingReadsPerformed << ",\n"
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
    WriteLatencyStatsJson(out, "GpuSyncWaitLatency", metrics.GpuSyncWaitLatency, true);
    WriteLatencyStatsJson(out, "HostVerifyAckLatency", metrics.HostVerifyAckLatency, true);
    WriteLatencyStatsJson(out, "EndToEndLatency", metrics.EndToEndLatency, true);
    WriteLatencyStatsJson(out, "LiveEndToEndLatency", metrics.LiveEndToEndLatency, true);
    WriteLatencyStatsJson(out, "InterFrameInterval", metrics.InterFrameInterval, true);

    out << "  \"Nvenc\": {\n"
        << "    \"Requested\": " << (nvencRequested ? "true" : "false") << ",\n"
        << "    \"Initialized\": " << (nvenc.Initialized ? "true" : "false") << ",\n"
        << "    \"DeviceRemovedOrReset\": " << (nvenc.DeviceRemovedOrReset ? "true" : "false") << ",\n"
        << "    \"Width\": " << nvenc.Width << ",\n"
        << "    \"Height\": " << nvenc.Height << ",\n"
        << "    \"TargetFps\": " << nvenc.TargetFps << ",\n"
        << "    \"ConfiguredBitrateBps\": " << nvenc.ConfiguredBitrateBps << ",\n"
        << "    \"NvencBitrateBps\": " << nvenc.NvencBitrateBps << ",\n"
        << "    \"EncoderOutputFps\": " << nvenc.EncoderOutputFps << ",\n"
        << "    \"NvencFramesSubmitted\": " << nvenc.NvencFramesSubmitted << ",\n"
        << "    \"NvencFramesEncoded\": " << nvenc.NvencFramesEncoded << ",\n"
        << "    \"NvencKeyFramesEncoded\": " << nvenc.NvencKeyFramesEncoded << ",\n"
        << "    \"NvencDroppedFrames\": " << nvenc.NvencDroppedFrames << ",\n"
        << "    \"NvencEncoderResets\": " << nvenc.NvencEncoderResets << ",\n"
        << "    \"EncodedQueueDrops\": " << nvenc.EncodedQueueDrops << ",\n"
        << "    \"EncodedQueueDepth\": " << nvenc.EncodedQueueDepth << ",\n"
        << "    \"EncodedQueuePeakDepth\": " << nvenc.EncodedQueuePeakDepth << ",\n"
        << "    \"TotalBitstreamBytes\": " << nvenc.TotalBitstreamBytes << ",\n"
        << "    \"LastEncodedFrameSizeBytes\": " << nvenc.LastEncodedFrameSizeBytes << ",\n"
        << "    \"LastNvencStatus\": " << static_cast<uint32_t>(nvenc.LastNvencStatus) << ",\n"
        << "    \"LastHResult\": \"" << nvencHrBuf << "\",\n"
        << "    \"RuntimeLibraryLoaded\": " << (nvenc.Capabilities.RuntimeLibraryLoaded ? "true" : "false") << ",\n"
        << "    \"H264Supported\": " << (nvenc.Capabilities.H264Supported ? "true" : "false") << ",\n"
        << "    \"SelectedInputFormatName\": \"" << EscapeJsonString(nvenc.Capabilities.SelectedInputFormatName) << "\",\n";
    WriteLatencyStatsJsonWithIndent(out, "    ", "EncodeLatencyUs", nvenc.EncodeLatencyUs, true);
    WriteLatencyStatsJsonWithIndent(out, "    ", "EncodedFrameSizeBytes", nvenc.EncodedFrameSizeBytes, true);
    WriteLatencyStatsJsonWithIndent(out, "    ", "PresentToBitstreamLatencyUs", nvenc.PresentToBitstreamLatencyUs, true);
    WriteLatencyStatsJsonWithIndent(out, "    ", "ExtractToBitstreamLatencyUs", nvenc.ExtractToBitstreamLatencyUs, false);
    out << "  },\n";

    out << "  \"H264DecodeValidation\": {\n"
        << "    \"Enabled\": " << (h264Validation.Enabled ? "true" : "false") << ",\n"
        << "    \"DecoderInitialized\": " << (h264Validation.DecoderInitialized ? "true" : "false") << ",\n"
        << "    \"DecoderName\": \"" << EscapeJsonString(h264Validation.DecoderName) << "\",\n"
        << "    \"PacketsInspected\": " << h264Validation.PacketsInspected << ",\n"
        << "    \"FramesDecoded\": " << h264Validation.FramesDecoded << ",\n"
        << "    \"NalParseFailures\": " << h264Validation.NalParseFailures << ",\n"
        << "    \"DecodeFailures\": " << h264Validation.DecodeFailures << ",\n"
        << "    \"PsnrPassCount\": " << h264Validation.PsnrPassCount << ",\n"
        << "    \"PsnrFailCount\": " << h264Validation.PsnrFailCount << ",\n"
        << "    \"SpsCount\": " << h264Validation.SpsCount << ",\n"
        << "    \"PpsCount\": " << h264Validation.PpsCount << ",\n"
        << "    \"IdrCount\": " << h264Validation.IdrCount << ",\n"
        << "    \"NonIdrCount\": " << h264Validation.NonIdrCount << ",\n"
        << "    \"MinYPsnrDb\": " << h264Validation.MinYPsnrDb << ",\n"
        << "    \"AvgYPsnrDb\": " << h264Validation.AvgYPsnrDb << ",\n"
        << "    \"MinUvPsnrDb\": " << h264Validation.MinUvPsnrDb << ",\n"
        << "    \"AvgUvPsnrDb\": " << h264Validation.AvgUvPsnrDb << ",\n"
        << "    \"Passed\": " << (h264Validation.Passed ? "true" : "false") << ",\n"
        << "    \"LastHResult\": \"" << h264HrBuf << "\"\n"
        << "  },\n";

    out << "  \"VisualStimulus\": {\n"
        << "    \"Requested\": " << (stimulus.Requested ? "true" : "false") << ",\n"
        << "    \"VirtualDisplayIdentified\": " << (stimulus.VirtualDisplayIdentified ? "true" : "false") << ",\n"
        << "    \"Started\": " << (stimulus.Started ? "true" : "false") << ",\n"
        << "    \"Active\": " << (stimulus.Active ? "true" : "false") << ",\n"
        << "    \"CompletedCleanly\": " << (stimulus.CompletedCleanly ? "true" : "false") << ",\n"
        << "    \"HighResolutionTimerUsed\": " << (stimulus.HighResolutionTimerUsed ? "true" : "false") << ",\n"
        << "    \"TargetFps\": " << stimulus.TargetFps << ",\n"
        << "    \"TicksPresented\": " << stimulus.TicksPresented << ",\n"
        << "    \"PaintCount\": " << stimulus.PaintCount << ",\n"
        << "    \"DurationUs\": " << stimulus.DurationUs << ",\n"
        << "    \"TickIntervalAvgUs\": " << stimulus.TickIntervalAvgUs << ",\n"
        << "    \"TickIntervalP95Us\": " << stimulus.TickIntervalP95Us << ",\n"
        << "    \"TickIntervalMaxUs\": " << stimulus.TickIntervalMaxUs << ",\n"
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
    bool requireGpuShared = false;
    bool enableNvenc = false;
    bool requireNvenc = false;
    uint32_t nvencBitrateBps = 15000000U;
    uint32_t nvencGopLength = 120U;
    uint32_t nvencForceIdrEvery = 0U;
    lumabridge::host::NvencColorConversionMode nvencColorMode =
        lumabridge::host::NvencColorConversionMode::Auto;
    bool verifyH264Decode = false;

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
        else if (arg == L"--transport" && (i + 1) < argc)
        {
            const std::wstring modeArg = argv[++i];
            if (modeArg == L"gpu" || modeArg == L"GPU")
            {
                config.TransportPreference = lumabridge::host::HostTransportPreference::GpuSharedOnly;
                config.AllowCpuFallback = false;
            }
            else if (modeArg == L"cpu" || modeArg == L"CPU")
            {
                config.TransportPreference = lumabridge::host::HostTransportPreference::CpuStagingOnly;
            }
            else if (modeArg == L"auto" || modeArg == L"AUTO")
            {
                config.TransportPreference = lumabridge::host::HostTransportPreference::Auto;
                config.AllowCpuFallback = true;
            }
            else
            {
                std::fprintf(stderr, "Invalid --transport value (expected gpu|cpu|auto).\n");
                return EXIT_FAILURE;
            }
        }
        else if (arg == L"--require-gpu-shared")
        {
            requireGpuShared = true;
            config.TransportPreference = lumabridge::host::HostTransportPreference::GpuSharedOnly;
            config.AllowCpuFallback = false;
        }
        else if (arg == L"--nvenc")
        {
            enableNvenc = true;
        }
        else if (arg == L"--require-nvenc")
        {
            enableNvenc = true;
            requireNvenc = true;
        }
        else if (arg == L"--nvenc-bitrate-bps" && (i + 1) < argc)
        {
            uint64_t val = 0ULL;
            if (!ParseUnsigned64(argv[++i], val) || val == 0ULL || val > 200000000ULL)
            {
                std::fprintf(stderr, "Invalid --nvenc-bitrate-bps value.\n");
                return EXIT_FAILURE;
            }
            nvencBitrateBps = static_cast<uint32_t>(val);
        }
        else if (arg == L"--nvenc-gop" && (i + 1) < argc)
        {
            uint64_t val = 0ULL;
            if (!ParseUnsigned64(argv[++i], val) || val == 0ULL || val > 6000U)
            {
                std::fprintf(stderr, "Invalid --nvenc-gop value.\n");
                return EXIT_FAILURE;
            }
            nvencGopLength = static_cast<uint32_t>(val);
        }
        else if (arg == L"--nvenc-force-idr-every" && (i + 1) < argc)
        {
            uint64_t val = 0ULL;
            if (!ParseUnsigned64(argv[++i], val) || val > 6000ULL)
            {
                std::fprintf(stderr, "Invalid --nvenc-force-idr-every value.\n");
                return EXIT_FAILURE;
            }
            nvencForceIdrEvery = static_cast<uint32_t>(val);
        }
        else if (arg == L"--nvenc-color-format" && (i + 1) < argc)
        {
            const std::wstring fmtArg = argv[++i];
            if (fmtArg == L"auto" || fmtArg == L"AUTO")
            {
                nvencColorMode = lumabridge::host::NvencColorConversionMode::Auto;
            }
            else if (fmtArg == L"argb" || fmtArg == L"ARGB")
            {
                nvencColorMode = lumabridge::host::NvencColorConversionMode::DirectArgb;
            }
            else if (fmtArg == L"nv12" || fmtArg == L"NV12")
            {
                nvencColorMode = lumabridge::host::NvencColorConversionMode::GpuVideoProcessorNv12;
            }
            else
            {
                std::fprintf(stderr, "Invalid --nvenc-color-format value (expected auto|argb|nv12).\n");
                return EXIT_FAILURE;
            }
        }
        else if (arg == L"--verify-h264-decode")
        {
            verifyH264Decode = true;
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
            const lumabridge::host::NvencMetricsSnapshot emptyNvenc{};
            const lumabridge::host::H264ValidationSummary emptyH264{};
            (void)WriteJsonSummary(
                jsonSummaryPath,
                config,
                emptyMetrics,
                stimPreSnap,
                emptyNvenc,
                emptyH264,
                enableNvenc,
                E_FAIL);
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

    lumabridge::host::NvencH264Encoder nvencEncoder;
    lumabridge::host::H264StreamValidationSession h264Validator;
    if (verifyH264Decode)
    {
        enableNvenc = true;
    }
    h264Validator.Configure(
        verifyH264Decode,
        stimulusFps,
        config.VerifySyntheticPattern,
        25.0);

    bool nvencInitialized = false;
    bool nvencInitFatal = false;
    HRESULT nvencLastHr = S_OK;
    ID3D11Device* nvencBoundDevice = nullptr;
    uint32_t nvencWidth = 0U;
    uint32_t nvencHeight = 0U;
    uint64_t nvencSubmitCount = 0ULL;

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
        },
        [quiet,
         enableNvenc,
         stimulusFps,
         nvencBitrateBps,
         nvencGopLength,
         nvencForceIdrEvery,
         nvencColorMode,
         verifyH264Decode,
         &nvencEncoder,
         &h264Validator,
         &nvencInitialized,
         &nvencInitFatal,
         &nvencLastHr,
         &nvencBoundDevice,
         &nvencWidth,
         &nvencHeight,
         &nvencSubmitCount](
            const lumabridge::ipc::FrameIpcGpuFrameHeader& gpuHeader,
            ID3D11Device* d3dDevice,
            ID3D11DeviceContext* d3dContext,
            ID3D11Texture2D* workingTexture) {
            if (!quiet && !enableNvenc)
            {
                std::printf(
                    "[LB-HOST] gpu-frame seq=%llu pres=%u slot=%u gen=%u %ux%u fmt=%u\n",
                    static_cast<unsigned long long>(gpuHeader.FrameSequence),
                    gpuHeader.PresentationFrameNumber,
                    gpuHeader.SlotIndex,
                    gpuHeader.SlotGeneration,
                    gpuHeader.Width,
                    gpuHeader.Height,
                    gpuHeader.PixelFormat);
            }

            if (!enableNvenc || d3dDevice == nullptr || d3dContext == nullptr || workingTexture == nullptr)
            {
                return;
            }

            const bool needInitOrReconf =
                !nvencInitialized ||
                nvencBoundDevice != d3dDevice ||
                nvencWidth != gpuHeader.Width ||
                nvencHeight != gpuHeader.Height;
            if (needInitOrReconf && !nvencInitFatal)
            {
                lumabridge::host::NvencEncoderConfig nvCfg{};
                nvCfg.Width = gpuHeader.Width;
                nvCfg.Height = gpuHeader.Height;
                nvCfg.TargetFps = stimulusFps;
                nvCfg.BitrateBps = nvencBitrateBps;
                nvCfg.MaxBitrateBps = (std::max)(nvencBitrateBps, nvencBitrateBps + nvencBitrateBps / 3U);
                nvCfg.GopLength = nvencGopLength;
                nvCfg.LowLatencyTuning = true;
                nvCfg.RepeatSpsPpsEveryIdr = true;
                nvCfg.ColorMode = nvencColorMode;

                if (!nvencInitialized || nvencBoundDevice != d3dDevice)
                {
                    nvencLastHr = nvencEncoder.Initialize(d3dDevice, d3dContext, nvCfg);
                }
                else
                {
                    nvencLastHr = nvencEncoder.ReconstructSession(d3dDevice, d3dContext, &nvCfg);
                }
                nvencInitialized = SUCCEEDED(nvencLastHr);
                nvencInitFatal = FAILED(nvencLastHr);
                nvencBoundDevice = d3dDevice;
                nvencWidth = gpuHeader.Width;
                nvencHeight = gpuHeader.Height;
            }

            if (!nvencInitialized)
            {
                return;
            }

            if (nvencForceIdrEvery > 0U &&
                nvencSubmitCount > 0ULL &&
                (nvencSubmitCount % nvencForceIdrEvery) == 0ULL)
            {
                nvencEncoder.RequestForceIdrOnNextFrame();
            }

            const HRESULT encHr = nvencEncoder.EncodeGpuTexture(
                workingTexture,
                gpuHeader.FrameSequence,
                gpuHeader.PresentationFrameNumber,
                gpuHeader.PresentDisplayQpcTime,
                gpuHeader.ExtractCompleteQpcTime,
                gpuHeader.QpcFrequency,
                nullptr);
            nvencLastHr = encHr;
            ++nvencSubmitCount;

            if (FAILED(encHr) && nvencEncoder.GetMetricsSnapshot().DeviceRemovedOrReset)
            {
                const HRESULT recHr = nvencEncoder.ReconstructSession(d3dDevice, d3dContext, nullptr);
                nvencInitialized = SUCCEEDED(recHr);
                nvencLastHr = recHr;
            }

            lumabridge::host::EncodedFramePacket pkt{};
            while (nvencEncoder.TryPopEncodedFrame(pkt))
            {
                if (verifyH264Decode)
                {
                    h264Validator.SubmitPacket(pkt);
                }
                if (!quiet)
                {
                    std::printf(
                        "[LB-HOST] nvenc seq=%llu pres=%u key=%u bytes=%zu encUs=%llu\n",
                        static_cast<unsigned long long>(pkt.FrameSequence),
                        pkt.PresentationFrameNumber,
                        pkt.IsKeyFrame ? 1U : 0U,
                        pkt.Bitstream.size(),
                        static_cast<unsigned long long>(pkt.EncodeLatencyUs));
                }
            }
        });

    lumabridge::host::EncodedFramePacket remainingPkt{};
    while (nvencEncoder.TryPopEncodedFrame(remainingPkt))
    {
        if (verifyH264Decode)
        {
            h264Validator.SubmitPacket(remainingPkt);
        }
    }
    h264Validator.Finish();

    (void)SetConsoleCtrlHandler(ConsoleCtrlHandler, FALSE);
    g_ConsoleStopEvent = nullptr;
    CloseHandle(stopEvent);

    stimulus.Stop();
    const lumabridge::host::StimulusMetricsSnapshot stimSnap = stimulus.GetMetricsSnapshot();
    const lumabridge::host::HostConsumerMetricsSnapshot metrics = consumer.GetMetricsSnapshot();
    const lumabridge::host::NvencMetricsSnapshot nvencSnap = nvencEncoder.GetMetricsSnapshot();
    const lumabridge::host::H264ValidationSummary h264Snap = h264Validator.GetSummary();

    h264Validator.Shutdown();
    nvencEncoder.Shutdown();

    const bool jsonOk = WriteJsonSummary(
        jsonSummaryPath,
        config,
        metrics,
        stimSnap,
        nvencSnap,
        h264Snap,
        enableNvenc,
        runHr);

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

    std::printf(
        "[LB-HOST] Transport: mode=%s fallback=%u pool=%u/%u gpuOpened=%llu gpuDrop=%llu openErr=%llu syncTimeout=%llu "
        "luidErr=%llu cpuReads=%llu syncWaitAvgUs=%llu syncWaitP95Us=%llu\n",
        TransportModeToString(metrics.NegotiatedTransportMode),
        metrics.FallbackToCpuActivated ? 1U : 0U,
        metrics.SharedTexturePoolSize,
        metrics.SharedTexturePoolPeakUsage,
        static_cast<unsigned long long>(metrics.GpuFramesOpened),
        static_cast<unsigned long long>(metrics.GpuFramesDropped),
        static_cast<unsigned long long>(metrics.GpuSharedOpenFailures),
        static_cast<unsigned long long>(metrics.GpuSyncTimeouts),
        static_cast<unsigned long long>(metrics.AdapterMismatchErrors),
        static_cast<unsigned long long>(metrics.CpuStagingReadsPerformed),
        static_cast<unsigned long long>(metrics.GpuSyncWaitLatency.AvgUs),
        static_cast<unsigned long long>(metrics.GpuSyncWaitLatency.P95Us));

    if (enableNvenc || nvencSnap.NvencFramesSubmitted > 0ULL)
    {
        std::printf(
            "[LB-HOST] NVENC: init=%u fmt=%s submitted=%llu encoded=%llu keys=%llu drops=%llu resets=%llu "
            "encAvgUs=%llu encP95Us=%llu presentToBsAvgUs=%llu outFps=%.2f bitrate=%llu bytes=%llu\n",
            nvencSnap.Initialized ? 1U : 0U,
            nvencSnap.Capabilities.SelectedInputFormatName.c_str(),
            static_cast<unsigned long long>(nvencSnap.NvencFramesSubmitted),
            static_cast<unsigned long long>(nvencSnap.NvencFramesEncoded),
            static_cast<unsigned long long>(nvencSnap.NvencKeyFramesEncoded),
            static_cast<unsigned long long>(nvencSnap.NvencDroppedFrames),
            static_cast<unsigned long long>(nvencSnap.NvencEncoderResets),
            static_cast<unsigned long long>(nvencSnap.EncodeLatencyUs.AvgUs),
            static_cast<unsigned long long>(nvencSnap.EncodeLatencyUs.P95Us),
            static_cast<unsigned long long>(nvencSnap.PresentToBitstreamLatencyUs.AvgUs),
            nvencSnap.EncoderOutputFps,
            static_cast<unsigned long long>(nvencSnap.NvencBitrateBps),
            static_cast<unsigned long long>(nvencSnap.TotalBitstreamBytes));
    }

    if (h264Snap.Enabled)
    {
        std::printf(
            "[LB-HOST] H264Decode: passed=%u packets=%llu decoded=%llu nalErr=%llu decErr=%llu "
            "sps=%llu pps=%llu idr=%llu minY=%.2fdB minUv=%.2fdB\n",
            h264Snap.Passed ? 1U : 0U,
            static_cast<unsigned long long>(h264Snap.PacketsInspected),
            static_cast<unsigned long long>(h264Snap.FramesDecoded),
            static_cast<unsigned long long>(h264Snap.NalParseFailures),
            static_cast<unsigned long long>(h264Snap.DecodeFailures),
            static_cast<unsigned long long>(h264Snap.SpsCount),
            static_cast<unsigned long long>(h264Snap.PpsCount),
            static_cast<unsigned long long>(h264Snap.IdrCount),
            h264Snap.MinYPsnrDb,
            h264Snap.MinUvPsnrDb);
    }

    if (stimSnap.Requested)
    {
        std::printf(
            "[LB-HOST] Stimulus: identified=%u started=%u hiRes=%u src=%s ticks=%llu paints=%llu achievedFps=%.2f tickAvgUs=%llu\n",
            stimSnap.VirtualDisplayIdentified ? 1U : 0U,
            stimSnap.Started ? 1U : 0U,
            stimSnap.HighResolutionTimerUsed ? 1U : 0U,
            stimSnap.IdentificationSource.c_str(),
            static_cast<unsigned long long>(stimSnap.TicksPresented),
            static_cast<unsigned long long>(stimSnap.PaintCount),
            stimSnap.AchievedFps,
            static_cast<unsigned long long>(stimSnap.TickIntervalAvgUs));
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
    const bool gpuTransportOk =
        (!requireGpuShared) ||
        (metrics.NegotiatedTransportMode == lumabridge::ipc::FrameIpcTransportMode::GpuSharedNtHandle &&
         !metrics.FallbackToCpuActivated &&
         metrics.GpuFramesOpened > 0ULL &&
         metrics.GpuSharedOpenFailures == 0ULL &&
         metrics.GpuSyncTimeouts == 0ULL &&
         metrics.AdapterMismatchErrors == 0ULL &&
         (config.VerifySyntheticPattern || metrics.CpuStagingReadsPerformed == 0ULL));
    const bool nvencOk =
        (!requireNvenc) ||
        (!nvencInitFatal &&
         SUCCEEDED(nvencLastHr) &&
         nvencSnap.NvencFramesEncoded > 0ULL &&
         nvencSnap.TotalBitstreamBytes > 0ULL);
    const bool h264DecodeOk = (!verifyH264Decode) || h264Snap.Passed;

    return (SUCCEEDED(runHr) &&
            metrics.HostProcessExitedNormally &&
            metrics.TransportHealthy &&
            integrityOk &&
            minFramesOk &&
            maxTargetOk &&
            stimulusOk &&
            gpuTransportOk &&
            nvencOk &&
            h264DecodeOk)
        ? EXIT_SUCCESS
        : EXIT_FAILURE;
}
