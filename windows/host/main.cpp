#include "AsyncH264ValidationWorker.h"
#include "FrameConsumer.h"
#include "H264BitstreamValidator.h"
#include "HostGateEvaluator.h"
#include "NvencH264Encoder.h"
#include "VirtualDisplayStimulus.h"

#include <objbase.h>
#include <psapi.h>

#include <algorithm>
#include <cmath>
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

bool
ParseDouble(
    const wchar_t* text,
    double& outValue
    ) noexcept
{
    if (text == nullptr || text[0] == L'\0')
    {
        return false;
    }
    wchar_t* endPtr = nullptr;
    const double parsed = std::wcstod(text, &endPtr);
    if (endPtr == text || *endPtr != L'\0' || !std::isfinite(parsed))
    {
        return false;
    }
    outValue = parsed;
    return true;
}

void
FormatUtcIso8601Now(
    char* dst,
    size_t dstSize
    ) noexcept
{
    SYSTEMTIME st{};
    GetSystemTime(&st);
    _snprintf_s(
        dst,
        dstSize,
        _TRUNCATE,
        "%04u-%02u-%02uT%02u:%02u:%02u.%03uZ",
        static_cast<unsigned int>(st.wYear),
        static_cast<unsigned int>(st.wMonth),
        static_cast<unsigned int>(st.wDay),
        static_cast<unsigned int>(st.wHour),
        static_cast<unsigned int>(st.wMinute),
        static_cast<unsigned int>(st.wSecond),
        static_cast<unsigned int>(st.wMilliseconds));
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
        "  --duration-counts-connected      Measure --duration-ms only across connected pipe time (pauses pre-connect/reconnect)\n"
        "  --max-execution-ms <ms>          Hard wall-clock safety execution timeout in ms (default: 0 = unlimited)\n"
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
        "  --verify-h264-psnr               Verify synthetic pattern PSNR after independent H.264 decode (zero CPU pixel readback)\n"
        "  --prewarm-width <px>             Pre-warm GPU/NVENC/MFT pipeline width before Connect (default: 1920, 0=skip)\n"
        "  --prewarm-height <px>            Pre-warm GPU/NVENC/MFT pipeline height before Connect (default: 1080, 0=skip)\n"
        "  --visual-stimulus                Render controlled motion window on active LumaBridge virtual display\n"
        "  --require-virtual-stimulus       Fail if --visual-stimulus cannot identify the virtual display\n"
        "  --stimulus-fps <fps>             Stimulus refresh frequency in Hz (default: 60, range 1..120)\n"
        "  --stimulus-display <gdiName>     Optional explicit GDI display device (e.g. \\\\.\\DISPLAY2)\n"
        "  --stimulus-backend <mode>        Stimulus backend: auto|dxgi|gdi (default: auto)\n"
        "  --run-id <id>                    Associate execution RunId in JSON telemetry summary\n"
        "  --require-valid-timestamps       Fail if TimestampMeasurementErrors > 0 or coverage < 95%%\n"
        "  --require-width <px>             Require exact LastFrameWidth (and NVENC width if active)\n"
        "  --require-height <px>            Require exact LastFrameHeight (and NVENC height if active)\n"
        "  --min-nvenc-encoded-frames <n>   Minimum NVENC encoded frames required when --require-nvenc\n"
        "  --min-nvenc-encode-ratio <r>     Minimum NvencFramesEncoded/FramesValid ratio [0..1] when --require-nvenc\n"
        "  --max-nvenc-drop-ratio <r>       Maximum drop ratio (Dropped+QueueDrops)/Submitted [0..1] when --require-nvenc\n"
        "  --json-summary <path>            Write non-visual telemetry summary JSON to file\n"
        "  --quiet                          Suppress per-frame console output\n"
        "  --help                           Show this help message\n");
}

struct ProcessResourceSample
{
    bool Available{false};
    DWORD Pid{0U};
    uint64_t WorkingSetBytes{0ULL};
    uint64_t PeakWorkingSetBytes{0ULL};
    uint64_t PrivateBytes{0ULL};
    uint64_t KernelTime100Ns{0ULL};
    uint64_t UserTime100Ns{0ULL};
    uint64_t SampleQpc{0ULL};
    bool HandleCountAvailable{false};
    uint32_t HandleCount{0U};
    bool VramAvailable{false};
    uint64_t DedicatedVramUsageBytes{0ULL};
};

struct ProcessResourceReport
{
    bool Available{false};
    DWORD Pid{0U};
    uint64_t WorkingSetBytes{0ULL};
    uint64_t PeakWorkingSetBytes{0ULL};
    uint64_t PrivateBytes{0ULL};
    int64_t WorkingSetDeltaBytes{0LL};
    int64_t PrivateBytesDeltaBytes{0LL};
    uint64_t CpuTimeMs{0ULL};
    double CpuUsagePercent{0.0};
    bool HandleCountAvailable{false};
    uint32_t HandleCount{0U};
    int64_t HandleCountDelta{0LL};
    bool VramAvailable{false};
    uint64_t DedicatedVramUsageBytes{0ULL};
    int64_t DedicatedVramDeltaBytes{0LL};
};

bool
QueryProcessDedicatedVramBytes(
    ID3D11Device* d3dDevice,
    uint64_t& outUsageBytes
    ) noexcept
{
    outUsageBytes = 0ULL;
    if (d3dDevice == nullptr)
    {
        return false;
    }

    Microsoft::WRL::ComPtr<IDXGIDevice> dxgiDevice;
    if (FAILED(d3dDevice->QueryInterface(IID_PPV_ARGS(&dxgiDevice))) || dxgiDevice == nullptr)
    {
        return false;
    }
    Microsoft::WRL::ComPtr<IDXGIAdapter> adapter;
    if (FAILED(dxgiDevice->GetAdapter(&adapter)) || adapter == nullptr)
    {
        return false;
    }
    Microsoft::WRL::ComPtr<IDXGIAdapter3> adapter3;
    if (FAILED(adapter.As(&adapter3)) || adapter3 == nullptr)
    {
        return false;
    }

    DXGI_QUERY_VIDEO_MEMORY_INFO vmi{};
    if (FAILED(adapter3->QueryVideoMemoryInfo(0U, DXGI_MEMORY_SEGMENT_GROUP_LOCAL, &vmi)))
    {
        return false;
    }
    outUsageBytes = static_cast<uint64_t>(vmi.CurrentUsage);
    return true;
}

uint64_t
QueryHostQpcNow() noexcept
{
    LARGE_INTEGER li{};
    (void)QueryPerformanceCounter(&li);
    return (li.QuadPart > 0) ? static_cast<uint64_t>(li.QuadPart) : 0ULL;
}

uint64_t
QueryHostQpcFreqSafe() noexcept
{
    LARGE_INTEGER li{};
    (void)QueryPerformanceFrequency(&li);
    return (li.QuadPart > 0) ? static_cast<uint64_t>(li.QuadPart) : 10000000ULL;
}

uint64_t
FileTimeTo100Ns(const FILETIME& ft) noexcept
{
    ULARGE_INTEGER ui{};
    ui.LowPart = ft.dwLowDateTime;
    ui.HighPart = ft.dwHighDateTime;
    return ui.QuadPart;
}

ProcessResourceSample
SampleProcessResources(
    DWORD pid,
    ID3D11Device* d3dDevice = nullptr
    ) noexcept
{
    ProcessResourceSample sample{};
    sample.Pid = pid;
    sample.SampleQpc = QueryHostQpcNow();
    if (pid == 0U)
    {
        return sample;
    }

    HANDLE procHandle = nullptr;
    bool ownHandle = false;
    if (pid == GetCurrentProcessId())
    {
        procHandle = GetCurrentProcess();
    }
    else
    {
        procHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        ownHandle = (procHandle != nullptr);
    }

    if (procHandle == nullptr)
    {
        return sample;
    }

    PROCESS_MEMORY_COUNTERS_EX pmc{};
    pmc.cb = sizeof(pmc);
    const BOOL memOk = GetProcessMemoryInfo(
        procHandle,
        reinterpret_cast<PPROCESS_MEMORY_COUNTERS>(&pmc),
        sizeof(pmc));

    FILETIME createFt{};
    FILETIME exitFt{};
    FILETIME kernelFt{};
    FILETIME userFt{};
    const BOOL timeOk = GetProcessTimes(procHandle, &createFt, &exitFt, &kernelFt, &userFt);

    DWORD handleCount = 0U;
    const BOOL handleOk = GetProcessHandleCount(procHandle, &handleCount);

    if (ownHandle)
    {
        CloseHandle(procHandle);
    }

    if (memOk != FALSE)
    {
        sample.Available = true;
        sample.WorkingSetBytes = static_cast<uint64_t>(pmc.WorkingSetSize);
        sample.PeakWorkingSetBytes = static_cast<uint64_t>(pmc.PeakWorkingSetSize);
        sample.PrivateBytes = static_cast<uint64_t>(pmc.PrivateUsage);
    }
    if (timeOk != FALSE)
    {
        sample.Available = true;
        sample.KernelTime100Ns = FileTimeTo100Ns(kernelFt);
        sample.UserTime100Ns = FileTimeTo100Ns(userFt);
    }
    if (handleOk != FALSE)
    {
        sample.Available = true;
        sample.HandleCountAvailable = true;
        sample.HandleCount = static_cast<uint32_t>(handleCount);
    }
    if (d3dDevice != nullptr && pid == GetCurrentProcessId())
    {
        uint64_t vramBytes = 0ULL;
        if (QueryProcessDedicatedVramBytes(d3dDevice, vramBytes))
        {
            sample.VramAvailable = true;
            sample.DedicatedVramUsageBytes = vramBytes;
        }
    }
    return sample;
}

ProcessResourceReport
ComputeProcessResourceReport(
    const ProcessResourceSample& startSample,
    const ProcessResourceSample& endSample,
    uint64_t fallbackDurationUs,
    uint64_t qpcFreq,
    DWORD logicalCpuCount
    ) noexcept
{
    ProcessResourceReport report{};
    if (!endSample.Available)
    {
        return report;
    }

    report.Available = true;
    report.Pid = endSample.Pid;
    report.WorkingSetBytes = endSample.WorkingSetBytes;
    report.PeakWorkingSetBytes = endSample.PeakWorkingSetBytes;
    report.PrivateBytes = endSample.PrivateBytes;
    report.HandleCountAvailable = endSample.HandleCountAvailable;
    report.HandleCount = endSample.HandleCount;
    report.VramAvailable = endSample.VramAvailable;
    report.DedicatedVramUsageBytes = endSample.DedicatedVramUsageBytes;

    const uint64_t endCpu100Ns = endSample.KernelTime100Ns + endSample.UserTime100Ns;
    uint64_t deltaCpu100Ns = endCpu100Ns;
    uint64_t wallUs = fallbackDurationUs;

    if (startSample.Available && startSample.Pid == endSample.Pid)
    {
        report.WorkingSetDeltaBytes =
            static_cast<int64_t>(endSample.WorkingSetBytes) - static_cast<int64_t>(startSample.WorkingSetBytes);
        report.PrivateBytesDeltaBytes =
            static_cast<int64_t>(endSample.PrivateBytes) - static_cast<int64_t>(startSample.PrivateBytes);
        if (startSample.HandleCountAvailable && endSample.HandleCountAvailable)
        {
            report.HandleCountDelta =
                static_cast<int64_t>(endSample.HandleCount) - static_cast<int64_t>(startSample.HandleCount);
        }
        if (startSample.VramAvailable && endSample.VramAvailable)
        {
            report.DedicatedVramDeltaBytes =
                static_cast<int64_t>(endSample.DedicatedVramUsageBytes) -
                static_cast<int64_t>(startSample.DedicatedVramUsageBytes);
        }

        const uint64_t startCpu100Ns = startSample.KernelTime100Ns + startSample.UserTime100Ns;
        deltaCpu100Ns = (endCpu100Ns >= startCpu100Ns) ? (endCpu100Ns - startCpu100Ns) : 0ULL;
        if (endSample.SampleQpc > startSample.SampleQpc && qpcFreq > 0ULL)
        {
            wallUs = ((endSample.SampleQpc - startSample.SampleQpc) * 1000000ULL) / qpcFreq;
        }
    }

    report.CpuTimeMs = deltaCpu100Ns / 10000ULL;
    const double cpuDenom =
        static_cast<double>(wallUs) * 10.0 * static_cast<double>((logicalCpuCount > 0U) ? logicalCpuCount : 1U);
    if (cpuDenom > 0.0)
    {
        report.CpuUsagePercent = (static_cast<double>(deltaCpu100Ns) * 100.0) / cpuDenom;
    }
    return report;
}

void
WriteProcessResourceJson(
    std::ofstream& out,
    const char* name,
    const ProcessResourceReport& report,
    bool trailingComma
    )
{
    out << "    \"" << name << "\": {\n"
        << "      \"Available\": " << (report.Available ? "true" : "false") << ",\n"
        << "      \"Pid\": " << report.Pid << ",\n"
        << "      \"WorkingSetBytes\": " << report.WorkingSetBytes << ",\n"
        << "      \"PeakWorkingSetBytes\": " << report.PeakWorkingSetBytes << ",\n"
        << "      \"PrivateBytes\": " << report.PrivateBytes << ",\n"
        << "      \"WorkingSetDeltaBytes\": " << report.WorkingSetDeltaBytes << ",\n"
        << "      \"PrivateBytesDeltaBytes\": " << report.PrivateBytesDeltaBytes << ",\n"
        << "      \"CpuTimeMs\": " << report.CpuTimeMs << ",\n"
        << "      \"CpuUsagePercent\": " << report.CpuUsagePercent << ",\n"
        << "      \"HandleCountAvailable\": " << (report.HandleCountAvailable ? "true" : "false") << ",\n"
        << "      \"HandleCountStatus\": \"" << (report.HandleCountAvailable ? "MEASURED" : "NOT_MEASURED") << "\",\n"
        << "      \"HandleCount\": ";
    if (report.HandleCountAvailable)
    {
        out << report.HandleCount << ",\n"
            << "      \"HandleCountDelta\": " << report.HandleCountDelta << ",\n";
    }
    else
    {
        out << "null,\n"
            << "      \"HandleCountDelta\": null,\n";
    }
    out << "      \"VramAvailable\": " << (report.VramAvailable ? "true" : "false") << ",\n"
        << "      \"DedicatedVramStatus\": \"" << (report.VramAvailable ? "MEASURED" : "NOT_MEASURED") << "\",\n"
        << "      \"DedicatedVramUsageBytes\": ";
    if (report.VramAvailable)
    {
        out << report.DedicatedVramUsageBytes << ",\n"
            << "      \"DedicatedVramDeltaBytes\": " << report.DedicatedVramDeltaBytes << "\n";
    }
    else
    {
        out << "null,\n"
            << "      \"DedicatedVramDeltaBytes\": null\n";
    }
    out << "    }" << (trailingComma ? "," : "") << "\n";
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
    const char* methodStr = lumabridge::host::LatencyPercentileMethodToString(stats.PercentileMethod);
    out << indent << "\"" << name << "\": {\n"
        << indent << "  \"Available\": " << (stats.Available ? "true" : "false") << ",\n"
        << indent << "  \"PercentilesAvailable\": " << (stats.PercentilesAvailable ? "true" : "false") << ",\n"
        << indent << "  \"PercentilesAreEstimated\": " << (stats.PercentilesAreEstimated ? "true" : "false") << ",\n"
        << indent << "  \"PercentileMethod\": \"" << EscapeJsonString(methodStr) << "\",\n"
        << indent << "  \"SampleCount\": " << stats.SampleCount << ",\n"
        << indent << "  \"StoredSampleCount\": " << stats.StoredSampleCount << ",\n"
        << indent << "  \"SamplesTruncated\": " << (stats.SamplesTruncated ? "true" : "false") << ",\n"
        << indent << "  \"ReservoirSampled\": " << (stats.ReservoirSampled ? "true" : "false") << ",\n"
        << indent << "  \"MinUs\": " << stats.MinUs << ",\n"
        << indent << "  \"AvgUs\": " << stats.AvgUs << ",\n"
        << indent << "  \"MaxUs\": " << stats.MaxUs << ",\n"
        << indent << "  \"P50Us\": ";
    if (stats.PercentilesAvailable)
    {
        out << stats.P50Us;
    }
    else
    {
        out << "null";
    }
    out << ",\n"
        << indent << "  \"P95Us\": ";
    if (stats.PercentilesAvailable)
    {
        out << stats.P95Us;
    }
    else
    {
        out << "null";
    }
    out << ",\n"
        << indent << "  \"P99Us\": ";
    if (stats.PercentilesAvailable)
    {
        out << stats.P99Us;
    }
    else
    {
        out << "null";
    }
    out << ",\n"
        << indent << "  \"LastUs\": " << stats.LastUs << "\n"
        << indent << "}" << (trailingComma ? "," : "") << "\n";
}

using lumabridge::host::EvaluateHostGates;
using lumabridge::host::HostGateConfig;
using lumabridge::host::HostGateEvaluation;

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
    const lumabridge::host::H264WorkerMetricsSnapshot& h264Worker,
    const ProcessResourceReport& hostResources,
    const ProcessResourceReport& serverResources,
    DWORD logicalProcessorCount,
    const HostGateConfig& gateConfig,
    const HostGateEvaluation& gateEval,
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

    char h264WorkerHrBuf[16]{};
    _snprintf_s(
        h264WorkerHrBuf,
        sizeof(h264WorkerHrBuf),
        _TRUNCATE,
        "0x%08lX",
        static_cast<unsigned long>(h264Worker.LastHResult));

    char utcNowBuf[40]{};
    FormatUtcIso8601Now(utcNowBuf, sizeof(utcNowBuf));

    out << "{\n"
        << "  \"RunId\": \"" << EscapeJsonString(NarrowAsciiFromWide(gateConfig.RunId.c_str())) << "\",\n"
        << "  \"HostProcessId\": " << GetCurrentProcessId() << ",\n"
        << "  \"GeneratedAtUtc\": \"" << utcNowBuf << "\",\n"
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
        << "  \"CpuFramesReceived\": " << metrics.CpuFramesReceived << ",\n"
        << "  \"GpuFramesReceived\": " << metrics.GpuFramesReceived << ",\n"
        << "  \"GpuSharedResourcesOpened\": " << metrics.GpuSharedResourcesOpened << ",\n"
        << "  \"UnexpectedCpuFramesInGpuSession\": " << metrics.UnexpectedCpuFramesInGpuSession << ",\n"
        << "  \"UnexpectedGpuFramesInCpuSession\": " << metrics.UnexpectedGpuFramesInCpuSession << ",\n"
        << "  \"TransportContractViolations\": " << metrics.TransportContractViolations << ",\n"
        << "  \"GpuFramesOpened\": " << metrics.GpuFramesOpened << ",\n"
        << "  \"GpuFramesDropped\": " << metrics.GpuFramesDropped << ",\n"
        << "  \"GpuSharedOpenFailures\": " << metrics.GpuSharedOpenFailures << ",\n"
        << "  \"GpuSyncTimeouts\": " << metrics.GpuSyncTimeouts << ",\n"
        << "  \"AdapterMismatchErrors\": " << metrics.AdapterMismatchErrors << ",\n"
        << "  \"CpuStagingReadsPerformed\": " << metrics.CpuStagingReadsPerformed << ",\n"
        << "  \"FrameTargetReached\": " << (metrics.FrameTargetReached ? "true" : "false") << ",\n"
        << "  \"MinFramesReached\": " << (metrics.MinFramesReached ? "true" : "false") << ",\n"
        << "  \"DurationTargetReached\": " << (metrics.DurationTargetReached ? "true" : "false") << ",\n"
        << "  \"SafetyExecutionTimeoutHit\": " << (metrics.SafetyExecutionTimeoutHit ? "true" : "false") << ",\n"
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
        << "  \"OutOfOrderSequenceCount\": " << metrics.OutOfOrderSequenceCount << ",\n"
        << "  \"NonMonotonicTimestampCount\": " << metrics.NonMonotonicTimestampCount << ",\n"
        << "  \"MissingCoreTimestampCount\": " << metrics.MissingCoreTimestampCount << ",\n"
        << "  \"MissingPresentTimestampCount\": " << metrics.MissingPresentTimestampCount << ",\n"
        << "  \"FutureTimestampErrorCount\": " << metrics.FutureTimestampErrorCount << ",\n"
        << "  \"IncompatibleTimestampUnitsCount\": " << metrics.IncompatibleTimestampUnitsCount << ",\n"
        << "  \"QpcFrequencyMismatchCount\": " << metrics.QpcFrequencyMismatchCount << ",\n"
        << "  \"ValidCoreTimestampSamples\": " << metrics.ValidCoreTimestampSamples << ",\n"
        << "  \"ValidLiveTimestampSamples\": " << metrics.ValidLiveTimestampSamples << ",\n"
        << "  \"ValidPresentTimestampSamples\": " << metrics.ValidPresentTimestampSamples << ",\n"
        << "  \"CoreTimestampCoveragePercent\": " << metrics.CoreTimestampCoveragePercent << ",\n"
        << "  \"LiveTimestampCoveragePercent\": " << metrics.LiveTimestampCoveragePercent << ",\n"
        << "  \"PresentTimestampCoveragePercent\": " << metrics.PresentTimestampCoveragePercent << ",\n"
        << "  \"TemporalTelemetry\": {\n"
        << "    \"TotalFramesReceived\": " << metrics.FramesReceived << ",\n"
        << "    \"LiveFramesReceived\": " << metrics.LiveFramesReceived << ",\n"
        << "    \"TimestampMeasurementErrors\": " << metrics.TimestampMeasurementErrors << ",\n"
        << "    \"OutOfOrderSequenceCount\": " << metrics.OutOfOrderSequenceCount << ",\n"
        << "    \"NonMonotonicTimestampCount\": " << metrics.NonMonotonicTimestampCount << ",\n"
        << "    \"MissingCoreTimestampCount\": " << metrics.MissingCoreTimestampCount << ",\n"
        << "    \"MissingPresentTimestampCount\": " << metrics.MissingPresentTimestampCount << ",\n"
        << "    \"FutureTimestampErrorCount\": " << metrics.FutureTimestampErrorCount << ",\n"
        << "    \"IncompatibleTimestampUnitsCount\": " << metrics.IncompatibleTimestampUnitsCount << ",\n"
        << "    \"QpcFrequencyMismatchCount\": " << metrics.QpcFrequencyMismatchCount << ",\n"
        << "    \"ValidCoreTimestampSamples\": " << metrics.ValidCoreTimestampSamples << ",\n"
        << "    \"ValidLiveTimestampSamples\": " << metrics.ValidLiveTimestampSamples << ",\n"
        << "    \"ValidPresentTimestampSamples\": " << metrics.ValidPresentTimestampSamples << ",\n"
        << "    \"CoreTimestampCoveragePercent\": " << metrics.CoreTimestampCoveragePercent << ",\n"
        << "    \"LiveTimestampCoveragePercent\": " << metrics.LiveTimestampCoveragePercent << ",\n"
        << "    \"PresentTimestampCoveragePercent\": " << metrics.PresentTimestampCoveragePercent << "\n"
        << "  },\n"
        << "  \"LastFrameSequence\": " << metrics.LastFrameSequence << ",\n"
        << "  \"LastPresentationFrameNumber\": " << metrics.LastPresentationFrameNumber << ",\n"
        << "  \"LastFrameWidth\": " << metrics.LastFrameWidth << ",\n"
        << "  \"LastFrameHeight\": " << metrics.LastFrameHeight << ",\n"
        << "  \"LastPixelFormat\": " << metrics.LastPixelFormat << ",\n"
        << "  \"LastFrameChecksumCrc32\": \"" << crcBuf << "\",\n"
        << "  \"QpcClockValid\": " << (metrics.QpcClockValid ? "true" : "false") << ",\n"
        << "  \"QpcFrequency\": " << metrics.QpcFrequency << ",\n"
        << "  \"DurationCountsConnected\": " << (metrics.DurationCountsConnected ? "true" : "false") << ",\n"
        << "  \"RequestedDurationUs\": " << metrics.RequestedDurationUs << ",\n"
        << "  \"MaxExecutionDurationMs\": " << config.MaxExecutionDurationMs << ",\n"
        << "  \"TotalExecutionDurationUs\": " << metrics.TotalExecutionDurationUs << ",\n"
        << "  \"TotalConnectedDurationUs\": " << metrics.TotalConnectedDurationUs << ",\n"
        << "  \"ActiveStreamingDurationUs\": " << metrics.ActiveStreamingDurationUs << ",\n"
        << "  \"LiveStreamingDurationUs\": " << metrics.LiveStreamingDurationUs << ",\n"
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
    WriteLatencyStatsJson(out, "HostGpuCopyLatency", metrics.HostGpuCopyLatency, true);
    WriteLatencyStatsJson(out, "HostVerifyAckLatency", metrics.HostVerifyAckLatency, true);
    WriteLatencyStatsJson(out, "EndToEndLatency", metrics.EndToEndLatency, true);
    WriteLatencyStatsJson(out, "LiveEndToEndLatency", metrics.LiveEndToEndLatency, true);
    WriteLatencyStatsJson(out, "InterFrameInterval", metrics.InterFrameInterval, true);
    WriteLatencyStatsJson(out, "InterFrameJitter", metrics.InterFrameJitter, true);

    out << "  \"Nvenc\": {\n"
        << "    \"Requested\": " << (gateConfig.EnableNvenc ? "true" : "false") << ",\n"
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
        << "    \"SessionInitializeLatencyUs\": " << nvenc.SessionInitializeLatencyUs << ",\n"
        << "    \"MissingPresentTimestampCount\": " << nvenc.MissingPresentTimestampCount << ",\n"
        << "    \"MissingExtractTimestampCount\": " << nvenc.MissingExtractTimestampCount << ",\n"
        << "    \"InvalidTimestampCount\": " << nvenc.InvalidTimestampCount << ",\n"
        << "    \"ValidPresentToBitstreamSamples\": " << nvenc.ValidPresentToBitstreamSamples << ",\n"
        << "    \"ValidExtractToBitstreamSamples\": " << nvenc.ValidExtractToBitstreamSamples << ",\n"
        << "    \"PresentToBitstreamCoveragePercent\": " << nvenc.PresentToBitstreamCoveragePercent << ",\n"
        << "    \"ExtractToBitstreamCoveragePercent\": " << nvenc.ExtractToBitstreamCoveragePercent << ",\n"
        << "    \"LastNvencStatus\": " << static_cast<uint32_t>(nvenc.LastNvencStatus) << ",\n"
        << "    \"LastHResult\": \"" << nvencHrBuf << "\",\n"
        << "    \"RuntimeLibraryLoaded\": " << (nvenc.Capabilities.RuntimeLibraryLoaded ? "true" : "false") << ",\n"
        << "    \"H264Supported\": " << (nvenc.Capabilities.H264Supported ? "true" : "false") << ",\n"
        << "    \"SelectedInputFormatName\": \"" << EscapeJsonString(nvenc.Capabilities.SelectedInputFormatName) << "\",\n";
    WriteLatencyStatsJsonWithIndent(out, "    ", "EncodeLatencyUs", nvenc.EncodeLatencyUs, true);
    WriteLatencyStatsJsonWithIndent(out, "    ", "HostReceiveToSubmitLatencyUs", nvenc.HostReceiveToSubmitLatencyUs, true);
    WriteLatencyStatsJsonWithIndent(out, "    ", "FormatPrepareLatencyUs", nvenc.FormatPrepareLatencyUs, true);
    WriteLatencyStatsJsonWithIndent(out, "    ", "EncodePictureLatencyUs", nvenc.EncodePictureLatencyUs, true);
    WriteLatencyStatsJsonWithIndent(out, "    ", "BitstreamLockCopyLatencyUs", nvenc.BitstreamLockCopyLatencyUs, true);
    WriteLatencyStatsJsonWithIndent(out, "    ", "EncodedQueueWaitLatencyUs", nvenc.EncodedQueueWaitLatencyUs, true);
    WriteLatencyStatsJsonWithIndent(out, "    ", "EncodeInterFrameJitterUs", nvenc.EncodeInterFrameJitterUs, true);
    WriteLatencyStatsJsonWithIndent(out, "    ", "EncodedFrameSizeBytes", nvenc.EncodedFrameSizeBytes, true);
    WriteLatencyStatsJsonWithIndent(out, "    ", "PresentToBitstreamLatencyUs", nvenc.PresentToBitstreamLatencyUs, true);
    WriteLatencyStatsJsonWithIndent(out, "    ", "ExtractToBitstreamLatencyUs", nvenc.ExtractToBitstreamLatencyUs, false);
    out << "  },\n";

    out << "  \"H264DecodeValidation\": {\n"
        << "    \"Enabled\": " << (h264Validation.Enabled ? "true" : "false") << ",\n"
        << "    \"DecoderInitialized\": " << (h264Validation.DecoderInitialized ? "true" : "false") << ",\n"
        << "    \"StructuralDecodeValidated\": " << (h264Validation.StructuralDecodeValidated ? "true" : "false") << ",\n"
        << "    \"FidelityPsnrValidated\": " << (h264Validation.FidelityPsnrValidated ? "true" : "false") << ",\n"
        << "    \"ValidationMode\": \"" << EscapeJsonString(h264Validation.ValidationMode) << "\",\n"
        << "    \"DecoderName\": \"" << EscapeJsonString(h264Validation.DecoderName) << "\",\n"
        << "    \"MatchedColorMatrix\": \"" << EscapeJsonString(h264Validation.MatchedColorMatrix) << "\",\n"
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
        << "    \"MinCombinedPsnrDb\": " << h264Validation.MinCombinedPsnrDb << ",\n"
        << "    \"AvgCombinedPsnrDb\": " << h264Validation.AvgCombinedPsnrDb << ",\n"
        << "    \"Passed\": " << (h264Validation.Passed ? "true" : "false") << ",\n"
        << "    \"LastHResult\": \"" << h264HrBuf << "\",\n"
        << "    \"Worker\": {\n"
        << "      \"Enabled\": " << (h264Worker.Enabled ? "true" : "false") << ",\n"
        << "      \"Healthy\": " << (h264Worker.Healthy ? "true" : "false") << ",\n"
        << "      \"SynchronousFallbackActive\": " << (h264Worker.SynchronousFallbackActive ? "true" : "false") << ",\n"
        << "      \"QueueCapacity\": " << h264Worker.QueueCapacity << ",\n"
        << "      \"PacketsEnqueued\": " << h264Worker.PacketsEnqueued << ",\n"
        << "      \"PacketsDequeued\": " << h264Worker.PacketsDequeued << ",\n"
        << "      \"PacketsProcessed\": " << h264Worker.PacketsProcessed << ",\n"
        << "      \"PacketsRejected\": " << h264Worker.PacketsRejected << ",\n"
        << "      \"QueuePeakDepth\": " << h264Worker.QueuePeakDepth << ",\n"
        << "      \"QueuePendingAtShutdown\": " << h264Worker.QueuePendingAtShutdown << ",\n"
        << "      \"QueueRemainingAtExit\": " << h264Worker.QueueRemainingAtExit << ",\n"
        << "      \"QueueFullWaitCount\": " << h264Worker.QueueFullWaitCount << ",\n"
        << "      \"QueueWaitTimeoutCount\": " << h264Worker.QueueWaitTimeoutCount << ",\n"
        << "      \"WorkerFailureCount\": " << h264Worker.WorkerFailureCount << ",\n"
        << "      \"DrainDeadlineExceeded\": " << (h264Worker.DrainDeadlineExceeded ? "true" : "false") << ",\n"
        << "      \"ComBalanced\": " << (h264Worker.ComBalanced ? "true" : "false") << ",\n"
        << "      \"WorkerComInitCount\": " << h264Worker.WorkerComInitCount << ",\n"
        << "      \"WorkerComUninitCount\": " << h264Worker.WorkerComUninitCount << ",\n"
        << "      \"CompletionState\": \"" << EscapeJsonString(lumabridge::host::H264WorkerCompletionStateToString(h264Worker.CompletionState)) << "\",\n"
        << "      \"LastHResult\": \"" << h264WorkerHrBuf << "\",\n"
        << "      \"LastErrorMessage\": \"" << EscapeJsonString(h264Worker.LastErrorMessage) << "\"\n"
        << "    },\n";
    WriteLatencyStatsJsonWithIndent(out, "    ", "MftDecodeLatencyUs", h264Validation.MftDecodeLatencyUs, false);
    out << "  },\n";

    out << "  \"ResourceUsage\": {\n"
        << "    \"LogicalProcessorCount\": " << logicalProcessorCount << ",\n";
    WriteProcessResourceJson(out, "Host", hostResources, true);
    WriteProcessResourceJson(out, "Server", serverResources, false);
    out << "  },\n";

    out << "  \"VisualStimulus\": {\n"
        << "    \"Requested\": " << (stimulus.Requested ? "true" : "false") << ",\n"
        << "    \"VirtualDisplayIdentified\": " << (stimulus.VirtualDisplayIdentified ? "true" : "false") << ",\n"
        << "    \"Started\": " << (stimulus.Started ? "true" : "false") << ",\n"
        << "    \"Active\": " << (stimulus.Active ? "true" : "false") << ",\n"
        << "    \"CompletedCleanly\": " << (stimulus.CompletedCleanly ? "true" : "false") << ",\n"
        << "    \"HighResolutionTimerUsed\": " << (stimulus.HighResolutionTimerUsed ? "true" : "false") << ",\n"
        << "    \"TargetFps\": " << stimulus.TargetFps << ",\n"
        << "    \"BackendRequested\": \"" << EscapeJsonString(stimulus.BackendRequested) << "\",\n"
        << "    \"BackendActive\": \"" << EscapeJsonString(stimulus.BackendActive) << "\",\n"
        << "    \"FallbackFromDxgiOccurred\": " << (stimulus.FallbackFromDxgiOccurred ? "true" : "false") << ",\n"
        << "    \"FallbackReason\": \"" << EscapeJsonString(stimulus.FallbackReason) << "\",\n"
        << "    \"PlannedTicks\": " << stimulus.PlannedTicks << ",\n"
        << "    \"ExecutedTicks\": " << stimulus.ExecutedTicks << ",\n"
        << "    \"TicksPresented\": " << stimulus.TicksPresented << ",\n"
        << "    \"PaintCount\": " << stimulus.PaintCount << ",\n"
        << "    \"PresentRequests\": " << stimulus.PresentRequests << ",\n"
        << "    \"PresentSucceeded\": " << stimulus.PresentSucceeded << ",\n"
        << "    \"PresentOccluded\": " << stimulus.PresentOccluded << ",\n"
        << "    \"PresentFailures\": " << stimulus.PresentFailures << ",\n"
        << "    \"SwapChainRecreations\": " << stimulus.SwapChainRecreations << ",\n"
        << "    \"PresentFastReturnGuardCount\": " << stimulus.PresentFastReturnGuardCount << ",\n"
        << "    \"DeadlineMissCount\": " << stimulus.DeadlineMissCount << ",\n"
        << "    \"DurationUs\": " << stimulus.DurationUs << ",\n"
        << "    \"TickIntervalAvgUs\": " << stimulus.TickIntervalAvgUs << ",\n"
        << "    \"TickIntervalP95Us\": " << stimulus.TickIntervalP95Us << ",\n"
        << "    \"TickIntervalMaxUs\": " << stimulus.TickIntervalMaxUs << ",\n"
        << "    \"WaitLatencyAvgUs\": " << stimulus.WaitLatencyAvgUs << ",\n"
        << "    \"WaitLatencyP95Us\": " << stimulus.WaitLatencyP95Us << ",\n"
        << "    \"WaitLatencyMaxUs\": " << stimulus.WaitLatencyMaxUs << ",\n"
        << "    \"PresentLatencyAvgUs\": " << stimulus.PresentLatencyAvgUs << ",\n"
        << "    \"PresentLatencyP95Us\": " << stimulus.PresentLatencyP95Us << ",\n"
        << "    \"PresentLatencyMaxUs\": " << stimulus.PresentLatencyMaxUs << ",\n"
        << "    \"CumulativeDriftUs\": " << stimulus.CumulativeDriftUs << ",\n"
        << "    \"MaxInterPresentGapUs\": " << stimulus.MaxInterPresentGapUs << ",\n"
        << "    \"InterPresentGapsOver25ms\": " << stimulus.InterPresentGapsOver25ms << ",\n"
        << "    \"AchievedFps\": " << stimulus.AchievedFps << ",\n"
        << "    \"DisplayDeviceName\": \"" << EscapeJsonString(NarrowAsciiFromWide(stimulus.DisplayDeviceName.c_str())) << "\",\n"
        << "    \"BoundsLeft\": " << stimulus.BoundsLeft << ",\n"
        << "    \"BoundsTop\": " << stimulus.BoundsTop << ",\n"
        << "    \"BoundsWidth\": " << stimulus.BoundsWidth << ",\n"
        << "    \"BoundsHeight\": " << stimulus.BoundsHeight << ",\n"
        << "    \"IdentificationSource\": \"" << EscapeJsonString(stimulus.IdentificationSource) << "\",\n"
        << "    \"ErrorMessage\": \"" << EscapeJsonString(stimulus.ErrorMessage) << "\"\n"
        << "  },\n"
        << "  \"PacingCorrelation\": {\n"
        << "    \"InterArrivalGapMaxUs\": " << metrics.PacingCorrelation.InterArrivalGapMaxUs << ",\n"
        << "    \"InterArrivalGapsOver25ms\": " << metrics.PacingCorrelation.InterArrivalGapsOver25ms << ",\n"
        << "    \"InterArrivalGapsOver33ms\": " << metrics.PacingCorrelation.InterArrivalGapsOver33ms << ",\n"
        << "    \"PresentationDeltaDistribution\": {\n"
        << "      \"Delta0\": " << metrics.PacingCorrelation.PresentationDelta0Count << ",\n"
        << "      \"Delta1\": " << metrics.PacingCorrelation.PresentationDelta1Count << ",\n"
        << "      \"Delta2\": " << metrics.PacingCorrelation.PresentationDelta2Count << ",\n"
        << "      \"Delta3Plus\": " << metrics.PacingCorrelation.PresentationDelta3PlusCount << ",\n"
        << "      \"Regression\": " << metrics.PacingCorrelation.PresentationDeltaRegressionCount << "\n"
        << "    },\n"
        << "    \"SequenceDeltaDistribution\": {\n"
        << "      \"Delta1\": " << metrics.PacingCorrelation.SequenceDelta1Count << ",\n"
        << "      \"Gap\": " << metrics.PacingCorrelation.SequenceDeltaGapCount << ",\n"
        << "      \"NonPositive\": " << metrics.PacingCorrelation.SequenceDeltaNonPositiveCount << "\n"
        << "    },\n"
        << "    \"TotalAnomaliesRecorded\": " << metrics.PacingCorrelation.TotalAnomaliesRecorded << ",\n"
        << "    \"RecentAnomalies\": [\n";
    for (size_t idx = 0U; idx < metrics.PacingCorrelation.RecentAnomalies.size(); ++idx)
    {
        const auto& a = metrics.PacingCorrelation.RecentAnomalies[idx];
        out << "      {"
            << "\"FrameSequence\": " << a.FrameSequence << ", "
            << "\"PresentationFrameNumber\": " << a.PresentationFrameNumber << ", "
            << "\"InterArrivalGapUs\": " << a.InterArrivalGapUs << ", "
            << "\"PresentationDelta\": " << a.PresentationDelta << ", "
            << "\"SequenceDelta\": " << a.SequenceDelta << ", "
            << "\"TransportMode\": " << a.TransportMode
            << "}" << ((idx + 1U < metrics.PacingCorrelation.RecentAnomalies.size()) ? "," : "") << "\n";
    }
    out << "    ]\n"
        << "  },\n"
        << "  \"GateEvaluation\": {\n"
        << "    \"RequireGpuShared\": " << (gateConfig.RequireGpuShared ? "true" : "false") << ",\n"
        << "    \"RequireNvenc\": " << (gateConfig.RequireNvenc ? "true" : "false") << ",\n"
        << "    \"VerifyH264Decode\": " << (gateConfig.VerifyH264Decode ? "true" : "false") << ",\n"
        << "    \"RequireValidTimestamps\": " << (gateConfig.RequireValidTimestamps ? "true" : "false") << ",\n"
        << "    \"RequireWidth\": " << gateConfig.RequireWidth << ",\n"
        << "    \"RequireHeight\": " << gateConfig.RequireHeight << ",\n"
        << "    \"MinNvencEncodedFrames\": " << gateConfig.MinNvencEncodedFrames << ",\n"
        << "    \"MinNvencEncodeRatio\": " << gateConfig.MinNvencEncodeRatio << ",\n"
        << "    \"MaxNvencDropRatio\": " << gateConfig.MaxNvencDropRatio << ",\n"
        << "    \"IntegrityOk\": " << (gateEval.IntegrityOk ? "true" : "false") << ",\n"
        << "    \"MinFramesOk\": " << (gateEval.MinFramesOk ? "true" : "false") << ",\n"
        << "    \"MaxTargetOk\": " << (gateEval.MaxTargetOk ? "true" : "false") << ",\n"
        << "    \"DurationOk\": " << (gateEval.DurationOk ? "true" : "false") << ",\n"
        << "    \"StimulusOk\": " << (gateEval.StimulusOk ? "true" : "false") << ",\n"
        << "    \"TransportContractOk\": " << (gateEval.TransportContractOk ? "true" : "false") << ",\n"
        << "    \"GpuTransportOk\": " << (gateEval.GpuTransportOk ? "true" : "false") << ",\n"
        << "    \"NvencOk\": " << (gateEval.NvencOk ? "true" : "false") << ",\n"
        << "    \"H264DecodeOk\": " << (gateEval.H264DecodeOk ? "true" : "false") << ",\n"
        << "    \"H264PsnrOk\": " << (gateEval.H264PsnrOk ? "true" : "false") << ",\n"
        << "    \"TimestampsOk\": " << (gateEval.TimestampsOk ? "true" : "false") << ",\n"
        << "    \"ResolutionOk\": " << (gateEval.ResolutionOk ? "true" : "false") << ",\n"
        << "    \"OverallExitOk\": " << (gateEval.OverallExitOk ? "true" : "false") << "\n"
        << "  },\n"
        << "  \"SummaryComplete\": true\n"
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
    lumabridge::host::StimulusBackend stimulusBackend = lumabridge::host::StimulusBackend::Auto;
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
    bool verifyH264Psnr = false;
    uint32_t prewarmWidth = 1920U;
    uint32_t prewarmHeight = 1080U;
    HostGateConfig gateConfig{};

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
        else if (arg == L"--duration-counts-connected")
        {
            config.DurationCountsConnected = true;
        }
        else if (arg == L"--max-execution-ms" && (i + 1) < argc)
        {
            uint64_t val = 0ULL;
            if (!ParseUnsigned64(argv[++i], val) || val > 0xFFFFFFFFULL)
            {
                std::fprintf(stderr, "Invalid --max-execution-ms value.\n");
                return EXIT_FAILURE;
            }
            config.MaxExecutionDurationMs = static_cast<uint32_t>(val);
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
        else if (arg == L"--verify-h264-psnr")
        {
            verifyH264Psnr = true;
            verifyH264Decode = true;
        }
        else if (arg == L"--prewarm-width" && (i + 1) < argc)
        {
            uint64_t val = 0ULL;
            if (!ParseUnsigned64(argv[++i], val) || val > 7680ULL)
            {
                std::fprintf(stderr, "Invalid --prewarm-width value.\n");
                return EXIT_FAILURE;
            }
            prewarmWidth = static_cast<uint32_t>(val);
        }
        else if (arg == L"--prewarm-height" && (i + 1) < argc)
        {
            uint64_t val = 0ULL;
            if (!ParseUnsigned64(argv[++i], val) || val > 4320ULL)
            {
                std::fprintf(stderr, "Invalid --prewarm-height value.\n");
                return EXIT_FAILURE;
            }
            prewarmHeight = static_cast<uint32_t>(val);
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
        else if (arg == L"--stimulus-backend" && (i + 1) < argc)
        {
            if (!lumabridge::host::ParseStimulusBackend(argv[++i], stimulusBackend))
            {
                std::fprintf(stderr, "Invalid --stimulus-backend value (must be auto|dxgi|gdi).\n");
                return EXIT_FAILURE;
            }
        }
        else if (arg == L"--run-id" && (i + 1) < argc)
        {
            gateConfig.RunId = argv[++i];
        }
        else if (arg == L"--require-valid-timestamps")
        {
            gateConfig.RequireValidTimestamps = true;
        }
        else if (arg == L"--require-width" && (i + 1) < argc)
        {
            uint64_t val = 0ULL;
            if (!ParseUnsigned64(argv[++i], val) || val == 0ULL || val > 7680ULL)
            {
                std::fprintf(stderr, "Invalid --require-width value.\n");
                return EXIT_FAILURE;
            }
            gateConfig.RequireWidth = static_cast<uint32_t>(val);
        }
        else if (arg == L"--require-height" && (i + 1) < argc)
        {
            uint64_t val = 0ULL;
            if (!ParseUnsigned64(argv[++i], val) || val == 0ULL || val > 4320ULL)
            {
                std::fprintf(stderr, "Invalid --require-height value.\n");
                return EXIT_FAILURE;
            }
            gateConfig.RequireHeight = static_cast<uint32_t>(val);
        }
        else if (arg == L"--min-nvenc-encoded-frames" && (i + 1) < argc)
        {
            uint64_t val = 0ULL;
            if (!ParseUnsigned64(argv[++i], val))
            {
                std::fprintf(stderr, "Invalid --min-nvenc-encoded-frames value.\n");
                return EXIT_FAILURE;
            }
            gateConfig.MinNvencEncodedFrames = val;
        }
        else if (arg == L"--min-nvenc-encode-ratio" && (i + 1) < argc)
        {
            double val = 0.0;
            if (!ParseDouble(argv[++i], val) || val < 0.0 || val > 1.0)
            {
                std::fprintf(stderr, "Invalid --min-nvenc-encode-ratio value (must be 0.0..1.0).\n");
                return EXIT_FAILURE;
            }
            gateConfig.MinNvencEncodeRatio = val;
        }
        else if (arg == L"--max-nvenc-drop-ratio" && (i + 1) < argc)
        {
            double val = 1.0;
            if (!ParseDouble(argv[++i], val) || val < 0.0 || val > 1.0)
            {
                std::fprintf(stderr, "Invalid --max-nvenc-drop-ratio value (must be 0.0..1.0).\n");
                return EXIT_FAILURE;
            }
            gateConfig.MaxNvencDropRatio = val;
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

    if (verifyH264Decode || verifyH264Psnr)
    {
        enableNvenc = true;
    }
    gateConfig.RequireGpuShared = requireGpuShared;
    gateConfig.EnableNvenc = enableNvenc;
    gateConfig.RequireNvenc = requireNvenc;
    gateConfig.VerifyH264Decode = verifyH264Decode;
    gateConfig.VerifyH264Psnr = verifyH264Psnr;
    gateConfig.RequireVirtualStimulus = requireVirtualStimulus;

    SYSTEM_INFO sysInfo{};
    GetSystemInfo(&sysInfo);
    const DWORD logicalCpuCount = (sysInfo.dwNumberOfProcessors > 0U) ? sysInfo.dwNumberOfProcessors : 1U;

    lumabridge::host::VirtualDisplayStimulus stimulus;
    if (enableVisualStimulus)
    {
        lumabridge::host::VirtualDisplayStimulusConfig stimCfg{};
        stimCfg.TargetFps = stimulusFps;
        stimCfg.Backend = stimulusBackend;
        stimCfg.ExplicitDisplayName = stimulusDisplayName;
        const bool stimStarted = stimulus.Start(stimCfg);
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
            const lumabridge::host::H264WorkerMetricsSnapshot emptyH264Worker{};
            const ProcessResourceReport emptyRes{};
            const HostGateEvaluation preGateEval = EvaluateHostGates(
                config,
                emptyMetrics,
                stimPreSnap,
                emptyNvenc,
                emptyH264,
                emptyH264Worker,
                gateConfig,
                false,
                S_OK,
                E_FAIL);
            (void)WriteJsonSummary(
                jsonSummaryPath,
                config,
                emptyMetrics,
                stimPreSnap,
                emptyNvenc,
                emptyH264,
                emptyH264Worker,
                emptyRes,
                emptyRes,
                logicalCpuCount,
                gateConfig,
                preGateEval,
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
    if (verifyH264Decode || verifyH264Psnr)
    {
        enableNvenc = true;
    }
    h264Validator.Configure(
        verifyH264Decode,
        stimulusFps,
        verifyH264Psnr || config.VerifySyntheticPattern,
        25.0);
    lumabridge::host::AsyncH264ValidationWorker asyncH264Worker(h264Validator);
    bool loggedWorkerEnqueueFailure = false;

    bool nvencInitialized = false;
    bool nvencInitFatal = false;
    HRESULT nvencLastHr = S_OK;
    ID3D11Device* nvencBoundDevice = nullptr;
    uint32_t nvencWidth = 0U;
    uint32_t nvencHeight = 0U;
    uint64_t nvencSubmitCount = 0ULL;

    lumabridge::host::FrameConsumer consumer(config);

    if (enableNvenc)
    {
        const HRESULT prewarmDevHr = consumer.PrewarmD3d11Device();
        if (SUCCEEDED(prewarmDevHr) &&
            prewarmWidth > 0U &&
            prewarmHeight > 0U &&
            consumer.GetD3d11Device() != nullptr &&
            consumer.GetD3d11Context() != nullptr)
        {
            lumabridge::host::NvencEncoderConfig preCfg{};
            preCfg.Width = prewarmWidth;
            preCfg.Height = prewarmHeight;
            preCfg.TargetFps = stimulusFps;
            preCfg.BitrateBps = nvencBitrateBps;
            preCfg.MaxBitrateBps = (std::max)(nvencBitrateBps, nvencBitrateBps + nvencBitrateBps / 3U);
            preCfg.GopLength = nvencGopLength;
            preCfg.LowLatencyTuning = true;
            preCfg.RepeatSpsPpsEveryIdr = true;
            preCfg.ColorMode = nvencColorMode;

            const HRESULT preEncHr = nvencEncoder.Initialize(
                consumer.GetD3d11Device(),
                consumer.GetD3d11Context(),
                preCfg);
            if (SUCCEEDED(preEncHr))
            {
                nvencInitialized = true;
                nvencBoundDevice = consumer.GetD3d11Device();
                nvencWidth = prewarmWidth;
                nvencHeight = prewarmHeight;
            }
            else if (!quiet)
            {
                std::fprintf(
                    stderr,
                    "[LB-HOST] NVENC pre-warm skipped (hr=0x%08lX); will initialize on live adapter.\n",
                    static_cast<unsigned long>(preEncHr));
            }
        }

        if (verifyH264Decode)
        {
            if (!asyncH264Worker.Start(prewarmWidth, prewarmHeight, stimulusFps))
            {
                const auto wSnap = asyncH264Worker.GetMetricsSnapshot();
                std::fprintf(
                    stderr,
                    "[LB-HOST] Async H.264 validation worker startup failed (hr=0x%08lX): %s\n",
                    static_cast<unsigned long>(wSnap.LastHResult),
                    wSnap.LastErrorMessage.c_str());
            }
        }
    }

    const uint64_t hostQpcFreq = QueryHostQpcFreqSafe();
    const ProcessResourceSample hostStartSample = SampleProcessResources(GetCurrentProcessId(), consumer.GetD3d11Device());
    ProcessResourceSample serverStartSample{};
    bool serverBaselineCaptured = false;

    const HRESULT runHr = consumer.RunLoop(
        stopEvent,
        [quiet,
         &consumer,
         &serverStartSample,
         &serverBaselineCaptured](const lumabridge::ipc::FrameIpcFrameHeader& header, const std::vector<uint8_t>&) {
            if (!serverBaselineCaptured)
            {
                const auto snap = consumer.GetMetricsSnapshot();
                if (snap.ServerProcessId != 0U)
                {
                    serverStartSample = SampleProcessResources(snap.ServerProcessId);
                    serverBaselineCaptured = true;
                }
            }
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
         &consumer,
         &serverStartSample,
         &serverBaselineCaptured,
         &nvencEncoder,
         &asyncH264Worker,
         &loggedWorkerEnqueueFailure,
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
            if (!serverBaselineCaptured)
            {
                const auto snap = consumer.GetMetricsSnapshot();
                if (snap.ServerProcessId != 0U)
                {
                    serverStartSample = SampleProcessResources(snap.ServerProcessId);
                    serverBaselineCaptured = true;
                }
            }
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
                nullptr,
                consumer.GetLastFrameReceiveQpc());
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
                if (verifyH264Decode)
                {
                    const auto enqStatus = asyncH264Worker.Enqueue(std::move(pkt));
                    if (enqStatus != lumabridge::host::H264WorkerEnqueueStatus::Enqueued &&
                        enqStatus != lumabridge::host::H264WorkerEnqueueStatus::ProcessedSynchronously &&
                        !loggedWorkerEnqueueFailure)
                    {
                        loggedWorkerEnqueueFailure = true;
                        std::fprintf(
                            stderr,
                            "[LB-HOST] Async H.264 worker enqueue failed (%s).\n",
                            lumabridge::host::H264WorkerEnqueueStatusToString(enqStatus));
                    }
                }
            }
        });

    const lumabridge::host::HostConsumerMetricsSnapshot metrics = consumer.GetMetricsSnapshot();

    lumabridge::host::EncodedFramePacket remainingPkt{};
    while (nvencEncoder.TryPopEncodedFrame(remainingPkt))
    {
        if (verifyH264Decode)
        {
            const auto enqStatus = asyncH264Worker.Enqueue(std::move(remainingPkt));
            if (enqStatus != lumabridge::host::H264WorkerEnqueueStatus::Enqueued &&
                enqStatus != lumabridge::host::H264WorkerEnqueueStatus::ProcessedSynchronously &&
                !loggedWorkerEnqueueFailure)
            {
                loggedWorkerEnqueueFailure = true;
                std::fprintf(
                    stderr,
                    "[LB-HOST] Async H.264 worker post-loop drain enqueue failed (%s).\n",
                    lumabridge::host::H264WorkerEnqueueStatusToString(enqStatus));
            }
        }
    }
    if (verifyH264Decode)
    {
        asyncH264Worker.StopAndDrain(metrics.SafetyExecutionTimeoutHit);
    }
    else
    {
        h264Validator.Finish();
    }

    (void)SetConsoleCtrlHandler(ConsoleCtrlHandler, FALSE);
    g_ConsoleStopEvent = nullptr;
    CloseHandle(stopEvent);

    stimulus.Stop();
    const lumabridge::host::StimulusMetricsSnapshot stimSnap = stimulus.GetMetricsSnapshot();
    const lumabridge::host::NvencMetricsSnapshot nvencSnap = nvencEncoder.GetMetricsSnapshot();
    const lumabridge::host::H264WorkerMetricsSnapshot h264WorkerSnap = asyncH264Worker.GetMetricsSnapshot();
    const lumabridge::host::H264ValidationSummary h264Snap =
        verifyH264Decode ? asyncH264Worker.GetFinalSessionSummary() : h264Validator.GetSummary();

    const ProcessResourceSample hostEndSample = SampleProcessResources(GetCurrentProcessId(), consumer.GetD3d11Device());
    const ProcessResourceSample serverEndSample = SampleProcessResources(metrics.ServerProcessId);
    const ProcessResourceReport hostResReport = ComputeProcessResourceReport(
        hostStartSample,
        hostEndSample,
        metrics.TotalExecutionDurationUs,
        hostQpcFreq,
        logicalCpuCount);
    const ProcessResourceReport serverResReport = ComputeProcessResourceReport(
        serverStartSample,
        serverEndSample,
        metrics.TotalExecutionDurationUs,
        hostQpcFreq,
        logicalCpuCount);

    h264Validator.Shutdown();
    nvencEncoder.Shutdown();

    const HostGateEvaluation gateEval = EvaluateHostGates(
        config,
        metrics,
        stimSnap,
        nvencSnap,
        h264Snap,
        h264WorkerSnap,
        gateConfig,
        nvencInitFatal,
        nvencLastHr,
        runHr);

    const bool jsonOk = WriteJsonSummary(
        jsonSummaryPath,
        config,
        metrics,
        stimSnap,
        nvencSnap,
        h264Snap,
        h264WorkerSnap,
        hostResReport,
        serverResReport,
        logicalCpuCount,
        gateConfig,
        gateEval,
        runHr);

    std::printf(
        "[LB-HOST] Summary: hr=0x%08lX exit=%s normal=%u healthy=%u qpcOk=%u durOk=%u session=%llu serverPid=%u connects=%llu reconnects=%llu "
        "frames=%llu valid=%llu live=%llu preConn=%llu bytes=%llu gaps=%llu crcErr=%llu patternErr=%llu protoErr=%llu "
        "recTimeout=%llu fatalTimeout=%llu partialTimeout=%llu tsErr=%llu covCore=%.1f%% covLive=%.1f%% covPres=%.1f%% "
        "execMs=%llu connMs=%llu activeMs=%llu idleMs=%llu execFps=%.2f activeFps=%.2f liveFps=%.2f sampleOk=%u "
        "avgE2EUs=%llu liveAvgE2EUs=%llu liveP95Us=%llu liveP99Us=%llu ipcAvgUs=%llu jitterAvgUs=%llu\n",
        static_cast<unsigned long>(runHr),
        lumabridge::host::HostExitReasonToString(metrics.ExitReason),
        metrics.HostProcessExitedNormally ? 1U : 0U,
        metrics.TransportHealthy ? 1U : 0U,
        metrics.QpcClockValid ? 1U : 0U,
        gateEval.DurationOk ? 1U : 0U,
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
        metrics.CoreTimestampCoveragePercent,
        metrics.LiveTimestampCoveragePercent,
        metrics.PresentTimestampCoveragePercent,
        static_cast<unsigned long long>(metrics.TotalExecutionDurationUs / 1000ULL),
        static_cast<unsigned long long>(metrics.TotalConnectedDurationUs / 1000ULL),
        static_cast<unsigned long long>(metrics.ActiveStreamingDurationUs / 1000ULL),
        static_cast<unsigned long long>(metrics.TotalIdleWaitDurationUs / 1000ULL),
        metrics.AverageExecutionFps,
        metrics.ObservedActiveFps,
        metrics.SustainedLiveFps,
        metrics.FpsSampleSufficient ? 1U : 0U,
        static_cast<unsigned long long>(metrics.AvgEndToEndLatencyUs),
        static_cast<unsigned long long>(metrics.LiveEndToEndLatency.AvgUs),
        static_cast<unsigned long long>(metrics.LiveEndToEndLatency.P95Us),
        static_cast<unsigned long long>(metrics.LiveEndToEndLatency.P99Us),
        static_cast<unsigned long long>(metrics.IpcTransitLatency.AvgUs),
        static_cast<unsigned long long>(metrics.InterFrameJitter.AvgUs));

    std::printf(
        "[LB-HOST] Transport: mode=%s fallback=%u pool=%u/%u cpuRx=%llu gpuRx=%llu gpuOpened=%llu gpuDrop=%llu "
        "unexpCpu=%llu contractViol=%llu openErr=%llu syncTimeout=%llu luidErr=%llu cpuReads=%llu "
        "syncWaitAvgUs=%llu syncWaitP95Us=%llu hostCopyAvgUs=%llu\n",
        TransportModeToString(metrics.NegotiatedTransportMode),
        metrics.FallbackToCpuActivated ? 1U : 0U,
        metrics.SharedTexturePoolSize,
        metrics.SharedTexturePoolPeakUsage,
        static_cast<unsigned long long>(metrics.CpuFramesReceived),
        static_cast<unsigned long long>(metrics.GpuFramesReceived),
        static_cast<unsigned long long>(metrics.GpuFramesOpened),
        static_cast<unsigned long long>(metrics.GpuFramesDropped),
        static_cast<unsigned long long>(metrics.UnexpectedCpuFramesInGpuSession),
        static_cast<unsigned long long>(metrics.TransportContractViolations),
        static_cast<unsigned long long>(metrics.GpuSharedOpenFailures),
        static_cast<unsigned long long>(metrics.GpuSyncTimeouts),
        static_cast<unsigned long long>(metrics.AdapterMismatchErrors),
        static_cast<unsigned long long>(metrics.CpuStagingReadsPerformed),
        static_cast<unsigned long long>(metrics.GpuSyncWaitLatency.AvgUs),
        static_cast<unsigned long long>(metrics.GpuSyncWaitLatency.P95Us),
        static_cast<unsigned long long>(metrics.HostGpuCopyLatency.AvgUs));

    if (enableNvenc || nvencSnap.NvencFramesSubmitted > 0ULL)
    {
        std::printf(
            "[LB-HOST] NVENC: init=%u initUs=%llu fmt=%s submitted=%llu encoded=%llu keys=%llu drops=%llu resets=%llu "
            "encAvgUs=%llu encP95Us=%llu prepAvgUs=%llu picAvgUs=%llu lockAvgUs=%llu bsCov=%.1f%% outFps=%.2f bitrate=%llu bytes=%llu\n",
            nvencSnap.Initialized ? 1U : 0U,
            static_cast<unsigned long long>(nvencSnap.SessionInitializeLatencyUs),
            nvencSnap.Capabilities.SelectedInputFormatName.c_str(),
            static_cast<unsigned long long>(nvencSnap.NvencFramesSubmitted),
            static_cast<unsigned long long>(nvencSnap.NvencFramesEncoded),
            static_cast<unsigned long long>(nvencSnap.NvencKeyFramesEncoded),
            static_cast<unsigned long long>(nvencSnap.NvencDroppedFrames),
            static_cast<unsigned long long>(nvencSnap.NvencEncoderResets),
            static_cast<unsigned long long>(nvencSnap.EncodeLatencyUs.AvgUs),
            static_cast<unsigned long long>(nvencSnap.EncodeLatencyUs.P95Us),
            static_cast<unsigned long long>(nvencSnap.FormatPrepareLatencyUs.AvgUs),
            static_cast<unsigned long long>(nvencSnap.EncodePictureLatencyUs.AvgUs),
            static_cast<unsigned long long>(nvencSnap.BitstreamLockCopyLatencyUs.AvgUs),
            nvencSnap.ExtractToBitstreamCoveragePercent,
            nvencSnap.EncoderOutputFps,
            static_cast<unsigned long long>(nvencSnap.NvencBitrateBps),
            static_cast<unsigned long long>(nvencSnap.TotalBitstreamBytes));
    }

    if (h264Snap.Enabled)
    {
        std::printf(
            "[LB-HOST] H264Decode: passed=%u mode=%s struct=%u psnrOk=%u matrix=%s packets=%llu decoded=%llu nalErr=%llu decErr=%llu "
            "decAvgUs=%llu decP95Us=%llu decP99Us=%llu sps=%llu pps=%llu idr=%llu minY=%.2fdB minUv=%.2fdB minComb=%.2fdB "
            "workerState=%s healthy=%u enq=%llu proc=%llu rej=%llu qPeak=%llu qWait=%llu qTimeout=%llu comBal=%u\n",
            h264Snap.Passed ? 1U : 0U,
            h264Snap.ValidationMode.c_str(),
            h264Snap.StructuralDecodeValidated ? 1U : 0U,
            h264Snap.FidelityPsnrValidated ? 1U : 0U,
            h264Snap.MatchedColorMatrix.c_str(),
            static_cast<unsigned long long>(h264Snap.PacketsInspected),
            static_cast<unsigned long long>(h264Snap.FramesDecoded),
            static_cast<unsigned long long>(h264Snap.NalParseFailures),
            static_cast<unsigned long long>(h264Snap.DecodeFailures),
            static_cast<unsigned long long>(h264Snap.MftDecodeLatencyUs.AvgUs),
            static_cast<unsigned long long>(h264Snap.MftDecodeLatencyUs.P95Us),
            static_cast<unsigned long long>(h264Snap.MftDecodeLatencyUs.P99Us),
            static_cast<unsigned long long>(h264Snap.SpsCount),
            static_cast<unsigned long long>(h264Snap.PpsCount),
            static_cast<unsigned long long>(h264Snap.IdrCount),
            h264Snap.MinYPsnrDb,
            h264Snap.MinUvPsnrDb,
            h264Snap.MinCombinedPsnrDb,
            lumabridge::host::H264WorkerCompletionStateToString(h264WorkerSnap.CompletionState),
            h264WorkerSnap.Healthy ? 1U : 0U,
            static_cast<unsigned long long>(h264WorkerSnap.PacketsEnqueued),
            static_cast<unsigned long long>(h264WorkerSnap.PacketsProcessed),
            static_cast<unsigned long long>(h264WorkerSnap.PacketsRejected),
            static_cast<unsigned long long>(h264WorkerSnap.QueuePeakDepth),
            static_cast<unsigned long long>(h264WorkerSnap.QueueFullWaitCount),
            static_cast<unsigned long long>(h264WorkerSnap.QueueWaitTimeoutCount),
            h264WorkerSnap.ComBalanced ? 1U : 0U);
    }

    if (hostResReport.Available || serverResReport.Available)
    {
        std::printf(
            "[LB-HOST] Resources: hostWsMB=%.2f hostDeltaMB=%.2f hostCpu=%.2f%% | serverAvail=%u serverWsMB=%.2f serverDeltaMB=%.2f serverCpu=%.2f%%\n",
            static_cast<double>(hostResReport.WorkingSetBytes) / (1024.0 * 1024.0),
            static_cast<double>(hostResReport.WorkingSetDeltaBytes) / (1024.0 * 1024.0),
            hostResReport.CpuUsagePercent,
            serverResReport.Available ? 1U : 0U,
            static_cast<double>(serverResReport.WorkingSetBytes) / (1024.0 * 1024.0),
            static_cast<double>(serverResReport.WorkingSetDeltaBytes) / (1024.0 * 1024.0),
            serverResReport.CpuUsagePercent);
    }

    if (stimSnap.Requested)
    {
        std::printf(
            "[LB-HOST] Stimulus: identified=%u started=%u hiRes=%u req=%s active=%s fallback=%u src=%s ticks=%llu paints=%llu presentOk=%llu occluded=%llu miss=%llu driftUs=%lld maxGapUs=%llu achievedFps=%.2f tickAvgUs=%llu\n",
            stimSnap.VirtualDisplayIdentified ? 1U : 0U,
            stimSnap.Started ? 1U : 0U,
            stimSnap.HighResolutionTimerUsed ? 1U : 0U,
            stimSnap.BackendRequested.c_str(),
            stimSnap.BackendActive.c_str(),
            stimSnap.FallbackFromDxgiOccurred ? 1U : 0U,
            stimSnap.IdentificationSource.c_str(),
            static_cast<unsigned long long>(stimSnap.TicksPresented),
            static_cast<unsigned long long>(stimSnap.PaintCount),
            static_cast<unsigned long long>(stimSnap.PresentSucceeded),
            static_cast<unsigned long long>(stimSnap.PresentOccluded),
            static_cast<unsigned long long>(stimSnap.DeadlineMissCount),
            static_cast<long long>(stimSnap.CumulativeDriftUs),
            static_cast<unsigned long long>(stimSnap.MaxInterPresentGapUs),
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

    return gateEval.OverallExitOk ? EXIT_SUCCESS : EXIT_FAILURE;
}
