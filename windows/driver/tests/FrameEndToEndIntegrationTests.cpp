#ifndef NOMINMAX
#define NOMINMAX
#endif

#include "../LumaBridgeIddDriver/SwapChainProcessor.h"
#include "../LumaBridgeIddDriver/FrameExtractor.h"
#include "../LumaBridgeIddDriver/FrameIpcProtocol.h"
#include "../LumaBridgeIddDriver/FrameTransport.h"
#include "../LumaBridgeIddDriver/SharedTexturePool.h"
#include "../../host/VirtualDisplayStimulus.h"

#include <d3d11.h>
#include <dxgi1_4.h>
#include <wrl/client.h>

#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <deque>
#include <filesystem>
#include <fstream>
#include <string>
#include <thread>
#include <vector>

using Microsoft::WRL::ComPtr;
using namespace lumabridge::driver;
using namespace lumabridge::ipc;

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

bool
CreateTestD3d11Device(
    ComPtr<ID3D11Device>& outDevice,
    ComPtr<ID3D11DeviceContext>& outContext,
    const char*& outKind
    ) noexcept
{
    static constexpr D3D_FEATURE_LEVEL kLevels[] = {
        D3D_FEATURE_LEVEL_11_1,
        D3D_FEATURE_LEVEL_11_0,
        D3D_FEATURE_LEVEL_10_1,
        D3D_FEATURE_LEVEL_10_0};
    D3D_FEATURE_LEVEL selected = D3D_FEATURE_LEVEL_11_0;

    HRESULT hr = D3D11CreateDevice(
        nullptr,
        D3D_DRIVER_TYPE_HARDWARE,
        nullptr,
        D3D11_CREATE_DEVICE_BGRA_SUPPORT,
        kLevels,
        ARRAYSIZE(kLevels),
        D3D11_SDK_VERSION,
        &outDevice,
        &selected,
        &outContext);
    if (SUCCEEDED(hr) && outDevice != nullptr && outContext != nullptr)
    {
        outKind = "Hardware";
        return true;
    }

    hr = D3D11CreateDevice(
        nullptr,
        D3D_DRIVER_TYPE_WARP,
        nullptr,
        D3D11_CREATE_DEVICE_BGRA_SUPPORT,
        kLevels,
        ARRAYSIZE(kLevels),
        D3D11_SDK_VERSION,
        &outDevice,
        &selected,
        &outContext);
    if (SUCCEEDED(hr) && outDevice != nullptr && outContext != nullptr)
    {
        outKind = "WARP";
        return true;
    }
    outKind = "None";
    return false;
}

bool
CreateSyntheticTexture(
    ID3D11Device* device,
    uint32_t width,
    uint32_t height,
    uint32_t frameNumber,
    ComPtr<ID3D11Texture2D>& outTex
    )
{
    uint32_t rowPitch = 0U;
    uint32_t payloadBytes = 0U;
    if (!ComputeTightRowPitchBytes(width, rowPitch) ||
        !ComputeValidatedFramePayloadBytes(width, height, rowPitch, payloadBytes))
    {
        return false;
    }

    std::vector<uint8_t> pixels(payloadBytes, 0U);
    if (!GenerateSyntheticTestPatternBgra8(frameNumber, width, height, pixels.data(), pixels.size()))
    {
        return false;
    }

    D3D11_TEXTURE2D_DESC desc{};
    desc.Width = width;
    desc.Height = height;
    desc.MipLevels = 1U;
    desc.ArraySize = 1U;
    desc.Format = DXGI_FORMAT_B8G8R8A8_UNORM;
    desc.SampleDesc.Count = 1U;
    desc.Usage = D3D11_USAGE_DEFAULT;
    desc.BindFlags = D3D11_BIND_SHADER_RESOURCE;

    D3D11_SUBRESOURCE_DATA init{};
    init.pSysMem = pixels.data();
    init.SysMemPitch = rowPitch;

    return SUCCEEDED(device->CreateTexture2D(&desc, &init, &outTex)) && outTex != nullptr;
}

bool
CreateD3d11DeviceWithLuid(
    ComPtr<ID3D11Device>& outDevice,
    ComPtr<ID3D11DeviceContext>& outContext,
    LUID& outAdapterLuid,
    const char*& outKind
    ) noexcept
{
    outAdapterLuid = LUID{0, 0};
    if (!CreateTestD3d11Device(outDevice, outContext, outKind))
    {
        return false;
    }
    ComPtr<IDXGIDevice> dxgiDev;
    ComPtr<IDXGIAdapter> adapter;
    if (SUCCEEDED(outDevice.As(&dxgiDev)) && dxgiDev != nullptr &&
        SUCCEEDED(dxgiDev->GetAdapter(&adapter)) && adapter != nullptr)
    {
        DXGI_ADAPTER_DESC desc{};
        if (SUCCEEDED(adapter->GetDesc(&desc)))
        {
            outAdapterLuid = desc.AdapterLuid;
        }
    }
    return true;
}

std::filesystem::path
ResolveHostExecutablePath()
{
    wchar_t exePath[MAX_PATH]{};
    const DWORD len = GetModuleFileNameW(nullptr, exePath, ARRAYSIZE(exePath));
    if (len > 0U && len < ARRAYSIZE(exePath))
    {
        const std::filesystem::path sibling = std::filesystem::path(exePath).parent_path() / L"lumabridge-host.exe";
        if (std::filesystem::exists(sibling))
        {
            return sibling;
        }
    }

    const std::filesystem::path relDebug = "windows/driver/x64/Debug/lumabridge-host.exe";
    if (std::filesystem::exists(relDebug))
    {
        return std::filesystem::absolute(relDebug);
    }

    const std::filesystem::path relRelease = "windows/driver/x64/Release/lumabridge-host.exe";
    if (std::filesystem::exists(relRelease))
    {
        return std::filesystem::absolute(relRelease);
    }

    return {};
}

std::string
ReadFileText(
    const std::filesystem::path& path
    )
{
    std::ifstream in(path, std::ios::binary);
    if (!in.is_open())
    {
        return {};
    }
    return std::string((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
}

bool
ExtractJsonNumber(
    const std::string& jsonText,
    const char* key,
    uint64_t& outValue
    )
{
    const std::string needle = std::string("\"") + key + "\":";
    const size_t pos = jsonText.find(needle);
    if (pos == std::string::npos)
    {
        return false;
    }
    size_t valPos = pos + needle.size();
    while (valPos < jsonText.size() && (jsonText[valPos] == ' ' || jsonText[valPos] == '\t'))
    {
        ++valPos;
    }
    if (valPos >= jsonText.size() || jsonText[valPos] < '0' || jsonText[valPos] > '9')
    {
        return false;
    }
    char* endPtr = nullptr;
    outValue = std::strtoull(jsonText.c_str() + valPos, &endPtr, 10);
    return endPtr != (jsonText.c_str() + valPos);
}

bool
ExtractJsonDouble(
    const std::string& jsonText,
    const char* key,
    double& outValue
    )
{
    const std::string needle = std::string("\"") + key + "\":";
    const size_t pos = jsonText.find(needle);
    if (pos == std::string::npos)
    {
        return false;
    }
    size_t valPos = pos + needle.size();
    while (valPos < jsonText.size() && (jsonText[valPos] == ' ' || jsonText[valPos] == '\t'))
    {
        ++valPos;
    }
    if (valPos >= jsonText.size())
    {
        return false;
    }
    char* endPtr = nullptr;
    outValue = std::strtod(jsonText.c_str() + valPos, &endPtr);
    return endPtr != (jsonText.c_str() + valPos);
}

bool
ExtractJsonNumberInScope(
    const std::string& jsonText,
    const char* sectionKey,
    const char* subSectionKey,
    const char* valueKey,
    uint64_t& outValue
    )
{
    size_t searchPos = 0U;
    if (sectionKey != nullptr)
    {
        const std::string needle = std::string("\"") + sectionKey + "\":";
        const size_t pos = jsonText.find(needle, searchPos);
        if (pos == std::string::npos)
        {
            return false;
        }
        searchPos = pos + needle.size();
    }
    if (subSectionKey != nullptr)
    {
        const std::string needle = std::string("\"") + subSectionKey + "\":";
        const size_t pos = jsonText.find(needle, searchPos);
        if (pos == std::string::npos)
        {
            return false;
        }
        searchPos = pos + needle.size();
    }
    const std::string needle = std::string("\"") + valueKey + "\":";
    const size_t pos = jsonText.find(needle, searchPos);
    if (pos == std::string::npos)
    {
        return false;
    }
    size_t valPos = pos + needle.size();
    while (valPos < jsonText.size() && (jsonText[valPos] == ' ' || jsonText[valPos] == '\t'))
    {
        ++valPos;
    }
    if (valPos >= jsonText.size() || jsonText[valPos] < '0' || jsonText[valPos] > '9')
    {
        return false;
    }
    char* endPtr = nullptr;
    outValue = std::strtoull(jsonText.c_str() + valPos, &endPtr, 10);
    return endPtr != (jsonText.c_str() + valPos);
}

bool
ExtractJsonDoubleInScope(
    const std::string& jsonText,
    const char* sectionKey,
    const char* subSectionKey,
    const char* valueKey,
    double& outValue
    )
{
    size_t searchPos = 0U;
    if (sectionKey != nullptr)
    {
        const std::string needle = std::string("\"") + sectionKey + "\":";
        const size_t pos = jsonText.find(needle, searchPos);
        if (pos == std::string::npos)
        {
            return false;
        }
        searchPos = pos + needle.size();
    }
    if (subSectionKey != nullptr)
    {
        const std::string needle = std::string("\"") + subSectionKey + "\":";
        const size_t pos = jsonText.find(needle, searchPos);
        if (pos == std::string::npos)
        {
            return false;
        }
        searchPos = pos + needle.size();
    }
    const std::string needle = std::string("\"") + valueKey + "\":";
    const size_t pos = jsonText.find(needle, searchPos);
    if (pos == std::string::npos)
    {
        return false;
    }
    size_t valPos = pos + needle.size();
    while (valPos < jsonText.size() && (jsonText[valPos] == ' ' || jsonText[valPos] == '\t'))
    {
        ++valPos;
    }
    if (valPos >= jsonText.size())
    {
        return false;
    }
    char* endPtr = nullptr;
    outValue = std::strtod(jsonText.c_str() + valPos, &endPtr);
    return endPtr != (jsonText.c_str() + valPos);
}

bool
LaunchHostProcessWithCustomArgsAndWait(
    const std::filesystem::path& hostExe,
    const std::wstring& pipeName,
    const std::wstring& extraArgs,
    const std::filesystem::path& jsonSummaryPath,
    DWORD& outExitCode,
    DWORD waitTimeoutMs = 30000U
    )
{
    outExitCode = 1U;
    std::wstring cmdLine =
        L"\"" + hostExe.wstring() + L"\"" +
        L" --pipe \"" + pipeName + L"\" " + extraArgs +
        L" --json-summary \"" + jsonSummaryPath.wstring() + L"\"" +
        L" --quiet";

    std::vector<wchar_t> cmdBuf(cmdLine.begin(), cmdLine.end());
    cmdBuf.push_back(L'\0');

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    if (CreateProcessW(
            hostExe.c_str(),
            cmdBuf.data(),
            nullptr,
            nullptr,
            FALSE,
            0U,
            nullptr,
            nullptr,
            &si,
            &pi) == FALSE)
    {
        return false;
    }

    const DWORD waitRes = WaitForSingleObject(pi.hProcess, waitTimeoutMs);
    if (waitRes != WAIT_OBJECT_0)
    {
        (void)TerminateProcess(pi.hProcess, 1U);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return false;
    }

    const BOOL gotExit = GetExitCodeProcess(pi.hProcess, &outExitCode);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return gotExit != FALSE;
}

bool
LaunchHostProcessAndWait(
    const std::filesystem::path& hostExe,
    const std::wstring& pipeName,
    uint32_t maxFrames,
    const std::filesystem::path& jsonSummaryPath,
    DWORD& outExitCode
    )
{
    return LaunchHostProcessWithCustomArgsAndWait(
        hostExe,
        pipeName,
        L"--max-frames " + std::to_wstring(maxFrames) +
        L" --connect-timeout-ms 5000 --io-timeout-ms 1000 --verify-synthetic-pattern",
        jsonSummaryPath,
        outExitCode,
        15000U);
}

std::filesystem::path
MakeTempJsonPath(
    const wchar_t* tag
    )
{
    wchar_t tmpDir[MAX_PATH]{};
    const DWORD len = GetTempPathW(ARRAYSIZE(tmpDir), tmpDir);
    std::filesystem::path dir = (len > 0U && len < ARRAYSIZE(tmpDir))
        ? std::filesystem::path(tmpDir)
        : std::filesystem::temp_directory_path();
    wchar_t fileName[128]{};
    _snwprintf_s(
        fileName,
        ARRAYSIZE(fileName),
        _TRUNCATE,
        L"lumabridge_%ls_%lu.json",
        tag,
        GetCurrentProcessId());
    return dir / fileName;
}

void
TestEndToEndRealD3d11ExtractionToSeparateHostProcess720pAnd1080p()
{
    const std::filesystem::path hostExe = ResolveHostExecutablePath();
    EXPECT_TRUE(!hostExe.empty());
    if (hostExe.empty())
    {
        return;
    }

    ComPtr<ID3D11Device> device;
    ComPtr<ID3D11DeviceContext> context;
    const char* driverKind = nullptr;
    EXPECT_TRUE(CreateTestD3d11Device(device, context, driverKind));
    if (device == nullptr || context == nullptr)
    {
        return;
    }

    wchar_t pipeBuf[128]{};
    _snwprintf_s(
        pipeBuf,
        ARRAYSIZE(pipeBuf),
        _TRUNCATE,
        L"\\\\.\\pipe\\LumaBridgeE2E_%lu_1",
        GetCurrentProcessId());
    const std::wstring pipeName(pipeBuf);

    FrameTransportConfig serverCfg;
    serverCfg.SetPipeName(pipeName.c_str());
    serverCfg.MaxQueueDepth = 3U;
    serverCfg.BufferPoolSize = 5U;
    serverCfg.AdapterLuid = LUID{0xABCD, 0x0001};

    FrameIpcServer server;
    EXPECT_EQ(server.Start(serverCfg), S_OK);

    D3d11FrameExtractor extractor;
    extractor.SetDevice(device.Get(), context.Get());

    const std::filesystem::path jsonPath = MakeTempJsonPath(L"e2e1");
    std::filesystem::remove(jsonPath);

    std::atomic<bool> producerOk{true};
    std::thread producer([&]() {
        // Wait briefly so child process starts connecting, then pump 3x720p + 3x1080p frames.
        for (uint32_t i = 1U; i <= 6U; ++i)
        {
            const uint32_t w = (i <= 3U) ? 1280U : 1920U;
            const uint32_t h = (i <= 3U) ? 720U : 1080U;
            ComPtr<ID3D11Texture2D> tex;
            if (!CreateSyntheticTexture(device.Get(), w, h, i, tex))
            {
                producerOk = false;
                return;
            }

            auto slot = server.AcquireBufferSlot();
            if (slot == nullptr)
            {
                producerOk = false;
                return;
            }

            FrameExtractionInput in{};
            in.SourceTexture = tex.Get();
            in.PresentationFrameNumber = i;
            in.DirtyRectCount = 1U;
            in.Flags = static_cast<uint32_t>(FrameIpcFlags::SyntheticTestFrame);

            const FrameExtractionResult ext = extractor.ExtractFrame(in, *slot);
            tex.Reset();
            if (FAILED(ext.HResult) || !ext.PixelsCopied)
            {
                server.RecycleBufferSlot(std::move(slot));
                producerOk = false;
                return;
            }

            // Pace frames gently so bounded queue (depth=3) delivers all 6 without dropping before connect.
            while (server.GetMetricsSnapshot().ActiveHostConnections == 0U)
            {
                Sleep(10U);
            }
            while (server.GetMetricsSnapshot().QueueDepth >= 2U)
            {
                Sleep(5U);
            }

            bool evicted = false;
            if (FAILED(server.EnqueueFrame(std::move(slot), evicted)))
            {
                producerOk = false;
                return;
            }
        }
    });

    DWORD exitCode = 1U;
    EXPECT_TRUE(LaunchHostProcessAndWait(hostExe, pipeName, 6U, jsonPath, exitCode));
    producer.join();

    EXPECT_TRUE(producerOk.load());
    EXPECT_EQ(exitCode, 0UL);

    const std::string jsonText = ReadFileText(jsonPath);
    EXPECT_TRUE(!jsonText.empty());
    uint64_t framesRecv = 0ULL;
    uint64_t crcErr = 99ULL;
    uint64_t patErr = 99ULL;
    uint64_t protoErr = 99ULL;
    uint64_t lastW = 0ULL;
    uint64_t lastH = 0ULL;
    uint64_t lastFmt = 0ULL;
    uint64_t avgLatUs = 0ULL;
    EXPECT_TRUE(ExtractJsonNumber(jsonText, "FramesReceived", framesRecv));
    EXPECT_TRUE(ExtractJsonNumber(jsonText, "ChecksumMismatches", crcErr));
    EXPECT_TRUE(ExtractJsonNumber(jsonText, "SyntheticPatternMismatches", patErr));
    EXPECT_TRUE(ExtractJsonNumber(jsonText, "ProtocolErrors", protoErr));
    EXPECT_TRUE(ExtractJsonNumber(jsonText, "LastFrameWidth", lastW));
    EXPECT_TRUE(ExtractJsonNumber(jsonText, "LastFrameHeight", lastH));
    EXPECT_TRUE(ExtractJsonNumber(jsonText, "LastPixelFormat", lastFmt));
    EXPECT_TRUE(ExtractJsonNumber(jsonText, "AvgEndToEndLatencyUs", avgLatUs));

    EXPECT_EQ(framesRecv, 6ULL);
    EXPECT_EQ(crcErr, 0ULL);
    EXPECT_EQ(patErr, 0ULL);
    EXPECT_EQ(protoErr, 0ULL);
    EXPECT_EQ(lastW, 1920ULL);
    EXPECT_EQ(lastH, 1080ULL);
    EXPECT_EQ(lastFmt, static_cast<uint64_t>(DXGI_FORMAT_B8G8R8A8_UNORM));

    const auto sSnap = server.GetMetricsSnapshot();
    EXPECT_EQ(sSnap.FramesDelivered, 6ULL);
    EXPECT_EQ(sSnap.ClientConnectionsAccepted, 1ULL);
    EXPECT_EQ(sSnap.FrameTransportFailures, 0ULL);

    std::printf(
        "[INFO] E2E (%s D3D11 -> lumabridge-host.exe): frames=%llu last=%llux%llu serverAvgDelivUs=%llu hostAvgE2EUs=%llu\n",
        driverKind,
        static_cast<unsigned long long>(framesRecv),
        static_cast<unsigned long long>(lastW),
        static_cast<unsigned long long>(lastH),
        static_cast<unsigned long long>(sSnap.AvgDeliveryLatencyUs),
        static_cast<unsigned long long>(avgLatUs));

    std::filesystem::remove(jsonPath);
    server.Stop();
}

class LiveSwapChainProducerBackend final : public ISwapChainBackend
{
public:
    LiveSwapChainProducerBackend(
        ID3D11Device* device,
        ID3D11DeviceContext* context,
        std::wstring pipeName
        ) noexcept
        : m_device(device),
          m_context(context),
          m_pipeName(std::move(pipeName))
    {
        m_extractor.SetDevice(device, context);
    }

    ~LiveSwapChainProducerBackend() override
    {
        m_ipcServer.Stop();
    }

    HRESULT InitializeDeviceAndBindSwapChain(
        void*,
        LUID renderAdapterLuid
        ) noexcept override
    {
        FrameTransportConfig cfg;
        cfg.SetPipeName(m_pipeName.c_str());
        cfg.MaxQueueDepth = 3U;
        cfg.BufferPoolSize = 5U;
        cfg.AdapterLuid = renderAdapterLuid;
        return m_ipcServer.Start(cfg);
    }

    HRESULT ReleaseAndAcquireBuffer(
        void*,
        SwapChainFrameMetadata& outMetadata
        ) noexcept override
    {
        outMetadata = {};
        if (!m_pendingSurface.exchange(false, std::memory_order_acq_rel))
        {
            return E_PENDING;
        }

        const uint32_t presNum = ++m_frameNumber;
        ComPtr<ID3D11Texture2D> tex;
        if (!CreateSyntheticTexture(m_device.Get(), 1280U, 720U, presNum, tex))
        {
            return E_OUTOFMEMORY;
        }

        outMetadata.PresentationFrameNumber = presNum;
        outMetadata.DirtyRectCount = 1U;
        outMetadata.HasValidSurface = true;
        outMetadata.ExtractionAttempted = true;

        auto slot = m_ipcServer.AcquireBufferSlot();
        if (slot == nullptr)
        {
            outMetadata.ExtractionHResult = E_OUTOFMEMORY;
            return S_OK;
        }

        FrameExtractionInput in{};
        in.SourceTexture = tex.Get();
        in.PresentationFrameNumber = presNum;
        in.Flags = static_cast<uint32_t>(FrameIpcFlags::SyntheticTestFrame);

        const FrameExtractionResult ext = m_extractor.ExtractFrame(in, *slot);
        tex.Reset();

        outMetadata.ExtractionAccepted = ext.AcceptedForExtraction;
        outMetadata.PixelsCopied = ext.PixelsCopied;
        outMetadata.ProtectedContentRejected = ext.ProtectedContentRejected;
        outMetadata.ExtractedWidth = ext.Width;
        outMetadata.ExtractedHeight = ext.Height;
        outMetadata.ExtractedFormat = ext.Format;
        outMetadata.FrameSequence = ext.FrameSequence;
        outMetadata.CopyLatencyUs = ext.CopyLatencyUs;
        outMetadata.ExtractionHResult = ext.HResult;

        if (ext.PixelsCopied)
        {
            bool evicted = false;
            (void)m_ipcServer.EnqueueFrame(std::move(slot), evicted);
            outMetadata.EvictedOldestByBackpressure = evicted;
        }
        else
        {
            m_ipcServer.RecycleBufferSlot(std::move(slot));
        }

        return S_OK;
    }

    HRESULT FinishProcessingFrame(void*) noexcept override
    {
        return S_OK;
    }

    void DeleteSwapChainObject(void*) noexcept override
    {
        m_ipcServer.FlushQueue();
    }

    void QueryFrameTransportMetrics(SwapChainMetricsSnapshot& inoutSnapshot) const noexcept override
    {
        inoutSnapshot.FrameExtractionEnabled = true;
        const FrameTransportMetricsSnapshot s = m_ipcServer.GetMetricsSnapshot();
        inoutSnapshot.FramesDelivered = s.FramesDelivered;
        inoutSnapshot.FramesDroppedByBackpressure = s.FramesDroppedByBackpressure;
        inoutSnapshot.FrameTransportFailures = s.FrameTransportFailures;
        inoutSnapshot.ActiveHostConnections = s.ActiveHostConnections;
        inoutSnapshot.FrameDeliveryLatencyUs = s.LastDeliveryLatencyUs;
        inoutSnapshot.AvgFrameDeliveryLatencyUs = s.AvgDeliveryLatencyUs;
        inoutSnapshot.MaxFrameDeliveryLatencyUs = s.MaxDeliveryLatencyUs;
        inoutSnapshot.QueueDepth = s.QueueDepth;
        inoutSnapshot.PeakQueueDepth = s.PeakQueueDepth;
    }

    void SignalNewFrame(HANDLE surfaceEvent) noexcept
    {
        m_pendingSurface.store(true, std::memory_order_release);
        (void)SetEvent(surfaceEvent);
    }

    void StopTransport() noexcept
    {
        m_ipcServer.Stop();
    }

private:
    ComPtr<ID3D11Device> m_device{};
    ComPtr<ID3D11DeviceContext> m_context{};
    std::wstring m_pipeName{};
    D3d11FrameExtractor m_extractor{};
    FrameIpcServer m_ipcServer{};
    std::atomic<bool> m_pendingSurface{false};
    uint32_t m_frameNumber{0U};
};

void
TestEndToEndHostDisconnectAndReconnectDuringActiveSwapChainLoop()
{
    const std::filesystem::path hostExe = ResolveHostExecutablePath();
    EXPECT_TRUE(!hostExe.empty());
    if (hostExe.empty())
    {
        return;
    }

    ComPtr<ID3D11Device> device;
    ComPtr<ID3D11DeviceContext> context;
    const char* driverKind = nullptr;
    EXPECT_TRUE(CreateTestD3d11Device(device, context, driverKind));

    wchar_t pipeBuf[128]{};
    _snwprintf_s(
        pipeBuf,
        ARRAYSIZE(pipeBuf),
        _TRUNCATE,
        L"\\\\.\\pipe\\LumaBridgeE2E_%lu_2",
        GetCurrentProcessId());
    const std::wstring pipeName(pipeBuf);

    LiveSwapChainProducerBackend backend(device.Get(), context.Get(), pipeName);
    SwapChainProcessor processor(&backend);
    ScopedWin32Handle surfaceEvent(CreateEventW(nullptr, FALSE, FALSE, nullptr));
    EXPECT_TRUE(surfaceEvent.IsValid());

    EXPECT_EQ(
        processor.AssignSwapChain(reinterpret_cast<void*>(0xEE01), surfaceEvent.Get(), LUID{77, 0}),
        STATUS_SUCCESS);

    std::atomic<bool> stopDwmPump{false};
    std::thread dwmPump([&]() {
        while (!stopDwmPump.load(std::memory_order_acquire))
        {
            backend.SignalNewFrame(surfaceEvent.Get());
            Sleep(16U);
        }
    });

    const std::filesystem::path json1 = MakeTempJsonPath(L"e2e2a");
    const std::filesystem::path json2 = MakeTempJsonPath(L"e2e2b");
    std::filesystem::remove(json1);
    std::filesystem::remove(json2);

    DWORD exit1 = 1U;
    EXPECT_TRUE(LaunchHostProcessAndWait(hostExe, pipeName, 3U, json1, exit1));
    EXPECT_EQ(exit1, 0UL);

    // Let frames continue pumping with NO host connected -> exercises backpressure eviction cleanly.
    Sleep(150U);

    DWORD exit2 = 1U;
    EXPECT_TRUE(LaunchHostProcessAndWait(hostExe, pipeName, 3U, json2, exit2));
    EXPECT_EQ(exit2, 0UL);

    stopDwmPump.store(true, std::memory_order_release);
    dwmPump.join();

    const auto midMetrics = processor.GetMetricsSnapshot();
    EXPECT_TRUE(midMetrics.FramesCopied >= 6ULL);
    EXPECT_TRUE(midMetrics.FramesDelivered >= 6ULL);
    EXPECT_TRUE(midMetrics.FramesDroppedByBackpressure >= 1ULL);
    EXPECT_EQ(midMetrics.FrameCopyFailures, 0ULL);

    EXPECT_EQ(processor.UnassignSwapChain(), STATUS_SUCCESS);
    backend.StopTransport();

    const std::string j1Text = ReadFileText(json1);
    const std::string j2Text = ReadFileText(json2);
    uint64_t r1 = 0ULL;
    uint64_t r2 = 0ULL;
    uint64_t p1 = 99ULL;
    uint64_t p2 = 99ULL;
    EXPECT_TRUE(ExtractJsonNumber(j1Text, "FramesReceived", r1));
    EXPECT_TRUE(ExtractJsonNumber(j2Text, "FramesReceived", r2));
    EXPECT_TRUE(ExtractJsonNumber(j1Text, "SyntheticPatternMismatches", p1));
    EXPECT_TRUE(ExtractJsonNumber(j2Text, "SyntheticPatternMismatches", p2));
    EXPECT_EQ(r1, 3ULL);
    EXPECT_EQ(r2, 3ULL);
    EXPECT_EQ(p1, 0ULL);
    EXPECT_EQ(p2, 0ULL);

    std::filesystem::remove(json1);
    std::filesystem::remove(json2);
}

void
RunResolutionBenchmarkPass(
    ID3D11Device* device,
    ID3D11DeviceContext* context,
    const char* driverKind,
    const std::filesystem::path& hostExe,
    uint32_t width,
    uint32_t height,
    uint32_t frameCount,
    uint32_t pipeIndex
    )
{
    constexpr uint32_t kPrebuiltRing = 4U;
    std::vector<ComPtr<ID3D11Texture2D>> ringTextures(kPrebuiltRing);
    for (uint32_t k = 0U; k < kPrebuiltRing; ++k)
    {
        EXPECT_TRUE(CreateSyntheticTexture(device, width, height, k + 1U, ringTextures[k]));
    }

    wchar_t pipeBuf[128]{};
    _snwprintf_s(
        pipeBuf,
        ARRAYSIZE(pipeBuf),
        _TRUNCATE,
        L"\\\\.\\pipe\\LumaBridgeBench_%lu_%u",
        GetCurrentProcessId(),
        pipeIndex);
    const std::wstring pipeName(pipeBuf);

    FrameTransportConfig serverCfg;
    serverCfg.SetPipeName(pipeName.c_str());
    serverCfg.MaxQueueDepth = 3U;
    serverCfg.BufferPoolSize = 5U;

    FrameIpcServer server;
    EXPECT_EQ(server.Start(serverCfg), S_OK);

    D3d11FrameExtractor extractor;
    extractor.SetDevice(device, context);

    wchar_t tagBuf[32]{};
    _snwprintf_s(tagBuf, ARRAYSIZE(tagBuf), _TRUNCATE, L"bench_%ux%u", width, height);
    const std::filesystem::path jsonPath = MakeTempJsonPath(tagBuf);
    std::filesystem::remove(jsonPath);

    std::atomic<bool> producerOk{true};
    std::atomic<uint64_t> totalCopyUs{0ULL};
    std::atomic<uint64_t> maxCopyUs{0ULL};

    std::thread producer([&]() {
        while (server.GetMetricsSnapshot().ActiveHostConnections == 0U)
        {
            Sleep(5U);
        }

        for (uint32_t i = 0U; i < frameCount; ++i)
        {
            const uint32_t patternFrame = (i % kPrebuiltRing) + 1U;
            auto slot = server.AcquireBufferSlot();
            if (slot == nullptr)
            {
                producerOk = false;
                return;
            }

            FrameExtractionInput in{};
            in.SourceTexture = ringTextures[i % kPrebuiltRing].Get();
            in.PresentationFrameNumber = patternFrame;
            in.Flags = static_cast<uint32_t>(FrameIpcFlags::SyntheticTestFrame);

            const FrameExtractionResult ext = extractor.ExtractFrame(in, *slot);
            if (FAILED(ext.HResult) || !ext.PixelsCopied)
            {
                server.RecycleBufferSlot(std::move(slot));
                producerOk = false;
                return;
            }

            totalCopyUs.fetch_add(ext.CopyLatencyUs, std::memory_order_relaxed);
            uint64_t prevMax = maxCopyUs.load(std::memory_order_relaxed);
            while (ext.CopyLatencyUs > prevMax &&
                   !maxCopyUs.compare_exchange_weak(prevMax, ext.CopyLatencyUs, std::memory_order_relaxed))
            {
            }

            while (server.GetMetricsSnapshot().QueueDepth >= 2U)
            {
                Sleep(1U);
            }

            bool evicted = false;
            if (FAILED(server.EnqueueFrame(std::move(slot), evicted)))
            {
                producerOk = false;
                return;
            }
        }
    });

    DWORD exitCode = 1U;
    EXPECT_TRUE(LaunchHostProcessAndWait(hostExe, pipeName, frameCount, jsonPath, exitCode));
    producer.join();

    EXPECT_TRUE(producerOk.load());
    EXPECT_EQ(exitCode, 0UL);

    const std::string jsonText = ReadFileText(jsonPath);
    uint64_t framesRecv = 0ULL;
    uint64_t framesValid = 0ULL;
    uint64_t crcErr = 99ULL;
    uint64_t patErr = 99ULL;
    uint64_t hostAvgE2E = 0ULL;
    uint64_t hostMaxE2E = 0ULL;
    double hostFps = 0.0;
    double activeFps = 0.0;
    EXPECT_TRUE(ExtractJsonNumber(jsonText, "FramesReceived", framesRecv));
    EXPECT_TRUE(ExtractJsonNumber(jsonText, "FramesValid", framesValid));
    EXPECT_TRUE(ExtractJsonNumber(jsonText, "ChecksumMismatches", crcErr));
    EXPECT_TRUE(ExtractJsonNumber(jsonText, "SyntheticPatternMismatches", patErr));
    EXPECT_TRUE(ExtractJsonNumber(jsonText, "AvgEndToEndLatencyUs", hostAvgE2E));
    EXPECT_TRUE(ExtractJsonNumber(jsonText, "MaxEndToEndLatencyUs", hostMaxE2E));
    EXPECT_TRUE(ExtractJsonDouble(jsonText, "ReceiveFps", hostFps));
    EXPECT_TRUE(ExtractJsonDouble(jsonText, "ObservedActiveFps", activeFps));
    EXPECT_EQ(framesRecv, static_cast<uint64_t>(frameCount));
    EXPECT_EQ(framesValid, static_cast<uint64_t>(frameCount));
    EXPECT_EQ(crcErr, 0ULL);
    EXPECT_EQ(patErr, 0ULL);
    EXPECT_TRUE(jsonText.find("\"TransportHealthy\": true") != std::string::npos);
    EXPECT_TRUE(jsonText.find("\"FrameTargetReached\": true") != std::string::npos);
    EXPECT_TRUE(jsonText.find("\"FpsSampleSufficient\": true") != std::string::npos);
    EXPECT_TRUE(activeFps > 0.0);

    const auto sSnap = server.GetMetricsSnapshot();
    const uint64_t avgCopyUs = totalCopyUs.load() / frameCount;
    std::printf(
        "[BENCH] %s %ux%u (%u frames): avgCopyUs=%llu maxCopyUs=%llu avgDeliveryUs=%llu hostAvgE2EUs=%llu hostMaxE2EUs=%llu activeFps=%.2f\n",
        driverKind,
        width,
        height,
        frameCount,
        static_cast<unsigned long long>(avgCopyUs),
        static_cast<unsigned long long>(maxCopyUs.load()),
        static_cast<unsigned long long>(sSnap.AvgDeliveryLatencyUs),
        static_cast<unsigned long long>(hostAvgE2E),
        static_cast<unsigned long long>(hostMaxE2E),
        activeFps);

    std::filesystem::remove(jsonPath);
    server.Stop();
}

void
TestEndToEndSmokeDurationExitAndMinFramesVsTargetCli()
{
    const std::filesystem::path hostExe = ResolveHostExecutablePath();
    EXPECT_TRUE(!hostExe.empty());
    if (hostExe.empty())
    {
        return;
    }

    ComPtr<ID3D11Device> device;
    ComPtr<ID3D11DeviceContext> context;
    const char* driverKind = nullptr;
    EXPECT_TRUE(CreateTestD3d11Device(device, context, driverKind));
    if (device == nullptr || context == nullptr)
    {
        return;
    }

    wchar_t pipeBuf[128]{};
    _snwprintf_s(
        pipeBuf,
        ARRAYSIZE(pipeBuf),
        _TRUNCATE,
        L"\\\\.\\pipe\\LumaBridgeSmokeCli_%lu",
        GetCurrentProcessId());
    const std::wstring pipeName(pipeBuf);

    FrameTransportConfig serverCfg;
    serverCfg.SetPipeName(pipeName.c_str());
    serverCfg.MaxQueueDepth = 3U;
    serverCfg.BufferPoolSize = 5U;

    FrameIpcServer server;
    EXPECT_EQ(server.Start(serverCfg), S_OK);

    D3d11FrameExtractor extractor;
    extractor.SetDevice(device.Get(), context.Get());

    auto enqueueThreeFrames = [&]() -> bool {
        for (uint32_t i = 1U; i <= 3U; ++i)
        {
            ComPtr<ID3D11Texture2D> tex;
            if (!CreateSyntheticTexture(device.Get(), 640U, 360U, i, tex))
            {
                return false;
            }
            auto slot = server.AcquireBufferSlot();
            if (slot == nullptr)
            {
                return false;
            }
            FrameExtractionInput in{};
            in.SourceTexture = tex.Get();
            in.PresentationFrameNumber = i;
            in.Flags = static_cast<uint32_t>(FrameIpcFlags::SyntheticTestFrame);
            const FrameExtractionResult ext = extractor.ExtractFrame(in, *slot);
            tex.Reset();
            if (FAILED(ext.HResult) || !ext.PixelsCopied)
            {
                server.RecycleBufferSlot(std::move(slot));
                return false;
            }
            bool evicted = false;
            if (FAILED(server.EnqueueFrame(std::move(slot), evicted)))
            {
                return false;
            }
        }
        return true;
    };

    auto runCustomCli = [&](const std::wstring& extraArgs, const std::filesystem::path& jsonOut, DWORD& outExit) -> bool {
        outExit = 99U;
        std::wstring cmdLine =
            L"\"" + hostExe.wstring() + L"\"" +
            L" --pipe \"" + pipeName + L"\" " + extraArgs +
            L" --json-summary \"" + jsonOut.wstring() + L"\" --quiet";
        std::vector<wchar_t> cmdBuf(cmdLine.begin(), cmdLine.end());
        cmdBuf.push_back(L'\0');
        STARTUPINFOW si{};
        si.cb = sizeof(si);
        PROCESS_INFORMATION pi{};
        if (CreateProcessW(hostExe.c_str(), cmdBuf.data(), nullptr, nullptr, FALSE, 0U, nullptr, nullptr, &si, &pi) == FALSE)
        {
            return false;
        }
        const DWORD waitRes = WaitForSingleObject(pi.hProcess, 10000U);
        if (waitRes != WAIT_OBJECT_0)
        {
            (void)TerminateProcess(pi.hProcess, 1U);
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            return false;
        }
        const BOOL ok = GetExitCodeProcess(pi.hProcess, &outExit);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return ok != FALSE;
    };

    // 1. Smoke mode (--min-frames 1 --max-frames 60 --duration-ms 350): 3 pre-connect frames arrive,
    //    then idle desktop -> ExitCode=0 while accurately reporting FrameTargetReached=false and PreConnect=3!
    EXPECT_TRUE(enqueueThreeFrames());
    const std::filesystem::path smokeJson = MakeTempJsonPath(L"smoke_ok");
    std::filesystem::remove(smokeJson);
    DWORD smokeExit = 99U;
    EXPECT_TRUE(runCustomCli(
        L"--min-frames 1 --max-frames 60 --duration-ms 350 --io-timeout-ms 80 --connect-timeout-ms 2000 --verify-synthetic-pattern",
        smokeJson,
        smokeExit));
    EXPECT_EQ(smokeExit, 0UL);
    const std::string smokeText = ReadFileText(smokeJson);
    uint64_t smokeValid = 0ULL;
    uint64_t smokePreConn = 0ULL;
    uint64_t smokeFatalTimeouts = 99ULL;
    uint64_t smokeRecTimeouts = 0ULL;
    EXPECT_TRUE(ExtractJsonNumber(smokeText, "FramesValid", smokeValid));
    EXPECT_TRUE(ExtractJsonNumber(smokeText, "PreConnectFramesReceived", smokePreConn));
    EXPECT_TRUE(ExtractJsonNumber(smokeText, "FatalIoTimeouts", smokeFatalTimeouts));
    EXPECT_TRUE(ExtractJsonNumber(smokeText, "RecoverableIoTimeouts", smokeRecTimeouts));
    EXPECT_EQ(smokeValid, 3ULL);
    EXPECT_EQ(smokePreConn, 3ULL);
    EXPECT_EQ(smokeFatalTimeouts, 0ULL);
    EXPECT_TRUE(smokeRecTimeouts >= 1ULL);
    EXPECT_TRUE(smokeText.find("\"ExitReason\": \"DurationElapsed\"") != std::string::npos);
    EXPECT_TRUE(smokeText.find("\"TransportHealthy\": true") != std::string::npos);
    EXPECT_TRUE(smokeText.find("\"MinFramesReached\": true") != std::string::npos);
    EXPECT_TRUE(smokeText.find("\"FrameTargetReached\": false") != std::string::npos);
    EXPECT_TRUE(smokeText.find("\"FpsSampleSufficient\": false") != std::string::npos);
    std::filesystem::remove(smokeJson);

    // 2. Strict performance target mode (--require-max-frames): 3 frames < 60 -> ExitCode=1 cleanly.
    EXPECT_TRUE(enqueueThreeFrames());
    const std::filesystem::path targetMissJson = MakeTempJsonPath(L"target_miss");
    std::filesystem::remove(targetMissJson);
    DWORD targetMissExit = 0U;
    EXPECT_TRUE(runCustomCli(
        L"--max-frames 60 --require-max-frames --duration-ms 300 --io-timeout-ms 80 --connect-timeout-ms 2000 --verify-synthetic-pattern",
        targetMissJson,
        targetMissExit));
    EXPECT_EQ(targetMissExit, 1UL);
    const std::string missText = ReadFileText(targetMissJson);
    EXPECT_TRUE(missText.find("\"ExitReason\": \"DurationElapsed\"") != std::string::npos);
    EXPECT_TRUE(missText.find("\"TransportHealthy\": true") != std::string::npos);
    EXPECT_TRUE(missText.find("\"FrameTargetReached\": false") != std::string::npos);
    std::filesystem::remove(targetMissJson);

    server.Stop();
}

void
TestEndToEndThroughputAndLatencyBenchmark720pAnd1080p()
{
    const std::filesystem::path hostExe = ResolveHostExecutablePath();
    EXPECT_TRUE(!hostExe.empty());
    if (hostExe.empty())
    {
        return;
    }

    ComPtr<ID3D11Device> device;
    ComPtr<ID3D11DeviceContext> context;
    const char* driverKind = nullptr;
    EXPECT_TRUE(CreateTestD3d11Device(device, context, driverKind));
    if (device == nullptr || context == nullptr)
    {
        return;
    }

    RunResolutionBenchmarkPass(device.Get(), context.Get(), driverKind, hostExe, 1280U, 720U, 30U, 10U);
    RunResolutionBenchmarkPass(device.Get(), context.Get(), driverKind, hostExe, 1920U, 1080U, 30U, 11U);
}

enum class BenchmarkPipelineMode
{
    CpuStagingM4_1_1 = 0,
    GpuSharedPhaseA = 1,
    GpuSharedPlusNvencPhaseB = 2,
};

struct ControlledBenchmarkResult
{
    bool Passed{false};
    bool StructuralDecodeValidated{false};
    bool FidelityPsnrValidated{false};
    uint64_t FramesValid{0ULL};
    uint64_t TimestampMeasurementErrors{0ULL};
    uint64_t LiveEndToEndSampleCount{0ULL};
    uint64_t CopyAvgUs{0ULL};
    uint64_t CopyP95Us{0ULL};
    uint64_t IpcAvgUs{0ULL};
    uint64_t GpuSyncWaitAvgUs{0ULL};
    uint64_t NvencEncodeAvgUs{0ULL};
    uint64_t NvencEncodeP95Us{0ULL};
    uint64_t NvencEncodeP99Us{0ULL};
    uint64_t HostAvgE2EUs{0ULL};
    uint64_t HostP95E2EUs{0ULL};
    uint64_t LiveEndToEndP99Us{0ULL};
    uint64_t PresentToBitstreamAvgUs{0ULL};
    uint64_t BytesTransferredOverPipe{0ULL};
    uint64_t TotalBitstreamBytes{0ULL};
    uint64_t CpuStagingReadsPerformed{0ULL};
    uint64_t GpuFramesOpened{0ULL};
    uint64_t NvencFramesEncoded{0ULL};
    uint64_t NvencKeyFramesEncoded{0ULL};
    uint64_t ConnectedDurationUs{0ULL};
    uint64_t HostWorkingSetBytes{0ULL};
    double AverageExecutionFps{0.0};
    double ConnectedFps{0.0};
    double ObservedActiveFps{0.0};
    double EncoderOutputFps{0.0};
    double CoreTimestampCoveragePercent{0.0};
    double LiveTimestampCoveragePercent{0.0};
    double PresentTimestampCoveragePercent{0.0};
    double ExtractToBitstreamCoveragePercent{0.0};
    double MinYPsnrDb{0.0};
    double MinUvPsnrDb{0.0};
};

ControlledBenchmarkResult
RunControlledPipelinePass(
    ID3D11Device* device,
    ID3D11DeviceContext* context,
    LUID adapterLuid,
    const std::filesystem::path& hostExe,
    BenchmarkPipelineMode mode,
    uint32_t width,
    uint32_t height,
    uint32_t frameCount,
    uint32_t pipeIndex,
    bool verifySynthetic,
    bool verifyH264Decode,
    bool verifyH264Psnr = false
    )
{
    ControlledBenchmarkResult res{};

    constexpr uint32_t kPrebuiltRing = 4U;
    std::vector<ComPtr<ID3D11Texture2D>> ringTextures(kPrebuiltRing);
    for (uint32_t i = 0U; i < kPrebuiltRing; ++i)
    {
        EXPECT_TRUE(CreateSyntheticTexture(device, width, height, i + 1U, ringTextures[i]));
        if (ringTextures[i] == nullptr)
        {
            return res;
        }
    }

    wchar_t pipeBuf[128]{};
    _snwprintf_s(
        pipeBuf,
        ARRAYSIZE(pipeBuf),
        _TRUNCATE,
        L"\\\\.\\pipe\\LumaBridgeM42Bench_%lu_%u",
        GetCurrentProcessId(),
        pipeIndex);
    const std::wstring pipeName(pipeBuf);

    const bool useGpu = (mode != BenchmarkPipelineMode::CpuStagingM4_1_1);
    D3d11SharedTexturePool gpuPool;
    if (useGpu)
    {
        EXPECT_EQ(gpuPool.Configure(
            kDefaultSharedTexturePoolSize,
            nullptr,
            false,
            true,
            true,
            true,
            25U), S_OK);
        gpuPool.SetDevice(device, context, adapterLuid);
    }

    FrameTransportConfig serverCfg;
    serverCfg.SetPipeName(pipeName.c_str());
    serverCfg.MaxQueueDepth = 3U;
    serverCfg.BufferPoolSize = 5U;
    serverCfg.AdapterLuid = adapterLuid;
    serverCfg.EnableGpuSharedTransport = useGpu;
    serverCfg.AllowCpuFallbackWhenGpuNegotiated = !useGpu;
    serverCfg.SharedTexturePool = useGpu ? &gpuPool : nullptr;
    serverCfg.SharedTexturePoolSize = kDefaultSharedTexturePoolSize;

    FrameIpcServer server;
    EXPECT_EQ(server.Start(serverCfg), S_OK);

    D3d11FrameExtractor cpuExtractor;
    if (!useGpu)
    {
        cpuExtractor.SetDevice(device, context);
    }

    wchar_t tagBuf[48]{};
    _snwprintf_s(
        tagBuf,
        ARRAYSIZE(tagBuf),
        _TRUNCATE,
        L"m42_%u_%ux%u_%u",
        static_cast<uint32_t>(mode),
        width,
        height,
        pipeIndex);
    const std::filesystem::path jsonPath = MakeTempJsonPath(tagBuf);
    std::filesystem::remove(jsonPath);

    std::wstring extraArgs =
        L"--max-frames " + std::to_wstring(frameCount) +
        L" --require-max-frames --connect-timeout-ms 5000 --io-timeout-ms 1500";
    if (useGpu)
    {
        extraArgs += L" --transport gpu --require-gpu-shared";
    }
    else
    {
        extraArgs += L" --transport cpu";
    }
    if (verifySynthetic)
    {
        extraArgs += L" --verify-synthetic-pattern";
    }
    if (mode == BenchmarkPipelineMode::GpuSharedPlusNvencPhaseB)
    {
        extraArgs +=
            L" --nvenc --require-nvenc --nvenc-bitrate-bps 20000000 --nvenc-gop 60"
            L" --prewarm-width " + std::to_wstring(width) +
            L" --prewarm-height " + std::to_wstring(height);
        if (verifyH264Psnr)
        {
            extraArgs += L" --nvenc-force-idr-every 5 --verify-h264-psnr";
        }
        else if (verifyH264Decode)
        {
            extraArgs += L" --nvenc-force-idr-every 5 --verify-h264-decode";
        }
    }

    std::atomic<bool> producerOk{true};
    std::atomic<bool> stopRequested{false};
    std::thread producer([&]() {
        const ULONGLONG connWaitStart = GetTickCount64();
        while (!stopRequested.load(std::memory_order_acquire))
        {
            const auto snap = server.GetMetricsSnapshot();
            if (snap.ActiveHostConnections > 0U &&
                (!useGpu || server.ShouldProduceGpuSharedFrame()))
            {
                break;
            }
            if ((GetTickCount64() - connWaitStart) > 8000ULL)
            {
                producerOk = false;
                return;
            }
            SwitchToThread();
        }

        LARGE_INTEGER qpcLi{};
        for (uint32_t i = 0U; i < frameCount; ++i)
        {
            const ULONGLONG slotWaitStart = GetTickCount64();
            while (!stopRequested.load(std::memory_order_acquire))
            {
                const auto sSnap = server.GetMetricsSnapshot();
                const auto pSnap = gpuPool.GetMetricsSnapshot();
                const bool queueReady = (sSnap.QueueDepth < 2U);
                const bool poolReady = (!useGpu || ((pSnap.QueuedSlots + pSnap.InUseByHostSlots) < 3U));
                if (queueReady && poolReady)
                {
                    break;
                }
                if ((GetTickCount64() - slotWaitStart) > 8000ULL)
                {
                    producerOk = false;
                    return;
                }
                SwitchToThread();
            }

            auto slot = server.AcquireBufferSlot();
            if (slot == nullptr)
            {
                producerOk = false;
                return;
            }

            const uint32_t patternFrame = (i % kPrebuiltRing) + 1U;
            (void)QueryPerformanceCounter(&qpcLi);
            FrameExtractionInput in{};
            in.SourceTexture = ringTextures[i % kPrebuiltRing].Get();
            in.PresentationFrameNumber = patternFrame;
            in.PresentDisplayQpcTime = static_cast<uint64_t>(qpcLi.QuadPart);
            in.Flags = static_cast<uint32_t>(FrameIpcFlags::SyntheticTestFrame);

            if (useGpu)
            {
                const SharedTextureExtractResult ext = gpuPool.ExtractToSharedTexture(in, *slot, true);
                if (FAILED(ext.HResult) || !ext.GpuCopied)
                {
                    server.RecycleBufferSlot(std::move(slot));
                    producerOk = false;
                    return;
                }
            }
            else
            {
                const FrameExtractionResult ext = cpuExtractor.ExtractFrame(in, *slot);
                if (FAILED(ext.HResult) || !ext.PixelsCopied)
                {
                    server.RecycleBufferSlot(std::move(slot));
                    producerOk = false;
                    return;
                }
            }

            bool evicted = false;
            if (FAILED(server.EnqueueFrame(std::move(slot), evicted)))
            {
                producerOk = false;
                return;
            }
        }
    });

    DWORD exitCode = 1U;
    const bool launchedOk = LaunchHostProcessWithCustomArgsAndWait(
        hostExe,
        pipeName,
        extraArgs,
        jsonPath,
        exitCode,
        45000U);
    stopRequested.store(true, std::memory_order_release);
    producer.join();

    EXPECT_TRUE(launchedOk);
    EXPECT_TRUE(producerOk.load());
    EXPECT_EQ(exitCode, 0UL);

    const std::string jsonText = ReadFileText(jsonPath);
    EXPECT_TRUE(!jsonText.empty());

    uint64_t crcErr = 99ULL;
    uint64_t patErr = 99ULL;
    uint64_t protoErr = 99ULL;
    uint64_t openErr = 99ULL;
    uint64_t syncTimeout = 99ULL;
    uint64_t luidErr = 99ULL;
    EXPECT_TRUE(ExtractJsonNumber(jsonText, "FramesValid", res.FramesValid));
    EXPECT_TRUE(ExtractJsonNumber(jsonText, "TimestampMeasurementErrors", res.TimestampMeasurementErrors));
    EXPECT_TRUE(ExtractJsonDouble(jsonText, "CoreTimestampCoveragePercent", res.CoreTimestampCoveragePercent));
    EXPECT_TRUE(ExtractJsonDouble(jsonText, "LiveTimestampCoveragePercent", res.LiveTimestampCoveragePercent));
    EXPECT_TRUE(ExtractJsonDouble(jsonText, "PresentTimestampCoveragePercent", res.PresentTimestampCoveragePercent));
    EXPECT_TRUE(ExtractJsonNumber(jsonText, "ChecksumMismatches", crcErr));
    EXPECT_TRUE(ExtractJsonNumber(jsonText, "SyntheticPatternMismatches", patErr));
    EXPECT_TRUE(ExtractJsonNumber(jsonText, "ProtocolErrors", protoErr));
    EXPECT_TRUE(ExtractJsonNumber(jsonText, "GpuSharedOpenFailures", openErr));
    EXPECT_TRUE(ExtractJsonNumber(jsonText, "GpuSyncTimeouts", syncTimeout));
    EXPECT_TRUE(ExtractJsonNumber(jsonText, "AdapterMismatchErrors", luidErr));
    EXPECT_TRUE(ExtractJsonNumber(jsonText, "BytesReceived", res.BytesTransferredOverPipe));
    EXPECT_TRUE(ExtractJsonNumber(jsonText, "CpuStagingReadsPerformed", res.CpuStagingReadsPerformed));
    EXPECT_TRUE(ExtractJsonNumber(jsonText, "GpuFramesOpened", res.GpuFramesOpened));
    EXPECT_TRUE(ExtractJsonNumber(jsonText, "TotalConnectedDurationUs", res.ConnectedDurationUs));
    EXPECT_TRUE(ExtractJsonDouble(jsonText, "AverageExecutionFps", res.AverageExecutionFps));
    EXPECT_TRUE(ExtractJsonDouble(jsonText, "ConnectedFps", res.ConnectedFps));
    EXPECT_TRUE(ExtractJsonDouble(jsonText, "ObservedActiveFps", res.ObservedActiveFps));

    EXPECT_TRUE(ExtractJsonNumberInScope(jsonText, "CopyLatency", nullptr, "AvgUs", res.CopyAvgUs));
    EXPECT_TRUE(ExtractJsonNumberInScope(jsonText, "CopyLatency", nullptr, "P95Us", res.CopyP95Us));
    EXPECT_TRUE(ExtractJsonNumberInScope(jsonText, "IpcTransitLatency", nullptr, "AvgUs", res.IpcAvgUs));
    EXPECT_TRUE(ExtractJsonNumberInScope(jsonText, "GpuSyncWaitLatency", nullptr, "AvgUs", res.GpuSyncWaitAvgUs));
    EXPECT_TRUE(ExtractJsonNumberInScope(jsonText, "EndToEndLatency", nullptr, "AvgUs", res.HostAvgE2EUs));
    EXPECT_TRUE(ExtractJsonNumberInScope(jsonText, "EndToEndLatency", nullptr, "P95Us", res.HostP95E2EUs));
    EXPECT_TRUE(ExtractJsonNumberInScope(jsonText, "LiveEndToEndLatency", nullptr, "SampleCount", res.LiveEndToEndSampleCount));
    EXPECT_TRUE(ExtractJsonNumberInScope(jsonText, "LiveEndToEndLatency", nullptr, "P99Us", res.LiveEndToEndP99Us));
    (void)ExtractJsonNumberInScope(jsonText, "ResourceUsage", "Host", "WorkingSetBytes", res.HostWorkingSetBytes);

    if (mode == BenchmarkPipelineMode::GpuSharedPlusNvencPhaseB)
    {
        EXPECT_TRUE(ExtractJsonNumberInScope(jsonText, "Nvenc", nullptr, "NvencFramesEncoded", res.NvencFramesEncoded));
        EXPECT_TRUE(ExtractJsonNumberInScope(jsonText, "Nvenc", nullptr, "NvencKeyFramesEncoded", res.NvencKeyFramesEncoded));
        EXPECT_TRUE(ExtractJsonNumberInScope(jsonText, "Nvenc", nullptr, "TotalBitstreamBytes", res.TotalBitstreamBytes));
        EXPECT_TRUE(ExtractJsonDoubleInScope(jsonText, "Nvenc", nullptr, "EncoderOutputFps", res.EncoderOutputFps));
        EXPECT_TRUE(ExtractJsonDoubleInScope(jsonText, "Nvenc", nullptr, "ExtractToBitstreamCoveragePercent", res.ExtractToBitstreamCoveragePercent));
        EXPECT_TRUE(ExtractJsonNumberInScope(jsonText, "Nvenc", "EncodeLatencyUs", "AvgUs", res.NvencEncodeAvgUs));
        EXPECT_TRUE(ExtractJsonNumberInScope(jsonText, "Nvenc", "EncodeLatencyUs", "P95Us", res.NvencEncodeP95Us));
        EXPECT_TRUE(ExtractJsonNumberInScope(jsonText, "Nvenc", "EncodeLatencyUs", "P99Us", res.NvencEncodeP99Us));
        EXPECT_TRUE(ExtractJsonNumberInScope(jsonText, "Nvenc", "PresentToBitstreamLatencyUs", "AvgUs", res.PresentToBitstreamAvgUs));
        if (verifyH264Decode || verifyH264Psnr)
        {
            res.StructuralDecodeValidated =
                (jsonText.find("\"StructuralDecodeValidated\": true") != std::string::npos);
            res.FidelityPsnrValidated =
                (jsonText.find("\"FidelityPsnrValidated\": true") != std::string::npos);
            EXPECT_TRUE(res.StructuralDecodeValidated);
            EXPECT_TRUE(jsonText.find("\"Passed\": true") != std::string::npos);
            if (verifyH264Psnr)
            {
                EXPECT_TRUE(res.FidelityPsnrValidated);
            }
            (void)ExtractJsonDoubleInScope(jsonText, "H264DecodeValidation", nullptr, "MinYPsnrDb", res.MinYPsnrDb);
            (void)ExtractJsonDoubleInScope(jsonText, "H264DecodeValidation", nullptr, "MinUvPsnrDb", res.MinUvPsnrDb);
        }
    }

    EXPECT_EQ(res.FramesValid, static_cast<uint64_t>(frameCount));
    EXPECT_EQ(res.TimestampMeasurementErrors, 0ULL);
    EXPECT_TRUE(res.CoreTimestampCoveragePercent >= 99.0);
    EXPECT_TRUE(res.LiveTimestampCoveragePercent >= 99.0);
    EXPECT_EQ(crcErr, 0ULL);
    EXPECT_EQ(patErr, 0ULL);
    EXPECT_EQ(protoErr, 0ULL);
    EXPECT_EQ(openErr, 0ULL);
    EXPECT_EQ(syncTimeout, 0ULL);
    EXPECT_EQ(luidErr, 0ULL);

    if (useGpu)
    {
        EXPECT_TRUE(jsonText.find("\"NegotiatedTransportMode\": \"GpuSharedNtHandle\"") != std::string::npos);
        EXPECT_TRUE(jsonText.find("\"FallbackToCpuActivated\": false") != std::string::npos);
        EXPECT_TRUE(res.GpuFramesOpened >= 1ULL && res.GpuFramesOpened <= kDefaultSharedTexturePoolSize);
        if (!verifySynthetic)
        {
            EXPECT_EQ(res.CpuStagingReadsPerformed, 0ULL);
        }
    }
    else
    {
        EXPECT_TRUE(jsonText.find("\"NegotiatedTransportMode\": \"CpuStagingPipe\"") != std::string::npos);
    }

    server.Stop();
    if (useGpu)
    {
        const auto poolSnap = gpuPool.GetMetricsSnapshot();
        EXPECT_EQ(poolSnap.QueuedSlots, 0U);
        EXPECT_EQ(poolSnap.InUseByHostSlots, 0U);
        gpuPool.Shutdown();
    }
    std::filesystem::remove(jsonPath);

    res.Passed = (exitCode == 0UL && res.FramesValid == static_cast<uint64_t>(frameCount));
    return res;
}

void
TestVirtualDisplayStimulusHighResTimer60FpsVerification()
{
    const auto candidates = lumabridge::host::EnumerateActiveDisplayCandidates();
    if (candidates.empty())
    {
        std::printf("[INFO] VirtualDisplayStimulus60Fps: skipped (no active desktop display candidates).\n");
        return;
    }

    std::wstring targetDisplay = candidates.front().DeviceName;
    for (const auto& c : candidates)
    {
        if (lumabridge::host::detail::HasValidBounds(c) && lumabridge::host::detail::IsLumaBridgeCandidate(c))
        {
            targetDisplay = c.DeviceName;
            break;
        }
    }

    lumabridge::host::VirtualDisplayStimulus stimulus;
    const bool started = stimulus.Start(60U, targetDisplay);
    EXPECT_TRUE(started);
    if (!started)
    {
        return;
    }

    Sleep(1500U);
    stimulus.Stop();
    const auto snap = stimulus.GetMetricsSnapshot();

    std::printf(
        "[INFO] VirtualDisplayStimulus 60Hz pacing: display=\"%ls\" hiResTimer=%u ticks=%llu paints=%llu "
        "achievedFps=%.2f tickAvgUs=%llu tickP95Us=%llu tickMaxUs=%llu\n",
        snap.DisplayDeviceName.c_str(),
        snap.HighResolutionTimerUsed ? 1U : 0U,
        static_cast<unsigned long long>(snap.TicksPresented),
        static_cast<unsigned long long>(snap.PaintCount),
        snap.AchievedFps,
        static_cast<unsigned long long>(snap.TickIntervalAvgUs),
        static_cast<unsigned long long>(snap.TickIntervalP95Us),
        static_cast<unsigned long long>(snap.TickIntervalMaxUs));

    EXPECT_TRUE(snap.CompletedCleanly);
    EXPECT_TRUE(snap.HighResolutionTimerUsed);
    EXPECT_TRUE(snap.TicksPresented >= 80ULL);
    EXPECT_TRUE(snap.AchievedFps >= 57.0 && snap.AchievedFps <= 63.0);
}

void
TestEndToEndPhaseAGpuSharedTextureSeparateHostProcess720pAnd1080p()
{
    const std::filesystem::path hostExe = ResolveHostExecutablePath();
    EXPECT_TRUE(!hostExe.empty());
    if (hostExe.empty())
    {
        return;
    }

    ComPtr<ID3D11Device> device;
    ComPtr<ID3D11DeviceContext> context;
    LUID adapterLuid{};
    const char* driverKind = nullptr;
    EXPECT_TRUE(CreateD3d11DeviceWithLuid(device, context, adapterLuid, driverKind));
    if (device == nullptr || context == nullptr)
    {
        return;
    }

    // 1. 720p with synthetic pixel verification across process boundary.
    const auto r720 = RunControlledPipelinePass(
        device.Get(),
        context.Get(),
        adapterLuid,
        hostExe,
        BenchmarkPipelineMode::GpuSharedPhaseA,
        1280U,
        720U,
        12U,
        20U,
        true,
        false);
    EXPECT_TRUE(r720.Passed);

    // 2. 1080p WITH synthetic pattern verification (proves visual integrity across processes).
    const auto r1080Verify = RunControlledPipelinePass(
        device.Get(),
        context.Get(),
        adapterLuid,
        hostExe,
        BenchmarkPipelineMode::GpuSharedPhaseA,
        1920U,
        1080U,
        12U,
        21U,
        true,
        false);
    EXPECT_TRUE(r1080Verify.Passed);

    // 3. 1080p NORMAL GPU mode (NO synthetic readback) -> proves CpuStagingReadsPerformed == 0.
    const auto r1080Normal = RunControlledPipelinePass(
        device.Get(),
        context.Get(),
        adapterLuid,
        hostExe,
        BenchmarkPipelineMode::GpuSharedPhaseA,
        1920U,
        1080U,
        16U,
        22U,
        false,
        false);
    EXPECT_TRUE(r1080Normal.Passed);
    EXPECT_EQ(r1080Normal.CpuStagingReadsPerformed, 0ULL);

    std::printf(
        "[INFO] Phase A Separate Process (%s): 720p connFps=%.2f syncUs=%llu | 1080p(normal, cpuReads=%llu, opened=%llu) execFps=%.2f connFps=%.2f copyUs=%llu e2eUs=%llu pipeBytes=%llu\n",
        driverKind,
        r720.ConnectedFps,
        static_cast<unsigned long long>(r720.GpuSyncWaitAvgUs),
        static_cast<unsigned long long>(r1080Normal.CpuStagingReadsPerformed),
        static_cast<unsigned long long>(r1080Normal.GpuFramesOpened),
        r1080Normal.AverageExecutionFps,
        r1080Normal.ConnectedFps,
        static_cast<unsigned long long>(r1080Normal.CopyAvgUs),
        static_cast<unsigned long long>(r1080Normal.HostAvgE2EUs),
        static_cast<unsigned long long>(r1080Normal.BytesTransferredOverPipe));
}

void
TestEndToEndPhaseBGpuSharedTexturePlusNvencAndIndependentDecode720pAnd1080p()
{
    const std::filesystem::path hostExe = ResolveHostExecutablePath();
    EXPECT_TRUE(!hostExe.empty());
    if (hostExe.empty())
    {
        return;
    }

    ComPtr<ID3D11Device> device;
    ComPtr<ID3D11DeviceContext> context;
    LUID adapterLuid{};
    const char* driverKind = nullptr;
    EXPECT_TRUE(CreateD3d11DeviceWithLuid(device, context, adapterLuid, driverKind));
    if (device == nullptr || context == nullptr)
    {
        return;
    }

    const auto nv720 = RunControlledPipelinePass(
        device.Get(),
        context.Get(),
        adapterLuid,
        hostExe,
        BenchmarkPipelineMode::GpuSharedPlusNvencPhaseB,
        1280U,
        720U,
        12U,
        30U,
        false,
        true,
        true);
    EXPECT_TRUE(nv720.Passed);
    EXPECT_EQ(nv720.CpuStagingReadsPerformed, 0ULL);
    EXPECT_EQ(nv720.NvencFramesEncoded, 12ULL);
    EXPECT_TRUE(nv720.NvencKeyFramesEncoded >= 2ULL);
    EXPECT_TRUE(nv720.StructuralDecodeValidated);
    EXPECT_TRUE(nv720.FidelityPsnrValidated);
    EXPECT_EQ(nv720.TimestampMeasurementErrors, 0ULL);
    EXPECT_EQ(nv720.LiveEndToEndSampleCount, 12ULL);
    EXPECT_TRUE(nv720.LiveTimestampCoveragePercent >= 99.9);
    EXPECT_TRUE(nv720.ExtractToBitstreamCoveragePercent >= 99.9);
    EXPECT_TRUE(nv720.MinYPsnrDb >= 25.0);
    EXPECT_TRUE(nv720.MinUvPsnrDb >= 25.0);

    const auto nv1080 = RunControlledPipelinePass(
        device.Get(),
        context.Get(),
        adapterLuid,
        hostExe,
        BenchmarkPipelineMode::GpuSharedPlusNvencPhaseB,
        1920U,
        1080U,
        12U,
        31U,
        false,
        true,
        true);
    EXPECT_TRUE(nv1080.Passed);
    EXPECT_EQ(nv1080.CpuStagingReadsPerformed, 0ULL);
    EXPECT_EQ(nv1080.NvencFramesEncoded, 12ULL);
    EXPECT_TRUE(nv1080.NvencKeyFramesEncoded >= 2ULL);
    EXPECT_TRUE(nv1080.StructuralDecodeValidated);
    EXPECT_TRUE(nv1080.FidelityPsnrValidated);
    EXPECT_EQ(nv1080.TimestampMeasurementErrors, 0ULL);
    EXPECT_EQ(nv1080.LiveEndToEndSampleCount, 12ULL);
    EXPECT_TRUE(nv1080.LiveTimestampCoveragePercent >= 99.9);
    EXPECT_TRUE(nv1080.ExtractToBitstreamCoveragePercent >= 99.9);
    EXPECT_TRUE(nv1080.MinYPsnrDb >= 25.0);
    EXPECT_TRUE(nv1080.MinUvPsnrDb >= 25.0);

    std::printf(
        "[INFO] Phase B Separate Process+NVENC+PSNR (%s): 720p encAvgUs=%llu presentToBsUs=%llu minY=%.2fdB minUv=%.2fdB cov=%.1f%% bsBytes=%llu | 1080p encAvgUs=%llu presentToBsUs=%llu minY=%.2fdB minUv=%.2fdB cov=%.1f%% bsBytes=%llu\n",
        driverKind,
        static_cast<unsigned long long>(nv720.NvencEncodeAvgUs),
        static_cast<unsigned long long>(nv720.PresentToBitstreamAvgUs),
        nv720.MinYPsnrDb,
        nv720.MinUvPsnrDb,
        nv720.LiveTimestampCoveragePercent,
        static_cast<unsigned long long>(nv720.TotalBitstreamBytes),
        static_cast<unsigned long long>(nv1080.NvencEncodeAvgUs),
        static_cast<unsigned long long>(nv1080.PresentToBitstreamAvgUs),
        nv1080.MinYPsnrDb,
        nv1080.MinUvPsnrDb,
        nv1080.LiveTimestampCoveragePercent,
        static_cast<unsigned long long>(nv1080.TotalBitstreamBytes));
}

void
TestEndToEndControlledThreeWayBenchmark720pAnd1080p()
{
    const std::filesystem::path hostExe = ResolveHostExecutablePath();
    EXPECT_TRUE(!hostExe.empty());
    if (hostExe.empty())
    {
        return;
    }

    ComPtr<ID3D11Device> device;
    ComPtr<ID3D11DeviceContext> context;
    LUID adapterLuid{};
    const char* driverKind = nullptr;
    EXPECT_TRUE(CreateD3d11DeviceWithLuid(device, context, adapterLuid, driverKind));
    if (device == nullptr || context == nullptr)
    {
        return;
    }

    constexpr uint32_t kBenchFrames = 120U;
    struct ResSpec
    {
        uint32_t Width;
        uint32_t Height;
        uint32_t BasePipe;
    };
    const ResSpec resolutions[] = {
        {1280U, 720U, 40U},
        {1920U, 1080U, 50U},
    };

    for (const auto& r : resolutions)
    {
        const auto aCpu = RunControlledPipelinePass(
            device.Get(), context.Get(), adapterLuid, hostExe,
            BenchmarkPipelineMode::CpuStagingM4_1_1,
            r.Width, r.Height, kBenchFrames, r.BasePipe + 0U, false, false);
        const auto bGpu = RunControlledPipelinePass(
            device.Get(), context.Get(), adapterLuid, hostExe,
            BenchmarkPipelineMode::GpuSharedPhaseA,
            r.Width, r.Height, kBenchFrames, r.BasePipe + 1U, false, false);
        const auto cNvenc = RunControlledPipelinePass(
            device.Get(), context.Get(), adapterLuid, hostExe,
            BenchmarkPipelineMode::GpuSharedPlusNvencPhaseB,
            r.Width, r.Height, kBenchFrames, r.BasePipe + 2U, false, false);

        EXPECT_TRUE(aCpu.Passed);
        EXPECT_TRUE(bGpu.Passed);
        EXPECT_TRUE(cNvenc.Passed);
        EXPECT_EQ(bGpu.CpuStagingReadsPerformed, 0ULL);
        EXPECT_EQ(cNvenc.CpuStagingReadsPerformed, 0ULL);

        std::printf(
            "\n=== CONTROLLED 3-WAY BENCHMARK %ux%u (%u frames, %s) ===\n"
            "  [A] M4.1.1 CPU Staging + Named Pipe : execFps=%.2f connFps=%.2f activeFps=%.2f (connMs=%llu) | copyAvg=%lluus p95=%lluus | ipcAvg=%lluus | e2eAvg=%lluus p95=%lluus | pipeBytes=%llu\n"
            "  [B] M4.2 Phase A GPU Shared Texture  : execFps=%.2f connFps=%.2f activeFps=%.2f (connMs=%llu) | copyAvg=%lluus p95=%lluus | ipcAvg=%lluus | syncAvg=%lluus | e2eAvg=%lluus p95=%lluus | pipeBytes=%llu | cpuReads=%llu\n"
            "  [C] M4.2 Phase B GPU + NVENC H.264   : execFps=%.2f connFps=%.2f activeFps=%.2f (connMs=%llu) | copyAvg=%lluus | ipcAvg=%lluus | syncAvg=%lluus | nvencAvg=%lluus p95=%lluus | presentToBs=%lluus | outFps=%.2f | bsBytes=%llu\n",
            r.Width, r.Height, kBenchFrames, driverKind,
            aCpu.AverageExecutionFps, aCpu.ConnectedFps, aCpu.ObservedActiveFps,
            static_cast<unsigned long long>(aCpu.ConnectedDurationUs / 1000ULL),
            static_cast<unsigned long long>(aCpu.CopyAvgUs),
            static_cast<unsigned long long>(aCpu.CopyP95Us),
            static_cast<unsigned long long>(aCpu.IpcAvgUs),
            static_cast<unsigned long long>(aCpu.HostAvgE2EUs),
            static_cast<unsigned long long>(aCpu.HostP95E2EUs),
            static_cast<unsigned long long>(aCpu.BytesTransferredOverPipe),
            bGpu.AverageExecutionFps, bGpu.ConnectedFps, bGpu.ObservedActiveFps,
            static_cast<unsigned long long>(bGpu.ConnectedDurationUs / 1000ULL),
            static_cast<unsigned long long>(bGpu.CopyAvgUs),
            static_cast<unsigned long long>(bGpu.CopyP95Us),
            static_cast<unsigned long long>(bGpu.IpcAvgUs),
            static_cast<unsigned long long>(bGpu.GpuSyncWaitAvgUs),
            static_cast<unsigned long long>(bGpu.HostAvgE2EUs),
            static_cast<unsigned long long>(bGpu.HostP95E2EUs),
            static_cast<unsigned long long>(bGpu.BytesTransferredOverPipe),
            static_cast<unsigned long long>(bGpu.CpuStagingReadsPerformed),
            cNvenc.AverageExecutionFps, cNvenc.ConnectedFps, cNvenc.ObservedActiveFps,
            static_cast<unsigned long long>(cNvenc.ConnectedDurationUs / 1000ULL),
            static_cast<unsigned long long>(cNvenc.CopyAvgUs),
            static_cast<unsigned long long>(cNvenc.IpcAvgUs),
            static_cast<unsigned long long>(cNvenc.GpuSyncWaitAvgUs),
            static_cast<unsigned long long>(cNvenc.NvencEncodeAvgUs),
            static_cast<unsigned long long>(cNvenc.NvencEncodeP95Us),
            static_cast<unsigned long long>(cNvenc.PresentToBitstreamAvgUs),
            cNvenc.EncoderOutputFps,
            static_cast<unsigned long long>(cNvenc.TotalBitstreamBytes));
    }
}

void
TestEndToEndProlonged1080p60GpuNvenc30SecondBenchmark()
{
    const std::filesystem::path hostExe = ResolveHostExecutablePath();
    EXPECT_TRUE(!hostExe.empty());
    if (hostExe.empty())
    {
        return;
    }

    ComPtr<ID3D11Device> device;
    ComPtr<ID3D11DeviceContext> context;
    LUID adapterLuid{};
    const char* driverKind = nullptr;
    EXPECT_TRUE(CreateD3d11DeviceWithLuid(device, context, adapterLuid, driverKind));
    if (device == nullptr || context == nullptr)
    {
        return;
    }

    constexpr uint32_t kWidth = 1920U;
    constexpr uint32_t kHeight = 1080U;
    constexpr uint32_t kTargetFps = 60U;
    constexpr uint32_t kDurationSec = 30U;
    constexpr uint32_t kTotalFrames = kTargetFps * kDurationSec;
    constexpr uint32_t kPrebuiltRing = 4U;

    std::vector<ComPtr<ID3D11Texture2D>> ringTextures(kPrebuiltRing);
    for (uint32_t i = 0U; i < kPrebuiltRing; ++i)
    {
        EXPECT_TRUE(CreateSyntheticTexture(device.Get(), kWidth, kHeight, i + 1U, ringTextures[i]));
        if (ringTextures[i] == nullptr)
        {
            return;
        }
    }

    wchar_t pipeBuf[128]{};
    _snwprintf_s(
        pipeBuf,
        ARRAYSIZE(pipeBuf),
        _TRUNCATE,
        L"\\\\.\\pipe\\LumaBridgeM421Bench30s_%lu",
        GetCurrentProcessId());
    const std::wstring pipeName(pipeBuf);

    D3d11SharedTexturePool gpuPool;
    EXPECT_EQ(gpuPool.Configure(
        kDefaultSharedTexturePoolSize,
        nullptr,
        false,
        true,
        true,
        true,
        25U), S_OK);
    gpuPool.SetDevice(device.Get(), context.Get(), adapterLuid);

    FrameTransportConfig serverCfg;
    serverCfg.SetPipeName(pipeName.c_str());
    serverCfg.MaxQueueDepth = 3U;
    serverCfg.BufferPoolSize = 5U;
    serverCfg.AdapterLuid = adapterLuid;
    serverCfg.EnableGpuSharedTransport = true;
    serverCfg.AllowCpuFallbackWhenGpuNegotiated = false;
    serverCfg.SharedTexturePool = &gpuPool;
    serverCfg.SharedTexturePoolSize = kDefaultSharedTexturePoolSize;

    FrameIpcServer server;
    EXPECT_EQ(server.Start(serverCfg), S_OK);

    const std::filesystem::path jsonPath = MakeTempJsonPath(L"m421_bench30s_1080p60");
    std::filesystem::remove(jsonPath);

    const std::wstring extraArgs =
        L"--max-frames " + std::to_wstring(kTotalFrames) +
        L" --require-max-frames --connect-timeout-ms 5000 --io-timeout-ms 1500"
        L" --transport gpu --require-gpu-shared --nvenc --require-nvenc"
        L" --nvenc-bitrate-bps 20000000 --nvenc-gop 60"
        L" --prewarm-width 1920 --prewarm-height 1080 --verify-h264-decode";

    std::atomic<bool> producerOk{true};
    std::atomic<bool> stopRequested{false};
    std::atomic<double> stimulusAchievedFps{0.0};

    std::thread producer([&]() {
        const ULONGLONG connWaitStart = GetTickCount64();
        while (!stopRequested.load(std::memory_order_acquire))
        {
            const auto snap = server.GetMetricsSnapshot();
            if (snap.ActiveHostConnections > 0U && server.ShouldProduceGpuSharedFrame())
            {
                break;
            }
            if ((GetTickCount64() - connWaitStart) > 8000ULL)
            {
                producerOk = false;
                return;
            }
            SwitchToThread();
        }

        LARGE_INTEGER freqLi{};
        QueryPerformanceFrequency(&freqLi);
        const uint64_t qpcFreq = (freqLi.QuadPart > 0) ? static_cast<uint64_t>(freqLi.QuadPart) : 10000000ULL;

        HANDLE hiResTimer = CreateWaitableTimerExW(
            nullptr,
            nullptr,
            CREATE_WAITABLE_TIMER_HIGH_RESOLUTION,
            TIMER_ALL_ACCESS);

        LARGE_INTEGER startLi{};
        QueryPerformanceCounter(&startLi);
        const uint64_t loopStartQpc = static_cast<uint64_t>(startLi.QuadPart);
        uint64_t firstPresentQpc = 0ULL;
        uint64_t lastPresentQpc = 0ULL;

        for (uint32_t i = 0U; i < kTotalFrames; ++i)
        {
            const uint64_t targetQpc =
                loopStartQpc + ((static_cast<uint64_t>(i) * qpcFreq) / static_cast<uint64_t>(kTargetFps));
            LARGE_INTEGER nowLi{};
            QueryPerformanceCounter(&nowLi);
            uint64_t nowQpc = static_cast<uint64_t>(nowLi.QuadPart);
            if (hiResTimer != nullptr && nowQpc < targetQpc)
            {
                const uint64_t remainingUs = ((targetQpc - nowQpc) * 1000000ULL) / qpcFreq;
                if (remainingUs > 1200ULL)
                {
                    LARGE_INTEGER due{};
                    due.QuadPart = -static_cast<LONGLONG>((remainingUs - 600ULL) * 10ULL);
                    if (SetWaitableTimer(hiResTimer, &due, 0, nullptr, nullptr, FALSE) != FALSE)
                    {
                        (void)WaitForSingleObject(hiResTimer, 2000U);
                    }
                }
            }
            while (true)
            {
                QueryPerformanceCounter(&nowLi);
                nowQpc = static_cast<uint64_t>(nowLi.QuadPart);
                if (nowQpc >= targetQpc || stopRequested.load(std::memory_order_acquire))
                {
                    break;
                }
                YieldProcessor();
            }

            const ULONGLONG slotWaitStart = GetTickCount64();
            while (!stopRequested.load(std::memory_order_acquire))
            {
                const auto sSnap = server.GetMetricsSnapshot();
                const auto pSnap = gpuPool.GetMetricsSnapshot();
                if (sSnap.QueueDepth < 2U && (pSnap.QueuedSlots + pSnap.InUseByHostSlots) < 3U)
                {
                    break;
                }
                if ((GetTickCount64() - slotWaitStart) > 5000ULL)
                {
                    producerOk = false;
                    if (hiResTimer != nullptr)
                    {
                        CloseHandle(hiResTimer);
                    }
                    return;
                }
                SwitchToThread();
            }

            auto slot = server.AcquireBufferSlot();
            if (slot == nullptr)
            {
                producerOk = false;
                if (hiResTimer != nullptr)
                {
                    CloseHandle(hiResTimer);
                }
                return;
            }

            QueryPerformanceCounter(&nowLi);
            const uint64_t presentQpc = static_cast<uint64_t>(nowLi.QuadPart);
            if (firstPresentQpc == 0ULL)
            {
                firstPresentQpc = presentQpc;
            }
            lastPresentQpc = presentQpc;

            const uint32_t patternFrame = (i % kPrebuiltRing) + 1U;
            FrameExtractionInput in{};
            in.SourceTexture = ringTextures[i % kPrebuiltRing].Get();
            in.PresentationFrameNumber = patternFrame;
            in.PresentDisplayQpcTime = presentQpc;
            in.Flags = static_cast<uint32_t>(FrameIpcFlags::SyntheticTestFrame);

            const SharedTextureExtractResult ext = gpuPool.ExtractToSharedTexture(in, *slot, true);
            if (FAILED(ext.HResult) || !ext.GpuCopied)
            {
                server.RecycleBufferSlot(std::move(slot));
                producerOk = false;
                if (hiResTimer != nullptr)
                {
                    CloseHandle(hiResTimer);
                }
                return;
            }

            bool evicted = false;
            if (FAILED(server.EnqueueFrame(std::move(slot), evicted)))
            {
                producerOk = false;
                if (hiResTimer != nullptr)
                {
                    CloseHandle(hiResTimer);
                }
                return;
            }
        }

        if (hiResTimer != nullptr)
        {
            CloseHandle(hiResTimer);
        }
        if (lastPresentQpc > firstPresentQpc)
        {
            const double spanSec =
                static_cast<double>(lastPresentQpc - firstPresentQpc) / static_cast<double>(qpcFreq);
            stimulusAchievedFps.store(static_cast<double>(kTotalFrames - 1U) / spanSec);
        }
    });

    DWORD exitCode = 1U;
    const bool launchedOk = LaunchHostProcessWithCustomArgsAndWait(
        hostExe,
        pipeName,
        extraArgs,
        jsonPath,
        exitCode,
        60000U);
    stopRequested.store(true, std::memory_order_release);
    producer.join();

    EXPECT_TRUE(launchedOk);
    EXPECT_TRUE(producerOk.load());
    EXPECT_EQ(exitCode, 0UL);

    const std::string jsonText = ReadFileText(jsonPath);
    EXPECT_TRUE(!jsonText.empty());

    uint64_t framesValid = 0ULL;
    uint64_t tsErrors = 99ULL;
    uint64_t cpuReads = 99ULL;
    uint64_t liveSampleCount = 0ULL;
    uint64_t liveE2EAvgUs = 0ULL;
    uint64_t liveE2EP95Us = 0ULL;
    uint64_t liveE2EP99Us = 0ULL;
    uint64_t jitterAvgUs = 0ULL;
    uint64_t poolPeak = 0ULL;
    uint64_t nvEncoded = 0ULL;
    uint64_t nvInitUs = 0ULL;
    uint64_t nvEncAvgUs = 0ULL;
    uint64_t nvEncP95Us = 0ULL;
    uint64_t nvEncP99Us = 0ULL;
    uint64_t nvPrepAvgUs = 0ULL;
    uint64_t nvPicAvgUs = 0ULL;
    uint64_t nvLockAvgUs = 0ULL;
    uint64_t extToBsP99Us = 0ULL;
    uint64_t framesDecoded = 0ULL;
    uint64_t nalFail = 99ULL;
    uint64_t decFail = 99ULL;
    uint64_t hostWsBytes = 0ULL;
    uint64_t hostPeakWsBytes = 0ULL;
    double coreCov = 0.0;
    double liveCov = 0.0;
    double presCov = 0.0;
    double extToBsCov = 0.0;
    double sustainedLiveFps = 0.0;
    double encOutputFps = 0.0;
    double hostCpuPct = 0.0;

    EXPECT_TRUE(ExtractJsonNumber(jsonText, "FramesValid", framesValid));
    EXPECT_TRUE(ExtractJsonNumber(jsonText, "TimestampMeasurementErrors", tsErrors));
    EXPECT_TRUE(ExtractJsonNumber(jsonText, "CpuStagingReadsPerformed", cpuReads));
    EXPECT_TRUE(ExtractJsonNumber(jsonText, "SharedTexturePoolPeakUsage", poolPeak));
    EXPECT_TRUE(ExtractJsonDouble(jsonText, "CoreTimestampCoveragePercent", coreCov));
    EXPECT_TRUE(ExtractJsonDouble(jsonText, "LiveTimestampCoveragePercent", liveCov));
    EXPECT_TRUE(ExtractJsonDouble(jsonText, "PresentTimestampCoveragePercent", presCov));
    EXPECT_TRUE(ExtractJsonDouble(jsonText, "SustainedLiveFps", sustainedLiveFps));

    EXPECT_TRUE(ExtractJsonNumberInScope(jsonText, "LiveEndToEndLatency", nullptr, "SampleCount", liveSampleCount));
    EXPECT_TRUE(ExtractJsonNumberInScope(jsonText, "LiveEndToEndLatency", nullptr, "AvgUs", liveE2EAvgUs));
    EXPECT_TRUE(ExtractJsonNumberInScope(jsonText, "LiveEndToEndLatency", nullptr, "P95Us", liveE2EP95Us));
    EXPECT_TRUE(ExtractJsonNumberInScope(jsonText, "LiveEndToEndLatency", nullptr, "P99Us", liveE2EP99Us));
    EXPECT_TRUE(ExtractJsonNumberInScope(jsonText, "InterFrameJitter", nullptr, "AvgUs", jitterAvgUs));

    EXPECT_TRUE(ExtractJsonNumberInScope(jsonText, "Nvenc", nullptr, "NvencFramesEncoded", nvEncoded));
    EXPECT_TRUE(ExtractJsonNumberInScope(jsonText, "Nvenc", nullptr, "SessionInitializeLatencyUs", nvInitUs));
    EXPECT_TRUE(ExtractJsonDoubleInScope(jsonText, "Nvenc", nullptr, "EncoderOutputFps", encOutputFps));
    EXPECT_TRUE(ExtractJsonDoubleInScope(jsonText, "Nvenc", nullptr, "ExtractToBitstreamCoveragePercent", extToBsCov));
    EXPECT_TRUE(ExtractJsonNumberInScope(jsonText, "Nvenc", "EncodeLatencyUs", "AvgUs", nvEncAvgUs));
    EXPECT_TRUE(ExtractJsonNumberInScope(jsonText, "Nvenc", "EncodeLatencyUs", "P95Us", nvEncP95Us));
    EXPECT_TRUE(ExtractJsonNumberInScope(jsonText, "Nvenc", "EncodeLatencyUs", "P99Us", nvEncP99Us));
    EXPECT_TRUE(ExtractJsonNumberInScope(jsonText, "Nvenc", "FormatPrepareLatencyUs", "AvgUs", nvPrepAvgUs));
    EXPECT_TRUE(ExtractJsonNumberInScope(jsonText, "Nvenc", "EncodePictureLatencyUs", "AvgUs", nvPicAvgUs));
    EXPECT_TRUE(ExtractJsonNumberInScope(jsonText, "Nvenc", "BitstreamLockCopyLatencyUs", "AvgUs", nvLockAvgUs));
    EXPECT_TRUE(ExtractJsonNumberInScope(jsonText, "Nvenc", "ExtractToBitstreamLatencyUs", "P99Us", extToBsP99Us));

    EXPECT_TRUE(ExtractJsonNumberInScope(jsonText, "H264DecodeValidation", nullptr, "FramesDecoded", framesDecoded));
    EXPECT_TRUE(ExtractJsonNumberInScope(jsonText, "H264DecodeValidation", nullptr, "NalParseFailures", nalFail));
    EXPECT_TRUE(ExtractJsonNumberInScope(jsonText, "H264DecodeValidation", nullptr, "DecodeFailures", decFail));
    (void)ExtractJsonNumberInScope(jsonText, "ResourceUsage", "Host", "WorkingSetBytes", hostWsBytes);
    (void)ExtractJsonNumberInScope(jsonText, "ResourceUsage", "Host", "PeakWorkingSetBytes", hostPeakWsBytes);
    (void)ExtractJsonDoubleInScope(jsonText, "ResourceUsage", "Host", "CpuUsagePercent", hostCpuPct);

    const auto poolSnap = gpuPool.GetMetricsSnapshot();

    EXPECT_EQ(framesValid, static_cast<uint64_t>(kTotalFrames));
    EXPECT_EQ(tsErrors, 0ULL);
    EXPECT_EQ(cpuReads, 0ULL);
    EXPECT_EQ(liveSampleCount, static_cast<uint64_t>(kTotalFrames));
    EXPECT_TRUE(coreCov >= 99.9);
    EXPECT_TRUE(liveCov >= 99.9);
    EXPECT_TRUE(presCov >= 99.9);
    EXPECT_EQ(nvEncoded, static_cast<uint64_t>(kTotalFrames));
    EXPECT_TRUE(extToBsCov >= 99.9);
    EXPECT_TRUE(sustainedLiveFps >= 57.0 && sustainedLiveFps <= 63.0);
    EXPECT_TRUE(encOutputFps >= 57.0 && encOutputFps <= 63.0);
    EXPECT_TRUE(jsonText.find("\"StructuralDecodeValidated\": true") != std::string::npos);
    EXPECT_TRUE(framesDecoded >= 1790ULL);
    EXPECT_EQ(nalFail, 0ULL);
    EXPECT_EQ(decFail, 0ULL);
    EXPECT_TRUE(nvEncP99Us < 25000ULL);
    EXPECT_TRUE(liveE2EP99Us < 30000ULL);
    EXPECT_TRUE(extToBsP99Us < 30000ULL);

    std::printf(
        "\n=== PROLONGED 30s 1080p60 GPU+NVENC BENCHMARK (%s, %u frames) ===\n"
        "  StimulusFPS=%.3f | HostLiveFPS=%.3f | NvencOutFPS=%.3f | Coverage(core=%.1f%%, live=%.1f%%, bs=%.1f%%)\n"
        "  HostLiveE2E(avg=%lluus, p95=%lluus, p99=%lluus) | JitterAvg=%lluus | PoolSlotWait(avg=%lluus, max=%lluus, peak=%llu/%u)\n"
        "  NVENC(init=%lluus, avg=%lluus, p95=%lluus, p99=%lluus | prep=%lluus, pic=%lluus, lock=%lluus) | ExtToBsP99=%lluus\n"
        "  HostMem(ws=%.2fMB, peak=%.2fMB, cpu=%.2f%%) | Decoded=%llu | CpuReads=%llu | TsErrors=%llu\n",
        driverKind,
        kTotalFrames,
        stimulusAchievedFps.load(),
        sustainedLiveFps,
        encOutputFps,
        coreCov,
        liveCov,
        extToBsCov,
        static_cast<unsigned long long>(liveE2EAvgUs),
        static_cast<unsigned long long>(liveE2EP95Us),
        static_cast<unsigned long long>(liveE2EP99Us),
        static_cast<unsigned long long>(jitterAvgUs),
        static_cast<unsigned long long>(poolSnap.AvgProducerSlotWaitUs),
        static_cast<unsigned long long>(poolSnap.MaxProducerSlotWaitUs),
        static_cast<unsigned long long>(poolPeak),
        poolSnap.PoolSize,
        static_cast<unsigned long long>(nvInitUs),
        static_cast<unsigned long long>(nvEncAvgUs),
        static_cast<unsigned long long>(nvEncP95Us),
        static_cast<unsigned long long>(nvEncP99Us),
        static_cast<unsigned long long>(nvPrepAvgUs),
        static_cast<unsigned long long>(nvPicAvgUs),
        static_cast<unsigned long long>(nvLockAvgUs),
        static_cast<unsigned long long>(extToBsP99Us),
        static_cast<double>(hostWsBytes) / (1024.0 * 1024.0),
        static_cast<double>(hostPeakWsBytes) / (1024.0 * 1024.0),
        hostCpuPct,
        static_cast<unsigned long long>(framesDecoded),
        static_cast<unsigned long long>(cpuReads),
        static_cast<unsigned long long>(tsErrors));

    server.Stop();
    EXPECT_EQ(poolSnap.QueuedSlots, 0U);
    EXPECT_EQ(poolSnap.InUseByHostSlots, 0U);
    gpuPool.Shutdown();
    std::filesystem::remove(jsonPath);
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
    RunTest("EndToEndRealD3d11ExtractionToSeparateHostProcess720pAnd1080p", TestEndToEndRealD3d11ExtractionToSeparateHostProcess720pAnd1080p);
    RunTest("EndToEndHostDisconnectAndReconnectDuringActiveSwapChainLoop", TestEndToEndHostDisconnectAndReconnectDuringActiveSwapChainLoop);
    RunTest("EndToEndSmokeDurationExitAndMinFramesVsTargetCli", TestEndToEndSmokeDurationExitAndMinFramesVsTargetCli);
    RunTest("EndToEndThroughputAndLatencyBenchmark720pAnd1080p", TestEndToEndThroughputAndLatencyBenchmark720pAnd1080p);
    RunTest("VirtualDisplayStimulusHighResTimer60FpsVerification", TestVirtualDisplayStimulusHighResTimer60FpsVerification);
    RunTest("EndToEndPhaseAGpuSharedTextureSeparateHostProcess720pAnd1080p", TestEndToEndPhaseAGpuSharedTextureSeparateHostProcess720pAnd1080p);
    RunTest("EndToEndPhaseBGpuSharedTexturePlusNvencAndIndependentDecode720pAnd1080p", TestEndToEndPhaseBGpuSharedTexturePlusNvencAndIndependentDecode720pAnd1080p);
    RunTest("EndToEndControlledThreeWayBenchmark720pAnd1080p", TestEndToEndControlledThreeWayBenchmark720pAnd1080p);
    RunTest("EndToEndProlonged1080p60GpuNvenc30SecondBenchmark", TestEndToEndProlonged1080p60GpuNvenc30SecondBenchmark);

    std::printf("Summary: %d tests run, %d assertion failures.\n", g_TestsRun, g_TestsFailed);
    return (g_TestsFailed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
