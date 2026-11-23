#include "../LumaBridgeIddDriver/SwapChainProcessor.h"
#include "../LumaBridgeIddDriver/FrameExtractor.h"
#include "../LumaBridgeIddDriver/FrameIpcProtocol.h"
#include "../LumaBridgeIddDriver/FrameTransport.h"

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
LaunchHostProcessAndWait(
    const std::filesystem::path& hostExe,
    const std::wstring& pipeName,
    uint32_t maxFrames,
    const std::filesystem::path& jsonSummaryPath,
    DWORD& outExitCode
    )
{
    outExitCode = 1U;
    std::wstring cmdLine =
        L"\"" + hostExe.wstring() + L"\"" +
        L" --pipe \"" + pipeName + L"\"" +
        L" --max-frames " + std::to_wstring(maxFrames) +
        L" --connect-timeout-ms 5000" +
        L" --io-timeout-ms 1000" +
        L" --verify-synthetic-pattern" +
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

    const DWORD waitRes = WaitForSingleObject(pi.hProcess, 15000U);
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
    uint64_t crcErr = 99ULL;
    uint64_t patErr = 99ULL;
    uint64_t hostAvgE2E = 0ULL;
    uint64_t hostMaxE2E = 0ULL;
    double hostFps = 0.0;
    EXPECT_TRUE(ExtractJsonNumber(jsonText, "FramesReceived", framesRecv));
    EXPECT_TRUE(ExtractJsonNumber(jsonText, "ChecksumMismatches", crcErr));
    EXPECT_TRUE(ExtractJsonNumber(jsonText, "SyntheticPatternMismatches", patErr));
    EXPECT_TRUE(ExtractJsonNumber(jsonText, "AvgEndToEndLatencyUs", hostAvgE2E));
    EXPECT_TRUE(ExtractJsonNumber(jsonText, "MaxEndToEndLatencyUs", hostMaxE2E));
    EXPECT_TRUE(ExtractJsonDouble(jsonText, "ReceiveFps", hostFps));
    EXPECT_EQ(framesRecv, static_cast<uint64_t>(frameCount));
    EXPECT_EQ(crcErr, 0ULL);
    EXPECT_EQ(patErr, 0ULL);

    const auto sSnap = server.GetMetricsSnapshot();
    const uint64_t avgCopyUs = totalCopyUs.load() / frameCount;
    std::printf(
        "[BENCH] %s %ux%u (%u frames): avgCopyUs=%llu maxCopyUs=%llu avgDeliveryUs=%llu hostAvgE2EUs=%llu hostMaxE2EUs=%llu hostReceiveFps=%.2f\n",
        driverKind,
        width,
        height,
        frameCount,
        static_cast<unsigned long long>(avgCopyUs),
        static_cast<unsigned long long>(maxCopyUs.load()),
        static_cast<unsigned long long>(sSnap.AvgDeliveryLatencyUs),
        static_cast<unsigned long long>(hostAvgE2E),
        static_cast<unsigned long long>(hostMaxE2E),
        hostFps);

    std::filesystem::remove(jsonPath);
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
    RunTest("EndToEndThroughputAndLatencyBenchmark720pAnd1080p", TestEndToEndThroughputAndLatencyBenchmark720pAnd1080p);

    std::printf("Summary: %d tests run, %d assertion failures.\n", g_TestsRun, g_TestsFailed);
    return (g_TestsFailed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
