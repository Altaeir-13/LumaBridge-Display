#include <Windows.h>
#include <d3d11.h>
#include <dxgi1_2.h>
#include <wrl/client.h>

#include "../../host/H264BitstreamValidator.h"
#include "../../host/NvencH264Encoder.h"
#include "../LumaBridgeIddDriver/FrameIpcProtocol.h"

#include <cstdio>
#include <cstdlib>
#include <vector>

using Microsoft::WRL::ComPtr;

namespace {

int g_failures = 0;

void
ReportFailure(
    const char* testName,
    const char* expr,
    int line
    )
{
    std::fprintf(stderr, "[FAIL] %s (line %d): %s\n", testName, line, expr);
    ++g_failures;
}

#define ASSERT_TRUE(cond)                                    \
    do                                                       \
    {                                                        \
        if (!(cond))                                         \
        {                                                    \
            ReportFailure(kTestName, #cond, __LINE__);       \
            return false;                                    \
        }                                                    \
    } while (false)

HRESULT
CreateNvidiaHardwareD3d11Device(
    ComPtr<ID3D11Device>& outDevice,
    ComPtr<ID3D11DeviceContext>& outContext,
    LUID* outAdapterLuid = nullptr
    ) noexcept
{
    outDevice.Reset();
    outContext.Reset();

    ComPtr<IDXGIFactory1> factory;
    HRESULT hr = CreateDXGIFactory1(IID_PPV_ARGS(&factory));
    if (FAILED(hr) || factory == nullptr)
    {
        return FAILED(hr) ? hr : E_FAIL;
    }

    ComPtr<IDXGIAdapter1> selectedAdapter;
    for (UINT i = 0U;; ++i)
    {
        ComPtr<IDXGIAdapter1> adapter;
        const HRESULT enumHr = factory->EnumAdapters1(i, &adapter);
        if (enumHr == DXGI_ERROR_NOT_FOUND)
        {
            break;
        }
        if (FAILED(enumHr) || adapter == nullptr)
        {
            continue;
        }

        DXGI_ADAPTER_DESC1 desc{};
        if (SUCCEEDED(adapter->GetDesc1(&desc)))
        {
            if ((desc.Flags & DXGI_ADAPTER_FLAG_SOFTWARE) != 0U)
            {
                continue;
            }
            if (desc.VendorId == 0x10DEU)
            {
                selectedAdapter = adapter;
                if (outAdapterLuid != nullptr)
                {
                    *outAdapterLuid = desc.AdapterLuid;
                }
                break;
            }
            if (selectedAdapter == nullptr)
            {
                selectedAdapter = adapter;
                if (outAdapterLuid != nullptr)
                {
                    *outAdapterLuid = desc.AdapterLuid;
                }
            }
        }
    }

    if (selectedAdapter == nullptr)
    {
        return DXGI_ERROR_NOT_FOUND;
    }

    static const D3D_FEATURE_LEVEL kLevels[] = {
        D3D_FEATURE_LEVEL_11_1,
        D3D_FEATURE_LEVEL_11_0,
    };

    const UINT flags = D3D11_CREATE_DEVICE_BGRA_SUPPORT | D3D11_CREATE_DEVICE_VIDEO_SUPPORT;
    D3D_FEATURE_LEVEL chosenLevel = D3D_FEATURE_LEVEL_11_0;
    hr = D3D11CreateDevice(
        selectedAdapter.Get(),
        D3D_DRIVER_TYPE_UNKNOWN,
        nullptr,
        flags,
        kLevels,
        ARRAYSIZE(kLevels),
        D3D11_SDK_VERSION,
        &outDevice,
        &chosenLevel,
        &outContext);
    if (FAILED(hr))
    {
        hr = D3D11CreateDevice(
            selectedAdapter.Get(),
            D3D_DRIVER_TYPE_UNKNOWN,
            nullptr,
            D3D11_CREATE_DEVICE_BGRA_SUPPORT,
            kLevels,
            ARRAYSIZE(kLevels),
            D3D11_SDK_VERSION,
            &outDevice,
            &chosenLevel,
            &outContext);
    }

    return hr;
}

HRESULT
CreateSyntheticGpuTexture(
    ID3D11Device* device,
    uint32_t width,
    uint32_t height,
    uint32_t frameNumber,
    DXGI_FORMAT format,
    ComPtr<ID3D11Texture2D>& outTexture
    ) noexcept
{
    outTexture.Reset();
    if (device == nullptr || width == 0U || height == 0U)
    {
        return E_INVALIDARG;
    }

    uint32_t rowPitch = 0U;
    uint32_t payloadBytes = 0U;
    if (!lumabridge::ipc::ComputeTightRowPitchBytes(width, rowPitch) ||
        !lumabridge::ipc::ComputeValidatedFramePayloadBytes(width, height, rowPitch, payloadBytes))
    {
        return E_INVALIDARG;
    }

    std::vector<uint8_t> pixels(payloadBytes);
    if (!lumabridge::ipc::GenerateSyntheticTestPatternBgra8(
            frameNumber,
            width,
            height,
            pixels.data(),
            pixels.size()))
    {
        return E_FAIL;
    }

    D3D11_TEXTURE2D_DESC desc{};
    desc.Width = width;
    desc.Height = height;
    desc.MipLevels = 1U;
    desc.ArraySize = 1U;
    desc.Format = format;
    desc.SampleDesc.Count = 1U;
    desc.Usage = D3D11_USAGE_DEFAULT;
    desc.BindFlags = D3D11_BIND_RENDER_TARGET | D3D11_BIND_SHADER_RESOURCE;

    D3D11_SUBRESOURCE_DATA initData{};
    initData.pSysMem = pixels.data();
    initData.SysMemPitch = rowPitch;

    return device->CreateTexture2D(&desc, &initData, &outTexture);
}

uint64_t
QueryQpcNow() noexcept
{
    LARGE_INTEGER li{};
    (void)QueryPerformanceCounter(&li);
    return static_cast<uint64_t>(li.QuadPart);
}

uint64_t
QueryQpcFreq() noexcept
{
    LARGE_INTEGER li{};
    (void)QueryPerformanceFrequency(&li);
    return (li.QuadPart > 0) ? static_cast<uint64_t>(li.QuadPart) : 10000000ULL;
}

class FaultInjectingNvencHooks final : public lumabridge::host::INvencApiHooks
{
public:
    uint64_t BusyOnFrameSequence{0ULL};
    bool TriggerDeviceRemovedOnPrepare{false};
    uint32_t BusyInjections{0U};
    uint32_t PrepareFailures{0U};

    NVENCSTATUS OnPreEncodePicture(
        uint64_t frameSequence,
        NV_ENC_PIC_PARAMS& picParams
        ) noexcept override
    {
        (void)picParams;
        if (BusyOnFrameSequence != 0ULL && frameSequence == BusyOnFrameSequence)
        {
            ++BusyInjections;
            return NV_ENC_ERR_ENCODER_BUSY;
        }
        return NV_ENC_SUCCESS;
    }

    HRESULT OnPreGpuFormatPrepare(
        ID3D11Texture2D* sourceTexture
        ) noexcept override
    {
        (void)sourceTexture;
        if (TriggerDeviceRemovedOnPrepare)
        {
            ++PrepareFailures;
            return DXGI_ERROR_DEVICE_REMOVED;
        }
        return S_OK;
    }
};

bool
TestNvencRuntimeDetectionAndCapabilityQueryOnRtx3060Ti()
{
    static constexpr const char* kTestName = "NvencRuntimeDetectionAndCapabilityQueryOnRtx3060Ti";

    ComPtr<ID3D11Device> device;
    ComPtr<ID3D11DeviceContext> context;
    ASSERT_TRUE(SUCCEEDED(CreateNvidiaHardwareD3d11Device(device, context)));

    lumabridge::host::NvencCapabilitiesSnapshot caps{};
    NVENCSTATUS st = NV_ENC_ERR_GENERIC;
    const bool available = lumabridge::host::NvencH264Encoder::ProbeAvailability(device.Get(), caps, &st);
    ASSERT_TRUE(available);
    ASSERT_TRUE(st == NV_ENC_SUCCESS);
    ASSERT_TRUE(caps.RuntimeLibraryLoaded);
    ASSERT_TRUE(caps.SessionOpened);
    ASSERT_TRUE(caps.H264Supported);
    ASSERT_TRUE(caps.SupportsArgbInput || caps.SupportsNv12Input);
    ASSERT_TRUE(caps.MaxWidth >= 1920U);
    ASSERT_TRUE(caps.MaxHeight >= 1080U);
    ASSERT_TRUE(caps.DriverMaxApiVersionMajor >= 12U);

    std::printf(
        "[INFO] %s: nvencMaxApi=%u.%u argb=%u abgr=%u nv12=%u max=%ux%u dynRes=%u dynBitrate=%u\n",
        kTestName,
        caps.DriverMaxApiVersionMajor,
        caps.DriverMaxApiVersionMinor,
        caps.SupportsArgbInput ? 1U : 0U,
        caps.SupportsAbgrInput ? 1U : 0U,
        caps.SupportsNv12Input ? 1U : 0U,
        caps.MaxWidth,
        caps.MaxHeight,
        caps.SupportsDynamicResolutionChange ? 1U : 0U,
        caps.SupportsDynamicBitrateChange ? 1U : 0U);
    std::printf("[PASS] %s\n", kTestName);
    return true;
}

bool
TestNvencSessionInitEncodeAndCleanDestroy720pAnd1080p()
{
    static constexpr const char* kTestName = "NvencSessionInitEncodeAndCleanDestroy720pAnd1080p";

    ComPtr<ID3D11Device> device;
    ComPtr<ID3D11DeviceContext> context;
    ASSERT_TRUE(SUCCEEDED(CreateNvidiaHardwareD3d11Device(device, context)));

    struct ResolutionCase
    {
        uint32_t Width;
        uint32_t Height;
    };
    const ResolutionCase cases[] = {
        {1280U, 720U},
        {1920U, 1080U},
    };

    const uint64_t qpcFreq = QueryQpcFreq();

    for (const auto& rc : cases)
    {
        lumabridge::host::NvencEncoderConfig cfg{};
        cfg.Width = rc.Width;
        cfg.Height = rc.Height;
        cfg.TargetFps = 60U;
        cfg.BitrateBps = 15000000U;
        cfg.MaxBitrateBps = 20000000U;
        cfg.GopLength = 60U;
        cfg.LowLatencyTuning = true;
        cfg.RepeatSpsPpsEveryIdr = true;
        cfg.ColorMode = lumabridge::host::NvencColorConversionMode::Auto;
        cfg.MaxEncodedQueueDepth = 8U;

        lumabridge::host::NvencH264Encoder encoder;
        ASSERT_TRUE(SUCCEEDED(encoder.Initialize(device.Get(), context.Get(), cfg)));
        ASSERT_TRUE(encoder.IsInitialized());

        for (uint32_t i = 1U; i <= 5U; ++i)
        {
            ComPtr<ID3D11Texture2D> tex;
            ASSERT_TRUE(SUCCEEDED(CreateSyntheticGpuTexture(
                device.Get(),
                rc.Width,
                rc.Height,
                i,
                DXGI_FORMAT_B8G8R8A8_UNORM,
                tex)));

            const uint64_t nowQpc = QueryQpcNow();
            lumabridge::host::EncodedFramePacket pkt{};
            ASSERT_TRUE(SUCCEEDED(encoder.EncodeGpuTexture(
                tex.Get(),
                static_cast<uint64_t>(i),
                i,
                nowQpc,
                nowQpc,
                qpcFreq,
                &pkt)));
            ASSERT_TRUE(!pkt.Bitstream.empty());
            ASSERT_TRUE(pkt.Width == rc.Width);
            ASSERT_TRUE(pkt.Height == rc.Height);
            ASSERT_TRUE(pkt.FrameSequence == static_cast<uint64_t>(i));
            ASSERT_TRUE(pkt.PresentationFrameNumber == i);
            if (i == 1U)
            {
                ASSERT_TRUE(pkt.IsKeyFrame);
            }
        }

        const auto snap = encoder.GetMetricsSnapshot();
        ASSERT_TRUE(snap.Initialized);
        ASSERT_TRUE(snap.NvencFramesSubmitted == 5ULL);
        ASSERT_TRUE(snap.NvencFramesEncoded == 5ULL);
        ASSERT_TRUE(snap.NvencKeyFramesEncoded >= 1ULL);
        ASSERT_TRUE(snap.EncodedQueueDepth == 5ULL);
        ASSERT_TRUE(snap.TotalBitstreamBytes > 0ULL);

        uint32_t poppedCount = 0U;
        lumabridge::host::EncodedFramePacket queuedPkt{};
        while (encoder.TryPopEncodedFrame(queuedPkt))
        {
            ++poppedCount;
        }
        ASSERT_TRUE(poppedCount == 5U);
        ASSERT_TRUE(!encoder.TryPopEncodedFrame(queuedPkt));

        encoder.Shutdown();
        ASSERT_TRUE(!encoder.IsInitialized());
    }

    std::printf("[PASS] %s\n", kTestName);
    return true;
}

bool
TestNvencDirectArgbAndGpuVideoProcessorNv12Conversion()
{
    static constexpr const char* kTestName = "NvencDirectArgbAndGpuVideoProcessorNv12Conversion";

    ComPtr<ID3D11Device> device;
    ComPtr<ID3D11DeviceContext> context;
    ASSERT_TRUE(SUCCEEDED(CreateNvidiaHardwareD3d11Device(device, context)));
    const uint64_t qpcFreq = QueryQpcFreq();

    const lumabridge::host::NvencColorConversionMode modes[] = {
        lumabridge::host::NvencColorConversionMode::DirectArgb,
        lumabridge::host::NvencColorConversionMode::GpuVideoProcessorNv12,
    };

    for (const auto mode : modes)
    {
        lumabridge::host::NvencEncoderConfig cfg{};
        cfg.Width = 1280U;
        cfg.Height = 720U;
        cfg.TargetFps = 60U;
        cfg.BitrateBps = 15000000U;
        cfg.MaxBitrateBps = 20000000U;
        cfg.GopLength = 60U;
        cfg.LowLatencyTuning = true;
        cfg.RepeatSpsPpsEveryIdr = true;
        cfg.ColorMode = mode;

        lumabridge::host::NvencH264Encoder encoder;
        ASSERT_TRUE(SUCCEEDED(encoder.Initialize(device.Get(), context.Get(), cfg)));

        lumabridge::host::H264StreamValidationSession validator;
        validator.Configure(true, 60U, false, 25.0);

        for (uint32_t i = 1U; i <= 4U; ++i)
        {
            ComPtr<ID3D11Texture2D> tex;
            ASSERT_TRUE(SUCCEEDED(CreateSyntheticGpuTexture(
                device.Get(),
                1280U,
                720U,
                i,
                DXGI_FORMAT_B8G8R8A8_UNORM,
                tex)));

            const uint64_t qpc = QueryQpcNow();
            lumabridge::host::EncodedFramePacket pkt{};
            ASSERT_TRUE(SUCCEEDED(encoder.EncodeGpuTexture(tex.Get(), i, i, qpc, qpc, qpcFreq, &pkt)));
            validator.SubmitPacket(pkt);
        }

        validator.Finish();
        const auto valSnap = validator.GetSummary();
        const auto encSnap = encoder.GetMetricsSnapshot();
        ASSERT_TRUE(encSnap.NvencFramesEncoded == 4ULL);
        ASSERT_TRUE(valSnap.Passed);
        ASSERT_TRUE(valSnap.FramesDecoded == 4ULL);
        if (mode == lumabridge::host::NvencColorConversionMode::GpuVideoProcessorNv12)
        {
            ASSERT_TRUE(encSnap.Capabilities.SelectedInputFormatName == "NV12");
        }
        else if (encSnap.Capabilities.SupportsArgbInput)
        {
            ASSERT_TRUE(encSnap.Capabilities.SelectedInputFormatName == "ARGB");
        }

        std::printf(
            "[INFO] %s: colorMode=%u selectedFmt=%s framesDecoded=%llu encAvgUs=%llu\n",
            kTestName,
            static_cast<uint32_t>(mode),
            encSnap.Capabilities.SelectedInputFormatName.c_str(),
            static_cast<unsigned long long>(valSnap.FramesDecoded),
            static_cast<unsigned long long>(encSnap.EncodeLatencyUs.AvgUs));

        validator.Shutdown();
        encoder.Shutdown();
    }

    std::printf("[PASS] %s\n", kTestName);
    return true;
}

bool
TestNvencIncompatibleDxgiFormatRejectedCleanly()
{
    static constexpr const char* kTestName = "NvencIncompatibleDxgiFormatRejectedCleanly";

    ComPtr<ID3D11Device> device;
    ComPtr<ID3D11DeviceContext> context;
    ASSERT_TRUE(SUCCEEDED(CreateNvidiaHardwareD3d11Device(device, context)));
    const uint64_t qpcFreq = QueryQpcFreq();

    lumabridge::host::NvencEncoderConfig cfg{};
    cfg.Width = 1280U;
    cfg.Height = 720U;
    cfg.TargetFps = 60U;
    cfg.BitrateBps = 12000000U;
    cfg.GopLength = 30U;

    lumabridge::host::NvencH264Encoder encoder;
    ASSERT_TRUE(SUCCEEDED(encoder.Initialize(device.Get(), context.Get(), cfg)));

    D3D11_TEXTURE2D_DESC badDesc{};
    badDesc.Width = 1280U;
    badDesc.Height = 720U;
    badDesc.MipLevels = 1U;
    badDesc.ArraySize = 1U;
    badDesc.Format = DXGI_FORMAT_R16G16B16A16_FLOAT;
    badDesc.SampleDesc.Count = 1U;
    badDesc.Usage = D3D11_USAGE_DEFAULT;
    badDesc.BindFlags = D3D11_BIND_RENDER_TARGET | D3D11_BIND_SHADER_RESOURCE;

    ComPtr<ID3D11Texture2D> badTex;
    ASSERT_TRUE(SUCCEEDED(device->CreateTexture2D(&badDesc, nullptr, &badTex)));

    const uint64_t qpc = QueryQpcNow();
    const HRESULT badHr = encoder.EncodeGpuTexture(badTex.Get(), 1ULL, 1U, qpc, qpc, qpcFreq, nullptr);
    ASSERT_TRUE(FAILED(badHr));
    ASSERT_TRUE(badHr == DXGI_ERROR_UNSUPPORTED);
    ASSERT_TRUE(encoder.GetMetricsSnapshot().NvencFramesEncoded == 0ULL);

    // Ensure session stayed completely usable for subsequent valid BGRA8 input.
    ComPtr<ID3D11Texture2D> validTex;
    ASSERT_TRUE(SUCCEEDED(CreateSyntheticGpuTexture(
        device.Get(),
        1280U,
        720U,
        1U,
        DXGI_FORMAT_B8G8R8A8_UNORM,
        validTex)));
    lumabridge::host::EncodedFramePacket pkt{};
    ASSERT_TRUE(SUCCEEDED(encoder.EncodeGpuTexture(validTex.Get(), 2ULL, 1U, qpc, qpc, qpcFreq, &pkt)));
    ASSERT_TRUE(!pkt.Bitstream.empty());
    ASSERT_TRUE(encoder.GetMetricsSnapshot().NvencFramesEncoded == 1ULL);

    encoder.Shutdown();
    std::printf("[PASS] %s\n", kTestName);
    return true;
}

bool
TestNvencPeriodicIdrAndExplicitForceKeyframeRequest()
{
    static constexpr const char* kTestName = "NvencPeriodicIdrAndExplicitForceKeyframeRequest";

    ComPtr<ID3D11Device> device;
    ComPtr<ID3D11DeviceContext> context;
    ASSERT_TRUE(SUCCEEDED(CreateNvidiaHardwareD3d11Device(device, context)));
    const uint64_t qpcFreq = QueryQpcFreq();

    lumabridge::host::NvencEncoderConfig cfg{};
    cfg.Width = 1280U;
    cfg.Height = 720U;
    cfg.TargetFps = 60U;
    cfg.BitrateBps = 15000000U;
    cfg.GopLength = 4U;
    cfg.RepeatSpsPpsEveryIdr = true;

    lumabridge::host::NvencH264Encoder encoder;
    ASSERT_TRUE(SUCCEEDED(encoder.Initialize(device.Get(), context.Get(), cfg)));

    bool sawForcedIdr = false;
    bool sawNonKeyFrame = false;
    bool sawPeriodicIdr = false;

    for (uint32_t i = 1U; i <= 8U; ++i)
    {
        if (i == 3U)
        {
            encoder.RequestForceIdrOnNextFrame();
        }

        ComPtr<ID3D11Texture2D> tex;
        ASSERT_TRUE(SUCCEEDED(CreateSyntheticGpuTexture(
            device.Get(),
            1280U,
            720U,
            i,
            DXGI_FORMAT_B8G8R8A8_UNORM,
            tex)));

        const uint64_t qpc = QueryQpcNow();
        lumabridge::host::EncodedFramePacket pkt{};
        ASSERT_TRUE(SUCCEEDED(encoder.EncodeGpuTexture(tex.Get(), i, i, qpc, qpc, qpcFreq, &pkt)));

        lumabridge::host::H264NalSummary nal{};
        ASSERT_TRUE(lumabridge::host::InspectH264AnnexBNals(
            pkt.Bitstream.data(),
            pkt.Bitstream.size(),
            nal));

        if (i == 1U)
        {
            ASSERT_TRUE(pkt.IsKeyFrame && nal.SpsCount >= 1U && nal.PpsCount >= 1U && nal.IdrSliceCount >= 1U);
        }
        else if (i == 2U)
        {
            ASSERT_TRUE(!pkt.IsKeyFrame && nal.NonIdrSliceCount >= 1U);
            sawNonKeyFrame = true;
        }
        else if (i == 3U)
        {
            ASSERT_TRUE(pkt.IsKeyFrame && nal.SpsCount >= 1U && nal.PpsCount >= 1U && nal.IdrSliceCount >= 1U);
            sawForcedIdr = true;
        }
        else if (i > 3U && pkt.IsKeyFrame && nal.IdrSliceCount >= 1U)
        {
            ASSERT_TRUE(nal.SpsCount >= 1U && nal.PpsCount >= 1U);
            sawPeriodicIdr = true;
        }
    }

    ASSERT_TRUE(sawNonKeyFrame);
    ASSERT_TRUE(sawForcedIdr);
    ASSERT_TRUE(sawPeriodicIdr);
    ASSERT_TRUE(encoder.GetMetricsSnapshot().NvencKeyFramesEncoded >= 3ULL);

    encoder.Shutdown();
    std::printf("[PASS] %s\n", kTestName);
    return true;
}

bool
TestNvencEncoderBusyDeviceRemovedAndSessionReconstruction()
{
    static constexpr const char* kTestName = "NvencEncoderBusyDeviceRemovedAndSessionReconstruction";

    ComPtr<ID3D11Device> device1;
    ComPtr<ID3D11DeviceContext> context1;
    ASSERT_TRUE(SUCCEEDED(CreateNvidiaHardwareD3d11Device(device1, context1)));
    const uint64_t qpcFreq = QueryQpcFreq();

    lumabridge::host::NvencEncoderConfig cfg{};
    cfg.Width = 1280U;
    cfg.Height = 720U;
    cfg.TargetFps = 60U;
    cfg.BitrateBps = 12000000U;
    cfg.GopLength = 60U;

    FaultInjectingNvencHooks hooks;
    hooks.BusyOnFrameSequence = 2ULL;

    lumabridge::host::NvencH264Encoder encoder;
    encoder.SetHooks(&hooks);
    ASSERT_TRUE(SUCCEEDED(encoder.Initialize(device1.Get(), context1.Get(), cfg)));

    // Frame 1 succeeds.
    ComPtr<ID3D11Texture2D> tex1;
    ASSERT_TRUE(SUCCEEDED(CreateSyntheticGpuTexture(device1.Get(), 1280U, 720U, 1U, DXGI_FORMAT_B8G8R8A8_UNORM, tex1)));
    const uint64_t qpc1 = QueryQpcNow();
    ASSERT_TRUE(SUCCEEDED(encoder.EncodeGpuTexture(tex1.Get(), 1ULL, 1U, qpc1, qpc1, qpcFreq, nullptr)));

    // Frame 2 returns injected NV_ENC_ERR_ENCODER_BUSY.
    const HRESULT busyHr = encoder.EncodeGpuTexture(tex1.Get(), 2ULL, 2U, qpc1, qpc1, qpcFreq, nullptr);
    ASSERT_TRUE(busyHr == HRESULT_FROM_WIN32(ERROR_BUSY));
    ASSERT_TRUE(hooks.BusyInjections == 1U);
    ASSERT_TRUE(encoder.GetMetricsSnapshot().NvencDroppedFrames == 1ULL);
    ASSERT_TRUE(encoder.GetMetricsSnapshot().LastNvencStatus == NV_ENC_ERR_ENCODER_BUSY);

    // Frame 3 recovers cleanly on the existing session.
    ASSERT_TRUE(SUCCEEDED(encoder.EncodeGpuTexture(tex1.Get(), 3ULL, 3U, qpc1, qpc1, qpcFreq, nullptr)));
    ASSERT_TRUE(encoder.GetMetricsSnapshot().NvencFramesEncoded == 2ULL);

    // Frame 4 injects device removed during GPU prepare.
    hooks.TriggerDeviceRemovedOnPrepare = true;
    const HRESULT removedHr = encoder.EncodeGpuTexture(tex1.Get(), 4ULL, 4U, qpc1, qpc1, qpcFreq, nullptr);
    ASSERT_TRUE(removedHr == DXGI_ERROR_DEVICE_REMOVED);
    ASSERT_TRUE(hooks.PrepareFailures == 1U);
    ASSERT_TRUE(encoder.GetMetricsSnapshot().DeviceRemovedOrReset);

    // Clear fault, spin up fresh D3D11 device + context, and reconstruct session.
    hooks.TriggerDeviceRemovedOnPrepare = false;
    ComPtr<ID3D11Device> device2;
    ComPtr<ID3D11DeviceContext> context2;
    ASSERT_TRUE(SUCCEEDED(CreateNvidiaHardwareD3d11Device(device2, context2)));

    ASSERT_TRUE(SUCCEEDED(encoder.ReconstructSession(device2.Get(), context2.Get(), nullptr)));
    ASSERT_TRUE(!encoder.GetMetricsSnapshot().DeviceRemovedOrReset);
    ASSERT_TRUE(encoder.GetMetricsSnapshot().NvencEncoderResets == 1ULL);

    ComPtr<ID3D11Texture2D> tex2;
    ASSERT_TRUE(SUCCEEDED(CreateSyntheticGpuTexture(device2.Get(), 1280U, 720U, 5U, DXGI_FORMAT_B8G8R8A8_UNORM, tex2)));
    lumabridge::host::EncodedFramePacket pkt5{};
    ASSERT_TRUE(SUCCEEDED(encoder.EncodeGpuTexture(tex2.Get(), 5ULL, 5U, qpc1, qpc1, qpcFreq, &pkt5)));
    ASSERT_TRUE(pkt5.IsKeyFrame);
    ASSERT_TRUE(encoder.GetMetricsSnapshot().NvencFramesEncoded == 3ULL);

    encoder.SetHooks(nullptr);
    encoder.Shutdown();
    std::printf("[PASS] %s\n", kTestName);
    return true;
}

bool
TestNvencH264IndependentMediaFoundationDecodeAndPsnrValidation()
{
    static constexpr const char* kTestName = "NvencH264IndependentMediaFoundationDecodeAndPsnrValidation";

    ComPtr<ID3D11Device> device;
    ComPtr<ID3D11DeviceContext> context;
    ASSERT_TRUE(SUCCEEDED(CreateNvidiaHardwareD3d11Device(device, context)));
    const uint64_t qpcFreq = QueryQpcFreq();

    lumabridge::host::NvencEncoderConfig cfg{};
    cfg.Width = 1280U;
    cfg.Height = 720U;
    cfg.TargetFps = 60U;
    cfg.BitrateBps = 25000000U;
    cfg.MaxBitrateBps = 35000000U;
    cfg.GopLength = 8U;
    cfg.LowLatencyTuning = true;
    cfg.RepeatSpsPpsEveryIdr = true;
    cfg.ColorMode = lumabridge::host::NvencColorConversionMode::Auto;

    lumabridge::host::NvencH264Encoder encoder;
    ASSERT_TRUE(SUCCEEDED(encoder.Initialize(device.Get(), context.Get(), cfg)));

    lumabridge::host::H264StreamValidationSession validator;
    validator.Configure(true, 60U, true, 25.0);

    for (uint32_t i = 1U; i <= 8U; ++i)
    {
        ComPtr<ID3D11Texture2D> tex;
        ASSERT_TRUE(SUCCEEDED(CreateSyntheticGpuTexture(
            device.Get(),
            1280U,
            720U,
            i,
            DXGI_FORMAT_B8G8R8A8_UNORM,
            tex)));

        const uint64_t qpc = QueryQpcNow();
        lumabridge::host::EncodedFramePacket pkt{};
        ASSERT_TRUE(SUCCEEDED(encoder.EncodeGpuTexture(tex.Get(), i, i, qpc, qpc, qpcFreq, &pkt)));
        validator.SubmitPacket(pkt);
    }

    validator.Finish();
    const auto valSnap = validator.GetSummary();

    std::printf(
        "[INFO] %s: decoder=\"%s\" packets=%llu decoded=%llu nalErr=%llu decErr=%llu "
        "psnrPass=%llu psnrFail=%llu minY=%.2fdB avgY=%.2fdB minUv=%.2fdB avgUv=%.2fdB\n",
        kTestName,
        valSnap.DecoderName.c_str(),
        static_cast<unsigned long long>(valSnap.PacketsInspected),
        static_cast<unsigned long long>(valSnap.FramesDecoded),
        static_cast<unsigned long long>(valSnap.NalParseFailures),
        static_cast<unsigned long long>(valSnap.DecodeFailures),
        static_cast<unsigned long long>(valSnap.PsnrPassCount),
        static_cast<unsigned long long>(valSnap.PsnrFailCount),
        valSnap.MinYPsnrDb,
        valSnap.AvgYPsnrDb,
        valSnap.MinUvPsnrDb,
        valSnap.AvgUvPsnrDb);

    ASSERT_TRUE(valSnap.DecoderInitialized);
    ASSERT_TRUE(valSnap.PacketsInspected == 8ULL);
    ASSERT_TRUE(valSnap.FramesDecoded == 8ULL);
    ASSERT_TRUE(valSnap.NalParseFailures == 0ULL);
    ASSERT_TRUE(valSnap.DecodeFailures == 0ULL);
    ASSERT_TRUE(valSnap.PsnrPassCount == 8ULL);
    ASSERT_TRUE(valSnap.PsnrFailCount == 0ULL);
    ASSERT_TRUE(valSnap.Passed);

    validator.Shutdown();
    encoder.Shutdown();
    std::printf("[PASS] %s\n", kTestName);
    return true;
}

bool
TestNvencTimestampCoverageValidationAndStageBreakdown()
{
    static constexpr const char* kTestName = "NvencTimestampCoverageValidationAndStageBreakdown";

    ComPtr<ID3D11Device> device;
    ComPtr<ID3D11DeviceContext> context;
    ASSERT_TRUE(SUCCEEDED(CreateNvidiaHardwareD3d11Device(device, context)));
    const uint64_t qpcFreq = QueryQpcFreq();

    lumabridge::host::NvencEncoderConfig cfg{};
    cfg.Width = 1280U;
    cfg.Height = 720U;
    cfg.TargetFps = 60U;
    cfg.BitrateBps = 15000000U;
    cfg.GopLength = 60U;
    cfg.LowLatencyTuning = true;
    cfg.RepeatSpsPpsEveryIdr = true;

    lumabridge::host::NvencH264Encoder encoder;
    // Empty encoder metrics must report Available == false rather than 0 us fake latency.
    {
        const auto emptySnap = encoder.GetMetricsSnapshot();
        ASSERT_TRUE(!emptySnap.EncodeLatencyUs.Available);
        ASSERT_TRUE(!emptySnap.PresentToBitstreamLatencyUs.Available);
        ASSERT_TRUE(!emptySnap.ExtractToBitstreamLatencyUs.Available);
        ASSERT_TRUE(emptySnap.PresentToBitstreamCoveragePercent == 0.0);
        ASSERT_TRUE(emptySnap.ExtractToBitstreamCoveragePercent == 0.0);
    }

    ASSERT_TRUE(SUCCEEDED(encoder.Initialize(device.Get(), context.Get(), cfg)));
    const auto initSnap = encoder.GetMetricsSnapshot();
    ASSERT_TRUE(initSnap.SessionInitializeLatencyUs > 0ULL && initSnap.SessionInitializeLatencyUs < 10000000ULL);

    ComPtr<ID3D11Texture2D> tex;
    ASSERT_TRUE(SUCCEEDED(CreateSyntheticGpuTexture(
        device.Get(),
        1280U,
        720U,
        1U,
        DXGI_FORMAT_B8G8R8A8_UNORM,
        tex)));

    // Frame 1: Fully valid present, extract, hostReceive QPCs.
    const uint64_t recv1 = QueryQpcNow();
    Sleep(1U);
    ASSERT_TRUE(SUCCEEDED(encoder.EncodeGpuTexture(tex.Get(), 1ULL, 1U, recv1, recv1, qpcFreq, nullptr, recv1)));

    // Frame 2: Missing optional PresentDisplayQpcTime (0), valid extract + hostReceive QPCs.
    const uint64_t recv2 = QueryQpcNow();
    ASSERT_TRUE(SUCCEEDED(encoder.EncodeGpuTexture(tex.Get(), 2ULL, 2U, 0ULL, recv2, qpcFreq, nullptr, recv2)));

    // Frame 3: Future timestamps (1 second ahead) -> must be rejected as InvalidTimestampCount, not recorded as 0 us!
    const uint64_t recv3 = QueryQpcNow();
    const uint64_t futureQpc = recv3 + qpcFreq;
    ASSERT_TRUE(SUCCEEDED(encoder.EncodeGpuTexture(tex.Get(), 3ULL, 3U, futureQpc, futureQpc, qpcFreq, nullptr, recv3)));

    // Frame 4: Incompatible QPC frequency -> must increment InvalidTimestampCount, not record corrupted deltas.
    const uint64_t recv4 = QueryQpcNow();
    ASSERT_TRUE(SUCCEEDED(encoder.EncodeGpuTexture(tex.Get(), 4ULL, 4U, recv4, recv4, qpcFreq + 12345ULL, nullptr, recv4)));

    // Pop 2 queued frames after brief wait to exercise EncodedQueueWaitLatencyUs.
    Sleep(2U);
    lumabridge::host::EncodedFramePacket popped{};
    uint32_t popCount = 0U;
    while (encoder.TryPopEncodedFrame(popped))
    {
        ++popCount;
    }
    ASSERT_TRUE(popCount == 4U);

    const auto snap = encoder.GetMetricsSnapshot();
    ASSERT_TRUE(snap.NvencFramesEncoded == 4ULL);
    ASSERT_TRUE(snap.MissingPresentTimestampCount == 1ULL);
    ASSERT_TRUE(snap.MissingExtractTimestampCount == 0ULL);
    // Frame 3 future present + future extract (2), Frame 4 incompatible units on hostRecv+present+extract (3) => 5.
    ASSERT_TRUE(snap.InvalidTimestampCount >= 4ULL);
    ASSERT_TRUE(snap.ValidPresentToBitstreamSamples == 1ULL);
    ASSERT_TRUE(snap.ValidExtractToBitstreamSamples == 2ULL);
    ASSERT_TRUE(snap.PresentToBitstreamCoveragePercent > 24.0 && snap.PresentToBitstreamCoveragePercent < 26.0);
    ASSERT_TRUE(snap.ExtractToBitstreamCoveragePercent > 49.0 && snap.ExtractToBitstreamCoveragePercent < 51.0);
    ASSERT_TRUE(snap.EncodeLatencyUs.Available && snap.EncodeLatencyUs.SampleCount == 4ULL);
    ASSERT_TRUE(snap.FormatPrepareLatencyUs.Available && snap.FormatPrepareLatencyUs.SampleCount == 4ULL);
    ASSERT_TRUE(snap.EncodePictureLatencyUs.Available && snap.EncodePictureLatencyUs.SampleCount == 4ULL);
    ASSERT_TRUE(snap.BitstreamLockCopyLatencyUs.Available && snap.BitstreamLockCopyLatencyUs.SampleCount == 4ULL);
    ASSERT_TRUE(snap.HostReceiveToSubmitLatencyUs.Available && snap.HostReceiveToSubmitLatencyUs.SampleCount == 3ULL);
    ASSERT_TRUE(snap.EncodedQueueWaitLatencyUs.Available && snap.EncodedQueueWaitLatencyUs.SampleCount == 4ULL);
    ASSERT_TRUE(snap.EncodeInterFrameJitterUs.Available && snap.EncodeInterFrameJitterUs.SampleCount >= 2ULL);

    encoder.Shutdown();
    std::printf("[PASS] %s\n", kTestName);
    return true;
}

} // namespace

int
main()
{
    int executed = 0;
    int passed = 0;

    auto run = [&](bool (*fn)()) {
        ++executed;
        if (fn())
        {
            ++passed;
        }
    };

    run(TestNvencRuntimeDetectionAndCapabilityQueryOnRtx3060Ti);
    run(TestNvencSessionInitEncodeAndCleanDestroy720pAnd1080p);
    run(TestNvencDirectArgbAndGpuVideoProcessorNv12Conversion);
    run(TestNvencIncompatibleDxgiFormatRejectedCleanly);
    run(TestNvencPeriodicIdrAndExplicitForceKeyframeRequest);
    run(TestNvencEncoderBusyDeviceRemovedAndSessionReconstruction);
    run(TestNvencH264IndependentMediaFoundationDecodeAndPsnrValidation);
    run(TestNvencTimestampCoverageValidationAndStageBreakdown);

    std::printf("NvencEncoderTests: %d/%d passed (%d failures)\n", passed, executed, g_failures);
    return (g_failures == 0 && passed == executed) ? EXIT_SUCCESS : EXIT_FAILURE;
}
