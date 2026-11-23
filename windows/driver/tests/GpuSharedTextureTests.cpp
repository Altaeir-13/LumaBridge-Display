#include "../LumaBridgeIddDriver/SharedTexturePool.h"
#include "../LumaBridgeIddDriver/FrameIpcProtocol.h"
#include "../LumaBridgeIddDriver/FrameTransport.h"
#include "../../host/FrameConsumer.h"

#include <d3d11_1.h>
#include <dxgi1_4.h>
#include <wrl/client.h>

#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

using Microsoft::WRL::ComPtr;
using namespace lumabridge::driver;
using namespace lumabridge::ipc;
using namespace lumabridge::host;

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
CreateRealD3d11Device1(
    ComPtr<ID3D11Device>& outDevice,
    ComPtr<ID3D11Device1>& outDevice1,
    ComPtr<ID3D11DeviceContext>& outContext,
    LUID& outAdapterLuid,
    const char*& outKind
    ) noexcept
{
    outDevice.Reset();
    outDevice1.Reset();
    outContext.Reset();
    outAdapterLuid = LUID{0, 0};
    outKind = "None";

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
    if (SUCCEEDED(hr) && outDevice != nullptr)
    {
        outKind = "Hardware";
    }
    else
    {
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
        if (SUCCEEDED(hr) && outDevice != nullptr)
        {
            outKind = "WARP";
        }
    }

    if (FAILED(hr) || outDevice == nullptr || outContext == nullptr)
    {
        return false;
    }

    if (FAILED(outDevice.As(&outDevice1)) || outDevice1 == nullptr)
    {
        return false;
    }

    ComPtr<IDXGIDevice> dxgiDev;
    ComPtr<IDXGIAdapter> adapter;
    if (SUCCEEDED(outDevice.As(&dxgiDev)) &&
        dxgiDev != nullptr &&
        SUCCEEDED(dxgiDev->GetAdapter(&adapter)) &&
        adapter != nullptr)
    {
        DXGI_ADAPTER_DESC desc{};
        if (SUCCEEDED(adapter->GetDesc(&desc)))
        {
            outAdapterLuid = desc.AdapterLuid;
        }
    }

    return true;
}

bool
CreateDeviceMatchingLuid(
    LUID targetLuid,
    ComPtr<ID3D11Device1>& outDevice1,
    ComPtr<ID3D11DeviceContext>& outContext
    ) noexcept
{
    outDevice1.Reset();
    outContext.Reset();

    ComPtr<IDXGIFactory4> factory;
    if (FAILED(CreateDXGIFactory1(IID_PPV_ARGS(&factory))) || factory == nullptr)
    {
        return false;
    }

    ComPtr<IDXGIAdapter1> adapter;
    if (FAILED(factory->EnumAdapterByLuid(targetLuid, IID_PPV_ARGS(&adapter))) || adapter == nullptr)
    {
        return false;
    }

    static constexpr D3D_FEATURE_LEVEL kLevels[] = {
        D3D_FEATURE_LEVEL_11_1,
        D3D_FEATURE_LEVEL_11_0,
        D3D_FEATURE_LEVEL_10_1,
        D3D_FEATURE_LEVEL_10_0};
    D3D_FEATURE_LEVEL selected = D3D_FEATURE_LEVEL_11_0;
    ComPtr<ID3D11Device> dev;
    if (FAILED(D3D11CreateDevice(
            adapter.Get(),
            D3D_DRIVER_TYPE_UNKNOWN,
            nullptr,
            D3D11_CREATE_DEVICE_BGRA_SUPPORT,
            kLevels,
            ARRAYSIZE(kLevels),
            D3D11_SDK_VERSION,
            &dev,
            &selected,
            &outContext)) ||
        dev == nullptr)
    {
        return false;
    }

    return SUCCEEDED(dev.As(&outDevice1)) && outDevice1 != nullptr;
}

bool
CreateSyntheticBgra8SourceTexture(
    ID3D11Device* device,
    uint32_t width,
    uint32_t height,
    uint32_t frameNumber,
    ComPtr<ID3D11Texture2D>& outTexture,
    DXGI_FORMAT format = DXGI_FORMAT_B8G8R8A8_UNORM,
    UINT miscFlags = 0U
    )
{
    outTexture.Reset();
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
    desc.Format = format;
    desc.SampleDesc.Count = 1U;
    desc.Usage = D3D11_USAGE_DEFAULT;
    desc.BindFlags = D3D11_BIND_SHADER_RESOURCE;
    desc.MiscFlags = miscFlags;

    D3D11_SUBRESOURCE_DATA init{};
    init.pSysMem = pixels.data();
    init.SysMemPitch = rowPitch;

    return SUCCEEDED(device->CreateTexture2D(&desc, &init, &outTexture)) && outTexture != nullptr;
}

bool
ReadBackTextureAndVerifySyntheticPattern(
    ID3D11Device* device,
    ID3D11DeviceContext* context,
    ID3D11Texture2D* tex,
    uint32_t frameNumber,
    uint32_t width,
    uint32_t height
    )
{
    D3D11_TEXTURE2D_DESC srcDesc{};
    tex->GetDesc(&srcDesc);

    D3D11_TEXTURE2D_DESC stDesc{};
    stDesc.Width = width;
    stDesc.Height = height;
    stDesc.MipLevels = 1U;
    stDesc.ArraySize = 1U;
    stDesc.Format = srcDesc.Format;
    stDesc.SampleDesc.Count = 1U;
    stDesc.Usage = D3D11_USAGE_STAGING;
    stDesc.CPUAccessFlags = D3D11_CPU_ACCESS_READ;

    ComPtr<ID3D11Texture2D> staging;
    if (FAILED(device->CreateTexture2D(&stDesc, nullptr, &staging)) || staging == nullptr)
    {
        return false;
    }

    context->CopyResource(staging.Get(), tex);
    D3D11_MAPPED_SUBRESOURCE mapped{};
    if (FAILED(context->Map(staging.Get(), 0U, D3D11_MAP_READ, 0U, &mapped)) || mapped.pData == nullptr)
    {
        return false;
    }

    uint32_t pitch = 0U;
    uint32_t bytes = 0U;
    bool ok = ComputeTightRowPitchBytes(width, pitch) &&
              ComputeValidatedFramePayloadBytes(width, height, pitch, bytes) &&
              mapped.RowPitch >= pitch;
    std::vector<uint8_t> packed;
    if (ok)
    {
        packed.resize(bytes);
        const uint8_t* srcBytes = static_cast<const uint8_t*>(mapped.pData);
        for (uint32_t y = 0U; y < height; ++y)
        {
            std::memcpy(
                packed.data() + static_cast<size_t>(y) * pitch,
                srcBytes + static_cast<size_t>(y) * mapped.RowPitch,
                pitch);
        }
        ok = VerifySyntheticTestPatternBgra8(frameNumber, width, height, packed.data(), packed.size());
    }
    context->Unmap(staging.Get(), 0U);
    return ok;
}

class FaultSharedTextureHooks final : public ID3d11SharedTextureHooks
{
public:
    HRESULT FailAcquireHr{S_OK};
    HRESULT FailReleaseHr{S_OK};
    HRESULT FailCreateHandleHr{S_OK};
    HRESULT FailCopyHr{S_OK};
    bool FailFirstAcquireOnly{false};
    uint32_t AcquireCalls{0U};

    HRESULT CreateSharedNtHandle(
        ID3D11Texture2D* texture,
        const SECURITY_ATTRIBUTES* securityAttributes,
        DWORD accessMask,
        HANDLE* outHandle
        ) noexcept override
    {
        if (FAILED(FailCreateHandleHr))
        {
            if (outHandle != nullptr)
            {
                *outHandle = nullptr;
            }
            return FailCreateHandleHr;
        }
        return ID3d11SharedTextureHooks::CreateSharedNtHandle(texture, securityAttributes, accessMask, outHandle);
    }

    HRESULT AcquireKeyedMutex(
        IDXGIKeyedMutex* keyedMutex,
        UINT64 key,
        DWORD timeoutMs
        ) noexcept override
    {
        ++AcquireCalls;
        if (FailAcquireHr != S_OK)
        {
            if (!FailFirstAcquireOnly || AcquireCalls == 1U)
            {
                return FailAcquireHr;
            }
        }
        return ID3d11SharedTextureHooks::AcquireKeyedMutex(keyedMutex, key, timeoutMs);
    }

    HRESULT ReleaseKeyedMutex(
        IDXGIKeyedMutex* keyedMutex,
        UINT64 key
        ) noexcept override
    {
        if (FAILED(FailReleaseHr))
        {
            return FailReleaseHr;
        }
        return ID3d11SharedTextureHooks::ReleaseKeyedMutex(keyedMutex, key);
    }

    HRESULT CopyTextureResource(
        ID3D11DeviceContext* context,
        ID3D11Texture2D* dstSharedTexture,
        ID3D11Texture2D* srcTexture
        ) noexcept override
    {
        if (FAILED(FailCopyHr))
        {
            return FailCopyHr;
        }
        return ID3d11SharedTextureHooks::CopyTextureResource(context, dstSharedTexture, srcTexture);
    }
};

void
TestSharedTexturePoolCreationAndReuse720pAnd1080p()
{
    ComPtr<ID3D11Device> prodDev;
    ComPtr<ID3D11Device1> prodDev1;
    ComPtr<ID3D11DeviceContext> prodCtx;
    LUID adapterLuid{0, 0};
    const char* kind = nullptr;
    EXPECT_TRUE(CreateRealD3d11Device1(prodDev, prodDev1, prodCtx, adapterLuid, kind));

    ComPtr<ID3D11Device1> consDev1;
    ComPtr<ID3D11DeviceContext> consCtx;
    EXPECT_TRUE(CreateDeviceMatchingLuid(adapterLuid, consDev1, consCtx));

    D3d11SharedTexturePool pool;
    EXPECT_EQ(pool.Configure(3U), S_OK);
    pool.SetDevice(prodDev.Get(), prodCtx.Get(), adapterLuid);

    // Extract 6 frames at 720p cycling through the 3-slot pool, then switch to 1080p.
    ComPtr<IDXGIKeyedMutex> slot0ConsumerMutex;
    uint32_t openedGen = 0U;
    for (uint32_t i = 1U; i <= 6U; ++i)
    {
        ComPtr<ID3D11Texture2D> src;
        EXPECT_TRUE(CreateSyntheticBgra8SourceTexture(prodDev.Get(), 1280U, 720U, i, src));

        ExtractedFrameBuffer meta{};
        FrameExtractionInput in{};
        in.AdoptSourceTexture = src.Detach();
        in.PresentationFrameNumber = i;
        const SharedTextureExtractResult res = pool.ExtractToSharedTexture(in, meta, true);
        EXPECT_EQ(res.HResult, S_OK);
        EXPECT_TRUE(res.GpuCopied);
        EXPECT_TRUE(meta.IsGpuSharedFrame);
        EXPECT_EQ(meta.Pixels.capacity(), 0ULL); // Zero CPU pixel allocation!

        HANDLE ntHandle = nullptr;
        LUID slotLuid{0, 0};
        EXPECT_TRUE(pool.BeginHostUseForSlot(res.SlotIndex, res.SlotGeneration, ntHandle, slotLuid));
        EXPECT_TRUE(ntHandle != nullptr && ntHandle != INVALID_HANDLE_VALUE);

        if (openedGen != res.SlotGeneration)
        {
            slot0ConsumerMutex.Reset();
            ComPtr<ID3D11Texture2D> openedTex;
            EXPECT_EQ(consDev1->OpenSharedResource1(ntHandle, IID_PPV_ARGS(&openedTex)), S_OK);
            EXPECT_EQ(openedTex.As(&slot0ConsumerMutex), S_OK);
            openedGen = res.SlotGeneration;
        }
        EXPECT_EQ(slot0ConsumerMutex->AcquireSync(kSharedTextureConsumerMutexKey, 1000U), S_OK);
        EXPECT_EQ(slot0ConsumerMutex->ReleaseSync(kSharedTextureProducerMutexKey), S_OK);

        pool.CompleteHostUseForSlot(res.SlotIndex, res.SlotGeneration, true, 12U);
    }

    auto snap720 = pool.GetMetricsSnapshot();
    EXPECT_EQ(snap720.GpuFramesShared, 6ULL);
    EXPECT_EQ(snap720.GpuSyncTimeouts, 0ULL);
    std::printf(
        "[INFO] SharedTexturePool 720p reuse: GpuFramesShared=%llu GpuResourceRecreations=%llu\n",
        static_cast<unsigned long long>(snap720.GpuFramesShared),
        static_cast<unsigned long long>(snap720.GpuResourceRecreations));
    EXPECT_EQ(snap720.GpuResourceRecreations, 1ULL); // Slot 0 reused cleanly across all 6 frames!

    ComPtr<ID3D11Texture2D> src1080;
    EXPECT_TRUE(CreateSyntheticBgra8SourceTexture(prodDev.Get(), 1920U, 1080U, 77U, src1080));
    ExtractedFrameBuffer meta1080{};
    FrameExtractionInput in1080{};
    in1080.AdoptSourceTexture = src1080.Detach();
    in1080.PresentationFrameNumber = 77U;
    const SharedTextureExtractResult res1080 = pool.ExtractToSharedTexture(in1080, meta1080, true);
    EXPECT_EQ(res1080.HResult, S_OK);
    EXPECT_TRUE(res1080.SlotRecreated);
    EXPECT_EQ(res1080.Width, 1920U);
    EXPECT_EQ(res1080.Height, 1080U);
    pool.Shutdown();
}

void
TestSharedTextureKeyedMutexProducerConsumerSync()
{
    ComPtr<ID3D11Device> prodDev;
    ComPtr<ID3D11Device1> prodDev1;
    ComPtr<ID3D11DeviceContext> prodCtx;
    LUID adapterLuid{0, 0};
    const char* kind = nullptr;
    EXPECT_TRUE(CreateRealD3d11Device1(prodDev, prodDev1, prodCtx, adapterLuid, kind));

    ComPtr<ID3D11Device1> consDev1;
    ComPtr<ID3D11DeviceContext> consCtx;
    EXPECT_TRUE(CreateDeviceMatchingLuid(adapterLuid, consDev1, consCtx));
    ComPtr<ID3D11Device> consDev;
    EXPECT_EQ(consDev1.As(&consDev), S_OK);

    D3d11SharedTexturePool pool;
    EXPECT_EQ(pool.Configure(2U), S_OK);
    pool.SetDevice(prodDev.Get(), prodCtx.Get(), adapterLuid);

    for (uint32_t f = 1U; f <= 4U; ++f)
    {
        ComPtr<ID3D11Texture2D> src;
        EXPECT_TRUE(CreateSyntheticBgra8SourceTexture(prodDev.Get(), 1280U, 720U, 50U + f, src));

        ExtractedFrameBuffer meta{};
        FrameExtractionInput in{};
        in.AdoptSourceTexture = src.Detach();
        in.PresentationFrameNumber = 50U + f;
        const SharedTextureExtractResult res = pool.ExtractToSharedTexture(in, meta, true);
        EXPECT_EQ(res.HResult, S_OK);

        HANDLE prodHandle = nullptr;
        LUID slotLuid{0, 0};
        EXPECT_TRUE(pool.BeginHostUseForSlot(res.SlotIndex, res.SlotGeneration, prodHandle, slotLuid));

        HANDLE dupHandle = nullptr;
        EXPECT_TRUE(DuplicateHandle(
            GetCurrentProcess(),
            prodHandle,
            GetCurrentProcess(),
            &dupHandle,
            0U,
            FALSE,
            DUPLICATE_SAME_ACCESS) != FALSE);
        ScopedWin32Handle dupGuard(dupHandle);

        ComPtr<ID3D11Texture2D> openedTex;
        EXPECT_EQ(consDev1->OpenSharedResource1(dupGuard.Get(), IID_PPV_ARGS(&openedTex)), S_OK);
        ComPtr<IDXGIKeyedMutex> consMutex;
        EXPECT_EQ(openedTex.As(&consMutex), S_OK);
        EXPECT_EQ(consMutex->AcquireSync(kSharedTextureConsumerMutexKey, 1000U), S_OK);
        EXPECT_TRUE(ReadBackTextureAndVerifySyntheticPattern(
            consDev.Get(),
            consCtx.Get(),
            openedTex.Get(),
            50U + f,
            1280U,
            720U));
        EXPECT_EQ(consMutex->ReleaseSync(kSharedTextureProducerMutexKey), S_OK);
        pool.CompleteHostUseForSlot(res.SlotIndex, res.SlotGeneration, true, 5U);
    }

    pool.Shutdown();
}

void
TestSharedTextureProtectedContentAndInvalidFormatRejected()
{
    ComPtr<ID3D11Device> prodDev;
    ComPtr<ID3D11Device1> prodDev1;
    ComPtr<ID3D11DeviceContext> prodCtx;
    LUID adapterLuid{0, 0};
    const char* kind = nullptr;
    EXPECT_TRUE(CreateRealD3d11Device1(prodDev, prodDev1, prodCtx, adapterLuid, kind));

    D3d11SharedTexturePool pool;
    EXPECT_EQ(pool.Configure(2U), S_OK);
    pool.SetDevice(prodDev.Get(), prodCtx.Get(), adapterLuid);

    // 1. Hardware-protected flag rejected immediately without touching pool slots.
    {
        ComPtr<ID3D11Texture2D> src;
        EXPECT_TRUE(CreateSyntheticBgra8SourceTexture(prodDev.Get(), 64U, 64U, 1U, src));
        ExtractedFrameBuffer meta{};
        FrameExtractionInput in{};
        in.SourceTexture = src.Get();
        in.HwProtectedSurface = true;
        const SharedTextureExtractResult res = pool.ExtractToSharedTexture(in, meta, true);
        EXPECT_EQ(res.HResult, DXGI_ERROR_ACCESS_DENIED);
        EXPECT_TRUE(res.ProtectedContentRejected);
        EXPECT_TRUE(!res.GpuCopied);
    }

    // 2. Unsupported DXGI format rejected cleanly.
    {
        D3D11_TEXTURE2D_DESC desc{};
        desc.Width = 64U;
        desc.Height = 64U;
        desc.MipLevels = 1U;
        desc.ArraySize = 1U;
        desc.Format = DXGI_FORMAT_R16G16B16A16_FLOAT;
        desc.SampleDesc.Count = 1U;
        desc.Usage = D3D11_USAGE_DEFAULT;
        desc.BindFlags = D3D11_BIND_SHADER_RESOURCE;
        ComPtr<ID3D11Texture2D> hdrTex;
        EXPECT_EQ(prodDev->CreateTexture2D(&desc, nullptr, &hdrTex), S_OK);

        ExtractedFrameBuffer meta{};
        FrameExtractionInput in{};
        in.SourceTexture = hdrTex.Get();
        const SharedTextureExtractResult res = pool.ExtractToSharedTexture(in, meta, true);
        EXPECT_EQ(res.HResult, DXGI_ERROR_UNSUPPORTED);
        EXPECT_TRUE(!res.GpuCopied);
    }

    EXPECT_EQ(pool.GetMetricsSnapshot().FreeSlots, 2U);
    pool.Shutdown();
}

void
TestSharedTexturePoolExhaustionDropsWithoutBlocking()
{
    ComPtr<ID3D11Device> prodDev;
    ComPtr<ID3D11Device1> prodDev1;
    ComPtr<ID3D11DeviceContext> prodCtx;
    LUID adapterLuid{0, 0};
    const char* kind = nullptr;
    EXPECT_TRUE(CreateRealD3d11Device1(prodDev, prodDev1, prodCtx, adapterLuid, kind));

    D3d11SharedTexturePool pool;
    EXPECT_EQ(pool.Configure(2U), S_OK);
    pool.SetDevice(prodDev.Get(), prodCtx.Get(), adapterLuid);

    uint32_t slotIdx[2]{};
    uint32_t slotGen[2]{};
    for (int i = 0; i < 2; ++i)
    {
        ComPtr<ID3D11Texture2D> src;
        EXPECT_TRUE(CreateSyntheticBgra8SourceTexture(prodDev.Get(), 64U, 64U, static_cast<uint32_t>(i + 1), src));
        ExtractedFrameBuffer meta{};
        FrameExtractionInput in{};
        in.SourceTexture = src.Get();
        const SharedTextureExtractResult res = pool.ExtractToSharedTexture(in, meta, true);
        EXPECT_EQ(res.HResult, S_OK);
        slotIdx[i] = res.SlotIndex;
        slotGen[i] = res.SlotGeneration;
        HANDLE h = nullptr;
        LUID l{};
        EXPECT_TRUE(pool.BeginHostUseForSlot(slotIdx[i], slotGen[i], h, l));
    }

    // Third attempt when both slots are InUseByHost must return non-blocking ERROR_BUSY and drop frame.
    {
        ComPtr<ID3D11Texture2D> src3;
        EXPECT_TRUE(CreateSyntheticBgra8SourceTexture(prodDev.Get(), 64U, 64U, 3U, src3));
        ExtractedFrameBuffer meta3{};
        FrameExtractionInput in3{};
        in3.SourceTexture = src3.Get();
        const SharedTextureExtractResult res3 = pool.ExtractToSharedTexture(in3, meta3, true);
        EXPECT_TRUE(res3.PoolExhausted);
        EXPECT_EQ(res3.HResult, HRESULT_FROM_WIN32(ERROR_BUSY));
        EXPECT_EQ(pool.GetMetricsSnapshot().GpuFramesDropped, 1ULL);
    }

    // Releasing slot 0 allows immediate acquisition.
    pool.CompleteHostUseForSlot(slotIdx[0], slotGen[0], true, 1U);
    {
        ComPtr<ID3D11Texture2D> src4;
        EXPECT_TRUE(CreateSyntheticBgra8SourceTexture(prodDev.Get(), 64U, 64U, 4U, src4));
        ExtractedFrameBuffer meta4{};
        FrameExtractionInput in4{};
        in4.SourceTexture = src4.Get();
        const SharedTextureExtractResult res4 = pool.ExtractToSharedTexture(in4, meta4, true);
        EXPECT_EQ(res4.HResult, S_OK);
    }
    pool.Shutdown();
}

void
TestSharedTextureSlotRetirementOnSyncTimeoutOrAbandonedClient()
{
    ComPtr<ID3D11Device> prodDev;
    ComPtr<ID3D11Device1> prodDev1;
    ComPtr<ID3D11DeviceContext> prodCtx;
    LUID adapterLuid{0, 0};
    const char* kind = nullptr;
    EXPECT_TRUE(CreateRealD3d11Device1(prodDev, prodDev1, prodCtx, adapterLuid, kind));

    D3d11SharedTexturePool pool;
    EXPECT_EQ(pool.Configure(2U), S_OK);
    pool.SetDevice(prodDev.Get(), prodCtx.Get(), adapterLuid);

    // Case A: First AcquireSync returns WAIT_TIMEOUT -> pool transparently recreates slot (generation++) and recovers!
    FaultSharedTextureHooks hooks;
    hooks.FailAcquireHr = static_cast<HRESULT>(WAIT_TIMEOUT);
    hooks.FailFirstAcquireOnly = true;
    pool.SetHooks(&hooks);

    ComPtr<ID3D11Texture2D> src;
    EXPECT_TRUE(CreateSyntheticBgra8SourceTexture(prodDev.Get(), 128U, 128U, 9U, src));
    ExtractedFrameBuffer meta{};
    FrameExtractionInput in{};
    in.SourceTexture = src.Get();
    const SharedTextureExtractResult res = pool.ExtractToSharedTexture(in, meta, true);
    EXPECT_EQ(res.HResult, S_OK);
    EXPECT_TRUE(res.SlotRecreated);
    EXPECT_EQ(pool.GetMetricsSnapshot().GpuSyncTimeouts, 1ULL);
    EXPECT_EQ(res.SlotGeneration, 2U);

    // Case B: Abandoned host use (cleanReleaseToProducer=false) forces generation increment on next use.
    HANDLE h = nullptr;
    LUID l{};
    EXPECT_TRUE(pool.BeginHostUseForSlot(res.SlotIndex, res.SlotGeneration, h, l));
    pool.CompleteHostUseForSlot(res.SlotIndex, res.SlotGeneration, false, 0U);
    EXPECT_EQ(pool.GetMetricsSnapshot().GpuFramesDropped, 1ULL);

    hooks.FailAcquireHr = S_OK;
    hooks.FailFirstAcquireOnly = false;
    ExtractedFrameBuffer meta2{};
    const SharedTextureExtractResult res2 = pool.ExtractToSharedTexture(in, meta2, true);
    EXPECT_EQ(res2.HResult, S_OK);
    EXPECT_TRUE(res2.SlotGeneration > res.SlotGeneration);

    pool.SetHooks(nullptr);
    pool.Shutdown();
}

void
TestSharedTextureDeviceRemovedAndResetRecovery()
{
    ComPtr<ID3D11Device> prodDev;
    ComPtr<ID3D11Device1> prodDev1;
    ComPtr<ID3D11DeviceContext> prodCtx;
    LUID adapterLuid{0, 0};
    const char* kind = nullptr;
    EXPECT_TRUE(CreateRealD3d11Device1(prodDev, prodDev1, prodCtx, adapterLuid, kind));

    D3d11SharedTexturePool pool;
    EXPECT_EQ(pool.Configure(2U), S_OK);
    pool.SetDevice(prodDev.Get(), prodCtx.Get(), adapterLuid);

    FaultSharedTextureHooks hooks;
    hooks.FailCopyHr = DXGI_ERROR_DEVICE_REMOVED;
    pool.SetHooks(&hooks);

    ComPtr<ID3D11Texture2D> src;
    EXPECT_TRUE(CreateSyntheticBgra8SourceTexture(prodDev.Get(), 128U, 128U, 5U, src));
    ExtractedFrameBuffer meta{};
    FrameExtractionInput in{};
    in.SourceTexture = src.Get();
    const SharedTextureExtractResult failRes = pool.ExtractToSharedTexture(in, meta, true);
    EXPECT_EQ(failRes.HResult, DXGI_ERROR_DEVICE_REMOVED);
    EXPECT_TRUE(failRes.DeviceRemovedOrReset);
    EXPECT_EQ(pool.GetMetricsSnapshot().FreeSlots, 2U);

    // Rebinding new device clears fault and resumes cleanly.
    hooks.FailCopyHr = S_OK;
    pool.SetHooks(nullptr);
    pool.SetDevice(prodDev.Get(), prodCtx.Get(), adapterLuid);
    const SharedTextureExtractResult okRes = pool.ExtractToSharedTexture(in, meta, true);
    EXPECT_EQ(okRes.HResult, S_OK);
    pool.Shutdown();
}

void
TestCrossProcessHandleDuplicationAndOpenSharedResource1()
{
    ComPtr<ID3D11Device> prodDev;
    ComPtr<ID3D11Device1> prodDev1;
    ComPtr<ID3D11DeviceContext> prodCtx;
    LUID adapterLuid{0, 0};
    const char* kind = nullptr;
    EXPECT_TRUE(CreateRealD3d11Device1(prodDev, prodDev1, prodCtx, adapterLuid, kind));

    D3d11SharedTexturePool pool;
    EXPECT_EQ(pool.Configure(4U), S_OK);
    pool.SetDevice(prodDev.Get(), prodCtx.Get(), adapterLuid);

    wchar_t pipeBuf[128]{};
    _snwprintf_s(pipeBuf, ARRAYSIZE(pipeBuf), _TRUNCATE, L"\\\\.\\pipe\\LumaBridgeGpuUnit_%lu", GetCurrentProcessId());
    const std::wstring pipeName(pipeBuf);

    FrameTransportConfig srvCfg;
    srvCfg.SetPipeName(pipeName.c_str());
    srvCfg.AdapterLuid = adapterLuid;
    srvCfg.EnableGpuSharedTransport = true;
    srvCfg.SharedTexturePool = &pool;

    FrameIpcServer server;
    EXPECT_EQ(server.Start(srvCfg), S_OK);

    HostConsumerConfig cliCfg;
    cliCfg.PipeName = pipeName;
    cliCfg.TransportPreference = HostTransportPreference::GpuSharedOnly;
    cliCfg.AllowCpuFallback = false;
    cliCfg.VerifySyntheticPattern = false; // Proves 0 CPU staging reads in normal path!
    FrameConsumer consumer(cliCfg);
    EXPECT_EQ(consumer.Connect(2000U), S_OK);

    const auto preSnap = consumer.GetMetricsSnapshot();
    EXPECT_EQ(preSnap.NegotiatedTransportMode, FrameIpcTransportMode::GpuSharedNtHandle);

    for (uint32_t i = 1U; i <= 4U; ++i)
    {
        ComPtr<ID3D11Texture2D> src;
        EXPECT_TRUE(CreateSyntheticBgra8SourceTexture(prodDev.Get(), 1280U, 720U, i, src));

        auto slot = server.AcquireBufferSlot();
        EXPECT_TRUE(slot != nullptr);
        FrameExtractionInput in{};
        in.AdoptSourceTexture = src.Detach();
        in.PresentationFrameNumber = i;
        const SharedTextureExtractResult ext = pool.ExtractToSharedTexture(in, *slot, true);
        EXPECT_EQ(ext.HResult, S_OK);

        bool evicted = false;
        EXPECT_EQ(server.EnqueueFrame(std::move(slot), evicted), S_OK);

        bool isGpu = false;
        FrameIpcGpuFrameHeader gpuHdr{};
        FrameIpcFrameHeader cpuHdr{};
        std::vector<uint8_t> cpuPixels;
        EXPECT_EQ(consumer.ReceiveNextGpuOrCpuFrame(isGpu, gpuHdr, cpuHdr, cpuPixels, 2000U), S_OK);
        EXPECT_TRUE(isGpu);
        EXPECT_EQ(cpuPixels.size(), 0U);
        EXPECT_TRUE(consumer.GetWorkingGpuTexture() != nullptr);
    }

    const auto postSnap = consumer.GetMetricsSnapshot();
    EXPECT_EQ(postSnap.FramesValid, 4ULL);
    EXPECT_EQ(postSnap.CpuStagingReadsPerformed, 0ULL);
    EXPECT_TRUE(postSnap.GpuFramesOpened >= 1ULL);

    consumer.Disconnect();
    server.Stop();
    pool.Shutdown();
}

void
TestInvalidHandleAndAdapterLuidMismatchRejected()
{
    ComPtr<ID3D11Device> prodDev;
    ComPtr<ID3D11Device1> prodDev1;
    ComPtr<ID3D11DeviceContext> prodCtx;
    LUID adapterLuid{0, 0};
    const char* kind = nullptr;
    EXPECT_TRUE(CreateRealD3d11Device1(prodDev, prodDev1, prodCtx, adapterLuid, kind));

    // 1. Direct invalid NT handle rejected by OpenSharedResource1.
    ComPtr<ID3D11Texture2D> badTex;
    EXPECT_TRUE(FAILED(prodDev1->OpenSharedResource1(
        reinterpret_cast<HANDLE>(static_cast<uintptr_t>(0x12345678ULL)),
        IID_PPV_ARGS(&badTex))));

    // 2. Consumer rejects mismatched forced AdapterLuid before opening any shared texture.
    wchar_t pipeBuf[128]{};
    _snwprintf_s(pipeBuf, ARRAYSIZE(pipeBuf), _TRUNCATE, L"\\\\.\\pipe\\LumaBridgeGpuMismatch_%lu", GetCurrentProcessId());
    const std::wstring pipeName(pipeBuf);

    D3d11SharedTexturePool pool;
    EXPECT_EQ(pool.Configure(2U), S_OK);
    pool.SetDevice(prodDev.Get(), prodCtx.Get(), adapterLuid);

    FrameTransportConfig srvCfg;
    srvCfg.SetPipeName(pipeName.c_str());
    srvCfg.AdapterLuid = adapterLuid;
    srvCfg.EnableGpuSharedTransport = true;
    srvCfg.SharedTexturePool = &pool;
    FrameIpcServer server;
    EXPECT_EQ(server.Start(srvCfg), S_OK);

    HostConsumerConfig badLuidCfg;
    badLuidCfg.PipeName = pipeName;
    badLuidCfg.TransportPreference = HostTransportPreference::GpuSharedOnly;
    badLuidCfg.AllowCpuFallback = false;
    badLuidCfg.HasForcedAdapterLuid = true;
    badLuidCfg.ForcedAdapterLuid = LUID{static_cast<DWORD>(adapterLuid.LowPart + 999U), adapterLuid.HighPart + 1};
    FrameConsumer badConsumer(badLuidCfg);
    EXPECT_EQ(badConsumer.Connect(2000U), DXGI_ERROR_INVALID_CALL);
    EXPECT_EQ(badConsumer.GetMetricsSnapshot().AdapterMismatchErrors, 1ULL);
    EXPECT_EQ(badConsumer.GetMetricsSnapshot().LastProtocolStatus, FrameIpcStatus::AdapterLuidMismatch);

    server.Stop();
    pool.Shutdown();
}

template <typename Fn>
void
RunTest(const char* name, Fn fn)
{
    ++g_TestsRun;
    const int before = g_TestsFailed;
    fn();
    if (g_TestsFailed == before)
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
    RunTest("SharedTexturePoolCreationAndReuse720pAnd1080p", TestSharedTexturePoolCreationAndReuse720pAnd1080p);
    RunTest("SharedTextureKeyedMutexProducerConsumerSync", TestSharedTextureKeyedMutexProducerConsumerSync);
    RunTest("SharedTextureProtectedContentAndInvalidFormatRejected", TestSharedTextureProtectedContentAndInvalidFormatRejected);
    RunTest("SharedTexturePoolExhaustionDropsWithoutBlocking", TestSharedTexturePoolExhaustionDropsWithoutBlocking);
    RunTest("SharedTextureSlotRetirementOnSyncTimeoutOrAbandonedClient", TestSharedTextureSlotRetirementOnSyncTimeoutOrAbandonedClient);
    RunTest("SharedTextureDeviceRemovedAndResetRecovery", TestSharedTextureDeviceRemovedAndResetRecovery);
    RunTest("CrossProcessHandleDuplicationAndOpenSharedResource1", TestCrossProcessHandleDuplicationAndOpenSharedResource1);
    RunTest("InvalidHandleAndAdapterLuidMismatchRejected", TestInvalidHandleAndAdapterLuidMismatchRejected);

    std::printf("Summary: %d tests run, %d assertion failures.\n", g_TestsRun, g_TestsFailed);
    return (g_TestsFailed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
