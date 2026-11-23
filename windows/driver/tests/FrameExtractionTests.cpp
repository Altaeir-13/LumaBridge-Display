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
#include <cstring>
#include <deque>
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
    const char*& outDriverKind
    ) noexcept
{
    outDevice.Reset();
    outContext.Reset();
    outDriverKind = "None";

    static constexpr D3D_FEATURE_LEVEL kLevels[] = {
        D3D_FEATURE_LEVEL_11_1,
        D3D_FEATURE_LEVEL_11_0,
        D3D_FEATURE_LEVEL_10_1,
        D3D_FEATURE_LEVEL_10_0};

    D3D_FEATURE_LEVEL level = D3D_FEATURE_LEVEL_11_0;
    HRESULT hr = D3D11CreateDevice(
        nullptr,
        D3D_DRIVER_TYPE_HARDWARE,
        nullptr,
        D3D11_CREATE_DEVICE_BGRA_SUPPORT,
        kLevels,
        ARRAYSIZE(kLevels),
        D3D11_SDK_VERSION,
        &outDevice,
        &level,
        &outContext);
    if (SUCCEEDED(hr) && outDevice != nullptr && outContext != nullptr)
    {
        outDriverKind = "Hardware";
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
        &level,
        &outContext);
    if (SUCCEEDED(hr) && outDevice != nullptr && outContext != nullptr)
    {
        outDriverKind = "WARP";
        return true;
    }

    return false;
}

bool
CreateSyntheticD3d11Texture(
    ID3D11Device* device,
    uint32_t width,
    uint32_t height,
    DXGI_FORMAT format,
    uint32_t frameNumber,
    ComPtr<ID3D11Texture2D>& outTexture
    ) noexcept
{
    outTexture.Reset();
    if (device == nullptr)
    {
        return false;
    }

    uint32_t rowPitch = 0U;
    uint32_t payloadBytes = 0U;
    if (!ComputeTightRowPitchBytes(width, rowPitch) ||
        !ComputeValidatedFramePayloadBytes(width, height, rowPitch, payloadBytes))
    {
        return false;
    }

    std::vector<uint8_t> initBytes(payloadBytes, 0U);
    if (!GenerateSyntheticTestPatternBgra8(frameNumber, width, height, initBytes.data(), initBytes.size()))
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
    desc.SampleDesc.Quality = 0U;
    desc.Usage = D3D11_USAGE_DEFAULT;
    desc.BindFlags = D3D11_BIND_SHADER_RESOURCE;

    D3D11_SUBRESOURCE_DATA initData{};
    initData.pSysMem = initBytes.data();
    initData.SysMemPitch = rowPitch;

    return SUCCEEDED(device->CreateTexture2D(&desc, &initData, &outTexture)) && outTexture != nullptr;
}

/// Minimal COM stub implementing IDXGIResource and an inner forwarding ID3D11Texture2D
/// (avoiding IDXGIResource::SetEvictionPriority vs ID3D11Resource::SetEvictionPriority signature collision)
/// with atomic reference count tracking.
class SyntheticDescTexture final : public IDXGIResource
{
public:
    SyntheticDescTexture(
        const D3D11_TEXTURE2D_DESC& desc,
        ID3D11Texture2D* realDelegate = nullptr,
        bool allowTextureQi = true
        ) noexcept
        : m_desc(desc),
          m_delegate(realDelegate),
          m_allowTextureQi(allowTextureQi),
          m_innerTexture(this)
    {
    }

    ULONG GetRefCount() const noexcept
    {
        return static_cast<ULONG>(m_refCount.load(std::memory_order_acquire));
    }

    ID3D11Texture2D* AsTexture2D() noexcept
    {
        return &m_innerTexture;
    }

    ID3D11Texture2D* GetDelegate() const noexcept
    {
        return m_delegate.Get();
    }

    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppvObject) override
    {
        if (ppvObject == nullptr)
        {
            return E_POINTER;
        }
        *ppvObject = nullptr;
        if (riid == __uuidof(IUnknown) || riid == __uuidof(IDXGIObject) || riid == __uuidof(IDXGIDeviceSubObject) || riid == __uuidof(IDXGIResource))
        {
            *ppvObject = static_cast<IDXGIResource*>(this);
            AddRef();
            return S_OK;
        }
        if (m_allowTextureQi && (riid == __uuidof(ID3D11DeviceChild) || riid == __uuidof(ID3D11Resource) || riid == __uuidof(ID3D11Texture2D)))
        {
            *ppvObject = static_cast<ID3D11Texture2D*>(&m_innerTexture);
            AddRef();
            return S_OK;
        }
        return E_NOINTERFACE;
    }

    ULONG STDMETHODCALLTYPE AddRef() override
    {
        return static_cast<ULONG>(m_refCount.fetch_add(1, std::memory_order_acq_rel) + 1);
    }

    ULONG STDMETHODCALLTYPE Release() override
    {
        const ULONG next = static_cast<ULONG>(m_refCount.fetch_sub(1, std::memory_order_acq_rel) - 1);
        if (next == 0U)
        {
            delete this;
        }
        return next;
    }

    HRESULT STDMETHODCALLTYPE SetPrivateData(REFGUID, UINT, const void*) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE SetPrivateDataInterface(REFGUID, const IUnknown*) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetPrivateData(REFGUID, UINT*, void*) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetParent(REFIID, void**) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetDevice(REFIID, void**) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetSharedHandle(HANDLE*) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetUsage(DXGI_USAGE*) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE SetEvictionPriority(UINT) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetEvictionPriority(UINT*) override { return E_NOTIMPL; }

private:
    class InnerTexture2D final : public ID3D11Texture2D
    {
    public:
        explicit InnerTexture2D(SyntheticDescTexture* outer) noexcept : m_outer(outer) {}

        HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppvObject) override
        {
            return m_outer->QueryInterface(riid, ppvObject);
        }
        ULONG STDMETHODCALLTYPE AddRef() override { return m_outer->AddRef(); }
        ULONG STDMETHODCALLTYPE Release() override { return m_outer->Release(); }

        void STDMETHODCALLTYPE GetDevice(ID3D11Device** ppDevice) override
        {
            if (m_outer->m_delegate != nullptr)
            {
                m_outer->m_delegate->GetDevice(ppDevice);
            }
            else if (ppDevice != nullptr)
            {
                *ppDevice = nullptr;
            }
        }
        HRESULT STDMETHODCALLTYPE GetPrivateData(REFGUID, UINT*, void*) override { return E_NOTIMPL; }
        HRESULT STDMETHODCALLTYPE SetPrivateData(REFGUID, UINT, const void*) override { return E_NOTIMPL; }
        HRESULT STDMETHODCALLTYPE SetPrivateDataInterface(REFGUID, const IUnknown*) override { return E_NOTIMPL; }
        void STDMETHODCALLTYPE GetType(D3D11_RESOURCE_DIMENSION* pResourceDimension) override
        {
            if (pResourceDimension != nullptr)
            {
                *pResourceDimension = D3D11_RESOURCE_DIMENSION_TEXTURE2D;
            }
        }
        void STDMETHODCALLTYPE SetEvictionPriority(UINT) override {}
        UINT STDMETHODCALLTYPE GetEvictionPriority() override { return 0U; }
        void STDMETHODCALLTYPE GetDesc(D3D11_TEXTURE2D_DESC* pDesc) override
        {
            if (pDesc != nullptr)
            {
                if (m_outer->m_delegate != nullptr)
                {
                    m_outer->m_delegate->GetDesc(pDesc);
                }
                else
                {
                    *pDesc = m_outer->m_desc;
                }
            }
        }

    private:
        SyntheticDescTexture* m_outer;
    };

    ~SyntheticDescTexture() = default;

    std::atomic<LONG> m_refCount{1};
    D3D11_TEXTURE2D_DESC m_desc{};
    ComPtr<ID3D11Texture2D> m_delegate{};
    bool m_allowTextureQi{true};
    InnerTexture2D m_innerTexture;
};

class FaultInjectionExtractionHooks final : public ID3d11ExtractionHooks
{
public:
    HRESULT FailCreateStagingHr{S_OK};
    HRESULT FailCopyHr{S_OK};
    HRESULT FailMapHr{S_OK};
    bool UseSyntheticMappedRowPitch{false};
    UINT SyntheticRowPitch{0U};
    std::vector<uint8_t> SyntheticMappedBytes{};
    uint32_t CreateStagingCalls{0U};
    uint32_t CopyCalls{0U};
    uint32_t MapCalls{0U};
    uint32_t UnmapCalls{0U};
    SyntheticDescTexture* TrackedSurface{nullptr};
    ULONG ObservedRefCountDuringCopy{0U};
    ULONG ObservedRefCountDuringMap{0U};

    HRESULT CreateStagingTexture(
        ID3D11Device* device,
        const D3D11_TEXTURE2D_DESC& desc,
        ID3D11Texture2D** outTexture
        ) noexcept override
    {
        ++CreateStagingCalls;
        if (FAILED(FailCreateStagingHr))
        {
            if (outTexture != nullptr)
            {
                *outTexture = nullptr;
            }
            return FailCreateStagingHr;
        }
        return ID3d11ExtractionHooks::CreateStagingTexture(device, desc, outTexture);
    }

    HRESULT CopyTextureResource(
        ID3D11DeviceContext* context,
        ID3D11Texture2D* dstStaging,
        ID3D11Texture2D* srcTexture
        ) noexcept override
    {
        ++CopyCalls;
        if (TrackedSurface != nullptr)
        {
            ObservedRefCountDuringCopy = TrackedSurface->GetRefCount();
        }
        if (FAILED(FailCopyHr))
        {
            return FailCopyHr;
        }
        ID3D11Texture2D* effectiveSrc = srcTexture;
        if (TrackedSurface != nullptr &&
            srcTexture == TrackedSurface->AsTexture2D() &&
            TrackedSurface->GetDelegate() != nullptr)
        {
            effectiveSrc = TrackedSurface->GetDelegate();
        }
        return ID3d11ExtractionHooks::CopyTextureResource(context, dstStaging, effectiveSrc);
    }

    HRESULT MapStagingTexture(
        ID3D11DeviceContext* context,
        ID3D11Texture2D* staging,
        D3D11_MAPPED_SUBRESOURCE& outMapped
        ) noexcept override
    {
        ++MapCalls;
        if (TrackedSurface != nullptr)
        {
            ObservedRefCountDuringMap = TrackedSurface->GetRefCount();
        }
        if (FAILED(FailMapHr))
        {
            outMapped = {};
            return FailMapHr;
        }
        if (UseSyntheticMappedRowPitch)
        {
            outMapped.pData = SyntheticMappedBytes.data();
            outMapped.RowPitch = SyntheticRowPitch;
            outMapped.DepthPitch = static_cast<UINT>(SyntheticMappedBytes.size());
            return S_OK;
        }
        return ID3d11ExtractionHooks::MapStagingTexture(context, staging, outMapped);
    }

    void UnmapStagingTexture(
        ID3D11DeviceContext* context,
        ID3D11Texture2D* staging
        ) noexcept override
    {
        ++UnmapCalls;
        if (!UseSyntheticMappedRowPitch)
        {
            ID3d11ExtractionHooks::UnmapStagingTexture(context, staging);
        }
    }
};

void
TestValidRealD3d11Texture720pAnd1080pExtraction()
{
    ComPtr<ID3D11Device> device;
    ComPtr<ID3D11DeviceContext> context;
    const char* driverKind = nullptr;
    EXPECT_TRUE(CreateTestD3d11Device(device, context, driverKind));
    if (device == nullptr || context == nullptr)
    {
        return;
    }

    std::printf("[INFO] Test D3D11 device backend: %s\n", driverKind);

    D3d11FrameExtractor extractor;
    extractor.SetDevice(device.Get(), context.Get());

    ExtractedFrameBuffer frameBuf;

    // 1. First 1280x720 BGRA8 frame creates staging texture.
    ComPtr<ID3D11Texture2D> tex720a;
    EXPECT_TRUE(CreateSyntheticD3d11Texture(device.Get(), 1280U, 720U, DXGI_FORMAT_B8G8R8A8_UNORM, 1U, tex720a));

    FrameExtractionInput in1{};
    in1.SourceTexture = tex720a.Get();
    in1.PresentationFrameNumber = 1U;
    in1.DirtyRectCount = 2U;
    in1.PresentDisplayQpcTime = 11111ULL;
    const FrameExtractionResult res1 = extractor.ExtractFrame(in1, frameBuf);
    EXPECT_EQ(res1.HResult, S_OK);
    EXPECT_TRUE(res1.SurfaceValid);
    EXPECT_TRUE(res1.AcceptedForExtraction);
    EXPECT_TRUE(res1.PixelsCopied);
    EXPECT_TRUE(res1.StagingRecreated);
    EXPECT_EQ(res1.Width, 1280U);
    EXPECT_EQ(res1.Height, 720U);
    EXPECT_EQ(res1.Format, static_cast<uint32_t>(DXGI_FORMAT_B8G8R8A8_UNORM));
    EXPECT_EQ(res1.FrameSequence, 1ULL);
    EXPECT_EQ(frameBuf.Pixels.size(), static_cast<size_t>(1280U * 720U * 4U));
    EXPECT_TRUE(VerifySyntheticTestPatternBgra8(1U, 1280U, 720U, frameBuf.Pixels.data(), frameBuf.Pixels.size()));
    EXPECT_EQ(frameBuf.PayloadCrc32, ComputeFrameCrc32(frameBuf.Pixels.data(), frameBuf.Pixels.size()));

    // 2. Second 1280x720 frame reuses cached staging texture without reallocation.
    ComPtr<ID3D11Texture2D> tex720b;
    EXPECT_TRUE(CreateSyntheticD3d11Texture(device.Get(), 1280U, 720U, DXGI_FORMAT_B8G8R8A8_UNORM, 2U, tex720b));
    FrameExtractionInput in2{};
    in2.SourceTexture = tex720b.Get();
    in2.PresentationFrameNumber = 2U;
    const FrameExtractionResult res2 = extractor.ExtractFrame(in2, frameBuf);
    EXPECT_EQ(res2.HResult, S_OK);
    EXPECT_TRUE(res2.PixelsCopied);
    EXPECT_TRUE(!res2.StagingRecreated);
    EXPECT_EQ(res2.FrameSequence, 2ULL);
    EXPECT_TRUE(VerifySyntheticTestPatternBgra8(2U, 1280U, 720U, frameBuf.Pixels.data(), frameBuf.Pixels.size()));

    // 3. 1920x1080 BGRA8 frame triggers staging recreation and preserves byte integrity.
    ComPtr<ID3D11Texture2D> tex1080;
    EXPECT_TRUE(CreateSyntheticD3d11Texture(device.Get(), 1920U, 1080U, DXGI_FORMAT_B8G8R8A8_UNORM, 3U, tex1080));
    FrameExtractionInput in3{};
    in3.SourceTexture = tex1080.Get();
    in3.PresentationFrameNumber = 3U;
    const FrameExtractionResult res3 = extractor.ExtractFrame(in3, frameBuf);
    EXPECT_EQ(res3.HResult, S_OK);
    EXPECT_TRUE(res3.PixelsCopied);
    EXPECT_TRUE(res3.StagingRecreated);
    EXPECT_EQ(res3.Width, 1920U);
    EXPECT_EQ(res3.Height, 1080U);
    EXPECT_EQ(res3.FrameSequence, 3ULL);
    EXPECT_EQ(frameBuf.Pixels.size(), static_cast<size_t>(1920U * 1080U * 4U));
    EXPECT_TRUE(VerifySyntheticTestPatternBgra8(3U, 1920U, 1080U, frameBuf.Pixels.data(), frameBuf.Pixels.size()));

    // 4. R8G8B8A8_UNORM 64x64 texture also supported.
    ComPtr<ID3D11Texture2D> texRgba;
    EXPECT_TRUE(CreateSyntheticD3d11Texture(device.Get(), 64U, 64U, DXGI_FORMAT_R8G8B8A8_UNORM, 4U, texRgba));
    FrameExtractionInput in4{};
    in4.SourceTexture = texRgba.Get();
    in4.PresentationFrameNumber = 4U;
    const FrameExtractionResult res4 = extractor.ExtractFrame(in4, frameBuf);
    EXPECT_EQ(res4.HResult, S_OK);
    EXPECT_TRUE(res4.PixelsCopied);
    EXPECT_EQ(res4.Format, static_cast<uint32_t>(DXGI_FORMAT_R8G8B8A8_UNORM));
    EXPECT_TRUE(VerifySyntheticTestPatternBgra8(4U, 64U, 64U, frameBuf.Pixels.data(), frameBuf.Pixels.size()));
}

void
TestInvalidDimensionsAndBoundsRejected()
{
    ComPtr<ID3D11Device> device;
    ComPtr<ID3D11DeviceContext> context;
    const char* driverKind = nullptr;
    EXPECT_TRUE(CreateTestD3d11Device(device, context, driverKind));

    D3d11FrameExtractor extractor;
    extractor.SetDevice(device.Get(), context.Get());
    ExtractedFrameBuffer frameBuf;

    D3D11_TEXTURE2D_DESC zeroDesc{};
    zeroDesc.Width = 0U;
    zeroDesc.Height = 720U;
    zeroDesc.MipLevels = 1U;
    zeroDesc.ArraySize = 1U;
    zeroDesc.Format = DXGI_FORMAT_B8G8R8A8_UNORM;
    zeroDesc.SampleDesc.Count = 1U;

    ComPtr<SyntheticDescTexture> zeroTex;
    zeroTex.Attach(new SyntheticDescTexture(zeroDesc));
    FrameExtractionInput inZero{};
    inZero.SourceTexture = zeroTex->AsTexture2D();
    const FrameExtractionResult resZero = extractor.ExtractFrame(inZero, frameBuf);
    EXPECT_EQ(resZero.HResult, E_INVALIDARG);
    EXPECT_TRUE(!resZero.SurfaceValid);
    EXPECT_TRUE(!resZero.AcceptedForExtraction);
    EXPECT_TRUE(!resZero.PixelsCopied);

    D3D11_TEXTURE2D_DESC overDesc = zeroDesc;
    overDesc.Width = kMaxFrameWidth + 1U;
    overDesc.Height = 1080U;
    ComPtr<SyntheticDescTexture> overTex;
    overTex.Attach(new SyntheticDescTexture(overDesc));
    FrameExtractionInput inOver{};
    inOver.SourceTexture = overTex->AsTexture2D();
    const FrameExtractionResult resOver = extractor.ExtractFrame(inOver, frameBuf);
    EXPECT_EQ(resOver.HResult, E_INVALIDARG);
    EXPECT_TRUE(resOver.SurfaceValid);
    EXPECT_TRUE(!resOver.AcceptedForExtraction);
    EXPECT_TRUE(!resOver.PixelsCopied);
    EXPECT_TRUE(frameBuf.Pixels.empty());
}

void
TestUnsupportedDxgiFormatRejected()
{
    ComPtr<ID3D11Device> device;
    ComPtr<ID3D11DeviceContext> context;
    const char* driverKind = nullptr;
    EXPECT_TRUE(CreateTestD3d11Device(device, context, driverKind));

    D3d11FrameExtractor extractor;
    extractor.SetDevice(device.Get(), context.Get());
    ExtractedFrameBuffer frameBuf;

    D3D11_TEXTURE2D_DESC hdrDesc{};
    hdrDesc.Width = 1280U;
    hdrDesc.Height = 720U;
    hdrDesc.MipLevels = 1U;
    hdrDesc.ArraySize = 1U;
    hdrDesc.Format = DXGI_FORMAT_R16G16B16A16_FLOAT;
    hdrDesc.SampleDesc.Count = 1U;
    hdrDesc.Usage = D3D11_USAGE_DEFAULT;

    ComPtr<ID3D11Texture2D> hdrTex;
    EXPECT_EQ(device->CreateTexture2D(&hdrDesc, nullptr, &hdrTex), S_OK);
    FrameExtractionInput inHdr{};
    inHdr.SourceTexture = hdrTex.Get();
    const FrameExtractionResult resHdr = extractor.ExtractFrame(inHdr, frameBuf);
    EXPECT_EQ(resHdr.HResult, DXGI_ERROR_UNSUPPORTED);
    EXPECT_TRUE(resHdr.SurfaceValid);
    EXPECT_TRUE(!resHdr.AcceptedForExtraction);
    EXPECT_TRUE(!resHdr.PixelsCopied);
    EXPECT_TRUE(frameBuf.Pixels.empty());
}

void
TestInvalidMipLevelsArraySizeAndMsaaRejected()
{
    ComPtr<ID3D11Device> device;
    ComPtr<ID3D11DeviceContext> context;
    const char* driverKind = nullptr;
    EXPECT_TRUE(CreateTestD3d11Device(device, context, driverKind));

    D3d11FrameExtractor extractor;
    extractor.SetDevice(device.Get(), context.Get());
    ExtractedFrameBuffer frameBuf;

    D3D11_TEXTURE2D_DESC badDesc{};
    badDesc.Width = 640U;
    badDesc.Height = 480U;
    badDesc.MipLevels = 2U;
    badDesc.ArraySize = 1U;
    badDesc.Format = DXGI_FORMAT_B8G8R8A8_UNORM;
    badDesc.SampleDesc.Count = 1U;

    {
        ComPtr<SyntheticDescTexture> tex;
        tex.Attach(new SyntheticDescTexture(badDesc));
        FrameExtractionInput in{};
        in.SourceTexture = tex->AsTexture2D();
        const FrameExtractionResult res = extractor.ExtractFrame(in, frameBuf);
        EXPECT_EQ(res.HResult, E_INVALIDARG);
        EXPECT_TRUE(!res.AcceptedForExtraction);
    }

    badDesc.MipLevels = 1U;
    badDesc.ArraySize = 2U;
    {
        ComPtr<SyntheticDescTexture> tex;
        tex.Attach(new SyntheticDescTexture(badDesc));
        FrameExtractionInput in{};
        in.SourceTexture = tex->AsTexture2D();
        const FrameExtractionResult res = extractor.ExtractFrame(in, frameBuf);
        EXPECT_EQ(res.HResult, E_INVALIDARG);
        EXPECT_TRUE(!res.AcceptedForExtraction);
    }

    badDesc.ArraySize = 1U;
    badDesc.SampleDesc.Count = 4U;
    {
        ComPtr<SyntheticDescTexture> tex;
        tex.Attach(new SyntheticDescTexture(badDesc));
        FrameExtractionInput in{};
        in.SourceTexture = tex->AsTexture2D();
        const FrameExtractionResult res = extractor.ExtractFrame(in, frameBuf);
        EXPECT_EQ(res.HResult, E_INVALIDARG);
        EXPECT_TRUE(!res.AcceptedForExtraction);
    }
}

void
TestNullSurfaceAndMissingDeviceRejected()
{
    D3d11FrameExtractor extractor;
    ExtractedFrameBuffer frameBuf;

    FrameExtractionInput emptyIn{};
    EXPECT_EQ(extractor.ExtractFrame(emptyIn, frameBuf).HResult, E_NOT_VALID_STATE);

    ComPtr<ID3D11Device> device;
    ComPtr<ID3D11DeviceContext> context;
    const char* driverKind = nullptr;
    EXPECT_TRUE(CreateTestD3d11Device(device, context, driverKind));

    extractor.SetDevice(device.Get(), context.Get());
    const FrameExtractionResult nullRes = extractor.ExtractFrame(emptyIn, frameBuf);
    EXPECT_EQ(nullRes.HResult, E_INVALIDARG);
    EXPECT_TRUE(!nullRes.SurfaceValid);

    D3D11_TEXTURE2D_DESC validDesc{};
    validDesc.Width = 64U;
    validDesc.Height = 64U;
    validDesc.MipLevels = 1U;
    validDesc.ArraySize = 1U;
    validDesc.Format = DXGI_FORMAT_B8G8R8A8_UNORM;
    validDesc.SampleDesc.Count = 1U;

    ComPtr<SyntheticDescTexture> nonTexResource;
    nonTexResource.Attach(new SyntheticDescTexture(validDesc, nullptr, false));
    FrameExtractionInput nonTexIn{};
    nonTexIn.SurfaceResource = static_cast<IDXGIResource*>(nonTexResource.Get());
    const FrameExtractionResult nonTexRes = extractor.ExtractFrame(nonTexIn, frameBuf);
    EXPECT_EQ(nonTexRes.HResult, E_NOINTERFACE);
    EXPECT_TRUE(!nonTexRes.SurfaceValid);
}

void
TestProtectedContentRejectedWithoutExposingPixels()
{
    ComPtr<ID3D11Device> device;
    ComPtr<ID3D11DeviceContext> context;
    const char* driverKind = nullptr;
    EXPECT_TRUE(CreateTestD3d11Device(device, context, driverKind));

    D3d11FrameExtractor extractor;
    extractor.SetDevice(device.Get(), context.Get());
    ExtractedFrameBuffer frameBuf;

    ComPtr<ID3D11Texture2D> realTex;
    EXPECT_TRUE(CreateSyntheticD3d11Texture(device.Get(), 64U, 64U, DXGI_FORMAT_B8G8R8A8_UNORM, 9U, realTex));

    // Case A: HwProtectedSurface flag in IDDCX metadata.
    FrameExtractionInput protInA{};
    protInA.SourceTexture = realTex.Get();
    protInA.PresentationFrameNumber = 9U;
    protInA.HwProtectedSurface = true;
    const FrameExtractionResult resA = extractor.ExtractFrame(protInA, frameBuf);
    EXPECT_EQ(resA.HResult, DXGI_ERROR_ACCESS_DENIED);
    EXPECT_TRUE(resA.ProtectedContentRejected);
    EXPECT_TRUE(!resA.AcceptedForExtraction);
    EXPECT_TRUE(!resA.PixelsCopied);
    EXPECT_TRUE(frameBuf.Pixels.empty());
    EXPECT_EQ(frameBuf.PayloadCrc32, 0U);

    // Case B: D3D11_RESOURCE_MISC_HW_PROTECTED flag on texture descriptor.
    D3D11_TEXTURE2D_DESC protDesc{};
    protDesc.Width = 64U;
    protDesc.Height = 64U;
    protDesc.MipLevels = 1U;
    protDesc.ArraySize = 1U;
    protDesc.Format = DXGI_FORMAT_B8G8R8A8_UNORM;
    protDesc.SampleDesc.Count = 1U;
    protDesc.MiscFlags = D3D11_RESOURCE_MISC_HW_PROTECTED;
    ComPtr<SyntheticDescTexture> protTex;
    protTex.Attach(new SyntheticDescTexture(protDesc));

    FrameExtractionInput protInB{};
    protInB.SourceTexture = protTex->AsTexture2D();
    protInB.PresentationFrameNumber = 10U;
    protInB.HwProtectedSurface = false;
    const FrameExtractionResult resB = extractor.ExtractFrame(protInB, frameBuf);
    EXPECT_EQ(resB.HResult, DXGI_ERROR_ACCESS_DENIED);
    EXPECT_TRUE(resB.ProtectedContentRejected);
    EXPECT_TRUE(!resB.PixelsCopied);
    EXPECT_TRUE(frameBuf.Pixels.empty());
}

void
TestStagingAllocationFailureHandledCleanly()
{
    ComPtr<ID3D11Device> device;
    ComPtr<ID3D11DeviceContext> context;
    const char* driverKind = nullptr;
    EXPECT_TRUE(CreateTestD3d11Device(device, context, driverKind));

    FaultInjectionExtractionHooks hooks;
    hooks.FailCreateStagingHr = E_OUTOFMEMORY;

    D3d11FrameExtractor extractor;
    extractor.SetDevice(device.Get(), context.Get());
    extractor.SetHooks(&hooks);

    ComPtr<ID3D11Texture2D> tex;
    EXPECT_TRUE(CreateSyntheticD3d11Texture(device.Get(), 64U, 64U, DXGI_FORMAT_B8G8R8A8_UNORM, 5U, tex));

    ExtractedFrameBuffer frameBuf;
    FrameExtractionInput in{};
    in.SourceTexture = tex.Get();
    in.PresentationFrameNumber = 5U;

    const FrameExtractionResult failRes = extractor.ExtractFrame(in, frameBuf);
    EXPECT_EQ(failRes.HResult, E_OUTOFMEMORY);
    EXPECT_TRUE(failRes.AcceptedForExtraction);
    EXPECT_TRUE(!failRes.PixelsCopied);
    EXPECT_EQ(hooks.CopyCalls, 0U);
    EXPECT_TRUE(frameBuf.Pixels.empty());

    // Recover once allocation succeeds.
    hooks.FailCreateStagingHr = S_OK;
    const FrameExtractionResult okRes = extractor.ExtractFrame(in, frameBuf);
    EXPECT_EQ(okRes.HResult, S_OK);
    EXPECT_TRUE(okRes.PixelsCopied);
    EXPECT_TRUE(VerifySyntheticTestPatternBgra8(5U, 64U, 64U, frameBuf.Pixels.data(), frameBuf.Pixels.size()));
}

void
TestMapAndCopyFailureHandledCleanly()
{
    ComPtr<ID3D11Device> device;
    ComPtr<ID3D11DeviceContext> context;
    const char* driverKind = nullptr;
    EXPECT_TRUE(CreateTestD3d11Device(device, context, driverKind));

    ComPtr<ID3D11Texture2D> tex;
    EXPECT_TRUE(CreateSyntheticD3d11Texture(device.Get(), 64U, 64U, DXGI_FORMAT_B8G8R8A8_UNORM, 7U, tex));

    FaultInjectionExtractionHooks hooks;
    D3d11FrameExtractor extractor;
    extractor.SetDevice(device.Get(), context.Get());
    extractor.SetHooks(&hooks);
    ExtractedFrameBuffer frameBuf;

    FrameExtractionInput in{};
    in.SourceTexture = tex.Get();
    in.PresentationFrameNumber = 7U;

    // 1. Copy failure must not map or unmap.
    hooks.FailCopyHr = E_FAIL;
    const FrameExtractionResult copyFail = extractor.ExtractFrame(in, frameBuf);
    EXPECT_EQ(copyFail.HResult, E_FAIL);
    EXPECT_TRUE(!copyFail.PixelsCopied);
    EXPECT_EQ(hooks.MapCalls, 0U);
    EXPECT_EQ(hooks.UnmapCalls, 0U);

    // 2. Map failure must not unmap.
    hooks.FailCopyHr = S_OK;
    hooks.FailMapHr = E_FAIL;
    const FrameExtractionResult mapFail = extractor.ExtractFrame(in, frameBuf);
    EXPECT_EQ(mapFail.HResult, E_FAIL);
    EXPECT_TRUE(!mapFail.PixelsCopied);
    EXPECT_EQ(hooks.UnmapCalls, 0U);

    // 3. Padded RowPitch repacked tightly + Unmap always invoked.
    hooks.FailMapHr = S_OK;
    hooks.UseSyntheticMappedRowPitch = true;
    constexpr uint32_t kWidth = 64U;
    constexpr uint32_t kHeight = 64U;
    constexpr uint32_t kTightPitch = kWidth * 4U;
    constexpr uint32_t kPaddedPitch = kTightPitch + 128U;
    hooks.SyntheticRowPitch = kPaddedPitch;
    hooks.SyntheticMappedBytes.assign(static_cast<size_t>(kPaddedPitch) * kHeight, 0xAAU);

    std::vector<uint8_t> pattern(static_cast<size_t>(kTightPitch) * kHeight, 0U);
    EXPECT_TRUE(GenerateSyntheticTestPatternBgra8(7U, kWidth, kHeight, pattern.data(), pattern.size()));
    for (uint32_t row = 0U; row < kHeight; ++row)
    {
        std::memcpy(
            hooks.SyntheticMappedBytes.data() + static_cast<size_t>(row) * kPaddedPitch,
            pattern.data() + static_cast<size_t>(row) * kTightPitch,
            kTightPitch);
    }

    const FrameExtractionResult paddedOk = extractor.ExtractFrame(in, frameBuf);
    EXPECT_EQ(paddedOk.HResult, S_OK);
    EXPECT_TRUE(paddedOk.PixelsCopied);
    EXPECT_EQ(hooks.UnmapCalls, 1U);
    EXPECT_EQ(frameBuf.RowPitchBytes, kTightPitch);
    EXPECT_EQ(frameBuf.Pixels.size(), pattern.size());
    EXPECT_TRUE(VerifySyntheticTestPatternBgra8(7U, kWidth, kHeight, frameBuf.Pixels.data(), frameBuf.Pixels.size()));
}

void
TestDeviceRemovedAndResetPropagated()
{
    ComPtr<ID3D11Device> device;
    ComPtr<ID3D11DeviceContext> context;
    const char* driverKind = nullptr;
    EXPECT_TRUE(CreateTestD3d11Device(device, context, driverKind));

    ComPtr<ID3D11Texture2D> tex;
    EXPECT_TRUE(CreateSyntheticD3d11Texture(device.Get(), 64U, 64U, DXGI_FORMAT_B8G8R8A8_UNORM, 11U, tex));

    FaultInjectionExtractionHooks hooks;
    D3d11FrameExtractor extractor;
    extractor.SetDevice(device.Get(), context.Get());
    extractor.SetHooks(&hooks);
    ExtractedFrameBuffer frameBuf;

    FrameExtractionInput in{};
    in.SourceTexture = tex.Get();
    in.PresentationFrameNumber = 11U;

    hooks.FailCreateStagingHr = DXGI_ERROR_DEVICE_REMOVED;
    const FrameExtractionResult remCreate = extractor.ExtractFrame(in, frameBuf);
    EXPECT_EQ(remCreate.HResult, DXGI_ERROR_DEVICE_REMOVED);
    EXPECT_TRUE(remCreate.DeviceRemovedOrReset);
    EXPECT_TRUE(!remCreate.PixelsCopied);

    hooks.FailCreateStagingHr = S_OK;
    hooks.FailCopyHr = DXGI_ERROR_DEVICE_RESET;
    const FrameExtractionResult resetCopy = extractor.ExtractFrame(in, frameBuf);
    EXPECT_EQ(resetCopy.HResult, DXGI_ERROR_DEVICE_RESET);
    EXPECT_TRUE(resetCopy.DeviceRemovedOrReset);
    EXPECT_TRUE(!resetCopy.PixelsCopied);

    hooks.FailCopyHr = S_OK;
    hooks.FailMapHr = DXGI_ERROR_DEVICE_REMOVED;
    const FrameExtractionResult remMap = extractor.ExtractFrame(in, frameBuf);
    EXPECT_EQ(remMap.HResult, DXGI_ERROR_DEVICE_REMOVED);
    EXPECT_TRUE(remMap.DeviceRemovedOrReset);
    EXPECT_TRUE(!remMap.PixelsCopied);
}

void
TestAcquiredSurfaceComReferenceLifetimeReleasedBeforeReturn()
{
    ComPtr<ID3D11Device> device;
    ComPtr<ID3D11DeviceContext> context;
    const char* driverKind = nullptr;
    EXPECT_TRUE(CreateTestD3d11Device(device, context, driverKind));

    ComPtr<ID3D11Texture2D> realTex;
    EXPECT_TRUE(CreateSyntheticD3d11Texture(device.Get(), 64U, 64U, DXGI_FORMAT_B8G8R8A8_UNORM, 13U, realTex));
    D3D11_TEXTURE2D_DESC desc{};
    realTex->GetDesc(&desc);

    ComPtr<SyntheticDescTexture> tracked;
    tracked.Attach(new SyntheticDescTexture(desc, realTex.Get(), true));
    EXPECT_EQ(tracked->GetRefCount(), 1UL);

    FaultInjectionExtractionHooks hooks;
    hooks.TrackedSurface = tracked.Get();

    D3d11FrameExtractor extractor;
    extractor.SetDevice(device.Get(), context.Get());
    extractor.SetHooks(&hooks);

    ExtractedFrameBuffer frameBuf;
    FrameExtractionInput in{};
    in.SurfaceResource = static_cast<IDXGIResource*>(tracked.Get());
    in.PresentationFrameNumber = 13U;

    const FrameExtractionResult res = extractor.ExtractFrame(in, frameBuf);
    EXPECT_EQ(res.HResult, S_OK);
    EXPECT_TRUE(res.PixelsCopied);

    // Extractor held a local ref during CopyTextureResource, then released it BEFORE MapStagingTexture!
    EXPECT_EQ(hooks.ObservedRefCountDuringCopy, 2UL);
    EXPECT_EQ(hooks.ObservedRefCountDuringMap, 1UL);
    EXPECT_EQ(tracked->GetRefCount(), 1UL);

    extractor.Reset();
    EXPECT_EQ(tracked->GetRefCount(), 1UL);
    EXPECT_EQ(tracked.Reset(), 0UL);
}

class RealD3d11SwapChainHarnessBackend final : public ISwapChainBackend
{
public:
    explicit RealD3d11SwapChainHarnessBackend(
        ID3D11Device* device,
        ID3D11DeviceContext* context
        ) noexcept
        : m_device(device),
          m_context(context)
    {
        InitializeSRWLock(&m_lock);
        m_activityEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        m_extractor.SetDevice(device, context);
    }

    ~RealD3d11SwapChainHarnessBackend() override
    {
        m_ipcServer.Stop();
        if (m_activityEvent != nullptr)
        {
            CloseHandle(m_activityEvent);
        }
    }

    void EnqueueSurfaceAction(
        HRESULT hr,
        ComPtr<ID3D11Texture2D> texture,
        uint32_t frameNumber,
        bool hwProtected = false
        )
    {
        AcquireSRWLockExclusive(&m_lock);
        m_actions.push_back(Action{hr, texture, frameNumber, hwProtected});
        ReleaseSRWLockExclusive(&m_lock);
    }

    bool WaitForFinishCount(uint32_t target, DWORD timeoutMs = 4000U) noexcept
    {
        const ULONGLONG deadline = GetTickCount64() + timeoutMs;
        for (;;)
        {
            AcquireSRWLockExclusive(&m_lock);
            const uint32_t val = m_finishCalls;
            if (val >= target)
            {
                ReleaseSRWLockExclusive(&m_lock);
                return true;
            }
            ResetEvent(m_activityEvent);
            ReleaseSRWLockExclusive(&m_lock);

            const ULONGLONG now = GetTickCount64();
            if (now >= deadline)
            {
                return false;
            }
            (void)WaitForSingleObject(m_activityEvent, static_cast<DWORD>(deadline - now));
        }
    }

    bool WaitForDeleteCount(uint32_t target, DWORD timeoutMs = 4000U) noexcept
    {
        const ULONGLONG deadline = GetTickCount64() + timeoutMs;
        for (;;)
        {
            AcquireSRWLockExclusive(&m_lock);
            const uint32_t val = m_deleteCalls;
            if (val >= target)
            {
                ReleaseSRWLockExclusive(&m_lock);
                return true;
            }
            ResetEvent(m_activityEvent);
            ReleaseSRWLockExclusive(&m_lock);

            const ULONGLONG now = GetTickCount64();
            if (now >= deadline)
            {
                return false;
            }
            (void)WaitForSingleObject(m_activityEvent, static_cast<DWORD>(deadline - now));
        }
    }

    uint32_t FinishCalls() noexcept
    {
        AcquireSRWLockExclusive(&m_lock);
        const uint32_t v = m_finishCalls;
        ReleaseSRWLockExclusive(&m_lock);
        return v;
    }

    uint32_t DeleteCalls() noexcept
    {
        AcquireSRWLockExclusive(&m_lock);
        const uint32_t v = m_deleteCalls;
        ReleaseSRWLockExclusive(&m_lock);
        return v;
    }

    HRESULT InitializeDeviceAndBindSwapChain(
        void*,
        LUID renderAdapterLuid
        ) noexcept override
    {
        FrameTransportConfig cfg;
        wchar_t pipeBuf[128]{};
        _snwprintf_s(
            pipeBuf,
            ARRAYSIZE(pipeBuf),
            _TRUNCATE,
            L"\\\\.\\pipe\\LumaBridgeExtHarness_%lu",
            GetCurrentProcessId());
        cfg.SetPipeName(pipeBuf);
        cfg.AdapterLuid = renderAdapterLuid;
        return m_ipcServer.Start(cfg);
    }

    HRESULT ReleaseAndAcquireBuffer(
        void*,
        SwapChainFrameMetadata& outMetadata
        ) noexcept override
    {
        outMetadata = {};
        Action next{};
        {
            AcquireSRWLockExclusive(&m_lock);
            if (m_actions.empty())
            {
                ReleaseSRWLockExclusive(&m_lock);
                return E_PENDING;
            }
            next = m_actions.front();
            m_actions.pop_front();
            ReleaseSRWLockExclusive(&m_lock);
        }

        if (FAILED(next.Result))
        {
            return next.Result;
        }

        outMetadata.PresentationFrameNumber = next.FrameNumber;
        outMetadata.DirtyRectCount = 1U;
        outMetadata.HwProtectedSurface = next.HwProtected;
        outMetadata.PresentDisplayQPCTime = 9000ULL + next.FrameNumber;
        outMetadata.HasValidSurface = (next.Texture != nullptr);

        if (outMetadata.HasValidSurface)
        {
            outMetadata.ExtractionAttempted = true;
            auto slot = m_ipcServer.AcquireBufferSlot();
            if (slot != nullptr)
            {
                FrameExtractionInput in{};
                in.SourceTexture = next.Texture.Get();
                in.PresentationFrameNumber = next.FrameNumber;
                in.HwProtectedSurface = next.HwProtected;
                in.PresentDisplayQpcTime = outMetadata.PresentDisplayQPCTime;

                const FrameExtractionResult ext = m_extractor.ExtractFrame(in, *slot);
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
            }
        }
        return S_OK;
    }

    HRESULT FinishProcessingFrame(void*) noexcept override
    {
        AcquireSRWLockExclusive(&m_lock);
        ++m_finishCalls;
        SetEvent(m_activityEvent);
        ReleaseSRWLockExclusive(&m_lock);
        return S_OK;
    }

    void DeleteSwapChainObject(void*) noexcept override
    {
        m_ipcServer.FlushQueue();
        AcquireSRWLockExclusive(&m_lock);
        ++m_deleteCalls;
        SetEvent(m_activityEvent);
        ReleaseSRWLockExclusive(&m_lock);
    }

    void QueryFrameTransportMetrics(SwapChainMetricsSnapshot& inoutSnapshot) const noexcept override
    {
        inoutSnapshot.FrameExtractionEnabled = true;
        const FrameTransportMetricsSnapshot ipcSnap = m_ipcServer.GetMetricsSnapshot();
        inoutSnapshot.FramesDelivered = ipcSnap.FramesDelivered;
        inoutSnapshot.FramesDroppedByBackpressure = ipcSnap.FramesDroppedByBackpressure;
        inoutSnapshot.FrameTransportFailures = ipcSnap.FrameTransportFailures;
        inoutSnapshot.ActiveHostConnections = ipcSnap.ActiveHostConnections;
        inoutSnapshot.QueueDepth = ipcSnap.QueueDepth;
        inoutSnapshot.PeakQueueDepth = ipcSnap.PeakQueueDepth;
    }

private:
    struct Action
    {
        HRESULT Result{S_OK};
        ComPtr<ID3D11Texture2D> Texture{};
        uint32_t FrameNumber{0U};
        bool HwProtected{false};
    };

    ComPtr<ID3D11Device> m_device{};
    ComPtr<ID3D11DeviceContext> m_context{};
    D3d11FrameExtractor m_extractor{};
    FrameIpcServer m_ipcServer{};
    SRWLOCK m_lock{SRWLOCK_INIT};
    HANDLE m_activityEvent{nullptr};
    std::deque<Action> m_actions{};
    uint32_t m_finishCalls{0U};
    uint32_t m_deleteCalls{0U};
};

void
TestSwapChainProcessorIntegrationWithExtractionAndIddCxFinish()
{
    ComPtr<ID3D11Device> device;
    ComPtr<ID3D11DeviceContext> context;
    const char* driverKind = nullptr;
    EXPECT_TRUE(CreateTestD3d11Device(device, context, driverKind));

    ComPtr<ID3D11Texture2D> validTex;
    ComPtr<ID3D11Texture2D> protTex;
    EXPECT_TRUE(CreateSyntheticD3d11Texture(device.Get(), 1280U, 720U, DXGI_FORMAT_B8G8R8A8_UNORM, 21U, validTex));
    EXPECT_TRUE(CreateSyntheticD3d11Texture(device.Get(), 1280U, 720U, DXGI_FORMAT_B8G8R8A8_UNORM, 22U, protTex));

    RealD3d11SwapChainHarnessBackend backend(device.Get(), context.Get());
    backend.EnqueueSurfaceAction(S_OK, validTex, 21U, false);
    backend.EnqueueSurfaceAction(S_OK, nullptr, 22U, false);
    backend.EnqueueSurfaceAction(S_OK, protTex, 23U, true);
    backend.EnqueueSurfaceAction(DXGI_ERROR_DEVICE_REMOVED, nullptr, 0U, false);

    SwapChainProcessor processor(&backend);
    ScopedWin32Handle surfaceEvent(CreateEventW(nullptr, FALSE, FALSE, nullptr));
    EXPECT_TRUE(surfaceEvent.IsValid());

    EXPECT_EQ(
        processor.AssignSwapChain(reinterpret_cast<void*>(0xAA01), surfaceEvent.Get(), LUID{55, 0}),
        STATUS_SUCCESS);

    EXPECT_TRUE(backend.WaitForDeleteCount(1U));

    const auto metrics = processor.GetMetricsSnapshot();
    EXPECT_TRUE(metrics.FrameExtractionEnabled);
    EXPECT_EQ(metrics.FramesAcquired, 3ULL);
    EXPECT_EQ(metrics.FramesProcessed, 2ULL);
    EXPECT_EQ(metrics.FramesDropped, 1ULL);
    EXPECT_EQ(metrics.FramesExtractionAccepted, 1ULL);
    EXPECT_EQ(metrics.FramesCopied, 1ULL);
    EXPECT_EQ(metrics.ProtectedFramesRejected, 1ULL);
    EXPECT_EQ(metrics.FrameCopyFailures, 0ULL);
    EXPECT_EQ(metrics.DeviceRemovedErrors, 1ULL);
    EXPECT_EQ(metrics.LastExtractedWidth, 1280U);
    EXPECT_EQ(metrics.LastExtractedHeight, 720U);
    EXPECT_EQ(metrics.QueueDepth, 0U);
    EXPECT_EQ(backend.FinishCalls(), 3U);
    EXPECT_EQ(backend.DeleteCalls(), 1U);
    EXPECT_EQ(processor.UnassignSwapChain(), STATUS_SUCCESS);
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
    RunTest("ValidRealD3d11Texture720pAnd1080pExtraction", TestValidRealD3d11Texture720pAnd1080pExtraction);
    RunTest("InvalidDimensionsAndBoundsRejected", TestInvalidDimensionsAndBoundsRejected);
    RunTest("UnsupportedDxgiFormatRejected", TestUnsupportedDxgiFormatRejected);
    RunTest("InvalidMipLevelsArraySizeAndMsaaRejected", TestInvalidMipLevelsArraySizeAndMsaaRejected);
    RunTest("NullSurfaceAndMissingDeviceRejected", TestNullSurfaceAndMissingDeviceRejected);
    RunTest("ProtectedContentRejectedWithoutExposingPixels", TestProtectedContentRejectedWithoutExposingPixels);
    RunTest("StagingAllocationFailureHandledCleanly", TestStagingAllocationFailureHandledCleanly);
    RunTest("MapAndCopyFailureHandledCleanly", TestMapAndCopyFailureHandledCleanly);
    RunTest("DeviceRemovedAndResetPropagated", TestDeviceRemovedAndResetPropagated);
    RunTest("AcquiredSurfaceComReferenceLifetimeReleasedBeforeReturn", TestAcquiredSurfaceComReferenceLifetimeReleasedBeforeReturn);
    RunTest("SwapChainProcessorIntegrationWithExtractionAndIddCxFinish", TestSwapChainProcessorIntegrationWithExtractionAndIddCxFinish);

    std::printf("Summary: %d tests run, %d assertion failures.\n", g_TestsRun, g_TestsFailed);
    return (g_TestsFailed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
