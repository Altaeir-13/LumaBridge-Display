#include "FrameExtractor.h"

#include <cstring>
#include <new>

using Microsoft::WRL::ComPtr;

namespace lumabridge::driver {

namespace {

class ScopedStagingUnmap final
{
public:
    ScopedStagingUnmap(
        ID3d11ExtractionHooks* hooks,
        ID3D11DeviceContext* context,
        ID3D11Texture2D* staging
        ) noexcept
        : m_hooks(hooks),
          m_context(context),
          m_staging(staging)
    {
    }

    ~ScopedStagingUnmap()
    {
        if (m_hooks != nullptr && m_context != nullptr && m_staging != nullptr)
        {
            m_hooks->UnmapStagingTexture(m_context, m_staging);
        }
    }

    ScopedStagingUnmap(const ScopedStagingUnmap&) = delete;
    ScopedStagingUnmap& operator=(const ScopedStagingUnmap&) = delete;

private:
    ID3d11ExtractionHooks* m_hooks;
    ID3D11DeviceContext* m_context;
    ID3D11Texture2D* m_staging;
};

uint64_t
QueryCurrentQpc() noexcept
{
    LARGE_INTEGER li{};
    (void)QueryPerformanceCounter(&li);
    return (li.QuadPart > 0) ? static_cast<uint64_t>(li.QuadPart) : 0ULL;
}

uint64_t
QueryQpcFrequencySafe() noexcept
{
    LARGE_INTEGER li{};
    (void)QueryPerformanceFrequency(&li);
    return (li.QuadPart > 0) ? static_cast<uint64_t>(li.QuadPart) : 10000000ULL;
}

} // namespace

HRESULT
ID3d11ExtractionHooks::CreateStagingTexture(
    ID3D11Device* device,
    const D3D11_TEXTURE2D_DESC& desc,
    ID3D11Texture2D** outTexture
    ) noexcept
{
    if (device == nullptr || outTexture == nullptr)
    {
        return E_INVALIDARG;
    }

    *outTexture = nullptr;
    return device->CreateTexture2D(&desc, nullptr, outTexture);
}

HRESULT
ID3d11ExtractionHooks::CopyTextureResource(
    ID3D11DeviceContext* context,
    ID3D11Texture2D* dstStaging,
    ID3D11Texture2D* srcTexture
    ) noexcept
{
    if (context == nullptr || dstStaging == nullptr || srcTexture == nullptr)
    {
        return E_INVALIDARG;
    }

    context->CopyResource(dstStaging, srcTexture);
    return S_OK;
}

HRESULT
ID3d11ExtractionHooks::MapStagingTexture(
    ID3D11DeviceContext* context,
    ID3D11Texture2D* staging,
    D3D11_MAPPED_SUBRESOURCE& outMapped
    ) noexcept
{
    outMapped = {};
    if (context == nullptr || staging == nullptr)
    {
        return E_INVALIDARG;
    }

    return context->Map(staging, 0U, D3D11_MAP_READ, 0U, &outMapped);
}

void
ID3d11ExtractionHooks::UnmapStagingTexture(
    ID3D11DeviceContext* context,
    ID3D11Texture2D* staging
    ) noexcept
{
    if (context != nullptr && staging != nullptr)
    {
        context->Unmap(staging, 0U);
    }
}

bool
D3d11FrameExtractor::IsDeviceRemovedOrResetHResult(
    HRESULT hr
    ) noexcept
{
    return hr == DXGI_ERROR_DEVICE_REMOVED ||
           hr == DXGI_ERROR_DEVICE_RESET ||
           hr == DXGI_ERROR_DEVICE_HUNG ||
           hr == DXGI_ERROR_DRIVER_INTERNAL_ERROR;
}

void
D3d11FrameExtractor::SetDevice(
    ID3D11Device* device,
    ID3D11DeviceContext* context
    ) noexcept
{
    if (m_d3dDevice.Get() != device || m_d3dContext.Get() != context)
    {
        m_stagingTexture.Reset();
        m_stagingWidth = 0U;
        m_stagingHeight = 0U;
        m_stagingFormat = DXGI_FORMAT_UNKNOWN;
    }

    m_d3dDevice = device;
    m_d3dContext = context;
}

void
D3d11FrameExtractor::SetHooks(
    ID3d11ExtractionHooks* hooks
    ) noexcept
{
    m_hooks = (hooks != nullptr) ? hooks : &m_defaultHooks;
}

void
D3d11FrameExtractor::Reset() noexcept
{
    m_stagingTexture.Reset();
    m_stagingWidth = 0U;
    m_stagingHeight = 0U;
    m_stagingFormat = DXGI_FORMAT_UNKNOWN;
    m_d3dContext.Reset();
    m_d3dDevice.Reset();
}

FrameExtractionResult
D3d11FrameExtractor::ExtractFrame(
    const FrameExtractionInput& input,
    ExtractedFrameBuffer& outFrame
    ) noexcept
{
    FrameExtractionResult result{};
    outFrame.ResetMetadataKeepCapacity();

    const uint64_t qpcFreq = QueryQpcFrequencySafe();
    const uint64_t startQpc = QueryCurrentQpc();

    if (m_d3dDevice == nullptr || m_d3dContext == nullptr || m_hooks == nullptr)
    {
        result.HResult = E_NOT_VALID_STATE;
        return result;
    }

    ComPtr<ID3D11Texture2D> sourceTexture;
    if (input.SourceTexture != nullptr)
    {
        sourceTexture = input.SourceTexture;
    }
    else if (input.SurfaceResource != nullptr)
    {
        const HRESULT qiHr = input.SurfaceResource->QueryInterface(IID_PPV_ARGS(&sourceTexture));
        if (FAILED(qiHr) || sourceTexture == nullptr)
        {
            result.HResult = FAILED(qiHr) ? qiHr : E_NOINTERFACE;
            return result;
        }
    }
    else
    {
        result.HResult = E_INVALIDARG;
        return result;
    }

    D3D11_TEXTURE2D_DESC desc{};
    sourceTexture->GetDesc(&desc);
    if (desc.Width == 0U || desc.Height == 0U)
    {
        sourceTexture.Reset();
        result.HResult = E_INVALIDARG;
        return result;
    }

    result.SurfaceValid = true;
    result.Width = desc.Width;
    result.Height = desc.Height;
    result.Format = static_cast<uint32_t>(desc.Format);

    // Reject hardware-protected content immediately without copying or mapping pixels.
    if (input.HwProtectedSurface || (desc.MiscFlags & D3D11_RESOURCE_MISC_HW_PROTECTED) != 0U)
    {
        sourceTexture.Reset();
        outFrame.ResetMetadataKeepCapacity();
        result.ProtectedContentRejected = true;
        result.HResult = DXGI_ERROR_ACCESS_DENIED;
        return result;
    }

    if (desc.Width > ipc::kMaxFrameWidth ||
        desc.Height > ipc::kMaxFrameHeight ||
        desc.MipLevels != 1U ||
        desc.ArraySize != 1U ||
        desc.SampleDesc.Count != 1U)
    {
        sourceTexture.Reset();
        result.HResult = E_INVALIDARG;
        return result;
    }

    if (!ipc::IsSupportedExtractionDxgiFormat(static_cast<uint32_t>(desc.Format)))
    {
        sourceTexture.Reset();
        result.HResult = DXGI_ERROR_UNSUPPORTED;
        return result;
    }

    uint32_t tightRowPitch = 0U;
    uint32_t payloadBytes = 0U;
    if (!ipc::ComputeTightRowPitchBytes(desc.Width, tightRowPitch) ||
        !ipc::ComputeValidatedFramePayloadBytes(desc.Width, desc.Height, tightRowPitch, payloadBytes))
    {
        sourceTexture.Reset();
        result.HResult = HRESULT_FROM_WIN32(ERROR_ARITHMETIC_OVERFLOW);
        return result;
    }

    result.AcceptedForExtraction = true;

    const bool needNewStaging =
        (m_stagingTexture == nullptr) ||
        (m_stagingWidth != desc.Width) ||
        (m_stagingHeight != desc.Height) ||
        (m_stagingFormat != desc.Format);

    if (needNewStaging)
    {
        m_stagingTexture.Reset();
        m_stagingWidth = 0U;
        m_stagingHeight = 0U;
        m_stagingFormat = DXGI_FORMAT_UNKNOWN;

        D3D11_TEXTURE2D_DESC stagingDesc{};
        stagingDesc.Width = desc.Width;
        stagingDesc.Height = desc.Height;
        stagingDesc.MipLevels = 1U;
        stagingDesc.ArraySize = 1U;
        stagingDesc.Format = desc.Format;
        stagingDesc.SampleDesc.Count = 1U;
        stagingDesc.SampleDesc.Quality = 0U;
        stagingDesc.Usage = D3D11_USAGE_STAGING;
        stagingDesc.BindFlags = 0U;
        stagingDesc.CPUAccessFlags = D3D11_CPU_ACCESS_READ;
        stagingDesc.MiscFlags = 0U;

        ComPtr<ID3D11Texture2D> newStaging;
        HRESULT createHr = m_hooks->CreateStagingTexture(
            m_d3dDevice.Get(),
            stagingDesc,
            &newStaging);
        if (FAILED(createHr) || newStaging == nullptr)
        {
            if (SUCCEEDED(createHr))
            {
                createHr = E_OUTOFMEMORY;
            }
            const HRESULT removedReason = m_d3dDevice->GetDeviceRemovedReason();
            if (IsDeviceRemovedOrResetHResult(createHr) || IsDeviceRemovedOrResetHResult(removedReason))
            {
                result.DeviceRemovedOrReset = true;
                if (IsDeviceRemovedOrResetHResult(removedReason) && !IsDeviceRemovedOrResetHResult(createHr))
                {
                    createHr = removedReason;
                }
            }
            sourceTexture.Reset();
            result.HResult = createHr;
            return result;
        }

        m_stagingTexture = newStaging;
        m_stagingWidth = desc.Width;
        m_stagingHeight = desc.Height;
        m_stagingFormat = desc.Format;
        result.StagingRecreated = true;
    }

    const HRESULT copyHr = m_hooks->CopyTextureResource(
        m_d3dContext.Get(),
        m_stagingTexture.Get(),
        sourceTexture.Get());

    // Release our COM reference to the acquired IddCx surface immediately after GPU copy submission
    // so it never survives past extraction or across CPU mapping.
    sourceTexture.Reset();

    if (FAILED(copyHr))
    {
        const HRESULT removedReason = m_d3dDevice->GetDeviceRemovedReason();
        if (IsDeviceRemovedOrResetHResult(copyHr) || IsDeviceRemovedOrResetHResult(removedReason))
        {
            result.DeviceRemovedOrReset = true;
            m_stagingTexture.Reset();
            m_stagingWidth = 0U;
            m_stagingHeight = 0U;
            m_stagingFormat = DXGI_FORMAT_UNKNOWN;
        }
        result.HResult = copyHr;
        return result;
    }

    D3D11_MAPPED_SUBRESOURCE mapped{};
    HRESULT mapHr = m_hooks->MapStagingTexture(m_d3dContext.Get(), m_stagingTexture.Get(), mapped);
    if (FAILED(mapHr))
    {
        const HRESULT removedReason = m_d3dDevice->GetDeviceRemovedReason();
        if (IsDeviceRemovedOrResetHResult(mapHr) || IsDeviceRemovedOrResetHResult(removedReason))
        {
            result.DeviceRemovedOrReset = true;
            if (IsDeviceRemovedOrResetHResult(removedReason) && !IsDeviceRemovedOrResetHResult(mapHr))
            {
                mapHr = removedReason;
            }
            m_stagingTexture.Reset();
            m_stagingWidth = 0U;
            m_stagingHeight = 0U;
            m_stagingFormat = DXGI_FORMAT_UNKNOWN;
        }
        result.HResult = mapHr;
        return result;
    }

    {
        ScopedStagingUnmap unmapGuard(m_hooks, m_d3dContext.Get(), m_stagingTexture.Get());

        if (mapped.pData == nullptr || mapped.RowPitch < tightRowPitch)
        {
            result.HResult = E_FAIL;
            return result;
        }

        if (!outFrame.Pixels.Resize(static_cast<size_t>(payloadBytes)))
        {
            outFrame.ResetMetadataKeepCapacity();
            result.HResult = E_OUTOFMEMORY;
            return result;
        }

        const uint8_t* srcBytes = static_cast<const uint8_t*>(mapped.pData);
        if (mapped.RowPitch == tightRowPitch)
        {
            std::memcpy(outFrame.Pixels.data(), srcBytes, static_cast<size_t>(payloadBytes));
        }
        else
        {
            for (uint32_t row = 0U; row < desc.Height; ++row)
            {
                uint8_t* dstRow = outFrame.Pixels.data() + static_cast<size_t>(row) * tightRowPitch;
                const uint8_t* srcRow = srcBytes + static_cast<size_t>(row) * mapped.RowPitch;
                std::memcpy(dstRow, srcRow, static_cast<size_t>(tightRowPitch));
            }
        }
    }

    const uint64_t endQpc = QueryCurrentQpc();
    const uint64_t copyTicks = (endQpc >= startQpc) ? (endQpc - startQpc) : 0ULL;
    const uint64_t copyLatencyUs = (copyTicks * 1000000ULL) / qpcFreq;

    const uint64_t seq = static_cast<uint64_t>(InterlockedIncrement64(&m_sequenceCounter));
    outFrame.FrameSequence = seq;
    outFrame.PresentationFrameNumber = input.PresentationFrameNumber;
    outFrame.Width = desc.Width;
    outFrame.Height = desc.Height;
    outFrame.RowPitchBytes = tightRowPitch;
    outFrame.Format = static_cast<uint32_t>(desc.Format);
    outFrame.DirtyRectCount = input.DirtyRectCount;
    outFrame.MoveRegionCount = input.MoveRegionCount;
    outFrame.Flags = input.Flags;
    outFrame.PresentDisplayQpcTime = input.PresentDisplayQpcTime;
    outFrame.ExtractCompleteQpcTime = endQpc;
    outFrame.QpcFrequency = qpcFreq;
    outFrame.CopyLatencyUs = copyLatencyUs;
    outFrame.PayloadCrc32 = ipc::ComputeFrameCrc32(outFrame.Pixels.data(), outFrame.Pixels.size());

    result.HResult = S_OK;
    result.PixelsCopied = true;
    result.FrameSequence = seq;
    result.CopyLatencyUs = copyLatencyUs;
    return result;
}

} // namespace lumabridge::driver
