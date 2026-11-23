#pragma once

#include "FrameIpcProtocol.h"

#include <d3d11.h>
#include <wrl/client.h>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <new>

namespace lumabridge::driver {

/// Exception-free, UMDF-safe byte buffer that retains capacity across frame resets.
class PixelByteBuffer final
{
public:
    PixelByteBuffer() noexcept = default;
    ~PixelByteBuffer() = default;

    PixelByteBuffer(const PixelByteBuffer&) = delete;
    PixelByteBuffer& operator=(const PixelByteBuffer&) = delete;

    PixelByteBuffer(PixelByteBuffer&& other) noexcept
        : m_data(std::move(other.m_data)),
          m_size(other.m_size),
          m_capacity(other.m_capacity)
    {
        other.m_size = 0U;
        other.m_capacity = 0U;
    }

    PixelByteBuffer& operator=(PixelByteBuffer&& other) noexcept
    {
        if (this != &other)
        {
            m_data = std::move(other.m_data);
            m_size = other.m_size;
            m_capacity = other.m_capacity;
            other.m_size = 0U;
            other.m_capacity = 0U;
        }
        return *this;
    }

    bool Resize(size_t newSize) noexcept
    {
        if (newSize == 0U)
        {
            m_size = 0U;
            return true;
        }

        if (newSize > m_capacity)
        {
            std::unique_ptr<uint8_t[]> next(new (std::nothrow) uint8_t[newSize]);
            if (next == nullptr)
            {
                return false;
            }
            m_data = std::move(next);
            m_capacity = newSize;
        }

        m_size = newSize;
        return true;
    }

    void ClearKeepCapacity() noexcept
    {
        m_size = 0U;
    }

    void FreeStorage() noexcept
    {
        m_data.reset();
        m_size = 0U;
        m_capacity = 0U;
    }

    uint8_t* data() noexcept { return m_data.get(); }
    const uint8_t* data() const noexcept { return m_data.get(); }
    size_t size() const noexcept { return m_size; }
    size_t capacity() const noexcept { return m_capacity; }
    bool empty() const noexcept { return m_size == 0U; }

private:
    std::unique_ptr<uint8_t[]> m_data{};
    size_t m_size{0U};
    size_t m_capacity{0U};
};

/// Reusable extracted frame buffer storing tightly packed BGRA8/RGBA8 pixels and frame metadata.
struct ExtractedFrameBuffer
{
    uint64_t FrameSequence{0};
    uint32_t PresentationFrameNumber{0};
    uint32_t Width{0};
    uint32_t Height{0};
    uint32_t RowPitchBytes{0};
    uint32_t Format{0};
    uint32_t DirtyRectCount{0};
    uint32_t MoveRegionCount{0};
    uint32_t Flags{0};
    uint64_t PresentDisplayQpcTime{0};
    uint64_t ExtractCompleteQpcTime{0};
    uint64_t QpcFrequency{0};
    uint64_t CopyLatencyUs{0};
    uint32_t PayloadCrc32{0};
    PixelByteBuffer Pixels{};

    void ResetMetadataKeepCapacity() noexcept
    {
        FrameSequence = 0ULL;
        PresentationFrameNumber = 0U;
        Width = 0U;
        Height = 0U;
        RowPitchBytes = 0U;
        Format = 0U;
        DirtyRectCount = 0U;
        MoveRegionCount = 0U;
        Flags = 0U;
        PresentDisplayQpcTime = 0ULL;
        ExtractCompleteQpcTime = 0ULL;
        QpcFrequency = 0ULL;
        CopyLatencyUs = 0ULL;
        PayloadCrc32 = 0U;
        Pixels.ClearKeepCapacity();
    }
};

/// Input parameters for extracting a single acquired IddCx/D3D11 frame surface.
struct FrameExtractionInput
{
    IDXGIResource* SurfaceResource{nullptr};
    ID3D11Texture2D* SourceTexture{nullptr};
    uint32_t PresentationFrameNumber{0};
    uint32_t DirtyRectCount{0};
    uint32_t MoveRegionCount{0};
    bool HwProtectedSurface{false};
    uint64_t PresentDisplayQpcTime{0};
    uint32_t Flags{0};
};

/// Outcome of a single D3D11 frame extraction attempt.
struct FrameExtractionResult
{
    HRESULT HResult{E_FAIL};
    bool SurfaceValid{false};
    bool AcceptedForExtraction{false};
    bool ProtectedContentRejected{false};
    bool PixelsCopied{false};
    bool DeviceRemovedOrReset{false};
    bool StagingRecreated{false};
    uint32_t Width{0};
    uint32_t Height{0};
    uint32_t Format{0};
    uint64_t FrameSequence{0};
    uint64_t CopyLatencyUs{0};
};

/// Testability seam over D3D11 staging allocation, copy, and map/unmap operations.
class ID3d11ExtractionHooks
{
public:
    virtual ~ID3d11ExtractionHooks() = default;

    virtual HRESULT CreateStagingTexture(
        ID3D11Device* device,
        const D3D11_TEXTURE2D_DESC& desc,
        ID3D11Texture2D** outTexture
        ) noexcept;

    virtual HRESULT CopyTextureResource(
        ID3D11DeviceContext* context,
        ID3D11Texture2D* dstStaging,
        ID3D11Texture2D* srcTexture
        ) noexcept;

    virtual HRESULT MapStagingTexture(
        ID3D11DeviceContext* context,
        ID3D11Texture2D* staging,
        D3D11_MAPPED_SUBRESOURCE& outMapped
        ) noexcept;

    virtual void UnmapStagingTexture(
        ID3D11DeviceContext* context,
        ID3D11Texture2D* staging
        ) noexcept;
};

/// Extracts tightly-packed CPU-readable pixel frames from acquired D3D11 swapchain textures
/// via a cached D3D11_USAGE_STAGING texture, releasing all references to the source texture
/// before returning or mapping CPU memory.
class D3d11FrameExtractor final
{
public:
    D3d11FrameExtractor() noexcept = default;
    ~D3d11FrameExtractor() = default;

    D3d11FrameExtractor(const D3d11FrameExtractor&) = delete;
    D3d11FrameExtractor& operator=(const D3d11FrameExtractor&) = delete;

    /// Binds the D3D11 device and immediate context used for staging allocation and copies.
    void SetDevice(
        ID3D11Device* device,
        ID3D11DeviceContext* context
        ) noexcept;

    /// Sets custom D3D11 operation hooks for fault injection; passes nullptr to restore real D3D11 hooks.
    void SetHooks(
        ID3d11ExtractionHooks* hooks
        ) noexcept;

    /// Releases cached staging texture and device references.
    void Reset() noexcept;

    /// Validates, copies, maps, and tightly packs pixels from the acquired surface into outFrame.
    FrameExtractionResult ExtractFrame(
        const FrameExtractionInput& input,
        ExtractedFrameBuffer& outFrame
        ) noexcept;

private:
    static bool IsDeviceRemovedOrResetHResult(HRESULT hr) noexcept;

    ID3d11ExtractionHooks m_defaultHooks{};
    ID3d11ExtractionHooks* m_hooks{&m_defaultHooks};

    Microsoft::WRL::ComPtr<ID3D11Device> m_d3dDevice{};
    Microsoft::WRL::ComPtr<ID3D11DeviceContext> m_d3dContext{};
    Microsoft::WRL::ComPtr<ID3D11Texture2D> m_stagingTexture{};

    uint32_t m_stagingWidth{0U};
    uint32_t m_stagingHeight{0U};
    DXGI_FORMAT m_stagingFormat{DXGI_FORMAT_UNKNOWN};
    volatile LONG64 m_sequenceCounter{0};
};

} // namespace lumabridge::driver
