#pragma once

#include "SwapChainProcessor.h"
#include "FrameExtractor.h"
#include "FrameIpcProtocol.h"

#include <d3d11.h>
#include <dxgi1_2.h>
#include <wrl/client.h>

#include <cstddef>
#include <cstdint>

namespace lumabridge::driver {

enum class SharedTextureSlotState : uint32_t
{
    Free = 0,
    InProducerCopy = 1,
    QueuedForIpc = 2,
    InUseByHost = 3,
};

struct SharedTexturePoolMetricsSnapshot
{
    uint32_t PoolSize{0U};
    uint32_t PeakUsage{0U};
    uint32_t FreeSlots{0U};
    uint32_t QueuedSlots{0U};
    uint32_t InUseByHostSlots{0U};
    uint64_t GpuFramesShared{0ULL};
    uint64_t GpuFramesDropped{0ULL};
    uint64_t GpuSyncTimeouts{0ULL};
    uint64_t GpuResourceRecreations{0ULL};
    uint64_t GpuCopyFailures{0ULL};
    uint64_t HandleCreateFailures{0ULL};
    uint64_t LastGpuSyncWaitUs{0ULL};
    uint64_t TotalGpuSyncWaitUs{0ULL};
    uint64_t AvgGpuSyncWaitUs{0ULL};
    uint64_t MaxGpuSyncWaitUs{0ULL};
    uint64_t LastProducerSlotWaitUs{0ULL};
    uint64_t TotalProducerSlotWaitUs{0ULL};
    uint64_t AvgProducerSlotWaitUs{0ULL};
    uint64_t MaxProducerSlotWaitUs{0ULL};
    HRESULT LastGpuError{S_OK};
};

struct SharedTextureExtractResult
{
    HRESULT HResult{E_FAIL};
    bool SurfaceValid{false};
    bool AcceptedForExtraction{false};
    bool ProtectedContentRejected{false};
    bool GpuCopied{false};
    bool DeviceRemovedOrReset{false};
    bool SlotRecreated{false};
    bool PoolExhausted{false};
    uint32_t SlotIndex{0U};
    uint32_t SlotGeneration{0U};
    uint32_t Width{0U};
    uint32_t Height{0U};
    uint32_t Format{0U};
    uint64_t FrameSequence{0ULL};
    uint64_t ProducerSlotAndMutexWaitUs{0ULL};
    uint64_t GpuCopyLatencyUs{0ULL};
};

/// Testability seam for D3D11 shared resource creation, NT handle generation, KeyedMutex sync, and GPU CopyResource.
class ID3d11SharedTextureHooks
{
public:
    virtual ~ID3d11SharedTextureHooks() = default;

    virtual HRESULT CreateSharedTexture(
        ID3D11Device* device,
        const D3D11_TEXTURE2D_DESC& desc,
        ID3D11Texture2D** outTexture
        ) noexcept;

    virtual HRESULT CreateSharedNtHandle(
        ID3D11Texture2D* texture,
        const SECURITY_ATTRIBUTES* securityAttributes,
        DWORD accessMask,
        HANDLE* outHandle
        ) noexcept;

    virtual HRESULT AcquireKeyedMutex(
        IDXGIKeyedMutex* keyedMutex,
        UINT64 key,
        DWORD timeoutMs
        ) noexcept;

    virtual HRESULT ReleaseKeyedMutex(
        IDXGIKeyedMutex* keyedMutex,
        UINT64 key
        ) noexcept;

    virtual HRESULT CopyTextureResource(
        ID3D11DeviceContext* context,
        ID3D11Texture2D* dstSharedTexture,
        ID3D11Texture2D* srcTexture
        ) noexcept;
};

/// Fixed-capacity D3D11 shared texture pool using NT handles + IDXGIKeyedMutex for zero-CPU-pixel cross-process sharing.
/// Lock ordering: m_poolLock is a leaf lock (never held across IPC I/O or external callbacks).
class D3d11SharedTexturePool final
{
public:
    D3d11SharedTexturePool() noexcept = default;
    ~D3d11SharedTexturePool();

    D3d11SharedTexturePool(const D3d11SharedTexturePool&) = delete;
    D3d11SharedTexturePool& operator=(const D3d11SharedTexturePool&) = delete;

    /// Initializes the pool capacity, security DACL policy, and sequence state.
    HRESULT Configure(
        size_t poolSize = ipc::kDefaultSharedTexturePoolSize,
        const wchar_t* authorizedUserSid = nullptr,
        bool restrictDaclToAuthorizedSid = false,
        bool allowSameUserAccess = true,
        bool allowBuiltinAdmins = true,
        bool allowActiveConsoleInteractiveUser = true,
        DWORD producerMutexTimeoutMs = 10U
        ) noexcept;

    /// Binds the D3D11 device, context, and AdapterLuid; releases stale textures if the device changed.
    void SetDevice(
        ID3D11Device* device,
        ID3D11DeviceContext* context,
        LUID adapterLuid
        ) noexcept;

    /// Installs custom hooks for deterministic fault injection; pass nullptr to restore defaults.
    void SetHooks(
        ID3d11SharedTextureHooks* hooks
        ) noexcept;

    /// Releases all GPU textures, keyed mutexes, and NT shared handles.
    void ResetResources() noexcept;

    /// Releases resources and resets configuration.
    void Shutdown() noexcept;

    /// Acquires a free shared slot (or fails non-blockingly when full), ensures matching D3D11 shared texture,
    /// copies the source IddCx texture directly on the GPU, releases source COM refs immediately, and releases
    /// IDXGIKeyedMutex to key=1 (consumer ready) without reading any pixels to CPU RAM.
    SharedTextureExtractResult ExtractToSharedTexture(
        const FrameExtractionInput& input,
        ExtractedFrameBuffer& outFrameMetadata,
        bool allowPoolSlotAcquire = true
        ) noexcept;

    /// Marks a queued slot as actively held by the IPC worker / consumer and retrieves its NT handle + metadata.
    bool BeginHostUseForSlot(
        uint32_t slotIndex,
        uint32_t slotGeneration,
        HANDLE& outSharedNtHandle,
        LUID& outAdapterLuid
        ) noexcept;

    /// Marks a queued slot as evicted by queue backpressure and returns it to Free state.
    void ReleaseQueuedSlot(
        uint32_t slotIndex,
        uint32_t slotGeneration,
        bool countAsDrop = true
        ) noexcept;

    /// Returns a slot still held in InProducerCopy (e.g. if EnqueueFrame is skipped/aborted) to Free state.
    void CancelProducerCopySlot(
        uint32_t slotIndex,
        uint32_t slotGeneration,
        bool needsRecreate = true
        ) noexcept;

    /// Completes consumer usage after FrameAck (either cleanly returning slot to Free with mutexKey=0
    /// or retiring/marking NeedsRecreate on timeout, error, or disconnect so next producer use recreates cleanly).
    void CompleteHostUseForSlot(
        uint32_t slotIndex,
        uint32_t slotGeneration,
        bool cleanReleaseToProducer,
        uint32_t consumerGpuSyncWaitUs = 0U
        ) noexcept;

    /// Returns the number of configured pool slots.
    size_t GetPoolSize() const noexcept;

    /// Returns the currently bound AdapterLuid.
    LUID GetAdapterLuid() const noexcept;

    /// Returns a thread-safe snapshot of GPU shared texture pool metrics.
    SharedTexturePoolMetricsSnapshot GetMetricsSnapshot() const noexcept;

private:
    struct SharedTextureSlot
    {
        uint32_t SlotIndex{0U};
        uint32_t Generation{0U};
        SharedTextureSlotState State{SharedTextureSlotState::Free};
        bool NeedsRecreate{false};
        uint64_t CurrentMutexKey{ipc::kSharedTextureProducerMutexKey};
        uint32_t Width{0U};
        uint32_t Height{0U};
        DXGI_FORMAT Format{DXGI_FORMAT_UNKNOWN};
        Microsoft::WRL::ComPtr<ID3D11Texture2D> Texture{};
        Microsoft::WRL::ComPtr<IDXGIKeyedMutex> KeyedMutex{};
        ScopedWin32Handle SharedNtHandle{};

        void ReleaseGpuObjects() noexcept
        {
            KeyedMutex.Reset();
            Texture.Reset();
            SharedNtHandle.Reset();
            Width = 0U;
            Height = 0U;
            Format = DXGI_FORMAT_UNKNOWN;
            CurrentMutexKey = ipc::kSharedTextureProducerMutexKey;
            NeedsRecreate = false;
        }
    };

    static bool IsDeviceRemovedOrResetHResult(HRESULT hr) noexcept;
    HRESULT EnsureSlotTextureLocked(
        SharedTextureSlot& slot,
        uint32_t width,
        uint32_t height,
        DXGI_FORMAT format,
        bool& outRecreated
        ) noexcept;
    HRESULT BuildSharedHandleSecurityDescriptor(
        PSECURITY_DESCRIPTOR& outSd
        ) const noexcept;
    void UpdateUsageMetricsLocked() noexcept;

    mutable SRWLOCK m_poolLock{SRWLOCK_INIT};
    ID3d11SharedTextureHooks m_defaultHooks{};
    ID3d11SharedTextureHooks* m_hooks{&m_defaultHooks};

    Microsoft::WRL::ComPtr<ID3D11Device> m_d3dDevice{};
    Microsoft::WRL::ComPtr<ID3D11DeviceContext> m_d3dContext{};
    LUID m_adapterLuid{0, 0};

    size_t m_poolSize{0U};
    SharedTextureSlot m_slots[ipc::kMaxSharedTexturePoolSize]{};
    DWORD m_producerMutexTimeoutMs{10U};

    wchar_t m_authorizedUserSid[128]{};
    bool m_restrictDaclToAuthorizedSid{false};
    bool m_allowSameUserAccess{true};
    bool m_allowBuiltinAdmins{true};
    bool m_allowActiveConsoleInteractiveUser{true};

    volatile LONG64 m_sequenceCounter{0};
    SharedTexturePoolMetricsSnapshot m_metrics{};
};

} // namespace lumabridge::driver
