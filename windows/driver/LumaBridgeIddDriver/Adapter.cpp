#include "Adapter.h"
#include "FrameExtractor.h"
#include "FrameTransport.h"
#include "SharedTexturePool.h"

#include <d3d11.h>
#include <dxgi1_4.h>
#include <psapi.h>
#include <wrl/client.h>

#include <memory>
#include <new>

using Microsoft::WRL::ComPtr;
using lumabridge::driver::AdapterLifecycleState;
using lumabridge::driver::D0EntryAction;
using lumabridge::driver::DriverDiagnosticStage;
using lumabridge::driver::LumaBridgeTraceError;
using lumabridge::driver::LumaBridgeTraceInfo;
using lumabridge::driver::LumaBridgeTraceMetrics;
using lumabridge::driver::LumaBridgeTraceWarn;

namespace lumabridge::driver {

namespace {

uint64_t
QueryAdapterQpcNow() noexcept
{
    LARGE_INTEGER li{};
    (void)QueryPerformanceCounter(&li);
    return (li.QuadPart > 0) ? static_cast<uint64_t>(li.QuadPart) : 0ULL;
}

uint64_t
QueryAdapterQpcFreqSafe() noexcept
{
    LARGE_INTEGER li{};
    (void)QueryPerformanceFrequency(&li);
    return (li.QuadPart > 0) ? static_cast<uint64_t>(li.QuadPart) : 10000000ULL;
}

} // namespace

/// D3D11/DXGI/IddCx implementation of ISwapChainBackend for UMDF runtime execution.
class D3d11IddCxSwapChainBackend final : public ISwapChainBackend
{
public:
    ~D3d11IddCxSwapChainBackend() override
    {
        ShutdownTransport();
    }

    void SetAuthorizedHostUserSid(const wchar_t* sidString) noexcept
    {
        bool sidChangedWhileRunning = false;
        FrameTransportConfig updatedConfig{};
        {
            ExclusiveLockGuard deviceGuard(&m_deviceLock);
            wchar_t normalized[128]{};
            if (sidString != nullptr && sidString[0] != L'\0')
            {
                (void)wcsncpy_s(normalized, ARRAYSIZE(normalized), sidString, _TRUNCATE);
            }

            if (wcscmp(m_authorizedHostUserSid, normalized) != 0)
            {
                (void)wcsncpy_s(m_authorizedHostUserSid, ARRAYSIZE(m_authorizedHostUserSid), normalized, _TRUNCATE);
                if (m_boundSwapChainHandle != nullptr &&
                    InterlockedCompareExchange(&m_frameExtractionEnabled, 0, 0) != 0 &&
                    m_ipcServer.IsRunning())
                {
                    sidChangedWhileRunning = true;
                    updatedConfig = BuildTransportConfigLocked(m_activeRenderAdapterLuid);
                }
            }
        }

        if (sidChangedWhileRunning)
        {
            m_ipcServer.Stop();
            {
                ExclusiveLockGuard deviceGuard(&m_deviceLock);
                ConfigureSharedPoolLocked();
            }
            (void)m_ipcServer.Start(updatedConfig);
        }
        else
        {
            ExclusiveLockGuard deviceGuard(&m_deviceLock);
            ConfigureSharedPoolLocked();
        }
    }

    void SetFrameExtractionEnabled(bool enabled) noexcept
    {
        const bool wasEnabled = (InterlockedExchange(&m_frameExtractionEnabled, enabled ? 1 : 0) != 0);
        if (!enabled)
        {
            if (wasEnabled || m_ipcServer.IsRunning())
            {
                m_ipcServer.Stop();
            }
            return;
        }

        bool hasBoundSwapChain = false;
        FrameTransportConfig transportConfig{};
        {
            ExclusiveLockGuard deviceGuard(&m_deviceLock);
            hasBoundSwapChain = (m_boundSwapChainHandle != nullptr);
            if (hasBoundSwapChain)
            {
                transportConfig = BuildTransportConfigLocked(m_activeRenderAdapterLuid);
            }
        }

        if (hasBoundSwapChain && !m_ipcServer.IsRunning())
        {
            (void)m_ipcServer.Start(transportConfig);
        }
    }

    void SetGpuSharedTransportEnabled(bool enabled) noexcept
    {
        const bool prev = (InterlockedExchange(&m_gpuSharedTransportEnabled, enabled ? 1 : 0) != 0);
        if (prev != enabled && m_ipcServer.IsRunning())
        {
            FrameTransportConfig updatedConfig{};
            bool shouldRestart = false;
            {
                ExclusiveLockGuard deviceGuard(&m_deviceLock);
                if (m_boundSwapChainHandle != nullptr &&
                    InterlockedCompareExchange(&m_frameExtractionEnabled, 0, 0) != 0)
                {
                    shouldRestart = true;
                    updatedConfig = BuildTransportConfigLocked(m_activeRenderAdapterLuid);
                }
            }
            if (shouldRestart)
            {
                m_ipcServer.Stop();
                (void)m_ipcServer.Start(updatedConfig);
            }
        }
    }

    void ShutdownTransport() noexcept
    {
        m_ipcServer.Stop();
        ExclusiveLockGuard deviceGuard(&m_deviceLock);
        m_extractor.Reset();
        m_sharedTexturePool.Shutdown();
    }

    HRESULT InitializeDeviceAndBindSwapChain(
        void* swapChainHandle,
        LUID renderAdapterLuid
        ) noexcept override
    {
        if (swapChainHandle == nullptr)
        {
            return E_INVALIDARG;
        }

        ComPtr<IDXGIFactory4> dxgiFactory;
        HRESULT hr = CreateDXGIFactory1(IID_PPV_ARGS(&dxgiFactory));
        if (FAILED(hr))
        {
            return hr;
        }

        ComPtr<IDXGIAdapter1> dxgiAdapter;
        hr = dxgiFactory->EnumAdapterByLuid(renderAdapterLuid, IID_PPV_ARGS(&dxgiAdapter));
        if (FAILED(hr))
        {
            return hr;
        }

        static constexpr D3D_FEATURE_LEVEL kFeatureLevels[] = {
            D3D_FEATURE_LEVEL_11_1,
            D3D_FEATURE_LEVEL_11_0,
            D3D_FEATURE_LEVEL_10_1,
            D3D_FEATURE_LEVEL_10_0};

        ComPtr<ID3D11Device> d3dDevice;
        ComPtr<ID3D11DeviceContext> d3dContext;
        D3D_FEATURE_LEVEL selectedLevel = D3D_FEATURE_LEVEL_11_0;
        hr = D3D11CreateDevice(
            dxgiAdapter.Get(),
            D3D_DRIVER_TYPE_UNKNOWN,
            nullptr,
            D3D11_CREATE_DEVICE_BGRA_SUPPORT,
            kFeatureLevels,
            ARRAYSIZE(kFeatureLevels),
            D3D11_SDK_VERSION,
            &d3dDevice,
            &selectedLevel,
            &d3dContext);
        if (FAILED(hr))
        {
            return hr;
        }

        ComPtr<IDXGIDevice> dxgiDevice;
        hr = d3dDevice.As(&dxgiDevice);
        if (FAILED(hr))
        {
            return hr;
        }

        IDARG_IN_SWAPCHAINSETDEVICE setDeviceArgs{};
        setDeviceArgs.pDevice = dxgiDevice.Get();
        hr = IddCxSwapChainSetDevice(
            static_cast<IDDCX_SWAPCHAIN>(swapChainHandle),
            &setDeviceArgs);
        if (FAILED(hr))
        {
            return hr;
        }

        bool shouldStartIpc = false;
        FrameTransportConfig transportConfig{};
        {
            ExclusiveLockGuard deviceGuard(&m_deviceLock);
            m_boundSwapChainHandle = swapChainHandle;
            m_activeRenderAdapterLuid = renderAdapterLuid;
            m_lastCausalPresentQpc = 0ULL;
            m_d3dDevice = d3dDevice;
            m_d3dContext = d3dContext;
            m_extractor.SetDevice(d3dDevice.Get(), d3dContext.Get());
            ConfigureSharedPoolLocked();
            m_sharedTexturePool.SetDevice(d3dDevice.Get(), d3dContext.Get(), renderAdapterLuid);
            if (InterlockedCompareExchange(&m_frameExtractionEnabled, 0, 0) != 0)
            {
                shouldStartIpc = true;
                transportConfig = BuildTransportConfigLocked(renderAdapterLuid);
            }
        }

        if (shouldStartIpc && !m_ipcServer.IsRunning())
        {
            (void)m_ipcServer.Start(transportConfig);
        }
        return S_OK;
    }

    HRESULT ReleaseAndAcquireBuffer(
        void* swapChainHandle,
        SwapChainFrameMetadata& outMetadata
        ) noexcept override
    {
        outMetadata = {};
        if (swapChainHandle == nullptr)
        {
            return E_INVALIDARG;
        }

        IDARG_OUT_RELEASEANDACQUIREBUFFER bufferOut{};
        const HRESULT hr = IddCxSwapChainReleaseAndAcquireBuffer(
            static_cast<IDDCX_SWAPCHAIN>(swapChainHandle),
            &bufferOut);
        if (FAILED(hr))
        {
            return hr;
        }

        // Capture causal acquisition QPC immediately on buffer acquire.
        // Note: WDK IDDCX_METADATA::PresentDisplayQPCTime is the target VSync time when
        // DWM expects the surface to scan out (often ahead of acquisition), so treat
        // future or stale static-desktop targets cleanly with a monotonic causal QPC.
        const uint64_t acquireQpc = QueryAdapterQpcNow();
        const uint64_t qpcFreq = QueryAdapterQpcFreqSafe();
        const uint64_t rawPresentQpc = bufferOut.MetaData.PresentDisplayQPCTime;

        // Adopt the OS-AddRef'd surface pointer without adding an extra COM reference so
        // ComPtr releases it automatically before the next acquire or frame completion.
        ComPtr<IDXGIResource> surface;
        surface.Attach(bufferOut.MetaData.pSurface);

        ComPtr<ID3D11Texture2D> texture;
        bool hasValidSurface = false;
        if (surface != nullptr)
        {
            if (SUCCEEDED(surface.As(&texture)) && texture != nullptr)
            {
                D3D11_TEXTURE2D_DESC desc{};
                texture->GetDesc(&desc);
                hasValidSurface = (desc.Width > 0 && desc.Height > 0);
            }
            surface.Reset();
        }

        uint64_t causalPresentQpc = acquireQpc;
        {
            ExclusiveLockGuard deviceGuard(&m_deviceLock);
            const uint64_t maxPastWindowTicks = qpcFreq / 20ULL; // 50 ms
            if (rawPresentQpc > 0ULL &&
                rawPresentQpc <= acquireQpc &&
                (acquireQpc - rawPresentQpc) <= maxPastWindowTicks &&
                rawPresentQpc >= m_lastCausalPresentQpc)
            {
                causalPresentQpc = rawPresentQpc;
            }
            else if (acquireQpc < m_lastCausalPresentQpc)
            {
                causalPresentQpc = m_lastCausalPresentQpc;
            }
            m_lastCausalPresentQpc = causalPresentQpc;
        }

        outMetadata.PresentationFrameNumber = bufferOut.MetaData.PresentationFrameNumber;
        outMetadata.DirtyRectCount = bufferOut.MetaData.DirtyRectCount;
        outMetadata.MoveRegionCount = bufferOut.MetaData.MoveRegionCount;
        outMetadata.HwProtectedSurface = (bufferOut.MetaData.HwProtectedSurface != FALSE);
        outMetadata.PresentDisplayQPCTime = causalPresentQpc;
        outMetadata.RawIddCxPresentDisplayQPCTime = rawPresentQpc;
        outMetadata.SwapChainAcquireQpcTime = acquireQpc;
        outMetadata.PresentDisplayQpcWasFutureTarget = (rawPresentQpc > acquireQpc);
        outMetadata.HasValidSurface = hasValidSurface;

        if (InterlockedCompareExchange(&m_frameExtractionEnabled, 0, 0) != 0 && hasValidSurface)
        {
            std::unique_ptr<ExtractedFrameBuffer> slot = m_ipcServer.AcquireBufferSlot();
            if (slot == nullptr)
            {
                outMetadata.ExtractionAttempted = true;
                texture.Reset();
                outMetadata.ExtractionHResult = E_OUTOFMEMORY;
                return S_OK;
            }

            const bool useGpuShared = m_ipcServer.ShouldProduceGpuSharedFrame();
            if (useGpuShared)
            {
                SharedTextureExtractResult gpuResult{};
                bool extractionPerformed = false;
                {
                    ExclusiveLockGuard deviceGuard(&m_deviceLock);
                    if (InterlockedCompareExchange(&m_frameExtractionEnabled, 0, 0) != 0 &&
                        m_boundSwapChainHandle == swapChainHandle)
                    {
                        extractionPerformed = true;
                        FrameExtractionInput input{};
                        input.AdoptSourceTexture = texture.Detach();
                        input.PresentationFrameNumber = outMetadata.PresentationFrameNumber;
                        input.DirtyRectCount = outMetadata.DirtyRectCount;
                        input.MoveRegionCount = outMetadata.MoveRegionCount;
                        input.HwProtectedSurface = outMetadata.HwProtectedSurface;
                        input.PresentDisplayQpcTime = outMetadata.PresentDisplayQPCTime;
                        input.Flags = static_cast<uint32_t>(ipc::FrameIpcFlags::None);

                        gpuResult = m_sharedTexturePool.ExtractToSharedTexture(input, *slot, true);
                    }
                    texture.Reset();
                }

                if (!extractionPerformed)
                {
                    m_ipcServer.RecycleBufferSlot(std::move(slot));
                    return S_OK;
                }

                outMetadata.ExtractionAttempted = true;
                outMetadata.ExtractionAccepted = gpuResult.AcceptedForExtraction;
                outMetadata.PixelsCopied = gpuResult.GpuCopied;
                outMetadata.ProtectedContentRejected = gpuResult.ProtectedContentRejected;
                outMetadata.ExtractedWidth = gpuResult.Width;
                outMetadata.ExtractedHeight = gpuResult.Height;
                outMetadata.ExtractedFormat = gpuResult.Format;
                outMetadata.FrameSequence = gpuResult.FrameSequence;
                outMetadata.CopyLatencyUs = gpuResult.GpuCopyLatencyUs;
                outMetadata.ExtractionHResult = gpuResult.HResult;

                if (gpuResult.DeviceRemovedOrReset)
                {
                    m_ipcServer.RecycleBufferSlot(std::move(slot));
                    return gpuResult.HResult;
                }

                if (gpuResult.GpuCopied)
                {
                    bool evictedOldest = false;
                    const HRESULT enqueueHr = m_ipcServer.EnqueueFrame(std::move(slot), evictedOldest);
                    outMetadata.EvictedOldestByBackpressure = evictedOldest;
                    if (FAILED(enqueueHr))
                    {
                        outMetadata.ExtractionHResult = enqueueHr;
                    }
                }
                else
                {
                    m_ipcServer.RecycleBufferSlot(std::move(slot));
                }
                return S_OK;
            }

            FrameExtractionResult extractResult{};
            bool extractionPerformed = false;
            {
                ExclusiveLockGuard deviceGuard(&m_deviceLock);
                if (InterlockedCompareExchange(&m_frameExtractionEnabled, 0, 0) != 0 &&
                    m_boundSwapChainHandle == swapChainHandle)
                {
                    extractionPerformed = true;
                    FrameExtractionInput input{};
                    input.AdoptSourceTexture = texture.Detach();
                    input.PresentationFrameNumber = outMetadata.PresentationFrameNumber;
                    input.DirtyRectCount = outMetadata.DirtyRectCount;
                    input.MoveRegionCount = outMetadata.MoveRegionCount;
                    input.HwProtectedSurface = outMetadata.HwProtectedSurface;
                    input.PresentDisplayQpcTime = outMetadata.PresentDisplayQPCTime;
                    input.Flags = static_cast<uint32_t>(ipc::FrameIpcFlags::None);

                    extractResult = m_extractor.ExtractFrame(input, *slot);
                }
                texture.Reset();
            }

            if (!extractionPerformed)
            {
                m_ipcServer.RecycleBufferSlot(std::move(slot));
                return S_OK;
            }

            outMetadata.ExtractionAttempted = true;
            outMetadata.ExtractionAccepted = extractResult.AcceptedForExtraction;
            outMetadata.PixelsCopied = extractResult.PixelsCopied;
            outMetadata.ProtectedContentRejected = extractResult.ProtectedContentRejected;
            outMetadata.ExtractedWidth = extractResult.Width;
            outMetadata.ExtractedHeight = extractResult.Height;
            outMetadata.ExtractedFormat = extractResult.Format;
            outMetadata.FrameSequence = extractResult.FrameSequence;
            outMetadata.CopyLatencyUs = extractResult.CopyLatencyUs;
            outMetadata.ExtractionHResult = extractResult.HResult;

            if (extractResult.DeviceRemovedOrReset)
            {
                m_ipcServer.RecycleBufferSlot(std::move(slot));
                return extractResult.HResult;
            }

            if (extractResult.PixelsCopied)
            {
                bool evictedOldest = false;
                const HRESULT enqueueHr = m_ipcServer.EnqueueFrame(std::move(slot), evictedOldest);
                outMetadata.EvictedOldestByBackpressure = evictedOldest;
                if (FAILED(enqueueHr))
                {
                    outMetadata.ExtractionHResult = enqueueHr;
                }
            }
            else
            {
                m_ipcServer.RecycleBufferSlot(std::move(slot));
            }
        }
        else
        {
            texture.Reset();
        }
        return S_OK;
    }

    HRESULT FinishProcessingFrame(
        void* swapChainHandle
        ) noexcept override
    {
        if (swapChainHandle == nullptr)
        {
            return E_INVALIDARG;
        }

        return IddCxSwapChainFinishedProcessingFrame(
            static_cast<IDDCX_SWAPCHAIN>(swapChainHandle));
    }

    void DeleteSwapChainObject(
        void* swapChainHandle
        ) noexcept override
    {
        {
            ExclusiveLockGuard deviceGuard(&m_deviceLock);
            if (m_boundSwapChainHandle == swapChainHandle)
            {
                m_boundSwapChainHandle = nullptr;
                m_activeRenderAdapterLuid = LUID{0, 0};
                m_lastCausalPresentQpc = 0ULL;
                m_extractor.Reset();
                m_sharedTexturePool.ResetResources();
                m_d3dContext.Reset();
                m_d3dDevice.Reset();
            }
        }
        m_ipcServer.FlushQueue();
        if (swapChainHandle != nullptr)
        {
            WdfObjectDelete(static_cast<IDDCX_SWAPCHAIN>(swapChainHandle));
        }
    }

    void QueryFrameTransportMetrics(
        SwapChainMetricsSnapshot& inoutSnapshot
        ) const noexcept override
    {
        inoutSnapshot.FrameExtractionEnabled =
            (InterlockedCompareExchange(const_cast<volatile LONG*>(&m_frameExtractionEnabled), 0, 0) != 0);
        const FrameTransportMetricsSnapshot ipcSnap = m_ipcServer.GetMetricsSnapshot();
        inoutSnapshot.FramesDelivered = ipcSnap.FramesDelivered;
        inoutSnapshot.FramesDroppedByBackpressure = ipcSnap.FramesDroppedByBackpressure;
        inoutSnapshot.FrameTransportFailures = ipcSnap.FrameTransportFailures;
        inoutSnapshot.ActiveHostConnections = ipcSnap.ActiveHostConnections;
        inoutSnapshot.FrameDeliveryLatencyUs = ipcSnap.LastDeliveryLatencyUs;
        inoutSnapshot.AvgFrameDeliveryLatencyUs = ipcSnap.AvgDeliveryLatencyUs;
        inoutSnapshot.MaxFrameDeliveryLatencyUs = ipcSnap.MaxDeliveryLatencyUs;
        inoutSnapshot.QueueDepth = ipcSnap.QueueDepth;
        inoutSnapshot.PeakQueueDepth = ipcSnap.PeakQueueDepth;
        inoutSnapshot.LastTransportError = ipcSnap.LastTransportError;
        inoutSnapshot.GpuSharedTransportEnabled = ipcSnap.GpuSharedTransportConfigured;
        inoutSnapshot.SharedTexturePoolSize = ipcSnap.SharedTexturePoolSize;
        inoutSnapshot.SharedTexturePoolPeakUsage = ipcSnap.SharedTexturePoolPeakUsage;
        inoutSnapshot.GpuFramesShared = ipcSnap.GpuFramesShared;
        inoutSnapshot.GpuFramesDropped = ipcSnap.GpuFramesDropped;
        inoutSnapshot.GpuSyncTimeouts = ipcSnap.GpuSyncTimeouts;
        inoutSnapshot.GpuSyncWaitUs = ipcSnap.LastGpuSyncWaitUs;
    }

private:
    class ExclusiveLockGuard final
    {
    public:
        explicit ExclusiveLockGuard(SRWLOCK* lock) noexcept
            : m_lock(lock)
        {
            if (m_lock != nullptr)
            {
                AcquireSRWLockExclusive(m_lock);
            }
        }

        ~ExclusiveLockGuard()
        {
            if (m_lock != nullptr)
            {
                ReleaseSRWLockExclusive(m_lock);
            }
        }

        ExclusiveLockGuard(const ExclusiveLockGuard&) = delete;
        ExclusiveLockGuard& operator=(const ExclusiveLockGuard&) = delete;

    private:
        SRWLOCK* m_lock;
    };

    FrameTransportConfig BuildTransportConfigLocked(LUID adapterLuid) const noexcept
    {
        FrameTransportConfig transportConfig{};
        transportConfig.AdapterLuid = adapterLuid;
        // WUDFHost.exe executes under LOCAL SERVICE; peer LOCAL SERVICE processes must not
        // implicitly consume virtual monitor frames.
        transportConfig.AllowSameUserAccess = false;
        transportConfig.EnableGpuSharedTransport =
            (InterlockedCompareExchange(const_cast<volatile LONG*>(&m_gpuSharedTransportEnabled), 0, 0) != 0);
        transportConfig.SharedTexturePool = const_cast<D3d11SharedTexturePool*>(&m_sharedTexturePool);
        if (m_authorizedHostUserSid[0] != L'\0')
        {
            transportConfig.SetAuthorizedUserSid(m_authorizedHostUserSid);
            transportConfig.RestrictDaclToAuthorizedSid = true;
        }
        return transportConfig;
    }

    void ConfigureSharedPoolLocked() noexcept
    {
        (void)m_sharedTexturePool.Configure(
            ipc::kDefaultSharedTexturePoolSize,
            (m_authorizedHostUserSid[0] != L'\0') ? m_authorizedHostUserSid : nullptr,
            m_authorizedHostUserSid[0] != L'\0',
            false,
            true,
            true,
            10U);
    }

    SRWLOCK m_deviceLock{SRWLOCK_INIT};
    volatile LONG m_frameExtractionEnabled{0};
    volatile LONG m_gpuSharedTransportEnabled{1};
    void* m_boundSwapChainHandle{nullptr};
    LUID m_activeRenderAdapterLuid{0, 0};
    uint64_t m_lastCausalPresentQpc{0ULL};
    wchar_t m_authorizedHostUserSid[128]{};
    ComPtr<ID3D11Device> m_d3dDevice;
    ComPtr<ID3D11DeviceContext> m_d3dContext;
    D3d11FrameExtractor m_extractor{};
    D3d11SharedTexturePool m_sharedTexturePool{};
    FrameIpcServer m_ipcServer{};
};

/// RAII guard for a transient WdfObjectReference/WdfObjectDereference pair.
class ScopedWdfObjectRef final
{
public:
    ScopedWdfObjectRef() noexcept = default;

    ScopedWdfObjectRef(
        WDFOBJECT object,
        bool addReference
        ) noexcept
        : m_object(object)
    {
        if (m_object != nullptr && addReference)
        {
            WdfObjectReference(m_object);
        }
    }

    ~ScopedWdfObjectRef()
    {
        Reset();
    }

    ScopedWdfObjectRef(const ScopedWdfObjectRef&) = delete;
    ScopedWdfObjectRef& operator=(const ScopedWdfObjectRef&) = delete;

    ScopedWdfObjectRef(ScopedWdfObjectRef&& other) noexcept
        : m_object(other.Release())
    {
    }

    ScopedWdfObjectRef& operator=(ScopedWdfObjectRef&& other) noexcept
    {
        if (this != &other)
        {
            Reset(other.Release());
        }
        return *this;
    }

    bool IsValid() const noexcept
    {
        return m_object != nullptr;
    }

    WDFOBJECT Get() const noexcept
    {
        return m_object;
    }

    WDFOBJECT Release() noexcept
    {
        WDFOBJECT detached = m_object;
        m_object = nullptr;
        return detached;
    }

    void Reset(WDFOBJECT newObject = nullptr) noexcept
    {
        if (m_object != nullptr && m_object != newObject)
        {
            WdfObjectDereference(m_object);
        }
        m_object = newObject;
    }

private:
    WDFOBJECT m_object{nullptr};
};

bool TryPinActiveDeviceForCreate(
    WDFDEVICE wdfDevice,
    ScopedWdfObjectRef& outPinnedDevice
    ) noexcept;

bool TryCommitCreatedMonitorObject(
    WDFDEVICE wdfDevice,
    IDDCX_MONITOR monitorObject,
    uint32_t connectorIndex
    ) noexcept;

/// IddCx implementation of IVirtualMonitorBackend for single-monitor MVP lifecycle.
class IddCxVirtualMonitorBackend final : public IVirtualMonitorBackend
{
public:
    IddCxVirtualMonitorBackend(
        WDFDEVICE wdfDevice,
        SwapChainProcessor* swapChainProcessor
        ) noexcept
        : m_wdfDevice(wdfDevice),
          m_swapChainProcessor(swapChainProcessor)
    {
    }

    NTSTATUS CreateMonitor(
        void* adapterHandle,
        uint32_t connectorIndex,
        const GUID& containerId,
        void*& outMonitorHandle
        ) noexcept override
    {
        outMonitorHandle = nullptr;
        if (adapterHandle == nullptr || m_wdfDevice == nullptr)
        {
            return STATUS_INVALID_PARAMETER;
        }

        ScopedWdfObjectRef devicePin;
        if (!TryPinActiveDeviceForCreate(m_wdfDevice, devicePin))
        {
            return STATUS_INVALID_DEVICE_STATE;
        }

        WDF_OBJECT_ATTRIBUTES monitorAttributes{};
        WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&monitorAttributes, LumaBridgeMonitorContext);
        monitorAttributes.EvtCleanupCallback = LumaBridgeEvtMonitorContextCleanup;

        IDDCX_MONITOR_INFO monitorInfo{};
        monitorInfo.Size = IDD_STRUCTURE_SIZE(IDDCX_MONITOR_INFO);
        monitorInfo.MonitorType = DISPLAYCONFIG_OUTPUT_TECHNOLOGY_INDIRECT_WIRED;
        monitorInfo.ConnectorIndex = connectorIndex;
        monitorInfo.MonitorContainerId = containerId;
        monitorInfo.MonitorDescription.Size = IDD_STRUCTURE_SIZE(IDDCX_MONITOR_DESCRIPTION);
        monitorInfo.MonitorDescription.Type = IDDCX_MONITOR_DESCRIPTION_TYPE_EDID;
        monitorInfo.MonitorDescription.DataSize = 0;
        monitorInfo.MonitorDescription.pData = nullptr;

        IDARG_IN_MONITORCREATE inArgs{};
        inArgs.ObjectAttributes = &monitorAttributes;
        inArgs.pMonitorInfo = &monitorInfo;

        IDARG_OUT_MONITORCREATE outArgs{};
        const NTSTATUS status = IddCxMonitorCreate(
            static_cast<IDDCX_ADAPTER>(adapterHandle),
            &inArgs,
            &outArgs);
        if (!NT_SUCCESS(status) || outArgs.MonitorObject == nullptr)
        {
            return NT_SUCCESS(status) ? STATUS_UNSUCCESSFUL : status;
        }

        if (!TryCommitCreatedMonitorObject(m_wdfDevice, outArgs.MonitorObject, connectorIndex))
        {
            WdfObjectDelete(outArgs.MonitorObject);
            return STATUS_INVALID_DEVICE_STATE;
        }

        outMonitorHandle = outArgs.MonitorObject;
        return STATUS_SUCCESS;
    }

    NTSTATUS ArriveMonitor(
        void* monitorHandle,
        LUID& outOsAdapterLuid,
        uint32_t& outOsTargetId
        ) noexcept override
    {
        outOsAdapterLuid = LUID{0, 0};
        outOsTargetId = 0;
        if (monitorHandle == nullptr)
        {
            return STATUS_INVALID_PARAMETER;
        }

        IDARG_OUT_MONITORARRIVAL outArgs{};
        const NTSTATUS status = IddCxMonitorArrival(
            static_cast<IDDCX_MONITOR>(monitorHandle),
            &outArgs);
        if (NT_SUCCESS(status))
        {
            outOsAdapterLuid = outArgs.OsAdapterLuid;
            outOsTargetId = outArgs.OsTargetId;
        }
        return status;
    }

    NTSTATUS DepartMonitor(
        void* monitorHandle
        ) noexcept override
    {
        if (monitorHandle == nullptr)
        {
            return STATUS_INVALID_PARAMETER;
        }

        return IddCxMonitorDeparture(static_cast<IDDCX_MONITOR>(monitorHandle));
    }

    void DeleteUnarrivedMonitorObject(
        void* monitorHandle
        ) noexcept override
    {
        if (monitorHandle != nullptr)
        {
            WdfObjectDelete(static_cast<IDDCX_MONITOR>(monitorHandle));
        }
    }

    void StopMonitorSwapChain(
        void* monitorHandle
        ) noexcept override
    {
        if (m_swapChainProcessor != nullptr && monitorHandle != nullptr)
        {
            (void)m_swapChainProcessor->UnassignSwapChainForMonitor(monitorHandle);
        }
    }

    void AcquireMonitorReference(
        void* monitorHandle
        ) noexcept override
    {
        if (monitorHandle != nullptr)
        {
            WdfObjectReference(static_cast<WDFOBJECT>(monitorHandle));
        }
    }

    void ReleaseMonitorReference(
        void* monitorHandle
        ) noexcept override
    {
        if (monitorHandle != nullptr)
        {
            WdfObjectDereference(static_cast<WDFOBJECT>(monitorHandle));
        }
    }

private:
    WDFDEVICE m_wdfDevice{nullptr};
    SwapChainProcessor* m_swapChainProcessor{nullptr};
};

volatile LONG g_NextDeviceInstanceIndex = 0;

/// Reference-counted per-WDFDEVICE swapchain and virtual monitor host safe across concurrent cleanup and callbacks.
struct DeviceSwapChainHost final
{
    DeviceSwapChainHost(
        WDFDEVICE wdfDevice,
        uint32_t deviceInstanceIndex
        ) noexcept
        : DeviceInstanceIndex(deviceInstanceIndex),
          MonitorBackend(wdfDevice, &Processor),
          MonitorManager(&MonitorBackend, deviceInstanceIndex)
    {
    }

    uint32_t DeviceInstanceIndex{0U};
    D3d11IddCxSwapChainBackend Backend{};
    SwapChainProcessor Processor{&Backend};
    IddCxVirtualMonitorBackend MonitorBackend;
    VirtualMonitorManager MonitorManager;
    volatile LONG RefCount{1};

    void AddRef() noexcept
    {
        InterlockedIncrement(&RefCount);
    }

    void Release() noexcept
    {
        if (InterlockedDecrement(&RefCount) == 0)
        {
            delete this;
        }
    }
};

void
EmitHostMetricsSnapshot(
    const DeviceSwapChainHost* host,
    DriverDiagnosticStage stage,
    AdapterLifecycleState adapterState
    ) noexcept
{
    if constexpr (!GetDiagnosticStageCapabilities(kActiveDiagnosticStage).EnableFullHostTelemetry)
    {
        UNREFERENCED_PARAMETER(host);
        UNREFERENCED_PARAMETER(stage);
        UNREFERENCED_PARAMETER(adapterState);
    }
    else
    {
        if (host == nullptr)
        {
            return;
        }

        const VirtualMonitorSnapshot mon = host->MonitorManager.GetSnapshot();
        const SwapChainMetricsSnapshot sc = host->Processor.GetMetricsSnapshot();

        PROCESS_MEMORY_COUNTERS pmc{};
        pmc.cb = sizeof(pmc);
        SIZE_T workingSetKb = 0;
        SIZE_T privateUsageKb = 0;
        if (K32GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc)) != FALSE)
        {
            workingSetKb = pmc.WorkingSetSize / 1024U;
            privateUsageKb = pmc.PagefileUsage / 1024U;
        }

        DWORD handleCount = 0;
        (void)GetProcessHandleCount(GetCurrentProcess(), &handleCount);

        LumaBridgeTraceMetrics(
            stage,
            adapterState,
            VirtualMonitorStateToString(mon.State),
            mon.CreateCount,
            mon.ArrivalCount,
            mon.DepartureCount,
            mon.DepartureFailures,
            SwapChainProcessorStateToString(sc.State),
            sc.IsActive,
            sc.AssignCount,
            sc.SwapChainDeletedCount,
            sc.FramesAcquired,
            sc.FramesProcessed,
            sc.FramesDropped,
            sc.AcquireFps,
            sc.ProcessFps,
            sc.LastFrameProcessingTimeUs,
            sc.AvgFrameProcessingTimeUs,
            sc.MaxFrameProcessingTimeUs,
            sc.DeviceRemovedErrors,
            sc.TransientErrors,
            sc.FatalErrors,
            workingSetKb,
            privateUsageKb,
            handleCount,
            sc.FrameExtractionEnabled,
            sc.FramesExtractionAccepted,
            sc.FramesCopied,
            sc.FramesDelivered,
            sc.FramesDroppedByBackpressure,
            sc.ProtectedFramesRejected,
            sc.FrameCopyFailures,
            sc.FrameTransportFailures,
            sc.ActiveHostConnections,
            sc.LastFrameSequence,
            sc.FrameCopyLatencyUs,
            sc.FrameDeliveryLatencyUs,
            sc.QueueDepth,
            sc.PeakQueueDepth,
            sc.LastExtractionError,
            sc.LastTransportError,
            sc.GpuFramesShared,
            sc.GpuFramesDropped,
            sc.GpuSyncWaitUs,
            sc.SharedTexturePoolSize,
            sc.SharedTexturePoolPeakUsage);
    }
}

} // namespace lumabridge::driver

namespace {

/// Serializes binding between IddCxAdapterInitAsync submission and EvtIddCxAdapterInitFinished
/// across multiple WDFDEVICE instances in the host process.
/// Lock ordering rule: always acquire g_AdapterInitGate before any DeviceContext::StateLock.
SRWLOCK g_AdapterInitGate = SRWLOCK_INIT;
CONDITION_VARIABLE g_AdapterInitSlotCv = CONDITION_VARIABLE_INIT;
lumabridge::driver::InFlightAdapterBindingSlot g_InFlightInitSlot{};

/// Deterministic RAII exclusive lock guard for SRWLOCK.
class ExclusiveLockGuard final
{
public:
    explicit ExclusiveLockGuard(SRWLOCK* lock) noexcept : m_lock(lock)
    {
        if (m_lock != nullptr)
        {
            AcquireSRWLockExclusive(m_lock);
        }
    }

    ~ExclusiveLockGuard()
    {
        if (m_lock != nullptr)
        {
            ReleaseSRWLockExclusive(m_lock);
        }
    }

    ExclusiveLockGuard(const ExclusiveLockGuard&) = delete;
    ExclusiveLockGuard& operator=(const ExclusiveLockGuard&) = delete;

private:
    SRWLOCK* m_lock;
};

/// Binds AdapterContext to its parent WDFDEVICE if EvtIddCxAdapterInitFinished arrives before
/// IddCxAdapterInitAsync returns to LumaBridgeStartAdapter. Requires g_AdapterInitGate held
/// without any DeviceContext::StateLock held.
WDFDEVICE
LumaBridgeBindAdapterAndResolveDeviceLocked(
    IDDCX_ADAPTER AdapterObject,
    WDFDEVICE ExplicitDevice
    ) noexcept
{
    auto* adapterContext = LumaBridgeGetAdapterContext(AdapterObject);
    if (adapterContext == nullptr || adapterContext->IsCleanedUp)
    {
        return nullptr;
    }

    if (adapterContext->AdapterObject == nullptr)
    {
        adapterContext->AdapterObject = AdapterObject;
    }

    if (adapterContext->WdfDevice == nullptr)
    {
        if (ExplicitDevice == nullptr &&
            g_InFlightInitSlot.InFlightDevice != nullptr &&
            g_InFlightInitSlot.InFlightDeviceCleanedUp &&
            !adapterContext->HasBoundDevice)
        {
            adapterContext->IsCleanedUp = true;
            adapterContext->HasBoundDevice = true;
            return nullptr;
        }

        const WDFDEVICE candidateDevice = static_cast<WDFDEVICE>(
            g_InFlightInitSlot.ResolveAdapterDevice(
                adapterContext->WdfDevice,
                adapterContext->HasBoundDevice || adapterContext->IsCleanedUp,
                ExplicitDevice));
        if (candidateDevice == nullptr)
        {
            return nullptr;
        }

        auto* candidateContext = LumaBridgeGetDeviceContext(candidateDevice);
        if (candidateContext == nullptr ||
            candidateContext->IsCleanedUp ||
            (candidateContext->AdapterObject != nullptr && candidateContext->AdapterObject != AdapterObject))
        {
            return nullptr;
        }

        adapterContext->WdfDevice = candidateDevice;
        adapterContext->HasBoundDevice = true;
        if (candidateContext->AdapterObject == nullptr)
        {
            candidateContext->AdapterObject = AdapterObject;
        }
        return candidateDevice;
    }

    auto* boundContext = LumaBridgeGetDeviceContext(adapterContext->WdfDevice);
    if (boundContext == nullptr || boundContext->IsCleanedUp)
    {
        adapterContext->WdfDevice = nullptr;
        adapterContext->IsCleanedUp = true;
        adapterContext->HasBoundDevice = true;
        return nullptr;
    }

    return adapterContext->WdfDevice;
}

class ScopedSwapChainHostRef final
{
public:
    ScopedSwapChainHostRef() noexcept = default;

    explicit ScopedSwapChainHostRef(lumabridge::driver::DeviceSwapChainHost* host) noexcept
        : m_host(host)
    {
    }

    ~ScopedSwapChainHostRef()
    {
        if (m_host != nullptr)
        {
            m_host->Release();
        }
    }

    ScopedSwapChainHostRef(const ScopedSwapChainHostRef&) = delete;
    ScopedSwapChainHostRef& operator=(const ScopedSwapChainHostRef&) = delete;

    ScopedSwapChainHostRef(ScopedSwapChainHostRef&& other) noexcept
        : m_host(other.m_host)
    {
        other.m_host = nullptr;
    }

    ScopedSwapChainHostRef& operator=(ScopedSwapChainHostRef&& other) noexcept
    {
        if (this != &other)
        {
            if (m_host != nullptr)
            {
                m_host->Release();
            }
            m_host = other.m_host;
            other.m_host = nullptr;
        }
        return *this;
    }

    lumabridge::driver::DeviceSwapChainHost* Get() const noexcept
    {
        return m_host;
    }

private:
    lumabridge::driver::DeviceSwapChainHost* m_host{nullptr};
};

ScopedSwapChainHostRef
AcquireSwapChainHostForDevice(
    WDFDEVICE Device,
    bool allowDuringCleanup = false
    ) noexcept
{
    if (Device == nullptr)
    {
        return {};
    }

    ExclusiveLockGuard gateLock(&g_AdapterInitGate);
    auto* deviceContext = LumaBridgeGetDeviceContext(Device);
    if (deviceContext == nullptr)
    {
        return {};
    }

    ExclusiveLockGuard stateLock(&deviceContext->StateLock);
    if (!allowDuringCleanup &&
        (deviceContext->IsCleanedUp || deviceContext->Lifecycle.IsCleanedUp))
    {
        return {};
    }

    if (deviceContext->SwapChainHost == nullptr)
    {
        return {};
    }

    deviceContext->SwapChainHost->AddRef();
    return ScopedSwapChainHostRef(deviceContext->SwapChainHost);
}

ScopedSwapChainHostRef
AcquireSwapChainHostForMonitor(
    IDDCX_MONITOR MonitorObject,
    bool allowDuringCleanup = false,
    lumabridge::driver::ScopedWdfObjectRef* outMonitorPin = nullptr,
    WDFDEVICE* outDevice = nullptr,
    lumabridge::driver::ScopedWdfObjectRef* outDevicePin = nullptr
    ) noexcept
{
    if (outDevice != nullptr)
    {
        *outDevice = nullptr;
    }
    if (outDevicePin != nullptr)
    {
        outDevicePin->Reset();
    }
    if (MonitorObject == nullptr)
    {
        return {};
    }

    WDFDEVICE device = nullptr;
    {
        ExclusiveLockGuard gateLock(&g_AdapterInitGate);
        auto* monitorContext = LumaBridgeGetMonitorContext(MonitorObject);
        if (monitorContext == nullptr ||
            (!allowDuringCleanup && monitorContext->IsCleanedUp) ||
            monitorContext->WdfDevice == nullptr)
        {
            return {};
        }
        device = monitorContext->WdfDevice;
        if (outMonitorPin != nullptr && !monitorContext->IsCleanedUp)
        {
            *outMonitorPin = lumabridge::driver::ScopedWdfObjectRef(
                static_cast<WDFOBJECT>(MonitorObject),
                true);
        }
    }

    ScopedSwapChainHostRef host = AcquireSwapChainHostForDevice(device, allowDuringCleanup);
    if (host.Get() != nullptr && outDevice != nullptr)
    {
        if (outDevicePin != nullptr)
        {
            if (lumabridge::driver::TryPinActiveDeviceForCreate(device, *outDevicePin))
            {
                *outDevice = device;
            }
        }
        else
        {
            *outDevice = device;
        }
    }
    return host;
}

bool
LumaBridgeQueryDeviceDwordFlag(
    WDFDEVICE Device,
    PCUNICODE_STRING ValueName,
    bool DefaultValue,
    bool FallbackToSubkey
    ) noexcept
{
    if (Device == nullptr || ValueName == nullptr)
    {
        return DefaultValue;
    }

    const ULONG flagsToTry[2] = {
        PLUGPLAY_REGKEY_DEVICE,
        PLUGPLAY_REGKEY_DEVICE | WDF_REGKEY_DEVICE_SUBKEY};
    const size_t attemptCount = FallbackToSubkey ? 2U : 1U;

    for (size_t i = 0U; i < attemptCount; ++i)
    {
        WDFKEY hardwareKey = nullptr;
        const NTSTATUS openStatus = WdfDeviceOpenRegistryKey(
            Device,
            flagsToTry[i],
            KEY_READ,
            WDF_NO_OBJECT_ATTRIBUTES,
            &hardwareKey);
        if (!NT_SUCCESS(openStatus) || hardwareKey == nullptr)
        {
            continue;
        }

        ULONG enableValue = 0;
        const NTSTATUS queryStatus = WdfRegistryQueryULong(hardwareKey, ValueName, &enableValue);
        WdfRegistryClose(hardwareKey);

        if (NT_SUCCESS(queryStatus))
        {
            return enableValue == 1UL;
        }
    }

    return DefaultValue;
}

bool
LumaBridgeQueryVirtualMonitorActivationEnabled(
    WDFDEVICE Device
    ) noexcept
{
    DECLARE_CONST_UNICODE_STRING(enableValueName, L"EnableVirtualMonitor");
    return LumaBridgeQueryDeviceDwordFlag(
        Device,
        &enableValueName,
        lumabridge::driver::kDefaultVirtualMonitorActivationEnabled,
        false);
}

bool
LumaBridgeQueryFrameExtractionEnabled(
    WDFDEVICE Device
    ) noexcept
{
    DECLARE_CONST_UNICODE_STRING(enableValueName, L"EnableFrameExtraction");
    return LumaBridgeQueryDeviceDwordFlag(
        Device,
        &enableValueName,
        lumabridge::driver::kDefaultFrameExtractionEnabled,
        true);
}

bool
LumaBridgeQueryAuthorizedHostUserSid(
    WDFDEVICE Device,
    wchar_t* outSidBuf,
    size_t outSidBufChars
    ) noexcept
{
    if (outSidBuf == nullptr || outSidBufChars == 0U)
    {
        return false;
    }
    outSidBuf[0] = L'\0';
    if (Device == nullptr || outSidBufChars < 2U)
    {
        return false;
    }

    DECLARE_CONST_UNICODE_STRING(sidValueName, L"AuthorizedHostUserSid");
    const ULONG flagsToTry[2] = {
        PLUGPLAY_REGKEY_DEVICE,
        PLUGPLAY_REGKEY_DEVICE | WDF_REGKEY_DEVICE_SUBKEY};

    for (size_t i = 0U; i < 2U; ++i)
    {
        WDFKEY hardwareKey = nullptr;
        const NTSTATUS openStatus = WdfDeviceOpenRegistryKey(
            Device,
            flagsToTry[i],
            KEY_READ,
            WDF_NO_OBJECT_ATTRIBUTES,
            &hardwareKey);
        if (!NT_SUCCESS(openStatus) || hardwareKey == nullptr)
        {
            continue;
        }

        UNICODE_STRING queryValue{};
        queryValue.Buffer = outSidBuf;
        queryValue.Length = 0U;
        queryValue.MaximumLength = static_cast<USHORT>((outSidBufChars - 1U) * sizeof(wchar_t));
        USHORT valueLength = 0U;
        const NTSTATUS queryStatus = WdfRegistryQueryUnicodeString(
            hardwareKey,
            &sidValueName,
            &valueLength,
            &queryValue);
        WdfRegistryClose(hardwareKey);

        if (NT_SUCCESS(queryStatus) && queryValue.Length > 0U)
        {
            const size_t charCount = static_cast<size_t>(queryValue.Length / sizeof(wchar_t));
            const size_t clampedChars = (charCount < outSidBufChars) ? charCount : (outSidBufChars - 1U);
            outSidBuf[clampedChars] = L'\0';
            if (outSidBuf[0] != L'\0')
            {
                return true;
            }
        }
        outSidBuf[0] = L'\0';
    }

    return false;
}

bool
LumaBridgeQueryGpuSharedTransportEnabled(
    WDFDEVICE Device
    ) noexcept
{
    DECLARE_CONST_UNICODE_STRING(gpuFlagName, L"EnableGpuSharedTransport");
    return LumaBridgeQueryDeviceDwordFlag(
        Device,
        &gpuFlagName,
        true,
        true);
}

void
LumaBridgeApplyFrameExtractionPolicy(
    WDFDEVICE Device,
    lumabridge::driver::D3d11IddCxSwapChainBackend& Backend
    ) noexcept
{
    wchar_t authorizedSid[128]{};
    const bool hasSid = LumaBridgeQueryAuthorizedHostUserSid(
        Device,
        authorizedSid,
        ARRAYSIZE(authorizedSid));
    Backend.SetAuthorizedHostUserSid(hasSid ? authorizedSid : nullptr);
    Backend.SetGpuSharedTransportEnabled(LumaBridgeQueryGpuSharedTransportEnabled(Device));
    Backend.SetFrameExtractionEnabled(LumaBridgeQueryFrameExtractionEnabled(Device));
}

void
AssignUnicodeDiagnosticValue(
    WDFKEY HardwareKey,
    PCUNICODE_STRING ValueName,
    const wchar_t* WideValue
    ) noexcept
{
    if (HardwareKey == nullptr || ValueName == nullptr || WideValue == nullptr)
    {
        return;
    }

    size_t charCount = 0;
    while (WideValue[charCount] != L'\0' && charCount < 256U)
    {
        ++charCount;
    }

    const USHORT byteLength = static_cast<USHORT>(charCount * sizeof(wchar_t));
    UNICODE_STRING value{};
    value.Length = byteLength;
    value.MaximumLength = static_cast<USHORT>(byteLength + sizeof(wchar_t));
    value.Buffer = const_cast<wchar_t*>(WideValue);
    (void)WdfRegistryAssignUnicodeString(HardwareKey, ValueName, &value);
}

void
LumaBridgePersistStartupDiagnostics(
    WDFDEVICE Device,
    DriverDiagnosticStage LastStage,
    DriverDiagnosticStage LastSuccessfulStage,
    NTSTATUS LastStatus,
    DriverDiagnosticStage LastErrorStage,
    NTSTATUS LastErrorStatus,
    ULONG IddCxVersion
    ) noexcept
{
    if constexpr (!lumabridge::driver::GetDiagnosticStageCapabilities(
                      lumabridge::driver::kActiveDiagnosticStage)
                      .EnableTraceLoggingAndRegistryBreadcrumbs)
    {
        UNREFERENCED_PARAMETER(Device);
        UNREFERENCED_PARAMETER(LastStage);
        UNREFERENCED_PARAMETER(LastSuccessfulStage);
        UNREFERENCED_PARAMETER(LastStatus);
        UNREFERENCED_PARAMETER(LastErrorStage);
        UNREFERENCED_PARAMETER(LastErrorStatus);
        UNREFERENCED_PARAMETER(IddCxVersion);
    }
    else
    {
        if (Device == nullptr)
        {
            return;
        }

        static volatile LONG g_DiagRegOpenFailureLogged = 0;

        // Bit 8 (WDF_REGKEY_DEVICE_SUBKEY) instructs WUDFx02000 to create/open
        // Device Parameters\<DriverServiceName> where LOCAL SERVICE has KEY_SET_VALUE access.
        WDFKEY hardwareKey = nullptr;
        NTSTATUS openStatus = WdfDeviceOpenRegistryKey(
            Device,
            PLUGPLAY_REGKEY_DEVICE | WDF_REGKEY_DEVICE_SUBKEY,
            KEY_SET_VALUE,
            WDF_NO_OBJECT_ATTRIBUTES,
            &hardwareKey);
        if (!NT_SUCCESS(openStatus) || hardwareKey == nullptr)
        {
            hardwareKey = nullptr;
            openStatus = WdfDeviceOpenRegistryKey(
                Device,
                PLUGPLAY_REGKEY_DEVICE,
                KEY_SET_VALUE,
                WDF_NO_OBJECT_ATTRIBUTES,
                &hardwareKey);
        }
        if (!NT_SUCCESS(openStatus) || hardwareKey == nullptr)
        {
            if (InterlockedCompareExchange(&g_DiagRegOpenFailureLogged, 1, 0) == 0)
            {
                const NTSTATUS effectiveStatus = !NT_SUCCESS(openStatus)
                    ? openStatus
                    : STATUS_UNSUCCESSFUL;
                char regErrMsg[192]{};
                _snprintf_s(
                    regErrMsg,
                    sizeof(regErrMsg),
                    _TRUNCATE,
                    "WdfDeviceOpenRegistryKey(PLUGPLAY_REGKEY_DEVICE, KEY_SET_VALUE) failed (0x%08lX); Diag* breadcrumbs unavailable",
                    static_cast<unsigned long>(effectiveStatus));
                LumaBridgeTraceWarn(
                    LastStage,
                    effectiveStatus,
                    AdapterLifecycleState::Uninitialized,
                    regErrMsg,
                    LastSuccessfulStage);
            }
            return;
        }

        DECLARE_CONST_UNICODE_STRING(nameLastStage, L"DiagLastStage");
        DECLARE_CONST_UNICODE_STRING(nameLastSuccess, L"DiagLastSuccessfulStage");
        DECLARE_CONST_UNICODE_STRING(nameLastStatus, L"DiagLastStatus");
        DECLARE_CONST_UNICODE_STRING(nameLastErrorStage, L"DiagLastErrorStage");
        DECLARE_CONST_UNICODE_STRING(nameLastErrorStatus, L"DiagLastErrorStatus");
        DECLARE_CONST_UNICODE_STRING(nameIddCxVer, L"DiagIddCxVersion");
        DECLARE_CONST_UNICODE_STRING(nameHostPid, L"DiagHostProcessId");
        DECLARE_CONST_UNICODE_STRING(nameDllAttach, L"DiagDllAttachCount");
        DECLARE_CONST_UNICODE_STRING(nameBuildStage, L"DiagBuildStage");
        DECLARE_CONST_UNICODE_STRING(nameTlRegistered, L"DiagTraceLoggingRegistered");
        DECLARE_CONST_UNICODE_STRING(nameTlStatus, L"DiagTraceLoggingStatus");

        AssignUnicodeDiagnosticValue(
            hardwareKey,
            &nameLastStage,
            lumabridge::driver::DriverDiagnosticStageToWideString(LastStage));
        AssignUnicodeDiagnosticValue(
            hardwareKey,
            &nameLastSuccess,
            lumabridge::driver::DriverDiagnosticStageToWideString(LastSuccessfulStage));
        (void)WdfRegistryAssignULong(hardwareKey, &nameLastStatus, static_cast<ULONG>(LastStatus));
        AssignUnicodeDiagnosticValue(
            hardwareKey,
            &nameLastErrorStage,
            lumabridge::driver::DriverDiagnosticStageToWideString(LastErrorStage));
        (void)WdfRegistryAssignULong(hardwareKey, &nameLastErrorStatus, static_cast<ULONG>(LastErrorStatus));
        (void)WdfRegistryAssignULong(hardwareKey, &nameIddCxVer, IddCxVersion);
        (void)WdfRegistryAssignULong(hardwareKey, &nameHostPid, GetCurrentProcessId());
        (void)WdfRegistryAssignULong(hardwareKey, &nameDllAttach, LumaBridgeGetDllProcessAttachCount());
        (void)WdfRegistryAssignULong(hardwareKey, &nameBuildStage, lumabridge::driver::kActiveDiagnosticStage);
        const HRESULT tlRegHr = LumaBridgeGetTraceLoggingRegisterResult();
        (void)WdfRegistryAssignULong(hardwareKey, &nameTlRegistered, SUCCEEDED(tlRegHr) ? 1UL : 0UL);
        (void)WdfRegistryAssignULong(hardwareKey, &nameTlStatus, static_cast<ULONG>(tlRegHr));

        WdfRegistryClose(hardwareKey);
    }
}

void
LumaBridgePersistTrackerDiagnostics(
    WDFDEVICE Device,
    const lumabridge::driver::AdapterLifecycleTracker& Tracker,
    ULONG IddCxVersion
    ) noexcept
{
    LumaBridgePersistStartupDiagnostics(
        Device,
        Tracker.LastStage,
        Tracker.LastSuccessfulStage,
        Tracker.LastStageStatus,
        Tracker.LastErrorStage,
        Tracker.LastErrorStatus,
        IddCxVersion);
}

} // namespace

namespace lumabridge::driver {

bool
TryPinActiveDeviceForCreate(
    WDFDEVICE wdfDevice,
    ScopedWdfObjectRef& outPinnedDevice
    ) noexcept
{
    outPinnedDevice.Reset();
    if (wdfDevice == nullptr)
    {
        return false;
    }

    ExclusiveLockGuard gateLock(&g_AdapterInitGate);
    auto* deviceContext = LumaBridgeGetDeviceContext(wdfDevice);
    if (deviceContext == nullptr || deviceContext->IsCleanedUp)
    {
        return false;
    }

    ExclusiveLockGuard stateLock(&deviceContext->StateLock);
    if (deviceContext->Lifecycle.IsCleanedUp)
    {
        return false;
    }

    outPinnedDevice = ScopedWdfObjectRef(static_cast<WDFOBJECT>(wdfDevice), true);
    return true;
}

bool
TryCommitCreatedMonitorObject(
    WDFDEVICE wdfDevice,
    IDDCX_MONITOR monitorObject,
    uint32_t connectorIndex
    ) noexcept
{
    if (wdfDevice == nullptr || monitorObject == nullptr)
    {
        return false;
    }

    ExclusiveLockGuard gateLock(&g_AdapterInitGate);
    auto* deviceContext = LumaBridgeGetDeviceContext(wdfDevice);
    if (deviceContext == nullptr || deviceContext->IsCleanedUp)
    {
        return false;
    }

    {
        ExclusiveLockGuard stateLock(&deviceContext->StateLock);
        if (deviceContext->Lifecycle.IsCleanedUp)
        {
            return false;
        }
    }

    auto* monitorContext = LumaBridgeGetMonitorContext(monitorObject);
    if (monitorContext == nullptr)
    {
        return false;
    }

    monitorContext->WdfDevice = wdfDevice;
    monitorContext->ConnectorIndex = connectorIndex;
    monitorContext->IsCleanedUp = false;

    // Transfer +1 WDF reference to VirtualMonitorManager for m_monitorHandle lifetime.
    WdfObjectReference(static_cast<WDFOBJECT>(monitorObject));
    return true;
}

} // namespace lumabridge::driver

_Use_decl_annotations_
NTSTATUS
LumaBridgeConfigureDeviceInit(
    PWDFDEVICE_INIT DeviceInit
    )
{
    if (DeviceInit == nullptr)
    {
        LumaBridgeTraceError(
            DriverDiagnosticStage::DeviceInitConfig,
            STATUS_INVALID_PARAMETER,
            AdapterLifecycleState::Uninitialized,
            "IddCxDeviceInitConfig skipped because DeviceInit is null");
        return STATUS_INVALID_PARAMETER;
    }

    IDD_CX_CLIENT_CONFIG iddConfig{};
    IDD_CX_CLIENT_CONFIG_INIT(&iddConfig);

    iddConfig.EvtIddCxAdapterInitFinished = LumaBridgeEvtAdapterInitFinished;
    iddConfig.EvtIddCxAdapterCommitModes = LumaBridgeEvtAdapterCommitModes;
    iddConfig.EvtIddCxParseMonitorDescription = LumaBridgeEvtParseMonitorDescription;
    iddConfig.EvtIddCxMonitorGetDefaultDescriptionModes = LumaBridgeEvtMonitorGetDefaultDescriptionModes;
    iddConfig.EvtIddCxMonitorQueryTargetModes = LumaBridgeEvtMonitorQueryTargetModes;
    iddConfig.EvtIddCxMonitorAssignSwapChain = LumaBridgeEvtMonitorAssignSwapChain;
    iddConfig.EvtIddCxMonitorUnassignSwapChain = LumaBridgeEvtMonitorUnassignSwapChain;

    {
        char preMsg[192]{};
        _snprintf_s(
            preMsg,
            sizeof(preMsg),
            _TRUNCATE,
            "Calling IddCxDeviceInitConfig (configSize=%lu)",
            static_cast<unsigned long>(iddConfig.Size));
        LumaBridgeTraceInfo(
            DriverDiagnosticStage::DeviceInitConfig,
            STATUS_SUCCESS,
            AdapterLifecycleState::Uninitialized,
            preMsg,
            DriverDiagnosticStage::DeviceAdd);
    }

    const NTSTATUS status = IddCxDeviceInitConfig(DeviceInit, &iddConfig);
    if (!NT_SUCCESS(status))
    {
        LumaBridgeTraceError(
            DriverDiagnosticStage::DeviceInitConfig,
            status,
            AdapterLifecycleState::Uninitialized,
            "IddCxDeviceInitConfig failed",
            DriverDiagnosticStage::DeviceAdd);
        return status;
    }

    LumaBridgeTraceInfo(
        DriverDiagnosticStage::DeviceInitConfig,
        status,
        AdapterLifecycleState::DeviceConfigured,
        "IddCxDeviceInitConfig succeeded",
        DriverDiagnosticStage::DeviceInitConfig);
    return status;
}

_Use_decl_annotations_
NTSTATUS
LumaBridgeInitializeDeviceContext(
    WDFDEVICE Device
    )
{
    if (Device == nullptr)
    {
        LumaBridgeTraceError(
            DriverDiagnosticStage::IddCxDeviceInitialize,
            STATUS_INVALID_PARAMETER,
            AdapterLifecycleState::Uninitialized,
            "IddCxDeviceInitialize skipped because WDFDEVICE is null",
            DriverDiagnosticStage::WdfDeviceCreate);
        return STATUS_INVALID_PARAMETER;
    }

    auto* deviceContext = LumaBridgeGetDeviceContext(Device);
    if (deviceContext == nullptr)
    {
        LumaBridgeTraceError(
            DriverDiagnosticStage::IddCxDeviceInitialize,
            STATUS_INVALID_DEVICE_STATE,
            AdapterLifecycleState::Uninitialized,
            "DeviceContext missing on WDFDEVICE",
            DriverDiagnosticStage::WdfDeviceCreate);
        return STATUS_INVALID_DEVICE_STATE;
    }

    InitializeSRWLock(&deviceContext->StateLock);
    deviceContext->WdfDevice = Device;
    deviceContext->AdapterObject = nullptr;
    deviceContext->SwapChainHost = nullptr;
    deviceContext->IddCxRuntimeVersion = 0;
    deviceContext->IsCleanedUp = false;
    deviceContext->Lifecycle = lumabridge::driver::AdapterLifecycleTracker{};

    if constexpr (!lumabridge::driver::GetDiagnosticStageCapabilities(
                      lumabridge::driver::kActiveDiagnosticStage)
                      .EnableAdapterStateMachineAndSync)
    {
        return IddCxDeviceInitialize(Device);
    }
    else
    {
        lumabridge::driver::TransitionOnDeviceConfigured(deviceContext->Lifecycle);
        lumabridge::driver::RecordDiagnosticSuccess(
            deviceContext->Lifecycle,
            DriverDiagnosticStage::WdfDeviceCreate,
            STATUS_SUCCESS);

        if constexpr (lumabridge::driver::GetDiagnosticStageCapabilities(
                          lumabridge::driver::kActiveDiagnosticStage)
                          .EnableVirtualMonitor)
        {
            const uint32_t deviceInstanceIndex =
                static_cast<uint32_t>(InterlockedIncrement(&lumabridge::driver::g_NextDeviceInstanceIndex) - 1);
            deviceContext->SwapChainHost = new (std::nothrow) lumabridge::driver::DeviceSwapChainHost(
                Device,
                deviceInstanceIndex);
            if (deviceContext->SwapChainHost == nullptr)
            {
                lumabridge::driver::RecordDiagnosticFailure(
                    deviceContext->Lifecycle,
                    DriverDiagnosticStage::IddCxDeviceInitialize,
                    STATUS_INSUFFICIENT_RESOURCES);
                LumaBridgePersistTrackerDiagnostics(Device, deviceContext->Lifecycle, 0UL);
                LumaBridgeTraceError(
                    DriverDiagnosticStage::IddCxDeviceInitialize,
                    STATUS_INSUFFICIENT_RESOURCES,
                    deviceContext->Lifecycle.State,
                    "Failed to allocate DeviceSwapChainHost",
                    DriverDiagnosticStage::WdfDeviceCreate);
                return STATUS_INSUFFICIENT_RESOURCES;
            }
        }

        LumaBridgePersistTrackerDiagnostics(Device, deviceContext->Lifecycle, 0UL);
        LumaBridgeTraceInfo(
            DriverDiagnosticStage::IddCxDeviceInitialize,
            STATUS_SUCCESS,
            deviceContext->Lifecycle.State,
            "Calling IddCxDeviceInitialize",
            DriverDiagnosticStage::WdfDeviceCreate);

        const NTSTATUS status = IddCxDeviceInitialize(Device);
        AdapterLifecycleState resultingState = AdapterLifecycleState::Uninitialized;
        lumabridge::driver::AdapterLifecycleTracker diagSnapshot{};
        lumabridge::driver::DeviceSwapChainHost* failedHost = nullptr;
        {
            ExclusiveLockGuard lock(&deviceContext->StateLock);
            lumabridge::driver::TransitionOnDeviceInitialized(deviceContext->Lifecycle, status);
            resultingState = deviceContext->Lifecycle.State;
            diagSnapshot = deviceContext->Lifecycle;
            if (!NT_SUCCESS(status))
            {
                failedHost = deviceContext->SwapChainHost;
                deviceContext->SwapChainHost = nullptr;
            }
        }

        LumaBridgePersistTrackerDiagnostics(Device, diagSnapshot, 0UL);

        if (failedHost != nullptr)
        {
            (void)failedHost->MonitorManager.Shutdown();
            (void)failedHost->Processor.Shutdown();
            failedHost->Backend.ShutdownTransport();
            failedHost->Release();
        }

        if (!NT_SUCCESS(status))
        {
            LumaBridgeTraceError(
                DriverDiagnosticStage::IddCxDeviceInitialize,
                status,
                resultingState,
                "IddCxDeviceInitialize failed",
                diagSnapshot.LastSuccessfulStage);
            return status;
        }

        LumaBridgeTraceInfo(
            DriverDiagnosticStage::IddCxDeviceInitialize,
            status,
            resultingState,
            "IddCxDeviceInitialize succeeded",
            diagSnapshot.LastSuccessfulStage);
        return STATUS_SUCCESS;
    }
}

_Use_decl_annotations_
NTSTATUS
LumaBridgeStartAdapter(
    WDFDEVICE Device
    )
{
    if (Device == nullptr)
    {
        LumaBridgeTraceError(
            DriverDiagnosticStage::DeviceD0Entry,
            STATUS_INVALID_PARAMETER,
            AdapterLifecycleState::Uninitialized,
            "D0 entry rejected because WDFDEVICE is null");
        return STATUS_INVALID_PARAMETER;
    }

    auto* deviceContext = LumaBridgeGetDeviceContext(Device);
    if (deviceContext == nullptr)
    {
        LumaBridgeTraceError(
            DriverDiagnosticStage::DeviceD0Entry,
            STATUS_INVALID_DEVICE_STATE,
            AdapterLifecycleState::Uninitialized,
            "D0 entry rejected because DeviceContext is null");
        return STATUS_INVALID_DEVICE_STATE;
    }

    if constexpr (lumabridge::driver::GetDiagnosticStageCapabilities(
                      lumabridge::driver::kActiveDiagnosticStage)
                      .EnableAdapterStateMachineAndSync)
    {
        lumabridge::driver::D0EntryTransitionResult entryAction{};
        AdapterLifecycleState currentState = AdapterLifecycleState::Uninitialized;
        {
            ExclusiveLockGuard lock(&deviceContext->StateLock);
            entryAction = lumabridge::driver::TransitionOnD0EntryBegin(deviceContext->Lifecycle);
            currentState = deviceContext->Lifecycle.State;
        }

        switch (entryAction.Action)
        {
        case D0EntryAction::FailPreviousError:
            LumaBridgeTraceError(
                DriverDiagnosticStage::DeviceD0Entry,
                entryAction.Status,
                currentState,
                "D0 entry rejected because adapter previously failed initialization");
            return entryAction.Status;

        case D0EntryAction::FailInvalidState:
            LumaBridgeTraceError(
                DriverDiagnosticStage::DeviceD0Entry,
                entryAction.Status,
                currentState,
                "D0 entry rejected due to invalid device lifecycle state");
            return entryAction.Status;

        case D0EntryAction::ResumeReady:
        {
            const ScopedSwapChainHostRef host = AcquireSwapChainHostForDevice(Device);
            IDDCX_ADAPTER adapterHandle = nullptr;
            {
                ExclusiveLockGuard gateLock(&g_AdapterInitGate);
                ExclusiveLockGuard stateLock(&deviceContext->StateLock);
                adapterHandle = deviceContext->AdapterObject;
            }
            if (host.Get() != nullptr)
            {
                LumaBridgeApplyFrameExtractionPolicy(Device, host.Get()->Backend);
                (void)host.Get()->MonitorManager.OnResume();
                (void)host.Get()->Processor.OnResume();
                if (adapterHandle != nullptr)
                {
                    const bool enabled = LumaBridgeQueryVirtualMonitorActivationEnabled(Device);
                    host.Get()->MonitorManager.SetActivationEnabled(enabled);
                    (void)host.Get()->MonitorManager.EnsureMonitorArrived(adapterHandle);
                }
                lumabridge::driver::EmitHostMetricsSnapshot(
                    host.Get(),
                    DriverDiagnosticStage::DeviceD0Entry,
                    currentState);
            }
            LumaBridgeTraceInfo(
                DriverDiagnosticStage::DeviceD0Entry,
                STATUS_SUCCESS,
                currentState,
                "Resumed existing IddCx adapter on D0 entry");
            return STATUS_SUCCESS;
        }

        case D0EntryAction::WaitPendingInit:
        {
            const ScopedSwapChainHostRef host = AcquireSwapChainHostForDevice(Device);
            if (host.Get() != nullptr)
            {
                LumaBridgeApplyFrameExtractionPolicy(Device, host.Get()->Backend);
                (void)host.Get()->MonitorManager.OnResume();
                (void)host.Get()->Processor.OnResume();
            }
            LumaBridgeTraceInfo(
                DriverDiagnosticStage::DeviceD0Entry,
                STATUS_SUCCESS,
                currentState,
                "D0 entry completed while prior IddCxAdapterInitAsync remains pending");
            return STATUS_SUCCESS;
        }

        case D0EntryAction::StartAsyncInit:
        {
            const ScopedSwapChainHostRef host = AcquireSwapChainHostForDevice(Device);
            if (host.Get() != nullptr)
            {
                LumaBridgeApplyFrameExtractionPolicy(Device, host.Get()->Backend);
                (void)host.Get()->MonitorManager.OnResume();
                (void)host.Get()->Processor.OnResume();
            }
            break;
        }
        }
    }

    IDARG_OUT_GETVERSION versionOut{};
    const NTSTATUS versionStatus = IddCxGetVersion(&versionOut);
    ULONG iddCxVersionSnapshot = 0;
    if (NT_SUCCESS(versionStatus))
    {
        {
            ExclusiveLockGuard lock(&deviceContext->StateLock);
            deviceContext->IddCxRuntimeVersion = versionOut.IddCxVersion;
        }
        iddCxVersionSnapshot = versionOut.IddCxVersion;
        char verMsg[160]{};
        _snprintf_s(
            verMsg,
            sizeof(verMsg),
            _TRUNCATE,
            "IddCxGetVersion succeeded (iddCxVersion=0x%08lX)",
            static_cast<unsigned long>(versionOut.IddCxVersion));
        LumaBridgeTraceInfo(
            DriverDiagnosticStage::IddCxGetVersion,
            versionStatus,
            AdapterLifecycleState::AdapterInitPending,
            verMsg,
            DriverDiagnosticStage::DeviceD0Entry);
    }
    else
    {
        LumaBridgeTraceWarn(
            DriverDiagnosticStage::IddCxGetVersion,
            versionStatus,
            AdapterLifecycleState::AdapterInitPending,
            "IddCxGetVersion failed",
            DriverDiagnosticStage::DeviceD0Entry);
    }

    IDDCX_ENDPOINT_VERSION endpointVersion{};
    endpointVersion.Size = IDD_STRUCTURE_SIZE(IDDCX_ENDPOINT_VERSION);
    endpointVersion.MajorVer = lumabridge::driver::kEndpointMajorVersion;
    endpointVersion.MinorVer = lumabridge::driver::kEndpointMinorVersion;
    endpointVersion.Build = lumabridge::driver::kEndpointBuildVersion;
    endpointVersion.SKU = 0;

    IDDCX_ENDPOINT_VERSION firmwareVersion = endpointVersion;

    IDDCX_ADAPTER_CAPS adapterCaps{};
    adapterCaps.Size = IDD_STRUCTURE_SIZE(IDDCX_ADAPTER_CAPS);
    adapterCaps.Flags = IDDCX_ADAPTER_FLAGS_NONE;
    adapterCaps.MaxDisplayPipelineRate = lumabridge::driver::kMaxDisplayPipelineRate;
    adapterCaps.MaxMonitorsSupported = lumabridge::driver::kMaxMonitorsSupported;
    adapterCaps.EndPointDiagnostics.Size = IDD_STRUCTURE_SIZE(IDDCX_ENDPOINT_DIAGNOSTIC_INFO);
    adapterCaps.EndPointDiagnostics.TransmissionType = lumabridge::driver::kAdapterTransmissionType;
    adapterCaps.EndPointDiagnostics.pEndPointFriendlyName = lumabridge::driver::kEndpointFriendlyName;
    adapterCaps.EndPointDiagnostics.pEndPointModelName = lumabridge::driver::kEndpointModelName;
    adapterCaps.EndPointDiagnostics.pEndPointManufacturerName = lumabridge::driver::kEndpointManufacturerName;
    adapterCaps.EndPointDiagnostics.pHardwareVersion = &endpointVersion;
    adapterCaps.EndPointDiagnostics.pFirmwareVersion = &firmwareVersion;
    adapterCaps.EndPointDiagnostics.GammaSupport = IDDCX_FEATURE_IMPLEMENTATION_NONE;
    adapterCaps.StaticDesktopReencodeFrameCount = 0;

    WDF_OBJECT_ATTRIBUTES adapterAttributes{};
    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&adapterAttributes, LumaBridgeAdapterContext);
    adapterAttributes.EvtCleanupCallback = LumaBridgeEvtAdapterContextCleanup;

    IDARG_IN_ADAPTER_INIT adapterInitIn{};
    adapterInitIn.WdfDevice = Device;
    adapterInitIn.pCaps = &adapterCaps;
    adapterInitIn.ObjectAttributes = &adapterAttributes;

    if constexpr (!lumabridge::driver::GetDiagnosticStageCapabilities(
                      lumabridge::driver::kActiveDiagnosticStage)
                      .EnableAdapterStateMachineAndSync)
    {
        (void)iddCxVersionSnapshot;
        IDARG_OUT_ADAPTER_INIT adapterInitOut{};
        const NTSTATUS initStatus = IddCxAdapterInitAsync(&adapterInitIn, &adapterInitOut);
        if (!NT_SUCCESS(initStatus) || adapterInitOut.AdapterObject == nullptr)
        {
            return NT_SUCCESS(initStatus) ? STATUS_UNSUCCESSFUL : initStatus;
        }

        ExclusiveLockGuard gateLock(&g_AdapterInitGate);
        auto* adapterContext = LumaBridgeGetAdapterContext(adapterInitOut.AdapterObject);
        if (adapterContext != nullptr)
        {
            adapterContext->WdfDevice = Device;
            adapterContext->AdapterObject = adapterInitOut.AdapterObject;
            adapterContext->HasBoundDevice = true;
            adapterContext->IsCleanedUp = false;
        }
        deviceContext->AdapterObject = adapterInitOut.AdapterObject;
        return STATUS_SUCCESS;
    }
    else
    {
        {
            lumabridge::driver::AdapterLifecycleTracker preInitTracker{};
            {
                ExclusiveLockGuard stateLock(&deviceContext->StateLock);
                preInitTracker = deviceContext->Lifecycle;
            }
            LumaBridgePersistTrackerDiagnostics(Device, preInitTracker, iddCxVersionSnapshot);

            char capsMsg[256]{};
            _snprintf_s(
                capsMsg,
                sizeof(capsMsg),
                _TRUNCATE,
                "Calling IddCxAdapterInitAsync (capsSize=%u diagSize=%u verSize=%u maxMon=%u maxRate=%llu flags=0x%X txType=%u)",
                adapterCaps.Size,
                adapterCaps.EndPointDiagnostics.Size,
                endpointVersion.Size,
                adapterCaps.MaxMonitorsSupported,
                static_cast<unsigned long long>(adapterCaps.MaxDisplayPipelineRate),
                static_cast<unsigned int>(adapterCaps.Flags),
                static_cast<unsigned int>(adapterCaps.EndPointDiagnostics.TransmissionType));
            LumaBridgeTraceInfo(
                DriverDiagnosticStage::AdapterInitAsync,
                STATUS_SUCCESS,
                preInitTracker.State,
                capsMsg,
                preInitTracker.LastSuccessfulStage);
        }

        bool acquiredSlot = false;
        NTSTATUS slotStatus = STATUS_INVALID_DEVICE_STATE;
        const ULONGLONG waitDeadlineTick = GetTickCount64() + lumabridge::driver::kAdapterInitSlotWaitTimeoutMs;
        {
            ExclusiveLockGuard gateLock(&g_AdapterInitGate);
            while (!acquiredSlot)
            {
                if (deviceContext->IsCleanedUp)
                {
                    slotStatus = STATUS_INVALID_DEVICE_STATE;
                    break;
                }

                {
                    ExclusiveLockGuard stateLock(&deviceContext->StateLock);
                    if (deviceContext->Lifecycle.IsCleanedUp)
                    {
                        slotStatus = STATUS_INVALID_DEVICE_STATE;
                        break;
                    }
                }

                if (g_InFlightInitSlot.TryAcquire(Device))
                {
                    acquiredSlot = true;
                    break;
                }

                const ULONGLONG nowTick = GetTickCount64();
                if (nowTick >= waitDeadlineTick)
                {
                    slotStatus = STATUS_IO_TIMEOUT;
                    break;
                }

                const ULONGLONG remainingTick = waitDeadlineTick - nowTick;
                const DWORD remainingMs = (remainingTick > lumabridge::driver::kAdapterInitSlotWaitTimeoutMs)
                    ? lumabridge::driver::kAdapterInitSlotWaitTimeoutMs
                    : static_cast<DWORD>(remainingTick);

                if (!SleepConditionVariableSRW(&g_AdapterInitSlotCv, &g_AdapterInitGate, remainingMs, 0))
                {
                    slotStatus = STATUS_IO_TIMEOUT;
                    break;
                }
            }
        }

        if (!acquiredSlot)
        {
            AdapterLifecycleState abortedState = AdapterLifecycleState::Uninitialized;
            lumabridge::driver::AdapterLifecycleTracker abortedTracker{};
            {
                ExclusiveLockGuard stateLock(&deviceContext->StateLock);
                if (!deviceContext->Lifecycle.IsCleanedUp)
                {
                    (void)lumabridge::driver::TransitionOnAdapterInitAsyncSubmitted(
                        deviceContext->Lifecycle,
                        slotStatus,
                        false);
                }
                abortedState = deviceContext->Lifecycle.State;
                abortedTracker = deviceContext->Lifecycle;
            }
            LumaBridgePersistTrackerDiagnostics(Device, abortedTracker, iddCxVersionSnapshot);

            LumaBridgeTraceWarn(
                DriverDiagnosticStage::AdapterInitAsync,
                slotStatus,
                abortedState,
                "Aborted IddCxAdapterInitAsync due to cleanup or bounded slot wait timeout",
                abortedTracker.LastSuccessfulStage);
            return slotStatus;
        }

        // Do not hold g_AdapterInitGate or StateLock across IddCxAdapterInitAsync to prevent
        // deadlock if IddCx invokes EvtIddCxAdapterInitFinished synchronously or re-entrantly.
        // g_InFlightInitSlot keeps other devices in this host process out of the unbound window.
        IDARG_OUT_ADAPTER_INIT adapterInitOut{};
        const NTSTATUS initStatus = IddCxAdapterInitAsync(&adapterInitIn, &adapterInitOut);

        NTSTATUS trackedStatus = STATUS_UNSUCCESSFUL;
        AdapterLifecycleState finalState = AdapterLifecycleState::AdapterFailed;
        lumabridge::driver::AdapterLifecycleTracker finalTracker{};
        bool hasValidHandle = false;
        {
            ExclusiveLockGuard gateLock(&g_AdapterInitGate);
            hasValidHandle = NT_SUCCESS(initStatus) && (adapterInitOut.AdapterObject != nullptr);
            const bool deviceCleanedUp = deviceContext->IsCleanedUp || g_InFlightInitSlot.InFlightDeviceCleanedUp;
            if (hasValidHandle)
            {
                if (deviceCleanedUp)
                {
                    auto* adapterContext = LumaBridgeGetAdapterContext(adapterInitOut.AdapterObject);
                    if (adapterContext != nullptr)
                    {
                        adapterContext->AdapterObject = adapterInitOut.AdapterObject;
                        adapterContext->WdfDevice = nullptr;
                        adapterContext->HasBoundDevice = true;
                        adapterContext->IsCleanedUp = true;
                    }
                }
                else
                {
                    (void)LumaBridgeBindAdapterAndResolveDeviceLocked(adapterInitOut.AdapterObject, Device);
                }
            }
            g_InFlightInitSlot.Release(Device);

            ExclusiveLockGuard stateLock(&deviceContext->StateLock);
            if (hasValidHandle && !deviceCleanedUp && !deviceContext->Lifecycle.IsCleanedUp)
            {
                deviceContext->AdapterObject = adapterInitOut.AdapterObject;
            }
            trackedStatus = lumabridge::driver::TransitionOnAdapterInitAsyncSubmitted(
                deviceContext->Lifecycle,
                initStatus,
                hasValidHandle);
            finalState = deviceContext->Lifecycle.State;
            finalTracker = deviceContext->Lifecycle;
        }
        WakeAllConditionVariable(&g_AdapterInitSlotCv);
        LumaBridgePersistTrackerDiagnostics(Device, finalTracker, iddCxVersionSnapshot);

        if (!NT_SUCCESS(trackedStatus))
        {
            char failMsg[192]{};
            _snprintf_s(
                failMsg,
                sizeof(failMsg),
                _TRUNCATE,
                "IddCxAdapterInitAsync failed (rawInitStatus=0x%08lX hasValidHandle=%u)",
                static_cast<unsigned long>(initStatus),
                hasValidHandle ? 1U : 0U);
            LumaBridgeTraceError(
                DriverDiagnosticStage::AdapterInitAsync,
                trackedStatus,
                finalState,
                failMsg,
                finalTracker.LastSuccessfulStage);
            return trackedStatus;
        }

        {
            char okMsg[192]{};
            _snprintf_s(
                okMsg,
                sizeof(okMsg),
                _TRUNCATE,
                "IddCxAdapterInitAsync submitted (rawInitStatus=0x%08lX hasValidHandle=%u)",
                static_cast<unsigned long>(initStatus),
                hasValidHandle ? 1U : 0U);
            LumaBridgeTraceInfo(
                DriverDiagnosticStage::AdapterInitAsync,
                trackedStatus,
                finalState,
                okMsg,
                finalTracker.LastSuccessfulStage);
        }
        return STATUS_SUCCESS;
    }
}

_Use_decl_annotations_
VOID
LumaBridgeStopAdapter(
    WDFDEVICE Device
    )
{
    if (Device == nullptr)
    {
        return;
    }

    auto* deviceContext = LumaBridgeGetDeviceContext(Device);
    if (deviceContext == nullptr)
    {
        return;
    }

    if constexpr (lumabridge::driver::GetDiagnosticStageCapabilities(
                      lumabridge::driver::kActiveDiagnosticStage)
                      .EnableAdapterStateMachineAndSync)
    {
        AdapterLifecycleState resultingState = AdapterLifecycleState::Uninitialized;
        {
            ExclusiveLockGuard stateLock(&deviceContext->StateLock);
            lumabridge::driver::TransitionOnD0Exit(deviceContext->Lifecycle);
            resultingState = deviceContext->Lifecycle.State;
        }

        {
            const ScopedSwapChainHostRef host = AcquireSwapChainHostForDevice(Device, true);
            if (host.Get() != nullptr)
            {
                (void)host.Get()->MonitorManager.OnSuspend();
                (void)host.Get()->Processor.OnSuspend();
                lumabridge::driver::EmitHostMetricsSnapshot(
                    host.Get(),
                    DriverDiagnosticStage::DeviceD0Exit,
                    resultingState);
                host.Get()->Backend.ShutdownTransport();
            }
        }

        LumaBridgeTraceInfo(
            DriverDiagnosticStage::DeviceD0Exit,
            STATUS_SUCCESS,
            resultingState,
            "Device exited D0 power state");
    }
}

_Use_decl_annotations_
VOID
LumaBridgeEvtDeviceContextCleanup(
    WDFOBJECT Object
    )
{
    if (Object == nullptr)
    {
        return;
    }

    const WDFDEVICE device = static_cast<WDFDEVICE>(Object);
    lumabridge::driver::DeviceSwapChainHost* detachedHost = nullptr;
    {
        ExclusiveLockGuard gateLock(&g_AdapterInitGate);
        g_InFlightInitSlot.MarkDeviceCleanedUp(device);

        auto* deviceContext = LumaBridgeGetDeviceContext(device);
        if (deviceContext != nullptr)
        {
            deviceContext->IsCleanedUp = true;

            IDDCX_ADAPTER adapter = nullptr;
            {
                ExclusiveLockGuard stateLock(&deviceContext->StateLock);
                adapter = deviceContext->AdapterObject;
                detachedHost = deviceContext->SwapChainHost;
                deviceContext->SwapChainHost = nullptr;
                deviceContext->AdapterObject = nullptr;
                deviceContext->WdfDevice = nullptr;
                lumabridge::driver::TransitionOnDeviceCleanup(deviceContext->Lifecycle);
            }

            // Parent WDFDEVICE cleanup runs before child IDDCX_ADAPTER cleanup; poison AdapterContext
            // while AdapterObject is still alive so late callbacks or AdapterContextCleanup cannot bind elsewhere.
            if (adapter != nullptr)
            {
                auto* adapterContext = LumaBridgeGetAdapterContext(adapter);
                if (adapterContext != nullptr)
                {
                    adapterContext->WdfDevice = nullptr;
                    adapterContext->IsCleanedUp = true;
                    adapterContext->HasBoundDevice = true;
                }
            }
        }
    }
    WakeAllConditionVariable(&g_AdapterInitSlotCv);

    if (detachedHost != nullptr)
    {
        (void)detachedHost->MonitorManager.Shutdown();
        (void)detachedHost->Processor.Shutdown();
        lumabridge::driver::EmitHostMetricsSnapshot(
            detachedHost,
            DriverDiagnosticStage::DeviceContextCleanup,
            AdapterLifecycleState::Uninitialized);
        detachedHost->Backend.ShutdownTransport();
        detachedHost->Release();
    }

    LumaBridgeTraceInfo(
        DriverDiagnosticStage::DeviceContextCleanup,
        STATUS_SUCCESS,
        AdapterLifecycleState::Uninitialized,
        "WDF device context cleaned up");
}

_Use_decl_annotations_
VOID
LumaBridgeEvtAdapterContextCleanup(
    WDFOBJECT Object
    )
{
    if (Object == nullptr)
    {
        return;
    }

    AdapterLifecycleState resultingState = AdapterLifecycleState::Uninitialized;
    WDFDEVICE deviceToStop = nullptr;
    {
        ExclusiveLockGuard gateLock(&g_AdapterInitGate);
        auto* adapterContext = LumaBridgeGetAdapterContext(Object);
        if (adapterContext != nullptr)
        {
            const WDFDEVICE wdfDevice = adapterContext->WdfDevice;
            const IDDCX_ADAPTER adapter = adapterContext->AdapterObject;
            deviceToStop = wdfDevice;

            if (wdfDevice != nullptr)
            {
                g_InFlightInitSlot.MarkDeviceCleanedUp(wdfDevice);
                auto* deviceContext = LumaBridgeGetDeviceContext(wdfDevice);
                if (deviceContext != nullptr)
                {
                    ExclusiveLockGuard stateLock(&deviceContext->StateLock);
                    if (deviceContext->AdapterObject == adapter ||
                        deviceContext->AdapterObject == static_cast<IDDCX_ADAPTER>(Object))
                    {
                        deviceContext->AdapterObject = nullptr;
                    }
                    lumabridge::driver::TransitionOnAdapterCleanup(deviceContext->Lifecycle);
                    resultingState = deviceContext->Lifecycle.State;
                }
            }

            adapterContext->IsCleanedUp = true;
            adapterContext->HasBoundDevice = true;
            adapterContext->AdapterObject = nullptr;
            adapterContext->WdfDevice = nullptr;
        }
    }
    WakeAllConditionVariable(&g_AdapterInitSlotCv);

    if (deviceToStop != nullptr)
    {
        const ScopedSwapChainHostRef host = AcquireSwapChainHostForDevice(deviceToStop, true);
        if (host.Get() != nullptr)
        {
            (void)host.Get()->MonitorManager.Shutdown();
            (void)host.Get()->Processor.Shutdown();
            lumabridge::driver::EmitHostMetricsSnapshot(
                host.Get(),
                DriverDiagnosticStage::AdapterContextCleanup,
                resultingState);
            host.Get()->Backend.ShutdownTransport();
        }
    }

    LumaBridgeTraceInfo(
        DriverDiagnosticStage::AdapterContextCleanup,
        STATUS_SUCCESS,
        resultingState,
        "IddCx adapter context cleaned up");
}

_Use_decl_annotations_
VOID
LumaBridgeEvtMonitorContextCleanup(
    WDFOBJECT Object
    )
{
    if (Object == nullptr)
    {
        return;
    }

    WDFDEVICE device = nullptr;
    {
        ExclusiveLockGuard gateLock(&g_AdapterInitGate);
        auto* monitorContext = LumaBridgeGetMonitorContext(Object);
        if (monitorContext != nullptr)
        {
            monitorContext->IsCleanedUp = true;
            device = monitorContext->WdfDevice;
            monitorContext->WdfDevice = nullptr;
        }
    }

    if (device != nullptr)
    {
        const ScopedSwapChainHostRef host = AcquireSwapChainHostForDevice(device, true);
        if (host.Get() != nullptr)
        {
            (void)host.Get()->Processor.UnassignSwapChainForMonitor(Object);
            host.Get()->MonitorManager.NotifyMonitorObjectCleanedUp(Object);
            lumabridge::driver::EmitHostMetricsSnapshot(
                host.Get(),
                DriverDiagnosticStage::MonitorContextCleanup,
                AdapterLifecycleState::Uninitialized);
        }
    }

    LumaBridgeTraceInfo(
        DriverDiagnosticStage::MonitorContextCleanup,
        STATUS_SUCCESS,
        AdapterLifecycleState::Uninitialized,
        "IddCx monitor context cleaned up");
}

_Use_decl_annotations_
NTSTATUS
LumaBridgeEvtAdapterInitFinished(
    IDDCX_ADAPTER AdapterObject,
    const IDARG_IN_ADAPTER_INIT_FINISHED* pInArgs
    )
{
    if (AdapterObject == nullptr || pInArgs == nullptr)
    {
        LumaBridgeTraceError(
            DriverDiagnosticStage::AdapterInitFinished,
            STATUS_INVALID_PARAMETER,
            AdapterLifecycleState::AdapterFailed,
            "EvtIddCxAdapterInitFinished received null parameters");
        return STATUS_INVALID_PARAMETER;
    }

    if constexpr (!lumabridge::driver::GetDiagnosticStageCapabilities(
                      lumabridge::driver::kActiveDiagnosticStage)
                      .EnableAdapterStateMachineAndSync)
    {
        WDFDEVICE wdfDevice = nullptr;
        bool deviceAlive = false;
        {
            ExclusiveLockGuard gateLock(&g_AdapterInitGate);
            wdfDevice = LumaBridgeBindAdapterAndResolveDeviceLocked(AdapterObject, nullptr);
            if (wdfDevice != nullptr)
            {
                auto* deviceContext = LumaBridgeGetDeviceContext(wdfDevice);
                if (deviceContext != nullptr && !deviceContext->IsCleanedUp)
                {
                    WdfObjectReference(wdfDevice);
                    deviceAlive = true;
                }
            }
        }
        if (!NT_SUCCESS(pInArgs->AdapterInitStatus))
        {
            if (deviceAlive)
            {
                WdfDeviceSetFailed(wdfDevice, WdfDeviceFailedNoRestart);
                WdfObjectDereference(wdfDevice);
            }
            return pInArgs->AdapterInitStatus;
        }
        if (deviceAlive)
        {
            WdfObjectDereference(wdfDevice);
        }
        return STATUS_SUCCESS;
    }
    else
    {
        {
            char enterMsg[160]{};
            _snprintf_s(
                enterMsg,
                sizeof(enterMsg),
                _TRUNCATE,
                "EvtIddCxAdapterInitFinished entered (adapterInitStatus=0x%08lX)",
                static_cast<unsigned long>(pInArgs->AdapterInitStatus));
            LumaBridgeTraceInfo(
                DriverDiagnosticStage::AdapterInitFinished,
                pInArgs->AdapterInitStatus,
                AdapterLifecycleState::AdapterInitPending,
                enterMsg,
                DriverDiagnosticStage::AdapterInitAsync);
        }

        WDFDEVICE wdfDevice = nullptr;
        NTSTATUS finishStatus = STATUS_INVALID_DEVICE_STATE;
        AdapterLifecycleState resultingState = AdapterLifecycleState::AdapterFailed;
        lumabridge::driver::AdapterLifecycleTracker diagSnapshot{};
        ULONG iddCxVersionSnapshot = 0;
        bool shouldMarkDeviceFailed = false;
        {
            ExclusiveLockGuard gateLock(&g_AdapterInitGate);
            wdfDevice = LumaBridgeBindAdapterAndResolveDeviceLocked(AdapterObject, nullptr);
            if (wdfDevice == nullptr)
            {
                LumaBridgeTraceWarn(
                    DriverDiagnosticStage::AdapterInitFinished,
                    STATUS_INVALID_DEVICE_STATE,
                    AdapterLifecycleState::Uninitialized,
                    "EvtIddCxAdapterInitFinished ignored because no active parent WDFDEVICE was resolved",
                    DriverDiagnosticStage::AdapterInitAsync);
                return STATUS_INVALID_DEVICE_STATE;
            }

            auto* deviceContext = LumaBridgeGetDeviceContext(wdfDevice);
            if (deviceContext == nullptr || deviceContext->IsCleanedUp)
            {
                LumaBridgeTraceWarn(
                    DriverDiagnosticStage::AdapterInitFinished,
                    STATUS_INVALID_DEVICE_STATE,
                    AdapterLifecycleState::Uninitialized,
                    "EvtIddCxAdapterInitFinished rejected for missing or cleaned-up DeviceContext",
                    DriverDiagnosticStage::AdapterInitAsync);
                return STATUS_INVALID_DEVICE_STATE;
            }

            ExclusiveLockGuard stateLock(&deviceContext->StateLock);
            if (deviceContext->Lifecycle.IsCleanedUp)
            {
                LumaBridgeTraceWarn(
                    DriverDiagnosticStage::AdapterInitFinished,
                    STATUS_INVALID_DEVICE_STATE,
                    deviceContext->Lifecycle.State,
                    "EvtIddCxAdapterInitFinished ignored late callback after cleanup",
                    deviceContext->Lifecycle.LastSuccessfulStage);
                return STATUS_INVALID_DEVICE_STATE;
            }

            if (deviceContext->AdapterObject == nullptr)
            {
                deviceContext->AdapterObject = AdapterObject;
            }
            finishStatus = lumabridge::driver::TransitionOnAdapterInitFinished(
                deviceContext->Lifecycle,
                pInArgs->AdapterInitStatus);
            resultingState = deviceContext->Lifecycle.State;
            diagSnapshot = deviceContext->Lifecycle;
            iddCxVersionSnapshot = deviceContext->IddCxRuntimeVersion;

            if (!NT_SUCCESS(finishStatus) && resultingState == AdapterLifecycleState::AdapterFailed)
            {
                // Keep WDFDEVICE alive across lock release while reporting device failure.
                WdfObjectReference(wdfDevice);
                shouldMarkDeviceFailed = true;
            }
        }

        LumaBridgePersistTrackerDiagnostics(wdfDevice, diagSnapshot, iddCxVersionSnapshot);

        if (shouldMarkDeviceFailed)
        {
            LumaBridgeTraceError(
                DriverDiagnosticStage::AdapterInitFinished,
                finishStatus,
                resultingState,
                "EvtIddCxAdapterInitFinished reported adapter initialization failure; failing WDF device",
                diagSnapshot.LastSuccessfulStage);
            LumaBridgePersistStartupDiagnostics(
                wdfDevice,
                DriverDiagnosticStage::WdfDeviceSetFailed,
                diagSnapshot.LastSuccessfulStage,
                finishStatus,
                DriverDiagnosticStage::AdapterInitFinished,
                finishStatus,
                iddCxVersionSnapshot);
            LumaBridgeTraceError(
                DriverDiagnosticStage::WdfDeviceSetFailed,
                finishStatus,
                resultingState,
                "Calling WdfDeviceSetFailed(WdfDeviceFailedNoRestart)",
                diagSnapshot.LastSuccessfulStage);
            WdfDeviceSetFailed(wdfDevice, WdfDeviceFailedNoRestart);
            WdfObjectDereference(wdfDevice);
            return finishStatus;
        }

        if (!NT_SUCCESS(finishStatus))
        {
            LumaBridgeTraceWarn(
                DriverDiagnosticStage::AdapterInitFinished,
                finishStatus,
                resultingState,
                "EvtIddCxAdapterInitFinished ignored invalid or duplicate completion state",
                diagSnapshot.LastSuccessfulStage);
            return finishStatus;
        }

        LumaBridgeTraceInfo(
            DriverDiagnosticStage::AdapterInitFinished,
            STATUS_SUCCESS,
            resultingState,
            "EvtIddCxAdapterInitFinished succeeded",
            diagSnapshot.LastSuccessfulStage);

        if constexpr (lumabridge::driver::GetDiagnosticStageCapabilities(
                          lumabridge::driver::kActiveDiagnosticStage)
                          .EnableVirtualMonitor)
        {
            if (resultingState == AdapterLifecycleState::AdapterReady)
            {
                const ScopedSwapChainHostRef host = AcquireSwapChainHostForDevice(wdfDevice);
                if (host.Get() != nullptr)
                {
                    LumaBridgeApplyFrameExtractionPolicy(wdfDevice, host.Get()->Backend);
                    const bool activationEnabled = LumaBridgeQueryVirtualMonitorActivationEnabled(wdfDevice);
                    host.Get()->MonitorManager.SetActivationEnabled(activationEnabled);
                    const NTSTATUS monitorStatus = host.Get()->MonitorManager.EnsureMonitorArrived(AdapterObject);
                    if (!NT_SUCCESS(monitorStatus))
                    {
                        LumaBridgeTraceError(
                            DriverDiagnosticStage::MonitorArrival,
                            monitorStatus,
                            resultingState,
                            "Controlled virtual monitor creation or arrival failed");
                        return monitorStatus;
                    }
                    if (activationEnabled)
                    {
                        LumaBridgeTraceInfo(
                            DriverDiagnosticStage::MonitorArrival,
                            STATUS_SUCCESS,
                            resultingState,
                            "Controlled virtual monitor arrived");
                    }
                    else
                    {
                        LumaBridgeTraceInfo(
                            DriverDiagnosticStage::MonitorArrival,
                            STATUS_SUCCESS,
                            resultingState,
                            "Virtual monitor activation is disabled by default; skipping IddCxMonitorCreate/Arrival");
                    }
                    lumabridge::driver::EmitHostMetricsSnapshot(
                        host.Get(),
                        DriverDiagnosticStage::MonitorArrival,
                        resultingState);
                }
            }
        }

        return STATUS_SUCCESS;
    }
}

_Use_decl_annotations_
NTSTATUS
LumaBridgeEvtAdapterCommitModes(
    IDDCX_ADAPTER AdapterObject,
    const IDARG_IN_COMMITMODES* pInArgs
    )
{
    if (AdapterObject == nullptr || pInArgs == nullptr)
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (pInArgs->PathCount > lumabridge::driver::kMaxMonitorsSupported)
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (pInArgs->PathCount > 0 && pInArgs->pPaths == nullptr)
    {
        return STATUS_INVALID_PARAMETER;
    }

    for (UINT i = 0; i < pInArgs->PathCount; ++i)
    {
        const IDDCX_PATH& path = pInArgs->pPaths[i];
        if (path.MonitorObject == nullptr)
        {
            return STATUS_INVALID_PARAMETER;
        }

        if ((path.Flags & IDDCX_PATH_FLAGS_ACTIVE) != 0)
        {
            if (!lumabridge::driver::ValidateTargetModeVideoSignalInfo(
                    path.TargetVideoSignalInfo,
                    lumabridge::driver::kMaxDisplayPipelineRate))
            {
                LumaBridgeTraceWarn(
                    DriverDiagnosticStage::AdapterCommitModes,
                    STATUS_INVALID_PARAMETER,
                    AdapterLifecycleState::AdapterReady,
                    "EvtIddCxAdapterCommitModes rejected unsupported, unadvertised, or invalid active path mode");
                return STATUS_INVALID_PARAMETER;
            }
        }
    }

    NTSTATUS commitStatus = STATUS_INVALID_DEVICE_STATE;
    AdapterLifecycleState resultingState = AdapterLifecycleState::Uninitialized;
    {
        ExclusiveLockGuard gateLock(&g_AdapterInitGate);
        const WDFDEVICE wdfDevice = LumaBridgeBindAdapterAndResolveDeviceLocked(AdapterObject, nullptr);
        if (wdfDevice == nullptr)
        {
            return STATUS_INVALID_DEVICE_STATE;
        }

        auto* deviceContext = LumaBridgeGetDeviceContext(wdfDevice);
        if (deviceContext == nullptr || deviceContext->IsCleanedUp)
        {
            return STATUS_INVALID_DEVICE_STATE;
        }

        ExclusiveLockGuard stateLock(&deviceContext->StateLock);
        commitStatus = lumabridge::driver::TransitionOnCommitModes(
            deviceContext->Lifecycle,
            pInArgs->PathCount);
        resultingState = deviceContext->Lifecycle.State;
    }

    if (!NT_SUCCESS(commitStatus))
    {
        LumaBridgeTraceWarn(
            DriverDiagnosticStage::AdapterCommitModes,
            commitStatus,
            resultingState,
            "EvtIddCxAdapterCommitModes rejected for inactive, cleaned-up, or failed adapter state");
        return commitStatus;
    }

    LumaBridgeTraceInfo(
        DriverDiagnosticStage::AdapterCommitModes,
        STATUS_SUCCESS,
        resultingState,
        "EvtIddCxAdapterCommitModes acknowledged");
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
LumaBridgeEvtParseMonitorDescription(
    const IDARG_IN_PARSEMONITORDESCRIPTION* pInArgs,
    IDARG_OUT_PARSEMONITORDESCRIPTION* pOutArgs
    )
{
    if (pInArgs == nullptr || pOutArgs == nullptr)
    {
        return STATUS_INVALID_PARAMETER;
    }

    pOutArgs->MonitorModeBufferOutputCount = 0;
    pOutArgs->PreferredMonitorModeIdx = NO_PREFERRED_MODE;

    if ((pInArgs->MonitorModeBufferInputCount > 0 && pInArgs->pMonitorModes == nullptr) ||
        (pInArgs->MonitorDescription.DataSize > 0 && pInArgs->MonitorDescription.pData == nullptr))
    {
        return STATUS_INVALID_PARAMETER;
    }

    // MVP uses driver-supplied default description modes (IDDCX_MONITOR_DESCRIPTION_TYPE_EDID
    // with DataSize = 0 and pData = nullptr) rather than synthetic EDID parsing.
    LumaBridgeTraceInfo(
        DriverDiagnosticStage::MonitorParseDescription,
        STATUS_NOT_SUPPORTED,
        AdapterLifecycleState::AdapterReady,
        "EvtIddCxParseMonitorDescription declined; MVP uses driver default description modes");
    return STATUS_NOT_SUPPORTED;
}

_Use_decl_annotations_
NTSTATUS
LumaBridgeEvtMonitorGetDefaultDescriptionModes(
    IDDCX_MONITOR MonitorObject,
    const IDARG_IN_GETDEFAULTDESCRIPTIONMODES* pInArgs,
    IDARG_OUT_GETDEFAULTDESCRIPTIONMODES* pOutArgs
    )
{
    if (MonitorObject == nullptr || pInArgs == nullptr || pOutArgs == nullptr)
    {
        return STATUS_INVALID_PARAMETER;
    }

    pOutArgs->DefaultMonitorModeBufferOutputCount = 0;
    pOutArgs->PreferredMonitorModeIdx = NO_PREFERRED_MODE;

    lumabridge::driver::VideoModeSpec modes[lumabridge::driver::kMaxSupportedVideoModes]{};
    const auto negotiation = lumabridge::driver::NegotiateModeBuffer(
        pInArgs->DefaultMonitorModeBufferInputCount,
        pInArgs->pDefaultMonitorModes != nullptr,
        lumabridge::driver::kMaxDisplayPipelineRate,
        modes);

    pOutArgs->DefaultMonitorModeBufferOutputCount = negotiation.OutputCount;
    pOutArgs->PreferredMonitorModeIdx = negotiation.PreferredIndex;

    if (!NT_SUCCESS(negotiation.Status))
    {
        LumaBridgeTraceWarn(
            DriverDiagnosticStage::MonitorGetDefaultDescriptionModes,
            negotiation.Status,
            AdapterLifecycleState::AdapterReady,
            "EvtIddCxMonitorGetDefaultDescriptionModes failed or buffer too small");
        return negotiation.Status;
    }

    if (pInArgs->pDefaultMonitorModes != nullptr && pInArgs->DefaultMonitorModeBufferInputCount > 0)
    {
        for (UINT i = 0; i < negotiation.OutputCount; ++i)
        {
            IDDCX_MONITOR_MODE& dst = pInArgs->pDefaultMonitorModes[i];
            dst = {};
            dst.Size = sizeof(IDDCX_MONITOR_MODE);
            dst.Origin = IDDCX_MONITOR_MODE_ORIGIN_DRIVER;
            if (!lumabridge::driver::FillMonitorModeVideoSignalInfo(
                    modes[i],
                    dst.MonitorVideoSignalInfo))
            {
                return STATUS_INVALID_PARAMETER;
            }
        }
    }

    LumaBridgeTraceInfo(
        DriverDiagnosticStage::MonitorGetDefaultDescriptionModes,
        STATUS_SUCCESS,
        AdapterLifecycleState::AdapterReady,
        "EvtIddCxMonitorGetDefaultDescriptionModes completed");
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
LumaBridgeEvtMonitorQueryTargetModes(
    IDDCX_MONITOR MonitorObject,
    const IDARG_IN_QUERYTARGETMODES* pInArgs,
    IDARG_OUT_QUERYTARGETMODES* pOutArgs
    )
{
    if (MonitorObject == nullptr || pInArgs == nullptr || pOutArgs == nullptr)
    {
        return STATUS_INVALID_PARAMETER;
    }

    pOutArgs->TargetModeBufferOutputCount = 0;

    lumabridge::driver::VideoModeSpec modes[lumabridge::driver::kMaxSupportedVideoModes]{};
    const auto negotiation = lumabridge::driver::NegotiateModeBuffer(
        pInArgs->TargetModeBufferInputCount,
        pInArgs->pTargetModes != nullptr,
        lumabridge::driver::kMaxDisplayPipelineRate,
        modes);

    pOutArgs->TargetModeBufferOutputCount = negotiation.OutputCount;

    if (!NT_SUCCESS(negotiation.Status))
    {
        LumaBridgeTraceWarn(
            DriverDiagnosticStage::MonitorQueryTargetModes,
            negotiation.Status,
            AdapterLifecycleState::AdapterReady,
            "EvtIddCxMonitorQueryTargetModes failed or buffer too small");
        return negotiation.Status;
    }

    if (pInArgs->pTargetModes != nullptr && pInArgs->TargetModeBufferInputCount > 0)
    {
        for (UINT i = 0; i < negotiation.OutputCount; ++i)
        {
            IDDCX_TARGET_MODE& dst = pInArgs->pTargetModes[i];
            dst = {};
            dst.Size = sizeof(IDDCX_TARGET_MODE);
            dst.RequiredBandwidth = modes[i].RequiredBandwidth;
            if (!lumabridge::driver::FillTargetModeVideoSignalInfo(
                    modes[i],
                    dst.TargetVideoSignalInfo.targetVideoSignalInfo))
            {
                return STATUS_INVALID_PARAMETER;
            }
        }
    }

    LumaBridgeTraceInfo(
        DriverDiagnosticStage::MonitorQueryTargetModes,
        STATUS_SUCCESS,
        AdapterLifecycleState::AdapterReady,
        "EvtIddCxMonitorQueryTargetModes completed");
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
LumaBridgeEvtMonitorAssignSwapChain(
    IDDCX_MONITOR MonitorObject,
    const IDARG_IN_SETSWAPCHAIN* pInArgs
    )
{
    // IddCx contract: when EvtIddCxMonitorAssignSwapChain returns
    // STATUS_GRAPHICS_INDIRECT_DISPLAY_ABANDON_SWAPCHAIN, the OS/IddCx retains ownership of
    // pInArgs->hSwapChain and cleans it up. Never call WdfObjectDelete on pre-ownership refusal.
    if (MonitorObject == nullptr || pInArgs == nullptr)
    {
        LumaBridgeTraceError(
            DriverDiagnosticStage::MonitorAssignSwapChain,
            STATUS_GRAPHICS_INDIRECT_DISPLAY_ABANDON_SWAPCHAIN,
            AdapterLifecycleState::AdapterReady,
            "EvtIddCxMonitorAssignSwapChain rejected null MonitorObject or pInArgs");
        return STATUS_GRAPHICS_INDIRECT_DISPLAY_ABANDON_SWAPCHAIN;
    }

    if constexpr (!lumabridge::driver::GetDiagnosticStageCapabilities(
                      lumabridge::driver::kActiveDiagnosticStage)
                      .EnableSwapChainProcessor)
    {
        LumaBridgeTraceInfo(
            DriverDiagnosticStage::MonitorAssignSwapChain,
            STATUS_GRAPHICS_INDIRECT_DISPLAY_ABANDON_SWAPCHAIN,
            AdapterLifecycleState::AdapterReady,
            "EvtIddCxMonitorAssignSwapChain skipped because SwapChainProcessor is disabled in this diagnostic build stage");
        return STATUS_GRAPHICS_INDIRECT_DISPLAY_ABANDON_SWAPCHAIN;
    }
    else
    {
        lumabridge::driver::ScopedWdfObjectRef monitorPin;
        lumabridge::driver::ScopedWdfObjectRef devicePin;
        WDFDEVICE wdfDevice = nullptr;
        const ScopedSwapChainHostRef host = AcquireSwapChainHostForMonitor(
            MonitorObject,
            false,
            &monitorPin,
            &wdfDevice,
            &devicePin);
        if (host.Get() == nullptr)
        {
            LumaBridgeTraceWarn(
                DriverDiagnosticStage::MonitorAssignSwapChain,
                STATUS_GRAPHICS_INDIRECT_DISPLAY_ABANDON_SWAPCHAIN,
                AdapterLifecycleState::DeviceStopped,
                "EvtIddCxMonitorAssignSwapChain abandoned swapchain because monitor device host is unavailable");
            return STATUS_GRAPHICS_INDIRECT_DISPLAY_ABANDON_SWAPCHAIN;
        }

        if (host.Get()->MonitorManager.GetActiveMonitorHandle() != static_cast<void*>(MonitorObject))
        {
            LumaBridgeTraceWarn(
                DriverDiagnosticStage::MonitorAssignSwapChain,
                STATUS_GRAPHICS_INDIRECT_DISPLAY_ABANDON_SWAPCHAIN,
                AdapterLifecycleState::AdapterReady,
                "EvtIddCxMonitorAssignSwapChain abandoned swapchain for stale or inactive monitor");
            return STATUS_GRAPHICS_INDIRECT_DISPLAY_ABANDON_SWAPCHAIN;
        }

        if (wdfDevice != nullptr)
        {
            LumaBridgeApplyFrameExtractionPolicy(wdfDevice, host.Get()->Backend);
        }

        const NTSTATUS status = host.Get()->Processor.AssignSwapChain(
            pInArgs->hSwapChain,
            pInArgs->hNextSurfaceAvailable,
            pInArgs->RenderAdapterLuid,
            static_cast<void*>(MonitorObject));

        if (!NT_SUCCESS(status))
        {
            LumaBridgeTraceWarn(
                DriverDiagnosticStage::MonitorAssignSwapChain,
                status,
                AdapterLifecycleState::AdapterReady,
                "EvtIddCxMonitorAssignSwapChain abandoned swapchain after backend/worker setup failure");
            return STATUS_GRAPHICS_INDIRECT_DISPLAY_ABANDON_SWAPCHAIN;
        }

        // Close assign/depart race: if this monitor lost active ownership while AssignSwapChain
        // initialized (after swapchain ownership already transferred), clean up immediately.
        if (host.Get()->MonitorManager.GetActiveMonitorHandle() != static_cast<void*>(MonitorObject))
        {
            (void)host.Get()->Processor.UnassignSwapChainForMonitor(static_cast<void*>(MonitorObject));
            LumaBridgeTraceWarn(
                DriverDiagnosticStage::MonitorAssignSwapChain,
                STATUS_SUCCESS,
                AdapterLifecycleState::AdapterReady,
                "EvtIddCxMonitorAssignSwapChain cleaned up newly owned swapchain after concurrent monitor departure");
            return STATUS_SUCCESS;
        }

        lumabridge::driver::EmitHostMetricsSnapshot(
            host.Get(),
            DriverDiagnosticStage::MonitorAssignSwapChain,
            AdapterLifecycleState::AdapterReady);

        LumaBridgeTraceInfo(
            DriverDiagnosticStage::MonitorAssignSwapChain,
            STATUS_SUCCESS,
            AdapterLifecycleState::AdapterReady,
            "EvtIddCxMonitorAssignSwapChain started D3D11 swapchain processor");
        return STATUS_SUCCESS;
    }
}

_Use_decl_annotations_
NTSTATUS
LumaBridgeEvtMonitorUnassignSwapChain(
    IDDCX_MONITOR MonitorObject
    )
{
    if (MonitorObject == nullptr)
    {
        return STATUS_INVALID_PARAMETER;
    }

    lumabridge::driver::ScopedWdfObjectRef monitorPin;
    const ScopedSwapChainHostRef host = AcquireSwapChainHostForMonitor(MonitorObject, true, &monitorPin);
    if (host.Get() != nullptr)
    {
        (void)host.Get()->Processor.UnassignSwapChainForMonitor(static_cast<void*>(MonitorObject));
        lumabridge::driver::EmitHostMetricsSnapshot(
            host.Get(),
            DriverDiagnosticStage::MonitorUnassignSwapChain,
            AdapterLifecycleState::AdapterReady);
    }

    LumaBridgeTraceInfo(
        DriverDiagnosticStage::MonitorUnassignSwapChain,
        STATUS_SUCCESS,
        AdapterLifecycleState::AdapterReady,
        "EvtIddCxMonitorUnassignSwapChain processed monitor swapchain unassignment");
    return STATUS_SUCCESS;
}
