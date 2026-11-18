#include "Adapter.h"

#include <d3d11.h>
#include <dxgi1_4.h>
#include <wrl/client.h>

#include <new>

using Microsoft::WRL::ComPtr;
using lumabridge::driver::AdapterLifecycleState;
using lumabridge::driver::D0EntryAction;
using lumabridge::driver::DriverDiagnosticStage;
using lumabridge::driver::LumaBridgeTraceError;
using lumabridge::driver::LumaBridgeTraceInfo;
using lumabridge::driver::LumaBridgeTraceWarn;

namespace lumabridge::driver {

/// D3D11/DXGI/IddCx implementation of ISwapChainBackend for UMDF runtime execution.
class D3d11IddCxSwapChainBackend final : public ISwapChainBackend
{
public:
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

        {
            ExclusiveLockGuard deviceGuard(&m_deviceLock);
            m_boundSwapChainHandle = swapChainHandle;
            m_d3dDevice = d3dDevice;
            m_d3dContext = d3dContext;
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

        // Adopt the OS-AddRef'd surface pointer without adding an extra COM reference so
        // ComPtr releases it automatically before the next acquire or frame completion.
        ComPtr<IDXGIResource> surface;
        surface.Attach(bufferOut.MetaData.pSurface);

        bool hasValidSurface = false;
        if (surface != nullptr)
        {
            ComPtr<ID3D11Texture2D> texture;
            if (SUCCEEDED(surface.As(&texture)) && texture != nullptr)
            {
                D3D11_TEXTURE2D_DESC desc{};
                texture->GetDesc(&desc);
                hasValidSurface = (desc.Width > 0 && desc.Height > 0);
            }
        }

        outMetadata.PresentationFrameNumber = bufferOut.MetaData.PresentationFrameNumber;
        outMetadata.DirtyRectCount = bufferOut.MetaData.DirtyRectCount;
        outMetadata.MoveRegionCount = bufferOut.MetaData.MoveRegionCount;
        outMetadata.HwProtectedSurface = (bufferOut.MetaData.HwProtectedSurface != FALSE);
        outMetadata.PresentDisplayQPCTime = bufferOut.MetaData.PresentDisplayQPCTime;
        outMetadata.HasValidSurface = hasValidSurface;
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
                m_d3dContext.Reset();
                m_d3dDevice.Reset();
            }
        }
        if (swapChainHandle != nullptr)
        {
            WdfObjectDelete(static_cast<IDDCX_SWAPCHAIN>(swapChainHandle));
        }
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

    SRWLOCK m_deviceLock{SRWLOCK_INIT};
    void* m_boundSwapChainHandle{nullptr};
    ComPtr<ID3D11Device> m_d3dDevice;
    ComPtr<ID3D11DeviceContext> m_d3dContext;
};

/// Reference-counted per-WDFDEVICE swapchain host safe across concurrent cleanup and callbacks.
struct DeviceSwapChainHost final
{
    D3d11IddCxSwapChainBackend Backend{};
    SwapChainProcessor Processor{&Backend};
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
    bool allowDuringCleanup = false
    ) noexcept
{
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
    }

    return AcquireSwapChainHostForDevice(device, allowDuringCleanup);
}

} // namespace

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

    const NTSTATUS status = IddCxDeviceInitConfig(DeviceInit, &iddConfig);
    if (!NT_SUCCESS(status))
    {
        LumaBridgeTraceError(
            DriverDiagnosticStage::DeviceInitConfig,
            status,
            AdapterLifecycleState::Uninitialized,
            "IddCxDeviceInitConfig failed");
        return status;
    }

    LumaBridgeTraceInfo(
        DriverDiagnosticStage::DeviceInitConfig,
        status,
        AdapterLifecycleState::DeviceConfigured,
        "IddCxDeviceInitConfig succeeded");
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
            "IddCxDeviceInitialize skipped because WDFDEVICE is null");
        return STATUS_INVALID_PARAMETER;
    }

    auto* deviceContext = LumaBridgeGetDeviceContext(Device);
    if (deviceContext == nullptr)
    {
        LumaBridgeTraceError(
            DriverDiagnosticStage::IddCxDeviceInitialize,
            STATUS_INVALID_DEVICE_STATE,
            AdapterLifecycleState::Uninitialized,
            "DeviceContext missing on WDFDEVICE");
        return STATUS_INVALID_DEVICE_STATE;
    }

    InitializeSRWLock(&deviceContext->StateLock);
    deviceContext->WdfDevice = Device;
    deviceContext->AdapterObject = nullptr;
    deviceContext->SwapChainHost = new (std::nothrow) lumabridge::driver::DeviceSwapChainHost();
    deviceContext->IddCxRuntimeVersion = 0;
    deviceContext->IsCleanedUp = false;
    deviceContext->Lifecycle = lumabridge::driver::AdapterLifecycleTracker{};
    lumabridge::driver::TransitionOnDeviceConfigured(deviceContext->Lifecycle);

    if (deviceContext->SwapChainHost == nullptr)
    {
        LumaBridgeTraceError(
            DriverDiagnosticStage::IddCxDeviceInitialize,
            STATUS_INSUFFICIENT_RESOURCES,
            deviceContext->Lifecycle.State,
            "Failed to allocate DeviceSwapChainHost");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    const NTSTATUS status = IddCxDeviceInitialize(Device);
    AdapterLifecycleState resultingState = AdapterLifecycleState::Uninitialized;
    lumabridge::driver::DeviceSwapChainHost* failedHost = nullptr;
    {
        ExclusiveLockGuard lock(&deviceContext->StateLock);
        lumabridge::driver::TransitionOnDeviceInitialized(deviceContext->Lifecycle, status);
        resultingState = deviceContext->Lifecycle.State;
        if (!NT_SUCCESS(status))
        {
            failedHost = deviceContext->SwapChainHost;
            deviceContext->SwapChainHost = nullptr;
        }
    }

    if (failedHost != nullptr)
    {
        (void)failedHost->Processor.Shutdown();
        failedHost->Release();
    }

    if (!NT_SUCCESS(status))
    {
        LumaBridgeTraceError(
            DriverDiagnosticStage::IddCxDeviceInitialize,
            status,
            resultingState,
            "IddCxDeviceInitialize failed");
        return status;
    }

    LumaBridgeTraceInfo(
        DriverDiagnosticStage::IddCxDeviceInitialize,
        status,
        resultingState,
        "IddCxDeviceInitialize succeeded");
    return STATUS_SUCCESS;
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
        if (host.Get() != nullptr)
        {
            (void)host.Get()->Processor.OnResume();
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
            (void)host.Get()->Processor.OnResume();
        }
        break;
    }
    }

    IDARG_OUT_GETVERSION versionOut{};
    const NTSTATUS versionStatus = IddCxGetVersion(&versionOut);
    if (NT_SUCCESS(versionStatus))
    {
        ExclusiveLockGuard lock(&deviceContext->StateLock);
        deviceContext->IddCxRuntimeVersion = versionOut.IddCxVersion;
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
    adapterCaps.EndPointDiagnostics.TransmissionType = IDDCX_TRANSMISSION_TYPE_NETWORK_OTHER;
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
        }

        LumaBridgeTraceWarn(
            DriverDiagnosticStage::AdapterInitAsync,
            slotStatus,
            abortedState,
            "Aborted IddCxAdapterInitAsync due to cleanup or bounded slot wait timeout");
        return slotStatus;
    }

    // Do not hold g_AdapterInitGate or StateLock across IddCxAdapterInitAsync to prevent
    // deadlock if IddCx invokes EvtIddCxAdapterInitFinished synchronously or re-entrantly.
    // g_InFlightInitSlot keeps other devices in this host process out of the unbound window.
    IDARG_OUT_ADAPTER_INIT adapterInitOut{};
    const NTSTATUS initStatus = IddCxAdapterInitAsync(&adapterInitIn, &adapterInitOut);

    NTSTATUS trackedStatus = STATUS_UNSUCCESSFUL;
    AdapterLifecycleState finalState = AdapterLifecycleState::AdapterFailed;
    {
        ExclusiveLockGuard gateLock(&g_AdapterInitGate);
        const bool hasValidHandle = NT_SUCCESS(initStatus) && (adapterInitOut.AdapterObject != nullptr);
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
    }
    WakeAllConditionVariable(&g_AdapterInitSlotCv);

    if (!NT_SUCCESS(trackedStatus))
    {
        LumaBridgeTraceError(
            DriverDiagnosticStage::AdapterInitAsync,
            trackedStatus,
            finalState,
            "IddCxAdapterInitAsync failed");
        return trackedStatus;
    }

    LumaBridgeTraceInfo(
        DriverDiagnosticStage::AdapterInitAsync,
        trackedStatus,
        finalState,
        "IddCxAdapterInitAsync submitted");
    return STATUS_SUCCESS;
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

    {
        const ScopedSwapChainHostRef host = AcquireSwapChainHostForDevice(Device, true);
        if (host.Get() != nullptr)
        {
            (void)host.Get()->Processor.OnSuspend();
        }
    }

    auto* deviceContext = LumaBridgeGetDeviceContext(Device);
    if (deviceContext == nullptr)
    {
        return;
    }

    AdapterLifecycleState resultingState = AdapterLifecycleState::Uninitialized;
    {
        ExclusiveLockGuard stateLock(&deviceContext->StateLock);
        lumabridge::driver::TransitionOnD0Exit(deviceContext->Lifecycle);
        resultingState = deviceContext->Lifecycle.State;
    }

    LumaBridgeTraceInfo(
        DriverDiagnosticStage::DeviceD0Exit,
        STATUS_SUCCESS,
        resultingState,
        "Device exited D0 power state");
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
        (void)detachedHost->Processor.Shutdown();
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
            (void)host.Get()->Processor.Shutdown();
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
            (void)host.Get()->Processor.UnassignSwapChain();
        }
    }
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

    WDFDEVICE wdfDevice = nullptr;
    NTSTATUS finishStatus = STATUS_INVALID_DEVICE_STATE;
    AdapterLifecycleState resultingState = AdapterLifecycleState::AdapterFailed;
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
                "EvtIddCxAdapterInitFinished ignored because no active parent WDFDEVICE was resolved");
            return STATUS_INVALID_DEVICE_STATE;
        }

        auto* deviceContext = LumaBridgeGetDeviceContext(wdfDevice);
        if (deviceContext == nullptr || deviceContext->IsCleanedUp)
        {
            LumaBridgeTraceWarn(
                DriverDiagnosticStage::AdapterInitFinished,
                STATUS_INVALID_DEVICE_STATE,
                AdapterLifecycleState::Uninitialized,
                "EvtIddCxAdapterInitFinished rejected for missing or cleaned-up DeviceContext");
            return STATUS_INVALID_DEVICE_STATE;
        }

        ExclusiveLockGuard stateLock(&deviceContext->StateLock);
        if (deviceContext->Lifecycle.IsCleanedUp)
        {
            LumaBridgeTraceWarn(
                DriverDiagnosticStage::AdapterInitFinished,
                STATUS_INVALID_DEVICE_STATE,
                deviceContext->Lifecycle.State,
                "EvtIddCxAdapterInitFinished ignored late callback after cleanup");
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

        if (!NT_SUCCESS(finishStatus) && resultingState == AdapterLifecycleState::AdapterFailed)
        {
            // Keep WDFDEVICE alive across lock release while reporting device failure.
            WdfObjectReference(wdfDevice);
            shouldMarkDeviceFailed = true;
        }
    }

    if (shouldMarkDeviceFailed)
    {
        LumaBridgeTraceError(
            DriverDiagnosticStage::AdapterInitFinished,
            finishStatus,
            resultingState,
            "EvtIddCxAdapterInitFinished reported adapter initialization failure; failing WDF device");
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
            "EvtIddCxAdapterInitFinished ignored invalid or duplicate completion state");
        return finishStatus;
    }

    LumaBridgeTraceInfo(
        DriverDiagnosticStage::AdapterInitFinished,
        STATUS_SUCCESS,
        resultingState,
        "EvtIddCxAdapterInitFinished succeeded");

    // Monitor creation and arrival are intentionally deferred to a dedicated issue.
    return STATUS_SUCCESS;
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

    // MVP uses driver-supplied default description modes (IDDCX_MONITOR_DESCRIPTION_TYPE_UNCONFIGURED)
    // rather than synthetic EDID parsing.
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

    const ScopedSwapChainHostRef host = AcquireSwapChainHostForMonitor(MonitorObject);
    if (host.Get() == nullptr)
    {
        LumaBridgeTraceWarn(
            DriverDiagnosticStage::MonitorAssignSwapChain,
            STATUS_GRAPHICS_INDIRECT_DISPLAY_ABANDON_SWAPCHAIN,
            AdapterLifecycleState::DeviceStopped,
            "EvtIddCxMonitorAssignSwapChain abandoned swapchain because monitor device host is unavailable");
        return STATUS_GRAPHICS_INDIRECT_DISPLAY_ABANDON_SWAPCHAIN;
    }

    const NTSTATUS status = host.Get()->Processor.AssignSwapChain(
        pInArgs->hSwapChain,
        pInArgs->hNextSurfaceAvailable,
        pInArgs->RenderAdapterLuid);

    if (!NT_SUCCESS(status))
    {
        LumaBridgeTraceWarn(
            DriverDiagnosticStage::MonitorAssignSwapChain,
            status,
            AdapterLifecycleState::AdapterReady,
            "EvtIddCxMonitorAssignSwapChain abandoned swapchain after backend/worker setup failure");
        return STATUS_GRAPHICS_INDIRECT_DISPLAY_ABANDON_SWAPCHAIN;
    }

    LumaBridgeTraceInfo(
        DriverDiagnosticStage::MonitorAssignSwapChain,
        STATUS_SUCCESS,
        AdapterLifecycleState::AdapterReady,
        "EvtIddCxMonitorAssignSwapChain started D3D11 swapchain processor");
    return STATUS_SUCCESS;
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

    const ScopedSwapChainHostRef host = AcquireSwapChainHostForMonitor(MonitorObject, true);
    if (host.Get() != nullptr)
    {
        (void)host.Get()->Processor.UnassignSwapChain();
    }

    LumaBridgeTraceInfo(
        DriverDiagnosticStage::MonitorUnassignSwapChain,
        STATUS_SUCCESS,
        AdapterLifecycleState::AdapterReady,
        "EvtIddCxMonitorUnassignSwapChain stopped swapchain processor");
    return STATUS_SUCCESS;
}
