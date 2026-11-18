#include "Adapter.h"

using lumabridge::driver::AdapterLifecycleState;
using lumabridge::driver::D0EntryAction;
using lumabridge::driver::DriverDiagnosticStage;
using lumabridge::driver::LumaBridgeTraceError;
using lumabridge::driver::LumaBridgeTraceInfo;
using lumabridge::driver::LumaBridgeTraceWarn;

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
    deviceContext->IddCxRuntimeVersion = 0;
    deviceContext->IsCleanedUp = false;
    deviceContext->Lifecycle = lumabridge::driver::AdapterLifecycleTracker{};
    lumabridge::driver::TransitionOnDeviceConfigured(deviceContext->Lifecycle);

    const NTSTATUS status = IddCxDeviceInitialize(Device);
    AdapterLifecycleState resultingState = AdapterLifecycleState::Uninitialized;
    {
        ExclusiveLockGuard lock(&deviceContext->StateLock);
        lumabridge::driver::TransitionOnDeviceInitialized(deviceContext->Lifecycle, status);
        resultingState = deviceContext->Lifecycle.State;
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
        LumaBridgeTraceInfo(
            DriverDiagnosticStage::DeviceD0Entry,
            STATUS_SUCCESS,
            currentState,
            "Resumed existing IddCx adapter on D0 entry");
        return STATUS_SUCCESS;

    case D0EntryAction::WaitPendingInit:
        LumaBridgeTraceInfo(
            DriverDiagnosticStage::DeviceD0Entry,
            STATUS_SUCCESS,
            currentState,
            "D0 entry completed while prior IddCxAdapterInitAsync remains pending");
        return STATUS_SUCCESS;

    case D0EntryAction::StartAsyncInit:
        break;
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
    {
        ExclusiveLockGuard gateLock(&g_AdapterInitGate);
        auto* adapterContext = LumaBridgeGetAdapterContext(Object);
        if (adapterContext != nullptr)
        {
            const WDFDEVICE wdfDevice = adapterContext->WdfDevice;
            const IDDCX_ADAPTER adapter = adapterContext->AdapterObject;

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

    LumaBridgeTraceInfo(
        DriverDiagnosticStage::AdapterContextCleanup,
        STATUS_SUCCESS,
        resultingState,
        "IddCx adapter context cleaned up");
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

    if (pInArgs->PathCount > 0 && pInArgs->pPaths == nullptr)
    {
        return STATUS_INVALID_PARAMETER;
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

    LumaBridgeTraceWarn(
        DriverDiagnosticStage::MonitorCallbackStub,
        STATUS_NOT_SUPPORTED,
        AdapterLifecycleState::AdapterReady,
        "EvtIddCxParseMonitorDescription stub invoked before monitor support");
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
    UNREFERENCED_PARAMETER(MonitorObject);

    if (pInArgs == nullptr || pOutArgs == nullptr)
    {
        return STATUS_INVALID_PARAMETER;
    }

    pOutArgs->DefaultMonitorModeBufferOutputCount = 0;
    pOutArgs->PreferredMonitorModeIdx = NO_PREFERRED_MODE;

    LumaBridgeTraceWarn(
        DriverDiagnosticStage::MonitorCallbackStub,
        STATUS_NOT_SUPPORTED,
        AdapterLifecycleState::AdapterReady,
        "EvtIddCxMonitorGetDefaultDescriptionModes stub invoked before monitor support");
    return STATUS_NOT_SUPPORTED;
}

_Use_decl_annotations_
NTSTATUS
LumaBridgeEvtMonitorQueryTargetModes(
    IDDCX_MONITOR MonitorObject,
    const IDARG_IN_QUERYTARGETMODES* pInArgs,
    IDARG_OUT_QUERYTARGETMODES* pOutArgs
    )
{
    UNREFERENCED_PARAMETER(MonitorObject);

    if (pInArgs == nullptr || pOutArgs == nullptr)
    {
        return STATUS_INVALID_PARAMETER;
    }

    pOutArgs->TargetModeBufferOutputCount = 0;

    LumaBridgeTraceWarn(
        DriverDiagnosticStage::MonitorCallbackStub,
        STATUS_NOT_SUPPORTED,
        AdapterLifecycleState::AdapterReady,
        "EvtIddCxMonitorQueryTargetModes stub invoked before video mode support");
    return STATUS_NOT_SUPPORTED;
}

_Use_decl_annotations_
NTSTATUS
LumaBridgeEvtMonitorAssignSwapChain(
    IDDCX_MONITOR MonitorObject,
    const IDARG_IN_SETSWAPCHAIN* pInArgs
    )
{
    UNREFERENCED_PARAMETER(MonitorObject);
    UNREFERENCED_PARAMETER(pInArgs);

    LumaBridgeTraceWarn(
        DriverDiagnosticStage::MonitorCallbackStub,
        STATUS_GRAPHICS_INDIRECT_DISPLAY_ABANDON_SWAPCHAIN,
        AdapterLifecycleState::AdapterReady,
        "EvtIddCxMonitorAssignSwapChain stub abandoning swapchain until swapchain pipeline is implemented");

    // IddCx 1.4+ contract: returning any failure NTSTATUS other than
    // STATUS_GRAPHICS_INDIRECT_DISPLAY_ABANDON_SWAPCHAIN causes IddCx to bugcheck the UMDF driver.
    // Note: this return value is strictly a defensive contract guard and NOT a functional
    // swapchain implementation, because Windows may repeatedly request a new swapchain if a
    // monitor were active. No virtual monitor (IddCxMonitorCreate / IddCxMonitorArrival) may
    // be announced until mode negotiation and swapchain frame processing are implemented.
    return STATUS_GRAPHICS_INDIRECT_DISPLAY_ABANDON_SWAPCHAIN;
}

_Use_decl_annotations_
NTSTATUS
LumaBridgeEvtMonitorUnassignSwapChain(
    IDDCX_MONITOR MonitorObject
    )
{
    UNREFERENCED_PARAMETER(MonitorObject);

    LumaBridgeTraceInfo(
        DriverDiagnosticStage::MonitorCallbackStub,
        STATUS_SUCCESS,
        AdapterLifecycleState::AdapterReady,
        "EvtIddCxMonitorUnassignSwapChain no-op stub completed");
    return STATUS_SUCCESS;
}
