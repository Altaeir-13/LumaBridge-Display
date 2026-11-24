#pragma once

namespace lumabridge::driver {

/// Lifecycle states for the WDF device and indirect display adapter.
enum class AdapterLifecycleState : UINT32
{
    Uninitialized = 0,
    DeviceConfigured,
    DeviceInitialized,
    AdapterInitPending,
    AdapterReady,
    AdapterFailed,
    DeviceStopped,
};

/// Diagnostic stages recorded in DeviceContext and emitted via UMDF tracing.
enum class DriverDiagnosticStage : UINT32
{
    None = 0,
    DriverEntry,
    DriverUnload,
    DeviceAdd,
    DeviceInitConfig,
    WdfDeviceCreate,
    IddCxDeviceInitialize,
    DeviceD0Entry,
    AdapterInitAsync,
    AdapterInitFinished,
    AdapterCommitModes,
    DeviceD0Exit,
    AdapterContextCleanup,
    DeviceContextCleanup,
    MonitorParseDescription,
    MonitorGetDefaultDescriptionModes,
    MonitorQueryTargetModes,
    MonitorCreate,
    MonitorArrival,
    MonitorDeparture,
    MonitorContextCleanup,
    MonitorAssignSwapChain,
    MonitorUnassignSwapChain,
    MonitorCallbackStub,
    DllProcessAttach,
    IddCxGetVersion,
    WdfDeviceSetFailed,
};

/// Action determined when entering D0 based on current lifecycle state.
enum class D0EntryAction : UINT32
{
    StartAsyncInit = 0,
    ResumeReady,
    WaitPendingInit,
    FailInvalidState,
    FailPreviousError,
};

/// Output of evaluating a D0 entry transition.
struct D0EntryTransitionResult
{
    D0EntryAction Action;
    NTSTATUS Status;
};

/// Pure state-machine tracking data embedded inside DeviceContext and unit-tested directly.
struct AdapterLifecycleTracker
{
    AdapterLifecycleState State{AdapterLifecycleState::Uninitialized};
    DriverDiagnosticStage LastStage{DriverDiagnosticStage::None};
    DriverDiagnosticStage LastSuccessfulStage{DriverDiagnosticStage::None};
    DriverDiagnosticStage LastErrorStage{DriverDiagnosticStage::None};
    NTSTATUS LastStageStatus{STATUS_SUCCESS};
    NTSTATUS LastAdapterInitStatus{STATUS_PENDING};
    NTSTATUS LastErrorStatus{STATUS_SUCCESS};
    UINT32 CommittedPathCount{0};
    UINT32 D0EntryCount{0};
    UINT32 D0ExitCount{0};
    bool HasAdapterHandle{false};
    bool AdapterInitCompleted{false};
    bool IsInD0{false};
    bool IsCleanedUp{false};
};

/// Serializes the unbound window of IddCxAdapterInitAsync across multiple WDFDEVICE instances
/// so concurrent device initializations and cleanups can never cross-bind AdapterObject handles.
struct InFlightAdapterBindingSlot
{
    void* InFlightDevice{nullptr};
    bool InFlightDeviceCleanedUp{false};

    bool TryAcquire(void* device) noexcept
    {
        if (device == nullptr || InFlightDevice != nullptr)
        {
            return false;
        }
        InFlightDevice = device;
        InFlightDeviceCleanedUp = false;
        return true;
    }

    void MarkDeviceCleanedUp(void* device) noexcept
    {
        if (InFlightDevice == device && device != nullptr)
        {
            InFlightDeviceCleanedUp = true;
        }
    }

    void Release(void* device) noexcept
    {
        if (InFlightDevice == device)
        {
            InFlightDevice = nullptr;
            InFlightDeviceCleanedUp = false;
        }
    }

    void* ResolveAdapterDevice(
        void* existingAdapterDevice,
        bool adapterWasBoundOrCleanedUp,
        void* explicitDevice
        ) const noexcept
    {
        if (existingAdapterDevice != nullptr)
        {
            return existingAdapterDevice;
        }
        if (adapterWasBoundOrCleanedUp)
        {
            return nullptr;
        }
        if (explicitDevice != nullptr)
        {
            return explicitDevice;
        }
        if (InFlightDeviceCleanedUp)
        {
            return nullptr;
        }
        return InFlightDevice;
    }
};

/// Returns true only when status represents completion without error and is not STATUS_PENDING.
inline bool
IsSucceededNonPendingStatus(
    NTSTATUS status
    ) noexcept
{
    return NT_SUCCESS(status) && (status != STATUS_PENDING);
}

/// Normalizes any non-negative status (including STATUS_SUCCESS or STATUS_PENDING) into a concrete failure status.
inline NTSTATUS
NormalizeFailureStatus(
    NTSTATUS status
    ) noexcept
{
    return NT_SUCCESS(status) ? STATUS_UNSUCCESSFUL : status;
}

/// Records the latest completed stage and status without clearing error history.
inline void
RecordDiagnosticSuccess(
    AdapterLifecycleTracker& tracker,
    DriverDiagnosticStage stage,
    NTSTATUS status = STATUS_SUCCESS
    ) noexcept
{
    tracker.LastStage = stage;
    tracker.LastSuccessfulStage = stage;
    tracker.LastStageStatus = status;
}

/// Records stage and error metadata for post-mortem diagnostics without overwriting LastSuccessfulStage.
inline void
RecordDiagnosticFailure(
    AdapterLifecycleTracker& tracker,
    DriverDiagnosticStage stage,
    NTSTATUS status
    ) noexcept
{
    tracker.LastStage = stage;
    tracker.LastStageStatus = status;
    tracker.LastErrorStage = stage;
    tracker.LastErrorStatus = status;
}

/// Transitions state after IddCxDeviceInitConfig succeeds during EvtDeviceAdd.
inline void
TransitionOnDeviceConfigured(
    AdapterLifecycleTracker& tracker
    ) noexcept
{
    RecordDiagnosticSuccess(tracker, DriverDiagnosticStage::DeviceInitConfig, STATUS_SUCCESS);
    tracker.State = AdapterLifecycleState::DeviceConfigured;
    tracker.IsCleanedUp = false;
}

/// Transitions state after IddCxDeviceInitialize completes during EvtDeviceAdd.
inline void
TransitionOnDeviceInitialized(
    AdapterLifecycleTracker& tracker,
    NTSTATUS status
    ) noexcept
{
    if (IsSucceededNonPendingStatus(status))
    {
        RecordDiagnosticSuccess(tracker, DriverDiagnosticStage::IddCxDeviceInitialize, status);
        tracker.State = AdapterLifecycleState::DeviceInitialized;
        return;
    }

    const NTSTATUS failureStatus = NormalizeFailureStatus(status);
    tracker.State = AdapterLifecycleState::AdapterFailed;
    tracker.LastAdapterInitStatus = failureStatus;
    RecordDiagnosticFailure(tracker, DriverDiagnosticStage::IddCxDeviceInitialize, failureStatus);
}

/// Evaluates D0 entry and returns whether to start init, resume, wait on pending init, or fail.
inline D0EntryTransitionResult
TransitionOnD0EntryBegin(
    AdapterLifecycleTracker& tracker
    ) noexcept
{
    tracker.LastStage = DriverDiagnosticStage::DeviceD0Entry;

    if (tracker.IsCleanedUp)
    {
        RecordDiagnosticFailure(tracker, DriverDiagnosticStage::DeviceD0Entry, STATUS_INVALID_DEVICE_STATE);
        return {D0EntryAction::FailInvalidState, STATUS_INVALID_DEVICE_STATE};
    }

    if (tracker.State == AdapterLifecycleState::AdapterFailed)
    {
        const NTSTATUS failureStatus = !IsSucceededNonPendingStatus(tracker.LastErrorStatus)
            ? tracker.LastErrorStatus
            : NormalizeFailureStatus(tracker.LastAdapterInitStatus);
        tracker.LastStageStatus = failureStatus;
        return {D0EntryAction::FailPreviousError, failureStatus};
    }

    if (tracker.State == AdapterLifecycleState::Uninitialized ||
        tracker.State == AdapterLifecycleState::DeviceConfigured)
    {
        RecordDiagnosticFailure(tracker, DriverDiagnosticStage::DeviceD0Entry, STATUS_INVALID_DEVICE_STATE);
        return {D0EntryAction::FailInvalidState, STATUS_INVALID_DEVICE_STATE};
    }

    tracker.D0EntryCount += 1;
    tracker.IsInD0 = true;

    if (tracker.HasAdapterHandle)
    {
        if (tracker.AdapterInitCompleted)
        {
            RecordDiagnosticSuccess(tracker, DriverDiagnosticStage::DeviceD0Entry, STATUS_SUCCESS);
            tracker.State = AdapterLifecycleState::AdapterReady;
            return {D0EntryAction::ResumeReady, STATUS_SUCCESS};
        }

        RecordDiagnosticSuccess(tracker, DriverDiagnosticStage::DeviceD0Entry, STATUS_SUCCESS);
        tracker.State = AdapterLifecycleState::AdapterInitPending;
        return {D0EntryAction::WaitPendingInit, STATUS_SUCCESS};
    }

    RecordDiagnosticSuccess(tracker, DriverDiagnosticStage::DeviceD0Entry, STATUS_SUCCESS);
    tracker.State = AdapterLifecycleState::AdapterInitPending;
    tracker.LastAdapterInitStatus = STATUS_PENDING;
    tracker.AdapterInitCompleted = false;
    return {D0EntryAction::StartAsyncInit, STATUS_SUCCESS};
}

/// Applies the synchronous return status of IddCxAdapterInitAsync while preserving earlier async completion.
inline NTSTATUS
TransitionOnAdapterInitAsyncSubmitted(
    AdapterLifecycleTracker& tracker,
    NTSTATUS callStatus,
    bool hasValidHandle
    ) noexcept
{
    if (tracker.IsCleanedUp || tracker.State == AdapterLifecycleState::Uninitialized)
    {
        return STATUS_INVALID_DEVICE_STATE;
    }

    tracker.LastStage = DriverDiagnosticStage::AdapterInitAsync;

    if (!IsSucceededNonPendingStatus(callStatus) || !hasValidHandle)
    {
        const NTSTATUS failureStatus = NormalizeFailureStatus(callStatus);
        tracker.HasAdapterHandle = hasValidHandle;
        tracker.AdapterInitCompleted = true;
        tracker.LastAdapterInitStatus = failureStatus;
        tracker.State = AdapterLifecycleState::AdapterFailed;
        RecordDiagnosticFailure(tracker, DriverDiagnosticStage::AdapterInitAsync, failureStatus);
        return failureStatus;
    }

    tracker.HasAdapterHandle = true;

    // If EvtIddCxAdapterInitFinished already executed on a worker thread before IddCxAdapterInitAsync
    // returned, preserve the completion state recorded by TransitionOnAdapterInitFinished.
    if (tracker.AdapterInitCompleted)
    {
        if (tracker.State == AdapterLifecycleState::AdapterFailed)
        {
            tracker.LastSuccessfulStage = DriverDiagnosticStage::AdapterInitAsync;
            return NormalizeFailureStatus(tracker.LastAdapterInitStatus);
        }
        return STATUS_SUCCESS;
    }

    RecordDiagnosticSuccess(tracker, DriverDiagnosticStage::AdapterInitAsync, callStatus);
    tracker.State = tracker.IsInD0
        ? AdapterLifecycleState::AdapterInitPending
        : AdapterLifecycleState::DeviceStopped;
    return STATUS_SUCCESS;
}

/// Applies the asynchronous completion callback result from EvtIddCxAdapterInitFinished.
inline NTSTATUS
TransitionOnAdapterInitFinished(
    AdapterLifecycleTracker& tracker,
    NTSTATUS initStatus
    ) noexcept
{
    const bool canCompletePendingInit =
        !tracker.IsCleanedUp &&
        !tracker.AdapterInitCompleted &&
        (tracker.State == AdapterLifecycleState::AdapterInitPending ||
         (tracker.State == AdapterLifecycleState::DeviceStopped && tracker.HasAdapterHandle));
    if (!canCompletePendingInit)
    {
        return STATUS_INVALID_DEVICE_STATE;
    }

    tracker.LastStage = DriverDiagnosticStage::AdapterInitFinished;
    tracker.HasAdapterHandle = true;
    tracker.AdapterInitCompleted = true;

    if (!IsSucceededNonPendingStatus(initStatus))
    {
        const NTSTATUS failureStatus = NormalizeFailureStatus(initStatus);
        tracker.LastAdapterInitStatus = failureStatus;
        tracker.State = AdapterLifecycleState::AdapterFailed;
        RecordDiagnosticFailure(tracker, DriverDiagnosticStage::AdapterInitFinished, failureStatus);
        return failureStatus;
    }

    RecordDiagnosticSuccess(tracker, DriverDiagnosticStage::AdapterInitFinished, STATUS_SUCCESS);
    tracker.LastAdapterInitStatus = STATUS_SUCCESS;
    tracker.State = tracker.IsInD0
        ? AdapterLifecycleState::AdapterReady
        : AdapterLifecycleState::DeviceStopped;
    return STATUS_SUCCESS;
}

/// Records the latest committed display path count reported by IddCx when the adapter is active.
inline NTSTATUS
TransitionOnCommitModes(
    AdapterLifecycleTracker& tracker,
    UINT32 pathCount
    ) noexcept
{
    if (tracker.IsCleanedUp ||
        !tracker.HasAdapterHandle ||
        !tracker.AdapterInitCompleted ||
        tracker.State == AdapterLifecycleState::Uninitialized ||
        tracker.State == AdapterLifecycleState::DeviceConfigured ||
        tracker.State == AdapterLifecycleState::AdapterFailed)
    {
        return STATUS_INVALID_DEVICE_STATE;
    }

    RecordDiagnosticSuccess(tracker, DriverDiagnosticStage::AdapterCommitModes, STATUS_SUCCESS);
    tracker.CommittedPathCount = pathCount;
    return STATUS_SUCCESS;
}

/// Transitions state on D0 exit without clobbering AdapterFailed or Uninitialized states.
inline void
TransitionOnD0Exit(
    AdapterLifecycleTracker& tracker
    ) noexcept
{
    tracker.LastStage = DriverDiagnosticStage::DeviceD0Exit;
    tracker.D0ExitCount += 1;
    tracker.IsInD0 = false;

    if (tracker.State != AdapterLifecycleState::AdapterFailed &&
        tracker.State != AdapterLifecycleState::Uninitialized)
    {
        tracker.State = AdapterLifecycleState::DeviceStopped;
    }
}

/// Transitions state when the WDF adapter context cleanup callback runs.
inline void
TransitionOnAdapterCleanup(
    AdapterLifecycleTracker& tracker
    ) noexcept
{
    tracker.LastStage = DriverDiagnosticStage::AdapterContextCleanup;
    tracker.HasAdapterHandle = false;
    tracker.AdapterInitCompleted = false;
    tracker.IsInD0 = false;
    tracker.IsCleanedUp = true;

    if (tracker.State != AdapterLifecycleState::AdapterFailed &&
        tracker.State != AdapterLifecycleState::Uninitialized)
    {
        tracker.State = AdapterLifecycleState::DeviceStopped;
    }
}

/// Resets device lifecycle tracking deterministically during WDFDEVICE context cleanup.
inline void
TransitionOnDeviceCleanup(
    AdapterLifecycleTracker& tracker
    ) noexcept
{
    tracker.LastStage = DriverDiagnosticStage::DeviceContextCleanup;
    tracker.HasAdapterHandle = false;
    tracker.AdapterInitCompleted = false;
    tracker.IsInD0 = false;
    tracker.IsCleanedUp = true;
    tracker.State = AdapterLifecycleState::Uninitialized;
}

} // namespace lumabridge::driver
