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
    MonitorCallbackStub,
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
    DriverDiagnosticStage LastErrorStage{DriverDiagnosticStage::None};
    NTSTATUS LastAdapterInitStatus{STATUS_PENDING};
    NTSTATUS LastErrorStatus{STATUS_SUCCESS};
    UINT32 CommittedPathCount{0};
    UINT32 D0EntryCount{0};
    UINT32 D0ExitCount{0};
    bool HasAdapterHandle{false};
    bool AdapterInitCompleted{false};
    bool IsInD0{false};
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

/// Records stage and error metadata for post-mortem diagnostics.
inline void
RecordDiagnosticFailure(
    AdapterLifecycleTracker& tracker,
    DriverDiagnosticStage stage,
    NTSTATUS status
    ) noexcept
{
    tracker.LastStage = stage;
    tracker.LastErrorStage = stage;
    tracker.LastErrorStatus = status;
}

/// Transitions state after IddCxDeviceInitConfig succeeds during EvtDeviceAdd.
inline void
TransitionOnDeviceConfigured(
    AdapterLifecycleTracker& tracker
    ) noexcept
{
    tracker.LastStage = DriverDiagnosticStage::DeviceInitConfig;
    tracker.State = AdapterLifecycleState::DeviceConfigured;
}

/// Transitions state after IddCxDeviceInitialize completes during EvtDeviceAdd.
inline void
TransitionOnDeviceInitialized(
    AdapterLifecycleTracker& tracker,
    NTSTATUS status
    ) noexcept
{
    tracker.LastStage = DriverDiagnosticStage::IddCxDeviceInitialize;
    if (IsSucceededNonPendingStatus(status))
    {
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

    if (tracker.State == AdapterLifecycleState::AdapterFailed)
    {
        const NTSTATUS failureStatus = !IsSucceededNonPendingStatus(tracker.LastErrorStatus)
            ? tracker.LastErrorStatus
            : NormalizeFailureStatus(tracker.LastAdapterInitStatus);
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
            tracker.State = AdapterLifecycleState::AdapterReady;
            return {D0EntryAction::ResumeReady, STATUS_SUCCESS};
        }

        tracker.State = AdapterLifecycleState::AdapterInitPending;
        return {D0EntryAction::WaitPendingInit, STATUS_SUCCESS};
    }

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
            return NormalizeFailureStatus(tracker.LastAdapterInitStatus);
        }
        return STATUS_SUCCESS;
    }

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

    tracker.LastAdapterInitStatus = STATUS_SUCCESS;
    tracker.State = tracker.IsInD0
        ? AdapterLifecycleState::AdapterReady
        : AdapterLifecycleState::DeviceStopped;
    return STATUS_SUCCESS;
}

/// Records the latest committed display path count reported by IddCx.
inline void
TransitionOnCommitModes(
    AdapterLifecycleTracker& tracker,
    UINT32 pathCount
    ) noexcept
{
    tracker.LastStage = DriverDiagnosticStage::AdapterCommitModes;
    tracker.CommittedPathCount = pathCount;
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
    tracker.State = AdapterLifecycleState::Uninitialized;
}

} // namespace lumabridge::driver
