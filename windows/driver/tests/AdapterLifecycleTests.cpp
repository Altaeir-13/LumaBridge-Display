#ifndef WIN32_NO_STATUS
#define WIN32_NO_STATUS
#endif
#include <Windows.h>
#undef WIN32_NO_STATUS
#include <ntstatus.h>

#include <cstdio>
#include <cstdlib>

using NTSTATUS = LONG;
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#include "../LumaBridgeIddDriver/AdapterStateMachine.h"
#include "../LumaBridgeIddDriver/DiagnosticStageConfig.h"

namespace {

using namespace lumabridge::driver;

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

void
TestNormalInitializationLifecycle()
{
    AdapterLifecycleTracker tracker{};
    EXPECT_EQ(tracker.State, AdapterLifecycleState::Uninitialized);

    TransitionOnDeviceConfigured(tracker);
    EXPECT_EQ(tracker.State, AdapterLifecycleState::DeviceConfigured);

    TransitionOnDeviceInitialized(tracker, STATUS_SUCCESS);
    EXPECT_EQ(tracker.State, AdapterLifecycleState::DeviceInitialized);

    const auto d0 = TransitionOnD0EntryBegin(tracker);
    EXPECT_EQ(d0.Action, D0EntryAction::StartAsyncInit);
    EXPECT_EQ(d0.Status, STATUS_SUCCESS);
    EXPECT_EQ(tracker.State, AdapterLifecycleState::AdapterInitPending);
    EXPECT_TRUE(tracker.IsInD0);

    EXPECT_EQ(TransitionOnAdapterInitAsyncSubmitted(tracker, STATUS_SUCCESS, true), STATUS_SUCCESS);
    EXPECT_EQ(tracker.State, AdapterLifecycleState::AdapterInitPending);
    EXPECT_TRUE(tracker.HasAdapterHandle);

    EXPECT_EQ(TransitionOnAdapterInitFinished(tracker, STATUS_SUCCESS), STATUS_SUCCESS);
    EXPECT_EQ(tracker.State, AdapterLifecycleState::AdapterReady);
    EXPECT_TRUE(tracker.AdapterInitCompleted);
    EXPECT_EQ(tracker.LastAdapterInitStatus, STATUS_SUCCESS);
}

void
TestEarlyAsyncCompletionBeforeInitAsyncReturns()
{
    AdapterLifecycleTracker tracker{};
    TransitionOnDeviceConfigured(tracker);
    TransitionOnDeviceInitialized(tracker, STATUS_SUCCESS);

    const auto d0 = TransitionOnD0EntryBegin(tracker);
    EXPECT_EQ(d0.Action, D0EntryAction::StartAsyncInit);

    // Worker invokes EvtIddCxAdapterInitFinished before IddCxAdapterInitAsync post-processing runs.
    EXPECT_EQ(TransitionOnAdapterInitFinished(tracker, STATUS_SUCCESS), STATUS_SUCCESS);
    EXPECT_EQ(tracker.State, AdapterLifecycleState::AdapterReady);

    // Post-processing of IddCxAdapterInitAsync return must NOT regress state back to AdapterInitPending.
    EXPECT_EQ(TransitionOnAdapterInitAsyncSubmitted(tracker, STATUS_SUCCESS, true), STATUS_SUCCESS);
    EXPECT_EQ(tracker.State, AdapterLifecycleState::AdapterReady);
    EXPECT_TRUE(tracker.HasAdapterHandle);
    EXPECT_TRUE(tracker.AdapterInitCompleted);
}

void
TestEarlyAsyncFailureBeforeInitAsyncReturns()
{
    AdapterLifecycleTracker tracker{};
    TransitionOnDeviceConfigured(tracker);
    TransitionOnDeviceInitialized(tracker, STATUS_SUCCESS);
    EXPECT_EQ(TransitionOnD0EntryBegin(tracker).Action, D0EntryAction::StartAsyncInit);

    EXPECT_EQ(TransitionOnAdapterInitFinished(tracker, STATUS_UNSUCCESSFUL), STATUS_UNSUCCESSFUL);
    EXPECT_EQ(tracker.State, AdapterLifecycleState::AdapterFailed);

    EXPECT_EQ(TransitionOnAdapterInitAsyncSubmitted(tracker, STATUS_SUCCESS, true), STATUS_UNSUCCESSFUL);
    EXPECT_EQ(tracker.State, AdapterLifecycleState::AdapterFailed);
}

void
TestSyncInitAsyncFailureNeverRecoversSilentlyOnRetry()
{
    AdapterLifecycleTracker tracker{};
    TransitionOnDeviceConfigured(tracker);
    TransitionOnDeviceInitialized(tracker, STATUS_SUCCESS);
    EXPECT_EQ(TransitionOnD0EntryBegin(tracker).Action, D0EntryAction::StartAsyncInit);

    EXPECT_EQ(
        TransitionOnAdapterInitAsyncSubmitted(tracker, STATUS_INSUFFICIENT_RESOURCES, false),
        STATUS_INSUFFICIENT_RESOURCES);
    EXPECT_EQ(tracker.State, AdapterLifecycleState::AdapterFailed);

    TransitionOnD0Exit(tracker);
    EXPECT_EQ(tracker.State, AdapterLifecycleState::AdapterFailed);

    const auto retryD0 = TransitionOnD0EntryBegin(tracker);
    EXPECT_EQ(retryD0.Action, D0EntryAction::FailPreviousError);
    EXPECT_EQ(retryD0.Status, STATUS_INSUFFICIENT_RESOURCES);
    EXPECT_EQ(tracker.State, AdapterLifecycleState::AdapterFailed);
}

void
TestAsyncFailureThenD0ExitThenD0EntryMustFail()
{
    AdapterLifecycleTracker tracker{};
    TransitionOnDeviceConfigured(tracker);
    TransitionOnDeviceInitialized(tracker, STATUS_SUCCESS);
    EXPECT_EQ(TransitionOnD0EntryBegin(tracker).Action, D0EntryAction::StartAsyncInit);
    EXPECT_EQ(TransitionOnAdapterInitAsyncSubmitted(tracker, STATUS_SUCCESS, true), STATUS_SUCCESS);

    // Async initialization fails while handle exists.
    EXPECT_EQ(TransitionOnAdapterInitFinished(tracker, STATUS_DEVICE_DATA_ERROR), STATUS_DEVICE_DATA_ERROR);
    EXPECT_EQ(tracker.State, AdapterLifecycleState::AdapterFailed);
    EXPECT_TRUE(tracker.HasAdapterHandle);

    // D0Exit must preserve AdapterFailed rather than overwriting with DeviceStopped.
    TransitionOnD0Exit(tracker);
    EXPECT_EQ(tracker.State, AdapterLifecycleState::AdapterFailed);

    // Subsequent D0Entry must NOT return STATUS_SUCCESS just because AdapterObject != nullptr.
    const auto retryD0 = TransitionOnD0EntryBegin(tracker);
    EXPECT_EQ(retryD0.Action, D0EntryAction::FailPreviousError);
    EXPECT_EQ(retryD0.Status, STATUS_DEVICE_DATA_ERROR);
    EXPECT_EQ(tracker.State, AdapterLifecycleState::AdapterFailed);
}

void
TestD0ExitDuringPendingInitPreservesDeviceStoppedOnAsyncSuccess()
{
    AdapterLifecycleTracker tracker{};
    TransitionOnDeviceConfigured(tracker);
    TransitionOnDeviceInitialized(tracker, STATUS_SUCCESS);
    EXPECT_EQ(TransitionOnD0EntryBegin(tracker).Action, D0EntryAction::StartAsyncInit);
    EXPECT_EQ(TransitionOnAdapterInitAsyncSubmitted(tracker, STATUS_SUCCESS, true), STATUS_SUCCESS);

    // Device exits D0 before EvtIddCxAdapterInitFinished arrives.
    TransitionOnD0Exit(tracker);
    EXPECT_EQ(tracker.State, AdapterLifecycleState::DeviceStopped);
    EXPECT_TRUE(!tracker.IsInD0);

    // Async init completes while device is stopped: state must remain DeviceStopped, not AdapterReady.
    EXPECT_EQ(TransitionOnAdapterInitFinished(tracker, STATUS_SUCCESS), STATUS_SUCCESS);
    EXPECT_EQ(tracker.State, AdapterLifecycleState::DeviceStopped);
    EXPECT_TRUE(tracker.AdapterInitCompleted);

    // Returning to D0 resumes to AdapterReady.
    const auto resumeD0 = TransitionOnD0EntryBegin(tracker);
    EXPECT_EQ(resumeD0.Action, D0EntryAction::ResumeReady);
    EXPECT_EQ(resumeD0.Status, STATUS_SUCCESS);
    EXPECT_EQ(tracker.State, AdapterLifecycleState::AdapterReady);
}

void
TestD0ReentryWhilePendingDoesNotTreatStatusPendingAsSuccess()
{
    AdapterLifecycleTracker tracker{};
    TransitionOnDeviceConfigured(tracker);
    TransitionOnDeviceInitialized(tracker, STATUS_SUCCESS);
    EXPECT_EQ(TransitionOnD0EntryBegin(tracker).Action, D0EntryAction::StartAsyncInit);
    EXPECT_EQ(TransitionOnAdapterInitAsyncSubmitted(tracker, STATUS_SUCCESS, true), STATUS_SUCCESS);

    TransitionOnD0Exit(tracker);
    EXPECT_EQ(tracker.State, AdapterLifecycleState::DeviceStopped);
    EXPECT_EQ(tracker.LastAdapterInitStatus, STATUS_PENDING);

    // Re-entering D0 before EvtIddCxAdapterInitFinished has run must stay AdapterInitPending.
    const auto reentryD0 = TransitionOnD0EntryBegin(tracker);
    EXPECT_EQ(reentryD0.Action, D0EntryAction::WaitPendingInit);
    EXPECT_EQ(reentryD0.Status, STATUS_SUCCESS);
    EXPECT_EQ(tracker.State, AdapterLifecycleState::AdapterInitPending);

    // Completing afterwards transitions to AdapterReady.
    EXPECT_EQ(TransitionOnAdapterInitFinished(tracker, STATUS_SUCCESS), STATUS_SUCCESS);
    EXPECT_EQ(tracker.State, AdapterLifecycleState::AdapterReady);
}

void
TestD0ExitDuringPendingInitFollowedByAsyncFailure()
{
    AdapterLifecycleTracker tracker{};
    TransitionOnDeviceConfigured(tracker);
    TransitionOnDeviceInitialized(tracker, STATUS_SUCCESS);
    EXPECT_EQ(TransitionOnD0EntryBegin(tracker).Action, D0EntryAction::StartAsyncInit);
    EXPECT_EQ(TransitionOnAdapterInitAsyncSubmitted(tracker, STATUS_SUCCESS, true), STATUS_SUCCESS);

    TransitionOnD0Exit(tracker);
    EXPECT_EQ(tracker.State, AdapterLifecycleState::DeviceStopped);

    EXPECT_EQ(TransitionOnAdapterInitFinished(tracker, STATUS_UNSUCCESSFUL), STATUS_UNSUCCESSFUL);
    EXPECT_EQ(tracker.State, AdapterLifecycleState::AdapterFailed);

    const auto reentryD0 = TransitionOnD0EntryBegin(tracker);
    EXPECT_EQ(reentryD0.Action, D0EntryAction::FailPreviousError);
    EXPECT_EQ(reentryD0.Status, STATUS_UNSUCCESSFUL);
}

void
TestPendingStatusRejectedAsInitFinishedResult()
{
    AdapterLifecycleTracker tracker{};
    TransitionOnDeviceConfigured(tracker);
    TransitionOnDeviceInitialized(tracker, STATUS_SUCCESS);
    EXPECT_EQ(TransitionOnD0EntryBegin(tracker).Action, D0EntryAction::StartAsyncInit);
    EXPECT_EQ(TransitionOnAdapterInitAsyncSubmitted(tracker, STATUS_SUCCESS, true), STATUS_SUCCESS);

    EXPECT_EQ(TransitionOnAdapterInitFinished(tracker, STATUS_PENDING), STATUS_UNSUCCESSFUL);
    EXPECT_EQ(tracker.State, AdapterLifecycleState::AdapterFailed);
    EXPECT_EQ(tracker.LastErrorStage, DriverDiagnosticStage::AdapterInitFinished);
}

void
TestSuspendResumeAndCommitModes()
{
    AdapterLifecycleTracker tracker{};
    TransitionOnDeviceConfigured(tracker);
    TransitionOnDeviceInitialized(tracker, STATUS_SUCCESS);
    EXPECT_EQ(TransitionOnD0EntryBegin(tracker).Action, D0EntryAction::StartAsyncInit);
    EXPECT_EQ(TransitionOnAdapterInitAsyncSubmitted(tracker, STATUS_SUCCESS, true), STATUS_SUCCESS);
    EXPECT_EQ(TransitionOnAdapterInitFinished(tracker, STATUS_SUCCESS), STATUS_SUCCESS);
    EXPECT_EQ(tracker.State, AdapterLifecycleState::AdapterReady);

    EXPECT_EQ(TransitionOnCommitModes(tracker, 1), STATUS_SUCCESS);
    EXPECT_EQ(tracker.CommittedPathCount, 1u);

    TransitionOnD0Exit(tracker);
    EXPECT_EQ(tracker.State, AdapterLifecycleState::DeviceStopped);
    EXPECT_EQ(tracker.D0ExitCount, 1u);

    const auto resume = TransitionOnD0EntryBegin(tracker);
    EXPECT_EQ(resume.Action, D0EntryAction::ResumeReady);
    EXPECT_EQ(resume.Status, STATUS_SUCCESS);
    EXPECT_EQ(tracker.State, AdapterLifecycleState::AdapterReady);
    EXPECT_EQ(tracker.D0EntryCount, 2u);
}

void
TestCleanupResetsHandlesAndState()
{
    AdapterLifecycleTracker tracker{};
    TransitionOnDeviceConfigured(tracker);
    TransitionOnDeviceInitialized(tracker, STATUS_SUCCESS);
    EXPECT_EQ(TransitionOnD0EntryBegin(tracker).Action, D0EntryAction::StartAsyncInit);
    EXPECT_EQ(TransitionOnAdapterInitAsyncSubmitted(tracker, STATUS_SUCCESS, true), STATUS_SUCCESS);
    EXPECT_EQ(TransitionOnAdapterInitFinished(tracker, STATUS_SUCCESS), STATUS_SUCCESS);

    TransitionOnAdapterCleanup(tracker);
    EXPECT_TRUE(!tracker.HasAdapterHandle);
    EXPECT_TRUE(!tracker.AdapterInitCompleted);
    EXPECT_EQ(tracker.State, AdapterLifecycleState::DeviceStopped);

    TransitionOnDeviceCleanup(tracker);
    EXPECT_EQ(tracker.State, AdapterLifecycleState::Uninitialized);
    EXPECT_EQ(tracker.LastStage, DriverDiagnosticStage::DeviceContextCleanup);
}

void
TestConcurrentMultiDeviceAssociationIsolation()
{
    int deviceAToken = 1;
    int deviceBToken = 2;
    void* const deviceA = &deviceAToken;
    void* const deviceB = &deviceBToken;

    InFlightAdapterBindingSlot slot{};
    EXPECT_TRUE(slot.TryAcquire(deviceA));
    EXPECT_TRUE(!slot.TryAcquire(deviceB));
    EXPECT_TRUE(!slot.TryAcquire(nullptr));

    // Adapter A early async callback before IddCxAdapterInitAsync returns resolves deterministically to device A.
    void* adapterABoundDevice = slot.ResolveAdapterDevice(nullptr, false, nullptr);
    EXPECT_EQ(adapterABoundDevice, deviceA);

    // Explicitly releasing by a non-owner device must not clear device A's slot.
    slot.Release(deviceB);
    EXPECT_EQ(slot.InFlightDevice, deviceA);

    // Once device A completes submission and releases the slot, device B may enter its init window.
    slot.Release(deviceA);
    EXPECT_EQ(slot.InFlightDevice, static_cast<void*>(nullptr));
    EXPECT_TRUE(slot.TryAcquire(deviceB));

    // Subsequent callbacks for already-bound Adapter A keep device A despite device B occupying the slot.
    EXPECT_EQ(slot.ResolveAdapterDevice(adapterABoundDevice, true, nullptr), deviceA);
    EXPECT_EQ(slot.ResolveAdapterDevice(nullptr, false, nullptr), deviceB);

    slot.Release(deviceB);
    EXPECT_EQ(slot.InFlightDevice, static_cast<void*>(nullptr));
}

void
TestCleanupDuringInFlightInitPreventsCrossDeviceLateCallbackBinding()
{
    int deviceAToken = 10;
    int deviceBToken = 20;
    void* const deviceA = &deviceAToken;
    void* const deviceB = &deviceBToken;

    InFlightAdapterBindingSlot slot{};
    EXPECT_TRUE(slot.TryAcquire(deviceA));

    // Cleanup of Device A marks the slot as cleaned up WITHOUT releasing it prematurely:
    // Device B still cannot take the slot while IddCxAdapterInitAsync(Device A) has not returned,
    // and any callback for an unbound adapter sees InFlightDeviceCleanedUp and resolves to nullptr.
    slot.MarkDeviceCleanedUp(deviceA);
    EXPECT_TRUE(slot.InFlightDeviceCleanedUp);
    EXPECT_TRUE(!slot.TryAcquire(deviceB));
    EXPECT_EQ(slot.ResolveAdapterDevice(nullptr, false, nullptr), static_cast<void*>(nullptr));

    // After IddCxAdapterInitAsync(Device A) returns on Thread A, Adapter A is poisoned as bound/cleaned up
    // and only then is the slot released so Device B can acquire it cleanly.
    const bool adapterAWasCleanedUp = true;
    slot.Release(deviceA);
    EXPECT_EQ(slot.InFlightDevice, static_cast<void*>(nullptr));
    EXPECT_TRUE(!slot.InFlightDeviceCleanedUp);

    EXPECT_TRUE(slot.TryAcquire(deviceB));

    // Even while Device B holds the slot, a late callback for Adapter A cannot bind to Device B.
    EXPECT_EQ(slot.ResolveAdapterDevice(nullptr, adapterAWasCleanedUp, nullptr), static_cast<void*>(nullptr));
    EXPECT_EQ(slot.ResolveAdapterDevice(nullptr, false, nullptr), deviceB);

    slot.Release(deviceB);
}

void
TestCleanupDuringPendingInitialization()
{
    AdapterLifecycleTracker tracker{};
    TransitionOnDeviceConfigured(tracker);
    TransitionOnDeviceInitialized(tracker, STATUS_SUCCESS);
    EXPECT_EQ(TransitionOnD0EntryBegin(tracker).Action, D0EntryAction::StartAsyncInit);
    EXPECT_EQ(TransitionOnAdapterInitAsyncSubmitted(tracker, STATUS_SUCCESS, true), STATUS_SUCCESS);
    EXPECT_EQ(tracker.State, AdapterLifecycleState::AdapterInitPending);
    EXPECT_TRUE(tracker.HasAdapterHandle);

    TransitionOnAdapterCleanup(tracker);
    EXPECT_TRUE(!tracker.HasAdapterHandle);
    EXPECT_TRUE(!tracker.AdapterInitCompleted);
    EXPECT_TRUE(tracker.IsCleanedUp);
    EXPECT_EQ(tracker.State, AdapterLifecycleState::DeviceStopped);

    TransitionOnDeviceCleanup(tracker);
    EXPECT_TRUE(!tracker.HasAdapterHandle);
    EXPECT_TRUE(!tracker.AdapterInitCompleted);
    EXPECT_TRUE(tracker.IsCleanedUp);
    EXPECT_EQ(tracker.State, AdapterLifecycleState::Uninitialized);

    const auto postCleanupD0 = TransitionOnD0EntryBegin(tracker);
    EXPECT_EQ(postCleanupD0.Action, D0EntryAction::FailInvalidState);
    EXPECT_EQ(postCleanupD0.Status, STATUS_INVALID_DEVICE_STATE);
}

void
TestLateAsyncInitFinishedAfterCleanupIsRejected()
{
    // Case 1: Late async completion after device cleanup must not resurrect Uninitialized state.
    {
        AdapterLifecycleTracker tracker{};
        TransitionOnDeviceConfigured(tracker);
        TransitionOnDeviceInitialized(tracker, STATUS_SUCCESS);
        EXPECT_EQ(TransitionOnD0EntryBegin(tracker).Action, D0EntryAction::StartAsyncInit);
        EXPECT_EQ(TransitionOnAdapterInitAsyncSubmitted(tracker, STATUS_SUCCESS, true), STATUS_SUCCESS);

        TransitionOnDeviceCleanup(tracker);
        EXPECT_EQ(tracker.State, AdapterLifecycleState::Uninitialized);

        EXPECT_EQ(TransitionOnAdapterInitFinished(tracker, STATUS_SUCCESS), STATUS_INVALID_DEVICE_STATE);
        EXPECT_EQ(tracker.State, AdapterLifecycleState::Uninitialized);
        EXPECT_TRUE(!tracker.HasAdapterHandle);
        EXPECT_TRUE(!tracker.AdapterInitCompleted);

        EXPECT_EQ(TransitionOnAdapterInitFinished(tracker, STATUS_UNSUCCESSFUL), STATUS_INVALID_DEVICE_STATE);
        EXPECT_EQ(tracker.State, AdapterLifecycleState::Uninitialized);
        EXPECT_TRUE(!tracker.HasAdapterHandle);
    }

    // Case 2: Late async completion after adapter cleanup must not resurrect handles or flip to AdapterReady.
    {
        AdapterLifecycleTracker tracker{};
        TransitionOnDeviceConfigured(tracker);
        TransitionOnDeviceInitialized(tracker, STATUS_SUCCESS);
        EXPECT_EQ(TransitionOnD0EntryBegin(tracker).Action, D0EntryAction::StartAsyncInit);
        EXPECT_EQ(TransitionOnAdapterInitAsyncSubmitted(tracker, STATUS_SUCCESS, true), STATUS_SUCCESS);

        TransitionOnAdapterCleanup(tracker);
        EXPECT_EQ(tracker.State, AdapterLifecycleState::DeviceStopped);

        EXPECT_EQ(TransitionOnAdapterInitFinished(tracker, STATUS_SUCCESS), STATUS_INVALID_DEVICE_STATE);
        EXPECT_EQ(tracker.State, AdapterLifecycleState::DeviceStopped);
        EXPECT_TRUE(!tracker.HasAdapterHandle);
        EXPECT_TRUE(!tracker.AdapterInitCompleted);
    }

    // Case 3: Late sync submission return after device cleanup must not mutate Uninitialized state.
    {
        AdapterLifecycleTracker tracker{};
        TransitionOnDeviceConfigured(tracker);
        TransitionOnDeviceInitialized(tracker, STATUS_SUCCESS);
        EXPECT_EQ(TransitionOnD0EntryBegin(tracker).Action, D0EntryAction::StartAsyncInit);

        TransitionOnDeviceCleanup(tracker);
        EXPECT_EQ(TransitionOnAdapterInitAsyncSubmitted(tracker, STATUS_SUCCESS, true), STATUS_INVALID_DEVICE_STATE);
        EXPECT_EQ(tracker.State, AdapterLifecycleState::Uninitialized);
        EXPECT_TRUE(!tracker.HasAdapterHandle);
    }

    // Case 4: Duplicate EvtIddCxAdapterInitFinished after already reaching AdapterReady or AdapterFailed is rejected.
    {
        AdapterLifecycleTracker tracker{};
        TransitionOnDeviceConfigured(tracker);
        TransitionOnDeviceInitialized(tracker, STATUS_SUCCESS);
        EXPECT_EQ(TransitionOnD0EntryBegin(tracker).Action, D0EntryAction::StartAsyncInit);
        EXPECT_EQ(TransitionOnAdapterInitAsyncSubmitted(tracker, STATUS_SUCCESS, true), STATUS_SUCCESS);
        EXPECT_EQ(TransitionOnAdapterInitFinished(tracker, STATUS_UNSUCCESSFUL), STATUS_UNSUCCESSFUL);
        EXPECT_EQ(tracker.State, AdapterLifecycleState::AdapterFailed);

        EXPECT_EQ(TransitionOnAdapterInitFinished(tracker, STATUS_SUCCESS), STATUS_INVALID_DEVICE_STATE);
        EXPECT_EQ(tracker.State, AdapterLifecycleState::AdapterFailed);
    }
}

void
TestLateCommitModesAfterFailureOrCleanupIsRejected()
{
    // CommitModes after async failure must fail without modifying CommittedPathCount.
    {
        AdapterLifecycleTracker tracker{};
        TransitionOnDeviceConfigured(tracker);
        TransitionOnDeviceInitialized(tracker, STATUS_SUCCESS);
        EXPECT_EQ(TransitionOnD0EntryBegin(tracker).Action, D0EntryAction::StartAsyncInit);
        EXPECT_EQ(TransitionOnAdapterInitAsyncSubmitted(tracker, STATUS_SUCCESS, true), STATUS_SUCCESS);
        EXPECT_EQ(TransitionOnAdapterInitFinished(tracker, STATUS_SUCCESS), STATUS_SUCCESS);
        EXPECT_EQ(TransitionOnCommitModes(tracker, 2), STATUS_SUCCESS);
        EXPECT_EQ(tracker.CommittedPathCount, 2u);

        TransitionOnAdapterCleanup(tracker);
        EXPECT_EQ(TransitionOnCommitModes(tracker, 5), STATUS_INVALID_DEVICE_STATE);
        EXPECT_EQ(tracker.CommittedPathCount, 2u);

        TransitionOnDeviceCleanup(tracker);
        EXPECT_EQ(TransitionOnCommitModes(tracker, 9), STATUS_INVALID_DEVICE_STATE);
        EXPECT_EQ(tracker.CommittedPathCount, 2u);
    }

    // CommitModes in AdapterFailed must be rejected.
    {
        AdapterLifecycleTracker tracker{};
        TransitionOnDeviceConfigured(tracker);
        TransitionOnDeviceInitialized(tracker, STATUS_SUCCESS);
        EXPECT_EQ(TransitionOnD0EntryBegin(tracker).Action, D0EntryAction::StartAsyncInit);
        EXPECT_EQ(TransitionOnAdapterInitAsyncSubmitted(tracker, STATUS_SUCCESS, true), STATUS_SUCCESS);
        EXPECT_EQ(TransitionOnAdapterInitFinished(tracker, STATUS_UNSUCCESSFUL), STATUS_UNSUCCESSFUL);
        EXPECT_EQ(tracker.State, AdapterLifecycleState::AdapterFailed);

        EXPECT_EQ(TransitionOnCommitModes(tracker, 1), STATUS_INVALID_DEVICE_STATE);
        EXPECT_EQ(tracker.CommittedPathCount, 0u);
    }
}

void
TestDiagnosticStageSuccessProgressionTracksLastSuccessfulStage()
{
    AdapterLifecycleTracker tracker{};
    EXPECT_EQ(tracker.LastStage, DriverDiagnosticStage::None);
    EXPECT_EQ(tracker.LastSuccessfulStage, DriverDiagnosticStage::None);
    EXPECT_EQ(tracker.LastStageStatus, STATUS_SUCCESS);

    TransitionOnDeviceConfigured(tracker);
    EXPECT_EQ(tracker.LastSuccessfulStage, DriverDiagnosticStage::DeviceInitConfig);
    EXPECT_EQ(tracker.LastStageStatus, STATUS_SUCCESS);

    RecordDiagnosticSuccess(tracker, DriverDiagnosticStage::WdfDeviceCreate, STATUS_SUCCESS);
    EXPECT_EQ(tracker.LastStage, DriverDiagnosticStage::WdfDeviceCreate);
    EXPECT_EQ(tracker.LastSuccessfulStage, DriverDiagnosticStage::WdfDeviceCreate);
    EXPECT_EQ(tracker.LastStageStatus, STATUS_SUCCESS);

    TransitionOnDeviceInitialized(tracker, STATUS_SUCCESS);
    EXPECT_EQ(tracker.LastSuccessfulStage, DriverDiagnosticStage::IddCxDeviceInitialize);
    EXPECT_EQ(tracker.LastStageStatus, STATUS_SUCCESS);

    EXPECT_EQ(TransitionOnD0EntryBegin(tracker).Action, D0EntryAction::StartAsyncInit);
    EXPECT_EQ(tracker.LastSuccessfulStage, DriverDiagnosticStage::DeviceD0Entry);
    EXPECT_EQ(tracker.LastStageStatus, STATUS_SUCCESS);

    EXPECT_EQ(TransitionOnAdapterInitAsyncSubmitted(tracker, STATUS_SUCCESS, true), STATUS_SUCCESS);
    EXPECT_EQ(tracker.LastSuccessfulStage, DriverDiagnosticStage::AdapterInitAsync);
    EXPECT_EQ(tracker.LastStageStatus, STATUS_SUCCESS);

    EXPECT_EQ(TransitionOnAdapterInitFinished(tracker, STATUS_SUCCESS), STATUS_SUCCESS);
    EXPECT_EQ(tracker.LastSuccessfulStage, DriverDiagnosticStage::AdapterInitFinished);
    EXPECT_EQ(tracker.LastStageStatus, STATUS_SUCCESS);
}

void
TestDeviceInitializeFailurePreservesPreviousSuccessfulStage()
{
    AdapterLifecycleTracker tracker{};
    TransitionOnDeviceConfigured(tracker);
    RecordDiagnosticSuccess(tracker, DriverDiagnosticStage::WdfDeviceCreate, STATUS_SUCCESS);

    TransitionOnDeviceInitialized(tracker, STATUS_DEVICE_POWER_FAILURE);
    EXPECT_EQ(tracker.State, AdapterLifecycleState::AdapterFailed);
    EXPECT_EQ(tracker.LastStage, DriverDiagnosticStage::IddCxDeviceInitialize);
    EXPECT_EQ(tracker.LastSuccessfulStage, DriverDiagnosticStage::WdfDeviceCreate);
    EXPECT_EQ(tracker.LastErrorStage, DriverDiagnosticStage::IddCxDeviceInitialize);
    EXPECT_EQ(tracker.LastErrorStatus, STATUS_DEVICE_POWER_FAILURE);
    EXPECT_EQ(tracker.LastStageStatus, STATUS_DEVICE_POWER_FAILURE);
}

void
TestAdapterInitFailuresPreserveLastSuccessfulStage()
{
    // Synchronous failure in IddCxAdapterInitAsync must preserve DeviceD0Entry as last successful stage.
    {
        AdapterLifecycleTracker tracker{};
        TransitionOnDeviceConfigured(tracker);
        TransitionOnDeviceInitialized(tracker, STATUS_SUCCESS);
        EXPECT_EQ(TransitionOnD0EntryBegin(tracker).Action, D0EntryAction::StartAsyncInit);

        EXPECT_EQ(
            TransitionOnAdapterInitAsyncSubmitted(tracker, STATUS_DEVICE_POWER_FAILURE, false),
            STATUS_DEVICE_POWER_FAILURE);
        EXPECT_EQ(tracker.State, AdapterLifecycleState::AdapterFailed);
        EXPECT_EQ(tracker.LastSuccessfulStage, DriverDiagnosticStage::DeviceD0Entry);
        EXPECT_EQ(tracker.LastErrorStage, DriverDiagnosticStage::AdapterInitAsync);
        EXPECT_EQ(tracker.LastErrorStatus, STATUS_DEVICE_POWER_FAILURE);
        EXPECT_EQ(tracker.LastStageStatus, STATUS_DEVICE_POWER_FAILURE);
    }

    // Asynchronous failure in EvtIddCxAdapterInitFinished must preserve AdapterInitAsync as last successful stage.
    {
        AdapterLifecycleTracker tracker{};
        TransitionOnDeviceConfigured(tracker);
        TransitionOnDeviceInitialized(tracker, STATUS_SUCCESS);
        EXPECT_EQ(TransitionOnD0EntryBegin(tracker).Action, D0EntryAction::StartAsyncInit);
        EXPECT_EQ(TransitionOnAdapterInitAsyncSubmitted(tracker, STATUS_SUCCESS, true), STATUS_SUCCESS);

        EXPECT_EQ(
            TransitionOnAdapterInitFinished(tracker, STATUS_DEVICE_POWER_FAILURE),
            STATUS_DEVICE_POWER_FAILURE);
        EXPECT_EQ(tracker.State, AdapterLifecycleState::AdapterFailed);
        EXPECT_EQ(tracker.LastSuccessfulStage, DriverDiagnosticStage::AdapterInitAsync);
        EXPECT_EQ(tracker.LastErrorStage, DriverDiagnosticStage::AdapterInitFinished);
        EXPECT_EQ(tracker.LastErrorStatus, STATUS_DEVICE_POWER_FAILURE);
        EXPECT_EQ(tracker.LastStageStatus, STATUS_DEVICE_POWER_FAILURE);
    }
}

void
TestIddCxRuntimeTransmissionTypeValidatorRejectsNetworkOtherAndAcceptsWiredOther()
{
    // Exact runtime validator in Windows 11 IddCx.dll (10.0.26100.9818)
    // IddCx!Validate(IDDCX_ADAPTER_CAPS)+0x13e rejects 0 and 9 (NETWORK_OTHER).
    EXPECT_TRUE(!IsSupportedIddCxRuntimeTransmissionType(0U));
    EXPECT_TRUE(!IsSupportedIddCxRuntimeTransmissionType(9U));
    EXPECT_TRUE(!IsSupportedIddCxRuntimeTransmissionType(10U));

    for (uint32_t tx = 1U; tx <= 8U; ++tx)
    {
        EXPECT_TRUE(IsSupportedIddCxRuntimeTransmissionType(tx));
    }

    EXPECT_TRUE(IsSupportedIddCxRuntimeTransmissionType(3U));          // IDDCX_TRANSMISSION_TYPE_WIRED_OTHER
    EXPECT_TRUE(IsSupportedIddCxRuntimeTransmissionType(0xFFFFFFFFU)); // IDDCX_TRANSMISSION_TYPE_OTHER
}

void
TestDiagnosticStageCapabilitiesProgressMonotonicallyFromStage1ToStage6()
{
    EXPECT_EQ(kActiveDiagnosticStage, 6U);

    const auto s1 = GetDiagnosticStageCapabilities(1U);
    EXPECT_TRUE(s1.EnableCoreWdfAndIddCxAdapterInit);
    EXPECT_TRUE(!s1.EnableAdapterStateMachineAndSync);
    EXPECT_TRUE(!s1.EnableTraceLoggingAndRegistryBreadcrumbs);
    EXPECT_TRUE(!s1.EnableVirtualMonitor);
    EXPECT_TRUE(!s1.EnableSwapChainProcessor);
    EXPECT_TRUE(!s1.EnableFullHostTelemetry);

    const auto s2 = GetDiagnosticStageCapabilities(2U);
    EXPECT_TRUE(s2.EnableCoreWdfAndIddCxAdapterInit);
    EXPECT_TRUE(s2.EnableAdapterStateMachineAndSync);
    EXPECT_TRUE(!s2.EnableTraceLoggingAndRegistryBreadcrumbs);
    EXPECT_TRUE(!s2.EnableVirtualMonitor);
    EXPECT_TRUE(!s2.EnableSwapChainProcessor);
    EXPECT_TRUE(!s2.EnableFullHostTelemetry);

    const auto s3 = GetDiagnosticStageCapabilities(3U);
    EXPECT_TRUE(s3.EnableTraceLoggingAndRegistryBreadcrumbs);
    EXPECT_TRUE(!s3.EnableVirtualMonitor);

    const auto s4 = GetDiagnosticStageCapabilities(4U);
    EXPECT_TRUE(s4.EnableVirtualMonitor);
    EXPECT_TRUE(!s4.EnableSwapChainProcessor);

    const auto s5 = GetDiagnosticStageCapabilities(5U);
    EXPECT_TRUE(s5.EnableSwapChainProcessor);
    EXPECT_TRUE(!s5.EnableFullHostTelemetry);

    const auto s6 = GetDiagnosticStageCapabilities(6U);
    EXPECT_TRUE(s6.EnableCoreWdfAndIddCxAdapterInit);
    EXPECT_TRUE(s6.EnableAdapterStateMachineAndSync);
    EXPECT_TRUE(s6.EnableTraceLoggingAndRegistryBreadcrumbs);
    EXPECT_TRUE(s6.EnableVirtualMonitor);
    EXPECT_TRUE(s6.EnableSwapChainProcessor);
    EXPECT_TRUE(s6.EnableFullHostTelemetry);
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
    RunTest("NormalInitializationLifecycle", TestNormalInitializationLifecycle);
    RunTest("EarlyAsyncCompletionBeforeInitAsyncReturns", TestEarlyAsyncCompletionBeforeInitAsyncReturns);
    RunTest("EarlyAsyncFailureBeforeInitAsyncReturns", TestEarlyAsyncFailureBeforeInitAsyncReturns);
    RunTest("SyncInitAsyncFailureNeverRecoversSilentlyOnRetry", TestSyncInitAsyncFailureNeverRecoversSilentlyOnRetry);
    RunTest("AsyncFailureThenD0ExitThenD0EntryMustFail", TestAsyncFailureThenD0ExitThenD0EntryMustFail);
    RunTest("D0ExitDuringPendingInitPreservesDeviceStoppedOnAsyncSuccess", TestD0ExitDuringPendingInitPreservesDeviceStoppedOnAsyncSuccess);
    RunTest("D0ReentryWhilePendingDoesNotTreatStatusPendingAsSuccess", TestD0ReentryWhilePendingDoesNotTreatStatusPendingAsSuccess);
    RunTest("D0ExitDuringPendingInitFollowedByAsyncFailure", TestD0ExitDuringPendingInitFollowedByAsyncFailure);
    RunTest("PendingStatusRejectedAsInitFinishedResult", TestPendingStatusRejectedAsInitFinishedResult);
    RunTest("SuspendResumeAndCommitModes", TestSuspendResumeAndCommitModes);
    RunTest("CleanupResetsHandlesAndState", TestCleanupResetsHandlesAndState);
    RunTest("ConcurrentMultiDeviceAssociationIsolation", TestConcurrentMultiDeviceAssociationIsolation);
    RunTest(
        "CleanupDuringInFlightInitPreventsCrossDeviceLateCallbackBinding",
        TestCleanupDuringInFlightInitPreventsCrossDeviceLateCallbackBinding);
    RunTest("CleanupDuringPendingInitialization", TestCleanupDuringPendingInitialization);
    RunTest("LateAsyncInitFinishedAfterCleanupIsRejected", TestLateAsyncInitFinishedAfterCleanupIsRejected);
    RunTest("LateCommitModesAfterFailureOrCleanupIsRejected", TestLateCommitModesAfterFailureOrCleanupIsRejected);
    RunTest(
        "DiagnosticStageSuccessProgressionTracksLastSuccessfulStage",
        TestDiagnosticStageSuccessProgressionTracksLastSuccessfulStage);
    RunTest(
        "DeviceInitializeFailurePreservesPreviousSuccessfulStage",
        TestDeviceInitializeFailurePreservesPreviousSuccessfulStage);
    RunTest(
        "AdapterInitFailuresPreserveLastSuccessfulStage",
        TestAdapterInitFailuresPreserveLastSuccessfulStage);
    RunTest(
        "IddCxRuntimeTransmissionTypeValidatorRejectsNetworkOtherAndAcceptsWiredOther",
        TestIddCxRuntimeTransmissionTypeValidatorRejectsNetworkOtherAndAcceptsWiredOther);
    RunTest(
        "DiagnosticStageCapabilitiesProgressMonotonicallyFromStage1ToStage6",
        TestDiagnosticStageCapabilitiesProgressMonotonicallyFromStage1ToStage6);

    std::printf("Summary: %d tests run, %d assertion failures.\n", g_TestsRun, g_TestsFailed);
    return (g_TestsFailed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
