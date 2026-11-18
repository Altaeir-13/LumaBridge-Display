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

    std::printf("Summary: %d tests run, %d assertion failures.\n", g_TestsRun, g_TestsFailed);
    return (g_TestsFailed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
