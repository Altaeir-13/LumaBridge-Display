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

    TransitionOnCommitModes(tracker, 1);
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

    std::printf("Summary: %d tests run, %d assertion failures.\n", g_TestsRun, g_TestsFailed);
    return (g_TestsFailed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
